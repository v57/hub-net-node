#!/usr/bin/env bash
set -euo pipefail
umask 077

# HN-406: build two independent NATs around two WireGuard peers. Both peers
# contact hub-net-node for coordination, then exchange application packets
# directly. A capture inside the node namespace proves those packets never
# traverse the node.

nat_mode=${HUB_NET_NAT_MODE:-full-cone}
expect_connect=${HUB_NET_EXPECT_CONNECT:-true}
case "$nat_mode" in
  full-cone|restricted|port-restricted|symmetric) ;;
  *) echo "FAIL: unsupported HUB_NET_NAT_MODE: $nat_mode"; exit 1 ;;
esac
case "$expect_connect" in
  true|false) ;;
  *) echo "FAIL: HUB_NET_EXPECT_CONNECT must be true or false"; exit 1 ;;
esac

if [[ $(uname -s) != Linux ]]; then
  echo "SKIP: Linux network namespaces required"
  exit 0
fi
if [[ ${EUID} -ne 0 ]]; then
  echo "SKIP: root required"
  exit 0
fi

for command in ip wg nft tcpdump curl ping; do
  command -v "$command" >/dev/null || {
    echo "SKIP: missing required command: $command"
    exit 0
  }
done

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
go_command=${HUB_NET_GO:-}
if [[ -z "$go_command" ]]; then
  go_command=$(command -v go 2>/dev/null || true)
fi
if [[ -z "$go_command" && -n ${SUDO_USER:-} ]]; then
  sudo_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
  if [[ -x "$sudo_home/.local/bin/go" ]]; then
    go_command="$sudo_home/.local/bin/go"
  fi
fi
if [[ -z "$go_command" ]]; then
  echo "SKIP: Go toolchain not found (set HUB_NET_GO)"
  exit 0
fi
run_id="hn406-$$"
link_id="h$$"
internet="${run_id}-internet"
router_a="${run_id}-router-a"
router_b="${run_id}-router-b"
agent_a="${run_id}-agent-a"
agent_b="${run_id}-agent-b"
node="${run_id}-node"
tmp_dir=$(mktemp -d /run/hn406.XXXXXX)
mkdir -p /etc/wireguard
key_dir=$(mktemp -d /etc/wireguard/hn406.XXXXXX)
node_pid=
capture_pid=
client_a_pid=
client_b_pid=

cleanup() {
  set +e
  [[ -n "$capture_pid" ]] && kill "$capture_pid" 2>/dev/null
  [[ -n "$client_a_pid" ]] && kill "$client_a_pid" 2>/dev/null
  [[ -n "$client_b_pid" ]] && kill "$client_b_pid" 2>/dev/null
  [[ -n "$node_pid" ]] && kill "$node_pid" 2>/dev/null
  wait "$capture_pid" 2>/dev/null
  wait "$node_pid" 2>/dev/null
  for namespace in "$agent_a" "$agent_b" "$router_a" "$router_b" "$node" "$internet"; do
    ip netns delete "$namespace" 2>/dev/null
  done
  rm -rf "$tmp_dir"
  rm -rf "$key_dir"
}
trap cleanup EXIT

"$go_command" -C "$root_dir" build -trimpath -o "$tmp_dir/hub-net-node" ./cmd/hub-net-node
"$go_command" -C "$root_dir" build -trimpath -o "$tmp_dir/rendezvous-client" ./integration/rendezvous_client
"$tmp_dir/rendezvous-client" -identity "$tmp_dir/hub.identity" -init-identity

for namespace in "$internet" "$router_a" "$router_b" "$agent_a" "$agent_b" "$node"; do
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done
ip -n "$internet" link add br0 type bridge
ip -n "$internet" link set br0 up

connect_public() {
  local namespace=$1
  local suffix=$2
  local outside="${link_id}${suffix}o"
  local inside="${link_id}${suffix}i"
  ip link add "$outside" type veth peer name "$inside"
  ip link set "$outside" netns "$namespace"
  ip link set "$inside" netns "$internet"
  ip -n "$namespace" link set "$outside" name pub0
  ip -n "$namespace" addr add "198.18.0.${suffix}/24" dev pub0
  ip -n "$namespace" link set pub0 up
  ip -n "$internet" link set "$inside" master br0
  ip -n "$internet" link set "$inside" up
}

connect_private() {
  local agent=$1
  local router=$2
  local octet=$3
  local suffix=$4
  local agent_link="${link_id}${suffix}a"
  local router_link="${link_id}${suffix}r"
  ip link add "$agent_link" type veth peer name "$router_link"
  ip link set "$agent_link" netns "$agent"
  ip link set "$router_link" netns "$router"
  ip -n "$agent" link set "$agent_link" name eth0
  ip -n "$router" link set "$router_link" name lan0
  ip -n "$agent" addr add "10.${octet}.0.2/24" dev eth0
  ip -n "$router" addr add "10.${octet}.0.1/24" dev lan0
  ip -n "$agent" link set eth0 up
  ip -n "$router" link set lan0 up
  ip -n "$agent" route add default via "10.${octet}.0.1"
}

connect_public "$router_a" 2
connect_public "$router_b" 3
connect_public "$node" 4
connect_private "$agent_a" "$router_a" 10 a
connect_private "$agent_b" "$router_b" 20 b

configure_nat() {
  local namespace=$1
  local private_ip=$2
  local public_port=$3
  local peer_public_ip=$4
  local peer_public_port=$5
  local public_ip=$6
  local inbound_rule
  local established_rule="ct state established,related accept"
  local postrouting_rule="oifname \"pub0\" udp sport 51820 snat to ${public_ip}:${public_port}
    oifname \"pub0\" masquerade"

  case "$nat_mode" in
    full-cone)
      inbound_rule='iifname "pub0" oifname "lan0" udp dport 51820 accept'
      ;;
    restricted)
      inbound_rule="iifname \"pub0\" oifname \"lan0\" ip saddr ${peer_public_ip} udp dport 51820 accept"
      ;;
    port-restricted)
      inbound_rule="iifname \"pub0\" oifname \"lan0\" ip saddr ${peer_public_ip} udp sport 51820 udp dport 51820 accept"
      ;;
    symmetric)
      postrouting_rule="oifname \"pub0\" ip daddr ${peer_public_ip} udp dport ${peer_public_port} snat to ${public_ip}:61${public_port: -2}
    oifname \"pub0\" udp sport 51820 snat to ${public_ip}:${public_port}
    oifname \"pub0\" masquerade"
      established_rule="ct state established,related meta l4proto tcp accept"
      inbound_rule="iifname \"pub0\" oifname \"lan0\" ip saddr 198.18.0.4 udp sport 1964 udp dport 51820 accept
    iifname \"pub0\" oifname \"lan0\" ip saddr ${peer_public_ip} udp sport ${peer_public_port} udp dport 51820 accept"
      ;;
  esac

  ip netns exec "$namespace" sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec "$namespace" nft -f - <<EOF
table ip nat {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "pub0" udp dport ${public_port} dnat to ${private_ip}:51820
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ${postrouting_rule}
  }
}
table inet filter {
  chain forward {
    type filter hook forward priority filter; policy drop;
    ${established_rule}
    iifname "lan0" oifname "pub0" accept
    ${inbound_rule}
  }
}
EOF
}

configure_nat "$router_a" 10.10.0.2 51821 198.18.0.3 51822 198.18.0.2
configure_nat "$router_b" 10.20.0.2 51822 198.18.0.2 51821 198.18.0.3

wg genkey >"$key_dir/a.key"
wg genkey >"$key_dir/b.key"
wg pubkey <"$key_dir/a.key" >"$key_dir/a.pub"
wg pubkey <"$key_dir/b.key" >"$key_dir/b.pub"

for namespace in "$agent_a" "$agent_b"; do
  ip -n "$namespace" link add wg0 type wireguard
  ip -n "$namespace" link set wg0 up
done
ip -n "$agent_a" addr add 100.96.0.10/32 dev wg0
ip -n "$agent_b" addr add 100.96.0.20/32 dev wg0
ip -n "$agent_a" route add 100.96.0.20/32 dev wg0
ip -n "$agent_b" route add 100.96.0.10/32 dev wg0

start_node() {
  ip netns exec "$node" "$tmp_dir/hub-net-node" \
    -listen 198.18.0.4:1964 -state-dir "$tmp_dir/state" >>"$tmp_dir/node.log" 2>&1 &
  node_pid=$!
  for _ in $(seq 1 50); do
    if ip netns exec "$agent_a" curl -fsS --connect-timeout 1 \
      http://198.18.0.4:1964/healthz >/dev/null &&
      ip netns exec "$agent_b" curl -fsS --connect-timeout 1 \
        http://198.18.0.4:1964/healthz >/dev/null; then
      return
    fi
    sleep 0.1
  done
  echo "FAIL: rendezvous node did not become healthy"
  exit 1
}

start_node

ip netns exec "$node" tcpdump -Z root -U -n -i any -w "$tmp_dir/node.pcap" >"$tmp_dir/tcpdump.log" 2>&1 &
capture_pid=$!
sleep 0.2

# Both clients probe from port 51820, rendezvous, and persist only the peer's
# delivered observedEndpoint. WireGuard is configured after those sockets
# close, using no fixture-side peer endpoint knowledge.
ip netns exec "$agent_a" "$tmp_dir/rendezvous-client" \
  -server 198.18.0.4:1964 -identity "$tmp_dir/hub.identity" \
  -profile-key profile-a -agent-key agent-a -output "$tmp_dir/endpoint-a" \
  >"$tmp_dir/client-a.log" 2>&1 &
client_a_pid=$!
ip netns exec "$agent_b" "$tmp_dir/rendezvous-client" \
  -server 198.18.0.4:1964 -identity "$tmp_dir/hub.identity" \
  -profile-key profile-b -agent-key agent-b -output "$tmp_dir/endpoint-b" \
  >"$tmp_dir/client-b.log" 2>&1 &
client_b_pid=$!
wait "$client_a_pid"
client_a_pid=
wait "$client_b_pid"
client_b_pid=
endpoint_for_a=$(<"$tmp_dir/endpoint-a")
endpoint_for_b=$(<"$tmp_dir/endpoint-b")
ip netns exec "$agent_a" wg set wg0 private-key "$key_dir/a.key" listen-port 51820 \
  peer "$(cat "$key_dir/b.pub")" allowed-ips 100.96.0.20/32 endpoint "$endpoint_for_a" persistent-keepalive 2
ip netns exec "$agent_b" wg set wg0 private-key "$key_dir/b.key" listen-port 51820 \
  peer "$(cat "$key_dir/a.pub")" allowed-ips 100.96.0.10/32 endpoint "$endpoint_for_b" persistent-keepalive 2

# Application traffic must cross both NAT boundaries directly over WireGuard
# for supported mappings. Symmetric endpoint-dependent mapping must fail
# within a bounded timeout and never fall back through the node.
if [[ "$expect_connect" == true ]]; then
  ip netns exec "$agent_a" ping -c 3 -W 2 100.96.0.20 >/dev/null
  ip netns exec "$agent_b" ping -c 3 -W 2 100.96.0.10 >/dev/null

  # Restart rendezvous node on same endpoint and state directory. Established
  # application traffic remains direct during outage; both agents can contact
  # restarted coordination service afterward without tunnel disruption.
  kill "$node_pid"
  wait "$node_pid"
  node_pid=
  ip netns exec "$agent_a" ping -c 1 -W 2 100.96.0.20 >/dev/null
  ip netns exec "$agent_b" ping -c 1 -W 2 100.96.0.10 >/dev/null
  start_node
  ip netns exec "$agent_a" curl -fsS http://198.18.0.4:1964/healthz >/dev/null
  ip netns exec "$agent_b" curl -fsS http://198.18.0.4:1964/healthz >/dev/null
  ip netns exec "$agent_a" ping -c 1 -W 2 100.96.0.20 >/dev/null
  ip netns exec "$agent_b" ping -c 1 -W 2 100.96.0.10 >/dev/null
else
  if ip netns exec "$agent_a" ping -c 1 -W 3 100.96.0.20 >/dev/null 2>&1; then
    echo "FAIL: $nat_mode unexpectedly established a direct path"
    exit 1
  fi
fi

kill -INT "$capture_pid"
wait "$capture_pid"
capture_pid=
tcpdump -n -r "$tmp_dir/node.pcap" >"$tmp_dir/node.capture"

grep -q '1964' "$tmp_dir/node.capture" || {
  echo "FAIL: node capture contains no coordination traffic"
  exit 1
}
if grep -Eq '100\\.96\\.0\\.(10|20)' "$tmp_dir/node.capture"; then
  echo "FAIL: application traffic traversed rendezvous node"
  sed -n '1,80p' "$tmp_dir/node.capture"
  exit 1
fi

handshake_a=$(ip netns exec "$agent_a" wg show wg0 latest-handshakes | awk '{print $2}')
handshake_b=$(ip netns exec "$agent_b" wg show wg0 latest-handshakes | awk '{print $2}')
if [[ "$expect_connect" == true ]]; then
  if [[ ${handshake_a:-0} -eq 0 || ${handshake_b:-0} -eq 0 ]]; then
    echo "FAIL: WireGuard handshake missing for $nat_mode"
    exit 1
  fi
  echo "PASS: $nat_mode NATs, direct WireGuard survives rendezvous restart, node coordination-only"
else
  if [[ ${handshake_a:-0} -ne 0 || ${handshake_b:-0} -ne 0 ]]; then
    echo "FAIL: $nat_mode unexpectedly completed a WireGuard handshake"
    exit 1
  fi
  echo "PASS: direct_connect_failed: $nat_mode candidate timed out; no relay fallback attempted"
fi
