# net.v57.dev

One public rendezvous node at `net.v57.dev`, on a Debian or Ubuntu host with
systemd. Agents given the node `net.v57.dev` (or `wss://net.v57.dev`) open
`wss://net.v57.dev/rendezvous` on TCP 443 and send their UDP probe to
`net.v57.dev:443`.

```
client ── TCP 443 (TLS) ──▶ nginx stream ── PROXY v1 + TCP ──▶ 127.0.0.1:1964  hub-net-node
client ── UDP 443 ─────────────────────────────────────────────▶ :443          hub-net-node
```

- nginx terminates TLS at layer 4 and starts each upstream connection with a
  PROXY protocol header, so admission limits, replay bounds and logs see the
  client. The node trusts headers from `127.0.0.1` only, and the TCP listener
  is bound to loopback, so nothing else can claim a source.
- UDP goes straight to the node. The node reports the source address and port
  it sees as the client's NAT mapping, so nothing may proxy or rewrite it, and
  nothing else may hold UDP 443 on the host. Don't enable HTTP/3 on this IP.

| File | Goes to |
|---|---|
| [`hub-net-node.default`](hub-net-node.default) | `/etc/default/hub-net-node` |
| [`bind-udp-443.conf`](bind-udp-443.conf) | `/etc/systemd/system/hub-net-node.service.d/bind-udp-443.conf` |
| [`nginx-stream.conf`](nginx-stream.conf) | `/etc/nginx/stream.d/net.v57.dev.conf` |
| [`reload-nginx.sh`](reload-nginx.sh) | `/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh` |

## DNS and firewall

- `net.v57.dev` A (and AAAA if the host has IPv6) to the host, **DNS only**. A
  proxying CDN (Cloudflare's orange cloud) can't carry the UDP probe and hides
  the client address.
- Open TCP 22, TCP 80 (certificate issuance and renewal), TCP 443 and UDP 443
  in the cloud firewall and on the host. TCP 1964 stays closed: it listens on
  loopback only.

```sh
sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw allow 443/udp && sudo ufw enable
```

## Build and copy

On a workstation, from the repository root (set `GOARCH=arm64` for an ARM
host):

```sh
make package GOOS=linux GOARCH=amd64 VERSION=1.0.0
scp build/hub-net-node-1.0.0-linux-amd64.tar.gz deploy/net.v57.dev/* net.v57.dev:/tmp/
```

## Node

```sh
cd /tmp && tar xzf hub-net-node-1.0.0-linux-amd64.tar.gz
cd hub-net-node-1.0.0-linux-amd64
sudo install -m 0755 hub-net-node /usr/bin/hub-net-node
sudo install -m 0644 packaging/hub-net-node.service /usr/lib/systemd/system/hub-net-node.service
sudo install -m 0644 packaging/hub-net-node.sysusers /usr/lib/sysusers.d/hub-net-node.conf
sudo install -m 0644 packaging/hub-net-node.tmpfiles /usr/lib/tmpfiles.d/hub-net-node.conf
sudo install -m 0644 /tmp/hub-net-node.default /etc/default/hub-net-node
sudo install -D -m 0644 /tmp/bind-udp-443.conf /etc/systemd/system/hub-net-node.service.d/bind-udp-443.conf
sudo systemd-sysusers /usr/lib/sysusers.d/hub-net-node.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/hub-net-node.conf
sudo systemctl daemon-reload
sudo systemctl enable --now hub-net-node
journalctl -u hub-net-node -n 5   # "node listening" 127.0.0.1:1964, "udp observation listening" [::]:443
```

`HUB_NET_NODE_ID` (`n1`) is the node's identifier. Keep it stable for this
host; a second node gets its own name and ID (see the clustering notes below).

## Certificate and nginx

```sh
sudo apt install nginx libnginx-mod-stream certbot
sudo rm -f /etc/nginx/sites-enabled/default        # frees port 80 for certbot
sudo systemctl stop nginx
sudo certbot certonly --standalone -d net.v57.dev
sudo install -D -m 0755 /tmp/reload-nginx.sh /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
sudo install -D -m 0644 /tmp/nginx-stream.conf /etc/nginx/stream.d/net.v57.dev.conf
echo 'stream { include /etc/nginx/stream.d/*.conf; }' | sudo tee -a /etc/nginx/nginx.conf
sudo nginx -t && sudo systemctl start nginx
sudo certbot renew --dry-run
```

Renewal uses certbot's standalone server on port 80, which nothing else on the
host serves; the deploy hook reloads nginx with the new certificate.

## Check

```sh
curl -fsS https://net.v57.dev/healthz                                # through TLS and PROXY protocol
curl -fsS --haproxy-protocol http://127.0.0.1:1964/healthz           # on the host
curl -sS http://127.0.0.1:1964/healthz                               # refused: no PROXY header
sudo ss -ulpn 'sport = :443'                                         # hub-net-node holds UDP 443
```

A headerless connection from `127.0.0.1` is closed and logged as `proxy
protocol rejected`. Admission rejections log the client address, not
`127.0.0.1`.

## Point Hubs at it

A Hub owner sets the node with `hub/net/node/set` to `wss://net.v57.dev`.
Inviters register there and put the same node in their invitation codes, so
joiners land on the node that holds the inviter. It is already the default in
hub-server (`defaultHubNetNode`), the Swift HubServer (`defaultNode`) and the
Hub app, so only Hubs whose owner set another node need this.

## Upgrade

```sh
sudo install -m 0755 hub-net-node /usr/bin/hub-net-node && sudo systemctl restart hub-net-node
```

All node state is in memory. A restart drops registrations and links; devices
re-register on their own and in-flight joins retry.

## More than one node

Every join must stay on one process: presence, UDP observations, link pairing
and replay state are process-local. Don't put several nodes behind
`net.v57.dev` with round-robin DNS or a load balancer. The agent resolves the
host once for the WebSocket and again for UDP, so even one client can split
across nodes. Scale with one name and ID per node (`n1.net.v57.dev`,
`n2.net.v57.dev`, ...), each set up like this one, and fail over by moving a
name to a replacement host.
