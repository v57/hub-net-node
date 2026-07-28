#!/usr/bin/env bash
set -euo pipefail

# HN-701: representative Linux NAT matrix. Each case uses fresh namespaces,
# real nftables NAT, kernel WireGuard, and the real rendezvous-node binary.

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

run_case() {
  local mode=$1
  local expected=$2
  echo "CASE: $mode (direct connect expected: $expected)"
  HUB_NET_NAT_MODE="$mode" HUB_NET_EXPECT_CONNECT="$expected" \
    "$root_dir/two_nat_no_relay.sh"
}

run_case full-cone true
run_case restricted true
run_case port-restricted true
run_case symmetric false

echo "PASS: representative NAT matrix"
