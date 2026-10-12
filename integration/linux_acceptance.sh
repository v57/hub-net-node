#!/usr/bin/env bash
set -euo pipefail
umask 077

# HN-405: exercise both supported Linux deployment forms. This intentionally
# runs through Docker so the gate is reproducible from Linux and macOS CI hosts
# while still executing the released linux/amd64 binary and container image.

for command in docker curl sha256sum tar; do
  command -v "$command" >/dev/null || {
    echo "FAIL: missing required command: $command"
    exit 1
  }
done
docker info >/dev/null

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version=${VERSION:-acceptance}
architecture=${GOARCH:-amd64}
run_id="hn405-$$"
standalone_name="${run_id}-standalone"
container_name="${run_id}-container"
image="hub-net-node:${run_id}"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/hn405.XXXXXX")

cleanup() {
  set +e
  docker rm -f "$standalone_name" "$container_name" >/dev/null 2>&1
  docker image rm "$image" >/dev/null 2>&1
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

wait_healthy() {
  local name=$1
  for _ in $(seq 1 50); do
    if docker exec "$name" wget -q -O /dev/null http://127.0.0.1:1964/healthz; then
      return
    fi
    sleep 0.1
  done
  echo "FAIL: $name did not become healthy"
  docker logs "$name"
  exit 1
}

assert_clean_sigterm() {
  local name=$1
  docker stop --signal SIGTERM --timeout 10 "$name" >/dev/null
  local exit_code
  exit_code=$(docker inspect --format '{{.State.ExitCode}}' "$name")
  if [[ "$exit_code" != 0 ]]; then
    echo "FAIL: $name exited $exit_code after SIGTERM"
    docker logs "$name"
    exit 1
  fi
}

make -C "$root_dir" VERSION="$version" GOOS=linux GOARCH="$architecture" package checksums
archive="hub-net-node-${version}-linux-${architecture}.tar.gz"
(
  cd "$root_dir/build"
  sha256sum --check "${archive}.sha256"
)
tar -C "$tmp_dir" -xzf "$root_dir/build/$archive"
package_dir="$tmp_dir/hub-net-node-${version}-linux-${architecture}"

docker run -d --name "$standalone_name" \
  --read-only --tmpfs /var/lib/hub-net-node:uid=65532,gid=65532,mode=0700 \
  --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
  -v "$package_dir:/package:ro" alpine:3.22 \
  /package/hub-net-node -node-id acceptance-standalone \
  -listen 0.0.0.0:1964 -state-dir /var/lib/hub-net-node >/dev/null
wait_healthy "$standalone_name"
assert_clean_sigterm "$standalone_name"

docker build --build-arg VERSION="$version" -t "$image" -f "$root_dir/Dockerfile" "$root_dir/.." >/dev/null
docker run -d --name "$container_name" "$image" \
  -node-id acceptance-container >/dev/null
wait_healthy "$container_name"
container_user=$(docker inspect --format '{{.Config.User}}' "$container_name")
if [[ "$container_user" != "65532:65532" ]]; then
  echo "FAIL: container runs as unexpected user: $container_user"
  exit 1
fi
assert_clean_sigterm "$container_name"

echo "PASS: Linux package and container health, unprivileged runtime, checksums, SIGTERM"
