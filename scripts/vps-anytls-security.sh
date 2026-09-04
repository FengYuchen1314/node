#!/usr/bin/env bash
# Runs only prebuilt binaries / plain JavaScript, on container loopback with no public ports.
set -euo pipefail
umask 077
test_dir="$(realpath -- "${1:?Pass a private /opt/xboard-anytls-test.* directory}")"
[[ "$test_dir" == /opt/xboard-anytls-test.* && "$(dirname -- "$test_dir")" == /opt ]]
[[ -f "$test_dir/SOURCE_COMMIT" && -x "$test_dir/mihomo" && -x "$test_dir/sing-box" ]]
[[ -x "$test_dir/rw-core-supervisor" && -f "$test_dir/anytls-runtime.test.cjs" ]]
read -r source_commit < "$test_dir/SOURCE_COMMIT"
[[ "$source_commit" =~ ^[a-f0-9]{40}$ ]]
mkdir -m 700 "$test_dir/certs"
bash "$test_dir/anytls-test-certificates.sh" "$test_dir/certs"
image='ghcr.io/fengyuchen1314/node@sha256:80e27e701376c14e04aba349bebb8c8d23ee0c7a9feca5442ed27223c7af090e'
container="xboard-anytls-$(basename -- "$test_dir")"
if docker container inspect "$container" >/dev/null 2>&1; then
  echo 'Refusing to replace an existing container.' >&2
  exit 1
fi
docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
trap 'docker container rm -f "$container" >/dev/null 2>&1 || true' EXIT
printf 'Testing security proof from Node repository commit %s\n' "$source_commit"
docker run --rm --name "$container" --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --memory 512m --cpus 2 \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m \
  --mount "type=bind,src=$test_dir,dst=/test,readonly" \
  --env RW_MIHOMO_BINARY=/test/mihomo --env RW_ANYTLS_CERT_DIR=/test/certs \
  --env RW_ANYTLS_INNER_BINARY=/test/sing-box \
  --env RW_ANYTLS_RUNTIME_INTEGRATION=1 --env RW_ANYTLS_SUPERVISOR_BINARY=/test/rw-core-supervisor \
  --env NODE_PATH=/opt/app/dist/node_modules \
  --entrypoint /usr/local/bin/node "$image" --test /test/anytls-shadowtls-security.mjs /test/anytls-runtime.test.cjs
