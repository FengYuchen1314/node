#!/usr/bin/env bash
set -euo pipefail
umask 077
fixture_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/rw-anytls-proof.XXXXXXXX")"
mkdir -m 700 "$fixture_dir/certs"
bash scripts/anytls-test-certificates.sh "$fixture_dir/certs"
curl --fail --location --retry 3 --output "$fixture_dir/mihomo.gz" \
  'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.30/mihomo-linux-amd64-v1-v1.19.30.gz'
printf '%s  %s\n' 'cbe553d0319a414bd3a372c5976a252155b2c4882b66bce88a4d6bba9571a553' "$fixture_dir/mihomo.gz" | sha256sum --check --strict
gzip --decompress "$fixture_dir/mihomo.gz"
chmod 700 "$fixture_dir/mihomo"
RW_MIHOMO_BINARY="$fixture_dir/mihomo" RW_ANYTLS_CERT_DIR="$fixture_dir/certs" \
  node --test scripts/anytls-shadowtls-security.mjs
# The upstream release omits cumulative statistics. Build the unchanged, pinned server source
# with its official accounting feature. Compilation is restricted to GitHub Actions, never VPS.
[[ "${GITHUB_ACTIONS:-}" == true ]] || { echo 'Server compilation must run in GitHub Actions.' >&2; exit 2; }
server_commit='0b8995879f29a9b98ee027bc17b75e101445b238'
git init --quiet "$fixture_dir/sing-box-source"
git -C "$fixture_dir/sing-box-source" remote add origin https://github.com/SagerNet/sing-box.git
git -C "$fixture_dir/sing-box-source" fetch --quiet --depth 1 origin "$server_commit"
git -C "$fixture_dir/sing-box-source" checkout --quiet --detach FETCH_HEAD
[[ "$(git -C "$fixture_dir/sing-box-source" rev-parse HEAD)" == "$server_commit" ]]
(
  cd "$fixture_dir/sing-box-source"
  go mod download
  go mod verify
  go build -mod=readonly -trimpath -tags with_v2ray_api,with_clash_api -ldflags '-s -w -buildid=' \
    -o "$fixture_dir/sing-box" ./cmd/sing-box
)
RW_MIHOMO_BINARY="$fixture_dir/mihomo" RW_ANYTLS_CERT_DIR="$fixture_dir/certs" \
  RW_ANYTLS_INNER_BINARY="$fixture_dir/sing-box" \
  node --test scripts/anytls-shadowtls-security.mjs
(
  cd tools/mita-control
  go build -mod=readonly -trimpath -ldflags '-s -w' -o "$fixture_dir/rw-core-supervisor" ./supervisor
)
export RW_ANYTLS_RUNTIME_INTEGRATION=1 RW_MIHOMO_BINARY="$fixture_dir/mihomo" RW_ANYTLS_STARTUP_GATE="$PWD/scripts/mihomo-startup-gate.sh" \
  RW_ANYTLS_INNER_BINARY="$fixture_dir/sing-box" RW_ANYTLS_SUPERVISOR_BINARY="$fixture_dir/rw-core-supervisor" RW_ANYTLS_CERT_DIR="$fixture_dir/certs"
npx tsx --test src/modules/anytls/anytls-runtime.linux.test.ts
NODE_ENV=production npx rspack build --config scripts/anytls-runtime-test.rspack.mjs
node --test test-dist/anytls-*.test.cjs
if [[ -n "${RW_ANYTLS_EXPORT_DIR:-}" ]]; then
  mkdir -p "$RW_ANYTLS_EXPORT_DIR"
  cp "$fixture_dir/mihomo" "$fixture_dir/sing-box" "$fixture_dir/rw-core-supervisor" test-dist/anytls-runtime.test.cjs test-dist/anytls-startup-readiness.test.cjs \
    scripts/anytls-shadowtls-security.mjs scripts/anytls-test-stats.mjs scripts/mihomo-test-readiness.mjs \
    scripts/anytls-test-certificates.sh scripts/mihomo-startup-gate.sh scripts/vps-anytls-security.sh "$RW_ANYTLS_EXPORT_DIR/"
  cp "$fixture_dir/sing-box-source/LICENSE" "$RW_ANYTLS_EXPORT_DIR/SINGBOX_LICENSE"
  printf '%s\n' "$server_commit" > "$RW_ANYTLS_EXPORT_DIR/SINGBOX_SOURCE_COMMIT"
  printf '%s\n' 'with_v2ray_api,with_clash_api' > "$RW_ANYTLS_EXPORT_DIR/SINGBOX_BUILD_TAGS"
fi
