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
if [[ -n "${RW_ANYTLS_EXPORT_DIR:-}" ]]; then
  mkdir -p "$RW_ANYTLS_EXPORT_DIR"
  cp "$fixture_dir/mihomo" scripts/anytls-shadowtls-security.mjs \
    scripts/anytls-test-certificates.sh scripts/vps-anytls-security.sh "$RW_ANYTLS_EXPORT_DIR/"
fi
