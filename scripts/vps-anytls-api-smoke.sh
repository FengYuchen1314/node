#!/usr/bin/env bash
# Complete Action-built Agent image, not a standalone runtime-class test.
set -euo pipefail
umask 077
test "$(id -u)" = 0
task_dir=$(pwd -P)
[[ "$task_dir" == /opt/xboard-anytls-api-test.* && "$(dirname -- "$task_dir")" == /opt ]]
image="${1:?Pass the exact Action-built ghcr.io/fengyuchen1314/node@sha256 digest}"
[[ "$image" =~ ^ghcr.io/fengyuchen1314/node@sha256:[a-f0-9]{64}$ ]]
test ! -e "$task_dir/state"
test -f vps-anytls-api-smoke.mjs
test -f anytls-test-certificates.sh
mkdir -m 700 state certs inner-certs
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=RW disposable API CA' -keyout certs/ca.key -out certs/ca.crt >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=localhost' -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' -addext 'extendedKeyUsage=serverAuth' -keyout certs/server.key -out certs/server.csr >/dev/null 2>&1
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -days 2 -copy_extensions copy -out certs/server.crt >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=RW disposable API client' -addext 'extendedKeyUsage=clientAuth' -keyout certs/client.key -out certs/client.csr >/dev/null 2>&1
openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key -CAserial certs/ca.srl -days 2 -copy_extensions copy -out certs/client.crt >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out certs/jwt.key >/dev/null 2>&1
openssl pkey -in certs/jwt.key -pubout -out certs/jwt.pub >/dev/null 2>&1
bash ./anytls-test-certificates.sh "$task_dir/inner-certs"
docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
docker run --rm --network none --entrypoint node -v "$task_dir:/test" "$image" /test/vps-anytls-api-smoke.mjs setup
container="rw-anytls-api-$(basename -- "$task_dir")"
if docker container inspect "$container" >/dev/null 2>&1; then
    echo 'Refusing to replace an existing container.' >&2
    exit 1
fi
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
# NET_ADMIN is confined to this new bridge-network namespace. No public ports or Docker socket.
docker run -d --name "$container" --cap-add NET_ADMIN --pids-limit 256 --memory 768m --cpus 2 \
    --env-file "$task_dir/agent.env" -v "$task_dir:/test" -v "$task_dir/state:/var/lib/remnanode" "$image" >/dev/null
docker exec "$container" node /test/vps-anytls-api-smoke.mjs initial
docker restart --timeout 30 "$container" >/dev/null
docker exec "$container" node /test/vps-anytls-api-smoke.mjs restored
docker restart --timeout 30 "$container" >/dev/null
docker exec "$container" node /test/vps-anytls-api-smoke.mjs stopped
echo 'PASS: complete Agent AnyTLS API image acceptance (no protocol traffic claim)'
