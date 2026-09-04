#!/usr/bin/env bash
# Run from a newly allocated, private /opt/xboard-remediation-test.* directory.
# Uses an Action-built image; never compiles on the VPS or touches existing services.
set -euo pipefail
umask 077
test "$(id -u)" = 0
test "$(uname -m)" = x86_64
task_dir=$(pwd -P)
case "$task_dir" in /opt/xboard-remediation-test.*) ;; *) exit 2 ;; esac
test ! -e "$task_dir/state"
image='ghcr.io/fengyuchen1314/node@sha256:80e27e701376c14e04aba349bebb8c8d23ee0c7a9feca5442ed27223c7af090e'
container="rw-mieru-smoke-$(basename "$task_dir" | cut -d. -f2)"
mkdir -m 700 state certs bin
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=RW disposable smoke CA' -keyout certs/ca.key -out certs/ca.crt >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=localhost' -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' -addext 'extendedKeyUsage=serverAuth' -keyout certs/server.key -out certs/server.csr >/dev/null 2>&1
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -days 2 -copy_extensions copy -out certs/server.crt >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=RW disposable client' -addext 'extendedKeyUsage=clientAuth' -keyout certs/client.key -out certs/client.csr >/dev/null 2>&1
openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key -CAserial certs/ca.srl -days 2 -copy_extensions copy -out certs/client.crt >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out certs/jwt.key >/dev/null 2>&1
openssl pkey -in certs/jwt.key -pubout -out certs/jwt.pub >/dev/null 2>&1
curl -fsSL --max-time 90 https://github.com/enfein/mieru/releases/download/v3.36.0/mieru_3.36.0_linux_amd64.tar.gz -o bin/mieru.tar.gz
printf '%s  %s\n' b3f8b32a8b5728c01f31e33ff7a71b3b33f3fd8e1341684fcb98d5ecebb7db7a bin/mieru.tar.gz | sha256sum -c -
tar -xzf bin/mieru.tar.gz -C bin
test -x bin/mieru
docker run --rm --network none --entrypoint node -v "$task_dir:/test" "$image" /test/vps-mieru-smoke.mjs setup
cleanup() {
    # Only the uniquely named container owned by this invocation is removed.
    docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT
# NET_ADMIN applies only inside this bridge-network container, never to the host.
# No management or proxy ports are published, and no Docker socket is mounted.
docker run -d --name "$container" --cap-add NET_ADMIN --env-file "$task_dir/agent.env" -v "$task_dir:/test" -v "$task_dir/state:/var/lib/remnanode" "$image" >/dev/null
docker exec "$container" node /test/vps-mieru-smoke.mjs initial
docker restart --timeout 30 "$container" >/dev/null
docker exec "$container" node /test/vps-mieru-smoke.mjs restored
docker restart --timeout 30 "$container" >/dev/null
docker exec "$container" node /test/vps-mieru-smoke.mjs stopped
echo 'PASS: isolated Agent image, mTLS/JWT, Mieru authorization, accounting and restart lifecycle'
