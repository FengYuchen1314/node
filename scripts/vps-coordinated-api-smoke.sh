#!/usr/bin/env bash
set -euo pipefail
umask 077
test "$(id -u)" = 0
task_dir=$(pwd -P)
[[ "$task_dir" =~ ^/opt/xboard-joint-api-test\.[A-Za-z0-9]{8}$ ]]
image="${1:?Exact Action-built Node image digest required}"
[[ "$image" =~ ^ghcr.io/fengyuchen1314/node@sha256:[a-f0-9]{64}$ ]]
test ! -e state
test -f vps-anytls-api-smoke.mjs
test -f vps-coordinated-api-smoke.mjs
test -f vps-anytls-client-smoke.mjs
test -f mihomo-test-readiness.mjs
prefix="rw-${task_dir##*/}"
anchor="$prefix-network"
agent="$prefix-agent"
haproxy="$prefix-haproxy"
caddy="$prefix-caddy"
for name in "$anchor" "$agent" "$haproxy" "$caddy"; do
  if docker inspect "$name" >/dev/null 2>&1; then echo 'Fixture name already exists' >&2; exit 1; fi
done
docker ps --quiet --no-trunc | sort > containers-before.txt
test "$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:38100)" = 200
cleanup() {
  local result=$?
  trap - EXIT
  for name in "$agent" "$haproxy" "$caddy" "$anchor"; do
    if docker inspect "$name" >/dev/null 2>&1; then
      test "$(docker inspect "$name" --format '{{index .Config.Labels "io.xboard.acceptance"}}')" = "$prefix" || exit 1
      docker logs "$name" > "$name.log" 2>&1 || true
      docker rm --force --volumes "$name" >/dev/null || result=1
    fi
  done
  docker ps --quiet --no-trunc | sort > containers-after.txt
  cmp containers-before.txt containers-after.txt || result=1
  test "$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:38100)" = 200 || result=1
  echo "Joint API acceptance exit=$result; fixture containers removed; evidence retained."
  exit "$result"
}
trap cleanup EXIT
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
docker run --rm --entrypoint node -v "$task_dir:/test" "$image" /test/vps-anytls-api-smoke.mjs setup
docker run --rm --network none --entrypoint node -v "$task_dir:/test" "$image" /test/vps-coordinated-api-smoke.mjs setup
# A dedicated bridge namespace survives Agent restarts. Nothing is published on the VPS.
docker run -d --name "$anchor" --label "io.xboard.acceptance=$prefix" --network bridge \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true --entrypoint sleep "$image" infinity >/dev/null
docker run -d --name "$caddy" --label "io.xboard.acceptance=$prefix" --network "container:$anchor" --user 0:0 \
  -v "$task_dir/edge/Caddyfile:/etc/caddy/Caddyfile:ro" \
  caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648 \
  caddy run --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
docker run -d --name "$haproxy" --label "io.xboard.acceptance=$prefix" --network "container:$anchor" --user 0:0 \
  -v "$task_dir/edge:/usr/local/etc/haproxy:ro" -v "$task_dir/edge/run:/run/edge" \
  haproxy:3.2.23-alpine3.24@sha256:6343ce34a132a5dceaa24767d739df2bd519f8f7c1079ae39e4821334e8eb42e \
  haproxy -W -db -f /usr/local/etc/haproxy/haproxy.cfg -S /run/edge/master.sock,uid,0,gid,0,mode,600 >/dev/null
docker run -d --name "$agent" --label "io.xboard.acceptance=$prefix" --network "container:$anchor" \
  --cap-add NET_ADMIN --pids-limit 256 --memory 768m --cpus 2 --env-file "$task_dir/agent.env" \
  -v "$task_dir:/test" -v "$task_dir/state:/var/lib/remnanode" "$image" >/dev/null
for name in "$anchor" "$agent" "$haproxy" "$caddy"; do
  test "$(docker inspect "$name" --format '{{len .HostConfig.PortBindings}}')" = 0
  test -z "$(docker inspect "$name" --format '{{.HostConfig.PidMode}}')"
done
docker exec "$agent" node /test/vps-coordinated-api-smoke.mjs initial
docker restart --timeout 30 "$agent" >/dev/null
docker exec "$agent" node /test/vps-coordinated-api-smoke.mjs reboot
docker restart --timeout 30 "$agent" >/dev/null
docker exec "$agent" node /test/vps-coordinated-api-smoke.mjs stopped
echo 'PASS: full joint Agent/native edge API lifecycle and encrypted client usage (no public ACME or panel billing claim)'
