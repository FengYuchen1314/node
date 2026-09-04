#!/usr/bin/env bash
# Disposable test trust anchor. These keys never belong in a release or subscription.
set -euo pipefail
umask 077
cert_dir="$(realpath -- "${1:?Pass a new, empty fixture directory}")"
[[ -d "$cert_dir" && -z "$(ls -A -- "$cert_dir")" ]]
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj '/CN=Disposable AnyTLS security proof CA' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$cert_dir/ca.key" -out "$cert_dir/ca.crt" >/dev/null 2>&1
for name in camouflage inner; do
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$name.test" \
    -addext "subjectAltName=DNS:$name.test" -addext 'extendedKeyUsage=serverAuth' \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -keyout "$cert_dir/$name.key" -out "$cert_dir/$name.csr" >/dev/null 2>&1
  openssl x509 -req -in "$cert_dir/$name.csr" -CA "$cert_dir/ca.crt" \
    -CAkey "$cert_dir/ca.key" -CAcreateserial -days 2 -copy_extensions copy \
    -out "$cert_dir/$name.crt" >/dev/null 2>&1
  cat "$cert_dir/ca.crt" >> "$cert_dir/$name.crt"
done
