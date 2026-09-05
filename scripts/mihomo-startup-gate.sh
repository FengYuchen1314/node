#!/bin/sh
# Native test fixture only. The production Agent never launches this script.
set -eu
post_up=''
next_is_hook=false
for argument in "$@"; do
  if [ "$next_is_hook" = true ]; then
    post_up="$argument"
    next_is_hook=false
  elif [ "$argument" = '-post-up' ]; then
    next_is_hook=true
  fi
done
# Native config validation (-t) does not supply or execute a startup callback.
if [ -z "$post_up" ]; then
  exec "$RW_MIHOMO_BINARY" "$@"
fi
# Preserve the exact Agent-generated callback after a test-owned release gate. The command
# is taken only from this test's production IO argv, never from an API/user configuration.
gate='while [ ! -f "$RW_ANYTLS_TEST_GATE_RELEASE" ]; do sleep 0.01; done; '
exec "$RW_MIHOMO_BINARY" "$@" -post-up "$gate$post_up"
