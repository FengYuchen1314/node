# Mixed shared-443 routing checkpoint

Functional source: `c9b38bef6a9eee0af6aac663c6c2088e45f06fc2`.

## Implemented boundary

The existing HAProxy renderer can distinguish PROXY-v2 VLESS routes from raw TLS routes
to the protected AnyTLS outer wrapper. Binding validation requires explicit Xray and AnyTLS
configurations for every raw route, and matches the exact wrapper tag, port and camouflage SNI.
It rejects inner TLS targets, unbound/control-port targets, missing routes, duplicate identities,
web/proxy SNI overlap and cross-runtime port collisions, including Xray comma lists and ranges.
Unknown or dynamic Xray ports fail closed in mixed validation.

The existing Agent start path still does **not** supply an AnyTLS binding context and rejects
raw routes before any core, journal or edge mutation. The panel's managed AnyTLS creation
gate remains closed. This is an additive routing prerequisite, not a coordinated runtime or
an indication that the panel can create/use the protocol yet. Existing VLESS plans and the
version-1 edge status response remain compatible; a future mixed-runtime capability must
not be inferred from that version number or standalone AnyTLS availability alone.

Negative tests also exposed an existing website-loop check bypass: URL normalization turns
IPv4-mapped IPv6 into hexadecimal form. The edge now shares AnyTLS's endpoint normalization
and rejects local mapped/expanded addresses, including the inner TLS port when mixed context
is supplied. Address-family-sensitive CIDR/CDN policy has not been relaxed. Full certificate
and live Cloudflare policy checks remain the responsibility of the runtime before activation.

## Verification

- Local: 107 tests passed, 4 Linux-only tests skipped; type-check, lint and diff checks passed.
- [Actions CI 33951248878](https://github.com/FengYuchen1314/node/actions/runs/33951248878)
  passed all checks, native Mieru lifecycle, native edge tests, 20 Actions-compiled edge tests,
  both standalone AnyTLS confidentiality variants and both managed AnyTLS lifecycle suites.
- Portable edge artifact: `9964902313`; archive SHA-256
  `d13ea70026dd2871917059aea75a697c05a494903c6f0c5e0867328dbd433cee`.
  Its archive entries, checksum and full source commit were checked locally and on the VPS.
- On `185.99.135.224`, all 20 compiled tests passed with **zero skips** in
  `/opt/xboard-edge-test.vUq3TLR6`. Evidence and the guarded runner are retained there.
  A private nested Docker engine contained the real HAProxy/Caddy test. The test's `host`
  network was only that engine's container namespace, not the VPS host. No host Docker socket,
  host PID namespace, published ports or VPS compilation were used.
- The Node runtime image supplied only Node/dependencies; tested code came from the new
  Actions artifact. The runtime dependency path is `/opt/app/dist/node_modules`. An initial
  attempt at `/opt/xboard-edge-test.z61ffmYb` used the wrong path and failed before native
  routing tests; its failure evidence is retained, not counted as acceptance.
- Temporary runner, nested engine and its private image-store volume were removed after
  each attempt. The set of existing running container IDs remained identical and PDF HTTP
  `127.0.0.1:38100` remained 200. The current test panel was not replaced.

The native edge fixture verifies two PROXY-v2 byte receivers, one raw TLS byte receiver and
the website on the same isolated port 443, before and after failed-reload rollback. These are
**not real VLESS/AnyTLS servers**. Website HTTPS verifies its ephemeral private CA and host;
untrusted issuer and wrong-SNI requests must fail. Only byte-routing probes stop after
ClientHello; they do not perform a certificate handshake. Public ACME and full mixed proxy
traffic are not claimed by this checkpoint.

## Still required before managed AnyTLS can be enabled

1. Application-ready outer-runtime admission, not just an open TCP port.
2. Serialized Xray/AnyTLS/edge startup, replacement, explicit stop and rollback, including
   crash recovery and Cloudflare revalidation on restoration. No independent API may race
   that transition or leave a stale admitted wrapper.
3. Panel profile/host representation and private certificate lifecycle, user entitlement
   synchronization, secure Mihomo subscription/topology rendering and mixed accounting.
4. Native encrypted VLESS/AnyTLS plus website acceptance on one server, followed by panel
   creation/update/restart and cross-server topology acceptance on the test VPS.

The overall original request also still includes the remaining one-click-update acceptance,
domain-pool/mainland-evidence work, public-certificate testing and UI issues. This checkpoint
does not narrow that scope or mark the overall goal complete.
