# AnyTLS + ShadowTLS: native Mihomo security and accounting proof

This is a test harness, **not a managed protocol implementation**. No creation option, Agent
runtime service or production subscription is enabled by these changes. The required client is
Clash Verge / Mihomo; sing-box is used only as an alternative **inner server** with cumulative
per-user accounting.

The inline upstream AnyTLS + ShadowTLS path replaces normal TLS and does not encrypt application
payloads. The harness includes a deliberately insecure **positive control**, available only on
owned loopback fixtures. Never ship that control listener in an Agent configuration.

The candidate secure path is:

```text
Mihomo visible AnyTLS outbound (verified TLS)
  -> private AnyTLS/ShadowTLS-v3 wrapper via dialer-proxy
  -> server wrapper restricted to exact loopback TCP inner-listener address/port
  -> TLS + subscriber-authenticated AnyTLS inner server
  -> application destination
```

Inner and outer servers are separate processes. Loopback detection stays enabled; this transport
dependency is not a user-created same-server topology loop. The wrapper cannot reach arbitrary
destinations. Internal loopback ports must not be exposed on a host/container network in production.
This adds an AnyTLS layer and has not been performance-benchmarked.

## Reproducibility

`scripts/test-anytls-security.sh` runs inside GitHub Actions. It verifies the official Mihomo
v1.19.30 archive SHA-256, generates fresh private test certificates and checks every generated
configuration with the native core before sending traffic. The first variant uses two Mihomo
server processes. The second uses an inner sing-box server compiled in Actions from unchanged
source commit `0b8995879f29a9b98ee027bc17b75e101445b238`, with `with_v2ray_api` enabled.
The normal upstream sing-box release binary omits that accounting API and fails configuration
validation; it must not silently fall back to polling active connections.

Sources:

- [Mihomo v1.19.30](https://github.com/MetaCubeX/mihomo/tree/ac017cdd246ce8bd547653d927e7bf77d7ee73d5)
- [sing-box v1.14.0 server source](https://github.com/SagerNet/sing-box/tree/0b8995879f29a9b98ee027bc17b75e101445b238)
- [ShadowTLS's encryption limitation](https://github.com/ihciah/shadow-tls#how-to-use-it)

The Actions artifact contains only scripts, binaries, source/build metadata and a checksum. It
does **not** include generated passwords, certificates or private keys. Download and verify the
archive locally and again on the VPS, then extract it into a new, private direct child of `/opt`
named `xboard-anytls-test.*`. Run `bash ./vps-anytls-security.sh /opt/xboard-anytls-test.<suffix>`.
The script generates fresh two-day fixture certificates; all user credentials are generated in
memory inside the test container. No compilation takes place on the VPS.

The container has no networking except its own loopback, no published ports or Docker socket,
read-only root/mounts, dropped capabilities, 512 MB memory and a private temporary filesystem.
It is removed on completion/failure. The private fixture directory remains for diagnostics;
never copy its generated certificates into a deployment or publish it as an artifact.

## What the checks establish

- The wire-capture positive control sees both plaintext markers. The encrypted candidate delivers
  the same kind of traffic without exposing either marker on the outer TCP wire.
- The inner TLS trust anchor and hostname are verified. A **CA pin** plus the full leaf/CA chain
  is used; leaf-only pin behavior in Mihomo is not equivalent to complete chain/name validation.
- Incorrect inner/outer credentials and incorrect certificate pins fail closed.
- Wrapper-only requests cannot reach arbitrary destinations; plaintext cannot use the allowed
  inner TLS port as a general proxy. Valid encrypted requests work after rejected attempts.
- The inner accounting server retains counters after short connections close. Reading counters
  does not consume them, reset returns the previous values, idle reads do not replay them, and
  traffic from a second user does not alter the first user's counters.
- Replacing the inner process without a removed user's credentials rejects new connections from
  that user while remaining users still connect.

The test-only statistics decoder speaks the upstream v2ray StatsService protocol using Node's
HTTP/2 implementation; it does not replace the production Xray SDK. A production adapter must
account for the service-name difference (`v2ray.core.app.stats.command.StatsService` versus Xray),
counter resets/epochs, unbilled deltas before shutdown and simultaneous Xray/AnyTLS aggregation.

## Not yet established

Production certificate lifecycle, user/session reconciliation, active-session revocation under a
managed reload, persistent accounting across Agent/process crashes, shared-443 routing, panel-only
artifact delivery, generated subscriptions/topology dependency preservation and browser/API
acceptance remain outstanding. These tests use one isolated VPS container, not multiple physical
servers. They do not establish mainland reachability, resistance to GFW interference or a speed
advantage. The user has no mainland probe endpoint.

## Verified checkpoint

Node commit `5f32667aa5f1d1ae4d7fa07a1dc613c545dd2825` passed
[CI](https://github.com/FengYuchen1314/node/actions/runs/33922409927) and its separate
[WIP image build](https://github.com/FengYuchen1314/node/actions/runs/33922409932).
CI passed 13 tests in the Mihomo-inner variant and 16 in the accounting-server variant (counts
include each parent test), plus the existing Node, Mieru and shared-edge checks. The Node image
does not acquire an AnyTLS managed runtime from these proof scripts, and WIP tags are not pushed.

The Actions artifact was SHA-256 verified locally and on 185.99.135.224:
`d549b9a3e3491704674023458256f5a6e9f8c38b68de8867d29b21efc6b7d96a`.
All 16 accounting-server variant tests passed there without skips. The private fixture directory
is `/opt/xboard-anytls-test.vEeHlL09`; the disposable container was removed. This used the pinned
backend image only as a Node.js runtime, with the verified cores/scripts mounted read-only from
the Actions artifact. The PDF services and existing host ports were not modified.
