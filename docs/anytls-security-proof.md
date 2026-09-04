# AnyTLS + ShadowTLS: native Mihomo security and accounting proof

The security harness is now accompanied by an **opt-in Agent runtime module**. Managed creation,
production subscriptions and shared-443 integration are still not connected; the feature remains
disabled by default. The required client is Clash Verge / Mihomo; sing-box is used only as an
**inner server** with cumulative per-user accounting, not as a required client.

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
source commit `0b8995879f29a9b98ee027bc17b75e101445b238`, with `with_v2ray_api` and `with_clash_api` enabled.
The normal upstream sing-box release binary omits that accounting API and fails configuration
validation; it must not silently fall back to polling active connections.

Sources:

- [Mihomo v1.19.30](https://github.com/MetaCubeX/mihomo/tree/ac017cdd246ce8bd547653d927e7bf77d7ee73d5)
- [sing-box v1.14.0 server source](https://github.com/SagerNet/sing-box/tree/0b8995879f29a9b98ee027bc17b75e101445b238)
- [ShadowTLS's encryption limitation](https://github.com/ihciah/shadow-tls#how-to-use-it)

The Actions artifact contains only scripts, binaries, source/build metadata and a checksum. It
does **not** include generated passwords, certificates or private keys. Download and verify the
archive locally and again on the VPS, then extract it into a new, private direct child of `/opt`
named `xboard-anytls-test.*`. Extract as root with `tar --no-same-owner`; the private directory and
files must be root-owned because the test container drops DAC-override capabilities. The current
packager normalizes tar ownership to numeric root as well. Run
`bash ./vps-anytls-security.sh /opt/xboard-anytls-test.<suffix>`.
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

The proof-only statistics decoder speaks the upstream v2ray StatsService protocol using Node's
HTTP/2 implementation. The new Agent adapter reuses the existing SDK's protobuf definitions with
the correct service name (`v2ray.core.app.stats.command.StatsService` rather than Xray's name).
Neither replaces the existing Xray adapter. Simultaneous Xray/AnyTLS billing is not yet wired.

## Opt-in managed Agent runtime

`src/modules/anytls` is registered in the existing Node module with `ANYTLS_ENABLED=false` by
default. Its JWT-protected API exposes start, stop, status and per-user statistics under
`/node/anytls`. No backend-managed start request or normal billing poll calls this API yet.

- Strict listener/config schemas reject duplicate SNI/ports, overlapping control ports, shared
  transport/subscriber secrets and unsupported fields. Certificate chain, expiry, hostname and
  private-key matching are validated before live mutation. Mapped IPv6 cannot disguise a local
  handshake loop. Both generated configs also pass native core validation before a reload.
- Separate supervised inner/outer processes retain verified inner TLS. Wrapper-only traffic is
  restricted to its exact inner TCP listener. Authenticated inner users cannot reach private
  egress addresses or local control/statistics services. Native tests allow only one additional
  owned HTTP fixture through a test-only renderer, never an API setting.
- Serialized updates persist explicit stop intent before mutation, drain connections, retain
  final counters and attempt rollback. An unconfirmed rollback is an error. Graceful Agent
  restart restores committed listeners; explicit stop cannot revive them.
- Cumulative statistics are never reset at the core by the production adapter. Durable decimal
  totals, per-generation snapshots and consumer baselines prevent duplicate billing after
  graceful restarts and concurrent consumption. Failed persistence does not consume a baseline;
  final counters stay pending for retry. This is not end-to-end exactly-once delivery to a panel.
- The Linux supervisor shuts down its exact core on Agent pipe EOF and uses kernel parent-death
  signaling if the supervisor is killed. Duplicate shutdown hooks are idempotent. A PID read from
  disk is never a target for process termination.
- Inactive configuration directories created by the current IO instance are cleaned after
  reload, rejection, stop and release. An active generation is retained. Unowned paths, even
  generation-shaped ones, and symlinks are not recursively removed. Cleanup failures are logged
  without credentials and retried on release, without losing the final accounting snapshot.

Runtime state belongs in a private persistent directory. A hard crash can lose the last
uncheckpointed traffic (normally up to the five-second checkpoint interval, more during storage
failure); it must not be described as crash-lossless accounting. Files left by a crashed older
owner are intentionally not adopted by the in-memory generation collector. Certificate renewal,
safe stale-state maintenance and end-to-end delivery acknowledgements need further integration.

## Not yet established

Production certificate lifecycle, panel-driven user/session reconciliation, mixed Xray billing,
crash-lossless accounting, shared-443 routing, panel-only artifact delivery, generated
subscriptions/topology dependency preservation and browser/full API acceptance remain outstanding.
Managed revocation, rollback and graceful-restart accounting now have native tests, but those
instantiate the runtime rather than calling the complete HTTPS/JWT Node API. These tests use one
isolated VPS container, not multiple physical
servers. They do not establish mainland reachability, resistance to GFW interference or a speed
advantage. A separately verified mainland VPS has now completed a read-only domain-discovery
run; see mainland-camouflage-probe.md. That observation does not establish protocol connectivity
or nationwide availability.

## Historical security-only checkpoint

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

## Managed runtime checkpoint

Node `b027eb956b4c4d9a08b57e4960f2946b4467cb1f` passed
[CI](https://github.com/FengYuchen1314/node/actions/runs/33924956212), including both source and
Actions-compiled managed-runtime tests. The archive checksum, verified locally and again on
185.99.135.224, is `dadc319d42c1336cf8e87cd5b009bfcb5a318a24e275c9d2111599e353b4ae90`.
All **24** tests passed on the VPS (16 security/accounting proof tests plus 8 managed lifecycle
tests, including parents), with no skips. Fixture directory: `/opt/xboard-anytls-test.AmVTMJLu`.

The first launch found an artifact ownership problem: tar had preserved Actions UID 1001, so
root inside the capability-dropped container could not read the private files. Ownership was
corrected only within the newly created test directory before rerunning. The packager now
normalizes ownership. The successful run used the previously published Node image as the
Node.js/dependency runtime, with new compiled test code and native cores mounted read-only from
Actions. It does not establish acceptance of the new complete AnyTLS Node image. The disposable
container was removed, both PDF containers remained healthy, and HTTP 38100 returned 200.

The cleanup/ownership patch `ec632cfe101dfebb010aabc6a522c536544eb0fb` passed
[CI](https://github.com/FengYuchen1314/node/actions/runs/33925806458) and the separate
[multi-architecture image build](https://github.com/FengYuchen1314/node/actions/runs/33925806431).
Its archive SHA-256 was verified locally and remotely:
`b712ee555961e2235304d6a2d2b2ebc99c6934710f1665193d7b3ccece5e29fd`.
All 24 tests passed again at `/opt/xboard-anytls-test.BeOzXq4t`, including assertions that reload,
rollback, shutdown and explicit stop leave no retired generated credential directories. The
standard VPS script worked without the ownership correction needed by the previous archive.
The disposable container was removed and both PDF services stayed healthy, HTTP 38100 = 200.

The ec632cf image was compile-only, with WIP pushing still disabled at that checkpoint. Following
it, the workflow publishes WIP images only to `sha-<source commit>` tags so complete-image API
acceptance can run without updating `xboard-dev`. Publishing a hash tag is not deployment; full
API and image-binary acceptance remain to be performed on that exact produced digest.
