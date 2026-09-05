# Coordinated Xray / AnyTLS / shared-443 lifecycle

Functional commits: `2236f7dab83932a52dc5f7dfd1b439a2ef242070` and
`ce43b7e9569ea635343d1bb2317e1a096d6ba210`.

## Agent interface and behavior

When both `ANYTLS_ENABLED` and `EDGE_ENABLED` are true, the existing authenticated
`POST /node/xray/start` requires `edgePlan` and `anyTlsConfig`. An explicit
`{ "version": 1, "listeners": [] }` removes AnyTLS; omission is rejected, not interpreted
as permission to keep or remove unknown listeners. Other Agents must omit this field.
`GET /node/anytls/capabilities` reports `coordinatedStartVersion: 1` only in joint mode;
the existing strict edge-status response has not changed.

The controller serializes the whole start/stop operation, including its rollback checkpoint.
The AnyTLS accounting lock remains held through edge commit or rollback. Standalone AnyTLS
start/stop and legacy incremental Xray user/plugin-sync mutations are rejected in joint mode.
Ordinary standalone Agents retain their previous interfaces. A joint panel must reconcile
complete entitlements instead of using the legacy incremental user endpoints.

Live camouflage/CDN policy is checked before changing the old generation, and is checked
again during activation and restoration. Mixed validation binds raw TLS only to the exact
AnyTLS wrapper, reserves inner/control/statistics/Agent ports against Xray numeric/list/range
ports, and prevents local website upstreams from reaching protected listeners.

Updates withdraw new proxy admission while keeping the existing Caddy website configuration,
drain both old cores, start the new cores and wait for AnyTLS application readiness before
publishing the new edge plan. Both old cores release their ports first, including when a port
moves between protocols. These full joint reconciliations currently drain connections even
for unchanged requests; the panel must coalesce configuration updates, not use start as a
periodic health or statistics poll. This is not a zero-downtime update claim.

Failure retires replacements and attempts to restore both previous cores with live policy
checks. Old proxy admission is restored only after confirmed core rollback. Otherwise the
edge persists and restores a routes-empty recovery target. Joint boot never auto-starts saved
AnyTLS listeners or replays admitted proxy routes based on saved state alone: it waits for a
complete panel reconciliation. Explicit stop preserves website configuration and attempts
both core stops even when one fails.

## Reboot defect found by the complete image test

The first image test reached successful mixed starts, native failed-core rollback, port swaps
and one restart, but failed on the next restart. A stale PID-only owner record matched an
unrelated PID in the new container namespace. In addition, an s6 shutdown exception could
interrupt later module cleanup hooks. The failing evidence is retained in
`/opt/xboard-joint-api-test.uDYkmfkB`; it is **not** accepted as a complete image pass.

The existing native supervisor now also holds a nonblocking kernel `flock` on the persistent
owner inode. It never unlinks/replaces that inode or kills a PID read from disk. Concurrent
owners are rejected; release/exit drops ownership independently of PID reuse. Unexpected
lease-helper death removes readiness and stops the owned proxy cores. Core shutdown errors
no longer prevent the later AnyTLS cleanup hook from running.

Legacy nonempty PID records remain conservative: a potentially live/ambiguous legacy owner
is not stolen. Stop an old enabled AnyTLS Agent safely before upgrading. This does not promise
automatic recovery of an ambiguous old PID record or permission to delete an unknown lock.

## Verified results

- Local: 131 tests passed; six Linux/POSIX checks skipped on Windows. Type-check, lint,
  changed-file formatting and diff checks passed. No application/native-core build ran locally.
- [CI 33954936969](https://github.com/FengYuchen1314/node/actions/runs/33954936969) passed,
  including native Go lease tests, Mieru/edge checks, confidentiality tests and source/compiled
  AnyTLS lifecycle/readiness tests. Native tests include lease loss stopping live cores.
- [Image build 33954936957](https://github.com/FengYuchen1314/node/actions/runs/33954936957)
  passed for amd64/arm64. Tested immutable image:
  `ghcr.io/fengyuchen1314/node@sha256:99974518c29a6279af0659b46dc58488da0db556894b823f832330e1759dc863`.
- **54/54**, zero skips, portable edge/controller/lifecycle tests passed on 185.99.135.224 in
  `/opt/xboard-edge-test.6LjHyaMm`. Artifact `9966043995`; tar SHA-256
  `db87462043921d8e60b103d150fc670bb047b06ad0f1a1b2fa0d9b937ab8823b`.
  Native HAProxy/Caddy tests now verify routes-empty crash recovery blocks old SNI targets
  while preserving the trusted private-CA website, then verify explicit restoration.
- **35/35**, zero skips, native security/runtime/readiness tests passed in
  `/opt/xboard-anytls-test.zkAgcrrl`. Artifact `9966072655`; GitHub ZIP SHA-256
  `09ae96c4470b38c56c3f872a7ff050d408ea77c4adfa20c933d1c6c279252fe0`; tar SHA-256
  `d074ce0189e119b06d6b88ef55e7a405f8e7a236a56d3fce729600e3899d1a58`.
  Only the short-lived artifact URL, never a GitHub account token, was passed to the VPS.
- Complete-image API acceptance passed in `/opt/xboard-joint-api-test.jdHOao9T` using the exact
  image above and `scripts/vps-coordinated-api-smoke.*`. It verifies authenticated capability
  discovery, rejection of partial user/plugin/AnyTLS mutations and missing configuration,
  live CF rejection before and after activation, native Xray failure/rollback, cross-runtime
  port swaps, reboot withdrawal, explicit reconciliation, AnyTLS removal, joint stop and another
  full restart without listener revival. Source archive SHA-256:
  `bc5ce28a9da77139d1099ddfcc3cd638ddb538b482b31f48178966108faa6828`.
  Export used `git -c core.autocrlf=false archive`; an earlier Windows CRLF-converted fixture
  at `/opt/xboard-joint-api-test.ZKhqPWLZ` failed shell syntax before deployment and was not used.

The portable suites use Actions-compiled code and binaries. The edge native fixture runs
inside a private nested Docker engine; its host network is not the VPS host. The complete
Agent API fixture uses a dedicated bridge namespace shared only by its new Agent/HAProxy/Caddy
containers. No VPS compilation, host Docker socket, host PID namespace or published ports
were used. Temporary containers/engine volumes were removed, existing running container IDs
remained identical and the PDF endpoint remained HTTP 200. Evidence/private fixture state
is retained; do not publish private certificates, credentials or logs wholesale.

## Remaining original scope

This closes the Node coordinated-lifecycle gap, not the complete product request. The current
test panel and its embedded Agent image pin were not replaced. Managed AnyTLS creation still
requires panel profile/host representation, certificate issuance/lifecycle, complete user
entitlement synchronization, mixed accounting and secure Mihomo subscription/topology wiring.
Traffic-reset delivery still lacks a panel acknowledgement protocol; lossless hard-crash
accounting is not claimed.

The API test starts real VLESS/AnyTLS cores but does not send mixed encrypted client traffic
through public 443. The separate native edge test uses byte receivers; its website uses a
private test CA. Real mixed VLESS/AnyTLS/website client acceptance, public ACME, panel workflows
and cross-physical-server topologies remain required. Continuous core/domain-health enforcement,
domain pools/mainland evidence, one-click updater acceptance and the remaining UI work also
remain in scope. Mainland observations must not be described as nationwide availability.
