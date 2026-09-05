# AnyTLS cumulative accounting

`GET /node/anytls/usage` retains the controller's JWT and transport authentication.
Disabled runtimes return `{ available: false }`. Enabled runtimes return version 1,
a durable epoch UUID and cumulative per-user uplink/downlink **decimal strings**.
The existing capability response is unchanged for old panel compatibility.

The first cumulative poll persists an immutable baseline equal to legacy `billed`
counters; only previously unbilled bytes enter the new epoch. Snapshot retries
never reset counters. Epoch, baseline and totals survive process restarts and
listener removal. Once enabled, destructive legacy `/stats` resets are refused so
two delivery modes cannot charge the same bytes. Old Agent versions do not know
the new private state field; do not downgrade a participating Agent without a
deliberate accounting-state migration.

The panel must commit cumulative watermarks and billing in one database transaction.
No HTTP response receipt is an accounting acknowledgement. The Agent keeps totals
after subscribers are revoked, so final bytes remain fetchable. Network loss after
durable sampling is retryable. There is no claim of zero loss on machine power
failure before sampling: the runtime currently checkpoints every five seconds and
drains on graceful shutdown; unresponsive cores or failed storage can widen that
window. Never advertise a strict five-second loss bound under failed I/O.

Local unit/type/lint checks do not prove native Linux behavior. Actions and isolated
VPS native replay are required before accepting this implementation for deployment.

## Accepted Agent checkpoint — 2026-09-05

Functional commit `9dc8750f346081f62dee6c20d9e2846d531815e5` passed
[CI 33960252397](https://github.com/FengYuchen1314/node/actions/runs/33960252397)
and [image run 33960252377](https://github.com/FengYuchen1314/node/actions/runs/33960252377).
The published image digest is
`ghcr.io/fengyuchen1314/node@sha256:3293d71dcab6838d470e3da70bd56661509847fef5966adafffe6ff1f8dfd286`.
This image does not have an OCI revision label; source provenance here is the
successful source-bound Actions run and its digest, not a nonexistent label.

- Artifact `9967735860`: ZIP SHA-256
  `4dfe0f97fc377b8113ac91336dd543aa2138885782a6f3b302ba31b406974e3d`;
  tar SHA-256 `861277348298002e879bed4441a3229a19cd61110fdaa40384e0c156d89a5ad9`.
  VPS `/opt/xboard-anytls-test.PR0MiJtd/acceptance.log`: 35/35 native tests passed,
  zero skips. This replays the Actions-compiled runtime with pinned native cores.
- The full image passed authenticated cumulative API, shared-443 core/edge
  lifecycle and reboot checks in `/opt/xboard-joint-api-test.VBMauJxN`.
- Plain-JavaScript acceptance scripts at commit `b4b885f` added a real Mihomo client
  through the full image's HAProxy port 443, with live non-Cloudflare camouflage,
  independent verified inner TLS and a public HTTP target. The test never relaxed
  Agent network policy or the client's certificate verification.
  `/opt/xboard-joint-api-test.oM9BL3kr/acceptance.log` passed. Its authenticated
  snapshot recorded exactly one user (`42`), uplink `88` and downlink `868` bytes;
  repeated GETs, runtime replacements, two Agent restarts, listener removal and
  explicit stop retained the same epoch and totals. Reset requests were rejected.

Each full-image test removed only its labelled fixture containers. The original
16 container IDs remained unchanged and the existing PDF service returned HTTP
200 on port 38100. Evidence and private disposable fixture files remain under the
above test directories. No production service, host port or existing panel data
was changed. These checks establish Agent TCP traffic/accounting transport, not
full panel billing, public ACME, UDP or cross-physical-server subscription routing.
