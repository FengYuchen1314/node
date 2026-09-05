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
