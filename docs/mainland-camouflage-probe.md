# Mainland discovery checkpoint, 2026-09-05

The operator provided a mainland VPS and independently confirmed its changed SSH ED25519
fingerprint from the cloud console. Only that host's old SSH entries were replaced, after a
local backup. No service, port, firewall rule or installed software was changed on the probe.
Its existing Node.js v20.12.2 executable ran a plain JavaScript, read-only discovery script from
a private temporary directory. The existing Java and MCSManager processes remained running.

`scripts/probe-camouflage-domains.mjs` takes explicit operator-declared source identity and
hostname arguments. It runs at most two domains concurrently, checks at most four A records
per domain, pins each TLS socket to its already-resolved public IPv4 address, verifies the
original DNS name/CA, and sends an HTTP/2 HEAD request over the same TLS 1.3/X25519 connection.
It never follows redirects, uses proxy environment variables, sends credentials or changes
panel state. Private/reserved addresses fail before any connection. Each connection has an
eight-second deadline. No compilation takes place on the VPS.

## Observed result

At 2026-09-04 22:49 UTC (2026-09-05 06:49 Asia/Shanghai), all **21 existing catalog seeds**
completed verified TLS 1.3/X25519/HTTP/2 requests from that one mainland probe. Every seed had
one IPv4 address in this snapshot; no A record was omitted. All requests had a matching SAN,
more than 14 days of certificate validity and no redirect. HTTP statuses included 200, 401 and
403; an authenticated storage/registry endpoint need not return a public homepage to complete
this handshake test. This is not an AnyTLS or REALITY connectivity test.

No observed address/routing/header/CNAME signal identified Cloudflare. Observed IPv4 origin
ASNs were AS20473, AS14061, AS23816 and AS8560. The source IP's routing lookup returned AS45090
with a CN registry country. Routing country is not independent physical geolocation; the
source's location is operator-declared and public egress was not independently reflected.
The raw point-in-time observations are in `evidence/mainland-camouflage-20260905.json`, with the
operator's exact source IP omitted. The script SHA-256 for this run is:
`9948fe5aa905be816bca2d9bcd753ef7054b15f3e0e7bc80aa4c73240af1bd39`.

Cloudflare is a **hard exclusion**, not a preference. The probe rejects any matching IPv4/IPv6
CDN range or Cloudflare CNAME before TLS, rejects AS13335 before connecting, and excludes
Cloudflare HTTP signals. Its ranges were rechecked against the official
[IPv4 list](https://www.cloudflare.com/ips-v4/) and [IPv6 list](https://www.cloudflare.com/ips-v6/).
ASN metadata uses [Team Cymru's DNS origin mapping](https://www.team-cymru.com/ip-asn-mapping),
with lookup failures kept as unknown. On 2026-09-04 22:55 UTC, a separate negative control using
`www.cloudflare.com` resolved to 104.16.123.96/104.16.124.96 and their Cloudflare IPv6 counterparts.
The probe returned `CLOUDFLARE_EXCLUDED` with `IP_RANGE` and made no TLS/HTTP connection.
That negative control is not a camouflage-pool entry.

## Boundaries and remaining work

Every report still sets `automaticallyEligible: false`. These are discovery observations, not
an authenticated panel probe API, a current deployment allow-list, nationwide reachability or
a guarantee of no GFW interference. IPv6 TLS connectivity and IPv6 origin-ASN lookup were not
tested (IPv6 DNS answers were checked against Cloudflare's listed ranges). Cloudflare absence
at one observation time cannot replace target-Agent live validation before use.

The existing panel policy requires two distinct mainland ASNs for automatic selection. One
operator-provided machine does not satisfy that gate; the script does not lower it or forge a
second source. Regional discovery seeds must still be expanded into the requested three
distinct pools per region. Signed/current probe evidence ingestion, policy/UI handling of
single-source observations and enforcement across all managed start/edit paths remain to be
finished. Imported external nodes must remain usable; no claim is made that all their supplied
metadata has been independently verified.
