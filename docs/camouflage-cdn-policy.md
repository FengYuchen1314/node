# Cloudflare exclusion: deployed guard scope

Every camouflage domain is subject to the user's prohibition on Cloudflare CDN, including
manually supplied domains. Cloudflare DNS hosting alone is not treated as CDN use: these
checks inspect destination addresses, requested hostnames, CNAME targets and HTTP evidence,
not the domain's authoritative nameserver provider.

The existing live Agent guard covers REALITY start/reconcile and AnyTLS start/reconcile,
rollback and saved-state restoration. It checks both address families against pinned CDN
ranges and available AS13335 data, CNAME/hostname suffixes and observed HTTP headers. It pins
the selected verified REALITY destination instead of letting Xray resolve it again. The
standalone mainland discovery script and independent panel/cache policy also exclude known
Cloudflare signals. Unknown or incomplete evidence must not be promoted to automatic eligibility.

## Multi-address and wire-header corrections

Four new regression tests failed before the corrections:

- The actual HTTP/2 response-copy path omitted `CF-Ray`, even though its downstream parser and
  mock-observation tests supported the field. The real loopback HTTP/2 test now covers absent,
  empty and nonempty values with a masked `Server: nginx`. Presence is retained internally
  and converted to the existing `HTTP_HEADER` report signal; no wire contract change is needed.
- Runtime and catalog validation returned after the first successful target IP. They now
  inspect the remaining resolved target addresses before accepting a clean result. An observed
  Cloudflare header on any inspected target excludes the entire domain.
- A failed primary SNI could skip the remaining SNIs on that address and fall back to another
  IP. All requested SNIs are now inspected, with positive Cloudflare evidence taking precedence.

Unreachable or otherwise invalid endpoints are not selected. The first completely verified
target is chosen deterministically only after the remaining targets have been checked for
positive evidence. An exhausted overall validation deadline still rejects the request.

The known-hostname rule also covers Cloudflare-hosted
[Pages](https://developers.cloudflare.com/pages/configuration/custom-domains/),
[Workers](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/)
and [public R2 endpoints](https://developers.cloudflare.com/r2/buckets/public-buckets/)
(`pages.dev`, `workers.dev`, `r2.dev`), including custom domains pointing to them by CNAME.
Matching is case-insensitive on exact DNS suffixes and tolerates a terminal dot; unrelated
names such as `pages.dev.example.com` are not classified by substring.

## Remaining limits

This is not periodic enforcement on already-running processes, a guarantee about hidden CDN
ownership, or proof of nationwide mainland reachability. A failed update preserves the prior
running configuration. Existing panel create/edit/import workflows still require integration
acceptance, and a third-party domain can change after a point-in-time check. Single-source
mainland discovery does not satisfy the current two-distinct-ASN automatic selection gate.
No bypass option, forced-positive cache flag or unverified preselected pool is provided.

The corrected code has local unit, real HTTP/2 fixture, type-check and lint coverage. The
full-image API smoke additionally checks rejection of known service domains before and after
listener startup and live authenticated domain-report wiring. Record the exact Actions run
and full-image VPS result after they finish; source tests alone are not deployment acceptance.
