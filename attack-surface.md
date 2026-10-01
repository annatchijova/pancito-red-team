# Attack Surface Triage — PANCITO web/API capability backlog — 2026-10-01

Authorization: repository owner request in this workspace. Mode: passive source
review plus active tests restricted to operator-owned loopback labs. Inventory as
of base commit `37f4fc3` and the current working tree.

## Candidate queue (ranked)

| # | Candidate | Entry point | Reachability | Asset behind it | Plausibility basis | Provenance | Falsifier | Level |
|---|---|---|---|---|---|---|---|---|
| 1 | Cross-tenant export disclosure | Tenant export route | AUTHENTICATED | Generated records, potentially containing a tenant-wide snapshot | Collection and search authorization do not establish that generated export bytes remain tenant-scoped; a bounded identical-path credential differential now exists | `offensive/export_authz.py` | Both tenant controls return only their own canaries and Alpha does not receive Bravo's canary | CANDIDATE |

## Below the line (enumerated, deprioritized)

- SSRF → high potential asset value, but deliberately below the line because the
  current active-target boundary forbids arbitrary destinations and no safe,
  closed loopback oracle has been specified.
- Injection payload execution → excluded from the current catalogue because a
  free-form payload surface would violate the closed-capability invariant.

## Refuted during triage

None. This artifact ranks capability gaps; it does not assert a target finding.

## Capability gaps closed

- Property-level authorization was removed from the capability-gap queue after
  `offensive/mass_assignment.py` established a bounded experiment. This closes
  an implementation gap; it does not refute or confirm any target candidate.
- Stale authority and nested-resource authorization were removed from the queue
  after bounded experiments established their test contracts. This closes
  implementation gaps; it does not assert that any target is safe or vulnerable.
- Function-level authorization was removed after its bounded credential-only
  experiment established a test contract. This closes an implementation gap;
  it does not assert a target finding.
- Cross-tenant collection listing was removed after its two-tenant differential
  established a test contract. This closes an implementation gap, not a target finding.
- Action-level token scope was removed after its bounded token differential
  established a test contract. This closes an implementation gap, not a target finding.
- Cross-tenant search was removed after its same-query differential established
  a test contract; cross-tenant export is now the highest-ranked unclosed
  authorization capability gap. Neither statement asserts a target finding.

## Not enumerated (coverage gaps)

- Remote production exposure: active probing is not authorized by this scope.
- Browser/client-side authorization: no browser harness was reviewed.
- GraphQL, WebSocket, and asynchronous job surfaces: not yet represented by a
  bounded capability contract.
- Third-party SaaS and shared infrastructure: outside scope.

## Ranking rule used

Order by: lowest prerequisite first (authenticated user before prior compromise),
then highest protected-asset value, then strongest repository-specific
plausibility evidence. Ties sort lexicographically by candidate name. Every row
remains `CANDIDATE` until a bounded experiment against an authorized target
confirms or falsifies it.
