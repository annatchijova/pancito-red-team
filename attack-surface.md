# Attack Surface Triage — PANCITO web/API capability backlog — 2026-10-01

Authorization: repository owner request in this workspace. Mode: passive source
review plus active tests restricted to operator-owned loopback labs. Inventory as
of base commit `c570ecc` and the current working tree.

## Candidate queue (ranked)

| # | Candidate | Entry point | Reachability | Asset behind it | Plausibility basis | Provenance | Falsifier | Level |
|---|---|---|---|---|---|---|---|---|
| 1 | Stale authority after role revocation | Authenticated request with an already-issued token | AUTHENTICATED | Revoked privileges and tenant data | Authority may be cached in an issued credential; a bounded reversible transition now exists | `offensive/stale_authority.py` | The same credential loses protected access after verified revocation | CANDIDATE |
| 2 | Nested-resource authorization mismatch | `/parents/{p}/children/{c}` | AUTHENTICATED | Cross-tenant child resources | Parent and child authorization may be resolved independently; a bounded child-only differential exists | `offensive/nested_bola.py` | Swapping only the child identifier is denied and returns no foreign canary | CANDIDATE |

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
