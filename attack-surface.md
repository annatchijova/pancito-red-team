# Attack Surface Triage — PANCITO web/API capability backlog — 2026-10-01

Authorization: repository owner request in this workspace. Mode: passive source
review plus active tests restricted to operator-owned loopback labs. Inventory as
of base commit `128bde8` and the current working tree.

## Candidate queue (ranked)

| # | Candidate | Entry point | Reachability | Asset behind it | Plausibility basis | Provenance | Falsifier | Level |
|---|---|---|---|---|---|---|---|---|
| 1 | Property-level authorization / mass assignment | Authenticated JSON `PATCH` | AUTHENTICATED | Roles and server-managed properties | PANCITO covered object authorization and public mutation, but had no actor × property negative cell | `offensive/bola.py`, `offensive/state_change.py` at `128bde8` | A working allowed-field control followed by protected-field read-back remaining at baseline | CANDIDATE |
| 2 | Stale authority after role revocation | Authenticated request with an already-issued token | AUTHENTICATED | Revoked privileges and tenant data | No current capability models a transition from valid authority to revoked authority | Current `offensive/` capability catalogue | Both session and token lose access within the declared invalidation contract | CANDIDATE |
| 3 | Nested-resource authorization mismatch | `/parents/{p}/children/{c}` | AUTHENTICATED | Cross-tenant child resources | Current BOLA differential tests one object identity, not parent/child binding | `offensive/bola.py` | Swapping only the child identifier is denied and returns no foreign canary | CANDIDATE |

## Below the line (enumerated, deprioritized)

- SSRF → high potential asset value, but deliberately below the line because the
  current active-target boundary forbids arbitrary destinations and no safe,
  closed loopback oracle has been specified.
- Injection payload execution → excluded from the current catalogue because a
  free-form payload surface would violate the closed-capability invariant.

## Refuted during triage

None. This artifact ranks capability gaps; it does not assert a target finding.

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
