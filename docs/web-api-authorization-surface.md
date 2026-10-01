# Web/API authorization surface

This matrix records the authorization cells implemented by PANCITO experiments.
It describes test capability, not the security state of an untested target.

Actors: anonymous, invalid credential, authenticated owner, authenticated peer,
authenticated member, administrator, low-privilege actor, privileged observer.

Resources: protected route, owned object, peer object, parent-scoped child,
allowed property, protected property, member function, administrative function.

Actions: read and update. List, search, export, share, transfer, invite, revoke,
restore, stale-session use, and scoped-token enforcement are not yet covered.

## Matrix

| Actor | Resource | Action | Expected | Experiment evidence |
|---|---|---|---|---|
| Anonymous / invalid credential | Protected route | Read | Denied | Authentication differential; valid-credential control plus protected canary oracle |
| Authenticated peer | Owner object | Read | Denied | BOLA differential; owner/peer controls plus credential-only replay |
| Authenticated owner | Peer child under owner parent | Read | Denied | Nested-BOLA differential; child identifier is the only changed request dimension |
| Administrator | Administrative function | Read | Allowed | Function-authorization admin control with an admin-only canary |
| Authenticated member | Member function | Read | Allowed | Function-authorization member control with a member-only canary |
| Authenticated member | Administrative function | Read | Denied | Function-authorization negative cell; only the credential changes from the admin control |
| Anonymous / invalid credential | Publicly reachable mutable resource | Update | Denied | State-change differential with authenticated read-back and restoration |
| Low-privilege actor | Own allowed property | Update | Allowed | Mass-assignment positive control |
| Low-privilege actor | Own protected property | Update | Denied | Mass-assignment negative cell with observer read-back |
| Pre-issued actor credential | Role-protected resource after revocation | Read | Denied | Stale-authority transition with revoke read-back and compensating restoration |

Cells not tested remain unknown. In particular, the matrix does not cover
multi-node revocation propagation, same-tenant role changes, child writes, inference from
error differences, browser-only controls, asynchronous jobs, GraphQL, or remote
production targets.

## Findings

None. An experiment receipt can confirm or falsify one authorized target cell;
this capability matrix does not promote implementation coverage into a finding.

## Structural remediation order

1. Bind object and child ownership in the data query or row policy.
2. Use deny-by-default policy middleware with explicit route and function declarations.
3. Generate negative tests from this matrix for every new actor/resource/action
   cell.

## Blue requirement

Log the authenticated subject and resolved role, route parent, selected child,
resolved child parent or tenant, function identifier, authorization decision,
and status. Alert when a granted child read crosses its ownership binding or a
non-admin role reaches an administrative function. The public PANCITO exercise
marker is correlation metadata, not the detection itself.
