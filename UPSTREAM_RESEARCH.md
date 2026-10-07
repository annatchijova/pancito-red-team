# Upstream research notes

Studied on 2026-10-01. Commit hashes pin the exact source reviewed. PANCITO
uses the architectural ideas listed here; no source files from these projects
were copied into this repository.

| Project | Reviewed commit | License observed | Useful pattern | PANCITO application |
|---|---|---|---|---|
| [AgentSploit](https://github.com/agentsploit/agentsploit) | `fc251ad4240a48ec443177d958543c1c01645c78` | Apache-2.0 plus NOTICE | File-backed authorization with a source digest; capability paths treated as hypotheses that require verification | Engagement artifacts now carry both byte-level and semantic SHA-256 identities. A future level can map PANCITO's closed capabilities without granting execution authority. |
| [BreachPilot](https://github.com/braydos-h/BreachPilot) | `802566699062ed2d801aa2bf4a9bb0c0b209d946` | Apache-2.0 | Scope checks before execution; execution outcome separated from evidential outcome; fail-closed sandbox boundary | The first implementation separates successful replay from the deterministic Blue detection oracle and keeps out-of-catalogue actions closed. |
| [Scarlight](https://github.com/giannisp09/scarlight) | `bfb1db1c69e480dfa63013ac3e655b3ff80f0731` | Apache-2.0; NOTICE retains upstream hermes-agent MIT terms | Mandatory engagement scope, explicit operator acknowledgment, bounded retry guardrails | PANCITO now loads a strict engagement manifest and rejects ambiguity, unknown fields, duplicate keys, oversized files, and capabilities absent from its catalogue. Retry guardrails remain a later level when active adapters exist. |
| [RedTeamAgent](https://github.com/NeoTheCapt/RedteamAgent) | `2e604769e424762471daccb703f8513470f2f29c` | No license file observed | Explicit subagent lifecycle, durable case queue, terminal states, and resumable runs | Architectural reference only. No code or documentation was reused because the reviewed tree did not grant a license. |

## Implemented synthesis

### Engagement manifest

`offensive/engagement.py` parses a dependency-free JSON authorization artifact.
The parser has a 64 KiB limit, rejects duplicate and unknown keys, requires a
literal operator acknowledgment, and permits only scenario IDs already present
in `offensive.replay`'s curated catalogue. It produces:

- `source_sha256`: identity of the exact file bytes;
- `scope_sha256`: identity of canonicalized authorization semantics;
- an `AuthorizationGrant` that contains no command, verdict, score, confidence,
  or model-controlled field.

The two hashes answer different audit questions. The source hash detects any
file rewrite. The scope hash stays stable across harmless JSON whitespace and
key ordering changes. They identify the manifest; they do not authenticate who
approved it. Until a later level verifies a signature, `authorized_by` and
`authorization_reference` remain explicit operator assertions and the receipt
reports that limitation.

### Evidence oracle

`offensive/oracle.py` evaluates a replay only after the existing forensic core
has sealed the verdict and its custody chain has verified. Its states are:

- `DETECTED_AS_EXPECTED`: state and expected ATT&CK techniques are present;
- `CONTROL_GAP`: trusted evidence exists but an expectation is missing;
- `INTEGRITY_FAILURE`: the verdict is unsealed or custody does not verify;
- `EXECUTION_FAILED`: the replay did not complete.

This oracle is deterministic, stdlib-only, and outside the forensic verdict. It
records whether execution succeeded separately from what the evidence proved.

## Vulnerability-class idea sources (MIT / BSD-3-Clause only)

Studied on 2026-10-07 while scoping new bounded differentials for the offensive
catalogue. Same rule as above: ideas and bug classes only, no source copied.
Restricted to permissive licenses (MIT, BSD-3-Clause) that do not narrow
PANCITO's own PolyForm Strict terms — copyleft sources (GPL, AGPL) are excluded
from this list even when the technique is well known.

| Project | Reviewed commit | License observed | Bug class / idea | PANCITO application |
|---|---|---|---|---|
| [CORScanner](https://github.com/chenjj/CORScanner) | `593043f836a158246fc6a13a89a5a1401cbff0b5` | MIT | Server reflects an arbitrary request `Origin` into `Access-Control-Allow-Origin` instead of checking an allowlist, sometimes paired with `Access-Control-Allow-Credentials: true`; wildcard and null-origin variants | Implemented as `offensive/cors_misconfiguration.py` — a bounded two-request differential (no-Origin baseline, canary-Origin test) with an exact-origin-match oracle, never a substring check |
| [graphql-cop](https://github.com/dolevf/graphql-cop) | `2b7e086efae672f28b419c7fcdfe6b48d846c9dc` | MIT | GraphQL introspection left enabled, field-suggestion schema leakage, batching/query-depth with no cost limit | Introspection exposure: `offensive/graphql_introspection.py` (bounded `{__typename}` baseline, `{__schema{queryType{name}}}` test, read structurally). Field-suggestion leakage: `offensive/graphql_field_suggestion.py` (same baseline, then a deliberate one-character typo of `__typename` whose error response is checked for a "did you mean" suggestion naming the real field). Batching: `offensive/graphql_batching.py` — a JSON array of `batch_size` (capped 2-10) copies of the already-harmless `{__typename}` query, confirmed only if the response is itself an array of exactly that many well-formed results; makes no attempt to measure a rate-limit bypass or any downstream impact. Query-depth: evaluated, **not implemented — the planned technique was refuted before shipping.** The design used a chained `__Type.ofType` probe as a deliberately safe, linear-size alternative to nesting a list-returning field (which risks exponential blowup since the target's schema fan-out is unknown and uncontrolled). But `ofType` is non-null only for the `LIST`/`NON_NULL` wrapper kinds per the GraphQL spec — `queryType` itself is always a plain `OBJECT` type, so the chain resolves to `null` at the very first hop regardless of whether the server enforces a depth limit. The technique would read as `FALSIFIED` (limit enforced) on every target, permissive or not — a guaranteed false negative, not an occasional one. The only field that actually nests arbitrarily (`fields`) is list-shaped and reintroduces the exponential risk the `ofType` approach was chosen to avoid. No safe, schema-independent, bounded depth probe was found; revisit only with a different technique, not a smaller depth on the same one |
| [graphw00f](https://github.com/dolevf/graphw00f) | `4901f824140a2da168876412593c213afbdd75fb` | BSD-3-Clause | Fingerprinting which GraphQL engine is running (Apollo, Hasura, Graphene, ~20 others) from an empirical per-engine table of malformed queries and their distinct error signatures | Deferred, not merely queued: this isn't a security differential (no benign-vs-vulnerable control pair, no violated invariant) and isn't a compact idea either -- the signal *is* the empirical per-engine table, so "reimplementing the idea" would mean porting the table itself. Revisit in a few weeks/months if a concrete PANCITO use for engine identification emerges; nothing to build here today |
| [SSRFmap](https://github.com/swisskyrepo/SSRFmap) | `290e07d75c52d68e021b6d0b4200c2a41ea20365` | MIT | Server-side outbound fetch reaches an attacker-controlled destination (cloud metadata, internal services) via an unvalidated URL parameter | Only the detection premise is implemented, as `offensive/ssrf_outbound_fetch.py` — SSRFmap's exploitation modules (cloud metadata, Redis, etc.) are out of scope entirely. A no-parameter baseline precedes one test naming a canary URL; the oracle is a second, independent witness: a loopback, ephemeral-port HTTP receiver PANCITO itself starts and tears down for the one experiment, polled once for an exact marker path after a bounded grace window — never a response-body check, since a vulnerable server can return 200 regardless of whether the outbound fetch happened |

Excluded from this list after review: Corsy (CORS scanner, GPL-3.0) and
jwt_tool (JWT testing, GPL-3.0) — same bug classes, incompatible license.

## Deliberately deferred

- General shell, browser, payload, exploit, arbitrary URL, and post-exploitation
  surfaces.
- Network targets and wildcard scope matching.
- A container sandbox. Active HTTP experiments remain restricted to literal
  loopback targets, fixed request shapes, bounded counts, and no redirects.
- Model-authored authorization, evidence assessment, scores, verdicts, or hashes.
