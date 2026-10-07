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
| [graphql-cop](https://github.com/dolevf/graphql-cop) | `2b7e086efae672f28b419c7fcdfe6b48d846c9dc` | MIT | GraphQL introspection left enabled, field-suggestion schema leakage, batching/query-depth with no cost limit | Evaluated, not yet implemented. Narrower applicability than CORS (only targets exposing a GraphQL endpoint) |
| [graphw00f](https://github.com/dolevf/graphw00f) | `4901f824140a2da168876412593c213afbdd75fb` | BSD-3-Clause | Fingerprinting which GraphQL engine is running from error-message and behavioral differentials | Evaluated as a companion to graphql-cop for a future GraphQL module; not yet implemented |
| [SSRFmap](https://github.com/swisskyrepo/SSRFmap) | `290e07d75c52d68e021b6d0b4200c2a41ea20365` | MIT | Server-side outbound fetch reaches an attacker-controlled destination (cloud metadata, internal services) via an unvalidated URL parameter | Evaluated, not yet implemented. Needs a self-hosted canary receiver (same pattern as the forwarded-redirect lab) and more careful bounding before it is safe to ship |

Excluded from this list after review: Corsy (CORS scanner, GPL-3.0) and
jwt_tool (JWT testing, GPL-3.0) — same bug classes, incompatible license.

## Deliberately deferred

- General shell, browser, payload, exploit, arbitrary URL, and post-exploitation
  surfaces.
- Network targets and wildcard scope matching.
- A container sandbox. Active HTTP experiments remain restricted to literal
  loopback targets, fixed request shapes, bounded counts, and no redirects.
- Model-authored authorization, evidence assessment, scores, verdicts, or hashes.
