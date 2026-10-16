# Upstream research notes

Studied on 2026-10-01. Commit hashes pin the exact source reviewed. PANCITO
uses the architectural ideas listed here; no source files from these projects
were copied into this repository.

## Agent evaluation and technique reference (MIT)

Reviewed on 2026-10-10 from shallow local clones. Exact commits pin the trees
examined. Both repositories contain MIT license files at those commits.

| Project | Reviewed commit | Pattern examined | PANCITO curation |
|---|---|---|---|
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | Benchmark separates task utility from security under prompt injection; task-specific state predicates determine outcomes | `offensive/agent_evaluation.py` implements a fixed recorded-trace corpus with separate utility/security states, isolated attack cases, and a benign quoted-injection twin. Schema v2 checks a typed final claim against the latest sealed state; v1 remains readable with an inconclusive claim assessment. Trace completeness and origin remain unverified. No agent, model, or tool executes. |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` | Atomic metadata associates ATT&CK technique IDs and tests; the reviewed technique YAML also contains executable commands and cleanup steps | `offensive/replay.py` records only technique IDs T1055.012 and T1070.006 as references for PANCITO's independently authored synthetic telemetry. No Atomic YAML, code, tests, fixture data, commands, or cleanup steps were copied or executed. |

The evaluator is exposed as `pancito-agent-evaluate` and consumes a bounded
local JSON trace. A SHA-256 digest identifies the supplied bytes but does not
authenticate them or establish that the trace is complete. The evaluation
receipt has no authority over PANCITO's sealed forensic verdict. See
[`docs/agent-evaluation.md`](docs/agent-evaluation.md) for the input contract.

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

## Offensive framework survey

Studied on 2026-10-15 from shallow local clones under `scratch/upstream-repos/`
(not committed; `scratch/` is gitignored). Commit hashes pin the exact trees
reviewed; license strings were read from each clone's `LICENSE*` file at that
commit, not from repository metadata — see the Security-Datasets row for why
that distinction matters. Same rule as the earlier passes: **ideas and
structure only — no source files, templates, rules, payloads, or datasets were
copied into this repository.**

This pass covers offensive-execution frameworks and technique catalogs not
previously reviewed (Atomic Red Team, CALDERA, AgentDojo, and the LLM/MCP
evaluation tooling were assessed in the sections above).

| Project | Reviewed commit | License observed | Useful pattern | PANCITO application |
|---|---|---|---|---|
| [Stratus Red Team](https://github.com/DataDog/stratus-red-team) | `592c425f1707d11dfda8cf16fe7027f159dfa172` | Apache-2.0 | Each technique is a registry entry carrying a stable dotted ID, platform, ATT&CK tactics, a `Detection` guidance block, `Detonate`/`Revert` functions, an `IsIdempotent` flag, and Terraform prerequisites; a `COLD → WARM → DETONATED` state machine governs the lifecycle, and every detonation stamps a `stratus-red-team_<uuid>` correlation ID into the HTTP user-agent | Strongest structural match found this pass: a closed registry of named, bounded techniques with paired warm-up/revert semantics and a correlation marker — the same contract shape as `offensive/` + `PANCITO-<hex16>` markers. Adaptable ideas: (a) an explicit scenario state field (declared/detonated/reverted) if active adapters ever arrive, (b) a `detection:` guidance text per catalog entry alongside `expected_techniques`, (c) `is_idempotent` metadata declaring whether a scenario may repeat without a revert. No Go code, Terraform, or live-cloud detonation adopted — PANCITO's boundary stays replay fixtures and bounded loopback differentials |
| [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) | `8af478bb9e4637df568ac1e596553b025b16cd1b` | MIT | Execution lifecycle split into `prereq check → execute → cleanup` with the cleanup command a first-class schema field; the test runs in its own process specifically so cleanup still runs if a defensive control kills the test process; pluggable `ExecutionLogger` backends (file, syslog, Windows event) record each run as a separate artifact | Two patterns worth keeping: (a) *cleanup outlives the test* — if PANCITO ever gains active experiments, the revert step must be scheduled independently of the test process, not as a finally-block; (b) *the run log is a separate evidence channel* — already realized here as the sealed receipt, so this validates rather than extends the design. No PowerShell or scheduler machinery applies |
| [Splunk Attack Range](https://github.com/splunk/attack_range) | `fc9b9e719d8835da0bbb5c20d46c52a9778d64e2` | Apache-2.0 | `simulate` accepts only an explicit list of ATT&CK technique IDs or `(technique, guid)` atomic selections — the operator names items from a closed catalog and cannot supply arbitrary behavior; simulated telemetry is forwarded into the analytic platform, and `attack_data/` supports replaying recorded data instead of re-attacking | Validates the engagement-manifest design: `allowed_scenarios` selecting from a fixed catalog by ID is exactly how Attack Range scopes detonation. Its replay of recorded telemetry into the detection stack is the role `offensive/replay.py` already fills locally. Cloud provisioning, Splunk forwarding, and the service's own attack execution remain outside the boundary |
| [Security-Datasets (Mordor)](https://github.com/OTRF/Security-Datasets) | `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` | MIT at the reviewed commit — but note the README footer still claims GPL-3.0; the `LICENSE` file (copyright 2021, OTR Forge) governs. Verify the file, not the label | Per-dataset `_metadata/SD*.yaml` records `attack_mappings` (technique + sub-technique + tactics), typed artifact links (`files:` host/network), and a `simulation:` provenance block naming the environment, the tool that produced the data (e.g. Empire module), and `permissions_required` — hostile telemetry with its generation method written down | Extends `replay.py`'s `technique_reference` field: a future fixture schema could carry a `simulation` provenance block (generator tool, environment, required permissions) plus a paired benign twin. Datasets themselves are large zipped captures hosted by URL — reference by URL + pinned hash if ever consumed; never vendor them, and note that any real capture embeds infrastructure-specific noise a synthetic fixture deliberately avoids |
| [Adversary Emulation Library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library) | `4467a6eed6e67d25009704130e1d27d1a8007f57` | Apache-2.0 | `format_dictionary.yaml` defines a scenario → step → sub-step/procedure structure; every procedure carries an ATT&CK ID, named executors, `input_arguments`, `dependencies` (prereq + get_prereq), and — distinctively — a `cti_source` field grounding each TTP in a cited threat-intelligence report; plans support loops and alternative phases | Two ideas: (a) `cti_source`-style provenance — grounding a PANCITO scenario in a documented report rather than bare technique IDs strengthens the Daubert posture; (b) the step/phase composition format is the reference shape *if* multi-step scenario chaining is ever wanted — currently deferred, since composed state expands the oracle surface. The repo ships ~1.3 GB of real adversary binaries/payloads; none of that material is relevant or adoptable |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | `3de629d823bb6eb00aa3769edc365b6525134fb1` | MIT | Fully declarative YAML: `id`, `info` (severity, references, `metadata.verified`, `metadata.max-request`), then a protocol block with fixed `method`/`path` and a `matchers` set (word / status / content_type / regex, with AND/OR conditions); each template ends with a signed `digest` line so tampered templates are detectable | Confirms the bounded-differential shape: request shape + deterministic matchers ≈ PANCITO's Python differentials. Adoptable concepts: (a) declare the request bound in metadata (`max-request` ≈ the existing bounded-count convention, made explicit); (b) a `verified` flag distinguishing reviewed templates; (c) a digest over the catalog entry definition itself — PANCITO already hash-pins agent manifests in `agent/registry.py`, and sealing scenario definitions the same way is a natural extension. Not adopted: the free-form `{{BaseURL}}` target surface — loopback/literal-target restriction stands |
| [Tsunami Security Scanner](https://github.com/google/tsunami-security-scanner) | `5dd969255145c0c237f8f57974c6519b49415046` | Apache-2.0 | Detection outcomes are a three-state enum: `SAFE`, `VULNERABILITY_PRESENT` (evidence suggests it but verification did not complete), `VULNERABILITY_VERIFIED` (the detector confirmed it) — the "present but unverified" middle state is a first-class result, not an error | Validates honest degradation: PANCITO's oracle already splits `CONTROL_GAP` / `INTEGRITY_FAILURE` / `EXECUTION_FAILED` on the same principle — a not-fully-verified result gets its own named state rather than folding into pass or fail. The plugin-service boundary (detectors as isolated processes behind a proto contract) is a reference shape only; PANCITO's modules stay in-process and stdlib-only |
| [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) | `9b52b40bb1d4deec9827b94a20d07e071b962ee7` | MIT | Hunt notebooks are structured Hypothesis → Technical Context → Offensive Tradecraft → Pre-Recorded Security Datasets: the detection hypothesis is written *before* the query, and every hunt cross-links the ATT&CK-mapped datasets that exercise it | Documentation pattern for detection expectations: each PANCITO scenario could carry a hypothesis-first description ("what should the blue side see") linking the fixture that exercises it — the same framing as the purple-team "expected telemetry is a hypothesis, not a fact" discipline. No notebook machinery adopted |

### Excluded after license or boundary review (not cloned)

| Project | License observed | Reason excluded |
|---|---|---|
| [Sliver](https://github.com/BishopFox/sliver) | GPL-3.0 (repo metadata) | Copyleft, incompatible with the reuse policy that already excluded Corsy and jwt_tool; also a free-form C2 — model-/operator-authored execution is exactly what the bounded catalog forbids |
| [Infection Monkey](https://github.com/guardicore/monkey) | GPL-3.0 (repo metadata) | Copyleft; autonomous propagation model is the opposite of an explicit per-engagement authorization grant |
| [Empire](https://github.com/EmpireProject/Empire) | BSD-3-Clause (repo metadata); upstream archived since 2020 (moved to BC-SECURITY) | C2/post-exploitation framework — outside the bounded-catalog invariant regardless of license |
| [Mythic](https://github.com/its-a-feature/Mythic) | No SPDX assertion (repo metadata) | License undetermined *and* a C2 framework — both gates fail |
| [elastic/detection-rules](https://github.com/elastic/detection-rules) | No SPDX assertion (Elastic/AGPL mix) | Non-standard license; also blue-side rule content — Sigma was already flagged for per-rule license review in the earlier pass. `elastic/RTA` (red team automation scripts) no longer exists as a standalone repo; its content was absorbed into this one |

### What this pass changes

Nothing yet — this section records adaptation *candidates*, each bounded:

1. **Scenario provenance block.** Extend the replay catalog's `technique_reference`
   toward the Security-Datasets `simulation:` shape (generator tool, environment,
   permissions required) plus an optional `cti_source` — all descriptive fields,
   none of which affects a sealed value.
2. **Sealed catalog definitions.** Apply the registry's existing manifest-hash
   pattern to `offensive/` scenario definitions so a catalog entry's identity is
   pinned the same way an agent's tool contract is (nuclei's template `digest`
   is the same idea, weaker — it authenticates the publisher, PANCITO only needs
   integrity).
3. **Detection-guidance text per scenario.** Stratus's `Detection` block and the
   playbook's hypothesis-first format both argue for storing expected-telemetry
   prose with each scenario — documentation only, read by the operator and the
   narrator, never by the oracle.
4. **Lifecycle vocabulary.** If active (non-replay) experiments are ever
   authorized, adopt the warmup → detonate → revert → cleanup state machine with
   cleanup survivable independent of the test process (Stratus + Invoke-AtomicRedTeam).
   Until then this is documentation, not a plan.

### Deliberately deferred (this pass)

- Executing any upstream technique, atomic, template, or emulation plan —
  everything reviewed stays reference material; PANCITO executes only its own
  bounded modules on authorized loopback targets.
- Multi-step scenario composition (the emulation-library step/phase format).
- Vendoring any dataset, template, rule, or payload.
- The cloud-provider detonation surfaces (Stratus/AWS/Azure/GCP/K8s) — PANCITO
  has no authorized cloud target.
