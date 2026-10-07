# Attributions

PANCITO-RED-TEAM builds on pre-existing and third-party work. This file records
what was incorporated, which terms apply, and where original PANCITO work
begins. The deterministic forensic core and much of the connected service are
inherited from VIGÍA/annaconda; the bounded offensive-validation layer is
specific to PANCITO.

## Repository licensing scope

Original PANCITO-RED-TEAM work is offered under PolyForm Strict 1.0.0. That
license does not replace or narrow rights already granted for inherited and
third-party material. The VIGÍA/annaconda portions identified below retain
their [Apache-2.0 terms](LICENSES/Apache-2.0.txt), Camel-derived material
retains its [MIT terms](LICENSES/Camel-MIT.txt), and Velociraptor remains a
separate AGPLv3 program. See each upstream project for additional notices.

---

## Prior work — the deterministic core (Apache-2.0)

### VIGÍA
<https://github.com/annatchijova/vigia-intent-analysis>

A deterministic forensic-intent engine (Peircean semiotics, Daubert-oriented),
developed before PANCITO. PANCITO uses it as its sealed decision core.
Incorporated subsystems:

- The deterministic scorer (`vigia_scorer.py`) and its dependency closure:
  canonical serialization (`core/canonicalize.py`), evidence aggregation, the
  decision/risk-bounded layers, likelihood/calibration, bundle sealing, graph
  stability.
- **CAIE — the Cross-Artifact Incongruence Engine (`tools/caie.py`)**: the
  cross-artifact fracture detectors (temporal-causality, process-injection,
  log-vs-memory, etc.) that produce PANCITO's sealed replay verdicts,
  and the MITRE ATT&CK mapping (`tools/mitre_mapping.py`).
- The 8-state quadripartite verdict (`verdict/quadripartite.py`).
- The SIFT analyzer suite (`sift/`): the forensic parsers and timeline
  engine PANCITO's offensive forensic-evasion experiments exercise. The
  standalone VIGÍA CLI (`vigia_agent.py`), its SIFT orchestrator and
  compatibility shim, the abductive reasoner (`inference/`), and the
  platform analyzers only that CLI reached were retired as unused by the
  PANCITO surface; see git history (and the cleanup report) for the removed
  set.
- The security / Model Armor layer (`security/`): LLMShield (prompt-injection
  firewall), sandboxed subprocess execution, path/output boundary validation.
- The LLM hallucination guard (`core/hallucination_guard.py`) — narrative
  claims mechanically verified against the sealed motor output.

This remains the majority of the repository and is disclosed so the provenance
line is explicit. Other prior projects (CRONOS, MNEME, raven-memory, MUTANTE)
are not included and are not imported by any module here.

### Protocol Kassandra — VIGÍA lineage (Apache-2.0)

`agent/kassandra.py` is a PANCITO-RED-TEAM adaptation of the semantic-tripwire design
from the author's VIGÍA repository. The adaptation deliberately changes the
contract: Kassandra reports only evidence-to-LLM channel integrity and cannot
produce a forensic verdict. It also uses domain-separated HMAC derivations,
content-bound heartbeat state, exact external response verification, and a
separate HMAC event chain.

---

## Connected annaconda layer retained during migration

These components connect the deterministic core to the inherited agentic and
service surfaces. They remain connected and tested, but are not evidence that
PANCITO has a production deployment:

- **Two Google ADK + Gemini agents** (`agent/`): the investigator that drives
  the hunt loop (`purple_team_agent.py`, `tools.py`) and the mentor for junior
  examiners (`consult_agent.py`, `consult_tools.py`). Neither can alter a
  sealed verdict.
- **The Velociraptor adapter** (`tools/velociraptor/`): curated VQL templates,
  Mock/Rest/Query transports, and sealed evidence windows.
- **The hash-chained sealed verdict stream** (`core/verdict_stream.py`) — the
  tamper-evident chain that makes a case one continuing record.
- **The Cloud Run service** (`service/`): FastAPI backend, the Firestore-backed
  case store (`case_store.py`), the analyst console and court-exhibit UI, the
  prompt-injection validation, and the autonomous sweep
  (Cloud Scheduler → Pub/Sub → `/tasks/sweep`).
- **The ML triage nominator** (`ml/nominator.py`) — see the Camel attribution
  below.
- The ABSTAIN-as-memory / autonomous-reentry logic, and the determinism and
  contract test suites (`tests/`).

---

## Third-party open source

### Velociraptor — AGPLv3
<https://github.com/Velocidex/velociraptor>

DFIR endpoint platform (VQL hunts). Used as an **independent service reached
over its own API / binary** — never modified, embedded, or forked — so its
AGPLv3 copyleft does not extend to annaconda's Apache-2.0 code. The official
signed release binary is fetched and GPG-verified by
`scripts/setup_velociraptor.sh`.

### Camel — MIT
<https://github.com/allisterb/Camel>

`ml/nominator.py` is a stdlib-Python port of Camel's label-free surprisal
ensemble (C#, MIT, © 2026 Allister Beharry), adapted to endpoint telemetry
(rare-path, rare-destination, content-entropy detectors retained; the name/type
detectors dropped as noise for this data). The nominator **nominates only** — it
never produces a sealed value.

### Strix — architectural reference only (Apache-2.0)

<https://github.com/usestrix/strix>

PANCITO-RED-TEAM borrows the product discipline of validating security findings with
reproducible evidence and using a bounded catalogue of capabilities. No Strix
source code is copied or imported. PANCITO-RED-TEAM does not inherit Strix's general
shell, browser, exploit, or post-exploitation surface; its current offensive
executor is replay-only and Blue-directed.

### Offensive-agent architecture study

PANCITO-RED-TEAM also studied AgentSploit, BreachPilot, Scarlight, and
RedTeamAgent for authorization, scope, evidence, capability, and lifecycle
patterns. Exact repositories, reviewed commits, observed licenses, adopted
ideas, and limitations are recorded in
[`UPSTREAM_RESEARCH.md`](UPSTREAM_RESEARCH.md). The implementation is original
to this repository; no upstream source files were copied. RedTeamAgent had no
license file in the reviewed tree and is treated as an architectural reference
only.

### Vulnerability-class research — CORS, GraphQL, SSRF (MIT / BSD-3-Clause)

New offensive differentials are scoped from MIT- or BSD-3-Clause-licensed
security tools, never from copyleft sources. `offensive/cors_misconfiguration.py`
reimplements, in PANCITO's own bounded Red/Blue style, the arbitrary-origin
reflection bug class that chenjj/CORScanner (MIT) tests for; `offensive/
graphql_introspection.py` and `offensive/graphql_field_suggestion.py` do the
same for two of dolevf/graphql-cop's (MIT) checks — schema introspection left
enabled, and field-name suggestions in validation errors. No source was
copied from any of them. Reviewed commits, licenses, and which ideas are
implemented versus still queued (graphql-cop's batching/depth checks,
graphw00f, SSRFmap) are recorded in
[`UPSTREAM_RESEARCH.md`](UPSTREAM_RESEARCH.md#vulnerability-class-idea-sources-mit--bsd-3-clause-only).

---

## Models

Gemini can narrate and drive the inherited agent layer; Gemma
(`gemma-4-26b-a4b-it`, via the Gemini Developer API) is the baseline narrator in
the prompt-injection validation. No model is in the decision path: the verdict
is sealed by the deterministic core before any model runs.
