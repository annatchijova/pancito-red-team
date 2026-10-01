[English overview](README.md) · [Resumen en español](README_ES.md) · [Technical README](TECHNICAL_README.md) · [Interactive architecture](docs/pancito-architecture.html)

# PANCITO-RED-TEAM technical reference

This document is the audit and extension surface for PANCITO. It describes the
current implementation, not a future autonomous-pentest claim.

## System boundary and status

PANCITO combines a new bounded offensive layer with inherited VIGÍA DFIR,
custody, agent, and service modules. The supported offensive product surface is:

1. deterministic replay of committed hostile telemetry;
2. passive local OpenAPI triage and provenance-preserving handoff;
3. four curated HTTP differentials restricted to literal loopback origins;
4. four offline SIFT differentials over module-owned synthetic data;
5. deterministic Purple evaluation of operator-supplied Blue evidence; and
6. optional model narration after consequential values already exist.

The inherited web service is retained and tested, but its investigation
transport is fixture-backed replay. There is no approved PANCITO production
deployment runbook and no claim of general autonomous exploitation.

## Architecture

Open the [interactive architecture](docs/pancito-architecture.html) to inspect
the main path, Blue-validation path, model boundary, and source links. The
[Archify specification](docs/pancito-architecture.architecture.json) pins the
repository revision and 15 code references; the
[visual-check receipt](docs/pancito-architecture.visual-check.json) records the
delivered artifact digest and containment measurements.

```text
operator authorization
  -> strict manifest
  -> closed capability boundary
  -> bounded executor
  -> deterministic decision / evidence code
  -> receipt

Blue evidence -> Purple evaluator ---------------------> receipt
receipt -> Kassandra-protected context -> optional LLM narration
```

There is intentionally no arrow from the model to adjudication, scoring,
canonicalization, custody, or sealing.

## Load-bearing invariants

### The model is outside the verdict

The deterministic core scores and seals before any narration turn. Agent tools
cannot supply or suppress a score, state, technique mapping, or hash. Provider
selection in [agent/model_provider.py](agent/model_provider.py) only affects
unsealed agent and consultation paths.

### Sealed values are deterministic

The sealed core is stdlib-only and uses integers or `fractions.Fraction`, not
floating-point arithmetic. Canonical representations and SHA-256 seals must be
byte-identical across fresh processes. [tests/test_determinism.py](tests/test_determinism.py)
is the load-bearing regression test.

### Sealed state is chained and reverified

Verdicts and mission memory append to hash chains. Reads verify continuity;
bounded chain segments prevent an attacker from making silent truncation look
like retention policy. Relevant implementations include
[core/verdict_stream.py](core/verdict_stream.py),
[core/chain_of_custody.py](core/chain_of_custody.py), and
[service/chain_store.py](service/chain_store.py).

### Degradation is observable

Missing evidence does not become BENIGN. Collection failure remains unobserved;
partial evidence can produce `ABSTAIN`; active experiments use `INCONCLUSIVE`
and require manual action when state cannot be verified or restored. Service
backend degradation is exposed through `/health`.

## Trust boundaries

| Boundary | Trusted for | Not trusted for |
|---|---|---|
| Operator manifest | Declaring requested scope and budget | Authenticating the named authorizer; current authorization identity is an explicit assertion |
| Passive OpenAPI artifact | Describing candidate routes present in those bytes | Proving a route is deployed, reachable, vulnerable, or valuable |
| Active HTTP response | Status, bounded metadata, and exact canary observations collected by the client | Security impact without the experiment-specific oracle and human context |
| Blue observation | Operator-supplied telemetry/alert statement | Rewriting the Red result or establishing global detection coverage |
| Protocol Kassandra | Detecting semantic-channel integrity anomalies under its threat model | Proving attacker presence or deciding MALICE/BENIGN |
| LLM output | Investigation choice and natural-language explanation | Verdict, score, confidence, mapping, digest, authorization, or seal |

## Offensive capability contracts

| Module | Requests / execution | Positive control | Negative cell | Cleanup / terminal evidence |
|---|---:|---|---|---|
| [offensive/replay.py](offensive/replay.py) | Fixed local fixture hunts within `max_runs` | Sealed pipeline completes and custody verifies | Curated hostile scenario | Detection oracle records expected state and techniques separately from execution |
| [offensive/bola.py](offensive/bola.py) | 3 GETs | Owner and peer reads establish object/canary behavior | Cross-principal object read | No response body retained; result is induction-scoped |
| [offensive/nested_bola.py](offensive/nested_bola.py) | 3 GETs | Owner-child and peer-child reads establish both canaries | Owner credential keeps its parent and substitutes only the peer child ID | Foreign-child canary is required; bodies are discarded and only bounded hashes/booleans remain |
| [offensive/authn.py](offensive/authn.py) | 3 GETs | Valid credential returns the protected canary | Anonymous and invalid bearer | A status alone cannot confirm protected-data exposure |
| [offensive/state_change.py](offensive/state_change.py) | At most 13 bounded requests | Baseline plus valid PATCH/read-back | Anonymous and invalid-bearer PATCH | Restore and authenticated restore verification after each observed mutation |
| [offensive/mass_assignment.py](offensive/mass_assignment.py) | At most 9 bounded requests | Low-privilege actor changes one allowed field | The same actor submits one allowed and one protected field | Separate observer reads both fields, restores both, and verifies the baseline |
| [offensive/stale_authority.py](offensive/stale_authority.py) | At most 7 bounded requests | Active membership and same-token protected read | Admin revokes membership, verifies it, then replays the pre-issued token | Compensating role restore plus authenticated state verification gates any conclusion |
| [offensive/file_ingress.py](offensive/file_ingress.py) | At most 12 bounded requests | Valid inert text stores exactly | Declared PNG mismatch and `limit + 1` bytes | DELETE plus authenticated 404/410 verification for every returned ID |
| [offensive/forensic_evasion.py](offensive/forensic_evasion.py) | Exactly 3 offline cells, zero requests | Coherent NTFS timestamps plus benign event sequence | `$SI`/`$FN` mismatch and logon→audit-log-clear chain | Exact ground truth is compared with targeted SIFT observations; receipt is explicitly unsealed |
| [offensive/prefetch_evasion.py](offensive/prefetch_evasion.py) | Exactly 3 offline cells, zero requests | Ten inert SCCA-signature files | Suspicious executable name and reduced Prefetch set | Module-owned temporary directory is deleted automatically; no path is retained |
| [offensive/registry_evasion.py](offensive/registry_evasion.py) | Exactly 3 offline cells, zero processes | Benign Run-key text and unique timestamps | Suspicious Run-key text and ten-key timestamp collision | Exercises parser-level detectors only; no hive or RegRipper execution |
| [offensive/timeline_evasion.py](offensive/timeline_evasion.py) | Exactly 3 offline cells, zero requests | Shared-entity causal inversion and Memory-only gap | Production-shaped Memory/MFT summary pair | Current result is `FALSIFIED`: producer summaries lose shared identity; sealed-verdict impact remains untested |

All active HTTP capabilities reject remote hosts, HTTPS, user information,
redirect following, arbitrary commands, and arbitrary sample files. Secrets are
resolved from named environment variables and are omitted from receipts.

### SIFT forensic-evasion differential

The forensic-evasion capability treats inherited SIFT code as a Blue sensor
under test, never as a source of truth. PANCITO constructs all bytes internally:
a minimal inert NTFS `FILE` record and canonical event facts. No manifest field
can name a target, file, payload, command, or network destination.

```text
fixed ground truth ───────────────┐
                                 ├─ exact comparison ─> unsealed receipt
synthetic MFT/events -> SIFT ─────┘
```

The fixed matrix contains `CONTROL`, `TIMESTOMP`, and `LOG_WIPE`. The MFT cell
passes through both `sift.mft_parser.parse_mft_bytes` and
`sift.disk_forensics.MFTTimelineAnalyzer`; the event cell passes through
`sift.event_log_correlator.AttackChainDetector`. Only the two declared semantic
signals are compared. A sensor exception, dirty control, or unexpected signal
is `INCONCLUSIVE`; a clean control with a missed mutation is `FALSIFIED`.
Detection of both mutations is `CONFIRMED_BY_INDUCTION`, scoped only to these
fixtures and versions.

SIFT's internal floating-point timestamp conversion remains outside the sealed
core. The capability never calls its float-producing `to_signal()` methods,
does not seal its receipt, and states `part_of_forensic_verdict: false`.

### Prefetch and Registry pair

[offensive/windows_artifact_cli.py](offensive/windows_artifact_cli.py)
coordinates two independently classified modules from one authorization
manifest:

```text
                         ┌─> PrefetchAnalyzer ─> exact expected signals ─┐
strict authorization ────┤                                               ├─> unsealed suite receipt
                         └─> Registry detectors -> exact expected signals ┘
```

The Prefetch module creates only minimal signature-valid inert files in a
private temporary directory and removes the directory before returning. The
Registry module invokes `PersistenceDetector` and `TimestompDetector` directly
over fixed text and exact `RegistryKey` facts. It never opens a hive and never
constructs `RegRipperInterface`, so this surface cannot launch a process.

Each module owns its ground truth, clean control, two negative cells, hashes,
and epistemic result. The suite reports `INCONCLUSIVE` if either sensor fails,
`FALSIFIED` if, with clean controls, either negative cell misses its mutation, and
`CONFIRMED_BY_INDUCTION` only when both narrow predictions survive. None of
these states is a forensic verdict.

### Timeline composition audit

The timeline experiment moves from isolated sensor behavior to a composition
contract. A hand-shaped Memory/MFT pair proves that the causal-inversion rule
works, and a Memory-only control proves the gap rule works. The production cell
then passes the same conceptual process through the real
`MemoryAnalysisResult.to_signal()` and `MFTAnalysisResult.to_signal()`
contracts.

On base commit `209db4d`, the production pair becomes two unrelated tool-level
entities with zero timestamps. `CAUSAL_INVERSION` is missed and a contradictory
`MEMORY_WITHOUT_DISK` gap is emitted despite an MFT signal being present. The
result is deliberately `FALSIFIED`, not normalized into a successful suite.
See the [reproducible audit note](docs/timeline-composition-audit.md).

## Passive triage and handoff

[offensive/openapi_surface.py](offensive/openapi_surface.py) reads a bounded
local OpenAPI JSON document and emits ranked review candidates with source
provenance and explicit coverage gaps. It performs no network request.

[offensive/handoff.py](offensive/handoff.py) can select BOLA, authentication,
public-state-change, or file-ingress candidates. Selection preserves
`CANDIDATE` and `UNSEALED_TRIAGE_HANDOFF`; priority never becomes a finding and
the concrete active path must match the selected template.

## Purple evaluation

[offensive/purple.py](offensive/purple.py) evaluates prevention and detection
as independent dimensions. It requires the Blue observation marker and steps
to match the exact Red receipt. Behavior-based alerts can earn detection for
that exercise; an alert that depends only on the public exercise marker is
reported as marker-only.

The Purple CLI hashes the exact Red and Blue source artifacts. Its output is an
`UNSEALED_DETERMINISTIC_DERIVATION`, not a forensic seal and not a claim of
coverage beyond the executed experiment.

## Protocol Kassandra

[agent/kassandra.py](agent/kassandra.py) protects the evidence-to-model channel
against prompt injection or evidence that attempts to cross the data →
instruction boundary.

At session start:

1. VIGÍA computes the evidence SHA-256.
2. HMAC-SHA256 with `KASSANDRA_SALT` derives a session nonce.
3. The nonce derives dynamic evidence delimiters and a secret tripwire ID of the
   form `PROTOCOLO_KASSANDRA_<dynamic hash>`.
4. The model receives the session ID, but the analyzed evidence should not know
   it.
5. External code verifies that the returned ID and response contract are exact.
   Mismatch or inconsistency is recorded as `KASSANDRA_PROTOCOL_VIOLATION` /
   `INTEGRITY_UNKNOWN`.

Evidence heartbeats are hash-chained and logs use a separate HMAC chain to
expose modification or reordering. Kassandra reports channel integrity only. It
does not prove attacker presence and cannot alter a forensic verdict.

Without a private salt, the public fallback can be precomputed by an attacker
who knows the evidence. Enforce fail-closed startup where this guarantee
matters:

```bash
export KASSANDRA_SALT="$(openssl rand -hex 32)"
export VIGIA_ENFORCE_KASSANDRA_SALT=true
```

## Command-line boundaries

Passive OpenAPI triage and typed handoffs:

```bash
python3 -m offensive.openapi_cli api.openapi.json triage-plan.json
python3 -m offensive.openapi_cli --select CANDIDATE-ID api.openapi.json triage-plan.json
python3 -m offensive.openapi_cli --select-authn CANDIDATE-ID api.openapi.json triage-plan.json
python3 -m offensive.openapi_cli --select-state-change CANDIDATE-ID api.openapi.json triage-plan.json
python3 -m offensive.openapi_cli --select-file-ingress CANDIDATE-ID api.openapi.json triage-plan.json
```

Validate an active manifest without requests, then execute only against the
literal loopback origin declared in that manifest:

```bash
python3 -m offensive.bola_cli --dry-run bola-plan.json
python3 -m offensive.bola_cli bola-plan.json

python3 -m offensive.nested_bola_cli --dry-run examples/nested-bola.loopback.json
python3 -m offensive.nested_bola_cli examples/nested-bola.loopback.json

python3 -m offensive.authn_cli --dry-run authn-plan.json
python3 -m offensive.authn_cli authn-plan.json

python3 -m offensive.state_change_cli --dry-run state-change-plan.json
python3 -m offensive.state_change_cli state-change-plan.json

python3 -m offensive.mass_assignment_cli --dry-run examples/mass-assignment.loopback.json
python3 -m offensive.mass_assignment_cli examples/mass-assignment.loopback.json

python3 -m offensive.stale_authority_cli --dry-run examples/stale-authority.loopback.json
python3 -m offensive.stale_authority_cli examples/stale-authority.loopback.json

python3 -m offensive.file_ingress_cli --dry-run file-ingress-plan.json
python3 -m offensive.file_ingress_cli file-ingress-plan.json

python3 -m offensive.forensic_evasion_cli --dry-run examples/forensic-evasion.synthetic.json
python3 -m offensive.forensic_evasion_cli examples/forensic-evasion.synthetic.json

python3 -m offensive.windows_artifact_cli --dry-run examples/windows-artifacts.synthetic.json
python3 -m offensive.windows_artifact_cli examples/windows-artifacts.synthetic.json

python3 -m offensive.timeline_evasion_cli --dry-run examples/timeline-evasion.synthetic.json
python3 -m offensive.timeline_evasion_cli examples/timeline-evasion.synthetic.json
```

Evaluate Blue evidence without changing the Red result:

```bash
python3 -m offensive.purple_cli bola red-receipt.json blue-observation.json
python3 -m offensive.purple_cli nested-bola red-receipt.json blue-observation.json
python3 -m offensive.purple_cli authn red-receipt.json blue-observation.json
python3 -m offensive.purple_cli state-change red-receipt.json blue-observation.json
python3 -m offensive.purple_cli mass-assignment red-receipt.json blue-observation.json
python3 -m offensive.purple_cli stale-authority red-receipt.json blue-observation.json
python3 -m offensive.purple_cli file-ingress red-receipt.json blue-observation.json
```

Example manifests are in [examples/](examples/). Strict JSON readers reject
unknown fields, duplicate keys, floats, oversized artifacts, symlinks where the
local-artifact boundary forbids them, and authority-expanding values.

## Optional model providers

OpenAI or Gemini may drive unsealed agent narration. Merely placing a key in the
environment does not select or spend against that provider; selection is
explicit:

```bash
export PANCITO_MODEL_PROVIDER=openai
export OPENAI_API_KEY='inject-from-your-shell-or-secret-manager'
export OPENAI_MODEL=gpt-6-astra  # optional default
```

Never commit the key, place it in a manifest, pass it as a command-line
argument, or expose it to prompts and logs. Without the selected provider's
credential, model-dependent routes fail explicitly while deterministic replay
and sealed verdict paths remain available.

## Reproducibility and verification

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

python3 -m pytest
python3 -m pytest tests/test_determinism.py -q
```

When testing the inherited service locally, force the case store to memory if
Firestore credentials are intentionally absent:

```bash
VIGIA_CASE_BACKEND=memory python3 -m pytest
```

The architecture artifact has its own reproducibility evidence in
[docs/pancito-architecture.architecture.json](docs/pancito-architecture.architecture.json)
and [docs/pancito-architecture.visual-check.json](docs/pancito-architecture.visual-check.json).

## Repository map

```text
offensive/       bounded manifests, passive triage, active loopback experiments,
                 deterministic oracles, receipts, and Purple evaluation
core/            deterministic adjudication, canonicalization, custody, seals
agent/           investigation orchestration, Kassandra, provider boundary
service/         inherited FastAPI surface and honestly degraded stores
contracts/       versioned serialized-artifact schemas
examples/        bounded operator-authored manifests
tests/           behavioral, adversarial, determinism, and regression evidence
docs/            interactive architecture and its validation evidence
tools/           ATT&CK mapping, Velociraptor adapter, bundle verification
pipeline/        inherited evidence-to-decision integration
verdict/         deterministic export surfaces
```

## Design decisions and rejected alternatives

| Decision | Rejected alternative | Reason |
|---|---|---|
| Closed capability catalogue | Model-authored shell, browser, exploit, or payload actions | Authorization cannot safely expand through generated text |
| Literal loopback for active HTTP | Remote URL or wildcard target input | Current sandbox and authorization model do not justify remote execution |
| Controls before negative cells | Treat any surprising response as a finding | A broken baseline cannot discriminate the tested hypothesis |
| Exact read-back | Infer impact from status codes or response prose | Consequential claims require an observable state oracle |
| Verified restoration/deletion | Best-effort cleanup | State-changing validation must stop visibly when reversibility is unknown |
| LLM after decision | LLM-generated score/verdict/hash | Consequential output must remain reproducible and auditable |

## Known limitations and non-goals

- Authorization identity is not cryptographically verified by active manifests;
  receipts label it as an unverified operator assertion.
- Active HTTP experiments are local-lab capabilities, not remote pentest
  automation.
- OpenAPI candidates describe an artifact and may not match deployed reality.
- Purple observations are operator assertions and Purple derivations are
  unsealed.
- The forensic-evasion result validates only two SIFT behaviors against three
  synthetic cells; it is not a claim about arbitrary NTFS or EVTX evidence.
- The Prefetch and Registry modules validate four parser-level behaviors; they
  do not establish coverage for arbitrary Prefetch files or Registry hives.
- The timeline audit confirms a summary-contract detection gap under synthetic
  facts; it does not establish exploitability or sealed-verdict impact.
- Kassandra without a private secret salt is precomputable.
- The inherited service and Python package still expose different product
  surfaces; deployment needs an explicit boundary decision.
- The fixture-backed service is not a live offensive transport.
- No general shell, browser, arbitrary payload, persistence, lateral movement,
  exploit generation, or post-exploitation surface is implemented.
- A confirmed experiment demonstrates the narrow tested behavior. Human context
  is still required to decide business impact and remediation priority.

Detailed cleanup and inherited-module classification remain in
[CLEANUP_REPORT.html](CLEANUP_REPORT.html). Research provenance is in
[UPSTREAM_RESEARCH.md](UPSTREAM_RESEARCH.md).

## License and provenance

Original PANCITO-RED-TEAM work is published under PolyForm Strict 1.0.0.
Inherited and third-party components retain their own license terms. See
[LICENSE](LICENSE), [LICENSES/](LICENSES/), and
[ATTRIBUTIONS.md](ATTRIBUTIONS.md).
