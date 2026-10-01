[English](README.md) · [Español](README_ES.md) · [Technical README](TECHNICAL_README.md) · [Interactive architecture](docs/pancito-architecture.html)

# PANCITO-RED-TEAM

Offensive security automation has an evidence problem: a tool can produce a
convincing attack narrative without proving that the target changed, that a
control failed, or that Blue telemetry observed the behavior.

PANCITO-RED-TEAM is a bounded adversary-validation toolkit for authorized
security labs. It runs small, reproducible experiments whose objective is
always defensive: test one control, preserve what was observed, clean up any
state it created, and report no stronger conclusion than the evidence supports.

The current active HTTP experiments accept only literal loopback targets. The
model may choose what to investigate or narrate an already-produced result; it
cannot decide, score, hash, seal, or suppress the result.

## What an experiment looks like

```text
authorized manifest
        ↓
working control ──fails──> INCONCLUSIVE
        ↓ works
bounded negative cell
        ↓
read-back / deterministic oracle
        ↓
verified cleanup ──fails──> MANUAL_ACTION_REQUIRED
        ↓
scoped Red receipt + independent Blue evaluation
```

A successful HTTP response is not automatically a finding. For example, the
file-ingress experiment only confirms persistence when authenticated metadata
reproduces the exact size and SHA-256 of an inert synthetic sample. A missing
object identifier, failed read-back, or unverifiable cleanup remains
`INCONCLUSIVE`.

## How this design differs

This table compares two implementation choices. It does not claim that every
agentic security product uses the first design.

| Design dimension | General-purpose model executor | PANCITO current implementation |
|---|---|---|
| Action surface | The model may compose commands or tool calls | Code selects from a closed capability catalogue |
| Active target | Runtime input may name a network destination | Active HTTP probes require a literal loopback origin |
| Evidential result | Model interpretation may become the report | Deterministic code produces the result before narration |
| Ambiguous observation | Often requires prose interpretation | Explicit `INCONCLUSIVE` or `MANUAL_ACTION_REQUIRED` |
| State-changing test | Cleanup depends on the generated workflow | Read-back, restoration, and restoration verification are part of the experiment |
| Blue objective | Detection may be reviewed after the test | Every step carries correlation metadata and is evaluated independently from prevention |

## What is implemented now

| Capability | Defensive question | Evidence boundary |
|---|---|---|
| Hostile telemetry replay | Does the sealed DFIR path detect the expected ATT&CK techniques? | Committed fixtures, fixed scenario catalogue, verified custody chain |
| BOLA differential | Can one authenticated principal read another principal's object? | Owner and peer controls before one cross-principal cell |
| Authentication differential | Does protected data survive absent or invalid credentials? | A 2xx response is insufficient without the protected canary |
| Public state change | Can an anonymous or invalid identity mutate one field? | Authenticated read-back and verified restoration after each successful negative cell |
| Mass assignment / BOPLA | Can a low-privilege actor modify a protected property? | Allowed-field control, observer read-back, and verified two-field restoration |
| File ingress | Does storage accept bytes that contradict type or size policy? | Three generated inert samples, exact digest/size read-back, verified deletion |
| Forensic-evasion differential | Do SIFT sensors distinguish known timestomp and log-wipe traces from a clean control? | Three module-owned synthetic cells; exact ground truth stays separate from unsealed sensor observations |
| Prefetch anti-forensics | Does SIFT distinguish suspicious execution and selective Prefetch removal? | Ten-file clean control plus fixed execution and wipe cells; temporary inert files only |
| Registry evasion | Does SIFT distinguish suspicious Run-key persistence and timestamp collision? | Parser-level synthetic facts only; no hive, RegRipper process, command, or payload input |
| Timeline composition audit | Do production Memory/MFT summaries preserve enough identity for cross-source causality? | Positive controls pass, but the production-shaped pair currently reports `FALSIFIED`; no sealed-verdict impact is claimed |
| OpenAPI triage | Which declared routes deserve a bounded follow-up experiment? | Passive local artifact analysis; every result remains a candidate, never a finding |
| Purple evaluation | Did Blue observe and alert on the exact executed behavior? | Red prevention and Blue detection remain separate conclusions |

See the [interactive architecture](docs/pancito-architecture.html) for the
component and trust-boundary view. Its source-evidence specification is
[versioned beside it](docs/pancito-architecture.architecture.json).

## Try the replay lab

Python 3.10 or newer is required.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
python3 -m pytest tests/test_offensive_engagement.py \
  tests/test_offensive_replay.py tests/test_determinism.py
```

Run the bundled, non-live replay:

```python
from offensive.engagement import load_engagement
from offensive.replay import ReplayCampaign

plan = load_engagement("examples/engagement.replay.json")
receipt = ReplayCampaign(
    plan.to_grant(),
    out_dir="offensive-runs",
).run("process-hollowing-timestomp")
```

`offensive-runs/` is ignored because it contains generated evidence. The
example grant is restricted to the bundled replay lab.

For environment setup and the optional inherited service, see
[INSTALL.md](INSTALL.md). For active loopback manifests and every CLI contract,
see the [Technical README](TECHNICAL_README.md#command-line-boundaries).

## Evidence behind the claims

- [Determinism test](tests/test_determinism.py) reproduces sealed output across
  fresh processes with different hash seeds.
- [Offensive replay tests](tests/test_offensive_replay.py) exercise the fixed
  catalogue, budget, custody verification, and deterministic Blue oracle.
- [BOLA](tests/test_bola_differential.py),
  [authentication](tests/test_authn_differential.py),
  [state-change](tests/test_state_change_differential.py),
  [mass-assignment](tests/test_mass_assignment_differential.py), and
  [file-ingress](tests/test_file_ingress_differential.py) suites exercise their
  control/negative-cell contracts and failure states.
- [Purple evaluation tests](tests/test_purple_cli.py) bind Blue assertions to
  the exact Red and Blue artifacts evaluated.
- [Forensic-evasion differential](tests/test_forensic_evasion_differential.py)
  tests the real SIFT MFT parser/analyzer and event-chain detector against
  fixed synthetic ground truth without promoting sensor output to a verdict.
- [Prefetch](tests/test_prefetch_evasion.py) and
  [Registry](tests/test_registry_evasion.py) differential tests exercise two
  more SIFT sensor families under the same controls-first contract.
- [Timeline composition tests](tests/test_timeline_evasion.py) reproduce a
  production-contract identity loss and retain the falsified prediction as a
  first-class result, documented in the
  [audit note](docs/timeline-composition-audit.md).
- The [architecture validation receipt](docs/pancito-architecture.visual-check.json)
  records desktop containment and capture evidence for the delivered diagram.

These tests support the properties they exercise; they are not a general claim
that every target or deployment is secure.

## Go deeper

- [Technical README](TECHNICAL_README.md) — invariants, trust boundaries,
  protocols, capability contracts, limitations, commands, and repository map.
- [README en español](README_ES.md) — a Spanish adaptation of this overview.
- [Interactive architecture](docs/pancito-architecture.html) — explorable
  component map with code provenance.
- [Upstream research notes](UPSTREAM_RESEARCH.md) — reviewed projects, pinned
  commits, licenses, and the ideas adapted without copying source files.
- [Attributions](ATTRIBUTIONS.md) — inherited and third-party provenance.

## License

PANCITO-RED-TEAM is a research and adversarial security testing toolkit. It is
published for study, experimentation, and non-commercial security research.
Commercial use, redistribution, and derivative works require a separate
written license from the author.

Original PANCITO-RED-TEAM work is published under PolyForm Strict 1.0.0.
Inherited and third-party components retain their own terms. The legal texts
and provenance records are in [LICENSE](LICENSE), [LICENSES/](LICENSES/), and
[ATTRIBUTIONS.md](ATTRIBUTIONS.md). Those legal texts control if this summary
differs from them.
