# PANCITO-RED-TEAM

PANCITO-RED-TEAM is a bounded adversary-validation system for authorized Blue
control testing. It reuses VIGÍA's deterministic forensic core and adds a
strict offensive boundary: explicit scope, a closed capability catalogue,
bounded execution, reproducible evidence, and sealed validation receipts.

The current active executor is limited to a three-request BOLA differential
experiment against a literal loopback origin. All other current offensive
execution is replay-only. PANCITO cannot run arbitrary commands, choose a
remote network target, generate a payload, follow redirects, or let a model
supply a verdict, score, confidence value, or hash.

## Current capability

`offensive.replay` replays committed hostile telemetry through the real sealed
engine. The first scenario validates detection of process hollowing and
timestomping. Each run:

1. loads an operator-authored engagement manifest;
2. rejects unknown fields, duplicate keys, floats, oversized input, and
   capabilities outside the catalogue;
3. enforces a fixed target, objective, scenario allowlist, and run budget;
4. produces and verifies the forensic custody chain;
5. evaluates the sealed result against a deterministic Blue expectation; and
6. returns a receipt that separates execution success from detection success.

Protocol Kassandra protects evidence-to-LLM channels. It reports channel
integrity only; it cannot produce or alter a forensic verdict.

Two additional bounded capabilities are available:

- `offensive.bola` runs positive owner/peer controls and one cross-principal
  object-read probe against an exact loopback HTTP origin. It emits
  `CONFIRMED_BY_INDUCTION`, `FALSIFIED`, or `INCONCLUSIVE` without retaining
  response bodies, canaries, or credentials. Each request carries a public
  exercise/step marker so Blue can correlate telemetry without treating the
  marker itself as detection.
- `offensive.openapi_surface` passively triages an operator-supplied OpenAPI
  JSON artifact. It produces provenance-preserving review candidates and
  explicit coverage gaps; it never contacts a target or promotes a candidate
  into a vulnerability finding.
- `offensive.handoff` preserves the selected OpenAPI candidate and source hash
  into the BOLA plan without importing the triage priority as a conclusion.
- `offensive.purple` evaluates operator-supplied Blue telemetry and alert
  observations independently from the Red prevention result.

## Quick start

Python 3.10 or newer is required.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
python3 -m pytest tests/test_offensive_engagement.py tests/test_offensive_replay.py
```

Run an authorized replay:

```python
from offensive.engagement import load_engagement
from offensive.replay import ReplayCampaign

plan = load_engagement("examples/engagement.replay.json")
receipt = ReplayCampaign(
    plan.to_grant(),
    out_dir="offensive-runs",
).run("process-hollowing-timestomp")
```

`offensive-runs/` is ignored because it contains generated run evidence. The
example engagement is intentionally limited to the bundled replay lab.

The strict command-line boundaries are available as modules:

```bash
# Passive OpenAPI triage; add --select CANDIDATE-ID for a BOLA handoff.
python3 -m offensive.openapi_cli api.openapi.json triage-plan.json

# Validate a BOLA manifest and its environment-backed secrets without requests.
python3 -m offensive.bola_cli --dry-run bola-plan.json

# Run the bounded three-request loopback experiment.
python3 -m offensive.bola_cli bola-plan.json
```

BOLA manifests name environment variables that contain both credentials and
canaries; secrets are never accepted inline in the manifest or emitted in the
receipt.

## Security invariants

- Every action must test a Blue control on an explicitly authorized target.
- Capabilities are curated code, never model-authored commands.
- The model stays outside the forensic decision and seal paths.
- Sealed values use deterministic, exact arithmetic and canonical SHA-256.
- A failed or incomplete observation is explicit; it never becomes a false
  clean result.
- Kassandra integrity signals never become MALICE/BENIGN, confidence, ATT&CK
  mappings, or sealed evidence.

For production Kassandra use, supply a private salt and require it at startup:

```bash
export KASSANDRA_SALT="$(openssl rand -hex 32)"
export VIGIA_ENFORCE_KASSANDRA_SALT=true
```

## Repository map

| Path | Purpose |
|---|---|
| `offensive/` | Engagement validation, replay, OpenAPI triage/handoff, loopback BOLA proof/CLI, and Blue observation oracle |
| `examples/` | Bounded example engagement manifests |
| `agent/tools.py` | Session boundary used by the replay executor |
| `core/`, `pipeline/`, `tools/`, `verdict/` | Deterministic inherited decision and sealing closure |
| `offensive/fixtures/attack/` | Packaged hostile telemetry used by replay scenarios |
| `service/` and the rest of `agent/` | Connected inherited backend; retained pending product-boundary work |
| `UPSTREAM_RESEARCH.md` | Reviewed offensive-agent patterns and provenance |
| `CLEANUP_REPORT.html` | Cleanup evidence, classifications, deletions, and deferred findings |

## Live telemetry validation

The offensive executor uses committed fixtures. It does not claim to attack or
collect from a live endpoint. The separate Velociraptor validator checks the
live collection path without broadening the replay authority:

```bash
scripts/setup_velociraptor.sh
python3 scripts_lib/validate_live_velociraptor.py
```

## Known structural debt

- `offensive.replay` currently reaches the inherited scoring pipeline through
  `agent.tools` and `vigia_scorer`; those modules are load-bearing and were not
  deleted during the cleanup.
- The Python package and the inherited Cloud service describe two different
  product surfaces. Deployment still needs a dedicated
  boundary decision before either is called production-ready.
- `service.app` is fixture-backed replay, not a live offensive transport.

These are recorded in detail in `CLEANUP_REPORT.html`.

## License and provenance

Original PANCITO-RED-TEAM work is licensed under PolyForm Strict 1.0.0.
Inherited and third-party components retain their own terms. See
[`ATTRIBUTIONS.md`](ATTRIBUTIONS.md), [`LICENSE`](LICENSE), and `LICENSES/`.
