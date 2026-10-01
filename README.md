# PANCITO-RED-TEAM

PANCITO-RED-TEAM is a bounded adversary-validation system for authorized Blue
control testing. It reuses VIGÍA's deterministic forensic core and adds a
strict offensive boundary: explicit scope, a closed capability catalogue,
bounded execution, reproducible evidence, and sealed validation receipts.

The current active executors are limited to BOLA, authentication-enforcement,
reversible public-state-change, and synthetic file-ingress differential
experiments against a literal loopback origin. All other current offensive
execution is replay-only.
PANCITO cannot run arbitrary commands, choose a remote network target,
generate a payload, follow redirects, or let a model supply a verdict, score,
confidence value, or hash.

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

Additional bounded capabilities are available:

- `offensive.bola` runs positive owner/peer controls and one cross-principal
  object-read probe against an exact loopback HTTP origin. It emits
  `CONFIRMED_BY_INDUCTION`, `FALSIFIED`, or `INCONCLUSIVE` without retaining
  response bodies, canaries, or credentials. Each request carries a public
  exercise/step marker so Blue can correlate telemetry without treating the
  marker itself as detection.
- `offensive.authn` runs one valid-credential control plus anonymous and
  invalid-bearer cells against a protected GET route. A 2xx response is not a
  finding unless the protected canary is observed.
- `offensive.state_change` tests one top-level field through `PATCH`. It proves
  mutation only through authenticated read-back, checks the operator-supplied
  baseline before writing, restores after every successful negative cell, and
  stops with `MANUAL_ACTION_REQUIRED` if restoration cannot be verified. A
  confirmed public mutation still carries `REQUIRES_HUMAN_CONTEXT`; public may
  be intentional, so execution alone does not establish security impact.
- `offensive.file_ingress` generates three inert samples in memory: a valid
  control, bytes that contradict a declared PNG type, and a body exactly one
  byte above the operator-declared limit. It accepts no file path or arbitrary
  sample bytes. Storage is confirmed only when authenticated metadata reproduces
  the exact SHA-256 and size; every returned object ID is deleted and then
  verified absent. An untrackable upload stops with `MANUAL_ACTION_REQUIRED`.
- `offensive.openapi_surface` passively triages an operator-supplied OpenAPI
  JSON artifact. It produces provenance-preserving review candidates and
  explicit coverage gaps; it never contacts a target or promotes a candidate
  into a vulnerability finding.
- `offensive.handoff` preserves a selected BOLA or authentication candidate
  and source hash into the active plan without importing triage priority as a
  conclusion.
- `offensive.purple` evaluates operator-supplied Blue telemetry and alert
  observations independently from the Red prevention result. Its CLI binds
  the evaluation to hashes of the exact Red and Blue input artifacts while
  stating explicitly that the derivation remains unsealed.

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
# Passive OpenAPI triage; select a bounded active handoff when required.
python3 -m offensive.openapi_cli api.openapi.json triage-plan.json
python3 -m offensive.openapi_cli --select-authn CANDIDATE-ID \
  api.openapi.json triage-plan.json
python3 -m offensive.openapi_cli --select-state-change CANDIDATE-ID \
  api.openapi.json triage-plan.json
python3 -m offensive.openapi_cli --select-file-ingress CANDIDATE-ID \
  api.openapi.json triage-plan.json

# Validate a BOLA manifest and its environment-backed secrets without requests.
python3 -m offensive.bola_cli --dry-run bola-plan.json

# Run the bounded three-request loopback experiment.
python3 -m offensive.bola_cli bola-plan.json

# Validate or run the authentication-enforcement differential.
python3 -m offensive.authn_cli --dry-run authn-plan.json
python3 -m offensive.authn_cli authn-plan.json

# Validate or run the reversible public-state-change differential.
python3 -m offensive.state_change_cli --dry-run state-change-plan.json
python3 -m offensive.state_change_cli state-change-plan.json

# Validate or run the inert, reversible file-ingress differential.
python3 -m offensive.file_ingress_cli --dry-run file-ingress-plan.json
python3 -m offensive.file_ingress_cli file-ingress-plan.json

# Evaluate Blue visibility/detection without changing the Red result.
python3 -m offensive.purple_cli bola red-receipt.json blue-observation.json
python3 -m offensive.purple_cli authn red-receipt.json blue-observation.json
python3 -m offensive.purple_cli state-change red-receipt.json blue-observation.json
python3 -m offensive.purple_cli file-ingress red-receipt.json blue-observation.json
```

Active manifests name environment variables that contain credentials and
canaries; secrets are never accepted inline in the manifest or emitted in a
receipt.

### Optional OpenAI narration and agent provider

OpenAI can drive the unsealed ADK agent and narrate an already sealed verdict.
It cannot supply or modify a verdict, score, confidence value, technique, or
hash. Provider selection is explicit so merely having a key in the environment
does not spend credit:

```bash
export PANCITO_MODEL_PROVIDER=openai
export OPENAI_API_KEY='set-this-in-your-shell-or-secret-manager'
# Optional; defaults to gpt-6-astra.
export OPENAI_MODEL=gpt-6-astra
```

Do not put the key in a manifest, `.env` committed to Git, command-line
argument, prompt, or log. For deployment, inject `OPENAI_API_KEY` from the
platform secret manager. `/health` reports provider, model, backend, and
availability, but never credential material. Without the selected provider's
credential, agent/consult routes fail explicitly while deterministic replay and
sealed verdict paths remain available.

## Security invariants

- Every action must test a Blue control on an explicitly authorized target.
- Capabilities are curated code, never model-authored commands.
- Every model provider stays outside the forensic decision and seal paths.
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
| `offensive/` | Engagement validation, replay, OpenAPI triage/handoff, bounded loopback proofs, and deterministic Purple evaluation |
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
