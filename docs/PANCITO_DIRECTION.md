# PANCITO-RED-TEAM direction

## Destination

PANCITO-RED-TEAM is an authorized adversary-validation platform that can
exercise a control, collect what the endpoint actually emitted, and seal the
Blue-side result into the same reproducible record. The model may choose among
approved experiments and explain results. It never authors execution, grants
itself scope, or decides whether the evidence is malicious.

## Threat model

- The attacker can read the public source, control endpoint-produced evidence,
  insert instruction-like text into that evidence, and attempt replay,
  reordering, or model-response manipulation.
- The attacker cannot read `KASSANDRA_SALT`, change reviewed code, alter an
  approved authorization grant, or rewrite an already anchored sealed chain.
- Tool output and evidence are untrusted data. Only operator policy and a
  deterministic authorization gate carry instruction authority.

If the salt is missing, the private-canary assumption no longer holds. The
default development posture is honest degradation (`degraded-predictable`);
`VIGIA_ENFORCE_KASSANDRA_SALT=true` makes that condition a startup failure.

## Level 1 — implemented

### Authorized attack-trace replay

`offensive/replay.py` exposes a closed scenario catalogue. A grant fixes the
local target, Blue objective, allowed scenarios, and maximum number of runs.
The executor has no network, shell, payload, exploit, or free-form command
capability. Its receipt is derived after sealing and explicitly says it is not
part of the forensic verdict.

Run the current scenario from Python:

```python
from offensive.replay import AuthorizationGrant, ReplayCampaign

grant = AuthorizationGrant(
    authorization_id="LAB-2026-001",
    target="bundled-replay-lab",
    objective="blue-control-validation",
    allowed_scenarios=("process-hollowing-timestomp",),
    max_runs=1,
)
receipt = ReplayCampaign(grant, out_dir="offensive-runs").run(
    "process-hollowing-timestomp"
)
```

### Protocol Kassandra

For a session seeded by the first evidence block:

1. SHA-256 identifies the seed evidence.
2. HMAC-SHA256 with `KASSANDRA_SALT` derives a private session nonce.
3. Domain-separated HMAC derivation produces a per-session semantic canary,
   `PROTOCOLO_KASSANDRA_<dynamic>`.
4. Dynamic delimiters envelope evidence as untrusted data. The canary is sent
   on the instruction side, never inserted into the evidence envelope.
5. Each evidence block advances a content-bound SHA-256 heartbeat.
6. Code verifies the model's exact tripwire response contract with the expected
   identifier. Wrong, missing, unsolicited, or malformed responses become
   `KASSANDRA_PROTOCOL_VIOLATION / INTEGRITY_UNKNOWN`.
7. Protocol events form a separate HMAC chain. This chain detects mutation and
   reordering of entries presented for verification.

Kassandra does not detect every prompt injection. A generic instruction that
does not know the private canary can still influence a model; the deterministic
verdict boundary and narration guard remain load-bearing. A local in-memory
HMAC chain also does not prove that an entire suffix was not discarded. Durable
deployment must anchor bounded log segments externally, following the same
anti-truncation discipline as `service/chain_store.py`.

## Next coherent levels

1. Add non-destructive, platform-specific emulation adapters behind the same
   authorization and catalogue boundary, starting in disposable labs only.
2. Bind every emulation action to pre/post collection windows and a signed
   scope artifact, then compare expected telemetry with what Blue observed.
3. Anchor Kassandra audit segments in durable storage and expose independent
   verification without exposing the salt.
4. Add CI scenarios and benign twins so a control must catch hostile behavior
   without blocking structurally similar legitimate activity.

Each level must preserve the existing invariant: the LLM cannot supply or
suppress a score, verdict, state, MITRE mapping, hash, authorization, or scope.
