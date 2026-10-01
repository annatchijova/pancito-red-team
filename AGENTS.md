# AGENTS.md — working in the PANCITO-RED-TEAM repo

Guidance for any AI coding agent (Claude Code, Cursor, or otherwise) with write
access here. It tells you how to build, run, and test the project, and — more
importantly — the invariants you must not break. Read this before you touch code.
The user-facing story and current product boundary are in `README.md`.

## What this is

PANCITO-RED-TEAM is a bounded offensive-validation system built on the inherited
VIGÍA/annaconda deterministic DFIR core. Every action exists to test a Blue
control on an explicitly authorized target.
Do not add free-form shell, payload, exploit, jailbreak, arbitrary URL/host, or
model-authored execution. Offensive capabilities enter through a deterministic
catalog and an authorization gate, and produce reproducible evidence receipts.

Protocol Kassandra protects evidence-to-LLM channels but remains outside the
forensic decision path. Its status is channel integrity only. Never translate a
tripwire event into MALICE/BENIGN, a score, confidence, MITRE mapping, or a
sealed value. When `VIGIA_ENFORCE_KASSANDRA_SALT=true`, missing
`KASSANDRA_SALT` must prevent startup.

## The one invariant (do not break this)

**A language model never touches the verdict.** This is the founding design
choice, not a preference. Every change you make must preserve it:

1. **The LLM does not decide.** The deterministic core (`core/`) scores the
   evidence and **seals** the result with SHA-256 *before* any agent is called.
   An agent's tools give it **no way to pass a score, a state, or a hash** — it
   may choose *what to investigate* and *put the result into words*, nothing
   more. If you add a tool, it must not let the model supply or suppress a
   sealed value.
2. **No floats, no black-box dependencies, in any sealed value.** The sealed
   core is **stdlib-only** and uses exact arithmetic (`fractions.Fraction`,
   integers). A float or a third-party call anywhere in the decision/seal path
   is a determinism defect — the seals must reproduce **bit-for-bit** across
   fresh processes (different `PYTHONHASHSEED`). `tests/test_determinism.py`
   guards this; it must stay green.
3. **Everything sealed is hash-chained.** Verdicts and mission memory each seal
   a new entry onto the previous one with the same canonical SHA-256 recipe;
   reads re-verify the chain. Never write a sealed value outside a chain, and
   never let a chain be truncated in a way an attacker could also truncate
   (`service/chain_store.py` stores bounded segments for exactly this reason).
4. **Honest degradation.** When something can't be guaranteed, say so, don't
   fake it: Firestore → in-memory is announced on `/health`; a partial
   collection yields `ABSTAIN` (a first-class verdict) with *what evidence would
   resolve it*, not a false BENIGN; a failed collection is recorded as
   unobserved, never as "looked at and found quiet".

If a change would put the model, a float, or a black-box dependency near a
sealed value, it is wrong regardless of how much cleaner it looks.

## Setup, run, test

Python 3.12. The sealed core needs no third-party packages; the service and
agents do.

```bash
pip install -r requirements.txt

# Run the backend locally:
export GEMINI_API_KEY=...              # ONLY for agent/mentor narration turns
uvicorn service.app:app --port 8080    # http://localhost:8080
```

Without a Gemini key the deterministic paths still work (scripted investigations,
sealing, replay); only the agent narration needs the model. Without Firestore
credentials the case store degrades to in-memory and reports it on `/health`.

```bash
# Tests (pytest >= 8, testpaths = tests):
pip install pytest && python3 -m pytest

# Prove the reproducibility guarantee explicitly:
python3 -m pytest tests/test_determinism.py -q
```

The load-bearing test: the same case scored in two fresh processes with different
`PYTHONHASHSEED` produces byte-identical seals. Keep it that way.

## Repo map

```
core/                the deterministic sealed engine (CAIE adjudication, MITRE
                     mapping, hallucination_guard) — stdlib-only, no floats
service/
  app.py             FastAPI app + all HTTP endpoints (/health, /cases, /exhibit,
                     /fleet-console, /tasks/sweep, ...)
  case_store.py      per-case store: Firestore backend, honest degradation to memory
  chain_store.py     bounded hash-chain segments (verdict + mission chains)
  tracing.py         OpenTelemetry -> Cloud Trace
agent/
  autonomy.py        the commander: one unattended cycle per due case
  fleet.py           specialists with strictly disjoint tool contracts
  purple_team_agent.py  the investigator (human-driven hunt loop)
  consult_agent.py   the mentor (read-only, teaches junior examiners)
  mission.py         tamper-evident mission memory + per-case self-scheduling (is_due)
  principal.py       identity: verified Google token vs asserted department
  catalog.py         the gate: who may task what, over which data class, in which region
  registry.py        sealed agent registry (refuses agents whose manifest hash isn't approved)
tests/               determinism, authorization, replay, custody, and inherited subsystem suites
tools/ pipeline/ ml/ inference/ security/ sift/ verdict/ contracts/   supporting modules
```

## Deployment status

There is no approved PANCITO production deployment runbook. The inherited
service is fixture-backed replay and must not be represented as a live
offensive transport. Resolve the package/service product boundary, identity,
persistence, quotas, and Kassandra salt before publishing it.

## Before you commit

- [ ] The change keeps the model, floats, and black-box deps out of every sealed
      value (the one invariant).
- [ ] `python3 -m pytest` is green — especially `test_determinism.py`.
- [ ] New sealed data is hash-chained and re-verified on read; degradation is
      honest and surfaced on `/health`.
- [ ] Comments, docstrings, and commit messages are in English; the commit
      message says *why*.
- [ ] Git is forward-only (`commit` / `merge` / `revert`); no `rebase`,
      `squash`, or force-push. Verify repo state with `git status` / `git log`
      before claiming anything about it.
