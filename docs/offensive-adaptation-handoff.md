# Offensive upstream adaptation — handoff for the next agent

**Date:** 2026-10-15
**Branch:** `research/offensive-repo-adaptation`
**Scope:** how to continue adapting offensive red-team repositories into
PANCITO-RED-TEAM without breaking its invariants. Read this together with
`AGENTS.md` (the one invariant), `UPSTREAM_RESEARCH.md` (the full per-repo
survey with pinned commits), and `attack-surface.md` (the candidate queue).

This document exists because the working material for this research is *local
and disposable* (see "Where things live"), while the decisions are durable.
If the clones are gone, everything needed to redo the review is pinned here.

---

## 1. The invariant you must not break

Every adaptation candidate is judged against one rule:

> **A language model never touches the verdict.**

Operationally that means, for anything you add:

1. The deterministic core scores and seals *before* any agent runs. A new
   offensive capability must not give a model (or a caller) a way to supply a
   score, state, verdict, hash, or command.
2. No floats and no third-party dependencies in anything that gets sealed.
   `tests/test_determinism.py` must stay green across fresh processes with
   different `PYTHONHASHSEED`.
3. Sealed data is hash-chained (`service/chain_store.py`); nothing sealed is
   written outside a chain.
4. Honest degradation: partial evidence yields `ABSTAIN`/named failure states,
   never a synthetic pass. Failed collection is recorded as *unobserved*.
5. The offensive boundary is a **closed catalog**: `offensive/` modules are the
   only capabilities, each a bounded, fixed-shape experiment on an explicitly
   authorized target (today: replay fixtures and loopback-literal HTTP
   differentials only). No free-form shell, payload, exploit, arbitrary URL,
   or model-authored execution — that exclusion is deliberate, not a gap.

If a proposed adaptation needs the model, a float, a network target, or an
arbitrary command to work, it fails the gate. Say so and defer it — do not
reshape it until it fits.

## 2. Where things live

| Thing | Location | Committed? |
|---|---|---|
| This handoff | `docs/offensive-adaptation-handoff.md` | yes, on the branch |
| Full survey (patterns + pinned commits) | `UPSTREAM_RESEARCH.md`, section "Offensive framework survey" | yes |
| Prior reuse assessment (LLM/MCP tooling, Sigma/Volatility/Velociraptor license calls) | `docs/upstream-reuse-assessment.md` | untracked as of this writing — check `git status` |
| Earlier technique-level pass (AgentDojo, Atomic Red Team, CORScanner, graphql-cop, SSRFmap, …) | `UPSTREAM_RESEARCH.md`, upper sections | yes |
| Shallow clones | `scratch/upstream-repos/<repo>/` | **no — `scratch/` is gitignored and may be wiped.** Re-clone with the commands below |
| The catalog being adapted to | `offensive/*.py` + `offensive/fixtures/` | yes |
| Authorization gate | `offensive/engagement.py`, `offensive/replay.py` (`AuthorizationGrant`) | yes |
| Post-seal oracle | `offensive/oracle.py` | yes |
| Correlation-marker contracts | `offensive/purple.py` (`PANCITO-<hex16>`) | yes |

Re-clone commands (shallow; add `--filter=blob:none --sparse` for the large
ones — Security-Datasets, nuclei-templates, ThreatHunter-Playbook):

```bash
mkdir -p scratch/upstream-repos && cd scratch/upstream-repos
for r in DataDog/stratus-red-team redcanaryco/invoke-atomicredteam \
         splunk/attack_range \
         center-for-threat-informed-defense/adversary_emulation_library \
         google/tsunami-security-scanner; do
  git clone --depth 1 "https://github.com/$r" "$(basename $r)"
done
git clone --depth 1 --filter=blob:none --sparse https://github.com/OTRF/Security-Datasets security-datasets
git clone --depth 1 --filter=blob:none --sparse https://github.com/projectdiscovery/nuclei-templates nuclei-templates
git clone --depth 1 --filter=blob:none --sparse https://github.com/OTRF/ThreatHunter-Playbook threathunter-playbook
```

Then pin: `git -C <repo> rev-parse HEAD` and compare against the commit recorded
in `UPSTREAM_RESEARCH.md`. If upstream moved, review the diff before trusting
any prior conclusion — a surveyed pattern at an old commit is a claim about
that commit only.

## 3. How an upstream pattern becomes a PANCITO capability

The pipeline that existing modules followed (see `offensive/ssrf_outbound_fetch.py`
for the reference shape):

1. **Extract the invariant, not the code.** State which control property the
   technique tests (e.g., "server must not fetch attacker-named URLs"), not
   how the upstream tool exploits it.
2. **Write the benign/vulnerable pair.** Every experiment is a differential: a
   baseline control step plus a test step, separated so the oracle can attribute
   the outcome. Fixed request shapes, bounded counts, literal loopback targets,
   no redirects.
3. **Define the oracle declaratively.** `DetectionExpectation`-style: exact
   observable conditions (status, marker path, structured fields) — never
   substring optimism, never response-body-alone checks when an independent
   witness is possible.
4. **Bind it to authorization.** The capability is reachable only through an
   `EngagementPlan`/`AuthorizationGrant` naming it from the closed catalog. A
   caller cannot smuggle a target or command.
5. **Seal the receipt.** Result flows through the real engine; execution success
   and evidential outcome are recorded separately (`EXECUTION_FAILED` vs
   `CONTROL_GAP`).
6. **Mark it.** Correlation canary (`PANCITO-<hex16>` or a canary URL/token) so
   the blue side can attribute exactly this event.
7. **Record provenance.** Update `UPSTREAM_RESEARCH.md`: repo, pinned commit,
   license *read from the file*, pattern examined, what was/wasn't copied. If
   material is actually copied (has not happened yet), also `ATTRIBUTIONS.md`
   and the license's own notice requirements.

## 4. Ranked adaptation backlog (from the 2026-10-15 survey)

Ordered by value-per-risk. None of these is started; each has a stated
falsifier for "is this actually worth doing."

### 4.1 Scenario provenance block — *ready to implement*

Extend the replay catalog's `technique_reference` toward the Security-Datasets
`simulation:` shape: `generator_tool`, `environment`, `permissions_required`,
optional `cti_source` (the Adversary Emulation Library field that grounds each
TTP in a cited report). All descriptive metadata — touches no sealed value.
*Falsifier:* if no scenario ever cites more than bare technique IDs, the added
fields are ceremony; drop the plan.

### 4.2 Sealed catalog definitions — *ready to implement*

nuclei-templates stamps a signed `digest` per template; `agent/registry.py`
already hash-pins agent manifests. Apply the same manifest-hash pattern to
`offensive/` scenario definitions so a catalog entry's identity is pinned
before it runs. *Falsifier:* if scenario definitions are frozen code (they are
today — `_SCENARIOS` is a literal dict), sealing adds integrity against
accidental edit only; still cheap, but say that's what it's for.

### 4.3 Per-scenario detection guidance — *documentation only*

Stratus's `Detection:` block and ThreatHunter-Playbook's hypothesis-first
structure both argue for storing expected-telemetry prose ("what should blue
see") next to each scenario. Read by operators and the narrator; **never** an
oracle input. *Falsifier:* if it drifts into the decision path (e.g., parsed
for expectations), it violates the invariant — keep it inert text.

### 4.4 Lifecycle vocabulary — *deferred until active adapters exist*

Stratus's `warmup → detonate → revert → cleanup` and Invoke-AtomicRedTeam's
"cleanup survives the test process" matter only if PANCITO ever runs
experiments with side effects. While everything is replay + loopback
differentials with no persistent state, adopting the state machine is
speculative generality — record, don't build.

### 4.5 Multi-step scenario composition — *deferred*

The emulation-library scenario → step → procedure format is the reference if
chaining is ever wanted. Composed state expands the oracle surface and breaks
the one-technique-one-outcome attribution the catalog relies on. Revisit only
with a composition oracle design.

## 5. Exclusion list — do not re-propose these

| Repo | Why it's out |
|---|---|
| Sliver, Infection Monkey | GPL-3.0 (copyleft) *and* free-form C2/autonomous propagation — both gates fail |
| Empire | BSD-3 but archived upstream (2020); C2 model outside the bounded catalog |
| Mythic | license undetermined (NOASSERTION) + C2 |
| elastic/detection-rules | non-standard license; blue-side content — and `elastic/RTA` no longer exists standalone |
| CALDERA, Velociraptor, Volatility, Sigma rules, PurpleLlama | already dispositioned in `docs/upstream-reuse-assessment.md` — read before re-litigating |
| Anything offering arbitrary command/payload/URL execution | fails the closed-catalog invariant regardless of license or quality |

License gate (from the repo's existing policy): permissive (MIT, BSD,
Apache-2.0) only for anything approaching reuse; copyleft is reference-only.
**Read the `LICENSE` file in the clone, not the GitHub API label** —
Security-Datasets' README still claims GPL-3.0 while its `LICENSE` file is MIT.
The file wins; record which file you read and at which commit.

## 6. Before you claim anything is done

- [ ] `python3 -m pytest` green — specifically `tests/test_determinism.py`.
- [ ] New capability selects only through the engagement manifest; no path from
      caller/model to command, target, score, verdict, or hash.
- [ ] Execution outcome and evidential outcome recorded separately.
- [ ] Provenance row added to `UPSTREAM_RESEARCH.md` with the real pinned commit
      and the license you read from the file.
- [ ] `git status` / `git log` actually show what you claim; forward-only git
      (no rebase/squash/force-push); restore-point tag exists for the session.
- [ ] Commit message in English, says *why*.

## 7. Honest scope note

This survey reviewed repository *structure and schemas* at pinned commits. It
did not run any upstream tool, audit their dependencies, or perform a legal
review — per-repo conclusions are engineering recommendations, not license
clearance. The `scratch/upstream-repos/` clones are working material, not
deliverables; nothing in them is part of PANCITO.
