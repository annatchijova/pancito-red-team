# PANCITO repository red-team audit

**Date:** 2026-10-01
**Audited base:** `main` at `cc5fd01`, plus uncommitted async-export work present
at audit start
**Method:** adversarial code review, authorization-surface mapping, invariant
hunting, falsifiable local tests, and provenance-preserving reporting
**Target boundary:** repository code and local test doubles only. No external
target, production service, credential, or third-party repository was probed.

## Executive result

Three findings were tracked. All three now have a remediation in the current
working tree; none has been committed or pushed. The async-export experiment
remains uncommitted work in progress and must not be treated as released
capability. The SIFT result is bounded to synthetic producer-shaped facts.

| ID | Priority | Finding | Evidence at discovery | Current status |
|---|---|---|---|---|
| RT-2026-01 | P1 | Pytest could bind the service's global case store to a configured Firestore project, making fixed-ID service tests depend on and potentially mutate persistent external state. | `GOOGLE_CLOUD_PROJECT` was set; a full-suite run returned 409 for pre-existing `SVC-*`, `CAP-*`, `DEFER-*`, and `AAA-VICTIM` IDs. `service.app` constructs the store at import; `build_case_store()` selects Firestore when the project is set and the memory override is absent. | Remediated in workspace by setting `VIGIA_CASE_BACKEND=memory` in `tests/conftest.py` before test modules import the app. The full suite passes with this isolation. No records were intentionally deleted. |
| RT-2026-02 | P2 | Async-export WIP populated `_Event` fields positionally after adding canary fields; response hashes landed in the wrong fields and `response_capture_sha256` remained empty. The declared `other_tenant_canary_observed` field was never computed, and Purple validation still expected the old event shape. | Targeted loopback test failed because response digests were not 64 hex characters. Code-path review found the canary field defaulting to `None`; receipt validation did not yet require field/event consistency. | Remediated in workspace using keyword fields, computing both canary observations, validating event-specific shape, and updating fixtures. Targeted tests pass. WIP is uncommitted. |
| RT-2026-03 | P2 | SIFT Memory/MFT producer summaries lost shared correlation identity, so the timeline missed a cross-source causal inversion despite both positive controls working. | Historical induction in [`timeline-composition-audit.md`](timeline-composition-audit.md), base `209db4d`; production-shaped synthetic pair yielded `MEMORY_WITHOUT_DISK` instead of `CAUSAL_INVERSION`. | Remediated in workspace for the unique-basename case; ambiguity deliberately remains uncorrelated. Regression test now detects the synthetic causal inversion. No real-image or sealed-verdict impact was established. |

Priority labels are ordinal triage within this audit, not CVSS scores. P1
reflects the possibility of tests using persistent operator data; P2 findings
affect evidence quality or a bounded experiment's receipt contract. No P0
emergency was identified in the reviewed scope.

## Threat model and trust boundaries

- A local operator may have cloud credentials and project variables in the
  environment while running the test suite.
- Experiment manifests, credentials, canaries, HTTP replies, and Blue
  observations are untrusted inputs at their respective boundaries.
- HTTP authorization experiments are intended to use exact loopback origins,
  fixed methods and bodies, bounded requests/responses, and disposable
  resources.
- Blue observations are operator-supplied and unsealed; they cannot rewrite the
  Red result or a forensic verdict.
- SIFT summary signals can be incomplete or ambiguous. Correlation is a
  candidate relation and must not be represented as proof of identity.

## Previous findings and claim limits

The only earlier finding document found in this repository was the SIFT timeline
composition audit. It is retained with its original base, fixture hash, initial
result, and new retest/remediation in [`timeline-composition-audit.md`](timeline-composition-audit.md).
The current API authorization matrix says “None” for findings on targets; that
is consistent with the evidence: the other authorization modules validate
capabilities against controlled local labs and do not establish vulnerabilities
in any real API.

The repository's experiments do not claim a penetration test of production
targets. Each result is evidence about only the exact tested cell.

## Reproduction and verification

The pre-remediation full suite produced 14 failures: one async receipt-integrity
failure and 13 service-test duplicate-ID failures. Those service failures were
consistent with the configured persistent backend and pre-existing test IDs;
the audit did not delete or overwrite those records. After isolating tests and
fixing the two code contracts, the full suite passed:

```bash
python3 -m pytest -q -p no:cacheprovider
```

The run required loopback permission for local test servers. One ADK experimental
feature warning remained. Targeted verification also passed:

```bash
python3 -m pytest tests/test_timeline_evasion.py tests/test_timeline_evasion_cli.py \
  tests/test_async_export_authz.py tests/test_async_export_authz_cli.py \
  tests/test_purple_cli.py tests/test_autonomous_service.py -q -p no:cacheprovider
```

## Falsified vectors and untested surface

- Wrong-tenant download denial versus job expiry is distinguished only in the
  local mock by the post-test owner-control request; no third-party API was
  tested.
- The async WIP has a bounded loopback origin, but its lifecycle is not released
  or externally validated. A response lost after resource creation remains an
  unknown possible orphan and requires operator cleanup.
- Existing authz matrix blind spots remain: cross-tenant job-status reads,
  multi-node revocation propagation, browser-only controls, GraphQL, share or
  transfer actions, and production/remote targets.
- SIFT basename correlation may be ambiguous or misleading; multiple distinct
  anomaly subjects intentionally fall back to tool-level grouping. This audit
  did not prove the added correlation changes a sealed verdict.
- Static review does not prove the absence of defects. Scope covered repository
  code, current dirty WIP, recent authorization modules, test isolation, and the
  prior documented timeline finding—not every dependency or deployed
  environment.

## Follow-up gates

1. Review and commit the audit/remediations only after confirming the service
   test harness cannot select Firestore, even when cloud variables are set.
2. Keep async-export work separate from release claims until its receipt
   contract, operator cleanup behavior, and full test set are reviewed again.
3. Treat the timeline fix as a correlation-candidate improvement, not a
   forensic conclusion; test ambiguous subject sets and representative real
   artifacts under a separately authorized validation plan before widening the
   claim.
