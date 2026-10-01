# PANCITO repository red-team audit

**Date:** 2026-10-01
**First-round base:** `main` at `cc5fd01`, plus async-export changes present at
audit start
**Second-round base:** `main` at `2b7d16c`
**Third-round base:** `main` at `a3b1c4f`
**Fourth-round base:** `main` at `971ce05`
**Fifth-round base:** `main` at `ef228b6`
**Method:** adversarial code review, authorization-surface mapping, invariant
hunting, falsifiable local tests, and provenance-preserving reporting
**Target boundary:** repository code and local test doubles only. No external
target, production service, credential, or third-party repository was probed.

## Executive result

Seven findings have now been tracked across five audit rounds.
The first four are remediated in commit `a3b1c4f`; RT-2026-05 is remediated in
`971ce05`, RT-2026-06 in `ef228b6`, and RT-2026-07 in the current working
tree. The async-export experiment is committed but only exercises controlled
loopback labs; it is not evidence about a real API. The SIFT result remains
bounded to synthetic producer-shaped facts.

| ID | Priority | Finding | Evidence at discovery | Current status |
|---|---|---|---|---|
| RT-2026-01 | P1 | Pytest could bind the service's global case store to a configured Firestore project, making fixed-ID service tests depend on and potentially mutate persistent external state. | `GOOGLE_CLOUD_PROJECT` was set; a full-suite run returned 409 for pre-existing `SVC-*`, `CAP-*`, `DEFER-*`, and `AAA-VICTIM` IDs. `service.app` constructs the store at import; `build_case_store()` selects Firestore when the project is set and the memory override is absent. | Remediated in `2b7d16c` by forcing `VIGIA_CASE_BACKEND=memory` before test imports and per test. Full suite passes with isolation. No records were intentionally deleted. |
| RT-2026-02 | P2 | Async-export work populated `_Event` fields positionally after adding canary fields; response hashes landed in the wrong fields and `response_capture_sha256` remained empty. The declared `other_tenant_canary_observed` field was never computed, and Purple validation still expected the old event shape. | Targeted loopback test failed because response digests were not 64 hex characters. Code-path review found the canary field defaulting to `None`; receipt validation did not yet require field/event consistency. | Remediated in `2b7d16c` using keyword fields, computing both canary observations, validating event-specific shape, and updating fixtures. Targeted and full tests pass. |
| RT-2026-03 | P2 | SIFT Memory/MFT producer summaries lost shared correlation identity, so the timeline missed a cross-source causal inversion despite both positive controls working. | Historical induction in [`timeline-composition-audit.md`](timeline-composition-audit.md), base `209db4d`; production-shaped synthetic pair yielded `MEMORY_WITHOUT_DISK` instead of `CAUSAL_INVERSION`. | Remediated in `2b7d16c` for the unique-basename case; ambiguity deliberately remains uncorrelated. Regression test detects the synthetic causal inversion. No real-image or sealed-verdict impact was established. |
| RT-2026-04 | P2 | Six authorization clients accepted explicit port `0` as if no port were supplied (`port or 80`) and then connected to port 80. A manifest could therefore escape its declared loopback endpoint, potentially sending Bearer credentials to a different local service. | Pure-code induction: `_origin("http://127.0.0.1:0")` returned a parsed origin whose port was `0`, while the client's fallback expression selected `80`. The pattern existed in async export, scope, search, collection, export, and function authorization. No socket was opened and credential delivery to a listener was not tested. | Remediated in `a3b1c4f` by distinguishing `None` from explicit zero in validation and connection setup across six affected clients. Regression cases require port 0 rejection. Targeted and full suites pass. |
| RT-2026-05 | P2 | The shared OpenAPI handoff matcher accepted an encoded route separator inside a placeholder: `/api/v1/users/%2e%2e%2fadmin` matched `/api/v1/users/{user_id}`. A downstream parser that decodes and normalizes the path can resolve it as `/api/v1/admin`, outside the selected candidate route. | Confirmed by local induction on `a3b1c4f`: `AuthnPlan` accepted the handoff/path pair and the matcher returned true; independent `unquote` + `normpath` produced `/api/v1/admin`. Runtime: Python 3.12.3. No live framework or real target was used, so downstream route remapping remains deployment-dependent. | Remediated in `971ce05` at the shared matcher by rejecting percent-encoded, backslash, control, empty, and dot-segment paths, and by bounding the concrete path to 2,048 characters before parsing/splitting. Regression covers Authn plan validation, all four handoff matchers, and max/max+1. |
| RT-2026-06 | P2 | A fresh `ReplayCampaign` object reset its in-memory run counter and reused `run-0001` for the same grant/output namespace. It rewrote the prior window artifact, then failed later when the stale verdict stream rejected the duplicate sequence. | Local replay induction with the bundled fixture and memory backend: first campaign succeeded; a second campaign with the same authorization ID and output root reached `append_entry` and raised `StreamError`. No external target or persistent case store was used. | Remediated in `ef228b6` by atomically creating each run directory with `exist_ok=False`, refusing collisions before creating `PurpleTeamSession`. Regression confirms the second session is never constructed. This does not establish a durable/global `max_runs` quota across processes or distinct output roots. |
| RT-2026-07 | P3 | The documented `load_engagement` file boundary followed a final symlink and could block indefinitely on a FIFO: it statted the path, then used `Path.read_bytes()`, which blocks opening a FIFO before the post-read size check. The shared bounded reader had the same FIFO-open ordering. | Red-first local regressions: a symlink to a valid manifest was accepted; a subprocess calling `load_engagement` on a FIFO timed out after 3 seconds. No service/remote interface was involved. | Remediated in the current patch by routing manifests through the shared regular-file reader, preserving the final path component so no-follow validation applies, and opening with `O_NONBLOCK` before `fstat`. Tests require symlink and FIFO rejection; FIFO test runs in a bounded subprocess. |

Priority labels are ordinal triage within this audit, not CVSS scores. P1
reflects the possibility of tests using persistent operator data; P2 findings
affect evidence quality, the declared target boundary, or a bounded
experiment's receipt contract. P3 is used for local-input availability issues
without a demonstrated remote reachability path. For RT-2026-04,
parser-to-client remapping is confirmed; actual credential receipt by a local
service was not tested. No P0 emergency was identified in the reviewed scope.
RT-2026-05 confirms an
accepted ambiguous route at the handoff boundary; actual framework routing and
credential delivery remain untested. RT-2026-06 concerns a local replay-output
namespace collision, not authorization against a remote target; persistent
cross-process quota enforcement remains outside the current in-memory grant
model. RT-2026-07 is a local artifact availability/integrity boundary; it does
not imply remote reachability.

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

The first-round pre-remediation full suite produced 14 failures: one async
receipt-integrity failure and 13 service-test duplicate-ID failures. Those
service failures were consistent with the configured persistent backend and
pre-existing test IDs;
the audit did not delete or overwrite those records. After isolating tests and
fixing the first-round code contracts, the full suite passed. After the
second-round port fix, the full suite also passed with one ADK
experimental-feature warning and five skipped tests:

```bash
python3 -m pytest -q -p no:cacheprovider
```

After the third-round handoff fix, the full suite again passed with five skipped
tests and one ADK experimental-feature warning. The focused route suite passed
after a red-first regression and negative-control mutation:

```bash
python3 -m pytest tests/test_candidate_handoff.py tests/test_authn_differential.py tests/test_bola_differential.py tests/test_state_change_differential.py tests/test_file_ingress_differential.py -q -p no:cacheprovider
```

For RT-2026-05, prediction on base `a3b1c4f`: the candidate matcher rejects an
encoded slash inside a route parameter. The following local-only induction
instead showed the plan accepting that path; no socket was opened:

```bash
python3 -c 'from offensive.handoff import AuthnCandidateHandoff, authn_path_matches_candidate_template; from offensive.authn import AuthnPlan; from urllib.parse import unquote; import posixpath; h=AuthnCandidateHandoff("CANDIDATE-0123456789abcdef", "openapi.json", "a"*64, "GET /api/v1/users/{user_id}"); p="/api/v1/users/%2e%2e%2fadmin"; plan=AuthnPlan("EXP-01", "AUTHZ-01", "operator", True, "http://127.0.0.1:8080", p, "protected-canary", "invalid-token", candidate_handoff=h); print({"plan_accepted": True, "matcher_accepts": authn_path_matches_candidate_template(h,p), "wire_path": p, "decoded_normalized_path": posixpath.normpath(unquote(p))})'
```

The run required loopback permission for local test servers. One ADK experimental
feature warning remained. Targeted verification also passed:

```bash
python3 -m pytest tests/test_timeline_evasion.py tests/test_timeline_evasion_cli.py tests/test_async_export_authz.py tests/test_async_export_authz_cli.py tests/test_purple_cli.py tests/test_autonomous_service.py tests/test_scope_authz_differential.py tests/test_search_authz_differential.py tests/test_collection_authz_differential.py tests/test_export_authz_differential.py tests/test_function_authz_differential.py -q -p no:cacheprovider
```

For RT-2026-06, the red-first regression on `971ce05` reproduced the stale
stream failure on a second campaign using the same grant and output root. After
remediation, the focused replay suite passes; the new assertion replaces the
session constructor and proves the collision is refused before the second
replay begins. Each run-directory reservation is exclusive; failed attempts
continue to consume the campaign object's in-memory run slot by design.

For RT-2026-07, the red-first symlink test showed that a final-component link
was followed, and a bounded subprocess proved the FIFO path blocked beyond the
3-second test deadline. The repaired engagement tests reject both inputs; the
shared reader now opens non-blocking before checking that the opened descriptor
is a regular file.

## Falsified vectors and untested surface

- The RT-2026-05 consequence is conditional on a downstream server/router
  decoding encoded delimiters and normalizing dot segments; actual products
  vary, and no framework-specific request was sent. A corpus of 261 percent,
  dot-segment, and slash-ambiguity vectors was rejected by the patched matcher.
- Wrong-tenant download denial versus job expiry is distinguished only in the
  local mock by the post-test owner-control request; no third-party API was
  tested.
- The committed async-export module has a bounded loopback origin, but its
  lifecycle has not been validated against a real API. A response lost after
  resource creation remains an unknown possible orphan and requires operator
  cleanup.
- Existing authz matrix blind spots remain: cross-tenant job-status reads,
  multi-node revocation propagation, browser-only controls, GraphQL, share or
  transfer actions, and production/remote targets.
- Other clients that use `origin.port or 80` were reviewed. Their validators
  normalize `None` to port 80 and reject explicit zero before connection; the
  RT-2026-04 defect was limited to six validators that also used the truthiness
  expression for validation.
- SIFT basename correlation may be ambiguous or misleading; multiple distinct
  anomaly subjects intentionally fall back to tool-level grouping. This audit
  did not prove the added correlation changes a sealed verdict.
- Static review does not prove the absence of defects. Scope covered repository
  code, current dirty WIP, recent authorization modules, test isolation, and the
  prior documented timeline finding—not every dependency or deployed
  environment.

## Follow-up gates

1. Keep async-export results scoped to controlled loopback labs until the
   operator cleanup behavior and a separately authorized real API validation
   plan have been reviewed.
2. Treat the timeline fix as a correlation-candidate improvement, not a
   forensic conclusion; test ambiguous subject sets and representative real
   artifacts under a separately authorized validation plan before widening the
   claim.
