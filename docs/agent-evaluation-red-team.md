# Offline agent evaluator: red-team notes

Date: 2026-10-11

## Scope and threat model

This review covers `offensive/agent_evaluation.py`, its trace builder, and the
CLI boundary that reads an operator-supplied trace. The findings RT-4 through
RT-6 were reproduced against `feat/agentdojo-atomic-curation` at
`6daf8d6cd92aec8b78ee9acd2cb49637ef24dd3a` before their fixes. An attacker may
influence values copied from an audit trail and may supply a serialized trace
to the evaluator. The reviewer does not assume control of the Python process,
trusted source code, or the verdict-chain implementation. The evaluator is an
offline receipt generator; it is not an execution boundary and does not
authenticate audit-trail provenance.

## Findings

### RT-1: Trace builder could allocate an oversized document before parsing

**Classification: CODE FACT; corrected.** The parser rejected serialized
traces larger than 1 MiB, but `build_agent_trace` previously assembled and
serialized the complete projected document before invoking that parser. With
512 actions and up to 512 hunt IDs per action, each up to 128 characters, the
builder could create a multi-megabyte intermediate value. This was reproduced
with an adversarial in-memory audit trail. The builder now tracks a conservative
serialized-size budget while projecting values and rejects projections above
900,000 bytes before final document serialization. It also bounds and validates
the scenario and final verdict claim, and validates sequence integers, before
serialization.

Regression coverage: `test_trace_builder_enforces_aggregate_size_before_serializing_document`
and `test_trace_builder_bounds_claim_before_serialization`.

### RT-2: Caller-supplied trace provenance and completeness are not proven

**Classification: CODE FACT; residual limitation.** The SHA-256 in the receipt
identifies the supplied bytes, but does not establish who produced them or
whether the caller omitted events. `trace_complete` is an operator assertion.
The receipt labels authentication as `unverified-operator-supplied-trace`, and
an incomplete trace yields an inconclusive security outcome. Consumers must not
treat this evaluator receipt as a custody-chain signature or as proof of agent
behavior absent an independently authenticated source.

### RT-3: A reported claim that differs from the latest sealed adjudication
is detected

**Classification: CONFIRMED BY INDUCTION.** The adversarial test supplies a
later sealed state that contradicts `final_claim`; evaluation reports
`CONTRADICTS_SEALED_VERDICT`, records `SEALED_VERDICT_CONTRADICTION`, and does
not mark the task satisfied. A controlled mutation that made the evaluator
always report a match caused this regression test to fail, confirming that the
assertion detects this defect class.

### RT-4: Earlier chain verification could cover a later adjudication

**Severity: Low. Epistemic level: CONFIRMED BY INDUCTION. Bucket: software
vulnerability in the trace evaluator.** Under the threat model where an
operator-supplied trace contains an additional sealed event, a trace containing a
successful adjudication, successful chain verification, then another sealed
adjudication for the same window was marked task-satisfied. The later sealed
entry had not yet been covered by a chain verification. The evaluator now
requires a successful verification after the latest sealed adjudication for
the collected window. Prediction: the unfixed evaluator would return
`TASK_SATISFIED`; induction: `test_chain_must_be_verified_after_latest_sealed_adjudication_for_window`
did so before the patch and now returns `TASK_NOT_SATISFIED`.

### RT-5: A single oversized retained field was copied before budget rejection

**Severity: Low. Epistemic level: CONFIRMED BY INDUCTION. Bucket: resource
exhaustion hardening.** Under the threat model where a caller passes an
untrusted, already allocated string through `audit_actions`, the builder
serialized a retained `window_id` to measure its size before applying the
aggregate budget. Prediction: an 8,000,000-character ID would produce a second
multi-megabyte allocation before rejection. A `tracemalloc` probe on the
unfixed `6daf8d6` source observed a peak of 8,000,327 traced bytes and then
`AgentEvaluationError`. The builder now rejects retained text above 128
characters before serializing it. The focused regression test asserts this
early-bound error; a mutation removing the guard made the test fail on the
different late budget error.

### RT-6: Oversized JSON integer leaked a parser implementation exception

**Severity: Low. Epistemic level: CONFIRMED BY INDUCTION. Bucket: input
validation defect.** Under the threat model where a caller supplies raw JSON,
a 5,000-digit integer in an otherwise well-formed trace escaped `evaluate_agent_trace`
as Python's raw `ValueError` instead of the public `AgentEvaluationError`.
Prediction: integrators catching the evaluator's documented exception would
not catch this malformed input. The reproduction returned `ValueError` and
`isinstance(exc, AgentEvaluationError) == False`. JSON parse `ValueError`s are
now normalized after the explicit `AgentEvaluationError` handler, and a
regression test pins the public error type.

### RT-7: A later sealed window escaped the final chain-verification check

**Severity: Low. Epistemic level: CONFIRMED BY INDUCTION. Bucket: software
vulnerability in workflow evaluation.** Under the threat model where a trace
contains multiple recorded windows, the evaluator accepted a completed and
verified first window, followed by another sealed adjudication with the same
state and no later chain verification. The earlier workflow still satisfied
the task, and the final claim matched the newer state. Prediction: the latest
sealed entry would lack a subsequent verification while the receipt said
`TASK_SATISFIED`; `test_later_sealed_window_invalidates_earlier_chain_verification`
reproduced that before the fix. Schema version 2 now exposes
`latest_sealed_chain_verified` and requires it to be `true` for task
satisfaction. A paired positive test confirms verification after the latest
window restores the satisfied result.

## Verification

Discarded vectors: bounded deeply nested JSON was rejected by the parser's
`RecursionError` handling; duplicate keys are rejected by the object hook;
neither produced a second confirmed issue. Trace authenticity remains an
explicit limitation (RT-2), because the wrapper has no authenticated source to
verify.

Test integrity: chain-order, cross-window freshness, and overlong-retained-text
cases were observed failing before their respective fixes. A hand mutation
removing the text bound made the targeted test fail. A mutation removing the
integer parse normalization made its test fail with raw `ValueError`. The
pre-change full suite was **981 passed, 6 skipped**; the post-change full suite
completed with **985 passed, 6 skipped**. These tests do not prove trace
provenance, real agent behavior, or that a trace is complete.
