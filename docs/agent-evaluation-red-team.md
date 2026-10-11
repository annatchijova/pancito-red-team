# Offline agent evaluator: red-team notes

Date: 2026-10-11

## Scope and threat model

This review covers `offensive/agent_evaluation.py` and its trace builder. An
attacker may influence values copied from an audit trail and may supply a
serialized trace to the evaluator. The reviewer does not assume control of the
Python process, trusted source code, or the verdict-chain implementation. The
evaluator is an offline receipt generator; it is not an execution boundary and
does not authenticate audit-trail provenance.

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

## Verification

The focused evaluator tests and complete repository suite are recorded with the
commit that adds this report. These tests cover the fixed schema, v1
compatibility, separate utility/security outcomes, claim contradiction,
ordering of chain verification, scope violations, projection of untrusted
detail, oversized inputs, and malformed headers.
