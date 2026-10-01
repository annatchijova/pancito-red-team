# SIFT timeline composition audit

**Date:** 2026-10-01  
**Method:** abductive engineering and adversarial induction  
**Vulnerable base:** `main` at `209db4d`; no timeline fix was present  
**Epistemic result:** `FALSIFIED` prediction / confirmed detection gap under the
stated threat model

## Threat model

- The attacker can cause the same process identity to appear in Memory and MFT
  evidence with a causal separation greater than five minutes.
- The attacker cannot modify PANCITO, SIFT, the experiment, or its ground truth.
- The crossed boundary is the summary contract between SIFT evidence producers
  and `UnifiedTimelineEngine`.

## Finding

**Bucket:** software defect / Blue detection gap  
**Severity:** unrated; downstream impact on a sealed verdict was not tested

### Abduction

The timeline groups events by `pid`, `filename`, IP, or a tool-name fallback.
The production Memory and MFT summaries appeared not to expose a shared entity,
so evidence about the same executable could enter different groups.

Rival explanations were:

1. the causal rule itself was inactive;
2. missing-source detection was inactive; or
3. the rules worked, but production summaries lost correlation identity.

### Prediction

A hand-shaped Memory/MFT pair with the same filename will produce
`CAUSAL_INVERSION`. A Memory-only signal will produce `MEMORY_WITHOUT_DISK`.
The same conceptual pair emitted through `MemoryAnalysisResult.to_signal()` and
`MFTAnalysisResult.to_signal()` will miss `CAUSAL_INVERSION` if producer
metadata loses identity.

### Induction

Run:

```bash
python3 -m offensive.timeline_evasion_cli \
  examples/timeline-evasion.synthetic.json
```

Observed:

| Cell | Expected | Observed | Result |
|---|---|---|---|
| `CONTROL_SHARED_ENTITY` | `CAUSAL_INVERSION` | `CAUSAL_INVERSION` | `DETECTED` |
| `MISSING_MFT` | `MEMORY_WITHOUT_DISK` | `MEMORY_WITHOUT_DISK` | `DETECTED` |
| `PRODUCTION_SHAPED_PAIR` | `CAUSAL_INVERSION` | `MEMORY_WITHOUT_DISK` | `MISSED` |

The production pair became `tool:MEMORY_FORENSICS` and `tool:MFT_ANALYZER`,
both at timestamp `0`. The experiment therefore falsified the prediction that
the current producer contracts preserve enough identity for causal
correlation. It did not test or claim that an attacker can alter a seal.

## Reproducibility

- Python: 3.12.3
- Pydantic: 2.13.4
- Fixture SHA-256:
  `b924baa5da8e77c4ace4e84ba9b791cb247d0a99b98c2ebfc68fdcbc66a9a098`
- Exact tests:
  `python3 -m pytest tests/test_timeline_evasion.py tests/test_timeline_evasion_cli.py -q`
- The receipt is deterministic across fresh processes with different
  `PYTHONHASHSEED` values.

## Discarded vectors

| Vector | Result | Why |
|---|---|---|
| Causal rule absent | Falsified | The shared-entity control triggered it. |
| Missing-source rule inactive | Falsified | The Memory-only control triggered it. |

## Known blind spots

The experiment does not use a real memory image or `$MFT`, does not prove that
all SIFT producer pairs lose identity, and does not measure whether this missed
correlation changes the sealed adjudication path. Those remain separate
hypotheses.

