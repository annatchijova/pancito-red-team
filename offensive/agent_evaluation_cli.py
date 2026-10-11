"""CLI for evaluating a bounded, operator-supplied PANCITO tool trace."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from offensive.agent_evaluation import AgentEvaluationError, evaluate_agent_trace, scenario_catalog
from offensive.local_artifact import LocalArtifactError, read_bounded_regular_file


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", nargs="?", help="JSON trace file (regular file; max 1 MiB)")
    parser.add_argument("--catalog", action="store_true", help="print the fixed scenario catalog")
    args = parser.parse_args()
    if args.catalog:
        if args.trace:
            parser.error("TRACE cannot be combined with --catalog")
        print(json.dumps(scenario_catalog(), ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    if not args.trace:
        parser.error("TRACE is required unless --catalog is used")
    try:
        raw = read_bounded_regular_file(
            Path(args.trace), maximum_bytes=1_048_576, label="agent trace"
        )
        receipt = evaluate_agent_trace(raw)
    except (AgentEvaluationError, LocalArtifactError, OSError, ValueError) as exc:
        print(f"pancito-agent-evaluate: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
