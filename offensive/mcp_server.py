"""Curated MCP bridge for pancito-red-team — passive tools only, by construction.

Most of this project's offensive.*_cli tools actively execute real network
actions (BOLA probes, CORS/SSRF/GraphQL tests, file-ingress writes), gated
at the CLI layer to loopback targets named in a signed manifest. This
bridge does not expose any of them. It exposes only the two CLIs that are
passive, local-file analysis with no network action at all:

- offensive.openapi_cli  — triages an OpenAPI document against a manifest.
- offensive.purple_cli   — scores a Red receipt against Blue evidence.

This is the entry surface, not a convenience subset of a larger allowlist:
growing it to cover any offensive.*_cli requires a deliberate, separately
reviewed design for authorization and loopback enforcement at the MCP
layer (manifest-gating that mirrors what the CLI already requires of a
human operator) — not an edit to this file's tool list.

Both CLIs are invoked as subprocesses, never imported and re-driven in
-process: their own argument parsing, manifest validation, and bounded
file reading (offensive/local_artifact.py — no-follow, regular-file-only,
size-capped) are the real boundary, not duplicated here.

Inherited property, not introduced by this bridge: neither CLI confines
file reads to a specific directory (read_bounded_regular_file validates
shape — regular file, no symlink, size cap — not location). A path
argument can therefore name any regular file on disk the process can
read; the CLI will only accept it if it also parses as the expected JSON
shape (OpenAPI document / manifest / receipt / observation), and on
failure reports an error message, never the file content. This is true of
the CLI run directly by a human today; this bridge changes nothing about
it, and does not add its own directory confinement so as not to diverge
from the CLI's own tested contract.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Literal, Optional

from mcp.server.fastmcp import FastMCP

REPO_ROOT = Path(__file__).resolve().parent.parent
TIMEOUT_SECONDS = 30

PURPLE_CATEGORIES = Literal[
    "bola", "authn", "state-change", "file-ingress", "mass-assignment",
    "nested-bola", "stale-authority", "function-authz", "collection-authz",
    "scope-authz", "search-authz", "export-authz", "async-export-authz",
    "forwarded-redirect", "cors-misconfiguration", "graphql-introspection",
    "graphql-field-suggestion", "ssrf-outbound-fetch", "graphql-batching",
]

mcp = FastMCP("pancito-red-team")


def _run(args: list[str]) -> dict:
    """Run a CLI module as a subprocess and parse its stdout JSON. Never
    raises to the caller: a non-zero exit or non-JSON stdout degrades to an
    explicit error field carrying stderr, instead of crashing the tool call."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"{' '.join(args)} timed out after {TIMEOUT_SECONDS}s"}
    if proc.returncode != 0:
        return {
            "error": f"{' '.join(args)} exited {proc.returncode}",
            "stderr": proc.stderr.strip(),
        }
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": "CLI did not print JSON on stdout", "stdout": proc.stdout.strip()}


@mcp.tool()
def pancito_openapi_triage(
    openapi_path: str,
    manifest_path: str,
    select_bola: Optional[str] = None,
    select_authn: Optional[str] = None,
    select_state_change: Optional[str] = None,
    select_file_ingress: Optional[str] = None,
) -> dict:
    """Passively triage an authorized OpenAPI document against a strict
    triage-plan manifest. No network action — pure local-file analysis.
    Pass at most one select_* to get a single ranked candidate handoff
    instead of the full receipt."""
    args = ["offensive.openapi_cli", openapi_path, manifest_path]
    selects = {
        "--select": select_bola,
        "--select-authn": select_authn,
        "--select-state-change": select_state_change,
        "--select-file-ingress": select_file_ingress,
    }
    chosen = [(flag, val) for flag, val in selects.items() if val is not None]
    if len(chosen) > 1:
        return {"error": "pass at most one select_* argument"}
    if chosen:
        flag, val = chosen[0]
        args += [flag, val]
    return _run(args)


@mcp.tool()
def pancito_purple_evaluate(
    category: PURPLE_CATEGORIES,
    red_receipt_path: str,
    blue_observation_path: str,
) -> dict:
    """Evaluate one bounded Red experiment receipt against operator-supplied
    Blue detection evidence for the given vulnerability category. No
    network action — scores two already-produced local JSON files."""
    return _run(["offensive.purple_cli", category, red_receipt_path, blue_observation_path])


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
