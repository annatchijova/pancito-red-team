"""The one invariant, enforced as a contract: an agent's tools give it no way
to pass a score, a state, or a hash.

AGENTS.md states it plainly: the deterministic core scores and *seals* the
result before any agent is called, and "an agent's tools give it no way to pass
a score, a state, or a hash — it may choose *what to investigate* and *put the
result into words*, nothing more." Today that holds by discipline and by
``test_determinism.py`` (which proves the seal is model-free). Nothing, however,
guarded the *shape* of the tool surface itself: a future tool could quietly add
a parameter through which the model hands back a verdict value, and every
existing test would stay green.

This module walks the complete, sealed tool surface — every agent and every
tool name in ``agent/registry.py``'s approved manifests — and checks two
properties of each parameter:

1. Structural (the real teeth): a tool parameter may be a scalar reference or
   free text (``str``/``int``/``bool``) or a list/tuple of those — a thing to
   investigate or words to record. It may never be a ``Mapping``/``dict`` or an
   arbitrary object, because that is the only way to hand over a *structured*
   ``{score, verdict_state, mitre_techniques, seal}`` payload. "No way to pass a
   score, a state, or a hash" is exactly "no structured verdict object crosses
   the tool boundary."
2. Nominal (a secondary net): no parameter name promises a verdict *value*.
   The blocklist is deliberately narrow — tokens that can only mean "a sealed
   value is being supplied" (score, verdict, seal, hash, a MALICE/BENIGN label,
   a MITRE mapping) — and deliberately excludes legitimate reference and
   working-memory words such as ``state`` (the mentor explains a verdict-state
   *definition*), ``status`` (a hypothesis is supported/refuted), and
   ``technique_id`` (a MITRE id looked up in read-only reference material).

The inventory is driven by the sealed registry, so a newly approved tool cannot
escape this guard: its manifest must change to load at all, and this test then
demands the new tool resolve and pass the contract.
"""

from __future__ import annotations

import inspect
import tempfile
import typing
from pathlib import Path

from agent.autonomy import commander_tools
from agent.consult_tools import ConsultTools
from agent.fleet import FLEET
from agent.registry import approved_registry
from agent.tools import PurpleTeamSession
from tools.velociraptor.adapter import MockTransport

REPO = Path(__file__).resolve().parent.parent

# Scalars a tool may legitimately accept: a reference ("which window") or the
# examiner-facing words a tool records. No float — the sealed core is exact
# arithmetic, and a tool has no numeric verdict input to offer.
_SCALARS = (str, int, bool)

# Tokens that can only denote a verdict *value* being supplied by the caller.
# Narrow on purpose: see the module docstring for why state/status/technique
# are NOT here.
_FORBIDDEN_NAME_TOKENS = (
    "score", "confidence", "verdict", "seal", "sealed",
    "hash", "sha256", "digest", "malice", "benign", "mitre",
)


def _session() -> PurpleTeamSession:
    """A replay-backed session — stdlib only, no ADK, no live transport."""
    return PurpleTeamSession(
        MockTransport(REPO / "offensive" / "fixtures" / "attack"),
        case_id="CONTRACT", host={"client_id": "C.1", "hostname": "H",
                                  "os": "windows"},
        examiner_id="op", out_dir=tempfile.mkdtemp(), source="replay",
        time_base="2026-08-12T14:10:00Z")


def _resolve_tools(session: PurpleTeamSession) -> dict[str, dict[str, object]]:
    """Map every agent name to {tool_name: callable}, built from the real
    factories without constructing an ADK Agent."""
    resolved: dict[str, dict[str, object]] = {}

    # Fleet specialists: each factory returns exactly that role's tools.
    for name, spec in FLEET.items():
        resolved[name] = {fn.__name__: fn for fn in spec["tools"](session)}

    # Commander: delegation and memory only; case/mission are closed over and
    # not touched until a tool is actually called, so empty dicts are fine here.
    resolved["fleet-commander"] = {
        fn.__name__: fn for fn in commander_tools(session, {}, {})}

    # Investigator and mentor expose bound methods; resolve by the names the
    # sealed manifest approves, so the inventory stays tied to the registry.
    resolved["vigia_purple_team"] = {"__provider__": session}
    resolved["vigia_mentor"] = {"__provider__": ConsultTools()}
    return resolved


def _agent_tools():
    """Yield (agent_name, tool_name, callable) for every approved tool."""
    session = _session()
    resolved = _resolve_tools(session)
    for entry in approved_registry():
        agent = entry["name"]
        bucket = resolved.get(agent)
        assert bucket is not None, (
            f"approved agent {agent!r} has no resolver in this test — wire it "
            f"in so its tools are contract-checked")
        provider = bucket.get("__provider__")
        for tool_name in entry["tools"]:
            if provider is not None:
                fn = getattr(provider, tool_name, None)
                assert fn is not None, (
                    f"approved tool {agent}.{tool_name} does not exist on its "
                    f"provider")
            else:
                fn = bucket.get(tool_name)
                assert fn is not None, (
                    f"approved tool {agent}.{tool_name} was not produced by its "
                    f"factory")
            yield agent, tool_name, fn


def _resolved_hints(fn) -> dict[str, object]:
    """Real types for a tool's parameters. The agent modules use
    ``from __future__ import annotations`` (PEP 563), so raw annotations are
    strings; get_type_hints resolves them against the function's own globals."""
    return typing.get_type_hints(fn)


def _annotation_is_reference_or_text(annotation: object) -> bool:
    """True iff the annotation is a scalar reference/text, or a list/tuple of
    those — never a mapping or an arbitrary structured object."""
    if annotation is None:
        return False  # an unannotated parameter could be anything; refuse it
    if annotation in _SCALARS:
        return True
    origin = typing.get_origin(annotation)
    if origin in (list, tuple):
        args = [a for a in typing.get_args(annotation) if a is not Ellipsis]
        return bool(args) and all(a in _SCALARS for a in args)
    return False


def test_every_approved_agent_tool_is_contract_checked():
    """Coverage guard: the registry's whole tool surface is reachable here, so
    the properties below are checked against all of it, not a subset."""
    tools = list(_agent_tools())
    approved = sum(len(e["tools"]) for e in approved_registry())
    assert len(tools) == approved
    assert approved >= 20  # the current fleet + investigator + commander + mentor


def test_no_tool_parameter_can_carry_a_structured_verdict():
    """No tool parameter may be a mapping or arbitrary object — only a scalar
    reference/text or a list of those. This is the structural form of 'no way
    to pass a score, a state, or a hash'."""
    offenders = []
    for agent, tool_name, fn in _agent_tools():
        hints = _resolved_hints(fn)
        for pname in inspect.signature(fn).parameters:
            if pname == "self":
                continue
            annotation = hints.get(pname)
            if not _annotation_is_reference_or_text(annotation):
                offenders.append(f"{agent}.{tool_name}({pname}: "
                                 f"{annotation!r})")
    assert not offenders, (
        "these tool parameters could carry a structured verdict payload: "
        + ", ".join(offenders))


def test_no_tool_parameter_name_promises_a_verdict_value():
    """A secondary net on intent: even as a plain string, a parameter named for
    a sealed value (score, verdict, seal, hash, a MALICE/BENIGN label, a MITRE
    mapping) would invite the model to supply what only the core may seal."""
    offenders = []
    for agent, tool_name, fn in _agent_tools():
        for pname in inspect.signature(fn).parameters:
            if pname == "self":
                continue
            low = pname.lower()
            hit = [tok for tok in _FORBIDDEN_NAME_TOKENS if tok in low]
            if hit:
                offenders.append(f"{agent}.{tool_name}({pname}) -> {hit}")
    assert not offenders, (
        "these tool parameter names promise a verdict value the model must not "
        "supply: " + ", ".join(offenders))
