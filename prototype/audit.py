"""Offline finite-model example; not a ROS/DDS parser or security scanner."""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any


SCHEMA_VERSION = 1
PROPERTY_NAMES = (
    "before_absolute_recovery_communication",
    "after_absolute_recovery_communication",
    "no_new_recovery_communication_regression",
)
LIMITS = [
    "Synthetic normalized authorization atoms and finite protocol graphs only.",
    "No ROS connection, launch execution, DDS/XML parsing, network scanning, or policy deployment.",
    "Shared-binding digests are declared assumptions, not verified artifact hashes.",
    "Paths establish authorized communication prerequisites, not delivery, liveness, deadlines, or physical safety.",
    "A path may differ per world; this is not proof of one executable strategy for all worlds.",
    "Trace obligations and real runtime enforcement are not implemented.",
]


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _strings(value: Any, nonempty: bool = False) -> bool:
    return (isinstance(value, list) and (bool(value) or not nonempty)
            and all(_nonempty_string(item) for item in value)
            and len(value) == len(set(value)))


def _scalar(value: Any) -> bool:
    if isinstance(value, float):
        return math.isfinite(value)
    return value is None or isinstance(value, (str, int, bool))


def _reject_json_constant(token: str) -> None:
    raise ValueError(f"Non-standard JSON constant is not supported: {token}")


def validate(model: Any) -> list[str]:
    """Reject ambiguous or vacuous normalized models before evaluation."""
    errors: list[str] = []
    if not isinstance(model, dict):
        return ["Model must be a JSON object."]
    if type(model.get("schema_version")) is not int or model["schema_version"] != 1:
        errors.append("schema_version must be integer 1.")
    for version in ("before", "after"):
        data = model.get(version)
        if not isinstance(data, dict):
            errors.append(f"{version} must be an object.")
            continue
        worlds = data.get("worlds")
        if not isinstance(worlds, list) or not worlds:
            errors.append(f"{version}.worlds must be nonempty.")
        else:
            ids: set[str] = set()
            for index, world in enumerate(worlds):
                prefix = f"{version}.worlds[{index}]"
                if not isinstance(world, dict):
                    errors.append(f"{prefix} must be an object.")
                    continue
                wid = world.get("id")
                if not _nonempty_string(wid) or wid in ids:
                    errors.append(f"{prefix}.id must be nonempty and unique.")
                else:
                    ids.add(wid)
                assignment = world.get("assignment")
                if (not isinstance(assignment, dict)
                        or not all(_nonempty_string(k) and _scalar(v) for k, v in assignment.items())):
                    errors.append(f"{prefix}.assignment must map strings to scalar values.")
                for field in ("capability_domain", "allowed"):
                    if not _strings(world.get(field)):
                        errors.append(f"{prefix}.{field} must be a unique string list.")
                if _strings(world.get("capability_domain")) and _strings(world.get("allowed")):
                    if not set(world["allowed"]) <= set(world["capability_domain"]):
                        errors.append(f"{prefix}.allowed must be contained in capability_domain.")
                if type(world.get("complete")) is not bool:
                    errors.append(f"{prefix}.complete must be boolean.")
                if "admit_new_goal" in world and type(world["admit_new_goal"]) is not bool:
                    errors.append(f"{prefix}.admit_new_goal must be boolean if present.")
        edges = data.get("edges")
        if not isinstance(edges, list):
            errors.append(f"{version}.edges must be a list.")
        else:
            ids = set()
            for index, edge in enumerate(edges):
                prefix = f"{version}.edges[{index}]"
                if not isinstance(edge, dict):
                    errors.append(f"{prefix} must be an object.")
                    continue
                eid = edge.get("id")
                if not _nonempty_string(eid) or eid in ids:
                    errors.append(f"{prefix}.id must be nonempty and unique.")
                else:
                    ids.add(eid)
                if not all(_nonempty_string(edge.get(k)) for k in ("from", "to")):
                    errors.append(f"{prefix}.from and .to must be nonempty strings.")
                if not _strings(edge.get("requires")):
                    errors.append(f"{prefix}.requires must be a unique string list.")
                guard = edge.get("when")
                if (not isinstance(guard, dict)
                        or not all(_nonempty_string(k) and _scalar(v) for k, v in guard.items())):
                    errors.append(f"{prefix}.when must map strings to scalar values.")
    obligations = model.get("obligations")
    if not isinstance(obligations, list) or not obligations:
        errors.append("obligations must be nonempty; empty obligations cannot pass vacuously.")
    else:
        ids = set()
        for index, obligation in enumerate(obligations):
            prefix = f"obligations[{index}]"
            if not isinstance(obligation, dict):
                errors.append(f"{prefix} must be an object.")
                continue
            oid = obligation.get("id")
            if not _nonempty_string(oid) or oid in ids:
                errors.append(f"{prefix}.id must be nonempty and unique.")
            else:
                ids.add(oid)
            if not _nonempty_string(obligation.get("start")) or not _strings(obligation.get("targets"), True):
                errors.append(f"{prefix} requires a start and nonempty unique targets.")
            if obligation.get("admitted_before") is not True:
                errors.append(f"{prefix}.admitted_before must be true for this persistent-obligation example.")
    relations = model.get("shared_bindings", [])
    if not isinstance(relations, list) or not all(isinstance(r, dict) for r in relations):
        errors.append("shared_bindings must be a list of objects.")
    else:
        variables: set[str] = set()
        for relation in relations:
            variable = relation.get("variable")
            if _nonempty_string(variable):
                if variable in variables:
                    errors.append(f"shared_bindings has duplicate declarations for variable: {variable}")
                variables.add(variable)
    return errors


def _and(values: list[bool | None]) -> bool | None:
    if False in values:
        return False
    return None if None in values else True


def _same_value(left: Any, right: Any) -> bool:
    # Avoid Python's True == 1 ambiguity for typed JSON configuration variables.
    return type(left) is type(right) and left == right


def _edge_state(edge: dict, world: dict) -> tuple[bool | None, list[str]]:
    checks: list[bool | None] = []
    reasons: list[str] = []
    for variable, expected in edge["when"].items():
        if variable not in world["assignment"]:
            checks.append(None)
            reasons.append(f"unknown guard variable: {variable}")
        else:
            matches = _same_value(world["assignment"][variable], expected)
            checks.append(matches)
            if not matches:
                reasons.append(f"guard mismatch: {variable}")
    for capability in edge["requires"]:
        if capability in world["allowed"]:
            checks.append(True)
        elif capability not in world["capability_domain"] or not world["complete"]:
            checks.append(None)
            reasons.append(f"unknown capability: {capability}")
        else:
            checks.append(False)
            reasons.append(f"denied capability: {capability}")
    return _and(checks), reasons


def _path(start: str, targets: list[str], edges: list[dict]) -> list[str] | None:
    queue = deque([(start, [])])
    seen = {start}
    while queue:
        node, path = queue.popleft()
        if node in targets:
            return path
        for edge in edges:
            if edge["from"] == node and edge["to"] not in seen:
                seen.add(edge["to"])
                queue.append((edge["to"], path + [edge["id"]]))
    return None


def evaluate_world(world: dict, edges: list[dict], obligations: list[dict]) -> dict:
    edge_states = []
    for edge in edges:
        value, reasons = _edge_state(edge, world)
        edge_states.append({"edge_id": edge["id"], "value": value, "reasons": reasons})
    definite = [edge for edge, state in zip(edges, edge_states) if state["value"] is True]
    possible = [edge for edge, state in zip(edges, edge_states) if state["value"] is not False]
    evaluations = []
    for obligation in obligations:
        path = _path(obligation["start"], obligation["targets"], definite)
        possible_path = _path(obligation["start"], obligation["targets"], possible)
        value = True if path is not None else False if possible_path is None else None
        evaluations.append({
            "obligation_id": obligation["id"], "value": value,
            "authorized_path": path, "possible_path": possible_path,
        })
    return {
        "world_id": world["id"], "assignment": world["assignment"],
        "admit_new_goal_metadata": world.get("admit_new_goal"),
        "value": _and([item["value"] for item in evaluations]),
        "obligations": evaluations, "edges": edge_states,
    }


def _possibilities(value: bool | None) -> list[bool]:
    return [False, True] if value is None else [value]


def verdict(values: list[bool | None], force_reason: str | None = None) -> dict:
    if force_reason or not values:
        return {"verdict": "UNKNOWN", "reason": force_reason or "no_cases", "cases": len(values)}
    possibilities = {p for value in values for p in _possibilities(value)}
    if possibilities == {True}:
        result, reason = "PASS", "all_cases_true"
    elif possibilities == {False}:
        result, reason = "FAIL", "all_cases_false"
    else:
        result, reason = "UNKNOWN", "incomplete" if None in values else "conditional"
    return {"verdict": result, "reason": reason, "cases": len(values)}


def _no_regression(before: bool | None, after: bool | None) -> bool | None:
    results = {not (b and not a) for b in _possibilities(before) for a in _possibilities(after)}
    return next(iter(results)) if len(results) == 1 else None


def _shared_relations(model: dict) -> tuple[list[dict], list[dict]]:
    applied, ignored = [], []
    for relation in model.get("shared_bindings", []):
        reason = None
        variable = relation.get("variable")
        if not _nonempty_string(variable):
            reason = "missing_variable"
        elif relation.get("relation") != "declared_unchanged":
            reason = "unsupported_relation"
        elif not _nonempty_string(relation.get("basis_ref")):
            reason = "missing_basis"
        elif (not isinstance(relation.get("before_digest"), str)
              or re.fullmatch(r"[0-9a-fA-F]{64}", relation["before_digest"]) is None
              or relation["before_digest"] != relation.get("after_digest")):
            reason = "digest_missing_invalid_or_changed"
        elif (not _nonempty_string(relation.get("before_context"))
              or relation["before_context"] != relation.get("after_context")):
            reason = "context_missing_or_changed"
        elif any(variable not in w["assignment"] for v in ("before", "after") for w in model[v]["worlds"]):
            reason = "unresolved_assignment"
        if reason:
            ignored.append({"evidence": relation, "reason": reason})
        else:
            applied.append(relation)
    return applied, ignored


def _analysis(before: list[dict], after: list[dict], pairs: list[tuple[dict, dict]],
              force_reason: str | None = None) -> dict:
    cases = []
    for b, a in pairs:
        after_obligations = {o["obligation_id"]: o for o in a["obligations"]}
        obligation_pairs = []
        for old in b["obligations"]:
            new = after_obligations[old["obligation_id"]]
            obligation_pairs.append({
                "obligation_id": old["obligation_id"], "before_value": old["value"],
                "after_value": new["value"],
                "no_new_regression": _no_regression(old["value"], new["value"]),
            })
        cases.append({"before_world": b["world_id"], "after_world": a["world_id"],
                      "before_value": b["value"], "after_value": a["value"],
                      "obligations": obligation_pairs,
                      "no_new_regression": _and([o["no_new_regression"] for o in obligation_pairs])})
    return {
        "verdicts": {
            PROPERTY_NAMES[0]: verdict([w["value"] for w in before], force_reason),
            PROPERTY_NAMES[1]: verdict([w["value"] for w in after], force_reason),
            PROPERTY_NAMES[2]: verdict([p["no_new_regression"] for p in cases], force_reason),
        },
        "pairs": cases,
    }


def audit(model: Any) -> dict:
    errors = validate(model)
    result = {
        "schema_version": SCHEMA_VERSION,
        "name": model.get("name", "unnamed") if isinstance(model, dict) else "invalid",
        "input_status": "VALID", "input_errors": errors, "limitations": LIMITS,
        "model_sha256": hashlib.sha256(json.dumps(model, sort_keys=True, ensure_ascii=False,
                                                  separators=(",", ":")).encode("utf-8")).hexdigest(),
        "evidence_scope": "declared synthetic finite model; no external artifact verification",
    }
    if errors:
        result.update(input_status="INPUT_ERROR", correlated=_analysis([], [], [], "input_error"),
                      independent_baseline=_analysis([], [], [], "input_error"))
        return result
    evaluations = {version: [evaluate_world(w, model[version]["edges"], model["obligations"])
                            for w in model[version]["worlds"]] for version in ("before", "after")}
    before, after = evaluations["before"], evaluations["after"]
    applied, ignored = _shared_relations(model)
    independent = [(b, a) for b in before for a in after]
    pairs = [(b, a) for b, a in independent if all(
        _same_value(b["assignment"][r["variable"]], a["assignment"][r["variable"]]) for r in applied)]
    unmatched_before = sorted({w["world_id"] for w in before} - {b["world_id"] for b, _ in pairs})
    unmatched_after = sorted({w["world_id"] for w in after} - {a["world_id"] for _, a in pairs})
    if not pairs or unmatched_before or unmatched_after:
        result["input_status"] = "INPUT_ERROR"
        result["input_errors"].append("Shared relation leaves no pairs or drops declared worlds; refusing vacuous/partial PASS.")
    elif any(edge["value"] is None for version in evaluations.values() for world in version for edge in world["edges"]):
        result["input_status"] = "INCOMPLETE"
    result.update(
        persistent_obligation_ids=[item["id"] for item in model["obligations"]],
        shared_bindings={"applied": applied, "ignored": ignored},
        world_evaluations=evaluations,
        unmatched_worlds={"before": unmatched_before, "after": unmatched_after},
        correlated=_analysis(before, after, pairs, "input_error" if result["input_status"] == "INPUT_ERROR" else None),
        independent_baseline=_analysis(before, after, independent,
                                       "input_error" if result["input_status"] == "INPUT_ERROR" else None),
    )
    if model.get("include_unsound_union_demo") is True:
        demo = {}
        for version in ("before", "after"):
            may_ids = {edge["edge_id"] for world in evaluations[version] for edge in world["edges"]
                       if edge["value"] is not False}
            edges = [edge for edge in model[version]["edges"] if edge["id"] in may_ids]
            demo[version] = [{"obligation_id": obligation["id"],
                              "union_path": _path(obligation["start"], obligation["targets"], edges)}
                             for obligation in model["obligations"]]
        result["unsound_union_demonstration"] = {"warning": "Intentionally unsound: never use as an audit verdict.",
                                                "versions": demo}
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=Path(__file__).parent / "fixtures")
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "results" / "audit_results.json")
    args = parser.parse_args()
    files = sorted(args.fixtures.glob("*.json"))
    if not files:
        parser.error("no JSON fixtures found")
    results = []
    for path in files:
        try:
            model = json.loads(path.read_text(encoding="utf-8-sig"), parse_constant=_reject_json_constant)
            item = audit(model)
        except (OSError, UnicodeError, ValueError) as exc:
            item = audit(None)
            item.update(name=path.stem, input_errors=[str(exc)])
        item["source_fixture"] = path.name
        results.append(item)
    output = {"schema_version": 1, "scope": "synthetic algorithm demonstration", "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for result in results:
        verdicts = result.get("correlated", {}).get("verdicts", {})
        label = ", ".join(f"{key}={value['verdict']}" for key, value in verdicts.items())
        print(f"{result['name']}: {result['input_status']} {label}")
    print(f"Wrote {len(results)} results to {args.output}")
    return 2 if any(item["input_status"] == "INPUT_ERROR" for item in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
