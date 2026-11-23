"""Reproduce the independent finite-model check performed on 2026-11-12.

This checks abstract graph reasoning only. It does not connect to ROS, parse
DDS security artifacts, run a security scanner, or control a robot.
The oracle uses fixed-point reachability and exhaustive completions, without
calling the audit implementation's path/edge/aggregation helpers.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import random
import sys


SEED = 20261112
CASE_COUNT = 1000
WORKSPACE = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True


def exact_reachable(edges, assignment, allowed, start="A", target="D"):
    """Independent fixed-point oracle for one fully completed assignment."""
    reached = {start}
    changed = True
    while changed:
        changed = False
        for edge in edges:
            enabled = (
                all(key in assignment
                    and type(assignment[key]) is type(value)
                    and assignment[key] == value
                    for key, value in edge["when"].items())
                and all(capability in allowed for capability in edge["requires"])
            )
            if enabled and edge["from"] in reached and edge["to"] not in reached:
                reached.add(edge["to"])
                changed = True
    return target in reached


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prototype", type=Path,
        default=WORKSPACE / "outputs" / "ROS2联合安全审计研究方案" / "prototype",
    )
    parser.add_argument(
        "--output", type=Path,
        default=Path(__file__).with_name("security_audit_independent_result.json"),
    )
    args = parser.parse_args()
    prototype = args.prototype.resolve()
    source = prototype / "audit.py"
    spec = importlib.util.spec_from_file_location("independently_reviewed_audit", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rng = random.Random(SEED)
    definite = 0
    completion_count = 0
    errors = []
    case_digest = hashlib.sha256()

    # This preserves the exact RNG calls and order of the earlier in-memory run.
    for case_index in range(CASE_COUNT):
        statuses = {capability: rng.choice(["yes", "no", "unknown"])
                    for capability in "abc"}
        known_domain = [capability for capability, state in statuses.items()
                        if state != "unknown"]
        known_allowed = [capability for capability, state in statuses.items()
                         if state == "yes"]
        assignment = {} if rng.choice([0, 1]) else {"mode": rng.choice(["X", "Y"])}
        edges = []
        for index in range(7):
            edges.append({
                "id": str(index), "from": rng.choice("ABCD"),
                "to": rng.choice("ABCD"),
                "requires": [capability for capability in "abc" if rng.random() < .3],
                "when": {} if rng.random() < .5 else {"mode": rng.choice(["X", "Y"])},
            })
        world = {
            "id": "one", "assignment": assignment,
            "capability_domain": known_domain,
            "allowed": known_allowed, "complete": True,
        }
        obligation = {"id": "old", "start": "A", "targets": ["D"], "admitted_before": True}
        case_digest.update(json.dumps(
            {"world": world, "edges": edges, "obligation": obligation},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8"))
        case_digest.update(b"\n")
        actual = module.evaluate_world(world, edges, [obligation])["value"]
        unknown = [capability for capability, state in statuses.items() if state == "unknown"]
        truth = set()
        for bits in itertools.product([False, True], repeat=len(unknown)):
            allowed = set(known_allowed) | {capability for capability, bit in zip(unknown, bits) if bit}
            for mode in [assignment["mode"]] if assignment else ["X", "Y"]:
                truth.add(exact_reachable(edges, {"mode": mode}, allowed))
                completion_count += 1
        if actual is not None:
            definite += 1
            if truth != {actual}:
                errors.append({
                    "case": case_index, "actual": actual, "oracle_values": sorted(truth),
                    "world": world, "edges": edges,
                })

    regressions = {}
    fixture_hashes = {}
    for prefix, name, expected in [
        ("03", "persistent_obligation_after_new_admission_denial", ["PASS", "FAIL", "FAIL"]),
        ("09", "preexisting_failure_does_not_mask_another_regression", ["FAIL", "FAIL", "FAIL"]),
    ]:
        path = next((prototype / "fixtures").glob(prefix + "*.json"))
        fixture_hashes[path.name] = sha256(path)
        result = module.audit(json.loads(path.read_text(encoding="utf-8")))
        actual = [result["correlated"]["verdicts"][key]["verdict"]
                  for key in module.PROPERTY_NAMES]
        regressions[name] = {"expected": expected, "actual": actual, "passed": actual == expected}

    passed = not errors and all(check["passed"] for check in regressions.values())
    output = {
        "result": "PASS" if passed else "FAIL",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "random_seed": SEED,
        "independent_random_graph_cases": CASE_COUNT,
        "definite_verdicts_checked_against_all_completions": definite,
        "unknown_verdicts": CASE_COUNT - definite,
        "fully_completed_oracle_cases": completion_count,
        "errors": len(errors),
        "counterexamples": errors[:5],
        "regressions": regressions,
        "generated_cases_sha256": case_digest.hexdigest(),
        "files_sha256": {
            "audit.py": sha256(source),
            "independent_check.py": sha256(Path(__file__)),
            **fixture_hashes,
        },
        "scope": "Offline abstract finite models only; no ROS/DDS/security/robot execution.",
        "limits": [
            "Random finite checks are not a general soundness proof or a research superiority result.",
            "This oracle checks evaluate_world definite verdicts against all selected finite completions.",
            "The two regression fixtures check persistent and per-task obligations, not every audit interface.",
            "No claim that UNKNOWN is always maximally precise; conservative UNKNOWN is permitted.",
            "Declared shared-binding evidence is not authenticated by this check.",
        ],
        "reproduce": "python -B -X utf8 validation/independent_check.py --prototype prototype --output validation/independent_result.json",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "result": output["result"], "cases": CASE_COUNT, "definite": definite,
        "unknown": CASE_COUNT - definite, "errors": len(errors),
        "output": str(args.output.resolve()),
    }, ensure_ascii=False))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
