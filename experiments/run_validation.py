"""Reproduce fixed scenario assertions, test suites, and the finite graph oracle."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
from time import perf_counter_ns

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from coaudit.pipeline import run_bundle

FIELDS = ("configuration_after", "migration", "authorization_after", "coverage_before",
          "coverage_after", "no_regression", "trace", "decision")
P, F, U = "PASS", "FAIL", "UNKNOWN"
M, B, R = "MODEL_PASS", "BLOCK", "REVIEW"
EXPECTED = {
    "01_healthy": (P, P, P, P, P, P, P, M),
    "02_cancel_removed": (P, P, P, P, F, F, P, B),
    "03_forbidden_grant": (P, P, F, P, P, P, P, B),
    "04_security_disabled": (F, P, P, P, P, P, P, B),
    "05_approved_fallback": (P, P, P, P, P, P, P, M),
    "06_unsupported_policy": (P, P, U, P, U, U, P, R),
    "07_missing_terminal": (P, P, P, P, P, P, F, B),
    "08_truncated_trace": (P, P, P, P, P, P, U, R),
    "09_late_terminal": (P, P, P, P, P, P, F, B),
    "10_context_changed": (P, U, P, P, P, P, P, R),
    "11_unknown_fallback": (P, P, P, P, U, U, P, R),
    "12_wrong_goal_terminal": (P, P, P, P, P, P, F, B),
}


def select(result):
    d = result["domains"]
    cfg = d["CONFIGURATION"]
    coverage = d["PROTOCOL_COVERAGE"]["correlated"]["verdicts"]
    return (
        cfg["after"]["verdict"], cfg["migration"]["verdict"], d["AUTHORIZATION"]["verdict"],
        coverage["before_absolute_recovery_communication"]["verdict"],
        coverage["after_absolute_recovery_communication"]["verdict"],
        coverage["no_new_recovery_communication_regression"]["verdict"],
        d["TRACE_OBLIGATION"]["verdict"], result["decision"],
    )


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_command(log_dir, name, arguments):
    proc = subprocess.run([sys.executable, "-B", "-X", "utf8", *arguments], cwd=ROOT,
                          capture_output=True, text=True, encoding="utf-8")
    combined = proc.stdout + proc.stderr
    (log_dir / (name + ".txt")).write_text(combined, encoding="utf-8")
    match = re.search(r"Ran (\d+) tests?", combined)
    return {"command": ["python", "-B", "-X", "utf8", *arguments],
            "exit": proc.returncode, "tests": int(match[1]) if match else None,
            "log": f"validation/logs/{name}.txt"}


def timing(samples):
    ordered = sorted(samples)
    return {"n": len(ordered), "median_ms": round(statistics.median(ordered), 3),
            "p95_ms": round(ordered[(95 * len(ordered) + 99) // 100 - 1], 3)}


def main():
    log_dir = ROOT / "validation/logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    jobs = {
        "v1_tests": ["-m", "unittest", "discover", "-s", "tests", "-v"],
        "core_tests": ["-m", "unittest", "discover", "-s", "prototype/tests", "-v"],
        "core_fixtures": ["-m", "prototype.audit", "--fixtures", "prototype/fixtures",
                          "--output", "prototype/results/audit_results.json"],
        "oracle": ["validation/independent_check.py", "--prototype", "prototype",
                   "--output", "validation/independent_result.json"],
        "demo": ["run_demo.py", "--output", "runs/demo"],
    }
    commands = {name: run_command(log_dir, name, cmd) for name, cmd in jobs.items()}
    bundles = {p.parent.name: p for p in ROOT.glob("examples/*/bundle.json")}
    if set(bundles) != set(EXPECTED):
        raise SystemExit("Scenario inventory differs from the fixed expectations.")
    cases, pooled = [], []
    for key, expected in EXPECTED.items():
        result = run_bundle(bundles[key])
        actual = select(result)
        times = []
        for _ in range(30):
            start = perf_counter_ns()
            observed = run_bundle(bundles[key])
            times.append((perf_counter_ns() - start) / 1_000_000)
            if observed != result:
                raise SystemExit(f"{key}: repeated results differ")
        pooled.extend(times)
        destination = ROOT / "runs" / "demo" / key / "result.json"
        same_cli = destination.is_file() and json.loads(destination.read_text(encoding="utf-8")) == result
        emitted = (destination.parent / "index.html").read_text(encoding="utf-8")
        match = re.search(r'<script id="audit-data" type="application/json">(.*?)</script>', emitted, re.S)
        same_html = match is not None and json.loads(match[1]) == result
        evidence_matches = all(digest(bundles[key].parent / row["path"]) == row["sha256"]
                               for row in result["evidence"])
        cases.append({"id": key, "name": result["name"], "input_status": result["input_status"],
                      "expected": dict(zip(FIELDS, expected)), "actual": dict(zip(FIELDS, actual)),
                      "same_demo_json": same_cli, "same_embedded_html_json": same_html,
                      "evidence_hashes_match": evidence_matches,
                      "trace_reason": result["domains"]["TRACE_OBLIGATION"]["reason"],
                      "timing": timing(times),
                      "output": destination.relative_to(ROOT).as_posix(),
                      "passed": actual == expected and same_cli and same_html and evidence_matches})
    checked_files = sorted(p for p in ROOT.rglob("*") if p.is_file() and (
        p.suffix == ".py" or p.relative_to(ROOT).parts[0] == "examples"))
    oracle = json.loads((ROOT / "validation/independent_result.json").read_text(encoding="utf-8"))
    passed = all(x["exit"] == 0 for x in commands.values()) and all(c["passed"] for c in cases)
    record = {"result": "PASS" if passed else "FAIL",
              "utc": datetime.now(timezone.utc).isoformat(),
              "python": platform.python_version(), "platform": platform.platform(),
              "commands": commands, "cases": cases,
              "decision_counts": dict(Counter(c["actual"]["decision"] for c in cases)),
              "timing": {**timing(pooled), "scope": "warm local bundle reads+audit only; no report rendering or ROS"},
              "oracle": oracle, "source_sha256": {p.relative_to(ROOT).as_posix(): digest(p) for p in checked_files}}
    (ROOT / "validation/full_validation.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": record["result"], "case_count": len(cases),
                      "decisions": record["decision_counts"], "timing": record["timing"],
                      "v1_tests": commands["v1_tests"]["tests"], "core_tests": commands["core_tests"]["tests"]},
                     ensure_ascii=False, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
