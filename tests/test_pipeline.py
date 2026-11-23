import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from coaudit.pipeline import run_bundle
from coaudit.report import render_html

ROOT = Path(__file__).resolve().parents[1]


class PipelineTests(unittest.TestCase):
    def sample(self, number):
        return run_bundle(next((ROOT / "examples").glob(f"{number:02d}_*/bundle.json")))

    def test_twelve_integration_outcomes(self):
        expected = ["MODEL_PASS", "BLOCK", "BLOCK", "BLOCK", "MODEL_PASS", "REVIEW", "BLOCK", "REVIEW", "BLOCK", "REVIEW", "REVIEW", "BLOCK"]
        for i, decision in enumerate(expected, 1):
            with self.subTest(i=i):
                r = self.sample(i)
                self.assertNotEqual(r["input_status"], "INPUT_ERROR", r["input_errors"])
                self.assertEqual(r["decision"], decision)

    def test_permission_failure_retains_old_obligation(self):
        r = self.sample(2)
        core = r["domains"]["PROTOCOL_COVERAGE"]
        self.assertEqual(core["persistent_obligation_ids"], ["navigate-1"])
        self.assertEqual(core["correlated"]["verdicts"]["no_new_recovery_communication_regression"]["verdict"], "FAIL")

    def test_good_trace_does_not_hide_policy_regression(self):
        r = self.sample(2)
        self.assertEqual(r["domains"]["TRACE_OBLIGATION"]["verdict"], "PASS")
        self.assertEqual(r["decision"], "BLOCK")

    def test_both_service_roles_required(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.clone(temp)
            policy = path.parent / "after.policy.xml"
            policy.write_text(policy.read_text().replace('execute="ALLOW"', 'execute="DENY"'))
            r = run_bundle(path)
            self.assertEqual(r["decision"], "BLOCK")
            values = r["domains"]["PROTOCOL_COVERAGE"]["correlated"]["verdicts"]
            self.assertEqual(values["after_absolute_recovery_communication"]["verdict"], "FAIL")

    def clone(self, temp):
        dest = Path(temp) / "bundle"
        shutil.copytree(ROOT / "examples/01_healthy", dest)
        return dest / "bundle.json"

    def mutate(self, file, callback):
        data = json.loads(file.read_text(encoding="utf-8"))
        callback(data)
        file.write_text(json.dumps(data), encoding="utf-8")

    def test_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p = self.clone(temp)
            self.mutate(p, lambda d: d.update(contract="../secret.json"))
            r = run_bundle(p)
            self.assertEqual(r["input_status"], "INPUT_ERROR")

    def test_unknown_fields_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as temp:
            p = self.clone(temp)
            self.mutate(p.parent / "contract.json", lambda d: d["obligations"][0].update(remap="/wrong"))
            self.assertEqual(run_bundle(p)["input_status"], "INPUT_ERROR")

    def test_duplicate_json_key(self):
        with tempfile.TemporaryDirectory() as temp:
            p = self.clone(temp)
            p.write_text('{"schema_version":1,"schema_version":1}')
            self.assertEqual(run_bundle(p)["input_status"], "INPUT_ERROR")

    def test_missing_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            p = self.clone(temp)
            self.mutate(p.parent / "after.json", lambda d: d["nodes"].pop())
            self.assertEqual(run_bundle(p)["input_status"], "INPUT_ERROR")

    def test_no_trace_requires_review(self):
        with tempfile.TemporaryDirectory() as temp:
            p = self.clone(temp)
            self.mutate(p, lambda d: d.pop("trace"))
            self.assertEqual(run_bundle(p)["decision"], "REVIEW")

    def test_no_forbidden_queries_not_global_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            p = self.clone(temp)
            self.mutate(p.parent / "contract.json", lambda d: d.update(forbidden=[]))
            r = run_bundle(p)
            self.assertEqual(r["domains"]["AUTHORIZATION"]["verdict"], "UNKNOWN")
            self.assertEqual(r["decision"], "REVIEW")

    def test_fingerprint_changes_with_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            p = self.clone(temp)
            before = run_bundle(p)
            policy = p.parent / "after.policy.xml"
            policy.write_bytes(policy.read_bytes() + b"\n")
            after = run_bundle(p)
            self.assertNotEqual(before["evidence_sha256"], after["evidence_sha256"])
            self.assertEqual(after["domains"]["TRACE_OBLIGATION"]["reason"], "trace_scope_missing_or_mismatch")
            self.assertEqual(after["decision"], "REVIEW")

    def test_security_enable_is_case_sensitive(self):
        with tempfile.TemporaryDirectory() as temp:
            p = self.clone(temp)
            self.mutate(p.parent / "after.json", lambda d: d["security"].update(enable="TRUE"))
            r = run_bundle(p)
            self.assertEqual(r["domains"]["CONFIGURATION"]["after"]["verdict"], "FAIL")
            self.assertEqual(r["decision"], "BLOCK")

    def test_report_cannot_embed_input_script(self):
        r = self.sample(1)
        r["name"] = '</script><img src=x onerror="alert(1)">'
        page = render_html(r)
        self.assertNotIn('</script><img', page)
        self.assertIn('\\u003c/script', page)

    def test_cli_gate_and_normal_modes(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = next((ROOT / "examples").glob("02_*/bundle.json"))
            cmd = [sys.executable, "-B", "-X", "utf8", "-m", "coaudit", str(bundle), "--output", temp]
            p = subprocess.run(cmd, cwd=ROOT, capture_output=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            p = subprocess.run(cmd + ["--gate"], cwd=ROOT, capture_output=True)
            self.assertEqual(p.returncode, 1, p.stderr)
            self.assertTrue((Path(temp) / "index.html").is_file())

    def test_invalid_input_cli_exit_two(self):
        with tempfile.TemporaryDirectory() as temp:
            cmd = [sys.executable, "-B", "-m", "coaudit", str(Path(temp) / "missing.json"), "--output", str(Path(temp) / "out")]
            p = subprocess.run(cmd, cwd=ROOT, capture_output=True)
            self.assertEqual(p.returncode, 2, p.stderr)


if __name__ == "__main__":
    unittest.main()
