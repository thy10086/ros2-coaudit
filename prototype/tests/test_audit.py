"""Behavioral counterexamples and a small exhaustive independent Boolean oracle."""
import copy
import itertools
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from audit import audit, PROPERTY_NAMES  # noqa: E402


def fixture(prefix):
    return json.loads(next((ROOT / "fixtures").glob(prefix + "*.json")).read_text(encoding="utf-8"))


def labels(result, method="correlated"):
    return [result[method]["verdicts"][key]["verdict"] for key in PROPERTY_NAMES]


class FiniteAuditTests(unittest.TestCase):
    def assert_input_error(self, model):
        result = audit(model)
        self.assertEqual(result["input_status"], "INPUT_ERROR")
        self.assertTrue(result["input_errors"])
        self.assertEqual(labels(result), ["UNKNOWN"] * 3)
        self.assertEqual(labels(result, "independent_baseline"), ["UNKNOWN"] * 3)

    def test_all_nine_documented_fixtures(self):
        paths = sorted((ROOT / "fixtures").glob("*.json"))
        self.assertEqual(len(paths), 9)
        for path in paths:
            with self.subTest(fixture=path.name):
                model = json.loads(path.read_text(encoding="utf-8"))
                result = audit(model)
                for method, expected in model["expected_verdicts"].items():
                    self.assertEqual(labels(result, method), expected)

    def test_shared_binding_reduces_pairs_without_fixing_absolute_problem(self):
        result = audit(fixture("01"))
        self.assertEqual(len(result["correlated"]["pairs"]), 2)
        self.assertEqual(len(result["independent_baseline"]["pairs"]), 4)
        self.assertEqual(labels(result), ["UNKNOWN", "UNKNOWN", "PASS"])
        self.assertEqual(result["independent_baseline"]["verdicts"][PROPERTY_NAMES[2]]["reason"], "conditional")

    def test_same_variable_names_do_not_establish_correlation(self):
        result = audit(fixture("05"))
        self.assertEqual(len(result["correlated"]["pairs"]), 4)
        self.assertEqual(labels(result)[2], "UNKNOWN")

    def test_missing_basis_disables_relation(self):
        model = fixture("01")
        model["shared_bindings"][0].pop("basis_ref")
        result = audit(model)
        self.assertEqual(labels(result)[2], "UNKNOWN")
        self.assertEqual(result["shared_bindings"]["ignored"][0]["reason"], "missing_basis")

    def test_changed_digest_disables_relation(self):
        model = fixture("01")
        model["shared_bindings"][0]["after_digest"] = "b" * 64
        result = audit(model)
        self.assertEqual(labels(result)[2], "UNKNOWN")
        self.assertFalse(result["shared_bindings"]["applied"])

    def test_invalid_digest_disables_relation(self):
        model = fixture("01")
        model["shared_bindings"][0].update(before_digest="not-a-hash", after_digest="not-a-hash")
        self.assertEqual(labels(audit(model))[2], "UNKNOWN")

    def test_changed_context_disables_relation(self):
        model = fixture("01")
        model["shared_bindings"][0]["after_context"] = "other-deployment"
        self.assertEqual(labels(audit(model))[2], "UNKNOWN")

    def test_unsupported_relation_disables_correlation(self):
        model = fixture("01")
        model["shared_bindings"][0]["relation"] = "same_spelling"
        self.assertEqual(labels(audit(model))[2], "UNKNOWN")

    def test_unresolved_shared_variable_falls_back_to_cartesian(self):
        model = fixture("01")
        model["after"]["worlds"][0]["assignment"] = {}
        result = audit(model)
        self.assertEqual(labels(result)[2], "UNKNOWN")
        self.assertEqual(result["shared_bindings"]["ignored"][0]["reason"], "unresolved_assignment")

    def test_mutually_exclusive_edges_never_form_real_path(self):
        result = audit(fixture("02"))
        self.assertEqual(labels(result)[:2], ["FAIL", "FAIL"])
        for version in result["world_evaluations"].values():
            for world in version:
                self.assertIsNone(world["obligations"][0]["possible_path"])
        self.assertEqual(result["unsound_union_demonstration"]["versions"]["before"][0]["union_path"],
                         ["cancel_only_in_A", "fallback_only_in_B"])

    def test_new_admission_denial_preserves_existing_obligation(self):
        model = fixture("03")
        result = audit(model)
        self.assertEqual(result["persistent_obligation_ids"], ["existing-goal-1"])
        self.assertFalse(result["world_evaluations"]["after"][0]["admit_new_goal_metadata"])
        self.assertEqual(labels(result), ["PASS", "FAIL", "FAIL"])
        model["after"]["worlds"][0]["admit_new_goal"] = True
        self.assertEqual(labels(audit(model)), labels(result))

    def test_legitimate_alternative_avoids_endpoint_deletion_false_alarm(self):
        result = audit(fixture("04"))
        self.assertEqual(labels(result), ["PASS"] * 3)
        self.assertEqual(result["world_evaluations"]["after"][0]["obligations"][0]["authorized_path"],
                         ["independent_stop"])

    def test_unknown_alternative_precondition_does_not_pass(self):
        result = audit(fixture("08"))
        self.assertEqual(result["input_status"], "INCOMPLETE")
        self.assertEqual(labels(result), ["PASS", "UNKNOWN", "UNKNOWN"])

    def test_missing_capability_coverage_does_not_mean_denied(self):
        result = audit(fixture("06"))
        self.assertEqual(result["input_status"], "INCOMPLETE")
        self.assertEqual(labels(result), ["PASS", "UNKNOWN", "UNKNOWN"])

    def test_incomplete_negative_permission_is_unknown(self):
        model = fixture("03")
        model["after"]["worlds"][0]["complete"] = False
        self.assertEqual(labels(audit(model)), ["PASS", "UNKNOWN", "UNKNOWN"])

    def test_known_positive_path_survives_unrelated_unknown_branch(self):
        model = fixture("04")
        model["after"]["edges"].append({"id": "irrelevant", "from": "UNREACHABLE", "to": "DONE",
                                           "requires": ["unknown_atom"], "when": {}})
        result = audit(model)
        self.assertEqual(result["input_status"], "INCOMPLETE")
        self.assertEqual(labels(result), ["PASS"] * 3)

    def test_preexisting_deficiency_remains_visible(self):
        self.assertEqual(labels(audit(fixture("07"))), ["FAIL", "FAIL", "PASS"])

    def test_other_broken_task_does_not_mask_new_regression(self):
        result = audit(fixture("09"))
        self.assertEqual(labels(result), ["FAIL", "FAIL", "FAIL"])
        tasks = result["correlated"]["pairs"][0]["obligations"]
        self.assertEqual([task["no_new_regression"] for task in tasks], [False, True])

    def test_empty_worlds_are_input_error(self):
        model = fixture("03")
        model["after"]["worlds"] = []
        self.assert_input_error(model)

    def test_empty_obligations_are_input_error(self):
        model = fixture("03")
        model["obligations"] = []
        self.assert_input_error(model)

    def test_unadmitted_obligation_is_not_silently_accepted(self):
        model = fixture("03")
        model["obligations"][0]["admitted_before"] = False
        self.assert_input_error(model)

    def test_contradictory_shared_worlds_are_input_error(self):
        model = fixture("01")
        for world in model["after"]["worlds"]:
            world["assignment"]["namespace"] = "C"
        self.assert_input_error(model)

    def test_partially_unmatched_worlds_are_not_silently_dropped(self):
        model = fixture("01")
        model["after"]["worlds"][1]["assignment"]["namespace"] = "C"
        self.assert_input_error(model)

    def test_duplicate_world_ids_are_input_error(self):
        model = fixture("01")
        model["before"]["worlds"][1]["id"] = model["before"]["worlds"][0]["id"]
        self.assert_input_error(model)

    def test_duplicate_shared_declaration_cannot_mask_conflicting_evidence(self):
        model = fixture("01")
        conflicting = copy.deepcopy(model["shared_bindings"][0])
        conflicting["after_digest"] = "b" * 64
        model["shared_bindings"].append(conflicting)
        self.assert_input_error(model)

    def test_malformed_model_is_reported_not_executed(self):
        for value in [None, [], "run any command", {}, {"schema_version": True}]:
            with self.subTest(value=value):
                self.assert_input_error(value)

    def test_boolean_and_integer_guards_are_distinct(self):
        model = fixture("04")
        model["after"]["worlds"][0]["assignment"]["independent_stop_ready"] = 1
        self.assertEqual(labels(audit(model)), ["PASS", "FAIL", "FAIL"])

    def test_nonfinite_assignment_is_input_error_not_guard_mismatch(self):
        for value in [float("nan"), float("inf"), float("-inf")]:
            with self.subTest(value=value):
                model = fixture("04")
                model["after"]["worlds"][0]["assignment"]["independent_stop_ready"] = value
                self.assert_input_error(model)

    def test_nonfinite_guard_is_input_error_not_definite_failure(self):
        for value in [float("nan"), float("inf"), float("-inf")]:
            with self.subTest(value=value):
                model = fixture("04")
                model["after"]["edges"][0]["when"]["independent_stop_ready"] = value
                self.assert_input_error(model)

    def test_finite_model_matches_independent_boolean_oracle(self):
        # Graph structure: ACTIVE --a--> MID --b--> DONE, or ACTIVE --c--> DONE.
        # Exhaustively verify 8 x 8 complete before/after authorization assignments.
        template = fixture("03")
        edges = [{"id": "first", "from": "ACTIVE", "to": "MID", "requires": ["a"], "when": {}},
                 {"id": "second", "from": "MID", "to": "DONE", "requires": ["b"], "when": {}},
                 {"id": "alternative", "from": "ACTIVE", "to": "DONE", "requires": ["c"], "when": {}},
                 {"id": "cycle", "from": "MID", "to": "ACTIVE", "requires": [], "when": {}}]
        possibilities = list(itertools.product([False, True], repeat=3))
        for before, after in itertools.product(possibilities, repeat=2):
            with self.subTest(before=before, after=after):
                model = copy.deepcopy(template)
                for version, bits in [("before", before), ("after", after)]:
                    model[version]["edges"] = edges
                    model[version]["worlds"][0].update(capability_domain=["a", "b", "c"],
                        allowed=[cap for cap, allowed in zip(["a", "b", "c"], bits) if allowed])
                old = (before[0] and before[1]) or before[2]
                new = (after[0] and after[1]) or after[2]
                oracle = [old, new, not old or new]
                self.assertEqual(labels(audit(model)), ["PASS" if value else "FAIL" for value in oracle])

    def test_hash_and_certificate_are_deterministic(self):
        model = fixture("01")
        self.assertEqual(audit(model), audit(copy.deepcopy(model)))

    def test_cli_writes_machine_readable_fail_result_with_success_exit(self):
        with tempfile.TemporaryDirectory() as folder:
            inputs = Path(folder) / "inputs"
            inputs.mkdir()
            (inputs / "case.json").write_text(json.dumps(fixture("03")), encoding="utf-8")
            output = Path(folder) / "results.json"
            completed = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / "audit.py"),
                                        "--fixtures", str(inputs), "--output", str(output)],
                                       capture_output=True, text=True, encoding="utf-8", check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(output.read_text(encoding="utf-8"))["results"][0]
            self.assertEqual(labels(result), ["PASS", "FAIL", "FAIL"])

    def test_cli_invalid_json_never_has_vacuous_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            inputs = Path(folder) / "inputs"
            inputs.mkdir()
            (inputs / "case.json").write_text("{invalid", encoding="utf-8")
            output = Path(folder) / "results.json"
            completed = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / "audit.py"),
                                        "--fixtures", str(inputs), "--output", str(output)],
                                       capture_output=True, text=True, encoding="utf-8", check=False)
            self.assertEqual(completed.returncode, 2, completed.stderr)
            result = json.loads(output.read_text(encoding="utf-8"))["results"][0]
            self.assertEqual(result["input_status"], "INPUT_ERROR")
            self.assertEqual(labels(result), ["UNKNOWN"] * 3)

    def test_cli_nonstandard_json_constants_are_input_errors(self):
        with tempfile.TemporaryDirectory() as folder:
            inputs = Path(folder) / "inputs"
            inputs.mkdir()
            for index, value in enumerate([float("nan"), float("inf"), float("-inf")]):
                model = fixture("04")
                model["after"]["worlds"][0]["assignment"]["independent_stop_ready"] = value
                (inputs / f"case-{index}.json").write_text(json.dumps(model), encoding="utf-8")
            output = Path(folder) / "results.json"
            completed = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / "audit.py"),
                                        "--fixtures", str(inputs), "--output", str(output)],
                                       capture_output=True, text=True, encoding="utf-8", check=False)
            self.assertEqual(completed.returncode, 2, completed.stderr)
            results = json.loads(output.read_text(encoding="utf-8"))["results"]
            self.assertEqual(len(results), 3)
            for result in results:
                self.assertEqual(result["input_status"], "INPUT_ERROR")
                self.assertEqual(labels(result), ["UNKNOWN"] * 3)


if __name__ == "__main__":
    unittest.main()
