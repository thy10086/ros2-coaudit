"""Behavioral tests for the offline cancellation-to-terminal adapter."""
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from coaudit.trace import audit_trace  # noqa: E402


def event(kind, time, goal="goal-1", **extra):
    return {"goal_id": goal, "event": kind, "ts_ms": time, **extra}


def trace(events=None, **extra):
    return {"clock": "monotonic_ms", "complete": True, "window_start_ms": 0,
            "window_end_ms": 200, "events": events if events is not None else [
                event("accepted", 0), event("cancel_requested", 20),
                event("cancel_accepted", 30), event("terminal", 60, status="CANCELED")], **extra}


def obligation(goal="goal-1", oid="task-1", **extra):
    return {"id": oid, "goal_id": goal, "admitted_before": True, "start": "ACTIVE",
            "targets": ["DONE"], "cancel_deadline_ms": 50, **extra}


class TraceAuditTests(unittest.TestCase):
    def audit(self, data=None, obligations=None):
        return audit_trace(trace() if data is None else data,
                           [obligation()] if obligations is None else obligations)

    def assert_input_error(self, data, obligations=None, code=None):
        result = audit_trace(data, [obligation()] if obligations is None else obligations)
        self.assertEqual(result["input_status"], "INPUT_ERROR")
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertEqual(result["reason"], "input_error")
        self.assertTrue(result["input_errors"])
        self.assertTrue(all(item["verdict"] == "UNKNOWN" for item in result["obligations"]))
        if code:
            self.assertIn(code, [item["code"] for item in result["input_errors"]])

    def test_complete_same_goal_terminal_within_deadline_passes(self):
        result = self.audit()
        self.assertEqual(result["verdict"], "PASS")
        task = result["obligations"][0]
        self.assertEqual(task["deadline_ms"], 70)
        self.assertEqual(task["elapsed_ms"], 40)
        self.assertTrue(task["cancel_acknowledged"])

    def test_all_legal_terminal_statuses_mean_termination_not_cancel_success(self):
        for status in ["SUCCEEDED", "CANCELED", "ABORTED"]:
            with self.subTest(status=status):
                data = trace()
                data["events"][-1]["status"] = status
                result = self.audit(data)
                self.assertEqual(result["verdict"], "PASS")
                self.assertEqual(result["obligations"][0]["observed_terminal_status"], status)

    def test_terminal_at_exact_deadline_is_inclusive(self):
        data = trace()
        data["events"][-1]["ts_ms"] = 70
        self.assertEqual(self.audit(data)["verdict"], "PASS")

    def test_late_terminal_is_fail_under_complete_coverage(self):
        data = trace()
        data["events"][-1]["ts_ms"] = 71
        result = self.audit(data)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["reason"], "terminal_after_deadline")

    def test_cancel_acknowledgment_is_not_terminal(self):
        data = trace([event("cancel_requested", 20), event("cancel_accepted", 30)])
        result = self.audit(data)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["reason"], "deadline_exceeded_without_terminal")
        self.assertTrue(result["obligations"][0]["cancel_acknowledged"])

    def test_ack_is_not_required_to_prove_observed_termination(self):
        data = trace([event("cancel_requested", 20), event("terminal", 60, status="CANCELED")])
        result = self.audit(data)
        self.assertEqual(result["verdict"], "PASS")
        self.assertFalse(result["obligations"][0]["cancel_acknowledged"])

    def test_missing_terminal_before_deadline_is_unknown(self):
        result = self.audit(trace([event("cancel_requested", 20)], window_end_ms=60))
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertEqual(result["reason"], "window_ends_before_deadline")

    def test_missing_terminal_at_window_deadline_boundary_is_unknown(self):
        result = self.audit(trace([event("cancel_requested", 20)], window_end_ms=70))
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertEqual(result["reason"], "deadline_boundary_unresolved")

    def test_incomplete_coverage_never_proves_pass_even_with_terminal(self):
        result = self.audit(trace(complete=False))
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertEqual(result["input_status"], "INCOMPLETE")
        self.assertTrue(result["obligations"][0]["observed_within_deadline"])

    def test_incomplete_coverage_never_proves_missing_terminal_fail(self):
        result = self.audit(trace([event("cancel_requested", 20)], complete=False))
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertEqual(result["reason"], "incomplete_coverage")

    def test_incomplete_coverage_keeps_late_terminal_unknown(self):
        data = trace(complete=False)
        data["events"][-1]["ts_ms"] = 100
        result = self.audit(data)
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertFalse(result["obligations"][0]["observed_within_deadline"])

    def test_running_goal_without_cancel_is_unknown(self):
        result = self.audit(trace([event("accepted", 0)]))
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertEqual(result["reason"], "no_cancel_observed")

    def test_terminal_without_cancel_does_not_claim_recovery_exercised(self):
        result = self.audit(trace([event("terminal", 60, status="SUCCEEDED")]))
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertEqual(result["reason"], "no_cancel_observed")

    def test_missing_accepted_uses_declaration_without_inventing_event(self):
        data = trace([event("cancel_requested", 20), event("terminal", 60, status="CANCELED")])
        result = self.audit(data)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["obligations"][0]["admission_basis"], "declared_admitted_before")
        self.assertEqual(len(data["events"]), 2)

    def test_foreign_goal_terminal_cannot_complete_this_goal(self):
        data = trace([event("cancel_requested", 20), event("terminal", 60, goal="other", status="CANCELED")])
        result = self.audit(data)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["unrelated_goal_ids"], ["other"])

    def test_repeated_cancel_does_not_extend_original_deadline(self):
        data = trace([event("cancel_requested", 20), event("cancel_requested", 60),
                      event("terminal", 80, status="CANCELED")])
        result = self.audit(data)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["obligations"][0]["deadline_ms"], 70)
        self.assertEqual(result["obligations"][0]["repeated_cancel_requests"], 1)

    def test_cancel_after_terminal_is_unknown(self):
        data = trace([event("terminal", 10, status="SUCCEEDED"), event("cancel_requested", 20)])
        result = self.audit(data)
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertEqual(result["reason"], "cancel_after_terminal")

    def test_repeated_cancel_after_valid_terminal_is_conservatively_unknown(self):
        data = trace([event("cancel_requested", 20), event("terminal", 50, status="CANCELED"),
                      event("cancel_requested", 80)])
        self.assertEqual(self.audit(data)["reason"], "cancel_after_terminal")

    def test_ack_before_request_is_unknown_not_matching_future_request(self):
        data = trace([event("cancel_accepted", 10), event("cancel_requested", 20),
                      event("terminal", 50, status="CANCELED")])
        self.assertEqual(self.audit(data)["reason"], "cancel_ack_before_request")

    def test_accepted_after_cancel_is_ambiguous(self):
        data = trace([event("cancel_requested", 20), event("accepted", 30),
                      event("terminal", 50, status="CANCELED")])
        self.assertEqual(self.audit(data)["reason"], "acceptance_after_cancel")

    def test_multiple_terminal_records_are_ambiguous(self):
        data = trace([event("cancel_requested", 20), event("terminal", 50, status="CANCELED"),
                      event("terminal", 60, status="ABORTED")])
        result = self.audit(data)
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertEqual(result["reason"], "ambiguous_terminal_history")

    def test_equal_timestamp_order_is_preserved(self):
        forward = trace([event("cancel_requested", 20), event("terminal", 20, status="CANCELED")])
        backward = trace(list(reversed(forward["events"])))
        self.assertEqual(self.audit(forward)["verdict"], "PASS")
        self.assertEqual(self.audit(backward)["reason"], "cancel_after_terminal")

    def test_zero_deadline_allows_same_timestamp_terminal(self):
        data = trace([event("cancel_requested", 20), event("terminal", 20, status="CANCELED")])
        self.assertEqual(self.audit(data, [obligation(cancel_deadline_ms=0)])["verdict"], "PASS")

    def test_two_goals_are_matched_independently(self):
        data = trace([event("cancel_requested", 20), event("cancel_requested", 25, goal="goal-2"),
                      event("terminal", 60, status="CANCELED"),
                      event("terminal", 90, goal="goal-2", status="ABORTED")])
        obligations = [obligation(), obligation(goal="goal-2", oid="task-2")]
        result = self.audit(data, obligations)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual([item["verdict"] for item in result["obligations"]], ["PASS", "FAIL"])

    def test_unknown_goal_prevents_all_obligations_pass(self):
        result = self.audit(trace(), [obligation(), obligation(goal="goal-2", oid="task-2")])
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertEqual([item["verdict"] for item in result["obligations"]], ["PASS", "UNKNOWN"])

    def test_empty_trace_does_not_pass_vacuously(self):
        self.assertEqual(self.audit(trace([]))["reason"], "no_cancel_observed")

    def test_empty_obligations_are_input_error(self):
        self.assert_input_error(trace(), [], "empty_or_invalid_obligations")

    def test_unknown_clock_is_input_error(self):
        self.assert_input_error(trace(clock="wall_clock"), code="unsupported_clock")

    def test_unknown_event_or_terminal_status_is_input_error(self):
        for data in [trace([event("cancel_ack", 20)]), trace([event("terminal", 20, status="STOPPED")]),
                     trace([event("terminal", 20)]), trace([event("accepted", 20, status="CANCELED")])]:
            with self.subTest(data=data):
                self.assert_input_error(data)

    def test_nonfinite_numbers_are_input_errors(self):
        for value in [float("nan"), float("inf"), float("-inf"), True]:
            with self.subTest(value=value):
                self.assert_input_error(trace([event("cancel_requested", value)]))
                self.assert_input_error(trace(window_end_ms=value))
                self.assert_input_error(trace(), [obligation(cancel_deadline_ms=value)])

    def test_derived_deadline_overflow_is_input_error(self):
        data = trace([event("cancel_requested", 1e308)], window_end_ms=1.5e308)
        self.assert_input_error(data, [obligation(cancel_deadline_ms=1e308)], "deadline_overflow")

    def test_out_of_order_events_are_input_error(self):
        data = trace([event("cancel_requested", 20), event("accepted", 10)])
        self.assert_input_error(data, code="events_out_of_order")

    def test_window_inconsistencies_are_input_errors(self):
        for data in [trace(window_start_ms=201), trace(window_start_ms=-1),
                     trace([event("cancel_requested", 201)]), trace(window_start_ms=1)]:
            with self.subTest(data=data):
                self.assert_input_error(data)

    def test_duplicate_obligation_id_is_input_error(self):
        self.assert_input_error(trace(), [obligation(), obligation(goal="other")], "duplicate_identifier")

    def test_duplicate_obligation_goal_id_is_input_error(self):
        self.assert_input_error(trace(), [obligation(), obligation(oid="other")], "duplicate_identifier")

    def test_duplicate_optional_event_ids_are_input_error(self):
        data = trace([event("cancel_requested", 20, id="event-1"),
                      event("terminal", 50, id="event-1", status="CANCELED")])
        self.assert_input_error(data, code="duplicate_event_id")

    def test_goal_id_reuse_with_multiple_acceptance_is_input_error(self):
        data = trace([event("accepted", 0), event("accepted", 10)])
        self.assert_input_error(data, code="reused_goal_id")

    def test_unadmitted_task_is_input_error_not_removed(self):
        self.assert_input_error(trace(), [obligation(admitted_before=False)], "not_admitted_before")

    def test_bad_json_shaped_inputs_return_structured_errors(self):
        cases = [(None, [obligation()]), ([], [obligation()]), ({}, [obligation()]),
                 (trace(events="bad"), [obligation()]), (trace([None]), [obligation()]),
                 (trace([event([], 20)]), [obligation()]),
                 (trace([event("cancel_requested", 20, goal=[])]), [obligation()]),
                 (trace(), None), (trace(), [None]), (trace(), [obligation(targets=[{}])]),
                 (trace(), [obligation(id=[])]), (trace(complete="yes"), [obligation()])]
        for data, tasks in cases:
            with self.subTest(data=data, tasks=tasks):
                # Direct invocation retains None rather than helper defaults.
                result = audit_trace(data, tasks)
                self.assertEqual(result["input_status"], "INPUT_ERROR")
                self.assertEqual(result["verdict"], "UNKNOWN")

    def test_input_is_not_mutated_and_result_is_deterministic(self):
        data, tasks = trace(), [obligation()]
        before = copy.deepcopy((data, tasks))
        self.assertEqual(audit_trace(data, tasks), audit_trace(data, tasks))
        self.assertEqual((data, tasks), before)


if __name__ == "__main__":
    unittest.main()
