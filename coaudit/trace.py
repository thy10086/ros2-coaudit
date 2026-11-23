"""Offline, bounded cancellation-to-terminal audit for exported task events.

This module interprets only the explicitly supplied time window and coverage
declaration. It does not connect to ROS, infer missing events, or prove physical
stopping. All public input failures produce structured UNKNOWN results.
"""
from __future__ import annotations

import math
from typing import Any


EVENT_TYPES = frozenset({"accepted", "cancel_requested", "cancel_accepted", "terminal"})
TERMINAL_STATUSES = frozenset({"SUCCEEDED", "CANCELED", "ABORTED"})
LIMITATIONS = [
    "Only supplied offline events and declared coverage are evaluated.",
    "goal_id must identify one task instance within one monotonic clock domain.",
    "One trace must belong to one session; cross-session merging and goal_id reuse are unsupported.",
    "A terminal status proves an observed terminal event, not physical stopping or successful cancellation.",
    "The adapter cannot authenticate events or independently verify complete=true.",
]


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, TypeError, ValueError):
        return False


def _error(path: str, code: str, message: str) -> dict:
    return {"path": path, "code": code, "message": message}


def _validate(trace: Any, obligations: Any) -> list[dict]:
    errors: list[dict] = []
    if not isinstance(trace, dict):
        errors.append(_error("trace", "invalid_type", "trace must be an object"))
        trace = {}
    if trace.get("clock") != "monotonic_ms":
        errors.append(_error("trace.clock", "unsupported_clock", "clock must be monotonic_ms"))
    if type(trace.get("complete")) is not bool:
        errors.append(_error("trace.complete", "invalid_coverage", "complete must be boolean"))
    start, end = trace.get("window_start_ms"), trace.get("window_end_ms")
    window_valid = _number(start) and _number(end) and 0 <= start <= end
    if not window_valid:
        errors.append(_error("trace.window", "invalid_window", "window requires finite 0 <= start <= end"))
    events = trace.get("events")
    if not isinstance(events, list):
        errors.append(_error("trace.events", "invalid_type", "events must be a list"))
        events = []
    event_ids: set[str] = set()
    accepted_goals: set[str] = set()
    previous_time = None
    valid_requests: list[tuple[str, int | float, str]] = []
    for index, event in enumerate(events):
        path = f"trace.events[{index}]"
        if not isinstance(event, dict):
            errors.append(_error(path, "invalid_type", "event must be an object"))
            continue
        goal = event.get("goal_id")
        if not _text(goal):
            errors.append(_error(path + ".goal_id", "invalid_goal_id", "goal_id must be a nonempty string"))
        kind = event.get("event")
        if not isinstance(kind, str) or kind not in EVENT_TYPES:
            errors.append(_error(path + ".event", "unknown_event", "unsupported event type"))
        status = event.get("status")
        if kind == "terminal":
            if not isinstance(status, str) or status not in TERMINAL_STATUSES:
                errors.append(_error(path + ".status", "unknown_terminal_status", "terminal requires SUCCEEDED, CANCELED, or ABORTED"))
        elif "status" in event:
            errors.append(_error(path + ".status", "unexpected_status", "status belongs only to terminal events"))
        ts = event.get("ts_ms")
        if not _number(ts) or ts < 0:
            errors.append(_error(path + ".ts_ms", "invalid_timestamp", "timestamp must be finite and nonnegative"))
        else:
            if previous_time is not None and ts < previous_time:
                errors.append(_error(path + ".ts_ms", "events_out_of_order", "events must be globally nondecreasing in timestamp"))
            previous_time = ts
            if window_valid and not start <= ts <= end:
                errors.append(_error(path + ".ts_ms", "outside_window", "event timestamp lies outside declared window"))
            if kind == "cancel_requested" and _text(goal):
                valid_requests.append((goal, ts, path))
        if "id" in event:
            eid = event["id"]
            if not _text(eid):
                errors.append(_error(path + ".id", "invalid_event_id", "optional event id must be a nonempty string"))
            elif eid in event_ids:
                errors.append(_error(path + ".id", "duplicate_event_id", "event id must be unique across the trace"))
            else:
                event_ids.add(eid)
        if kind == "accepted" and _text(goal):
            if goal in accepted_goals:
                errors.append(_error(path, "reused_goal_id", "multiple accepted events for one goal_id make task-instance identity ambiguous"))
            accepted_goals.add(goal)
    if not isinstance(obligations, list) or not obligations:
        errors.append(_error("obligations", "empty_or_invalid_obligations", "obligations must be a nonempty list"))
        obligations = []
    ids: set[str] = set()
    goals: set[str] = set()
    for index, obligation in enumerate(obligations):
        path = f"obligations[{index}]"
        if not isinstance(obligation, dict):
            errors.append(_error(path, "invalid_type", "obligation must be an object"))
            continue
        oid, goal = obligation.get("id"), obligation.get("goal_id")
        for key, value, seen in [("id", oid, ids), ("goal_id", goal, goals)]:
            if not _text(value):
                errors.append(_error(path + "." + key, "invalid_identifier", "identifier must be a nonempty string"))
            elif value in seen:
                errors.append(_error(path + "." + key, "duplicate_identifier", "one unique obligation and goal_id are required per task instance"))
            else:
                seen.add(value)
        if obligation.get("admitted_before") is not True:
            errors.append(_error(path + ".admitted_before", "not_admitted_before", "persistent obligations require admitted_before=true"))
        if not _text(obligation.get("start")):
            errors.append(_error(path + ".start", "invalid_start", "start must be a nonempty string"))
        targets = obligation.get("targets")
        if (not isinstance(targets, list) or not targets or not all(_text(target) for target in targets)
                or len(targets) != len(set(targets))):
            errors.append(_error(path + ".targets", "invalid_targets", "targets must be a nonempty unique string list"))
        duration = obligation.get("cancel_deadline_ms")
        if not _number(duration) or duration < 0:
            errors.append(_error(path + ".cancel_deadline_ms", "invalid_deadline", "deadline duration must be finite and nonnegative"))
        elif _text(goal):
            for request_goal, ts, request_path in valid_requests:
                if request_goal == goal:
                    try:
                        deadline = ts + duration
                    except (OverflowError, TypeError, ValueError):
                        deadline = float("inf")
                    if not _number(deadline):
                        errors.append(_error(request_path, "deadline_overflow", "request timestamp plus deadline must remain finite"))
    return errors


def _unknown_input_obligations(obligations: Any) -> list[dict]:
    if not isinstance(obligations, list):
        return []
    return [{"id": item.get("id") if _text(item.get("id")) else None,
             "goal_id": item.get("goal_id") if _text(item.get("goal_id")) else None,
             "verdict": "UNKNOWN", "reason": "input_error"}
            for item in obligations if isinstance(item, dict)]


def _audit_obligation(trace: dict, obligation: dict) -> dict:
    goal = obligation["goal_id"]
    indexed = [(i, event) for i, event in enumerate(trace["events"]) if event["goal_id"] == goal]
    requests = [(i, e) for i, e in indexed if e["event"] == "cancel_requested"]
    terminals = [(i, e) for i, e in indexed if e["event"] == "terminal"]
    accepted = [(i, e) for i, e in indexed if e["event"] == "accepted"]
    acknowledgments = [(i, e) for i, e in indexed if e["event"] == "cancel_accepted"]
    result = {
        "id": obligation["id"], "goal_id": goal,
        "verdict": "UNKNOWN", "reason": "no_cancel_observed",
        "admission_basis": "observed_accepted" if accepted else "declared_admitted_before",
        "event_indices": [i for i, _ in indexed],
        "cancel_request_indices": [i for i, _ in requests],
        "terminal_indices": [i for i, _ in terminals],
        "cancel_acknowledged": False,
        "coverage_complete": trace["complete"],
        "observed_terminal_status": terminals[0][1]["status"] if terminals else None,
    }
    if not requests:
        return result
    request_index, request = requests[0]
    deadline = request["ts_ms"] + obligation["cancel_deadline_ms"]
    result.update(cancel_requested_at_ms=request["ts_ms"], deadline_ms=deadline,
                  repeated_cancel_requests=max(0, len(requests) - 1),
                  cancel_acknowledged=any(i > request_index for i, _ in acknowledgments))
    if terminals and any(i > terminals[0][0] for i, _ in requests):
        result["reason"] = "cancel_after_terminal"
        return result
    if accepted and accepted[0][0] > request_index:
        result["reason"] = "acceptance_after_cancel"
        return result
    if any(i < request_index for i, _ in acknowledgments):
        result["reason"] = "cancel_ack_before_request"
        return result
    if len(terminals) > 1:
        result["reason"] = "ambiguous_terminal_history"
        return result
    terminal = terminals[0][1] if terminals else None
    if terminal is not None:
        result.update(terminal_at_ms=terminal["ts_ms"],
                      elapsed_ms=terminal["ts_ms"] - request["ts_ms"],
                      observed_within_deadline=terminal["ts_ms"] <= deadline)
    if not trace["complete"]:
        result["reason"] = "incomplete_coverage"
        return result
    if terminal is not None:
        if terminal["ts_ms"] <= deadline:
            result.update(verdict="PASS", reason="terminal_within_deadline")
        else:
            result.update(verdict="FAIL", reason="terminal_after_deadline")
        return result
    if trace["window_end_ms"] > deadline:
        result.update(verdict="FAIL", reason="deadline_exceeded_without_terminal")
    elif trace["window_end_ms"] == deadline:
        result["reason"] = "deadline_boundary_unresolved"
    else:
        result["reason"] = "window_ends_before_deadline"
    return result


def audit_trace(trace: dict, obligations: list[dict]) -> dict:
    """Audit observed cancellation episodes for persistent before-admitted tasks.

    PASS requires complete declared coverage and a same-goal terminal event no
    later than the deadline measured from the earliest observed cancel request.
    Missing evidence stays UNKNOWN. Explicit input inconsistencies become
    INPUT_ERROR/UNKNOWN, never exceptions or a vacuous PASS.
    """
    errors = _validate(trace, obligations)
    base = {"domain": "TRACE_OBLIGATION", "input_status": "VALID", "verdict": "UNKNOWN",
            "reason": "input_error" if errors else "pending", "input_errors": errors,
            "limitations": list(LIMITATIONS)}
    if errors:
        base.update(input_status="INPUT_ERROR", obligations=_unknown_input_obligations(obligations))
        return base
    results = [_audit_obligation(trace, obligation) for obligation in obligations]
    values = [result["verdict"] for result in results]
    if "FAIL" in values:
        verdict, reason = "FAIL", "at_least_one_obligation_failed"
    elif all(value == "PASS" for value in values):
        verdict, reason = "PASS", "all_observed_cancellations_met_deadline"
    else:
        verdict, reason = "UNKNOWN", "at_least_one_obligation_unknown"
    # Preserve the precise reason in the common single-obligation case.
    if len(results) == 1:
        reason = results[0]["reason"]
    base.update(input_status="VALID" if trace["complete"] else "INCOMPLETE",
                verdict=verdict, reason=reason, obligations=results,
                clock=trace["clock"],
                window={"start_ms": trace["window_start_ms"], "end_ms": trace["window_end_ms"]},
                coverage_complete=trace["complete"],
                events_seen=len(trace["events"]),
                unrelated_goal_ids=sorted({event["goal_id"] for event in trace["events"]}
                                          - {obligation["goal_id"] for obligation in obligations}))
    return base
