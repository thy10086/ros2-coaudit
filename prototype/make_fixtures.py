"""Rebuild the explicitly synthetic, inspectable example models."""
import copy
import json
from pathlib import Path


def world(name, allowed, assignment=None, domain=None, **extra):
    return {"id": name, "assignment": assignment or {},
            "capability_domain": domain or ["cancel_req", "cancel_reply", "fallback_req", "fallback_ack"],
            "allowed": allowed, "complete": True, "admit_new_goal": True, **extra}


def edge(name, source, target, requires, when=None):
    return {"id": name, "from": source, "to": target, "requires": requires, "when": when or {}}


def model(name, before, after, before_edges=None, after_edges=None):
    edges = [edge("cancel", "ACTIVE", "CANCEL_ACK", ["cancel_req", "cancel_reply"]),
             edge("fallback", "CANCEL_ACK", "DONE", ["fallback_req", "fallback_ack"])]
    return {"schema_version": 1, "name": name,
            "scope": "Synthetic finite model; DONE means communication prerequisites only.",
            "before": {"worlds": before, "edges": before_edges if before_edges is not None else edges},
            "after": {"worlds": after, "edges": after_edges if after_edges is not None else copy.deepcopy(edges)},
            "obligations": [{"id": "existing-goal-1", "start": "ACTIVE", "targets": ["DONE"],
                             "admitted_before": True}], "shared_bindings": []}


def expected(model, correlated, independent=None):
    model["expected_verdicts"] = {"correlated": correlated, "independent_baseline": independent or correlated}
    return model


def build():
    caps = ["cancel_req", "cancel_reply", "fallback_req", "fallback_ack"]
    shared = model("01_shared_binding_correlation",
                   [world("before-A", caps, {"namespace": "A"}), world("before-B", [], {"namespace": "B"})],
                   [world("after-A", caps, {"namespace": "A"}), world("after-B", [], {"namespace": "B"})])
    shared["shared_bindings"] = [{"variable": "namespace", "relation": "declared_unchanged",
                                  "basis_ref": "synthetic assumption E1; no external artifact validated",
                                  "before_digest": "a" * 64, "after_digest": "a" * 64,
                                  "before_context": "deployment-X", "after_context": "deployment-X"}]
    expected(shared, ["UNKNOWN", "UNKNOWN", "PASS"], ["UNKNOWN", "UNKNOWN", "UNKNOWN"])
    exclusive_edges = [edge("cancel_only_in_A", "ACTIVE", "CANCEL_ACK", ["cancel_req", "cancel_reply"], {"mode": "A"}),
                       edge("fallback_only_in_B", "CANCEL_ACK", "DONE", ["fallback_req", "fallback_ack"], {"mode": "B"})]
    exclusive = model("02_mutually_exclusive_edges",
                      [world("before-A", caps, {"mode": "A"}), world("before-B", caps, {"mode": "B"})],
                      [world("after-A", caps, {"mode": "A"}), world("after-B", caps, {"mode": "B"})],
                      exclusive_edges, exclusive_edges)
    exclusive["include_unsound_union_demo"] = True
    expected(exclusive, ["FAIL", "FAIL", "PASS"])
    persistent = model("03_existing_task_survives_admission_denial", [world("before", caps)],
                       [world("after", ["cancel_req", "fallback_req", "fallback_ack"], admit_new_goal=False)])
    expected(persistent, ["PASS", "FAIL", "FAIL"])
    domain = caps + ["stop_req", "stop_ack"]
    alternative_edges = [edge("independent_stop", "ACTIVE", "DONE", ["stop_req", "stop_ack"],
                              {"independent_stop_ready": True})]
    alternative = model("04_legitimate_alternative_path", [world("before", caps, domain=domain)],
                        [world("after", ["stop_req", "stop_ack"], {"independent_stop_ready": True}, domain)],
                        after_edges=alternative_edges)
    expected(alternative, ["PASS", "PASS", "PASS"])
    missing = copy.deepcopy(shared)
    missing["name"] = "05_same_names_without_binding_evidence"
    missing["shared_bindings"] = []
    expected(missing, ["UNKNOWN", "UNKNOWN", "UNKNOWN"])
    incomplete = model("06_incomplete_capability_domain", [world("before", caps)],
                       [world("after", caps[:-1], domain=caps[:-1])])
    expected(incomplete, ["PASS", "UNKNOWN", "UNKNOWN"])
    deficient = model("07_preexisting_deficiency_not_hidden", [world("before", [])], [world("after", [])])
    expected(deficient, ["FAIL", "FAIL", "PASS"])
    unknown_alternative = copy.deepcopy(alternative)
    unknown_alternative["name"] = "08_unknown_alternative_precondition"
    unknown_alternative["after"]["worlds"][0]["assignment"] = {}
    expected(unknown_alternative, ["PASS", "UNKNOWN", "UNKNOWN"])
    # Two distinct existing instances use different protocol stages/capabilities.
    multi_edges = [edge("recover_healthy", "HEALTHY_ACTIVE", "DONE", ["healthy_ack"]),
                   edge("recover_broken", "BROKEN_ACTIVE", "DONE", ["broken_ack"])]
    multi = model("09_one_broken_task_must_not_mask_another_regression",
                  [world("before", ["healthy_ack"], domain=["healthy_ack", "broken_ack"])],
                  [world("after", [], domain=["healthy_ack", "broken_ack"])], multi_edges, multi_edges)
    multi["obligations"] = [
        {"id": "previously-healthy-task", "start": "HEALTHY_ACTIVE", "targets": ["DONE"], "admitted_before": True},
        {"id": "already-broken-task", "start": "BROKEN_ACTIVE", "targets": ["DONE"], "admitted_before": True},
    ]
    expected(multi, ["FAIL", "FAIL", "FAIL"])
    return [shared, exclusive, persistent, alternative, missing, incomplete, deficient, unknown_alternative, multi]


if __name__ == "__main__":
    folder = Path(__file__).parent / "fixtures"
    folder.mkdir(exist_ok=True)
    for fixture in build():
        (folder / (fixture["name"] + ".json")).write_text(
            json.dumps(fixture, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(build())} synthetic fixtures to {folder}")
