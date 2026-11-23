"""Read-only integration for exported ROS 2 configuration evidence.

This interprets SROS2 source policies, never installed/signed DDS permissions.
It neither executes launch files nor contacts a ROS graph.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re

from prototype.audit import audit as audit_model
from .policy import load_policy
from .trace import audit_trace

LIMITATIONS = [
    "Offline exported declarations only; runtime identity and enforcement are not authenticated.",
    "SROS2 source-policy subset, not signed DDS permissions/governance evaluation.",
    "Service-role coverage is not proof of message delivery, cancel acceptance, or physical stopping.",
    "One resolved deployment snapshot per version in bundle mode; finite-world mode is separate.",
    "Trace scope is a declared match to the after snapshot; origin, clock and coverage are not authenticated.",
]
OPS = {"publish", "subscribe", "request", "reply"}
NAME = re.compile(r"/(?:[A-Za-z_][A-Za-z0-9_]*)(?:/[A-Za-z_][A-Za-z0-9_]*)*$")


def strict_json(path: Path, raw: bytes | None = None):
    def constant(token):
        raise ValueError(f"non-finite JSON constant: {token}")
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON key: {key}")
            out[key] = value
        return out
    if path.stat().st_size > 8_000_000:
        raise ValueError("JSON exceeds the 8 MB input limit")
    def finite_float(token):
        value = float(token)
        if not math.isfinite(value):
            raise ValueError(f"JSON number outside finite range: {token}")
        return value
    data = json.loads((raw if raw is not None else path.read_bytes()).decode("utf-8-sig"), parse_constant=constant,
                      parse_float=finite_float, object_pairs_hook=unique)
    json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
    return data


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _object(value, allowed, required, label):
    _require(isinstance(value, dict), f"{label}: expected object")
    _require(not set(value) - set(allowed), f"{label}: unsupported fields: {sorted(set(value)-set(allowed))}")
    _require(set(required) <= set(value), f"{label}: missing fields: {sorted(set(required)-set(value))}")


def _name(value):
    return isinstance(value, str) and NAME.fullmatch(value) is not None


def _string(value):
    return isinstance(value, str) and bool(value.strip())


def _number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


class EvidenceReader:
    def __init__(self, root):
        self.root = root.resolve()
        self.records = {}

    def path(self, relative):
        _require(_string(relative), "evidence path must be a nonempty relative string")
        rel = Path(relative)
        _require(not rel.is_absolute(), "absolute evidence paths are unsupported")
        path = (self.root / rel).resolve()
        _require(path.is_relative_to(self.root), "evidence path escapes bundle directory")
        _require(path.is_file(), f"missing evidence file: {relative}")
        _require(path.stat().st_size <= 8_000_000, f"evidence too large: {relative}")
        self.records[relative] = {"path": relative, "bytes": path.stat().st_size,
                                  "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        return path

    def read(self, relative):
        path = self.path(relative)
        raw = path.read_bytes()
        self.records[relative] = {"path": relative, "bytes": len(raw),
                                  "sha256": hashlib.sha256(raw).hexdigest()}
        return strict_json(path, raw)


def _deployment(data, label):
    fields = {"schema_version", "context_id", "ros_distro", "rmw", "security", "nodes"}
    _object(data, fields, fields, label)
    _require(type(data["schema_version"]) is int and data["schema_version"] == 1, "deployment schema_version must be 1")
    for key in ("context_id", "ros_distro", "rmw"):
        _require(_string(data[key]), f"{label}.{key}: expected nonempty string")
    _object(data["security"], {"enable", "strategy"}, {"enable", "strategy"}, label + ".security")
    for key in ("enable", "strategy"):
        _require(data["security"][key] is None or isinstance(data["security"][key], str), f"security.{key}: string or null required")
    _require(isinstance(data["nodes"], list) and data["nodes"], "nodes must be nonempty list")
    nodes = {}
    fqns = set()
    for n in data["nodes"]:
        _object(n, {"id", "fqn", "enclave"}, {"id", "fqn", "enclave"}, "node")
        _require(_string(n["id"]) and n["id"] not in nodes, "node ID missing or duplicated")
        _require(_name(n["fqn"]) and n["fqn"] not in fqns, "node fqn invalid or duplicated")
        _require(n["enclave"] == "/" or _name(n["enclave"]), "enclave must be resolved absolute path")
        nodes[n["id"]] = n
        fqns.add(n["fqn"])
    return nodes


def _contract(data):
    _object(data, {"schema_version", "obligations", "forbidden"}, {"schema_version", "obligations", "forbidden"}, "contract")
    _require(type(data["schema_version"]) is int and data["schema_version"] == 1, "contract schema_version must be 1")
    _require(isinstance(data["obligations"], list) and data["obligations"], "nonempty obligations required")
    ids, goals = set(), set()
    required = {"id", "goal_id", "action", "client", "server", "admitted_before", "cancel_deadline_ms"}
    for o in data["obligations"]:
        _object(o, required | {"fallback"}, required, "obligation")
        for key in ("id", "goal_id", "client", "server"):
            _require(_string(o[key]), f"obligation.{key} must be nonempty")
        _require(o["id"] not in ids and o["goal_id"] not in goals, "duplicate obligation or goal ID")
        ids.add(o["id"]); goals.add(o["goal_id"])
        _require(o["admitted_before"] is True, "only admitted-before obligations supported")
        _require(_name(o["action"]), "action must be final absolute ROS name")
        _require(_number(o["cancel_deadline_ms"]) and o["cancel_deadline_ms"] > 0, "cancel deadline must be finite and positive")
        if "fallback" in o:
            f = o["fallback"]
            _object(f, {"service", "client", "server", "approved"}, {"service", "client", "server", "approved"}, "fallback")
            _require(_name(f["service"]) and _string(f["client"]) and _string(f["server"]), "fallback names invalid")
            _require(f["approved"] is None or type(f["approved"]) is bool, "fallback approval must be boolean or null")
    _require(isinstance(data["forbidden"], list), "forbidden must be a list (explicit [] allowed)")
    for f in data["forbidden"]:
        _object(f, {"node", "resource", "operation"}, {"node", "resource", "operation"}, "forbidden")
        _require(_string(f["node"]) and _name(f["resource"]) and f["operation"] in OPS, "invalid forbidden capability")


def aggregate(checks):
    if not checks:
        return "UNKNOWN"
    if any(c["verdict"] == "FAIL" for c in checks):
        return "FAIL"
    return "PASS" if all(c["verdict"] == "PASS" for c in checks) else "UNKNOWN"


def _config(data, policy, label):
    checks = []
    supported_rmw = data["rmw"] in {"rmw_fastrtps_cpp", "rmw_fastrtps_dynamic_cpp", "rmw_cyclonedds_cpp"}
    checks.append({"rule": f"{label}.declared_dds_rmw", "verdict": "PASS" if supported_rmw else "UNKNOWN",
                   "observed": data["rmw"], "reason": "dds_source_policy_scope" if supported_rmw else "unsupported_rmw"})
    for key, expected in (("enable", "true"), ("strategy", "Enforce")):
        value = data["security"][key]
        verdict = "UNKNOWN" if value is None or not supported_rmw else "PASS" if value == expected else "FAIL"
        checks.append({"rule": f"{label}.security.{key}", "verdict": verdict,
                       "observed": value, "expected": expected})
    for node in data["nodes"]:
        known = node["enclave"] in policy.enclaves
        checks.append({"rule": f"{label}.enclave.{node['id']}",
                       "verdict": "PASS" if known else "UNKNOWN", "enclave": node["enclave"],
                       "reason": "declared_policy_enclave" if known else "no_readable_policy_enclave"})
    return {"verdict": aggregate(checks), "checks": checks, "scope": "exported configuration declarations"}


def run_bundle(bundle_path):
    """Return structured results, including invalid-input reports, without mutations."""
    bundle_path = Path(bundle_path).resolve()
    reader = EvidenceReader(bundle_path.parent)
    result = {"schema_version": 1, "tool_version": "1.0.0", "name": bundle_path.parent.name,
              "input_status": "VALID", "input_errors": [], "limitations": LIMITATIONS,
              "domains": {}, "evidence": [], "decision": "REVIEW"}
    try:
        manifest = reader.read(bundle_path.name)
        fields = {"schema_version", "name", "before", "after", "contract", "trace"}
        _object(manifest, fields, fields - {"trace"}, "bundle")
        _require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1, "bundle schema_version must be 1")
        _require(_string(manifest["name"]), "bundle name must be nonempty")
        if "trace" in manifest:
            _require(_string(manifest["trace"]), "trace must be a nonempty relative path when present")
        result["name"] = manifest["name"]
        contract = reader.read(manifest["contract"])
        _contract(contract)
        deployments, policies, nodes = {}, {}, {}
        for version in ("before", "after"):
            _object(manifest[version], {"deployment", "policy"}, {"deployment", "policy"}, version)
            deployments[version] = reader.read(manifest[version]["deployment"])
            nodes[version] = _deployment(deployments[version], version)
            policy_ref = manifest[version]["policy"]
            policies[version] = load_policy(reader.path(policy_ref), source_name=policy_ref)
            _require(policies[version].sha256 == reader.records[policy_ref]["sha256"],
                     f"{version}: policy file changed while being read or could not be read")
        for version in nodes:
            for o in contract["obligations"]:
                ids = [o["client"], o["server"]]
                if "fallback" in o:
                    ids += [o["fallback"]["client"], o["fallback"]["server"]]
                _require(all(n in nodes[version] for n in ids), f"{version}: missing obligation node binding")
            _require(all(f["node"] in nodes[version] for f in contract["forbidden"]), f"{version}: forbidden rule node missing")
        config = {v: _config(deployments[v], policies[v], v) for v in nodes}
        same_context = deployments["before"]["context_id"] == deployments["after"]["context_id"]
        endpoint_ids = {o[k] for o in contract["obligations"] for k in ("client", "server")}
        binding_changes = sorted(n for n in endpoint_ids if nodes["before"][n] != nodes["after"][n])
        platform_changes = [k for k in ("ros_distro", "rmw") if deployments["before"][k] != deployments["after"][k]]
        stable = same_context and not binding_changes and not platform_changes
        config["migration"] = {"verdict": "PASS" if stable else "UNKNOWN",
                               "reason": "stable_declared_bindings" if stable else "goal_migration_unproven",
                               "binding_changes": binding_changes, "platform_changes": platform_changes,
                               "context_unchanged": same_context}
        config["verdict"] = aggregate([config["before"], config["after"], config["migration"]])
        result["domains"]["CONFIGURATION"] = config
        authorization = {}
        for v in nodes:
            checks = []
            for f in contract["forbidden"]:
                enclave = nodes[v][f["node"]]["enclave"]
                evidence = policies[v].check(enclave, f["resource"], f["operation"])
                value = evidence["value"]
                checks.append({**f, "enclave": enclave, "policy_decision": evidence,
                               "verdict": "FAIL" if value is True else "PASS" if value is False else "UNKNOWN"})
            authorization[v] = {"verdict": aggregate(checks), "checks": checks,
                                "reason": "explicit_forbidden_queries" if checks else "no_forbidden_queries"}
        # Gate current source-policy constraints; historical findings are retained separately.
        authorization["verdict"] = authorization["after"]["verdict"]
        result["domains"]["AUTHORIZATION"] = authorization
        model = {"schema_version": 1, "name": result["name"], "obligations": [], "shared_bindings": []}
        capabilities = {"before": [], "after": []}
        for o in contract["obligations"]:
            model["obligations"].append({"id": o["id"], "goal_id": o["goal_id"], "admitted_before": True,
                                         "start": o["id"] + ":ACTIVE", "targets": [o["id"] + ":COVERED"]})
        for version in nodes:
            edges, allowed, domain, assignment = [], [], [], {}
            def rpc(oid, tag, client, server, service, start, target, when=None):
                requires = []
                for nid, op in ((client, "request"), (server, "reply")):
                    atom = f"{oid}:{tag}:{op}:{nid}"
                    evidence = policies[version].check(nodes[version][nid]["enclave"], service, op)
                    capabilities[version].append({"atom": atom, "node": nid, "enclave": nodes[version][nid]["enclave"],
                                                  "resource": service, "operation": op, **evidence})
                    if evidence["value"] is not None:
                        domain.append(atom)
                    if evidence["value"] is True:
                        allowed.append(atom)
                    requires.append(atom)
                edges.append({"id": f"{oid}:{tag}", "from": start, "to": target, "requires": requires, "when": when or {}})
            for o in contract["obligations"]:
                oid = o["id"]
                start, middle, target = oid + ":ACTIVE", oid + ":CANCEL_RPC", oid + ":COVERED"
                rpc(oid, "cancel", o["client"], o["server"], o["action"] + "/_action/cancel_goal", start, middle)
                rpc(oid, "result", o["client"], o["server"], o["action"] + "/_action/get_result", middle, target)
                if "fallback" in o:
                    f = o["fallback"]
                    key = oid + ":fallback_approved"
                    if f["approved"] is not None:
                        assignment[key] = f["approved"]
                    rpc(oid, "fallback", f["client"], f["server"], f["service"], start, target, {key: True})
            model[version] = {"edges": edges, "worlds": [{"id": version, "assignment": assignment,
                               "complete": True, "allowed": allowed, "capability_domain": domain}]}
        coverage = audit_model(model)
        result["compiled_model"] = model
        result["capability_evidence"] = capabilities
        result["domains"]["PROTOCOL_COVERAGE"] = coverage
        trace = reader.read(manifest["trace"]) if manifest.get("trace") else None
        trace_obligations = [{**o, "start": o["id"] + ":ACTIVE", "targets": [o["id"] + ":COVERED"]} for o in contract["obligations"]]
        expected_scope = {
            "context_id": deployments["after"]["context_id"],
            "deployment_sha256": reader.records[manifest["after"]["deployment"]]["sha256"],
            "policy_sha256": policies["after"].sha256,
        }
        if "trace" not in manifest:
            trace_result = {"input_status": "INCOMPLETE", "verdict": "UNKNOWN",
                            "reason": "no_trace_supplied", "obligations": []}
        else:
            trace_result = audit_trace(trace, trace_obligations)
            observed_scope = trace.get("scope") if isinstance(trace, dict) else None
            if trace_result["input_status"] != "INPUT_ERROR" and observed_scope != expected_scope:
                trace_result = {"input_status": "INCOMPLETE", "verdict": "UNKNOWN",
                                "reason": "trace_scope_missing_or_mismatch", "obligations": [],
                                "unbound_observation": trace_result}
            trace_result["expected_scope"] = expected_scope
            trace_result["declared_scope"] = observed_scope
        result["domains"]["TRACE_OBLIGATION"] = trace_result
        result["policy_issues"] = {v: policies[v].issues for v in policies}
        trace_status = result["domains"]["TRACE_OBLIGATION"].get("input_status")
        if trace_status == "INPUT_ERROR":
            result["input_status"] = "INPUT_ERROR"
            result["input_errors"].extend(result["domains"]["TRACE_OBLIGATION"].get("input_errors", []))
        elif coverage["input_status"] != "VALID" or any(p.issues for p in policies.values()) or trace_status == "INCOMPLETE":
            result["input_status"] = "INCOMPLETE"
        cv = coverage["correlated"]["verdicts"]
        gate_values = [config["after"]["verdict"], config["migration"]["verdict"], authorization["verdict"],
                       cv["after_absolute_recovery_communication"]["verdict"],
                       cv["no_new_recovery_communication_regression"]["verdict"],
                       result["domains"]["TRACE_OBLIGATION"]["verdict"]]
        if "UNKNOWN" in gate_values and result["input_status"] == "VALID":
            result["input_status"] = "INCOMPLETE"
        result["decision"] = "BLOCK" if "FAIL" in gate_values else "REVIEW" if result["input_status"] == "INCOMPLETE" else "MODEL_PASS"
        if result["input_status"] == "INPUT_ERROR":
            result["decision"] = "INPUT_ERROR"
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError) as exc:
        result.update(input_status="INPUT_ERROR", decision="INPUT_ERROR")
        result["input_errors"].append(str(exc))
    result["evidence"] = list(reader.records.values())
    result["evidence_sha256"] = hashlib.sha256(json.dumps(result["evidence"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return result
