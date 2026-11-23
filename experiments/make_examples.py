"""Create explicitly synthetic local SROS2 source-policy/trace fixtures."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def policy(client=None, server=None, extra=""):
    client = '<actions call="ALLOW"><action>/navigate</action></actions>' if client is None else client
    server = '<actions execute="ALLOW"><action>/navigate</action></actions>' if server is None else server
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<policy version="0.2.0"><enclaves>
  <enclave path="/operator"><profiles><profile ns="/" node="mission_client">{client}{extra}</profile></profiles></enclave>
  <enclave path="/robot"><profiles><profile ns="/" node="navigation_server">{server}</profile></profiles></enclave>
</enclaves></policy>
'''


def main():
    deployment = {"schema_version": 1, "context_id": "sim-deployment-01", "ros_distro": "jazzy",
                  "rmw": "rmw_fastrtps_cpp", "security": {"enable": "true", "strategy": "Enforce"},
                  "nodes": [{"id": "client", "fqn": "/mission_client", "enclave": "/operator"},
                            {"id": "server", "fqn": "/navigation_server", "enclave": "/robot"}]}
    contract = {"schema_version": 1, "obligations": [{"id": "navigate-1", "goal_id": "goal-001",
                 "action": "/navigate", "client": "client", "server": "server", "admitted_before": True,
                 "cancel_deadline_ms": 1000}],
                "forbidden": [{"node": "client", "resource": "/admin/command", "operation": "publish"}]}
    trace = {"clock": "monotonic_ms", "complete": True, "window_start_ms": 0, "window_end_ms": 2000,
             "events": [{"goal_id": "goal-001", "event": "accepted", "ts_ms": 100},
                        {"goal_id": "goal-001", "event": "cancel_requested", "ts_ms": 200},
                        {"goal_id": "goal-001", "event": "cancel_accepted", "ts_ms": 250},
                        {"goal_id": "goal-001", "event": "terminal", "status": "CANCELED", "ts_ms": 500}]}
    labels = [
        ("01_healthy", "完整恢复通信与按期终态"),
        ("02_cancel_removed", "权限收紧删除旧任务取消能力"),
        ("03_forbidden_grant", "恢复正常但出现禁止授权"),
        ("04_security_disabled", "策略存在但配置关闭安全机制"),
        ("05_approved_fallback", "取消能力缺失但批准回退服务可用"),
        ("06_unsupported_policy", "通配符超出解释器支持范围"),
        ("07_missing_terminal", "取消已接受但完整窗口没有终态"),
        ("08_truncated_trace", "不完整观察不能证明终态缺失"),
        ("09_late_terminal", "终态晚于契约期限"),
        ("10_context_changed", "部署上下文改变且无任务迁移证明"),
        ("11_unknown_fallback", "回退前提未知"),
        ("12_wrong_goal_terminal", "其他目标终态不能履行本目标义务"),
    ]
    for key, name in labels:
        dest = ROOT / "examples" / key
        dest.mkdir(parents=True, exist_ok=True)
        before, after, ct, tr = deepcopy(deployment), deepcopy(deployment), deepcopy(contract), deepcopy(trace)
        bp, ap = policy(), policy()
        result_only = '<services request="ALLOW"><service>/navigate/_action/get_result</service></services>'
        if key in {"02_cancel_removed", "05_approved_fallback", "11_unknown_fallback"}:
            ap = policy(client=result_only)
        if key == "03_forbidden_grant":
            ap = policy(extra='<topics publish="ALLOW"><topic>/admin/command</topic></topics>')
        if key == "04_security_disabled":
            after["security"]["enable"] = "false"
            after["security"]["strategy"] = "Permissive"
        if key in {"05_approved_fallback", "11_unknown_fallback"}:
            fallback = {"service": "/emergency_stop", "client": "client", "server": "server",
                        "approved": True if key == "05_approved_fallback" else None}
            ct["obligations"][0]["fallback"] = fallback
            extra_client = '<services request="ALLOW"><service>/emergency_stop</service></services>'
            extra_server = '<services reply="ALLOW"><service>/emergency_stop</service></services>'
            bp = policy(extra=extra_client, server='<actions execute="ALLOW"><action>/navigate</action></actions>' + extra_server)
            ap = policy(client=result_only + extra_client, server='<actions execute="ALLOW"><action>/navigate</action></actions>' + extra_server)
        if key == "06_unsupported_policy":
            ap = policy(client='<actions call="ALLOW"><action>/*</action></actions>')
        if key in {"07_missing_terminal", "08_truncated_trace"}:
            tr["events"] = tr["events"][:-1]
        if key == "08_truncated_trace":
            tr["complete"] = False
        if key == "09_late_terminal":
            tr["events"][-1]["ts_ms"] = 1300
        if key == "10_context_changed":
            after["context_id"] = "replacement-process-context"
        if key == "12_wrong_goal_terminal":
            tr["events"][-1]["goal_id"] = "unrelated-goal"
        manifest = {"schema_version": 1, "name": name,
                    "before": {"deployment": "before.json", "policy": "before.policy.xml"},
                    "after": {"deployment": "after.json", "policy": "after.policy.xml"},
                    "contract": "contract.json", "trace": "trace.json"}
        for filename, data in [("bundle.json", manifest), ("before.json", before), ("after.json", after),
                               ("contract.json", ct)]:
            (dest / filename).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (dest / "before.policy.xml").write_text(bp, encoding="utf-8")
        (dest / "after.policy.xml").write_text(ap, encoding="utf-8")
        tr["scope"] = {
            "context_id": after["context_id"],
            "deployment_sha256": hashlib.sha256((dest / "after.json").read_bytes()).hexdigest(),
            "policy_sha256": hashlib.sha256((dest / "after.policy.xml").read_bytes()).hexdigest(),
        }
        (dest / "trace.json").write_text(json.dumps(tr, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Created {len(labels)} synthetic bundles in {ROOT / 'examples'}")


if __name__ == "__main__":
    main()
