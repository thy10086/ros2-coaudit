# ROS2-CoAudit

配置、权限与任务约束联合审计

项目实现、关键代码与可复现实验　·　v1.0.0　·　2026 年 11 月

## 摘要

机器人任务已经被接纳后，安全策略收紧可能保留常用接口，却移除取消或读取终态所需的通信权限。ROS2-CoAudit 将更新前后的部署清单、SROS2 源策略、任务契约和任务事件放到同一份审计结果中。它检查配置声明、禁止授权、旧任务的恢复通信条件和取消后的终态期限，并把每项结果关联到 XML 行号、协议路径或事件索引。

首版交付为可离线运行的科研原型，含 Python 命令行、可回放的合成证据包和无需服务器的 HTML 报告。验证在 Windows 与 Python 3.12.14 环境完成。12 个集成场景的 96 项预设分域和总判定均得到复现。

|验证层|实测结果|
|---|---|
|端到端合成证据包|12 个场景，2 MODEL_PASS，6 BLOCK，4 REVIEW|
|自动测试|联合入口与适配器 80 项，有限模型内核 34 项|
|独立有限图检查|1000 个图，835 个确定裁定与独立枚举对比，0 处不一致|

评估覆盖静态配置与合成日志。DDS 签名产物、实际中间件执行、ROS 图、机器人控制和物理仿真留给后续验证阶段。

## 阅读导航

|页码|内容|
|---|---|
|02–04|立项问题、整体架构、运行方式与输入模型|
|05–08|SROS2 权限、Action 编译、有限世界推理、事件期限|
|09–11|端到端实测、关键场景下钻、内核对照与独立检查|
|12|研究贡献边界、后续实验和来源|

<!-- page -->

## 1  项目解决什么问题

设一个巡检机器人已有正在执行的导航任务。维护人员更新源策略，打算停止接纳新任务，并把导航客户端的授权缩到仅能读结果。客户端的终态读取角色仍在，但取消服务角色已消失。对于必须经“取消 → 读终态”进入恢复流程的旧任务，读取结果单独成立仍不足以覆盖整条路径。

这个例子有三个可独立核对的问题。更新后是否还允许契约明令禁止的能力？旧任务是否仍拥有契约规定的恢复通信条件？事件记录里是否在期限内观察到同一个任务的终态？另外，配置清单还需要满足声明的安全启用方式与身份映射。

|输出域|审查对象|PASS 的精确含义|
|---|---|---|
|CONFIGURATION|声明的 RMW、安全开关、enclave 和迁移前提|指定配置项符合检查规则；旧任务端点绑定与上下文声明稳定|
|AUTHORIZATION|明列的禁止能力三元组|受支持的源策略对这些查询均给出拒绝|
|PROTOCOL_COVERAGE|旧任务在更新前后的授权路径|更新前、更新后以及无新增退化各自有独立裁定|
|TRACE_OBLIGATION|单会话日志中的任务与时间|按给定覆盖声明，在取消期限内观察到同 goal ID 终态|

### 为什么保留既有任务

每个义务有独立的 ID 和 goal ID。编译器从契约中固定收集更新前已接纳的义务，新版本的 send_goal 能力没有参与筛选。前态和后态使用同一批任务做路径检查，避免新准入关闭后旧任务从结果中消失。

### 适合的使用场景

操作者在配置审查、仿真实验准备或论文答辩中选择同一部署的两份快照，先找禁止授权与通信回归，再用观察日志核对截止时间。教学演示可直接打开随包的 12 个样例结果，改变一项权限或一个事件后重新运行，对照证据链发生的变化。

<!-- page -->

## 2  架构与可交付范围

~~~text
bundle.json
  |-- before / after deployment.json --> configuration and identity checks
  |-- before / after policy.xml -------> exact source-policy decisions
  |-- contract.json ------------------> Action template + fixed obligations
  |-- trace.json ---------------------> scoped goal event and deadline audit
  |
  +--> normalized protocol graph --> finite-world audit
                    |
                    +--> result.json + standalone index.html
~~~

|模块|实现位置|输入与产物|
|---|---|---|
|证据入口与整合|coaudit/pipeline.py|读取受限目录内的工件，校验结构，记录字节摘要并计算各域|
|权限适配器|coaudit/policy.py|索引 enclave、最终名称和角色，返回三值及 XML 行号|
|有限模型|prototype/audit.py|按世界评估可达性，用兼容世界对比较每个旧任务|
|日志检查|coaudit/trace.py|按 goal ID 分组并核对最早取消请求、终态与期限|
|展示与复跑|coaudit/report.py、run_demo.py、experiments/|生成 JSON、证据视图和验证记录|

### 两条互补的运行路径

**联合入口**每版读取一份已解析快照，自动把真实格式的受支持 SROS2 XML 映射为归一化能力，检查任务契约和声明归属明确的日志。它体现从工件到结果的完整软件流程。部署清单与 Action 名称由使用者提供最终绑定。

**有限世界入口**读取人工枚举的世界集合。它展示条件关联的研究算法，允许分别输入多种配置赋值、受支持的前后关系以及未解析能力。它与联合入口共用内核，实验结果单列。联合入口目前每版只生成一个世界。

### 证据追踪借鉴

ARTEX 社区镜像将被审对象、活动和证据版本分开记录。本项目采用对应的轻量文件结构，给每份工件记录 SHA-256，让能力行回指 XML，让路径回指协议边，让期限结论回指事件索引。审查代理参与反例与设计复核，执行时由确定性规则计算各域。本原型独立实现，ARTEX 只作静态结构参考。 [固定镜像及记录结构](https://github.com/Hinln/ARTEX/blob/f3e3f54b6c93916388a0a3dc6a439893a9abe37a/db/schema.sql#L1143)

<!-- page -->

## 3  运行与准备输入

解压后进入含 coaudit 和 run_demo.py 的目录。运行依赖 Python 3.10+ 标准库，演示浏览器可直接打开本地 HTML。下列命令可以复现审计、独立检查与完整验证。

~~~powershell
python -B -X utf8 run_demo.py --output runs/demo
python -B -X utf8 -m coaudit examples/02_cancel_removed/bundle.json --output runs/check
python -B -X utf8 experiments/run_validation.py
~~~

|文件|必填内容和用途|
|---|---|
|bundle.json|schema_version=1、名称、before/after 的部署与策略引用、契约和可选日志|
|before.json、after.json|context_id、ros_distro、rmw、安全变量声明、节点 ID/FQN/enclave|
|before.policy.xml、after.policy.xml|UTF-8 SROS2 0.2.0 源策略的受支持子集|
|contract.json|持久义务 ID、唯一 goal ID、最终 Action 名、客户端和服务端节点 ID、取消期限；可加批准回退与禁止授权查询|
|trace.json|单会话单调时间窗口、覆盖声明、带 goal ID 的事件和更新后快照声明|

### 最小输入入口

~~~json
{
  "schema_version": 1,
  "name": "权限收紧删除旧任务取消能力",
  "before": {
    "deployment": "before.json",
    "policy": "before.policy.xml"
  },
  "after": {
    "deployment": "after.json",
    "policy": "after.policy.xml"
  },
  "contract": "contract.json",
  "trace": "trace.json"
}
~~~

默认退出码 0 表示成功生成审计产物，语义上可能是 BLOCK 或 REVIEW。加上 --gate 后只有 MODEL_PASS 返回 0，BLOCK 或 REVIEW 返回 1，输入错误返回 2。单次执行输出 index.html 和 result.json，演示命令另生成总索引。证据文件路径须位于 manifest 所在目录内。

<!-- page -->

## 4  SROS2 源策略如何求值

查询键为 (enclave, 最终绝对 ROS 名称, 角色)。一个 enclave 中的 profiles 为该身份共同提供规则；同一精确能力上的 DENY 优先。已定位且完整受支持的 enclave 缺少 ALLOW 时采用默认拒绝。缺失 enclave、通配符、include 或无法解释的结构会把相关查询置为 UNKNOWN。

SROS2 的 Action 组展开三项服务 send_goal、cancel_goal、get_result 以及 feedback、status 两项 topic。call 生成服务客户端和 topic 订阅角色，execute 生成服务端和发布角色。服务 request/reply 在此分别表示客户端、服务端，两者各自覆盖其角色的双向交互。 [SROS2 官方转换模板](https://github.com/ros2/sros2/blob/bb2505b58b44ab18d1b2005bb22b70c611c58acc/sros2/sros2/policy/templates/dds/permissions.xsl#L144)

源码 coaudit/policy.py，第 161–182 行（去掉外层公共缩进）。

~~~python
matching = self._rules.get((enclave, resource, operation), ())
denied = [rule for rule in matching if not rule.allowed]
if denied:
    return {
        "value": False,
        "reasons": ["EXPLICIT_DENY: an exact DENY overrides ALLOW across this enclave's profiles"],
        "sources": _unique([rule.source for rule in matching]),
    }
if matching:
    return {
        "value": True,
        "reasons": [
            "EXPLICIT_ALLOW: exact source-policy permission; runtime DDS enforcement is not checked",
            *_unique([rule.origin for rule in matching]),
        ],
        "sources": _unique([rule.source for rule in matching]),
    }
return {
    "value": False,
    "reasons": ["DEFAULT_DENY: no exact grant in this complete supported enclave"],
    "sources": [self._enclave_sources[enclave]],
}
~~~

上面的逻辑在未知结构、无效查询和 enclave 缺失已提前退出之后执行。sources 指向原始表达式的 XML 行或完整 enclave 的行；派生 Action 规则保留原表达式来源，因此可以从缺权限的协议边回到相应策略。

### 配置声明与权限裁定独立

对于支持范围内的 DDS RMW 标识，配置检查要求环境变量 ROS_SECURITY_ENABLE 声明为区分大小写的 true，ROS_SECURITY_STRATEGY 声明为 Enforce。节点身份取部署清单中已解析的 enclave。上下文、主路径端点身份或平台标识变化会令迁移前提 UNKNOWN。签名、进程存活和实际运行时归属由外部证据验证。 [ROS 2 安全探究文档](https://github.com/ros2/ros2_documentation/blob/rolling/source/Developer-Tools/Introspection-and-analysis/Security/About-Security.rst) [Enclave 设计](https://design.ros2.org/articles/ros2_security_enclaves.html)

<!-- page -->

## 5  从任务契约生成协议图

每个已接纳任务的模板从 ACTIVE 出发。主分支先检查 cancel_goal，再检查 get_result。每一步分别查询客户端的 request 与服务端的 reply。只要一侧明确被拒绝，这一步就在该世界中不可达。环境清单负责把逻辑节点 ID 映射为各自的 enclave。

~~~text
ACTIVE -- cancel_goal --> CANCEL_RPC -- get_result --> COVERED
   |                                                   ^
   +--------- approved fallback service ---------------+
~~~

COVERED 表示模板规定的服务角色权限覆盖。模板描述必要通信条件，目标生命周期和时序仍由日志检查提供证据。默认不把 send_goal、feedback 或 status 当成旧任务恢复的必要边。 [ROS 2 Action 官方设计](https://design.ros2.org/articles/actions.html)

源码 coaudit/pipeline.py，第 244–255 行（去掉外层公共缩进）。

~~~python
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
~~~

源码 coaudit/pipeline.py，第 259–267 行（去掉外层公共缩进）。

~~~python
start, middle, target = oid + ":ACTIVE", oid + ":CANCEL_RPC", oid + ":COVERED"
rpc(oid, "cancel", o["client"], o["server"], o["action"] + "/_action/cancel_goal", start, middle)
rpc(oid, "result", o["client"], o["server"], o["action"] + "/_action/get_result", middle, target)
if "fallback" in o:
    f = o["fallback"]
    key = oid + ":fallback_approved"
    if f["approved"] is not None:
        assignment[key] = f["approved"]
    rpc(oid, "fallback", f["client"], f["server"], f["service"], start, target, {key: True})
~~~

编译器用 capability_domain 保存已可判定的能力，用 allowed 保存其中的允许项。未解析权限留在域外，内核因此区分明确拒绝与证据缺失。回退分支还要求契约中的 approved=true；approved=null 时对应条件保持未知。回退只是契约中显式批准的替代服务，实际回退效果需要运行验证。

<!-- page -->

## 6  三值路径与逐任务回归

在单个世界中，边所需的配置条件和能力必须同时满足。构建两个图。确定图只保留真边，可能图保留真边和未知边。确定图存在路径给 True；可能图仍无法到达目标给 False；只有可能图可达给 None。可能图是上界，可能仍含尚未解析的关联，因而候选路径只能支持 UNKNOWN。

源码 prototype/audit.py，第 201–207 行（去掉外层公共缩进）。

~~~python
definite = [edge for edge, state in zip(edges, edge_states) if state["value"] is True]
possible = [edge for edge, state in zip(edges, edge_states) if state["value"] is not False]
evaluations = []
for obligation in obligations:
    path = _path(obligation["start"], obligation["targets"], definite)
    possible_path = _path(obligation["start"], obligation["targets"], possible)
    value = True if path is not None else False if possible_path is None else None
~~~

### 前后世界配对

有限模式先构造前后笛卡尔积，再用显式的共享绑定约束筛配。依据至少包含声明的关系、引用、相同摘要与部署上下文，而且变量必须在相关世界中都有值。任一显式世界无合法配对会产生输入错误。未满足依据的关系保留为忽略原因，比较空间相应扩大。

~~~text
N(before_world, after_world) =
    AND over task i: NOT(K_before(i) AND NOT K_after(i))
~~~

K 表示对应任务的通信覆盖。公式逐项比较，所以已经坏掉的任务不能掩盖另一个任务新增的退化。每个性质对所有显式案例求值：全真为 PASS，全假为 FAIL，其余为 UNKNOWN。一个通过的世界可有自己的路径。跨世界回归的“无新增退化”与更新后绝对覆盖独立输出。

<!-- page -->

## 7  按 goal ID 核对取消期限

日志使用单会话的单调毫秒时间。目标 g 的最早取消请求为 t0，截止时间为 t0 + 该任务的 cancel_deadline_ms。后续重复取消不重置这个截止时间。取消接受事件单独保留，终态以同一 goal ID 的 SUCCEEDED、CANCELED 或 ABORTED 记录为准。

源码 coaudit/trace.py，第 189–208 行（去掉外层公共缩进）。

~~~python
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
~~~

完整观察窗内，终态在截止时刻或之前为 PASS，超时到达为 FAIL，严格超过截止且仍无终态为 FAIL。刚到截止而缺终态时采用保守的 UNKNOWN。日志截断、没有看到取消请求、时钟不明或事件历史歧义需要分别处理。非法时钟、非法状态和倒序时间给结构化输入错误。

### 日志归属

联合入口要求日志的 scope 声明与更新后 context_id、部署清单摘要和策略摘要匹配。摘要变化后，旧日志的原始观察结果仍可在 unbound_observation 中复核，但顶层日志性质回到 UNKNOWN。哈希一致只说明声明引用了相同字节，不能认证采集者、会话连续性或 complete=true 的真实性。

<!-- page -->

## 8  端到端实验

从 12 份合成 bundle.json 读取真实 XML 格式的源策略与 JSON 工件。独立于被测输出预置每场景八项期望。逐场景复核分域结论、证据字节摘要、演示 JSON 与 HTML 内嵌 JSON。表中 P 为 PASS，F 为 FAIL，U 为 UNKNOWN。

| 场景 | 配置 | 迁移 | 授权 | 前覆盖 | 后覆盖 | 无退化 | 日志 | 门禁 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 01 完整基线 | P | P | P | P | P | P | P | MODEL_PASS |
| 02 取消权限移除 | P | P | P | P | F | F | P | BLOCK |
| 03 禁止授权出现 | P | P | F | P | P | P | P | BLOCK |
| 04 关闭安全 | F | P | P | P | P | P | P | BLOCK |
| 05 批准回退 | P | P | P | P | P | P | P | MODEL_PASS |
| 06 策略不支持 | P | P | U | P | U | U | P | REVIEW |
| 07 缺终态 | P | P | P | P | P | P | F | BLOCK |
| 08 窗口截断 | P | P | P | P | P | P | U | REVIEW |
| 09 终态超时 | P | P | P | P | P | P | F | BLOCK |
| 10 上下文改变 | P | U | P | P | P | P | P | REVIEW |
| 11 回退未知 | P | P | P | P | U | U | P | REVIEW |
| 12 其他目标终态 | P | P | P | P | P | P | F | BLOCK |

前/后覆盖表示绝对恢复通信前提；无退化表示逐旧任务比较。配置列为更新后配置检查，迁移列是绑定连续性前提。授权列检查更新后显式禁止权限。全部 12 个场景命中预设值，单元测试和有限世界实验另行统计。

### 局部耗时与展示验证

每例热运行 30 次，共 360 次。当前主机对本地小型 bundle 读入与审计的合并中位数为 10.352 ms，p95 为 15.232 ms。计时包含文件读取、XML 解析与审计计算，排除 HTML 输出、Python 进程启动及 ROS/DDS 运行。结果随环境变化，不宜外推到大型部署。

在 Edge 中实测示例索引、BLOCK/REVIEW、版本切换、权限筛选与 JSON 下载。390 像素视口通过横向溢出检查，页面加载未发出 HTTP 请求。

<!-- page -->

## 9  读懂三组代表性场景

### 02  策略收紧以后只剩结果读取

更新前，客户端 /operator 的 Action call 规则同时覆盖取消、读结果。更新后只剩 get_result 的 request 授权，cancel_goal 对客户端返回 DEFAULT_DENY，服务器 reply 仍为允许。主路径在第一条边中断。

|证据|运行结果|可复核位置|
|---|---|---|
|更新前授权路径|navigate-1:cancel → navigate-1:result|world_evaluations.before|
|更新后取消客户端|value=false，原因 DEFAULT_DENY|after.policy.xml 第 3 行|
|覆盖及差分|更新前 P，更新后 F，无新增退化 F|correlated.verdicts|
|同一合成事件记录|日志期限 P，整体 BLOCK|TRACE_OBLIGATION 与 decision|

此场景独立设置策略和日志输入，用于验证一栏通过不会覆盖另一栏的失败。它不用于推断缺失权限发生时真实中间件仍能送达取消。

### 05 与 11  替代分支的批准条件

两例删除的都是主路径取消角色，双方仍有 /emergency_stop 的服务权限。05 中回退被明确批准，更新后授权路径为 navigate-1:fallback。11 中 approved=null，仅有可能路径，更新后覆盖和无新增退化均为 UNKNOWN，结果进入 REVIEW。

### 07、08、09 与 12  时间证据的区分

样例最早取消时刻为 200 ms，契约允许 1,000 ms，因此截止时刻为 1,200 ms。07 的完整窗口到 2,000 ms 仍只有取消接受，期限 FAIL。08 在不完整覆盖下返回 UNKNOWN。09 在 1,300 ms 才终态，超过 100 ms。12 的终态 ID 属于其他任务，原任务仍超时。读取报告时先看 TRACE_OBLIGATION 的 reason，再在 obligations 找 event_indices 与计算出的截止时刻。

<!-- page -->

## 10  有限模型对照与独立检查

另以 9 个有限世界模型检验关系推理。独立基线保留正确三值语义、使用无关联的笛卡尔积。下表为实际裁定；P、F、U 与上一表含义一致。

| 模型 | 前覆盖 | 后覆盖 | 关联无退化 | 独立无退化 |
| --- | --- | --- | --- | --- |
| 01 共享绑定 | U | U | P | U |
| 02 互斥边 | F | F | P | P |
| 03 旧任务保留 | P | F | F | F |
| 04 替代路径 | P | P | P | P |
| 05 缺共享依据 | U | U | U | U |
| 06 能力缺证据 | P | U | U | U |
| 07 既有缺陷 | F | F | P | P |
| 08 回退前提未知 | P | U | U | U |
| 09 多任务掩盖 | F | F | F | F |

### 读法与效度

样本 01 只允许 A→A、B→B，所以关联算法的无新增退化为 P，更新后绝对覆盖仍为 U。独立基线还包含 A→B 与 B→A，回归为 U。样本 02 的两个世界分别缺少连续协议的不同边，受支持世界均不可达。把两世界边混合会画出伪路径，交付中的该演示明确标为错误算法。样本 09 显示两版绝对覆盖均失败时仍可发现新的逐任务退化。

34 个内核测试中有一项穷举 64 种布尔赋值。另用独立的固定点可达性算法枚举未定值补全。种子为 20261112，在 1000 个图中对 835 个确定裁定执行检查，共 3540 个补全实例，观察到 0 处错误，其余 165 个图的实现裁定为 UNKNOWN。独立检查的范围是有限可达性与两项旧任务反例，未评估 XML、事件解析或普遍正确性。

<!-- page -->

## 11  验收、研究边界与下一步

|验收项|交付证据|
|---|---|
|配置、权限、任务联合执行|run_demo.py 与 12 份本地证据包；可从 manifest 一次生成 JSON/HTML|
|复核失败与未知|权限来源、任务路径、事件索引、配对、配置条件和输入摘要均随结果保存|
|结果复现|validation/full_validation.json、validation/logs、validation/browser_check.json|
|复审入口|README.md、docs/policy_adapter.md、关键代码与行号、tests 和 prototype/tests|

### 研究贡献可如何检验

候选贡献在于把旧任务持续义务、已解析部署和权限条件批量编译成可对照的恢复通信模型，并用有依据的关系减少不必要的未知。Margrave 已研究策略变更影响，LiSA4ROS2 已研究从 ROS 2 软件架构提取权限。论文需要证明跨层输入及解释能力带来的实证增量；当通用求解器得到同一模型与约束时，预期语义裁定应一致。 [Margrave](https://www.cs.cmu.edu/~mtschant/pubs/fkmt-verif-change-impact-xacml.pdf) [LiSA4ROS2 论文](https://lucaneg.github.io/papers/IROS24.pdf) [LiSA4ROS2 项目](https://github.com/lisa-analyzer/lisa4ros2)

### 下一阶段的三组证据

1. 固定 ROS 2 发行版与 DDS RMW，导出真实的进程、context、enclave 和最终名称。用可公布的模拟部署单独记录签名产物、governance、消息端点与日志来源。
2. 在无硬件 ROS 仿真中运行正常任务和恢复流程，采集同一 goal 的发送、取消、终态与状态迁移，并把每一项与审计预测核对。建立可独立标注的授权及运行期真值。
3. 用项目级拆分扩展样本，对比独立三值基线和共享同一模型的通用模型检查器，报告 UNKNOWN 原因、标注差异、成本和失败案例。当前 12 例与 9 例为合成机制验证。

### 语义参考

ROS 接口、命名与权限层以官方设计和固定 SROS2 代码版本为参考。ARTEX 使用 Hinln/ARTEX 社区镜像固定提交 f3e3f54，原 Autumn-27/ARTEX 在此前查验时返回 404，镜像与上游发布的关系未获核实。镜像为 AGPLv3，本包独立实现按 MIT 分发。 [ROS 2 策略设计](https://design.ros2.org/articles/ros2_access_control_policies.html) [SROS2 固定源码](https://github.com/ros2/sros2/tree/bb2505b58b44ab18d1b2005bb22b70c611c58acc) [ARTEX 固定镜像](https://github.com/Hinln/ARTEX/tree/f3e3f54b6c93916388a0a3dc6a439893a9abe37a)
