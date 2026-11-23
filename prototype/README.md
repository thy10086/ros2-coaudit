# ROS 2 联合安全审计：有限世界算法示例

这份原型把研究方案中最容易产生错误结论的部分变成可复算示例：**在同一个配置世界内检查已准入任务的授权通信路径，并在有依据的前后世界配对上逐任务检查新增退化。**

它是新项目的概念算法，不是旧 MissionGuard 的重命名。代码不连接 ROS、不执行 launch、不解析 DDS XML、不扫描网络，也不自动修改或部署权限。输入仅为人工给定的归一化能力原子、有限协议图和假设配置世界。它不构成真实机器人安全评估结果。

## 1. 快速运行

需要 Python 3.10 或更新版本，仅使用标准库。在本目录执行：

```powershell
python -B -X utf8 -m unittest discover -s tests -v
python -B -X utf8 audit.py --fixtures fixtures --output results/audit_results.json
```

本次实际验证使用 Python 3.12.14，34 项测试通过。其中一个测试另外穷举 8×8=64 种前后权限赋值，与独立的布尔表达式 oracle 比较。`results/audit_results.json` 是实际运行输出，不是手写预期结果。

可用 `python -X utf8 make_fixtures.py` 重建 9 个合成 JSON。该操作会重写本目录下这 9 个同名 fixture；修改过 fixture 后请先保存自己的版本。

命令成功生成审计结果时退出码为 0；性质出现 FAIL 仍表示审计正常完成。输入非法时退出码为 2，并在结果中写明 INPUT_ERROR。

## 2. 已经实现与尚未实现

已经实现：

- 有限配置世界与协议图的结构校验。
- 依赖能力和条件的确定/可能边判定。
- 每个世界内部的 BFS 路径证据与缺失能力说明。
- 固定 before 已准入任务的持续义务，不因 after 拒绝新任务而删掉旧任务。
- 有显式依据的共享变量关联；缺少依据时回退到独立笛卡尔积基线。
- 分别输出 before 绝对前提、after 绝对前提、逐任务无新增退化三个性质。
- 规范化输入 SHA-256、世界对、逐任务布尔结果、已用/忽略的关联依据。

尚未实现：ROS/launch 导出器、真实 node/enclave/participant 映射、DDS XML 与通配符语义、身份签名与 Enforce 检查、日志 TRACE_OBLIGATION、时钟与截止时间、实际消息送达、机器人控制和物理停止。这些都不能由本原型的 PASS 推出。

`AUTHORIZATION` 在本例中是输入事实，不是从真实策略推导出的证明。`PROTOCOL_COVERAGE` 是主要演示对象。输出中的路径只代表**模型内恢复所需的授权通信前提**。

## 3. 输入含义

每个 fixture 包括：

|字段|含义|
|---|---|
|`before.worlds` / `after.worlds`|各版本显式给出的非空有限世界集合|
|`assignment`|该世界的联合配置赋值，例如 namespace 和模式|
|`capability_domain`|已声明可解释的归一化能力原子集合|
|`allowed`|有正面证据支持的获准能力，必须属于 capability_domain|
|`complete`|在 domain 内是否允许把未列入 allowed 的能力判为拒绝|
|`edges`|协议边：源状态、终状态、所需能力集合、相等条件|
|`obligations`|before 已准入实例、当前状态和完成通信义务的终态|
|`shared_bindings`|支持跨版本同值关联的显式假设依据|
|`admit_new_goal`|元数据，不参与已有任务义务的筛选|

能力名如 `cancel_reply`、`fallback_ack` 只是合成原子，不能直接当成实际 DDS topic 名称或 ROS Action 的完整通信映射。`DONE` 也只表示声明的通信前提已满足，不表示机器人已停止或任务已完成。

权限不完整时，明确列在 allowed 中的能力仍是已知正事实；未列入 allowed 的能力只能判为未知。即使 complete=true，某个 requires 原子不在 capability_domain 中也判未知，不能默认为拒绝。

`shared_bindings` 只有同时满足以下条件才会被使用：关系为 `declared_unchanged`；basis_ref 非空；两个 digest 是相同的 64 位十六进制字符串；两个 deployment context 相同且非空；对应变量在所有相关世界都有赋值。**本原型只检查这些声明是否一致，没有读取工件来验证 hash，也没有验证真实部署上下文。** 示例中的重复字符 hash 是明确的合成假设。

字段同名、世界 ID 同名或 namespace 拼写相同都不会自动建立共享关系。任何必要依据缺失、改变或不支持时，该关系会被忽略并记录原因，随后使用未被其他有效关系限制的世界配对。同一变量的重复关联声明被拒绝为 INPUT_ERROR，避免一条格式有效的声明掩盖另一条矛盾声明。本例无法识别任意格式正确的伪造依据；真实工件真实性验证是后续导出器和证据验证层的职责。

## 4. 算法与三值语义

对于版本 V、世界 w、已准入实例 i，定义 K(V,w,i) 为从该实例当前状态到允许终态的一条授权路径是否存在。

1. 对每条边检查所有条件与所需能力。明确不满足任一项为假；全部明确满足为真；其余为未知。
2. 仅用真边做 BFS：找到路径则 K=真。
3. 用真边和未知边做 BFS：仍找不到路径则 K=假；仅可能图有路径则 K=未知。
4. 所有路径都在同一个世界内求解，不能跨互斥世界拼接。

未知边的“可能图”是保守上界，可能包含尚未解析的互斥条件。因此可能图有路径只足以得到 UNKNOWN，不能得到 PASS。

绝对性质对各任务的 K 合取，再跨可接受世界归约。对于兼容的前后世界对 (b,a)，无新增退化按每项任务分别定义：

```text
N(b,a) = AND over i [ NOT(K(before,b,i) AND NOT K(after,a,i)) ]
```

不能改成“before 所有任务都满足 ⇒ after 所有任务都满足”：那会让一个原本失败的任务掩盖另一个原本正常任务的新退化。fixture 09 专门验证这一点。

未知值按可能的真/假补全做保守计算。所有可接受案例为真则 PASS；全部为假则 FAIL；真假混合则 UNKNOWN(reason=conditional)，含未解析影响则通常为 UNKNOWN(reason=incomplete)。未解析边与当前性质无关时，该性质仍可有确定结论。

顶层 `input_status` 与性质裁定不同：

- `VALID`：本例所需输入结构完整且没有未解析边。
- `INCOMPLETE`：至少一条边的相关事实未解析；具体性质仍分别判定。
- `INPUT_ERROR`：空世界、空义务、非法结构或关联导致世界无法配对等。所有性质为 UNKNOWN，不允许空集上的真空 PASS。

任何显式世界被共享关系排除到完全无法配对，都会导致 INPUT_ERROR。本例要求完整枚举的共同部署范围；“本次只比较某个子范围”需要由调用者显式另建模型，不能悄悄丢弃世界。

每个世界可以选择不同路径，所以结果最多是“每个世界分别存在路径”，**不是**“存在一个控制器能在未知世界中共同执行的策略”。

## 5. 九个示例的真实结果

下表中的“绝对”均指授权通信前提。`独立 N` 是没有跨版本关联的正确三值基线，不是故意设置的弱基线。

|示例|before 绝对|after 绝对|关联 N|独立 N|解释|
|---|---|---|---|---|---|
|01 共享绑定关联|UNKNOWN|UNKNOWN|PASS|UNKNOWN|同一未知 namespace 的前后状态保持一致，已有缺陷仍显示|
|02 互斥边|FAIL|FAIL|PASS|PASS|每个世界都缺完整路径；并集算法会制造伪路径|
|03 旧任务与新准入拒绝|PASS|FAIL|FAIL|FAIL|拒绝新任务不能取消旧任务恢复义务|
|04 合法替代路径|PASS|PASS|PASS|PASS|独立 stop+ack 分支满足声明前置条件|
|05 缺少共享依据|UNKNOWN|UNKNOWN|UNKNOWN|UNKNOWN|字段同名不足以关联|
|06 能力域缺证据|PASS|UNKNOWN|UNKNOWN|UNKNOWN|缺事实不等于已拒绝|
|07 已有缺陷|FAIL|FAIL|PASS|PASS|无新增退化不代表系统已有能力完整|
|08 替代分支前置条件未知|PASS|UNKNOWN|UNKNOWN|UNKNOWN|不能假设 stop 分支可用|
|09 多任务掩盖反例|FAIL|FAIL|FAIL|FAIL|旧缺陷不能掩盖另一个任务的新退化|

fixture 02 额外输出 `unsound_union_demonstration`，刻意展示错误方法将不同世界的 may 边取并集后找到伪路径。该字段显式标为不健全演示，不参与正式裁定，也不是合法基线。

## 6. 如何阅读结果证书

先看 input_status 和 input_errors，再看三个性质，不要只取 no_new_regression。

`world_evaluations` 列出每个世界的义务结果、authorized_path、possible_path 和逐边 reasons。`correlated.pairs` 给出实际允许的世界对、每个任务前后结果和无退化结论。`shared_bindings.applied/ignored` 解释为何有些世界组合被排除或保留。

例如 fixture 01 的合法配对只有 A→A、B→B。独立基线还包含 A→B 和 B→A，因此对无新增退化保持 UNKNOWN。关联方法没有“修复”B：before 和 after 绝对结果仍然 UNKNOWN。

fixture 09 的绝对前提两版均 FAIL，但 `previously-healthy-task` 由真变假，最终 N=FAIL；`already-broken-task` 的既有失败不能抵消这一反例。

## 7. 测试边界

34 个测试方法覆盖上述 9 个 fixture、共享证据缺失/变化/上下文变化/重复声明、未知条件与权限、空输入和未匹配世界、多任务掩盖、不同 JSON 类型以及 CLI 成功和损坏输入。NaN/Infinity/-Infinity 等非有限赋值、条件或非标准 JSON 常量被判为 INPUT_ERROR，不能因 NaN 不等于自身而产生确定的 guard mismatch。另有一个完整 64 组合 oracle 子实验验证“两段主路径或一个替代路径”的逻辑。

这些测试验证有限算法的行为，不证明真实 ROS 策略解析正确，也不构成论文级有效性实验。论文阶段仍需固定实际 ROS/RMW/DDS 支持子集、独立标注、项目级数据拆分、真实导出器验证、强基线和失败案例审查。

## 8. 文件导航

- `audit.py`：纯标准库审计器和 CLI。
- `make_fixtures.py`：生成明确的合成模型。
- `fixtures/*.json`：9 个可手工检查的模型，附预期结果。
- `tests/test_audit.py`：行为反例和独立布尔 oracle。
- `results/audit_results.json`：本次实际计算证书。

研究贡献仍须查新。世界关联、三值逻辑与图遍历本身不是新算法；本例的用途是帮助检验“持续任务义务 + 有依据的前后配置关联”是否值得在 ROS 2 实际配置审阅中继续研究。
