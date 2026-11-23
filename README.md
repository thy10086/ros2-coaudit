# ROS2-CoAudit v1.0.0

ROS 2 配置、权限与任务约束联合审计的离线科研原型。导入更新前后的部署快照、SROS2 源策略 XML、任务契约与可选事件日志，检查声明的安全配置、明列的禁止授权、已接纳任务的恢复通信退化，以及观察窗口内的取消终态期限。每个域保留独立结论和证据定位。

- [完整讲解与实验报告](ROS2-CoAudit_完整讲解与实验报告.pdf)
- [离线演示索引](runs/demo/index.html)
- [SROS2 适配器说明](docs/policy_adapter.md)
- [实验验证记录](validation/full_validation.json)
- [有限世界模式](prototype/README.md)

## 运行

在解压后的项目根目录执行。需要 Python 3.10 或更新版本，运行依赖为标准库。交付实测版本见验证记录。

~~~powershell
python -B -X utf8 run_demo.py --output runs/demo
python -B -X utf8 -m coaudit examples/02_cancel_removed/bundle.json --output runs/check
python -B -X utf8 experiments/run_validation.py
~~~

打开 runs/demo/index.html 查看全部样例，或者打开 runs/check/index.html 查看单次结果。result.json 包含同一结果。生成报告成功时退出 0。加 --gate 后，BLOCK 或 REVIEW 返回 1。输入错误返回 2。

运行验证会重新生成样例结果、测试日志与内核独立检查记录。可用 experiments/make_examples.py 重建合成输入文件。重建会覆盖 examples 中的同名示例。

## 自定义证据包

复制 examples/01_healthy 的整个目录。bundle.json 使用相对于自身目录的引用。修改 before.json 和 after.json 的声明快照、源策略 XML 和 contract.json，保留结构版本 1。字段与实例见完整报告第 3 节。

部署文件必须提供最终节点 FQN 与其 enclave，任务契约使用最终绝对 Action 名和逻辑节点 ID。每项旧任务义务要求 admitted_before=true、唯一 goal ID 与正的取消期限毫秒值。fallback 可声明独立服务的两端与 approved=true、false 或 null。forbidden 是明确要核对的节点、ROS 资源及角色列表。空列表产生 UNKNOWN。

日志可省略。使用单会话的单调毫秒时钟，按时间提供 accepted、cancel_requested、cancel_accepted 与 terminal。终态 status 取 SUCCEEDED、CANCELED 或 ABORTED。仅在确知日志关联的配置时填写 scope.context_id、scope.deployment_sha256 与 scope.policy_sha256。这三个字段应分别来自更新后上下文、部署文件和策略文件字节摘要。日志采集的完整性以 complete 声明。

## 结果怎么读

|结果|适用解释|
|---|---|
|MODEL_PASS|更新后配置、迁移前提、禁止授权、绝对覆盖、无新增退化和日志均满足当前有限检查|
|BLOCK|上述门禁涉及至少一项明确 FAIL|
|REVIEW|存在未知、策略超出范围或输入证据不完整|
|INPUT_ERROR|输入结构、工件引用或日志事件不符合接口|

更新前配置与授权判定可供对照，联合门禁检查更新后配置、更新后禁止授权和前后任务通信的差分。日志通过仅针对给定会话中在期限内观察到的终态。项目验证使用合成配置与日志。实际 DDS 加载、签名校验、机器人运动与物理仿真需要独立验证。应用默认按 ROS 2 Action 取消和读结果的主路径审查旧任务，已知并经契约批准的替代路径可另行显式表示。

独立的有限世界入口保留多个可接受配置、声明式前后关系与正确三值基线。联合证据包入口在每个版本使用一份已解析快照。原创代码按 MIT 许可分发。

## 后续实验

- [Jazzy 容器任务与日志复测](docs/复测报告.md)
- [批量权限变更对照](docs/批量对照报告.md)
