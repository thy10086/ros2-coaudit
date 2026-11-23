# SROS2 XML 策略适配器

本模块读取真实格式的本地 SROS2 **源策略** XML，并对明确支持的子集计算权限意图。它不读取或验证签名后的 DDS `permissions.p7s`，不检查 DDS 治理、证书、Domain、发现、QoS、RMW 实现或运行时是否开启安全机制。因此结果必须称为“源策略层授权”，不能称为“DDS 强制执行已验证”或“机器人已经安全”。

## 接口

```python
from pathlib import Path
from coaudit.policy import load_policy

policy = load_policy(Path("policy.xml"))
decision = policy.check("/robot", "/navigate/_action/cancel_goal", "request")
# {"value": True | False | None, "reasons": [str, ...], "sources": [str, ...]}
print(policy.issues)    # list[str]，格式/不支持项及其源位置
print(policy.sha256)    # 完整原始文件字节的 SHA-256；读失败/超限时为 None
print(policy.enclaves)  # tuple[str, ...]，文件中已识别的 enclave 路径
```

`resource` 必须是部署解析器提供的最终绝对 ROS 资源名；`operation` 只能为 `publish`、`subscribe`、`request`、`reply`。本模块按策略自身 `profile ns/node` 解释相对和私有名称，不执行 launch，也不应用部署 remap。运行节点是否真的使用指定 enclave，由其他证据与部署适配器负责。

`True` 表示受支持源策略中存在精确 ALLOW 且没有适用 DENY；`False` 表示精确 DENY，或已存在、完整受支持的 enclave 内没有相应授权；`None` 表示 UNKNOWN。不存在的 enclave 返回 UNKNOWN，避免把缺少身份策略证据伪装成已经确认的默认拒绝。

查询返回的列表和 `policy.issues` 是副本。`sources` 使用原始文件路径与 `#L行号`，Action 展开得到的规则仍指向原 Action XML 表达式。默认拒绝引用整个 enclave 的来源，配合 `policy.sha256` 固定证据版本。

## 核实依据

2026-11-13 核实官方 [ros2/sros2](https://github.com/ros2/sros2)，固定提交 `bb2505b58b44ab18d1b2005bb22b70c611c58acc`，提交元数据日期为 2026-11-03。参考位置：

- [policy.xsd](https://github.com/ros2/sros2/blob/bb2505b58b44ab18d1b2005bb22b70c611c58acc/sros2/sros2/policy/schemas/policy.xsd#L10)：策略版本、层级、属性及 ALLOW/DENY 枚举。
- [permissions.xsl](https://github.com/ros2/sros2/blob/bb2505b58b44ab18d1b2005bb22b70c611c58acc/sros2/sros2/policy/templates/dds/permissions.xsl#L27)：同一 profiles 块的规则聚合、先 DENY 后 ALLOW、默认 DENY；144 行起为服务角色，190 行起为 Action，248 行起为名称展开。
- [最小 Action 策略样例](https://github.com/ros2/sros2/blob/bb2505b58b44ab18d1b2005bb22b70c611c58acc/sros2/test/policies/minimal_action.policy.xml#L5)：Action 客户端/服务端的声明方式。该官方样例带有 XInclude；本适配器不会跟随它，须先得到已展开且可审查的本地策略。
- [官方策略设计](https://design.ros2.org/articles/ros2_access_control_policies.html)：profile 聚合、拒绝优先以及源策略与底层权限的区分。

实现是对受支持子集的独立解释，不复制 SROS2 实现源码，不调用或安装 ROS/SROS2。锁定源码是可审查的语义参照，不意味着已经针对任何发行版/RMW 完成联调认证。

## 受支持的 XML 子集

```xml
<?xml version="1.0" encoding="UTF-8"?>
<policy version="0.2.0">
  <enclaves>
    <enclave path="/robot">
      <profiles>
        <profile ns="/fleet/robot" node="controller">
          <topics publish="ALLOW">
            <topic>/clock</topic>
            <topic>status</topic>
            <topic>~/diagnostics</topic>
          </topics>
          <services request="ALLOW"><service>/halt</service></services>
          <actions call="ALLOW"><action>/navigate</action></actions>
        </profile>
        <profile ns="/fleet/robot" node="restriction">
          <services request="DENY">
            <service>/navigate/_action/send_goal</service>
          </services>
        </profile>
      </profiles>
    </enclave>
  </enclaves>
</policy>
```

支持多个不同路径的 enclave；每个 enclave 恰有一个无属性的 `profiles` 块；该块有一个或多个具有唯一 `(ns,node)` 的 `profile`。profile 可没有权限组，表示不授予任何受审资源权限。权限组与相同资源表达式可以重复；精确 DENY 覆盖同一 enclave 中任何 profile 的 ALLOW。这里的 ALLOW/DENY 重叠具有已定义语义，不是未解析的冲突。

权限组分别为 `topics`/`topic`、`services`/`service`、`actions`/`action`；合法权限属性为相应组的官方属性，值必须是大写 `ALLOW` 或 `DENY`。属性缺省不授予对应能力；整个权限组不带权限属性时也不授予能力。

名称支持：绝对名 `/clock`；相对名 `status`，按 profile namespace 展开；私有名 `~/diagnostics`，按 namespace 和 node 展开。namespace 必须绝对，可以带末尾 `/`；不会将 enclave 路径当成 namespace。资源名称不自动删除空格、不补齐重复斜线、不做大小写转换。

本版 ROS 名称限于 ASCII 字母/数字/下划线，各 token 首字符为字母或下划线，展开后最多 255 字符；资源不能是根 `/`，不能有空 token、尾斜线或替换表达式。这个限制是本适配器的子集边界，不宣称所有被拒输入都是无效 ROS 名称。enclave 路径支持根 `/` 或绝对路径，各段可含 ASCII 字母、数字、`_`、`-`、`.`，但禁止空段、`.`、`..`，最长 1024 字符。

## Action 与服务的准确含义

|源策略声明|派生服务角色|派生 topic 能力|
|---|---|---|
|`actions call="ALLOW"`|`<action>/_action/send_goal`、`cancel_goal`、`get_result` 的 `request`|`<action>/_action/feedback` 与 `status` 的 `subscribe`|
|`actions execute="ALLOW"`|上述三个服务的 `reply`|上述两个 topic 的 `publish`|
|同样声明为 `DENY`|拒绝对应角色|拒绝对应 topic 能力|

`request` 是服务客户端角色：官方模板为它生成“发布请求 + 订阅回复”的组合。`reply` 是服务端角色：对应“订阅请求 + 发布回复”。它们不能被解释为单条 DDS 消息的方向。本模块没有逐 DDS 通道查询接口，也不能证明独立部署的权限产物仍然遵守该模板。

例如同时出现 Action `call=ALLOW` 和某个派生服务 `request=DENY` 时，该服务客户端能力返回 False，其他没有被拒绝的服务仍可能返回 True。Action feedback/status 的授权也会被显式 topic DENY 覆盖。

策略展开必然保留这五个接口的授权声明；**任务是否需要使用 feedback/status，由任务契约决定**。主控不能因为策略中展开了某个接口，就把该接口自动视为每个任务的必需义务。取消响应、终态结果及物理停止的区别也属于上层任务/运行语义。

## UNKNOWN 与输入错误边界

为保持主控接口简单，本模块不设独立的 PASS/FAIL/INPUT_ERROR 枚举，所有无法可靠解释的情况均以 `value=None`、`issues` 和带代码的原因返回。主控可依据原因分类展示输入错误或不支持；不能把 `issues` 丢弃后只显示某条已读 ALLOW。

- 整体读取失败、过大、无效 UTF-8/XML、DTD/实体声明、未知 policy 版本/根、顶层未知构造、缺少无法定位的 enclave 身份：全局 UNKNOWN。
- 已定位 enclave 中的通配符、名称替换、非法结构/名称、XInclude、`xml:base`、metadata、`profiles type`、额外 transport/profile 块、remap 或未知元素/属性：该 enclave 的所有查询 UNKNOWN，其他完整独立 enclave 仍可裁定。
- 重复 enclave 路径、重复 `(ns,node)` profile：对应 enclave UNKNOWN，即使重复文本恰好相同也不猜测意图。
- 非法查询 operation、相对查询资源、非法 enclave 查询：该查询 UNKNOWN，不改变策略快照。

这些规则刻意保守。例如有一条精确 ALLOW 加上一个无法解释的 DENY 通配符时，不会悄悄忽略通配符并给出 True。未知 metadata 也不会被当成无关备注，因为官方设计允许它携带约束。

XML 限制：只接受 XML 1.0/UTF-8（允许 BOM），2 MiB 文件、20,000 元素、32 层深度。DTD、实体声明/外部实体、处理指令均拒绝；不处理 XInclude，不访问 URL，不读取引用文件。普通 XML 注释、未使用的命名空间声明及 XML 内建字符转义可以出现，但解码后的资源仍须满足名称约束。超过文件大小时不将部分输入哈希冒充完整文件哈希。

## 验证方式

在项目目录运行：

```text
python -m unittest discover -s tests -p test_policy.py -v
```

测试以正常策略、拒绝优先、Action 角色、enclave 聚合、名称展开和故障边界为重点；包括通配符混入精确授权、XInclude、metadata、重复定义、未知属性、DTD/实体、格式损坏和大小/深度限制。测试不需要网络、ROS、机器人或 DDS。

测试通过证明本模块在这些输入上的行为符合声明子集，不证明真实部署、底层权限产物或机器人运行安全。
