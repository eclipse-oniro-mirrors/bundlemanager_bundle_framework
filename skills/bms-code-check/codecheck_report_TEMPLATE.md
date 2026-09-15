# 代码检视报告 — {scope}（Round {round} / 最新提交）

> 统一报告由 codecheck 工作台生成，**用于门禁管控**。所有 codecheck 报告（含 orchestrator 合并出的统一报告、单 scanner 直接产出的统一报告）必须遵循本模板：章节顺序、字段名、报告元数据块、评分与门禁规则均为**固定格式**，跨报告保持一致，便于门禁脚本解析与历史对比。
> 生成入口：[`README.md`](README.md) → Step 5；合并逻辑见 [`orchestrator/SKILL.md`](orchestrator/SKILL.md)。
> 权威评分与门禁规则为**通用规则**，不在输出报告中呈现；生成时必须按 [`conventions.md`](conventions.md) §7（等级归一化）/ §8（必检维度）/ §9（评分与决策矩阵）计算，不得自创分值。

---

## 报告元数据

> **门禁脚本只读取本 YAML 块**。字段名与取值域为固定合约，禁止改名、增删或自定义取值。人工阅读部分从「1. 门禁结论」开始。

<!-- codecheck-report-metadata:start -->
```yaml
codecheck_report:
  schema_version: "1.1"
  scope: "{scope}"
  round: {round}
  commit_id: "{commit_id}"
  change_id: "{change_id}"
  report_id: "{change_id}-R{round}"
  date: "{date}"
  gate_decision: "{gate_decision}"
  risk_level: "{risk_level}"
  score: {score}
  dimensions_required: {dimensions_required}
  dimensions_executed: {dimensions_executed}
  compat_risk: "{compat_risk}"
  historical_issues_rechecked: "{historical_issues_rechecked}"
  findings_total: {findings_total}
  findings_by_severity: {findings_by_severity}
  gate_blockers: {gate_blockers}
  must_fix: {must_fix}
  followups: {followups}
```
<!-- codecheck-report-metadata:end -->

> **v1.1 新增字段**：
> - `compat_risk`：兼容性风险结论，取值域固定为 `none | low | medium | high`（与第 6 节结论一致）。
> - `historical_issues_rechecked`：历史典型问题核对是否完成，取值域固定为 `yes | partial | no`（partial/no 时第 6.3 节必须说明缺口及理由）。


---

## 1. 门禁结论

| 项目 | 结论 |
|---|---|
| 决策 | **{gate_decision}** |
| 风险等级 | {risk_level_emoji} {risk_level} |
| 评分 | **{score}/100** |
| 阻塞项 | {gate_blockers_summary} |
| 必须修复（P0/P1） | {must_fix_count} 项 |
| 建议跟进（P2/P3） | {followups_count} 项 |

**一句话结论**：{one_line_conclusion}

---

## 2. 扣分原因（仅 gate_decision=block 时呈现；approve/conditional/insufficient 时本节省略）

> 共扣 **{total_deduction} 分**，由 {p2_count} 个 P2 和 {p3_count} 个 P3 组成。

| 扣分项 | 扣分数 | 问题 | 位置 |
|---|---|---|---|
{deduction_table_rows}

**如果想快速提分**：优先修复 **{top_deduction_id}（−{top_deduction_score} 分）**，再顺手补低优先级项即可。

---

## 3. 必须立即处理（P0/P1）

| ID | 优先级 | Scanner | 问题 | file:line | 触发路径 | 影响 |
|---|---|---|---|---|---|---|
{p0p1_table_rows}

> 无 P0/P1 项时固定写法：**无。**　详情见第 6 节。

---

## 4. 建议本轮或下一补档处理（P2/P3）

| ID | 优先级 | 问题 | 建议行动 | 排期 |
|---|---|---|---|---|
{followup_table_rows}

---

## 5. 分维度速览

| 维度 | 结果 | 关键说明 |
|---|---|---|
{dimension_table_rows}

---

## 6. 兼容性影响评估 🔥 v1.1 新增（必填章节）

> 本节评估**本次修改对当前代码功能与历史功能的影响**，是每个维度检视都必须参与的输出维度。生成规则：由 `code_review_checklist`（§A 兼容性自检）主导，`logic_analyzer`（影响范围识别）与 `test_coverage_reviewer`（回归覆盖）提供输入，orchestrator 汇总。填写依据与检查点见 [`code_review_checklist/SKILL.md`](code_review_checklist/SKILL.md) §A 与 [`bundle_framework_common_issues.md`](bundle_framework_common_issues.md)。
> `compat_risk` 取值：`none`（无接口/行为变化）→ `low`（仅内部行为微调且有回归覆盖）→ `medium`（行为变化但已识别全部影响面并有兜底）→ `high`（存在破坏性变更或影响面未知，gate_decision 至少为 conditional）。

### 6.1 影响面分析（修改 → 受影响的功能）

| # | 修改点（file:line） | 变更类型 | 直接影响的功能 | 波及的历史功能/调用方 | 影响程度 |
|---|---|---|---|---|---|
| 1 | {file}:{line} | {新增/修改/删除} | {如：ProcessBundleInstall 的校验顺序} | {如：OTA 升级路径（SystemBundleInstaller 复用同一流程）、预装恢复} | {高/中/低} |

> 分析要求：不只列直接调用方。bundle_framework 中必须沿以下四条历史链路追踪波及：
> 1. **安装/卸载/更新主流程**（`BundleInstaller` → `BaseBundleInstaller` → `SystemBundleInstaller`/`BundleMultiUserInstaller`/Clone/HSP 安装器共享基类逻辑，改基类即全链路受影响）；
> 2. **启动恢复链路**（`BundleMgrService` OnStart → 开机扫描/`loadExistData_`/`pre_install_exception_mgr`，改数据格式或状态语义必须验证重启后恢复）；
> 3. **查询链路**（`bundle_mgr_host_impl` → `BundleDataMgr` → 各查询接口，含 `_V9`/`_WITH_INT_FLAGS` 双版本接口，改过滤/返回字段必须双版本核对）；
> 4. **持久化链路**（`BundleDataMgr` ↔ RDB（`bundle_data_storage_rdb`）↔ JSON 序列化，改结构体字段/序列化顺序必须验证旧数据加载）。

### 6.2 兼容性检查结论

| 兼容性项 | 是否涉及 | 结论 | 证据（file:line） |
|---|---|---|---|
| IPC code（`bundle_framework_core_ipc_interface_code.h` / `bundle_framework_services_ipc_interface_code.h`）是否仅追加在枚举末尾、无删改/中间插入 | {是/否} | {✅/❌ 结论} | {证据} |
| Parcel 序列化（新增字段是否追加在 Marshalling/Unmarshalling 末尾、读写顺序一致、旧数据可读） | {是/否} | {✅/❌} | {证据} |
| 错误码（`appexecfwk_errors.h`：是否新增而非修改既有码；JS/NAPI 映射是否同步） | {是/否} | {✅/❌} | {证据} |
| 对外行为（既有接口返回值/回调时序/参数取值范围/权限要求是否变化） | {是/否} | {✅/❌} | {证据} |
| 持久化数据（RDB 记录/JSON 字段是否向后兼容旧版本数据） | {是/否} | {✅/❌} | {证据} |
| 新特性 flag/policy 是否覆盖 install/uninstall/OTA/预置/query 五条主流程（防"新特性遗漏旧分支"） | {是/否} | {✅/❌} | {证据} |
| 性能（接口性能是否明显劣化，尤其查询热路径与开机扫描） | {是/否} | {✅/❌} | {证据} |

### 6.3 历史问题核对（对照 [`bundle_framework_common_issues.md`](bundle_framework_common_issues.md)）

| 问题类别（HIST 编号） | 本 PR 是否涉及 | 核对结论 |
|---|---|---|
| 1. userId 语义混用 | {是/否} | {✅ 未复发 / ⚠️ 疑似 / ❌ 复发 + 证据 file:line；不涉及时写"—（未触碰共享资源）"或未核对理由} |
| 2. 并发与锁问题 | {是/否} | {...} |
| 3. RDB 异常兜底缺失 | {是/否} | {...} |
| 4. 错误码返回遗漏/映射不合理 | {是/否} | {...} |
| 5. JSON 解析健壮性 | {是/否} | {...} |
| 6. IPC/Parcel 参数校验缺失 | {是/否} | {...} |
| 7. 路径处理/路径穿越 | {是/否} | {...} |
| 8. 安装/卸载数据一致性与 ID 复用 | {是/否} | {...} |
| 9. 预置应用 × OTA 场景 | {是/否} | {...} |
| 10. HSP/共享包与双模式适配 | {是/否} | {...} |
| 11. 日志/DFX 规范不达标 | {是/否} | {...} |
| 12. 静态告警与 fuzz 用例质量 | {是/否} | {...} |

> 核对规则：变更涉及热点文件（`base_bundle_installer.cpp`、`bundle_data_mgr.cpp`、`bundle_mgr_host_impl.cpp`）时 HIST-1~12 **全部必核**；`historical_issues_rechecked = partial/no` 时必须在此说明缺口理由。判定"复发/疑似复发"的问题按 P1 起评级，编号追加 `HIST-{n}` 标签进入第 7 节 finding 卡片。

### 6.4 兼容性结论

- **compat_risk**：{none/low/medium/high}
- **一句话结论**：{本次修改对既有功能的影响与兜底情况}
- **回归建议**：{需重点回归的历史功能清单，如"OTA 升级后首次开机扫描、多用户卸载保留数据场景"}

---

## 7. 关键发现详情

> P0/P1 必出全量卡片；P2/P3 按需精选或全出。每条 finding 按以下固定卡片格式呈现；复发历史典型问题的 finding 需在标题追加 `HIST-{n}` 标签，并在"影响"中注明对应 [`bundle_framework_common_issues.md`](bundle_framework_common_issues.md) 的问题类别：

### [{finding_id}] {finding_title} ({severity}, scanner={scanner_name})

- **位置**：`{file}:{line}`
- **触发路径**：{trigger_path}
- **影响**：{impact}
- **证据**：{evidence}
- **建议**：{recommendation}
