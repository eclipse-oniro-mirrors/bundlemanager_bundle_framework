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
  schema_version: "1.0"
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
  findings_total: {findings_total}
  findings_by_severity: {findings_by_severity}
  gate_blockers: {gate_blockers}
  must_fix: {must_fix}
  followups: {followups}
```
<!-- codecheck-report-metadata:end -->


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

## 6. 关键发现详情

> P0/P1 必出全量卡片；P2/P3 按需精选或全出。每条 finding 按以下固定卡片格式呈现：

### [{finding_id}] {finding_title} ({severity}, scanner={scanner_name})

- **位置**：`{file}:{line}`
- **触发路径**：{trigger_path}
- **影响**：{impact}
- **证据**：{evidence}
- **建议**：{recommendation}
