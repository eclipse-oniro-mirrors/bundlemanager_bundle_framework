# 代码检视报告 — bms-code-check 模板文件新增（Round 1 / 最新提交）

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
  scope: "bms-code-check 模板文件新增"
  round: 1
  commit_id: "6fe613d98"
  change_id: "ai_reviewDoc-2024-08-11"
  report_id: "ai_reviewDoc-2024-08-11-R1"
  date: "2024-08-11"
  gate_decision: "approve"
  risk_level: "low"
  score: 95
  dimensions_required: 4
  dimensions_executed: 4
  findings_total: 3
  findings_by_severity: {"P2": 2, "P3": 1}
  gate_blockers: 0
  must_fix: 0
  followups: 3
```
<!-- codecheck-report-metadata:end -->


---

## 1. 门禁结论

| 项目 | 结论 |
|---|---|
| 决策 | **approve** |
| 风险等级 | 🟢 low |
| 评分 | **95/100** |
| 阻塞项 | 0 项 |
| 必须修复（P0/P1） | 0 项 |
| 建议跟进（P2/P3） | 3 项 |

**一句话结论**：模板结构完整，符合代码检视报告规范，建议合并。

---

## 2. 扣分原因（仅 gate_decision=block 时呈现；approve/conditional/insufficient 时本节省略）

> 共扣 **5 分**，由 2 个 P2 和 1 个 P3 组成。

| 扣分项 | 扣分数 | 问题 | 位置 |
|---|---|---|---|
| DOC-001 | -2 | 缺少模板使用示例 | codecheck_report_TEMPLATE.md:1 |
| DOC-002 | -2 | 缺少与 orchestrator 集成说明示例 | codecheck_report_TEMPLATE.md:3 |
| DOC-003 | -1 | 示例行未展示完整格式 | codecheck_report_TEMPLATE.md:60 |

**如果想快速提分**：优先修复 **DOC-001（−2 分）**，再顺手补低优先级项即可。

---

## 3. 必须立即处理（P0/P1）

| ID | 优先级 | Scanner | 问题 | file:line | 触发路径 | 影响 |
|---|---|---|---|---|---|---|

> 无 P0/P1 项时固定写法：**无。**　详情见第 6 节。

---

## 4. 建议本轮或下一补档处理（P2/P3）

| ID | 优先级 | 问题 | 建议行动 | 排期 |
|---|---|---|---|---|
| DOC-001 | P2 | 缺少模板使用示例 | 添加 README 或示例展示如何填充模板 | 本轮 |
| DOC-002 | P2 | 缺少与 orchestrator 集成说明 | 在 SKILL.md 中添加具体使用流程 | 本轮 |
| DOC-003 | P3 | 示例行未展示完整格式 | 补充 deduction_table_rows 完整示例 | 下一补档 |

---

## 5. 分维度速览

| 维度 | 结果 | 关键说明 |
|---|---|---|
| 文档规范 | ✅ 通过 | 模板结构完整，元数据定义清晰 |
| 兼容性 | ✅ 通过 | 纯 Markdown 格式，无兼容性问题 |
| 安全编码 | ⚠️ 跳过 | 文档文件，不涉及代码安全 |
| 编码风格 | ✅ 通过 | Markdown 格式规范 |

---

## 6. 关键发现详情

> P0/P1 必出全量卡片；P2/P3 按需精选或全出。每条 finding 按以下固定卡片格式呈现：

### [DOC-001] 缺少模板使用示例 (P2, scanner=documentation)

- **位置**：`codecheck_report_TEMPLATE.md:1`
- **触发路径**：文件根目录
- **影响**：用户可能不清楚如何正确填充模板字段
- **证据**：模板仅包含占位符，缺少具体使用示例
- **建议**：在 `skills/bms-code-check/README.md` 中添加模板填充示例

### [DOC-002] 缺少与 orchestrator 集成说明 (P2, scanner=documentation)

- **位置**：`codecheck_report_TEMPLATE.md:3`
- **触发路径**：文档注释引用
- **影响**：用户可能不理解模板与 orchestrator 的关系
- **证据**：注释提到 orchestrator 但无具体集成示例
- **建议**：补充 orchestrator/SKILL.md 集成流程说明

### [DOC-003] 示例行未展示完整格式 (P3, scanner=documentation)

- **位置**：`codecheck_report_TEMPLATE.md:60`
- **触发路径**：表格示例行
- **影响**：轻微，用户可参考其他部分理解格式
- **证据**：deduction_table_rows 占位符未展开
- **建议**：可选优化，补充完整示例行

---

**检视完成**。模板文件质量良好，建议补充使用文档后合并。
