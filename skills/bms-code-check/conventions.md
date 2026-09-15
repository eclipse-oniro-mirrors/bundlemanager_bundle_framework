# Codecheck 通用约定（conventions）

> 本文件是 [`codecheck_report_TEMPLATE.md`](codecheck_report_TEMPLATE.md) 与 [`orchestrator/SKILL.md`](orchestrator/SKILL.md) 引用的**权威评分与门禁规则**。规则为通用约定，不写入检视报告正文；生成报告时按本文件计算，不得自创分值。

## 1. 严重等级归一化（§7）

各 scanner 使用不同等级体系，合并进统一报告前必须归一化为 P0–P3：

| P 级 | 含义 | 对应常见原始等级 |
|------|------|-----------------|
| P0 | 阻塞上库：崩溃/安全漏洞/破坏性兼容变更/数据丢失 | 致命、Critical、安全 9–10 分 |
| P1 | 必须修复：功能缺陷、历史问题复发（HIST 复发/疑似复发）、关键路径无覆盖 | 严重、High、安全 7–8 分 |
| P2 | 本轮或下轮修复：规范违反、覆盖缺口、可确证的性能劣化 | 警告、Medium |
| P3 | 建议跟进：风格、可维护性、优化建议 | 建议、Low、Info |

归一化规则：
- 同一 finding 被多个 scanner 报告时，取**最高**等级；
- 历史问题核对判定"复发/疑似复发"（`bundle_framework_common_issues.md` HIST-{n}）→ **不低于 P1**；
- 兼容性影响评估 `compat_risk = high` 且存在破坏性变更 → 该变更对应 finding 为 **P0**。

## 2. 必检维度（§8）

| 目标类型 | 必检维度 |
|---------|---------|
| 代码变更（默认） | `security_review` + `logic_analyzer` + `dfx_reviewer` + `code_review_checklist` + `test_coverage_reviewer` + **兼容性影响评估（模板 §6，checklist 主导）** |
| 大型架构变更 | 上述全部 + `architecture_analyzer` |
| 纯文档变更 | 仅文档规范检查，跳过代码 scanner，但 §6 兼容性影响评估仍须给出 `compat_risk = none` 结论 |

兼容性影响评估与历史问题核对是**必填输出**：缺失时整份报告按 `insufficient` 处理。

## 3. 评分与决策矩阵（§9）

- `评分 = max(0, 100 − (30×P0 + 12×P1 + 5×P2 + 2×P3))`
- 决策规则（按顺序取首个命中）：
  1. 存在 P0 → **block**
  2. 存在 P1 → **conditional**
  3. 必检维度缺失 → **insufficient**
  4. 评分 ≥ 90 → **approve**
  5. 评分 ≥ 70 → **conditional**
  6. 其余 → **block**
- `risk_level`：`high`（存在 P0 或 compat_risk=high）/ `medium`（存在 P1 或 compat_risk=medium）/ `low`（其余）；无法评估时 `unknown`。
