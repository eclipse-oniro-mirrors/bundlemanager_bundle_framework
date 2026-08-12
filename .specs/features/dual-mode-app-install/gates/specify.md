# 规格化阶段 Gate 检查 — FEAT-20260715-001

> 对应 gate-checklist.md「二、规格化阶段」。命中 Profile：无。
> 本 Gate 结论：**Approved**（design ADR-1~29 / spec AC-1~40 完整一致）。

## 入口检查

| 检查项 | 结果 | 证据/理由 |
|--------|------|-----------|
| Stage 1 已 Approved（前置） | ✅ | [define.md](./define.md) 总结论 Approved |

## 设计检查

| 检查项 | 结果 | 证据/理由 |
|--------|------|-----------|
| design.md 覆盖 P0/P1 AC | ✅ | ADR-1~29（[design.md](../design.md)） |
| 不涉及项已承接，N/A 与展开项都有结论 | ✅ | design.md「不涉及项承接」 |
| 涉及仓和模块职责清楚 | ✅ | bundlemanager_bundle_framework 单仓 |
| 分层和子系统边界合规 | ✅ | BMS 经 IPC 调 installd（SA 511） |
| API 变更有签名/权限/错误码/兼容性说明 | ✅ | DeviceModeDistributionPolicy + AppSandboxPolicy 枚举 + BundleInfo/InstallParam 字段 + 错误码 8519943/8519942 |
| BUILD.gn/bundle.json 影响明确 | ✅ | 新增 dual_mode_helper.cpp 源 |
| 关键设计决策有理由和影响说明 | ✅ | ADR-1~29 每条含问题/方案/取舍/影响 |

## 一致性检查（design.md × spec.md 交叉校验）

| 检查项 | 结果 | 证据/理由 |
|--------|------|-----------|
| 每个 ADR 有对应 AC，反之亦然 | ✅ | ADR-26↔AC-34、ADR-27↔AC-35、ADR-28↔AC-38、ADR-29↔AC-39/40 等 |
| 无多余/遗漏实现 | ✅ | AC-1~40 全部由 ADR-1~29 覆盖 |

## Spec 检查

| 检查项 | 结果 | 证据/理由 |
|--------|------|-----------|
| 所有 AC 使用 WHEN/THEN 格式，可独立测试 | ✅ | spec.md AC-1~40 |
| 范围边界明确（做什么/不做什么清晰） | ✅ | proposal.md / spec.md 范围边界 |
| 无语义模糊表述 | ✅ | — |
| AC 与业务/异常/恢复规则交叉一致 | ✅ | BR/FR/EX/RC 表与 AC 对齐 |

## 出口检查

| 检查项 | 结果 | 证据/理由 |
|--------|------|-----------|
| 上述全项通过 | ✅ | design + spec 完整、一致 |

## 总结论

**Approved** — design ADR-1~29 / spec AC-1~40 完整、交叉一致。AC-1~35 `_04` 编译验证通过 + AC-1~21 运行 PASS（2026-07-18）；AC-36~40 代码已落地（`14eb7f286`）待集成环境编译/单测验证。代码静态核对见 [review.md](../review.md)。

## Approval 记录

| 字段 | 内容 |
|----|------|
| 阶段 | 规格化 |
| 决策 | Approved |
| 审查人 | 用户 |
| 证据 | design.md / spec.md 审阅通过；ADR-1~29 / AC-1~40 范围均已纳入 |
