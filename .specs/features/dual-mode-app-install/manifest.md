---
id: FEAT-20260715-001
type: feature
title: "双模式同包名不同安装包应用安装支持"
spec_schema: ohos-sdd/v1
profile: none
target_release:
  id: OpenHarmony-6.0-Release
  status: proposed
complexity: standard
lineage: new
status: reviewing
owner: "[待确认]"
source_issue: "REQ-DUALMODE-001"
created_at: 2026-07-15
updated_at: 2026-08-11
related_features: []
related_bugs: []
related_tasks: []
related_decisions:
  - "最终状态（2026-08-11）：代码基线 `appIndex_dual_mode_07_doc` HEAD `020de12b8`（代码落地 `14eb7f286`，2026-08-06）。Stage 1 基线 + Stage 2 design/spec + Stage 3 主体实现均已批准；design ADR-1~29 / spec AC-1~40 完整一致。AC-1~35 编译验证通过 + AC-1~21 运行 PASS（2026-07-18）；增量（AC-36~40 + AC-17 5 字段 + AC-19 appIndex 置位）代码已落地、待集成环境编译/单测/运行时回归；单测 123 例。发布 Gate Blocked（运行时全 AC 回归 + 人类 Owner 发布批准未决）"
code_refs:
  - "bundlemanager_bundle_framework"
commits:
  - "80d089208（_04 tip，2026-08-01，dual mode install，IssueNo:#9695，11 文件 +363 -114）：双模式安装特性 _04 实现基线（dual_mode_helper / base_bundle_installer / bundle_data_mgr / bundle_service_constants / appexecfwk_errors / bundle_exception_handler / status_receiver_proxy / bundle_common_event_mgr / 单测 112 例）。编译验证通过（用户确认）"
  - "14eb7f286（2026-08-06，add dual appSandboxPolicy，IssueNo:#9753，13 文件 +349 -47）：增量代码落地（AppSandboxPolicy 枚举+序列化 / SetDualModeAppInfo isDiffPackage 校验+SetAppIndex / ComputeCurrentAppSandboxPolicy 粘性+before 成员+ResetInstallProperties / NotifyBundleEvents 5 字段 / Get/SetAppSandboxPolicy / 移除 instIndex 覆写特例 / 单测 +11 例至 123 例）。在当前分支 HEAD `020de12b8` 历史内（`git merge-base --is-ancestor` 确认）。编译/单测/运行时回归待集成环境"
baseline_approval:
  approved: true
  approver: "用户"
  evidence: "Stage 1 基线经需求方逐轮澄清并显式批准，proposal.md 基线结论通过，gates/define.md 总结论通过"
  date: "2026-07-15"
---
