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
updated_at: 2026-08-04
related_features: []
related_bugs: []
related_tasks: []
related_decisions:
  - "Stage 1 基线已批准（2026-07-15）；Stage 2 design/spec 已批准；Stage 3 主体实现集成验证 PASS（AC-1~21，2026-07-18），增量 ADR-16~27 / AC-22~35 编译验证通过（2026-08-01，_04 commit 80d089208）"
  - "Sync-21（2026-08-01）：全套 spec 刷新至 `appIndex_dual_mode_04` tip `80d089208`（112 例单测）；新增 AC-34/35 + ADR-26/27；运行时全 AC 集成回归 + 人类发布批准仍为发布 Gate 未决项"
  - "Sync-22（2026-08-04）：Stage 2 枚举定义迭代——AppCategory→DeviceModeDistributionPolicy（int32_t，9 成员连续 int 0~8，不支持按位或），字段 appCategory→deviceModeDistributionPolicy，事件 Want key 同步改名；IsDiffPackageCategory 由按位与 (appCategory&32) 改为集合判定 policy∈{4,6,8}；旧'类别7'等价为'不同包体类别（4/6/8）'。design.md/spec.md 已同步刷新，ADR/AC 语义边界不变；Public API 契约变更；Stage 2 迭代已批准（用户 2026-08-04），进入 Stage 3 代码实现"
  - "Sync-23（2026-08-04）：Stage 2 枚举/字段位置迁移——DeviceModeDistributionPolicy 枚举从 application_info.h 迁到 bundle_info.h；deviceModeDistributionPolicy 字段从 ApplicationInfo 迁到 BundleInfo；Parcel/JSON 序列化同步迁移（application_info.cpp→bundle_info.cpp，JSON key APPLICATION_DEVICE_MODE_DISTRIBUTION_POLICY→BUNDLE_INFO_DEVICE_MODE_DISTRIBUTION_POLICY）；InnerBundleInfo Get/Set 访问 baseApplicationInfo_→baseBundleInfo_；InstallParam 字段保留。baseBundleInfo_ 经 BASE_BUNDLE_INFO 节点完整持久化，AC-1 不破坏。代码已落地待集成验证"
code_refs:
  - "bundlemanager_bundle_framework"
commits:
  - "80d089208（_04 tip，2026-08-01，dual mode install，IssueNo:#9695，11 文件 +363 -114）：双模式安装特性当前实现基线（dual_mode_helper / base_bundle_installer / bundle_data_mgr / bundle_service_constants / appexecfwk_errors / bundle_exception_handler / status_receiver_proxy / bundle_common_event_mgr / 单测 112 例）。编译验证通过（用户确认）"
  - "2f9bf3d9b（_03，support dual-mode install，10 文件）+ 085961697（_03，dual mode install，7 文件）：_03 重提交基线（已被 _04 超越）"
baseline_approval:
  approved: true
  approver: "用户"
  evidence: "Stage 1 基线经需求方逐轮澄清并显式批准，proposal.md 基线结论通过，gates/define.md 总结论通过"
  date: "2026-07-15"
---
