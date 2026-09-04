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
status: verifying
owner: "[待确认]"
source_issue: "REQ-DUALMODE-001"
created_at: 2026-07-15
updated_at: 2026-09-04
related_features: []
related_bugs: []
related_tasks: []
related_decisions:
  - "规则检视修复轮（2026-09-04）：ohos-test-spec-rule-checking 46 条检视 spec.md，首轮 5 项不通过（TBD 子串/AC 章节内部标识符/颗粒度/孤立码 8519686/术语）全量修复——AC-41/43/45/17 按单一可验证行为拆分出 AC-48~54（行为语义零变化），实现锚点自用户故事章节迁至验收追溯证据列（头部裁剪声明标定豁免域），目标版本去 TBD（OpenHarmony-6.0-Release 引 manifest.target_release），新增术语说明表 7 条；复检终态 43 通过/0 不通过/3 不适用，✅ 可进入测试设计（spec-check-report.md）。specify/implement/release gate 范围经用户批准由 AC-1~47 编辑性同步至 AC-1~54，proposal AC 注记同步。纯文档修复，零代码改动"
  - "最终状态（2026-08-31）：代码基线 `fix_dual_doc` HEAD `bcbfe06a9`（含 `appIndex_dual_mode_13` 合流）。Stage 1 基线 + Stage 2 design/spec + Stage 3 主体实现均已批准；spec/design/proposal 已对照代码终态完成同步补齐——新增 AC-42~47 / FR-17~22 / EX-6~8 / ADR-31~36（模式独占拦截 8519947、预置 ERMS 两趟 fan-out、跨模式变体存储 tempBundleInfos_、切换互斥 8519944 安装侧接入、查询结果回显 clone appIndex=10000、DeviceModeDistributionPolicy 枚举 NAPI 运行时注册），ADR-10 重写为直读系统参数（无缓存），ispcmode 生产 key 为 bool（`ReadValidIspcmodeParam` 双路径，测试注入 key 仍 int），错误码表/对外映射/架构约束/遗留清单同步刷新。AC-1~35 编译验证通过 + AC-1~21 运行 PASS（2026-07-18）；增量（AC-36~47）代码已落地、待集成环境编译/单测/运行时回归；安装专项单测 install 164 + query 95 = 259 例（另有切换专项 42 例重叠面）。发布 Gate Blocked（运行时全 AC 回归 + 人类 Owner 发布批准未决）"
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
