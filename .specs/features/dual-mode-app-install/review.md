# 统一审查 — FEAT-20260715-001

> 双模式同包名不同安装包应用安装支持。本审查为 AI 代码审查（逐 AC 对照源码 + 模板规则）。最终阶段（Stage 4 发布）批准权属人类 Owner。

## 审查元数据

| 字段 | 内容 |
|------|------|
| 特性 | FEAT-20260715-001 双模式同包名不同安装包应用安装支持 |
| 审查人 | Claude（AI 审查） |
| 代码基线 | `appIndex_dual_mode_04` tip `80d089208`（112 例单测） |
| 审查范围 | spec AC-1~35 + design ADR-1~27 + 实现代码静态对照 |
| 复杂度 | 标准 |

## 审查输入

| 项 | 内容 |
|----|------|
| Requirement | [proposal.md](./proposal.md) |
| Design | [design.md](./design.md)（ADR-1~27） |
| Spec | [spec.md](./spec.md)（AC-1~35、FR-1~15） |
| 代码 | `services/bundlemgr/`（dual_mode_helper / base_bundle_installer / bundle_data_mgr / bundle_data_storage_rdb / bundle_resource/ / bundle_exception_handler / install_exception_mgr 等） |
| 单测 | `services/bundlemgr/test/unittest/bms_dual_mode_install_test/bms_dual_mode_install_test.cpp`（112 例 HWTEST_F） |

## 规范符合性

| 检查项 | 结果 | 证据 |
|--------|------|------|
| 需求覆盖（AC-1~35 全部由代码实现） | PASS | 逐 AC 对照源码，安装/更新路径与 `_04` 代码一致；AC-34/35（cat7 仅系统应用 + 跨 map 一致性）由 `SetDualModeAppInfo`（:5737-5764）/`CheckDualModeCategoryConsistencyInTemp`（:5782-5803）实现 |
| 架构合规（特权文件操作经 SA 511；IPC Parcel 序列化） | PASS | 安装目录创建/轮转跨 IPC 到 installd；appCategory 经 Parcel 跨进程 |
| API 契约（AppCategory 枚举 0/1/2/4/8/16/32 + ApplicationInfo/InstallParam 字段） | PASS | 与 `application_info.h` 实现一致 |
| 错误码（CATEGORY_CONFLICT 8519943 / NOT_SYSTEM_APP 8519942） | PASS | `appexecfwk_errors.h:213-214` + `status_receiver_proxy.cpp:720-723` 映射 |
| 多余实现 | 无 | 无超范围代码 |

## 代码质量

| 检查项 | 结果 | 证据 |
|--------|------|------|
| 分层（BMS 组织 / installd 操作） | PASS | 文件操作经 SA 511 |
| 线程安全 | PASS | tempBundleInfos_ 复用 bundleInfoMutex_；DualModeHelper cacheMutex_ |
| 错误处理 | PASS | CHECK_RESULT 宏 + ROLLBACK |
| 锁契约/DRY/日志 | PASS | effective name 集中 helper；日志保持原名 |

## 验证证据

| 项 | 结果 | 证据 |
|----|------|------|
| 编译（bms_target + 单测编译） | ✅ 通过 | 用户确认 `_04` `80d089208` 代码与单测均编译 OK |
| 单测 | ✅ 编译通过；112 例 | 覆盖 DualModeHelper 谓词 / GetEffectiveBundleName / Classify / Resource / AppCategory+Json / FillDualModeEventFields / Router / Skill / FetchTempBundleInfo / GenerateOdid 双 map / UpdateBundleInstallState / SetDualModeAppInfo（系统应用）/ CheckDualModeCategoryConsistencyInTemp / DeliveryProfileToCodeSign |
| 主体集成回归（AC-1~21） | ✅ 运行 PASS | 2026-07-18 集成环境编译 + 单测 + AC-1~21 全回归 PASS |
| 增量 AC（AC-22~35）运行时集成回归 | ⏳ 待集成环境 | 编译验证通过 ≠ 运行回归 PASS |

## 关键遗留（不阻塞 Stage 3，影响发布范围）

| 遗留 | 性质 | 影响 |
|------|------|------|
| 数据表未适配（10 张功能表，ADR-25） | P0/P1 | shortcut×3 / bundle_user_info.json / idle_info / patch / quickfix / app_jump / app_clone_preference / disable_forbidden 主副撞键或交叉影响 |
| Router 查询（ProcessBundleRouterMap） | 高危 | 副模式应用启动路由断裂 |
| UninstallBundleResourceRdb 全表用原名 | 高危 | keepData 重装恢复串数据 |
| AppProvisionInfo 其他查询（getAllAppProvisionInfo/ProcessCertificate/GenerateSignatureInfo） | 中 | 副模式 provision 部分查询查不到 |
| BundleResource 卸载删除/恢复 + OTA 重建 | 中 | clone prefixed resource 记录卸载残留 |
| 卸载主路径 effective-name（installStates_/provision/SetInstallMark/resource） | 中 | `_04` 卸载主路径仍原名，clone 卸载状态机/resource 清理存错配风险 |
| BMSEventHandler DB 丢失异常恢复（SaveInstallInfoToCache） | 极端 | 仅 DB 丢失极端触发，正常 OTA/重启跳过 |
| AC-17 对外契约（currentMode string→int） | 范围外 | 须同步需求二上层消费者 |

> 遗留修复方向见 [design.md](./design.md) ADR-25 / 「风险、遗留与后续计划」节。

## 审查决策

| 字段 | 内容 |
|----|------|
| 阶段 | 实现（Stage 3） |
| 决策 | **静态审查 PASS + 编译验证通过** — spec AC-1~35 / design ADR-1~27 与 `_04` 代码静态一致；编译验证通过（用户 2026-08-01 确认）。运行时全 AC 集成回归 + 人类 Owner 发布批准仍待 |
| 下一阶段 | 集成环境全 AC（AC-1~35）运行回归 PASS + 人类 Owner 发布批准 + 复盘 → [gates/release.md](./gates/release.md) 解阻塞 |
| 重检范围 | 全量（`_04` 编译 + 112 例单测运行 + 全 AC 运行时集成回归 + 人工发布批准） |

> **编译验证通过的精确含义**：用户「代码和用例均编译验证 OK」= bms_target 编译通过 + 单测编译通过（112 例）。按「证据先于声明」，运行时逐 AC 集成回归（clone app 安装/更新/卸载隔离、副模式目录/key、重启分类、跨模式 odid 等）仍须集成环境运行，编译通过不等于运行时回归 PASS。Stage 4 发布仍需人类 Owner 批准。
