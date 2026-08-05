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

## Sync-22 迭代审查（2026-08-04，Stage 3 增量）

> 枚举定义迭代（AppCategory → DeviceModeDistributionPolicy）的代码层落地。本次为命名/取值重构，不改 ADR/AC 语义边界。详见 [gates/specify.md](./gates/specify.md) Sync-22 章节。上方「规范符合性 / 代码质量 / 验证证据」为原 Stage 3 审查记录（描述旧 AppCategory 实现），保留作历史；新枚举以本节 + design/spec 为准。

### 变更范围（12 文件）

| 层 | 文件 | 改动 |
|----|------|------|
| 枚举/字段 | `application_info.h/cpp` | 枚举 `AppCategory`(`uint32_t`,7 成员,按位或) → `DeviceModeDistributionPolicy`(`int32_t`,9 成员,连续 int 0~8)；字段 `appCategory`→`deviceModeDistributionPolicy`；JSON key 常量 `APPLICATION_APP_CATEGORY`→`APPLICATION_DEVICE_MODE_DISTRIBUTION_POLICY`；Parcel `Uint32`→`Int32`；to_json/from_json 同步 |
| 字段 | `install_param.h/cpp` | 字段重命名 + Parcel `Int32` |
| 访问器 | `inner_bundle_info.h` | `Get/SetAppCategory`→`Get/SetDeviceModeDistributionPolicy` |
| 判定 | `dual_mode_helper.h/cpp` | `IsDiffPackageCategory` 实现由按位与 `(appCategory&32)!=0` 改为集合判定 `policy∈{4,6,8}`；`NeedDualModeHandle` 参数类型同步；注释更新 |
| 事件 | `bundle_common_event_mgr.h/cpp` | `NotifyBundleEvents.appCategory`→`deviceModeDistributionPolicy`；事件 Want key `"appCategory"`→`"deviceModeDistributionPolicy"`（AC-17 对外契约变更，须同步需求二） |
| 调用点 | `base_bundle_installer.h/cpp` | `SetDualModeAppInfo`/`FillDualModeEventFields`/`CheckDualModeCategoryConsistency`/`CheckDualModeCategoryConsistencyInTemp` 调用点更新（Get/Set 改名 + installParam/installRes 字段名 + 变量名 oldIsCategory7→oldIsDiffPackage + 日志/注释） |
| 调用点 | `bundle_data_mgr.cpp` | `ClassifyDualModeAppsNoLock` 3 处 `GetDeviceModeDistributionPolicy`+`IsDiffPackageCategory` + 注释 |
| 注释 | `bundle_data_mgr.h` / `inner_bundle_info.h` / `bundle_resource_parser.cpp` | "category 7"/"category-7" → "different-package" 注释一致性 |
| 单测 | `bms_dual_mode_install_test.cpp` | 枚举成员/字段/访问器全量改写；`IsDiffPackageCategory_0200` 按位或组合用例改写为多 DIFFERENT_PACKAGE 值；序列化契约测试值断言 `32u/33u/0u`→`4/1/0`、`static_cast<uint32_t>`→`<int32_t>`、`Parcel_0200` 按位或改 MAIN_ONLY 往返 |
| 单测 | `bms_bundle_kit_service_test_two.cpp` | `SetAppCategory_001`→`SetDeviceModeDistributionPolicy_001` |
| 单测 | `bms_bundle_data_storage_database_test.cpp` | JSON 测试数据 key `"appCategory"`→`"deviceModeDistributionPolicy"` |

### 静态审查结果

| 检查项 | 结果 | 证据 |
|--------|------|------|
| 全仓库代码（services + interfaces）旧 token 清零 | ✅ | grep `AppCategory\|APP_CATEGORY\|appCategory\|Get/SetAppCategory` = 0 代码命中（仅 .specs 历史对比/基线保留） |
| 注释一致性（category-7 / category 7 / cat7） | ✅ | 全部替换为 different-package / diff-package |
| `IsDiffPackageCategory` 5 调用点语义等价 | ✅ | `CheckDualModeCategoryConsistency`×2 + `ClassifyDualModeAppsNoLock`×3；集合判定 `{4,6,8}` ≡ 旧 `(x&32)!=0` 覆盖的 DIFF_PACKAGE |
| 序列化类型一致（int32_t 底层 + Int32 Parcel） | ✅ | `application_info.cpp`/`install_param.cpp` ReadInt32/WriteInt32 + `static_cast<int32_t>` |
| 单测按位或用例改写（新枚举不支持按位或） | ✅ | `IsDiffPackageCategory_0200`→多 DIFFERENT_PACKAGE 值；`Parcel_0200`→MAIN_ONLY 往返 |
| ADR/AC 语义边界不变 | ✅ | 仅命名/取值/判定实现变，隔离/校验/分类逻辑零变化 |

### 验证状态

| 项 | 结果 | 证据 |
|----|------|------|
| 本地编译 | ⏳ 待集成环境 | 本地 Windows 单仓无 build.sh/hb，无法本地编译验证 |
| 单测编译 + 运行 | ⏳ 待集成环境 | 需集成环境编译 + 全量单测（含改写用例）运行回归 |
| 运行时全 AC 集成回归 | ⏳ 待集成环境 | 编译/单测通过 ≠ 运行时回归 PASS |

### 重检范围

Sync-22 增量需在集成环境重检：① bms_target 编译通过；② 单测编译 + 全量运行（重点 `IsDiffPackageCategory`/`NeedDualModeHandle`/`DeviceModeDistributionPolicy` 序列化契约/`SetDeviceModeDistributionPolicy`）；③ 全 AC 运行时集成回归（clone app 安装/更新/卸载隔离、副模式目录/key、重启分类、跨模式 odid）无回归。人类 Owner 发布批准仍为 Stage 4 Gate。

> Sync-22 代码改动留在工作区，未经用户明确指令不 commit/push。`proposal.md`（Stage 1 基线）/`execution-plan.md`（Stage 3 原计划）保留原始记录，新枚举以 design.md / spec.md / gates/specify.md Sync-22 为准。

## Sync-23 迭代审查（2026-08-04，枚举/字段位置迁移）

> Sync-22 基础上的位置迁移（`application_info`→`bundle_info` / `ApplicationInfo`→`BundleInfo`），**语义不变**。代码改动：`bundle_info.h/cpp`（加枚举+字段+Parcel `Int32`+JSON `BUNDLE_INFO_DEVICE_MODE_DISTRIBUTION_POLICY`）、`application_info.h/cpp`（移除枚举+字段+序列化）、`inner_bundle_info.h`（Get/Set 改 `baseBundleInfo_`）、`install_param.h`（加 include `bundle_info.h`，字段保留）、`dual_mode_helper.h`/`bundle_common_event_mgr.h`（include 调整为 `bundle_info.h`）、单测（序列化契约改 `BundleInfo`，`Default_0200` InstallParam 保留；`bms_bundle_data_storage` JSON 数据清理 applicationInfo 段的无效字段）。

**静态审查**：`application_info.h/cpp` 无 `deviceModeDistributionPolicy` 残留；`bundle_info.h/cpp` 序列化完整（ReadFromParcel/Marshalling 在 applicationInfo 之后、to_json/from_json `BUNDLE_INFO_DEVICE_MODE_DISTRIBUTION_POLICY`）；`baseBundleInfo_` 经 `BASE_BUNDLE_INFO` 节点持久化（inner_bundle_info.cpp:636），**AC-1 持久化不破坏**；新特性无存量数据，AC-18 缺字段走默认值仍成立。

**验证状态**：本地 Windows 无 build.sh，编译 + 单测 + 运行时回归均待集成环境（未声明 PASS）。代码留工作区未 commit。
