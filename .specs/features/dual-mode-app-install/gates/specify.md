# 规格化阶段 Gate 检查 — FEAT-20260715-001

> 对应 gate-checklist.md「二、规格化阶段」。命中 Profile：无。
> 本 Gate 结论：**Approved**（design ADR-1~27 / spec AC-1~35 完整一致）。

## 入口检查

| 检查项 | 结果 | 证据/理由 |
|--------|------|-----------|
| Stage 1 已 Approved（前置） | ✅ | [define.md](./define.md) 总结论 Approved |

## 设计检查

| 检查项 | 结果 | 证据/理由 |
|--------|------|-----------|
| design.md 覆盖 P0/P1 AC | ✅ | ADR-1~27（[design.md](../design.md)） |
| 不涉及项已承接，N/A 与展开项都有结论 | ✅ | design.md「不涉及项承接」 |
| 涉及仓和模块职责清楚 | ✅ | bundlemanager_bundle_framework 单仓 |
| 分层和子系统边界合规 | ✅ | BMS 经 IPC 调 installd（SA 511） |
| API 变更有签名/权限/错误码/兼容性说明 | ✅ | AppCategory 枚举 + ApplicationInfo/InstallParam 字段 + 错误码 8519943/8519942 |
| BUILD.gn/bundle.json 影响明确 | ✅ | 新增 dual_mode_helper.cpp 源 |
| 关键设计决策有理由和影响说明 | ✅ | ADR-1~27 每条含问题/方案/取舍/影响 |

## 一致性检查（design.md × spec.md 交叉校验）

| 检查项 | 结果 | 证据/理由 |
|--------|------|-----------|
| 每个 ADR 有对应 AC，反之亦然 | ✅ | ADR-26↔AC-34、ADR-27↔AC-35、ADR-21↔AC-27/28/32 等 |
| 无多余/遗漏实现 | ✅ | AC-1~35 全部由 ADR-1~27 覆盖 |

## Spec 检查

| 检查项 | 结果 | 证据/理由 |
|--------|------|-----------|
| 所有 AC 使用 WHEN/THEN 格式，可独立测试 | ✅ | spec.md AC-1~35 |
| 范围边界明确（做什么/不做什么清晰） | ✅ | proposal.md / spec.md 范围边界 |
| 无语义模糊表述 | ✅ | — |
| AC 与业务/异常/恢复规则交叉一致 | ✅ | BR/FR/EX/RC 表与 AC 对齐 |

## 出口检查

| 检查项 | 结果 | 证据/理由 |
|--------|------|-----------|
| 上述全项通过 | ✅ | design + spec 完整、一致 |

## 总结论

**Approved** — design ADR-1~27 / spec AC-1~35 完整、交叉一致；编译验证通过（`_04` commit `80d089208`）。

## Approval 记录

| 字段 | 内容 |
|----|------|
| 阶段 | 规格化 |
| 决策 | Approved |
| 审查人 | 用户 |
| 证据 | design.md / spec.md 审阅通过；AC-34/35 + ADR-26/27 范围追加已纳入 |

## Stage 2 迭代变更记录（Sync-22，2026-08-04）

> 在原 Approved 基线（ADR-1~27 / AC-1~35）上的枚举定义迭代。本次为命名/取值重构，不改 ADR/AC 语义边界，但涉及 Public API 契约（枚举/字段/事件 key 改名），需重新审批 Stage 2。

### 变更点

| 项 | 旧 | 新 |
|----|----|----|
| 枚举类型名 | `AppCategory`（`uint32_t`，7 成员，按位或幂次值） | `DeviceModeDistributionPolicy`（`int32_t`，9 成员，连续 int 0~8，不支持按位或） |
| 枚举成员名 | `APP_CATEGORY_*` 前缀 | 无前缀短名（依赖 `enum class` 作用域）：UNSPECIFIED=0、MAIN_ONLY=1、SUB_ONLY=2、UNIVERSAL_IDENTICAL_PACKAGE=3、UNIVERSAL_DIFFERENT_PACKAGE=4、PARTIAL_COMPATIBLE_IDENTICAL_PACKAGE=5、PARTIAL_COMPATIBLE_DIFFERENT_PACKAGE=6、FULL_COMPATIBLE_IDENTICAL_PACKAGE=7、FULL_COMPATIBLE_DIFFERENT_PACKAGE=8 |
| 字段名 | `appCategory` | `deviceModeDistributionPolicy` |
| 访问器 | `Get/SetAppCategory` | `Get/SetDeviceModeDistributionPolicy` |
| 事件 Want key | `"appCategory"` | `"deviceModeDistributionPolicy"`（AC-17 对外契约变更，须同步需求二上层消费者） |
| "不同包体类别"判定 | `(appCategory & 32) != 0`（按位与，对应旧 DIFF_PACKAGE=32） | `IsDiffPackageCategory(policy)`：`policy ∈ {UNIVERSAL_DIFFERENT_PACKAGE(4), PARTIAL_COMPATIBLE_DIFFERENT_PACKAGE(6), FULL_COMPATIBLE_DIFFERENT_PACKAGE(8)}`（枚举值集合判定） |
| 概念名 | "类别7" | "不同包体类别（DiffPackage）"——旧"类别7"等价为新枚举 4/6/8 三个值 |

### 一致性复核

| 检查项 | 结果 | 证据/理由 |
|--------|------|-----------|
| ADR-8 重写为 DeviceModeDistributionPolicy 枚举设计 | ✅ | design.md ADR-8 |
| 数据模型枚举代码块替换 | ✅ | design.md「数据模型」 |
| `IsDiffPackageCategory` 实现由按位与改为集合判定（5 调用点语义等价） | ✅ | design.md「不同包体类别判定」；调用点：CheckDualModeCategoryConsistency / CheckDualModeCategoryConsistencyInTemp / ClassifyDualModeAppsNoLock×3 |
| spec 枚举契约表 + AC-1/2/6/13/17 + API 变更 + 兼容性 + 规则表同步 | ✅ | spec.md 全文 |
| 旧"类别7"概念全部等价迁移为"不同包体类别"，ADR/AC 语义边界不变 | ✅ | design.md + spec.md（仅命名/取值变，隔离/校验/分类逻辑不变） |
| 历史对比引用保留以说明变迁 | ✅ | ADR-8 / 判定句 / 枚举契约节"旧 AppCategory 方案"有意保留 |
| 代码层未改（仅设计文档迭代） | ✅ | 本次仅 design.md/spec.md；代码改动属 Stage 3，待 Stage 2 重新批准后执行 |

### 审批结果

- **已批准**（用户，2026-08-04）：Stage 2 枚举定义迭代（Sync-22）design.md / spec.md 审阅通过，可进入 Stage 3 代码实现。
- Stage 3 代码改动清单：`application_info.h`（枚举定义）、`install_param.h/cpp` + `application_info.cpp`（字段+序列化）、`inner_bundle_info.h`（Get/Set 改名）、`dual_mode_helper.h/cpp`（`IsDiffPackageCategory` 实现+注释）、`bundle_common_event_mgr.h/cpp`（字段+事件 key）、`base_bundle_installer.cpp`/`bundle_data_mgr.cpp`（5 调用点语义等价无需改逻辑）、单测（`bms_dual_mode_install_test.cpp` `IsDiffPackageCategory_0200` 按位或组合用例需移除/改写为新枚举值）。

## Stage 2 迭代变更记录（Sync-23，2026-08-04，枚举/字段位置迁移）

> Sync-22 基础上的位置迁移：枚举 `DeviceModeDistributionPolicy` 与字段 `deviceModeDistributionPolicy` 从 `application_info.h`/`ApplicationInfo` 迁到 `bundle_info.h`/`BundleInfo`。**语义不变**（枚举值、`IsDiffPackageCategory` 判定逻辑均不变），仅位置调整。`InstallParam.deviceModeDistributionPolicy` 保留（安装入参，独立结构体）。

### 变更点

| 项 | 迁移 |
|----|------|
| 枚举定义 | `application_info.h` → `bundle_info.h`（BundleInfo 前，namespace 顶层） |
| 字段 | `ApplicationInfo` → `BundleInfo` |
| Parcel 序列化（Int32，applicationInfo 之后） | `application_info.cpp` → `bundle_info.cpp` |
| JSON 序列化 | `APPLICATION_DEVICE_MODE_DISTRIBUTION_POLICY`（application_info.cpp）→ `BUNDLE_INFO_DEVICE_MODE_DISTRIBUTION_POLICY`（bundle_info.cpp） |
| `InnerBundleInfo` Get/Set 访问 | `baseApplicationInfo_->` → `baseBundleInfo_->` |
| InstallParam.deviceModeDistributionPolicy | **保留**（安装入参，不动） |

### 持久化与兼容性

`baseBundleInfo_` 经 InnerBundleInfo to_json `jsonObject[BASE_BUNDLE_INFO] = *baseBundleInfo_`（inner_bundle_info.cpp:636）完整持久化，字段迁后随 `baseBundleInfo` JSON 节点存储，**AC-1 持久化不破坏**；新特性无存量数据，AC-18 缺字段走默认值（UNSPECIFIED）仍成立。

### 一致性复核

| 检查项 | 结果 |
|--------|------|
| `application_info.h/cpp` 无 deviceModeDistributionPolicy 残留 | ✅ |
| `bundle_info.h/cpp` 枚举+字段+Parcel+JSON 完整 | ✅ |
| `InnerBundleInfo` Get/Set 改 `baseBundleInfo_` | ✅ |
| includes 调整（install_param / dual_mode_helper / bundle_common_event_mgr 加 bundle_info.h） | ✅ |
| 单测序列化契约改 BundleInfo（Default_0200 InstallParam 保留） | ✅ |
| design/spec 同步（ApplicationInfo→BundleInfo） | ✅ |

### 审批结果

代码已按用户明确指令落地（机械重构，语义不变）。运行时编译 + 单测 + 集成回归待集成环境验证。
