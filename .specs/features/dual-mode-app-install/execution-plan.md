# 执行计划

> 将 Spec 拆成可独立执行、可验证、可审查的 Task。每个 Task 自包含。当前代码基线：`appIndex_dual_mode_04` tip `80d089208`，TASK-1~6 已落地（编译验证通过）。

## Plan 元数据

| 字段 | 内容 |
|------|------|
| Plan ID | PLAN-20260715-001 |
| 关联 Feature | FEAT-20260715-001 |
| 关联文档 | proposal.md / design.md / spec.md |
| 复杂度 | 标准 |
| 状态 | Approved（已实现） |
| Owner | [待确认] |

## 输入状态

| 输入 | 路径 | 要求状态 |
|------|------|----------|
| Requirement | [proposal.md](./proposal.md) | Approved ✅ |
| Design | [design.md](./design.md) | Approved ✅ |
| Spec | [spec.md](./spec.md) | Approved ✅ |

## AC 到 Task 追溯

| AC | Task | 验证方式 |
|----|------|----------|
| AC-1 / AC-2 / AC-18 | TASK-1 | 单测（序列化往返 / 默认值 / 缺字段） |
| AC-3 / AC-33 | TASK-2, TASK-3 | 单测+集成（ispcmode/mainmode 缺失/非法回退） |
| AC-4 / AC-5 / AC-6 / AC-10 | TASK-3, TASK-4 | 集成（副模式目录隔离 / 主模式不处理 / 类别1~6 / 轮转） |
| AC-7 / AC-8 / AC-9 / AC-35 | TASK-3 | 集成（类别一致性校验：同类别/类别7互转/非7互转/跨map） |
| AC-11 | TASK-4, TASK-5 | 集成（查询验证） |
| AC-12 / AC-13 / AC-14 / AC-15 | TASK-5 | 集成（重启分类加载） |
| AC-16 | TASK-3, TASK-5 | 集成（跨模式 odid 比对） |
| AC-17 | TASK-6 | 集成（事件字段 appCategory/currentMode int/isSharedSandbox） |
| AC-19 / AC-20 / AC-21 | TASK-3 | 集成（hap token instIndex=10000 / 独立 uid / 异常恢复按原名查询） |
| AC-22 / AC-23 | TASK-3 | 集成（skills 目录 / skills description 数据层 effective name） |
| AC-24 / AC-25 | TASK-3 | 集成（AppProvisionInfo 插入删除 / getAppProvisionInfo 查询 effective name） |
| AC-26 | TASK-3 | 集成（Router 插入删除更新 effective name） |
| AC-27 / AC-28 / AC-32 | TASK-3 | 集成（installStates_ effective name 状态机 / 非clone回归 / 4独立调用方零回归） |
| AC-29 / AC-30 / AC-31 | TASK-3 | 集成（BundleResource 写入重启重建 effective name / 非clone回归 / 语言主题刷新） |
| AC-34 | TASK-3 | 单测+集成（类别7仅系统应用准入 NOT_SYSTEM_APP 8519942） |

## 阶段计划

| 阶段 | 目标 | 关键 Task | 结束门槛 |
|------|------|-----------|----------|
| Phase-1 | 基础骨架：枚举字段 + 模式工具类 | TASK-1, TASK-2 | 序列化单测 + 工具类单测通过 |
| Phase-2 | 核心隔离：安装前缀 + DB key 适配 | TASK-3, TASK-4 | 副模式目录隔离 + key 不被自愈误删 |
| Phase-3 | 查询与通知：重启加载 + 事件字段 | TASK-5, TASK-6 | 重启分类加载正确 + 事件字段正确 |

## Task 列表

| Task ID | 目标 | 文件范围 | AC 映射 | 前置依赖 | 完成判据 | 验证命令 |
|---------|------|----------|---------|----------|----------|----------|
| TASK-1 | 应用类别枚举 + ApplicationInfo/InstallParam 字段与序列化 | application_info.h/cpp, install_param.h/cpp | AC-1, AC-2, AC-18 | 无 | 序列化往返保持字段；缺字段默认 UNSPECIFIED(0) | `unittest` |
| TASK-2 | DualModeHelper 工具类（ispcmode/mainmode 模式判断、前缀生成解析、测试注入开关） | dual_mode_helper.h/cpp(新增), bundle_service_constants.h | AC-3, AC-33 | TASK-1 | 模式判断/值域校验/前缀生成解析单测通过 | `unittest` |
| TASK-3 | 安装流程前缀处理 + 类别一致性校验 + 各数据层 effective name 适配 + 系统应用准入 + 跨map校验 | base_bundle_installer.cpp, bundle_data_mgr.cpp, bundle_permission_mgr.cpp, bundle_resource/*, bundle_exception_handler.cpp, install_exception_mgr.cpp, appexecfwk_errors.h | AC-3~AC-10, AC-16, AC-19~AC-29, AC-32, AC-34, AC-35 | TASK-1, TASK-2 | 副模式隔离安装 + 类别校验 + token/uid 隔离 + 各数据表 effective key | `bms_target` + 集成 |
| TASK-4 | DB key 前缀适配 + 自愈陷阱修复 | bundle_data_storage_rdb.cpp, inner_bundle_info.cpp | AC-4, AC-11 | TASK-2, TASK-3 | 副模式 key 不被自愈误删 + 查询正确 | 集成 |
| TASK-5 | 重启数据加载分类 + tempBundleInfos_ | bundle_data_mgr.h/cpp | AC-11~AC-16 | TASK-4 | 重启按模式分类加载 + odid 跨模式一致 | 集成 |
| TASK-6 | 安装事件字段扩展 | bundle_common_event_mgr.h/cpp, base_bundle_installer.cpp | AC-17 | TASK-1 | 事件含 appCategory/currentMode(int)/isSharedSandbox | 集成 |

## Task 详情

### TASK-1: 应用类别枚举 + ApplicationInfo/InstallParam 字段与序列化

- **目标**：新增 `AppCategory` 枚举（位值 0/1/2/4/8/16/32）；ApplicationInfo / InstallParam 新增 appCategory 字段，完成 Parcel + JSON 序列化，默认 `APP_CATEGORY_UNSPECIFIED`(0)。
- **文件**：`application_info.h/cpp`（枚举 + 成员 + ReadFromParcel/Marshalling/to_json/from_json）、`install_param.h/cpp`（成员 + Parcel）。
- **完成判据**：序列化往返字段保持；缺字段反序列化默认 0；编译通过。
- **关联**：AC-1/AC-2/AC-18，design ADR-8。

### TASK-2: DualModeHelper 工具类

- **目标**：新建 DualModeHelper，封装读 `persist.sceneboard.ispcmode`/`mainmode`（int）、判断主/副模式（值域校验 {0,1}）、类别7判断、前缀生成/解析（复用 BundleCloneCommonHelper，appIndex=10000）；测试注入开关 `IsTestDualMode`（切参数 key）。
- **文件**：`dual_mode_helper.h/cpp`（新增）、`bundle_service_constants.h`（常量）、`BUILD.gn`（源文件）。
- **完成判据**：IsDualModeDevice/IsSecondaryMode/IsDiffPackageCategory/GetDualModeBundleName/ParseDualModeBundleName 单测通过；参数缺失/非法回退非双模式。
- **关联**：AC-3/AC-33，design ADR-5/6/10/22。

### TASK-3: 安装流程前缀处理 + 类别一致性校验 + 数据层 effective name 适配

- **目标**：
  - 副模式类别7应用 bundleName_ 拼接 `+clone-10000+` 前缀（`InitDualModeBundleName`），目录/轮转用 effective name（`GetEffectiveBundleName` 无参 + info 重载，ADR-14/23）
  - 更新类别一致性校验：当前模式 `CheckDualModeCategoryConsistency` + 跨 map `CheckDualModeCategoryConsistencyInTemp`，类别7互转返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT`(8519943)
  - 类别7仅系统应用准入：`SetDualModeAppInfo`（void→ErrCode）校验 `IsSystemApp`，非系统应用返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP`(8519942)
  - token 隔离（instIndex=10000，ADR-11）、uid 隔离（带前缀名派生 bundleId，ADR-13）、异常恢复反向解析（ADR-15）
  - 各数据层 effective name 适配：skills 目录/描述（ADR-16/17）、AppProvisionInfo 插入删除查询（ADR-18/19）、Router 插入删除更新（ADR-20）、installStates_ 状态机（ADR-21，调用方传 effective + 删表）、BundleResource 写入重启重建（ADR-24）、签名 profile 投递/回滚（ADR-14）
  - 跨模式 odid：`GenerateOdidNoLock` 遍历 bundleInfos_ + tempBundleInfos_（ADR-7）
- **文件**：`base_bundle_installer.h/cpp`、`bundle_data_mgr.cpp`、`bundle_permission_mgr.cpp`、`bundle_resource/*`、`bundle_exception_handler.cpp`、`install_exception_mgr.cpp`、`appexecfwk_errors.h`、`status_receiver_proxy.cpp`。
- **完成判据**：副模式隔离安装生效；类别校验/系统应用准入生效；各数据表 effective key；token/uid 隔离；odid 跨模式一致。
- **关联**：AC-3~AC-10/AC-16/AC-19~AC-29/AC-32/AC-34/AC-35，design ADR-1/7/11/12/13/14/15/16/17/18/19/20/21/24/26/27。

### TASK-4: DB key 前缀适配 + 自愈陷阱修复

- **目标**：副模式类别7应用 DB key 用 `+clone-10000+{bundleName}`；`TransResult`/`UpdateDataBase` 对 `+clone-` 前缀 key 跳过"key!=GetBundleName 重写"自愈（按 `isDualModeCloneApp` 字段 + `IsDualModeCloneKey`，ADR-3/9）。
- **文件**：`bundle_data_storage_rdb.cpp`、`inner_bundle_info.h/cpp`（isDualModeCloneApp 字段 + Parcel/JSON 序列化）。
- **完成判据**：副模式 key 存储后重启不被自愈误删；查询正确。
- **关联**：AC-4/AC-11，design ADR-2/3/9。

### TASK-5: 重启数据加载分类 + tempBundleInfos_

- **目标**：BundleDataMgr 新增 `tempBundleInfos_`；`LoadDataFromPersistentStorage` 中 `installStates_` 初始化（DB key）→ `ClassifyDualModeAppsNoLock` 按模式+类别7分类（副模式 clone 去前缀入 bundleInfos_，主模式入 tempBundleInfos_；副模式 primary-only 兜底移入 tempBundleInfos_）；新增 `FetchTempBundleInfo`/`GetAllTempBundleName`。
- **文件**：`bundle_data_mgr.h/cpp`。
- **完成判据**：重启后副模式可查询类别7应用（去前缀名），主模式不可查询；参数缺失全可查询。
- **关联**：AC-11~AC-16，design ADR-4/7。

### TASK-6: 安装事件字段扩展

- **目标**：`NotifyBundleEvents` 新增 appCategory/currentMode/isSharedSandbox 字段；`SetNotifyWant` 追加 SetParam；`FillDualModeEventFields`（base_bundle_installer.cpp:5711-5721）填充（currentMode = `GetSysMode()` 返回 int，isSharedSandbox = `!NeedDualModeHandle(appCategory)`），仅双模式设备填充。
- **文件**：`bundle_common_event_mgr.h/cpp`、`base_bundle_installer.cpp`。
- **完成判据**：安装/更新事件含 3 个新字段；currentMode 为 int（0/1/-1）。
- **关联**：AC-17，design ADR-10（currentMode int 对外契约，须同步需求二）。

## Plan 自审清单

- [x] 每个 P0/P1 AC 至少映射到一个 Task
- [x] 每个 Task 文件范围明确
- [x] 每个 Task 明确前置依赖、完成判据
- [x] 每个 Task 有验证命令
- [x] Task 粒度形成能力闭环
- [x] 无 TBD/TODO/占位符
- [x] 无超 3000 行阈值的 Task

**Plan 结论:** Approved — TASK-1~6 已实现落地（`_04` commit `80d089208`，112 例单测编译验证通过）；运行时全 AC（AC-1~35）集成回归 + 人类 Owner 发布批准仍待（见 [gates/release.md](./gates/release.md)）。
