# 执行计划

> 将 Spec 拆成可独立执行、可验证、可审查的 Task。每个 Task 自包含。当前代码基线：`appIndex_dual_mode_07_doc` HEAD `020de12b8`（含代码落地提交 `14eb7f286`，2026-08-06，13 文件 +349 -47，123 例单测）。TASK-1~6 已落地；TASK-7（TS 接口 parameters 透传，AC-41）为 2026-08-17 增量，2026-08-18 增补 ANI `install` 入口（接入点共 2 处：NAPI `install` + ANI `install`；NAPI/ANI `updateBundleForSelf` 均未接入）。

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
| AC-4 / AC-5 / AC-6 / AC-10 | TASK-3, TASK-4 | 集成（副模式目录隔离 / 主模式不处理 / 策略值域 / 轮转） |
| AC-7 / AC-8 / AC-9 / AC-35 | TASK-3 | 集成（策略一致性校验：同策略/不同包体类别互转/非不同包体类别互转/跨map） |
| AC-11 | TASK-4, TASK-5 | 集成（查询验证） |
| AC-12 / AC-13 / AC-14 / AC-15 | TASK-5 | 集成（重启分类加载） |
| AC-16 | TASK-3, TASK-5 | 集成（跨模式 odid 比对） |
| AC-17 | TASK-6 | 集成（事件 5 字段：currentMode int / appSandboxPolicy / before×2） |
| AC-19 / AC-20 / AC-21 | TASK-3 | 集成（hap token instIndex=10000（appIndex 安装时置位）/ 独立 uid / 异常恢复按原名查询） |
| AC-22 / AC-23 | TASK-3 | 集成（skills 目录 / skills description 数据层 effective name） |
| AC-24 / AC-25 | TASK-3 | 集成（AppProvisionInfo 插入删除 / getAppProvisionInfo 查询 effective name） |
| AC-26 | TASK-3 | 集成（Router 插入删除更新 effective name） |
| AC-27 / AC-28 / AC-32 | TASK-3 | 集成（installStates_ effective name 状态机 / 非clone回归 / 4独立调用方零回归） |
| AC-29 / AC-30 / AC-31 | TASK-3 | 集成（BundleResource 写入重启重建 effective name / 非clone回归 / 语言主题刷新） |
| AC-34 | TASK-3 | 单测+集成（不同包体类别仅系统应用准入（不分主副模式）NOT_SYSTEM_APP 8519942） |
| AC-36 / AC-37 | TASK-1 | 单测（AppSandboxPolicy Parcel+JSON 序列化往返保真 / 缺字段默认 SHARED_SANDBOX） |
| AC-38 | TASK-3 | 单测+集成（副模式不同包体 appIndex=10000 单一数据源、CreateHapInfoParams 直接传播） |
| AC-39 / AC-40 | TASK-6 | 单测+集成（粘性隔离 / before 值更新捕获/首装默认） |
| AC-41 | TASK-7 | 单测+集成（parameters 保留 key 刷新枚举 / 缺 key 零回归 / 非法 value 告警降级） |

## 阶段计划

| 阶段 | 目标 | 关键 Task | 结束门槛 |
|------|------|-----------|----------|
| Phase-1 | 基础骨架：枚举字段 + 模式工具类 | TASK-1, TASK-2 | 序列化单测 + 工具类单测通过 |
| Phase-2 | 核心隔离：安装前缀 + DB key 适配 | TASK-3, TASK-4 | 副模式目录隔离 + key 不被自愈误删 |
| Phase-3 | 查询与通知：重启加载 + 事件字段 | TASK-5, TASK-6 | 重启分类加载正确 + 事件字段正确 |

## Task 列表

| Task ID | 目标 | 文件范围 | AC 映射 | 前置依赖 | 完成判据 | 验证命令 |
|---------|------|----------|---------|----------|----------|----------|
| TASK-1 | 设备模式分发策略枚举 + 应用沙箱策略枚举 + BundleInfo/InstallParam 字段与序列化 | bundle_info.h/cpp, install_param.h/cpp | AC-1, AC-2, AC-18, AC-36, AC-37 | 无 | 序列化往返保持字段；缺字段默认 UNSPECIFIED(0)/SHARED_SANDBOX(0) | `unittest` |
| TASK-2 | DualModeHelper 工具类（ispcmode/mainmode 模式判断、前缀生成解析、IsDiffPackageCategory 集合判定、测试注入开关） | dual_mode_helper.h/cpp(新增), bundle_service_constants.h | AC-3, AC-33 | TASK-1 | 模式判断/值域校验/前缀生成解析/不同包体类别集合判定单测通过 | `unittest` |
| TASK-3 | 安装流程前缀处理 + 策略一致性校验 + 各数据层 effective name 适配 + 系统应用准入（不分主副模式）+ 跨map校验 + appIndex 单一数据源 + 粘性沙箱写入 | base_bundle_installer.cpp, bundle_data_mgr.cpp, bundle_permission_mgr.cpp, bundle_resource/*, bundle_exception_handler.cpp, install_exception_mgr.cpp, appexecfwk_errors.h | AC-3~AC-10, AC-16, AC-19~AC-29, AC-32, AC-34, AC-35, AC-38 | TASK-1, TASK-2 | 副模式隔离安装 + 策略校验 + token/uid 隔离 + appIndex 单一数据源 + 各数据表 effective key | `bms_target` + 集成 |
| TASK-4 | DB key 前缀适配 + 自愈陷阱修复 | bundle_data_storage_rdb.cpp, inner_bundle_info.cpp | AC-4, AC-11 | TASK-2, TASK-3 | 副模式 key 不被自愈误删 + 查询正确 | 集成 |
| TASK-5 | 重启数据加载分类 + tempBundleInfos_ | bundle_data_mgr.h/cpp | AC-11~AC-16 | TASK-4 | 重启按模式分类加载 + odid 跨模式一致 | 集成 |
| TASK-6 | 安装事件字段扩展（5 双模式字段 + before 值 + 粘性规则） | bundle_common_event_mgr.h/cpp, base_bundle_installer.h/cpp, inner_bundle_info.h | AC-17, AC-39, AC-40 | TASK-1 | 事件含 5 字段（deviceModeDistributionPolicy/currentMode int/appSandboxPolicy/before×2）；粘性隔离保持 | 集成 |
| TASK-7 | TS 接口 parameters 保留 key 透传设备模式分发策略 | bundle_constants.h, install_param.h/cpp, installer.cpp, ani_bundle_installer.cpp, common_fun_ani.cpp | AC-41 | TASK-1 | parameters 携带保留 key 时刷新 InstallParam.deviceModeDistributionPolicy（NAPI install + ANI install 共 2 入口；NAPI/ANI updateBundleForSelf 均不适配（2026-08-18 裁定））；缺 key 零回归；非法 value 仅告警降级；服务端 ReadFromParcel 越界值降级 UNSPECIFIED；NAPI/ANI 重复 key 统一 first-wins（codecheck R1 加固，2026-08-18） | `unittest` |

## Task 详情

### TASK-1: 设备模式分发策略枚举 + 应用沙箱策略枚举 + BundleInfo/InstallParam 字段与序列化

- **目标**：新增 `DeviceModeDistributionPolicy` 枚举（int32_t，9 成员连续 int 0~8，互斥单值不支持按位或）+ `AppSandboxPolicy` 枚举（int32_t，SHARED_SANDBOX=0/ISOLATED_SANDBOX=1）；BundleInfo 新增 `deviceModeDistributionPolicy` / `appSandboxPolicy` 字段，InstallParam 新增 `deviceModeDistributionPolicy`，完成 Parcel + JSON 序列化，默认 UNSPECIFIED(0) / SHARED_SANDBOX(0)。
- **文件**：`bundle_info.h/cpp`（枚举 + 成员 + ReadFromParcel/Marshalling/to_json/from_json）、`install_param.h/cpp`（成员 + Parcel）。
- **完成判据**：序列化往返字段保持；缺字段反序列化默认 0；编译通过。
- **关联**：AC-1/AC-2/AC-18/AC-36/AC-37，design ADR-8。

### TASK-2: DualModeHelper 工具类

- **目标**：新建 DualModeHelper，封装读 `persist.sceneboard.ispcmode`/`mainmode`（int）、判断主/副模式（值域校验 {0,1}）、不同包体类别集合判定（`IsDiffPackageCategory`：policy ∈ {4,6,8}）、前缀生成/解析（复用 BundleCloneCommonHelper，appIndex=10000）；测试注入开关 `IsTestDualMode`（切参数 key）。
- **文件**：`dual_mode_helper.h/cpp`（新增）、`bundle_service_constants.h`（常量）、`BUILD.gn`（源文件）。
- **完成判据**：IsDualModeDevice/IsSecondaryMode/IsDiffPackageCategory/GetDualModeBundleName/ParseDualModeBundleName 单测通过；参数缺失/非法回退非双模式。
- **关联**：AC-3/AC-33，design ADR-5/6/10/22。

### TASK-3: 安装流程前缀处理 + 策略一致性校验 + 数据层 effective name 适配 + appIndex 单一数据源 + 粘性沙箱

- **目标**：
  - 副模式不同包体类别应用 bundleName_ 拼接 `+clone-10000+` 前缀（`InitDualModeBundleName`），目录/轮转用 effective name（`GetEffectiveBundleName` 无参 + info 重载，ADR-14/23）
  - 更新策略一致性校验：当前模式 `CheckDualModeCategoryConsistency` + 跨 map `CheckDualModeCategoryConsistencyInTemp`，不同包体类别↔非不同包体类别互转返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT`(8519943)
  - 不同包体类别仅系统应用准入（不分主副模式）：`SetDualModeAppInfo`（void→ErrCode）在 `IsDiffPackageCategory` 时校验 `IsSystemApp`，非系统应用返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP`(8519942)；`isDualModeCloneApp` 仍仅副模式（isCloneApp）置位
  - **appIndex 单一数据源（ADR-28）**：`SetDualModeAppInfo` 在 isCloneApp 分支内 `info.SetAppIndex(DUAL_MODE_CLONE_APP_INDEX=10000)`；`CreateHapInfoParams` 移除运行时覆写特例、直接传播 `GetAppIndex()`
  - **粘性沙箱写入（ADR-29）**：`ComputeCurrentAppSandboxPolicy(newPolicy)` helper（before=ISOLATED 则 ISOLATED，否则 IsDiffPackageCategory?ISOLATED:SHARED），`SetDualModeAppInfo` 调 `info.SetAppSandboxPolicy` 写入；`ResetInstallProperties` 重置 before 成员防泄漏
  - token 隔离（instIndex=10000，ADR-28）、uid 隔离（带前缀名派生 bundleId，ADR-13）、异常恢复反向解析（ADR-15）
  - 各数据层 effective name 适配：skills 目录/描述（ADR-16/17）、AppProvisionInfo 插入删除查询（ADR-18/19）、Router 插入删除更新（ADR-20）、installStates_ 状态机（ADR-21，调用方传 effective + 删表）、BundleResource 写入重启重建（ADR-24）、签名 profile 投递/回滚（ADR-14）
  - 跨模式 odid：`GenerateOdidNoLock` 遍历 bundleInfos_ + tempBundleInfos_（ADR-7）
- **文件**：`base_bundle_installer.h/cpp`、`bundle_data_mgr.cpp`、`bundle_permission_mgr.cpp`、`bundle_resource/*`、`bundle_exception_handler.cpp`、`install_exception_mgr.cpp`、`appexecfwk_errors.h`、`status_receiver_proxy.cpp`、`inner_bundle_info.h`（Get/SetAppSandboxPolicy）。
- **完成判据**：副模式隔离安装生效；策略校验/系统应用准入（主副模式）生效；appIndex 单一数据源（info=token=10000）；粘性沙箱闭环；各数据表 effective key；token/uid 隔离；odid 跨模式一致。
- **关联**：AC-3~AC-10/AC-16/AC-19~AC-29/AC-32/AC-34/AC-35/AC-38，design ADR-1/7/11/12/13/14/15/16/17/18/19/20/21/24/26/27/28/29。

### TASK-4: DB key 前缀适配 + 自愈陷阱修复

- **目标**：副模式不同包体类别应用 DB key 用 `+clone-10000+{bundleName}`；`TransResult`/`UpdateDataBase` 对 `+clone-` 前缀 key 跳过"key!=GetBundleName 重写"自愈（按 `isDualModeCloneApp` 字段 + `IsDualModeCloneKey`，ADR-3/9）。
- **文件**：`bundle_data_storage_rdb.cpp`、`inner_bundle_info.h/cpp`（isDualModeCloneApp 字段 + Parcel/JSON 序列化）。
- **完成判据**：副模式 key 存储后重启不被自愈误删；查询正确。
- **关联**：AC-4/AC-11，design ADR-2/3/9。

### TASK-5: 重启数据加载分类 + tempBundleInfos_

- **目标**：BundleDataMgr 新增 `tempBundleInfos_`；`LoadDataFromPersistentStorage` 中 `installStates_` 初始化（DB key）→ `ClassifyDualModeAppsNoLock` 按模式+不同包体类别分类（副模式 clone 去前缀入 bundleInfos_，主模式入 tempBundleInfos_；副模式 primary-only 兜底移入 tempBundleInfos_）；新增 `FetchTempBundleInfo`/`GetAllTempBundleName`。
- **文件**：`bundle_data_mgr.h/cpp`。
- **完成判据**：重启后副模式可查询不同包体类别应用（去前缀名），主模式不可查询；参数缺失全可查询。
- **关联**：AC-11~AC-16，design ADR-4/7。

### TASK-6: 安装事件字段扩展（5 双模式字段 + before 值 + 粘性规则）

- **目标**：`NotifyBundleEvents` 双模式扩展字段 5 个：`deviceModeDistributionPolicy`（当前）、`currentMode`（int）、`appSandboxPolicy`（当前，由 isSharedSandbox 改名）、`beforeDeviceModeDistributionPolicy`（更新前，新增）、`beforeAppSandboxPolicy`（更新前，新增）；`SetNotifyWant` 追加 5 个 SetParam（Int32）；`FillDualModeEventFields`（base_bundle_installer.cpp:5723-5738）填充 5 字段（currentMode = `GetSysMode()`，appSandboxPolicy = `ComputeCurrentAppSandboxPolicy` 粘性重算，before 从成员变量读），仅双模式设备填充；before 成员在 `InitTempBundleFromCache` 后（:1802-1811，isAppExist_=true）从 oldInfo 捕获；`ResetInstallProperties`（:7278-7279）重置 before 成员防实例复用泄漏。
- **文件**：`bundle_common_event_mgr.h/cpp`、`base_bundle_installer.h/cpp`、`inner_bundle_info.h`（Get/SetAppSandboxPolicy）。
- **完成判据**：安装/更新事件含 5 双模式字段；currentMode 为 int（0/1/-1）；粘性隔离保持（before=ISOLATED 则当前 ISOLATED）；before 值更新捕获/首装默认。
- **关联**：AC-17/AC-39/AC-40，design ADR-29（currentMode int + Want key 改名 isSharedSandbox→appSandboxPolicy + 新增 2 before key 属对外契约变更，须同步需求二）。

### TASK-7: TS 接口 parameters 保留 key 透传设备模式分发策略

- **目标**：TS 侧经 installParam.parameters 既有通用通道（`Array<{key, value}>`，无需改 d.ts）传入 key `ohos.bms.param.deviceModeDistributionPolicy`、value 为枚举值十进制字符串（如 "4"）；`InstallParam::RefreshDeviceModeDistributionPolicy()`（新方法，对齐 `IsVerifyUninstallRule` 的 parameters 提取模式）在 parameters 含该 key 时将字符串解析为 int 并校验值域 [0,8]、刷新 `deviceModeDistributionPolicy` 字段；接入点共 2 处（均在参数解析/校验完成之后调用）：NAPI `Install`（installer.cpp:891，对 `callbackPtr->installParam` 调用；初版曾误写未声明标识符 `installParam` 致编译不过，2026-08-18 工作区修正为 `callbackPtr->installParam`）+ ANI `AniInstall`（ani_bundle_installer.cpp:225，`GetInstallParamForInstall` 返回之后对局部 installParam 调用，2026-08-18 增补 ANI；刷新调用在 `AniInstall` 函数体内、不在共享 helper 内部，故 `AniUpdateBundleForSelf`（:311 经同一 helper）不被覆盖）；key 缺失保持默认 UNSPECIFIED 零回归，value 非法（非十进制整数/超 0~8）返回 false，适配层 `APP_LOGW` 告警后继续安装、字段不被污染（2026-08-17 需求方裁定：不报 401、静默降级）；NAPI `updateBundleForSelf`（installer.cpp:1146 `CheckInstallParam` 之后）与 ANI `AniUpdateBundleForSelf` 均不接入，保留 key 在该两入口不生效（**2026-08-18 需求方裁定：updateBundleForSelf 接口不适配，透传范围即 install 入口，非缺口**）。
- **文件**：`bundle_constants.h`（key 常量 `DEVICE_MODE_DISTRIBUTION_POLICY_KEY`，`ohos.bms.param.*` 保留前缀区）、`install_param.h/cpp`（方法声明+实现）、`installer.cpp`（NAPI `Install` 接入）、`ani_bundle_installer.cpp`（ANI `AniInstall` 路径接入）、`bms_dual_mode_install_test.cpp`（单测组）。
- **完成判据**：带 key "4" → 字段刷新为 UNIVERSAL_DIFFERENT_PACKAGE(4)；缺 key → 默认 UNSPECIFIED；"abc"/"9"/"-1"/"4x" → 返回 false 且字段保持刷新前值（适配层仅告警、继续安装）。
- **codecheck R1 加固（2026-08-18，codecheck_report_192a99ab_R1 F-P2-01/F-P2-02，用户裁定方向：越界静默降级 UNSPECIFIED + 双栈重复 key 严格剥离）**：
  - **F-P2-01（服务端值域白名单）**：`InstallParam::ReadFromParcel`（install_param.cpp）对 policy 字段加值域白名单 `[UNSPECIFIED(0), FULL_COMPATIBLE_DIFFERENT_PACKAGE(8)]`，越界 int32（原生 IPC 调用方绕过 kit 校验场景）`APP_LOGW` 告警后降级 UNSPECIFIED（与 amended AC-41 静默降级口径一致，不阻断 IPC 安装请求），越界值不再可达广播事件字段；单测 `RefreshDeviceModeDistributionPolicy_0600`（越界 999/-5 降级 + 边界 0/8 直通）。
  - **F-P2-02（重复 key 跨栈统一 first-wins）**：NAPI `ParseParameters`（installer.cpp）遇重复 key 从 `APP_LOGE + return false`（中断循环、调用方吞错后实际 first-wins 且丢失后续合法 key）改为 `APP_LOGW` 告警 + `continue` 跳过（保留首个、后续重复忽略，循环继续解析其余 key）；ANI `ParseInstallParam` parameters 分支（common_fun_ani.cpp）从 `operator[]` last-wins 改为 find 检查 + `continue`——双栈统一为 **first-wins**（保留首个、忽略后续重复、`APP_LOGW` 告警），单次 key 零回归；kit 层解析无本仓单测覆盖（XTS 待集成，同 F-P3-05 遗留口径）。
- **关联**：AC-41/FR-16。

## Plan 自审清单

- [x] 每个 P0/P1 AC 至少映射到一个 Task
- [x] 每个 Task 文件范围明确
- [x] 每个 Task 明确前置依赖、完成判据
- [x] 每个 Task 有验证命令
- [x] Task 粒度形成能力闭环
- [x] 无 TBD/TODO/占位符
- [x] 无超 3000 行阈值的 Task

**Plan 结论:** Approved — TASK-1~6 已实现落地（`_04` commit `80d089208` 基线 + 增量代码落地提交 `14eb7f286`，2026-08-06，13 文件 +349 -47，123 例单测）。AC-1~35 已编译验证通过（`_04`）；AC-36~40 代码已落地、待集成环境编译/单测/运行时回归。TASK-7（AC-41，TS 接口 parameters 透传）代码已落地（2026-08-17 NAPI `Install` 入口，2026-08-18 增补 ANI `AniInstall` 入口 + 提交 `192a99abb`；2026-08-18 codecheck R1 加固 F-P2-01/F-P2-02 落地工作区——服务端 ReadFromParcel 值域白名单 + NAPI/ANI 重复 key 统一剥离语义，单测扩至 129 例，见 TASK-7 详情）待集成环境编译/单测/运行时回归。运行时全 AC（AC-1~41）集成回归 + 人类 Owner 发布批准仍待（见 [gates/release.md](./gates/release.md)）。
