# 特性规格

> 双模式同包名不同安装包应用安装支持。固化用户可见行为、API 契约与验收标准。内部实现（类名、调用链、前缀拼接机制）见 [design.md](./design.md)。

## 概述

| 属性 | 值 |
|------|-----|
| 特性名称 | 双模式同包名不同安装包应用安装支持 |
| 特性编号 | FEAT-20260715-001 |
| 所属 Epic | 无（独立特性；需求二"模式切换接口"另立特性） |
| 优先级 | P1 |
| 目标版本 | OpenHarmony-6.0-Release（TBD） |
| SIG 归属 | BundleManager SIG |
| 状态 | Review |
| 复杂度 | 标准 |
| 当前代码基线 | `appIndex_dual_mode_07_doc` HEAD `020de12b8`（含代码落地 `14eb7f286`） |

## 本次变更范围（Delta）

| 类型 | 内容 | 说明 |
|------|------|------|
| ADDED | 设备模式分发策略枚举 DeviceModeDistributionPolicy（9 个连续 int 值，不支持按位或） | Public API |
| ADDED | BundleInfo.deviceModeDistributionPolicy 字段 | Public API，默认"不区分" |
| ADDED | InstallParam.deviceModeDistributionPolicy 入参 | Public API，安装时指定设备模式分发策略 |
| ADDED | 副模式不同包体类别应用安装目录/数据隔离行为 | 同包名不同包体在副模式独立安装 |
| ADDED | 设备重启后按当前模式分类加载应用列表 | 副模式可查询到对应应用 |
| ADDED | 不同包体类别 仅系统应用准入 + 跨模式类别一致性校验 | 非系统应用副模式 不同包体类别 安装失败（8519942）+ 跨模式类别冲突拦截（8519943） |
| ADDED | 应用沙箱策略枚举 AppSandboxPolicy（SHARED_SANDBOX=0 / ISOLATED_SANDBOX=1，连续 int 值，互斥单值） | Public API |
| ADDED | BundleInfo.appSandboxPolicy 字段（默认 SHARED_SANDBOX，完整 Parcel+JSON 序列化） | Public API；业务消费留后续 |
| MODIFIED | 安装更新时新增"设备模式分发策略一致性"校验 | 不同包体类别与其他类别互转则更新失败 |

## 输入文档

| 文档 | 路径 | 状态 |
|------|------|------|
| Requirement | [proposal.md](./proposal.md) | Approved |
| Design | [design.md](./design.md) | Approved |

## 设备模式分发策略枚举定义（API 契约）

> 枚举类型 `DeviceModeDistributionPolicy`（底层 `int32_t`），9 个成员取连续整数值 0~8，**不支持按位或组合**（策略互斥）。与 `interfaces/inner_api/appexecfwk_base/include/application_info.h` 实现一致。成员名采用无前缀短名（依赖 `enum class` 作用域）。语义为"模式分发策略 + 兼容性维度 + 包体异同维度"三轴：MAIN_ONLY/SUB_ONLY 表单模式独有；UNIVERSAL/PARTIAL_COMPATIBLE/FULL_COMPATIBLE 表两模式覆盖度；IDENTICAL_PACKAGE/DIFFERENT_PACKAGE 表包体异同。其中 `*_DIFFERENT_PACKAGE`（4/6/8）为"不同包体类别"，是副模式隔离处理对象，由 `DualModeHelper::IsDiffPackageCategory` 判定（`policy ∈ {4,6,8}`）。

| 枚举成员 | 值 | 含义 |
|----------|----|------|
| UNSPECIFIED | 0 | 不区分设备模式分发策略（默认） |
| MAIN_ONLY | 1 | 仅主模式 |
| SUB_ONLY | 2 | 仅副模式 |
| UNIVERSAL_IDENTICAL_PACKAGE | 3 | 通用·相同包体 |
| UNIVERSAL_DIFFERENT_PACKAGE | 4 | 通用·不同包体（不同包体类别，副模式隔离） |
| PARTIAL_COMPATIBLE_IDENTICAL_PACKAGE | 5 | 部分兼容·相同包体 |
| PARTIAL_COMPATIBLE_DIFFERENT_PACKAGE | 6 | 部分兼容·不同包体（不同包体类别，副模式隔离） |
| FULL_COMPATIBLE_IDENTICAL_PACKAGE | 7 | 完全兼容·相同包体 |
| FULL_COMPATIBLE_DIFFERENT_PACKAGE | 8 | 完全兼容·不同包体（不同包体类别，副模式隔离） |

> 枚举值互斥、不支持按位或组合。判断"是否不同包体类别"用 `DualModeHelper::IsDiffPackageCategory(policy)`（判定 `policy ∈ {UNIVERSAL_DIFFERENT_PACKAGE(4), PARTIAL_COMPATIBLE_DIFFERENT_PACKAGE(6), FULL_COMPATIBLE_DIFFERENT_PACKAGE(8)}`）。

### 应用沙箱策略枚举 AppSandboxPolicy（API 契约）

> 枚举类型 `AppSandboxPolicy`（底层 `int32_t`），2 个成员取连续整数值 0~1，互斥单值（不支持按位或）。位于 `bundle_info.h`（`DeviceModeDistributionPolicy` 之后、`BundleInfo` 之前），字段 `BundleInfo.appSandboxPolicy` 默认 `SHARED_SANDBOX`。与 AC-17 事件层 `isSharedSandbox`（bool）概念呼应——`ISOLATED_SANDBOX` 语义对应副模式不同包体类别隔离应用。**本次仅建立数据模型 + 完整序列化（Parcel Int32 + JSON NUMBER）+ InnerBundleInfo Get/Set；InstallParam 入参 / 业务消费点留后续**。

| 枚举成员 | 值 | 含义 |
|----------|----|------|
| SHARED_SANDBOX | 0 | 共享沙箱（默认） |
| ISOLATED_SANDBOX | 1 | 隔离沙箱 |

## 用户故事

### US-1: 为应用指定设备模式分发策略

**作为** 应用安装方,
**需要** 在安装时为应用指定设备模式分发策略,
**以便** 系统按类别在 PC/PAD 双模式下正确处理该应用。

**验收标准：**

- **AC-1:** WHEN 安装应用且 InstallParam 携带 deviceModeDistributionPolicy THEN 该设备模式分发策略持久化存储于应用的 ApplicationInfo 中
- **AC-2:** WHEN InstallParam 或 ApplicationInfo 未设置 deviceModeDistributionPolicy THEN 设备模式分发策略默认值为"不区分"（值 0，UNSPECIFIED）
- **AC-18:** WHEN 读取升级前已安装、无 deviceModeDistributionPolicy 字段的存量应用 THEN 默认归为"不区分设备模式分发策略"，主副模式均不做特殊处理

### US-2: 副模式不同包体类别应用安装隔离

**作为** 系统,
**需要** 在副模式下安装不同包体类别（相同包名不同包体）应用时使用隔离的安装目录与数据目录,
**以便** 与主模式同名应用互不覆盖。

**验收标准：**

- **AC-3:** WHEN `persist.sceneboard.ispcmode` / `mainmode` 任一缺失（参数不存在/读取失败，GetIntParameter 返回 -1）或非法（∉{0,1}）THEN `IsDualModeDevice()=false`，完全回退正常安装流程，不做任何设备模式分发策略相关处理（不拼前缀、不持久化 deviceModeDistributionPolicy 触发、不填事件字段）。`IsDualModeDevice()` = `(cachedIspcmode_∈{0,1} && cachedMainmode_∈{0,1})`，值域校验使"参数缺失"与"参数非法"统一判为非双模式设备（design ADR-10）
- **AC-4:** WHEN 当前为副模式（ispcmode≠mainmode，两者均∈{0,1}）安装不同包体类别应用 THEN 安装目录、数据目录及 code-dir 下所有子目录（so/lib/ext-profile 等）与轮转目录（+new-/+old-/+temp-）均使用带前缀的隔离命名，与主模式同名应用物理隔离
- **AC-5:** WHEN 当前为主模式（ispcmode==mainmode）安装不同包体类别应用 THEN 不做目录特殊处理，按正常流程安装
- **AC-6:** WHEN 安装非不同包体类别（即 deviceModeDistributionPolicy ∉ {4,6,8}）的应用 THEN 无论主副模式均不做目录特殊处理
- **AC-10:** WHEN 副模式更新不同包体类别应用触发安装目录轮转 THEN 目录轮转（+new-/+old-）正确作用于带前缀的隔离目录
- **AC-11:** WHEN 在副模式下查询不同包体类别应用 THEN 可查询到该应用（查询结果为去前缀的应用名）；主模式下查询不同包体类别副模式应用 THEN 查询不到

### US-3: 更新时类别一致性校验

**作为** 系统,
**需要** 更新不同包体类别应用时校验设备模式分发策略一致性,
**以便** 避免错误的跨类别覆盖安装。

**验收标准：**

- **AC-7:** WHEN 更新已安装应用且已安装类别与待安装类别一致 THEN 继续安装流程
- **AC-8:** WHEN 更新时已安装类别与待安装类别不一致且涉及不同包体类别与其他类别互转 THEN 返回更新失败（错误码 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT`=8519943）。当前模式侧 `CheckDualModeCategoryConsistency`（base_bundle_installer.cpp:5804-5818）+ 跨 map 侧 `CheckDualModeCategoryConsistencyInTemp`（:5820-5842，查 `tempBundleInfos_` 另一模式变体，详见 AC-35），`DualModeHelper::IsDiffPackageCategory` 判定不同包体类别
- **AC-9:** WHEN 更新时类别不一致但不涉及不同包体类别互转 THEN 继续安装流程并更新设备模式分发策略为最新值

### US-4: 设备重启后按模式加载应用列表

**作为** 系统,
**需要** 设备重启后按当前模式正确加载可查询的应用列表,
**以便** 副模式下能查询到对应的同包名不同包体应用。

**验收标准：**

- **AC-12:** WHEN 设备重启且 `persist.sceneboard.ispcmode` / `mainmode` 任一缺失或非法(∉{0,1}) THEN `IsDualModeDevice()=false`，`ClassifyDualModeAppsNoLock` 早退，所有已安装应用加入可查询列表（bundleInfos_），不可查询列表（tempBundleInfos_）为空
- **AC-13:** WHEN 设备重启且双模式（ispcmode / mainmode 均∈{0,1}） THEN 仅对不同包体类别应用（DeviceModeDistributionPolicy 的 *_DIFFERENT_PACKAGE，即 4/6/8）分类：先将带前缀 key 的不同包体类别（副模式安装的 clone，DB key 形如 `+clone-10000+{name}`，由 `IsDualModeCloneKey(dbKey)` 判定）移入不可查询列表（tempBundleInfos_，移入后改为去前缀原名为 key），主模式不同包体类别（原名 key）不动；副模式（ispcmode≠mainmode）下再将这些副模式 clone 加入可查询列表（bundleInfos_）；非不同包体类别应用（含 UNSPECIFIED）不做模式分类，始终保留在可查询列表
- **AC-14:** WHEN 重启加载不同包体类别应用且当前为副模式 THEN 副模式安装的应用（isDualModeCloneApp==true）加入可查询列表（bundleInfos_），应用名为去前缀原始名；若同时存在主副模式安装的同一应用，则将主模式安装的应用交换到不可查询列表（tempBundleInfos_）。若某不同包体类别应用仅有主模式变体（无 clone 对应），兜底遍历将其移入 tempBundleInfos_ 隐藏（bundle_data_mgr.cpp:400-411）——即副模式下 bundleInfos_ 仅保留 clone，所有非 clone 不同包体类别 primary 一律隐藏
- **AC-15:** WHEN 重启加载不同包体类别应用且当前为主模式 THEN 副模式安装的应用（isDualModeCloneApp==true）加入不可查询列表（tempBundleInfos_）

### US-5: 跨模式 odid 一致

**作为** 系统,
**需要** 跨模式安装的同包名应用保持 odid 一致,
**以便** 应用数据/权限等标识跨模式一致。

**验收标准：**

- **AC-16:** WHEN 同一应用分别在主模式和副模式安装 THEN 两个模式下该应用的 odid 保持一致（`GenerateOdidNoLock` 同时遍历 `bundleInfos_` + `tempBundleInfos_` 按 developerId 复用，design ADR-7）

### US-6: 安装事件携带模式信息

**作为** 系统（供需求二上层消费）,
**需要** 安装/更新事件携带设备模式分发策略、当前模式、是否共沙箱字段,
**以便** 上层正确处理模式切换。

**验收标准：**

- **AC-17:** WHEN 双模式设备发送安装/更新事件 THEN 事件含 5 个双模式扩展字段（Want key 同名）：设备模式分发策略 `deviceModeDistributionPolicy`（当前）、当前模式 `currentMode`（**int**：0=tablet, 1=2in1, -1=未读取/非双模式）、应用沙箱策略 `appSandboxPolicy`（当前，默认 SHARED_SANDBOX）、更新前策略 `beforeDeviceModeDistributionPolicy`（默认 UNSPECIFIED）、更新前沙箱策略 `beforeAppSandboxPolicy`（默认 SHARED_SANDBOX）。`currentMode = GetSysMode()`；当前 `appSandboxPolicy` 按粘性规则计算（AC-39）；before 两值在存量加载后从 oldInfo 捕获（AC-40）。仅双模式设备填充（`FillDualModeEventFields` base_bundle_installer.cpp:5723-5738），非双模式设备保持默认值。**对外契约变更**：Want key `isSharedSandbox`（bool）更名为 `appSandboxPolicy`（int 枚举 0/1）并新增 2 个 before key，须同步需求二「模式切换接口」上层消费者

### US-7: 副模式完整隔离（权限 token / uid / 异常恢复 / 数据层）

**作为** 系统,
**需要** 副模式不同包体类别应用在权限 token、数据目录 uid、安装异常恢复及各数据表（skills / provision / router / installStates_ / resource）与主模式同名应用完整隔离,
**以便** 主副同名应用互不干扰、异常恢复时查询正确。

**验收标准：**

- **AC-19:** WHEN 副模式安装不同包体类别应用（isDualModeCloneApp=true，appIndex=`DUAL_MODE_CLONE_APP_INDEX(10000)`，由 `SetDualModeAppInfo` 安装时置位）THEN 其 HAP token 通过 instIndex=10000 与主模式同名应用隔离（独立 hap token；`CreateHapInfoParams` 直接传播 `GetAppIndex()`，见 design ADR-11/ADR-28）
- **AC-20:** WHEN 副模式安装不同包体类别应用 THEN 其数据目录/asan 日志目录归属独立 uid（基于带前缀名分配的 bundleId 派生），与主模式同名应用 uid 不同；重启后 uid 保持一致（持久化 uid，不重新生成，见 design ADR-13）
- **AC-21:** WHEN 安装异常恢复（InnerProcessNewToRealPath）接收带前缀的 bundleName THEN FetchInnerBundleInfo 用解析回的原名查询；目录轮转操作仍用带前缀名（见 design ADR-15）
- **AC-22:** WHEN 副模式（isDualModeCloneApp=true）安装/更新/卸载不同包体类别应用 THEN skills 安装目录（`/data/app/el1/skills/public/<bundleName>/<module>` 及其 +TMP temp 目录）的提取落盘、temp→real 重命名、删除均使用带 `+clone-10000+` 前缀的隔离命名（info-driven：`info.IsDualModeCloneApp()` 判定），与主模式同名应用 skills 目录物理隔离；主模式用原名按正常流程（见 design ADR-16）
- **AC-23:** WHEN 副模式（isDualModeCloneApp=true）安装/更新/卸载带 skill 的不同包体类别应用 THEN skills description 数据层（SkillsDescriptionRdb）的插入/删除/查询均以带 `+clone-10000+` 前缀的 effective name 作 RDB key，主模式同名应用 description 不被覆盖/误删/误查；对外 `SkillInfo.bundleName`（Parcelable）仍返回原名；主模式用原名作 key，行为零变化（见 design ADR-17）
- **AC-24:** WHEN 副模式（isDualModeCloneApp=true）安装/更新应用 THEN AppProvisionInfo 数据层的插入（AddAppProvisionInfo + SetSpecifiedDistributionType + SetAdditionalInfo）以带 `+clone-10000+` 前缀的 effective name 作 RDB key 写入，主模式同名 provision 不被覆盖；卸载时 DeleteAppProvisionInfo 以 effective name 删除，不残留孤儿 provision；主模式（isDualModeCloneApp=false）effective name 回落原名作 key，行为零变化（见 design ADR-18）
- **AC-25:** WHEN 副模式调 Public API `getAppProvisionInfo(原名)` THEN `BundleDataMgr::GetAppProvisionInfo`（:9489）`find(原名)` 命中后用 `IsDualModeCloneApp()` 判定，provisionKey 取带前缀 effective name 查 Manager 返回副模式 provision；返回值 `appProvisionInfo.bundleName` 仍为原名；主模式或非双模式应用 provisionKey 取原名，行为零变化（见 design ADR-19）。**范围：仅 `getAppProvisionInfo`（单数）；`getAllAppProvisionInfo` / ProcessCertificate / GenerateSignatureInfo 同源查询遗留后续**
- **AC-26:** WHEN 副模式（isDualModeCloneApp=true）安装/更新应用 THEN Router 数据层的插入（InsertRouterInfo）/更新（UpdateRouterInfo）以带 `+clone-10000+` 前缀的 effective name 作 routerStorage_ key 写入，主模式同名 router 不被覆盖；卸载/模块更新删旧时 DeleteRouterInfo 以 effective name 删除，不残留孤儿；主模式或非双模式 effective name 回落原名，零变化（见 design ADR-20）。**已知高风险遗留：Router 查询（ProcessBundleRouterMap）未适配 → 副模式应用启动路由断裂，由后续其他需求解决**
- **AC-27:** WHEN 双模式副模式 clone app（isDualModeCloneApp=true）安装/更新/卸载 THEN BaseBundleInstaller 各状态调用点（INSTALL_START/FAIL/SUCCESS、UPDATING_START/SUCCESS/FAIL、ROLL_BACK、UNINSTALL_START/SUCCESS）传带 `+clone-10000+` 前缀的 effective name（`GetEffectiveBundleName()` / `GetEffectiveBundleName(info/oldInfo)`），`UpdateBundleInstallState` 以**传入名作 stateKey** 与 `installStates_`（重启加载带前缀 key）匹配，clone app 状态正确流转；5 处查询点（AddInnerBundleInfo/AddNewModuleInfo/RemoveModuleInfo/RemoveHspModuleByVersionCode/UpdateInnerBundleInfo）维持 info-driven 不变；`DeleteBundleInfo` 按 `IsDualModeCloneKey` 解析原名删 `bundleInfos_`（见 design ADR-21）
- **AC-28:** WHEN 非双模式设备或非 clone app（isDualModeCloneApp=false）THEN effective name 回落原名，`UpdateBundleInstallState` 以传入名（=原名）作 stateKey，行为与现状完全一致；5 处查询 info-driven 回归零影响（见 design ADR-21）
- **AC-29:** WHEN 副模式（isDualModeCloneApp=true）安装/更新不同包体类别应用 THEN `BundleResourceRdb`（label/iconId，NAME 单列主键）的写入（`AddResourceInfos`）+ 更新清理（`DeleteNotExistResourceInfo` 按 effective 名查询）+ 重启重建以带 `+clone-10000+` 前缀的 effective name 作 RDB key（硬约束：写入数据库时 key 带前缀），主模式同名应用 label/iconId 不被覆盖；`BundleResourceIconRdb`（icon 字节）按设计保留原始 bundleName（不隔离 clone/主模式）；parser `resourceManagerMap` 按 effective 名区分两模式 hap（不串解析）；对外 Parcelable `BundleResourceInfo.bundleName` 仍为原名（见 design ADR-24）。**已知局限（遗留其他需求）**：① 卸载删除/恢复路径（`DeleteBundleResourceInfo`/`DeleteUninstallBundleResource`/`AddUninstallBundleResource`）未适配——仍用原始 bundleName，clone 的 prefixed `BundleResourceRdb` 记录卸载后残留；② resource 表查询转换（`getBundleResourceInfo` 等 Public API）；③ OTA 重建。语言/主题刷新见 AC-31
- **AC-30:** WHEN 非双模式设备或非 clone app（isDualModeCloneApp=false）THEN effective name 回落原名，BundleResourceManager 写入/更新/重启重建/刷新行为与现状完全一致（回归零影响）；卸载路径本就用原名，亦零变化（见 design ADR-24）
- **AC-31:** WHEN 双模式设备发生语言或主题切换 THEN `GetAllResourceInfo` 同时覆盖 `bundleInfos_`（当前模式）与 `tempBundleInfos_`（另一模式变体）的同名应用，两模式的名称资源（`BundleResourceRdb` label）均被刷新（clone 落 `+clone-10000+` prefixed key、primary 落 original key），切回另一模式后 label 为新语言/主题；两模式各自刷新到自己的 key，不交叉污染（见 design ADR-24）。**注：OTA（ProcessThemeAndDynamicIconWhenOta）仍遗留其他需求**
- **AC-32:** WHEN 4 个独立调用方（AppServiceFwkInstaller/IndependentSkillsInstaller/InnerSharedBundleInstaller/BMSEventHandler）调 `UpdateBundleInstallState`（传原名） THEN 行为零变化：所处理应用的 BundleType（APP_SERVICE_FWK/SKILL/SHARED）与 clone app（BundleType::APP）互斥，正常生命周期不触达 clone，`installStates_` key 为原名匹配正确；BMSEventHandler DB 丢失异常恢复路径（`SaveInstallInfoToCache`）对 clone app 用原名的错配作为**已知遗留**（仅 DB 丢失极端异常触发，正常 OTA/重启走 `LoadInstallInfosFromDb` 跳过）（见 design ADR-21）
- **AC-33:** WHEN `persist.sceneboard.ispcmode` 或 `mainmode` 参数存在但值非法（如 2，∉{0,1}） THEN 视为该参数无效（等价"参数缺失"），`IsDualModeDevice()=false` → 回退正常安装流程，不做前缀/分类/事件字段处理（值域校验 {0,1}，见 design ADR-10）

### US-8: 双模式安装准入与跨模式类别一致性

**作为** 系统,
**需要** 限制不同包体类别仅系统应用可配置、并校验跨模式（当前 map 与另一模式 map）类别一致,
**以便** 避免普通应用误用双模式类别造成隔离资源浪费、避免主副模式类别冲突覆盖。

**验收标准：**

- **AC-34:** WHEN 双模式设备安装不同包体类别应用（`SetDualModeAppInfo`，`IsDiffPackageCategory(policy)==true`，**不分主副模式**，base_bundle_installer.cpp:5766-5802）THEN 仅系统应用（`info.IsSystemApp()==true`）允许，继续安装流程；WHEN 非系统应用（`IsSystemApp()==false`）THEN 安装失败，返回错误码 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP`（**8519942**，appexecfwk_errors.h:213，`status_receiver_proxy.cpp:720-721` 映射对外为 `ERR_INSTALL_PARSE_FAILED`），校验先于 `isDualModeCloneApp` 置位（`SetDualModeAppInfo` void→`ErrCode`，:5717 调用点 `CHECK_RESULT` 提前返回）。主模式不同包体类别 + 系统应用 THEN 通过校验但 **不置** `isDualModeCloneApp`（仅副模式 clone 置位）；非不同包体类别 / 非双模式设备 THEN 零回归（不触发该校验）。单测：`SetDualModeAppInfo_0500/0600/0700/0800`
- **AC-35:** WHEN 双模式设备副模式安装不同包体类别应用 THEN `CheckDualModeCategoryConsistencyInTemp`（base_bundle_installer.cpp:5820-5842，`InnerProcessBundleInstall` :1063 调用，紧随 :1059 当前模式侧 `CheckDualModeCategoryConsistency`）经 `FetchTempBundleInfo(bundleName_)` 查 `tempBundleInfos_` 另一模式变体；WHEN 另一模式已存在该应用且类别不一致（涉及不同包体类别↔非不同包体类别互转）THEN 返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT`（**8519943**）；WHEN 两模式均不同包体类别 或 另一模式不存在该应用 THEN 放行继续安装。补 AC-8（当前模式侧）的跨 map 维度；非双模式设备 `IsDualModeDevice=false` 守卫早退、零回归。单测：`CheckDualModeCategoryConsistencyInTemp_0100~0500`（5 例）

### US-9: 应用沙箱策略数据模型

**作为** 系统,
**需要** 在 BundleInfo 中持久化应用沙箱策略（共享/隔离）,
**以便** 后续双模式隔离逻辑统一读取该字段（本次仅数据模型 + 完整序列化，业务消费留后续 Sync）。

**验收标准：**

- **AC-36:** WHEN BundleInfo 经 Parcel（`Marshalling`/`ReadFromParcel`，bundle_info.cpp）或 JSON（`to_json`/`from_json`，key `BUNDLE_INFO_APP_SANDBOX_POLICY = "appSandboxPolicy"`）序列化往返 THEN `appSandboxPolicy` 保持原值（`SHARED_SANDBOX`/`ISOLATED_SANDBOX` 均保真）；字段随 `baseBundleInfo_` 经 `BASE_BUNDLE_INFO` 节点持久化（inner_bundle_info.cpp:636），AC-1 持久化不破坏
- **AC-37:** WHEN 反序列化不含 `appSandboxPolicy` 字段的存量 BundleInfo JSON THEN `appSandboxPolicy` 默认为 `SHARED_SANDBOX`（值 0，字段类内默认值 + `from_json` 缺 key 回退机制，与 AC-18 同理）

### US-10: appIndex 单一数据源

**作为** 系统,
**需要** 副模式不同包体类别（clone）应用的 appIndex 在安装时一次置位为 10000,
**以便** hap token instIndex 等所有消费方直接读 10000，消除「info=0 / token=10000」分裂，与目录/DB key 的 `+clone-10000+` 前缀及 ADR-6 前提统一。

**验收标准：**

- **AC-38:** WHEN 双模式设备副模式安装不同包体类别应用（`SetDualModeAppInfo`，`isCloneApp=true`）THEN `InnerBundleInfo.appIndex` 置为 `DUAL_MODE_CLONE_APP_INDEX(10000)`（单一数据源，安装时一次置位，随 InnerBundleInfo 持久化），`CreateHapInfoParams` 直接 `hapInfo.instIndex = GetAppIndex()` 得 10000（不再运行时覆写，AC-19 结果等价）；WHEN 非副模式 / 非不同包体类别 / 非双模式设备 THEN appIndex 保持默认（0），零回归。单测：`SetDualModeAppInfo_0300`（`GetAppIndex()==10000`）、`CreateHapInfoParams_0100`（`instIndex==10000`）。见 design ADR-28

### US-11: 广播沙箱策略与更新前值

**作为** 系统（供需求二上层消费）,
**需要** 安装/更新广播携带应用沙箱策略（当前 + 更新前），且隔离一旦生效即"粘性"保持,
**以便** 上层一次广播即可判断沙箱/策略变更，且隔离不被更新翻覆。

**验收标准：**

- **AC-39:** WHEN 双模式设备计算当前 `appSandboxPolicy`（`ComputeCurrentAppSandboxPolicy` 私有 helper，`SetDualModeAppInfo` 写入 info 与 `FillDualModeEventFields` 填广播同源）THEN 若 `beforeAppSandboxPolicy==ISOLATED_SANDBOX`（存量已隔离）当前恒为 `ISOLATED_SANDBOX`（**粘性**，与新 policy 无关）；否则（共沙箱或首装默认 SHARED）当前 = `IsDiffPackageCategory(newPolicy) ? ISOLATED_SANDBOX : SHARED_SANDBOX`。WHEN 存量隔离应用更新为非不同包体类别 THEN 当前仍 ISOLATED（粘性保持）。单测：`FillDualModeEventFields_0100`（首装+不同包体→ISOLATED）、`FillDualModeEventFields_0300`（粘性：before=ISOLATED + 非不同包体→仍 ISOLATED）
- **AC-40:** WHEN 更新（存量存在，`isAppExist_=true`）THEN `beforeDeviceModeDistributionPolicy`/`beforeAppSandboxPolicy` 从 oldInfo 捕获（`InitTempBundleFromCache` 后 base_bundle_installer.cpp:1802-1811，存入 BaseBundleInstaller 成员）；WHEN 首次安装（无存量）THEN before 两字段为默认（UNSPECIFIED/SHARED_SANDBOX）；WHEN 非双模式设备 THEN 5 字段全默认、零回归。`appSandboxPolicy` 经 `InnerBundleInfo.SetAppSandboxPolicy` 写入并随 baseBundleInfo_ 持久化（粘性闭环，AC-39 下次更新可读）；`ResetInstallProperties`（:7278-7279）重置 before 成员防实例复用泄漏。单测：`FillDualModeEventFields_0100`（首装 before 默认）、`FillDualModeEventFields_0200`（非双模式保持预置标记）

### US-12: TS 接口透传设备模式分发策略

**作为** 上层分发调用方（经 TS installer 接口）,
**需要** 在调用 TS 安装接口时经 installParam.parameters 通用通道传入设备模式分发策略,
**以便** 分发平台在安装时刻指定策略，走既有 IPC 字段链路（AC-1）持久化，无需新增独立 TS 参数字段。

**验收标准：**

- **AC-41:** WHEN TS 侧调用 `install` 接口且 installParam.parameters 携带 key `ohos.bms.param.deviceModeDistributionPolicy`（value 为枚举值的十进制字符串，如 "4"） THEN 适配层解析后将 `InstallParam.deviceModeDistributionPolicy` 刷新为对应枚举值（int 0~8），经既有 Parcel 字段（IPC）传至服务端，衔接 AC-1 持久化链路；WHEN parameters 不含该 key THEN 字段保持默认 UNSPECIFIED（0），现有调用方零回归；WHEN key 存在但 value 非法（非十进制整数/空串/超出 0~8 值域）THEN 忽略该 key 仅打印 warning 日志（`RefreshDeviceModeDistributionPolicy` 返回 false，适配层 `APP_LOGW` 告警后继续安装流程，字段不被污染、保持刷新前值即默认 UNSPECIFIED），不拦截安装、不返回异常（2026-08-17 需求方裁定：非法值不报 401，静默降级走默认策略）。实现：`InstallParam::RefreshDeviceModeDistributionPolicy()`（install_param.cpp，从 parameters map 提取并刷新字段，对齐 `IsVerifyUninstallRule` 的 parameters 提取模式），接入点共 2 处（均在参数解析/校验完成之后调用）：NAPI `Install`（installer.cpp:891，对 `callbackPtr->installParam` 调用）与 ANI `AniInstall`（ani_bundle_installer.cpp:225，`GetInstallParamForInstall` 返回之后对局部 `installParam` 调用，2026-08-18 增补 ANI；刷新调用在 `AniInstall` 函数体内、不在共享 helper 内部，故经同一 helper 的 `AniUpdateBundleForSelf` 不被覆盖）；NAPI `updateBundleForSelf`（installer.cpp:1146 `CheckInstallParam` 之后）与 ANI `AniUpdateBundleForSelf`（ani_bundle_installer.cpp:311 helper 调用之后）均不接入刷新，该两入口携带保留 key 不生效、字段走默认（**2026-08-18 需求方裁定：updateBundleForSelf 接口不适配，保留 key 透传范围即 install 入口，非功能覆盖缺口**）；key 常量 `Constants::DEVICE_MODE_DISTRIBUTION_POLICY_KEY`（bundle_constants.h，对齐 `ohos.bms.param.*` 保留前缀惯例）；**codecheck R1 加固（2026-08-18，F-P2-01/F-P2-02）**：① 服务端 `InstallParam::ReadFromParcel` 对该字段加值域白名单 [0,8]，原生 IPC 调用方携越界 int32 时 `APP_LOGW` 告警后降级 UNSPECIFIED（与非法 value 静默降级同口径，不阻断安装请求），越界值不可达广播事件字段；② NAPI `ParseParameters` 与 ANI `ParseInstallParam`（common_fun_ani.cpp）对 parameters 重复 key 统一为 **first-wins**——遇重复 key `APP_LOGW` 告警 + 跳过（保留首个、忽略后续，消除原 NAPI 吞错中断 / ANI last-wins 跨栈分歧），单次 key 行为零回归

## 验收追溯

> 全 AC（AC-1~41）代码已落地、待集成环境编译/单测验证；AC-41 为 TS 接口透传增量（2026-08-17 NAPI `install`，2026-08-18 增补 ANI `install`，接入点共 2 处；NAPI/ANI `updateBundleForSelf` 均不适配——2026-08-18 需求方裁定，透传范围即 install 入口，非缺口）；AC-17（5 字段）、AC-19（instIndex=10000）待集成环境重验；AC-1~35 已编译验证通过（`80d089208`，112 例单测编译 OK）；增量代码落地提交 `14eb7f286`（2026-08-06）后单测扩至 123 例。运行时集成回归 + 人类 Owner 发布批准为发布 Gate 未决项（见 [gates/release.md](./gates/release.md)）。

| AC | 关联规则 | 关联 Task | 验证方式 | 证据 |
|----|----------|-----------|----------|------|
| AC-1 | FR-1 | TASK-1 | 单测（序列化往返） | ✅ 编译通过；install_param.h / application_info.h / to_json 静态一致 |
| AC-2 | FR-1 | TASK-1 | 单测（默认值） | ✅ 编译通过；`UNSPECIFIED=0` |
| AC-18 | EX-1 | TASK-1 | 单测（缺字段反序列化） | ✅ 编译通过；`from_json` 缺字段保留默认值 |
| AC-3 | EX-2 | TASK-2/3 | 单测+集成（参数缺失/非法回退） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-4 | FR-2 | TASK-3/4 | 集成（副模式目录检查） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-5 | FR-2 | TASK-3 | 集成（主模式目录检查） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-6 | FR-2 | TASK-3 | 集成（非不同包体类别不处理） | ✅ 已集成验证 PASS（2026-07-18） |
| AC-7 | FR-3 | TASK-3 | 集成（同类更新） | ✅ 已集成验证 PASS（2026-07-18） |
| AC-8 | EX-3 | TASK-3 | 集成（不同包体类别互转失败 8519943） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-9 | FR-3 | TASK-3 | 集成（非不同包体类别互转更新） | ✅ 已集成验证 PASS（2026-07-18） |
| AC-10 | FR-4 | TASK-3 | 集成（轮转目录检查） | ✅ 已集成验证 PASS（2026-07-18） |
| AC-11 | FR-5 | TASK-4/5 | 集成（查询验证） | ✅ 已集成验证 PASS（2026-07-18） |
| AC-12 | RC-1 | TASK-5 | 集成（重启加载，参数缺失/非法） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-13 | FR-6 | TASK-5 | 集成（分类加载） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-14 | FR-6 | TASK-5 | 集成（副模式加载+边界） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-15 | FR-6 | TASK-5 | 集成（主模式加载） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-16 | FR-7 | TASK-5 | 集成（跨模式odid一致） | ✅ 编译通过；单测 GenerateOdid_ReuseFromTempBundleInfos_×4；运行时集成回归待集成环境 |
| AC-17 | FR-8 | TASK-6 | 集成（事件 5 字段：currentMode int / appSandboxPolicy / before×2） | ✅ 编译通过；运行时集成回归待集成环境；**对外契约变更**（isSharedSandbox→appSandboxPolicy + before key），须同步需求二 |
| AC-19 | FR-9 | TASK-3 | 集成（副模式 hap token 隔离） | ✅ 编译通过；appIndex 安装时置位、CreateHapInfoParams 直接传播，instIndex=10000，待集成环境重验 |
| AC-20 | FR-10 | TASK-3/5 | 集成（副模式独立 uid + 重启一致） | ✅ 已集成验证 PASS（2026-07-18） |
| AC-21 | FR-11 | TASK-3 | 集成（异常恢复按原名查询） | ✅ 已集成验证 PASS（2026-07-18） |
| AC-22 | FR-2 | TASK-3 | 集成（副模式 skills 目录隔离） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-23 | FR-2 | TASK-3 | 集成（副模式 skills description 数据层隔离） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-24 | FR-2 | TASK-3 | 集成（副模式 AppProvisionInfo 插入/删除 effective name 隔离） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-25 | FR-2 | TASK-3 | 集成（副模式 getAppProvisionInfo 经 IsDualModeCloneApp 判定查到） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-26 | FR-2 | TASK-3 | 集成（副模式 Router 插入/删除/更新 effective name 隔离） | ✅ 编译通过；运行时集成回归待集成环境；查询遗留 |
| AC-27 | FR-2 | TASK-3 | 集成（clone app installStates_ effective name 状态机对齐） | ✅ 编译通过；单测 UpdateBundleInstallState×5；运行时集成回归待集成环境 |
| AC-28 | FR-2 | TASK-3 | 集成（非双模式/非 clone installStates_ 回归零影响） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-29 | FR-12 | TASK-3 | 集成（副模式 resource 写入/更新/重启重建 effective name 隔离） | ✅ 编译通过；运行时集成回归待集成环境；卸载删除/查询/OTA 遗留 |
| AC-30 | FR-12 | TASK-3 | 集成（非双模式/非 clone resource 三表回归零影响） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-31 | FR-13 | TASK-3 | 集成（语言/主题切换两模式 label 均刷新） | ✅ 编译通过；运行时集成回归待集成环境；OTA 遗留 |
| AC-32 | FR-2 | TASK-3 | 集成（4 独立调用方 BundleType 互斥零回归） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-33 | EX-2 | TASK-2/3 | 单测+集成（参数非法值∉{0,1}回退） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-34 | EX-4 | TASK-3 | 单测+集成（非系统应用 不同包体类别 主/副模式安装失败 8519942） | ✅ 编译通过；单测 SetDualModeAppInfo_0500/0600/0700/0800；运行时集成回归待集成环境 |
| AC-35 | EX-3 | TASK-3 | 单测+集成（跨 map 类别不一致拦截 8519943） | ✅ 编译通过；单测 CheckDualModeCategoryConsistencyInTemp_×5；运行时集成回归待集成环境 |
| AC-36 | — | TASK-1 | 单测（AppSandboxPolicy Parcel+JSON 序列化往返保真） | ⏳ 代码已落地，待集成环境编译/单测 |
| AC-37 | EX-5 | TASK-1 | 单测（缺字段默认 SHARED_SANDBOX） | ⏳ 代码已落地，待集成环境编译/单测 |
| AC-38 | — | TASK-3 | 单测+集成（副模式不同包体 appIndex=10000、CreateHapInfoParams 直接传播） | ⏳ 代码已落地，待集成环境编译/单测/运行时回归 |
| AC-39 | — | TASK-6 | 单测+集成（粘性隔离：隔离后更新仍隔离） | ⏳ 代码已落地，待集成环境编译/单测/运行时回归 |
| AC-40 | — | TASK-6 | 单测+集成（before 值更新捕获/首装默认/非双模式零回归） | ⏳ 代码已落地，待集成环境编译/单测/运行时回归 |
| AC-41 | FR-16 | TASK-7 | 单测（parameters key 刷新枚举/缺 key 零回归/非法 value 静默降级/Parcel 越界值降级） | ⏳ 代码已落地（NAPI install + ANI install 共 2 入口；NAPI/ANI updateBundleForSelf 均不适配（2026-08-18 裁定）；codecheck R1 加固：服务端值域白名单 + 双栈重复 key first-wins，已随提交 `e148c7a34` 入库、R2 报告 approve/94），待集成环境编译/单测/运行时回归 |

## 业务规则

| 编号 | 规则描述 | 约束条件 | 关联 AC |
|------|----------|----------|---------|
| BR-1 | 设备模式分发策略默认"不区分"，任何未指定场景均按此处理 | 默认值 0 | AC-2/AC-18 |
| BR-2 | 仅不同包体类别（相同包名不同包体）在副模式需隔离；其他类别不隔离 | 不同包体类别 且 副模式 | AC-4/AC-5/AC-6 |
| BR-3 | 不同包体类别 clone 安装仅限系统应用 | 双模式 + 不同包体类别 | AC-34 |

## 功能规则

| 编号 | 规则描述 | 触发条件 | 作用对象 | 关联 AC |
|------|----------|----------|----------|---------|
| FR-1 | deviceModeDistributionPolicy 随 ApplicationInfo 持久化，跨 IPC 传递 | 安装时 InstallParam 携带 | ApplicationInfo / InstallParam | AC-1/AC-2 |
| FR-2 | 副模式不同包体类别应用使用隔离安装目录与数据目录 | 副模式 + 不同包体类别 | 安装目录/数据目录 | AC-4/AC-5/AC-6 |
| FR-3 | 更新时校验类别一致性，不同包体类别互转则失败 | 更新 + 类别变化 | 更新流程 | AC-7/AC-8/AC-9 |
| FR-4 | 副模式更新不同包体类别应用时目录轮转作用于隔离目录 | 副模式 + 不同包体类别 + 更新 | 目录轮转 | AC-10 |
| FR-5 | 副模式可查询不同包体类别应用，主模式不可查询 | 模式 + 不同包体类别 | 应用查询 | AC-11 |
| FR-6 | 重启后按当前模式与设备模式分发策略分类加载到可查询/不可查询列表 | 重启 | 应用列表加载 | AC-13/AC-14/AC-15 |
| FR-7 | 同应用跨模式 odid 一致 | 同应用主副模式各安装 | odid | AC-16 |
| FR-8 | 安装事件携带设备模式分发策略/当前模式/是否共沙箱 | 安装/更新事件 | 事件 | AC-17 |
| FR-9 | 副模式不同包体类别应用通过 instIndex=10000 获得独立 HAP token | 副模式 + 不同包体类别 + isDualModeCloneApp | 权限 token | AC-19 |
| FR-10 | 副模式不同包体类别应用数据/asan 目录归属独立 uid（带前缀名派生 bundleId），跨重启稳定 | 副模式 + 不同包体类别 | uid | AC-20 |
| FR-11 | 安装异常恢复接收带前缀名时解析回原名查询 FetchInnerBundleInfo | 异常恢复 + 带前缀名 | exception 查询 | AC-21 |
| FR-12 | 副模式不同包体类别应用资源缓存隔离：`BundleResourceRdb` 写入/更新/重启重建以带 `+clone-10000+` 前缀 effective name 作 key（写入 key 带前缀，硬约束）；`BundleResourceIconRdb` 保留原始 bundleName（按设计不隔离）；`UninstallBundleResourceRdb` + 卸载删除路径未适配（用原名，遗留其他需求） | 副模式 + 不同包体类别 + 写入/更新/重启重建 | BundleResourceManager | AC-29/30 |
| FR-13 | 语言/主题切换时刷新双模式（`bundleInfos_` + `tempBundleInfos_`）同名应用的名称资源，两模式各自 key 不交叉污染 | 语言/主题切换 + 双模式 | BundleResourceManager 刷新路径（GetAllResourceInfo） | AC-31 |
| FR-14 | 双模式设备不同包体类别（**不分主副模式**）仅限系统应用，非系统应用安装失败返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP`；`isDualModeCloneApp` 仅副模式置位 | 双模式 + 不同包体类别 + 安装准入 | SetDualModeAppInfo（IsDiffPackageCategory 时校验 IsSystemApp） | AC-34 |
| FR-15 | 副模式安装时跨 map（`tempBundleInfos_`）校验类别一致性，不同包体类别 互转拦截返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT` | 双模式 + 不同包体类别 + 跨模式 | CheckDualModeCategoryConsistencyInTemp | AC-35 |
| FR-16 | TS 安装接口经 installParam.parameters 保留 key `ohos.bms.param.deviceModeDistributionPolicy`（value 为枚举值十进制字符串）透传设备模式分发策略，适配层解析刷新 `InstallParam.deviceModeDistributionPolicy` 字段后走既有 IPC 链路；NAPI/ANI `updateBundleForSelf` 均不适配（2026-08-18 裁定，保留 key 透传范围即 install 入口，该两入口走默认非缺口）；服务端 ReadFromParcel 值域白名单 [0,8] 越界降级 UNSPECIFIED；NAPI/ANI parameters 重复 key 统一 first-wins（codecheck R1 加固）；保留 key 为内部分发平台契约，不出对外资料（2026-08-18 裁定） | NAPI `install`（installer.cpp:893）+ ANI `install`（ani_bundle_installer.cpp:225）+ parameters 携带保留 key | InstallParam::RefreshDeviceModeDistributionPolicy（接入点 2 处，参数校验之后调用）+ ReadFromParcel 值域白名单 + 双栈重复 key first-wins | AC-41 |

## 异常/豁免规则

| 编号 | 异常码/枚举 | 规则描述 | 触发条件 | 超时阈值 | 处理结果 | 关联 AC |
|------|------------|----------|----------|----------|----------|---------|
| EX-1 | 默认值兜底 | 存量应用无 deviceModeDistributionPolicy 字段 | 反序列化缺失字段 | N/A | 默认"不区分设备模式分发策略" | AC-18 |
| EX-2 | 模式回退 | 系统模式参数缺失/非法 | persist.sceneboard.ispcmode / mainmode 任一读取失败(返回 -1)或非法(∉{0,1}) | N/A | 回退正常安装流程 | AC-3/AC-33 |
| EX-3 | 更新失败 | 不同包体类别与其他类别互转 | 更新时类别不一致且涉及不同包体类别（当前模式侧 `CheckDualModeCategoryConsistency` + 跨 map `CheckDualModeCategoryConsistencyInTemp`） | N/A | 返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT`（8519943） | AC-8/AC-35 |
| EX-4 | 安装失败 | 不同包体类别仅系统应用 | 双模式设备非系统应用安装不同包体类别（`SetDualModeAppInfo` 校验 `IsSystemApp`） | N/A | 返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP`（8519942） | AC-34 |
| EX-5 | 默认值兜底 | 存量应用无 appSandboxPolicy 字段 | 反序列化缺失字段 | N/A | 默认 SHARED_SANDBOX（值 0） | AC-37 |

## 恢复契约

| 编号 | 触发条件 | 恢复策略 | 恢复结果 | 约束 |
|------|----------|----------|----------|------|
| RC-1 | 重启后 ispcmode / mainmode 缺失/非法(∉{0,1}) | 所有应用加载到可查询列表 | 应用全部可查询 | tempBundleInfos_ 为空 |

## 验证映射

| 编号 | 对应规格项 | 验证方式 | 验证重点 |
|------|------------|----------|----------|
| VM-1 | FR-1/AC-1 | 单测 | 序列化往返字段保持 |
| VM-2 | FR-2/AC-4 | 集成测试 | 副模式目录隔离命名 |
| VM-3 | FR-3/AC-8 | 集成测试 | 不同包体类别互转失败 |
| VM-4 | FR-6/AC-13 | 集成测试 | 重启分类加载 |

## API 变更分析

### 新增 API

| API 名称 | 开放范围 | 入参概要 | 返回值 | 错误码范围 | 功能描述 | 关联 AC |
|----------|----------|----------|--------|------------|----------|---------|
| DeviceModeDistributionPolicy（枚举） | Public | 9 个枚举成员（值 0~8） | - | N/A | 设备模式分发策略定义，连续 int 值不支持按位或 | AC-1 |
| BundleInfo.deviceModeDistributionPolicy | Public | number（枚举值，0~8） | - | N/A | 应用设备模式分发策略，默认 UNSPECIFIED（值 0） | AC-1/AC-2 |
| InstallParam.deviceModeDistributionPolicy | Public | number（枚举值，0~8） | - | N/A | 安装时指定的设备模式分发策略，默认 UNSPECIFIED（值 0）；TS 侧经 parameters 保留 key 透传（AC-41），native/IPC 侧为字段 | AC-1/AC-41 |
| AppSandboxPolicy（枚举） | Public | 2 个枚举成员（值 0~1） | - | N/A | 应用沙箱策略定义，连续 int 值互斥单值 | AC-36 |
| BundleInfo.appSandboxPolicy | Public | number（枚举值，0~1） | - | N/A | 应用沙箱策略，默认 SHARED_SANDBOX（值 0） | AC-36/37 |

### 新增错误码

| 错误码 | 码值 | 含义 | 关联 AC |
|--------|------|------|---------|
| ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT | 8519943 | 不同包体类别互转/跨 map 类别冲突 | AC-8/AC-35 |
| ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP | 8519942 | 非系统应用安装不同包体类别 | AC-34 |

### 变更/废弃 API

| API 名称 | 变更类型 | 影响场景 | 迁移指引 | 关联 AC |
|----------|----------|----------|----------|---------|
| InstallParam（结构扩展） | 新增可选字段 | 现有调用方不传 deviceModeDistributionPolicy 时走默认值 | 无需迁移，向后兼容 | AC-1/AC-2 |
| InstallParam.parameters（保留 key 透传） | 新增保留 key 语义 | TS 侧经既有 parameters 数组（`Array<{key, value}>`）传 key `ohos.bms.param.deviceModeDistributionPolicy`、value 为枚举值十进制字符串（如 "4"）；适配层（NAPI `install`；ANI `install`）刷新 `deviceModeDistributionPolicy` 字段 | 无需迁移：不传该 key 走默认 UNSPECIFIED；传非法 value（非十进制整数/超 0~8）仅打 warning 日志、静默降级默认策略，不拦截安装（2026-08-17 裁定不报 401） | AC-41 |
| ApplicationInfo（结构扩展） | 新增可选字段 | 反序列化老数据时字段缺失 | from_json 默认值兜底，无需迁移 | AC-18 |
| BundleInfo（结构扩展） | 新增可选字段 appSandboxPolicy | 反序列化老数据时字段缺失 | from_json 默认值兜底（SHARED_SANDBOX），无需迁移 | AC-37 |

> API 签名细节、d.ts 位置、SysCap 见 design.md「API 签名、Kit 与权限」。

## 兼容性声明

- **已有 API 行为变更:** 是。安装/更新广播 Want key `isSharedSandbox`（bool）更名为 `appSandboxPolicy`（int 枚举 0/1），并新增 `beforeDeviceModeDistributionPolicy` / `beforeAppSandboxPolicy` 两个 key——对外契约变更，须同步需求二上层消费者；其余仅新增可选字段，现有调用方行为不变
- **配置文件格式变更:** 否
- **数据存储格式变更:** 是（installed_bundle 表 JSON value 新增 deviceModeDistributionPolicy + isDualModeCloneApp 字段；副模式不同包体类别记录 DB key 带 `+clone-10000+` 前缀，由 isDualModeCloneApp 字段驱动；追加 appSandboxPolicy 字段，随 baseBundleInfo_ 节点存储）。**向后兼容**：老数据缺字段走默认值（deviceModeDistributionPolicy=0 / isDualModeCloneApp=false，AC-18；appSandboxPolicy=SHARED_SANDBOX(0)，AC-37）
- **最低支持版本:** OpenHarmony-6.0-Release
- **API 版本号策略:** 新增字段与枚举标注 `@since` 目标版本

## 架构约束

> 架构规则适用性及设计方案见 design.md。

| 关键约束 | 约束说明 | 影响 AC |
|----------|----------|---------|
| 特权文件操作经 SA 511 | 安装目录创建/轮转一律跨 IPC 到 installd 进程 | AC-4/AC-10 |
| 副模式记录 key 带前缀 | 副模式不同包体类别应用 DB 记录 key 为 `+clone-10000+{bundleName}` | AC-4/AC-11 |
| 加载去前缀 | 重启加载到内存时副模式不同包体类别应用以原始 bundleName 入可查询列表 | AC-11/AC-14 |

## 非功能性需求

> N/A 判定见 proposal.md。本节为适用项指标。

| 类型 | 指标/阈值 | 验证方式 | 证据 |
|------|-----------|----------|------|
| 内存 | tempBundleInfos_ 增量按不可查询应用数量计，无额外放大 | hidumper | 待补 |
| 问题定位 | 模式判断、前缀处理关键节点有 hilog（BMS_TAG_INSTALLER） | hilog | 待补 |
| 可靠性 | 模式参数缺失时回退正常流程，不阻塞安装 | 压力测试 | 待补 |

## 多设备适配声明

> 本特性核心即 PC/PAD 双模式适配。

| 设备类型 | 行为差异 | 规格/约束 | 验证方式 | 证据 |
|----------|----------|-----------|----------|------|
| 2in1（PC） | mainmode=1(2in1) 为主；ispcmode=0(tablet) 为副 | 主模式不同包体类别不隔离；副模式不同包体类别隔离安装 | 集成测试 | 待补 |
| tablet（PAD） | mainmode=0(tablet) 为主；ispcmode=1(2in1) 为副 | 主模式不同包体类别不隔离；副模式不同包体类别隔离安装 | 集成测试 | 待补 |
| default（手机） | ispcmode / mainmode 参数不存在 | 非双模式设备，回退正常流程（AC-3） | 集成测试 | 待补 |

## 全局特性影响

| 特性 | 适用？ | 结论 | 关联场景 |
|------|--------|------|----------|
| 无障碍 | 否 | 无 UI | N/A |
| 大字体 | 否 | 无 UI | N/A |
| 深色模式 | 否 | 无 UI | N/A |
| 多窗口/分屏 | 否 | 安装侧特性 | N/A |
| 多用户 | 否 | 本需求单次安装内自洽；多用户维度不在范围 | N/A |
| 版本升级 | 是 | 存量应用默认类别1，向后兼容 | AC-18 |
| 生态兼容 | 否 | 仅系统/预置应用使用设备模式分发策略 | N/A |

## Spec 自审清单

- [x] 无"待定""TBD""TODO"等占位符（目标版本 TBD 为待用户确认项，已标注）
- [x] 所有 AC 使用 WHEN/THEN 格式，可独立测试
- [x] 范围边界明确（做什么/不做什么清晰）
- [x] 无语义模糊表述
- [x] AC 与业务规则/异常规则/恢复契约交叉一致

## context-references

```yaml
context-queries:
  - repo: "bundlemanager_bundle_framework"
    query: "副模式不同包体类别应用安装目录隔离、DB key 前缀、重启分类加载的实现细节"
```

**关键文档：** [双模式应用安装方案.md](../../双模式应用安装方案.md)、[proposal.md](./proposal.md)、[design.md](./design.md)
