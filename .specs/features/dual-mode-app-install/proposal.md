# 需求文档

> 双模式同包名不同安装包应用安装支持。本文档覆盖"需求一：支持双模式同包名不同安装包的应用安装"与"需求三：支持双模式同包名不同安装包的应用预置"（US-14）；"需求二：模式切换接口"另立特性（`.specs/features/dual-mode-app-switch/`）。源诉求快照与演进对照见 [feature.md](./feature.md)。
> 当前代码基线：`fix_dual_doc` HEAD `bcbfe06a9`（含 `appIndex_dual_mode_13` 合流）。基线契约为 `DeviceModeDistributionPolicy` + `AppSandboxPolicy`。

## 一、原始需求

### 基本信息

| 字段 | 内容 |
|------|------|
| 需求ID | REQ-DUALMODE-001 |
| 需求名称 | 双模式同包名不同安装包应用安装支持 |
| 来源 | [feature.md](./feature.md)（原始诉求快照：需求一 + 需求三；源文档《支持双模式应用安装和切换》＝bundlemanager_design_doc 仓 `双模式安装方案设计.md`，原始表述与现行口径的演进对照见 feature.md 第二节） |
| 提出人 | 用户 |
| 目标发行版本 | OpenHarmony-6.0-Release |
| 优先级 | P1 |

### 问题陈述

同一台设备支持 PC、PAD 两种模式切换，每种模式下都有特殊应用：仅 PC 的应用在 PAD 模式下不露出；仅 PAD 的应用在 PC 模式下不露出。还有一种特殊应用，在 PC 和 PAD 下都存在，但属于**包名相同、应用包体不相同**。需要在不同模式下查询到相应模式下的应用包信息。

本需求（需求一）聚焦：支持同包名不同包体的应用安装更新，涉及安装目录、数据目录、应用信息的区分。

**期望结果**：同包名不同包体（`DeviceModeDistributionPolicy` ∈ {4,6,8}）应用在副模式下安装时，通过目录前缀与数据库 key 前缀实现与主模式应用的安装隔离；设备重启后按当前模式正确加载可查询应用列表；跨模式保持 odid 一致。

### 痛点

| 用户类型 | 当前痛点 | 影响 |
|----------|----------|------|
| 系统应用/预置应用 | 同包名不同包体应用在双模式下无法共存，副模式会覆盖主模式应用 | 应用数据丢失、目录冲突 |
| 系统开发者 | 缺少按"应用类别 + 设备模式"区分安装目录与数据信息的机制 | 无法实现双模式应用隔离 |

## 二、需求基线

### 基线信息

| 字段 | 内容 |
|------|------|
| 基线版本 | v1.0 |
| 基线日期 | 2026-07-15 |
| Owner | [待确认] |
| 确认人 | 用户 |
| 复杂度 | 标准（单仓特性，涉及多模块但均在 BMS 服务内，需架构设计决策） |
| Profile | none |
| 目标发行版本 | OpenHarmony-6.0-Release |
| 版本状态 | baselined |

### 设备模式分发策略枚举定义（基线锚点）

#### DeviceModeDistributionPolicy（`bundle_info.h`，int32_t，9 成员连续 int 0~8，互斥单值不支持按位或）

| 枚举成员 | 值 | 含义 |
|----------|----|------|
| UNSPECIFIED | 0 | 不区分（默认） |
| MAIN_ONLY | 1 | 仅主模式 |
| SUB_ONLY | 2 | 仅副模式 |
| UNIVERSAL_IDENTICAL_PACKAGE | 3 | 全模式同包体 |
| UNIVERSAL_DIFFERENT_PACKAGE | 4 | 全模式不同包体（**不同包体类别**） |
| PARTIAL_COMPATIBLE_IDENTICAL_PACKAGE | 5 | 部分兼容同包体 |
| PARTIAL_COMPATIBLE_DIFFERENT_PACKAGE | 6 | 部分兼容不同包体（**不同包体类别**） |
| FULL_COMPATIBLE_IDENTICAL_PACKAGE | 7 | 全兼容同包体 |
| FULL_COMPATIBLE_DIFFERENT_PACKAGE | 8 | 全兼容不同包体（**不同包体类别**） |

> 判断"是否不同包体类别"用 `DualModeHelper::IsDiffPackageCategory(policy)`：`policy ∈ {4, 6, 8}`（集合判定）。

#### AppSandboxPolicy（`bundle_info.h`，int32_t，2 成员连续 int 0~1，互斥单值）

| 枚举成员 | 值 | 含义 |
|----------|----|------|
| SHARED_SANDBOX | 0 | 共享沙箱（默认） |
| ISOLATED_SANDBOX | 1 | 隔离沙箱（语义对应副模式不同包体类别隔离应用） |

### 主副模式判断规则（基线锚点）

| ispcmode（当前模式） | mainmode（主模式） | IsDualModeDevice | IsSecondaryMode | 模式归类 |
|---|---|---|---|---|
| 1 (2in1) | 1 (2in1) | true | false | 主模式 |
| 0 (tablet) | 0 (tablet) | true | false | 主模式 |
| 1 (2in1) | 0 (tablet) | true | **true** | 副模式 |
| 0 (tablet) | 1 (2in1) | true | **true** | 副模式 |
| -1 / 非法(∉{0,1}) | * | false | false | 非双模式（回退正常流程） |
| * | -1 / 非法(∉{0,1}) | false | false | 非双模式（回退正常流程） |

> 参数源：`persist.sceneboard.ispcmode`（生产 key 为 **bool**：true=2in1/false=tablet，`GetBoolParameter` 读取、存在性检查判缺失）+ `const.sceneboard.mainmode`（int：0=主tablet/1=主2in1）。mainmode `GetIntParameter(key, -1)` 用 -1 作"参数不存在/读取失败"sentinel，再校验值域 ∈{0,1}；ispcmode 归一化为 0/1/-1（-1=缺失）。测试注入 key `persist.bms.ispcmode` 仍为 int（缺失/非法两态可模拟）。仅不同包体类别（policy ∈ {4,6,8}）应用在**副模式**（ispcmode≠mainmode）下安装时做目录/key 前缀特殊处理；主模式及非双模式均不做处理。

### 目标和成功指标

| 目标 | 成功指标 | 验证方式 |
|------|----------|----------|
| 副模式不同包体类别应用安装隔离 | 副模式安装目录/数据目录使用 `+clone-10000+bundleName` | 功能测试 + 目录检查 |
| 与主模式应用互不覆盖 | 主模式应用数据在副模式安装后仍完整 | 数据校验 |
| 更新时类别一致性校验 | 不同包体类别与其他类别互转时更新失败返回错误码 | 安装测试 |
| 重启后按模式正确加载 | 副模式可查询到去前缀的同包名应用 | 重启测试 + 查询验证 |
| 跨模式 odid 一致 | 两模式下 odid 相同 | odid 比对 |
| 不同包体类别仅系统应用准入 | 非系统应用主/副模式装不同包体类别失败 | 安装测试 |
| 模式独占策略安装准入 | MAIN_ONLY×副模式 / SUB_ONLY×主模式安装失败（8519947），匹配模式正常 | 安装测试 |
| 预置两模式包体分发 | 预置目录两模式 hap 一次预置装出主/副两变体，切换后各自可见 | 预置 + 重启测试 |
| 切换互斥快速失败 | 切换进行中提交安装/更新/卸载即拒（8519944），切换结束可重试成功 | 并发测试 |

### 用户故事与 AC

| Story ID | 用户故事 | 优先级 |
|----------|----------|--------|
| US-1 | 作为应用安装方，需要为应用指定设备模式分发策略，以便系统按策略在双模式下正确处理 | P0 |
| US-2 | 作为系统，需要在副模式下安装不同包体类别应用时使用隔离目录与key，以便与主模式同名应用互不干扰 | P0 |
| US-3 | 作为系统，需要更新不同包体类别应用时校验策略一致性，以便避免错误的跨类别覆盖安装 | P0 |
| US-4 | 作为系统，需要设备重启后按当前模式正确加载应用列表，以便副模式下查询到正确的应用 | P0 |
| US-5 | 作为系统，需要跨模式安装的同包名应用保持 odid 一致，以便应用数据/权限跨模式一致 | P1 |
| US-6 | 作为系统，需要安装事件携带模式/沙箱策略相关信息（当前+更新前），以便上层（需求二）正确处理模式切换 | P1 |
| US-7 | 作为系统，需要副模式不同包体类别应用在权限 token / uid / 异常恢复 / 各数据表与主模式完整隔离 | P0 |
| US-8 | 作为系统，需要限制不同包体类别仅系统应用可配置、并校验跨模式策略一致 | P0 |
| US-9 | 作为系统，需要在 BundleInfo 中持久化应用沙箱策略（数据模型） | P1 |
| US-10 | 作为系统，需要副模式不同包体类别应用 appIndex 安装时一次置位 10000（单一数据源） | P1 |
| US-11 | 作为系统，需要安装/更新广播携带沙箱策略且隔离粘性保持 | P1 |
| US-12 | 作为上层分发调用方，需要经 TS 安装接口 parameters 保留 key 透传设备模式分发策略 | P1 |
| US-13 | 作为系统，需要校验模式独占策略（MAIN_ONLY/SUB_ONLY）与当前模式匹配（不匹配拒绝 8519947） | P0 |
| US-14 | 作为系统，需要预置目录含两模式 hap 的不同包体类别应用一次预置完成主/副两变体安装（ERMS 解析 + 两趟 fan-out），变体按所属模式入对应 map | P0 |
| US-15 | 作为系统，需要安装/更新/卸载与模式切换互斥（切换中快速失败 8519944，不排队） | P0 |
| US-16 | 作为上层查询调用方，需要双模式 clone 应用查询结果回显 appIndex=10000（查询 key 零改动） | P1 |
| US-17 | 作为 TS 应用开发者，需要 `bundleManager.DeviceModeDistributionPolicy` 枚举 JS 运行时可用（9 命名值） | P1 |

> AC-1~54 的 WHEN/THEN 完整定义见 [spec.md](./spec.md)。AC-36/37 为 AppSandboxPolicy 数据模型、AC-38 为 appIndex 单一数据源、AC-39/40 为广播沙箱策略+粘性+before 值、AC-41 为 TS 保留 key 透传、AC-42 为模式独占拦截（8519947）、AC-43/44 为预置 ERMS 两趟 fan-out 与跨模式变体存储、AC-45 为切换互斥（8519944）、AC-46 为查询结果回显 clone appIndex、AC-47 为 NAPI 枚举运行时注册；AC-48~54 为 2026-09-04 规则检视拆分项（自 AC-41/43/45/17 按单一可验证行为拆出，行为语义零变化：服务端越界降级/重复 key first-wins/ERMS 退化兜底/两趟独立失败/user-100 恢复/切换对称面/卸载事件 3 字段）。

### 范围边界

**包含：**
- 设备模式分发策略枚举 `DeviceModeDistributionPolicy`（9 成员连续 int）+ 应用沙箱策略枚举 `AppSandboxPolicy`（2 成员）定义与持久化
- BundleInfo 新增 `deviceModeDistributionPolicy` / `appSandboxPolicy` 字段；InstallParam 新增 `deviceModeDistributionPolicy`（Public API）
- 安装流程：读取 ispcmode/mainmode、主副模式判断、副模式不同包体类别特殊处理
- 目录前缀机制 `+clone-10000+bundleName`（封装 DualModeHelper 工具类）
- 首次安装 / 更新场景区分与策略一致性校验（当前模式 + 跨 map）
- 不同包体类别 仅系统应用准入（不分主副模式）
- 模式独占策略安装准入（MAIN_ONLY×副模式 / SUB_ONLY×主模式拒绝 8519947）
- 预置双模式分发安装：ERMS 策略解析（dlopen liberms_sdk.z.so）+ 主/副两趟 fan-out（`forceDualModeCloneInstall` 进程内字段，不走 IPC）+ 退化整目录单包兜底 + user-100 恢复带存储策略（免重查 ERMS）
- 跨模式变体存储（IsCrossModeInstall → tempBundleInfos_，原名 key；含 MAIN_ONLY/SUB_ONLY 单模式应用）
- 安装/更新/卸载与模式切换互斥接入（TryLockForBundleOperation + 队列两时点拒绝 + 10 直连入口 guard，8519944 快速失败；互斥本体与切换排他侧属需求二）
- 卸载事件双模式字段（policy/currentMode/appSandboxPolicy 3 字段，无 before 值）
- 目录轮转适配（`+new-`/`+old-` 改造、InstallExceptionMgr）
- 数据库 key 前缀适配与按模式查询逻辑
- 设备重启数据加载（BundleDataMgr 新增 tempBundleInfos_、按模式分类）
- 跨模式 odid 一致性
- effective name 数据层适配（skills / provision / router / installStates_ / resource 核心表）
- appIndex 单一数据源（副模式不同包体类别 clone 应用安装时置位 10000）
- 安装事件字段扩展（5 双模式字段：deviceModeDistributionPolicy / currentMode int / appSandboxPolicy / beforeDeviceModeDistributionPolicy / beforeAppSandboxPolicy）

**不包含：**
- 需求二：模式切换接口（另立特性）
- 分身应用、沙箱应用的创建（规格限制）
- 存量应用主动数据迁移（默认类别1即可）
- 应用类别 2~6 的展示露出控制（属需求二查询侧范畴）
- 功能数据表全面适配（10 张表，design ADR-25 遗留，后续需求）
- 查询转换收口（Router/Resource/Provision 部分查询遗留，后续需求）
- 卸载路径 effective-name 全面适配（卸载主路径仍原名，留卸载专项）

### 影响范围

| 子系统 | 仓库 | 模块/路径 | 影响类型 |
|--------|------|-----------|----------|
| bundlemanager | bundlemanager_bundle_framework | BundleInfo（bundle_info.h） | 修改（新增 deviceModeDistributionPolicy / appSandboxPolicy 字段 + 枚举定义） |
| bundlemanager | bundlemanager_bundle_framework | InstallParam（install_param.h） | 修改（新增 deviceModeDistributionPolicy 属性） |
| bundlemanager | bundlemanager_bundle_framework | DualModeHelper（dual_mode_helper.h/cpp，新增） | 新增（模式判断、前缀工具、IsDiffPackageCategory 集合判定） |
| bundlemanager | bundlemanager_bundle_framework | 安装流程（base_bundle_installer / bundle_permission_mgr） | 修改（模式判断、前缀处理、策略校验、token/uid 隔离、appIndex 单一数据源、粘性沙箱） |
| bundlemanager | bundlemanager_bundle_framework | InstalldService / InstalldOperator | 修改（目录命名、轮转适配） |
| bundlemanager | bundlemanager_bundle_framework | InstallExceptionMgr / BundleExceptionHandler | 修改（前缀命名/异常恢复适配） |
| bundlemanager | bundlemanager_bundle_framework | BundleDataMgr | 修改（新增 tempBundleInfos_、重启加载、key 查询、状态机、跨模式变体入 temp 存储、TryLockForBundleOperation） |
| bundlemanager | bundlemanager_bundle_framework | SystemBundleInstaller（预置分发） | 修改（ERMS 两趟 fan-out：主趟收窄 + 副趟 forceDualModeCloneInstall） |
| bundlemanager | bundlemanager_bundle_framework | BundleInstallerManager / BundleInstallerHost（互斥接入） | 修改（队列两时点拒绝 + 10 直连入口 DualModeSwitchGuard） |
| bundlemanager | bundlemanager_bundle_framework | 数据库层（installed_bundle / SkillsDescription / AppProvisionInfo / Router / BundleResource） | 修改（key 前缀适配） |
| bundlemanager | bundlemanager_bundle_framework | 事件系统（安装事件） | 修改（扩展 5 双模式字段 + before 值） |
| bundlemanager | bundlemanager_bundle_framework | 查询结果组装（InnerBundleInfo / BundleDataMgr / extend_resource） | 修改（clone 应用查询结果回显 appIndex=10000，查询 key 零改动） |
| bundlemanager | bundlemanager_bundle_framework | NAPI 层（interfaces/kits/js/bundle_manager） | 修改（DeviceModeDistributionPolicy 枚举 9 命名值运行时注册） |

### 1+8设备差异规格

> 本特性核心即 1+8 设备形态中 2in1（PC）/tablet（PAD）两形态的双模式差异；主/副模式由 ispcmode/mainmode 参数对值判定（见「主副模式判断规则」基线锚点），非按设备类型硬编码分支。

| 设备形态 | 行为差异 | 规格/约束 | 验证方式 |
|----------|----------|-----------|----------|
| 2in1（PC） | mainmode=1(2in1) 为主模式侧；ispcmode=0(tablet) 为副模式侧 | 主模式侧不同包体类别不隔离；副模式侧不同包体类别隔离安装（`+clone-10000+` 前缀） | 集成测试 |
| tablet（PAD） | mainmode=0(tablet) 为主模式侧；ispcmode=1(2in1) 为副模式侧 | 同 2in1 对称：主模式侧不隔离、副模式侧隔离安装 | 集成测试 |
| default（手机等其他形态） | ispcmode / mainmode 参数不存在或非法 | 非双模式设备，全部回退正常安装流程（AC-3/AC-12） | 集成测试 |

> 未配置双模式参数的其余设备形态均走 default 行为；本特性不含按设备类型分支的其他 UI/交互差异。

### DFX设计

| 维度 | 设计 | 指标/阈值 | 验证方式 |
|------|------|-----------|----------|
| 可靠性 | 模式参数缺失/非法回退正常安装流程不阻塞（AC-3/AC-12/AC-33）；ERMS 不可用退化整目录单包预置（AC-50）；切换互斥快速失败可重试（AC-45，8519944） | 回退/退化路径功能用例全通过；8519944 拒绝后重试成功 | 功能测试 + 并发测试 |
| 可维护性（问题定位） | 模式判断、前缀处理、互斥拒绝关键节点输出 hilog（BMS_TAG_INSTALLER） | 关键节点日志可按标签检索 | hilog 抓取 |
| 资源（内存） | tempBundleInfos_ 增量按不可查询应用数量计，无额外放大 | 增量与应用数量线性、无放大 | hidumper |
| 可测试性 | 模式判断支持测试注入 key（`persist.bms.ispcmode`，缺失/非法两态可模拟，design ADR-22 双路径） | 注入缺失/非法两态用例通过 | 单元测试 |

> 指标证据收集与全量非功能回归属发布 Gate 范畴（与 spec.md「非功能需求」表口径一致，证据在发布阶段回填）。

### API 变更项清单

| API 名称 | 变更类型 | 开放范围 | 概要说明 |
|----------|----------|----------|----------|
| DeviceModeDistributionPolicy（枚举） | 新增枚举 | Public | 9 成员连续 int 0~8，互斥单值不支持按位或 |
| BundleInfo.deviceModeDistributionPolicy | 新增字段 | Public | 应用设备模式分发策略，默认 UNSPECIFIED(0) |
| InstallParam.deviceModeDistributionPolicy | 新增字段 | Public | 安装时指定的策略，默认 UNSPECIFIED(0) |
| AppSandboxPolicy（枚举） | 新增枚举 | Public | 2 成员连续 int 0~1（SHARED_SANDBOX / ISOLATED_SANDBOX） |
| BundleInfo.appSandboxPolicy | 新增字段 | Public | 应用沙箱策略，默认 SHARED_SANDBOX(0) |
| ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT | 新增错误码 | System | 不同包体类别互转/跨map冲突（8519943） |
| ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP | 新增错误码 | System | 非系统应用装不同包体类别（8519942） |
| ERR_APPEXECFWK_INSTALL_DUAL_MODE_POLICY_NOT_SUPPORTED | 新增错误码 | System | 模式独占策略与当前模式不匹配：MAIN_ONLY×副模式 / SUB_ONLY×主模式（8519947） |
| ERR_APPEXECFWK_DUAL_MODE_SWITCH_BUSY | 共用错误码（需求二定义） | System | 模式切换进行中安装/更新/卸载快速失败（8519944，可重试；安装侧消费，完整语义见需求二） |

### 不涉及项确认

| 维度 | 涉及？ | 依据 | 若涉及，进入哪个下游文档 |
|------|--------|------|--------------------------|
| 性能 | 否 | 模式判断与前缀拼接为常量开销；tempBundleInfos_ 内存按应用数量，可接受 | N/A |
| 安全与权限 | 否 | 不改文件权限模型；ispcmode/mainmode 为系统参数只读 | N/A |
| 兼容性 | 是 | 存量应用默认类别1；新增字段带默认值 | spec.md |
| API/SDK | 是 | 新增 Public 字段 + 枚举 + 错误码 | design.md / spec.md |
| IPC/跨进程 | 是 | 安装/目录操作经 InstalldService（SA 511） | design.md |
| 构建与部件 | 否 | 无新增部件，仅现有模块修改 | N/A |
| 国际化/无障碍 | 否 | 无 UI 相关 | N/A |
| 数据迁移 | 否 | 存量应用默认类别1，零迁移（已在 AC-18 覆盖） | N/A |

### 兼容性与非功能需求

| 类别 | 结论 |
|------|------|
| 向前/向后兼容 | 向后兼容：存量应用默认 UNSPECIFIED / SHARED_SANDBOX；新增字段有默认值，不破坏现有调用 |
| 性能 | 模式判断与前缀拼接为常量开销；新增 tempBundleInfos_ 增加常驻内存（按应用数量） |
| 安全 | ispcmode/mainmode 读取为系统参数；目录前缀不改文件权限模型 |
| 可靠性 | 模式参数缺失/非法时回退正常安装流程，不阻塞 |

### 依赖与风险

| 依赖项 | 类型 | 说明 |
|--------|------|------|
| persist.sceneboard.ispcmode / mainmode 系统参数 | 运行 | 由 sceneboard 模式管理模块写入，BMS 只读 |

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| 前缀处理遗漏点导致数据不一致 | 中 | 统一封装 DualModeHelper；design.md 列全改动点；逐点审查 |
| 目录轮转逻辑改造引入安装失败 | 中 | 复用现有 +clone 命名解析；专项测试更新/异常中断场景 |
| Public API 兼容性承诺 | 中 | 枚举值为连续 int（互斥单值，不支持按位或），新增字段带默认值；广播 Want key 改名（isSharedSandbox→appSandboxPolicy + 2 before key）属对外契约变更，须同步需求二 |

### 变更控制

| 变更类型 | 触发条件 | 处理规则 |
|----------|----------|----------|
| 范围新增 | 新增用户故事或仓/模块 | 重新评估复杂度和设计影响 |
| AC 变更 | 修改可观察行为或错误码 | 重新审批基线和 Spec |
| API 变更 | 新增/修改 Public/System API | 触发设计审批 |
| 非功能指标变更 | 性能/安全/兼容性阈值变化 | 重新确认测试计划 |
| 目标版本变更 | 交付版本调整 | 更新 manifest.target_release |

### 基线结论

**通过** — 功能范围、子系统影响、API 变更、兼容性与非功能需求、依赖与风险均已确认；AC 完整可测试。
