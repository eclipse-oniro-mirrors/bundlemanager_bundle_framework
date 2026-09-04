# 特性规格

> 双模式同包名不同安装包应用安装支持。固化用户可见行为、API 契约与验收标准。内部实现（类名、调用链、前缀拼接机制）见 [design.md](./design.md)。
>
> **裁剪声明**：用户故事/验收标准章节为纯黑盒规格（不含框架层实现标识符）；代码锚点（类名/方法名/文件行号）集中保留于「功能规则」触发条件/作用对象列、「架构约束」章节与「验收追溯」证据列，仅作实现追溯与验证定位，权威定义以 design.md 为准——此为对 spec 模板"不应包含框架层类名/方法名"的定向豁免（本特性以代码先行、文档对照终态同步的方式演进，锚点保证每条 AC 可对照代码核对）。

## 概述

| 属性 | 值 |
|------|-----|
| 特性名称 | 双模式同包名不同安装包应用安装支持 |
| 特性编号 | FEAT-20260715-001 |
| 所属 Epic | 无（独立特性；需求二"模式切换接口"另立特性） |
| 优先级 | P1 |
| 目标版本 | OpenHarmony-6.0-Release（引用 manifest.target_release，与 design.md 一致） |
| SIG 归属 | BundleManager SIG |
| 状态 | Approved |
| 复杂度 | 标准 |
| 当前代码基线 | `fix_dual_doc` HEAD `bcbfe06a9`（含 `appIndex_dual_mode_13` 合流） |

## 本次变更范围（Delta）

| 类型 | 内容 | 说明 |
|------|------|------|
| ADDED | 设备模式分发策略枚举 DeviceModeDistributionPolicy（9 个连续 int 值，不支持按位或） | Public API |
| ADDED | BundleInfo.deviceModeDistributionPolicy 字段 | Public API，默认"不区分" |
| ADDED | InstallParam.deviceModeDistributionPolicy 入参 | Public API，安装时指定设备模式分发策略 |
| ADDED | 副模式不同包体类别应用安装目录/数据隔离行为 | 同包名不同包体在副模式独立安装 |
| ADDED | 设备重启后按当前模式分类加载应用列表 | 副模式可查询到对应应用 |
| ADDED | 不同包体类别 仅系统应用准入 + 跨模式类别一致性校验 | 非系统应用副模式 不同包体类别 安装失败（8519942）+ 跨模式类别冲突拦截（8519943） |
| ADDED | 模式独占策略安装准入校验 | MAIN_ONLY 在副模式 / SUB_ONLY 在主模式安装失败（8519947），见 AC-42 |
| ADDED | 预置双模式分发安装（ERMS 策略解析 + 主/副两趟 fan-out） | 预置目录含两模式 hap 时主趟装主模式 hap 集、副趟以 clone 名装副模式 hap 集，见 AC-43/AC-50~AC-52 |
| ADDED | 跨模式变体存储（tempBundleInfos_） | fan-out 副趟变体与 MAIN_ONLY/SUB_ONLY 目标模式≠当前模式的包，安装即入不可查询列表（原名 key），见 AC-44 |
| ADDED | 安装/更新/卸载与模式切换互斥（快速失败 8519944） | 切换进行中安装类任务不排队、同步拒绝；与需求二「模式切换接口」共用 shared_mutex 互斥（需求二引入），见 AC-45/AC-53 |
| ADDED | 双模式 clone 应用查询结果回显 appIndex=10000 | 查询 key 零改动（分类后两 map 均原始名 key），仅结果 payload 回显 clone 标识维度，见 AC-46 |
| ADDED | DeviceModeDistributionPolicy 枚举 NAPI 运行时注册 | JS 侧 `bundleManager.DeviceModeDistributionPolicy` 9 命名值可用（d.ts 契约的运行时补齐），见 AC-47 |
| ADDED | 应用沙箱策略枚举 AppSandboxPolicy（SHARED_SANDBOX=0 / ISOLATED_SANDBOX=1，连续 int 值，互斥单值） | Public API |
| ADDED | BundleInfo.appSandboxPolicy 字段（默认 SHARED_SANDBOX，完整 Parcel+JSON 序列化） | Public API；业务消费留后续 |
| ADDED | 卸载事件携带双模式字段（deviceModeDistributionPolicy / currentMode / appSandboxPolicy，无 before 值） | 卸载主路径 effective-name 适配仍留卸载专项（范围不变），仅事件字段扩展，见 AC-54 |
| MODIFIED | 安装更新时新增"设备模式分发策略一致性"校验 | 不同包体类别与其他类别互转则更新失败 |

## 输入文档

| 文档 | 路径 | 状态 |
|------|------|------|
| Requirement | [proposal.md](./proposal.md) | Approved |

## 术语说明

| 术语 | 定义 |
|------|------|
| 不同包体类别 | 设备模式分发策略值 ∈ {4, 6, 8}（`*_DIFFERENT_PACKAGE`），见枚举定义；副模式隔离处理对象 |
| clone 应用 | 副模式安装的不同包体类别变体；存储名（effective name）带 `+clone-10000+` 前缀，appIndex=10000 |
| effective name（存储名） | 数据层实际使用的 key 名：clone 应用带 `+clone-10000+` 前缀，其余应用为原始 bundleName |
| ERMS | 预置应用分发策略管理服务，预置安装时经动态库 `liberms_sdk.z.so` 查询分发策略与按设备类型分组的 hap 清单（仅预置路径触发，design ADR-32） |
| fan-out（两趟分发） | 一次预置安装拆为主模式趟（原名，装主模式 hap 集）+ 副模式趟（clone 前缀名，装副模式 hap 集）两趟安装 |
| odid | 应用安装时由 BMS 生成并持久化的设备-开发者维度标识；跨模式安装按 developerId 复用以保持一致（design ADR-7） |
| 主/副模式 | ispcmode（当前模式）与 mainmode（主模式）均 ∈ {0,1} 时：两者相等为主模式侧，不等为副模式侧；任一无效即非双模式设备（design ADR-5/ADR-10） |

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
**以便** 系统按该类别执行对应的隔离与查询可见性处理。

**验收标准：**

- **AC-1:** WHEN 安装应用且 `InstallParam` 携带 `deviceModeDistributionPolicy` THEN 该设备模式分发策略持久化存储于应用的 `ApplicationInfo` 中
- **AC-2:** WHEN `InstallParam` 或 `ApplicationInfo` 未设置 `deviceModeDistributionPolicy` THEN 设备模式分发策略默认值为"不区分"（值 0，UNSPECIFIED）
- **AC-18:** WHEN 读取升级前已安装、无 `deviceModeDistributionPolicy` 字段的存量应用 THEN 默认归为"不区分设备模式分发策略"，主副模式均不做特殊处理

### US-2: 副模式不同包体类别应用安装隔离

**作为** 系统,
**需要** 在副模式下安装不同包体类别（相同包名不同包体）应用时使用隔离的安装目录与数据目录,
**以便** 与主模式同名应用互不覆盖。

**验收标准：**

- **AC-3:** WHEN `persist.sceneboard.ispcmode` / `const.sceneboard.mainmode` 任一无效 THEN 判定为非双模式设备，完全回退正常安装流程，不做任何设备模式分发策略相关处理（不拼前缀、不置 clone 标志、不填事件双模式字段）。无效态定义（design ADR-5/ADR-10）：ispcmode 生产 key 为 **bool**（true=2in1/false=tablet），仅"缺失"一种无效态；mainmode 为 int，缺失（参数不存在/读取失败）或非法（∉{0,1}）均无效；两参数每次使用时**直读**系统参数（无缓存）并做归一化/值域校验（有效 ⇔ ispcmode∈{0,1} 且 mainmode∈{0,1}），"参数缺失"与"参数非法"统一判为非双模式；直读保证模式切换后安装侧判定即时生效。测试注入 key（`persist.bms.ispcmode`，int）保留缺失/非法两种无效态（ADR-22），与生产 bool key 读取路径分流
- **AC-4:** WHEN 当前为副模式（ispcmode≠mainmode，两者均∈{0,1}）安装不同包体类别应用 THEN 安装目录、数据目录及 code-dir 下所有子目录（so/lib/ext-profile 等）与轮转目录（+new-/+old-/+temp-）均使用带前缀的隔离命名，与主模式同名应用物理隔离
- **AC-5:** WHEN 当前为主模式（ispcmode==mainmode）安装不同包体类别应用 THEN 不做目录特殊处理，按正常流程安装
- **AC-6:** WHEN 安装非不同包体类别（即 `deviceModeDistributionPolicy` ∉ {4,6,8}）的应用 THEN 无论主副模式均不做目录特殊处理
- **AC-10:** WHEN 副模式更新不同包体类别应用触发安装目录轮转 THEN 目录轮转（+new-/+old-）正确作用于带前缀的隔离目录
- **AC-11:** WHEN 在副模式下查询不同包体类别应用 THEN 可查询到该应用（查询结果为去前缀的应用名）；主模式下查询不同包体类别副模式应用 THEN 查询不到

### US-3: 更新时类别一致性校验

**作为** 系统,
**需要** 更新不同包体类别应用时校验设备模式分发策略一致性,
**以便** 避免错误的跨类别覆盖安装。

**验收标准：**

- **AC-7:** WHEN 更新已安装应用且已安装类别与待安装类别一致 THEN 继续安装流程
- **AC-8:** WHEN 更新时已安装类别与待安装类别不一致且涉及不同包体类别与其他类别互转 THEN 返回更新失败（错误码 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT`=8519943）。校验覆盖两个维度：当前模式已安装记录（当前模式侧）与另一模式变体记录（跨 map 侧，见 AC-35）；"不同包体类别"以策略值 ∈ {4,6,8} 判定（见枚举定义）
- **AC-9:** WHEN 更新时类别不一致但不涉及不同包体类别互转 THEN 继续安装流程并更新设备模式分发策略为最新值

### US-4: 设备重启后按模式加载应用列表

**作为** 系统,
**需要** 设备重启后按当前模式正确加载可查询的应用列表,
**以便** 副模式下能查询到对应的同包名不同包体应用。

**验收标准：**

- **AC-12:** WHEN 设备重启且 ispcmode（生产 bool，缺失即无效）/ mainmode（缺失或非法 ∉{0,1}）任一无效 THEN 判定为非双模式设备，重启分类早退：所有已安装应用加入可查询列表，不可查询列表为空
- **AC-13:** WHEN 设备重启且双模式（ispcmode / mainmode 均∈{0,1}） THEN 仅对不同包体类别应用（策略值 4/6/8）分类：先将带前缀存储 key 的副模式安装 clone 记录（DB key 形如 `+clone-10000+{name}`）移入不可查询列表（移入后以去前缀原名为 key），主模式记录（原名 key）不动；副模式（ispcmode≠mainmode）下再将这些 clone 加入可查询列表；非不同包体类别应用（含 UNSPECIFIED）不做模式分类，始终保留在可查询列表
- **AC-14:** WHEN 重启加载不同包体类别应用且当前为副模式 THEN 副模式安装的 clone 应用加入可查询列表，应用名为去前缀原始名；若同一应用主副模式均已安装，则主模式安装的应用交换到不可查询列表；若某不同包体类别应用仅有主模式变体（无 clone 对应），兜底遍历将其移入不可查询列表隐藏——即副模式下可查询列表仅保留 clone，非 clone 不同包体类别主模式变体一律隐藏
- **AC-15:** WHEN 重启加载不同包体类别应用且当前为主模式 THEN 副模式安装的 clone 应用加入不可查询列表

### US-5: 跨模式 odid 一致

**作为** 系统,
**需要** 跨模式安装的同包名应用保持 odid 一致,
**以便** 应用数据/权限等标识跨模式一致。

**验收标准：**

- **AC-16:** WHEN 同一应用分别在主模式和副模式安装 THEN 两个模式下该应用的 odid 保持一致（odid 生成时同时遍历两模式应用记录、按 developerId 复用，design ADR-7）

### US-6: 安装事件携带模式信息

**作为** 系统（供需求二上层消费）,
**需要** 安装/更新事件携带设备模式分发策略、当前模式、是否共沙箱字段,
**以便** 上层依据事件字段执行模式切换的对应处理。

**验收标准：**

- **AC-17:** WHEN 双模式设备发送安装/更新事件 THEN 事件含 5 个双模式扩展字段（Want key 同名）：设备模式分发策略 `deviceModeDistributionPolicy`（当前）、当前模式 `currentMode`（**int**：0=tablet, 1=2in1, -1=未读取/非双模式）、应用沙箱策略 `appSandboxPolicy`（当前，默认 SHARED_SANDBOX，粘性规则见 AC-39）、更新前策略 `beforeDeviceModeDistributionPolicy`（默认 UNSPECIFIED，更新时从旧值捕获，见 AC-40）、更新前沙箱策略 `beforeAppSandboxPolicy`（默认 SHARED_SANDBOX，同前）。仅双模式设备填充，非双模式设备保持默认值；clone 命名安装时事件另携带 `appIndex=10000`。**对外契约变更**：Want key `isSharedSandbox`（bool）更名为 `appSandboxPolicy`（int 枚举 0/1）并新增 2 个 before key，须同步需求二「模式切换接口」上层消费者
- **AC-54:** WHEN 双模式设备发送卸载事件 THEN 事件携带 3 个双模式字段（Want key 同名）：`deviceModeDistributionPolicy` / `currentMode` / `appSandboxPolicy`（无 before 值）；非双模式设备保持默认。卸载主路径存储名适配仍留卸载专项（范围不变）

### US-7: 副模式完整隔离（权限 token / uid / 异常恢复 / 数据层）

**作为** 系统,
**需要** 副模式不同包体类别应用在权限 token、数据目录 uid、安装异常恢复及各数据表（skills / provision / router / 安装状态 / resource）与主模式同名应用完整隔离,
**以便** 主副同名应用互不干扰、异常恢复时查询正确。

**验收标准：**

- **AC-19:** WHEN 副模式安装不同包体类别应用（clone 应用，appIndex 已于安装时置位 10000，见 AC-38）THEN 其 HAP token 通过 instIndex=10000 与主模式同名应用隔离（独立 hap token，见 design ADR-11/ADR-28）
- **AC-20:** WHEN 副模式安装不同包体类别应用 THEN 其数据目录/asan 日志目录归属独立 uid（基于带前缀名分配的 bundleId 派生），与主模式同名应用 uid 不同；重启后 uid 保持一致（持久化 uid，不重新生成，见 design ADR-13）
- **AC-21:** WHEN 安装异常恢复接收带前缀的 bundleName THEN 按解析回的原名查询应用记录；目录轮转操作仍用带前缀名（见 design ADR-15）
- **AC-22:** WHEN 副模式安装/更新/卸载不同包体类别应用（clone 应用）THEN skills 安装目录（`/data/app/el1/skills/public/<bundleName>/<module>` 及其 +TMP temp 目录）的提取落盘、temp→real 重命名、删除均使用带 `+clone-10000+` 前缀的隔离命名，与主模式同名应用 skills 目录物理隔离；主模式用原名按正常流程（见 design ADR-16）
- **AC-23:** WHEN 副模式安装/更新/卸载带 skill 的不同包体类别应用（clone 应用）THEN skills description 数据层的插入/删除/查询均以带 `+clone-10000+` 前缀的存储名作 RDB key，主模式同名应用 description 不被覆盖/误删/误查；对外 `SkillInfo.bundleName`（Parcelable）仍返回原名；主模式用原名作 key，行为零变化（见 design ADR-17）
- **AC-24:** WHEN 副模式安装/更新应用（clone 应用）THEN AppProvisionInfo 数据层的插入/更新以带 `+clone-10000+` 前缀的存储名作 RDB key 写入，主模式同名 provision 不被覆盖；卸载时以存储名删除，不残留孤儿 provision；主模式存储名回落原名作 key，行为零变化（见 design ADR-18）
- **AC-25:** WHEN 副模式调 Public API `getAppProvisionInfo`（入参传原名） THEN 以原名命中应用记录后按 clone 判定，provision 查询 key 取带前缀存储名，返回副模式 provision；返回值 `appProvisionInfo.bundleName` 仍为原名；主模式或非双模式应用查询 key 取原名，行为零变化（见 design ADR-19）。**范围：仅 `getAppProvisionInfo`（单数）；`getAllAppProvisionInfo` 及证书/签名信息同源查询遗留后续**
- **AC-26:** WHEN 副模式安装/更新应用（clone 应用）THEN Router 数据层的插入/更新以带 `+clone-10000+` 前缀的存储名作 key 写入，主模式同名 router 不被覆盖；卸载/模块更新删旧时以存储名删除，不残留孤儿；主模式或非双模式存储名回落原名，零变化（见 design ADR-20）。**已知高风险遗留：Router 查询未适配 → 副模式应用启动路由断裂，由后续其他需求解决**
- **AC-27:** WHEN 副模式 clone 应用安装/更新/卸载 THEN 安装状态机各调用点（安装/更新/卸载的开始、成功、失败与回滚）以带 `+clone-10000+` 前缀的存储名作状态 key 匹配流转，clone 应用状态正确；应用信息增删改各查询点维持按应用记录自带 clone 标志判定不变；删除应用信息时按前缀 key 解析回原名删除主记录（见 design ADR-21）
- **AC-28:** WHEN 非双模式设备或非 clone 应用 THEN 存储名回落原名，状态机以原名作状态 key，行为与现状完全一致；应用信息增删改各查询点回归零影响（见 design ADR-21）
- **AC-29:** WHEN 副模式安装/更新不同包体类别应用（clone 应用）THEN 资源数据层（label/iconId，NAME 单列主键）的写入、更新清理与重启重建均以带 `+clone-10000+` 前缀的存储名作 RDB key（硬约束：写入数据库时 key 带前缀），主模式同名应用 label/iconId 不被覆盖；icon 字节表按设计保留原始 bundleName（不隔离 clone/主模式）；hap 解析缓存按存储名区分两模式 hap（不串解析）；对外 Parcelable `BundleResourceInfo.bundleName` 仍为原名（见 design ADR-24）。**已知局限（遗留其他需求）**：① 卸载删除/恢复路径未适配——仍用原始 bundleName，clone 的前缀资源记录卸载后残留；② 资源表查询转换（`getBundleResourceInfo` 等 Public API）；③ OTA 重建。语言/主题刷新见 AC-31
- **AC-30:** WHEN 非双模式设备或非 clone 应用 THEN 资源数据层写入/更新/重启重建/刷新行为与现状完全一致（回归零影响）；卸载路径本就用原名，亦零变化（见 design ADR-24）
- **AC-31:** WHEN 双模式设备发生语言或主题切换 THEN 两模式同名应用的名称资源（label）均被刷新（clone 落前缀 key、主模式落原名 key），切回另一模式后 label 为新语言/主题；两模式各自刷新到自己的 key，不交叉污染（见 design ADR-24）。**注：OTA 主题/动态图标刷新仍遗留其他需求**
- **AC-32:** WHEN 与本特性无关的 4 类独立调用方（应用服务框架/skills/共享包安装器及事件处理）更新安装状态（传原名） THEN 行为零变化：所处理应用的类型（应用服务框架/skills/共享包）与 clone 应用（普通应用）互斥，正常生命周期不触达 clone，状态 key 为原名匹配正确；DB 丢失极端异常恢复路径对 clone 应用用原名的错配作为**已知遗留**（仅 DB 丢失触发，正常 OTA/重启不走该恢复分支）（见 design ADR-21）
- **AC-33:** WHEN `mainmode` 参数存在但值非法（如 2，∉{0,1}），或 ispcmode 参数无效（生产 bool key 仅"缺失"一种无效态、无"非法值"态；测试注入 int key 可模拟非法值） THEN 视为该参数无效（等价"参数缺失"），判定为非双模式设备 → 回退正常安装流程，不做前缀/分类/事件字段处理（mainmode 值域校验 {0,1}；ispcmode 归一化 0/1/-1，见 design ADR-5/ADR-10）

### US-8: 双模式安装准入与跨模式类别一致性

**作为** 系统,
**需要** 限制不同包体类别仅系统应用可配置、并校验跨模式（当前 map 与另一模式 map）类别一致,
**以便** 避免普通应用误用双模式类别造成隔离资源浪费、避免主副模式类别冲突覆盖。

**验收标准：**

- **AC-34:** WHEN 双模式设备安装不同包体类别应用（策略值 ∈ {4,6,8}，**不分主副模式**）THEN 仅系统应用允许，继续安装流程；WHEN 非系统应用 THEN 安装失败，返回错误码 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP`（**8519942**，对外映射 `ERR_INSTALL_PARSE_FAILED`，见错误码表），校验先于 clone 标志置位（失败时应用信息无任何突变）。主模式不同包体类别 + 系统应用 THEN 通过校验但**不置** clone 标志（仅副模式 clone 置位）；非不同包体类别 / 非双模式设备 THEN 零回归（不触发该校验）
- **AC-35:** WHEN 双模式设备副模式安装不同包体类别应用 THEN 在当前模式校验（AC-8）之后追加跨模式校验：查询另一模式变体记录；WHEN 另一模式已存在该应用且类别不一致（涉及不同包体类别↔非不同包体类别互转）THEN 返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT`（**8519943**，对外映射 `ERR_INSTALL_BUNDLE_TYPE_NOT_SAME`）；WHEN 两模式均不同包体类别 或 另一模式不存在该应用 THEN 放行继续安装。补 AC-8（当前模式侧）的跨模式维度；非双模式设备守卫早退、零回归

### US-9: 应用沙箱策略数据模型

**作为** 系统,
**需要** 在 BundleInfo 中持久化应用沙箱策略（共享/隔离）,
**以便** 后续双模式隔离逻辑统一读取该字段（本次仅数据模型 + 完整序列化，业务消费留后续 Sync）。

**验收标准：**

- **AC-36:** WHEN BundleInfo 经 Parcel 或 JSON（key `appSandboxPolicy`）序列化往返 THEN `appSandboxPolicy` 保持原值（`SHARED_SANDBOX`/`ISOLATED_SANDBOX` 均保真）；字段随基础信息节点持久化，AC-1 持久化不破坏
- **AC-37:** WHEN 反序列化不含 `appSandboxPolicy` 字段的存量 BundleInfo JSON THEN `appSandboxPolicy` 默认为 `SHARED_SANDBOX`（值 0，字段类内默认值 + 缺 key 回退，与 AC-18 同理）

### US-10: appIndex 单一数据源

**作为** 系统,
**需要** 副模式不同包体类别（clone）应用的 appIndex 在安装时一次置位为 10000,
**以便** hap token instIndex 等所有消费方直接读 10000，消除「info=0 / token=10000」分裂，与目录/DB key 的 `+clone-10000+` 前缀及 ADR-6 前提统一。

**验收标准：**

- **AC-38:** WHEN 双模式设备副模式安装不同包体类别应用（clone 应用）THEN appIndex 一次置位为 **10000**（单一数据源，随应用信息持久化），hap token 的 instIndex 直接读取该值得 10000（不再运行时覆写，AC-19 结果等价，见 design ADR-28）；WHEN 非副模式 / 非不同包体类别 / 非双模式设备 THEN appIndex 保持默认（0），零回归

### US-11: 广播沙箱策略与更新前值

**作为** 系统（供需求二上层消费）,
**需要** 安装/更新广播携带应用沙箱策略（当前 + 更新前），且隔离一旦生效即"粘性"保持,
**以便** 上层一次广播即可判断沙箱/策略变更，且隔离不被更新翻覆。

**验收标准：**

- **AC-39:** WHEN 双模式设备计算当前 `appSandboxPolicy`（写入应用信息与填广播同源）THEN 若 `beforeAppSandboxPolicy==ISOLATED_SANDBOX`（存量已隔离）当前恒为 `ISOLATED_SANDBOX`（**粘性**，与新 policy 无关）；否则（共沙箱或首装默认 SHARED）当前 = 新策略为不同包体类别 ? `ISOLATED_SANDBOX` : `SHARED_SANDBOX`。WHEN 存量隔离应用更新为非不同包体类别 THEN 当前仍 ISOLATED（粘性保持）
- **AC-40:** WHEN 更新（存量应用已存在）THEN `beforeDeviceModeDistributionPolicy`/`beforeAppSandboxPolicy` 从旧应用信息捕获（随应用信息持久化，供下次更新读取，粘性闭环，AC-39）；WHEN 首次安装（无存量）THEN before 两字段为默认（UNSPECIFIED/SHARED_SANDBOX）；WHEN 非双模式设备 THEN 5 字段全默认、零回归；安装器实例复用时 before 状态重置防泄漏

### US-12: TS 接口透传设备模式分发策略

**作为** 上层分发调用方（经 TS installer 接口）,
**需要** 在调用 TS 安装接口时经 installParam.parameters 通用通道传入设备模式分发策略,
**以便** 分发平台在安装时刻指定策略，走既有 IPC 字段链路（AC-1）持久化，无需新增独立 TS 参数字段。

**验收标准：**

- **AC-41:** WHEN TS 侧调用 `install` 接口且 installParam.parameters 携带保留 key `ohos.bms.param.deviceModeDistributionPolicy`（value 为枚举值的十进制字符串，如 "4"） THEN 适配层解析后将 `InstallParam.deviceModeDistributionPolicy` 刷新为对应枚举值（int 0~8），经既有 IPC 字段传至服务端，衔接 AC-1 持久化链路（NAPI 与 ANI 两个 `install` 入口均在参数校验之后接入刷新）；WHEN parameters 不含该 key THEN 字段保持默认 UNSPECIFIED（0），现有调用方零回归；WHEN key 存在但 value 非法（非十进制整数/空串/超出 0~8 值域）THEN 忽略该 key 仅打印 warning 日志、字段不被污染（保持刷新前值即默认 UNSPECIFIED），不拦截安装、不返回异常（2026-08-17 需求方裁定：非法值不报 401，静默降级走默认策略）。NAPI/ANI `updateBundleForSelf` 均不适配（2026-08-18 需求方裁定：保留 key 透传范围即 install 入口，非功能覆盖缺口）；保留 key 为内部分发平台契约，不出对外资料
- **AC-48:** WHEN 原生/IPC 调用方不经 TS 适配层、直接携带越界 [0,8] 的 `deviceModeDistributionPolicy` int32 THEN 服务端 Parcel 读取侧值域白名单校验失败，打印 warning 后降级为 UNSPECIFIED（与 AC-41 非法 value 静默降级同口径），不阻断安装请求，越界值不可达广播事件字段（codecheck R1 加固）
- **AC-49:** WHEN TS 侧 parameters 携带重复的保留 key THEN NAPI/ANI 解析统一 **first-wins**：打印 warning 并保留首个、忽略后续（消除原 NAPI 吞错中断 / ANI last-wins 跨栈分歧），安装流程不受影响，单次 key 行为零回归（codecheck R1 加固）

### US-13: 模式独占策略安装准入

**作为** 系统,
**需要** 在安装时校验模式独占策略（MAIN_ONLY/SUB_ONLY）与当前设备模式匹配,
**以便** 单模式应用不在其不可见的模式下被安装（如仅主模式应用在副模式下安装）。

**验收标准：**

- **AC-42:** WHEN 双模式设备安装 `MAIN_ONLY(1)` 策略应用且当前为副模式，或安装 `SUB_ONLY(2)` 策略应用且当前为主模式 THEN 安装失败，返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_POLICY_NOT_SUPPORTED`（**8519947**，对外映射 `ERR_INSTALL_PARSE_FAILED`，见错误码表），校验先于策略写入，失败时应用信息无任何突变（不置 policy / 不置 clone 标志）；WHEN MAIN_ONLY×主模式 或 SUB_ONLY×副模式 THEN 校验通过、正常安装（单模式应用以**原名**为 key，无 clone 前缀、不置 clone 标志）。非双模式设备不触发该校验，零回归。此外策略写入入口对 effectivePolicy 做值域硬校验 [0,8]，越界返回 `ERR_APPEXECFWK_INSTALL_PARAM_ERROR`（**8519686**，既有码，见错误码表注；IPC 侧白名单 AC-48 已先行降级，此处为非 IPC 进程内调用的纵深防御，正常流不可达）

### US-14: 预置双模式分发安装（ERMS 两趟 fan-out）

**作为** 系统,
**需要** 预置目录同时含两模式 hap 的不同包体类别应用在一次预置安装中完成主/副两个模式变体的安装,
**以便** 双模式设备首次开机即在两个模式下都有该应用的正确包体。

**验收标准：**

- **AC-43:** WHEN 双模式设备预置安装（预置目录输入、非显式 hap 文件路径）THEN 经 ERMS 查询分发策略与按 deviceType 分组的 hap 清单；WHEN 策略为不同包体类别且主模式 hap 集可识别 THEN 本趟（主趟）仅安装主模式 hap 子集（从已验签清单中筛选，**免二次验签**），随后以 clone 前缀名发起副趟安装副模式 hap 集（clone 命名不依赖当前设备模式）；策略与副模式 hap 清单随趟内缓存传递，副趟不重复查询 ERMS
- **AC-50:** WHEN ERMS 查询失败 / 策略非不同包体类别 / 主模式 hap 集不可识别 THEN 退化整目录单包安装，不失败不阻断，行为与非双模式预置一致（EX-8）
- **AC-51:** WHEN 两趟安装中仅单侧失败 THEN 不回滚另一侧（已装变体保留）；WHEN 双侧均失败 THEN 整体安装失败
- **AC-52:** WHEN user-100 恢复安装 THEN 携带预置时存储的策略与 clone 标志按对应命名路径（clone 标志 → clone 命名）恢复安装，不重查 ERMS
- **AC-44:** WHEN 安装"包所属模式 ≠ 当前设备模式"的变体（fan-out 副趟变体，或 MAIN_ONLY/SUB_ONLY 单模式应用目标模式≠当前模式）THEN 该变体以**原始 bundleName** 为 key 存入不可查询列表，当前模式查询不可见，切换模式后经需求二迁移翻转可见；WHEN 包所属模式 == 当前模式 THEN 存可查询列表正常可见；非双模式设备恒走可查询列表（守卫防 clone 残留 key 误入）。主模式安装的不同包体类别应用（主趟）即使在副模式设备上预置，也保持**原名**安装不入 clone 路径（clone 命名仅由副趟或"副模式+不同包体类别"触发）

### US-15: 安装/更新/卸载与模式切换互斥

**作为** 系统,
**需要** 安装/更新/卸载类操作与设备模式切换（需求二）互斥执行,
**以便** 切换迁移内存双 map 期间不被安装类任务并发修改，安装期间切换不被打断。

**验收标准：**

- **AC-45:** WHEN 双模式设备上一次模式切换进行中 THEN 安装/更新/卸载类任务**不排队、不等待、快速失败**，返回 `ERR_APPEXECFWK_DUAL_MODE_SWITCH_BUSY`（**8519944**，需求二定义、安装侧消费；安装接口经 statusReceiver 回调同步通知）。三类接入面行为一致：① 任务创建入队前探测——切换中则任务不创建不入队、直接回调通知；② 任务执行期再探测——仍切换中则丢弃任务体并回调通知；③ 同步直连入口（不经队列，共 10 个）——构造时探测、同步直返。WHEN 非双模式设备 THEN 全部守卫跳过（不触锁，任务原样入队，路径与无互斥时逐字节一致）；WHEN 数据管理不可用 THEN 降级为不加锁执行（互斥永不阻塞安装路径本身）
- **AC-53:** WHEN 安装/更新/卸载任务持共享锁运行中 THEN 并发模式切换以尝试取排他锁失败、同样快速失败 8519944（对称面；切换侧完整语义与锁序见需求二「模式切换接口」spec/design 及本文架构约束表）

### US-16: 查询结果回显 clone 应用 appIndex

**作为** 上层查询调用方（launcher/分发平台等，需区分同包名双模式变体）,
**需要** 双模式 clone 应用（副模式不同包体类别）在各查询接口的结果 payload 中回显 appIndex=10000,
**以便** 以 appIndex 维度区分同包名的主/副模式变体，无需感知 `+clone-10000+` 前缀与内部存储 key 细节。

**验收标准：**

- **AC-46:** WHEN 双模式设备查询命中不同包体类别 clone 应用（两模式分类后均以**原始名**为查询 key，查询入口零改动）THEN 组装结果 payload 时该应用的 appIndex 恒为 **10000**，统一覆盖所有结果组装路径：BundleInfo/AbilityInfo 组装与 extension 查询、shortcut 可见性、按名取包名+索引、动态图标模块、扩展资源参数校验（appIndex=10000 且 clone 应用时放行）；WHEN 主模式应用或非 clone 应用 THEN appIndex 回显请求值/默认（0），行为零回归

### US-17: `DeviceModeDistributionPolicy` 枚举 NAPI 运行时注册

**作为** TS 应用开发者/上层分发调用方,
**需要** `bundleManager.DeviceModeDistributionPolicy` 枚举对象在 JS 运行时可访问（9 个命名值）,
**以便** 在安装参数与查询结果处理中使用命名枚举值而非裸数字字面量。

**验收标准：**

- **AC-47:** WHEN JS 侧访问 `bundleManager.DeviceModeDistributionPolicy` THEN 得到含 9 个命名值的枚举对象（UNSPECIFIED=0 ~ FULL_COMPATIBLE_DIFFERENT_PACKAGE=8），挂到 bundleManager 导出对象（对齐既有枚举导出模式）；WHEN 经 AC-41 保留 key 透传策略 THEN 命名值与裸数字字面量等价，value 仍为枚举值十进制字符串；WHEN 不涉及该枚举的既有调用方 THEN NAPI 导出对象仅新增一个属性，零回归。见 design ADR-36

## 验收追溯

> 全 AC（AC-1~54）代码已落地（分支 `fix_dual_doc`，HEAD `bcbfe06a9`）、待集成环境编译/单测/运行时全量回归；AC-42~45 为 2026-08-29 文档同步补录（模式独占拦截 8519947、预置 ERMS 两趟 fan-out、跨模式变体存储、切换互斥 8519944）；AC-46/47 为 2026-08-31 文档同步补录（查询结果回显 clone appIndex、NAPI 枚举运行时注册），均代码先于文档落库、单测随代码入库（安装专项套件 install 164 + query 95 = 259 例）。AC-48~54 为 2026-09-04 规则检视拆分项——自 AC-41/43/45/17 按单一可验证行为拆出（行为语义零变化），同时实现锚点自 AC 行文迁至本表证据列。AC-41 为 TS 接口透传增量（NAPI/ANI `install` 共 2 处接入；NAPI/ANI `updateBundleForSelf` 均不适配——2026-08-18 需求方裁定，透传范围即 install 入口，非缺口）。运行时集成回归 + 人类 Owner 发布批准为发布 Gate 未决项（见 [gates/release.md](./gates/release.md)）。

| AC | 关联规则 | 关联 Task | 验证方式 | 证据 |
|----|----------|-----------|----------|------|
| AC-1 | FR-1 | TASK-1 | 单测（序列化往返） | ✅ 编译通过；锚点：`install_param.h` / `application_info.h` / `to_json` 静态一致 |
| AC-2 | FR-1 | TASK-1 | 单测（默认值） | ✅ 编译通过；锚点：`UNSPECIFIED=0` |
| AC-18 | EX-1 | TASK-1 | 单测（缺字段反序列化） | ✅ 编译通过；锚点：`from_json` 缺字段保留默认值 |
| AC-3 | EX-2 | TASK-2/3 | 单测+集成（参数缺失/非法回退） | ✅ 编译通过；锚点：`ReadValidIspcmodeParam` 双路径（生产 bool/测试 int，`dual_mode_helper`）；运行时集成回归待集成环境 |
| AC-4 | FR-2 | TASK-3/4 | 集成（副模式目录检查） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-5 | FR-2 | TASK-3 | 集成（主模式目录检查） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-6 | FR-2 | TASK-3 | 集成（非不同包体类别不处理） | ✅ 已集成验证 PASS（2026-07-18） |
| AC-7 | FR-3 | TASK-3 | 集成（同类更新） | ✅ 已集成验证 PASS（2026-07-18） |
| AC-8 | EX-3 | TASK-3 | 集成（不同包体类别互转失败 8519943） | ✅ 编译通过；锚点：`CheckDualModeCategoryConsistency`（base_bundle_installer.cpp:6143-6157）；运行时集成回归待集成环境 |
| AC-9 | FR-3 | TASK-3 | 集成（非不同包体类别互转更新） | ✅ 已集成验证 PASS（2026-07-18） |
| AC-10 | FR-4 | TASK-3 | 集成（轮转目录检查） | ✅ 已集成验证 PASS（2026-07-18） |
| AC-11 | FR-5 | TASK-4/5 | 集成（查询验证） | ✅ 已集成验证 PASS（2026-07-18） |
| AC-12 | RC-1 | TASK-5 | 集成（重启加载，参数缺失/非法） | ✅ 编译通过；锚点：`ClassifyDualModeAppsNoLock` 早退（bundle_data_mgr.cpp）；运行时集成回归待集成环境 |
| AC-13 | FR-6 | TASK-5 | 集成（分类加载） | ✅ 编译通过；锚点：`IsDualModeCloneKey(dbKey)` 前缀判定；运行时集成回归待集成环境 |
| AC-14 | FR-6 | TASK-5 | 集成（副模式加载+边界） | ✅ 编译通过；锚点：`ClassifyDualModeAppsNoLock` 兜底段（bundle_data_mgr.cpp:505-511）；运行时集成回归待集成环境 |
| AC-15 | FR-6 | TASK-5 | 集成（主模式加载） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-16 | FR-7 | TASK-5 | 集成（跨模式odid一致） | ✅ 编译通过；锚点：`GenerateOdidNoLock` 双 map 遍历；单测 GenerateOdid_ReuseFromTempBundleInfos_×4；运行时集成回归待集成环境 |
| AC-17 | FR-8 | TASK-6 | 集成（事件 5 字段：currentMode int / appSandboxPolicy / before×2） | ✅ 编译通过；锚点：`FillDualModeEventFields`（base_bundle_installer.cpp:5843-5859）；运行时集成回归待集成环境；**对外契约变更**（isSharedSandbox→appSandboxPolicy + before key），须同步需求二 |
| AC-54 | FR-8 | TASK-6 | 单测+集成（卸载事件 3 字段、无 before） | ⏳ 代码已落地；锚点：`FillDualModeUninstallEventFields`（:5954-5961）；待集成环境编译/单测/运行时回归 |
| AC-19 | FR-9 | TASK-3 | 集成（副模式 hap token 隔离） | ✅ 编译通过；锚点：`CreateHapInfoParams` 直接传播 `GetAppIndex()`；appIndex 安装时置位、instIndex=10000，待集成环境重验 |
| AC-20 | FR-10 | TASK-3/5 | 集成（副模式独立 uid + 重启一致） | ✅ 已集成验证 PASS（2026-07-18） |
| AC-21 | FR-11 | TASK-3 | 集成（异常恢复按原名查询） | ✅ 已集成验证 PASS（2026-07-18）；锚点：`InnerProcessNewToRealPath` |
| AC-22 | FR-2 | TASK-3 | 集成（副模式 skills 目录隔离） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-23 | FR-2 | TASK-3 | 集成（副模式 skills description 数据层隔离） | ✅ 编译通过；锚点：`SkillsDescriptionRdb`；运行时集成回归待集成环境 |
| AC-24 | FR-2 | TASK-3 | 集成（副模式 AppProvisionInfo 插入/删除 effective name 隔离） | ✅ 编译通过；锚点：`AddAppProvisionInfo`/`SetSpecifiedDistributionType`/`SetAdditionalInfo`/`DeleteAppProvisionInfo`；运行时集成回归待集成环境 |
| AC-25 | FR-2 | TASK-3 | 集成（副模式 getAppProvisionInfo 经 clone 判定查到） | ✅ 编译通过；锚点：`BundleDataMgr::GetAppProvisionInfo`（bundle_data_mgr.cpp:10719）`find(原名)` + `IsDualModeCloneApp()`；运行时集成回归待集成环境 |
| AC-26 | FR-2 | TASK-3 | 集成（副模式 Router 插入/删除/更新 effective name 隔离） | ✅ 编译通过；锚点：`InsertRouterInfo`/`UpdateRouterInfo`/`DeleteRouterInfo`（`routerStorage_` key）；运行时集成回归待集成环境；查询遗留 |
| AC-27 | FR-2 | TASK-3 | 集成（clone app installStates_ effective name 状态机对齐） | ✅ 编译通过；锚点：`UpdateBundleInstallState` stateKey=传入名、`GetEffectiveBundleName()`、`installStates_` 前缀 key、`DeleteBundleInfo` 按 `IsDualModeCloneKey` 解析；单测 UpdateBundleInstallState×5；运行时集成回归待集成环境 |
| AC-28 | FR-2 | TASK-3 | 集成（非双模式/非 clone installStates_ 回归零影响） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-29 | FR-12 | TASK-3 | 集成（副模式 resource 写入/更新/重启重建 effective name 隔离） | ✅ 编译通过；锚点：`BundleResourceRdb` + `AddResourceInfos`/`DeleteNotExistResourceInfo`；`BundleResourceIconRdb` 保留原名；parser `resourceManagerMap`；运行时集成回归待集成环境；卸载删除/查询/OTA 遗留 |
| AC-30 | FR-12 | TASK-3 | 集成（非双模式/非 clone resource 三表回归零影响） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-31 | FR-13 | TASK-3 | 集成（语言/主题切换两模式 label 均刷新） | ✅ 编译通过；锚点：`GetAllResourceInfo` 双 map（`bundleInfos_`+`tempBundleInfos_`）；运行时集成回归待集成环境；OTA 遗留 |
| AC-32 | FR-2 | TASK-3 | 集成（4 独立调用方 BundleType 互斥零回归） | ✅ 编译通过；锚点：AppServiceFwkInstaller/IndependentSkillsInstaller/InnerSharedBundleInstaller/BMSEventHandler；`SaveInstallInfoToCache` 已知遗留（正常走 `LoadInstallInfosFromDb`）；运行时集成回归待集成环境 |
| AC-33 | EX-2 | TASK-2/3 | 单测+集成（参数非法值∉{0,1}回退） | ✅ 编译通过；运行时集成回归待集成环境 |
| AC-34 | EX-4 | TASK-3 | 单测+集成（非系统应用 不同包体类别 主/副模式安装失败 8519942） | ✅ 编译通过；锚点：`SetDualModeAppInfo`（base_bundle_installer.cpp:5963-6015）、appexecfwk_errors.h:214、status_receiver_proxy.cpp:724-725；单测 SetDualModeAppInfo_0500/0600/0700/0800；运行时集成回归待集成环境 |
| AC-35 | EX-3 | TASK-3 | 单测+集成（跨 map 类别不一致拦截 8519943） | ✅ 编译通过；锚点：`CheckDualModeCategoryConsistencyInTemp`（:6159-6181，`InnerProcessBundleInstall` :1106 调用）经 `FetchTempBundleInfo` 查 `tempBundleInfos_`；单测 CheckDualModeCategoryConsistencyInTemp_×5；运行时集成回归待集成环境 |
| AC-36 | FR-23 | TASK-1 | 单测（AppSandboxPolicy Parcel+JSON 序列化往返保真） | ⏳ 代码已落地；锚点：bundle_info.cpp `Marshalling`/`ReadFromParcel` + `to_json`/`from_json`（key `BUNDLE_INFO_APP_SANDBOX_POLICY`）、inner_bundle_info.cpp:636（`baseBundleInfo_`/`BASE_BUNDLE_INFO` 节点）；待集成环境编译/单测 |
| AC-37 | EX-5 | TASK-1 | 单测（缺字段默认 SHARED_SANDBOX） | ⏳ 代码已落地，待集成环境编译/单测 |
| AC-38 | FR-24 | TASK-3 | 单测+集成（副模式不同包体 appIndex=10000、instIndex 直接传播） | ⏳ 代码已落地；锚点：`SetDualModeAppInfo` 置位（`DUAL_MODE_CLONE_APP_INDEX`）、`CreateHapInfoParams` 传播；单测 SetDualModeAppInfo_0300（`GetAppIndex()==10000`）、CreateHapInfoParams_0100（`instIndex==10000`）；待集成环境编译/单测/运行时回归 |
| AC-39 | FR-8 | TASK-6 | 单测+集成（粘性隔离：隔离后更新仍隔离） | ⏳ 代码已落地；锚点：`ComputeCurrentAppSandboxPolicy`（`SetDualModeAppInfo` 写入与 `FillDualModeEventFields` 填广播同源）；单测 FillDualModeEventFields_0100/0300；待集成环境编译/单测/运行时回归 |
| AC-40 | FR-8 | TASK-6 | 单测+集成（before 值更新捕获/首装默认/非双模式零回归） | ⏳ 代码已落地；锚点：before 捕获 base_bundle_installer.cpp:1872-1880、`ResetInstallProperties` :7640-7641、`InnerBundleInfo.SetAppSandboxPolicy` 持久化；单测 FillDualModeEventFields_0100/0200；待集成环境编译/单测/运行时回归 |
| AC-41 | FR-16 | TASK-7 | 单测（parameters key 刷新枚举/缺 key 零回归/非法 value 静默降级） | ⏳ 代码已落地；锚点：`InstallParam::RefreshDeviceModeDistributionPolicy`（install_param.cpp，对齐 `IsVerifyUninstallRule` 提取模式）、接入点 NAPI `Install` installer.cpp:891 + ANI `AniInstall` ani_bundle_installer.cpp:225、key 常量 `Constants::DEVICE_MODE_DISTRIBUTION_POLICY_KEY`（bundle_constants.h）；待集成环境编译/单测/运行时回归 |
| AC-48 | FR-16 | TASK-7 | 单测（服务端 Parcel 越界值降级 UNSPECIFIED） | ⏳ 代码已落地；锚点：`InstallParam::ReadFromParcel` 值域白名单 [0,8]（codecheck R1 加固 F-P2-01）；待集成环境编译/单测/运行时回归 |
| AC-49 | FR-16 | TASK-7 | 单测（重复 key first-wins 告警+保留首个） | ⏳ 代码已落地；锚点：NAPI `ParseParameters` 与 ANI `ParseInstallParam`（common_fun_ani.cpp）重复 key first-wins（codecheck R1 加固 F-P2-02）；待集成环境编译/单测/运行时回归 |
| AC-42 | FR-17 | TASK-3 | 单测+集成（模式独占拦截 8519947 / 匹配模式放行） | ⏳ 代码已落地；锚点：`SetDualModeAppInfo` :5978-5984（先于策略写入循环）+ 值域硬校验 :5970-5976、appexecfwk_errors.h:219、status_receiver_proxy.cpp:726-727；单测 SetDualModeAppInfo_1000/1100/1200；待集成环境编译/单测/运行时回归 |
| AC-43 | FR-18 | TASK-3 | 单测+集成（ERMS 解析/主趟筛选/副趟 fan-out/趟内缓存） | ⏳ 代码已落地；锚点：`ResolveDualModePolicy`（base_bundle_installer.cpp:6017-6141，dlopen `liberms_sdk.z.so`/`GetDeviceModelDistributionPolicy`）、`SystemBundleInstaller::InstallSystemBundle`（system_bundle_installer.cpp:53-88，`forceDualModeCloneInstall=true`）、`DualModeErmsCache`；待集成环境编译/单测/运行时回归 |
| AC-50 | FR-18/EX-8 | TASK-3 | 单测+集成（ERMS 不可用退化整目录单包、不失败不阻断） | ⏳ 代码已落地；锚点：`ResolveDualModePolicy` 退化分支（role=NONE）；待集成环境编译/单测/运行时回归 |
| AC-51 | FR-18 | TASK-3 | 单测+集成（单侧失败不回滚/双失败才整体失败） | ⏳ 代码已落地；锚点：两趟独立结果处理（`SystemBundleInstaller` fan-out）；待集成环境编译/单测/运行时回归 |
| AC-52 | FR-18 | TASK-3 | 单测+集成（user-100 恢复带存储策略不重查 ERMS） | ⏳ 代码已落地；锚点：`RecoverPreInstallBundleInfo`（:3058-3065，IsDualModeCloneApp→forceDualModeCloneInstall）；待集成环境编译/单测/运行时回归 |
| AC-44 | FR-19 | TASK-3 | 单测+集成（跨模式变体入不可查询列表、主趟原名/副趟 clone 名） | ⏳ 代码已落地；锚点：`IsCrossModeInstall`（:5902-5924，`dualModeInstallRole_` 判定）、`AddInnerBundleInfo`/`UpdateInnerBundleInfo` `toTempBundle` 参数（:9523 调用点）、守卫 :6864-6867、`ShouldUseDualModeCloneName` :5884-5900（`tempBundleInfos_` 原名 key）；待集成环境编译/单测/运行时回归 |
| AC-45 | FR-20 | TASK-3 | 单测+集成（切换中任务入队拒绝/执行期丢弃/直连入口 8519944；非双模式零回归） | ⏳ 代码已落地；锚点：`RejectTaskIfSwitchInFlight`（bundle_installer_manager.cpp:336-352）、`AddTask` wrapper（:388-411，`g_taskCounter--` 配平）、`DualModeSwitchGuard`（bundle_installer_host.cpp:804/840/878/909/1187/1262/1324/1362/1757/1794 共 10 入口：InstallSandboxApp/UninstallSandboxApp/InstallPlugin/UninstallPlugin/InstallCloneApp/UninstallCloneApp/InstallExisted/UninstallNewPreinstalledApps/CreateCliSandboxApp/DestroyCliSandboxApp）、`TryLockForBundleOperation`（bundle_data_mgr.cpp:718-726，try_lock_shared）；单测 bms_bundle_installer_manager_test / bms_dual_mode_switch_test；待集成环境编译/单测/运行时回归 |
| AC-53 | FR-20 | TASK-3 | 单测（安装持锁运行时切换 try 排他失败对称面） | ⏳ 代码已落地；锚点：`TryLockForBundleOperation` 共享侧 / 切换 `try_to_lock` 排他侧（锁序 `dualModeSwitchMutex_` → `bundleInfoMutex_` → `stateMutex_`）；单测 bms_dual_mode_switch_test；待集成环境编译/单测/运行时回归 |
| AC-46 | FR-21 | TASK-3 | 单测+集成（clone 查询结果 appIndex=10000 回显；主模式/非 clone 零回归） | ⏳ 代码已落地；锚点：`InnerBundleInfo::ResolveDualModeResponseAppIndex`（inner_bundle_info.h:1759，clone 恒返 10000/非 clone 回显请求值）统一覆盖 BundleInfo/AbilityInfo/extension 组装、shortcut 可见性、`GetBundleNameAndIndexByName`（bundle_data_mgr.cpp:3233）、`GetCurDynamicIconModule`（:15332）、`CheckParamInvalid`（extend_resource_manager_host_impl.cpp:811-814）；单测 bms_dual_mode_query_test（查询专项 95 例）；待集成环境编译/单测/运行时回归 |
| AC-47 | FR-22 | TASK-7 | 集成/XTS（JS 侧 `bundleManager.DeviceModeDistributionPolicy` 9 命名值可访问） | ⏳ 代码已落地；锚点：`CreateDeviceModeDistributionPolicyObject`（bundle_manager.cpp:6229-6288，对齐 `CreateBundleFlagObject` 模式）+ `native_module.cpp:106-108` 经 `DECLARE_NAPI_PROPERTY` 挂载；待集成环境编译/运行时验证 |

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
| FR-8 | 安装/更新/卸载事件携带双模式字段：deviceModeDistributionPolicy、currentMode（int）、appSandboxPolicy（当前，粘性规则）及更新前 before 双值（首装默认；卸载事件仅前 3 字段、无 before 值） | 双模式设备 安装/更新/卸载事件 | 事件 Want 字段 | AC-17/AC-39/AC-40/AC-54 |
| FR-9 | 副模式不同包体类别应用通过 instIndex=10000 获得独立 HAP token | 副模式 + 不同包体类别 + clone 应用 | 权限 token | AC-19 |
| FR-10 | 副模式不同包体类别应用数据/asan 目录归属独立 uid（带前缀名派生 bundleId），跨重启稳定 | 副模式 + 不同包体类别 | uid | AC-20 |
| FR-11 | 安装异常恢复接收带前缀名时解析回原名查询 | 异常恢复 + 带前缀名 | exception 查询 | AC-21 |
| FR-12 | 副模式不同包体类别应用资源缓存隔离：`BundleResourceRdb` 写入/更新/重启重建以带 `+clone-10000+` 前缀 effective name 作 key（写入 key 带前缀，硬约束）；`BundleResourceIconRdb` 保留原始 bundleName（按设计不隔离）；`UninstallBundleResourceRdb` + 卸载删除路径未适配（用原名，遗留其他需求） | 副模式 + 不同包体类别 + 写入/更新/重启重建 | BundleResourceManager | AC-29/30 |
| FR-13 | 语言/主题切换时刷新双模式（`bundleInfos_` + `tempBundleInfos_`）同名应用的名称资源，两模式各自 key 不交叉污染 | 语言/主题切换 + 双模式 | BundleResourceManager 刷新路径（GetAllResourceInfo） | AC-31 |
| FR-14 | 双模式设备不同包体类别（**不分主副模式**）仅限系统应用，非系统应用安装失败返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP`；clone 标志仅副模式置位 | 双模式 + 不同包体类别 + 安装准入 | SetDualModeAppInfo（IsDiffPackageCategory 时校验 IsSystemApp） | AC-34 |
| FR-15 | 副模式安装时跨 map（`tempBundleInfos_`）校验类别一致性，不同包体类别 互转拦截返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT` | 双模式 + 不同包体类别 + 跨模式 | CheckDualModeCategoryConsistencyInTemp | AC-35 |
| FR-16 | TS 安装接口经 installParam.parameters 保留 key `ohos.bms.param.deviceModeDistributionPolicy`（value 为枚举值十进制字符串）透传设备模式分发策略，适配层解析刷新 `InstallParam.deviceModeDistributionPolicy` 字段后走既有 IPC 链路；NAPI/ANI `updateBundleForSelf` 均不适配（2026-08-18 裁定，保留 key 透传范围即 install 入口，该两入口走默认非缺口）；服务端 ReadFromParcel 值域白名单 [0,8] 越界降级 UNSPECIFIED；NAPI/ANI parameters 重复 key 统一 first-wins（codecheck R1 加固）；保留 key 为内部分发平台契约，不出对外资料（2026-08-18 裁定） | NAPI `install`（installer.cpp:891）+ ANI `install`（ani_bundle_installer.cpp:225）+ parameters 携带保留 key | InstallParam::RefreshDeviceModeDistributionPolicy（接入点 2 处，参数校验之后调用）+ ReadFromParcel 值域白名单 + 双栈重复 key first-wins | AC-41/AC-48/AC-49 |
| FR-17 | 模式独占策略安装准入：MAIN_ONLY 仅可在主模式安装、SUB_ONLY 仅可在副模式安装，违反返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_POLICY_NOT_SUPPORTED`（8519947），校验先于策略写入、失败无状态突变；SetDualModeAppInfo 另对 effectivePolicy 做值域硬校验 [0,8]（越界 `ERR_APPEXECFWK_INSTALL_PARAM_ERROR`=8519686 既有码，非 IPC 调用纵深防御） | 双模式 + 安装 + policy ∈ {MAIN_ONLY, SUB_ONLY} | SetDualModeAppInfo（base_bundle_installer.cpp:5963-6015） | AC-42 |
| FR-18 | 预置双模式分发安装：预置目录输入时经 ERMS 查询分发策略与按 deviceType 分组 hap 清单，不同包体类别拆主趟（原名，免二次验签）+ 副趟（clone 前缀名，forceDualModeCloneInstall）两趟安装，趟内缓存传递副趟不重查 ERMS；单侧失败不回滚、双失败才整体失败；ERMS 失败/非不同包体/主集不可识别退化整目录单包安装；user-100 恢复携带存储策略不重查 ERMS | 双模式 + isPreInstallApp + 预置目录输入 | ResolveDualModePolicy（:6017-6141）+ DualModeErmsCache + SystemBundleInstaller::InstallSystemBundle（system_bundle_installer.cpp:53-88）+ RecoverPreInstallBundleInfo（:3058-3065） | AC-43/AC-50/AC-51/AC-52 |
| FR-19 | 跨模式变体存储：包所属模式≠当前设备模式的变体（fan-out role 或 MAIN_ONLY/SUB_ONLY 目标模式判定）以原始 bundleName 为 key 存 `tempBundleInfos_`（当前模式不可见），包所属模式==当前模式存 `bundleInfos_`；clone 命名仅由 role=SECONDARY 或"副模式+不同包体类别"触发，主趟 role=PRIMARY 恒原名 | 双模式 + 跨模式变体安装 | IsCrossModeInstall（:5902-5924）+ Add/UpdateInnerBundleInfo toTempBundle 参数 | AC-44 |
| FR-20 | 安装/更新/卸载与模式切换互斥：任务入队前探测 + 执行期 try + 10 直连入口 guard 三层接入，切换进行中任务不排队快速失败 `ERR_APPEXECFWK_DUAL_MODE_SWITCH_BUSY`（8519944，与需求二共用错误码）；安装任务持锁运行中并发切换同样快速失败（对称面）；非双模式设备/ dataMgr 不可用跳过守卫，互斥永不阻塞安装路径；锁序 dualModeSwitchMutex_ → bundleInfoMutex_ → stateMutex_ | 双模式 + 切换进行中 + 安装/更新/卸载任务 | TryLockForBundleOperation（bundle_data_mgr.cpp:718-726）+ RejectTaskIfSwitchInFlight / AddTask wrapper（bundle_installer_manager.cpp:336-352/388-411）+ DualModeSwitchGuard（bundle_installer_host.cpp 10 入口） | AC-45/AC-53 |
| FR-21 | 查询结果回显：双模式 clone 应用查询结果 payload 中 appIndex 恒回显 10000（`DUAL_MODE_CLONE_APP_INDEX`）；查询 key 零改动（分类后两 map 均原始名 key），仅结果 payload 回显 clone 标识维度，非 clone 回显请求值 | 双模式 + clone 应用 + 查询结果组装 | InnerBundleInfo::ResolveDualModeResponseAppIndex（inner_bundle_info.h:1759，覆盖 BundleInfo/AbilityInfo/extension 组装、shortcut 可见性、GetBundleNameAndIndexByName :3233、GetCurDynamicIconModule :15332、CheckParamInvalid extend_resource_manager_host_impl.cpp:811-814） | AC-46 |
| FR-22 | DeviceModeDistributionPolicy 枚举 NAPI 运行时注册：JS 侧 `bundleManager.DeviceModeDistributionPolicy` 提供 9 个命名值（0~8），d.ts 契约运行时可用 | NAPI 模块初始化（bundleManagerExport） | CreateDeviceModeDistributionPolicyObject（bundle_manager.cpp:6229-6288）+ DECLARE_NAPI_PROPERTY 挂载（native_module.cpp:106-108） | AC-47 |
| FR-23 | AppSandboxPolicy 数据模型完整：字段随 BundleInfo 经 Parcel（Int32）与 JSON（NUMBER，key appSandboxPolicy）序列化往返保真，存量数据缺字段默认 SHARED_SANDBOX 兜底 | BundleInfo 序列化/反序列化（含存量缺字段） | BundleInfo.appSandboxPolicy | AC-36/AC-37 |
| FR-24 | clone 应用 appIndex 单一数据源：副模式安装不同包体类别时一次置位 DUAL_MODE_CLONE_APP_INDEX(10000) 并随 InnerBundleInfo 持久化，消费方（hap token instIndex 等）直接读取；非 clone 保持默认 0 | 副模式 + 不同包体类别安装 | InnerBundleInfo.appIndex 及其消费方 | AC-38 |

## 异常/豁免规则

| 编号 | 异常码/枚举 | 规则描述 | 触发条件 | 超时阈值 | 处理结果 | 关联 AC |
|------|------------|----------|----------|----------|----------|---------|
| EX-1 | 默认值兜底 | 存量应用无 deviceModeDistributionPolicy 字段 | 反序列化缺失字段 | N/A | 默认"不区分设备模式分发策略" | AC-18 |
| EX-2 | 模式回退 | 系统模式参数缺失/非法 | ispcmode（生产 bool key）缺失，或 mainmode（int）读取失败(返回 -1)/非法(∉{0,1}) | N/A | 回退正常安装流程 | AC-3/AC-33 |
| EX-3 | 更新失败 | 不同包体类别与其他类别互转 | 更新时类别不一致且涉及不同包体类别（当前模式侧 + 跨 map 侧） | N/A | 返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT`（8519943） | AC-8/AC-35 |
| EX-4 | 安装失败 | 不同包体类别仅系统应用 | 双模式设备非系统应用安装不同包体类别 | N/A | 返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP`（8519942） | AC-34 |
| EX-5 | 默认值兜底 | 存量应用无 appSandboxPolicy 字段 | 反序列化缺失字段 | N/A | 默认 SHARED_SANDBOX（值 0） | AC-37 |
| EX-6 | 安装失败 | 模式独占策略与当前模式不匹配 | 双模式设备安装 MAIN_ONLY×副模式 或 SUB_ONLY×主模式 | N/A | 返回 `ERR_APPEXECFWK_INSTALL_DUAL_MODE_POLICY_NOT_SUPPORTED`（8519947，对外映射 ERR_INSTALL_PARSE_FAILED），无状态突变 | AC-42 |
| EX-7 | 快速失败 | 模式切换进行中提交安装/更新/卸载 | 双模式设备切换持有排他锁期间，任务入队时点 / 执行时点 / 直连入口任一探测失败 | N/A | 任务不排队不执行，同步返回 `ERR_APPEXECFWK_DUAL_MODE_SWITCH_BUSY`（8519944），可重试 | AC-45 |
| EX-8 | 退化兜底 | 预置 ERMS 解析不可用 | ERMS 库/符号缺失、查询失败、策略非不同包体类别、主模式 hap 集不可识别 | N/A | 退化整目录单包安装（不阻断、不失败），行为与非双模式预置一致 | AC-50 |

## 恢复契约

| 编号 | 触发条件 | 恢复策略 | 恢复结果 | 约束 |
|------|----------|----------|----------|------|
| RC-1 | 重启后 ispcmode（生产 bool，缺失即无效）/ mainmode（缺失/非法 ∉{0,1}）任一无效 | 所有应用加载到可查询列表 | 应用全部可查询 | tempBundleInfos_ 为空 |

## 验证映射

> VM-1~4 为维度级抽样映射；全量 AC 级验证映射（每 AC 一行：关联规则/Task/验证方式/证据）见上文「验收追溯」表。

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
| DeviceModeDistributionPolicy（枚举） | Public | 9 个枚举成员（值 0~8） | - | N/A | 设备模式分发策略定义，连续 int 值不支持按位或；NAPI 运行时已注册 9 命名值（`bundleManager.DeviceModeDistributionPolicy`，AC-47） | AC-1/AC-47 |
| BundleInfo.deviceModeDistributionPolicy | Public | number（枚举值，0~8） | - | N/A | 应用设备模式分发策略，默认 UNSPECIFIED（值 0） | AC-1/AC-2 |
| InstallParam.deviceModeDistributionPolicy | Public | number（枚举值，0~8） | - | N/A | 安装时指定的设备模式分发策略，默认 UNSPECIFIED（值 0）；TS 侧经 parameters 保留 key 透传（AC-41），native/IPC 侧为字段 | AC-1/AC-41 |
| AppSandboxPolicy（枚举） | Public | 2 个枚举成员（值 0~1） | - | N/A | 应用沙箱策略定义，连续 int 值互斥单值 | AC-36 |
| BundleInfo.appSandboxPolicy | Public | number（枚举值，0~1） | - | N/A | 应用沙箱策略，默认 SHARED_SANDBOX（值 0） | AC-36/37 |

### 新增错误码

| 错误码 | 码值 | 含义 | 对外映射（status_receiver_proxy） | 关联 AC |
|--------|------|------|----------------------------------|---------|
| ERR_APPEXECFWK_INSTALL_DUAL_MODE_CATEGORY_CONFLICT | 8519943 | 不同包体类别互转/跨 map 类别冲突 | ERR_INSTALL_BUNDLE_TYPE_NOT_SAME | AC-8/AC-35 |
| ERR_APPEXECFWK_INSTALL_DUAL_MODE_NOT_SYSTEM_APP | 8519942 | 非系统应用安装不同包体类别 | ERR_INSTALL_PARSE_FAILED | AC-34 |
| ERR_APPEXECFWK_INSTALL_DUAL_MODE_POLICY_NOT_SUPPORTED | 8519947 | 模式独占策略与当前设备模式不匹配（MAIN_ONLY×副模式 / SUB_ONLY×主模式） | ERR_INSTALL_PARSE_FAILED | AC-42 |
| ERR_APPEXECFWK_DUAL_MODE_SWITCH_BUSY | 8519944 | 模式切换进行中，安装/更新/卸载任务快速失败（需求二定义、安装侧消费；可重试） | 经 statusReceiver 直传服务端码（无专属客户端码，暂折入通用槽位） | AC-45/AC-53 |

> 8519944 与 8519945/8519946/8519948（切换链路错误码）同属需求二「模式切换接口」错误码族，完整语义见需求二 spec；本表仅收录安装路径会返回的码。双模式安装拒绝码暂无专属 IStatusReceiver 客户端码（8519942/8519947 折入通用 PARSE_FAILED 槽位，8519943 折入 BUNDLE_TYPE_NOT_SAME），专属客户端码留后续。
>
> **既有码引用**：`ERR_APPEXECFWK_INSTALL_PARAM_ERROR`（**8519686**，appexecfwk_errors.h:66）——模式独占校验入口对 effectivePolicy 值域 [0,8] 越界的纵深防御返回码（AC-42/FR-17，非 IPC 进程内调用路径，正常流不可达）；既有码非本特性新增，不入上表。

### 变更/废弃 API

| API 名称 | 变更类型 | 影响场景 | 迁移指引 | 关联 AC |
|----------|----------|----------|----------|---------|
| InstallParam（结构扩展） | 新增可选字段 | 现有调用方不传 deviceModeDistributionPolicy 时走默认值 | 无需迁移，向后兼容 | AC-1/AC-2 |
| InstallParam.parameters（保留 key 透传） | 新增保留 key 语义 | TS 侧经既有 parameters 数组（`Array<{key, value}>`）传 key `ohos.bms.param.deviceModeDistributionPolicy`、value 为枚举值十进制字符串（如 "4"）；适配层（NAPI `install`；ANI `install`）刷新 `deviceModeDistributionPolicy` 字段 | 无需迁移：不传该 key 走默认 UNSPECIFIED；传非法 value（非十进制整数/超 0~8）仅打 warning 日志、静默降级默认策略，不拦截安装（2026-08-17 裁定不报 401） | AC-41 |
| InstallParam.forceDualModeCloneInstall（内部字段） | 新增进程内控制字段（非 API） | 预置 fan-out 副趟与 user-100 clone 恢复安装强制走 clone 命名路径；**不参与 IPC 序列化**（install_param.h 注释明确），外部调用方不可见、零影响 | N/A | AC-43/AC-52 |
| ApplicationInfo（结构扩展） | 新增可选字段 | 反序列化老数据时字段缺失 | from_json 默认值兜底，无需迁移 | AC-18 |
| BundleInfo（结构扩展） | 新增可选字段 appSandboxPolicy | 反序列化老数据时字段缺失 | from_json 默认值兜底（SHARED_SANDBOX），无需迁移 | AC-37 |

> API 签名细节、d.ts 位置、SysCap 见 design.md「API 签名、Kit 与权限」。

## 兼容性声明

- **已有 API 行为变更:** 是。安装/更新广播 Want key `isSharedSandbox`（bool）更名为 `appSandboxPolicy`（int 枚举 0/1），并新增 `beforeDeviceModeDistributionPolicy` / `beforeAppSandboxPolicy` 两个 key——对外契约变更，须同步需求二上层消费者；其余仅新增可选字段，现有调用方行为不变
- **配置文件格式变更:** 否
- **数据存储格式变更:** 是（`installed_bundle` 表 JSON value 新增 `deviceModeDistributionPolicy` + `isDualModeCloneApp` 字段；副模式不同包体类别记录 DB key 带 `+clone-10000+` 前缀，由 `isDualModeCloneApp` 字段驱动；追加 `appSandboxPolicy` 字段，随 `baseBundleInfo_` 节点存储；`PreInstallBundleInfo` 存储预置解析所得 `deviceModeDistributionPolicy` 与 clone 标志，供 `user-100` 恢复安装复用，免重查 ERMS）。**向后兼容**：老数据缺字段走默认值（`deviceModeDistributionPolicy`=0 / `isDualModeCloneApp`=false，AC-18；`appSandboxPolicy`=`SHARED_SANDBOX`(0)，AC-37）
- **最低支持版本:** OpenHarmony-6.0-Release
- **API 版本号策略:** 新增字段与枚举标注 `@since` 目标版本

## 架构约束

> 架构规则适用性及设计方案见 design.md。

| 关键约束 | 约束说明 | 影响 AC |
|----------|----------|---------|
| 特权文件操作经 SA 511 | 安装目录创建/轮转一律跨 IPC 到 installd 进程 | AC-4/AC-10 |
| 副模式记录 key 带前缀 | 副模式不同包体类别应用 DB 记录 key 为 `+clone-10000+{bundleName}` | AC-4/AC-11 |
| 加载去前缀 | 重启加载到内存时副模式不同包体类别应用以原始 bundleName 入可查询列表 | AC-11/AC-14 |
| 切换互斥锁序 | 安装类任务持 dualModeSwitchMutex_ 共享侧（try，不等待），切换持排他侧（try）；锁序 dualModeSwitchMutex_ → bundleInfoMutex_ → stateMutex_ | AC-45/AC-53 |
| ERMS 仅预置路径 | ERMS 分发查询仅预置目录输入触发（dlopen liberms_sdk.z.so）；普通安装/OTA 显式 hap 路径输入不查 ERMS，保持原行为 | AC-43/AC-50 |
| 模式判断直读不缓存 | ispcmode/mainmode 每次调用直读系统参数（ispcmode 生产 key 为 bool、测试注入 key 为 int，读取路径在 DualModeHelper 内分流；对外归一化 0/1/-1），无进程级缓存；判定即时反映参数变化 | AC-3/AC-33 |

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

- [x] 无"待定""TBD""TODO"等占位符
- [x] 所有 AC 使用 WHEN/THEN 格式，可独立测试
- [x] 范围边界明确（做什么/不做什么清晰）
- [x] 无语义模糊表述
- [x] AC 与业务规则/异常规则/恢复契约交叉一致
- [x] 实现锚点裁剪豁免已声明（头部裁剪声明：用户故事/验收标准章节为纯黑盒规格；锚点集中于功能规则/架构约束/验收追溯证据列，权威定义在 design.md）

## context-references

```yaml
context-queries:
  - repo: "bundlemanager_bundle_framework"
    query: "副模式不同包体类别应用安装目录隔离、DB key 前缀、重启分类加载的实现细节"
  - repo: "bundlemanager_bundle_framework"
    query: "SetDualModeAppInfo / CheckDualModeCategoryConsistency(InTemp) 安装准入与类别一致性校验实现（base_bundle_installer.cpp）"
  - repo: "bundlemanager_bundle_framework"
    query: "FillDualModeEventFields / ComputeCurrentAppSandboxPolicy 事件双模式字段与粘性计算实现"
  - repo: "bundlemanager_bundle_framework"
    query: "ResolveDualModePolicy / SystemBundleInstaller::InstallSystemBundle 预置 ERMS 两趟 fan-out 实现"
  - repo: "bundlemanager_bundle_framework"
    query: "TryLockForBundleOperation / RejectTaskIfSwitchInFlight / DualModeSwitchGuard 切换互斥接入实现"
  - repo: "bundlemanager_bundle_framework"
    query: "ResolveDualModeResponseAppIndex clone 应用查询结果 appIndex 回显覆盖面"
```

**关键文档：** [proposal.md](./proposal.md)、[design.md](./design.md)
