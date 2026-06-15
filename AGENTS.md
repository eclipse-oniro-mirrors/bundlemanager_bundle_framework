# AGENTS.md

本文件是给 AI 编码助手使用的仓库工作指南。所有在本仓库中进行的分析、修改、测试和提交说明，都应优先遵循这里的约定。

## 项目定位

本仓库属于 OpenHarmony Bundle Manager Bundle Framework，主要负责应用包管理相关能力，包括应用安装、更新、卸载、查询、资源管理、权限校验以及若干扩展能力。

工作时请把它视为系统级基础组件：接口稳定性、权限边界、用户隔离、数据一致性和错误码兼容性都很重要。

## 工作原则

- 修改前先阅读相关目录、调用链和已有测试，优先沿用现有风格。
- 保持改动范围收敛，不做与任务无关的重构、格式化或命名调整。
- 不回滚用户已有改动；遇到工作区脏文件时，只处理与当前任务直接相关的文件。
- 对系统能力、安装卸载流程、权限、数据库、IPC、用户态隔离等逻辑保持谨慎。
- 新增行为应尽量有测试或至少说明无法测试的原因。
- 日志、错误码、权限检查和空指针检查应遵循仓库已有模式。

## 代码地图

### 目录与分层

```
应用层 (ArkTS/JS/CJ/C++)
  ↓ interfaces/ (NAPI/NNative/CJ/ANI 多语言绑定)
inner_api/appexecfwk_core/ IPC接口层 (Proxy/Host/Client：IBundleMgr 等 12 组 IPC)
  ↓
inner_api/appexecfwk_base/ 数据模型层 (BundleInfo 等 68+ Parcelable 结构)
  ↓
services/bundlemgr/ 服务实现层 (SA 401 foundation 进程)
  ↓ InstalldClient (IPC 跨进程调用)
services/bundlemgr/src/installd/ 特权操作层 (SA 511 installs 进程 · 目录创建/HAP解压/权限设置)
  ↓
OpenHarmony 其他系统服务
```

### 关键目录

- `interfaces/`：对外或内部接口定义。
- `services/bundlemgr/`：Bundle Manager 服务主体实现。
- `services/bundlemgr/include/`：服务层头文件。
- `services/bundlemgr/src/`：服务层实现代码。
- `services/bundlemgr/src/installd/`：与安装守护进程相关的客户端和特权操作协作逻辑。
- `services/bundlemgr/src/rdb/`：持久化数据库相关实现。
- `services/bundlemgr/src/verify/`：签名、完整性等校验相关逻辑。
- `services/bundlemgr/test/`：服务层测试。
- `test/`：单元、模块、系统、性能、模糊等测试资源。
- `sa_profile/`：系统能力配置。
- `bundle.json`：组件元信息和依赖声明。

## 知识路由

本工程的专用 skill 放在仓库根目录的 `skills/` 下，skill中的reference文档包含本领域的权威知识。命中触发条件后，必须在规划阶段读取对应 skill 的 `SKILL.md` 和 `references/`，再开始编辑。

### 按场景路由

| 任务场景 | 加载 Skill |
|----------|-----------|
| 安装、更新、卸载、恢复、HAP/HSP 解析、Installd 文件操作 | `bms-install-flow` |
| 新增 IPC 接口方法、修改 SA 401/511 通信 | `bms-add-ipc` |
| 签名校验、权限授予、Provision profile、Code signature、调用方检查 | `bms-security-verify` |
| userId 语义、多用户隔离、跨用户权限、用户维度安装/查询 | `bms-user-model` |
| 日志新增/修改/审查、APP_LOG/LOG_NOFUNC、HiSysEvent、敏感信息标注 | `bms-logging` |
| 测试编写、测试定位、GN 测试 target、mock 选择 | `bms-testing-patterns` |
| 源码定位、模块职责、调用链、构建目标 | `bms-navigation` |

### 领域词汇路由

当任务描述、issue、日志、API 名称或变更文件涉及以下术语时，读取对应 skill 或文档后再规划：

| 术语 | 风险提示 | 读取 |
|------|---------|------|
| Installd / SA 511 | 特权文件操作进程，所有方法必须校验 Foundation UID | `bms-install-flow`, `bms-security-verify` |
| Foundation / SA 401 | 主业务进程，不得直接做需要特权的文件操作 | `bms-add-ipc`, `bms-install-flow` |
| IPC 枚举 / interface_code | 新增消息码必须同时在枚举和 host 分发注册 | `bms-add-ipc` |
| userId / ALL_USERID / ANY_USERID | 不要把 ALL_USERID/ANY_USERID 当作真实用户；0/1/100 有特殊语义 | `bms-user-model` |
| InnerBundleInfo | 内存态核心数据结构，变更须同时检查持久化和缓存一致性 | `bms-install-flow` |
| Quick Fix | 快速修复有独立安装流程和状态约束 | `bms-navigation` references |
| Overlay | 资源覆盖有优先级和同名约束 | `bms-navigation` references |
| Sandbox App | 运行受限应用有独立沙箱路径和权限模型 | `bms-navigation` references |
| Clone | 克隆应用共享基础包但有独立用户数据 | `bms-navigation` references |
| Shared Bundle / HSP | 共享库有独立加载和版本约束 | `bms-navigation` references |
| appexecfwk_errors | 错误码是公共兼容性边界，新增/修改需归类到已有模块偏移 | `bms-navigation` references |
| BundlePermissionMgr | 权限检查必须在能力入口执行，不能信任入参 | `bms-security-verify` |
| RDB / 数据迁移 | 表结构变更需考虑跨版本迁移脚本和缓存失效 | `bms-install-flow` |
| APP_LOG / LOG_NOFUNC / %{public} %{private} | 日志敏感信息标注规则，BMS tag 区分 installer/query/installd/ext 等 | `bms-logging` |
| Provision profile / code signature | 安装安全校验链，失败后不能继续写入 | `bms-security-verify` |
| bundle.json / appexecfwk.gni | 功能开关影响构建范围，不要假设代码一定参与编译 | `bms-navigation` references |

### 规划声明

在开始编辑前，必须明确：
- 任务属于哪类场景（安装/IPC/权限/用户/日志/测试/查询/其他）
- 已读取哪些 skill 或 references
- 发现了哪些约束或边界
- 是否需要使用某个 skill 的工作流程

## 约束与边界

### 架构与业务不变量

- 双进程 IPC 分层：Foundation 进程（SA 401）控制业务流程与权限，Installd 进程（SA 511）执行特权文件操作。Foundation 进程不得直接做需要高权限的文件系统操作，必须通过 InstalldClient IPC 请求 Installd 进程完成。
- 权限检查必须在能力入口执行（HostImpl 层），不能信任调用方入参。
- userId 不是可选参数：入参含特殊值须显式解析，不能默认当前用户；request userId 经推导和权限校验后可能变为不同用户或 INVALID_USERID（response userId），须同时处理两条路径。
- 安装、更新、卸载共用 BaseBundleInstaller，修改任一流程须同时检查其余两个；每个流程内部均有回滚、清理和异常恢复分支，不能只改成功路径。
- IPC 消息码注册必须在枚举文件和 host 分发中同步完成，缺一则 IPC 不完整。
- 错误码属于公共兼容性边界，新增错误码必须归入 `appexecfwk_errors.h` 的已有模块偏移。

### Do not

- 不要在 Foundation 进程中新增需要特权的文件操作；必须通过 InstalldClient IPC 请求。
- 不要把userid `0`、`1`、`100` 写成魔法数字；使用 `Constants::DEFAULT_USERID`、`Constants::U1`、`Constants::START_USERID`。
- 不要把 `ALL_USERID`、`ANY_USERID`、`UNSPECIFIED_USERID` 当作真实用户 ID。
- 不要修改或删除已有错误码；新增错误码必须归入 `appexecfwk_errors.h` 的已有模块偏移。
- 不要修改 Public API 签名、权限行为或生命周期语义，除非任务明确要求。
- 不要绕过已有的权限、安全、DFX 或兼容性检查来使测试通过。
- 不要在高频循环或热路径中新增大量 INFO/ERROR 日志。
- 不要在多层调用中对同一失败重复打印 error，避免日志噪音。
- 不要为通过测试而删除日志、HiSysEvent、错误码或诊断信息。
- 不要在 Installd 进程方法中跳过 Foundation UID 校验。
- 不要做与任务无关的重构、格式化或命名调整。
- 不要回滚用户已有改动；遇到工作区脏文件时，只处理与当前任务直接相关的文件。

### Ask before

以下变更必须先向用户确认，不得自行决定：

- 修改 `interfaces/` 下任何对外 API 的签名、语义或错误码。
- 修改权限授予逻辑、安全边界或 Installd IPC 协议。
- 修改 RDB 表结构、序列化格式或 `InnerBundleInfo` 持久化字段。
- 新增第三方依赖或修改已有依赖版本。
- 删除兼容性垫片或数据迁移逻辑。
- 新增需要特权的文件操作（必须走 InstalldClient）。
- 修改 `appexecfwk.gni` 或 `appexecfwk_bundlemgr.gni` 中的功能开关默认值。

### 已知易错点

- 安装流程修改只改主路径而忽略回滚/清理分支是最常见遗漏。
- userId 默认当前用户会导致 0 号用户或 ALL_USERID 逻辑错误。
- IPC 新增消息码只加枚举未加 host 分发，导致 IPC 不完整。
- Installd 方法未校验 Foundation UID，导致安全边界被绕过。
- 修改功能开关后未验证构建范围变化。

## 验证闭环

### 最小验证命令

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```bash
# 编译验证
./build.sh --product-name rk3568 --build-target bundle_framework

# 编译服务模块（更快）
./build.sh --product-name rk3568 --build-target services/bundlemgr:bms_target

# 服务单元测试
./build.sh --product-name rk3568 --build-target services/bundlemgr/test:unittest

# 全量测试
./build.sh --product-name rk3568 --build-target test_target
```

如果当前环境缺少 OpenHarmony 构建链、产品配置或依赖仓库，请不要伪造构建结果；在最终说明中明确写出未能运行的命令和原因。

### 按变更类型验证

| 变更类型 | 最小验证 |
|----------|---------|
| 修改内部实现（services/bundlemgr/src/） | 编译通过 + 相关模块单测 |
| 新增/修改 IPC 方法 | 编译通过 + 搜索 interface_code.h 确认枚举已注册 + 搜索 host 分发确认方法已处理 |
| 新增/修改 Public API（interfaces/kits/） | 编译通过 + 全量单测 + 各语言绑定编译 + 兼容性评估 |
| 修改权限或安全边界 | 编译通过 + 权限相关单测 + 搜索所有调用方确认影响 |
| 修改 RDB 或数据持久化 | 编译通过 + 数据相关单测 + 确认迁移逻辑覆盖 |
| 修改 userId 相关逻辑 | 编译通过 + 多用户单测 + 确认 ALL_USERID/ANY_USERID 路径 |
| 日志新增/修改 | 确认 %{public}/%{private} 标注正确 + 搜索相邻模块日志风格保持一致 |
| 测试变更 | 运行变更的测试 + 至少一个相邻相关测试 |

### Done 定义

一个任务只有同时满足以下条件才算完成：

1. 请求的行为已实现。
2. 相关编译、测试、兼容性验证已运行，或已说明无法运行的原因。
3. `git diff` 仅包含预期改动，无无关重构或格式化。
4. 新增或修改的错误路径有清晰返回值和日志。
5. 修改接口、配置或构建文件时，已检查相关依赖和目标。

### 最终回复格式

向用户汇报时请包含：

- 改了哪些文件。
- 行为上解决了什么问题。
- 运行了哪些验证及结果。
- 哪些验证因环境限制未运行，以及残留风险。
