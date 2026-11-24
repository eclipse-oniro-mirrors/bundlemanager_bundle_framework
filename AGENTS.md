# AGENTS.md

## 1. 概述

本 AGENTS.md 用于指导开发与应用运行时管理相关特性分析、需求导入、设计、编码及验证各环节。在SDD流程开发各阶段，涉及本代码仓所有修改需要遵从本文档描述及其指向的其他更细则文档的内容，如果本文档指向的其他文档存在与本文档规定冲突内容，以本文档内容为准。本文档描述内容包括代码目录、知识体系、约束与限制三个章节，其中代码目录等内容就在本代码仓中，所引用的详细知识库内容均引自abilitykit_sdd，在执行具体要求前请确认该知识库已在本地存在，知识库的检索路径一般满足如下规则:
    - Windows: %LOCALAPPDATA%\sdd-insight\kb\（即 C:\Users\<工号对应机器用户>\AppData\Local\sdd-insight\kb\）
    - Linux / macOS（含 WSL 跑 opencode 的情况）:	~/.local/share/sdd-insight/kb/
如不存在，则应代码仓同级目录下执行git clone https://gitcode.com/abilitykit_public/abilitykit_sdd.git 下载代码仓后，在相应的代码仓中查找具体规则。

本仓库属于 OpenHarmony Bundle Manager Bundle Framework，主要负责应用包管理相关能力，包括应用安装、更新、卸载、查询、资源管理、权限校验以及若干扩展能力。
工作时请把它视为系统级基础组件：接口稳定性、权限边界、用户隔离、数据一致性和错误码兼容性都很重要。

### 代码目录职责


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
```

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

## 2. 知识体系

### 2.1 Summarys: 领域概念与概述

**文档路径**：abilitykit_sdd/summarys

**文档内容**：abilitykit业务范围关键概念、概述、设计约束等基础知识。

**文档适用**：涉及abilitykit领域的相关问题、需求及业务讨论，均需要遵从本目录下文档所述相关术语、概念及要求。例如用户说"多HAP需要新增一个XXX规格"，需要先通过本目录下的文档查询多HAP相关概念。

**SDD适用**：可在Define/Specify/Design/Plan等各阶段使用，重点在Define阶段使用。

### 2.2 Standards：编码与设计规范

**文档路径**：abilitykit_sdd/standards

**文档内容**：abilitykit业务范围编码规范要求及通用设计规范要求基础知识。

**文档适用**：涉及abilitykit领域相关代码仓（主要包括ability_ability_runtime/ability_ability_base/bundlemanager_bundle_framework等代码仓）的代码修改，均需要严格遵从本文档规则。

**SDD适用**：可在Design/Plan等各阶段使用，重点在Plan阶段使用。

### 2.3 Specifications：模块场景与特性规格

**文档路径**：abilitykit_sdd/specifications

**文档内容**：abilitykit业务范围全量模块、业务场景及特性规格等基础知识。

**文档适用**：涉及abilitykit领域的相关问题、需求及业务讨论，均需要参考本目录下相关模块、场景及特性等基础知识。新增需求或业务讨论如果是或者新增模块、场景或特性，则需要关注不要与现有规格出现冲突；新增需求或业务讨论如果是对原有模块、场景或特性进行调整的，则需要和用户交互明确相关模块、场景和特性变更点。需要注意：不管是哪种情况，一旦出现specifications内容的变更（新增、删除或调整），都必须以当前用户身份向abilitykit_sdd代码仓中按照原有格式提交变更，并推送到远端请求Committer合入。

**SDD适用**：可在Define/Specify/Design/Plan等各阶段使用，重点在Specify/Design阶段使用。

### 2.4 Suits：研发工具套件

**文档路径**：abilitykit_sdd/suits

**文档内容**：abilitykit业务范围开发自测试工具套件。

**文档适用**：涉及abilitykit领域的代码在完成编码后进行测试验证阶段时使用本目录下的相关工具。

**SDD适用**：可在Plan阶段及Plan之后的阶段使用。

## 3.编码、验证、检视及上库规则

### 3.1 代码编写：Coding

**触发条件**：SDD流程中Plan阶段主动触发或用户主动要求生成代码时触发。

**执行规则**：

1）编码前严格读取abilitykit_sdd/standards所有规则后开始编码，编码及后续修改不得出现违反规则的实现。

2）所有业务代码修改都需要包含测试用例的同步编写和生成，其中ArkTS 接口的XTS可参考[ArkTS XTS 生成Skill](https://gitcode.com/openharmony-ai-testdesign/oh-test-skills/tree/main/ohos-test-design/skills-refactor/ohos-test-arkts-xts-generation)生成，CAPI接口的XTS可参考[CAPI XTS 生成Skill](https://gitcode.com/openharmony-ai-testdesign/oh-test-skills/tree/main/ohos-test-design/skills-refactor/ohos-test-capi-xts-generation)

### 3.2 功能验证：Verify

**触发条件**：完成编码且变更模块编译通过后**自动触发**（无需等待用户显式要求；SDD 流程中由 Verify 阶段承接）；用户主动要求验证时可随时提前触发。在模拟器验证执行完成后，需要提醒用户进行真机复测。

**执行规则**：使用 abilitykit_sdd/suits/simulator_use Skill进行系统编译、UT及XTS测试用例编译、系统烧录和测试，输出测试报告。自动触发时优先走 simulator_use 的**模式 B（增量热替换验证）**：只构建变更库并热替换到既有镜像（含 UT 执行与 IPC 冒烟），全量镜像构建仅在模式 B 前置不满足时使用。

**自动触发前置探测矩阵**（逐项判定，降级路径必须显式登记移交，禁止冒充通过）：

| 探测项 | 通过 → | 不通过 → |
|--------|--------|----------|
| 变更模块编译（ninja 窄目标） | 进入部署 | 先修编译；编译不过则阻断验证 |
| 构建环境健康（`simulator_use/scripts/preflight_env.py --check`） | 继续 | 自动执行自愈（`--fix`，幂等）后重试一次 |
| QEMU 可启动且 hdc 可连 | 变更库热替换 → UT + IPC 冒烟 + 原路径回归 → 测试报告 + 提醒真机复测 | 降级编译级/结构检查 + 移交登记（3.1 自测试反伪规则同口径） |

### 3.3 代码检视：Review

**触发条件**：完成验证且验证报告通过后主动触发或当用户表达"检视一下代码""帮我审一下""做一次 code review""深度扫描""安全审计""查高危 bug""接口审计"等检视意图时，需要通过abilitykit_sdd/suits/codecheck中的Skills进行代码的检视。

**执行规则**：

- 仅检视，禁止直接修改代码。
- 检视发现的问题，经过用户确认允许修改代码后，回到3.1 Coding阶段，进入小循环：Coding->Verify->Review，直到检视代码无新增问题。

### 3.4 代码上库：Commit

**触发条件**：代码检视完成且无新增问题后主动询问用户是否触发，或当用户表达"帮我提交代码"时触发。**禁止**未经用户确认直接提交代码。

**执行规则**：
1、确定修改涉及代码仓；
2、使用abilitykit_sdd/suits/atomic-fork-pr-workflow Skill提交并推送pr。