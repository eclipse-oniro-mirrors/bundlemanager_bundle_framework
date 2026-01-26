# CLAUDE.md

此文件为 Claude Code (claude.ai/code) 在此代码仓库中工作时提供指导。

## 概述

这是 OpenHarmony 的 **BundleManager Bundle Framework（包管理包框架）**，是一个负责应用包（bundle）管理的核心子系统。它提供应用的安装、更新、卸载和信息查询能力。

## 架构

### 目录结构

```
bundlemanager_bundle_framework/
├── interfaces/                      # 接口层
│   ├── inner_api/                   # 内部 API（供其他子系统使用）
│   └── kits/                        # 应用开发接口（支持 C/C++、JS、Cangjie、ANI）
├── services/                        # 服务实现
│   └── bundlemgr/                   # 包管理器服务
│       ├── include/                 # 头文件（组织方式与 src/ 相同）
│       ├── src/                     # 源代码
│       │   ├── aging/               # 包老化管理（资源清理）
│       │   ├── aot/                 # AOT（Ahead-Of-Time）编译管理
│       │   ├── app_control/         # 应用控制和应用跳转拦截
│       │   ├── app_provision_info/  # 应用配置文件（profile）管理
│       │   ├── app_service_fwk/     # 应用服务框架安装
│       │   ├── bms_extension/       # BMS 扩展客户端
│       │   ├── bundle_backup/       # 备份和恢复功能
│       │   ├── bundle_resource/     # Bundle 资源管理
│       │   ├── bundlemgr_ext/       # BundleManager 扩展
│       │   ├── clone/               # 应用克隆支持
│       │   ├── common/              # 公共工具和辅助类
│       │   ├── data/                # 数据处理
│       │   ├── default_app/         # 默认应用管理
│       │   ├── distributed_manager/ # 分布式包管理
│       │   ├── driver/              # 驱动安装支持
│       │   ├── exception/           # 异常处理
│       │   ├── extend_resource/     # 扩展资源管理
│       │   ├── first_install_data_mgr/ # 首次安装数据管理
│       │   ├── free_install/        # 免安装（按需安装）能力
│       │   ├── idle_condition_mgr/  # 空闲条件管理
│       │   ├── installd/            # Installd 客户端（特权进程）
│       │   ├── ipc/                 # IPC 通信
│       │   ├── navigation/          # 导航相关
│       │   ├── on_demand_install/   # 按需安装
│       │   ├── overlay/             # 叠加安装支持
│       │   ├── plugin/              # 插件支持
│       │   ├── quick_fix/           # 快速修复（补丁）管理
│       │   ├── rdb/                 # 关系型数据库封装
│       │   ├── rpcid_decode/        # RPC ID 解码
│       │   ├── sandbox_app/         # 沙箱应用支持
│       │   ├── shared/              # 共享包管理
│       │   ├── uninstall_data_mgr/  # 卸载数据管理
│       │   ├── user_auth/           # 用户认证
│       │   ├── utd/                 # 统类型描述（Unified Type Descriptor）
│       │   └── verify/              # 验证功能
│       └── test/                    # 服务层单元测试
├── test/                            # 系统/集成级测试
└── etc/                             # 配置文件
```

### 关键组件

包管理框架的核心组件和功能子系统（位于 `services/bundlemgr/src/`）：

#### 核心服务类

- **bundle_mgr_service.cpp**: BundleMgrService 实现（SA 401），主系统能力服务，协调所有包管理操作
- **bundle_data_mgr.cpp**: BundleDataMgr 实现，中央数据管理器，存储和查询包/组件信息
- **bundle_installer.cpp**: BundleInstaller 实现，处理安装、更新和卸载逻辑
- **bundle_mgr_host_impl.cpp**: BundleMgrHostImpl 实现，提供 IBundleMgr 接口的 IPC 主机

#### 功能模块分类

**安装与卸载**
- **base_bundle_installer.cpp**: 基础安装器实现
- **bundle_install_checker.cpp**: 安装检查器
- **bundle_parser.cpp**: Bundle 解析器
- **installd/**: Installd 客户端，与 InstalldService (SA 511) IPC 通信，执行特权文件/目录操作

**数据与资源管理**
- **data/**: 数据处理模块
- **rdb/**: 关系型数据库封装
- **bundle_resource/**: Bundle 资源管理
- **extend_resource/**: 扩展资源管理
- **bundle_backup/**: 备份和恢复功能

**权限与安全**
- **verify/**: 验证功能（代码签名、完整性校验等）
- **bundle_permission_mgr.cpp**: Bundle 权限管理
- **user_auth/**: 用户认证

**高级特性**
- **free_install/**: 免安装（按需安装）能力
- **on_demand_install/**: 按需安装
- **overlay/**: 叠加安装支持
- **quick_fix/**: 快速修复（补丁）管理
- **clone/**: 应用克隆支持
- **sandbox_app/**: 沙箱应用支持
- **shared/**: 共享包管理
- **aot/**: AOT（Ahead-Of-Time）编译管理

**应用控制**
- **app_control/**: 应用控制和应用跳转拦截
- **default_app/**: 默认应用管理
- **app_service_fwk/**: 应用服务框架安装

**分布式与备份**
- **distributed_manager/**: 分布式包管理
- **first_install_data_mgr/**: 首次安装数据管理
- **uninstall_data_mgr/**: 卸载数据管理

**系统功能**
- **aging/**: 包老化管理，用于资源清理
- **app_provision_info/**: 应用配置文件（profile）管理
- **bms_extension/**: BMS 扩展客户端
- **bundlemgr_ext/**: BundleManager 扩展
- **driver/**: 驱动安装支持
- **exception/**: 异常处理
- **idle_condition_mgr/**: 空闲条件管理
- **navigation/**: 导航相关
- **plugin/**: 插件支持
- **rpcid_decode/**: RPC ID 解码
- **utd/**: 统类型描述（Unified Type Descriptor）

**通信与基础设施**
- **ipc/**: IPC 通信
- **common/**: 公共工具和辅助类

### 进程架构

包管理框架采用**多进程架构**，将不同权限级别的操作分离到独立进程中，包管理调用installd模块时需通过IPC：

#### BundleMgrService (SA 401)
- **进程**: Foundation 进程
- **功能**: 提供应用包管理的核心 API（安装、卸载、查询等）
- **依赖服务**:
  - 公共事件服务（用于系统事件）
  - 包代理服务
  - EL5 文件密钥服务
  - InstalldService (SA 511)

#### InstalldService (SA 511)
- **进程**: Installs 进程（独立特权进程）
- **功能**: 执行需要提升权限的文件系统操作
- **配置**: 见 `sa_profile/511.json`
  - 进程名: `installs`
  - 库文件: `libinstalls.z.so`
  - 启动阶段: `CoreStartPhase`
  - 按需卸载: 长期未使用 180 秒后自动卸载

## 构建系统

此项目使用 **GN (Generate Ninja)** 作为构建系统。

### 关键构建文件

- 根构建: `BUILD.gn`
- 服务构建: `services/bundlemgr/BUILD.gn`
- 配置: `appexecfwk.gni`, `services/bundlemgr/appexecfwk_bundlemgr.gni`

### 构建目标

主构建目标：
```bash
# 构建所有包框架目标
./build.sh --product-name <product> --build-target bundle_framework
```

测试目标：
```bash
# 单元测试
./build.sh --product-name <product> --build-target BmsBundleCommonTest
./build.sh --product-name <product> --build-target BmsBundleDataMgrTest

# 模块测试
./build.sh --product-name <product> --build-target moduletest

# 系统测试
./build.sh --product-name <product> --build-target systemtest_bms

# 性能测试
./build.sh --product-name <product> --build-target benchmarktest
```

单个测试示例：
- `services/bundlemgr/test/unittest/` 包含 40+ 个单元测试目录
- 每个测试目录都有一个 `BUILD.gn` 文件定义测试目标
- 测试命名模式: `Bms*Test` (例如: `BmsBundleCommonTest`, `BmsBundleDataMgrNullptrTest`)

### 构建配置

特性开关（定义在 `appexecfwk.gni` 中）：
- `bundle_framework_free_install`: 启用免安装能力
- `bundle_framework_default_app`: 启用默认应用管理
- `bundle_framework_quick_fix`: 启用快速修复支持
- `bundle_framework_overlay_install`: 启用叠加安装
- `bundle_framework_sandbox_app`: 启用沙箱应用支持

## 开发模式

### 日志

**位置**：`common/log/`（详见 `common/log/README.md`）

**使用方法**：
```cpp
// 包含头文件
#include "app_log_wrapper.h"

// 在 GN 文件中定义
defines = [
    "APP_LOG_TAG = \"BMS\"",
    "LOG_DOMAIN = 0xD001120",
]

// 使用日志宏
APP_LOGD("调试: %{public}d", 123);         // Debug
APP_LOGI("信息: %{public}s", "string");    // Info
APP_LOGW("警告");                          // Warning
APP_LOGE("错误: %{private}s", "敏感信息"); // Error
```

### 数据存储

**技术**：使用 RDB（关系型数据库）进行持久化存储

**关键文件**：
- 接口：`services/bundlemgr/include/bundle_data_storage_interface.h`
- 实现：`services/bundlemgr/src/rdb/`

### 错误处理

**错误码定义**：`interfaces/kits/native/inner_api/appexecfwk_errors.h`
- 按模块分类：通用、安装、数据库、代码签名、快速修复、叠加安装等

**错误检查宏**：`services/bundlemgr/src/common/common_fun_ani.h`
- RETURN_IF_NULL、RETURN_FALSE_IF_NULL 等空指针检查宏

**处理模式**：检查-返回、错误码转换（RDB_ERR_MAP、CODE_SIGNATURE_ERR_MAP）、异常保护（JSON、动态库加载）、重试机制

### 线程同步

**同步机制**：
- **读写锁**（std::shared_mutex）：读多写少场景，如 `bundle_data_mgr.cpp` 的 bundleInfoMutex_
- **互斥锁**（std::mutex）：独占访问，如 `bundle_mgr_service.cpp` 的 bundleConnectMutex_
- **条件变量**（std::condition_variable）：线程等待和通知，如 `installd_client.cpp`
- **单例模式**：DelayedSingleton 模板实现线程安全单例

**最佳实践**：读写分离（读共享、写独占）、分层锁设计、固定加锁顺序避免死锁、RAII 管理锁生命周期

## 测试

### 测试结构

- `test/unittest/`: 单个组件的单元测试
- `test/moduletest/`: 模块集成测试
- `test/systemtest/`: 系统级端到端测试
- `test/benchmarktest/`: 性能基准测试
- `test/fuzztest/`: 模糊测试
- `test/sceneProject/`: 测试 HAP 文件和测试应用

### 测试资源

- `test/resource/bmssystemtestability/`: 测试 Ability 源码
- `test/resource/bundlemgrservice/`: 包管理器服务测试资源

### 运行测试

```bash
# 运行特定单元测试
./build.sh --product-name <product> --build-target BmsBundleCommonTest
# 然后在设备上运行测试二进制文件

# 运行所有单元测试
./build.sh --product-name <product> --build-target unittest
```

## 重要概念

- **Bundle**: 应用包（HAP 文件），包含代码、资源和配置
- **HAP**: Harmonymony Ability Package - OpenHarmony 应用的包格式
- **Module**: 包含一个或多个 Ability 的 HAP 文件
- **Ability**: 表示功能的应用组件（类似于 Android 的 Activity/Service）
- **Extension**: 特殊的 Ability 类型（数据、卡片等）
- **InnerBundleInfo**: 包信息的内部表示，包含丰富的元数据
- **ApplicationInfo**: 应用级信息（包名、版本、权限等）
- **AbilityInfo**: 组件级信息（类型、启动模式、权限等）

## 关键依赖

此组件依赖众多 OpenHarmony 子系统（完整列表见 `bundle.json`）：
- `ability_runtime`: Ability 框架
- `samgr`: 系统能力管理器
- `ipc`: IPC 框架
- `storage_service`: 文件存储
- `access_token`: 权限管理
- `resource_manager`: 资源管理
- `appverify`: 应用验证
- `hitrace`, `hisysevent`, `hilog`: DFX 能力

## 配置文件

- `bundle.json`: 组件元数据和依赖
- `sa_profile/401.json`: BundleMgrService 的系统能力配置
- `sa_profile/511.json`: 安装服务的系统能力配置
- `services/bundlemgr/installs.cfg`: 安装配置
- `hisysevent.yaml`: HiSysEvent 事件报告配置
