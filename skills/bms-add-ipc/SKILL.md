---
name: bms-add-ipc
description: 在 OpenHarmony BundleManager 中添加新 IPC 接口方法的专用 skill。当用户需要在 BundleManager 框架中新增 IPC 通信方法时使用此 skill，支持在 Foundation 进程 (IBundleMgr) 和 Installs 进程 (IInstalld) 中添加接口方法。
---

# BundleManager IPC 接口方法添加

本 skill 提供在 BundleManager 中添加新 IPC 接口方法的完整指导流程。

## 使用场景

当用户提出以下需求时，使用此 skill：

- "在 BundleManager 中添加一个新的 IPC 接口方法"
- "实现一个新的 Bundle Manager 通信方法"
- "添加一个新的 API 到 bundle_mgr_service"
- "需要新增跨进程通信方法"
- "在 installd 服务中添加新的文件操作接口"

## 工作流程

添加 IPC 接口方法遵循以下标准流程：

```
1. 确定目标进程和接口签名
   ↓
2. 在接口定义中添加方法声明
   ↓
3. 在接口代码枚举中添加新代码
   ↓
4. 在 Proxy 中实现请求发送
   ↓
5. 在 Host 中实现请求处理
   ↓
6. 在业务逻辑实现中添加功能
```

## 双进程架构

BundleManager 使用双进程 IPC 架构：

### Foundation 进程 (SA 401)

**用途**: 核心业务逻辑处理，Bundle 信息查询和管理

**接口类**: `IBundleMgr`
**接口描述符**: `u"ohos.appexecfwk.BundleMgr"`

**关键文件**:
```
interfaces/inner_api/appexecfwk_core/
├── include/bundlemgr/
│   ├── bundle_mgr_interface.h         # IBundleMgr 接口定义
│   ├── bundle_mgr_proxy.h             # BundleMgrProxy 类定义
│   └── bundle_mgr_host.h              # BundleMgrHost 类定义
├── src/bundlemgr/
│   └── bundle_mgr_proxy.cpp           # Proxy 实现
└── include/
    └── bundle_framework_core_ipc_interface_code.h  # 接口代码枚举

services/bundlemgr/
├── include/bundle_mgr_host_impl.h     # BundleMgrHostImpl 类定义
└── src/
    ├── bundle_mgr_host.cpp            # BundleMgrHost 服务实现
    └── bundle_mgr_host_impl.cpp       # BundleMgrHostImpl 业务逻辑实现
```

### Installs 进程 (SA 511)

**用途**: 特权文件操作，需要高权限的安装相关操作

**接口类**: `IInstalld`
**接口描述符**: `u"ohos.appexecfwk.Installd"`

**关键文件**:
```
services/bundlemgr/
├── include/ipc/
│   ├── installd_interface.h           # IInstalld 接口定义
│   ├── installd_proxy.h               # Proxy 类定义
│   └── installd_host.h                # Host 类定义
├── src/ipc/
│   ├── installd_proxy.cpp             # Proxy 实现
│   └── installd_host.cpp              # Host 实现
├── include/installd/
│   └── installd_host_impl.h           # InstalldHostImpl 类定义
└── src/installd/
    └── installd_host_impl.cpp         # InstalldHostImpl 业务逻辑实现
└── include/
    └── bundle_framework_services_ipc_interface_code.h  # 接口代码枚举
```

## 进程选择指导

### 选择 Foundation 进程

适用于以下场景：
- Bundle 信息查询和管理
- 权限验证和控制
- 应用安装/卸载流程控制
- 需要访问权限系统的操作
- 业务逻辑处理

### 选择 Installs 进程

适用于以下场景：
- 创建/删除目录
- 提取 HAP 文件
- 设置文件权限
- 获取磁盘使用量
- 文件系统操作
- 需要高权限的底层操作

## 实现步骤

### 第一步：确定目标进程和接口签名

**需要用户提供的信息：**

1. **目标进程**: Foundation 或 Installs
2. **方法名称**: 例如 `GetCustomInfo`
3. **返回类型**: 例如 `ErrCode`、`bool` 等
4. **参数列表**: 参数类型和参数名
5. **出参列表** (可选): 如果存在出参，列出哪些参数是出参
   - **默认**: 所有参数都是入参（由 Proxy 写入，Host 读取）
   - **有出参时**: 需要明确列出出参的参数名
6. **功能说明** (可选): 方法的用途说明

**示例接口签名：**
```cpp
// 纯入参示例（默认）
virtual ErrCode SetCustomInfo(const std::string &bundleName, int32_t userId) = 0;
// 出参列表：无

// 带出参示例
virtual ErrCode GetCustomInfo(const std::string &bundleName, int32_t userId,
                              CustomInfo &info) = 0;
// 出参列表：info（需要在 Host 侧写入，Proxy 侧读取）

// Installs 进程
virtual ErrCode CleanSpecificDir(const std::string &targetDir)
{
    return ERR_OK;
}
// 出参列表：无
```

**重要提示**：
- **入参**: 在 Proxy 侧通过 `data.WriteXxx()` 写入，在 Host 侧通过 `data.ReadXxx()` 读取
- **出参**: 在 Host 侧通过 `reply.WriteXxx()` 写入，在 Proxy 侧通过 `reply.ReadXxx()` 读取
- **返回值**: 方法返回值（如 `ErrCode`）始终通过 `reply.WriteInt32()` 写入和读取

---

## 实现步骤详细指南

详细实现步骤请参考以下文档：

### Foundation 进程（SA 401）
- **用途**: 核心业务逻辑、Bundle 信息管理、权限控制
- **详细步骤**: [Foundation 进程步骤指南](references/foundation-steps.md)
- **涉及文件**（8个）:
  1. `interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_interface.h`
  2. `interfaces/inner_api/appexecfwk_core/include/bundle_framework_core_ipc_interface_code.h`
  3. `interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_proxy.h`
  4. `interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_mgr_proxy.cpp`
  5. `interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_host.h`
  6. `interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_mgr_host.cpp`
  7. `services/bundlemgr/include/bundle_mgr_host_impl.h`
  8. `services/bundlemgr/src/bundle_mgr_host_impl.cpp`

### Installs 进程（SA 511）
- **用途**: 特权文件操作、目录管理、底层操作
- **详细步骤**: [Installs 进程步骤指南](references/installs-steps.md)
- **涉及文件**（8个）:
  1. `services/bundlemgr/include/ipc/installd_interface.h`
  2. `services/bundlemgr/include/bundle_framework_services_ipc_interface_code.h`
  3. `services/bundlemgr/include/ipc/installd_proxy.h`
  4. `services/bundlemgr/src/ipc/installd_proxy.cpp`
  5. `services/bundlemgr/include/ipc/installd_host.h`
  6. `services/bundlemgr/src/ipc/installd_host.cpp`
  7. `services/bundlemgr/include/installd/installd_host_impl.h`
  8. `services/bundlemgr/src/installd/installd_host_impl.cpp`

**重要**: Installs 进程的所有方法都必须首先检查调用方是否为 foundation 进程

---

## 常见问题

### 如何选择进程？

- **Foundation 进程**: 用于业务逻辑、Bundle 信息查询、权限控制等
- **Installs 进程**: 用于文件操作、目录创建、文件提取等需要高权限的操作

### 接口代码编号冲突

查看对应进程的接口代码枚举文件，使用下一个未使用的编号。

### 参数序列化顺序错误

Proxy 的 `WriteXxx()` 顺序必须与 Host 的 `ReadXxx()` 顺序一致。

### 如何处理出参？

**出参**（输出参数）是指由 Host 侧写入、Proxy 侧读取的参数，区别于入参：

| 参数类型 | Proxy 侧操作 | Host 侧操作 |
|---------|-------------|-------------|
| 入参 | `data.WriteXxx()` 写入 | `data.ReadXxx()` 读取 |
| 出参 | `reply.ReadXxx()` 读取 | `reply.WriteXxx()` 写入 |
| 返回值 | `reply.ReadInt32()` 读取 | `reply.WriteInt32()` 写入 |

**关键点**：
- 出参必须在接口参数列表中明确列出
- 出参通常使用引用类型传递（如 `OutType &outParam`）
- 写入顺序：先写入方法返回值，再依次写入各个出参
- 读取顺序：与写入顺序严格一致

### Installs 进程权限检查

Installs 进程的所有方法都必须检查调用方是否为 foundation 进程，使用：
```cpp
InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)
```

## 参考资料

### 详细文档

- [Foundation 进程步骤指南](references/foundation-steps.md) - Foundation 进程详细实现步骤
- [Installs 进程步骤指南](references/installs-steps.md) - Installs 进程详细实现步骤
- [快速参考](references/quick-reference.md) - 常用代码片段和快速查找

### 现有方法示例

**Foundation 进程**:
参考 `bundle_mgr_interface.h` 中的 `GetJsonProfile`, `GetBundleStats` 等方法

**Installs 进程**:
参考 `installd_interface.h` 中的 `CreateBundleDir`, `GetBundleStats` 等方法
