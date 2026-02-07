# BundleManager Interface Guide Skill

## Description

提供 OpenHarmony BundleManager 添加新接口的完整指南，包括 Installd 层、服务层、IPC 层和 JS NAPI 层的实现步骤。

## Usage

使用以下命令调用此技能：

```bash
/bundle-interface-guide
```

或使用别名：

```bash/
/bm-guide
```

## What This Skill Provides

此技能提供：

1. **快速参考**：实现新接口需要的文件清单（约 20-24 个文件）
2. **完整实现流程**：从底层到 JS 层的详细步骤
3. **代码示例**：每个层次的实际代码示例
4. **关键注意事项**：接口码分配、IPC 通信、日志规范等
5. **编译指南**：需要编译的 SO 和编译命令
6. **测试指南**：单元测试、系统测试和 Fuzz 测试
7. **常见问题**：FAQ 和解决方案

## Implementation Layers

添加新接口需要修改以下层次：

1. **Installd 层** (8 个文件)
   - installd_operator.h/cpp - 底层系统调用
   - installd_interface.h - IPC 接口定义
   - installd_host_impl.h/cpp - 服务端实现
   - installd_proxy.h/cpp - 客户端代理
   - installd_client.h/cpp - 客户端封装
   - installd_host.cpp - IPC 消息处理
   - bundle_framework_services_ipc_interface_code.h - 接口码

2. **服务层** (4 个文件)
   - bundle_data_mgr.h/cpp - 核心业务逻辑
   - bundle_mgr_host_impl.h/cpp - 服务端实现

3. **IPC 层** (6 个文件)
   - bundle_mgr_interface.h - 接口定义
   - bundle_mgr_proxy.h/cpp - IPC 代理
   - bundle_framework_core_ipc_interface_code.h - 接口码

4. **JS 层** (4 个文件)
   - napi_constants.h - 常量定义
   - bundle_manager.h/cpp - NAPI 函数实现
   - native_module.cpp - 函数注册

5. **测试** (3+ 个文件)
   - 系统测试 (ST)
   - 模糊测试 (Fuzz)
   - 单元测试 (UT)

## Key Files Reference

### Documentation
- `docs/bundle_manager_interface_guide.md` - 完整指南文档

### Installd Layer
```
services/bundlemgr/include/installd/installd_operator.h
services/bundlemgr/src/installd/installd_operator.cpp
services/bundlemgr/include/ipc/installd_interface.h
services/bundlemgr/include/installd/installd_host_impl.h
services/bundlemgr/src/installd/installd_host_impl.cpp
services/bundlemgr/include/ipc/installd_proxy.h
services/bundlemgr/src/ipc/installd_proxy.cpp
services/bundlemgr/include/installd_client.h
services/bundlemgr/src/installd_client.cpp
services/bundlemgr/include/ipc/installd_host.h
services/bundlemgr/src/ipc/installd_host.cpp
services/bundlemgr/include/bundle_framework_services_ipc_interface_code.h
```

### Service Layer
```
services/bundlemgr/include/bundle_data_mgr.h
services/bundlemgr/src/bundle_data_mgr.cpp
services/bundlemgr/include/bundle_mgr_host_impl.h
services/bundlemgr/src/bundle_mgr_host_impl.cpp
```

### IPC Layer
```
interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_interface.h
interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_proxy.h
interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_mgr_proxy.cpp
interfaces/inner_api/appexecfwk_core/include/bundle_framework_core_ipc_interface_code.h
```

### JS Layer
```
interfaces/kits/js/common/napi_constants.h
interfaces/kits/js/bundle_manager/bundle_manager.h
interfaces/kits/js/bundle_manager/bundle_manager.cpp
interfaces/kits/js/bundle_manager/native_module.cpp
```

## Common Build Targets

```bash
# 完整编译 bundle_framework
./build.sh --product-name rk3568 --ccache --target-cpu arm --build-target bundle_framework/bundle_framework

# 只编译服务层
./build.sh --product-name rk3568 --ccache --target-cpu arm \
  --build-target //foundation/bundlemanager/bundle_framework/services/bundlemgr:bms_target

# 只编译客户端 API
./build.sh --product-name rk3568 --ccache --target-cpu arm \
  --build-target //foundation/bundlemanager/bundle_framework/interfaces/inner_api/appexecfwk_core:appexecfwk_core

# 只编译 JS NAPI 模块
./build.sh --product-name rk3568 --ccache --target-cpu arm \
  --build-target //foundation/bundlemanager/bundle_framework/interfaces/kits/js/bundle_manager:bundlemanager
```

## Important Notes

### Interface Code Assignment
⚠️ **必须将新接口码添加到枚举末尾！不要在中间插入！**

```cpp
// ❌ 错误：在中间插入
enum class InstalldInterfaceCode : uint32_t {
    GET_DISK_USAGE_FROM_PATH = 54,
    GET_INODE_COUNT_FROM_QUOTA = 55,  // 错误
    CREATE_DATA_GROUP_DIRS = 56,
    // ...
};

// ✅ 正确：添加到末尾
enum class InstalldInterfaceCode : uint32_t {
    GET_DISK_USAGE_FROM_PATH = 54,
    CREATE_DATA_GROUP_DIRS = 55,
    // ...
    STOP_SET_FILE_CON = 74,
    GET_INODE_COUNT_FROM_QUOTA = 75,  // 正确
};
```

### IPC Communication
- MessageParcel 写入和读取顺序必须一致
- 始终先写入 interface token
- 使用智能宏进行错误检查

### Thread Safety
- 使用 `std::shared_lock` 保护数据访问
- Installd Operator 使用递归锁 `std::lock_guard<std::recursive_mutex>`

### Permission Check
- Installd 层：只允许 foundation 进程调用
- BundleManager 层：使用 `IPCSkeleton::GetCallingUid()` 获取调用方 UID

## Example: GetBundleInodeCountForSelf

本指南基于实际实现的 `GetBundleInodeCountForSelf` 接口。相关实现可查看：

```bash
# 查看实现代码的 git 历史
git log --all --oneline --grep="inode"

# 查看相关文件修改
git log --all --oneline --follow -- services/bundlemgr/src/bundle_data_mgr.cpp
```

## Related Skills

- `/bms-structure` - 查看 BundleManager 代码结构
- `/bms-compile` - 编译 BundleManager 模块
- `/bms-test` - 运行 BundleManager 测试

## See Also

- OpenHarmony BundleManager 文档
- Installd 服务设计文档
- IPC 接口设计规范
- NAPI 开发指南
