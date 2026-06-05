# IPC 接口快速参考

本文档提供在 BundleManager 中添加 IPC 接口方法的常用代码片段和快速参考。

## 双进程架构速查

### Foundation 进程 (SA 401)

| 项目 | 内容 |
|------|------|
| 接口类 | `IBundleMgr` |
| 接口描述符 | `u"ohos.appexecfwk.BundleMgr"` |
| 接口文件 | `interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_interface.h` |
| Proxy 类定义 | `interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_proxy.h` |
| Host 类定义 | `interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_host.h` |
| Proxy 文件 | `interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_mgr_proxy.cpp` |
| Host 文件 | `services/bundlemgr/src/bundle_mgr_host.cpp` |
| 业务实现文件 | `services/bundlemgr/src/bundle_mgr_host_impl.cpp` |
| 业务实现头文件 | `services/bundlemgr/include/bundle_mgr_host_impl.h` |
| 接口代码文件 | `interfaces/inner_api/appexecfwk_core/include/bundle_framework_core_ipc_interface_code.h` |
| 用途 | 业务逻辑、权限控制、Bundle 信息管理 |

### Installs 进程 (SA 511)

| 项目 | 内容 |
|------|------|
| 接口类 | `IInstalld` |
| 接口描述符 | `u"ohos.appexecfwk.Installd"` |
| 接口文件 | `services/bundlemgr/include/ipc/installd_interface.h` |
| Host 类定义 | `services/bundlemgr/include/ipc/installd_host.h` |
| Proxy 头文件 | `services/bundlemgr/include/ipc/installd_proxy.h` |
| Proxy 文件 | `services/bundlemgr/src/ipc/installd_proxy.cpp` |
| Host 文件 | `services/bundlemgr/src/ipc/installd_host.cpp` |
| 业务实现文件 | `services/bundlemgr/src/installd/installd_host_impl.cpp` |
| 业务实现头文件 | `services/bundlemgr/include/installd/installd_host_impl.h` |
| 接口代码文件 | `services/bundlemgr/include/bundle_framework_services_ipc_interface_code.h` |
| 用途 | 文件操作、目录管理、特权操作 |
| 安全检查 | 必须验证调用方是否为 foundation 进程 |

## 进程选择决策表

| 功能类型 | 目标进程 | 原因 |
|---------|---------|------|
| Bundle 信息查询 | Foundation | 业务逻辑 |
| 权限验证 | Foundation | 需要权限系统 |
| 应用安装/卸载 | Foundation | 流程控制 |
| 创建/删除目录 | Installs | 需要文件系统权限 |
| 提取 HAP 文件 | Installs | 需要文件系统权限 |
| 设置文件权限 | Installs | 需要文件系统权限 |
| 获取磁盘使用量 | Installs | 需要访问文件系统 |

## 文件修改清单

### Foundation 进程

- [ ] `interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_interface.h` - 添加接口方法声明
- [ ] `interfaces/inner_api/appexecfwk_core/include/bundle_framework_core_ipc_interface_code.h` - 添加接口代码枚举
- [ ] `interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_proxy.h` - 添加 Proxy 方法声明
- [ ] `interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_mgr_proxy.cpp` - 实现 Proxy 方法
- [ ] `interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_host.h` - 添加 Handle 方法声明
- [ ] `services/bundlemgr/src/bundle_mgr_host.cpp` - 实现 Host case
- [ ] `services/bundlemgr/include/bundle_mgr_host_impl.h` - 添加方法声明
- [ ] `services/bundlemgr/src/bundle_mgr_host_impl.cpp` - 实现业务逻辑

### Installs 进程

- [ ] `services/bundlemgr/include/ipc/installd_interface.h` - 添加接口方法声明
- [ ] `services/bundlemgr/include/bundle_framework_services_ipc_interface_code.h` - 添加接口代码枚举
- [ ] `services/bundlemgr/include/ipc/installd_proxy.h` - 添加 Proxy 方法声明（虚函数）
- [ ] `services/bundlemgr/src/ipc/installd_proxy.cpp` - 实现 Proxy 方法
- [ ] `services/bundlemgr/include/ipc/installd_host.h` - 添加方法声明（如需要）
- [ ] `services/bundlemgr/src/ipc/installd_host.cpp` - 实现 Host case
- [ ] `services/bundlemgr/include/installd/installd_host_impl.h` - 添加方法声明
- [ ] `services/bundlemgr/src/installd/installd_host_impl.cpp` - 实现业务逻辑（必须包含 foundation 进程检查）

## MessageParcel 读写方法

### 基本类型

| C++ 类型 | 写入方法 | 读取方法 |
|---------|---------|---------|
| `int32_t` | `WriteInt32(v)` | `ReadInt32()` |
| `uint32_t` | `WriteUint32(v)` | `ReadUint32()` |
| `int64_t` | `WriteInt64(v)` | `ReadInt64()` |
| `uint64_t` | `WriteUint64(v)` | `ReadUint64()` |
| `bool` | `WriteBool(v)` | `ReadBool()` |
| `float` | `WriteFloat(v)` | `ReadFloat()` |
| `double` | `WriteDouble(v)` | `ReadDouble()` |

### 字符串

```cpp
// Foundation 进程
// 写入
data.WriteString(str);
// 读取
std::string str = Str16ToStr8(data.ReadString16());

// Installs 进程
INSTALLD_PARCEL_WRITE(data, String, str);
// 读取（手动）
std::string str = Str16ToStr8(data.ReadString16());
```

### 容器

```cpp
// vector<string>
data.WriteStringVector(vec);
data.ReadStringVector(&vec);

// vector<int32_t>
data.ReadInt32Vector(&vec);
data.WriteInt32Vector(vec);

// map
data.WriteStringStringMap(map);
data.ReadStringStringMap(&map);
```

### 自定义结构体

**方法 1**: Marshalling/Unmarshalling
```cpp
// 结构体实现
bool CustomStruct::Marshalling(Parcel &parcel) const {
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, field1);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, field2);
    return true;
}

bool CustomStruct::Unmarshalling(Parcel &parcel) {
    field1 = Str16ToStr8(parcel.ReadString16());
    field2 = parcel.ReadInt32();
    return true;
}

// 使用
obj.Marshall(reply);
CustomStruct obj;
obj.Unmarshalling(data);
```

**方法 2**: RawData
```cpp
// 写入
data.WriteRawData(&obj, sizeof(ObjectType));

// 读取
const char* ptr = reinterpret_cast<const char*>(data.ReadRawData(sizeof(ObjectType)));
if (ptr == nullptr) {
    return ERR_APPEXECFWK_IPC_READ_PARCEL_ERROR;
}
ObjectType obj = *reinterpret_cast<const ObjectType*>(ptr);
```

## 常用错误码

```cpp
// IPC 相关
ERR_APPEXECFWK_IPC_WRITE_PARCEL_ERROR        // 写入 MessageParcel 失败
ERR_APPEXECFWK_IPC_READ_PARCEL_ERROR         // 读取 MessageParcel 失败
ERR_APPEXECFWK_IPC_GET_REMOTE_OBJECT_FAILED  // 获取远程对象失败
ERR_APPEXECFWK_IPC_SEND_REQUEST_FAILED       // 发送请求失败

// 通用错误
ERR_OK                                       // 成功
ERR_APPEXECFWK_INVALID_PARAM                 // 无效参数
ERR_APPEXECFWK_PERMISSION_DENIED             // 权限被拒绝
ERR_APPEXECFWK_OPERATION_FAILED              // 操作失败

// Installs 进程错误
ERR_APPEXECFWK_INSTALLD_PARAM_ERROR           // Installs 参数错误
ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED    // Installs 权限被拒绝
```

## 日志输出

```cpp
// Foundation 进程
#include "app_log_wrapper.h"

APP_LOGD("debug: %{public}s", str.c_str());
APP_LOGI("info message");
APP_LOGW("warning: value=%{public}d", value);
APP_LOGE("error occurred: %{public}d", errorCode);

// Installs 进程
#include "installd_log.h"

LOG_D(BMS_TAG_INSTALLD, "debug: %{public}s", str.c_str());
LOG_I(BMS_TAG_INSTALLD, "info message");
LOG_W(BMS_TAG_INSTALLD, "warning: value=%{public}d", value);
LOG_E(BMS_TAG_INSTALLD, "error occurred: %{public}d", errorCode);
```

**注意：**
- 敏感信息使用 `%{private}`
- 公开信息使用 `%{public}`
- 字符串需要 `.c_str()`

## 权限检查

```cpp
// Foundation 进程 - 检查特定权限
bool BundleMgrHostImpl::VerifyCallingPermission(const std::string &permissionName)
{
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    return AccessTokenKit::VerifyAccessToken(tokenId, permissionName)
           == PERMISSION_GRANTED;
}

// Foundation 进程 - 检查是否为系统调用
bool BundleMgrHostImpl::IsSystemApiCall()
{
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto type = AccessTokenKit::GetTokenFlag(tokenId);
    return (type == ATokenTypeEnum::TOKEN_NATIVE) ||
           (type == ATokenTypeEnum::TOKEN_SHELL);
}

// 获取调用者信息
int32_t uid = IPCSkeleton::GetCallingUid();
int32_t pid = IPCSkeleton::GetCallingPid();

// Installs 进程 - 检查调用方是否为 foundation 进程
InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)
```

**注意**: Installs 进程通常只需要检查调用方是否为 foundation 进程，不需要其他权限检查。

## Installs 进程专用宏

```cpp
// installd_interface.h 中定义
#define INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(parcel, token)
#define INSTALLD_PARCEL_WRITE(parcel, type, value)

// 使用示例
INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, InstalldProxy::GetDescriptor());
INSTALLD_PARCEL_WRITE(data, String, bundleName);
INSTALLD_PARCEL_WRITE(data, Int32, userId);
```

## 常见问题

### 接口描述符不匹配

确保使用正确的描述符：
- Foundation: `u"ohos.appexecfwk.BundleMgr"`
- Installs: `u"ohos.appexecfwk.Installd"`

### 参数序列化顺序错误

Proxy 的 `WriteXxx()` 顺序必须与 Host 的 `ReadXxx()` 顺序一致。

### 接口代码编号冲突

查看对应进程的接口代码枚举文件，使用下一个未使用的编号。

### Installs 进程权限被拒绝

确保在 installd_host_impl.cpp 的方法开头添加了 foundation 进程检查：
```cpp
if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
    LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
    return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
}
```
