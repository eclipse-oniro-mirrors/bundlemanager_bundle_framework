# Installs 进程 IPC 步骤指南

> 本文档是 [bms-add-ipc](../bms-add-ipc/references/installs-steps.md) 中 Installs 进程 IPC 步骤的副本，供 installd 接口下沉重构 skill 独立参考。

## 文件清单

Installs 进程添加新方法需要修改 8 个文件：

1. `services/bundlemgr/include/ipc/installd_interface.h` — 接口方法声明
2. `services/bundlemgr/include/bundle_framework_services_ipc_interface_code.h` — 接口代码枚举
3. `services/bundlemgr/include/ipc/installd_proxy.h` — Proxy 类声明
4. `services/bundlemgr/src/ipc/installd_proxy.cpp` — Proxy 实现
5. `services/bundlemgr/include/ipc/installd_host.h` — Host Handle 声明
6. `services/bundlemgr/src/ipc/installd_host.cpp` — Host case + Handle 实现
7. `services/bundlemgr/include/installd/installd_host_impl.h` — HostImpl 声明
8. `services/bundlemgr/src/installd/installd_host_impl.cpp` — 业务逻辑实现

## 步骤 1：接口代码枚举

**文件**: `include/bundle_framework_services_ipc_interface_code.h`

使用下一个未使用的编号：

```cpp
enum class InstalldInterfaceCode : uint32_t {
    // ... 现有代码
    GET_CACHE_DISK_USAGE_FROM_PATH = 83,
    NEW_METHOD = 84,  // 新增
};
```

## 步骤 2：接口方法声明

**文件**: `include/ipc/installd_interface.h`

```cpp
/**
 * @brief 方法功能描述
 * @param param1 参数说明
 * @return Returns ERR_OK if successful; returns error code otherwise.
 */
virtual ErrCode NewMethod(const std::string &param1, int32_t param2, bool param3)
{
    return ERR_OK;
}
```

注意：`IInstalld` 中的方法提供默认实现 `return ERR_OK;`。

## 步骤 3：Proxy 声明

**文件**: `include/ipc/installd_proxy.h`

```cpp
virtual ErrCode NewMethod(const std::string &param1, int32_t param2, bool param3) override;
```

## 步骤 4：Proxy 实现

**文件**: `src/ipc/installd_proxy.cpp`

```cpp
ErrCode InstalldProxy::NewMethod(const std::string &param1, int32_t param2, bool param3)
{
    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String16, Str8ToStr16(param1));
    INSTALLD_PARCEL_WRITE(data, Int32, param2);
    INSTALLD_PARCEL_WRITE(data, Bool, param3);

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::NEW_METHOD, data, reply, option);
}
```

**写入顺序必须与 Host 读取顺序完全一致**。

## 步骤 5：Host 声明

**文件**: `include/ipc/installd_host.h`

```cpp
bool HandleNewMethod(MessageParcel &data, MessageParcel &reply);
```

## 步骤 6：Host 实现

**文件**: `src/ipc/installd_host.cpp`

### 6.1 OnRemoteRequest switch case

```cpp
case static_cast<uint32_t>(InstalldInterfaceCode::NEW_METHOD):
    result = this->HandleNewMethod(data, reply);
    break;
```

### 6.2 Handle 方法

```cpp
bool InstalldHost::HandleNewMethod(MessageParcel &data, MessageParcel &reply)
{
    std::string param1 = Str16ToStr8(data.ReadString16());
    int32_t param2 = data.ReadInt32();
    bool param3 = data.ReadBool();

    ErrCode result = NewMethod(param1, param2, param3);
    WRITE_PARCEL_ERRCODE_ERRNO_RETURN_FALSE_IF_FAIL(Int32, reply, result);
    return true;
}
```

## 步骤 7：HostImpl 声明

**文件**: `include/installd/installd_host_impl.h`

```cpp
virtual ErrCode NewMethod(const std::string &param1, int32_t param2, bool param3) override;
```

## 步骤 8：HostImpl 实现

**文件**: `src/installd/installd_host_impl.cpp`

```cpp
ErrCode InstalldHostImpl::NewMethod(const std::string &param1, int32_t param2, bool param3)
{
    // 权限校验（必须）
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    // 参数校验
    if (param1.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "param1 is empty");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    // 业务逻辑
    // ...

    return ERR_OK;
}
```

## 平铺参数 vs Parcelable struct

- **平铺参数**（推荐）：参数 ≤ 8 个时使用，参考 `ExtractModuleFiles`（6 参数）、`ExtractDiffFiles`（3 参数）
- **Parcelable struct**：参数较多或复杂时使用，参考 `ExtractFiles`（使用 `ExtractParam`）
