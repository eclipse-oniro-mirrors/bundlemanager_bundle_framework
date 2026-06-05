# Installs 进程 IPC 接口方法添加步骤指南

本文档详细说明了在 Installs 进程中添加新 IPC 接口方法的完整流程。

## Installs 进程架构

- **系统能力 ID**: SA 511
- **接口类**: `IInstalld`
- **接口描述符**: `u"ohos.appexecfwk.Installd"`
- **用途**: 特权文件操作、目录管理、底层操作
- **安全机制**: 必须验证调用方是否为 foundation 进程

## 文件清单

需要修改的文件（共 8 个）：

1. `services/bundlemgr/include/ipc/installd_interface.h` - 接口方法声明
2. `services/bundlemgr/include/bundle_framework_services_ipc_interface_code.h` - 接口代码枚举
3. `services/bundlemgr/include/ipc/installd_proxy.h` - Proxy 类定义
4. `services/bundlemgr/src/ipc/installd_proxy.cpp` - Proxy 实现
5. `services/bundlemgr/include/ipc/installd_host.h` - Host 类定义
6. `services/bundlemgr/src/ipc/installd_host.cpp` - Host case 处理
7. `services/bundlemgr/include/installd/installd_host_impl.h` - 业务实现类定义
8. `services/bundlemgr/src/installd/installd_host_impl.cpp` - 业务逻辑实现（必须包含 foundation 进程检查）

## 完整实现步骤

### 第二步：添加接口方法声明

**文件**: `services/bundlemgr/include/ipc/installd_interface.h`

在 `IInstalld` 类中添加方法声明：

```cpp
class IInstalld : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.Installd");

    // ... 现有方法

    /**
     * @brief 清理特定目录
     * @param targetDir 目标目录路径
     * @param cleanOptions 清理选项
     * @return 成功返回 ERR_OK，失败返回错误码
     */
    virtual ErrCode CleanSpecificDir(const std::string &targetDir,
        const CleanOptions &cleanOptions)
    {
        return ERR_OK;
    }
};
```

**注意**: `IInstalld` 中的方法提供默认实现 `return ERR_OK;`

### 第三步：添加接口代码枚举

**文件**: `services/bundlemgr/include/bundle_framework_services_ipc_interface_code.h`

查看现有枚举值，使用下一个未使用的编号：

```cpp
enum class InstalldInterfaceCode : uint32_t {
    CREATE_BUNDLE_DIR = 1,
    EXTRACT_MODULE_FILES = 2,
    // ... 现有代码
    CLEAR_DIR = 95,
    RESTORECON_PATH = 96,
    RESET_BMS_DB_SECURITY = 97,
    COPY_DIR = 98,
    DELETE_CERT_AND_REMOVE_KEY = 99,
    CLEAN_SPECIFIC_DIR = 100,  // 新增 - 使用下一个可用的编号
};
```

### 第四步：实现 Proxy

#### 4.1 在 installd_proxy.h 中添加方法声明（如需要）

**文件**: `services/bundlemgr/include/ipc/installd_proxy.h`

```cpp
class InstalldProxy : public IRemoteProxy<IInstalld> {
public:
    explicit InstalldProxy(const sptr<IRemoteObject> &impl);
    virtual ~InstalldProxy() override;

    // ... 现有方法声明

    // 新增方法
    ErrCode CleanSpecificDir(const std::string &targetDir,
        const CleanOptions &cleanOptions) override;
};
```

#### 4.2 在 installd_proxy.cpp 中实现方法

**文件**: `services/bundlemgr/src/ipc/installd_proxy.cpp`

**推荐使用已定义的模板方法**：
- `TransactInstalldCmd` - Installd IPC 请求发送方法

```cpp
ErrCode InstalldProxy::CleanSpecificDir(const std::string &targetDir,
    const CleanOptions &cleanOptions)
{
    LOG_D(BMS_TAG_INSTALLD, "call CleanSpecificDir, targetDir: %{public}s", targetDir.c_str());

    MessageParcel data;
    INSTALLD_PARCEL_WRITE_INTERFACE_TOKEN(data, (GetDescriptor()));
    INSTALLD_PARCEL_WRITE(data, String, targetDir);

    // 写入复杂参数
    if (!data.WriteRawData(&cleanOptions, sizeof(CleanOptions))) {
        LOG_E(BMS_TAG_INSTALLD, "fail to write cleanOptions");
        return ERR_APPEXECFWK_IPC_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    return TransactInstalldCmd(InstalldInterfaceCode::CLEAN_SPECIFIC_DIR, data, reply, option);
}
```

**TransactInstalldCmd 封装了以下操作**：
- Remote() 对象检查
- SendRequest 调用
- 错误处理
- 返回值读取

### 第五步：实现 Host

#### 5.1 在 installd_host.h 中添加 Handle 方法声明（如需要）

**文件**: `services/bundlemgr/include/ipc/installd_host.h`

```cpp
class InstalldHost : public IRemoteStub<IInstalld> {
private:
    /**
     * @brief Handles CleanSpecificDir function called from a IInstalld proxy object.
     * @param data Indicates data to be read.
     * @param reply Indicates reply to be sent;
     * @return Returns true if called successfully; returns false otherwise.
     */
    bool HandleCleanSpecificDir(MessageParcel &data, MessageParcel &reply);
};
```

#### 5.2 在 installd_host.cpp 中实现 Handle 方法

**文件**: `services/bundlemgr/src/ipc/installd_host.cpp`

实现 Handle 方法来处理 IPC 请求，在该方法中完成 data 读取、调用业务逻辑、reply 写入：

```cpp
bool InstalldHost::HandleCleanSpecificDir(MessageParcel &data, MessageParcel &reply)
{
    // 1. 从 data 中读取参数
    std::string targetDir = Str16ToStr8(data.ReadString16());

    CleanOptions cleanOptions;
    const char* dataPtr = reinterpret_cast<const char*>(data.ReadRawData(sizeof(CleanOptions)));
    if (dataPtr == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "fail to read cleanOptions");
        reply.WriteInt32(ERR_APPEXECFWK_IPC_READ_PARCEL_ERROR);
        return false;
    }
    cleanOptions = *reinterpret_cast<const CleanOptions*>(dataPtr);

    // 2. 调用业务逻辑方法
    ErrCode result = CleanSpecificDir(targetDir, cleanOptions);

    // 3. 将返回值写入 reply
    if (!reply.WriteInt32(result)) {
        LOG_E(BMS_TAG_INSTALLD, "fail to write result");
        return false;
    }

    return true;
}
```

#### 5.3 在 installd_host.cpp 的 OnRemoteRequest 中添加 case

**文件**: `services/bundlemgr/src/ipc/installd_host.cpp`

```cpp
int InstalldHost::OnRemoteRequest(uint32_t code, MessageParcel &data,
                                  MessageParcel &reply, MessageOption &option)
{
    std::u16string descriptor = InstalldHost::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        LOG_E(BMS_TAG_INSTALLD, "InstalldHost::OnRemoteRequest descriptor verification failed");
        return OBJECT_NULL;
    }

    bool ret = false;
    switch (code) {
        // ... 现有 case

        // 新增 case 处理
        case static_cast<uint32_t>(InstalldInterfaceCode::CLEAN_SPECIFIC_DIR): {
            ret = HandleCleanSpecificDir(data, reply);
            break;
        }

        // ... 其他 case
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return ret ? NO_ERROR : ERR_NULL;
}
```

#### 5.4 在 installd_host_impl.h 中添加方法声明

**文件**: `services/bundlemgr/include/installd/installd_host_impl.h`

```cpp
class InstalldHostImpl : public InstalldHost {
public:
    // ... 现有方法声明

    // 新增方法声明
    ErrCode CleanSpecificDir(const std::string &targetDir,
        const CleanOptions &cleanOptions) override;
};
```

#### 5.5 在 installd_host_impl.cpp 中实现业务逻辑

**文件**: `services/bundlemgr/src/installd/installd_host_impl.cpp`

```cpp
ErrCode InstalldHostImpl::CleanSpecificDir(const std::string &targetDir,
    const CleanOptions &cleanOptions)
{
    // 1. 检查调用方是否为 foundation 进程（必须）
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    // 2. 参数验证
    if (targetDir.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "targetDir is empty");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    // 3. 业务逻辑实现 - 由用户根据实际需求实现
    // TODO: 在此处实现具体的业务逻辑
    // 示例：文件/目录操作、调用系统服务等

    return ERR_OK;
}
```

**重要**: Installs 进程的所有方法都必须首先检查调用方是否为 foundation 进程：
```cpp
if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
    LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
    return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
}
```

## 参考示例

参考 `installd_interface.h` 中的现有方法：

- `CreateBundleDir` - 创建 Bundle 目录
- `ExtractFiles` - 提取文件
- `RemoveBundleDataDir` - 删除 Bundle 数据目录
- `SetDirApl` - 设置目录 APL

这些方法的完整实现分布在以下文件中：
- `installd_interface.h` - 接口定义
- `installd_proxy.h/cpp` - Proxy 实现
- `installd_host.cpp` - Host case 处理
- `installd_host_impl.cpp` - 业务逻辑实现
