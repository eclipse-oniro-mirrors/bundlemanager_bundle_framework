# Foundation 进程 IPC 接口方法添加步骤指南

本文档详细说明了在 Foundation 进程中添加新 IPC 接口方法的完整流程。

## Foundation 进程架构

- **系统能力 ID**: SA 401
- **接口类**: `IBundleMgr`
- **接口描述符**: `u"ohos.appexecfwk.BundleMgr"`
- **用途**: 核心业务逻辑、Bundle 信息管理、权限控制

## 文件清单

需要修改的文件（共 8 个）：

1. `interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_interface.h` - 接口方法声明
2. `interfaces/inner_api/appexecfwk_core/include/bundle_framework_core_ipc_interface_code.h` - 接口代码枚举
3. `interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_proxy.h` - Proxy 类定义
4. `interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_mgr_proxy.cpp` - Proxy 实现
5. `interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_host.h` - Host 类定义
6. `interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_mgr_host.cpp` - Host case 处理
7. `services/bundlemgr/include/bundle_mgr_host_impl.h` - 业务实现类定义
8. `services/bundlemgr/src/bundle_mgr_host_impl.cpp` - 业务逻辑实现

## 完整实现步骤

### 第二步：添加接口方法声明

**文件**: `interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_interface.h`

在 `IBundleMgr` 类中添加方法声明：

```cpp
class IBundleMgr : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.BundleMgr");

    // ... 现有方法

    /**
     * @brief 获取自定义 Bundle 信息
     * @param bundleName Bundle 名称
     * @param userId 用户 ID
     * @param customInfo 输出参数，自定义信息
     * @return 成功返回 ERR_OK，失败返回错误码
     */
    virtual ErrCode GetCustomBundleInfo(const std::string &bundleName,
        int32_t userId, CustomInfo &customInfo) = 0;
};
```

### 第三步：添加接口代码枚举

**文件**: `interfaces/inner_api/appexecfwk_core/include/bundle_framework_core_ipc_interface_code.h`

查看现有枚举值，使用下一个未使用的编号：

```cpp
enum class BundleMgrInterfaceCode : uint32_t {
    // ... 现有代码
    GET_BUNDLE_INSTALL_STATUS = 211,
    GET_ALL_JSON_PROFILE = 212,
    GET_BUNDLE_INFO_FOR_EXCEPTION = 213,
    BATCH_GET_COMPATIBLED_DEVICE_TYPE = 214,
    GET_ALL_APP_PROVISION_INFO = 215,
    ADD_DYNAMIC_SHORTCUT_INFOS = 216,
    DELETE_DYNAMIC_SHORTCUT_INFOS = 217,
    GET_ASSET_GROUPS_INFOS_BY_UID = 218,
    SET_SHORTCUTS_ENABLED = 219,
    GET_PLUGIN_EXTENSION_INFO = 220,
    AUTO_CLEAN_CACHE_BY_INODE = 221,
    GET_ALL_APP_INSTALL_EXTENSION_INFO = 222,
    IS_APPLICATION_DISABLE_FORBIDDEN = 223,
    GET_CUSTOM_BUNDLE_INFO = 224,  // 新增 - 使用下一个可用的编号
};
```

### 第四步：实现 Proxy

#### 4.1 在 bundle_mgr_proxy.h 中添加方法声明

**文件**: `interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_proxy.h`

```cpp
class BundleMgrProxy : public IRemoteProxy<IBundleMgr> {
public:
    explicit BundleMgrProxy(const sptr<IRemoteObject> &impl);
    virtual ~BundleMgrProxy() override;

    // ... 现有方法声明

    // 新增方法
    ErrCode GetCustomBundleInfo(const std::string &bundleName,
        int32_t userId, CustomInfo &customInfo) override;
};
```

#### 4.2 在 bundle_mgr_proxy.cpp 中实现方法

**文件**: `interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_mgr_proxy.cpp`

**推荐使用已定义的模板方法**：
- `SendTransactCmd` - 通用 IPC 请求发送方法（最常用）
- `SendTransactCmdWithLogErrCode` - 发送请求并记录错误码
- `GetParcelableInfo` - 获取单个 Parcelable 对象
- `GetVectorFromParcelIntelligent` - 获取对象向量

```cpp
ErrCode BundleMgrProxy::GetCustomBundleInfo(const std::string &bundleName,
    int32_t userId, CustomInfo &customInfo)
{
    APP_LOGD("call GetCustomBundleInfo, bundleName: %{public}s, userId: %{public}d",
              bundleName.c_str(), userId);

    MessageParcel data;

    // 1. 写入接口令牌
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    // 2. 写入参数
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to write bundleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to write userId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    // 3. 使用 GetParcelableInfoWithErrCode 发送请求并获取结果
    return GetParcelableInfoWithErrCode<CustomInfo>(
        BundleMgrInterfaceCode::GET_CUSTOM_BUNDLE_INFO, data, customInfo);
}
```

### 第五步：实现 Host

#### 5.1 在 bundle_mgr_host.h 中添加 Handle 方法声明（如需要）

**文件**: `interfaces/inner_api/appexecfwk_core/include/bundlemgr/bundle_mgr_host.h`

```cpp
class BundleMgrHost : public IRemoteStub<IBundleMgr> {
private:
    /**
     * @brief Handles GetCustomBundleInfo function called from a IBundleMgr proxy object.
     * @param data Indicates data to be read.
     * @param reply Indicates reply to be sent;
     * @return Returns ERR_OK if called successfully; returns error code otherwise.
     */
    ErrCode HandleGetCustomBundleInfo(MessageParcel &data, MessageParcel &reply);
};
```

#### 5.2 在 bundle_mgr_host.cpp 中实现 Handle 方法

**文件**: `interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_mgr_host.cpp`

实现 Handle 方法来处理 IPC 请求，在该方法中完成 data 读取、调用业务逻辑、reply 写入：

```cpp
ErrCode BundleMgrHost::HandleGetCustomBundleInfo(MessageParcel &data, MessageParcel &reply)
{
    // 1. 从 data 中读取参数
    std::string bundleName = Str16ToStr8(data.ReadString16());
    int32_t userId = data.ReadInt32();

    // 2. 调用业务逻辑方法
    CustomInfo customInfo;
    ErrCode result = GetCustomBundleInfo(bundleName, userId, customInfo);

    // 3. 将返回值和输出参数写入 reply
    if (!reply.WriteInt32(result)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (result == ERR_OK) {
        if (!reply.WriteParcelable(&customInfo)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    return ERR_OK;
}
```

#### 5.3 在 bundle_mgr_host.cpp 的 OnRemoteRequest 中添加 case 处理

**文件**: `interfaces/inner_api/appexecfwk_core/src/bundlemgr/bundle_mgr_host.cpp`

```cpp
int BundleMgrHost::OnRemoteRequest(uint32_t code, MessageParcel &data,
                                   MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    APP_LOGD("bundle mgr host received message, code: %{public}u", code);

    // 验证接口描述符
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        APP_LOGE("descriptor verification failed");
        return OBJECT_NULL;
    }

    ErrCode errCode = ERR_OK;
    switch (code) {
        // ... 现有 case

        // 新增 case 处理
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_CUSTOM_BUNDLE_INFO): {
            errCode = HandleGetCustomBundleInfo(data, reply);
            break;
        }

        // ... 其他 case
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return errCode;
}
```

#### 5.4 在 bundle_mgr_host_impl.h 中添加方法声明

**文件**: `services/bundlemgr/include/bundle_mgr_host_impl.h`

```cpp
class BundleMgrHostImpl : public BundleMgrHost {
public:
    // ... 现有方法声明

    // 新增方法声明
    ErrCode GetCustomBundleInfo(const std::string &bundleName,
        int32_t userId, CustomInfo &customInfo) override;
};
```

#### 5.5 在 bundle_mgr_host_impl.cpp 中实现业务逻辑

**文件**: `services/bundlemgr/src/bundle_mgr_host_impl.cpp`

```cpp
ErrCode BundleMgrHostImpl::GetCustomBundleInfo(const std::string &bundleName,
    int32_t userId, CustomInfo &customInfo)
{
    APP_LOGI("GetCustomBundleInfo called, bundleName: %{public}s, userId: %{public}d",
              bundleName.c_str(), userId);

    // 1. 权限检查（可选）
    if (!VerifyCallingPermission("ohos.permission.GET_BUNDLE_INFO")) {
        APP_LOGE("permission verification failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }

    // 2. 参数验证
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_APPEXECFWK_INVALID_PARAM;
    }

    if (userId < 0) {
        APP_LOGE("invalid userId: %{public}d", userId);
        return ERR_APPEXECFWK_INVALID_PARAM;
    }

    // 3. 业务逻辑实现 - 由用户根据实际需求实现
    // TODO: 在此处实现具体的业务逻辑
    // 示例：查询数据库、调用其他服务、计算结果等

    return ERR_OK;
}
```

## 参考示例

参考 `bundle_mgr_interface.h` 中的现有方法：

- `GetBundleInfo` - 获取 Bundle 信息
- `GetApplicationInfo` - 获取应用信息
- `GetJsonProfile` - 查询配置文件信息

这些方法的完整实现分布在以下文件中：
- `bundle_mgr_interface.h` - 接口定义
- `bundle_mgr_proxy.h/cpp` - Proxy 实现
- `bundle_mgr_host.cpp` - Host case 处理
- `bundle_mgr_host_impl.cpp` - 业务逻辑实现
