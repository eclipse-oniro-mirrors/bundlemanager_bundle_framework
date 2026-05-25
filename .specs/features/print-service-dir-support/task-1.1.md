# 任务规格：TASK-1.1

> 在 InstalldService 中添加创建打印服务目录接口

## 任务信息

| 字段 | 值 |
|------|-----|
| 任务ID | TASK-1.1 |
| 任务名称 | InstalldService 添加创建打印服务目录接口 |
| 优先级 | P0 |
| 预估工时 | 4h |
| 状态 | Pending |
| 关联 AC | AC-1, AC-2, AC-3, AC-5 |

## 需求描述

在 InstalldService 中添加接口，用于创建驱动应用的打印服务专属目录，并设置正确的属主、属组和权限。

## 验收标准

| AC编号 | 验收标准 |
|--------|----------|
| AC-TASK-1.1-1 | WHEN 调用创建接口 THEN 创建 `/data/service/el1/<userId>/print_service/data/<bundleName>` 目录 |
| AC-TASK-1.1-2 | WHEN 创建目录 THEN 属主为应用 uid，属组为 3823 |
| AC-TASK-1.1-3 | WHEN 创建目录 THEN 权限为 2750 |
| AC-TASK-1.1-4 | WHEN 父目录不存在 THEN 返回 ERR_PRINT_SERVICE_PARENT_DIR_NOT_EXISTS |
| AC-TASK-1.1-5 | WHEN 目录创建成功 THEN 返回 ERR_OK |
| AC-TASK-1.1-6 | WHEN 目录创建失败 THEN 记录错误日志，返回相应错误码 |

## 实现要点

### 接口定义

```cpp
// installd_host.h / installd_proxy.h
ErrCode CreatePrintServiceDir(
    const std::string& bundleName,
    int32_t userId,
    int32_t appIndex,
    uid_t appUid
);
```

### 实现位置

- 头文件：`services/bundlemgr/include/ipc/install_hnp_param.h`（可能需要新建）
- 实现文件：`services/bundlemgr/src/ipc/installd_operator.cpp` 或 `installd_service.cpp`

### 伪代码逻辑

```cpp
ErrCode InstalldService::CreatePrintServiceDir(
    const std::string& bundleName, int32_t userId, int32_t appIndex, uid_t appUid)
{
    // 1. 构建目录路径
    std::string baseDir = "/data/service/el1/" + std::to_string(userId) + "/print_service/data";
    std::string bundleDir = baseDir + "/" + GetBundleDirName(bundleName, appIndex);

    // 2. 检查父目录是否存在
    if (!FileExists(baseDir)) {
        APP_LOGE("Print service base directory not exists: %{public}s", baseDir.c_str());
        return ERR_PRINT_SERVICE_PARENT_DIR_NOT_EXISTS;
    }

    // 3. 检查目录是否已存在
    if (FileExists(bundleDir)) {
        // 验证并修复权限
        VerifyAndFixPermission(bundleDir, appUid, 3823, 02750);
        return ERR_OK;
    }

    // 4. 创建目录
    if (mkdir(bundleDir.c_str(), 02750) != 0) {
        APP_LOGE("Failed to create print service dir: %{public}s, error: %{public}d",
            bundleDir.c_str(), errno);
        return ERR_PRINT_SERVICE_DIR_CREATE_FAILED;
    }

    // 5. 设置属主属组
    if (chown(bundleDir.c_str(), appUid, 3823) != 0) {
        APP_LOGE("Failed to chown print service dir: %{public}s, error: %{public}d",
            bundleDir.c_str(), errno);
        return ERR_PRINT_SERVICE_DIR_CHOWN_FAILED;
    }

    // 6. 设置权限（确保 sticky bit）
    if (chmod(bundleDir.c_str(), 02750) != 0) {
        APP_LOGE("Failed to chmod print service dir: %{public}s, error: %{public}d",
            bundleDir.c_str(), errno);
        return ERR_PRINT_SERVICE_DIR_CHMOD_FAILED;
    }

    return ERR_OK;
}

std::string GetBundleDirName(const std::string& bundleName, int32_t appIndex)
{
    if (appIndex == 0) {
        return bundleName;
    }
    return BundleCloneCommonHelper::GetCloneDataDir(bundleName, appIndex);
}
```

### 错误码定义

在 `interfaces/inner_api/appexecfwk_base/include/appexecfwk_errors.h` 中添加：

```cpp
// Print service directory errors
constexpr ErrCode APPEXECFWK_PRINT_SERVICE_DIR_BASE = ERR_APPEXECFWK_BUNDLEMGR_ERR_OFFSET + 0x0500;

enum {
    ERR_PRINT_SERVICE_PARENT_DIR_NOT_EXISTS = APPEXECFWK_PRINT_SERVICE_DIR_BASE + 1,
    ERR_PRINT_SERVICE_DIR_CREATE_FAILED = APPEXECFWK_PRINT_SERVICE_DIR_BASE + 2,
    ERR_PRINT_SERVICE_DIR_CHOWN_FAILED = APPEXECFWK_PRINT_SERVICE_DIR_BASE + 3,
    ERR_PRINT_SERVICE_DIR_CHMOD_FAILED = APPEXECFWK_PRINT_SERVICE_DIR_BASE + 4,
};
```

## 测试用例

| 用例ID | 描述 | 期望结果 |
|--------|------|----------|
| TC-1.1-1 | 正常创建目录 | 目录创建成功，权限正确 |
| TC-1.1-2 | 父目录不存在 | 返回 ERR_PRINT_SERVICE_PARENT_DIR_NOT_EXISTS |
| TC-1.1-3 | 目录已存在且权限正确 | 返回 ERR_OK，不重复创建 |
| TC-1.1-4 | 分身应用目录名 | 目录名格式为 +clone-{appIndex}+{bundleName} |

## 依赖文件

- `services/bundlemgr/include/inner_bundle_clone_common.h`
- `services/bundlemgr/src/installd/installd_service.cpp`
- `interfaces/inner_api/appexecfwk_base/include/appexecfwk_errors.h`
