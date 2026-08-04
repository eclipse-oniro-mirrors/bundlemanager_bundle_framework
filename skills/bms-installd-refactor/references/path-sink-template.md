# 路径下沉模板与校验

## InstalldHostImpl 路径下沉完整模板

```cpp
ErrCode InstalldHostImpl::NewMethod(
    const std::string &bundleName,           // 标识符：包名
    const std::string &externalFilePath,      // 外部输入：源文件路径（保留）
    const std::string &metadataField,         // 元数据：相对路径（保留，不下沉）
    const std::string &cpuAbi,                // 元数据：CPU ABI（保留，不下沉）
    bool isReplace,                           // 标识符：模式标志
    int32_t versionCode,                      // 标识符：版本号
    const std::string &targetPathSuffix)      // 标识符：可选的路径后缀
{
    // === 1. 权限校验（必须，不可省略） ===
    if (!InstalldPermissionMgr::VerifyCallingPermission(Constants::FOUNDATION_UID)) {
        LOG_E(BMS_TAG_INSTALLD, "installd permission denied, only used for foundation process");
        return ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED;
    }

    // === 2. 包名校验 ===
    if (!InstalldOperator::IsValidBundleName(bundleName)) {
        LOG_E(BMS_TAG_INSTALLD, "invalid bundleName");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    // === 3. 外部输入和元数据非空校验 ===
    // externalFilePath 和 metadataField 是外部输入/元数据，必须非空
    // bundleName 和 versionCode 是标识符，由调用方保证有效性
    if (externalFilePath.empty() || metadataField.empty() || cpuAbi.empty()) {
        LOG_E(BMS_TAG_INSTALLD, "required param is empty");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    // === 4. 路径构造（从 BMS 下沉的核心逻辑） ===
    // 此处替换为实际的路径构造逻辑，使用标识符 + 已知常量
    std::string basePath = std::string(Constants::BUNDLE_CODE_DIR) +
        ServiceConstants::PATH_SEPARATOR + bundleName + ServiceConstants::PATH_SEPARATOR;

    std::string workDir;
    if (isReplace) {
        workDir = basePath;
    } else if (!targetPathSuffix.empty()) {
        workDir = basePath + "patch/" + targetPathSuffix + "/";
    } else {
        workDir = basePath + "patch_" + std::to_string(versionCode) + "/";
    }

    // 构造最终目标路径
    std::string targetPath = workDir + metadataField;

    // === 5. 路径前缀校验 ===
    // 确保构造出的路径在允许的前缀范围内
    if (!InstalldOperator::IsValidPathByBundleDirScene(
            BundleDirScene::EXTRACT_FILES, targetPath)) {
        LOG_E(BMS_TAG_INSTALLD, "invalid targetPath prefix");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    // === 6. 委托给现有 operator ===
    ExtractParam extractParam;
    extractParam.bundleName = bundleName;
    extractParam.extractFileType = ExtractFileType::SO;
    extractParam.srcPath = externalFilePath;
    extractParam.targetPath = targetPath;
    extractParam.cpuAbi = cpuAbi;
    extractParam.needRemoveOld = isReplace;

    if (!InstalldOperator::ExtractFiles(extractParam)) {
        LOG_E(BMS_TAG_INSTALLD, "extract failed, errno:%{public}d", errno);
        return ERR_APPEXECFWK_INSTALLD_EXTRACT_FAILED;
    }
    return ERR_OK;
}
```

## Client 校验模板

```cpp
ErrCode InstalldClient::NewMethod(
    const std::string &bundleName, const std::string &externalFilePath,
    const std::string &metadataField, const std::string &cpuAbi,
    bool isReplace, int32_t versionCode, const std::string &targetPathSuffix)
{
    // 仅校验非标识符参数（外部输入和元数据）
    if (externalFilePath.empty() || metadataField.empty() || cpuAbi.empty()) {
        APP_LOGE("required param is empty");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    return CallService(&IInstalld::NewMethod, bundleName, externalFilePath,
        metadataField, cpuAbi, isReplace, versionCode, targetPathSuffix);
}
```

## BMS 调用方简化模板

```cpp
// === 旧代码（删除） ===
// std::string finalPath = workDir + ServiceConstants::PATH_SEPARATOR + metadataField;
// ExtractParam extractParam;
// extractParam.bundleName = bundleInfo.name;
// extractParam.extractFileType = ExtractFileType::SO;
// extractParam.srcPath = externalFilePath;
// extractParam.targetPath = finalPath;
// extractParam.cpuAbi = cpuAbi;
// extractParam.needRemoveOld = isReplace;
// if (InstalldClient::GetInstance()->ExtractFiles(extractParam) != ERR_OK) {
//     LOG_W(TAG, "extract failed");
//     continue;
// }

// === 新代码 ===
if (InstalldClient::GetInstance()->NewMethod(bundleInfo.name, externalFilePath,
    metadataField, cpuAbi, isReplace, versionCode, targetPathSuffix) != ERR_OK) {
    LOG_W(TAG, "extract failed");
    continue;
}
```

## Mock 文件模板

```cpp
// test/mock/src/installd_client.cpp
ErrCode InstalldClient::NewMethod(
    const std::string &bundleName, const std::string &externalFilePath,
    const std::string &metadataField, const std::string &cpuAbi,
    bool isReplace, int32_t versionCode, const std::string &targetPathSuffix)
{
    if (externalFilePath.empty() || metadataField.empty() || cpuAbi.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    return CallService(&IInstalld::NewMethod, bundleName, externalFilePath,
        metadataField, cpuAbi, isReplace, versionCode, targetPathSuffix);
}
```

```cpp
// test/mock/src/mock_install_client.cpp
ErrCode InstalldClient::NewMethod(
    const std::string &bundleName, const std::string &externalFilePath,
    const std::string &metadataField, const std::string &cpuAbi,
    bool isReplace, int32_t versionCode, const std::string &targetPathSuffix)
{
    return 0;
}
```

```cpp
// test/mock/src/mock_installd_host_impl.cpp
ErrCode InstalldHostImpl::NewMethod(
    const std::string &bundleName, const std::string &externalFilePath,
    const std::string &metadataField, const std::string &cpuAbi,
    bool isReplace, int32_t versionCode, const std::string &targetPathSuffix)
{
    return ERR_OK;
}
```

## 路径构造常见模式

### 模式 1：固定前缀 + bundleName

```cpp
// 路径模式：BUNDLE_CODE_DIR/{bundleName}/subdir
std::string path = std::string(Constants::BUNDLE_CODE_DIR) +
    ServiceConstants::PATH_SEPARATOR + bundleName + ServiceConstants::PATH_SEPARATOR + "subdir";
```

### 模式 2：Replace/Patch 分支

```cpp
// 路径模式：
//   Replace: BUNDLE_CODE_DIR/{bundleName}/
//   Patch:   BUNDLE_CODE_DIR/{bundleName}/patch/{suffix}/ 或 .../patch_{versionCode}/
if (isReplace) {
    dir = basePath;
} else if (!suffix.empty()) {
    dir = basePath + "patch/" + suffix + "/";
} else {
    dir = basePath + "patch_" + std::to_string(versionCode) + "/";
}
```

### 模式 3：HotReload 路径

```cpp
// 路径模式：BUNDLE_CODE_DIR/{bundleName}/hotreload_{versionCode}/
dir = basePath + "hotreload_" + std::to_string(versionCode) + "/";
```

## 校验层级总结

| 层级 | 校验内容 | 不可省略 |
|---|---|---|
| InstalldClient | 外部输入/元数据非空 | ❌ 可调整 |
| InstalldHostImpl | `VerifyCallingPermission(FOUNDATION_UID)` | ✅ 必须 |
| InstalldHostImpl | `IsValidBundleName` | ✅ 推荐 |
| InstalldHostImpl | `IsValidPathByBundleDirScene` | ✅ 必须 |
| InstalldOperator | 内部 `ExtractFiles` 校验 | ✅ 自动 |
