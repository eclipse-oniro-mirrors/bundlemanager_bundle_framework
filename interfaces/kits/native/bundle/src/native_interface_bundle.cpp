/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "native_interface_bundle.h"

#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "application_info.h"
#include "bundle_info.h"
#include "app_log_wrapper.h"
#include "bundle_mgr_proxy_native.h"
#include "ipc_skeleton.h"
#include "securec.h"
namespace {
const size_t CHAR_MIN_LENGTH = 1;
const size_t CHAR_MAX_LENGTH = 10240;
const size_t MAX_ALLOWED_SIZE = 1024 * 1024;
const size_t ARRAY_MAX_LENGTH = 1024;
}

// Helper function to release char* memory
static void ReleaseMemory(char* &str)
{
    if (str != nullptr) {
        free(str);
        str = nullptr;
    }
}

template <typename... Args>
void ReleaseStrings(Args... args)
{
    (ReleaseMemory(args), ...);
}

bool CopyStringToChar(char* &name, const std::string &value)
{
    size_t length = value.size();
    if ((length == 0) || (length + 1) > CHAR_MAX_LENGTH) {
        APP_LOGE("failed due to the length of value is empty or too long");
        return false;
    }
    name = static_cast<char*>(malloc(length + 1));
    if (name == nullptr) {
        APP_LOGE("failed due to malloc error");
        return false;
    }
    if (strcpy_s(name, length + 1, value.c_str()) != EOK) {
        APP_LOGE("failed due to strcpy_s error");
        ReleaseStrings(name);
        return false;
    }
    return true;
}

bool GetElementNameByAbilityInfo(
    const OHOS::AppExecFwk::AbilityInfo &abilityInfo, OH_NativeBundle_ElementName &elementName)
{
    if (!CopyStringToChar(elementName.bundleName, abilityInfo.bundleName)) {
        APP_LOGE("failed to obtains bundleName");
        return false;
    }

    if (!CopyStringToChar(elementName.moduleName, abilityInfo.moduleName)) {
        APP_LOGE("failed to obtains moduleName");
        ReleaseStrings(elementName.bundleName);
        return false;
    }

    if (!CopyStringToChar(elementName.abilityName, abilityInfo.name)) {
        APP_LOGE("failed to obtains abilityName");
        ReleaseStrings(elementName.bundleName, elementName.moduleName);
        return false;
    }
    return true;
}

bool GetElementNameByModuleInfo(
    const OHOS::AppExecFwk::HapModuleInfo &hapModuleInfo, OH_NativeBundle_ElementName &elementName)
{
    for (const auto &abilityInfo : hapModuleInfo.abilityInfos) {
        if (abilityInfo.name.compare(hapModuleInfo.mainElementName) == 0) {
            return GetElementNameByAbilityInfo(abilityInfo, elementName);
        }
    }
    return false;
}

OH_NativeBundle_ApplicationInfo OH_NativeBundle_GetCurrentApplicationInfo()
{
    OH_NativeBundle_ApplicationInfo nativeApplicationInfo;
    OHOS::AppExecFwk::BundleMgrProxyNative bundleMgrProxyNative;
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    auto bundleInfoFlag = static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION) |
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO);

    if (!bundleMgrProxyNative.GetBundleInfoForSelf(bundleInfoFlag, bundleInfo)) {
        APP_LOGE("can not get bundleInfo for self");
        return nativeApplicationInfo;
    };
    size_t bundleNameLen = bundleInfo.applicationInfo.bundleName.size();
    if ((bundleNameLen == 0) || (bundleNameLen + 1) > CHAR_MAX_LENGTH) {
        APP_LOGE("failed due to the length of bundleName is empty or too long");
        return nativeApplicationInfo;
    }
    nativeApplicationInfo.bundleName = static_cast<char*>(malloc(bundleNameLen + 1));
    if (nativeApplicationInfo.bundleName == nullptr) {
        APP_LOGE("failed due to malloc error");
        return nativeApplicationInfo;
    }
    if (strcpy_s(nativeApplicationInfo.bundleName, bundleNameLen + 1,
        bundleInfo.applicationInfo.bundleName.c_str()) != EOK) {
        APP_LOGE("failed due to strcpy_s error");
        ReleaseStrings(nativeApplicationInfo.bundleName);
        return nativeApplicationInfo;
    }
    size_t fingerprintLen = bundleInfo.signatureInfo.fingerprint.size();
    if ((fingerprintLen == 0) || (fingerprintLen + 1) > CHAR_MAX_LENGTH) {
        APP_LOGE("failed due to the length of fingerprint is empty or too long");
        ReleaseStrings(nativeApplicationInfo.bundleName);
        return nativeApplicationInfo;
    }
    nativeApplicationInfo.fingerprint = static_cast<char*>(malloc(fingerprintLen + 1));
    if (nativeApplicationInfo.fingerprint == nullptr) {
        APP_LOGE("failed due to malloc error");
        ReleaseStrings(nativeApplicationInfo.bundleName);
        return nativeApplicationInfo;
    }
    if (strcpy_s(nativeApplicationInfo.fingerprint, fingerprintLen + 1,
        bundleInfo.signatureInfo.fingerprint.c_str()) != EOK) {
        APP_LOGE("failed due to strcpy_s error");
        ReleaseStrings(nativeApplicationInfo.bundleName, nativeApplicationInfo.fingerprint);
        return nativeApplicationInfo;
    }
    APP_LOGD("OH_NativeBundle_GetCurrentApplicationInfo success");
    return nativeApplicationInfo;
}

char* OH_NativeBundle_GetAppId()
{
    OHOS::AppExecFwk::BundleMgrProxyNative bundleMgrProxyNative;
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    auto bundleInfoFlag =
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO);

    if (!bundleMgrProxyNative.GetBundleInfoForSelf(bundleInfoFlag, bundleInfo)) {
        APP_LOGE("can not get bundleInfo for self");
        return nullptr;
    };

    size_t appIdLen = bundleInfo.signatureInfo.appId.size();
    if ((appIdLen == 0) || (appIdLen + 1) > CHAR_MAX_LENGTH) {
        APP_LOGE("failed due to the length of appId is empty or too long");
        return nullptr;
    }
    char *appId = static_cast<char*>(malloc(appIdLen + 1));
    if (appId == nullptr) {
        APP_LOGE("failed due to malloc error");
        return nullptr;
    }
    if (strcpy_s(appId, appIdLen + 1, bundleInfo.signatureInfo.appId.c_str()) != EOK) {
        APP_LOGE("failed due to strcpy_s error");
        free(appId);
        return nullptr;
    }
    APP_LOGD("OH_NativeBundle_GetAppId success");
    return appId;
}

char* OH_NativeBundle_GetAppIdentifier()
{
    OHOS::AppExecFwk::BundleMgrProxyNative bundleMgrProxyNative;
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    auto bundleInfoFlag =
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO);

    if (!bundleMgrProxyNative.GetBundleInfoForSelf(bundleInfoFlag, bundleInfo)) {
        APP_LOGE("can not get bundleInfo for self");
        return nullptr;
    };

    size_t appIdentifierLen = bundleInfo.signatureInfo.appIdentifier.size();
    if (appIdentifierLen + 1 > CHAR_MAX_LENGTH) {
        APP_LOGE("failed due to the length of appIdentifier is too long");
        return nullptr;
    }
    char* appIdentifier = static_cast<char*>(malloc(appIdentifierLen + 1));
    if (appIdentifier == nullptr) {
        APP_LOGE("failed due to malloc error");
        return nullptr;
    }
    if (strcpy_s(appIdentifier, appIdentifierLen + 1,
        bundleInfo.signatureInfo.appIdentifier.c_str()) != EOK) {
        APP_LOGE("failed due to strcpy_s error");
        free(appIdentifier);
        return nullptr;
    }
    APP_LOGD("Native_Identifier success");
    return appIdentifier;
}

OH_NativeBundle_ElementName OH_NativeBundle_GetMainElementName()
{
    OH_NativeBundle_ElementName elementName;
    OHOS::AppExecFwk::BundleMgrProxyNative bundleMgrProxyNative;
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    auto bundleInfoFlag = static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
                          static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY);

    if (!bundleMgrProxyNative.GetBundleInfoForSelf(bundleInfoFlag, bundleInfo)) {
        APP_LOGE("can not get bundleInfo for self");
        return elementName;
    };

    for (const auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        if (hapModuleInfo.moduleType != OHOS::AppExecFwk::ModuleType::ENTRY) {
            continue;
        }
        if (GetElementNameByModuleInfo(hapModuleInfo, elementName)) {
            return elementName;
        }
    }

    for (const auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        if (hapModuleInfo.moduleType != OHOS::AppExecFwk::ModuleType::FEATURE) {
            continue;
        }
        if (GetElementNameByModuleInfo(hapModuleInfo, elementName)) {
            return elementName;
        }
    }

    for (const auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        for (const auto &abilityInfo : hapModuleInfo.abilityInfos) {
            GetElementNameByAbilityInfo(abilityInfo, elementName);
            return elementName;
        }
    }
    return elementName;
}

char* OH_NativeBundle_GetCompatibleDeviceType()
{
    OHOS::AppExecFwk::BundleMgrProxyNative bundleMgrProxyNative;
    std::string deviceType;
    if (!bundleMgrProxyNative.GetCompatibleDeviceTypeNative(deviceType)) {
        APP_LOGE("can not get compatible device type");
        return nullptr;
    }
    if (deviceType.size() + 1 > CHAR_MAX_LENGTH) {
        APP_LOGE("failed due to the length of device type is too long");
        return nullptr;
    }
    char* deviceTypeC = static_cast<char*>(malloc(deviceType.size() + 1));
    if (deviceTypeC == nullptr) {
        APP_LOGE("failed due to malloc error");
        return nullptr;
    }
    if (strcpy_s(deviceTypeC, deviceType.size() + 1, deviceType.c_str()) != EOK) {
        APP_LOGE("failed due to strcpy_s error");
        free(deviceTypeC);
        return nullptr;
    }
    APP_LOGD("OH_NativeBundle_GetCompatibleDeviceType success");
    return deviceTypeC;
}

bool OH_NativeBundle_IsDebugMode(bool* isDebugMode)
{
    if (isDebugMode == nullptr) {
        APP_LOGE("invalid param isDebugMode");
        return false;
    }
    OHOS::AppExecFwk::BundleMgrProxyNative bundleMgrProxyNative;
    OHOS::AppExecFwk::BundleInfo bundleInfo;

    auto bundleInfoFlag =
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);

    if (!bundleMgrProxyNative.GetBundleInfoForSelf(bundleInfoFlag, bundleInfo)) {
        APP_LOGE("can not get bundleInfo for self");
        return false;
    }

    *isDebugMode = bundleInfo.applicationInfo.debug;
    APP_LOGD("OH_NativeBundle_IsDebugMode success");
    return true;
}

void FreeMetadataArray(OH_NativeBundle_Metadata *&metadata, size_t metadataSize)
{
    if (metadata == nullptr || metadataSize == 0) {
        APP_LOGE("invalid param");
        return;
    }
    for (size_t i = 0; i < metadataSize; ++i) {
        free(metadata[i].name);
        free(metadata[i].value);
        free(metadata[i].resource);
    }
    free(metadata);
}

void FreeModuleMetadataArray(OH_NativeBundle_ModuleMetadata *&moduleMetadata, size_t moduleMetadataSize)
{
    if (moduleMetadata == nullptr || moduleMetadataSize == 0) {
        APP_LOGE("invalid param");
        return;
    }

    for (size_t i = 0; i < moduleMetadataSize; ++i) {
        free(moduleMetadata[i].moduleName);
        FreeMetadataArray(moduleMetadata[i].metadataArray, moduleMetadata[i].metadataArraySize);
    }
    free(moduleMetadata);
}

void ResetMetadataArray(OH_NativeBundle_Metadata *&metadata, size_t metadataSize)
{
    if (metadata == nullptr || metadataSize == 0) {
        APP_LOGE("invalid param");
        return;
    }
    for (size_t i = 0; i < metadataSize; ++i) {
        metadata[i].name = nullptr;
        metadata[i].value = nullptr;
        metadata[i].resource = nullptr;
    }
}

void ResetModuleMetadataArray(OH_NativeBundle_ModuleMetadata *&moduleMetadata, size_t moduleMetadataSize)
{
    if (moduleMetadata == nullptr || moduleMetadataSize == 0) {
        APP_LOGE("invalid param");
        return;
    }

    for (size_t i = 0; i < moduleMetadataSize; ++i) {
        moduleMetadata[i].moduleName = nullptr;
        moduleMetadata[i].metadataArray = nullptr;
        moduleMetadata[i].metadataArraySize = 0;
    }
}

bool CopyMetadataStringToChar(char *&name, const std::string &value)
{
    size_t length = value.size();
    if ((length == 0) || (length + 1) > CHAR_MAX_LENGTH) {
        APP_LOGW("failed due to the length of value is empty or too long");
        name = static_cast<char *>(malloc(CHAR_MIN_LENGTH));
        if (name == nullptr) {
            APP_LOGE("failed due to malloc error");
            return false;
        }
        name[0] = '\0';
        return true;
    }
    name = static_cast<char *>(malloc(length + 1));
    if (name == nullptr) {
        APP_LOGE("failed due to malloc error");
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        name[i] = 0;
    }
    name[length] = '\0';
    if (strcpy_s(name, length + 1, value.c_str()) != EOK) {
        APP_LOGE("failed due to strcpy_s error");
        return false;
    }
    return true;
}

OH_NativeBundle_ModuleMetadata* AllocateModuleMetadata(size_t moduleMetadataSize)
{
    if (moduleMetadataSize == 0 || moduleMetadataSize > MAX_ALLOWED_SIZE) {
        APP_LOGE("failed due to the length of value is empty or too long");
        return nullptr;
    }
    OH_NativeBundle_ModuleMetadata *moduleMetadata = static_cast<OH_NativeBundle_ModuleMetadata *>(
        malloc(moduleMetadataSize * sizeof(OH_NativeBundle_ModuleMetadata)));
    if (moduleMetadata == nullptr) {
        APP_LOGE("failed to allocate memory for OH_NativeBundle_ModuleMetadata");
    }
    ResetModuleMetadataArray(moduleMetadata, moduleMetadataSize);
    return moduleMetadata;
}

OH_NativeBundle_ModuleMetadata* FillBundleModuleNames(const std::vector<std::string> &moduleNames)
{
    if (moduleNames.empty() || moduleNames.size() > MAX_ALLOWED_SIZE) {
        APP_LOGE("moduleNames is empty or too long");
        return nullptr;
    }
    OH_NativeBundle_ModuleMetadata *moduleMetadata = static_cast<OH_NativeBundle_ModuleMetadata *>(
        malloc(moduleNames.size() * sizeof(OH_NativeBundle_ModuleMetadata)));
    if (moduleMetadata == nullptr) {
        APP_LOGE("failed to allocate memory for OH_NativeBundle_ModuleMetadata");
        return nullptr;
    }
    ResetModuleMetadataArray(moduleMetadata, moduleNames.size());
    for (size_t i = 0; i < moduleNames.size(); ++i) {
        if (!CopyMetadataStringToChar(moduleMetadata[i].moduleName, moduleNames[i])) {
            APP_LOGE("failed to allocate memory for OH_NativeBundle_ModuleMetadata moduleName");
            FreeModuleMetadataArray(moduleMetadata, i + 1);
            return nullptr;
        }
        moduleMetadata[i].metadataArray = nullptr;
        moduleMetadata[i].metadataArraySize = 0;
    }
    return moduleMetadata;
}

bool FillModuleMetadata(OH_NativeBundle_ModuleMetadata &moduleMetadata, const std::string &moduleName,
    const std::vector<OHOS::AppExecFwk::Metadata> &metadataArray)
{
    if (!CopyMetadataStringToChar(moduleMetadata.moduleName, moduleName.c_str())) {
        APP_LOGE("failed to allocate memory for OH_NativeBundle_ModuleMetadata moduleName");
        return false;
    }

    auto metadataArraySize = metadataArray.size();
    if (metadataArraySize == 0) {
        moduleMetadata.metadataArray = nullptr;
        moduleMetadata.metadataArraySize = metadataArraySize;
        APP_LOGI("metadataArray is empty");
        return true;
    }

    if (metadataArraySize > MAX_ALLOWED_SIZE) {
        APP_LOGE("metadataArraySize is too long");
        return false;
    }

    moduleMetadata.metadataArray =
        static_cast<OH_NativeBundle_Metadata *>(malloc(metadataArraySize * sizeof(OH_NativeBundle_Metadata)));
    if (moduleMetadata.metadataArray == nullptr) {
        APP_LOGE("failed to allocate memory for metadataArray");
        return false;
    }
    ResetMetadataArray(moduleMetadata.metadataArray, metadataArraySize);
    moduleMetadata.metadataArraySize = metadataArraySize;

    for (size_t j = 0; j < metadataArraySize; ++j) {
        if (!CopyMetadataStringToChar(moduleMetadata.metadataArray[j].name, metadataArray[j].name.c_str())) {
            APP_LOGE("failed to allocate memory for OH_NativeBundle_ModuleMetadata name");
            return false;
        }
        if (!CopyMetadataStringToChar(moduleMetadata.metadataArray[j].value, metadataArray[j].value.c_str())) {
            APP_LOGE("failed to allocate memory for OH_NativeBundle_ModuleMetadata value");
            return false;
        }
        if (!CopyMetadataStringToChar(moduleMetadata.metadataArray[j].resource, metadataArray[j].resource.c_str())) {
            APP_LOGE("failed to allocate memory for OH_NativeBundle_ModuleMetadata resource");
            return false;
        }
    }
    return true;
}

OH_NativeBundle_ModuleMetadata* CreateModuleMetadata(const std::map<std::string,
    std::vector<OHOS::AppExecFwk::Metadata>> &metadata)
{
    auto moduleMetadataSize = metadata.size();
    OH_NativeBundle_ModuleMetadata *moduleMetadata = AllocateModuleMetadata(moduleMetadataSize);
    if (moduleMetadata == nullptr) {
        APP_LOGE("allocate module metadata failed");
        return nullptr;
    }

    size_t i = 0;
    for (const auto &[moduleName, metadataArray] : metadata) {
        if (!FillModuleMetadata(moduleMetadata[i], moduleName, metadataArray)) {
            FreeModuleMetadataArray(moduleMetadata, i + 1);
            APP_LOGE("fill module metadata failed");
            return nullptr;
        }
        ++i;
    }

    return moduleMetadata;
}

OH_NativeBundle_ModuleMetadata* OH_NativeBundle_GetModuleMetadata(size_t* size)
{
    if (size == nullptr) {
        APP_LOGE("invalid param size");
        return nullptr;
    }
    *size = 0;
    OHOS::AppExecFwk::BundleMgrProxyNative bundleMgrProxyNative;
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    auto bundleInfoFlag =
        static_cast<uint32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA) |
        static_cast<uint32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);

    if (!bundleMgrProxyNative.GetBundleInfoForSelf(bundleInfoFlag, bundleInfo)) {
        APP_LOGE("failed to get bundleInfo for self, flags: %{public}d", bundleInfoFlag);
        return nullptr;
    }

    OH_NativeBundle_ModuleMetadata *moduleMetadata = nullptr;

    if (bundleInfo.applicationInfo.metadata.empty()) {
        if (bundleInfo.moduleNames.empty()) {
            APP_LOGE("bundleInfo applicationInfo metadata and bundleInfo moduleNames is empty");
            return nullptr;
        }

        moduleMetadata = FillBundleModuleNames(bundleInfo.moduleNames);
        if (moduleMetadata == nullptr) {
            APP_LOGE("failed to fill bundle module names");
            return nullptr;
        }

        *size = bundleInfo.moduleNames.size();
        APP_LOGI("bundleInfo applicationInfo metadata is empty");
        return moduleMetadata;
    }
    moduleMetadata = CreateModuleMetadata(bundleInfo.applicationInfo.metadata);
    if (moduleMetadata == nullptr) {
        APP_LOGE("failed to create moduleMetadata");
        return nullptr;
    }
    *size = bundleInfo.applicationInfo.metadata.size();
    APP_LOGD("OH_NativeBundle_GetModuleMetadata success");
    return moduleMetadata;
}

BundleManager_ErrorCode OH_NativeBundle_GetAbilityResourceInfo(
    char* fileType, OH_NativeBundle_AbilityResourceInfo** abilityResourceInfo, size_t* size)
{
    if (fileType == nullptr || size == nullptr || abilityResourceInfo == nullptr) {
        APP_LOGE("invalid param");
        return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
    }
    *size = 0;
    std::string fileTypeStr(fileType);
    OHOS::AppExecFwk::BundleMgrProxyNative bundleMgrProxyNative;
    std::vector<OHOS::AppExecFwk::LauncherAbilityResourceInfo> launcherAbilityResourceInfoArr;

    if (bundleMgrProxyNative.GetLauncherAbilityResourceInfoNative(fileTypeStr, launcherAbilityResourceInfoArr) ==
        BUNDLE_MANAGER_ERROR_CODE_PERMISSION_DENIED) {
        APP_LOGE("failed to get launcher Ability Resource Info Arr because of permission denied");
        return BUNDLE_MANAGER_ERROR_CODE_PERMISSION_DENIED;
    }

    size_t abilityResourceInfoSize = launcherAbilityResourceInfoArr.size();
    if (abilityResourceInfoSize == 0 || abilityResourceInfoSize > ARRAY_MAX_LENGTH) {
        APP_LOGW("failed due to the length of value is empty or too long");
        return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
    }

    *abilityResourceInfo = OH_AbilityResourceInfo_Create(abilityResourceInfoSize);
    if (*abilityResourceInfo == nullptr) {
        APP_LOGE("failed to allocate memory for OH_NativeBundle_ModuleMetadata");
        return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
    }

    size_t i = 0;
    for (auto &info : launcherAbilityResourceInfoArr) {
        auto p =
            (OH_NativeBundle_AbilityResourceInfo *)((char *)(*abilityResourceInfo) + OH_NativeBundle_GetSize() * i);
        if (OH_NativeBundle_SetAbilityResourceInfo_AppIndex(p, info.appIndex) != BUNDLE_MANAGER_ERROR_CODE_NO_ERROR ||
            OH_NativeBundle_SetAbilityResourceInfo_IsDefaultApp(p, info.isDefaultApp) !=
                BUNDLE_MANAGER_ERROR_CODE_NO_ERROR ||
            OH_NativeBundle_SetAbilityResourceInfo_BundleName(p, info.bundleName.c_str()) !=
                BUNDLE_MANAGER_ERROR_CODE_NO_ERROR ||
            OH_NativeBundle_SetAbilityResourceInfo_ModuleName(p, info.moduleName.c_str()) !=
                BUNDLE_MANAGER_ERROR_CODE_NO_ERROR ||
            OH_NativeBundle_SetAbilityResourceInfo_AbilityName(p, info.abilityName.c_str()) !=
                BUNDLE_MANAGER_ERROR_CODE_NO_ERROR ||
            OH_NativeBundle_SetAbilityResourceInfo_Label(p, info.label.c_str()) != BUNDLE_MANAGER_ERROR_CODE_NO_ERROR ||
            OH_NativeBundle_SetAbilityResourceInfo_Icon(p, info.icon.c_str()) != BUNDLE_MANAGER_ERROR_CODE_NO_ERROR) {
            APP_LOGE("failed to set ability resource info");
            OH_AbilityResourceInfo_Destroy(*abilityResourceInfo, i + 1);
            return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
        }
        ++i;
    }

    *size = abilityResourceInfoSize;
    return BUNDLE_MANAGER_ERROR_CODE_NO_ERROR;
}