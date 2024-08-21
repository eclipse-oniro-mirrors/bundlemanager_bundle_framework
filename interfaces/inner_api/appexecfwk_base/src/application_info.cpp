/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "application_info.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <set>
#include <unistd.h>

#include "message_parcel.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "json_serializer.h"
#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* APPLICATION_NAME = "name";
const char* APPLICATION_VERSION_CODE = "versionCode";
const char* APPLICATION_VERSION_NAME = "versionName";
const char* APPLICATION_MIN_COMPATIBLE_VERSION_CODE = "minCompatibleVersionCode";
const char* APPLICATION_API_COMPATIBLE_VERSION = "apiCompatibleVersion";
const char* APPLICATION_API_TARGET_VERSION = "apiTargetVersion";
const char* APPLICATION_ICON_PATH = "iconPath";
const char* APPLICATION_ICON_ID = "iconId";
const char* APPLICATION_LABEL = "label";
const char* APPLICATION_LABEL_ID = "labelId";
const char* APPLICATION_DESCRIPTION = "description";
const char* APPLICATION_DESCRIPTION_ID = "descriptionId";
const char* APPLICATION_KEEP_ALIVE = "keepAlive";
const char* APPLICATION_REMOVABLE = "removable";
const char* APPLICATION_SINGLETON = "singleton";
const char* APPLICATION_USER_DATA_CLEARABLE = "userDataClearable";
const char* ALLOW_APP_RUN_WHEN_DEVICE_FIRST_LOCKED = "allowAppRunWhenDeviceFirstLocked";
const char* APPLICATION_IS_SYSTEM_APP = "isSystemApp";
const char* APPLICATION_IS_LAUNCHER_APP = "isLauncherApp";
const char* APPLICATION_IS_FREEINSTALL_APP = "isFreeInstallApp";
const char* APPLICATION_RUNNING_RESOURCES_APPLY = "runningResourcesApply";
const char* APPLICATION_ASSOCIATED_WAKE_UP = "associatedWakeUp";
const char* APPLICATION_HIDE_DESKTOP_ICON = "hideDesktopIcon";
const char* APPLICATION_FORM_VISIBLE_NOTIFY = "formVisibleNotify";
const char* APPLICATION_ALLOW_COMMON_EVENT = "allowCommonEvent";
const char* APPLICATION_CODE_PATH = "codePath";
const char* APPLICATION_DATA_DIR = "dataDir";
const char* APPLICATION_DATA_BASE_DIR = "dataBaseDir";
const char* APPLICATION_CACHE_DIR = "cacheDir";
const char* APPLICATION_ENTRY_DIR = "entryDir";
const char* APPLICATION_API_RELEASETYPE = "apiReleaseType";
const char* APPLICATION_DEBUG = "debug";
const char* APPLICATION_DEVICE_ID = "deviceId";
const char* APPLICATION_DISTRIBUTED_NOTIFICATION_ENABLED = "distributedNotificationEnabled";
const char* APPLICATION_ENTITY_TYPE = "entityType";
const char* APPLICATION_PROCESS = "process";
const char* APPLICATION_SUPPORTED_MODES = "supportedModes";
const char* APPLICATION_VENDOR = "vendor";
const char* APPLICATION_ACCESSIBLE = "accessible";
const char* APPLICATION_PRIVILEGE_LEVEL = "appPrivilegeLevel";
const char* APPLICATION_ACCESSTOKEN_ID = "accessTokenId";
const char* APPLICATION_ACCESSTOKEN_ID_EX = "accessTokenIdEx";
const char* APPLICATION_ENABLED = "enabled";
const char* APPLICATION_UID = "uid";
const char* APPLICATION_PERMISSIONS = "permissions";
const char* APPLICATION_MODULE_SOURCE_DIRS = "moduleSourceDirs";
const char* APPLICATION_HNP_PACKAGES = "hnpPackages";
const char* APPLICATION_HNP_PACKAGES_PACKAGE = "package";
const char* APPLICATION_HNP_PACKAGES_TYPE = "type";
const char* APPLICATION_MODULE_INFOS = "moduleInfos";
const char* APPLICATION_META_DATA_CONFIG_JSON = "metaData";
const char* APPLICATION_META_DATA_MODULE_JSON = "metadata";
const char* APPLICATION_FINGERPRINT = "fingerprint";
const char* APPLICATION_ICON = "icon";
const char* APPLICATION_FLAGS = "flags";
const char* APPLICATION_ENTRY_MODULE_NAME = "entryModuleName";
const char* APPLICATION_NATIVE_LIBRARY_PATH = "nativeLibraryPath";
const char* APPLICATION_CPU_ABI = "cpuAbi";
const char* APPLICATION_ARK_NATIVE_FILE_PATH = "arkNativeFilePath";
const char* APPLICATION_ARK_NATIVE_FILE_ABI = "arkNativeFileAbi";
const char* APPLICATION_IS_COMPRESS_NATIVE_LIBS = "isCompressNativeLibs";
const char* APPLICATION_SIGNATURE_KEY = "signatureKey";
const char* APPLICATION_TARGETBUNDLELIST = "targetBundleList";
const char* APPLICATION_APP_DISTRIBUTION_TYPE = "appDistributionType";
const char* APPLICATION_APP_PROVISION_TYPE = "appProvisionType";
const char* APPLICATION_ICON_RESOURCE = "iconResource";
const char* APPLICATION_LABEL_RESOURCE = "labelResource";
const char* APPLICATION_DESCRIPTION_RESOURCE = "descriptionResource";
const char* APPLICATION_MULTI_PROJECTS = "multiProjects";
const char* APPLICATION_CROWDTEST_DEADLINE = "crowdtestDeadline";
const char* APPLICATION_APP_QUICK_FIX = "appQuickFix";
const char* RESOURCE_ID = "id";
const uint16_t APPLICATION_CAPACITY = 10240; // 10K
const char* APPLICATION_NEED_APP_DETAIL = "needAppDetail";
const char* APPLICATION_APP_DETAIL_ABILITY_LIBRARY_PATH = "appDetailAbilityLibraryPath";
const char* APPLICATION_APP_TARGET_BUNDLE_NAME = "targetBundleName";
const char* APPLICATION_APP_TARGET_PRIORITY = "targetPriority";
const char* APPLICATION_APP_OVERLAY_STATE = "overlayState";
const char* APPLICATION_ASAN_ENABLED = "asanEnabled";
const char* APPLICATION_ASAN_LOG_PATH = "asanLogPath";
const char* APPLICATION_APP_TYPE = "bundleType";
const char* APPLICATION_COMPILE_SDK_VERSION = "compileSdkVersion";
const char* APPLICATION_COMPILE_SDK_TYPE = "compileSdkType";
const char* APPLICATION_RESOURCES_APPLY = "resourcesApply";
const char* APPLICATION_ALLOW_ENABLE_NOTIFICATION = "allowEnableNotification";
const char* APPLICATION_GWP_ASAN_ENABLED = "GWPAsanEnabled";
const char* APPLICATION_RESERVED_FLAG = "applicationReservedFlag";
const char* APPLICATION_TSAN_ENABLED = "tsanEnabled";
const char* APPLICATION_APP_ENVIRONMENTS = "appEnvironments";
const char* APPLICATION_MULTI_APP_MODE = "multiAppMode";
const char* APPLICATION_MULTI_APP_MODE_TYPE = "multiAppModeType";
const char* APPLICATION_MULTI_APP_MODE_MAX_ADDITIONAL_NUMBER = "maxCount";
const char* APP_ENVIRONMENTS_NAME = "name";
const char* APP_ENVIRONMENTS_VALUE = "value";
const char* APPLICATION_ORGANIZATION = "organization";
const char* APPLICATION_MAX_CHILD_PROCESS = "maxChildProcess";
const char* APPLICATION_APP_INDEX = "appIndex";
const char* APPLICATION_INSTALL_SOURCE = "installSource";
const char* APPLICATION_CONFIGURATION = "configuration";
const char* APPLICATION_HWASAN_ENABLED = "hwasanEnabled";
const char* APPLICATION_CLOUD_FILE_SYNC_ENABLED = "cloudFileSyncEnabled";
const char* APPLICATION_APPLICATION_FLAGS = "applicationFlags";
const char* APPLICATION_UBSAN_ENABLED = "ubsanEnabled";
}

bool MultiAppModeData::ReadFromParcel(Parcel &parcel)
{
    multiAppModeType = static_cast<MultiAppModeType>(parcel.ReadInt32());
    maxCount = parcel.ReadInt32();
    return true;
}

bool MultiAppModeData::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(multiAppModeType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, maxCount);
    return true;
}

MultiAppModeData *MultiAppModeData::Unmarshalling(Parcel &parcel)
{
    MultiAppModeData *multiAppMode = new (std::nothrow) MultiAppModeData;
    if (multiAppMode && !multiAppMode->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete multiAppMode;
        multiAppMode = nullptr;
    }
    return multiAppMode;
}

Metadata::Metadata(const std::string &paramName, const std::string &paramValue, const std::string &paramResource)
    : name(paramName), value(paramValue), resource(paramResource)
{
}

bool Metadata::ReadFromParcel(Parcel &parcel)
{
    name = Str16ToStr8(parcel.ReadString16());
    value = Str16ToStr8(parcel.ReadString16());
    resource = Str16ToStr8(parcel.ReadString16());
    return true;
}

bool Metadata::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(value));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(resource));
    return true;
}

Metadata *Metadata::Unmarshalling(Parcel &parcel)
{
    Metadata *metadata = new (std::nothrow) Metadata;
    if (metadata && !metadata->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete metadata;
        metadata = nullptr;
    }
    return metadata;
}

bool HnpPackage::ReadFromParcel(Parcel &parcel)
{
    package = Str16ToStr8(parcel.ReadString16());
    type = Str16ToStr8(parcel.ReadString16());
    return true;
}

bool HnpPackage::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(package));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(type));
    return true;
}

HnpPackage *HnpPackage::Unmarshalling(Parcel &parcel)
{
    HnpPackage *hnpPackage = new (std::nothrow) HnpPackage;
    if (hnpPackage && !hnpPackage->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete hnpPackage;
        hnpPackage = nullptr;
    }
    return hnpPackage;
}

CustomizeData::CustomizeData(std::string paramName, std::string paramValue, std::string paramExtra)
    :name(paramName), value(paramValue), extra(paramExtra)
{
}

bool CustomizeData::ReadFromParcel(Parcel &parcel)
{
    name = Str16ToStr8(parcel.ReadString16());
    value = Str16ToStr8(parcel.ReadString16());
    extra = Str16ToStr8(parcel.ReadString16());
    return true;
}

CustomizeData *CustomizeData::Unmarshalling(Parcel &parcel)
{
    CustomizeData *customizeData = new (std::nothrow) CustomizeData;
    if (customizeData && !customizeData->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete customizeData;
        customizeData = nullptr;
    }
    return customizeData;
}

bool CustomizeData::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(value));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(extra));
    return true;
}

bool Resource::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    id = parcel.ReadInt32();
    return true;
}

bool Resource::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, id);
    return true;
}

Resource *Resource::Unmarshalling(Parcel &parcel)
{
    Resource *resource = new (std::nothrow) Resource;
    if (resource && !resource->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete resource;
        resource = nullptr;
    }
    return resource;
}

bool ApplicationInfo::ReadMetaDataFromParcel(Parcel &parcel)
{
    int32_t metaDataSize = parcel.ReadInt32();
    CONTAINER_SECURITY_VERIFY(parcel, metaDataSize, &metaData);
    for (int32_t i = 0; i < metaDataSize; i++) {
        std::string moduleName = Str16ToStr8(parcel.ReadString16());
        int32_t customizeDataSize = parcel.ReadInt32();
        std::vector<CustomizeData> customizeDatas;
        metaData[moduleName] = customizeDatas;
        CONTAINER_SECURITY_VERIFY(parcel, customizeDataSize, &customizeDatas);
        for (int j = 0; j < customizeDataSize; j++) {
            std::unique_ptr<CustomizeData> customizeData(parcel.ReadParcelable<CustomizeData>());
            if (!customizeData) {
                APP_LOGE("ReadParcelable<CustomizeData> failed");
                return false;
            }
            metaData[moduleName].emplace_back(*customizeData);
        }
    }
    return true;
}

bool ApplicationEnvironment::ReadFromParcel(Parcel &parcel)
{
    name = Str16ToStr8(parcel.ReadString16());
    value = Str16ToStr8(parcel.ReadString16());
    return true;
}

bool ApplicationEnvironment::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(value));
    return true;
}

ApplicationEnvironment *ApplicationEnvironment::Unmarshalling(Parcel &parcel)
{
    ApplicationEnvironment *info = new (std::nothrow) ApplicationEnvironment();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

void to_json(nlohmann::json &jsonObject, const ApplicationEnvironment &applicationEnvironment)
{
    jsonObject = nlohmann::json {
        {APP_ENVIRONMENTS_NAME, applicationEnvironment.name},
        {APP_ENVIRONMENTS_VALUE, applicationEnvironment.value}
    };
}

void from_json(const nlohmann::json &jsonObject, ApplicationEnvironment &applicationEnvironment)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APP_ENVIRONMENTS_NAME,
        applicationEnvironment.name,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APP_ENVIRONMENTS_VALUE,
        applicationEnvironment.value,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read database error : %{public}d", parseResult);
    }
}

bool ApplicationInfo::ReadFromParcel(Parcel &parcel)
{
    name = Str16ToStr8(parcel.ReadString16());
    bundleName = Str16ToStr8(parcel.ReadString16());
    versionCode = parcel.ReadUint32();
    versionName = Str16ToStr8(parcel.ReadString16());
    minCompatibleVersionCode = parcel.ReadInt32();
    apiCompatibleVersion = parcel.ReadUint32();
    apiTargetVersion = parcel.ReadInt32();
    crowdtestDeadline = parcel.ReadInt64();

    iconPath = Str16ToStr8(parcel.ReadString16());
    iconId = parcel.ReadInt32();
    std::unique_ptr<Resource> iconResourcePtr(parcel.ReadParcelable<Resource>());
    if (!iconResourcePtr) {
        APP_LOGE("icon ReadParcelable<Resource> failed");
        return false;
    }
    iconResource = *iconResourcePtr;

    label = Str16ToStr8(parcel.ReadString16());
    labelId = parcel.ReadInt32();
    std::unique_ptr<Resource> labelResourcePtr(parcel.ReadParcelable<Resource>());
    if (!labelResourcePtr) {
        APP_LOGE("label ReadParcelable<Resource> failed");
        return false;
    }
    labelResource = *labelResourcePtr;

    description = Str16ToStr8(parcel.ReadString16());
    descriptionId = parcel.ReadInt32();
    std::unique_ptr<Resource> descriptionResourcePtr(parcel.ReadParcelable<Resource>());
    if (!descriptionResourcePtr) {
        APP_LOGE("description ReadParcelable<Resource> failed");
        return false;
    }
    descriptionResource = *descriptionResourcePtr;

    keepAlive = parcel.ReadBool();
    removable = parcel.ReadBool();
    singleton = parcel.ReadBool();
    userDataClearable = parcel.ReadBool();
    accessible = parcel.ReadBool();
    isSystemApp = parcel.ReadBool();
    isLauncherApp = parcel.ReadBool();
    isFreeInstallApp = parcel.ReadBool();
    runningResourcesApply = parcel.ReadBool();
    associatedWakeUp = parcel.ReadBool();
    hideDesktopIcon = parcel.ReadBool();
    formVisibleNotify = parcel.ReadBool();
    allowAppRunWhenDeviceFirstLocked = parcel.ReadBool();
    int32_t allowCommonEventSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, allowCommonEventSize);
    CONTAINER_SECURITY_VERIFY(parcel, allowCommonEventSize, &allowCommonEvent);
    for (auto i = 0; i < allowCommonEventSize; i++) {
        allowCommonEvent.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    codePath = Str16ToStr8(parcel.ReadString16());
    dataDir = Str16ToStr8(parcel.ReadString16());
    dataBaseDir = Str16ToStr8(parcel.ReadString16());
    cacheDir = Str16ToStr8(parcel.ReadString16());
    entryDir = Str16ToStr8(parcel.ReadString16());

    apiReleaseType = Str16ToStr8(parcel.ReadString16());
    debug = parcel.ReadBool();
    deviceId = Str16ToStr8(parcel.ReadString16());
    distributedNotificationEnabled = parcel.ReadBool();
    allowEnableNotification = parcel.ReadBool();
    entityType = Str16ToStr8(parcel.ReadString16());
    process = Str16ToStr8(parcel.ReadString16());
    supportedModes = parcel.ReadInt32();
    vendor = Str16ToStr8(parcel.ReadString16());
    appPrivilegeLevel = Str16ToStr8(parcel.ReadString16());
    appDistributionType = Str16ToStr8(parcel.ReadString16());
    appProvisionType = Str16ToStr8(parcel.ReadString16());
    accessTokenId = parcel.ReadUint32();
    accessTokenIdEx = parcel.ReadUint64();
    enabled = parcel.ReadBool();
    uid = parcel.ReadInt32();
    nativeLibraryPath = Str16ToStr8(parcel.ReadString16());
    cpuAbi = Str16ToStr8(parcel.ReadString16());
    arkNativeFilePath = Str16ToStr8(parcel.ReadString16());
    arkNativeFileAbi = Str16ToStr8(parcel.ReadString16());

    int32_t permissionsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, permissionsSize);
    CONTAINER_SECURITY_VERIFY(parcel, permissionsSize, &permissions);
    for (auto i = 0; i < permissionsSize; i++) {
        permissions.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    int32_t moduleSourceDirsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, moduleSourceDirsSize);
    CONTAINER_SECURITY_VERIFY(parcel, moduleSourceDirsSize, &moduleSourceDirs);
    for (auto i = 0; i < moduleSourceDirsSize; i++) {
        moduleSourceDirs.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    int32_t moduleInfosSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, moduleInfosSize);
    CONTAINER_SECURITY_VERIFY(parcel, moduleInfosSize, &moduleInfos);
    for (auto i = 0; i < moduleInfosSize; i++) {
        std::unique_ptr<ModuleInfo> moduleInfo(parcel.ReadParcelable<ModuleInfo>());
        if (!moduleInfo) {
            APP_LOGE("ReadParcelable<ModuleInfo> failed");
            return false;
        }
        moduleInfos.emplace_back(*moduleInfo);
    }

    int32_t hnpPackageSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, hnpPackageSize);
    CONTAINER_SECURITY_VERIFY(parcel, hnpPackageSize, &hnpPackages);
    for (int32_t i = 0; i < hnpPackageSize; ++i) {
        std::string key = Str16ToStr8(parcel.ReadString16());
        int32_t hnpSize = parcel.ReadInt32();
        CONTAINER_SECURITY_VERIFY(parcel, hnpSize, &hnpPackages[key]);
        for (int n = 0; n < hnpSize; ++n) {
            std::unique_ptr<HnpPackage> hnp(parcel.ReadParcelable<HnpPackage>());
            if (!hnp) {
                APP_LOGE("ReadParcelable<HnpPackage> failed");
                return false;
            }
            hnpPackages[key].emplace_back(*hnp);
        }
    }

    int32_t metaDataSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, metaDataSize);
    CONTAINER_SECURITY_VERIFY(parcel, metaDataSize, &metaData);
    for (int32_t i = 0; i < metaDataSize; ++i) {
        std::string key = Str16ToStr8(parcel.ReadString16());
        int32_t customizeDataSize = parcel.ReadInt32();
        CONTAINER_SECURITY_VERIFY(parcel, customizeDataSize, &metaData[key]);
        for (int n = 0; n < customizeDataSize; ++n) {
            std::unique_ptr<CustomizeData> customizeData(parcel.ReadParcelable<CustomizeData>());
            if (!customizeData) {
                APP_LOGE("ReadParcelable<CustomizeData> failed");
                return false;
            }
            metaData[key].emplace_back(*customizeData);
        }
    }

    int32_t metadataSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, metadataSize);
    CONTAINER_SECURITY_VERIFY(parcel, metadataSize, &metadata);
    for (int32_t i = 0; i < metadataSize; ++i) {
        std::string key = Str16ToStr8(parcel.ReadString16());
        int32_t metaSize = parcel.ReadInt32();
        CONTAINER_SECURITY_VERIFY(parcel, metaSize, &metadata[key]);
        for (int n = 0; n < metaSize; ++n) {
            std::unique_ptr<Metadata> meta(parcel.ReadParcelable<Metadata>());
            if (!meta) {
                APP_LOGE("ReadParcelable<Metadata> failed");
                return false;
            }
            metadata[key].emplace_back(*meta);
        }
    }

    int32_t targetBundleListSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, targetBundleListSize);
    CONTAINER_SECURITY_VERIFY(parcel, targetBundleListSize, &targetBundleList);
    for (auto i = 0; i < targetBundleListSize; i++) {
        targetBundleList.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    fingerprint = Str16ToStr8(parcel.ReadString16());
    icon = Str16ToStr8(parcel.ReadString16());
    flags = parcel.ReadInt32();
    entryModuleName = Str16ToStr8(parcel.ReadString16());
    isCompressNativeLibs = parcel.ReadBool();
    signatureKey = Str16ToStr8(parcel.ReadString16());
    multiProjects = parcel.ReadBool();
    std::unique_ptr<AppQuickFix> appQuickFixPtr(parcel.ReadParcelable<AppQuickFix>());
    if (appQuickFixPtr == nullptr) {
        APP_LOGE("ReadParcelable<AppQuickFixPtr> failed");
        return false;
    }
    appQuickFix = *appQuickFixPtr;
    needAppDetail = parcel.ReadBool();
    appDetailAbilityLibraryPath = Str16ToStr8(parcel.ReadString16());
    targetBundleName = Str16ToStr8(parcel.ReadString16());
    targetPriority = parcel.ReadInt32();
    overlayState = parcel.ReadInt32();
    asanEnabled = parcel.ReadBool();
    asanLogPath = Str16ToStr8(parcel.ReadString16());
    bundleType = static_cast<BundleType>(parcel.ReadInt32());
    compileSdkVersion = Str16ToStr8(parcel.ReadString16());
    compileSdkType = Str16ToStr8(parcel.ReadString16());
    int32_t resourceApplySize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, resourceApplySize);
    CONTAINER_SECURITY_VERIFY(parcel, resourceApplySize, &resourcesApply);
    for (int32_t i = 0; i < resourceApplySize; ++i) {
        resourcesApply.emplace_back(parcel.ReadInt32());
    }

    gwpAsanEnabled = parcel.ReadBool();
    applicationReservedFlag = parcel.ReadUint32();
    tsanEnabled = parcel.ReadBool();
    hwasanEnabled = parcel.ReadBool();
    int32_t applicationEnvironmentsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, applicationEnvironmentsSize);
    CONTAINER_SECURITY_VERIFY(parcel, applicationEnvironmentsSize, &appEnvironments);
    for (int32_t i = 0; i < applicationEnvironmentsSize; ++i) {
        std::unique_ptr<ApplicationEnvironment> applicationEnvironment(parcel.ReadParcelable<ApplicationEnvironment>());
        if (!applicationEnvironment) {
            APP_LOGE("ReadParcelable<ApplicationEnvironment> failed");
            return false;
        }
        appEnvironments.emplace_back(*applicationEnvironment);
    }
    organization = Str16ToStr8(parcel.ReadString16());

    std::unique_ptr<MultiAppModeData> multiAppModePtr(parcel.ReadParcelable<MultiAppModeData>());
    if (!multiAppModePtr) {
        APP_LOGE("icon ReadParcelable<MultiAppMode> failed");
        return false;
    }
    multiAppMode = *multiAppModePtr;
    maxChildProcess = parcel.ReadInt32();
    appIndex = parcel.ReadInt32();
    installSource = Str16ToStr8(parcel.ReadString16());

    configuration = Str16ToStr8(parcel.ReadString16());
    cloudFileSyncEnabled = parcel.ReadBool();
    applicationFlags = parcel.ReadInt32();
    ubsanEnabled = parcel.ReadBool();
    return true;
}

ApplicationInfo *ApplicationInfo::Unmarshalling(Parcel &parcel)
{
    ApplicationInfo *info = new (std::nothrow) ApplicationInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool ApplicationInfo::Marshalling(Parcel &parcel) const
{
    APP_LOGD("ApplicationInfo::Marshalling called, bundleName: %{public}s", bundleName.c_str());
    CHECK_PARCEL_CAPACITY(parcel, APPLICATION_CAPACITY);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(versionName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, minCompatibleVersionCode);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, apiCompatibleVersion);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, apiTargetVersion);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, crowdtestDeadline);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(iconPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, iconId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &iconResource);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(label));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, labelId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &labelResource);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(description));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, descriptionId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &descriptionResource);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, keepAlive);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, removable);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, singleton);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, userDataClearable);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, accessible);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isSystemApp);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isLauncherApp);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isFreeInstallApp);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, runningResourcesApply);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, associatedWakeUp);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, hideDesktopIcon);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, formVisibleNotify);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, allowAppRunWhenDeviceFirstLocked);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, allowCommonEvent.size());
    for (auto &event : allowCommonEvent) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(event));
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(codePath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(dataDir));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(dataBaseDir));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(cacheDir));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(entryDir));

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(apiReleaseType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, debug);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(deviceId));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, distributedNotificationEnabled);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, allowEnableNotification);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(entityType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(process));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportedModes);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(vendor));

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appPrivilegeLevel));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appDistributionType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appProvisionType));

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, accessTokenId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint64, parcel, accessTokenIdEx);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, enabled);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uid);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(nativeLibraryPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(cpuAbi));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(arkNativeFilePath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(arkNativeFileAbi));
    CHECK_PARCEL_CAPACITY(parcel, APPLICATION_CAPACITY);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, permissions.size());
    for (auto &permission : permissions) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(permission));
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, moduleSourceDirs.size());
    for (auto &moduleSourceDir : moduleSourceDirs) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleSourceDir));
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, moduleInfos.size());
    for (auto &moduleInfo : moduleInfos) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &moduleInfo);
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, hnpPackages.size());
    for (auto &item : hnpPackages) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(item.first));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, item.second.size());
        for (auto &hnp : item.second) {
            WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &hnp);
        }
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, metaData.size());
    for (auto &item : metaData) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(item.first));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, item.second.size());
        for (auto &customizeData : item.second) {
            WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &customizeData);
        }
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, metadata.size());
    for (auto &item : metadata) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(item.first));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, item.second.size());
        for (auto &meta : item.second) {
            WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &meta);
        }
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, targetBundleList.size());
    for (auto &targetBundle : targetBundleList) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(targetBundle));
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(fingerprint));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(icon));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, flags);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(entryModuleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isCompressNativeLibs);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(signatureKey));

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, multiProjects);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &appQuickFix);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, needAppDetail);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appDetailAbilityLibraryPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(targetBundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, targetPriority);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, overlayState);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, asanEnabled);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(asanLogPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(bundleType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(compileSdkVersion));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(compileSdkType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, resourcesApply.size());
    for (auto &item : resourcesApply) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, item);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, gwpAsanEnabled);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, applicationReservedFlag);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, tsanEnabled);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, hwasanEnabled);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appEnvironments.size());
    for (auto &item : appEnvironments) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &item);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(organization));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &multiAppMode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, maxChildProcess);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(installSource));

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(configuration));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, cloudFileSyncEnabled);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, applicationFlags);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, ubsanEnabled);
    return true;
}

void ApplicationInfo::Dump(std::string prefix, int fd)
{
    APP_LOGI("called dump ApplicationInfo");
    if (fd < 0) {
        APP_LOGE("dump ApplicationInfo fd error");
        return;
    }
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        APP_LOGE("dump fcntl error : %{public}d", errno);
        return;
    }
    uint uflags = static_cast<uint>(flags);
    uflags &= O_ACCMODE;
    if ((uflags == O_WRONLY) || (uflags == O_RDWR)) {
        nlohmann::json jsonObject = *this;
        std::string result;
        result.append(prefix);
        result.append(jsonObject.dump(Constants::DUMP_INDENT));
        int ret = TEMP_FAILURE_RETRY(write(fd, result.c_str(), result.size()));
        if (ret < 0) {
            APP_LOGE("dump write error : %{public}d", errno);
        }
    }
    return;
}

bool ApplicationInfo::CheckNeedPreload(const std::string &moduleName) const
{
    std::set<std::string> preloadModules;
    auto it = std::find_if(std::begin(moduleInfos), std::end(moduleInfos),
        [&moduleName](ModuleInfo info) {
            return info.moduleName == moduleName;
        });
    if (it != moduleInfos.end()) {
        for (const std::string &name : it->preloads) {
            preloadModules.insert(name);
        }
    }
    if (preloadModules.empty()) {
        APP_LOGD("the module have no preloads");
        return false;
    }
    for (const ModuleInfo &moduleInfo : moduleInfos) {
        auto iter = preloadModules.find(moduleInfo.moduleName);
        if (iter != preloadModules.end()) {
            preloadModules.erase(iter);
        }
    }
    if (preloadModules.empty()) {
        APP_LOGD("all preload modules exist locally");
        return false;
    }
    APP_LOGD("need to process preload");
    return true;
}

void to_json(nlohmann::json &jsonObject, const Resource &resource)
{
    jsonObject = nlohmann::json {
        {Constants::BUNDLE_NAME, resource.bundleName},
        {Constants::MODULE_NAME, resource.moduleName},
        {RESOURCE_ID, resource.id}
    };
}

void from_json(const nlohmann::json &jsonObject, Resource &resource)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        resource.bundleName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        resource.moduleName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        RESOURCE_ID,
        resource.id,
        JsonType::NUMBER,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read Resource error : %{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const MultiAppModeData &multiAppMode)
{
    jsonObject = nlohmann::json {
        {APPLICATION_MULTI_APP_MODE_TYPE, multiAppMode.multiAppModeType},
        {APPLICATION_MULTI_APP_MODE_MAX_ADDITIONAL_NUMBER, multiAppMode.maxCount},
    };
}

void from_json(const nlohmann::json &jsonObject, MultiAppModeData &multiAppMode)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<MultiAppModeType>(jsonObject, jsonObjectEnd, APPLICATION_MULTI_APP_MODE_TYPE,
        multiAppMode.multiAppModeType, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, APPLICATION_MULTI_APP_MODE_MAX_ADDITIONAL_NUMBER,
        multiAppMode.maxCount, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("from_json error : %{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const HnpPackage &hnpPackage)
{
    jsonObject = nlohmann::json {
        {APPLICATION_HNP_PACKAGES_PACKAGE, hnpPackage.package},
        {APPLICATION_HNP_PACKAGES_TYPE, hnpPackage.type},
    };
}

void from_json(const nlohmann::json &jsonObject, HnpPackage &hnpPackage)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_HNP_PACKAGES_PACKAGE,
        hnpPackage.package,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_HNP_PACKAGES_TYPE,
        hnpPackage.type,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read Resource error %{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const ApplicationInfo &applicationInfo)
{
    jsonObject = nlohmann::json {
        {APPLICATION_NAME, applicationInfo.name},
        {Constants::BUNDLE_NAME, applicationInfo.bundleName},
        {APPLICATION_VERSION_CODE, applicationInfo.versionCode},
        {APPLICATION_VERSION_NAME, applicationInfo.versionName},
        {APPLICATION_MIN_COMPATIBLE_VERSION_CODE, applicationInfo.minCompatibleVersionCode},
        {APPLICATION_API_COMPATIBLE_VERSION, applicationInfo.apiCompatibleVersion},
        {APPLICATION_API_TARGET_VERSION, applicationInfo.apiTargetVersion},
        {APPLICATION_ICON_PATH, applicationInfo.iconPath},
        {APPLICATION_ICON_ID, applicationInfo.iconId},
        {APPLICATION_LABEL, applicationInfo.label},
        {APPLICATION_LABEL_ID, applicationInfo.labelId},
        {APPLICATION_DESCRIPTION, applicationInfo.description},
        {APPLICATION_DESCRIPTION_ID, applicationInfo.descriptionId},
        {APPLICATION_KEEP_ALIVE, applicationInfo.keepAlive},
        {APPLICATION_REMOVABLE, applicationInfo.removable},
        {APPLICATION_SINGLETON, applicationInfo.singleton},
        {APPLICATION_USER_DATA_CLEARABLE, applicationInfo.userDataClearable},
        {ALLOW_APP_RUN_WHEN_DEVICE_FIRST_LOCKED, applicationInfo.allowAppRunWhenDeviceFirstLocked},
        {APPLICATION_ACCESSIBLE, applicationInfo.accessible},
        {APPLICATION_IS_SYSTEM_APP, applicationInfo.isSystemApp},
        {APPLICATION_IS_LAUNCHER_APP, applicationInfo.isLauncherApp},
        {APPLICATION_IS_FREEINSTALL_APP, applicationInfo.isFreeInstallApp},
        {APPLICATION_RUNNING_RESOURCES_APPLY, applicationInfo.runningResourcesApply},
        {APPLICATION_ASSOCIATED_WAKE_UP, applicationInfo.associatedWakeUp},
        {APPLICATION_HIDE_DESKTOP_ICON, applicationInfo.hideDesktopIcon},
        {APPLICATION_FORM_VISIBLE_NOTIFY, applicationInfo.formVisibleNotify},
        {APPLICATION_ALLOW_COMMON_EVENT, applicationInfo.allowCommonEvent},
        {APPLICATION_CODE_PATH, applicationInfo.codePath},
        {APPLICATION_DATA_DIR, applicationInfo.dataDir},
        {APPLICATION_DATA_BASE_DIR, applicationInfo.dataBaseDir},
        {APPLICATION_CACHE_DIR, applicationInfo.cacheDir},
        {APPLICATION_ENTRY_DIR, applicationInfo.entryDir},
        {APPLICATION_API_RELEASETYPE, applicationInfo.apiReleaseType},
        {APPLICATION_DEBUG, applicationInfo.debug},
        {APPLICATION_DEVICE_ID, applicationInfo.deviceId},
        {APPLICATION_DISTRIBUTED_NOTIFICATION_ENABLED, applicationInfo.distributedNotificationEnabled},
        {APPLICATION_ALLOW_ENABLE_NOTIFICATION, applicationInfo.allowEnableNotification},
        {APPLICATION_ENTITY_TYPE, applicationInfo.entityType},
        {APPLICATION_PROCESS, applicationInfo.process},
        {APPLICATION_SUPPORTED_MODES, applicationInfo.supportedModes},
        {APPLICATION_VENDOR, applicationInfo.vendor},
        {APPLICATION_PRIVILEGE_LEVEL, applicationInfo.appPrivilegeLevel},
        {APPLICATION_ACCESSTOKEN_ID, applicationInfo.accessTokenId},
        {APPLICATION_ACCESSTOKEN_ID_EX, applicationInfo.accessTokenIdEx},
        {APPLICATION_ENABLED, applicationInfo.enabled},
        {APPLICATION_UID, applicationInfo.uid},
        {APPLICATION_PERMISSIONS, applicationInfo.permissions},
        {APPLICATION_MODULE_SOURCE_DIRS, applicationInfo.moduleSourceDirs},
        {APPLICATION_MODULE_INFOS, applicationInfo.moduleInfos},
        {APPLICATION_HNP_PACKAGES, applicationInfo.hnpPackages},
        {APPLICATION_META_DATA_CONFIG_JSON, applicationInfo.metaData},
        {APPLICATION_META_DATA_MODULE_JSON, applicationInfo.metadata},
        {APPLICATION_FINGERPRINT, applicationInfo.fingerprint},
        {APPLICATION_ICON, applicationInfo.icon},
        {APPLICATION_FLAGS, applicationInfo.flags},
        {APPLICATION_ENTRY_MODULE_NAME, applicationInfo.entryModuleName},
        {APPLICATION_NATIVE_LIBRARY_PATH, applicationInfo.nativeLibraryPath},
        {APPLICATION_CPU_ABI, applicationInfo.cpuAbi},
        {APPLICATION_ARK_NATIVE_FILE_PATH, applicationInfo.arkNativeFilePath},
        {APPLICATION_ARK_NATIVE_FILE_ABI, applicationInfo.arkNativeFileAbi},
        {APPLICATION_IS_COMPRESS_NATIVE_LIBS, applicationInfo.isCompressNativeLibs},
        {APPLICATION_SIGNATURE_KEY, applicationInfo.signatureKey},
        {APPLICATION_TARGETBUNDLELIST, applicationInfo.targetBundleList},
        {APPLICATION_APP_DISTRIBUTION_TYPE, applicationInfo.appDistributionType},
        {APPLICATION_APP_PROVISION_TYPE, applicationInfo.appProvisionType},
        {APPLICATION_ICON_RESOURCE, applicationInfo.iconResource},
        {APPLICATION_LABEL_RESOURCE, applicationInfo.labelResource},
        {APPLICATION_DESCRIPTION_RESOURCE, applicationInfo.descriptionResource},
        {APPLICATION_MULTI_PROJECTS, applicationInfo.multiProjects},
        {APPLICATION_CROWDTEST_DEADLINE, applicationInfo.crowdtestDeadline},
        {APPLICATION_APP_QUICK_FIX, applicationInfo.appQuickFix},
        {APPLICATION_NEED_APP_DETAIL, applicationInfo.needAppDetail},
        {APPLICATION_APP_DETAIL_ABILITY_LIBRARY_PATH, applicationInfo.appDetailAbilityLibraryPath},
        {APPLICATION_APP_TARGET_BUNDLE_NAME, applicationInfo.targetBundleName},
        {APPLICATION_APP_TARGET_PRIORITY, applicationInfo.targetPriority},
        {APPLICATION_APP_OVERLAY_STATE, applicationInfo.overlayState},
        {APPLICATION_ASAN_ENABLED, applicationInfo.asanEnabled},
        {APPLICATION_ASAN_LOG_PATH, applicationInfo.asanLogPath},
        {APPLICATION_APP_TYPE, applicationInfo.bundleType},
        {APPLICATION_COMPILE_SDK_VERSION, applicationInfo.compileSdkVersion},
        {APPLICATION_COMPILE_SDK_TYPE, applicationInfo.compileSdkType},
        {APPLICATION_RESOURCES_APPLY, applicationInfo.resourcesApply},
        {APPLICATION_GWP_ASAN_ENABLED, applicationInfo.gwpAsanEnabled},
        {APPLICATION_HWASAN_ENABLED, applicationInfo.hwasanEnabled},
        {APPLICATION_RESERVED_FLAG, applicationInfo.applicationReservedFlag},
        {APPLICATION_TSAN_ENABLED, applicationInfo.tsanEnabled},
        {APPLICATION_APP_ENVIRONMENTS, applicationInfo.appEnvironments},
        {APPLICATION_ORGANIZATION, applicationInfo.organization},
        {APPLICATION_MULTI_APP_MODE, applicationInfo.multiAppMode},
        {APPLICATION_MAX_CHILD_PROCESS, applicationInfo.maxChildProcess},
        {APPLICATION_APP_INDEX, applicationInfo.appIndex},
        {APPLICATION_INSTALL_SOURCE, applicationInfo.installSource},
        {APPLICATION_CONFIGURATION, applicationInfo.configuration},
        {APPLICATION_CLOUD_FILE_SYNC_ENABLED, applicationInfo.cloudFileSyncEnabled},
        {APPLICATION_APPLICATION_FLAGS, applicationInfo.applicationFlags},
        {APPLICATION_UBSAN_ENABLED, applicationInfo.ubsanEnabled}
    };
}

void from_json(const nlohmann::json &jsonObject, ApplicationInfo &applicationInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_NAME,
        applicationInfo.name, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, Constants::BUNDLE_NAME,
        applicationInfo.bundleName, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, APPLICATION_VERSION_CODE,
        applicationInfo.versionCode, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_VERSION_NAME,
        applicationInfo.versionName, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, APPLICATION_MIN_COMPATIBLE_VERSION_CODE,
        applicationInfo.minCompatibleVersionCode, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, APPLICATION_API_COMPATIBLE_VERSION,
        applicationInfo.apiCompatibleVersion, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, APPLICATION_API_TARGET_VERSION,
        applicationInfo.apiTargetVersion, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_ICON_PATH,
        applicationInfo.iconPath, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, APPLICATION_ICON_ID,
        applicationInfo.iconId, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_LABEL,
        applicationInfo.label, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, APPLICATION_LABEL_ID,
        applicationInfo.labelId, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_DESCRIPTION,
        applicationInfo.description, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, APPLICATION_DESCRIPTION_ID,
        applicationInfo.descriptionId, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_KEEP_ALIVE,
        applicationInfo.keepAlive, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_REMOVABLE,
        applicationInfo.removable, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_SINGLETON,
        applicationInfo.singleton, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_USER_DATA_CLEARABLE,
        applicationInfo.userDataClearable, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, ALLOW_APP_RUN_WHEN_DEVICE_FIRST_LOCKED,
        applicationInfo.allowAppRunWhenDeviceFirstLocked, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_ACCESSIBLE,
        applicationInfo.accessible, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_IS_SYSTEM_APP,
        applicationInfo.isSystemApp, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_IS_LAUNCHER_APP,
        applicationInfo.isLauncherApp, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_IS_FREEINSTALL_APP,
        applicationInfo.isFreeInstallApp, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_RUNNING_RESOURCES_APPLY,
        applicationInfo.runningResourcesApply, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_ASSOCIATED_WAKE_UP,
        applicationInfo.associatedWakeUp, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_HIDE_DESKTOP_ICON,
        applicationInfo.hideDesktopIcon, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_FORM_VISIBLE_NOTIFY,
        applicationInfo.formVisibleNotify, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject, jsonObjectEnd, APPLICATION_ALLOW_COMMON_EVENT,
        applicationInfo.allowCommonEvent, JsonType::ARRAY, false, parseResult, ArrayType::STRING);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_CODE_PATH,
        applicationInfo.codePath, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_DATA_DIR,
        applicationInfo.dataDir, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_DATA_BASE_DIR,
        applicationInfo.dataBaseDir, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_CACHE_DIR,
        applicationInfo.cacheDir, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_ENTRY_DIR,
        applicationInfo.entryDir, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_API_RELEASETYPE,
        applicationInfo.apiReleaseType, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_DEBUG,
        applicationInfo.debug, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_DEVICE_ID,
        applicationInfo.deviceId, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_DISTRIBUTED_NOTIFICATION_ENABLED,
        applicationInfo.distributedNotificationEnabled, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_ALLOW_ENABLE_NOTIFICATION,
        applicationInfo.allowEnableNotification, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_ENTITY_TYPE,
        applicationInfo.entityType, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_PROCESS,
        applicationInfo.process, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject, jsonObjectEnd, APPLICATION_SUPPORTED_MODES,
        applicationInfo.supportedModes, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_VENDOR,
        applicationInfo.vendor, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_PRIVILEGE_LEVEL,
        applicationInfo.appPrivilegeLevel, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, APPLICATION_ACCESSTOKEN_ID,
        applicationInfo.accessTokenId, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint64_t>(jsonObject, jsonObjectEnd, APPLICATION_ACCESSTOKEN_ID_EX,
        applicationInfo.accessTokenIdEx, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_ENABLED,
        applicationInfo.enabled, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject, jsonObjectEnd, APPLICATION_UID,
        applicationInfo.uid, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject, jsonObjectEnd, APPLICATION_PERMISSIONS,
        applicationInfo.permissions, JsonType::ARRAY, false, parseResult, ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject, jsonObjectEnd, APPLICATION_MODULE_SOURCE_DIRS,
        applicationInfo.moduleSourceDirs, JsonType::ARRAY, false, parseResult, ArrayType::STRING);
    GetValueIfFindKey<std::vector<ModuleInfo>>(jsonObject, jsonObjectEnd, APPLICATION_MODULE_INFOS,
        applicationInfo.moduleInfos, JsonType::ARRAY, false, parseResult, ArrayType::OBJECT);
    GetValueIfFindKey<std::map<std::string, std::vector<HnpPackage>>>(jsonObject, jsonObjectEnd,
        APPLICATION_HNP_PACKAGES, applicationInfo.hnpPackages, JsonType::OBJECT, false,
        parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, std::vector<CustomizeData>>>(jsonObject, jsonObjectEnd,
        APPLICATION_META_DATA_CONFIG_JSON,
        applicationInfo.metaData, JsonType::OBJECT, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, std::vector<Metadata>>>(jsonObject, jsonObjectEnd,
        APPLICATION_META_DATA_MODULE_JSON,
        applicationInfo.metadata, JsonType::OBJECT, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_FINGERPRINT,
        applicationInfo.fingerprint, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_ICON,
        applicationInfo.icon, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject, jsonObjectEnd, APPLICATION_FLAGS,
        applicationInfo.flags, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_ENTRY_MODULE_NAME,
        applicationInfo.entryModuleName, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_NATIVE_LIBRARY_PATH,
        applicationInfo.nativeLibraryPath, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_CPU_ABI,
        applicationInfo.cpuAbi, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_ARK_NATIVE_FILE_PATH,
        applicationInfo.arkNativeFilePath, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_ARK_NATIVE_FILE_ABI,
        applicationInfo.arkNativeFileAbi, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_IS_COMPRESS_NATIVE_LIBS,
        applicationInfo.isCompressNativeLibs, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_SIGNATURE_KEY,
        applicationInfo.signatureKey, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject, jsonObjectEnd, APPLICATION_TARGETBUNDLELIST,
        applicationInfo.targetBundleList, JsonType::ARRAY, false, parseResult, ArrayType::STRING);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_APP_DISTRIBUTION_TYPE,
        applicationInfo.appDistributionType, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_APP_PROVISION_TYPE,
        applicationInfo.appProvisionType, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<Resource>(jsonObject, jsonObjectEnd, APPLICATION_ICON_RESOURCE,
        applicationInfo.iconResource, JsonType::OBJECT, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<Resource>(jsonObject, jsonObjectEnd, APPLICATION_LABEL_RESOURCE,
        applicationInfo.labelResource, JsonType::OBJECT, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<Resource>(jsonObject, jsonObjectEnd, APPLICATION_DESCRIPTION_RESOURCE,
        applicationInfo.descriptionResource, JsonType::OBJECT, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_MULTI_PROJECTS,
        applicationInfo.multiProjects, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int64_t>(jsonObject, jsonObjectEnd, APPLICATION_CROWDTEST_DEADLINE,
        applicationInfo.crowdtestDeadline, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<AppQuickFix>(jsonObject, jsonObjectEnd, APPLICATION_APP_QUICK_FIX,
        applicationInfo.appQuickFix, JsonType::OBJECT, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_NEED_APP_DETAIL,
        applicationInfo.needAppDetail, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_APP_DETAIL_ABILITY_LIBRARY_PATH,
        applicationInfo.appDetailAbilityLibraryPath, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_APP_TARGET_BUNDLE_NAME,
        applicationInfo.targetBundleName, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject, jsonObjectEnd, APPLICATION_APP_TARGET_PRIORITY,
        applicationInfo.targetPriority, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject, jsonObjectEnd, APPLICATION_APP_OVERLAY_STATE,
        applicationInfo.overlayState, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_ASAN_ENABLED,
        applicationInfo.asanEnabled, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_ASAN_LOG_PATH,
        applicationInfo.asanLogPath, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<BundleType>(jsonObject, jsonObjectEnd, APPLICATION_APP_TYPE,
        applicationInfo.bundleType, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_COMPILE_SDK_VERSION,
        applicationInfo.compileSdkVersion, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_COMPILE_SDK_TYPE,
        applicationInfo.compileSdkType, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<int32_t>>(jsonObject, jsonObjectEnd, APPLICATION_RESOURCES_APPLY,
        applicationInfo.resourcesApply, JsonType::ARRAY, false, parseResult, ArrayType::NUMBER);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_GWP_ASAN_ENABLED,
        applicationInfo.gwpAsanEnabled, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, APPLICATION_RESERVED_FLAG,
        applicationInfo.applicationReservedFlag, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_TSAN_ENABLED,
        applicationInfo.tsanEnabled, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_ORGANIZATION,
        applicationInfo.organization, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<ApplicationEnvironment>>(jsonObject, jsonObjectEnd,
        APPLICATION_APP_ENVIRONMENTS,
        applicationInfo.appEnvironments, JsonType::ARRAY, false, parseResult, ArrayType::OBJECT);
    GetValueIfFindKey<MultiAppModeData>(jsonObject, jsonObjectEnd, APPLICATION_MULTI_APP_MODE,
        applicationInfo.multiAppMode, JsonType::OBJECT, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, APPLICATION_APP_INDEX,
        applicationInfo.appIndex, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, APPLICATION_MAX_CHILD_PROCESS,
        applicationInfo.maxChildProcess, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_INSTALL_SOURCE,
        applicationInfo.installSource, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_HWASAN_ENABLED,
        applicationInfo.hwasanEnabled, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, APPLICATION_CONFIGURATION,
        applicationInfo.configuration, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_CLOUD_FILE_SYNC_ENABLED,
        applicationInfo.cloudFileSyncEnabled, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, APPLICATION_APPLICATION_FLAGS,
        applicationInfo.applicationFlags, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, APPLICATION_UBSAN_ENABLED,
        applicationInfo.ubsanEnabled, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("from_json error : %{public}d", parseResult);
    }
}

void ApplicationInfo::ConvertToCompatibleApplicationInfo(CompatibleApplicationInfo& compatibleApplicationInfo) const
{
    APP_LOGD("ApplicationInfo::ConvertToCompatibleApplicationInfo called");
    compatibleApplicationInfo.name = name;
    compatibleApplicationInfo.icon = icon;
    compatibleApplicationInfo.label = label;
    compatibleApplicationInfo.description = description;
    compatibleApplicationInfo.cpuAbi = cpuAbi;
    compatibleApplicationInfo.process = process;
    compatibleApplicationInfo.systemApp = isSystemApp;
    compatibleApplicationInfo.isCompressNativeLibs = isCompressNativeLibs;
    compatibleApplicationInfo.iconId = iconId;
    compatibleApplicationInfo.labelId = labelId;
    compatibleApplicationInfo.descriptionId = descriptionId;
    compatibleApplicationInfo.permissions = permissions;
    compatibleApplicationInfo.moduleInfos = moduleInfos;
    compatibleApplicationInfo.supportedModes = supportedModes;
    compatibleApplicationInfo.enabled = enabled;
    compatibleApplicationInfo.debug = debug;
}
}  // namespace AppExecFwk
}  // namespace OHOS
