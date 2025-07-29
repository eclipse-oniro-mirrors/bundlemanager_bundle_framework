/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "ability_info.h"

#include <cstdint>
#include <errno.h>
#include <fcntl.h>
#include <string>
#include <unistd.h>

#include "bundle_constants.h"
#include "common_json_converter.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* META_DATA_VALUEID = "valueId";
constexpr const char* META_DATA_NAME = "name";
constexpr const char* META_DATA_VALUE = "value";
constexpr const char* META_DATA_RESOURCE = "resource";
constexpr const char* START_WINDOW_APP_ICON_ID = "startWindowAppIconId";
constexpr const char* START_WINDOW_ILLUSTRATION_ID = "startWindowIllustrationId";
constexpr const char* START_WINDOW_BRANDING_IMAGE_ID = "startWindowBrandingImageId";
constexpr const char* START_WINDOW_BACKGROUND_COLOR_ID = "startWindowBackgroundColorId";
constexpr const char* START_WINDOW_BACKGROUND_IMAGE_ID = "startWindowBackgroundImageId";
constexpr const char* START_WINDOW_BACKGROUND_IMAGE_FIT = "startWindowBackgroundImageFit";
constexpr const uint32_t ABILITY_CAPACITY = 204800; // 200K
}  // namespace

bool AbilityInfo::ReadFromParcel(Parcel &parcel)
{
    name = Str16ToStr8(parcel.ReadString16());
    label = Str16ToStr8(parcel.ReadString16());
    description = Str16ToStr8(parcel.ReadString16());
    iconPath = Str16ToStr8(parcel.ReadString16());
    labelId = parcel.ReadUint32();
    descriptionId = parcel.ReadUint32();
    iconId = parcel.ReadUint32();
    theme = Str16ToStr8(parcel.ReadString16());
    visible = parcel.ReadBool();
    kind = Str16ToStr8(parcel.ReadString16());
    type = static_cast<AbilityType>(parcel.ReadInt32());
    extensionTypeName = Str16ToStr8(parcel.ReadString16());
    extensionAbilityType = static_cast<ExtensionAbilityType>(parcel.ReadInt32());
    orientation = static_cast<DisplayOrientation>(parcel.ReadInt32());
    launchMode = static_cast<LaunchMode>(parcel.ReadInt32());
    srcPath = Str16ToStr8(parcel.ReadString16());
    srcLanguage = Str16ToStr8(parcel.ReadString16());
    arkTSMode = parcel.ReadString();

    int32_t permissionsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, permissionsSize);
    CONTAINER_SECURITY_VERIFY(parcel, permissionsSize, &permissions);
    for (auto i = 0; i < permissionsSize; i++) {
        permissions.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    process = Str16ToStr8(parcel.ReadString16());

    int32_t deviceTypesSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, deviceTypesSize);
    CONTAINER_SECURITY_VERIFY(parcel, deviceTypesSize, &deviceTypes);
    for (auto i = 0; i < deviceTypesSize; i++) {
        deviceTypes.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    int32_t deviceCapabilitiesSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, deviceCapabilitiesSize);
    CONTAINER_SECURITY_VERIFY(parcel, deviceCapabilitiesSize, &deviceCapabilities);
    for (auto i = 0; i < deviceCapabilitiesSize; i++) {
        deviceCapabilities.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }
    uri = Str16ToStr8(parcel.ReadString16());
    targetAbility = Str16ToStr8(parcel.ReadString16());

    std::unique_ptr<ApplicationInfo> appInfo(parcel.ReadParcelable<ApplicationInfo>());
    if (!appInfo) {
        APP_LOGE("ReadParcelable<ApplicationInfo> failed");
        return false;
    }
    applicationInfo = *appInfo;

    isLauncherAbility = parcel.ReadBool();
    isNativeAbility = parcel.ReadBool();
    enabled = parcel.ReadBool();
    supportPipMode = parcel.ReadBool();
    formEnabled = parcel.ReadBool();
    removeMissionAfterTerminate = parcel.ReadBool();

    readPermission = Str16ToStr8(parcel.ReadString16());
    writePermission = Str16ToStr8(parcel.ReadString16());
    int32_t configChangesSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, configChangesSize);
    CONTAINER_SECURITY_VERIFY(parcel, configChangesSize, &configChanges);
    for (auto i = 0; i < configChangesSize; i++) {
        configChanges.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }
    formEntity = parcel.ReadUint32();
    minFormHeight = parcel.ReadInt32();
    defaultFormHeight = parcel.ReadInt32();
    minFormWidth = parcel.ReadInt32();
    defaultFormWidth = parcel.ReadInt32();
    int32_t metaDataSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, metaDataSize);
    CONTAINER_SECURITY_VERIFY(parcel, metaDataSize, &metaData.customizeData);
    for (auto i = 0; i < metaDataSize; i++) {
        std::unique_ptr<CustomizeData> customizeDataPtr(parcel.ReadParcelable<CustomizeData>());
        if (!customizeDataPtr) {
            APP_LOGE("ReadParcelable<Metadata> failed");
            return false;
        }
        metaData.customizeData.emplace_back(*customizeDataPtr);
    }
    backgroundModes = parcel.ReadUint32();

    package = Str16ToStr8(parcel.ReadString16());
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    applicationName = Str16ToStr8(parcel.ReadString16());

    codePath = Str16ToStr8(parcel.ReadString16());
    resourcePath = Str16ToStr8(parcel.ReadString16());
    hapPath = Str16ToStr8(parcel.ReadString16());

    srcEntrance = Str16ToStr8(parcel.ReadString16());
    int32_t metadataSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, metadataSize);
    CONTAINER_SECURITY_VERIFY(parcel, metadataSize, &metadata);
    for (auto i = 0; i < metadataSize; i++) {
        std::unique_ptr<Metadata> metadataPtr(parcel.ReadParcelable<Metadata>());
        if (!metadataPtr) {
            APP_LOGE("ReadParcelable<Metadata> failed");
            return false;
        }
        metadata.emplace_back(*metadataPtr);
    }
    isModuleJson = parcel.ReadBool();
    isStageBasedModel = parcel.ReadBool();
    continuable = parcel.ReadBool();
    priority = parcel.ReadInt32();

    startWindow = Str16ToStr8(parcel.ReadString16());
    startWindowId = parcel.ReadUint32();
    startWindowIcon = Str16ToStr8(parcel.ReadString16());
    startWindowIconId = parcel.ReadUint32();
    startWindowBackground = Str16ToStr8(parcel.ReadString16());
    startWindowBackgroundId = parcel.ReadUint32();

    originalBundleName = Str16ToStr8(parcel.ReadString16());
    appName = Str16ToStr8(parcel.ReadString16());
    privacyUrl = Str16ToStr8(parcel.ReadString16());
    privacyName = Str16ToStr8(parcel.ReadString16());
    downloadUrl = Str16ToStr8(parcel.ReadString16());
    versionName = Str16ToStr8(parcel.ReadString16());
    className = Str16ToStr8(parcel.ReadString16());
    originalClassName = Str16ToStr8(parcel.ReadString16());
    uriPermissionMode = Str16ToStr8(parcel.ReadString16());
    uriPermissionPath = Str16ToStr8(parcel.ReadString16());
    packageSize = parcel.ReadUint32();
    multiUserShared = parcel.ReadBool();
    grantPermission = parcel.ReadBool();
    directLaunch = parcel.ReadBool();
    subType = static_cast<AbilitySubType>(parcel.ReadInt32());
    libPath = Str16ToStr8(parcel.ReadString16());
    deviceId = Str16ToStr8(parcel.ReadString16());
    compileMode = static_cast<CompileMode>(parcel.ReadInt32());

    int32_t windowModeSize = parcel.ReadInt32();
    CONTAINER_SECURITY_VERIFY(parcel, windowModeSize, &windowModes);
    for (auto index = 0; index < windowModeSize; ++index) {
        windowModes.emplace_back(static_cast<SupportWindowMode>(parcel.ReadInt32()));
    }
    maxWindowRatio = parcel.ReadDouble();
    minWindowRatio = parcel.ReadDouble();
    maxWindowWidth = parcel.ReadUint32();
    minWindowWidth = parcel.ReadUint32();
    maxWindowHeight = parcel.ReadUint32();
    minWindowHeight = parcel.ReadUint32();
    uid = parcel.ReadInt32();
    recoverable = parcel.ReadBool();
    installTime = parcel.ReadInt64();
    int32_t supportExtNameSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportExtNameSize);
    CONTAINER_SECURITY_VERIFY(parcel, supportExtNameSize, &supportExtNames);
    for (auto i = 0; i < supportExtNameSize; i++) {
        supportExtNames.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }
    int32_t supportMimeTypeSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportMimeTypeSize);
    CONTAINER_SECURITY_VERIFY(parcel, supportMimeTypeSize, &supportMimeTypes);
    for (auto i = 0; i < supportMimeTypeSize; i++) {
        supportMimeTypes.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }
    int32_t skillUriSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, skillUriSize);
    CONTAINER_SECURITY_VERIFY(parcel, skillUriSize, &skillUri);
    for (auto i = 0; i < skillUriSize; i++) {
        SkillUriForAbilityAndExtension stctUri;
        stctUri.scheme = Str16ToStr8(parcel.ReadString16());
        stctUri.host = Str16ToStr8(parcel.ReadString16());
        stctUri.port = Str16ToStr8(parcel.ReadString16());
        stctUri.path = Str16ToStr8(parcel.ReadString16());
        stctUri.pathStartWith = Str16ToStr8(parcel.ReadString16());
        stctUri.pathRegex = Str16ToStr8(parcel.ReadString16());
        stctUri.type = Str16ToStr8(parcel.ReadString16());
        stctUri.utd = Str16ToStr8(parcel.ReadString16());
        stctUri.maxFileSupported = parcel.ReadInt32();
        stctUri.linkFeature = Str16ToStr8(parcel.ReadString16());
        stctUri.isMatch = parcel.ReadBool();
        skillUri.emplace_back(stctUri);
    }
    isolationProcess = parcel.ReadBool();
    excludeFromMissions = parcel.ReadBool();
    unclearableMission = parcel.ReadBool();
    excludeFromDock = parcel.ReadBool();
    preferMultiWindowOrientation = Str16ToStr8(parcel.ReadString16());
    int32_t continueTypeSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, continueTypeSize);
    CONTAINER_SECURITY_VERIFY(parcel, continueTypeSize, &continueType);
    for (auto i = 0; i < continueTypeSize; i++) {
        continueType.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    int32_t continueBundleNameSize = 0;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, continueBundleNameSize);
    CONTAINER_SECURITY_VERIFY(parcel, continueBundleNameSize, &continueBundleNames);
    for (auto i = 0; i < continueBundleNameSize; ++i) {
        continueBundleNames.emplace(Str16ToStr8(parcel.ReadString16()));
    }

    linkType = static_cast<LinkType>(parcel.ReadInt32());

    int32_t skillsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, skillsSize);
    CONTAINER_SECURITY_VERIFY(parcel, skillsSize, &skills);
    for (auto i = 0; i < skillsSize; i++) {
        std::unique_ptr<Skill> abilitySkillPtr(parcel.ReadParcelable<Skill>());
        if (!abilitySkillPtr) {
            APP_LOGE("ReadParcelable<SkillForAbility> failed");
            return false;
        }
        skills.emplace_back(*abilitySkillPtr);
    }
    appIndex = parcel.ReadInt32();
    orientationId = parcel.ReadUint32();
    std::unique_ptr<StartWindowResource> startWindowResourcePtr(parcel.ReadParcelable<StartWindowResource>());
    if (!startWindowResourcePtr) {
        APP_LOGE("ReadParcelable<StartWindowResource> failed");
        return false;
    }
    startWindowResource = *startWindowResourcePtr;
    return true;
}

AbilityInfo *AbilityInfo::Unmarshalling(Parcel &parcel)
{
    AbilityInfo *info = new (std::nothrow) AbilityInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool AbilityInfo::Marshalling(Parcel &parcel) const
{
    CHECK_PARCEL_CAPACITY(parcel, ABILITY_CAPACITY);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(label));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(description));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(iconPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, labelId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, descriptionId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, iconId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(theme));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, visible);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(kind));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(type));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(extensionTypeName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(extensionAbilityType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(orientation));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(launchMode));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(srcPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(srcLanguage));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, arkTSMode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, permissions.size());
    for (auto &permission : permissions) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(permission));
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(process));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, deviceTypes.size());
    for (auto &deviceType : deviceTypes) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(deviceType));
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, deviceCapabilities.size());
    for (auto &deviceCapability : deviceCapabilities) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(deviceCapability));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uri));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(targetAbility));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &applicationInfo);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isLauncherAbility);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isNativeAbility);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, enabled);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, supportPipMode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, formEnabled);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, removeMissionAfterTerminate);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(readPermission));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(writePermission));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, configChanges.size());
    for (auto &configChange : configChanges) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(configChange));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, formEntity);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, minFormHeight);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, defaultFormHeight);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, minFormWidth);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, defaultFormWidth);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, metaData.customizeData.size());
    for (auto &meta : metaData.customizeData) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &meta);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, backgroundModes);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(package));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(applicationName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(codePath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(resourcePath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapPath));

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(srcEntrance));

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, metadata.size());
    for (auto &meta : metadata) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &meta);
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isModuleJson);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isStageBasedModel);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, continuable);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, priority);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(startWindow));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, startWindowId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(startWindowIcon));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, startWindowIconId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(startWindowBackground));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, startWindowBackgroundId);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(originalBundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(privacyUrl));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(privacyName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(downloadUrl));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(versionName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(className));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(originalClassName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uriPermissionMode));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uriPermissionPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, packageSize);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, multiUserShared);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, grantPermission);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, directLaunch);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(subType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(libPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(deviceId));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(compileMode));

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, windowModes.size());
    for (auto &mode : windowModes) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(mode));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Double, parcel, maxWindowRatio);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Double, parcel, minWindowRatio);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, maxWindowWidth);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, minWindowWidth);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, maxWindowHeight);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, minWindowHeight);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, recoverable);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, installTime);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportExtNames.size());
    for (auto &supporExtName : supportExtNames) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(supporExtName));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportMimeTypes.size());
    for (auto &supportMimeType : supportMimeTypes) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(supportMimeType));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, skillUri.size());
    for (auto &uri : skillUri) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uri.scheme));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uri.host));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uri.port));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uri.path));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uri.pathStartWith));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uri.pathRegex));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uri.type));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uri.utd));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uri.maxFileSupported);
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uri.linkFeature));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, uri.isMatch);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isolationProcess);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, excludeFromMissions);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, unclearableMission);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, excludeFromDock);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(preferMultiWindowOrientation));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, continueType.size());
    for (auto &continueTypeItem : continueType) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(continueTypeItem));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, continueBundleNames.size());
    for (auto &continueBundleNameItem : continueBundleNames) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(continueBundleNameItem));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(linkType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, skills.size());
    for (auto &skill : skills) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &skill);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, orientationId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &startWindowResource);
    return true;
}

void AbilityInfo::Dump(std::string prefix, int fd)
{
    APP_LOGI("call Dump");
    if (fd < 0) {
        APP_LOGE("dump Abilityinfo fd error");
        return;
    }
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        APP_LOGE("dump Abilityinfo fcntl error : %{public}d", errno);
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
            APP_LOGE("dump Abilityinfo write error : %{public}d", errno);
        }
    }
    return;
}

void to_json(nlohmann::json &jsonObject, const StartWindowResource &startWindowResource)
{
    jsonObject = nlohmann::json {
        {START_WINDOW_APP_ICON_ID, startWindowResource.startWindowAppIconId},
        {START_WINDOW_ILLUSTRATION_ID, startWindowResource.startWindowIllustrationId},
        {START_WINDOW_BRANDING_IMAGE_ID, startWindowResource.startWindowBrandingImageId},
        {START_WINDOW_BACKGROUND_COLOR_ID, startWindowResource.startWindowBackgroundColorId},
        {START_WINDOW_BACKGROUND_IMAGE_ID, startWindowResource.startWindowBackgroundImageId},
        {START_WINDOW_BACKGROUND_IMAGE_FIT, startWindowResource.startWindowBackgroundImageFit}
    };
}

void from_json(const nlohmann::json &jsonObject, StartWindowResource &startWindowResource)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd,
        START_WINDOW_APP_ICON_ID,
        startWindowResource.startWindowAppIconId,
        JsonType::NUMBER, false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd,
        START_WINDOW_ILLUSTRATION_ID,
        startWindowResource.startWindowIllustrationId,
        JsonType::NUMBER, false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd,
        START_WINDOW_BRANDING_IMAGE_ID,
        startWindowResource.startWindowBrandingImageId,
        JsonType::NUMBER, false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd,
        START_WINDOW_BACKGROUND_COLOR_ID,
        startWindowResource.startWindowBackgroundColorId,
        JsonType::NUMBER, false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd,
        START_WINDOW_BACKGROUND_IMAGE_ID,
        startWindowResource.startWindowBackgroundImageId,
        JsonType::NUMBER, false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd,
        START_WINDOW_BACKGROUND_IMAGE_FIT,
        startWindowResource.startWindowBackgroundImageFit,
        false,
        parseResult);
    if (parseResult != ERR_OK) {
        APP_LOGE("read Resource error %{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const CustomizeData &customizeData)
{
    jsonObject = nlohmann::json {
        {JSON_KEY_NAME, customizeData.name},
        {JSON_KEY_META_VALUE, customizeData.value},
        {JSON_KEY_META_EXTRA, customizeData.extra}
    };
}

void to_json(nlohmann::json &jsonObject, const MetaData &metaData)
{
    jsonObject = nlohmann::json {
        {JSON_KEY_CUSTOMIZE_DATA, metaData.customizeData}
    };
}

void to_json(nlohmann::json &jsonObject, const Metadata &metadata)
{
    jsonObject = nlohmann::json {
        {META_DATA_VALUEID, metadata.valueId},
        {META_DATA_NAME, metadata.name},
        {META_DATA_VALUE, metadata.value},
        {META_DATA_RESOURCE, metadata.resource}
    };
}

void to_json(nlohmann::json &jsonObject, const AbilityInfo &abilityInfo)
{
    APP_LOGD("AbilityInfo to_json begin");
    AbilityToJson(jsonObject, abilityInfo);
}

void from_json(const nlohmann::json &jsonObject, CustomizeData &customizeData)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_NAME,
        customizeData.name,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_META_VALUE,
        customizeData.value,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_META_EXTRA,
        customizeData.extra,
        false,
        parseResult);
}

void from_json(const nlohmann::json &jsonObject, MetaData &metaData)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::vector<CustomizeData>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_CUSTOMIZE_DATA,
        metaData.customizeData,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
}

void from_json(const nlohmann::json &jsonObject, Metadata &metadata)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        META_DATA_VALUEID,
        metadata.valueId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        META_DATA_NAME,
        metadata.name,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        META_DATA_VALUE,
        metadata.value,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        META_DATA_RESOURCE,
        metadata.resource,
        false,
        parseResult);
    if (parseResult != ERR_OK) {
        APP_LOGE("read database error : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, AbilityInfo &abilityInfo)
{
    APP_LOGD("AbilityInfo from_json begin");
    AbilityFromJson(jsonObject, abilityInfo);
}

void AbilityInfo::ConvertToCompatiableAbilityInfo(CompatibleAbilityInfo& compatibleAbilityInfo) const
{
    APP_LOGE("AbilityInfo::ConvertToCompatiableAbilityInfo called");
    compatibleAbilityInfo.package = package;
    compatibleAbilityInfo.name = name;
    compatibleAbilityInfo.label = label;
    compatibleAbilityInfo.description = description;
    compatibleAbilityInfo.iconPath = iconPath;
    compatibleAbilityInfo.uri = uri;
    compatibleAbilityInfo.moduleName = moduleName;
    compatibleAbilityInfo.process = process;
    compatibleAbilityInfo.targetAbility = targetAbility;
    compatibleAbilityInfo.appName = appName;
    compatibleAbilityInfo.privacyUrl = privacyUrl;
    compatibleAbilityInfo.privacyName = privacyName;
    compatibleAbilityInfo.downloadUrl = downloadUrl;
    compatibleAbilityInfo.versionName = versionName;
    compatibleAbilityInfo.backgroundModes = backgroundModes;
    compatibleAbilityInfo.packageSize = packageSize;
    compatibleAbilityInfo.visible = visible;
    compatibleAbilityInfo.formEnabled = formEnabled;
    compatibleAbilityInfo.multiUserShared = multiUserShared;
    compatibleAbilityInfo.type = type;
    compatibleAbilityInfo.subType = subType;
    compatibleAbilityInfo.orientation = orientation;
    compatibleAbilityInfo.launchMode = launchMode;
    compatibleAbilityInfo.permissions = permissions;
    compatibleAbilityInfo.deviceTypes = deviceTypes;
    compatibleAbilityInfo.deviceCapabilities = deviceCapabilities;
    compatibleAbilityInfo.supportPipMode = supportPipMode;
    compatibleAbilityInfo.grantPermission = grantPermission;
    compatibleAbilityInfo.readPermission = readPermission;
    compatibleAbilityInfo.writePermission = writePermission;
    compatibleAbilityInfo.uriPermissionMode = uriPermissionMode;
    compatibleAbilityInfo.uriPermissionPath = uriPermissionPath;
    compatibleAbilityInfo.directLaunch = directLaunch;
    compatibleAbilityInfo.bundleName = bundleName;
    compatibleAbilityInfo.className = className;
    compatibleAbilityInfo.originalClassName = originalClassName;
    compatibleAbilityInfo.deviceId = deviceId;
    CompatibleApplicationInfo convertedCompatibleApplicationInfo;
    applicationInfo.ConvertToCompatibleApplicationInfo(convertedCompatibleApplicationInfo);
    compatibleAbilityInfo.applicationInfo = convertedCompatibleApplicationInfo;
    compatibleAbilityInfo.formEntity = formEntity;
    compatibleAbilityInfo.minFormHeight = minFormHeight;
    compatibleAbilityInfo.defaultFormHeight = defaultFormHeight;
    compatibleAbilityInfo.minFormWidth = minFormWidth;
    compatibleAbilityInfo.defaultFormWidth = defaultFormWidth;
    compatibleAbilityInfo.iconId = iconId;
    compatibleAbilityInfo.labelId = labelId;
    compatibleAbilityInfo.descriptionId = descriptionId;
    compatibleAbilityInfo.enabled = enabled;
}

bool StartWindowResource::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, startWindowAppIconId);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, startWindowIllustrationId);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, startWindowBrandingImageId);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, startWindowBackgroundColorId);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, startWindowBackgroundImageId);
    std::u16string startWindowBackgroundImageFitVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, startWindowBackgroundImageFitVal);
    startWindowBackgroundImageFit = Str16ToStr8(startWindowBackgroundImageFitVal);
    return true;
}

bool StartWindowResource::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, startWindowAppIconId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, startWindowIllustrationId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, startWindowBrandingImageId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, startWindowBackgroundColorId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, startWindowBackgroundImageId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(startWindowBackgroundImageFit));
    return true;
}

StartWindowResource *StartWindowResource::Unmarshalling(Parcel &parcel)
{
    StartWindowResource *startWindowResource = new (std::nothrow) StartWindowResource;
    if (startWindowResource && !startWindowResource->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete startWindowResource;
        startWindowResource = nullptr;
    }
    return startWindowResource;
}
}  // namespace AppExecFwk
}  // namespace OHOS
