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

#include "ability_info.h"

#include <cstdint>
#include <errno.h>
#include <fcntl.h>
#include <string>
#include <unistd.h>

#include "bundle_constants.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* JSON_KEY_PACKAGE = "package";
const char* JSON_KEY_NAME = "name";
const char* JSON_KEY_APPLICATION_NAME = "applicationName";
const char* JSON_KEY_LABEL = "label";
const char* JSON_KEY_DESCRIPTION = "description";
const char* JSON_KEY_ICON_PATH = "iconPath";
const char* JSON_KEY_THEME = "theme";
const char* JSON_KEY_VISIBLE = "visible";
const char* JSON_KEY_KIND = "kind";
const char* JSON_KEY_TYPE = "type";
const char* JSON_KEY_EXTENSION_ABILITY_TYPE = "extensionAbilityType";
const char* JSON_KEY_ORIENTATION = "orientation";
const char* JSON_KEY_LAUNCH_MODE = "launchMode";
const char* JSON_KEY_CODE_PATH = "codePath";
const char* JSON_KEY_RESOURCE_PATH = "resourcePath";
const char* JSON_KEY_PERMISSIONS = "permissions";
const char* JSON_KEY_PROCESS = "process";
const char* JSON_KEY_DEVICE_TYPES = "deviceTypes";
const char* JSON_KEY_DEVICE_CAPABILITIES = "deviceCapabilities";
const char* JSON_KEY_URI = "uri";
const char* JSON_KEY_IS_LAUNCHER_ABILITY = "isLauncherAbility";
const char* JSON_KEY_REMOVE_MISSION_AFTER_TERMINATE = "removeMissionAfterTerminate";
const char* JSON_KEY_IS_NATIVE_ABILITY = "isNativeAbility";
const char* JSON_KEY_ENABLED = "enabled";
const char* JSON_KEY_SUPPORT_PIP_MODE = "supportPipMode";
const char* JSON_KEY_TARGET_ABILITY = "targetAbility";
const char* JSON_KEY_READ_PERMISSION = "readPermission";
const char* JSON_KEY_WRITE_PERMISSION = "writePermission";
const char* JSON_KEY_CONFIG_CHANGES = "configChanges";
const char* JSON_KEY_FORM_ENTITY = "formEntity";
const char* JSON_KEY_MIN_FORM_HEIGHT = "minFormHeight";
const char* JSON_KEY_DEFAULT_FORM_HEIGHT = "defaultFormHeight";
const char* JSON_KEY_MIN_FORM_WIDTH = "minFormWidth";
const char* JSON_KEY_DEFAULT_FORM_WIDTH = "defaultFormWidth";
const char* JSON_KEY_BACKGROUND_MODES = "backgroundModes";
const char* JSON_KEY_CUSTOMIZE_DATA = "customizeData";
const char* JSON_KEY_META_DATA = "metaData";
const char* JSON_KEY_META_VALUE = "value";
const char* JSON_KEY_META_EXTRA = "extra";
const char* JSON_KEY_LABEL_ID = "labelId";
const char* JSON_KEY_DESCRIPTION_ID = "descriptionId";
const char* JSON_KEY_ICON_ID = "iconId";
const char* JSON_KEY_FORM_ENABLED = "formEnabled";
const char* JSON_KEY_SRC_PATH = "srcPath";
const char* JSON_KEY_SRC_LANGUAGE = "srcLanguage";
const char* JSON_KEY_START_WINDOW_ICON = "startWindowIcon";
const char* JSON_KEY_START_WINDOW_ICON_ID = "startWindowIconId";
const char* JSON_KEY_START_WINDOW_BACKGROUND = "startWindowBackground";
const char* JSON_KEY_START_WINDOW_BACKGROUND_ID = "startWindowBackgroundId";
const char* JSON_KEY_COMPILE_MODE = "compileMode";
const char* META_DATA = "metadata";
const char* META_DATA_NAME = "name";
const char* META_DATA_VALUE = "value";
const char* META_DATA_RESOURCE = "resource";
const char* SRC_ENTRANCE = "srcEntrance";
const char* IS_MODULE_JSON = "isModuleJson";
const char* IS_STAGE_BASED_MODEL = "isStageBasedModel";
const char* CONTINUABLE = "continuable";
const char* PRIORITY = "priority";
const char* JOSN_KEY_SUPPORT_WINDOW_MODE = "supportWindowMode";
const char* JOSN_KEY_MAX_WINDOW_RATIO = "maxWindowRatio";
const char* JOSN_KEY_MIN_WINDOW_RATIO = "minWindowRatio";
const char* JOSN_KEY_MAX_WINDOW_WIDTH = "maxWindowWidth";
const char* JOSN_KEY_MIN_WINDOW_WIDTH = "minWindowWidth";
const char* JOSN_KEY_MAX_WINDOW_HEIGHT = "maxWindowHeight";
const char* JOSN_KEY_MIN_WINDOW_HEIGHT = "minWindowHeight";
const char* JOSN_KEY_UID = "uid";
const char* JOSN_KEY_EXCLUDE_FROM_MISSIONS = "excludeFromMissions";
const char* JOSN_KEY_UNCLEARABLE_MISSION = "unclearableMission";
const char* JSON_KEY_EXCLUDE_FROM_DOCK_MISSION = "excludeFromDock";
const char* JSON_KEY_PREFER_MULTI_WINDOW_ORIENTATION_MISSION = "preferMultiWindowOrientation";
const char* JSON_KEY_RECOVERABLE = "recoverable";
const char* JSON_KEY_SUPPORT_EXT_NAMES = "supportExtNames";
const char* JSON_KEY_SUPPORT_MIME_TYPES = "supportMimeTypes";
const char* JSON_KEY_ISOLATION_PROCESS = "isolationProcess";
const char* JSON_KEY_CONTINUE_TYPE = "continueType";
const char* JSON_KEY_APP_INDEX = "appIndex";
const char* JSON_KEY_SKILLS = "skills";
const char* JSON_KEY_ORIENTATION_ID = "orientationId";
const char* JSON_KEY_CONTINUE_BUNDLE_NAME = "continueBundleName";
const uint32_t ABILITY_CAPACITY = 204800; // 200K
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
    codeLanguage = parcel.ReadString();

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
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, codeLanguage);
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
        {META_DATA_NAME, metadata.name},
        {META_DATA_VALUE, metadata.value},
        {META_DATA_RESOURCE, metadata.resource}
    };
}

void to_json(nlohmann::json &jsonObject, const AbilityInfo &abilityInfo)
{
    APP_LOGD("AbilityInfo to_json begin");
    jsonObject = nlohmann::json {
        {JSON_KEY_NAME, abilityInfo.name},
        {JSON_KEY_LABEL, abilityInfo.label},
        {JSON_KEY_DESCRIPTION, abilityInfo.description},
        {JSON_KEY_ICON_PATH, abilityInfo.iconPath},
        {JSON_KEY_LABEL_ID, abilityInfo.labelId},
        {JSON_KEY_DESCRIPTION_ID, abilityInfo.descriptionId},
        {JSON_KEY_ICON_ID, abilityInfo.iconId},
        {JSON_KEY_THEME, abilityInfo.theme},
        {JSON_KEY_VISIBLE, abilityInfo.visible},
        {JSON_KEY_KIND, abilityInfo.kind},
        {JSON_KEY_TYPE, abilityInfo.type},
        {JSON_KEY_EXTENSION_ABILITY_TYPE, abilityInfo.extensionAbilityType},
        {JSON_KEY_ORIENTATION, abilityInfo.orientation},
        {JSON_KEY_LAUNCH_MODE, abilityInfo.launchMode},
        {JSON_KEY_SRC_PATH, abilityInfo.srcPath},
        {JSON_KEY_SRC_LANGUAGE, abilityInfo.srcLanguage},
        {Constants::CODE_LANGUAGE, abilityInfo.codeLanguage},
        {JSON_KEY_PERMISSIONS, abilityInfo.permissions},
        {JSON_KEY_PROCESS, abilityInfo.process},
        {JSON_KEY_DEVICE_TYPES, abilityInfo.deviceTypes},
        {JSON_KEY_DEVICE_CAPABILITIES, abilityInfo.deviceCapabilities},
        {JSON_KEY_URI, abilityInfo.uri},
        {JSON_KEY_TARGET_ABILITY, abilityInfo.targetAbility},
        {JSON_KEY_IS_LAUNCHER_ABILITY, abilityInfo.isLauncherAbility},
        {JSON_KEY_IS_NATIVE_ABILITY, abilityInfo.isNativeAbility},
        {JSON_KEY_ENABLED, abilityInfo.enabled},
        {JSON_KEY_SUPPORT_PIP_MODE, abilityInfo.supportPipMode},
        {JSON_KEY_FORM_ENABLED, abilityInfo.formEnabled},
        {JSON_KEY_READ_PERMISSION, abilityInfo.readPermission},
        {JSON_KEY_WRITE_PERMISSION, abilityInfo.writePermission},
        {JSON_KEY_CONFIG_CHANGES, abilityInfo.configChanges},
        {JSON_KEY_FORM_ENTITY, abilityInfo.formEntity},
        {JSON_KEY_MIN_FORM_HEIGHT, abilityInfo.minFormHeight},
        {JSON_KEY_DEFAULT_FORM_HEIGHT, abilityInfo.defaultFormHeight},
        {JSON_KEY_MIN_FORM_WIDTH, abilityInfo.minFormWidth},
        {JSON_KEY_DEFAULT_FORM_WIDTH, abilityInfo.defaultFormWidth},
        {JSON_KEY_META_DATA, abilityInfo.metaData},
        {JSON_KEY_BACKGROUND_MODES, abilityInfo.backgroundModes},
        {JSON_KEY_PACKAGE, abilityInfo.package},
        {Constants::BUNDLE_NAME, abilityInfo.bundleName},
        {Constants::MODULE_NAME, abilityInfo.moduleName},
        {JSON_KEY_APPLICATION_NAME, abilityInfo.applicationName},
        {JSON_KEY_CODE_PATH, abilityInfo.codePath},
        {JSON_KEY_RESOURCE_PATH, abilityInfo.resourcePath},
        {Constants::HAP_PATH, abilityInfo.hapPath},
        {SRC_ENTRANCE, abilityInfo.srcEntrance},
        {META_DATA, abilityInfo.metadata},
        {IS_MODULE_JSON, abilityInfo.isModuleJson},
        {IS_STAGE_BASED_MODEL, abilityInfo.isStageBasedModel},
        {CONTINUABLE, abilityInfo.continuable},
        {PRIORITY, abilityInfo.priority},
        {JSON_KEY_START_WINDOW_ICON, abilityInfo.startWindowIcon},
        {JSON_KEY_START_WINDOW_ICON_ID, abilityInfo.startWindowIconId},
        {JSON_KEY_START_WINDOW_BACKGROUND, abilityInfo.startWindowBackground},
        {JSON_KEY_START_WINDOW_BACKGROUND_ID, abilityInfo.startWindowBackgroundId},
        {JSON_KEY_REMOVE_MISSION_AFTER_TERMINATE, abilityInfo.removeMissionAfterTerminate},
        {JSON_KEY_COMPILE_MODE, abilityInfo.compileMode},
        {JOSN_KEY_SUPPORT_WINDOW_MODE, abilityInfo.windowModes},
        {JOSN_KEY_MAX_WINDOW_WIDTH, abilityInfo.maxWindowWidth},
        {JOSN_KEY_MIN_WINDOW_WIDTH, abilityInfo.minWindowWidth},
        {JOSN_KEY_MAX_WINDOW_HEIGHT, abilityInfo.maxWindowHeight},
        {JOSN_KEY_MIN_WINDOW_HEIGHT, abilityInfo.minWindowHeight},
        {JOSN_KEY_UID, abilityInfo.uid},
        {JOSN_KEY_EXCLUDE_FROM_MISSIONS, abilityInfo.excludeFromMissions},
        {JOSN_KEY_UNCLEARABLE_MISSION, abilityInfo.unclearableMission},
        {JSON_KEY_EXCLUDE_FROM_DOCK_MISSION, abilityInfo.excludeFromDock},
        {JSON_KEY_PREFER_MULTI_WINDOW_ORIENTATION_MISSION, abilityInfo.preferMultiWindowOrientation},
        {JSON_KEY_RECOVERABLE, abilityInfo.recoverable},
        {JSON_KEY_SUPPORT_EXT_NAMES, abilityInfo.supportExtNames},
        {JSON_KEY_SUPPORT_MIME_TYPES, abilityInfo.supportMimeTypes},
        {JSON_KEY_ISOLATION_PROCESS, abilityInfo.isolationProcess},
        {JSON_KEY_CONTINUE_TYPE, abilityInfo.continueType},
        {JSON_KEY_CONTINUE_BUNDLE_NAME, abilityInfo.continueBundleNames},
        {JSON_KEY_SKILLS, abilityInfo.skills},
        {JSON_KEY_APP_INDEX, abilityInfo.appIndex},
        {JSON_KEY_ORIENTATION_ID, abilityInfo.orientationId}
    };
    if (abilityInfo.maxWindowRatio == 0) {
        // maxWindowRatio in json string will be 0 instead of 0.0
        jsonObject[JOSN_KEY_MAX_WINDOW_RATIO] = 0;
    } else {
        jsonObject[JOSN_KEY_MAX_WINDOW_RATIO] = abilityInfo.maxWindowRatio;
    }

    if (abilityInfo.minWindowRatio == 0) {
        jsonObject[JOSN_KEY_MIN_WINDOW_RATIO] = 0;
    } else {
        jsonObject[JOSN_KEY_MIN_WINDOW_RATIO] = abilityInfo.minWindowRatio;
    }
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
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_NAME,
        abilityInfo.name,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_LABEL,
        abilityInfo.label,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DESCRIPTION,
        abilityInfo.description,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ICON_PATH,
        abilityInfo.iconPath,
        false,
        parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_LABEL_ID,
        abilityInfo.labelId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DESCRIPTION_ID,
        abilityInfo.descriptionId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ICON_ID,
        abilityInfo.iconId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_THEME,
        abilityInfo.theme,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_VISIBLE,
        abilityInfo.visible,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_KIND,
        abilityInfo.kind,
        false,
        parseResult);
    GetValueIfFindKey<AbilityType>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_TYPE,
        abilityInfo.type,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<ExtensionAbilityType>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_EXTENSION_ABILITY_TYPE,
        abilityInfo.extensionAbilityType,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<DisplayOrientation>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ORIENTATION,
        abilityInfo.orientation,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<LaunchMode>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_LAUNCH_MODE,
        abilityInfo.launchMode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SRC_PATH,
        abilityInfo.srcPath,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SRC_LANGUAGE,
        abilityInfo.srcLanguage,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::CODE_LANGUAGE,
        abilityInfo.codeLanguage,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_PERMISSIONS,
        abilityInfo.permissions,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_PROCESS,
        abilityInfo.process,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DEVICE_TYPES,
        abilityInfo.deviceTypes,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DEVICE_CAPABILITIES,
        abilityInfo.deviceCapabilities,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_URI,
        abilityInfo.uri,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_TARGET_ABILITY,
        abilityInfo.targetAbility,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_IS_LAUNCHER_ABILITY,
        abilityInfo.isLauncherAbility,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_IS_NATIVE_ABILITY,
        abilityInfo.isNativeAbility,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ENABLED,
        abilityInfo.enabled,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SUPPORT_PIP_MODE,
        abilityInfo.supportPipMode,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_FORM_ENABLED,
        abilityInfo.formEnabled,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_READ_PERMISSION,
        abilityInfo.readPermission,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_WRITE_PERMISSION,
        abilityInfo.writePermission,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_CONFIG_CHANGES,
        abilityInfo.configChanges,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_FORM_ENTITY,
        abilityInfo.formEntity,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_MIN_FORM_HEIGHT,
        abilityInfo.minFormHeight,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DEFAULT_FORM_HEIGHT,
        abilityInfo.defaultFormHeight,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_MIN_FORM_WIDTH,
        abilityInfo.minFormWidth,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_DEFAULT_FORM_WIDTH,
        abilityInfo.defaultFormWidth,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<MetaData>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_META_DATA,
        abilityInfo.metaData,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BACKGROUND_MODES,
        abilityInfo.backgroundModes,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_PACKAGE,
        abilityInfo.package,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        abilityInfo.bundleName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        abilityInfo.moduleName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_APPLICATION_NAME,
        abilityInfo.applicationName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_CODE_PATH,
        abilityInfo.codePath,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_RESOURCE_PATH,
        abilityInfo.resourcePath,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::HAP_PATH,
        abilityInfo.hapPath,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        SRC_ENTRANCE,
        abilityInfo.srcEntrance,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<Metadata>>(jsonObject,
        jsonObjectEnd,
        META_DATA,
        abilityInfo.metadata,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        IS_MODULE_JSON,
        abilityInfo.isModuleJson,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        IS_STAGE_BASED_MODEL,
        abilityInfo.isStageBasedModel,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        CONTINUABLE,
        abilityInfo.continuable,
        false,
        parseResult);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        PRIORITY,
        abilityInfo.priority,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_START_WINDOW_ICON,
        abilityInfo.startWindowIcon,
        false,
        parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_START_WINDOW_ICON_ID,
        abilityInfo.startWindowIconId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_START_WINDOW_BACKGROUND,
        abilityInfo.startWindowBackground,
        false,
        parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_START_WINDOW_BACKGROUND_ID,
        abilityInfo.startWindowBackgroundId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_REMOVE_MISSION_AFTER_TERMINATE,
        abilityInfo.removeMissionAfterTerminate,
        false,
        parseResult);
    GetValueIfFindKey<CompileMode>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_COMPILE_MODE,
        abilityInfo.compileMode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<SupportWindowMode>>(jsonObject,
        jsonObjectEnd,
        JOSN_KEY_SUPPORT_WINDOW_MODE,
        abilityInfo.windowModes,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::NUMBER);
    GetValueIfFindKey<double>(jsonObject,
        jsonObjectEnd,
        JOSN_KEY_MAX_WINDOW_RATIO,
        abilityInfo.maxWindowRatio,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<double>(jsonObject,
        jsonObjectEnd,
        JOSN_KEY_MIN_WINDOW_RATIO,
        abilityInfo.minWindowRatio,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JOSN_KEY_MAX_WINDOW_WIDTH,
        abilityInfo.maxWindowWidth,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JOSN_KEY_MIN_WINDOW_WIDTH,
        abilityInfo.minWindowWidth,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JOSN_KEY_MAX_WINDOW_HEIGHT,
        abilityInfo.maxWindowHeight,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JOSN_KEY_MIN_WINDOW_HEIGHT,
        abilityInfo.minWindowHeight,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JOSN_KEY_UID,
        abilityInfo.uid,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JOSN_KEY_EXCLUDE_FROM_MISSIONS,
        abilityInfo.excludeFromMissions,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JOSN_KEY_UNCLEARABLE_MISSION,
        abilityInfo.unclearableMission,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_EXCLUDE_FROM_DOCK_MISSION,
        abilityInfo.excludeFromDock,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_PREFER_MULTI_WINDOW_ORIENTATION_MISSION,
        abilityInfo.preferMultiWindowOrientation,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_RECOVERABLE,
        abilityInfo.recoverable,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SUPPORT_EXT_NAMES,
        abilityInfo.supportExtNames,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SUPPORT_MIME_TYPES,
        abilityInfo.supportMimeTypes,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ISOLATION_PROCESS,
        abilityInfo.isolationProcess,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_CONTINUE_TYPE,
        abilityInfo.continueType,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::unordered_set<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_CONTINUE_BUNDLE_NAME,
        abilityInfo.continueBundleNames,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<Skill>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SKILLS,
        abilityInfo.skills,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_APP_INDEX,
        abilityInfo.appIndex,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ORIENTATION_ID,
        abilityInfo.orientationId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("AbilityInfo from_json error : %{public}d", parseResult);
    }
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
}  // namespace AppExecFwk
}  // namespace OHOS
