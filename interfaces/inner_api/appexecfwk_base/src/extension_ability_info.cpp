/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "extension_ability_info.h"

#include <fcntl.h>
#include <set>
#include <string>
#include <unistd.h>

#include "bundle_constants.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
const char* JSON_KEY_SKILLS = "skills";
namespace {
const char* NAME = "name";
const char* SRC_ENTRANCE = "srcEntrance";
const char* ICON = "icon";
const char* ICON_ID = "iconId";
const char* LABEL = "label";
const char* LABEL_ID = "labelId";
const char* DESCRIPTION = "description";
const char* DESCRIPTION_ID = "descriptionId";
const char* PRIORITY = "priority";
const char* TYPE = "type";
const char* EXTENSION_TYPE_NAME = "extensionTypeName";
const char* PERMISSIONS = "permissions";
const char* READ_PERMISSION = "readPermission";
const char* WRITE_PERMISSION = "writePermission";
const char* URI = "uri";
const char* VISIBLE = "visible";
const char* META_DATA = "metadata";
const char* RESOURCE_PATH = "resourcePath";
const char* ENABLED = "enabled";
const char* PROCESS = "process";
const char* COMPILE_MODE = "compileMode";
const char* UID = "uid";
const char* APP_INDEX = "appIndex";
const uint32_t ABILITY_CAPACITY = 204800; // 200K
const char* EXTENSION_PROCESS_MODE = "extensionProcessMode";
const char* SKILLS = "skills";
const char* NEED_CREATE_SANDBOX = "needCreateSandbox";
const char* DATA_GROUP_IDS = "dataGroupIds";
const char* JSON_KEY_VALID_DATA_GROUP_IDS = "validDataGroupIds";

const std::unordered_map<std::string, ExtensionAbilityType> EXTENSION_TYPE_MAP = {
    { "form", ExtensionAbilityType::FORM },
    { "workScheduler", ExtensionAbilityType::WORK_SCHEDULER },
    { "inputMethod", ExtensionAbilityType::INPUTMETHOD },
    { "service", ExtensionAbilityType::SERVICE },
    { "accessibility", ExtensionAbilityType::ACCESSIBILITY },
    { "fence", ExtensionAbilityType::FENCE },
    { "dataShare", ExtensionAbilityType::DATASHARE },
    { "fileShare", ExtensionAbilityType::FILESHARE },
    { "staticSubscriber", ExtensionAbilityType::STATICSUBSCRIBER },
    { "wallpaper", ExtensionAbilityType::WALLPAPER },
    { "backup", ExtensionAbilityType::BACKUP },
    { "window", ExtensionAbilityType::WINDOW },
    { "enterpriseAdmin", ExtensionAbilityType::ENTERPRISE_ADMIN },
    { "fileAccess", ExtensionAbilityType::FILEACCESS_EXTENSION },
    { "thumbnail", ExtensionAbilityType::THUMBNAIL },
    { "preview", ExtensionAbilityType::PREVIEW },
    { "print", ExtensionAbilityType::PRINT },
    { "share", ExtensionAbilityType::SHARE },
    { "push", ExtensionAbilityType::PUSH },
    { "driver", ExtensionAbilityType::DRIVER },
    { "action", ExtensionAbilityType::ACTION },
    { "adsService", ExtensionAbilityType::ADS_SERVICE },
    { "embeddedUI", ExtensionAbilityType::EMBEDDED_UI },
    { "statusBarView", ExtensionAbilityType::STATUS_BAR_VIEW },
    { "insightIntentUI", ExtensionAbilityType::INSIGHT_INTENT_UI },
    { "autoFill/password", ExtensionAbilityType::AUTO_FILL_PASSWORD },
    { "appAccountAuthorization", ExtensionAbilityType::APP_ACCOUNT_AUTHORIZATION },
    { "ui", ExtensionAbilityType::UI },
    { "remoteNotification", ExtensionAbilityType::REMOTE_NOTIFICATION },
    { "remoteLocation", ExtensionAbilityType::REMOTE_LOCATION },
    { "voip", ExtensionAbilityType::VOIP },
    { "accountLogout", ExtensionAbilityType::ACCOUNTLOGOUT },
    { "sysDialog/userAuth", ExtensionAbilityType::SYSDIALOG_USERAUTH },
    { "sysDialog/common", ExtensionAbilityType::SYSDIALOG_COMMON },
    { "sysPicker/mediaControl", ExtensionAbilityType::SYSPICKER_MEDIACONTROL },
    { "sysDialog/atomicServicePanel", ExtensionAbilityType::SYSDIALOG_ATOMICSERVICEPANEL },
    { "sysDialog/power", ExtensionAbilityType::SYSDIALOG_POWER },
    { "sysPicker/share", ExtensionAbilityType::SYSPICKER_SHARE },
    { "hms/account", ExtensionAbilityType::HMS_ACCOUNT },
    { "ads", ExtensionAbilityType::ADS },
    { "sysDialog/meetimeCall", ExtensionAbilityType::SYSDIALOG_MEETIMECALL },
    { "sysDialog/meetimeContact", ExtensionAbilityType::SYSDIALOG_MEETIMECONTACT },
    { "sysDialog/meetimeMessage", ExtensionAbilityType::SYSDIALOG_MEETIMEMESSAGE },
    { "sysDialog/print", ExtensionAbilityType::SYSDIALOG_PRINT },
    { "sysPicker/meetimeContact", ExtensionAbilityType::SYSPICKER_MEETIMECONTACT },
    { "sysPicker/meetimeCallLog", ExtensionAbilityType::SYSPICKER_MEETIMECALLLOG },
    { "sysPicker/photoPicker", ExtensionAbilityType::SYSPICKER_PHOTOPICKER },
    { "sysPicker/navigation", ExtensionAbilityType::SYSPICKER_NAVIGATION },
    { "sysPicker/appSelector", ExtensionAbilityType::SYSPICKER_APPSELECTOR },
    { "sysPicker/camera", ExtensionAbilityType::SYSPICKER_CAMERA },
    { "sysPicker/filePicker", ExtensionAbilityType::SYSPICKER_FILEPICKER },
    { "sysPicker/audioPicker", ExtensionAbilityType::SYSPICKER_AUDIOPICKER },
    { "sys/commonUI", ExtensionAbilityType::SYS_COMMON_UI },
    { "vpn", ExtensionAbilityType::VPN },
    { "autoFill/smart", ExtensionAbilityType::AUTO_FILL_SMART },
    { "liveViewLockScreen", ExtensionAbilityType::LIVEVIEW_LOCKSCREEN },
    { "photoEditor", ExtensionAbilityType::PHOTO_EDITOR },
    { "callerInfoQuery", ExtensionAbilityType::CALLER_INFO_QUERY },
    { "sysPicker/photoEditor", ExtensionAbilityType::SYSPICKER_PHOTOEDITOR },
    { "sys/visualExtension", ExtensionAbilityType::SYS_VISUAL },
    { "uiService", ExtensionAbilityType::UI_SERVICE },
    { "recentPhoto", ExtensionAbilityType::RECENT_PHOTO }
};

// the new extension type does not need to be added here
const std::set<std::string> NOT_NEED_CREATE_SANBOX_MODE = {
    "form", "workScheduler", "service", "accessibility", "dataShare", "fileShare", "staticSubscriber", "wallpaper",
    "backup", "window", "enterpriseAdmin", "fileAccess", "thumbnail", "preview", "print", "share", "push", "driver",
    "action", "adsService", "embeddedUI", "insightIntentUI", "statusBarView", "autoFill/password",
    "appAccountAuthorization", "ui", "remoteNotification", "remoteLocation", "voip", "accountLogout",
    "sysDialog/userAuth", "sysDialog/common", "sysPicker/mediaControl", "sysDialog/atomicServicePanel",
    "sysDialog/power", "sysPicker/share", "hms/account", "ads", "sysDialog/meetimeCall",
    "sysDialog/meetimeContact", "sysDialog/meetimeMessage", "sysDialog/print", "sysPicker/meetimeContact",
    "sysPicker/meetimeCallLog", "sysPicker/photoPicker", "sysPicker/camera", "sysPicker/navigation",
    "sysPicker/appSelector", "sys/commonUI", "vpn", "autoFill/smart", "liveViewLockScreen"
};

const std::unordered_map<std::string, ExtensionProcessMode> EXTENSION_PROCESS_MODE_MAP = {
    { "instance", ExtensionProcessMode::INSTANCE },
    { "type", ExtensionProcessMode::TYPE },
    { "bundle", ExtensionProcessMode::BUNDLE },
    { "runWithMainProcess", ExtensionProcessMode::RUN_WITH_MAIN_PROCESS }
};

bool ReadSkillInfoFromParcel(Parcel &parcel, std::vector<SkillUriForAbilityAndExtension> &skillUri)
{
    int32_t skillUriSize = 0;
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
    return true;
}

bool ReadMetadataFromParcel(Parcel &parcel, std::vector<Metadata> &metadata)
{
    int32_t metadataSize = 0;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, metadataSize);
    CONTAINER_SECURITY_VERIFY(parcel, metadataSize, &metadata);
    for (auto i = 0; i < metadataSize; i++) {
        std::unique_ptr<Metadata> meta(parcel.ReadParcelable<Metadata>());
        if (!meta) {
            APP_LOGE("ReadParcelable<Metadata> failed");
            return false;
        }
        metadata.emplace_back(*meta);
    }
    return true;
}
}; // namespace

bool ExtensionAbilityInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    name = Str16ToStr8(parcel.ReadString16());
    srcEntrance = Str16ToStr8(parcel.ReadString16());
    icon = Str16ToStr8(parcel.ReadString16());
    iconId = parcel.ReadUint32();
    label = Str16ToStr8(parcel.ReadString16());
    labelId = parcel.ReadUint32();
    description = Str16ToStr8(parcel.ReadString16());
    descriptionId = parcel.ReadUint32();
    priority = parcel.ReadInt32();
    int32_t permissionsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, permissionsSize);
    CONTAINER_SECURITY_VERIFY(parcel, permissionsSize, &permissions);
    for (auto i = 0; i < permissionsSize; i++) {
        permissions.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }
    readPermission = Str16ToStr8(parcel.ReadString16());
    writePermission = Str16ToStr8(parcel.ReadString16());
    uri = Str16ToStr8(parcel.ReadString16());
    type = static_cast<ExtensionAbilityType>(parcel.ReadInt32());
    extensionTypeName = Str16ToStr8(parcel.ReadString16());
    visible = parcel.ReadBool();
    if (!ReadMetadataFromParcel(parcel, metadata)) {
        APP_LOGE("Read meta data failed");
        return false;
    }

    std::unique_ptr<ApplicationInfo> appInfo(parcel.ReadParcelable<ApplicationInfo>());
    if (!appInfo) {
        APP_LOGE("ReadParcelable<ApplicationInfo> failed");
        return false;
    }
    applicationInfo = *appInfo;

    resourcePath = Str16ToStr8(parcel.ReadString16());
    hapPath = Str16ToStr8(parcel.ReadString16());
    enabled = parcel.ReadBool();
    process = Str16ToStr8(parcel.ReadString16());
    codeLanguage = parcel.ReadString();
    compileMode = static_cast<CompileMode>(parcel.ReadInt32());
    uid = parcel.ReadInt32();
    appIndex = parcel.ReadInt32();
    if (!ReadSkillInfoFromParcel(parcel, skillUri)) {
        APP_LOGE("Read skill info failed");
        return false;
    }
    extensionProcessMode = static_cast<ExtensionProcessMode>(parcel.ReadInt32());
    int32_t skillsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, skillsSize);
    CONTAINER_SECURITY_VERIFY(parcel, skillsSize, &skills);
    for (auto i = 0; i < skillsSize; i++) {
        std::unique_ptr<Skill> extensionSkillPtr(parcel.ReadParcelable<Skill>());
        if (!extensionSkillPtr) {
            APP_LOGE("ReadParcelable<SkillForExtension> failed");
            return false;
        }
        skills.emplace_back(*extensionSkillPtr);
    }

    needCreateSandbox = parcel.ReadBool();
    int32_t dataGroupIdsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, dataGroupIdsSize);
    CONTAINER_SECURITY_VERIFY(parcel, dataGroupIdsSize, &dataGroupIds);
    for (auto i = 0; i < dataGroupIdsSize; i++) {
        dataGroupIds.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }
    int32_t validDataGroupIdsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, validDataGroupIdsSize);
    CONTAINER_SECURITY_VERIFY(parcel, validDataGroupIdsSize, &validDataGroupIds);
    for (auto i = 0; i < validDataGroupIdsSize; i++) {
        dataGroupIds.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }
    return true;
}

ExtensionAbilityInfo *ExtensionAbilityInfo::Unmarshalling(Parcel &parcel)
{
    ExtensionAbilityInfo *info = new (std::nothrow) ExtensionAbilityInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool ExtensionAbilityInfo::MarshallingSkillUri(Parcel &parcel, SkillUriForAbilityAndExtension uri) const
{
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
    return true;
}

bool ExtensionAbilityInfo::Marshalling(Parcel &parcel) const
{
    CHECK_PARCEL_CAPACITY(parcel, ABILITY_CAPACITY);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(srcEntrance));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(icon));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, iconId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(label));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, labelId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(description));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, descriptionId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, priority);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, permissions.size());
    for (auto &permission : permissions) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(permission));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(readPermission));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(writePermission));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uri));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(type));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(extensionTypeName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, visible);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, metadata.size());
    for (auto &mete : metadata) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &mete);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &applicationInfo);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(resourcePath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, enabled);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(process));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, codeLanguage);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(compileMode));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, skillUri.size());
    for (auto &uri : skillUri) {
        MarshallingSkillUri(parcel, uri);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(extensionProcessMode));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, skills.size());
    for (auto &skill : skills) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &skill);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, needCreateSandbox);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, dataGroupIds.size());
    for (auto &dataGroupId : dataGroupIds) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(dataGroupId));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, validDataGroupIds.size());
    for (auto &dataGroupId : validDataGroupIds) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(dataGroupId));
    }
    return true;
}

void to_json(nlohmann::json &jsonObject, const ExtensionAbilityInfo &extensionInfo)
{
    APP_LOGD("ExtensionAbilityInfo to_json begin");
    jsonObject = nlohmann::json {
        {Constants::BUNDLE_NAME, extensionInfo.bundleName},
        {Constants::MODULE_NAME, extensionInfo.moduleName},
        {NAME, extensionInfo.name},
        {SRC_ENTRANCE, extensionInfo.srcEntrance},
        {ICON, extensionInfo.icon},
        {ICON_ID, extensionInfo.iconId},
        {LABEL, extensionInfo.label},
        {LABEL_ID, extensionInfo.labelId},
        {DESCRIPTION, extensionInfo.description},
        {DESCRIPTION_ID, extensionInfo.descriptionId},
        {PRIORITY, extensionInfo.priority},
        {TYPE, extensionInfo.type},
        {EXTENSION_TYPE_NAME, extensionInfo.extensionTypeName},
        {READ_PERMISSION, extensionInfo.readPermission},
        {WRITE_PERMISSION, extensionInfo.writePermission},
        {URI, extensionInfo.uri},
        {PERMISSIONS, extensionInfo.permissions},
        {VISIBLE, extensionInfo.visible},
        {META_DATA, extensionInfo.metadata},
        {RESOURCE_PATH, extensionInfo.resourcePath},
        {Constants::HAP_PATH, extensionInfo.hapPath},
        {ENABLED, extensionInfo.enabled},
        {PROCESS, extensionInfo.process},
        {Constants::CODE_LANGUAGE, extensionInfo.codeLanguage},
        {COMPILE_MODE, extensionInfo.compileMode},
        {UID, extensionInfo.uid},
        {APP_INDEX, extensionInfo.appIndex},
        {EXTENSION_PROCESS_MODE, extensionInfo.extensionProcessMode},
        {JSON_KEY_SKILLS, extensionInfo.skills},
        {NEED_CREATE_SANDBOX, extensionInfo.needCreateSandbox},
        {DATA_GROUP_IDS, extensionInfo.dataGroupIds},
        {JSON_KEY_VALID_DATA_GROUP_IDS, extensionInfo.validDataGroupIds}
    };
}

void from_json(const nlohmann::json &jsonObject, ExtensionAbilityInfo &extensionInfo)
{
    APP_LOGD("ExtensionAbilityInfo from_json begin");
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        extensionInfo.bundleName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        extensionInfo.moduleName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        NAME,
        extensionInfo.name,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        SRC_ENTRANCE,
        extensionInfo.srcEntrance,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ICON,
        extensionInfo.icon,
        false,
        parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        ICON_ID,
        extensionInfo.iconId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        LABEL,
        extensionInfo.label,
        false,
        parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        LABEL_ID,
        extensionInfo.labelId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        DESCRIPTION,
        extensionInfo.description,
        false,
        parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        DESCRIPTION_ID,
        extensionInfo.descriptionId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        PRIORITY,
        extensionInfo.priority,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<ExtensionAbilityType>(jsonObject,
        jsonObjectEnd,
        TYPE,
        extensionInfo.type,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        EXTENSION_TYPE_NAME,
        extensionInfo.extensionTypeName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        READ_PERMISSION,
        extensionInfo.readPermission,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        WRITE_PERMISSION,
        extensionInfo.writePermission,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        URI,
        extensionInfo.uri,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        PERMISSIONS,
        extensionInfo.permissions,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        VISIBLE,
        extensionInfo.visible,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<Metadata>>(jsonObject,
        jsonObjectEnd,
        META_DATA,
        extensionInfo.metadata,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        RESOURCE_PATH,
        extensionInfo.resourcePath,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::HAP_PATH,
        extensionInfo.hapPath,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ENABLED,
        extensionInfo.enabled,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        PROCESS,
        extensionInfo.process,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::CODE_LANGUAGE,
        extensionInfo.codeLanguage,
        false,
        parseResult);
    GetValueIfFindKey<CompileMode>(jsonObject,
        jsonObjectEnd,
        COMPILE_MODE,
        extensionInfo.compileMode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        UID,
        extensionInfo.uid,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        APP_INDEX,
        extensionInfo.appIndex,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<ExtensionProcessMode>(jsonObject,
        jsonObjectEnd,
        EXTENSION_PROCESS_MODE,
        extensionInfo.extensionProcessMode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<Skill>>(jsonObject,
        jsonObjectEnd,
        SKILLS,
        extensionInfo.skills,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        NEED_CREATE_SANDBOX,
        extensionInfo.needCreateSandbox,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        DATA_GROUP_IDS,
        extensionInfo.dataGroupIds,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_VALID_DATA_GROUP_IDS,
        extensionInfo.validDataGroupIds,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    if (parseResult != ERR_OK) {
        APP_LOGE("ExtensionAbilityInfo from_json error : %{public}d", parseResult);
    }
}

ExtensionAbilityType ConvertToExtensionAbilityType(const std::string &type)
{
    if (EXTENSION_TYPE_MAP.find(type) != EXTENSION_TYPE_MAP.end()) {
        return EXTENSION_TYPE_MAP.at(type);
    }

    return ExtensionAbilityType::UNSPECIFIED;
}

std::string ConvertToExtensionTypeName(ExtensionAbilityType type)
{
    for (const auto &[key, val] : EXTENSION_TYPE_MAP) {
        if (val == type) {
            return key;
        }
    }

    return "Unspecified";
}

ExtensionProcessMode ConvertToExtensionProcessMode(const std::string &extensionProcessMode)
{
    if (EXTENSION_PROCESS_MODE_MAP.find(extensionProcessMode) != EXTENSION_PROCESS_MODE_MAP.end()) {
        return EXTENSION_PROCESS_MODE_MAP.at(extensionProcessMode);
    }

    return ExtensionProcessMode::UNDEFINED;
}

void ExtensionAbilityInfo::UpdateNeedCreateSandbox()
{
    needCreateSandbox = false;
}
}  // namespace AppExecFwk
}  // namespace OHOS
