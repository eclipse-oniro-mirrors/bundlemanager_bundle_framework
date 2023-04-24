/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
const std::string NAME = "name";
const std::string SRC_ENTRANCE = "srcEntrance";
const std::string ICON = "icon";
const std::string ICON_ID = "iconId";
const std::string LABEL = "label";
const std::string LABEL_ID = "labelId";
const std::string DESCRIPTION = "description";
const std::string DESCRIPTION_ID = "descriptionId";
const std::string PRIORITY = "priority";
const std::string TYPE = "type";
const std::string PERMISSIONS = "permissions";
const std::string READ_PERMISSION = "readPermission";
const std::string WRITE_PERMISSION = "writePermission";
const std::string URI = "uri";
const std::string VISIBLE = "visible";
const std::string META_DATA = "metadata";
const std::string APPLICATION_INFO = "applicationInfo";
const std::string RESOURCE_PATH = "resourcePath";
const std::string ENABLED = "enabled";
const std::string PROCESS = "process";
const std::string COMPILE_MODE = "compileMode";
}; // namespace

bool ExtensionAbilityInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    name = Str16ToStr8(parcel.ReadString16());
    srcEntrance = Str16ToStr8(parcel.ReadString16());
    icon = Str16ToStr8(parcel.ReadString16());
    iconId = parcel.ReadInt32();
    label = Str16ToStr8(parcel.ReadString16());
    labelId = parcel.ReadInt32();
    description = Str16ToStr8(parcel.ReadString16());
    descriptionId = parcel.ReadInt32();
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
    visible = parcel.ReadBool();

    int32_t metadataSize;
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
    compileMode = static_cast<CompileMode>(parcel.ReadInt32());
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

bool ExtensionAbilityInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(srcEntrance));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(icon));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, iconId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(label));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, labelId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(description));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, descriptionId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, priority);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, permissions.size());
    for (auto &permission : permissions) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(permission));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(readPermission));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(writePermission));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uri));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(type));
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
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(compileMode));
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
        {READ_PERMISSION, extensionInfo.readPermission},
        {WRITE_PERMISSION, extensionInfo.writePermission},
        {URI, extensionInfo.uri},
        {PERMISSIONS, extensionInfo.permissions},
        {VISIBLE, extensionInfo.visible},
        {META_DATA, extensionInfo.metadata},
        {APPLICATION_INFO, extensionInfo.applicationInfo},
        {RESOURCE_PATH, extensionInfo.resourcePath},
        {Constants::HAP_PATH, extensionInfo.hapPath},
        {ENABLED, extensionInfo.enabled},
        {PROCESS, extensionInfo.process},
        {COMPILE_MODE, extensionInfo.compileMode}
    };
}

void from_json(const nlohmann::json &jsonObject, ExtensionAbilityInfo &extensionInfo)
{
    APP_LOGD("ExtensionAbilityInfo from_json begin");
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        extensionInfo.bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        extensionInfo.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        NAME,
        extensionInfo.name,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        SRC_ENTRANCE,
        extensionInfo.srcEntrance,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ICON,
        extensionInfo.icon,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        ICON_ID,
        extensionInfo.iconId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        LABEL,
        extensionInfo.label,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        LABEL_ID,
        extensionInfo.labelId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        DESCRIPTION,
        extensionInfo.description,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
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
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        READ_PERMISSION,
        extensionInfo.readPermission,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        WRITE_PERMISSION,
        extensionInfo.writePermission,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        URI,
        extensionInfo.uri,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        PERMISSIONS,
        extensionInfo.permissions,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        VISIBLE,
        extensionInfo.visible,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<Metadata>>(jsonObject,
        jsonObjectEnd,
        META_DATA,
        extensionInfo.metadata,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<ApplicationInfo>(jsonObject,
        jsonObjectEnd,
        APPLICATION_INFO,
        extensionInfo.applicationInfo,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        RESOURCE_PATH,
        extensionInfo.resourcePath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::HAP_PATH,
        extensionInfo.hapPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ENABLED,
        extensionInfo.enabled,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        PROCESS,
        extensionInfo.process,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<CompileMode>(jsonObject,
        jsonObjectEnd,
        COMPILE_MODE,
        extensionInfo.compileMode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("ExtensionAbilityInfo from_json error, error code : %{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS