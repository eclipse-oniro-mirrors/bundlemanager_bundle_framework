/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_COMMON_JSON_CONVERTER_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_COMMON_JSON_CONVERTER_H

#include "app_log_wrapper.h"
#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
template<typename T>
void ExtensionFromJson(const nlohmann::json &jsonObject, T &extensionInfo)
{
    APP_LOGD("ExtensionFromJson begin");
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
        Constants::NAME,
        extensionInfo.name,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::SRC_ENTRANCE,
        extensionInfo.srcEntrance,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::ICON,
        extensionInfo.icon,
        false,
        parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        Constants::ICON_ID,
        extensionInfo.iconId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::LABEL,
        extensionInfo.label,
        false,
        parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        Constants::LABEL_ID,
        extensionInfo.labelId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::DESCRIPTION,
        extensionInfo.description,
        false,
        parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        Constants::DESCRIPTION_ID,
        extensionInfo.descriptionId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        Constants::PRIORITY,
        extensionInfo.priority,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<ExtensionAbilityType>(jsonObject,
        jsonObjectEnd,
        Constants::TYPE,
        extensionInfo.type,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::EXTENSION_TYPE_NAME,
        extensionInfo.extensionTypeName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::READ_PERMISSION,
        extensionInfo.readPermission,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::WRITE_PERMISSION,
        extensionInfo.writePermission,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::URI,
        extensionInfo.uri,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        Constants::PERMISSIONS,
        extensionInfo.permissions,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        Constants::APPIDENTIFIER_ALLOW_LIST,
        extensionInfo.appIdentifierAllowList,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::VISIBLE,
        extensionInfo.visible,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<Metadata>>(jsonObject,
        jsonObjectEnd,
        Constants::META_DATA,
        extensionInfo.metadata,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::RESOURCE_PATH,
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
        Constants::ENABLED,
        extensionInfo.enabled,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::PROCESS,
        extensionInfo.process,
        false,
        parseResult);
    GetValueIfFindKey<CompileMode>(jsonObject,
        jsonObjectEnd,
        Constants::COMPILE_MODE,
        extensionInfo.compileMode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        Constants::UID,
        extensionInfo.uid,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        Constants::APP_INDEX,
        extensionInfo.appIndex,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<ExtensionProcessMode>(jsonObject,
        jsonObjectEnd,
        Constants::EXTENSION_PROCESS_MODE,
        extensionInfo.extensionProcessMode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<Skill>>(jsonObject,
        jsonObjectEnd,
        Constants::SKILLS,
        extensionInfo.skills,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::NEED_CREATE_SANDBOX,
        extensionInfo.needCreateSandbox,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        Constants::DATA_GROUP_IDS,
        extensionInfo.dataGroupIds,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        Constants::VALID_DATA_GROUP_IDS,
        extensionInfo.validDataGroupIds,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::CUSTOM_PROCESS,
        extensionInfo.customProcess,
        false,
        parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::ISOLATION_PROCESS,
        extensionInfo.isolationProcess,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::ARKTS_MODE,
        extensionInfo.arkTSMode,
        false,
        parseResult);
    if (parseResult != ERR_OK) {
        APP_LOGE("ExtensionFromJson error : %{public}d", parseResult);
    }
}

template<typename T>
void ExtensionToJson(nlohmann::json &jsonObject, const T &extensionInfo)
{
    APP_LOGD("ExtensionToJson begin");
    jsonObject = nlohmann::json {
        {Constants::BUNDLE_NAME, extensionInfo.bundleName},
        {Constants::MODULE_NAME, extensionInfo.moduleName},
        {Constants::NAME, extensionInfo.name},
        {Constants::SRC_ENTRANCE, extensionInfo.srcEntrance},
        {Constants::ICON, extensionInfo.icon},
        {Constants::ICON_ID, extensionInfo.iconId},
        {Constants::LABEL, extensionInfo.label},
        {Constants::LABEL_ID, extensionInfo.labelId},
        {Constants::DESCRIPTION, extensionInfo.description},
        {Constants::DESCRIPTION_ID, extensionInfo.descriptionId},
        {Constants::PRIORITY, extensionInfo.priority},
        {Constants::TYPE, extensionInfo.type},
        {Constants::EXTENSION_TYPE_NAME, extensionInfo.extensionTypeName},
        {Constants::READ_PERMISSION, extensionInfo.readPermission},
        {Constants::WRITE_PERMISSION, extensionInfo.writePermission},
        {Constants::URI, extensionInfo.uri},
        {Constants::PERMISSIONS, extensionInfo.permissions},
        {Constants::APPIDENTIFIER_ALLOW_LIST, extensionInfo.appIdentifierAllowList},
        {Constants::VISIBLE, extensionInfo.visible},
        {Constants::META_DATA, extensionInfo.metadata},
        {Constants::RESOURCE_PATH, extensionInfo.resourcePath},
        {Constants::HAP_PATH, extensionInfo.hapPath},
        {Constants::ENABLED, extensionInfo.enabled},
        {Constants::PROCESS, extensionInfo.process},
        {Constants::COMPILE_MODE, extensionInfo.compileMode},
        {Constants::UID, extensionInfo.uid},
        {Constants::APP_INDEX, extensionInfo.appIndex},
        {Constants::EXTENSION_PROCESS_MODE, extensionInfo.extensionProcessMode},
        {Constants::SKILLS, extensionInfo.skills},
        {Constants::NEED_CREATE_SANDBOX, extensionInfo.needCreateSandbox},
        {Constants::DATA_GROUP_IDS, extensionInfo.dataGroupIds},
        {Constants::VALID_DATA_GROUP_IDS, extensionInfo.validDataGroupIds},
        {Constants::CUSTOM_PROCESS, extensionInfo.customProcess},
        {Constants::ISOLATION_PROCESS, extensionInfo.isolationProcess},
        {Constants::ARKTS_MODE, extensionInfo.arkTSMode}
    };
}
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_COMMON_JSON_CONVERTER_H
