/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "shortcut_info.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "bundle_constants.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string JSON_KEY_BUNDLE_ID = "id";
const std::string JSON_KEY_BUNDLE_HOST_ABILITY = "hostAbility";
const std::string JSON_KEY_BUNDLE_ICON = "icon";
const std::string JSON_KEY_BUNDLE_LABEL = "label";
const std::string JSON_KEY_BUNDLE_DISABLE_MESSAGE = "disableMessage";
const std::string JSON_KEY_BUNDLE_IS_STATIC = "isStatic";
const std::string JSON_KEY_BUNDLE_IS_HOME_SHORTCUT = "isHomeShortcut";
const std::string JSON_KEY_BUNDLE_IS_ENABLES = "isEnables";
const std::string JSON_KEY_BUNDLE_INTENTS = "intents";
const std::string JSON_KEY_BUNDLE_TARGET_BUNDLE = "targetBundle";
const std::string JSON_KEY_BUNDLE_TARGET_MODULE = "targetModule";
const std::string JSON_KEY_BUNDLE_TARGET_CLASS = "targetClass";
const std::string JSON_KEY_BUNDLE_PARAMETERS = "parameters";
const std::string JSON_KEY_ICON_ID = "iconId";
const std::string JSON_KEY_LABEL_ID = "labelId";
const std::string JSON_KEY_APP_INDEX = "appIndex";
const std::string JSON_KEY_SOURCE_TYPE = "sourceType";
const std::string SHORTCUTS = "shortcuts";
const std::string SHORTCUT_ID = "shortcutId";
const std::string SHORTCUT_WANTS = "wants";
const std::string ICON = "icon";
const std::string ICON_ID = "iconId";
const std::string LABEL = "label";
const std::string LABEL_ID = "labelId";
}  // namespace

bool ShortcutInfo::ReadFromParcel(Parcel &parcel)
{
    id = Str16ToStr8(parcel.ReadString16());
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    hostAbility = Str16ToStr8(parcel.ReadString16());
    icon = Str16ToStr8(parcel.ReadString16());
    label = Str16ToStr8(parcel.ReadString16());
    iconId = parcel.ReadUint32();
    labelId = parcel.ReadUint32();
    disableMessage = Str16ToStr8(parcel.ReadString16());
    isStatic = parcel.ReadBool();
    isHomeShortcut = parcel.ReadBool();
    isEnables = parcel.ReadBool();
    int32_t intentsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, intentsSize);
    CONTAINER_SECURITY_VERIFY(parcel, intentsSize, &intents);
    for (auto i = 0; i < intentsSize; i++) {
        ShortcutIntent shortcutIntent;
        shortcutIntent.targetBundle = Str16ToStr8(parcel.ReadString16()); // target bundle name
        shortcutIntent.targetModule = Str16ToStr8(parcel.ReadString16()); // target module name
        shortcutIntent.targetClass = Str16ToStr8(parcel.ReadString16()); // target class name
        int32_t parametersSize;
        READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, parametersSize);
        CONTAINER_SECURITY_VERIFY(parcel, parametersSize, &shortcutIntent.parameters);
        for (int32_t i = 0; i < parametersSize; ++i) {
            std::string key = Str16ToStr8(parcel.ReadString16());
            std::string value = Str16ToStr8(parcel.ReadString16());
            shortcutIntent.parameters.emplace(key, value);
        }
        intents.emplace_back(shortcutIntent);
    }
    appIndex = parcel.ReadInt32();
    sourceType = parcel.ReadInt32();
    return true;
}

ShortcutInfo *ShortcutInfo::Unmarshalling(Parcel &parcel)
{
    ShortcutInfo *info = new (std::nothrow) ShortcutInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool ShortcutInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(id));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hostAbility));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(icon));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(label));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, iconId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, labelId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(disableMessage));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isStatic);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isHomeShortcut);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isEnables);

    const auto intentsSize = static_cast<int32_t>(intents.size());
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, intentsSize);
    for (auto i = 0; i < intentsSize; i++) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(intents[i].targetBundle));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(intents[i].targetModule));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(intents[i].targetClass));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(intents[i].parameters.size()));
        for (const auto &dataItem : intents[i].parameters) {
            WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(dataItem.first));
            WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(dataItem.second));
        }
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, sourceType);
    return true;
}

void to_json(nlohmann::json &jsonObject, const ShortcutIntent &shortcutIntent)
{
    jsonObject = nlohmann::json {
        {JSON_KEY_BUNDLE_TARGET_BUNDLE, shortcutIntent.targetBundle},
        {JSON_KEY_BUNDLE_TARGET_MODULE, shortcutIntent.targetModule},
        {JSON_KEY_BUNDLE_TARGET_CLASS, shortcutIntent.targetClass},
        {JSON_KEY_BUNDLE_PARAMETERS, shortcutIntent.parameters},
    };
}

void to_json(nlohmann::json &jsonObject, const ShortcutInfo &shortcutInfo)
{
    jsonObject = nlohmann::json {
        {JSON_KEY_BUNDLE_ID, shortcutInfo.id},
        {Constants::BUNDLE_NAME, shortcutInfo.bundleName},
        {Constants::MODULE_NAME, shortcutInfo.moduleName},
        {JSON_KEY_BUNDLE_HOST_ABILITY, shortcutInfo.hostAbility},
        {JSON_KEY_BUNDLE_ICON, shortcutInfo.icon},
        {JSON_KEY_BUNDLE_LABEL, shortcutInfo.label},
        {JSON_KEY_BUNDLE_DISABLE_MESSAGE, shortcutInfo.disableMessage},
        {JSON_KEY_BUNDLE_IS_STATIC, shortcutInfo.isStatic},
        {JSON_KEY_BUNDLE_IS_HOME_SHORTCUT, shortcutInfo.isHomeShortcut},
        {JSON_KEY_BUNDLE_IS_ENABLES, shortcutInfo.isEnables},
        {JSON_KEY_BUNDLE_INTENTS, shortcutInfo.intents},
        {JSON_KEY_ICON_ID, shortcutInfo.iconId},
        {JSON_KEY_LABEL_ID, shortcutInfo.labelId},
        {JSON_KEY_APP_INDEX, shortcutInfo.appIndex},
        {JSON_KEY_SOURCE_TYPE, shortcutInfo.sourceType},
  };
}

void from_json(const nlohmann::json &jsonObject, ShortcutIntent &shortcutIntent)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BUNDLE_TARGET_BUNDLE,
        shortcutIntent.targetBundle,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BUNDLE_TARGET_MODULE,
        shortcutIntent.targetModule,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BUNDLE_TARGET_CLASS,
        shortcutIntent.targetClass,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BUNDLE_PARAMETERS,
        shortcutIntent.parameters,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read shortcutIntent jsonObject error : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, ShortcutInfo &shortcutInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BUNDLE_ID,
        shortcutInfo.id,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        shortcutInfo.bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        shortcutInfo.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BUNDLE_HOST_ABILITY,
        shortcutInfo.hostAbility,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BUNDLE_ICON,
        shortcutInfo.icon,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BUNDLE_LABEL,
        shortcutInfo.label,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BUNDLE_DISABLE_MESSAGE,
        shortcutInfo.disableMessage,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BUNDLE_IS_STATIC,
        shortcutInfo.isStatic,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BUNDLE_IS_HOME_SHORTCUT,
        shortcutInfo.isHomeShortcut,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BUNDLE_IS_ENABLES,
        shortcutInfo.isEnables,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<ShortcutIntent>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BUNDLE_INTENTS,
        shortcutInfo.intents,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ICON_ID,
        shortcutInfo.iconId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_LABEL_ID,
        shortcutInfo.labelId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_APP_INDEX,
        shortcutInfo.appIndex,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SOURCE_TYPE,
        shortcutInfo.sourceType,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read shortcutInfo jsonObject error : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, ShortcutWant &shortcutWant)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        shortcutWant.bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        shortcutWant.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::ABILITY_NAME,
        shortcutWant.abilityName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_BUNDLE_PARAMETERS,
        shortcutWant.parameters,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read shortcutWant module.json error : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, Shortcut &shortcut)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        SHORTCUT_ID,
        shortcut.shortcutId,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ICON,
        shortcut.icon,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        ICON_ID,
        shortcut.iconId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        LABEL,
        shortcut.label,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        LABEL_ID,
        shortcut.labelId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<ShortcutWant>>(jsonObject,
        jsonObjectEnd,
        SHORTCUT_WANTS,
        shortcut.wants,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    if (parseResult != ERR_OK) {
        APP_LOGE("read Shortcut module.json error : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json &jsonObject, ShortcutJson &shortcutJson)
{
    APP_LOGD("read shortcuts tag from module.json");
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::vector<Shortcut>>(jsonObject,
        jsonObjectEnd,
        SHORTCUTS,
        shortcutJson.shortcuts,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    if (parseResult != ERR_OK) {
        APP_LOGE("read ShortcutJson module.json error : %{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
