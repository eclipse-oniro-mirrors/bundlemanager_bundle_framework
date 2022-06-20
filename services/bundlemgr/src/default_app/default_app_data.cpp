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

#include "default_app_data.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "default_app_mgr.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::string INFOS = "infos";
    const std::string BUNDLE_NAME = "bundleName";
    const std::string MODULE_NAME = "moduleName";
    const std::string ABILITY_NAME = "abilityName";
    const std::string EXTENSION_NAME = "extensionName";
    const std::string TYPE = "type";
}

std::string DefaultAppData::ToString() const
{
    APP_LOGD("DefaultAppData ToString begin.");
    nlohmann::json j;
    j[INFOS] = infos;
    return j.dump();
}

void DefaultAppData::ToJson(nlohmann::json& jsonObject) const
{
    APP_LOGD("DefaultAppData ToJson begin.");
    jsonObject[INFOS] = infos;
}

int32_t DefaultAppData::FromJson(const nlohmann::json& jsonObject)
{
    APP_LOGD("DefaultAppData FromJson begin.");
    const auto& jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::map<std::string, Element>>(jsonObject,
        jsonObjectEnd,
        INFOS,
        infos,
        JsonType::OBJECT,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("DefaultAppData FromJson failed, error code : %{public}d", parseResult);
    }
    return parseResult;
}

bool DefaultAppData::ParseDefaultApplicationConfig(const nlohmann::json& jsonObject)
{
    APP_LOGD("begin to ParseDefaultApplicationConfig.");
    if (jsonObject.is_discarded() || !jsonObject.is_array() || jsonObject.empty()) {
        APP_LOGW("json format error.");
        return false;
    }
    for (const auto& object : jsonObject) {
        if (!object.is_object()) {
            APP_LOGW("not json object.");
            continue;
        }
        Element element;
        from_json(object, element);
        if (element.type.empty() || !DefaultAppMgr::VerifyElementFormat(element)) {
            APP_LOGW("bad element format.");
            continue;
        }
        infos.try_emplace(element.type, element);
    }
    return true;
}

void to_json(nlohmann::json& jsonObject, const Element& element)
{
    APP_LOGD("Element to_json begin.");
    jsonObject = nlohmann::json {
        {BUNDLE_NAME, element.bundleName},
        {MODULE_NAME, element.moduleName},
        {ABILITY_NAME, element.abilityName},
        {EXTENSION_NAME, element.extensionName},
        {TYPE, element.type}
    };
}

void from_json(const nlohmann::json& jsonObject, Element& element)
{
    APP_LOGD("Element from_json begin.");
    const auto& jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_NAME,
        element.bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_NAME,
        element.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ABILITY_NAME,
        element.abilityName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        EXTENSION_NAME,
        element.extensionName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        TYPE,
        element.type,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("Element from_json error, error code : %{public}d", parseResult);
    }
}
}
}