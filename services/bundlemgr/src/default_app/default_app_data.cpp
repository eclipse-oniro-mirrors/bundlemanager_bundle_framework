/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "app_log_tag_wrapper.h"
#include "default_app_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    int32_t g_defaultAppJson = ERR_OK;
    std::mutex g_mutex;
    constexpr const char* INFOS = "infos";
    constexpr const char* BUNDLE_NAME = "bundleName";
    constexpr const char* MODULE_NAME = "moduleName";
    constexpr const char* ABILITY_NAME = "abilityName";
    constexpr const char* EXTENSION_NAME = "extensionName";
    constexpr const char* TYPE = "type";
    constexpr const char* APP_TYPE = "appType";
}

std::string DefaultAppData::ToString() const
{
    LOG_D(BMS_TAG_DEFAULT, "DefaultAppData ToString begin");
    nlohmann::json jsonObject;
    jsonObject[INFOS] = infos;
    return jsonObject.dump();
}

void DefaultAppData::ToJson(nlohmann::json& jsonObject) const
{
    LOG_D(BMS_TAG_DEFAULT, "DefaultAppData ToJson begin");
    jsonObject[INFOS] = infos;
}

int32_t DefaultAppData::FromJson(const nlohmann::json& jsonObject)
{
    LOG_D(BMS_TAG_DEFAULT, "DefaultAppData FromJson begin");
    const auto& jsonObjectEnd = jsonObject.end();
    std::lock_guard<std::mutex> lock(g_mutex);
    g_defaultAppJson = ERR_OK;
    GetValueIfFindKey<std::map<std::string, Element>>(jsonObject,
        jsonObjectEnd,
        INFOS,
        infos,
        JsonType::OBJECT,
        true,
        g_defaultAppJson,
        ArrayType::NOT_ARRAY);
    if (g_defaultAppJson != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "DefaultAppData FromJson failed, error code : %{public}d", g_defaultAppJson);
    }
    int32_t ret = g_defaultAppJson;
    g_defaultAppJson = ERR_OK;
    return ret;
}

void DefaultAppData::ParseDefaultApplicationConfig(const nlohmann::json& jsonObject)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to ParseDefaultApplicationConfig");
    if (jsonObject.is_discarded() || !jsonObject.is_array() || jsonObject.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "json format error");
        return;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    for (const auto& object : jsonObject) {
        if (!object.is_object()) {
            LOG_W(BMS_TAG_DEFAULT, "not json object");
            continue;
        }
        Element element;
        g_defaultAppJson = ERR_OK;
        from_json(object, element);
        g_defaultAppJson = ERR_OK;
        if (element.type.empty() || !DefaultAppMgr::VerifyElementFormat(element)) {
            LOG_W(BMS_TAG_DEFAULT, "bad element format");
            continue;
        }
        std::vector<std::string> normalizedTypeVector = DefaultAppMgr::Normalize(element.type);
        if (normalizedTypeVector.empty()) {
            LOG_W(BMS_TAG_DEFAULT, "normalizedTypeVector empty");
            continue;
        }
        for (const std::string& normalizedType : normalizedTypeVector) {
            element.type = normalizedType;
            infos.try_emplace(normalizedType, element);
        }
    }
}

void to_json(nlohmann::json& jsonObject, const Element& element)
{
    LOG_D(BMS_TAG_DEFAULT, "Element to_json begin");
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
    LOG_D(BMS_TAG_DEFAULT, "Element from_json begin");
    const auto& jsonObjectEnd = jsonObject.end();
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        BUNDLE_NAME,
        element.bundleName,
        false,
        g_defaultAppJson);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_NAME,
        element.moduleName,
        false,
        g_defaultAppJson);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        ABILITY_NAME,
        element.abilityName,
        false,
        g_defaultAppJson);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        EXTENSION_NAME,
        element.extensionName,
        false,
        g_defaultAppJson);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        TYPE,
        element.type,
        false,
        g_defaultAppJson);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        APP_TYPE,
        element.type,
        false,
        g_defaultAppJson);
    if (g_defaultAppJson != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "Element from_json error, error code : %{public}d", g_defaultAppJson);
    }
}
}
}