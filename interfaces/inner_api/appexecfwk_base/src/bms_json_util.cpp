/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
void BMSJsonUtil::GetStrValueIfFindKey(const nlohmann::json &jsonObject,
    const nlohmann::detail::iter_impl<const nlohmann::json> &end,
    const std::string &key, std::string &data, bool isNecessary, int32_t &parseResult)
{
    if (parseResult) {
        return;
    }
    auto iter = jsonObject.find(key);
    if (iter != end) {
        if (!iter->is_string()) {
            APP_LOGE("type error %{public}s not string", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
            return;
        }
        data = iter->get<std::string>();
        if (data.length() > Constants::MAX_JSON_STRING_LENGTH) {
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_SIZE_CHECK_ERROR;
        }
        return;
    }
    if (isNecessary) {
        APP_LOGE("profile prop %{public}s mission", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
    }
}

void BMSJsonUtil::GetBoolValueIfFindKey(const nlohmann::json &jsonObject,
    const nlohmann::detail::iter_impl<const nlohmann::json> &end,
    const std::string &key, bool &data, bool isNecessary, int32_t &parseResult)
{
    if (parseResult) {
        return;
    }
    auto iter = jsonObject.find(key);
    if (iter != end) {
        if (!iter->is_boolean()) {
            APP_LOGE("type error %{public}s not bool", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
            return;
        }
        data = iter->get<bool>();
        return;
    }
    if (isNecessary) {
        APP_LOGE("profile prop %{public}s mission", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
    }
}

bool BMSJsonUtil::CheckArrayValueType(const nlohmann::json &value, ArrayType arrayType)
{
    if (!value.is_array()) {
        APP_LOGE("not array");
        return false;
    }
    switch (arrayType) {
        case ArrayType::NUMBER:
            for (const auto &item : value) {
                if (!item.is_number()) {
                    APP_LOGE("array item not number");
                    return false;
                }
            }
            return true;
        case ArrayType::STRING:
            for (const auto &item : value) {
                if (!item.is_string()) {
                    APP_LOGE("array item not string");
                    return false;
                }
            }
            return true;
        default:
            APP_LOGE("not support arrayType: %{public}d", static_cast<int32_t>(arrayType));
            return false;
    }
}

// Validate a map value that is an array of objects (used by GetMapObject for vector-value maps).
// Separate from CheckArrayValueType because the latter is called by GetMapValueIfFindKey
// which deliberately rejects OBJECT as an unsupported arrayType.
static bool CheckArrayOfObjects(const nlohmann::json &value)
{
    if (!value.is_array()) {
        return false;
    }
    for (const auto &item : value) {
        if (!item.is_object() || item.is_null()) {
            return false;
        }
    }
    return true;
}

bool BMSJsonUtil::CheckMapValueType(const nlohmann::json &value, JsonType valueType, ArrayType arrayType)
{
    switch (valueType) {
        case JsonType::BOOLEAN:
            return value.is_boolean();
        case JsonType::NUMBER:
            return value.is_number();
        case JsonType::STRING:
            return value.is_string();
        case JsonType::OBJECT:
            return value.is_object() && !value.is_null() && !value.is_discarded();
        case JsonType::ARRAY:
            return CheckArrayValueType(value, arrayType);
        default:
            APP_LOGE("not support valueType: %{public}d", static_cast<int32_t>(valueType));
            return false;
    }
}

void BMSJsonUtil::GetMapObject(const nlohmann::json &jsonObject,
    const nlohmann::detail::iter_impl<const nlohmann::json> &end,
    const std::string &key, const nlohmann::json *&outPtr,
    JsonType valueType, ArrayType arrayType,
    bool isNecessary, int32_t &parseResult)
{
    if (parseResult != ERR_OK) {
        return;
    }
    auto iter = jsonObject.find(key);
    if (iter != end) {
        if (!iter->is_object()) {
            APP_LOGE("type error %{public}s not map object", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
            return;
        }
        for (const auto &[mapKey, mapValue] : iter->items()) {
            if (valueType == JsonType::ARRAY && arrayType == ArrayType::OBJECT) {
                // vector-value map: use dedicated validator to avoid changing
                // CheckArrayValueType which is shared with GetMapValueIfFindKey
                if (!CheckArrayOfObjects(mapValue)) {
                    APP_LOGE("type error %{public}s.%{public}s value not array of objects",
                        key.c_str(), std::string(mapKey).c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                    return;
                }
            } else if (!CheckMapValueType(mapValue, valueType, arrayType)) {
                APP_LOGE("type error %{public}s.%{public}s value type mismatch",
                    key.c_str(), std::string(mapKey).c_str());
                parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                return;
            }
        }
        outPtr = &(*iter);
        return;
    }
    if (isNecessary) {
        APP_LOGE("profile prop %{public}s missing", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS