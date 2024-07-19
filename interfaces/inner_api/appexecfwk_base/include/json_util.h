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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_JSON_UTIL_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_JSON_UTIL_H

#include <string>

#include "appexecfwk_errors.h"
#include "app_log_wrapper.h"
#include "json_serializer.h"

namespace OHOS {
namespace AppExecFwk {
enum class JsonType {
    NULLABLE,
    BOOLEAN,
    NUMBER,
    OBJECT,
    ARRAY,
    STRING,
};

enum class ArrayType {
    NUMBER,
    OBJECT,
    STRING,
    NOT_ARRAY,
};

template<typename T, typename dataType>
void CheckArrayType(
    const nlohmann::json &jsonObject, const std::string &key, dataType &data, ArrayType arrayType, int32_t &parseResult)
{
    auto arrays = jsonObject.at(key);
    if (arrays.empty()) {
        return;
    }
    if (arrays.size() > Constants::MAX_JSON_ARRAY_LENGTH) {
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_SIZE_CHECK_ERROR;
        return;
    }
    switch (arrayType) {
        case ArrayType::STRING:
            for (const auto &array : arrays) {
                if (!array.is_string()) {
                    APP_LOGE("%{public}s not string", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                }
            }
            if (parseResult == ERR_OK) {
                data = jsonObject.at(key).get<T>();
            }
            break;
        case ArrayType::OBJECT:
            for (const auto &array : arrays) {
                if (!array.is_object()) {
                    APP_LOGE("%{public}s not object", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                    break;
                }
            }
            if (parseResult == ERR_OK) {
                data = jsonObject.at(key).get<T>();
            }
            break;
        case ArrayType::NUMBER:
            for (const auto &array : arrays) {
                if (!array.is_number()) {
                    APP_LOGE("%{public}s not number", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                }
            }
            if (parseResult == ERR_OK) {
                data = jsonObject.at(key).get<T>();
            }
            break;
        case ArrayType::NOT_ARRAY:
            APP_LOGE("%{public}s not string", key.c_str());
            break;
        default:
            APP_LOGE("%{public}s error", key.c_str());
            break;
    }
}

template<typename T, typename dataType>
void GetValueIfFindKey(const nlohmann::json &jsonObject, const nlohmann::detail::iter_impl<const nlohmann::json> &end,
    const std::string &key, dataType &data, JsonType jsonType, bool isNecessary, int32_t &parseResult,
    ArrayType arrayType)
{
    if (parseResult) {
        return;
    }
    if (jsonObject.find(key) != end) {
        switch (jsonType) {
            case JsonType::BOOLEAN:
                if (!jsonObject.at(key).is_boolean()) {
                    APP_LOGE("type error %{public}s not boolean", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                    break;
                }
                data = jsonObject.at(key).get<T>();
                break;
            case JsonType::NUMBER:
                if (!jsonObject.at(key).is_number()) {
                    APP_LOGE("type error %{public}s not number", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                    break;
                }
                data = jsonObject.at(key).get<T>();
                break;
            case JsonType::OBJECT:
                if (!jsonObject.at(key).is_object()) {
                    APP_LOGE("type error %{public}s not object", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                    break;
                }
                data = jsonObject.at(key).get<T>();
                break;
            case JsonType::ARRAY:
                if (!jsonObject.at(key).is_array()) {
                    APP_LOGE("type error %{public}s not array", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                    break;
                }
                CheckArrayType<T>(jsonObject, key, data, arrayType, parseResult);
                break;
            case JsonType::STRING:
                if (!jsonObject.at(key).is_string()) {
                    APP_LOGE("type error %{public}s not string", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                    break;
                }
                data = jsonObject.at(key).get<T>();
                if (jsonObject.at(key).get<std::string>().length() > Constants::MAX_JSON_STRING_LENGTH) {
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_SIZE_CHECK_ERROR;
                }
                break;
            case JsonType::NULLABLE:
                APP_LOGE("type error %{public}s nullable", key.c_str());
                break;
            default:
                APP_LOGE("type error %{public}s not jsonType", key.c_str());
                parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        }
        return;
    }
    if (isNecessary) {
        APP_LOGE("profile prop %{public}s mission", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
    }
}

template<typename T>
const std::string GetJsonStrFromInfo(T &t)
{
    nlohmann::json json = t;
    return json.dump();
}

template<typename T>
bool ParseInfoFromJsonStr(const char *data, T &t)
{
    if (data == nullptr) {
        APP_LOGE("data is nullptr");
        return false;
    }

    nlohmann::json jsonObject = nlohmann::json::parse(data, nullptr, false);
    if (jsonObject.is_discarded()) {
        APP_LOGE("jsonObject discarded");
        return false;
    }

    t = jsonObject.get<T>();
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_JSON_UTIL_H