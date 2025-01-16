/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
    if (jsonObject.find(key) != end) {
        if (!jsonObject.at(key).is_string()) {
            APP_LOGE("type error %{public}s not string", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
            return;
        }
        data = jsonObject.at(key).get<std::string>();
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
    if (jsonObject.find(key) != end) {
        if (!jsonObject.at(key).is_boolean()) {
            APP_LOGE("type error %{public}s not bool", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
            return;
        }
        data = jsonObject.at(key).get<bool>();
        return;
    }
    if (isNecessary) {
        APP_LOGE("profile prop %{public}s mission", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS