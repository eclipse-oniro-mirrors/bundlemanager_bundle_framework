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
#include "first_install_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* const KEY_FIRST_INSTALL_TIME = "firstInstallTime";
const char* const KEY_ODID_RESET_COUNT = "odidResetCount";
const char* const KEY_LAST_ODID = "lastOdid";
constexpr int32_t MAX_RESET_COUNT = 99999;
} // namespace

void to_json(nlohmann::json& jsonObject, const FirstInstallBundleInfo& firstInstallBundleInfo)
{
    jsonObject = nlohmann::json {
        {KEY_FIRST_INSTALL_TIME, firstInstallBundleInfo.firstInstallTime},
        {KEY_ODID_RESET_COUNT, firstInstallBundleInfo.odidResetCount},
        {KEY_LAST_ODID, firstInstallBundleInfo.lastOdid},
    };
}

void from_json(const nlohmann::json& jsonObject, FirstInstallBundleInfo& firstInstallBundleInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<int64_t>(jsonObject, jsonObjectEnd, KEY_FIRST_INSTALL_TIME,
        firstInstallBundleInfo.firstInstallTime, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, KEY_ODID_RESET_COUNT,
        firstInstallBundleInfo.odidResetCount, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd, KEY_LAST_ODID,
        firstInstallBundleInfo.lastOdid, false, parseResult);
    if (parseResult != ERR_OK) {
        APP_LOGE("read firstInstallBundleUserInfo from jsonObject error, error code : %{public}d", parseResult);
    }
}

void FirstInstallBundleInfo::IncrementOdidResetCount()
{
    if (odidResetCount >= MAX_RESET_COUNT || odidResetCount < 0) {
        odidResetCount = MAX_RESET_COUNT;
        return;
    }
    odidResetCount++;
}

std::string FirstInstallBundleInfo::ToString() const
{
    nlohmann::json jsonObject;
    to_json(jsonObject, *this);
    return jsonObject.dump();
}
} // namespace AppExecFwk
} // namespace OHOS