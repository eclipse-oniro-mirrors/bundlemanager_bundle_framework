/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "inner_cli_sandbox_info.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string CLI_SANDBOX_INFO_USER_ID = "userId";
const std::string CLI_SANDBOX_INFO_APP_INDEX = "appIndex";
const std::string CLI_SANDBOX_INFO_UID = "uid";
const std::string CLI_SANDBOX_INFO_GIDS = "gids";
const std::string CLI_SANDBOX_INFO_ACCESS_TOKEN_ID = "accessTokenId";
const std::string CLI_SANDBOX_INFO_ACCESS_TOKEN_ID_EX = "accessTokenIdEx";
const std::string CLI_SANDBOX_INFO_INSTALL_TIME = "installTime";
const std::string CLI_SANDBOX_INFO_SANDBOX_TYPE = "sandboxType";
const std::string CLI_SANDBOX_INFO_CREATOR_BUNDLE_NAMES = "creatorBundleNames";
} // namespace

void to_json(nlohmann::json& jsonObject, const InnerCliSandboxInfo& info)
{
    jsonObject = nlohmann::json {
        {CLI_SANDBOX_INFO_USER_ID, info.userId},
        {CLI_SANDBOX_INFO_APP_INDEX, info.appIndex},
        {CLI_SANDBOX_INFO_UID, info.uid},
        {CLI_SANDBOX_INFO_GIDS, info.gids},
        {CLI_SANDBOX_INFO_ACCESS_TOKEN_ID, info.accessTokenId},
        {CLI_SANDBOX_INFO_ACCESS_TOKEN_ID_EX, info.accessTokenIdEx},
        {CLI_SANDBOX_INFO_INSTALL_TIME, info.installTime},
        {CLI_SANDBOX_INFO_SANDBOX_TYPE, static_cast<int32_t>(info.sandboxType)},
        {CLI_SANDBOX_INFO_CREATOR_BUNDLE_NAMES, info.creatorBundleNames}
    };
}

void from_json(const nlohmann::json& jsonObject, InnerCliSandboxInfo& info)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, CLI_SANDBOX_INFO_USER_ID,
        info.userId, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, CLI_SANDBOX_INFO_APP_INDEX,
        info.appIndex, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, CLI_SANDBOX_INFO_UID,
        info.uid, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<int32_t>>(jsonObject, jsonObjectEnd, CLI_SANDBOX_INFO_GIDS,
        info.gids, JsonType::ARRAY, false, parseResult, ArrayType::NUMBER);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, CLI_SANDBOX_INFO_ACCESS_TOKEN_ID,
        info.accessTokenId, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint64_t>(jsonObject, jsonObjectEnd, CLI_SANDBOX_INFO_ACCESS_TOKEN_ID_EX,
        info.accessTokenIdEx, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int64_t>(jsonObject, jsonObjectEnd, CLI_SANDBOX_INFO_INSTALL_TIME,
        info.installTime, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    int32_t sandboxType = 0;
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, CLI_SANDBOX_INFO_SANDBOX_TYPE,
        sandboxType, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    info.sandboxType = static_cast<SandboxIsolationType>(sandboxType);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject, jsonObjectEnd, CLI_SANDBOX_INFO_CREATOR_BUNDLE_NAMES,
        info.creatorBundleNames, JsonType::ARRAY, false, parseResult, ArrayType::STRING);
    if (parseResult != ERR_OK) {
        APP_LOGE("read module InnerCliSandboxInfo from jsonObject error, error code : %{public}d", parseResult);
    }
}
} // namespace AppExecFwk
} // namespace OHOS
