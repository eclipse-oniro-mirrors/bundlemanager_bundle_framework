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
#include "inner_bundle_clone_info.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string BUNDLE_CLONE_INFO_USER_ID = "userId";
const std::string BUNDLE_CLONE_INFO_APP_INDEX = "appIndex";
const std::string BUNDLE_CLONE_INFO_UID = "uid";
const std::string BUNDLE_CLONE_INFO_GIDS = "gids";
const std::string BUNDLE_CLONE_INFO_ENABLE = "enabled";
const std::string BUNDLE_CLONE_INFO_DISABLE_ABILITIES = "disabledAbilities";

const std::string BUNDLE_CLONE_INFO_ACCESS_TOKEN_ID = "accessTokenId";
const std::string BUNDLE_CLONE_INFO_ACCESS_TOKEN_ID_EX = "accessTokenIdEx";
const std::string BUNDLE_CLONE_INFO_INSTALL_TIME = "installTime";
const std::string BUNDLE_CLONE_INFO_ENCRYPTED_KEY_EXISTED = "encryptedKeyExisted";
const std::string BUNDLE_CLONE_INFO_INFO_SET_ENABLED_CALLER = "setEnabledCaller";
const std::string BUNDLE_CLONE_INFO_KEY_ID = "keyId";
constexpr const char* INNER_BUNDLE_CLONE_INFO_CUR_DYNAMIC_ICON_MODULE = "curDynamicIconModule";
} // namespace

void to_json(nlohmann::json& jsonObject, const InnerBundleCloneInfo& bundleCloneInfo)
{
    jsonObject = nlohmann::json {
        {BUNDLE_CLONE_INFO_USER_ID, bundleCloneInfo.userId},
        {BUNDLE_CLONE_INFO_APP_INDEX, bundleCloneInfo.appIndex},
        {BUNDLE_CLONE_INFO_UID, bundleCloneInfo.uid},
        {BUNDLE_CLONE_INFO_GIDS, bundleCloneInfo.gids},
        {BUNDLE_CLONE_INFO_ENABLE, bundleCloneInfo.enabled},
        {BUNDLE_CLONE_INFO_DISABLE_ABILITIES, bundleCloneInfo.disabledAbilities},
        {BUNDLE_CLONE_INFO_ACCESS_TOKEN_ID, bundleCloneInfo.accessTokenId},
        {BUNDLE_CLONE_INFO_ACCESS_TOKEN_ID_EX, bundleCloneInfo.accessTokenIdEx},
        {BUNDLE_CLONE_INFO_INSTALL_TIME, bundleCloneInfo.installTime},
        {BUNDLE_CLONE_INFO_ENCRYPTED_KEY_EXISTED, bundleCloneInfo.encryptedKeyExisted},
        {BUNDLE_CLONE_INFO_INFO_SET_ENABLED_CALLER, bundleCloneInfo.setEnabledCaller},
        {BUNDLE_CLONE_INFO_KEY_ID, bundleCloneInfo.keyId},
        {INNER_BUNDLE_CLONE_INFO_CUR_DYNAMIC_ICON_MODULE, bundleCloneInfo.curDynamicIconModule}
    };
}

void from_json(const nlohmann::json& jsonObject, InnerBundleCloneInfo& bundleCloneInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_USER_ID,
        bundleCloneInfo.userId, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_APP_INDEX,
        bundleCloneInfo.appIndex, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_UID,
        bundleCloneInfo.uid, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<int32_t>>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_GIDS,
        bundleCloneInfo.gids, JsonType::ARRAY, false, parseResult, ArrayType::NUMBER);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_ENABLE,
        bundleCloneInfo.enabled, false, parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_DISABLE_ABILITIES,
        bundleCloneInfo.disabledAbilities, JsonType::ARRAY, false, parseResult, ArrayType::STRING);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_ACCESS_TOKEN_ID,
        bundleCloneInfo.accessTokenId, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint64_t>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_ACCESS_TOKEN_ID_EX,
        bundleCloneInfo.accessTokenIdEx, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int64_t>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_INSTALL_TIME,
        bundleCloneInfo.installTime, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_ENCRYPTED_KEY_EXISTED,
        bundleCloneInfo.encryptedKeyExisted, false, parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_INFO_SET_ENABLED_CALLER,
        bundleCloneInfo.setEnabledCaller, false, parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_KEY_ID,
        bundleCloneInfo.keyId, false, parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd, INNER_BUNDLE_CLONE_INFO_CUR_DYNAMIC_ICON_MODULE,
        bundleCloneInfo.curDynamicIconModule, false, parseResult);
    if (parseResult != ERR_OK) {
        APP_LOGE("read module bundleCloneInfo from jsonObject error, error code : %{public}d", parseResult);
    }
}
} // namespace AppExecFwk
} // namespace OHOS