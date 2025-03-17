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
#include "uninstall_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* const KEY_UID = "uid";
const char* const KEY_GIDS = "gids";
const char* const KEY_ACCESS_TOKENID = "accessTokenId";
const char* const KEY_ACCESS_TOKENIDEX = "accessTokenIdEx";
const char* const KEY_USER_INFOS = "userInfos";
const char* const KEY_APP_ID = "appId";
const char* const KEY_BUNDLE_TYPE = "bundleType";
const char* const KEY_APP_IDENTIFIER = "appIdentifier";
const char* const KEY_APP_PROVISION_TYPE = "appProvisionType";
const char* const KEY_EXTENSION_DIRS = "extensionDirs";
} // namespace

void to_json(nlohmann::json& jsonObject, const UninstallDataUserInfo& uninstallDataUserInfo)
{
    jsonObject = nlohmann::json {
        {KEY_UID, uninstallDataUserInfo.uid},
        {KEY_GIDS, uninstallDataUserInfo.gids},
        {KEY_ACCESS_TOKENID, uninstallDataUserInfo.accessTokenId},
        {KEY_ACCESS_TOKENIDEX, uninstallDataUserInfo.accessTokenIdEx}
    };
}

void to_json(nlohmann::json& jsonObject, const UninstallBundleInfo& uninstallBundleInfo)
{
    jsonObject = nlohmann::json {
        {KEY_USER_INFOS, uninstallBundleInfo.userInfos},
        {KEY_APP_ID, uninstallBundleInfo.appId},
        {KEY_APP_IDENTIFIER, uninstallBundleInfo.appIdentifier},
        {KEY_APP_PROVISION_TYPE, uninstallBundleInfo.appProvisionType},
        {KEY_BUNDLE_TYPE, uninstallBundleInfo.bundleType},
        {KEY_EXTENSION_DIRS, uninstallBundleInfo.extensionDirs}
    };
}

void from_json(const nlohmann::json& jsonObject, UninstallDataUserInfo& uninstallDataUserInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, KEY_UID,
        uninstallDataUserInfo.uid, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<int32_t>>(jsonObject, jsonObjectEnd, KEY_GIDS,
        uninstallDataUserInfo.gids, JsonType::ARRAY, false, parseResult, ArrayType::NUMBER);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, KEY_ACCESS_TOKENID,
        uninstallDataUserInfo.accessTokenId, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint64_t>(jsonObject, jsonObjectEnd, KEY_ACCESS_TOKENIDEX,
        uninstallDataUserInfo.accessTokenIdEx, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read uninstallDataUserInfo from jsonObject error, error code : %{public}d", parseResult);
    }
}

void from_json(const nlohmann::json& jsonObject, UninstallBundleInfo& uninstallBundleInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::map<std::string, UninstallDataUserInfo>>(jsonObject, jsonObjectEnd, KEY_USER_INFOS,
        uninstallBundleInfo.userInfos, JsonType::OBJECT, false, parseResult, ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd, KEY_APP_ID,
        uninstallBundleInfo.appId, false, parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd, KEY_APP_IDENTIFIER,
        uninstallBundleInfo.appIdentifier, false, parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd, KEY_APP_PROVISION_TYPE,
        uninstallBundleInfo.appProvisionType, false, parseResult);
    GetValueIfFindKey<BundleType>(jsonObject, jsonObjectEnd, KEY_BUNDLE_TYPE,
        uninstallBundleInfo.bundleType, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject, jsonObjectEnd, KEY_EXTENSION_DIRS,
        uninstallBundleInfo.extensionDirs, JsonType::ARRAY, false, parseResult, ArrayType::STRING);
    if (parseResult != ERR_OK) {
        APP_LOGE("read uninstallBundleInfo from jsonObject error, error code : %{public}d", parseResult);
    }
}

std::string UninstallBundleInfo::ToString() const
{
    nlohmann::json jsonObject;
    to_json(jsonObject, *this);
    return jsonObject.dump();
}

void UninstallBundleInfo::Init()
{
    userInfos.clear();
    appId.clear();
    appIdentifier.clear();
    appProvisionType.clear();
    bundleType = BundleType::APP;
    extensionDirs.clear();
}
} // namespace AppExecFwk
} // namespace OHOS