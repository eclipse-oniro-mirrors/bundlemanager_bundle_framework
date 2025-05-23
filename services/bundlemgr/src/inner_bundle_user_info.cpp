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

#include "inner_bundle_user_info.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* INNER_BUNDLE_USER_INFO_UID = "uid";
constexpr const char* INNER_BUNDLE_USER_INFO_GIDS = "gids";
constexpr const char* INNER_BUNDLE_USER_INFO_ACCESS_TOKEN_ID = "accessTokenId";
constexpr const char* INNER_BUNDLE_USER_INFO_ACCESS_TOKEN_ID_EX = "accessTokenIdEx";
constexpr const char* INNER_BUNDLE_USER_INFO_BUNDLE_NAME = "bundleName";
constexpr const char* INNER_BUNDLE_USER_INFO_INSTALL_TIME = "installTime";
constexpr const char* INNER_BUNDLE_USER_INFO_UPDATE_TIME = "updateTime";
constexpr const char* INNER_BUNDLE_USER_INFO_FIRST_INSTALL_TIME = "firstInstallTime";
constexpr const char* INNER_BUNDLE_USER_INFO_BUNDLE_USER_INFO = "bundleUserInfo";
constexpr const char* INNER_BUNDLE_USER_INFO_IS_REMOVABLE = "isRemovable";
constexpr const char* INNER_BUNDLE_USER_INFO_CLONE_INFOS = "cloneInfos";
constexpr const char* INNER_BUNDLE_USER_INFO_KEYID = "keyId";
constexpr const char* INNER_BUNDLE_USER_INFO_INSTALLED_PLUGIN_SET = "installedPluginSet";
constexpr const char* INNER_BUNDLE_USER_INFO_CUR_DYNAMIC_ICON_MODULE = "curDynamicIconModule";
} // namespace

void to_json(nlohmann::json& jsonObject, const InnerBundleUserInfo& innerBundleUserInfo)
{
    jsonObject = nlohmann::json {
        {INNER_BUNDLE_USER_INFO_UID, innerBundleUserInfo.uid},
        {INNER_BUNDLE_USER_INFO_GIDS, innerBundleUserInfo.gids},
        {INNER_BUNDLE_USER_INFO_ACCESS_TOKEN_ID, innerBundleUserInfo.accessTokenId},
        {INNER_BUNDLE_USER_INFO_ACCESS_TOKEN_ID_EX, innerBundleUserInfo.accessTokenIdEx},
        {INNER_BUNDLE_USER_INFO_BUNDLE_NAME, innerBundleUserInfo.bundleName},
        {INNER_BUNDLE_USER_INFO_INSTALL_TIME, innerBundleUserInfo.installTime},
        {INNER_BUNDLE_USER_INFO_UPDATE_TIME, innerBundleUserInfo.updateTime},
        {INNER_BUNDLE_USER_INFO_FIRST_INSTALL_TIME, innerBundleUserInfo.firstInstallTime},
        {INNER_BUNDLE_USER_INFO_BUNDLE_USER_INFO, innerBundleUserInfo.bundleUserInfo},
        {INNER_BUNDLE_USER_INFO_IS_REMOVABLE, innerBundleUserInfo.isRemovable},
        {INNER_BUNDLE_USER_INFO_CLONE_INFOS, innerBundleUserInfo.cloneInfos},
        {INNER_BUNDLE_USER_INFO_KEYID, innerBundleUserInfo.keyId},
        {INNER_BUNDLE_USER_INFO_INSTALLED_PLUGIN_SET, innerBundleUserInfo.installedPluginSet},
        {INNER_BUNDLE_USER_INFO_CUR_DYNAMIC_ICON_MODULE, innerBundleUserInfo.curDynamicIconModule},
    };
}

void from_json(const nlohmann::json& jsonObject, InnerBundleUserInfo& innerBundleUserInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, INNER_BUNDLE_USER_INFO_UID,
        innerBundleUserInfo.uid, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<int32_t>>(jsonObject, jsonObjectEnd, INNER_BUNDLE_USER_INFO_GIDS,
        innerBundleUserInfo.gids, JsonType::ARRAY, false, parseResult, ArrayType::NUMBER);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, INNER_BUNDLE_USER_INFO_ACCESS_TOKEN_ID,
        innerBundleUserInfo.accessTokenId, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint64_t>(jsonObject, jsonObjectEnd, INNER_BUNDLE_USER_INFO_ACCESS_TOKEN_ID_EX,
        innerBundleUserInfo.accessTokenIdEx, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd, INNER_BUNDLE_USER_INFO_BUNDLE_NAME,
        innerBundleUserInfo.bundleName, false, parseResult);
    GetValueIfFindKey<int64_t>(jsonObject, jsonObjectEnd, INNER_BUNDLE_USER_INFO_INSTALL_TIME,
        innerBundleUserInfo.installTime, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int64_t>(jsonObject, jsonObjectEnd, INNER_BUNDLE_USER_INFO_UPDATE_TIME,
        innerBundleUserInfo.updateTime, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int64_t>(jsonObject, jsonObjectEnd, INNER_BUNDLE_USER_INFO_FIRST_INSTALL_TIME,
        innerBundleUserInfo.firstInstallTime, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<BundleUserInfo>(jsonObject, jsonObjectEnd, INNER_BUNDLE_USER_INFO_BUNDLE_USER_INFO,
        innerBundleUserInfo.bundleUserInfo, JsonType::OBJECT, false, parseResult, ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject, jsonObjectEnd, INNER_BUNDLE_USER_INFO_IS_REMOVABLE,
        innerBundleUserInfo.isRemovable, false, parseResult);
    GetValueIfFindKey<std::map<std::string, InnerBundleCloneInfo>>(jsonObject, jsonObjectEnd,
        INNER_BUNDLE_USER_INFO_CLONE_INFOS,
        innerBundleUserInfo.cloneInfos, JsonType::OBJECT, false, parseResult, ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd, INNER_BUNDLE_USER_INFO_KEYID,
        innerBundleUserInfo.keyId, false, parseResult);
    GetValueIfFindKey<std::unordered_set<std::string>>(jsonObject, jsonObjectEnd,
        INNER_BUNDLE_USER_INFO_INSTALLED_PLUGIN_SET,
        innerBundleUserInfo.installedPluginSet, JsonType::ARRAY, false, parseResult, ArrayType::STRING);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd, INNER_BUNDLE_USER_INFO_CUR_DYNAMIC_ICON_MODULE,
        innerBundleUserInfo.curDynamicIconModule, false, parseResult);
}
} // namespace AppExecFwk
} // namespace OHOS