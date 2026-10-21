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

#include "atm_recovery_record_decoder.h"

#include <limits>
#include <set>
#include <utility>
#include "bundle_constants.h"
#include "bundle_info.h"
#include "bundle_service_constants.h"
#include "json_util.h"

namespace OHOS::AppExecFwk::AtmRecovery {
namespace {
using Json = nlohmann::json;
using Policy = DeviceModeDistributionPolicy;
constexpr int32_t PRIMARY_MODE = 0;
constexpr int32_t SECONDARY_MODE = 1;
constexpr const char* UID = "uid";
constexpr const char* ACCESS_TOKEN_ID = "accessTokenId";
constexpr const char* INNER_MODULE_INFO = "innerModuleInfos";
constexpr const char* MODULE_HAP_PATH = "hapPath";
constexpr const char* USER_ID = "userId";
constexpr const char* APP_INDEX = "appIndex";
constexpr const char* BUNDLE_USER_INFO = "bundleUserInfo";
constexpr const char* INNER_BUNDLE_USER_INFOS = "innerBundleUserInfos";
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* CLONE_INFOS = "cloneInfos";
constexpr const char* BASE_BUNDLE_INFO = "baseBundleInfo";
constexpr const char* NAME = "name";
constexpr const char* IS_PREINSTALL_APP = "isPreInstallApp";
constexpr const char* IS_DUAL_MODE_CLONE_APP = "isDualModeCloneApp";
constexpr const char* DEVICE_MODE_DISTRIBUTION_POLICY = "deviceModeDistributionPolicy";
const std::string SECONDARY_PREFIX = std::string(ServiceConstants::CLONE_PREFIX) +
    std::to_string(Constants::DUAL_MODE_CLONE_APP_INDEX) + "+";

template<typename T>
bool ReadInteger(const Json &object, const char *key, T &number, bool required = true)
{
    auto it = object.find(key);
    if (it == object.end()) {
        return !required;
    }
    // BMS's general numeric reader permits conversion; recovery identities must not truncate or wrap.
    if (!it->is_number_integer() || (!it->is_number_unsigned() && it->get<int64_t>() < 0) ||
        it->get<uint64_t>() > static_cast<uint64_t>(std::numeric_limits<T>::max())) {
        return false;
    }
    number = it->get<T>();
    return true;
}

bool ReadIdentity(const Json &object, AtmBundleRecoveryInfo &info)
{
    return object.is_object() && ReadInteger(object, UID, info.uid) &&
        ReadInteger(object, ACCESS_TOKEN_ID, info.accessTokenId);
}

bool ParseModulePaths(const Json &root, std::vector<std::string> &paths)
{
    const Json *modules = nullptr;
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetMapObject(root, root.end(), INNER_MODULE_INFO, modules,
        JsonType::OBJECT, ArrayType::NOT_ARRAY, true, parseResult);
    if (modules == nullptr || modules->empty()) {
        return false;
    }
    for (const auto &module : *modules) {
        std::string path;
        // Missing hapPath has the historical empty-string meaning (unpacked installation).
        BMSJsonUtil::GetStrValueIfFindKey(module, module.end(), MODULE_HAP_PATH, path, false, parseResult);
        if (parseResult != ERR_OK) {
            return false;
        }
        paths.push_back(std::move(path));
    }
    return true;
}

bool ParseInstances(const Json &user, const char *field, const AtmBundleRecoveryInfo &parent,
    std::set<std::pair<int32_t, int32_t>> &identities, std::vector<AtmBundleRecoveryInfo> &infos)
{
    const Json *children = nullptr;
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetMapObject(user, user.end(), field, children,
        JsonType::OBJECT, ArrayType::NOT_ARRAY, false, parseResult);
    if (parseResult != ERR_OK) {
        return false;
    }
    if (children == nullptr) {
        return true;
    }
    for (const auto &child : children->items()) {
        AtmBundleRecoveryInfo info = parent;
        if (!ReadIdentity(child.value(), info) || !ReadInteger(child.value(), USER_ID, info.userId) ||
            !ReadInteger(child.value(), APP_INDEX, info.appIndex) || info.userId != parent.userId ||
            info.appIndex == Constants::DEFAULT_APP_INDEX || child.key() != std::to_string(info.appIndex) ||
            !identities.emplace(info.userId, info.appIndex).second) {
            return false;
        }
        infos.push_back(std::move(info));
    }
    return true;
}

bool ParseUsers(const Json &root, const AtmBundleRecoveryInfo &base, std::vector<AtmBundleRecoveryInfo> &infos)
{
    const Json *users = nullptr;
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetMapObject(root, root.end(), INNER_BUNDLE_USER_INFOS, users,
        JsonType::OBJECT, ArrayType::NOT_ARRAY, true, parseResult);
    if (users == nullptr || users->empty()) {
        return false;
    }
    std::set<std::pair<int32_t, int32_t>> identities;
    for (const auto &user : users->items()) {
        AtmBundleRecoveryInfo info = base;
        const auto &value = user.value();
        const auto userInfo = value.find(BUNDLE_USER_INFO);
        if (!ReadIdentity(value, info) || userInfo == value.end() || !userInfo->is_object() ||
            !ReadInteger(*userInfo, USER_ID, info.userId) ||
            info.userId < Constants::DEFAULT_USERID ||
            user.key() != base.bundleName + "_" + std::to_string(info.userId) ||
            !identities.emplace(info.userId, info.appIndex).second) {
            return false;
        }
        std::string name = base.bundleName;
        BMSJsonUtil::GetStrValueIfFindKey(value, value.end(), BUNDLE_NAME, name, false, parseResult);
        if (parseResult != ERR_OK || name != base.bundleName) {
            return false;
        }
        infos.push_back(info);
        if (!ParseInstances(value, CLONE_INFOS, info, identities, infos)) {
            return false;
        }
    }
    return true;
}

bool ParseBundleInfo(const std::string &key, const Json &root, AtmBundleRecoveryInfo &info)
{
    const auto bundleInfo = root.find(BASE_BUNDLE_INFO);
    if (bundleInfo == root.end() || !bundleInfo->is_object()) {
        return false;
    }
    const auto &bundle = *bundleInfo;
    bool secondary = false;
    int32_t policy = static_cast<int32_t>(Policy::UNSPECIFIED);
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(bundle, bundle.end(), NAME, info.bundleName, true, parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(bundle, bundle.end(), IS_PREINSTALL_APP,
        info.isPreInstallApp, false, parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(root, root.end(), IS_DUAL_MODE_CLONE_APP, secondary, false, parseResult);
    if (parseResult != ERR_OK || info.bundleName.empty() ||
        !ReadInteger(bundle, DEVICE_MODE_DISTRIBUTION_POLICY, policy, false) ||
        policy > static_cast<int32_t>(Policy::FULL_COMPATIBLE_DIFFERENT_PACKAGE) ||
        !ReadInteger(root, APP_INDEX, info.appIndex, false) ||
        secondary != (key == SECONDARY_PREFIX + info.bundleName)) {
        return false;
    }
    if (secondary) {
        if (info.appIndex != Constants::DEFAULT_APP_INDEX &&
            info.appIndex != Constants::DUAL_MODE_CLONE_APP_INDEX) {
            return false;
        }
        info.appIndex = Constants::DUAL_MODE_CLONE_APP_INDEX;
    }
    if (policy == static_cast<int32_t>(Policy::UNIVERSAL_DIFFERENT_PACKAGE) ||
        policy == static_cast<int32_t>(Policy::PARTIAL_COMPATIBLE_DIFFERENT_PACKAGE) ||
        policy == static_cast<int32_t>(Policy::FULL_COMPATIBLE_DIFFERENT_PACKAGE)) {
        info.mode = secondary ? SECONDARY_MODE : PRIMARY_MODE;
    }
    return true;
}

Json ParseRecordJson(const std::string &value)
{
    // Reject duplicate fields instead of silently accepting the last identity value.
    bool duplicateKey = false;
    std::vector<std::set<std::string>> objectKeys;
    auto callback = [&](int, Json::parse_event_t event, Json &parsed) {
        if (event == Json::parse_event_t::object_start) {
            objectKeys.emplace_back();
        } else if (event == Json::parse_event_t::object_end) {
            objectKeys.pop_back();
        } else if (event == Json::parse_event_t::key) {
            duplicateKey |= !objectKeys.back().insert(parsed.get<std::string>()).second;
        }
        return true;
    };
    auto root = Json::parse(value, callback, false);
    if (duplicateKey) {
        return {};
    }
    return root;
}
} // namespace

bool ParseAtmRecoveryRecord(const std::string &key, const std::string &value,
    std::vector<AtmBundleRecoveryInfo> &infos)
{
    infos.clear();
    const auto root = ParseRecordJson(value);
    AtmBundleRecoveryInfo base;
    if (root.is_object() && ParseBundleInfo(key, root, base) && ParseModulePaths(root, base.hapPaths) &&
        ParseUsers(root, base, infos)) {
        return true;
    }
    infos.clear();
    return false;
}
} // namespace OHOS::AppExecFwk::AtmRecovery
