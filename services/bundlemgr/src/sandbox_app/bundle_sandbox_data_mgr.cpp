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

#include "bundle_sandbox_data_mgr.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_mgr_service.h"
#include "bundle_util.h"

namespace OHOS {
namespace AppExecFwk {
BundleSandboxDataMgr::BundleSandboxDataMgr()
{
    APP_LOGI("BundleSandboxDataMgr instance is created");
    sandboxManagerDb_ = std::make_shared<SandboxManagerRdb>();
    if (sandboxManagerDb_ == nullptr) {
        APP_LOGE("create sandboxManagerDb_ failed.");
        return;
    }
    if (!RestoreSandboxPersistentInnerBundleInfo()) {
        APP_LOGW("RestoreSandboxPersistentInnerBundleInfo failed.");
    }
}

BundleSandboxDataMgr::~BundleSandboxDataMgr()
{
    APP_LOGI("BundleSandboxDataMgr instance is destroyed");
}

void BundleSandboxDataMgr::SaveSandboxAppInfo(const InnerBundleInfo &info, const int32_t &appIndex)
{
    APP_LOGI("SaveSandboxAppInfo begin");
    std::string bundleName = info.GetBundleName();
    if (bundleName.empty()) {
        APP_LOGE("SaveSandboxAppInfo bundleName is empty");
        return;
    }
    std::string key = std::to_string(appIndex) + Constants::FILE_UNDERLINE + bundleName;
    std::unique_lock<std::shared_mutex> lock(sandboxAppMutex_);
    sandboxAppInfos_[key] = info;
    APP_LOGD("save sandbox app %{public}s info successfully", key.c_str());
}

void BundleSandboxDataMgr::DeleteSandboxAppInfo(const std::string &bundleName, const int32_t &appIndex)
{
    APP_LOGI("DeleteSandboxAppInfo begin");
    if (bundleName.empty()) {
        APP_LOGE("DeleteSandboxAppInfo bundleName is empty");
        return;
    }
    auto key = std::to_string(appIndex) + Constants::FILE_UNDERLINE + bundleName;
    std::unique_lock<std::shared_mutex> lock(sandboxAppMutex_);
    auto ret = sandboxAppInfos_.erase(key);
    if (ret == 0) {
        APP_LOGE("delete sandbox app info failed due to no sandbox app in the dataMgr");
        return;
    }
    APP_LOGD("delete sandbox app %{public}s info successfully", key.c_str());
}

ErrCode BundleSandboxDataMgr::GetSandboxAppInfo(
    const std::string &bundleName, const int32_t &appIndex, int32_t &userId, InnerBundleInfo &info) const
{
    APP_LOGI("GetSandboxAppInfo begin");
    if (bundleName.empty()) {
        APP_LOGE("GetSandboxAppInfo bundleName is empty");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    if (appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX) {
        APP_LOGE("GetSandboxAppInfo appIndex is invalid");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    if (userId < Constants::DEFAULT_USERID) {
        APP_LOGE("userId(%{public}d) is invalid.", userId);
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }

    auto key = std::to_string(appIndex) + Constants::FILE_UNDERLINE + bundleName;

    {
        std::shared_lock<std::shared_mutex> lock(sandboxAppMutex_);
        auto it = sandboxAppInfos_.find(key);
        if (it == sandboxAppInfos_.end()) {
            APP_LOGE("GetSandboxAppInfo no sandbox app info can be found");
            return ERR_APPEXECFWK_SANDBOX_INSTALL_NO_SANDBOX_APP_INFO;
        }

        InnerBundleUserInfo userInfo;
        if (!(it->second).GetInnerBundleUserInfo(userId, userInfo)) {
            APP_LOGE("the sandbox app is not installed at this user %{public}d", userId);
            return ERR_APPEXECFWK_SANDBOX_INSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID;
        }
        info = it->second;
    }

    APP_LOGI("GetSandboxAppInfo successfully");
    return ERR_OK;
}

ErrCode BundleSandboxDataMgr::GetSandboxAppBundleInfo(
    const std::string &bundleName, const int32_t &appIndex, const int32_t &userId, BundleInfo &info) const
{
    APP_LOGI("GetSandboxAppBundleInfo begin");
    InnerBundleInfo innerBundleInfo;
    int32_t requestUserId = userId;
    ErrCode result = ERR_OK;
    if ((result = GetSandboxAppInfo(bundleName, appIndex, requestUserId, innerBundleInfo)) != ERR_OK) {
        APP_LOGE("GetSandboxAppBundleInfo get sandbox app info failed");
        return result;
    }
    InnerBundleUserInfo userInfo;
    if (!innerBundleInfo.GetInnerBundleUserInfo(requestUserId, userInfo)) {
        APP_LOGE("the origin application is not installed at current user");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID;
    }

    innerBundleInfo.GetBundleInfo(
        BundleFlag::GET_BUNDLE_DEFAULT |
        BundleFlag::GET_BUNDLE_WITH_ABILITIES |
        BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION |
        BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO |
        BundleFlag::GET_BUNDLE_WITH_HASH_VALUE, info, requestUserId);
    APP_LOGI("GetSandboxAppBundleInfo successfully");
    return ERR_OK;
}

int32_t BundleSandboxDataMgr::GenerateSandboxAppIndex(const std::string &bundleName)
{
    APP_LOGI("GenerateSandboxAppIndex begin");
    if (bundleName.empty()) {
        APP_LOGE("GenerateSandboxAppIndex bundleName is empty");
        return Constants::INITIAL_SANDBOX_APP_INDEX;
    }
    std::unique_lock<std::mutex> lock(sandboxAppIndexMapMutex_);
    auto firstIterator = sandboxAppIndexMap_.find(bundleName);
    if (firstIterator == sandboxAppIndexMap_.end()) {
        std::set<int32_t> innerSet { Constants::INITIAL_SANDBOX_APP_INDEX + 1 };
        sandboxAppIndexMap_.emplace(bundleName, innerSet);
        APP_LOGD("GenerateSandboxAppIndex successfully");
        return Constants::INITIAL_SANDBOX_APP_INDEX + 1;
    }

    if (firstIterator->second.empty()) {
        firstIterator->second.insert(Constants::INITIAL_SANDBOX_APP_INDEX + 1);
        APP_LOGD("GenerateSandboxAppIndex successfully");
        return Constants::INITIAL_SANDBOX_APP_INDEX + 1;
    }

    int32_t pre = Constants::INITIAL_SANDBOX_APP_INDEX;
    for (const auto &item : firstIterator->second) {
        if (item == pre + 1) {
            pre++;
            continue;
        }
        break;
    }

    int32_t newAppIndex = pre + 1;
    if (newAppIndex > Constants::MAX_SANDBOX_APP_INDEX) {
        APP_LOGE("GenerateSandboxAppIndex failed due to exceed limitation of maximum appIndex");
        return Constants::INITIAL_SANDBOX_APP_INDEX;
    }
    firstIterator->second.insert(newAppIndex);
    APP_LOGD("GenerateSandboxAppIndex successfully with appIndex %{public}d", newAppIndex);
    return newAppIndex;
}

bool BundleSandboxDataMgr::DeleteSandboxAppIndex(const std::string &bundleName, int32_t appIndex)
{
    APP_LOGI("DeleteSandboxAppIndex begin");
    if (bundleName.empty()) {
        APP_LOGE("DeleteSandboxAppIndex bundleName is empty");
        return false;
    }
    std::unique_lock<std::mutex> lock(sandboxAppIndexMapMutex_);
    auto it = sandboxAppIndexMap_.find(bundleName);
    if (it == sandboxAppIndexMap_.end() || it->second.empty()) {
        APP_LOGE("no sandbox app can be found %{public}s", bundleName.c_str());
        return false;
    }

    auto ret = it->second.erase(appIndex);
    if (ret == 0) {
        APP_LOGE("no sandbox app index can be found %{public}d", appIndex);
        return false;
    }

    if (it->second.empty()) {
        sandboxAppIndexMap_.erase(bundleName);
    }
    APP_LOGI("DeleteSandboxAppIndex successfully");
    return true;
}

std::unordered_map<std::string, InnerBundleInfo> BundleSandboxDataMgr::GetSandboxAppInfoMap() const
{
    std::shared_lock<std::shared_mutex> lock(sandboxAppMutex_);
    return sandboxAppInfos_;
}

ErrCode BundleSandboxDataMgr::GetSandboxHapModuleInfo(const AbilityInfo &abilityInfo, int32_t appIndex, int32_t userId,
    HapModuleInfo &hapModuleInfo) const
{
    APP_LOGD("GetSandboxHapModuleInfo %{public}s", abilityInfo.bundleName.c_str());
    // check appIndex
    if (appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX || appIndex > Constants::MAX_SANDBOX_APP_INDEX) {
        APP_LOGE("the appIndex %{public}d is invalid", appIndex);
        return ERR_APPEXECFWK_SANDBOX_QUERY_PARAM_ERROR;
    }
    std::shared_lock<std::shared_mutex> lock(sandboxAppMutex_);
    auto key = std::to_string(appIndex) + Constants::FILE_UNDERLINE + abilityInfo.bundleName;
    auto infoItem = sandboxAppInfos_.find(key);
    if (infoItem == sandboxAppInfos_.end()) {
        APP_LOGE("no sandbox app can be found %{public}s", abilityInfo.bundleName.c_str());
        return ERR_APPEXECFWK_SANDBOX_QUERY_NO_SANDBOX_APP;
    }

    const InnerBundleInfo &innerBundleInfo = infoItem->second;
    int32_t responseUserId = innerBundleInfo.GetResponseUserId(userId);
    auto module = innerBundleInfo.FindHapModuleInfo(abilityInfo.package, responseUserId);
    if (!module) {
        APP_LOGE("can not find module %{public}s", abilityInfo.package.c_str());
        return ERR_APPEXECFWK_SANDBOX_QUERY_NO_MODULE_INFO;
    }
    hapModuleInfo = *module;
    return ERR_OK;
}

ErrCode BundleSandboxDataMgr::GetInnerBundleInfoByUid(const int32_t &uid, InnerBundleInfo &innerBundleInfo) const
{
    APP_LOGD("GetInnerBundleInfoByUid with uid is %{public}d", uid);
    if (uid < Constants::BASE_APP_UID) {
        APP_LOGD("the uid(%{public}d) is not an application.", uid);
        return ERR_APPEXECFWK_SANDBOX_QUERY_NO_SANDBOX_APP;
    }
    int32_t userId = BundleUtil::GetUserIdByUid(uid);
    APP_LOGD("GetInnerBundleInfoByUid with userId is %{public}d", userId);

    {
        std::shared_lock<std::shared_mutex> lock(sandboxAppMutex_);
        if (!sandboxAppInfos_.empty()) {
            for (const auto &item : sandboxAppInfos_) {
                const InnerBundleInfo &info = item.second;
                auto innerUid = info.GetUid(userId);
                APP_LOGD("GetInnerBundleInfoByUid with innerUid is %{public}d", innerUid);
                if (innerUid == uid) {
                    innerBundleInfo = info;
                    return ERR_OK;
                }
            }
        }
    }
    return ERR_APPEXECFWK_SANDBOX_QUERY_NO_SANDBOX_APP;
}

bool BundleSandboxDataMgr::SaveSandboxPersistentInfo(const std::string &bundleName,
    const InnerBundleInfo &innerBundleInfo)
{
    APP_LOGD("SaveSandboxPersistentInfo for bundleName %{public}s", bundleName.c_str());
    std::unique_lock<std::shared_mutex> lock(sandboxDbMutex_);
    if (sandboxManagerDb_ == nullptr) {
        APP_LOGE("error sandboxManagerDb_ is nullptr.");
        return false;
    }
    return sandboxManagerDb_->SaveSandboxInnerBundleInfo(bundleName, innerBundleInfo);
}

bool BundleSandboxDataMgr::RemoveSandboxPersistentInfo(const std::string &bundleName)
{
    APP_LOGD("RemoveSandboxPersistentInfo for bundleName %{public}s", bundleName.c_str());
    std::unique_lock<std::shared_mutex> lock(sandboxDbMutex_);
    if (sandboxManagerDb_ == nullptr) {
        APP_LOGE("error sandboxManagerDb_ is nullptr.");
        return false;
    }
    return sandboxManagerDb_->DeleteSandboxInnerBundleInfo(bundleName);
}

bool BundleSandboxDataMgr::RestoreSandboxPersistentInnerBundleInfo()
{
    APP_LOGD("start to RestoreSandboxPersistentInnerBundleInfo");
    std::unique_lock<std::shared_mutex> lockDbMutex(sandboxDbMutex_);
    if (sandboxManagerDb_ == nullptr) {
        APP_LOGE("error sandboxManagerDb_ is nullptr.");
        return false;
    }
    std::unique_lock<std::shared_mutex> lockAppMutex(sandboxAppMutex_);
    if (!sandboxManagerDb_->QueryAllSandboxInnerBundleInfo(sandboxAppInfos_)) {
        APP_LOGE("QueryAllSandboxInnerBundleInfo failed");
        return false;
    }
    for (const auto &sandboxInfo : sandboxAppInfos_) {
        auto fileUnderlinePos = sandboxInfo.first.find(Constants::FILE_UNDERLINE);
        if (fileUnderlinePos == std::string::npos) {
            APP_LOGW("invalid bundleName_appIndex");
            continue;
        }
        std::string appIndexStr = sandboxInfo.first.substr(0, fileUnderlinePos);
        std::string bundleName = sandboxInfo.first.substr(fileUnderlinePos + 1);
        int32_t appIndex = 0;
        if (!OHOS::StrToInt(appIndexStr, appIndex)) {
            APP_LOGW("invalid appIndex %{public}s", appIndexStr.c_str());
            continue;
        }
        if (!RestoreSandboxAppIndex(bundleName, appIndex)) {
            APP_LOGW("RestoreSandboxAppIndex appIndex failed");
        }
    }
    return true;
}

bool BundleSandboxDataMgr::RestoreSandboxAppIndex(const std::string &bundleName, int32_t appIndex)
{
    APP_LOGD("RestoreSandboxAppIndex begin");
    if (bundleName.empty()) {
        APP_LOGE("RestoreSandboxAppIndex bundleName is empty");
        return false;
    }
    std::unique_lock<std::mutex> lock(sandboxAppIndexMapMutex_);
    auto firstIterator = sandboxAppIndexMap_.find(bundleName);
    if (firstIterator == sandboxAppIndexMap_.end()) {
        std::set<int32_t> innerSet { appIndex };
        sandboxAppIndexMap_.emplace(bundleName, innerSet);
        APP_LOGD("RestoreSandboxAppIndex successfully");
        return true;
    }

    firstIterator->second.insert(appIndex);
    APP_LOGD("RestoreSandboxAppIndex finish");
    return true;
}

void BundleSandboxDataMgr::RestoreSandboxUidAndGid(std::map<int32_t, std::string> &bundleIdMap)
{
    APP_LOGD("RestoreSandboxUidAndGid begin");
    std::unique_lock<std::shared_mutex> lock(sandboxAppMutex_);
    for (const auto &info : sandboxAppInfos_) {
        for (auto infoItem : info.second.GetInnerBundleUserInfos()) {
            auto innerBundleUserInfo = infoItem.second;
            int32_t bundleId = innerBundleUserInfo.uid -
                innerBundleUserInfo.bundleUserInfo.userId * Constants::BASE_USER_RANGE;
            auto item = bundleIdMap.find(bundleId);
            if (item == bundleIdMap.end()) {
                bundleIdMap.emplace(bundleId, info.first);
            } else {
                bundleIdMap[bundleId] = info.first;
            }
            BundleUtil::MakeFsConfig(info.first, bundleId, Constants::HMDFS_CONFIG_PATH);
            BundleUtil::MakeFsConfig(info.first, bundleId, Constants::SHAREFS_CONFIG_PATH);
        }
    }
    APP_LOGD("RestoreSandboxUidAndGid finish");
}
} // AppExecFwk
} // OHOS
