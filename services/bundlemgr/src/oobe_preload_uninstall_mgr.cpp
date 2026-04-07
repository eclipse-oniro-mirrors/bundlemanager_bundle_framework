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

#include "oobe_preload_uninstall_mgr.h"

#include <algorithm>
#include <map>
#include <set>

#include "app_log_wrapper.h"
#include "bundle_installer.h"
#include "bundle_mgr_service.h"
#include "datetime_ex.h"
#include "ffrt.h"
#include "json_util.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* OOBE_PENDING_PRELOAD_UNINSTALL_BUNDLES = "OOBE_PENDING_PRELOAD_UNINSTALL_BUNDLES";
}

OobePreloadUninstallMgr::OobePreloadUninstallMgr()
{}

OobePreloadUninstallMgr::~OobePreloadUninstallMgr()
{}

bool OobePreloadUninstallMgr::LoadPendingBundlesLocked(PendingBundleUserIds &pendingBundles)
{
    auto bmsParam = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsParam == nullptr) {
        APP_LOGE("bmsParam is nullptr");
        return false;
    }
    std::string value;
    if (!bmsParam->GetBmsParam(OOBE_PENDING_PRELOAD_UNINSTALL_BUNDLES, value) || value.empty()) {
        pendingBundles.clear();
        return true;
    }
    std::map<std::string, std::vector<int32_t>> pendingBundleMap;
    if (!ParseInfoFromJsonStr(value.c_str(), pendingBundleMap)) {
        APP_LOGE("ParseInfoFromJsonStr failed");
        return false;
    }
    PendingBundleUserIds tempPendingBundles;
    for (const auto &[bundleName, userIdVec] : pendingBundleMap) {
        if (bundleName.empty()) {
            APP_LOGE("pending bundle item is invalid");
            continue;
        }
        std::set<int32_t> userIds;
        for (int32_t userId : userIdVec) {
            if (userId < 0) {
                APP_LOGE("pending bundle userId is invalid");
                continue;
            }
            userIds.emplace(userId);
        }
        if (!userIds.empty()) {
            tempPendingBundles.emplace(bundleName, std::move(userIds));
        }
    }
    pendingBundles = std::move(tempPendingBundles);
    return true;
}

bool OobePreloadUninstallMgr::SavePendingBundlesLocked(const PendingBundleUserIds &pendingBundles)
{
    auto bmsParam = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsParam == nullptr) {
        APP_LOGE("bmsParam is nullptr");
        return false;
    }
    if (pendingBundles.empty()) {
        return bmsParam->DeleteBmsParam(OOBE_PENDING_PRELOAD_UNINSTALL_BUNDLES);
    }
    std::map<std::string, std::vector<int32_t>> pendingBundleMap;
    for (const auto &[bundleName, userIds] : pendingBundles) {
        if (bundleName.empty() || userIds.empty()) {
            continue;
        }
        pendingBundleMap.emplace(bundleName, std::vector<int32_t>(userIds.begin(), userIds.end()));
    }
    if (pendingBundleMap.empty()) {
        return bmsParam->DeleteBmsParam(OOBE_PENDING_PRELOAD_UNINSTALL_BUNDLES);
    }
    if (!bmsParam->SaveBmsParam(OOBE_PENDING_PRELOAD_UNINSTALL_BUNDLES, GetJsonStrFromInfo(pendingBundleMap))) {
        APP_LOGE("SaveBmsParam failed");
        return false;
    }
    return true;
}

OobePreloadUninstallMgr::PendingBundleUserIds OobePreloadUninstallMgr::GetPendingBundles()
{
    std::lock_guard<std::mutex> lock(mutex_);
    PendingBundleUserIds pendingBundles;
    if (!LoadPendingBundlesLocked(pendingBundles)) {
        APP_LOGE("LoadPendingBundlesLocked failed");
        pendingBundles.clear();
    }
    return pendingBundles;
}

bool OobePreloadUninstallMgr::AddPendingBundle(const std::string &bundleName, int32_t userId)
{
    if (bundleName.empty() || userId < 0) {
        APP_LOGE("bundleName or userId is invalid");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    PendingBundleUserIds pendingBundles;
    if (!LoadPendingBundlesLocked(pendingBundles)) {
        APP_LOGE("LoadPendingBundlesLocked failed");
        return false;
    }
    pendingBundles[bundleName].emplace(userId);
    return SavePendingBundlesLocked(pendingBundles);
}

bool OobePreloadUninstallMgr::RemovePendingBundle(const std::string &bundleName, int32_t userId)
{
    if (bundleName.empty() || userId < 0) {
        APP_LOGE("bundleName or userId is invalid");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    PendingBundleUserIds pendingBundles;
    if (!LoadPendingBundlesLocked(pendingBundles)) {
        APP_LOGE("LoadPendingBundlesLocked failed");
        return false;
    }
    auto bundleIt = pendingBundles.find(bundleName);
    if (bundleIt == pendingBundles.end()) {
        return true;
    }
    bundleIt->second.erase(userId);
    if (bundleIt->second.empty()) {
        pendingBundles.erase(bundleIt);
    }
    return SavePendingBundlesLocked(pendingBundles);
}

void OobePreloadUninstallMgr::RecoverPendingBundles(int32_t userId)
{
    APP_LOGI("start, userId:%{public}d", userId);
    if (userId < 0) {
        APP_LOGE("userId is invalid");
        return;
    }
    auto pendingBundles = GetPendingBundles();
    if (pendingBundles.empty()) {
        return;
    }
    auto task = [pendingBundles, userId]() {
        auto service = DelayedSingleton<BundleMgrService>::GetInstance();
        if (service == nullptr) {
            APP_LOGE("service is nullptr");
            return;
        }
        auto mgr = service->GetOobePreloadUninstallMgr();
        if (mgr == nullptr) {
            APP_LOGE("mgr is nullptr");
            return;
        }
        auto dataMgr = service->GetDataMgr();
        if (dataMgr == nullptr) {
            APP_LOGE("dataMgr is nullptr");
            return;
        }
        auto installer = std::make_shared<BundleInstaller>(GetMicroTickCount(), nullptr);
        for (const auto &[bundleName, userIds] : pendingBundles) {
            if (userIds.find(userId) == userIds.end()) {
                continue;
            }
            UninstallBundleInfo uninstallBundleInfo;
            if (!dataMgr->GetUninstallBundleInfo(bundleName, uninstallBundleInfo)) {
                APP_LOGW("uninstall bundle info missing, remove pending bundle:%{public}s", bundleName.c_str());
                (void)mgr->RemovePendingBundle(bundleName, userId);
                continue;
            }
            if (uninstallBundleInfo.userInfos.find(std::to_string(userId)) == uninstallBundleInfo.userInfos.end()) {
                APP_LOGW("pending userId:%{public}d not found in uninstall info, remove pending bundle:%{public}s",
                    userId, bundleName.c_str());
                (void)mgr->RemovePendingBundle(bundleName, userId);
                continue;
            }
            InstallParam installParam;
            installParam.userId = userId;
            installParam.isKeepData = false;
            ErrCode ret = installer->UninstallForInternal(bundleName, installParam);
            if (ret == ERR_OK) {
                (void)mgr->RemovePendingBundle(bundleName, userId);
                APP_LOGI("recover second stage uninstall success, %{public}s %{public}d", bundleName.c_str(), userId);
            } else {
                APP_LOGE("recover second stage uninstall failed, %{public}s %{public}d %{public}d",
                    bundleName.c_str(), userId, ret);
            }
        }
    };
    ffrt::submit(task);
}
} // namespace AppExecFwk
} // namespace OHOS
