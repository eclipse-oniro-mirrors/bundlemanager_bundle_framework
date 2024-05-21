/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <mutex>

#include "ability_manager_helper.h"
#include "account_helper.h"
#include "aging/aging_handler.h"
#include "app_log_wrapper.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_promise.h"
#include "event_report.h"
#include "install_param.h"
#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
class AgingUninstallReceiveImpl : public StatusReceiverHost {
public:
    AgingUninstallReceiveImpl() = default;
    virtual ~AgingUninstallReceiveImpl() override = default;

    bool IsRunning()
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        return isRunning_;
    }

    void MarkRunning()
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        isRunning_ = true;
    }

    void SetAgingPromise(const std::shared_ptr<BundlePromise>& agingPromise)
    {
        agingPromise_ = agingPromise;
    }

    void OnStatusNotify(const int progress) override
    {}

    void OnFinished(const int32_t resultCode, const std::string &resultMsg) override
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        isRunning_ = false;
        if (agingPromise_) {
            APP_LOGD("Notify task end.");
            agingPromise_->NotifyAllTasksExecuteFinished();
        }
    }

private:
    std::mutex stateMutex_;
    bool isRunning_ = false;
    std::shared_ptr<BundlePromise> agingPromise_ = nullptr;
};
}

bool RecentlyUnuseBundleAgingHandler::Process(AgingRequest &request) const
{
    return ProcessBundle(request);
}

bool RecentlyUnuseBundleAgingHandler::ProcessBundle(AgingRequest &request) const
{
    APP_LOGD("aging handler start: cleanType: %{public}d, totalDataBytes: %{public}" PRId64,
        static_cast<int32_t>(request.GetAgingCleanType()), request.GetTotalDataBytes());
    for (const auto &agingBundle : request.GetAgingBundles()) {
        bool isBundleRunning = AbilityManagerHelper::IsRunning(agingBundle.GetBundleName());
        APP_LOGD("found matching bundle: %{public}s, isRunning: %{public}d.",
            agingBundle.GetBundleName().c_str(), isBundleRunning);
        if (isBundleRunning != AbilityManagerHelper::NOT_RUNNING) {
            continue;
        }

        bool result = AgingClean(agingBundle, request);
        if (!result) {
            continue;
        }

        UpdateUsedTotalDataBytes(request);
        if (!NeedContinue(request)) {
            APP_LOGD("there is no need to continue now.");
            return false;
        }
    }

    UpdateUsedTotalDataBytes(request);
    return NeedContinue(request);
}

bool RecentlyUnuseBundleAgingHandler::NeedContinue(const AgingRequest &request) const
{
    return !request.IsReachEndAgingThreshold();
}

bool RecentlyUnuseBundleAgingHandler::UpdateUsedTotalDataBytes(AgingRequest &request) const
{
    auto dataMgr = OHOS::DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return false;
    }

    request.SetTotalDataBytes(dataMgr->GetAllFreeInstallBundleSpaceSize());
    return true;
}

bool RecentlyUnuseBundleAgingHandler::AgingClean(
    const AgingBundleInfo &agingBundleInfo, AgingRequest &request) const
{
    if (request.GetAgingCleanType() == AgingCleanType::CLEAN_CACHE) {
        return CleanCache(agingBundleInfo);
    }

    return UnInstallBundle(agingBundleInfo.GetBundleName());
}

bool RecentlyUnuseBundleAgingHandler::CleanCache(const AgingBundleInfo &agingBundle) const
{
    std::vector<std::string> caches;
    if (!GetCachePath(agingBundle, caches)) {
        APP_LOGW("Get cache path failed: %{public}s", agingBundle.GetBundleName().c_str());
        EventReport::SendCleanCacheSysEvent(
            agingBundle.GetBundleName(), Constants::ALL_USERID, true, true);
        return false;
    }

    bool hasCleanCache = false;
    for (const auto &cache : caches) {
        APP_LOGD("cache path: %{public}s", cache.c_str());
        ErrCode ret = InstalldClient::GetInstance()->CleanBundleDataDir(cache);
        if (ret != ERR_OK) {
            APP_LOGE("CleanBundleDataDir failed, path: %{private}s", cache.c_str());
            continue;
        }

        hasCleanCache = true;
    }

    EventReport::SendCleanCacheSysEvent(
        agingBundle.GetBundleName(), Constants::ALL_USERID, true, !hasCleanCache);
    return hasCleanCache;
}

bool RecentlyUnuseBundleAgingHandler::GetCachePath(
    const AgingBundleInfo &agingBundle, std::vector<std::string> &caches) const
{
    auto dataMgr = OHOS::DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return false;
    }

    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    if (!dataMgr->GetInnerBundleUserInfos(agingBundle.GetBundleName(), innerBundleUserInfos)) {
        APP_LOGE("GetInnerBundleUserInfos failed bundle: %{public}s",
            agingBundle.GetBundleName().c_str());
        return false;
    }

    std::vector<std::string> rootDir;
    for (const auto &innerBundleUserInfo : innerBundleUserInfos) {
        int32_t userId = innerBundleUserInfo.bundleUserInfo.userId;
        for (const auto &el : ServiceConstants::BUNDLE_EL) {
            std::string dataDir =
                ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + el +
                ServiceConstants::PATH_SEPARATOR + std::to_string(userId) +
                ServiceConstants::BASE + agingBundle.GetBundleName();
            rootDir.emplace_back(dataDir);
        }
    }

    for (const auto &st : rootDir) {
        std::vector<std::string> cache;
        if (InstalldClient::GetInstance()->GetBundleCachePath(st, cache) != ERR_OK) {
            APP_LOGW("GetBundleCachePath failed, path: %{public}s", st.c_str());
            continue;
        }

        std::copy(cache.begin(), cache.end(), std::back_inserter(caches));
    }

    return !caches.empty();
}

bool RecentlyUnuseBundleAgingHandler::UnInstallBundle(const std::string &bundleName) const
{
    auto bms = DelayedSingleton<BundleMgrService>::GetInstance();
    if (bms == nullptr) {
        return false;
    }

    auto bundleInstaller = bms->GetBundleInstaller();
    if (bundleInstaller == nullptr) {
        APP_LOGE("bundleInstaller is null.");
        return false;
    }

    sptr<AgingUninstallReceiveImpl> unInstallReceiverImpl(new (std::nothrow) AgingUninstallReceiveImpl());
    if (unInstallReceiverImpl == nullptr) {
        return false;
    }

    std::shared_ptr<BundlePromise> agingPromise = std::make_shared<BundlePromise>();
    unInstallReceiverImpl->SetAgingPromise(agingPromise);
    unInstallReceiverImpl->MarkRunning();
    InstallParam installParam;
    installParam.userId = Constants::ALL_USERID;
    installParam.installFlag = InstallFlag::FREE_INSTALL;
    installParam.isAgingUninstall = true;
    installParam.noSkipsKill = false;
    bundleInstaller->Uninstall(bundleName, installParam, unInstallReceiverImpl);
    if (unInstallReceiverImpl->IsRunning()) {
        APP_LOGD("Wait for UnInstallBundle end %{public}s.", bundleName.c_str());
        agingPromise->WaitForAllTasksExecute();
    }

    return true;
}
}  //  namespace AppExecFwk
}  //  namespace OHOS
