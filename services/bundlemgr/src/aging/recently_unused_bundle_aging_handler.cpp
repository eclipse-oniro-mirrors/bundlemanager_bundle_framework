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

#include <cinttypes>
#include <mutex>

#include "ability_manager_helper.h"
#include "account_helper.h"
#include "aging/aging_handler.h"
#include "app_log_wrapper.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_promise.h"
#include "install_param.h"

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

    virtual void OnStatusNotify(const int progress) override
    {}

    virtual void OnFinished(const int32_t resultCode, const std::string &resultMsg) override
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
    bool needContinue = true;
    APP_LOGD("aging handler start: %{public}s, currentTotalDataBytes: %{pubic}" PRId64,
        GetName().c_str(), request.GetTotalDataBytes());
    std::vector<AgingBundleInfo> &agingBundles =
        const_cast<std::vector<AgingBundleInfo> &>(request.GetAgingBundles());
    APP_LOGD("aging handler start: agingBundles size :%{public}zu / %{public}" PRId64,
        agingBundles.size(), request.GetTotalDataBytes());
    auto iter = agingBundles.begin();
    while (iter != agingBundles.end()) {
        if (!CheckBundle(*iter)) {
            break;
        }

        APP_LOGI("found matching bundle: %{public}s.", iter->GetBundleName().c_str());
        bool isBundlerunning = AbilityManagerHelper::IsRunning(iter->GetBundleName(), iter->GetBundleUid());
        if (isBundlerunning == AbilityManagerHelper::NOT_RUNNING) {
            bool isBundleUnistalled = UnInstallBundle(iter->GetBundleName(), "");
            if (isBundleUnistalled) {
                request.UpdateTotalDataBytesAfterUninstalled(iter->GetDataBytes());
            }
        }

        iter = agingBundles.erase(iter);
        if (NeedCheckEndAgingThreshold()) {
            if (!NeedContinue(request)) {
                APP_LOGD("there is no need to continue now.");
                needContinue = false;
                return needContinue;
            }
        }
    }

    if (!NeedContinue(request)) {
        APP_LOGD("there is no need to continue now.");
        needContinue = false;
    }

    APP_LOGD("aging handle done: %{public}s, currentTotalDataBytes: %{public}" PRId64, GetName().c_str(),
        request.GetTotalDataBytes());
    return needContinue;
}

bool RecentlyUnuseBundleAgingHandler::ProcessModule(AgingRequest &request) const
{
    APP_LOGD("aging handler start: %{public}s, totalDataBytes: %{public}" PRId64,
        GetName().c_str(), request.GetTotalDataBytes());
    for (const auto &agingModule : request.GetAgingModules()) {
        if (!CheckModule(agingModule)) {
            break;
        }

        bool isModuleRunning = AbilityManagerHelper::IsRunning(
            agingModule.GetBundleName(), agingModule.GetModuleName());
        APP_LOGD("found matching bundle: %{public}s , module: %{public}s, isRunning: %{public}d.",
            agingModule.GetBundleName().c_str(), agingModule.GetModuleName().c_str(), isModuleRunning);
        if (isModuleRunning != AbilityManagerHelper::NOT_RUNNING) {
            continue;
        }

        UnInstallBundle(agingModule.GetBundleName(), agingModule.GetModuleName());
        if (NeedCheckEndAgingThreshold()) {
            UpdateUsedTotalDataBytes(request);
            if (!NeedContinue(request)) {
                APP_LOGD("there is no need to continue now.");
                return false;
            }
        }
    }

    UpdateUsedTotalDataBytes(request);
    return NeedContinue(request);
}

bool RecentlyUnuseBundleAgingHandler::NeedContinue(const AgingRequest &request) const
{
    return !request.IsReachEndAgingThreshold();
}

bool RecentlyUnuseBundleAgingHandler::NeedCheckEndAgingThreshold() const
{
    return GetName() == AgingConstants::UNUSED_FOR_10_DAYS_BUNDLE_AGING_HANDLER ||
        GetName() == AgingConstants::BUNDLE_DATA_SIZE_AGING_HANDLER;
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

bool RecentlyUnuseBundleAgingHandler::UnInstallBundle(
    const std::string &bundleName, const std::string &moduleName) const
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
    installParam.noSkipsKill = false;
    if (moduleName.empty()) {
        bundleInstaller->Uninstall(bundleName, installParam, unInstallReceiverImpl);
    } else {
        bundleInstaller->Uninstall(bundleName, moduleName, installParam, unInstallReceiverImpl);
    }

    if (unInstallReceiverImpl->IsRunning()) {
        APP_LOGD("Wait for UnInstallBundle end %{public}s.", bundleName.c_str());
        agingPromise->WaitForAllTasksExecute();
    }

    return true;
}
}  //  namespace AppExecFwk
}  //  namespace OHOS
