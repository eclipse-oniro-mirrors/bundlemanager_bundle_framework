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

#include "bundle_user_mgr_host_impl.h"

#include "app_log_wrapper.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_promise.h"
#include "bundle_util.h"
#include "hitrace_meter.h"
#include "installd_client.h"
#ifdef BMS_RDB_ENABLE
#include "rdb_data_manager.h"
#endif
#include "status_receiver_host.h"
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
#include "default_app_mgr.h"
#endif

namespace OHOS {
namespace AppExecFwk {
std::atomic_uint g_installedHapNum = 0;
const std::string ARK_PROFILE_PATH = "/data/local/ark-profile/";

class UserReceiverImpl : public StatusReceiverHost {
public:
    UserReceiverImpl() = default;
    virtual ~UserReceiverImpl() override = default;

    void SetBundlePromise(const std::shared_ptr<BundlePromise>& bundlePromise)
    {
        bundlePromise_ = bundlePromise;
    }

    void SetTotalHapNum(int32_t totalHapNum)
    {
        totalHapNum_ = totalHapNum;
    }

    virtual void OnStatusNotify(const int progress) override {}
    virtual void OnFinished(const int32_t resultCode, const std::string &resultMsg) override
    {
        g_installedHapNum++;
        APP_LOGD("OnFinished::resultCode:(%{public}d) resultMsg:(%{public}s).",
            resultCode, resultMsg.c_str());
        if (static_cast<int32_t>(g_installedHapNum) >= totalHapNum_ && bundlePromise_ != nullptr) {
            bundlePromise_->NotifyAllTasksExecuteFinished();
        }
    }
private:
    std::shared_ptr<BundlePromise> bundlePromise_ = nullptr;
    int32_t totalHapNum_ = INT32_MAX;
};

void BundleUserMgrHostImpl::CreateNewUser(int32_t userId)
{
    HITRACE_METER(HITRACE_TAG_APP);
    APP_LOGD("CreateNewUser user(%{public}d) start.", userId);
    std::lock_guard<std::mutex> lock(bundleUserMgrMutex_);
    CheckInitialUser();
    BeforeCreateNewUser(userId);
    OnCreateNewUser(userId);
    AfterCreateNewUser(userId);
    APP_LOGD("CreateNewUser end userId: (%{public}d)", userId);
}

void BundleUserMgrHostImpl::BeforeCreateNewUser(int32_t userId)
{
    if (!BundlePermissionMgr::Init()) {
        APP_LOGW("BundlePermissionMgr::Init failed");
    }
}

void BundleUserMgrHostImpl::OnCreateNewUser(int32_t userId)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return;
    }

    auto installer = GetBundleInstaller();
    if (installer == nullptr) {
        APP_LOGE("installer is nullptr");
        return;
    }

    if (dataMgr->HasUserId(userId)) {
        APP_LOGE("Has create user %{public}d.", userId);
        return;
    }

    dataMgr->AddUserId(userId);
    // Scan preset applications and parse package information.
    std::vector<PreInstallBundleInfo> preInstallBundleInfos = dataMgr->GetAllPreInstallBundleInfos();
    g_installedHapNum = 0;
    std::shared_ptr<BundlePromise> bundlePromise = std::make_shared<BundlePromise>();
    int32_t totalHapNum = static_cast<int32_t>(preInstallBundleInfos.size());

    // Read apps installed by other users that are visible to all users
    for (const auto &info : preInstallBundleInfos) {
        InstallParam installParam;
        installParam.userId = userId;
        installParam.isPreInstallApp = true;
        installParam.installFlag = InstallFlag::NORMAL;
        sptr<UserReceiverImpl> userReceiverImpl(new (std::nothrow) UserReceiverImpl());
        userReceiverImpl->SetBundlePromise(bundlePromise);
        userReceiverImpl->SetTotalHapNum(totalHapNum);
        installer->InstallByBundleName(info.GetBundleName(), installParam, userReceiverImpl);
    }

    if (static_cast<int32_t>(g_installedHapNum) < totalHapNum) {
        bundlePromise->WaitForAllTasksExecute();
    }
}

void BundleUserMgrHostImpl::AfterCreateNewUser(int32_t userId)
{
    if (userId == Constants::START_USERID) {
        DelayedSingleton<BundleMgrService>::GetInstance()->NotifyBundleScanStatus();
    }

    BundlePermissionMgr::UnInit();
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
    DefaultAppMgr::GetInstance().HandleCreateUser(userId);
#endif
#ifdef BMS_RDB_ENABLE
        RdbDataManager::ClearCache();
#endif
}

void BundleUserMgrHostImpl::RemoveUser(int32_t userId)
{
    HITRACE_METER(HITRACE_TAG_APP);
    APP_LOGD("RemoveUser user(%{public}d) start.", userId);
    std::lock_guard<std::mutex> lock(bundleUserMgrMutex_);
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return;
    }

    auto installer = GetBundleInstaller();
    if (installer == nullptr) {
        APP_LOGE("installer is nullptr");
        return;
    }

    if (!dataMgr->HasUserId(userId)) {
        APP_LOGE("Has remove user %{public}d.", userId);
        return;
    }

    std::vector<BundleInfo> bundleInfos;
    if (!dataMgr->GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, userId)) {
        APP_LOGE("get all bundle info failed when userId is %{public}d.", userId);
        RemoveArkProfile(userId);
        RemoveAsanLogDirectory(userId);
        dataMgr->RemoveUserId(userId);
        return;
    }

    g_installedHapNum = 0;
    std::shared_ptr<BundlePromise> bundlePromise = std::make_shared<BundlePromise>();
    int32_t totalHapNum = static_cast<int32_t>(bundleInfos.size());
    for (const auto &info : bundleInfos) {
        InstallParam installParam;
        installParam.userId = userId;
        installParam.forceExecuted = true;
        installParam.isPreInstallApp = true;
        installParam.installFlag = InstallFlag::NORMAL;
        sptr<UserReceiverImpl> userReceiverImpl(new UserReceiverImpl());
        userReceiverImpl->SetBundlePromise(bundlePromise);
        userReceiverImpl->SetTotalHapNum(totalHapNum);
        installer->Uninstall(info.name, installParam, userReceiverImpl);
    }

    if (static_cast<int32_t>(g_installedHapNum) < totalHapNum) {
        bundlePromise->WaitForAllTasksExecute();
    }

    RemoveArkProfile(userId);
    RemoveAsanLogDirectory(userId);
    dataMgr->RemoveUserId(userId);
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
    DefaultAppMgr::GetInstance().HandleRemoveUser(userId);
#endif
    APP_LOGD("RemoveUser end userId: (%{public}d)", userId);
}

void BundleUserMgrHostImpl::RemoveArkProfile(int32_t userId)
{
    std::string arkProfilePath;
    arkProfilePath.append(ARK_PROFILE_PATH).append(std::to_string(userId));
    APP_LOGI("DeleteArkProfile %{public}s when remove user", arkProfilePath.c_str());
    InstalldClient::GetInstance()->RemoveDir(arkProfilePath);
}

void BundleUserMgrHostImpl::RemoveAsanLogDirectory(int32_t userId)
{
    std::string asanLogDir = Constants::BUNDLE_ASAN_LOG_DIR + Constants::PATH_SEPARATOR
        + std::to_string(userId);
    APP_LOGI("remove asan log directory %{public}s when remove user", asanLogDir.c_str());
    InstalldClient::GetInstance()->RemoveDir(asanLogDir);
}

void BundleUserMgrHostImpl::CheckInitialUser()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return;
    }

    if (!dataMgr->HasInitialUserCreated()) {
        APP_LOGD("Bms initial user do not created successfully and wait.");
        std::shared_ptr<BundlePromise> bundlePromise = std::make_shared<BundlePromise>();
        dataMgr->SetBundlePromise(bundlePromise);
        bundlePromise->WaitForAllTasksExecute();
        APP_LOGD("Bms initial user created successfully.");
    }
}

const std::shared_ptr<BundleDataMgr> BundleUserMgrHostImpl::GetDataMgrFromService()
{
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
}

const sptr<IBundleInstaller> BundleUserMgrHostImpl::GetBundleInstaller()
{
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
}
}  // namespace AppExecFwk
}  // namespace OHOS
