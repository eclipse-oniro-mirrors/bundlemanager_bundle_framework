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

#include "bundle_user_mgr_host_impl.h"

#include "bms_extension_data_mgr.h"
#include "bms_key_event_mgr.h"
#include "bundle_mgr_service.h"
#include "hitrace_meter.h"
#include "installd_client.h"
#include "ipc_skeleton.h"
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
#include "default_app_mgr.h"
#endif
#ifdef WINDOW_ENABLE
#include "scene_board_judgement.h"
#endif
#include "status_receiver_host.h"

namespace OHOS {
namespace AppExecFwk {
std::atomic_uint g_installedHapNum = 0;
const std::string ARK_PROFILE_PATH = "/data/local/ark-profile/";
const uint32_t FACTOR = 8;
const uint32_t INTERVAL = 6;
constexpr const char* QUICK_FIX_APP_PATH = "/data/update/quickfix/app/temp/cold";
constexpr const char* ACCESSTOKEN_PROCESS_NAME = "accesstoken_service";

class UserReceiverImpl : public StatusReceiverHost {
public:
    UserReceiverImpl(const std::string &bundleName, bool needReInstall)
        : bundleName_(bundleName), needReInstall_(needReInstall) {};
    virtual ~UserReceiverImpl() override = default;

    void SetBundlePromise(const std::shared_ptr<BundlePromise>& bundlePromise)
    {
        bundlePromise_ = bundlePromise;
    }

    void SetTotalHapNum(int32_t totalHapNum)
    {
        totalHapNum_ = totalHapNum;
    }

    void SavePreInstallException(const std::string &bundleName)
    {
        auto preInstallExceptionMgr =
            DelayedSingleton<BundleMgrService>::GetInstance()->GetPreInstallExceptionMgr();
        if (preInstallExceptionMgr == nullptr) {
            APP_LOGE("preInstallExceptionMgr is nullptr");
            return;
        }

        preInstallExceptionMgr->SavePreInstallExceptionBundleName(bundleName);
    }

    virtual void OnStatusNotify(const int progress) override {}
    virtual void OnFinished(const int32_t resultCode, const std::string &resultMsg) override
    {
        g_installedHapNum++;
        APP_LOGI("OnFinished, resultCode : %{public}d, resultMsg : %{public}s, count : %{public}u",
            resultCode, resultMsg.c_str(), g_installedHapNum.load());
        if (static_cast<int32_t>(g_installedHapNum) >= totalHapNum_ && bundlePromise_ != nullptr) {
            bundlePromise_->NotifyAllTasksExecuteFinished();
        }

        if (resultCode != ERR_OK && resultCode !=
            ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON && needReInstall_) {
            APP_LOGI("needReInstall bundleName: %{public}s", bundleName_.c_str());
            BmsKeyEventMgr::ProcessMainBundleInstallFailed(bundleName_, resultCode);
            SavePreInstallException(bundleName_);
        }
    }
private:
    std::shared_ptr<BundlePromise> bundlePromise_ = nullptr;
    int32_t totalHapNum_ = INT32_MAX;
    std::string bundleName_;
    bool needReInstall_ = false;
};

ErrCode BundleUserMgrHostImpl::CreateNewUser(int32_t userId, const std::vector<std::string> &disallowList)
{
    HITRACE_METER(HITRACE_TAG_APP);
    EventReport::SendUserSysEvent(UserEventType::CREATE_START, userId);
    EventReport::SendCpuSceneEvent(ACCESSTOKEN_PROCESS_NAME, 1 << 1); // second scene
    APP_LOGI("CreateNewUser user(%{public}d) start", userId);
    std::lock_guard<std::mutex> lock(bundleUserMgrMutex_);
    if (CheckInitialUser() != ERR_OK) {
        APP_LOGE("CheckInitialUser failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    BeforeCreateNewUser(userId);
    OnCreateNewUser(userId, disallowList);
    UninstallBackupUninstallList(userId);
    AfterCreateNewUser(userId);
    EventReport::SendUserSysEvent(UserEventType::CREATE_END, userId);
    APP_LOGI("CreateNewUser end userId: (%{public}d)", userId);
    return ERR_OK;
}

void BundleUserMgrHostImpl::BeforeCreateNewUser(int32_t userId)
{
    ClearBundleEvents();
}

void BundleUserMgrHostImpl::OnCreateNewUser(int32_t userId, const std::vector<std::string> &disallowList)
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
        APP_LOGE("Has create user %{public}d", userId);
        return;
    }

    dataMgr->AddUserId(userId);
    std::set<PreInstallBundleInfo> preInstallBundleInfos;
    if (!GetAllPreInstallBundleInfos(disallowList, userId, preInstallBundleInfos)) {
        APP_LOGE("GetAllPreInstallBundleInfos failed %{public}d", userId);
        return;
    }

    g_installedHapNum = 0;
    std::shared_ptr<BundlePromise> bundlePromise = std::make_shared<BundlePromise>();
    int32_t totalHapNum = static_cast<int32_t>(preInstallBundleInfos.size());
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    bool needReinstall = userId == Constants::START_USERID;
    // Read apps installed by other users that are visible to all users
    for (const auto &info : preInstallBundleInfos) {
        InstallParam installParam;
        installParam.userId = userId;
        installParam.isPreInstallApp = true;
        installParam.installFlag = InstallFlag::NORMAL;
        installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_BOOT_INSTALLED;
        sptr<UserReceiverImpl> userReceiverImpl(
            new (std::nothrow) UserReceiverImpl(info.GetBundleName(), needReinstall));
        userReceiverImpl->SetBundlePromise(bundlePromise);
        userReceiverImpl->SetTotalHapNum(totalHapNum);
        installer->InstallByBundleName(info.GetBundleName(), installParam, userReceiverImpl);
    }
    if (static_cast<int32_t>(g_installedHapNum) < totalHapNum) {
        bundlePromise->WaitForAllTasksExecute();
        APP_LOGI("OnCreateNewUser wait complete");
    }
    // process keep alive bundle
    if (userId == Constants::START_USERID) {
        BMSEventHandler::ProcessRebootQuickFixBundleInstall(QUICK_FIX_APP_PATH, false);
    }
    IPCSkeleton::SetCallingIdentity(identity);
}

bool BundleUserMgrHostImpl::GetAllPreInstallBundleInfos(
    const std::vector<std::string> &disallowList,
    int32_t userId,
    std::set<PreInstallBundleInfo> &preInstallBundleInfos)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }

    bool isStartUser = userId == Constants::START_USERID;
    std::vector<PreInstallBundleInfo> allPreInstallBundleInfos = dataMgr->GetAllPreInstallBundleInfos();
    // Scan preset applications and parse package information.
    for (auto &preInfo : allPreInstallBundleInfos) {
        InnerBundleInfo innerBundleInfo;
        if (dataMgr->FetchInnerBundleInfo(preInfo.GetBundleName(), innerBundleInfo)
            && innerBundleInfo.IsSingleton()) {
            APP_LOGI("BundleName is IsSingleton %{public}s", preInfo.GetBundleName().c_str());
            continue;
        }
        if (std::find(disallowList.begin(), disallowList.end(),
            preInfo.GetBundleName()) != disallowList.end()) {
            APP_LOGI("BundleName is same as black list %{public}s", preInfo.GetBundleName().c_str());
            continue;
        }
        if (isStartUser) {
            preInfo.CalculateHapTotalSize();
        }
        preInstallBundleInfos.insert(preInfo);
    }

    return !preInstallBundleInfos.empty();
}

void BundleUserMgrHostImpl::AfterCreateNewUser(int32_t userId)
{
    if (userId == Constants::START_USERID) {
        DelayedSingleton<BundleMgrService>::GetInstance()->NotifyBundleScanStatus();
        // need process main bundle status
        BmsKeyEventMgr::ProcessMainBundleStatusFinally();
    }

#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
    DefaultAppMgr::GetInstance().HandleCreateUser(userId);
#endif
    HandleSceneBoard(userId);
    RdbDataManager::ClearCache();
}

ErrCode BundleUserMgrHostImpl::RemoveUser(int32_t userId)
{
    HITRACE_METER(HITRACE_TAG_APP);
    EventReport::SendUserSysEvent(UserEventType::REMOVE_START, userId);
    EventReport::SendCpuSceneEvent(ACCESSTOKEN_PROCESS_NAME, 1 << 1); // second scene
    APP_LOGI("RemoveUser user(%{public}d) start", userId);
    std::lock_guard<std::mutex> lock(bundleUserMgrMutex_);
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    auto installer = GetBundleInstaller();
    if (installer == nullptr) {
        APP_LOGE("installer is nullptr");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    if (!dataMgr->HasUserId(userId)) {
        APP_LOGE("Has remove user %{public}d", userId);
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }

    std::vector<BundleInfo> bundleInfos;
    if (!dataMgr->GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, userId)) {
        APP_LOGE("get all bundle info failed when userId %{public}d", userId);
        RemoveArkProfile(userId);
        RemoveAsanLogDirectory(userId);
        dataMgr->RemoveUserId(userId);
        return ERR_OK;
    }

    ClearBundleEvents();
    InnerUninstallBundle(userId, bundleInfos);
    RemoveArkProfile(userId);
    RemoveAsanLogDirectory(userId);
    dataMgr->RemoveUserId(userId);
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
    DefaultAppMgr::GetInstance().HandleRemoveUser(userId);
#endif
    EventReport::SendUserSysEvent(UserEventType::REMOVE_END, userId);
    HandleNotifyBundleEventsAsync();
    APP_LOGI("RemoveUser end userId: (%{public}d)", userId);
    return ERR_OK;
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
    std::string asanLogDir = ServiceConstants::BUNDLE_ASAN_LOG_DIR + ServiceConstants::PATH_SEPARATOR
        + std::to_string(userId);
    APP_LOGI("remove asan log directory %{public}s when remove user", asanLogDir.c_str());
    InstalldClient::GetInstance()->RemoveDir(asanLogDir);
}

ErrCode BundleUserMgrHostImpl::CheckInitialUser()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    if (!dataMgr->HasInitialUserCreated()) {
        APP_LOGI("Bms initial user do not created successfully and wait");
        std::shared_ptr<BundlePromise> bundlePromise = std::make_shared<BundlePromise>();
        dataMgr->SetBundlePromise(bundlePromise);
        bundlePromise->WaitForAllTasksExecute();
        APP_LOGI("Bms initial user created successfully");
    }
    return ERR_OK;
}

const std::shared_ptr<BundleDataMgr> BundleUserMgrHostImpl::GetDataMgrFromService()
{
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
}

const sptr<IBundleInstaller> BundleUserMgrHostImpl::GetBundleInstaller()
{
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
}

void BundleUserMgrHostImpl::InnerUninstallBundle(
    int32_t userId,
    const std::vector<BundleInfo> &bundleInfos)
{
    APP_LOGI("InnerUninstallBundle for userId: %{public}d start", userId);
    auto installer = GetBundleInstaller();
    if (installer == nullptr) {
        APP_LOGE("InnerUninstallBundle installer is nullptr");
        return;
    }
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    g_installedHapNum = 0;
    std::shared_ptr<BundlePromise> bundlePromise = std::make_shared<BundlePromise>();
    int32_t totalHapNum = static_cast<int32_t>(bundleInfos.size());
    for (const auto &info : bundleInfos) {
        InstallParam installParam;
        installParam.userId = userId;
        installParam.SetForceExecuted(true);
        installParam.concentrateSendEvent = true;
        installParam.isPreInstallApp = info.isPreInstallApp;
        installParam.installFlag = InstallFlag::NORMAL;
        installParam.isRemoveUser = true;
        sptr<UserReceiverImpl> userReceiverImpl(
            new (std::nothrow) UserReceiverImpl(info.name, false));
        userReceiverImpl->SetBundlePromise(bundlePromise);
        userReceiverImpl->SetTotalHapNum(totalHapNum);
        installer->Uninstall(info.name, installParam, userReceiverImpl);
    }
    if (static_cast<int32_t>(g_installedHapNum) < totalHapNum) {
        bundlePromise->WaitForAllTasksExecute();
    }
    IPCSkeleton::SetCallingIdentity(identity);
    APP_LOGI("InnerUninstallBundle for userId: %{public}d end", userId);
}

void BundleUserMgrHostImpl::ClearBundleEvents()
{
    std::lock_guard<std::mutex> uninstallEventLock(bundleEventMutex_);
    bundleEvents_.clear();
}

void BundleUserMgrHostImpl::AddNotifyBundleEvents(const NotifyBundleEvents &notifyBundleEvents)
{
    std::lock_guard<std::mutex> lock(bundleEventMutex_);
    bundleEvents_.emplace_back(notifyBundleEvents);
}

void BundleUserMgrHostImpl::HandleNotifyBundleEventsAsync()
{
    auto task = [this] {
        HandleNotifyBundleEvents();
    };
    std::thread taskThread(task);
    taskThread.detach();
}

void BundleUserMgrHostImpl::HandleNotifyBundleEvents()
{
    APP_LOGI("HandleNotifyBundleEvents");
    std::lock_guard<std::mutex> lock(bundleEventMutex_);
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return;
    }

    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    for (size_t i = 0; i < bundleEvents_.size(); ++i) {
        commonEventMgr->NotifyBundleStatus(bundleEvents_[i], dataMgr);
        if ((i != 0) && (i % FACTOR == 0)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(INTERVAL));
        }
    }

    bundleEvents_.clear();
}

void BundleUserMgrHostImpl::HandleSceneBoard(int32_t userId) const
{
#ifdef WINDOW_ENABLE
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return;
    }
    bool sceneBoardEnable = Rosen::SceneBoardJudgement::IsSceneBoardEnabled();
    APP_LOGI("userId : %{public}d, sceneBoardEnable : %{public}d", userId, sceneBoardEnable);
    dataMgr->SetApplicationEnabled(Constants::SCENE_BOARD_BUNDLE_NAME, 0, sceneBoardEnable,
        ServiceConstants::CALLER_NAME_BMS, userId);
    dataMgr->SetApplicationEnabled(ServiceConstants::LAUNCHER_BUNDLE_NAME, 0, !sceneBoardEnable,
        ServiceConstants::CALLER_NAME_BMS, userId);
#endif
}

void BundleUserMgrHostImpl::UninstallBackupUninstallList(int32_t userId)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    std::set<std::string> uninstallList;
    bmsExtensionDataMgr.GetBackupUninstallList(userId, uninstallList);
    if (uninstallList.empty()) {
        APP_LOGI("userId : %{public}d, back uninstall list is empty", userId);
        return;
    }
    auto installer = GetBundleInstaller();
    if (installer == nullptr) {
        APP_LOGE("installer is nullptr");
        return;
    }

    std::string identity = IPCSkeleton::ResetCallingIdentity();
    g_installedHapNum = 0;
    std::shared_ptr<BundlePromise> bundlePromise = std::make_shared<BundlePromise>();
    int32_t totalHapNum = static_cast<int32_t>(uninstallList.size());
    for (const auto &bundleName : uninstallList) {
        InstallParam installParam;
        installParam.userId = userId;
        installParam.needSendEvent = false;
        installParam.isPreInstallApp = true;
        sptr<UserReceiverImpl> userReceiverImpl(
            new (std::nothrow) UserReceiverImpl(bundleName, false));
        userReceiverImpl->SetBundlePromise(bundlePromise);
        userReceiverImpl->SetTotalHapNum(totalHapNum);
        installer->Uninstall(bundleName, installParam, userReceiverImpl);
    }
    if (static_cast<int32_t>(g_installedHapNum) < totalHapNum) {
        bundlePromise->WaitForAllTasksExecute();
    }
    IPCSkeleton::SetCallingIdentity(identity);
    bmsExtensionDataMgr.ClearBackupUninstallFile(userId);
}
}  // namespace AppExecFwk
}  // namespace OHOS
