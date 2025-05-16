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

#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "securec.h"
#include "aot_handler.h"
#include "bms_extension_data_mgr.h"
#include "bms_key_event_mgr.h"
#include "bundle_mgr_service.h"
#include "hitrace_meter.h"
#include "installd_client.h"
#include "ipc_skeleton.h"
#include "parameters.h"
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
constexpr const char* DATA_PRELOAD_APP = "/data/preload/app/";
constexpr uint8_t FACTOR = 8;
constexpr uint8_t INTERVAL = 6;
constexpr const char* QUICK_FIX_APP_PATH = "/data/update/quickfix/app/temp/cold";
constexpr const char* ACCESSTOKEN_PROCESS_NAME = "accesstoken_service";
constexpr const char* PRELOAD_APP = "/preload/app/";
constexpr const char* MULTIUSER_INSTALL_THIRD_PRELOAD_APP = "const.bms.multiUserInstallThirdPreloadApp";

struct BootFailProcParam {
    char padForErrno[16];
    int  bootFailErrno;
    char padForStage[8];
    int  stage; /* stage saved by bootdetector */
    char padForSuggest[4];
    int  suggestRecoveryMethod;
    char padForDetailInfo[28]; /* reserved count */
    char detailInfo[384]; /* max exception info count */
    char reserved[572]; /* reserved count */
} __attribute((packed));
 
#define NATIVE_SUBSYS_FAULT  0x40000009
#define NATIVE_STAGE 0x4FFFFFFE
#define BOOT_DETECTOR_DEV_PATH "/dev/bbox"
#define BOOT_DETECTOR_IOCTL_BASE 'B'
#define PROCESS_BOOTFAIL _IOW(BOOT_DETECTOR_IOCTL_BASE, 102, struct BootFailProcParam)

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

bool BundleUserMgrHostImpl::SkipThirdPreloadAppInstallation(const int32_t userId, const PreInstallBundleInfo &preInfo)
{
    if (userId == Constants::START_USERID) {
        return false;
    }
    const std::vector<std::string> bundlePaths = preInfo.GetBundlePaths();
    if (bundlePaths.empty()) {
        return false;
    }
    const std::string firstBundlePath = bundlePaths.front();
    if (firstBundlePath.rfind(DATA_PRELOAD_APP, 0) == 0) {
        APP_LOGI("-n %{public}s -u %{public}d not install data preload app", preInfo.GetBundleName().c_str(), userId);
        return true;
    }
    bool multiUserInstallThirdPreloadApp = OHOS::system::GetBoolParameter(MULTIUSER_INSTALL_THIRD_PRELOAD_APP, true);
    if (firstBundlePath.rfind(PRELOAD_APP, 0) == 0 && !multiUserInstallThirdPreloadApp) {
        APP_LOGI("-n %{public}s -u %{public}d not install preload app", preInfo.GetBundleName().c_str(), userId);
        return true;
    }
    return false;
}

ErrCode BundleUserMgrHostImpl::CreateNewUser(int32_t userId, const std::vector<std::string> &disallowList,
    const std::optional<std::vector<std::string>> &allowList)
{
    HITRACE_METER(HITRACE_TAG_APP);
    EventReport::SendCpuSceneEvent(ACCESSTOKEN_PROCESS_NAME, 1 << 1); // second scene
    APP_LOGI("CreateNewUser user(%{public}d) start", userId);
    BmsExtensionDataMgr bmsExtensionDataMgr;
    bool needToSkipPreBundleInstall = bmsExtensionDataMgr.IsNeedToSkipPreBundleInstall();
    if (needToSkipPreBundleInstall) {
        APP_LOGI("need to skip pre bundle install");
        EventReport::SendUserSysEvent(UserEventType::CREATE_WITH_SKIP_PRE_INSTALL_START, userId);
    } else {
        EventReport::SendUserSysEvent(UserEventType::CREATE_START, userId);
    }
    std::lock_guard<std::mutex> lock(bundleUserMgrMutex_);
    if (CheckInitialUser() != ERR_OK) {
        APP_LOGE("CheckInitialUser failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    BeforeCreateNewUser(userId);
    OnCreateNewUser(userId, needToSkipPreBundleInstall, disallowList, allowList);
    UninstallBackupUninstallList(userId, needToSkipPreBundleInstall);
    AfterCreateNewUser(userId);
    if (needToSkipPreBundleInstall) {
        EventReport::SendUserSysEvent(UserEventType::CREATE_WITH_SKIP_PRE_INSTALL_END, userId);
    } else {
        EventReport::SendUserSysEvent(UserEventType::CREATE_END, userId);
    }
    APP_LOGI("CreateNewUser end userId: (%{public}d)", userId);
    return ERR_OK;
}

void BundleUserMgrHostImpl::BeforeCreateNewUser(int32_t userId)
{
    ClearBundleEvents();
    InstalldClient::GetInstance()->AddUserDirDeleteDfx(userId);
}

void BundleUserMgrHostImpl::OnCreateNewUser(int32_t userId, bool needToSkipPreBundleInstall,
    const std::vector<std::string> &disallowList, const std::optional<std::vector<std::string>> &allowList)
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
        APP_LOGW("Has create user %{public}d", userId);
        ErrCode ret = InnerRemoveUser(userId, false); // no need lock
        if (ret != ERR_OK) {
            APP_LOGW("remove user %{public}d failed, error %{public}d", userId, ret);
        }
    }

    dataMgr->AddUserId(userId);
    dataMgr->CreateAppInstallDir(userId);
    std::set<PreInstallBundleInfo> preInstallBundleInfos;
    if (!GetAllPreInstallBundleInfos(disallowList, userId, needToSkipPreBundleInstall,
        preInstallBundleInfos, allowList)) {
        APP_LOGE("GetAllPreInstallBundleInfos failed %{public}d", userId);
        return;
    }
    GetAdditionalBundleInfos(preInstallBundleInfos);
    g_installedHapNum = 0;
    std::shared_ptr<BundlePromise> bundlePromise = std::make_shared<BundlePromise>();
    int32_t totalHapNum = static_cast<int32_t>(preInstallBundleInfos.size());
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    bool needReinstall = userId == Constants::START_USERID;
    // Read apps installed by other users that are visible to all users
    for (const auto &info : preInstallBundleInfos) {
        InstallParam installParam;
        installParam.userId = userId;
        installParam.isPreInstallApp = !info.GetIsAdditionalApp();
        installParam.installFlag = InstallFlag::NORMAL;
        installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_BOOT_INSTALLED;
        sptr<UserReceiverImpl> userReceiverImpl(
            new (std::nothrow) UserReceiverImpl(info.GetBundleName(), needReinstall));
        if (userReceiverImpl == nullptr) {
            APP_LOGE("userReceiverImpl is nullptr, -n %{public}s", info.GetBundleName().c_str());
            g_installedHapNum++;
            if (needReinstall) {
                SavePreInstallException(info.GetBundleName());
            }
            continue;
        }
        userReceiverImpl->SetBundlePromise(bundlePromise);
        userReceiverImpl->SetTotalHapNum(totalHapNum);
        installer->InstallByBundleName(info.GetBundleName(), installParam, userReceiverImpl);
    }
    if (static_cast<int32_t>(g_installedHapNum) < totalHapNum) {
        bundlePromise->WaitForAllTasksExecute();
        APP_LOGI("OnCreateNewUser wait complete");
    }
    CheckSystemHspInstallPath();
    // process keep alive bundle
    if (userId == Constants::START_USERID) {
        BMSEventHandler::ProcessRebootQuickFixBundleInstall(QUICK_FIX_APP_PATH, false);
    }
    IPCSkeleton::SetCallingIdentity(identity);
}

void BundleUserMgrHostImpl::BootFailError(const char *exceptionInfo)
{
    APP_LOGI("BootFailError start, exceptionInfo is %{public}s", exceptionInfo);
    struct BootFailProcParam parm;
    parm.bootFailErrno = NATIVE_SUBSYS_FAULT;
    parm.stage = NATIVE_STAGE;
    parm.suggestRecoveryMethod = 0;
    ErrCode ret = ERR_OK;
    if (exceptionInfo != NULL) {
        ret = strncpy_s(parm.detailInfo, sizeof(parm.detailInfo),
            exceptionInfo, std::min(sizeof(parm.detailInfo) - 1,
            strlen(exceptionInfo)));
        if (ret != ERR_OK) {
            APP_LOGE("strncpy_s failed: %{public}d", ret);
            return;
        }
    }
    APP_LOGD("parm.detailInfo is %{public}s,bootFailErrno is %{public}d",
        parm.detailInfo, parm.bootFailErrno);
    int fd = TEMP_FAILURE_RETRY(open(BOOT_DETECTOR_DEV_PATH, O_WRONLY));
    if (fd < 0) {
        APP_LOGE("open file %{public}s failed, errorNo: %{public}d:%{public}s",
            BOOT_DETECTOR_DEV_PATH, errno, strerror(errno));
        return;
    }

    ret = ioctl(fd, PROCESS_BOOTFAIL, &parm); // 1: the order of the cmd
    if (ret < 0) {
        APP_LOGE("BootFailError ioctl failed, errorNo: %{public}d, :%{public}s", errno, strerror(errno));
    }
    close(fd);
    return;
}
 
void BundleUserMgrHostImpl::CheckSystemHspInstallPath()
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return;
    }
    
    std::vector<std::string> systemHspCodePaths = dataMgr->GetAllSystemHspCodePaths();
    for (auto &codePath : systemHspCodePaths) {
        bool isExist = false;
        ErrCode result = InstalldClient::GetInstance()->IsExistDir(codePath, isExist);
        if (result != ERR_OK || !isExist) {
            APP_LOGE("%{public}s not exist, set parameter BOOT_FAIL_ERR false", codePath.c_str());
            BootFailError("bms boot fail");
            return;
        }
    }
}


bool BundleUserMgrHostImpl::GetAllPreInstallBundleInfos(
    const std::vector<std::string> &disallowList,
    int32_t userId, bool needToSkipPreBundleInstall,
    std::set<PreInstallBundleInfo> &preInstallBundleInfos,
    const std::optional<std::vector<std::string>> &allowList)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }

    bool isStartUser = userId == Constants::START_USERID;
    std::vector<PreInstallBundleInfo> allPreInstallBundleInfos = dataMgr->GetAllPreInstallBundleInfos();
    // Scan preset applications and parse package information.
    std::vector<std::string> allowLst = allowList.value_or(std::vector<std::string>());
    std::unordered_set<std::string> allowSet = allowLst.empty() ? std::unordered_set<std::string>() :
        std::unordered_set<std::string>(allowLst.begin(), allowLst.end());
    std::unordered_set<std::string> disallowSet= disallowList.empty() ? std::unordered_set<std::string>() :
        std::unordered_set<std::string>(disallowList.begin(), disallowList.end());
    bool isU1 = (userId == Constants::U1);
    for (auto &preInfo : allPreInstallBundleInfos) {
        InnerBundleInfo innerBundleInfo;
        if (dataMgr->FetchInnerBundleInfo(preInfo.GetBundleName(), innerBundleInfo)
            && innerBundleInfo.IsSingleton()) {
            APP_LOGI("BundleName is IsSingleton %{public}s", preInfo.GetBundleName().c_str());
            continue;
        }
        
        if ((isU1 && !preInfo.GetU1Enable()) || (!isU1 && preInfo.GetU1Enable())) {
            APP_LOGI(" %{public}s u1enable and u1 not matched", preInfo.GetBundleName().c_str());
            continue;
        }
        if (disallowSet.find(preInfo.GetBundleName()) != disallowSet.end()) {
            APP_LOGI("BundleName is same as black list %{public}s", preInfo.GetBundleName().c_str());
            continue;
        }
        if (allowList.has_value() && allowSet.find(preInfo.GetBundleName()) == allowSet.end()) {
            APP_LOGI("BundleName is not in white list %{public}s", preInfo.GetBundleName().c_str());
            continue;
        }
        if (needToSkipPreBundleInstall && !preInfo.GetBundlePaths().empty() &&
            (preInfo.GetBundlePaths().front().find(PRELOAD_APP) == 0)) {
            APP_LOGI("-n %{public}s -u %{public}d skip install", preInfo.GetBundleName().c_str(), userId);
            continue;
        }
        if (SkipThirdPreloadAppInstallation(userId, preInfo)) {
            continue;
        }
        if (isStartUser) {
            preInfo.CalculateHapTotalSize();
        }
        preInstallBundleInfos.insert(preInfo);
    }

    return !preInstallBundleInfos.empty();
}

void BundleUserMgrHostImpl::GetAdditionalBundleInfos(std::set<PreInstallBundleInfo> &preInstallBundleInfos)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return;
    }
    // get all non pre-installed driver apps to install for new user
    std::vector<std::string> bundleNames = dataMgr->GetBundleNamesForNewUser();
    for (auto &bundleName : bundleNames) {
        PreInstallBundleInfo preInstallBundleInfo;
        preInstallBundleInfo.SetBundleName(bundleName);
        preInstallBundleInfo.SetIsAdditionalApp(true);
        preInstallBundleInfos.insert(preInstallBundleInfo);
    }
}

void BundleUserMgrHostImpl::AfterCreateNewUser(int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
    DefaultAppMgr::GetInstance().HandleCreateUser(userId);
#endif
    HandleSceneBoard(userId);
    RdbDataManager::ClearCache();
    if (userId == Constants::START_USERID) {
        DelayedSingleton<BundleMgrService>::GetInstance()->NotifyBundleScanStatus();
        // need process main bundle status
        BmsKeyEventMgr::ProcessMainBundleStatusFinally();
    }
}

ErrCode BundleUserMgrHostImpl::RemoveUser(int32_t userId)
{
    return InnerRemoveUser(userId, true);
}

ErrCode BundleUserMgrHostImpl::InnerRemoveUser(int32_t userId, bool needLock)
{
    HITRACE_METER(HITRACE_TAG_APP);
    EventReport::SendUserSysEvent(UserEventType::REMOVE_START, userId);
    EventReport::SendCpuSceneEvent(ACCESSTOKEN_PROCESS_NAME, 1 << 1); // second scene
    APP_LOGI("RemoveUser user(%{public}d) start needLock %{public}d", userId, needLock);
    if (needLock) {
        std::lock_guard<std::mutex> lock(bundleUserMgrMutex_);
        return ProcessRemoveUser(userId);
    }
    return ProcessRemoveUser(userId);
}

ErrCode BundleUserMgrHostImpl::ProcessRemoveUser(int32_t userId)
{
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
        dataMgr->RemoveAppInstallDir(userId);
        dataMgr->DeleteFirstInstallBundleInfo(userId);
        return ERR_OK;
    }

    ClearBundleEvents();
    InnerUninstallBundle(userId, bundleInfos);
    RemoveArkProfile(userId);
    RemoveAsanLogDirectory(userId);
    dataMgr->RemoveUserId(userId);
    dataMgr->RemoveAppInstallDir(userId);
    dataMgr->DeleteFirstInstallBundleInfo(userId);
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
    std::string arkProfilePath = AOTHandler::BuildArkProfilePath(userId);
    APP_LOGI("DeleteArkProfile %{public}s when remove user", arkProfilePath.c_str());
    InstalldClient::GetInstance()->RemoveDir(arkProfilePath);
}

void BundleUserMgrHostImpl::RemoveAsanLogDirectory(int32_t userId)
{
    std::string asanLogDir = std::string(ServiceConstants::BUNDLE_ASAN_LOG_DIR) + ServiceConstants::PATH_SEPARATOR
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
        if (userReceiverImpl == nullptr) {
            APP_LOGE("userReceiverImpl is nullptr, -n %{public}s", info.name.c_str());
            g_installedHapNum++;
            continue;
        }
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
    std::vector<NotifyBundleEvents> bundleEvents;
    {
        std::lock_guard<std::mutex> lock(bundleEventMutex_);
        bundleEvents = bundleEvents_;
        bundleEvents_.clear();
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return;
    }

    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    for (size_t i = 0; i < bundleEvents.size(); ++i) {
        commonEventMgr->NotifyBundleStatus(bundleEvents[i], dataMgr);
        if ((i != 0) && (i % FACTOR == 0)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(INTERVAL));
        }
    }
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

bool BundleUserMgrHostImpl::InnerProcessSkipPreInstallBundles(
    const std::set<std::string> &uninstallList, bool needToSkipPreBundleInstall)
{
    if (uninstallList.empty() || !needToSkipPreBundleInstall) {
        return true;
    }
    APP_LOGI("process skip pre bundle install start");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    bool ret = true;
    for (const auto &name : uninstallList) {
        PreInstallBundleInfo preInfo;
        preInfo.SetBundleName(name);
        if (!dataMgr->GetPreInstallBundleInfo(name, preInfo)) {
            APP_LOGI("no pre bundleInfo %{public}s in db", name.c_str());
            continue;
        }
        if (!preInfo.GetBundlePaths().empty() && (preInfo.GetBundlePaths().front().find(PRELOAD_APP) == 0)) {
            preInfo.SetIsUninstalled(true);
            if (!dataMgr->SavePreInstallBundleInfo(name, preInfo)) {
                APP_LOGE("save pre bundle %{public}s failed", name.c_str());
                ret = false;
            }
        }
    }
    APP_LOGI("process skip pre bundle install end");
    return ret;
}

void BundleUserMgrHostImpl::UninstallBackupUninstallList(int32_t userId, bool needToSkipPreBundleInstall)
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
        if (userReceiverImpl == nullptr) {
            APP_LOGE("userReceiverImpl is nullptr, -n %{public}s", bundleName.c_str());
            g_installedHapNum++;
            continue;
        }
        userReceiverImpl->SetBundlePromise(bundlePromise);
        userReceiverImpl->SetTotalHapNum(totalHapNum);
        installer->Uninstall(bundleName, installParam, userReceiverImpl);
    }
    if (static_cast<int32_t>(g_installedHapNum) < totalHapNum) {
        bundlePromise->WaitForAllTasksExecute();
    }
    IPCSkeleton::SetCallingIdentity(identity);
    bmsExtensionDataMgr.ClearBackupUninstallFile(userId);
    (void)InnerProcessSkipPreInstallBundles(uninstallList, needToSkipPreBundleInstall);
}

void BundleUserMgrHostImpl::SavePreInstallException(const std::string &bundleName)
{
    auto preInstallExceptionMgr =
        DelayedSingleton<BundleMgrService>::GetInstance()->GetPreInstallExceptionMgr();
    if (preInstallExceptionMgr == nullptr) {
        APP_LOGE("preInstallExceptionMgr is nullptr, -n %{public}s save failed", bundleName.c_str());
        return;
    }

    preInstallExceptionMgr->SavePreInstallExceptionBundleName(bundleName);
}
}  // namespace AppExecFwk
}  // namespace OHOS
