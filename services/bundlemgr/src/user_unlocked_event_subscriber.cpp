/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "user_unlocked_event_subscriber.h"

#include <filesystem>
#include <sys/stat.h>

#include "account_helper.h"
#include "app_log_tag_wrapper.h"
#include "bundle_mgr_service.h"
#include "dual_mode_helper.h"
#include "inner_bundle_clone_common.h"
#include "pre_install_bundle_info.h"
#if defined (BUNDLE_FRAMEWORK_SANDBOX_APP) && defined (DLP_PERMISSION_ENABLE)
#include "dlp_permission_kit.h"
#endif
#include "installd_client.h"
#include "new_bundle_data_dir_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
static constexpr int16_t MODE_BASE = 07777;
constexpr const char* BUNDLE_BACKUP_HOME_PATH_EL1_NEW = "/data/app/el1/%/base/";
constexpr const char* BUNDLE_BACKUP_HOME_PATH_EL2_NEW = "/data/app/el2/%/base/";
constexpr const char* BUNDLE_BACKUP_INNER_DIR = "/.backup";
const std::vector<std::string> BUNDLE_DATA_DIR = {
    "/cache",
    "/files",
    "/temp",
    "/preferences",
    "/haps"
};
constexpr const char* OOBE_HWSTARTUPGUIDE_FINISHED_EVENT = "custom.event.OOBE.HWSTARTUPGUIDE.FINISHED";
constexpr const char* OOBE_OTA_PARAM = "ota";
static std::mutex TASK_MUTEX;
static std::atomic<uint32_t> CURRENT_TASK_NUM = 0;

template<typename Func, typename...Args>
inline void ReturnIfNewTask(Func func, uint32_t tempTask, Args&&... args)
{
    if (CURRENT_TASK_NUM != tempTask) {
        APP_LOGI("need stop current task, new first");
        return;
    }
    func(std::forward<Args>(args)...);
}

// dual-mode: effective (prefixed) name for dual-mode clone variants (appIndex 10000), matching
// install-time isolation. Resolved from the record's own appIndex, NOT by re-fetching the
// current-mode record from bundleInfos_: the same-name variant living there belongs to the other
// mode, so its clone flag would resolve the wrong variant's dir name.
// Regular clones (appIndex 1..N) always keep the original name — their dir layout
// (+clone-N+name) is mode-independent, so the dual-mode prefix belongs to the
// dual-mode clone variant (appIndex 10000) only.
std::string GetDirBundleName(const BundleInfo &bundleInfo)
{
    return bundleInfo.appIndex == ServiceConstants::DUAL_MODE_CLONE_APP_INDEX
        ? DualModeHelper::GetDualModeBundleName(bundleInfo.name)
        : bundleInfo.name;
}

bool IsCloneDirUidMatched(const std::string &bundleName,
    int32_t userId, const InnerBundleCloneInfo &cloneInfo)
{
    std::string cloneDirName = BundleCloneCommonHelper::GetCloneDataDir(
        bundleName, cloneInfo.appIndex);
    std::string cloneBaseDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR +
        ServiceConstants::BUNDLE_EL[1] + ServiceConstants::PATH_SEPARATOR +
        std::to_string(userId) + ServiceConstants::BASE + cloneDirName;
    bool isExist = false;
    if (InstalldClient::GetInstance()->IsExistDir(cloneBaseDir, isExist) != ERR_OK ||
        !isExist) {
        APP_LOGD("CloneDir check: bundle=%{public}s appIndex=%{public}d dir not exist",
            bundleName.c_str(), cloneInfo.appIndex);
        return false;
    }
    FileStat fileStat;
    if (InstalldClient::GetInstance()->GetFileStat(cloneBaseDir,
        BundleDirScene::GET_DATA_BASE_FILE_STAT, fileStat) != ERR_OK) {
        APP_LOGW("CloneDir check: bundle=%{public}s appIndex=%{public}d GetFileStat failed",
            bundleName.c_str(), cloneInfo.appIndex);
        return false;
    }
    if (fileStat.uid != cloneInfo.uid) {
        APP_LOGD("CloneDir check: bundle=%{public}s appIndex=%{public}d "
            "uid mismatch dir=%{public}d expected=%{public}d, need recreate",
            bundleName.c_str(), cloneInfo.appIndex, fileStat.uid, cloneInfo.uid);
        return false;
    }
    return true;
}

void CreateCloneDataDir(const std::string &bundleName,
    int32_t userId, const InnerBundleCloneInfo &cloneInfo, const InnerBundleInfo &info)
{
    APP_LOGD("CloneDir create: bundle=%{public}s appIndex=%{public}d",
        bundleName.c_str(), cloneInfo.appIndex);
    CreateDirParam param;
    param.bundleName = BundleCloneCommonHelper::GetCloneDataDir(
        bundleName, cloneInfo.appIndex);
    param.userId = userId;
    param.uid = cloneInfo.uid;
    param.gid = cloneInfo.uid;
    param.appIndex = cloneInfo.appIndex;
    param.apl = info.GetAppPrivilegeLevel();
    param.isPreInstallApp = info.IsPreInstallApp();
    param.debug = info.GetBaseApplicationInfo().appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG;
    param.hasDriverExtension = info.HasDriverExtension();
    param.createDirFlag = CreateDirFlag::CREATE_DIR_ALL;
    if (InstalldClient::GetInstance()->CreateBundleDataDir(param) != ERR_OK) {
        APP_LOGW("CloneDir create failed, bundle:%{public}s appIndex:%{public}d uid:%{public}d",
            bundleName.c_str(), cloneInfo.appIndex, cloneInfo.uid);
    } else {
        APP_LOGI("CloneDir create: bundle=%{public}s appIndex=%{public}d uid=%{public}d",
            bundleName.c_str(), cloneInfo.appIndex, cloneInfo.uid);
    }
}

void ProcessCloneDirsForBundle(const std::string &bundleName,
    int32_t userId, const InnerBundleInfo &info, const InnerBundleUserInfo &userInfo)
{
    APP_LOGD("CloneDir bundle: bundle=%{public}s %{public}zu clones",
        bundleName.c_str(), userInfo.cloneInfos.size());
    for (const auto &[idx, cloneInfo] : userInfo.cloneInfos) {
        if (cloneInfo.appIndex <= 0) {
            continue;
        }
        if (IsCloneDirUidMatched(bundleName, userId, cloneInfo)) {
            continue;
        }
        CreateCloneDataDir(bundleName, userId, cloneInfo, info);
    }
}

bool IsSandboxDirUidMatched(const std::string &dirName,
    int32_t userId, int32_t appIndex, int32_t expectedUid)
{
    std::string baseDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR +
        ServiceConstants::BUNDLE_EL[1] + ServiceConstants::PATH_SEPARATOR +
        std::to_string(userId) + ServiceConstants::BASE + dirName;
    bool isExist = false;
    if (InstalldClient::GetInstance()->IsExistDir(baseDir, isExist) != ERR_OK ||
        !isExist) {
        APP_LOGD("SandboxDir check: appIndex=%{public}d dir not exist",
            appIndex);
        return false;
    }
    FileStat fileStat;
    if (InstalldClient::GetInstance()->GetFileStat(baseDir,
        BundleDirScene::GET_DATA_BASE_FILE_STAT, fileStat) != ERR_OK) {
        APP_LOGW("SandboxDir check: appIndex=%{public}d GetFileStat failed",
            appIndex);
        return false;
    }
    if (fileStat.uid != expectedUid) {
        APP_LOGD("SandboxDir check: appIndex=%{public}d "
            "uid mismatch dir=%{public}d expected=%{public}d",
            appIndex, fileStat.uid, expectedUid);
        return false;
    }
    return true;
}

void CreateSandboxDataDir(const std::string &dirName,
    int32_t userId, int32_t appIndex, int32_t uid, const InnerBundleInfo &info)
{
    APP_LOGD("SandboxDir create: appIndex=%{public}d", appIndex);
    CreateDirParam param;
    param.bundleName = dirName;
    param.userId = userId;
    param.uid = uid;
    param.gid = uid;
    param.appIndex = appIndex;
    param.apl = info.GetAppPrivilegeLevel();
    param.isPreInstallApp = info.IsPreInstallApp();
    param.debug = info.GetBaseApplicationInfo().appProvisionType ==
        Constants::APP_PROVISION_TYPE_DEBUG;
    param.hasDriverExtension = info.HasDriverExtension();
    param.createDirFlag = CreateDirFlag::CREATE_DIR_ALL;
    if (InstalldClient::GetInstance()->CreateBundleDataDir(param) != ERR_OK) {
        APP_LOGW("SandboxDir create failed, appIndex:%{public}d uid:%{public}d",
            appIndex, uid);
    } else {
        APP_LOGI("SandboxDir create: appIndex=%{public}d uid=%{public}d",
            appIndex, uid);
    }
}

void ProcessCliSandboxDirsForBundle(const std::string &bundleName,
    int32_t userId, const InnerBundleInfo &info, const InnerBundleUserInfo &userInfo)
{
    APP_LOGD("SandboxDir cli: bundle=%{public}s %{public}zu cli sandboxes",
        bundleName.c_str(), userInfo.sandboxInfos.size());
    for (const auto &[key, sandboxInfo] : userInfo.sandboxInfos) {
        std::string dirName = BundleCloneCommonHelper::GetCloneDataDir(
            bundleName, sandboxInfo.appIndex);
        if (IsSandboxDirUidMatched(dirName, userId,
            sandboxInfo.appIndex, sandboxInfo.uid)) {
            continue;
        }
        CreateSandboxDataDir(dirName, userId,
            sandboxInfo.appIndex, sandboxInfo.uid, info);
    }
}

void ProcessDlpSandboxEntry(const std::string &key,
    const InnerBundleInfo &sandboxInfo, int32_t userId)
{
    std::string bn = sandboxInfo.GetBundleName();
    int32_t appIndex = 0;
    auto pos = key.find(Constants::FILE_UNDERLINE);
    if (pos != std::string::npos) {
        if (!OHOS::StrToInt(key.substr(0, pos), appIndex)) {
            APP_LOGW("DlpSandbox: key=%{public}s appIndex parse failed, skip", key.c_str());
            return;
        }
    }
    std::string dirName = std::to_string(appIndex) +
        Constants::FILE_UNDERLINE + bn;
    InnerBundleUserInfo userInfo;
    if (!sandboxInfo.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGW("DlpSandbox: bundle=%{public}s userId=%{public}d appIndex=%{public}d "
            "userInfo not found", bn.c_str(), userId, appIndex);
        return;
    }
    if (IsSandboxDirUidMatched(dirName, userId, appIndex, userInfo.uid)) {
        return;
    }
    CreateSandboxDataDir(dirName, userId, appIndex, userInfo.uid, sandboxInfo);
}

void ProcessDlpSandboxDirs(const std::shared_ptr<BundleDataMgr> &dataMgr, int32_t userId)
{
    auto sandboxHelper = dataMgr->GetSandboxAppHelper();
    if (sandboxHelper == nullptr) {
        APP_LOGD("SandboxDir dlp: sandbox helper null, skip");
        return;
    }
    auto sandboxMap = sandboxHelper->GetSandboxAppInfoMap();
    APP_LOGD("SandboxDir dlp: %{public}zu dlp sandboxes", sandboxMap.size());
    for (const auto &[key, sandboxInfo] : sandboxMap) {
        ProcessDlpSandboxEntry(key, sandboxInfo, userId);
    }
}
}
UserUnlockedEventSubscriber::UserUnlockedEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo) : EventFwk::CommonEventSubscriber(subscribeInfo)
{}

UserUnlockedEventSubscriber::~UserUnlockedEventSubscriber()
{}

void UserUnlockedEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    if (action == OOBE_HWSTARTUPGUIDE_FINISHED_EVENT) {
        if (!data.GetWant().GetBoolParam(OOBE_OTA_PARAM, false)) {
            APP_LOGI_NOFUNC("OOBE HWSTARTUPGUIDE.FINISHED ignored, ota is not true");
            return;
        }
        // OTA new-preload white list: clear otaNewInstallUsers for current foreground user.
        int32_t foregroundUserId = AccountHelper::GetCurrentActiveUserId();
        APP_LOGI_NOFUNC("OOBE HWSTARTUPGUIDE.FINISHED (ota=true), foregroundUserId:%{public}d", foregroundUserId);
        if (foregroundUserId == Constants::INVALID_USERID) {
            return;
        }
        auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr == nullptr) {
            return;
        }
        std::vector<PreInstallBundleInfo> preInstallBundleInfos = dataMgr->GetAllPreInstallBundleInfos();
        for (auto &bundleInfo : preInstallBundleInfos) {
            if (!bundleInfo.HasOtaNewInstallUser(foregroundUserId)) {
                continue;
            }
            bundleInfo.DeleteOtaNewInstallUser(foregroundUserId);
            // Delete ota new install user for default user and u1 user
            bundleInfo.DeleteOtaNewInstallUser(Constants::DEFAULT_USERID);
            bundleInfo.DeleteOtaNewInstallUser(Constants::U1);
            (void)dataMgr->SavePreInstallBundleInfo(bundleInfo.GetBundleName(), bundleInfo);
        }
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) {
        int32_t userId = data.GetCode();
        APP_LOGI_NOFUNC("UserUnlockedEventSubscriber -u %{public}d unlocked", userId);
        std::lock_guard<std::mutex> lock(mutex_);
        if ((userId_ != userId)) {
            userId_ = userId;
            std::thread updateDataDirThread(UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel, userId);
            updateDataDirThread.detach();
            std::thread(UpdateAppDataMgr::DeleteUninstallTmpDirs, std::set<int32_t>{userId}).detach();
            auto preloadUninstallMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetOobePreloadUninstallMgr();
            if (preloadUninstallMgr != nullptr) {
                preloadUninstallMgr->RecoverPendingBundles(userId);
            }
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
            DelayedSingleton<AppControlManager>::GetInstance()->SetAppInstallControlStatus();
#endif
        }
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        int32_t userId = data.GetCode();
        APP_LOGI_NOFUNC("UserUnlockedEventSubscriber -u %{public}d switched", userId);
        std::lock_guard<std::mutex> lock(mutex_);
        if (AccountHelper::IsOsAccountVerified(userId) && (userId_ != userId)) {
            APP_LOGI_NOFUNC("UserUnlockedEventSubscriber -u %{public}d unlocked", userId);
            userId_ = userId;
            std::thread updateDataDirThread(UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel, userId);
            updateDataDirThread.detach();
            std::thread(UpdateAppDataMgr::DeleteUninstallTmpDirs, std::set<int32_t>{userId}).detach();
        }
#if defined (BUNDLE_FRAMEWORK_SANDBOX_APP) && defined (DLP_PERMISSION_ENABLE)
        APP_LOGI("RemoveUnreservedSandbox call ClearUnreservedSandbox");
        Security::DlpPermission::DlpPermissionKit::ClearUnreservedSandbox();
#endif
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
        DelayedSingleton<AppControlManager>::GetInstance()->SetAppInstallControlStatus();
#endif
    }
}

void UpdateAppDataMgr::CheckPathAttribute(const std::string &path, const BundleInfo &bundleInfo, bool &isExist)
{
    if (!isExist) {
        return;
    }
    FileStat fileStat;
    if (InstalldClient::GetInstance()->GetFileStat(path, BundleDirScene::GET_DATA_BASE_FILE_STAT, fileStat) != ERR_OK) {
        APP_LOGE("GetFileStat path(%{public}s) failed", path.c_str());
        return;
    }
    if (fileStat.uid != bundleInfo.uid) {
        APP_LOGW("path: %{public}s uid is not same, fileStat.uid:%{public}d, bundleInfo.uid:%{public}d",
            path.c_str(), static_cast<int32_t>(fileStat.uid), bundleInfo.uid);
        isExist = false;
    }
    uint32_t fileMode = static_cast<uint32_t>(fileStat.mode);
    if ((fileMode & MODE_BASE) != (S_IRWXU | S_IRWXG | S_ISGID)) {
        APP_LOGD("path: %{public}s mode is not same, fileStat.mode:%{public}d, mode:%{public}d",
            path.c_str(), static_cast<int32_t>(fileStat.mode), static_cast<int32_t>((S_IRWXU | S_IRWXG | S_ISGID)));
    }
}

bool UpdateAppDataMgr::CreateBundleDataDir(
    const BundleInfo &bundleInfo, int32_t userId, const std::string &elDir, bool toTempBundle)
{
    std::string dirBundleName = GetDirBundleName(bundleInfo);
    std::string baseBundleDataDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + elDir +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::DATABASE + dirBundleName;
    bool isExist = false;
    if (InstalldClient::GetInstance()->IsExistDir(baseBundleDataDir, isExist) != ERR_OK) {
        APP_LOGE("path: %{public}s IsExistDir failed", baseBundleDataDir.c_str());
        return false;
    }
    CheckPathAttribute(baseBundleDataDir, bundleInfo, isExist);
    // also check el2 base dir (primary data dirs cache/files/...): recover when missing even if database dir exists.
    if (isExist && elDir == ServiceConstants::BUNDLE_EL[1]) {
        std::string el2BaseBundleDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
            ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::BASE + dirBundleName;
        bool isEl2BaseExist = false;
        if (InstalldClient::GetInstance()->IsExistDir(el2BaseBundleDir, isEl2BaseExist) != ERR_OK) {
            APP_LOGW_NOFUNC("path: %{public}s IsExistDir failed", el2BaseBundleDir.c_str());
        } else if (!isEl2BaseExist) {
            isExist = false;
        }
    }
    if (!isExist) {
        APP_LOGI_NOFUNC("path: %{public}s need CreateBundleDataDir", baseBundleDataDir.c_str());
        EventReport::SendTriggerFallbackEvent(HighRiskOperationType::USER_UNLOCK_DATA_DIR_RECOVERY,
            bundleInfo.name, userId, std::vector<std::string>{baseBundleDataDir});
        CreateDirParam createDirParam;
        createDirParam.userId = userId;
        createDirParam.bundleName = dirBundleName;
        createDirParam.uid = bundleInfo.uid;
        createDirParam.gid = bundleInfo.gid;
        createDirParam.apl = bundleInfo.applicationInfo.appPrivilegeLevel;
        createDirParam.isPreInstallApp = bundleInfo.isPreInstallApp;
        createDirParam.debug = bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG;
        if (elDir != ServiceConstants::BUNDLE_EL[0]) {
            createDirParam.createDirFlag = CreateDirFlag::CREATE_DIR_UNLOCKED;
        }
        if (elDir == ServiceConstants::DIR_EL5) {
            return CreateEl5Dir(createDirParam, toTempBundle);
        }
        ProcessExtensionDir(bundleInfo, createDirParam.extensionDirs);
        ProcessPrintSericeDir(bundleInfo, createDirParam.hasDriverExtension);
        if (InstalldClient::GetInstance()->CreateBundleDataDir(createDirParam) != ERR_OK) {
            APP_LOGW("failed to CreateBundleDataDir");
        }
    }
    if (elDir == ServiceConstants::BUNDLE_EL[1]) {
        CreateDataGroupDir(bundleInfo, userId, toTempBundle);
    }
    return true;
}

bool UpdateAppDataMgr::CreateEl5Dir(const CreateDirParam &createDirParam, bool toTempBundle)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("CreateEl5Dir failed for DataMgr is nullptr");
        return false;
    }
    std::vector<CreateDirParam> params;
    params.emplace_back(createDirParam);
    InnerBundleInfo info;
    // dual-mode: createDirParam.bundleName may be the effective (prefixed) name of a
    // dual-mode clone variant, while both maps are keyed by the original bundle name —
    // resolve records by the original name and keep the prefixed name for dir creation only.
    std::string fetchName = createDirParam.bundleName;
    std::string originalName;
    int32_t parsedAppIndex = 0;
    if (BundleCloneCommonHelper::ParseCloneDataDir(fetchName, originalName, parsedAppIndex)) {
        fetchName = originalName;
    }
    // dual-mode: the clone/sandbox extras must come from the same variant being processed —
    // toTempBundle selects tempBundleInfos_ (the other-mode variant's own record).
    bool fetched = toTempBundle ? dataMgr->FetchTempBundleInfo(fetchName, info)
        : dataMgr->FetchInnerBundleInfo(fetchName, info);
    if (fetched) {
        InnerBundleUserInfo userInfo;
        if (info.GetInnerBundleUserInfo(createDirParam.userId, userInfo)) {
            // dual-mode: clone/sandbox extras use the ORIGINAL name as the base — the
            // install-time layout (+clone-N+name, see BundleCloneInstaller::CreateEl5Dir /
            // BundleCliSandboxInstaller::CreateEl5Dir) never stacks the dual-mode prefix,
            // and the cleanup (RemoveEl5Dir) walks that layout as well.
            for (const auto &cloneInfo : userInfo.cloneInfos) {
                CreateDirParam cloneParam = createDirParam;
                cloneParam.bundleName = fetchName;
                cloneParam.uid = cloneInfo.second.uid;
                cloneParam.gid = cloneInfo.second.uid;
                cloneParam.appIndex = cloneInfo.second.appIndex;
                params.emplace_back(cloneParam);
            }
            for (const auto &cliSandboxInfo : userInfo.sandboxInfos) {
                CreateDirParam cliParam = createDirParam;
                cliParam.bundleName = fetchName;
                cliParam.uid = cliSandboxInfo.second.uid;
                cliParam.gid = cliSandboxInfo.second.uid;
                cliParam.appIndex = cliSandboxInfo.second.appIndex;
                params.emplace_back(cliParam);
            }
        }
    }
    // dual-mode: pass toTempBundle so the el5 dir policy is also resolved from the same
    // variant's record, and resolve the el5 group dirs by the original name (map key).
    dataMgr->CreateEl5Dir(params, true, toTempBundle);
    dataMgr->CreateAppEl5GroupDir(fetchName, createDirParam.userId, toTempBundle);
    return true;
}

void UpdateAppDataMgr::DeleteUninstallTmpDirs(const std::set<int32_t>& userIds)
{
    std::vector<std::string> dirs;
    for (const int32_t &userId : userIds) {
        std::vector<std::string> tmpDirs = GetBundleDataDirs(userId);
        dirs.insert(dirs.end(), tmpDirs.begin(), tmpDirs.end());
    }
    dirs.emplace_back(Constants::BUNDLE_CODE_DIR);
    dirs.emplace_back(ServiceConstants::NEW_CLOUD_SHADER_PATH);
    ErrCode ret = InstalldClient::GetInstance()->DeleteUninstallTmpDirs(dirs);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "delete tmp dirs failed:%{public}d", ret);
    }
}

std::vector<std::string> UpdateAppDataMgr::GetBundleDataDirs(const int32_t userId)
{
    std::vector<std::string> dirs;
    std::vector<std::string> dataVector = { "base", "database" };
    for (const std::string &el : ServiceConstants::BUNDLE_EL) {
        std::filesystem::path userPath =
            std::filesystem::path(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR) / el / std::to_string(userId);
        for (const std::string &data : dataVector) {
            std::filesystem::path dataPath = userPath / data;
            dirs.emplace_back(dataPath.string());
        }
    }
    // residual =uninstall_tmp_ dirs renamed from async-uninstalled hmdfs account data dirs
    std::string hmdfsAccountDataDir = ServiceConstants::HMDFS_ACCOUNT_DATA_PATH;
    hmdfsAccountDataDir = hmdfsAccountDataDir.replace(
        hmdfsAccountDataDir.find("%"), 1, std::to_string(userId));
    dirs.emplace_back(hmdfsAccountDataDir);
    return dirs;
}

void UpdateAppDataMgr::CreateDataGroupDir(const BundleInfo &bundleInfo, int32_t userId, bool toTempBundle)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("CreateDataGroupDir failed for DataMgr is nullptr");
        return;
    }
    if (!dataMgr->CreateAppGroupDir(bundleInfo.name, userId, toTempBundle)) {
        APP_LOGE("CreateAppGroupDir %{public}s in %{public}d failed", bundleInfo.name.c_str(), userId);
        return;
    }
}

void UpdateAppDataMgr::UpdateTempModeAppDataDirs(int32_t userId, uint32_t taskNum)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("UpdateTempModeAppDataDirs failed for DataMgr is nullptr");
        return;
    }
    // tempBundleInfos_ is only populated on dual-mode devices; empty means nothing to rebuild.
    std::vector<BundleInfo> tempBundleInfos;
    (void)dataMgr->GetTempBundleInfos(BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO |
        BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION_NO_DETAILED, tempBundleInfos, userId);
    if (tempBundleInfos.empty()) {
        return;
    }
    // Same dir set as the current-mode passes in UpdateAppDataDirSelinuxLabel; the internal
    // toTempBundle=true passes route the per-variant record fetches (data groups, el5
    // clone/sandbox extras, U1 flag) to tempBundleInfos_ — the other-mode variant's own record.
    APP_LOGI("UpdateTempModeAppDataDirs userId:%{public}d start", userId);
    ReturnIfNewTask(ProcessUpdateAppDataDirInternal, taskNum, userId, tempBundleInfos,
        ServiceConstants::BUNDLE_EL[1], true);
#ifdef CHECK_ELDIR_ENABLED
    ReturnIfNewTask(ProcessUpdateAppDataDirInternal, taskNum, userId, tempBundleInfos,
        ServiceConstants::DIR_EL3, true);
    ReturnIfNewTask(ProcessUpdateAppDataDirInternal, taskNum, userId, tempBundleInfos,
        ServiceConstants::DIR_EL4, true);
#endif
    ReturnIfNewTask(ProcessUpdateAppDataDirInternal, taskNum, userId, tempBundleInfos,
        ServiceConstants::DIR_EL5, true);
    // dual-mode: rebuild the other-mode variants' regular clone data dirs as well — the
    // current-mode clone pass only walks bundleInfos_ records.
    ReturnIfNewTask(ProcessUpdateCloneDataDir, taskNum, userId, dataMgr, true);
    ReturnIfNewTask(ProcessUpdateAppLogDirInternal, taskNum, tempBundleInfos, userId, true);
    ReturnIfNewTask(ProcessFileManagerDir, taskNum, tempBundleInfos, userId);
    ReturnIfNewTask(ProcessNewBackupDir, taskNum, tempBundleInfos, userId);
    ReturnIfNewTask(CreateShareFilesSubDataDirs, taskNum, tempBundleInfos, userId);
    APP_LOGI("UpdateTempModeAppDataDirs userId:%{public}d end", userId);
}

void UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel(int32_t userId)
{
    uint32_t tempTaskNum = CURRENT_TASK_NUM.fetch_add(1) + 1;
    std::lock_guard<std::mutex> guard(TASK_MUTEX);
    APP_LOGI("UpdateAppDataDirSelinuxLabel hold task_mutex_");
    if (tempTaskNum != CURRENT_TASK_NUM) {
        APP_LOGI("need stop current task, new first, -u %{public}d", userId);
        return;
    }
    APP_LOGI("UpdateAppDataDirSelinuxLabel userId:%{public}d start", userId);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("UpdateAppDataDirSelinuxLabel DataMgr is nullptr");
        return;
    }
    std::vector<BundleInfo> bundleInfos;
    if (!dataMgr->GetBundleInfos(BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO |
        BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION_NO_DETAILED, bundleInfos, userId)) {
        APP_LOGE("UpdateAppDataDirSelinuxLabel GetAllBundleInfos failed");
        return;
    }
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    if (newBundleDirMgr != nullptr) {
        std::set<std::string> otaNewInstallBundleNames = newBundleDirMgr->GetAllNewBundleDataDirBundleName();
        std::stable_partition(bundleInfos.begin(), bundleInfos.end(),
            [&otaNewInstallBundleNames](const BundleInfo &info) {
                return otaNewInstallBundleNames.find(info.name) != otaNewInstallBundleNames.end();
            });
    }
    ReturnIfNewTask(ProcessUpdateAppDataDir, tempTaskNum, userId, bundleInfos, ServiceConstants::BUNDLE_EL[1]);
#ifdef CHECK_ELDIR_ENABLED
    ReturnIfNewTask(ProcessUpdateAppDataDir, tempTaskNum, userId, bundleInfos, ServiceConstants::DIR_EL3);
    ReturnIfNewTask(ProcessUpdateAppDataDir, tempTaskNum, userId, bundleInfos, ServiceConstants::DIR_EL4);
#endif
    ReturnIfNewTask(ProcessUpdateAppDataDir, tempTaskNum, userId, bundleInfos, ServiceConstants::DIR_EL5);
    // Default args do not apply through the ReturnIfNewTask forwarding; pass false explicitly.
    ReturnIfNewTask(ProcessUpdateCloneDataDir, tempTaskNum, userId, dataMgr, false);
    ReturnIfNewTask(ProcessUpdateAppLogDir, tempTaskNum, bundleInfos, userId);
    ReturnIfNewTask(ProcessFileManagerDir, tempTaskNum, bundleInfos, userId);
    ReturnIfNewTask(ProcessNewBackupDir, tempTaskNum, bundleInfos, userId);
    ReturnIfNewTask(CreateShareFilesSubDataDirs, tempTaskNum, bundleInfos, userId);
    // dual-mode: rebuild the other-mode (hidden) variants' dirs in one dedicated pass.
    if (DualModeHelper::IsDualModeDevice()) {
        UpdateTempModeAppDataDirs(userId, tempTaskNum);
    }
    if (newBundleDirMgr != nullptr) {
        (void)newBundleDirMgr->DeleteUserId(userId);
    }
    APP_LOGI("UpdateAppDataDirSelinuxLabel userId:%{public}d end", userId);
}

void UpdateAppDataMgr::ProcessUpdateAppDataDir(
    int32_t userId, const std::vector<BundleInfo> &bundleInfos, const std::string &elDir)
{
    ProcessUpdateAppDataDirInternal(userId, bundleInfos, elDir);
}

void UpdateAppDataMgr::ProcessUpdateAppDataDirInternal(
    int32_t userId, const std::vector<BundleInfo> &bundleInfos, const std::string &elDir, bool toTempBundle)
{
    std::string baseBundleDataDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + elDir +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId);
    for (const auto &bundleInfo : bundleInfos) {
        // dual-mode: skip regular clones (1..5) but keep dual-mode clones (10000) for dir recovery.
        if (bundleInfo.appIndex > 0 &&
            bundleInfo.appIndex != ServiceConstants::DUAL_MODE_CLONE_APP_INDEX) {
            APP_LOGI("bundleName:%{public}s appIndex:%{public}d clone app no need to change",
                bundleInfo.name.c_str(), bundleInfo.appIndex);
            continue;
        }
        if (elDir == ServiceConstants::DIR_EL5) {
            std::vector<std::string> reqPermissions = bundleInfo.reqPermissions;
            auto it = std::find_if(reqPermissions.begin(), reqPermissions.end(), [](const std::string &permission) {
                return permission == ServiceConstants::PERMISSION_PROTECT_SCREEN_LOCK_DATA;
            });
            if (it == reqPermissions.end()) {
                continue;
            }
        }
        if ((userId != Constants::DEFAULT_USERID && bundleInfo.singleton) ||
            (userId != Constants::U1 && CheckU1EnableProcess(bundleInfo, toTempBundle))) {
            continue;
        }
        if (!CreateBundleDataDir(bundleInfo, userId, elDir, toTempBundle)) {
            continue;
        }
        // dual-mode: path uses effective name; SetDirApl label (2nd arg) stays original bundleName.
        std::string dirBundleName = GetDirBundleName(bundleInfo);
        std::string baseDir = baseBundleDataDir + ServiceConstants::BASE + dirBundleName;
        if (InstalldClient::GetInstance()->SetDirApl(baseDir, bundleInfo.name,
            bundleInfo.applicationInfo.appPrivilegeLevel, bundleInfo.isPreInstallApp,
            bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG,
            bundleInfo.uid) != ERR_OK) {
            APP_LOGW_NOFUNC("failed to SetDirApl baseDir dir");
            continue;
        }
        std::string baseDataDir = baseBundleDataDir + ServiceConstants::DATABASE + dirBundleName;
        if (InstalldClient::GetInstance()->SetDirApl(baseDataDir, bundleInfo.name,
            bundleInfo.applicationInfo.appPrivilegeLevel, bundleInfo.isPreInstallApp,
            bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG,
            bundleInfo.uid) != ERR_OK) {
            APP_LOGW_NOFUNC("failed to SetDirApl baseDataDir dir");
        }
    }
}

void UpdateAppDataMgr::ProcessUpdateCloneDataDir(int32_t userId,
    const std::shared_ptr<BundleDataMgr> &dataMgr, bool toTempBundle)
{
    bool migrateDone = false;
    BMSEventHandler::CheckOtaFlag(OTAFlag::MIGRATE_UID_TO_ATM, migrateDone);
    if (migrateDone && dataMgr != nullptr) {
        APP_LOGI("ProcessUpdateCloneDataDir userId=%{public}d toTempBundle=%{public}d start",
            userId, toTempBundle);
        ProcessCloneBundleDirs(userId, dataMgr, toTempBundle);
        APP_LOGI("ProcessUpdateCloneDataDir userId=%{public}d toTempBundle=%{public}d done",
            userId, toTempBundle);
    } else {
        APP_LOGD("ProcessUpdateCloneDataDir skip: migrateDone=%{public}d dataMgr=%{public}s",
            static_cast<int32_t>(migrateDone), dataMgr != nullptr ? "ok" : "null");
    }
}

void UpdateAppDataMgr::ProcessCloneBundleDirs(int32_t userId,
    const std::shared_ptr<BundleDataMgr> &dataMgr, bool toTempBundle)
{
    // dual-mode: toTempBundle walks the other-mode (hidden) variants recorded in
    // tempBundleInfos_, so their regular clones' data dirs are rebuilt as well.
    auto bundleNames = toTempBundle ? dataMgr->GetAllTempBundleName() : dataMgr->GetAllBundleName();
    APP_LOGI("ProcessCloneBundleDirs userId=%{public}d %{public}zu bundles",
        userId, bundleNames.size());
    for (const auto &bundleName : bundleNames) {
        InnerBundleInfo info;
        bool fetched = toTempBundle ? dataMgr->FetchTempBundleInfo(bundleName, info)
            : dataMgr->FetchInnerBundleInfo(bundleName, info);
        if (!fetched) {
            continue;
        }
        InnerBundleUserInfo userInfo;
        if (info.GetInnerBundleUserInfo(userId, userInfo)) {
            ProcessCloneDirsForBundle(bundleName, userId, info, userInfo);
            ProcessCliSandboxDirsForBundle(bundleName, userId, info, userInfo);
        }
    }
    // DLP sandbox apps are runtime records shared by both modes — only the current-mode
    // pass needs to rebuild them; the other-mode pass would just repeat the same
    // idempotent scan.
    if (!toTempBundle) {
        ProcessDlpSandboxDirs(dataMgr, userId);
    }
}

void UpdateAppDataMgr::ProcessExtensionDir(const BundleInfo &bundleInfo, std::vector<std::string> &dirs)
{
    for (const ExtensionAbilityInfo &info : bundleInfo.extensionInfos) {
        if (!info.needCreateSandbox) {
            continue;
        }
        std::string extensionDir = ServiceConstants::EXTENSION_DIR + info.moduleName +
            ServiceConstants::FILE_SEPARATOR_LINE + info.name +
            ServiceConstants::FILE_SEPARATOR_PLUS + info.bundleName;
        dirs.emplace_back(extensionDir);
    }
}

void UpdateAppDataMgr::ProcessPrintSericeDir(const BundleInfo &bundleInfo, bool &hasDriverExtension)
{
    for (const auto &extInfo : bundleInfo.extensionInfos) {
        if (extInfo.type == ExtensionAbilityType::DRIVER) {
            hasDriverExtension = true;
            break;
        }
    }
}

void UpdateAppDataMgr::ProcessUpdateAppLogDir(const std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    ProcessUpdateAppLogDirInternal(bundleInfos, userId);
}

void UpdateAppDataMgr::ProcessUpdateAppLogDirInternal(
    const std::vector<BundleInfo> &bundleInfos, int32_t userId, bool toTempBundle)
{
    for (const auto &bundleInfo : bundleInfos) {
        if (userId != Constants::DEFAULT_USERID && bundleInfo.singleton) {
            continue;
        }
        if (userId != Constants::U1 && CheckU1EnableProcess(bundleInfo, toTempBundle)) {
            continue;
        }
        if (!CreateBundleLogDir(bundleInfo, userId)) {
            APP_LOGD("log dir create failed or already exists");
        }
    }
}

void UpdateAppDataMgr::ProcessNewBackupDir(const std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    APP_LOGI_NOFUNC("process new back up dir, start");
    for (const auto &bundleInfo : bundleInfos) {
        if (bundleInfo.appIndex > 0) {
            APP_LOGI("bundleName:%{public}s appIndex %{public}d clone app no need to create",
                bundleInfo.name.c_str(), bundleInfo.appIndex);
            continue;
        }
        if (bundleInfo.singleton) {
            CreateNewBackupDir(bundleInfo, Constants::DEFAULT_USERID);
            continue;
        }
        if (userId != Constants::DEFAULT_USERID) {
            CreateNewBackupDir(bundleInfo, userId);
        }
    }
    APP_LOGI_NOFUNC("process new back up dir, end");
}

void UpdateAppDataMgr::CreateNewBackupDir(const BundleInfo &bundleInfo, int32_t userId)
{
    // dual-mode: clone apps' backup dir uses the effective (prefixed) name.
    std::string dirBundleName = GetDirBundleName(bundleInfo);
    std::string parentEl1Dir = BUNDLE_BACKUP_HOME_PATH_EL1_NEW;
    parentEl1Dir = parentEl1Dir.replace(parentEl1Dir.find("%"), 1, std::to_string(userId)) + dirBundleName;
    std::string parentEl2Dir = BUNDLE_BACKUP_HOME_PATH_EL2_NEW;
    parentEl2Dir = parentEl2Dir.replace(parentEl2Dir.find("%"), 1, std::to_string(userId)) + dirBundleName;
    bool isEl1Existed = false;
    auto result = InstalldClient::GetInstance()->IsExistDir(parentEl1Dir, isEl1Existed);
    if (result == ERR_OK && !isEl1Existed) {
        APP_LOGE("parent dir(%{public}s) missing: backup", parentEl1Dir.c_str());
        return;
    }
    bool isEl2Existed = false;
    result = InstalldClient::GetInstance()->IsExistDir(parentEl2Dir, isEl2Existed);
    if (result == ERR_OK && !isEl2Existed) {
        APP_LOGE("parent dir(%{public}s) missing: backup", parentEl2Dir.c_str());
        return;
    }
    std::string backupDirEl1 = parentEl1Dir + BUNDLE_BACKUP_INNER_DIR;
    std::string backupDirEl2 = parentEl2Dir + BUNDLE_BACKUP_INNER_DIR;
    std::vector<std::string> backupDirList;
    backupDirList.emplace_back(backupDirEl1);
    backupDirList.emplace_back(backupDirEl2);

    for (const std::string &dir : backupDirList) {
        bool isDirExisted = false;
        auto result = InstalldClient::GetInstance()->IsExistDir(dir, isDirExisted);
        if (result != ERR_OK || isDirExisted) {
            continue;
        }
        APP_LOGI("bundle %{public}s not exist backup dir", bundleInfo.name.c_str());
        CreateDirParam createDirParam;
        createDirParam.bundleName = dirBundleName;
        createDirParam.bundleDirScene = BundleDirScene::BACK_UP_DIR;
        result = InstalldClient::GetInstance()->Mkdir(dir, S_IRWXU | S_IRWXG | S_ISGID,
            bundleInfo.uid, ServiceConstants::BACKU_HOME_GID, createDirParam);
        if (result != ERR_OK) {
            APP_LOGW("bundle %{public}s create backup dir for user %{public}d failed",
                bundleInfo.name.c_str(), userId);
        }
    }
}

bool UpdateAppDataMgr::CreateBundleLogDir(const BundleInfo &bundleInfo, int32_t userId)
{
    std::string parentDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::LOG;
    if (!BundleUtil::IsExistDir(parentDir)) {
        APP_LOGE("parent dir(%{public}s) missing: log", parentDir.c_str());
        return false;
    }
    // dual-mode: clone apps' log dir uses the effective (prefixed) name.
    std::string dirBundleName = GetDirBundleName(bundleInfo);
    std::string bundleLogDir = parentDir + dirBundleName;
    bool isExist = false;
    if (InstalldClient::GetInstance()->IsExistDir(bundleLogDir, isExist) != ERR_OK) {
        APP_LOGE("path: %{public}s IsExistDir failed", bundleLogDir.c_str());
        return false;
    }
    if (isExist) {
        APP_LOGD("path: %{public}s is exist", bundleLogDir.c_str());
        return false;
    }
    CreateDirParam createDirParam;
    createDirParam.bundleName = dirBundleName;
    createDirParam.bundleDirScene = BundleDirScene::APP_EL2_LOG_DIR;
    if (InstalldClient::GetInstance()->Mkdir(bundleLogDir, S_IRWXU | S_IRWXG | S_ISGID, bundleInfo.uid,
        ServiceConstants::LOG_DIR_GID, createDirParam) != ERR_OK) {
        APP_LOGE("CreateBundleLogDir failed");
        return false;
    }
    return true;
}

void UpdateAppDataMgr::ProcessFileManagerDir(const std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    for (const auto &bundleInfo : bundleInfos) {
        if (userId != Constants::DEFAULT_USERID && bundleInfo.singleton) {
            continue;
        }
        CreateBundleCloudDir(bundleInfo, userId);
    }
}

bool UpdateAppDataMgr::CreateBundleCloudDir(const BundleInfo &bundleInfo, int32_t userId)
{
    std::string parentDir = "/data/service/el2/%/hmdfs/cloud/data/";
    parentDir = parentDir.replace(parentDir.find("%"), 1, std::to_string(userId));
    if (!BundleUtil::IsExistDir(parentDir)) {
        APP_LOGE("parent dir(%{public}s) missing: cloud errno:%{public}d", parentDir.c_str(), errno);
        return false;
    }
    // dual-mode: clone apps' cloud dir uses the effective (prefixed) name.
    std::string dirBundleName = GetDirBundleName(bundleInfo);
    std::string bundleCloudDir = parentDir + dirBundleName;
    bool isExist = false;
    if (InstalldClient::GetInstance()->IsExistDir(bundleCloudDir, isExist) != ERR_OK) {
        APP_LOGE("path: %{private}s IsExistDir failed", bundleCloudDir.c_str());
        return false;
    }
    if (isExist) {
        APP_LOGD("path: %{private}s is exist", bundleCloudDir.c_str());
        return false;
    }
    CreateDirParam createDirParam;
    createDirParam.bundleName = dirBundleName;
    createDirParam.bundleDirScene = BundleDirScene::SERVICE_HMDFS_CLOUD_DATA_DIR;
    if (InstalldClient::GetInstance()->Mkdir(bundleCloudDir, S_IRWXU | S_IRWXG | S_ISGID,
        bundleInfo.uid, ServiceConstants::DFS_GID, createDirParam) != ERR_OK) {
        APP_LOGW("CreateCloudDir failed for bundle %{private}s errno:%{public}d",
            bundleInfo.name.c_str(), errno);
    }
    return true;
}

void UpdateAppDataMgr::CreateShareFilesSubDataDirs(const std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    APP_LOGD("begin for userid: [%{public}d]", userId);
    std::string parentDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::SHAREFILES;
    for (const auto &bundleInfo : bundleInfos) {
        // dual-mode: path uses effective name; SetDirApl/RemoveDir label (bundleInfo.name) stays original.
        std::string dirBundleName = GetDirBundleName(bundleInfo);
        std::string sharefilesDataDir = parentDir + dirBundleName;
        if (userId != Constants::DEFAULT_USERID && bundleInfo.singleton) {
            APP_LOGD("Bundle: %{public}s in DEFAULT_USERID, do not create sharefiles for other user",
                bundleInfo.name.c_str());
            InstalldClient::GetInstance()->RemoveDir(
                sharefilesDataDir, BundleDirScene::REMOVE_SHARE_FILE_DIR, bundleInfo.name);
            continue;
        }

        bool isExist = false;
        if (InstalldClient::GetInstance()->IsExistDir(sharefilesDataDir, isExist) != ERR_OK) {
            APP_LOGW("path: %{public}s IsExistDir failed",
                sharefilesDataDir.c_str());
            continue;
        }
        CreateDirParam createDirParam;
        createDirParam.bundleName = dirBundleName;
        createDirParam.bundleDirScene = BundleDirScene::EL2_SHARE_FILES_DIR;
        if (InstalldClient::GetInstance()->Mkdir(sharefilesDataDir,
            S_IRWXU, bundleInfo.uid, bundleInfo.gid, createDirParam) != ERR_OK) {
            APP_LOGW("MkOwnerDir %{public}s failed: %{public}d",
                sharefilesDataDir.c_str(), errno);
            continue;
        }
        for (const auto &dir : BUNDLE_DATA_DIR) {
            std::string childBundleDataDir = sharefilesDataDir + dir;
            if (InstalldClient::GetInstance()->Mkdir(childBundleDataDir,
                S_IRWXU, bundleInfo.uid, bundleInfo.gid, createDirParam) != ERR_OK) {
                APP_LOGW("MkOwnerDir [%{public}s] failed: %{public}d",
                    childBundleDataDir.c_str(), errno);
            }
        }
        if (InstalldClient::GetInstance()->SetDirApl(sharefilesDataDir, bundleInfo.name,
            bundleInfo.applicationInfo.appPrivilegeLevel, bundleInfo.isPreInstallApp,
            bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG,
            bundleInfo.uid) != ERR_OK) {
            APP_LOGW("SetDirApl failed: %{public}s", sharefilesDataDir.c_str());
            continue;
        }
        APP_LOGD("succeed for %{public}s", bundleInfo.name.c_str());
    }
    APP_LOGD("end for userid: [%{public}d]", userId);
}

bool UpdateAppDataMgr::CheckU1EnableProcess(const BundleInfo &bundleInfo, bool toTempBundle)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    bool singleton = bundleInfo.singleton;
    bool u1Enable = false;
    InnerBundleInfo info;
    // dual-mode: the U1 flag must come from the same variant being processed
    // (toTempBundle -> tempBundleInfos_).
    if (toTempBundle) {
        dataMgr->FetchTempBundleInfo(bundleInfo.name, info);
    } else {
        dataMgr->FetchInnerBundleInfo(bundleInfo.name, info);
    }
    u1Enable = info.IsU1Enable();
    if (u1Enable && !singleton) {
        return true;
    }
    return false;
}
}  // namespace AppExecFwk
}  // namespace OHOS