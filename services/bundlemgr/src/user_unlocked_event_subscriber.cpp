/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#if defined (BUNDLE_FRAMEWORK_SANDBOX_APP) && defined (DLP_PERMISSION_ENABLE)
#include "dlp_permission_kit.h"
#endif
#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
static constexpr int16_t MODE_BASE = 07777;
static constexpr int16_t DATA_GROUP_DIR_MODE = 02770;
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
}
UserUnlockedEventSubscriber::UserUnlockedEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo) : EventFwk::CommonEventSubscriber(subscribeInfo)
{}

UserUnlockedEventSubscriber::~UserUnlockedEventSubscriber()
{}

void UserUnlockedEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) {
        int32_t userId = data.GetCode();
        APP_LOGI_NOFUNC("UserUnlockedEventSubscriber -u %{public}d unlocked", userId);
        std::lock_guard<std::mutex> lock(mutex_);
        if ((userId_ != userId)) {
            userId_ = userId;
            std::thread updateDataDirThread(UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel, userId);
            updateDataDirThread.detach();
            std::thread(UpdateAppDataMgr::DeleteUninstallTmpDirs, userId).detach();
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
            std::thread(UpdateAppDataMgr::DeleteUninstallTmpDirs, userId).detach();
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
    if (InstalldClient::GetInstance()->GetFileStat(path, fileStat) != ERR_OK) {
        APP_LOGE("GetFileStat path(%{public}s) failed", path.c_str());
        return;
    }
    if (fileStat.uid != bundleInfo.uid) {
        APP_LOGW("path: %{public}s uid is not same, fileStat.uid:%{public}d, bundleInfo.uid:%{public}d",
            path.c_str(), static_cast<int32_t>(fileStat.uid), bundleInfo.uid);
        isExist = false;
    }
    if (fileStat.gid != ServiceConstants::DATABASE_DIR_GID) {
        APP_LOGW("path: %{public}s gid is not same, fileStat.gid:%{public}d, gid:%{public}d",
            path.c_str(), static_cast<int32_t>(fileStat.gid), ServiceConstants::DATABASE_DIR_GID);
        isExist = false;
    }
    uint32_t fileMode = static_cast<uint32_t>(fileStat.mode);
    if ((fileMode & MODE_BASE) != (S_IRWXU | S_IRWXG | S_ISGID)) {
        APP_LOGW("path: %{public}s mode is not same, fileStat.mode:%{public}d, mode:%{public}d",
            path.c_str(), static_cast<int32_t>(fileStat.mode), static_cast<int32_t>((S_IRWXU | S_IRWXG | S_ISGID)));
    }
}

bool UpdateAppDataMgr::CreateBundleDataDir(
    const BundleInfo &bundleInfo, int32_t userId, const std::string &elDir)
{
    std::string baseBundleDataDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + elDir +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::DATABASE + bundleInfo.name;
    bool isExist = false;
    if (InstalldClient::GetInstance()->IsExistDir(baseBundleDataDir, isExist) != ERR_OK) {
        APP_LOGE("path: %{public}s IsExistDir failed", baseBundleDataDir.c_str());
        return false;
    }
    CheckPathAttribute(baseBundleDataDir, bundleInfo, isExist);
    if (!isExist) {
        APP_LOGI_NOFUNC("path: %{public}s need CreateBundleDataDir", baseBundleDataDir.c_str());
        CreateDirParam createDirParam;
        createDirParam.userId = userId;
        createDirParam.bundleName = bundleInfo.name;
        createDirParam.uid = bundleInfo.uid;
        createDirParam.gid = bundleInfo.gid;
        createDirParam.apl = bundleInfo.applicationInfo.appPrivilegeLevel;
        createDirParam.isPreInstallApp = bundleInfo.isPreInstallApp;
        createDirParam.debug = bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG;
        if (elDir != ServiceConstants::BUNDLE_EL[0]) {
            createDirParam.createDirFlag = CreateDirFlag::CREATE_DIR_UNLOCKED;
        }
        if (elDir == ServiceConstants::DIR_EL5) {
            return CreateEl5Dir(createDirParam);
        }
        ProcessExtensionDir(bundleInfo, createDirParam.extensionDirs);
        if (InstalldClient::GetInstance()->CreateBundleDataDir(createDirParam) != ERR_OK) {
            APP_LOGW("failed to CreateBundleDataDir");
        }
    }
    CreateDataGroupDir(bundleInfo, userId);
    return true;
}

bool UpdateAppDataMgr::CreateEl5Dir(const CreateDirParam &createDirParam)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("CreateEl5Dir failed for DataMgr is nullptr");
        return false;
    }
    std::vector<CreateDirParam> params;
    params.emplace_back(createDirParam);
    InnerBundleInfo info;
    if (dataMgr->FetchInnerBundleInfo(createDirParam.bundleName, info)) {
        InnerBundleUserInfo userInfo;
        if (info.GetInnerBundleUserInfo(createDirParam.userId, userInfo)) {
            for (const auto &cloneInfo : userInfo.cloneInfos) {
                CreateDirParam cloneParam = createDirParam;
                cloneParam.uid = cloneInfo.second.uid;
                cloneParam.gid = cloneInfo.second.uid;
                cloneParam.appIndex = cloneInfo.second.appIndex;
                params.emplace_back(cloneParam);
            }
        }
    }
    dataMgr->CreateEl5Dir(params, true);
    return true;
}

void UpdateAppDataMgr::DeleteUninstallTmpDirs(const int32_t userId)
{
    std::vector<std::string> dirs = GetBundleDataDirs(userId);
    if (dirs.empty()) {
        LOG_I(BMS_TAG_DEFAULT, "dirs empty");
        return;
    }
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
    return dirs;
}

void UpdateAppDataMgr::CreateDataGroupDir(const BundleInfo &bundleInfo, int32_t userId)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("CreateDataGroupDir failed for DataMgr is nullptr");
        return;
    }
    std::vector<DataGroupInfo> dataGroupInfos;
    if (!dataMgr->QueryDataGroupInfos(bundleInfo.name, userId, dataGroupInfos)) {
        APP_LOGW("QueryDataGroupInfo for bundle %{public}s userId %{public}d failed", bundleInfo.name.c_str(), userId);
        return;
    }
    if (dataGroupInfos.empty()) {
        return;
    }

    std::string parentDir = std::string(ServiceConstants::REAL_DATA_PATH) + ServiceConstants::PATH_SEPARATOR
        + std::to_string(userId);
    if (!BundleUtil::IsExistDir(parentDir)) {
        APP_LOGE("parent dir(%{public}s) missing: group", parentDir.c_str());
        return;
    }
    for (const DataGroupInfo &dataGroupInfo : dataGroupInfos) {
        std::string dir = parentDir + ServiceConstants::DATA_GROUP_PATH + dataGroupInfo.uuid;
        APP_LOGD("create group dir: %{public}s", dir.c_str());
        auto result = InstalldClient::GetInstance()->Mkdir(dir,
            DATA_GROUP_DIR_MODE, dataGroupInfo.uid, dataGroupInfo.gid);
        if (result != ERR_OK) {
            APP_LOGW("create data group dir %{public}s userId %{public}d failed", dataGroupInfo.uuid.c_str(), userId);
        }
    }
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
        BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION, bundleInfos, userId)) {
        APP_LOGE("UpdateAppDataDirSelinuxLabel GetAllBundleInfos failed");
        return;
    }

    ReturnIfNewTask(ProcessUpdateAppDataDir, tempTaskNum, userId, bundleInfos, ServiceConstants::BUNDLE_EL[1]);
#ifdef CHECK_ELDIR_ENABLED
    ReturnIfNewTask(ProcessUpdateAppDataDir, tempTaskNum, userId, bundleInfos, ServiceConstants::DIR_EL3);
    ReturnIfNewTask(ProcessUpdateAppDataDir, tempTaskNum, userId, bundleInfos, ServiceConstants::DIR_EL4);
#endif
    ReturnIfNewTask(ProcessUpdateAppDataDir, tempTaskNum, userId, bundleInfos, ServiceConstants::DIR_EL5);
    ReturnIfNewTask(ProcessUpdateAppLogDir, tempTaskNum, bundleInfos, userId);
    ReturnIfNewTask(ProcessFileManagerDir, tempTaskNum, bundleInfos, userId);
    ReturnIfNewTask(ProcessNewBackupDir, tempTaskNum, bundleInfos, userId);
    ReturnIfNewTask(CreateSharefilesSubDataDirs, tempTaskNum, bundleInfos, userId);
    APP_LOGI("UpdateAppDataDirSelinuxLabel userId:%{public}d end", userId);
}

void UpdateAppDataMgr::ProcessUpdateAppDataDir(
    int32_t userId, const std::vector<BundleInfo> &bundleInfos, const std::string &elDir)
{
    std::string baseBundleDataDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + elDir +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId);
    for (const auto &bundleInfo : bundleInfos) {
        if (bundleInfo.appIndex > 0) {
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
            !CreateBundleDataDir(bundleInfo, userId, elDir)) {
            continue;
        }
        std::string baseDir = baseBundleDataDir + ServiceConstants::BASE + bundleInfo.name;
        if (InstalldClient::GetInstance()->SetDirApl(baseDir, bundleInfo.name,
            bundleInfo.applicationInfo.appPrivilegeLevel, bundleInfo.isPreInstallApp,
            bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG) != ERR_OK) {
            APP_LOGW_NOFUNC("failed to SetDirApl baseDir dir");
            continue;
        }
        std::string baseDataDir = baseBundleDataDir + ServiceConstants::DATABASE + bundleInfo.name;
        if (InstalldClient::GetInstance()->SetDirApl(baseDataDir, bundleInfo.name,
            bundleInfo.applicationInfo.appPrivilegeLevel, bundleInfo.isPreInstallApp,
            bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG) != ERR_OK) {
            APP_LOGW_NOFUNC("failed to SetDirApl baseDataDir dir");
        }
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

void UpdateAppDataMgr::ProcessUpdateAppLogDir(const std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    for (const auto &bundleInfo : bundleInfos) {
        if (userId != Constants::DEFAULT_USERID && bundleInfo.singleton) {
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
    std::string parentEl1Dir = BUNDLE_BACKUP_HOME_PATH_EL1_NEW;
    parentEl1Dir = parentEl1Dir.replace(parentEl1Dir.find("%"), 1, std::to_string(userId)) + bundleInfo.name;
    std::string parentEl2Dir = BUNDLE_BACKUP_HOME_PATH_EL2_NEW;
    parentEl2Dir = parentEl2Dir.replace(parentEl2Dir.find("%"), 1, std::to_string(userId)) + bundleInfo.name;
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
        result = InstalldClient::GetInstance()->Mkdir(dir, S_IRWXU | S_IRWXG | S_ISGID,
            bundleInfo.uid, ServiceConstants::BACKU_HOME_GID);
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
    std::string bundleLogDir = parentDir + bundleInfo.name;
    bool isExist = false;
    if (InstalldClient::GetInstance()->IsExistDir(bundleLogDir, isExist) != ERR_OK) {
        APP_LOGE("path: %{public}s IsExistDir failed", bundleLogDir.c_str());
        return false;
    }
    if (isExist) {
        APP_LOGD("path: %{public}s is exist", bundleLogDir.c_str());
        return false;
    }
    if (InstalldClient::GetInstance()->Mkdir(
        bundleLogDir, S_IRWXU | S_IRWXG, bundleInfo.uid, ServiceConstants::LOG_DIR_GID) != ERR_OK) {
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
        APP_LOGE("parent dir(%{public}s) missing: cloud", parentDir.c_str());
        return false;
    }
    std::string bundleCloudDir = parentDir + bundleInfo.name;
    bool isExist = false;
    if (InstalldClient::GetInstance()->IsExistDir(bundleCloudDir, isExist) != ERR_OK) {
        APP_LOGE("path: %{private}s IsExistDir failed", bundleCloudDir.c_str());
        return false;
    }
    if (isExist) {
        APP_LOGD("path: %{private}s is exist", bundleCloudDir.c_str());
        return false;
    }
    if (!InstalldClient::GetInstance()->Mkdir(bundleCloudDir, S_IRWXU | S_IRWXG | S_ISGID,
        bundleInfo.uid, ServiceConstants::DFS_GID)) {
        static std::once_flag cloudOnce;
        std::call_once(cloudOnce, [bundleInfo]() {
            APP_LOGW("CreateCloudDir failed for bundle %{private}s errno:%{public}d",
                     bundleInfo.name.c_str(), errno);
        });
    }
    return true;
}

void UpdateAppDataMgr::CreateSharefilesSubDataDirs(const std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    APP_LOGD("begin for userid: [%{public}d]", userId);
    std::string parentDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::SHAREFILES;
    for (const auto &bundleInfo : bundleInfos) {
        std::string sharefilesDataDir = parentDir + bundleInfo.name;
        bool isExist = false;
        if (InstalldClient::GetInstance()->IsExistDir(sharefilesDataDir, isExist) != ERR_OK) {
            APP_LOGW("path: %{public}s IsExistDir failed",
                sharefilesDataDir.c_str());
            continue;
        }
        if (InstalldClient::GetInstance()->Mkdir(sharefilesDataDir,
            S_IRWXU, bundleInfo.uid, bundleInfo.gid) != ERR_OK) {
            APP_LOGW("MkOwnerDir %{public}s failed: %{public}d",
                sharefilesDataDir.c_str(), errno);
            continue;
        }
        for (const auto &dir : BUNDLE_DATA_DIR) {
            std::string childBundleDataDir = sharefilesDataDir + dir;
            if (InstalldClient::GetInstance()->Mkdir(childBundleDataDir,
                S_IRWXU, bundleInfo.uid, bundleInfo.gid) != ERR_OK) {
                APP_LOGW("MkOwnerDir [%{public}s] failed: %{public}d",
                    childBundleDataDir.c_str(), errno);
            }
        }
        if (InstalldClient::GetInstance()->SetDirApl(sharefilesDataDir, bundleInfo.name,
            bundleInfo.applicationInfo.appPrivilegeLevel, bundleInfo.isPreInstallApp,
            bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG) != ERR_OK) {
            APP_LOGW("SetDirApl failed: %{public}s", sharefilesDataDir.c_str());
            continue;
        }
        APP_LOGD("succeed for %{public}s", bundleInfo.name.c_str());
    }
    APP_LOGD("end for userid: [%{public}d]", userId);
}
}  // namespace AppExecFwk
}  // namespace OHOS