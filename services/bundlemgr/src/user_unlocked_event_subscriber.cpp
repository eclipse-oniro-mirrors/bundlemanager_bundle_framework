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

#include <sys/stat.h>
#include <thread>

#include "account_helper.h"
#include "app_control_manager.h"
#include "app_log_wrapper.h"
#include "bundle_mgr_service.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#if defined (BUNDLE_FRAMEWORK_SANDBOX_APP) && defined (DLP_PERMISSION_ENABLE)
#include "dlp_permission_kit.h"
#endif
#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
static constexpr int32_t MODE_BASE = 07777;
static constexpr int32_t DATA_GROUP_DIR_MODE = 02770;
const std::string BUNDLE_BACKUP_HOME_PATH_EL1_NEW = "/data/app/el1/%/base/";
const std::string BUNDLE_BACKUP_HOME_PATH_EL2_NEW = "/data/app/el2/%/base/";
const std::string BUNDLE_BACKUP_INNER_DIR = "/.backup";
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
        APP_LOGI("UserUnlockedEventSubscriber userId %{public}d unlocked", userId);
        std::lock_guard<std::mutex> lock(mutex_);
        if ((userId_ != userId)) {
            userId_ = userId;
            std::thread updateDataDirThread(UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel, userId);
            updateDataDirThread.detach();
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
            DelayedSingleton<AppControlManager>::GetInstance()->SetAppInstallControlStatus();
#endif
        }
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        int32_t userId = data.GetCode();
        APP_LOGI("UserUnlockedEventSubscriber userId %{public}d switched", userId);
        std::lock_guard<std::mutex> lock(mutex_);
        if (AccountHelper::IsOsAccountVerified(userId) && (userId_ != userId)) {
            APP_LOGI("UserUnlockedEventSubscriber userId:%{public}d unlocked", userId);
            userId_ = userId;
            std::thread updateDataDirThread(UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel, userId);
            updateDataDirThread.detach();
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
    if (isExist) {
        FileStat fileStat;
        if (InstalldClient::GetInstance()->GetFileStat(baseBundleDataDir, fileStat) != ERR_OK) {
            APP_LOGE("GetFileStat path(%{public}s) failed", baseBundleDataDir.c_str());
            return false;
        }
        uint32_t fileMode = static_cast<uint32_t>(fileStat.mode);
        if ((fileStat.uid != bundleInfo.uid) || (fileStat.gid != ServiceConstants::DATABASE_DIR_GID) ||
            ((fileMode & MODE_BASE) != (S_IRWXU | S_IRWXG | S_ISGID))) {
            APP_LOGW("path: %{public}s uid or gid or mode not same: fileStat.uid:%{public}d,"
                "bundleInfo.uid:%{public}d, fileStat.gid:%{public}d ", baseBundleDataDir.c_str(),
                static_cast<int32_t>(fileStat.uid), bundleInfo.uid, static_cast<int32_t>(fileStat.mode));
            isExist = false;
        }
    }
    if (!isExist) {
        APP_LOGI("path: %{public}s not exist, need create", baseBundleDataDir.c_str());
        CreateDirParam createDirParam;
        createDirParam.userId = userId;
        createDirParam.bundleName = bundleInfo.name;
        createDirParam.uid = bundleInfo.uid;
        createDirParam.gid = bundleInfo.gid;
        createDirParam.apl = bundleInfo.applicationInfo.appPrivilegeLevel;
        createDirParam.isPreInstallApp = bundleInfo.isPreInstallApp;
        createDirParam.debug = bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG;
        createDirParam.createDirFlag = CreateDirFlag::CREATE_DIR_UNLOCKED;
        ProcessExtensionDir(bundleInfo, createDirParam.extensionDirs);
        if (InstalldClient::GetInstance()->CreateBundleDataDir(createDirParam) != ERR_OK) {
            APP_LOGE("failed to CreateBundleDataDir");
            return false;
        }
    }
    CreateDataGroupDir(bundleInfo, userId);
    return true;
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
    for (const DataGroupInfo &dataGroupInfo : dataGroupInfos) {
        std::string dir = ServiceConstants::REAL_DATA_PATH + ServiceConstants::PATH_SEPARATOR
            + std::to_string(userId) + ServiceConstants::DATA_GROUP_PATH + dataGroupInfo.uuid;
        bool dirExist = false;
        auto result = InstalldClient::GetInstance()->IsExistDir(dir, dirExist);
        if (result == ERR_OK && dirExist) {
            continue;
        }
        APP_LOGD("create group dir: %{public}s", dir.c_str());
        result = InstalldClient::GetInstance()->Mkdir(dir,
            DATA_GROUP_DIR_MODE, dataGroupInfo.uid, dataGroupInfo.gid);
        if (result != ERR_OK) {
            APP_LOGW("create data group dir %{public}s userId %{public}d failed", dataGroupInfo.uuid.c_str(), userId);
        }
    }
}

void UpdateAppDataMgr::ChmodBundleDataDir(const std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    APP_LOGI("start chmod data dir");
    std::vector<CreateDirParam> createDirParams;
    for (const auto &bundleInfo : bundleInfos) {
        CreateDirParam createDirParam;
        createDirParam.bundleName = bundleInfo.name;
        if (bundleInfo.singleton) {
            createDirParam.userId = Constants::DEFAULT_USERID;
        } else {
            createDirParam.userId = userId;
        }
        createDirParam.uid = bundleInfo.uid;
        createDirParam.gid = bundleInfo.gid;
        createDirParam.apl = bundleInfo.applicationInfo.appPrivilegeLevel;
        createDirParam.isPreInstallApp = bundleInfo.isPreInstallApp;
        createDirParam.debug = bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG;
        createDirParam.createDirFlag = CreateDirFlag::FIX_DIR_AND_FILES_PROPERTIES;
        ProcessExtensionDir(bundleInfo, createDirParam.extensionDirs);
        createDirParams.emplace_back(createDirParam);
    }
    if (InstalldClient::GetInstance()->CreateBundleDataDirWithVector(createDirParams) != ERR_OK) {
        APP_LOGE("failed to chmod data dir");
    }
    APP_LOGI("end chmod data dir");
}

void UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel(int32_t userId)
{
    APP_LOGI("UpdateAppDataDirSelinuxLabel userId:%{public}d start", userId);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("UpdateAppDataDirSelinuxLabel DataMgr is nullptr");
        return;
    }
    std::vector<BundleInfo> bundleInfos;
    if (!dataMgr->GetBundleInfos(BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO, bundleInfos, userId)) {
        APP_LOGE("UpdateAppDataDirSelinuxLabel GetAllBundleInfos failed");
        return;
    }

    ProcessUpdateAppDataDir(userId, bundleInfos, ServiceConstants::BUNDLE_EL[1]);
#ifdef CHECK_ELDIR_ENABLED
    ProcessUpdateAppDataDir(userId, bundleInfos, ServiceConstants::DIR_EL3);
    ProcessUpdateAppDataDir(userId, bundleInfos, ServiceConstants::DIR_EL4);
#endif
    ProcessUpdateAppLogDir(bundleInfos, userId);
    ProcessFileManagerDir(bundleInfos, userId);
    ProcessNewBackupDir(bundleInfos, userId);
    ChmodBundleDataDir(bundleInfos, userId);
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
        if ((userId != Constants::DEFAULT_USERID && bundleInfo.singleton) ||
            !CreateBundleDataDir(bundleInfo, userId, elDir)) {
            continue;
        }
        std::string baseDir = baseBundleDataDir + ServiceConstants::BASE + bundleInfo.name;
        if (InstalldClient::GetInstance()->SetDirApl(baseDir, bundleInfo.name,
            bundleInfo.applicationInfo.appPrivilegeLevel, bundleInfo.isPreInstallApp,
            bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG) != ERR_OK) {
            APP_LOGW("failed to SetDirApl baseDir dir");
            continue;
        }
        std::string baseDataDir = baseBundleDataDir + ServiceConstants::DATABASE + bundleInfo.name;
        if (InstalldClient::GetInstance()->SetDirApl(baseDataDir, bundleInfo.name,
            bundleInfo.applicationInfo.appPrivilegeLevel, bundleInfo.isPreInstallApp,
            bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG) != ERR_OK) {
            APP_LOGW("failed to SetDirApl baseDataDir dir");
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
    APP_LOGI("process new back up dir, start");
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
    APP_LOGI("process new back up dir, end");
}

void UpdateAppDataMgr::CreateNewBackupDir(const BundleInfo &bundleInfo, int32_t userId)
{
    std::string backupDirEl1 = BUNDLE_BACKUP_HOME_PATH_EL1_NEW + bundleInfo.name + BUNDLE_BACKUP_INNER_DIR;
    backupDirEl1 = backupDirEl1.replace(backupDirEl1.find("%"), 1, std::to_string(userId));
    std::vector<std::string> backupDirList;
    backupDirList.emplace_back(backupDirEl1);
    std::string backupDirEl2 = BUNDLE_BACKUP_HOME_PATH_EL2_NEW + bundleInfo.name + BUNDLE_BACKUP_INNER_DIR;
    backupDirEl2 = backupDirEl2.replace(backupDirEl2.find("%"), 1, std::to_string(userId));
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
    std::string bundleLogDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::LOG + bundleInfo.name;
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
    const std::string CLOUD_FILE_PATH = "/data/service/el2/%/hmdfs/cloud/data/";
    std::string bundleCloudDir = CLOUD_FILE_PATH + bundleInfo.name;
    bundleCloudDir = bundleCloudDir.replace(bundleCloudDir.find("%"), 1, std::to_string(userId));
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
}  // namespace AppExecFwk
}  // namespace OHOS