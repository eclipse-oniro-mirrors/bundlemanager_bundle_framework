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
        APP_LOGI("UserUnlockedEventSubscriber userId %{public}d is unlocked", userId);
        std::thread updateDataDirThread(UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel, userId);
        updateDataDirThread.detach();
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
        DelayedSingleton<AppControlManager>::GetInstance()->SetAppInstallControlStatus();
#endif
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
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
    std::string baseBundleDataDir = Constants::BUNDLE_APP_DATA_BASE_DIR + elDir +
        Constants::PATH_SEPARATOR + std::to_string(userId) + Constants::BASE + bundleInfo.name;
    bool isExist = false;
    if (InstalldClient::GetInstance()->IsExistDir(baseBundleDataDir, isExist) != ERR_OK) {
        APP_LOGE("path: %{private}s IsExistDir failed", baseBundleDataDir.c_str());
        return false;
    }
    if (isExist) {
        FileStat fileStat;
        if (InstalldClient::GetInstance()->GetFileStat(baseBundleDataDir, fileStat) != ERR_OK) {
            APP_LOGE("GetFileStat path(%{private}s) failed", baseBundleDataDir.c_str());
            return false;
        }
        if (fileStat.uid != bundleInfo.uid || fileStat.gid != bundleInfo.gid) {
            APP_LOGD("path: %{private}s uid or gid is not same", baseBundleDataDir.c_str());
            isExist = false;
        }
    }
    if (!isExist) {
        APP_LOGD("path: %{private}s is not exist, need to create it", baseBundleDataDir.c_str());
        CreateDirParam createDirParam;
        createDirParam.userId = userId;
        createDirParam.bundleName = bundleInfo.name;
        createDirParam.uid = bundleInfo.uid;
        createDirParam.gid = bundleInfo.gid;
        createDirParam.apl = bundleInfo.applicationInfo.appPrivilegeLevel;
        createDirParam.isPreInstallApp = bundleInfo.isPreInstallApp;
        createDirParam.debug = bundleInfo.applicationInfo.debug;
        createDirParam.createDirFlag = CreateDirFlag::CREATE_DIR_UNLOCKED;
        if (InstalldClient::GetInstance()->CreateBundleDataDir(createDirParam) != ERR_OK) {
            APP_LOGE("failed to CreateBundleDataDir");
            return false;
        }
    }
    return true;
}

void UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel(int32_t userId)
{
    APP_LOGD("UpdateAppDataDirSelinuxLabel userId:%{public}d", userId);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("UpdateAppDataDirSelinuxLabel DataMgr is nullptr");
        return;
    }
    std::vector<BundleInfo> bundleInfos;
    if (!dataMgr->GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, userId)) {
        APP_LOGE("UpdateAppDataDirSelinuxLabel GetAllBundleInfos failed");
        return;
    }

    ProcessUpdateAppDataDir(userId, bundleInfos, Constants::BUNDLE_EL[1]);
#ifdef CHECK_ELDIR_ENABLED
    ProcessUpdateAppDataDir(userId, bundleInfos, Constants::DIR_EL3);
    ProcessUpdateAppDataDir(userId, bundleInfos, Constants::DIR_EL4);
#endif
    ProcessUpdateAppLogDir(bundleInfos, userId);
}

void UpdateAppDataMgr::ProcessUpdateAppDataDir(
    int32_t userId, const std::vector<BundleInfo> &bundleInfos, const std::string &elDir)
{
    std::string baseBundleDataDir = Constants::BUNDLE_APP_DATA_BASE_DIR + elDir +
        Constants::PATH_SEPARATOR + std::to_string(userId);
    for (const auto &bundleInfo : bundleInfos) {
        if ((userId != Constants::DEFAULT_USERID && bundleInfo.singleton) ||
            !CreateBundleDataDir(bundleInfo, userId, elDir)) {
            continue;
        }
        std::string baseDir = baseBundleDataDir + Constants::BASE + bundleInfo.name;
        if (InstalldClient::GetInstance()->SetDirApl(baseDir, bundleInfo.name,
            bundleInfo.applicationInfo.appPrivilegeLevel, bundleInfo.isPreInstallApp,
            bundleInfo.applicationInfo.debug) != ERR_OK) {
            APP_LOGW("failed to SetDirApl baseDir dir");
            continue;
        }
        std::string baseDataDir = baseBundleDataDir + Constants::DATABASE + bundleInfo.name;
        if (InstalldClient::GetInstance()->SetDirApl(baseDataDir, bundleInfo.name,
            bundleInfo.applicationInfo.appPrivilegeLevel, bundleInfo.isPreInstallApp,
            bundleInfo.applicationInfo.debug) != ERR_OK) {
            APP_LOGW("failed to SetDirApl baseDataDir dir");
        }
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

bool UpdateAppDataMgr::CreateBundleLogDir(const BundleInfo &bundleInfo, int32_t userId)
{
    std::string bundleLogDir = Constants::BUNDLE_APP_DATA_BASE_DIR + Constants::BUNDLE_EL[1] +
        Constants::PATH_SEPARATOR + std::to_string(userId) + Constants::LOG + bundleInfo.name;
    bool isExist = false;
    if (InstalldClient::GetInstance()->IsExistDir(bundleLogDir, isExist) != ERR_OK) {
        APP_LOGE("path: %{private}s IsExistDir failed", bundleLogDir.c_str());
        return false;
    }
    if (isExist) {
        APP_LOGD("path: %{private}s is exist", bundleLogDir.c_str());
        return false;
    }
    if (InstalldClient::GetInstance()->Mkdir(
        bundleLogDir, S_IRWXU | S_IRWXG, bundleInfo.uid, Constants::LOG_DIR_GID) != ERR_OK) {
        APP_LOGE("CreateBundleLogDir failed");
        return false;
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS