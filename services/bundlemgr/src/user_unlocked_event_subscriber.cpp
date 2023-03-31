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

#include <thread>

#include "app_log_wrapper.h"
#include "bundle_mgr_service.h"
#include "common_event_manager.h"
#include "common_event_support.h"
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
        APP_LOGD("UserUnlockedEventSubscriber userId %{public}d is unlocked", userId);
        std::thread updateDataDirThread(UpdateAppDataDirSelinuxLabel, userId);
        updateDataDirThread.detach();
    }
}

bool UserUnlockedEventSubscriber::CreateBundleDataDir(const BundleInfo &bundleInfo, int32_t userId)
{
    std::string baseBundleDataDir = Constants::BUNDLE_APP_DATA_BASE_DIR + Constants::BUNDLE_EL[1] +
        Constants::PATH_SEPARATOR + std::to_string(userId) + Constants::BASE + bundleInfo.name;
    bool isExist = false;
    if (InstalldClient::GetInstance()->IsExistDir(baseBundleDataDir, isExist) != ERR_OK) {
        APP_LOGE("path: %{private}s IsExistDir failed", baseBundleDataDir.c_str());
        return false;
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

void UserUnlockedEventSubscriber::UpdateAppDataDirSelinuxLabel(int32_t userId)
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
    for (const auto &bundleInfo : bundleInfos) {
        if (bundleInfo.singleton) {
            continue;
        }
        if (!CreateBundleDataDir(bundleInfo, userId)) {
            APP_LOGE("bundleName: %{public}s CreateBundleDataDir failed", bundleInfo.name.c_str());
        }
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS