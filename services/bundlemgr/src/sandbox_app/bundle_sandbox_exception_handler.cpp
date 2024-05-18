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

#include "bundle_sandbox_exception_handler.h"

#include <thread>

#include "account_helper.h"
#include "bundle_common_event_mgr.h"
#include "bundle_constants.h"
#include "bundle_permission_mgr.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "installd_client.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t WAIT_TIMES = 40;
const int32_t EACH_TIME = 1000; // 1000ms
} // namespace
using namespace OHOS::Security;
BundleMgrCommonEventSubscriber::BundleMgrCommonEventSubscriber(
    const CommonEventSubscribeInfo &subscribeInfo,
    const std::map<int32_t, std::vector<std::string>> &sandboxDirs)
    : CommonEventSubscriber(subscribeInfo), toDeleteSandboxDir_(sandboxDirs)
{}

void BundleMgrCommonEventSubscriber::OnReceiveEvent(const CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    APP_LOGD("receive action %{public}s", action.c_str());
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) {
        int32_t userId = data.GetCode();
        APP_LOGD("userId %{public}d is unlocked", userId);
        std::thread removeThread(RemoveSandboxDataDir, userId, toDeleteSandboxDir_);
        removeThread.detach();
    }
}

void BundleMgrCommonEventSubscriber::RemoveSandboxDataDir(int32_t userId,
    const std::map<int32_t, std::vector<std::string>> &toDeleteSandboxDir)
{
    // delete sandbox data dir
    if (toDeleteSandboxDir.empty() || (toDeleteSandboxDir.find(userId) == toDeleteSandboxDir.end())) {
        APP_LOGW("toDeleteSandboxDir is empty or no dir to be deleted");
        return;
    }

    for (const auto &dir : toDeleteSandboxDir.at(userId)) {
        APP_LOGD("the dir %{public}s needs to be deleted", dir.c_str());
        auto result = InstalldClient::GetInstance()->RemoveDir(dir);
        if (result != ERR_OK) {
            APP_LOGE("fail to remove data dir: %{public}s, error is %{public}d", dir.c_str(), result);
        }
    }
}

BundleSandboxExceptionHandler::BundleSandboxExceptionHandler(
    const std::shared_ptr<IBundleDataStorage> &dataStorage) : dataStorage_(dataStorage)
{
    APP_LOGI("create bundle sandbox exception handler instance");
}

BundleSandboxExceptionHandler::~BundleSandboxExceptionHandler()
{
    APP_LOGI("destroy bundle sandbox exception handler instance");
}

void BundleSandboxExceptionHandler::RemoveSandboxApp(InnerBundleInfo &info)
{
    std::string bundleName = info.GetBundleName();
    auto sandboxPersistentInfo = info.GetSandboxPersistentInfo();
    if (sandboxPersistentInfo.empty()) {
        APP_LOGD("no sandbox app info");
        return;
    }
    info.ClearSandboxPersistentInfo();
    UpdateBundleInfoToStorage(info);
    RemoveTokenIdAndKeepSandboxDir(bundleName, sandboxPersistentInfo, info);
}

void BundleSandboxExceptionHandler::RemoveTokenIdAndKeepSandboxDir(const std::string &bundleName,
    const std::vector<SandboxAppPersistentInfo> &sandboxPersistentInfo, const InnerBundleInfo &info)
{
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();

    for (const auto& sandboxInfo : sandboxPersistentInfo) {
        APP_LOGD("start to remove sandbox accessTokenId of %{public}s_%{public}d", bundleName.c_str(),
            sandboxInfo.appIndex);
        if (sandboxInfo.appIndex <= 0) {
            APP_LOGW("invalid app index %{public}d", sandboxInfo.appIndex);
            continue;
        }
        // delete accessToken id from ATM
        if (BundlePermissionMgr::DeleteAccessTokenId(sandboxInfo.accessTokenId) !=
            AccessToken::AccessTokenKitRet::RET_SUCCESS) {
            APP_LOGE("delete accessToken failed");
        }
        // send notification for uninstall sandbox bundle when reboot
        if (commonEventMgr != nullptr) {
            int32_t userId = sandboxInfo.userId;
            commonEventMgr->NotifySandboxAppStatus(info, info.GetUid(userId), userId, SandboxInstallType::UNINSTALL);
        }

        // keep sandbox dir when reboot
        KeepSandboxDirs(bundleName, sandboxInfo.appIndex, sandboxInfo.userId);
    }
    RemoveDataDir();
    ListeningUserUnlocked();
}

void BundleSandboxExceptionHandler::KeepSandboxDirs(const std::string &bundleName, int32_t appIndex, int32_t userId)
{
    APP_LOGD("start to keep sandbox dir");
    std::string innerBundleName = std::to_string(appIndex) + Constants::FILE_UNDERLINE + bundleName;
    for (const auto &el : ServiceConstants::BUNDLE_EL) {
        std::string baseDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + el + ServiceConstants::PATH_SEPARATOR +
            std::to_string(userId) + ServiceConstants::BASE + innerBundleName;
        std::string databaseDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + el + ServiceConstants::PATH_SEPARATOR +
            std::to_string(userId) + ServiceConstants::DATABASE + innerBundleName;
        APP_LOGD("to keep sandbox dirs data dir %{public}s, database dir %{public}s", baseDir.c_str(),
            databaseDir.c_str());
        if (sandboxDirs_.find(userId) == sandboxDirs_.end()) {
            std::vector<std::string> innerVec { baseDir, databaseDir };
            sandboxDirs_[userId] = innerVec;
        } else {
            sandboxDirs_[userId].emplace_back(baseDir);
            sandboxDirs_[userId].emplace_back(databaseDir);
        }
    }
    APP_LOGD("finish to keep sandbox dir");
}

void BundleSandboxExceptionHandler::ListeningUserUnlocked()
{
    APP_LOGD("listen the unlock of someone user");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);

    auto subscriberPtr = std::make_shared<BundleMgrCommonEventSubscriber>(subscribeInfo, sandboxDirs_);
    if (!CommonEventManager::SubscribeCommonEvent(subscriberPtr)) {
        APP_LOGW("subscribe common event %{public}s failed",
            EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED.c_str());
    }
}

void BundleSandboxExceptionHandler::RemoveDataDir()
{
    APP_LOGD("start to remove sandbox data dir");
    auto execFunc =
        [](const std::map<int32_t, std::vector<std::string>> &sandboxDirs, int32_t waitTimes,
            int32_t eachTime) {
        int32_t currentUserId = Constants::INVALID_USERID;
        while (waitTimes--) {
            std::this_thread::sleep_for(std::chrono::milliseconds(eachTime));
            APP_LOGD("wait for account started");
            if (currentUserId == Constants::INVALID_USERID) {
                currentUserId = AccountHelper::GetCurrentActiveUserId();
                APP_LOGD("current active userId is %{public}d", currentUserId);
                if (currentUserId == Constants::INVALID_USERID) {
                    continue;
                }
            }
            auto it = sandboxDirs.find(currentUserId);
            if (it == sandboxDirs.end()) {
                APP_LOGW("no data dir needs to be deleted");
                break;
            }
            bool isDirDeleteSuccessfully = true;
            for (const auto &dir : it->second) {
                APP_LOGD("start to remove data dir %{public}s", dir.c_str());
                auto result = InstalldClient::GetInstance()->RemoveDir(dir);
                if (result != ERR_OK) {
                    APP_LOGE("fail to remove data dir: %{public}s, error is %{public}d", dir.c_str(), result);
                    isDirDeleteSuccessfully = false;
                    break;
                }
            }
            if (isDirDeleteSuccessfully) {
                APP_LOGD("successfully to delete the sandbox dir");
                break;
            }
        }
    };

    std::thread removeThread(execFunc, sandboxDirs_, WAIT_TIMES, EACH_TIME);
    removeThread.detach();
}

void BundleSandboxExceptionHandler::UpdateBundleInfoToStorage(const InnerBundleInfo &info)
{
    auto storage = dataStorage_.lock();
    if (storage) {
        APP_LOGD("update bundle info of %{public}s to the storage", info.GetBundleName().c_str());
        storage->SaveStorageBundleInfo(info);
    } else {
        APP_LOGE(" fail to remove bundle info of %{public}s from the storage", info.GetBundleName().c_str());
    }
}
} // AppExecFwk
} // OHOS