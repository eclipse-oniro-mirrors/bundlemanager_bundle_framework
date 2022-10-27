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

#include "bundle_sandbox_exception_handler.h"

#include <thread>

#include "bundle_common_event_mgr.h"
#include "bundle_constants.h"
#include "bundle_permission_mgr.h"
#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::Security;

BundleSandboxExceptionHandler::BundleSandboxExceptionHandler(
    const std::shared_ptr<IBundleDataStorage> &dataStorage) : dataStorage_(dataStorage)
{
    APP_LOGI("create bundle excepetion handler instance");
}

BundleSandboxExceptionHandler::~BundleSandboxExceptionHandler()
{
    APP_LOGI("destroy bundle excepetion handler instance");
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

    std::thread removeThread(RemoveSandboxDataDirAndTokenId, bundleName, sandboxPersistentInfo, info);
    removeThread.detach();
}

void BundleSandboxExceptionHandler::RemoveSandboxDataDirAndTokenId(const std::string &bundleName,
    const std::vector<SandboxAppPersistentInfo> &sandboxPersistentInfo, const InnerBundleInfo &info)
{
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();

    for (const auto& sandboxInfo : sandboxPersistentInfo) {
        APP_LOGD("start to remove sandbox dir of %{public}s_%{public}d", bundleName.c_str(), sandboxInfo.appIndex);
        if (sandboxInfo.appIndex <= 0) {
            APP_LOGW("invalid app index %{public}d", sandboxInfo.appIndex);
            continue;
        }
        // delete accessToken id from ATM
        if (BundlePermissionMgr::DeleteAccessTokenId(sandboxInfo.accessTokenId) !=
            AccessToken::AccessTokenKitRet::RET_SUCCESS) {
            APP_LOGE("delete accessToken failed");
        }
        // delete sandbox data dir
        std::string innerBundleName = bundleName + Constants::FILE_UNDERLINE + std::to_string(sandboxInfo.appIndex);
        ErrCode result = InstalldClient::GetInstance()->RemoveBundleDataDir(innerBundleName, sandboxInfo.userId);
        if (result != ERR_OK) {
            APP_LOGE("fail to remove data dir: %{public}s, error is %{public}d", innerBundleName.c_str(), result);
        }

        if (commonEventMgr != nullptr) {
            int32_t userId = sandboxInfo.userId;
            commonEventMgr->NotifySandboxAppStatus(info, info.GetUid(userId), userId, SandboxInstallType::UNINSTALL);
        }
    }
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