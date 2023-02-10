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

#include "bundle_overlay_manager_host_impl.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_overlay_manager.h"
#include "bundle_util.h"

namespace OHOS {
namespace AppExecFwk {
OverlayManagerHostImpl::OverlayManagerHostImpl()
{
    APP_LOGI("create OverlayManagerHostImpl");
}

OverlayManagerHostImpl::~OverlayManagerHostImpl()
{
    APP_LOGI("destory OverlayManagerHostImpl");
}

ErrCode OverlayManagerHostImpl::GetAllOverlayModuleInfo(const std::string &bundleName,
    std::vector<OverlayModuleInfo> &overlayModuleInfo, int32_t userId)
{
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);
    return BundleOverlayManager::GetInstance()->GetAllOverlayModuleInfo(bundleName, overlayModuleInfo, userId);
}

ErrCode OverlayManagerHostImpl::GetOverlayModuleInfo(const std::string &bundleName, const std::string &moduleName,
    OverlayModuleInfo &overlayModuleInfo, int32_t userId)
{
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);
    return BundleOverlayManager::GetInstance()->GetOverlayModuleInfo(bundleName, moduleName, overlayModuleInfo, userId);
}

ErrCode OverlayManagerHostImpl::GetOverlayBundleInfoForTarget(const std::string &targetBundleName,
    std::vector<OverlayBundleInfo> &overlayBundleInfo, int32_t userId)
{
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);
    return BundleOverlayManager::GetInstance()->
        GetOverlayBundleInfoForTarget(targetBundleName, overlayBundleInfo, userId);
}

ErrCode OverlayManagerHostImpl::GetOverlayModuleInfoForTarget(const std::string &targetBundleName,
    const std::string &targetModuleName, std::vector<OverlayModuleInfo> &overlayModuleInfo, int32_t userId)
{
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);
    return BundleOverlayManager::GetInstance()->GetOverlayModuleInfoForTarget(targetBundleName, targetModuleName,
        overlayModuleInfo, userId);
}
} // AppExecFwk
} // OHOS
