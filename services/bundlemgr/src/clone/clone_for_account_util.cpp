/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "clone_for_account_util.h"

#include "app_log_tag_wrapper.h"
#include "bundle_constants.h"
#include "inner_bundle_info.h"
#include "inner_bundle_user_info.h"

namespace OHOS {
namespace AppExecFwk {

int32_t CloneForAccountUtil::GetEnabledCloneAppIndex(const InnerBundleInfo &innerBundleInfo,
    int32_t responseUserId)
{
    if (responseUserId == Constants::INVALID_USERID) {
        return Constants::ALL_CLONE_APP_INDEX;
    }

    const InnerBundleUserInfo *bundleUserInfoPtr = nullptr;
    (void)innerBundleInfo.GetInnerBundleUserInfo(responseUserId, bundleUserInfoPtr);
    if (bundleUserInfoPtr == nullptr) {
        return Constants::ALL_CLONE_APP_INDEX;
    }

    // Check if main app is enabled via bundleUserInfo.enabled directly
    if (bundleUserInfoPtr->bundleUserInfo.enabled) {
        return Constants::MAIN_APP_INDEX;
    }

    if (bundleUserInfoPtr->cloneInfos.empty()) {
        return Constants::ALL_CLONE_APP_INDEX;
    }

    for (const auto &cloneItem : bundleUserInfoPtr->cloneInfos) {
        // Check clone enabled status via cloneInfo.enabled directly
        if (cloneItem.second.enabled) {
            return cloneItem.second.appIndex;
        }
    }
    return Constants::ALL_CLONE_APP_INDEX;
}

} // namespace AppExecFwk
} // namespace OHOS