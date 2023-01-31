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

#include "bundle_overlay_data_manager.h"
#include "bundle_overlay_manager.h"

namespace OHOS {
namespace AppExecFwk {
bool BundleOverlayManager::IsExistedNonOverlayHap(const std::string &bundleName)
{
    APP_LOGI("overlayManager query if the bundle contain non overlay hap");
    if (bundleName.empty()) {
        APP_LOGE("invalid bundleName for checking whether non-overlay hap in the bundle");
        return false;
    }
    return OverlayDataMgr::GetInstance()->IsExistedNonOverlayHap(bundleName);
}

bool BundleOverlayManager::GetInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &info)
{
    APP_LOGI("start get inner bundleInfo");
    if (bundleName.empty()) {
        APP_LOGE("invalid bundleName for get innerBundleInfo");
        return false;
    }

    bool result = OverlayDataMgr::GetInstance()->GetOverlayInnerBundleInfo(bundleName, info);
    if (result) {
        OverlayDataMgr::GetInstance()->EnableOverlayBundle(bundleName);
    }

    return result;
}
} // AppExecFwk
} // OHOS