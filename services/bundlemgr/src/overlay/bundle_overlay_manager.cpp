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
    APP_LOGD("start");
    if (bundleName.empty()) {
        APP_LOGE("invalid bundleName");
        return false;
    }
    return OverlayDataMgr::GetInstance()->IsExistedNonOverlayHap(bundleName);
}

bool BundleOverlayManager::GetInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &info)
{
    APP_LOGD("start");
    if (bundleName.empty()) {
        APP_LOGE("invalid bundleName");
        return false;
    }

    return OverlayDataMgr::GetInstance()->QueryOverlayInnerBundleInfo(bundleName, info);
}

ErrCode BundleOverlayManager::GetAllOverlayModuleInfo(const std::string &bundleName,
    std::vector<OverlayModuleInfo> &overlayModuleInfo, int32_t userId)
{
    APP_LOGD("start");
    if (bundleName.empty() || userId == Constants::INVALID_USERID) {
        APP_LOGE("invalid bundleName or userId");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }

    return OverlayDataMgr::GetInstance()->GetAllOverlayModuleInfo(bundleName, overlayModuleInfo, userId);
}

ErrCode BundleOverlayManager::GetOverlayModuleInfo(const std::string &bundleName, const std::string &moduleName,
    OverlayModuleInfo &overlayModuleInfo, int32_t userId)
{
    APP_LOGD("start");
    if (bundleName.empty() || moduleName.empty() || userId == Constants::INVALID_USERID) {
        APP_LOGE("invalid bundleName、moduleName or userId");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }

    return OverlayDataMgr::GetInstance()->GetOverlayModuleInfo(bundleName, moduleName, overlayModuleInfo, userId);
}

ErrCode BundleOverlayManager::GetOverlayBundleInfoForTarget(const std::string &targetBundleName,
    std::vector<OverlayBundleInfo> &overlayBundleInfo, int32_t userId)
{
    APP_LOGD("start");
    if (targetBundleName.empty() || userId == Constants::INVALID_USERID) {
        APP_LOGE("invalid bundleName or userId");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }

    return OverlayDataMgr::GetInstance()->GetOverlayBundleInfoForTarget(targetBundleName, overlayBundleInfo, userId);
}

ErrCode BundleOverlayManager::GetOverlayModuleInfoForTarget(const std::string &targetBundleName,
    const std::string &targetModuleName, std::vector<OverlayModuleInfo> &overlayModuleInfo, int32_t userId)
{
    APP_LOGD("start");
    if (targetBundleName.empty() || userId == Constants::INVALID_USERID) {
        APP_LOGE("invalid bundleName or userId");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }

    return OverlayDataMgr::GetInstance()->GetOverlayModuleInfoForTarget(targetBundleName, targetModuleName,
        overlayModuleInfo, userId);
}

ErrCode BundleOverlayManager::SetOverlayEnabled(const std::string &bundleName, const std::string &moduleName,
    bool isEnabled, int32_t userId)
{
    APP_LOGD("start");
    if (bundleName.empty() || moduleName.empty() || userId == Constants::INVALID_USERID) {
        APP_LOGE("invalid bundleName、moduleName or userId");
        return ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR;
    }
    return OverlayDataMgr::GetInstance()->SetOverlayEnabled(bundleName, moduleName, isEnabled, userId);
}
} // AppExecFwk
} // OHOS