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
#include "bundle_permission_mgr.h"
#include "bundle_overlay_data_manager.h"
#include "bundle_overlay_manager.h"
#include "bundle_util.h"
#include "ipc_skeleton.h"

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
    if (bundleName.empty()) {
        APP_LOGE("invalid param");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);
    if (!VerifyQueryPermission(bundleName, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("no permission to query overlay info of bundleName %{public}s", bundleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
    }
    return BundleOverlayManager::GetInstance()->GetAllOverlayModuleInfo(bundleName, overlayModuleInfo, userId);
}

ErrCode OverlayManagerHostImpl::GetOverlayModuleInfo(const std::string &bundleName, const std::string &moduleName,
    OverlayModuleInfo &overlayModuleInfo, int32_t userId)
{
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("invalid param");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);

    if (!VerifyQueryPermission(bundleName, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("no permission to query overlay info of bundleName %{public}s", bundleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
    }
    return BundleOverlayManager::GetInstance()->GetOverlayModuleInfo(bundleName, moduleName, overlayModuleInfo, userId);
}

ErrCode OverlayManagerHostImpl::GetOverlayBundleInfoForTarget(const std::string &targetBundleName,
    std::vector<OverlayBundleInfo> &overlayBundleInfo, int32_t userId)
{
    if (targetBundleName.empty()) {
        APP_LOGE("invalid param");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);
    if (!VerifyQueryPermission(targetBundleName, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("no permission to query overlay info of targetBundleName %{public}s", targetBundleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
    }
    return BundleOverlayManager::GetInstance()->
        GetOverlayBundleInfoForTarget(targetBundleName, overlayBundleInfo, userId);
}

ErrCode OverlayManagerHostImpl::GetOverlayModuleInfoForTarget(const std::string &targetBundleName,
    const std::string &targetModuleName, std::vector<OverlayModuleInfo> &overlayModuleInfo, int32_t userId)
{
    if (targetBundleName.empty() || targetModuleName.empty()) {
        APP_LOGE("invalid param");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);

    if (!VerifyQueryPermission(targetBundleName, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("no permission to query overlay info of targetBundleName %{public}s", targetBundleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
    }
    return BundleOverlayManager::GetInstance()->GetOverlayModuleInfoForTarget(targetBundleName, targetModuleName,
        overlayModuleInfo, userId);
}

ErrCode OverlayManagerHostImpl::SetOverlayEnabled(const std::string &bundleName, const std::string &moduleName,
    bool isEnabled, int32_t userId)
{
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("invalid param");
        return ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);
    if (!VerifyQueryPermission(bundleName, Constants::PERMISSION_CHANGE_OVERLAY_ENABLED_STATE)) {
        APP_LOGE("no permission to query overlay info of bundleName %{public}s", bundleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
    }
    return BundleOverlayManager::GetInstance()->SetOverlayEnabled(bundleName, moduleName, isEnabled, userId);
}

bool OverlayManagerHostImpl::VerifyQueryPermission(const std::string &queryBundleName,
    const std::string &permission) const
{
    std::string callingBundleName = OverlayDataMgr::GetInstance()->GetCallingBundleName();
    if (queryBundleName == callingBundleName) {
        APP_LOGD("query own info, verify success");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(permission)) {
        APP_LOGE("verify query permission failed");
        return false;
    }
    APP_LOGD("verify query permission successfully");
    return true;
}
} // AppExecFwk
} // OHOS
