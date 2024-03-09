/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "dynamic_icon_manager_host_impl.h"

#include <fcntl.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_util.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
DynamicIconManagerHostImpl::DynamicIconManagerHostImpl()
{
    APP_LOGI("create DynamicIconManagerHostImpl.");
}

DynamicIconManagerHostImpl::~DynamicIconManagerHostImpl()
{
    APP_LOGI("destroy DynamicIconManagerHostImpl.");
}

ErrCode DynamicIconManagerHostImpl::EnableDynamicIcon(const std::string &bundleName,
    const std::string &dynamicIconKey, const std::string &filePath)
{
    if (bundleName.empty() || dynamicIconKey.empty() || filePath.empty()) {
        APP_LOGE("fail to EnableDynamicIcon due to param is empty.");
        return ERR_BUNDLE_MANAGER_DYNAMIC_ICON_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_ACCESS_DYNAMIC_ICON})) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode DynamicIconManagerHostImpl::DisableDynamicIcon(const std::string &bundleName)
{
    if (bundleName.empty()) {
        APP_LOGE("fail to DisableDynamicIcon due to param is empty.");
        return ERR_BUNDLE_MANAGER_DYNAMIC_ICON_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_ACCESS_DYNAMIC_ICON})) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode DynamicIconManagerHostImpl::GetDynamicIcon(
    const std::string &bundleName, std::string &dynamicIconKey)
{
    if (bundleName.empty()) {
        APP_LOGE("fail to GetDynamicIcon due to param is empty.");
        return ERR_BUNDLE_MANAGER_DYNAMIC_ICON_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_ACCESS_DYNAMIC_ICON})) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode DynamicIconManagerHostImpl::CreateFd(const std::string &fileName, int32_t &fd, std::string &path)
{
    if (fileName.empty()) {
        APP_LOGE("fail to CreateFd due to param is empty.");
        return ERR_BUNDLE_MANAGER_DYNAMIC_ICON_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_ACCESS_DYNAMIC_ICON})) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    return ERR_OK;
}
} // AppExecFwk
} // namespace OHOS
