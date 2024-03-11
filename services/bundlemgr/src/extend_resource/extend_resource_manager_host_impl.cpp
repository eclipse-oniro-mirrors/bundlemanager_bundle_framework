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

#include "extend_resource_manager_host_impl.h"

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
ExtendResourceManagerHostImpl::ExtendResourceManagerHostImpl()
{
    APP_LOGI("create ExtendResourceManagerHostImpl.");
}

ExtendResourceManagerHostImpl::~ExtendResourceManagerHostImpl()
{
    APP_LOGI("destroy ExtendResourceManagerHostImpl.");
}

ErrCode ExtendResourceManagerHostImpl::AddExtResource(
    const std::string &bundleName, const std::vector<std::string> &filePaths)
{
    if (bundleName.empty() || filePaths.empty()) {
        APP_LOGE("fail to AddExtResource due to param is empty.");
        return ERR_EXT_RESOURCE_MANAGER_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(
        Constants::PERMISSION_INSTALL_BUNDLE)) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode ExtendResourceManagerHostImpl::RemoveExtResource(
    const std::string &bundleName, const std::vector<std::string> &moduleNames)
{
    if (bundleName.empty() || moduleNames.empty()) {
        APP_LOGE("fail to RemoveExtResource due to param is empty.");
        return ERR_EXT_RESOURCE_MANAGER_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(
        Constants::PERMISSION_INSTALL_BUNDLE)) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode ExtendResourceManagerHostImpl::GetExtResource(
    const std::string &bundleName, std::vector<std::string> &moduleNames)
{
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(
        Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode ExtendResourceManagerHostImpl::EnableDynamicIcon(
    const std::string &bundleName, const std::string &moduleName)
{
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("fail to EnableDynamicIcon due to param is empty.");
        return ERR_EXT_RESOURCE_MANAGER_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(
        Constants::PERMISSION_ACCESS_DYNAMIC_ICON)) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode ExtendResourceManagerHostImpl::DisableDynamicIcon(const std::string &bundleName)
{
    if (bundleName.empty()) {
        APP_LOGE("fail to DisableDynamicIcon due to param is empty.");
        return ERR_EXT_RESOURCE_MANAGER_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(
        Constants::PERMISSION_ACCESS_DYNAMIC_ICON)) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode ExtendResourceManagerHostImpl::GetDynamicIcon(
    const std::string &bundleName, std::string &moudleName)
{
    if (bundleName.empty()) {
        APP_LOGE("fail to GetDynamicIcon due to param is empty.");
        return ERR_EXT_RESOURCE_MANAGER_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(
        Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode ExtendResourceManagerHostImpl::CreateFd(
    const std::string &fileName, int32_t &fd, std::string &path)
{
    if (fileName.empty()) {
        APP_LOGE("fail to CreateFd due to param is empty.");
        return ERR_EXT_RESOURCE_MANAGER_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(
        Constants::PERMISSION_INSTALL_BUNDLE)) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    return ERR_OK;
}
} // AppExecFwk
} // namespace OHOS
