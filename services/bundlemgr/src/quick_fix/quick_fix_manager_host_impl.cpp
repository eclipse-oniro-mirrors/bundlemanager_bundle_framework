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

#include "quick_fix_manager_host_impl.h"

#include "app_log_tag_wrapper.h"
#include "bundle_permission_mgr.h"
#include "bundle_util.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixManagerHostImpl::QuickFixManagerHostImpl()
{
    LOG_I(BMS_TAG_DEFAULT, "create QuickFixManagerHostImpl");
}

QuickFixManagerHostImpl::~QuickFixManagerHostImpl()
{
    LOG_I(BMS_TAG_DEFAULT, "destory QuickFixManagerHostImpl");
}

ErrCode QuickFixManagerHostImpl::DeployQuickFix(const std::vector<std::string> &bundleFilePaths,
    const sptr<IQuickFixStatusCallback> &statusCallback, bool isDebug, const std::string &targetPath,
    bool isReplace)
{
    LOG_I(BMS_TAG_DEFAULT, "QuickFixManagerHostImpl::DeployQuickFix start");
    if (bundleFilePaths.empty() || (statusCallback == nullptr)) {
        LOG_E(BMS_TAG_DEFAULT, "QuickFixManagerHostImpl::DeployQuickFix wrong parms");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_DEFAULT, "non-system app is not allowed call this function");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_QUICK_FIX_BUNDLE)) {
        LOG_E(BMS_TAG_DEFAULT, "verify install permission failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PERMISSION_DENIED;
    }
    if (!GetQuickFixMgr()) {
        LOG_E(BMS_TAG_DEFAULT, "QuickFixManagerHostImpl::DeployQuickFix quickFixerMgr is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    std::vector<std::string> securityFilePaths;
    ErrCode result = CopyHqfToSecurityDir(bundleFilePaths, securityFilePaths);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "copy file to secure dir failed %{public}d", result);
        return result;
    }
    return quickFixMgr_->DeployQuickFix(securityFilePaths, statusCallback, isDebug, targetPath, isReplace);
}

ErrCode QuickFixManagerHostImpl::SwitchQuickFix(const std::string &bundleName, bool enable,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    LOG_I(BMS_TAG_DEFAULT, "QuickFixManagerHostImpl::SwitchQuickFix start");
    if (bundleName.empty() || (statusCallback == nullptr)) {
        LOG_E(BMS_TAG_DEFAULT, "QuickFixManagerHostImpl::SwitchQuickFix wrong parms");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_DEFAULT, "non-system app is not allowed call this function");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_QUICK_FIX_BUNDLE)) {
        LOG_E(BMS_TAG_DEFAULT, "verify install permission failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PERMISSION_DENIED;
    }
    if (!GetQuickFixMgr()) {
        LOG_E(BMS_TAG_DEFAULT, "QuickFixManagerHostImpl::SwitchQuickFix quickFixerMgr is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    return quickFixMgr_->SwitchQuickFix(bundleName, enable, statusCallback);
}

ErrCode QuickFixManagerHostImpl::DeleteQuickFix(const std::string &bundleName,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    LOG_I(BMS_TAG_DEFAULT, "QuickFixManagerHostImpl::DeleteQuickFix start");
    if (bundleName.empty() || (statusCallback == nullptr)) {
        LOG_E(BMS_TAG_DEFAULT, "QuickFixManagerHostImpl::DeleteQuickFix wrong parms");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_DEFAULT, "non-system app is not allowed call this function");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_UNINSTALL_QUICK_FIX_BUNDLE)) {
        LOG_E(BMS_TAG_DEFAULT, "verify install permission failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PERMISSION_DENIED;
    }
    if (!GetQuickFixMgr()) {
        LOG_E(BMS_TAG_DEFAULT, "QuickFixManagerHostImpl::DeleteQuickFix quickFixerMgr is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    return quickFixMgr_->DeleteQuickFix(bundleName, statusCallback);
}

ErrCode QuickFixManagerHostImpl::CreateFd(const std::string &fileName, int32_t &fd, std::string &path)
{
    LOG_D(BMS_TAG_DEFAULT, "QuickFixManagerHostImpl::CreateFd start");
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_DEFAULT, "non-system app is not allowed call this function");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_QUICK_FIX_BUNDLE)) {
        LOG_E(BMS_TAG_DEFAULT, "verify install permission failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PERMISSION_DENIED;
    }
    if (!BundleUtil::CheckFileType(fileName, ServiceConstants::QUICK_FIX_FILE_SUFFIX)) {
        LOG_E(BMS_TAG_DEFAULT, "not quick fix file");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    if (!IsFileNameValid(fileName)) {
        LOG_E(BMS_TAG_DEFAULT, "invalid fileName");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    std::string tmpDir = BundleUtil::CreateInstallTempDir(++id_, DirType::QUICK_FIX_DIR);
    if (tmpDir.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "create tmp dir failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_CREATE_TARGET_DIR_FAILED;
    }
    path = tmpDir + fileName;
    if ((fd = BundleUtil::CreateFileDescriptor(path, 0)) < 0) {
        LOG_E(BMS_TAG_DEFAULT, "create file descriptor failed");
        BundleUtil::DeleteDir(tmpDir);
        return ERR_BUNDLEMANAGER_QUICK_FIX_CREATE_FD_FAILED;
    }
    return ERR_OK;
}

bool QuickFixManagerHostImpl::GetQuickFixMgr()
{
    if (quickFixMgr_ == nullptr) {
        quickFixMgr_ = std::make_shared<QuickFixMgr>();
    }
    return true;
}

bool QuickFixManagerHostImpl::IsFileNameValid(const std::string &fileName) const
{
    if (fileName.find("..") != std::string::npos
        || fileName.find("/") != std::string::npos
        || fileName.find("\\") != std::string::npos
        || fileName.find("%") != std::string::npos) {
        return false;
    }
    return true;
}

ErrCode QuickFixManagerHostImpl::CopyHqfToSecurityDir(const std::vector<std::string> &bundleFilePaths,
    std::vector<std::string> &securityFilePaths) const
{
    LOG_D(BMS_TAG_DEFAULT, "start to copy hqf files to securityFilePaths");
    std::string prefixStr = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR
        + ServiceConstants::QUICK_FIX_PATH;
    for (const auto &path : bundleFilePaths) {
        if (path.find(ServiceConstants::RELATIVE_PATH) != std::string::npos) {
            LOG_E(BMS_TAG_DEFAULT, "invalid hqf path %{public}s", path.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATH;
        }
        if (path.find(prefixStr) != 0) {
            LOG_E(BMS_TAG_DEFAULT, "invalid hqf path %{public}s", path.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATH;
        }
        std::string securityPathPrefix = std::string(ServiceConstants::HAP_COPY_PATH) +
            ServiceConstants::PATH_SEPARATOR +
            ServiceConstants::SECURITY_QUICK_FIX_PATH;
        std::string securityPath = path;
        securityPath.replace(0, prefixStr.length(), securityPathPrefix);

        auto pos = securityPath.rfind(ServiceConstants::PATH_SEPARATOR);
        if (pos == std::string::npos) {
            return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATH;
        }
        std::string secureDir = securityPath.substr(0, pos);
        if (!BundleUtil::CreateDir(secureDir)) {
            return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
        }
        LOG_D(BMS_TAG_DEFAULT, "copy hqf file from path(%{public}s) to securePath(%{public}s)",
            path.c_str(), securityPath.c_str());
        if (!BundleUtil::CopyFile(path, securityPath)) {
            LOG_E(BMS_TAG_DEFAULT, "CopyFile failed");
            return ERR_BUNDLEMANAGER_QUICK_FIX_MOVE_PATCH_FILE_FAILED;
        }
        securityFilePaths.emplace_back(securityPath);
    }
    BundleUtil::DeleteDir(prefixStr);
    return ERR_OK;
}
}
} // namespace OHOS
