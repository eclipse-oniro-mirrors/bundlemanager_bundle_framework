/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "install_exception_mgr.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_service_constants.h"
#include "bundle_constants.h"
#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {

InstallExceptionMgr::InstallExceptionMgr()
{
    installExceptionMgr_ = std::make_shared<InstallExceptionMgrRdb>();
}

InstallExceptionMgr::~InstallExceptionMgr()
{
}

ErrCode InstallExceptionMgr::SaveBundleExceptionInfo(
    const std::string &bundleName, const InstallExceptionInfo &installExceptionInfo)
{
    if (installExceptionMgr_ == nullptr) {
        APP_LOGE("installExceptionMgr_ is null");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    return installExceptionMgr_->SaveBundleExceptionInfo(bundleName, installExceptionInfo);
}

ErrCode InstallExceptionMgr::DeleteBundleExceptionInfo(const std::string &bundleName)
{
    if (installExceptionMgr_ == nullptr) {
        APP_LOGE("installExceptionMgr_ is null");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    return installExceptionMgr_->DeleteBundleExceptionInfo(bundleName);
}

void InstallExceptionMgr::HandleBundleExceptionInfo(
    const std::string &bundleName, const InstallExceptionInfo &installExceptionInfo)
{
    APP_LOGI("wtt bundle %{public}s install exception status %{public}d", bundleName.c_str(),
        static_cast<int32_t>(installExceptionInfo.status));
    switch (installExceptionInfo.status) {
        case InstallRenameExceptionStatus::RENAME_RELA_TO_OLD_PATH :
        case InstallRenameExceptionStatus::RENAME_NEW_TO_RELA_PATH : {
            std::string realPath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR +
                bundleName;
            std::string oldPath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR +
                std::string(ServiceConstants::BUNDLE_OLD_CODE_DIR) + bundleName;
            ErrCode result = InstalldClient::GetInstance()->RenameModuleDir(oldPath, realPath);
            if (result == ERR_OK) {
                (void)DeleteBundleExceptionInfo(bundleName);
            } else {
                APP_LOGE("rename module dir failed, error is %{public}d, errno %{public}d", result, errno);
            }
            std::string newPath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR +
                std::string(ServiceConstants::BUNDLE_NEW_CODE_DIR) + bundleName;
            result = InstalldClient::GetInstance()->RemoveDir(newPath);
            if (result != ERR_OK) {
                APP_LOGE("remove dir failed, error is %{public}d, errno %{public}d", result, errno);
            }
            break;
        }
        case InstallRenameExceptionStatus::DELETE_OLD_PATH : {
            std::string oldPath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR +
                std::string(ServiceConstants::BUNDLE_OLD_CODE_DIR) + bundleName;
            ErrCode result = InstalldClient::GetInstance()->RemoveDir(oldPath);
            if (result == ERR_OK) {
                (void)DeleteBundleExceptionInfo(bundleName);
            } else {
                APP_LOGE("remove dir failed, error is %{public}d, errno %{public}d", result, errno);
            }
            break;
        }
        default :
            (void)DeleteBundleExceptionInfo(bundleName);
            APP_LOGE("bundle %{public}s install unknown exception status %{public}d",
                bundleName.c_str(), static_cast<int32_t>(installExceptionInfo.status));
    }
}

void InstallExceptionMgr::HandleAllBundleExceptionInfo()
{
    if (installExceptionMgr_ == nullptr) {
        APP_LOGE("installExceptionMgr_ is null");
        return;
    }
    std::map<std::string, InstallExceptionInfo> bundleExceptionInfos;
    installExceptionMgr_->GetAllBundleExceptionInfo(bundleExceptionInfos);
    for (const auto &exceptionInfo : bundleExceptionInfos) {
        HandleBundleExceptionInfo(exceptionInfo.first, exceptionInfo.second);
    }
}
} // AppExecFwk
} // OHOS
