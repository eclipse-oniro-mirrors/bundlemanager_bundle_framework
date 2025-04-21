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
#include "bundle_mgr_service.h"
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
    APP_LOGI("bundle %{public}s install exception status %{public}d", bundleName.c_str(),
        static_cast<int32_t>(installExceptionInfo.status));
    switch (installExceptionInfo.status) {
        case InstallRenameExceptionStatus::RENAME_RELA_TO_OLD_PATH :
        case InstallRenameExceptionStatus::RENAME_NEW_TO_RELA_PATH : {
            InnerBundleInfo bundleInfo;
            auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
            if ((dataMgr != nullptr) && (!dataMgr->FetchInnerBundleInfo(bundleName, bundleInfo))) {
                APP_LOGW("bundle %{public}s not exist", bundleName.c_str());
            }
            if (bundleInfo.GetVersionCode() <= installExceptionInfo.versionCode) {
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
                return;
            }
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
            APP_LOGE("bundle %{public}s install unknown exception status %{public}d",
                bundleName.c_str(), static_cast<int32_t>(installExceptionInfo.status));
            (void)DeleteBundleExceptionInfo(bundleName);
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
    // process +old- +new- path throw scan code path
    std::vector<std::string> allCodePath;
    ErrCode result = InstalldClient::GetInstance()->ScanDir(Constants::BUNDLE_CODE_DIR,
        ScanMode::SUB_FILE_DIR, ResultMode::RELATIVE_PATH, allCodePath);
    if (result != ERR_OK) {
        APP_LOGW("ScanDir code path failed");
        return;
    }
    for (const auto &codePath : allCodePath) {
        if (codePath.find(ServiceConstants::BUNDLE_OLD_CODE_DIR) == 0) {
            APP_LOGI("+old- code path %{public}s", codePath.c_str());
            std::string bundleName = codePath.substr(std::string(ServiceConstants::BUNDLE_OLD_CODE_DIR).size());
            if (bundleName.empty()) {
                continue;
            }
            std::string oldCodePath = std::string(Constants::BUNDLE_CODE_DIR) +
                ServiceConstants::PATH_SEPARATOR + codePath;
            std::string realCodePath = std::string(Constants::BUNDLE_CODE_DIR) +
                ServiceConstants::PATH_SEPARATOR + bundleName;
            ErrCode result = InstalldClient::GetInstance()->RenameModuleDir(oldCodePath, realCodePath);
            if (result != ERR_OK) {
                APP_LOGW("rename +old- to real code path failed, error is %{public}d", result);
            }
            continue;
        }
        if (codePath.find(ServiceConstants::BUNDLE_NEW_CODE_DIR) == 0) {
            APP_LOGI("+new- code path %{public}s", codePath.c_str());
            std::string newCodePath = std::string(Constants::BUNDLE_CODE_DIR) +
                ServiceConstants::PATH_SEPARATOR + codePath;
            (void)InstalldClient::GetInstance()->RemoveDir(newCodePath);
        }
    }
}
} // AppExecFwk
} // OHOS
