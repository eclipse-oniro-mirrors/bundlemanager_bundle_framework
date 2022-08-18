/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "quick_fix_deleter.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixDeleter::QuickFixDeleter(const std::string &bundleName) : bundleName_(bundleName)
{
    APP_LOGI("enter QuickFixDeleter");
}

ErrCode QuickFixDeleter::Execute()
{
    APP_LOGI("start execute");
    auto ret = DeleteQuickFix();
    if (ret != ERR_OK) {
        APP_LOGE("DeleteQuickFix is failed");
    }
    return ret;
}

ErrCode QuickFixDeleter::DeleteQuickFix()
{
    APP_LOGI("DeleteQuickFix start");
    if (bundleName_.empty()) {
        APP_LOGE("InnerDeleteQuickFix failed due to empty bundleName");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    if (GetQuickFixDataMgr() != ERR_OK) {
        APP_LOGE("quickFixDataMgr is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    InnerAppQuickFix innerAppQuickFix;
    if (!quickFixDataMgr_->QueryInnerAppQuickFix(bundleName_, innerAppQuickFix)) {
        APP_LOGE("no patch in the db");
        return ERR_BUNDLEMANAGER_QUICK_FIX_NO_PATCH_IN_DATABASE;
    }

    if (!quickFixDataMgr_->UpdateQuickFixStatus(QuickFixStatus::DELETE_START, innerAppQuickFix)) {
        APP_LOGE("update quickfix status %{public}d failed", QuickFixStatus::DELETE_START);
        return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATCH_STATUS;
    }

    // to delete patch path
    ErrCode errCode = ToDeletePatchDir(innerAppQuickFix);
    if (errCode != ERR_OK) {
        APP_LOGE("ToDeletePatchDir failed");
        return errCode;
    }

    // to remove old patch info from db
    if (!quickFixDataMgr_->DeleteInnerAppQuickFix(bundleName_)) {
        APP_LOGE("InnerDeleteQuickFix failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    return ERR_OK;
}

ErrCode QuickFixDeleter::ToDeletePatchDir(const InnerAppQuickFix &innerAppQuickFix)
{
    APP_LOGI("start to delete patch dir");
    const auto &appqfInfo = innerAppQuickFix.GetAppQuickFix().deployedAppqfInfo;
    if (appqfInfo.hqfInfos.empty()) {
        APP_LOGD("no patch info in bundleInfo");
        return ERR_OK;
    }

    if (appqfInfo.type == QuickFixType::UNKNOWN) {
        APP_LOGE("unknown quick fix type");
        return ERR_BUNDLEMANAGER_QUICK_FIX_UNKNOWN_QUICK_FIX_TYPE;
    }

    std::string patchPath = Constants::BUNDLE_CODE_DIR;
    if (appqfInfo.type == QuickFixType::PATCH) {
        patchPath += Constants::PATH_SEPARATOR + innerAppQuickFix.GetAppQuickFix().bundleName +
            Constants::PATH_SEPARATOR + Constants::PATCH_PATH + std::to_string(appqfInfo.versionCode);
    }
    if (appqfInfo.type == QuickFixType::HOT_RELOAD) {
        patchPath += Constants::PATH_SEPARATOR + innerAppQuickFix.GetAppQuickFix().bundleName +
            Constants::PATH_SEPARATOR + Constants::HOT_RELOAD_PATH + std::to_string(appqfInfo.versionCode);
    }

    APP_LOGD("patch path is %{public}s", patchPath.c_str());
    if (InstalldClient::GetInstance()->RemoveDir(patchPath) != ERR_OK) {
        APP_LOGE("RemoveDir patch path or hot reload path failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_REMOVE_PATCH_SO_PATH_FAILED;
    }

    return ERR_OK;
}

ErrCode QuickFixDeleter::GetQuickFixDataMgr()
{
    if (quickFixDataMgr_ == nullptr) {
        quickFixDataMgr_ = DelayedSingleton<QuickFixDataMgr>::GetInstance();
        if (quickFixDataMgr_ == nullptr) {
            APP_LOGE("quickFix dataMgr is nullptr");
            return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
        }
    }
    return ERR_OK;
}
} // AppExecFwk
} // OHOS