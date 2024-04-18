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

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_mgr_service.h"
#include "installd_client.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixDeleter::QuickFixDeleter(const std::string &bundleName) : bundleName_(bundleName)
{
    LOG_I(BMS_TAG_QUICK_FIX, "enter QuickFixDeleter");
}

ErrCode QuickFixDeleter::Execute()
{
    LOG_I(BMS_TAG_QUICK_FIX, "start execute");
    auto ret = DeleteQuickFix();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "DeleteQuickFix is failed");
    }
    return ret;
}

ErrCode QuickFixDeleter::DeleteQuickFix()
{
    LOG_I(BMS_TAG_QUICK_FIX, "DeleteQuickFix start");
    if (bundleName_.empty()) {
        LOG_E(BMS_TAG_QUICK_FIX, "InnerDeleteQuickFix failed due to empty bundleName");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    if (GetQuickFixDataMgr() != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "quickFixDataMgr is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    InnerAppQuickFix innerAppQuickFix;
    // 1. query quick fix info form db
    if (!quickFixDataMgr_->QueryInnerAppQuickFix(bundleName_, innerAppQuickFix)) {
        LOG_I(BMS_TAG_QUICK_FIX, "no patch in the db");
        return ERR_OK;
    }
    // 2. update quick fix status
    if (!quickFixDataMgr_->UpdateQuickFixStatus(QuickFixStatus::DELETE_START, innerAppQuickFix)) {
        LOG_E(BMS_TAG_QUICK_FIX, "update quickfix status %{public}d failed", QuickFixStatus::DELETE_START);
        return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATCH_STATUS;
    }
    // 3. utilize stateGuard to rollback quick fix info status in db
    ScopeGuard stateGuard([&] {
        quickFixDataMgr_->UpdateQuickFixStatus(QuickFixStatus::SWITCH_END, innerAppQuickFix);
    });

    // 4. to delete patch path
    ErrCode errCode = ToDeletePatchDir(innerAppQuickFix);
    if (errCode != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "ToDeletePatchDir failed");
        return errCode;
    }
    // 5. to remove deployingAppqfInfo from cache
    errCode = RemoveDeployingInfo(bundleName_);
    if (errCode != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "RemoveDeployingInfo failed");
        return errCode;
    }
    // 6. to remove old patch info from db
    if (!quickFixDataMgr_->DeleteInnerAppQuickFix(bundleName_)) {
        LOG_E(BMS_TAG_QUICK_FIX, "InnerDeleteQuickFix failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    stateGuard.Dismiss();
    return ERR_OK;
}

ErrCode QuickFixDeleter::ToDeletePatchDir(const InnerAppQuickFix &innerAppQuickFix)
{
    LOG_I(BMS_TAG_QUICK_FIX, "start to delete patch dir");
    std::string bundleName = innerAppQuickFix.GetAppQuickFix().bundleName;
    auto res = InnerDeletePatchDir(innerAppQuickFix.GetAppQuickFix().deployedAppqfInfo, bundleName);
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "delete patch dir of deployedAppqfInfo failed");
        return res;
    }
    res = InnerDeletePatchDir(innerAppQuickFix.GetAppQuickFix().deployingAppqfInfo, bundleName);
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "delete patch dir of deployingAppqfInfo failed");
        return res;
    }
    return ERR_OK;
}

ErrCode QuickFixDeleter::InnerDeletePatchDir(const AppqfInfo &appqfInfo, const std::string &bundleName)
{
    if (appqfInfo.hqfInfos.empty()) {
        LOG_D(BMS_TAG_QUICK_FIX, "no patch info in bundleInfo");
        return ERR_OK;
    }

    if (appqfInfo.type == QuickFixType::UNKNOWN) {
        LOG_E(BMS_TAG_QUICK_FIX, "unknown quick fix type");
        return ERR_BUNDLEMANAGER_QUICK_FIX_UNKNOWN_QUICK_FIX_TYPE;
    }

    std::string patchPath = Constants::BUNDLE_CODE_DIR;
    if (appqfInfo.type == QuickFixType::PATCH) {
        patchPath += Constants::PATH_SEPARATOR + bundleName + Constants::PATH_SEPARATOR + Constants::PATCH_PATH +
            std::to_string(appqfInfo.versionCode);
    }
    if (appqfInfo.type == QuickFixType::HOT_RELOAD) {
        patchPath += Constants::PATH_SEPARATOR + bundleName + Constants::PATH_SEPARATOR + Constants::HOT_RELOAD_PATH +
            std::to_string(appqfInfo.versionCode);
    }

    LOG_D(BMS_TAG_QUICK_FIX, "patch path is %{public}s", patchPath.c_str());
    if (InstalldClient::GetInstance()->RemoveDir(patchPath) != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "RemoveDir patch path or hot reload path failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_REMOVE_PATCH_PATH_FAILED;
    }

    return ERR_OK;
}

ErrCode QuickFixDeleter::GetQuickFixDataMgr()
{
    if (quickFixDataMgr_ == nullptr) {
        quickFixDataMgr_ = DelayedSingleton<QuickFixDataMgr>::GetInstance();
        if (quickFixDataMgr_ == nullptr) {
            LOG_E(BMS_TAG_QUICK_FIX, "quickFix dataMgr is nullptr");
            return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode QuickFixDeleter::GetDataMgr()
{
    if (dataMgr_ == nullptr) {
        dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr_ == nullptr) {
            LOG_E(BMS_TAG_QUICK_FIX, "dataMgr_ is nullptr");
            return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode QuickFixDeleter::RemoveDeployingInfo(const std::string &bundleName)
{
    if (GetDataMgr() != ERR_OK) {
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    InnerBundleInfo innerBundleInfo;
    auto isExisted = dataMgr_->GetInnerBundleInfo(bundleName, innerBundleInfo);
    if (isExisted) {
        AppQuickFix appQuickFix = innerBundleInfo.GetAppQuickFix();
        if (appQuickFix.deployingAppqfInfo.hqfInfos.empty()) {
            dataMgr_->EnableBundle(bundleName_);
            return ERR_OK;
        }
        appQuickFix.deployingAppqfInfo = AppqfInfo();
        innerBundleInfo.SetAppQuickFix(appQuickFix);
        innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
        if (!dataMgr_->UpdateQuickFixInnerBundleInfo(bundleName, innerBundleInfo)) {
            LOG_E(BMS_TAG_QUICK_FIX, "update quickfix innerbundleInfo failed");
            return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
        }
    }
    return ERR_OK;
}
} // AppExecFwk
} // OHOS