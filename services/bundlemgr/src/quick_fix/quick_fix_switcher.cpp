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

#include "quick_fix_switcher.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_mgr_service.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixSwitcher::QuickFixSwitcher(const std::string &bundleName, bool enable)
    : bundleName_(bundleName), enable_(enable)
{
    APP_LOGI("enter QuickFixSwitcher");
}

ErrCode QuickFixSwitcher::Execute()
{
    APP_LOGI("start execute");
    return SwitchQuickFix();
}

ErrCode QuickFixSwitcher::SwitchQuickFix()
{
    ErrCode result = enable_ ? EnableQuickFix(bundleName_) : DisableQuickFix(bundleName_);
    if (result != ERR_OK) {
        APP_LOGE("SwitchQuickFix failed");
    }

    return result;
}

ErrCode QuickFixSwitcher::EnableQuickFix(const std::string &bundleName)
{
    if (bundleName.empty()) {
        APP_LOGE("EnableQuickFix failed due to empty bundleName");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    // enable is true, obtain patch from db to replace the current patch
    if (GetQuickFixDataMgr() != ERR_OK) {
        APP_LOGE("quickFixDataMgr is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    InnerAppQuickFix innerAppQuickFix;
    if (!quickFixDataMgr_->QueryInnerAppQuickFix(bundleName, innerAppQuickFix)) {
        APP_LOGE("no patch in the db");
        return ERR_BUNDLEMANAGER_QUICK_FIX_NO_PATCH_IN_DATABASE;
    }
    // start to switch patch
    if (!quickFixDataMgr_->UpdateQuickFixStatus(QuickFixStatus::SWITCH_START, innerAppQuickFix)) {
        APP_LOGE("update quickfix status %{public}d failed", QuickFixStatus::SWITCH_START);
        return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATCH_STATUS;
    }
    // rollback quick fix in db
    ScopeGuard stateGuard([&] {
        innerAppQuickFix.SwitchQuickFix();
        quickFixDataMgr_->UpdateQuickFixStatus(QuickFixStatus::DEPLOY_END, innerAppQuickFix);
    });

    innerAppQuickFix.SwitchQuickFix();
    ErrCode res = InnerSwitchQuickFix(bundleName, innerAppQuickFix, true);
    if (res != ERR_OK) {
        APP_LOGE("InnerSwitchQuickFix failed");
        return res;
    }
    stateGuard.Dismiss();
    return res;
}

ErrCode QuickFixSwitcher::DisableQuickFix(const std::string &bundleName)
{
    if (bundleName.empty()) {
        APP_LOGE("DisableQuickFix failed due to empty bundleName");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    InnerAppQuickFix innerAppQuickFix;
    return InnerSwitchQuickFix(bundleName, innerAppQuickFix, false);
}

ErrCode QuickFixSwitcher::InnerSwitchQuickFix(const std::string &bundleName, const InnerAppQuickFix &innerAppQuickFix,
    bool enable)
{
    APP_LOGD("InnerSwitchQuickFix start with bundleName: %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("InnerSwitchQuickFix failed due to empty bundleName");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }

    if (GetDataMgr() != ERR_OK) {
        APP_LOGE("obtain data mgr failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    InnerBundleInfo innerBundleInfo;
    if (!dataMgr_->GetInnerBundleInfo(bundleName, innerBundleInfo)) {
        APP_LOGE("cannot obtain the innerbundleInfo from data mgr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_NOT_EXISTED_BUNDLE_INFO;
    }
    dataMgr_->EnableBundle(bundleName);
    // utilize rbAppqfInfo to rollback
    AppqfInfo rbAppqfInfo = innerBundleInfo.GetAppqfInfo();
    if (!enable && rbAppqfInfo.hqfInfos.empty()) {
        APP_LOGE("no patch info to be disabled");
        return ERR_BUNDLEMANAGER_QUICK_FIX_NO_PATCH_INFO_IN_BUNDLE_INFO;
    }
    InnerAppQuickFix oldInnerAppQuickFix;
    auto errCode = CreateInnerAppqf(innerBundleInfo, QuickFixStatus::SWITCH_START, enable, oldInnerAppQuickFix);
    if (errCode != ERR_OK) {
        APP_LOGE("CreateInnerAppqf failed");
        return errCode;
    }
    innerBundleInfo.SetAppqfInfo(innerAppQuickFix.GetAppQuickFix().deployedAppqfInfo);
    if (!dataMgr_->UpdateQuickFixInnerBundleInfo(bundleName, innerBundleInfo)) {
        APP_LOGE("update quickfix innerbundleInfo failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    // rollback inner bundle info in db and memory
    ScopeGuard innerBundleInfoGuard([&] {
        innerBundleInfo.SetAppqfInfo(rbAppqfInfo);
        dataMgr_->UpdateQuickFixInnerBundleInfo(bundleName, innerBundleInfo);
    });

    if (GetQuickFixDataMgr() != ERR_OK) {
        APP_LOGE("quickFixDataMgr is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    if (!quickFixDataMgr_->UpdateQuickFixStatus(QuickFixStatus::SWITCH_END, oldInnerAppQuickFix)) {
        APP_LOGE("update quickfix status %{public}d failed", QuickFixStatus::SWITCH_END);
        return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATCH_STATUS;
    }
    innerBundleInfoGuard.Dismiss();
    return ERR_OK;
}

ErrCode QuickFixSwitcher::CreateInnerAppqf(const InnerBundleInfo &innerBundleInfo,
    const QuickFixStatus &status, bool enable, InnerAppQuickFix &innerAppQuickFix)
{
    std::string bundleName = innerBundleInfo.GetBundleName();
    APP_LOGD("CreateInnerAppqf start with bundleName: %{public}s", bundleName.c_str());

    InnerAppQuickFix innerAppqf;
    if (GetQuickFixDataMgr() != ERR_OK) {
        APP_LOGE("quickFixDataMgr_ is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    auto res = quickFixDataMgr_->QueryInnerAppQuickFix(bundleName, innerAppqf);
    // old patch or reload in db will lead failure to create innerAppqf
    if (res && !innerAppqf.GetAppQuickFix().deployedAppqfInfo.hqfInfos.empty()) {
        APP_LOGE("CreateInnerAppqf failed due to some old patch or hot reload in db");
        return ERR_BUNDLEMANAGER_QUICK_FIX_OLD_PATCH_OR_HOT_RELOAD_IN_DB;
    }

    AppQuickFix appQuickFix;
    appQuickFix.bundleName = bundleName;
    appQuickFix.deployedAppqfInfo = innerBundleInfo.GetAppqfInfo();

    if (!enable && res) {
        appQuickFix.deployingAppqfInfo = innerAppqf.GetAppQuickFix().deployingAppqfInfo;
    }
    QuickFixMark fixMark = { .status = status };
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    innerAppQuickFix.SetQuickFixMark(fixMark);
    return ERR_OK;
}

ErrCode QuickFixSwitcher::GetQuickFixDataMgr()
{
    if (quickFixDataMgr_ == nullptr) {
        quickFixDataMgr_ = DelayedSingleton<QuickFixDataMgr>::GetInstance();
        if (quickFixDataMgr_ == nullptr) {
            APP_LOGE("quickFixDataMgr_ is nullptr");
            return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode QuickFixSwitcher::GetDataMgr()
{
    if (dataMgr_ == nullptr) {
        dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr_ == nullptr) {
            APP_LOGE("dataMgr_ is nullptr");
            return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
        }
    }
    return ERR_OK;
}
} // AppExecFwk
} // OHOS