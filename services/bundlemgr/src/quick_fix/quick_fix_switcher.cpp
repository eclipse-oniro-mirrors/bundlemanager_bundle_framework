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

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_mgr_service.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixSwitcher::QuickFixSwitcher(const std::string &bundleName, bool enable)
    : bundleName_(bundleName), enable_(enable)
{
    LOG_I(BMS_TAG_QUICK_FIX, "enter QuickFixSwitcher");
}

ErrCode QuickFixSwitcher::Execute()
{
    LOG_I(BMS_TAG_QUICK_FIX, "start execute");
    return SwitchQuickFix();
}

ErrCode QuickFixSwitcher::SwitchQuickFix()
{
    ErrCode result = enable_ ? EnableQuickFix(bundleName_) : DisableQuickFix(bundleName_);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "SwitchQuickFix failed");
    }

    return result;
}

ErrCode QuickFixSwitcher::EnableQuickFix(const std::string &bundleName)
{
    if (bundleName.empty()) {
        LOG_E(BMS_TAG_QUICK_FIX, "EnableQuickFix failed due to empty bundleName");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    // enable is true, obtain quick fix info from db to replace the current patch
    if (GetQuickFixDataMgr() != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "quickFixDataMgr is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    InnerAppQuickFix innerAppQuickFix;
    // 1. query quick fix info from db
    if (!quickFixDataMgr_->QueryInnerAppQuickFix(bundleName, innerAppQuickFix)) {
        LOG_E(BMS_TAG_QUICK_FIX, "no patch in the db");
        return ERR_BUNDLEMANAGER_QUICK_FIX_NO_PATCH_IN_DATABASE;
    }
    // 2. update status in db and start to switch patch
    if (!quickFixDataMgr_->UpdateQuickFixStatus(QuickFixStatus::SWITCH_ENABLE_START, innerAppQuickFix)) {
        LOG_E(BMS_TAG_QUICK_FIX, "update quickfix status %{public}d failed", QuickFixStatus::SWITCH_ENABLE_START);
        return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATCH_STATUS;
    }
    // 3. utilize stateGuard to rollback quick fix in db
    ScopeGuard stateGuard([&] {
        innerAppQuickFix.SwitchQuickFix();
        quickFixDataMgr_->UpdateQuickFixStatus(QuickFixStatus::DEPLOY_END, innerAppQuickFix);
    });

    innerAppQuickFix.SwitchQuickFix();
    ErrCode res = InnerSwitchQuickFix(bundleName, innerAppQuickFix, true);
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "InnerSwitchQuickFix failed");
        return res;
    }
    stateGuard.Dismiss();
    return ERR_OK;
}

ErrCode QuickFixSwitcher::DisableQuickFix(const std::string &bundleName)
{
    if (bundleName.empty()) {
        LOG_E(BMS_TAG_QUICK_FIX, "DisableQuickFix failed due to empty bundleName");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }
    if (GetQuickFixDataMgr() != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "quickFixDataMgr is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    InnerAppQuickFix innerAppQuickFix;
    // 1. query quick fix info from db, if quick fix info exists, use it to disable quick fix
    bool isExisted = quickFixDataMgr_->QueryInnerAppQuickFix(bundleName, innerAppQuickFix);
    if (!isExisted) {
        LOG_W(BMS_TAG_QUICK_FIX, "no patch in the db");
        // 1.1 if quick fix info does not exist, use the temporary quick fix info to mark disable-status in db
        QuickFixMark fixMark = { .status = QuickFixStatus::DEPLOY_END };
        AppQuickFix appQuickFix;
        appQuickFix.bundleName = bundleName;
        innerAppQuickFix.SetAppQuickFix(appQuickFix);
        innerAppQuickFix.SetQuickFixMark(fixMark);
    }
    // 2. update disable-status in db
    if (!quickFixDataMgr_->UpdateQuickFixStatus(QuickFixStatus::SWITCH_DISABLE_START, innerAppQuickFix)) {
        LOG_E(BMS_TAG_QUICK_FIX, "update quickfix status %{public}d failed", QuickFixStatus::SWITCH_DISABLE_START);
        return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATCH_STATUS;
    }
    // 3. if quick fix exist, stateGuard is utilized to rollback quick fix info in db
    ScopeGuard stateGuard([&] {
        if (isExisted) {
            quickFixDataMgr_->UpdateQuickFixStatus(QuickFixStatus::DEPLOY_END, innerAppQuickFix);
        } else {
            quickFixDataMgr_->DeleteInnerAppQuickFix(bundleName);
        }
    });

    ErrCode res = InnerSwitchQuickFix(bundleName, innerAppQuickFix, false);
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "InnerSwitchQuickFix failed %{public}d", res);
        return res;
    }
    stateGuard.Dismiss();
    return ERR_OK;
}

ErrCode QuickFixSwitcher::InnerSwitchQuickFix(const std::string &bundleName, const InnerAppQuickFix &innerAppQuickFix,
    bool enable)
{
    LOG_D(BMS_TAG_QUICK_FIX, "InnerSwitchQuickFix start with bundleName: %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        LOG_E(BMS_TAG_QUICK_FIX, "InnerSwitchQuickFix failed due to empty bundleName");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PARAM_ERROR;
    }

    if (GetDataMgr() != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "GetDataMgr failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    InnerBundleInfo innerBundleInfo;
    // 4. obtain innerBundleInfo and enableGuard used to enable bundle which is under disable status
    if (!dataMgr_->GetInnerBundleInfo(bundleName, innerBundleInfo)) {
        LOG_E(BMS_TAG_QUICK_FIX, "cannot obtain the innerbundleInfo from data mgr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_NOT_EXISTED_BUNDLE_INFO;
    }
    ScopeGuard enableGuard([&] { dataMgr_->EnableBundle(bundleName_); });
    // utilize appQuickFix to rollback
    AppQuickFix oldAppQuickFix = innerBundleInfo.GetAppQuickFix();
    if (!enable && oldAppQuickFix.deployedAppqfInfo.hqfInfos.empty()) {
        LOG_E(BMS_TAG_QUICK_FIX, "no patch info to be disabled");
        return ERR_BUNDLEMANAGER_QUICK_FIX_NO_PATCH_INFO_IN_BUNDLE_INFO;
    }
    InnerAppQuickFix oldInnerAppQuickFix;
    // 5. to generate old quick fix info which is about to be deleted from db
    auto errCode = CreateInnerAppqf(innerBundleInfo, enable, oldInnerAppQuickFix);
    if (errCode != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "CreateInnerAppqf failed");
        return errCode;
    }
    // 6. update innerBundleInfo in memory cache and db
    AppQuickFix newAppQuickFix = innerAppQuickFix.GetAppQuickFix();
    newAppQuickFix.deployingAppqfInfo = enable ? AppqfInfo() : oldAppQuickFix.deployingAppqfInfo;
    innerBundleInfo.SetAppQuickFix(newAppQuickFix);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    if (!dataMgr_->UpdateQuickFixInnerBundleInfo(bundleName, innerBundleInfo)) {
        LOG_E(BMS_TAG_QUICK_FIX, "update quickfix innerbundleInfo failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    // 7. utilize innerBundleInfoGuard to rollback inner bundle info in db and memory cache
    ScopeGuard innerBundleInfoGuard([&] {
        innerBundleInfo.SetAppQuickFix(oldAppQuickFix);
        dataMgr_->UpdateQuickFixInnerBundleInfo(bundleName, innerBundleInfo);
    });

    if (GetQuickFixDataMgr() != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "GetQuickFixDataMgr failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    // 8. update quick fix info status of SWITCH_END
    auto appQuickFix = oldInnerAppQuickFix.GetAppQuickFix();
    if (appQuickFix.deployedAppqfInfo.hqfInfos.empty() && appQuickFix.deployingAppqfInfo.hqfInfos.empty()) {
        quickFixDataMgr_->DeleteInnerAppQuickFix(bundleName);
    } else {
        if (!quickFixDataMgr_->UpdateQuickFixStatus(QuickFixStatus::SWITCH_END, oldInnerAppQuickFix)) {
            LOG_E(BMS_TAG_QUICK_FIX, "update quickfix status %{public}d failed", QuickFixStatus::SWITCH_END);
            return ERR_BUNDLEMANAGER_QUICK_FIX_INVALID_PATCH_STATUS;
        }
    }
    innerBundleInfoGuard.Dismiss();
    return ERR_OK;
}

ErrCode QuickFixSwitcher::CreateInnerAppqf(const InnerBundleInfo &innerBundleInfo,
    bool enable, InnerAppQuickFix &innerAppQuickFix)
{
    std::string bundleName = innerBundleInfo.GetBundleName();
    LOG_D(BMS_TAG_QUICK_FIX, "CreateInnerAppqf start with bundleName: %{public}s", bundleName.c_str());

    InnerAppQuickFix innerAppqf;
    if (GetQuickFixDataMgr() != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "quickFixDataMgr_ is nullptr");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    auto res = quickFixDataMgr_->QueryInnerAppQuickFix(bundleName, innerAppqf);
    // old patch or reload in db will lead failure to create innerAppqf
    const auto &appQf = innerAppqf.GetAppQuickFix();
    if (res && !appQf.deployedAppqfInfo.hqfInfos.empty()) {
        LOG_E(BMS_TAG_QUICK_FIX, "CreateInnerAppqf failed due to some old patch or hot reload in db");
        return ERR_BUNDLEMANAGER_QUICK_FIX_OLD_PATCH_OR_HOT_RELOAD_IN_DB;
    }

    AppQuickFix appQuickFix;
    appQuickFix.bundleName = bundleName;
    appQuickFix.versionName = appQf.versionName;
    appQuickFix.versionCode = appQf.versionCode;
    appQuickFix.deployedAppqfInfo = innerBundleInfo.GetAppQuickFix().deployedAppqfInfo;

    if (!enable && res) {
        appQuickFix.deployingAppqfInfo = appQf.deployingAppqfInfo;
    }
    QuickFixMark fixMark;
    fixMark.bundleName = bundleName;
    fixMark.status = enable ? QuickFixStatus::SWITCH_ENABLE_START : QuickFixStatus::SWITCH_DISABLE_START;
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    innerAppQuickFix.SetQuickFixMark(fixMark);
    return ERR_OK;
}

ErrCode QuickFixSwitcher::GetQuickFixDataMgr()
{
    if (quickFixDataMgr_ == nullptr) {
        quickFixDataMgr_ = DelayedSingleton<QuickFixDataMgr>::GetInstance();
        if (quickFixDataMgr_ == nullptr) {
            LOG_E(BMS_TAG_QUICK_FIX, "quickFixDataMgr_ is nullptr");
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
            LOG_E(BMS_TAG_QUICK_FIX, "dataMgr_ is nullptr");
            return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
        }
    }
    return ERR_OK;
}
} // AppExecFwk
} // OHOS