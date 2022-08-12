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
        return ERR_APPEXECFWK_QUICK_FIX_PARAM_ERROR;
    }
    return ERR_OK;
}

ErrCode QuickFixSwitcher::DisableQuickFix(const std::string &bundleName)
{
    if (bundleName.empty()) {
        APP_LOGE("DisableQuickFix failed due to empty bundleName");
        return ERR_APPEXECFWK_QUICK_FIX_PARAM_ERROR;
    }
    return ERR_OK;
}

ErrCode QuickFixSwitcher::InnerSwitchQuickFix(const std::string &bundleName, const InnerAppQuickFix &innerAppQuickFix)
{
    APP_LOGD("InnerSwitchQuickFix start with bundleName: %{public}s", bundleName.c_str());
    return ERR_OK;
}

InnerAppQuickFix QuickFixSwitcher::CreateInnerAppqf(const InnerBundleInfo &innerBundleInfo,
    const QuickFixStatus &status)
{
    InnerAppQuickFix innerAppQuickFix;
    return innerAppQuickFix;
}
} // AppExecFwk
} // OHOS