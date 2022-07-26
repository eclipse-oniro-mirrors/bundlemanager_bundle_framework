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

#include "quick_fix_data_mgr.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#ifdef BMS_RDB_ENABLE
#include "quick_fix_manager_rdb.h"
#endif
#include "inner_app_quick_fix.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixDataMgr::QuickFixDataMgr()
{
    APP_LOGD("create QuickFixDataMgr start.");
#ifdef BMS_RDB_ENABLE
    quickFixManagerDb_ = std::make_shared<QuickFixManagerRdb>();
#endif
    if (quickFixManagerDb_ == nullptr) {
        APP_LOGE("create QuickFixDataMgr failed.");
        return;
    }
}

QuickFixDataMgr::~QuickFixDataMgr()
{
    APP_LOGD("destroy QuickFixDataMgr.");
}

bool QuickFixDataMgr::DeployQuickFix(const std::vector<std::string> &bundleFilePaths,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    if (bundleFilePaths.empty() || (statusCallback == nullptr)) {
        APP_LOGE("QuickFixDataMgr::DeployQuickFix wrong parms");
        return false;
    }
    return true;
}

bool QuickFixDataMgr::SwitchQuickFix(const std::string &bundleName,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    if (bundleName.empty() || (statusCallback == nullptr)) {
        APP_LOGE("QuickFixDataMgr::SwitchQuickFix wrong parms");
        return false;
    }
    return true;
}

bool QuickFixDataMgr::DeleteQuickFix(const std::string &bundleName,
    const sptr<IQuickFixStatusCallback> &statusCallback)
{
    if (bundleName.empty() || (statusCallback == nullptr)) {
        APP_LOGE("QuickFixDataMgr::DeleteQuickFix wrong parms");
        return false;
    }
    return true;
}

bool QuickFixDataMgr::QueryAllInnerAppQuickFix(std::map<std::string, InnerAppQuickFix> &innerAppQuickFixs)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (quickFixManagerDb_ == nullptr) {
        APP_LOGE("error quickFixManagerDb_ is nullptr.");
        return false;
    }
    return quickFixManagerDb_->QueryAllInnerAppQuickFix(innerAppQuickFixs);
}

bool QuickFixDataMgr::QueryInnerAppQuickFix(const std::string &bundleName, InnerAppQuickFix &innerAppQuickFix)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (quickFixManagerDb_ == nullptr) {
        APP_LOGE("error quickFixManagerDb_ is nullptr.");
        return false;
    }
    return quickFixManagerDb_->QueryInnerAppQuickFix(bundleName, innerAppQuickFix);
}

bool QuickFixDataMgr::SaveInnerAppQuickFix(const InnerAppQuickFix &innerAppQuickFix)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (quickFixManagerDb_ == nullptr) {
        APP_LOGE("error quickFixManagerDb_ is nullptr.");
        return false;
    }
    return quickFixManagerDb_->SaveInnerAppQuickFix(innerAppQuickFix);
}

bool QuickFixDataMgr::DeleteInnerAppQuickFix(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (quickFixManagerDb_ == nullptr) {
        APP_LOGE("error quickFixManagerDb_ is nullptr.");
        return false;
    }
    return quickFixManagerDb_->DeleteInnerAppQuickFix(bundleName);
}
} // OHOS
} // AppExecFwk
