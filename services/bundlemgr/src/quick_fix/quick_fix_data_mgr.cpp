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

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "quick_fix_manager_rdb.h"
#include "inner_app_quick_fix.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixDataMgr::QuickFixDataMgr()
{
    LOG_D(BMS_TAG_DEFAULT, "create QuickFixDataMgr start");
    quickFixManagerDb_ = std::make_shared<QuickFixManagerRdb>();
    if (quickFixManagerDb_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "create QuickFixDataMgr failed");
        return;
    }

    InitStatesMap();
}

QuickFixDataMgr::~QuickFixDataMgr()
{
    LOG_D(BMS_TAG_DEFAULT, "destroy QuickFixDataMgr");
}

void QuickFixDataMgr::InitStatesMap()
{
    statesMap_ = {
        {QuickFixStatus::DEPLOY_START, QuickFixStatus::DEPLOY_END},
        {QuickFixStatus::DEPLOY_START, QuickFixStatus::DELETE_START},
        {QuickFixStatus::DEPLOY_END, QuickFixStatus::SWITCH_ENABLE_START},
        {QuickFixStatus::DEPLOY_END, QuickFixStatus::SWITCH_DISABLE_START},
        {QuickFixStatus::DEPLOY_END, QuickFixStatus::DELETE_START},
        {QuickFixStatus::SWITCH_ENABLE_START, QuickFixStatus::SWITCH_END},
        {QuickFixStatus::SWITCH_ENABLE_START, QuickFixStatus::SWITCH_ENABLE_START},
        {QuickFixStatus::SWITCH_DISABLE_START, QuickFixStatus::SWITCH_END},
        {QuickFixStatus::SWITCH_DISABLE_START, QuickFixStatus::SWITCH_DISABLE_START},
        {QuickFixStatus::SWITCH_ENABLE_START, QuickFixStatus::DEPLOY_END},
        {QuickFixStatus::SWITCH_DISABLE_START, QuickFixStatus::DEPLOY_END},
        {QuickFixStatus::SWITCH_END, QuickFixStatus::DELETE_START},
        {QuickFixStatus::DELETE_START, QuickFixStatus::SWITCH_END},
        {QuickFixStatus::DELETE_START, QuickFixStatus::DELETE_START},
        {QuickFixStatus::DELETE_START, QuickFixStatus::DELETE_END}
    };
}

bool QuickFixDataMgr::QueryAllInnerAppQuickFix(std::map<std::string, InnerAppQuickFix> &innerAppQuickFixes)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (quickFixManagerDb_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "error quickFixManagerDb_ is nullptr");
        return false;
    }
    return quickFixManagerDb_->QueryAllInnerAppQuickFix(innerAppQuickFixes);
}

bool QuickFixDataMgr::QueryInnerAppQuickFix(const std::string &bundleName, InnerAppQuickFix &innerAppQuickFix)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (quickFixManagerDb_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "error quickFixManagerDb_ is nullptr");
        return false;
    }
    return quickFixManagerDb_->QueryInnerAppQuickFix(bundleName, innerAppQuickFix);
}

bool QuickFixDataMgr::SaveInnerAppQuickFix(const InnerAppQuickFix &innerAppQuickFix)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (quickFixManagerDb_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "error quickFixManagerDb_ is nullptr");
        return false;
    }
    return quickFixManagerDb_->SaveInnerAppQuickFix(innerAppQuickFix);
}

bool QuickFixDataMgr::DeleteInnerAppQuickFix(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (quickFixManagerDb_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "error quickFixManagerDb_ is nullptr");
        return false;
    }
    return quickFixManagerDb_->DeleteInnerAppQuickFix(bundleName);
}

bool QuickFixDataMgr::IsNextStatusExisted(const QuickFixStatus &curStatus, const QuickFixStatus &nextStatus)
{
    auto statusRange = statesMap_.equal_range(curStatus);
    for (auto curIterator = statusRange.first; curIterator != statusRange.second; ++curIterator) {
        if (curIterator->second == nextStatus) {
            return true;
        }
    }
    LOG_E(BMS_TAG_DEFAULT, "IsNextStatusExisted failed due to invalid curStatus %{public}d", curStatus);
    return false;
}

bool QuickFixDataMgr::UpdateQuickFixStatus(const QuickFixStatus &nextStatus, InnerAppQuickFix &innerAppQuickFix)
{
    QuickFixMark fixMark = innerAppQuickFix.GetQuickFixMark();
    // invalid status can be transferred as DELETE_START status
    if (nextStatus == QuickFixStatus::DELETE_START && (fixMark.status == QuickFixStatus::DEFAULT_STATUS ||
        fixMark.status == QuickFixStatus::DELETE_END)) {
        fixMark.status = nextStatus;
        innerAppQuickFix.SetQuickFixMark(fixMark);
        return SaveInnerAppQuickFix(innerAppQuickFix);
    }

    if (fixMark.status == QuickFixStatus::DEFAULT_STATUS || nextStatus == QuickFixStatus::DEFAULT_STATUS) {
        LOG_E(BMS_TAG_DEFAULT, "status is invalid");
        return false;
    }

    // check next status to be updated
    if (!IsNextStatusExisted(static_cast<QuickFixStatus>(fixMark.status), nextStatus)) {
        LOG_E(BMS_TAG_DEFAULT, "next status %{public}d cannot be transferred by current status %{public}d",
            nextStatus, fixMark.status);
        return false;
    }

    fixMark.status = nextStatus;
    innerAppQuickFix.SetQuickFixMark(fixMark);

    return SaveInnerAppQuickFix(innerAppQuickFix);
}
} // OHOS
} // AppExecFwk
