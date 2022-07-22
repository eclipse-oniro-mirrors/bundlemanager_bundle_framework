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

#include "quick_fix_mgr.h"

#ifdef BMS_RDB_ENABLE
#include "quick_fix_manager_rdb.h"
#endif

namespace OHOS {
namespace AppExecFwk {
QuickFixMgr::QuickFixMgr()
{
    APP_LOGD("create QuickFixMgr start.");
#ifdef BMS_RDB_ENABLE
    quickFixManagerDb_ = std::make_share<QuickFixManagerRdb>();
#endif
    if (quickFixManagerDb_ == nullptr) {
        APP_LOGE("create QuickFixMgr failed.");
        return;
    }
    quickFixManagerDb_->RegisterDeathListener();
}

QuickFixMgr::~QuickFixMgr()
{
    APP_LOGD("destroy QuickFixMgr.");
    if (quickFixManagerDb_ != nullptr) {
        quickFixManagerDb_->UnRegisterDeathListener();
    }
}

QuickFixMgr& QuickFixMgr::QuickFixMgrGetInstance()
{
    static QuickFixMgr quickFixMgr;
    return quickFixMgr;
}

bool QuickFixMgr::QueryAllInnerAppQuickFix(std::map<std::string, InnerAppQuickFix> &innerAppQuickFixs)
{
    if (quickFixManagerDb_ == nullptr) {
        APP_LOGE("error quickFixManagerDb_ is nullptr.");
        return false;
    }
    return quickFixManagerDb_->QueryAllInnerAppQuickFix(innerAppQuickFixs);
}

bool QuickFixMgr::QueryInnerAppQuickFix(const std::string &bundleName, InnerAppQuickFix &innerAppQuickFix)
{
    if (quickFixManagerDb_ == nullptr) {
        APP_LOGE("error quickFixManagerDb_ is nullptr.");
        return false;
    }
    return quickFixManagerDb_->QueryInnerAppQuickFix(bundleName, innerAppQuickFix);
}

bool QuickFixMgr::SaveInnerAppQuickFix(const InnerAppQuickFix &innerAppQuickFix)
{
    if (quickFixManagerDb_ == nullptr) {
        APP_LOGE("error quickFixManagerDb_ is nullptr.");
        return false;
    }
    return quickFixManagerDb_->SaveInnerAppQuickFix(innerAppQuickFix);
}

bool QuickFixMgr::DeleteInnerAppQuickFix(const std::string &bundleName)
{
    if (quickFixManagerDb_ == nullptr) {
        APP_LOGE("error quickFixManagerDb_ is nullptr.");
        return false;
    }
    return quickFixManagerDb_->DeleteInnerAppQuickFix(bundleName);
}
} // OHOS
} // AppExecFwk
