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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_QUICK_FIX_DATA_MGR_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_QUICK_FIX_DATA_MGR_H

#include "quick_fix_manager_db_interface.h"

#include <mutex>
#include <map>

#include "quick_fix_status_callback_interface.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixDataMgr : public DelayedSingleton<QuickFixDataMgr> {
public:
    QuickFixDataMgr();
    ~QuickFixDataMgr();

    bool QueryAllInnerAppQuickFix(std::map<std::string, InnerAppQuickFix> &innerAppQuickFixes);

    bool QueryInnerAppQuickFix(const std::string &bundleName, InnerAppQuickFix &innerAppQuickFix);

    bool SaveInnerAppQuickFix(const InnerAppQuickFix &innerAppQuickFix);

    bool DeleteInnerAppQuickFix(const std::string &bundleName);

    bool IsNextStatusExisted(const QuickFixStatus &curStatus, const QuickFixStatus &nextStatus);

    bool UpdateQuickFixStatus(const QuickFixStatus &nextStatus, InnerAppQuickFix &innerAppQuickFix);

private:
    void InitStatesMap();

    mutable std::mutex mutex_;
    std::shared_ptr<IQuickFixManagerDb> quickFixManagerDb_ = nullptr;
    std::multimap<QuickFixStatus, QuickFixStatus> statesMap_;
};
} // OHOS
} // AppExecFwk
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_QUICK_FIX_DATA_MGR_H