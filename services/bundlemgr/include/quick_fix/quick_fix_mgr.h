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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_QUICK_FIX_MGR_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_QUICK_FIX_MGR_H

#include "quick_fix_manager_db_interface.h"

#include "nocopyable.h"
#include "quick_fix_status_callback_interface.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixMgr {
public:
    static QuickFixMgr& GetInstance();

    bool DeployQuickFix(const std::vector<std::string> &bundleFilePaths,
        const sptr<IQuickFixStatusCallback> &statusCallback);

    bool SwitchQuickFix(const std::string &bundleName,
        const sptr<IQuickFixStatusCallback> &statusCallback);

    bool DeleteQuickFix(const std::string &bundleName,
        const sptr<IQuickFixStatusCallback> &statusCallback);

    bool QueryAllInnerAppQuickFix(std::map<std::string, InnerAppQuickFix> &innerAppQuickFixs);

    bool QueryInnerAppQuickFix(const std::string &bundleName, InnerAppQuickFix &innerAppQuickFix);

    bool SaveInnerAppQuickFix(const InnerAppQuickFix &innerAppQuickFix);

    bool DeleteInnerAppQuickFix(const std::string &bundleName);

private:
    QuickFixMgr();
    ~QuickFixMgr();
    DISALLOW_COPY_AND_MOVE(QuickFixMgr);
    std::shared_ptr<IQuickFixManagerDb> quickFixManagerDb_ = nullptr;
};
} // OHOS
} // AppExecFwk
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_QUICK_FIX_MGR_H