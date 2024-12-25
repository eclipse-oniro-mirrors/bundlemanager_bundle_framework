/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIXER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIXER_H

#include "bundle_data_mgr.h"
#include "event_handler.h"
#include "quick_fix_data_mgr.h"
#include "quick_fix_status_callback_interface.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixer {
public:
    QuickFixer(const sptr<IQuickFixStatusCallback> &statusCallback);
    ~QuickFixer() = default;

    void DeployQuickFix(const std::vector<std::string> &bundleFilePaths, bool isDebug = false,
        const std::string &targetPath = "", bool isReplace = false);
    void SwitchQuickFix(const std::string &bundleName, bool enable);
    void DeleteQuickFix(const std::string &bundleName);

private:
    const sptr<IQuickFixStatusCallback> statusCallback_;

    DISALLOW_COPY_AND_MOVE(QuickFixer);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_QUICK_FIXER_H