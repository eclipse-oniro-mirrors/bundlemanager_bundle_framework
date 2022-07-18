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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_MANAGER_INTERFACE_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_MANAGER_INTERFACE_H

#include "app_quick_fix_info.h"
#include "quick_fix_status_callback_interface.h"
#include "iremote_broker.h"

#include <vector>
#include <string>

namespace OHOS {
namespace AppExecFwk {
class IQuickFixManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.QuickFixManager");

    virtual bool DeployQuickFix(const std::vector<string> &bundleFilePaths,
        const sptr<IQuickFixStatusCallBack> &statusCallBack) = 0;

    virtual bool SwitchQuickFix(const std::string &bundleName,
        const sptr<IQuickFixStatusCallBack> &statusCallBack) = 0;

    virtual bool DeleteQuickFix(const std::string &bundleName,
        const sptr<IQuickFixStatusCallBack> &statusCallBack) = 0;

    enum Message : uint32_t {
        DEPLOY_QUICK_FIX = 0,
        SWITCH_QUICK_FIX = 1,
        DELETE_QUICK_FIX = 2
    };
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_MANAGER_INTERFACE_H