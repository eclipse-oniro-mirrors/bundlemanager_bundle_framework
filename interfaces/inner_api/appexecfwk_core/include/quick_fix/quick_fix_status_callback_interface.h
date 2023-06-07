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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_QUICK_FIX_STATUS_CALLBACK_INTERFACE_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_QUICK_FIX_STATUS_CALLBACK_INTERFACE_H

#include "iremote_broker.h"
#include "quick_fix_result_info.h"

namespace OHOS {
namespace AppExecFwk {
class IQuickFixStatusCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.bundleManager.QuickFixStatusCallback");

    virtual void OnPatchDeployed(const std::shared_ptr<QuickFixResult> &result) = 0;
    virtual void OnPatchSwitched(const std::shared_ptr<QuickFixResult> &result) = 0;
    virtual void OnPatchDeleted(const std::shared_ptr<QuickFixResult> &result) = 0;

    enum Message : uint32_t {
        ON_PATCH_DEPLOYED = 1,
        ON_PATCH_SWITCHED = 2,
        ON_PATCH_DELETED = 3
    };
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_QUICK_FIX_STATUS_CALLBACK_INTERFACE_H
