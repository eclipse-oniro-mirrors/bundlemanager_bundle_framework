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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_MANAGER_HOST_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_MANAGER_HOST_H

#include "quick_fix_manager_interface.h"
#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixManagerHost : public IRemoteStub<IQuickFixManager> {
public:
    QuickFixManagerHost();
    virtual ~QuickFixManagerHost();

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:
    ErrCode HandleDeployQuickFix(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleSwitchQuickFix(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleDeleteQuickFix(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleCreateFd(MessageParcel& data, MessageParcel& reply);

    DISALLOW_COPY_AND_MOVE(QuickFixManagerHost);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_MANAGER_HOST_H
