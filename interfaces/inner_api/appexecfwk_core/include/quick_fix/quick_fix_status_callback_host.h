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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_STATUS_CALLBACK_HOST_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_STATUS_CALLBACK_HOST_H

#include <unordered_map>

#include "iremote_stub.h"
#include "nocopyable.h"
#include "quick_fix_status_callback_interface.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixStatusCallbackHost : public IRemoteStub<IQuickFixStatusCallback> {
public:
    QuickFixStatusCallbackHost();
    virtual ~QuickFixStatusCallbackHost() override;

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    void Init();
    void HandleOnPatchDeployed(MessageParcel &data, MessageParcel &reply);
    void HandleOnPatchSwitched(MessageParcel &data, MessageParcel &reply);
    void HandleOnPatchDeleted(MessageParcel &data, MessageParcel &reply);

    using QuickFixCallbackFunc = void (QuickFixStatusCallbackHost::*)(MessageParcel &, MessageParcel &);
    std::unordered_map<uint32_t, QuickFixCallbackFunc> funcMap_;

    DISALLOW_COPY_AND_MOVE(QuickFixStatusCallbackHost);
};
}
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_STATUS_CALLBACK_HOST_H
