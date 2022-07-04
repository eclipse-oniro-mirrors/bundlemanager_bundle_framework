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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DISTRIBUTED_MANAGER_BUNDLE_MANAGER_CALLBACK_STUB_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DISTRIBUTED_MANAGER_BUNDLE_MANAGER_CALLBACK_STUB_H

#include "nocopyable.h"

#include "iremote_object.h"
#include "iremote_stub.h"
#include "i_bundle_manager_callback.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class BundleManagerCallbackStub
 * BundleManagerCallbackStub.
 */
class BundleManagerCallbackStub : public IRemoteStub<IBundleManagerCallback> {
public:
    BundleManagerCallbackStub();
    virtual ~BundleManagerCallbackStub() = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
private:
    int32_t HandleQueryRpcIdCallBack(MessageParcel &data, MessageParcel &reply);
    DISALLOW_COPY_AND_MOVE(BundleManagerCallbackStub);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DISTRIBUTED_MANAGER_BUNDLE_MANAGER_CALLBACK_STUB_H