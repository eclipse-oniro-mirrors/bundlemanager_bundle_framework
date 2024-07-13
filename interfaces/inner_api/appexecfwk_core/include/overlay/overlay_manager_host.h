/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_OVERLAY_MANAGER_HOST_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_OVERLAY_MANAGER_HOST_H

#include "overlay_manager_interface.h"
#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class OverlayManagerHost : public IRemoteStub<IOverlayManager> {
public:
    OverlayManagerHost();
    virtual ~OverlayManagerHost();

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:
    ErrCode HandleGetAllOverlayModuleInfo(MessageParcel &data, MessageParcel &reply);

    ErrCode HandleGetOverlayModuleInfoByName(MessageParcel &data, MessageParcel &reply);

    ErrCode HandleGetOverlayModuleInfo(MessageParcel &data, MessageParcel &reply);

    ErrCode HandleGetTargetOverlayModuleInfo(MessageParcel &data, MessageParcel &reply);

    ErrCode HandleGetOverlayModuleInfoByBundleName(MessageParcel &data, MessageParcel &reply);

    ErrCode HandleGetOverlayBundleInfoForTarget(MessageParcel &data, MessageParcel &reply);

    ErrCode HandleGetOverlayModuleInfoForTarget(MessageParcel &data, MessageParcel &reply);

    ErrCode HandleSetOverlayEnabled(MessageParcel &data, MessageParcel &reply);

    ErrCode HandleSetOverlayEnabledForSelf(MessageParcel &data, MessageParcel &reply);

    template<typename T>
    bool WriteParcelableVector(std::vector<T> &parcelableVector, MessageParcel &reply);

    DISALLOW_COPY_AND_MOVE(OverlayManagerHost);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_OVERLAY_MANAGER_HOST_H
