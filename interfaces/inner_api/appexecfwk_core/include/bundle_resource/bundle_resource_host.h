/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_RESOURCE_HOST_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_RESOURCE_HOST_H

#include <mutex>

#include "iremote_stub.h"
#include "nocopyable.h"

#include "appexecfwk_errors.h"
#include "bundle_resource_interface.h"
#include "bundle_resource_proxy.h"

namespace OHOS {
namespace AppExecFwk {
class BundleResourceHost : public IRemoteStub<IBundleResource> {
public:
    BundleResourceHost();
    virtual ~BundleResourceHost() = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    ErrCode HandleGetBundleResourceInfo(MessageParcel &data, MessageParcel &reply);

    ErrCode HandleGetLauncherAbilityResourceInfo(MessageParcel &data, MessageParcel &reply);

    ErrCode HandleGetAllBundleResourceInfo(MessageParcel &data, MessageParcel &reply);

    ErrCode HandleGetAllLauncherAbilityResourceInfo(MessageParcel &data, MessageParcel &reply);

    void ClearAshmem(sptr<Ashmem> &optMem);

    int32_t AllocatAshmemNum();

    ErrCode WriteParcelableIntoAshmem(MessageParcel &tempParcel, MessageParcel &reply);

    ErrCode HandleAddResourceInfoByBundleName(MessageParcel &data, MessageParcel &reply);

    ErrCode HandleAddResourceInfoByAbility(MessageParcel &data, MessageParcel &reply);

    ErrCode HandleDeleteResourceInfo(MessageParcel &data, MessageParcel &reply);

    template<typename T>
    ErrCode WriteParcelInfo(const T &parcelInfo, MessageParcel &reply);

    template<typename T>
    ErrCode WriteVectorToParcel(std::vector<T> &parcelVector, MessageParcel &reply);

    int32_t ashmemNum_ = 0;
    std::mutex bundleAshmemMutex_;

    DISALLOW_COPY_AND_MOVE(BundleResourceHost);
};
}
}
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_RESOURCE_HOST_H
