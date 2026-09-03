/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_DEFAULT_APP_HOST_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_DEFAULT_APP_HOST_H


#include <mutex>

#include "default_app_interface.h"
#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class DefaultAppHost : public IRemoteStub<IDefaultApp> {
public:
    DefaultAppHost();
    virtual ~DefaultAppHost();

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:
    ErrCode HandleIsDefaultApplication(Parcel& data, Parcel& reply);
    ErrCode HandleGetDefaultApplication(Parcel& data, Parcel& reply);
    ErrCode HandleSetDefaultApplication(Parcel& data, Parcel& reply);
    ErrCode HandleResetDefaultApplication(Parcel& data, Parcel& reply);
    ErrCode HandleSetDefaultApplicationForAppClone(Parcel& data, Parcel& reply);
    ErrCode HandleSetDefaultApplicationForCustom(Parcel& data, Parcel& reply);
    ErrCode HandleGetDefaultApplicationCandidates(MessageParcel& data, MessageParcel& reply);

    int32_t AllocatAshmemNum();
    ErrCode WriteParcelableIntoAshmem(MessageParcel& tempParcel, MessageParcel& reply);
    template<typename T>
    ErrCode WriteVectorToParcel(std::vector<T>& parcelVector, MessageParcel& reply);

    int32_t ashmemNum_ = 0;
    std::mutex bundleAshmemMutex_;

    DISALLOW_COPY_AND_MOVE(DefaultAppHost);
};
}
}
#endif
