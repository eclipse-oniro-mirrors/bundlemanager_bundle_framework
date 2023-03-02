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

#ifndef FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_SERVICE_ROUTER_MANAGER_STUB_H
#define FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_SERVICE_ROUTER_MANAGER_STUB_H

#include "iremote_stub.h"
#include "nocopyable.h"
#include "parcel_macro.h"
#include "service_router_mgr_interface.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class ServiceRouterMgrStub
 * ServiceRouterMgrStub.
 */
class ServiceRouterMgrStub : public IRemoteStub<IServiceRouterManager> {
public:
    ServiceRouterMgrStub();
    virtual ~ServiceRouterMgrStub();

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int HandleQueryServiceInfos(MessageParcel &data, MessageParcel &reply);
    int HandleQueryIntentInfos(MessageParcel &data, MessageParcel &reply);
    bool VerifyCallingPermission(const std::string &permissionName);
    bool VerifySystemApp();
    template <typename T>
    bool WriteParcelableVector(std::vector<T> &parcelableVector, Parcel &data);

    DISALLOW_COPY_AND_MOVE(ServiceRouterMgrStub);
};
}  // namespace AAFwk
}  // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_SERVICE_ROUTER_MANAGER_STUB_H