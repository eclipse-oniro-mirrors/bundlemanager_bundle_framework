/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_FREE_INSTALL_SERVICE_CENTER_CONNECTION_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_FREE_INSTALL_SERVICE_CENTER_CONNECTION_H

#include <condition_variable>

#include "ability_connect_callback_stub.h"
#include "bundle_connect_ability_mgr.h"
#include "service_center_death_recipient.h"

namespace OHOS {
namespace AppExecFwk {
class BundleConnectAbilityMgr;
class ServiceCenterDeathRecipient;

class ServiceCenterConnection : public AAFwk::AbilityConnectionStub {
public:
    ServiceCenterConnection(int32_t &connectState, std::condition_variable &cv,
        const std::weak_ptr<BundleConnectAbilityMgr> connectAbilityMgr)
        : connectState_(connectState), cv_(cv), connectAbilityMgr_(connectAbilityMgr)
    {
    }
    virtual ~ServiceCenterConnection();
    /**
     * @brief OnAbilityConnectDone, AbilityMs notify caller ability the result of connect.
     * @param element Service ability's ElementName.
     * @param remoteObject The session proxy of service ability.
     * @param resultCode ERR_OK on success, others on failure.
     */
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;

    /**
     * @brief OnAbilityDisconnectDone, AbilityMs notify caller ability the result of disconnect.
     * @param element Service ability's ElementName.
     * @param resultCode ERR_OK on success, others on failure.
     */
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode) override;

    sptr<IRemoteObject> GetRemoteObject();

private:
    int32_t &connectState_;
    sptr<IRemoteObject> serviceCenterRemoteObject_;
    sptr<ServiceCenterDeathRecipient> deathRecipient_;
    std::condition_variable &cv_;
    std::weak_ptr<BundleConnectAbilityMgr> connectAbilityMgr_;
};
}  //  namespace AppExecFwk
}  //  namespace OHOS
#endif  //  FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_FREE_INSTALL_SERVICE_CENTER_CONNECTION_H