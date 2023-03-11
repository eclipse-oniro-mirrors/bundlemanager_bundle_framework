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

#ifndef FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_INCLUDE_SERVICE_ROUTER_MANAGER_H
#define FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_INCLUDE_SERVICE_ROUTER_MANAGER_H

#include <string>
#include <vector>

#include "ability_connect_callback_interface.h"
#include "extension_ability_info.h"
#include "iremote_broker.h"
#include "service_info.h"
#include "session_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AAFwk;
constexpr const char* SERVICE_ROUTER_MANAGER_SERVICE_NAME = "ServiceRouterMgrService";
const int DEFAULT_INVAL_VALUE = -1;

/**
 * @class IServiceRouterManager
 * IServiceRouterManager interface is used to access service router manager services.
 */
class IServiceRouterManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.aafwk.ServiceRouterManager")

    /**
     * @brief Query the ServiceInfo of list by the given Want.
     * @param want Indicates the information of the ability.
     * @param serviceType Indicates the type of the service.
     * @param serviceInfos Indicates the obtained ServiceInfos object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t QueryServiceInfos(const Want &want, const ExtensionServiceType &serviceType,
        std::vector<ServiceInfo> &serviceInfos) = 0;

    /**
     * @brief Query the PurposeInfo of list by the given Want.
     * @param want Indicates the information of the purpose.
     * @param purposeName Indicates the purposeName.
     * @param purposeInfos Indicates the obtained PurposeInfos object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t QueryPurposeInfos(const Want &want, const std::string purposeName,
        std::vector<PurposeInfo> &purposeInfos) = 0;

    /**
     * Start ui extension ability with want, send want to ability manager service.
     *
     * @param want, the want of the ability to start.
     * @param sessionInfo the extension session info of the ability to start.
     * @param userId, Designation User ID.
     * @param extensionType If an ExtensionAbilityType is set, only extension of that type can be started.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t StartUIExtensionAbility(const Want &want, const sptr<SessionInfo> &sessionInfo,
        int32_t userId = DEFAULT_INVAL_VALUE, ExtensionAbilityType extensionType = ExtensionAbilityType::UNSPECIFIED)
    {
        return 0;
    }

    /**
     * Connect ui extension ability with want, connect session with service ability.
     *
     * @param want, Special want for service type's ability.
     * @param connect, Callback used to notify caller the result of connecting or disconnecting.
     * @param sessionInfo the extension session info of the ability to start.
     * @param userId, Designation User ID.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t ConnectUIExtensionAbility(const Want &want, const sptr<IAbilityConnection> &connect,
        const sptr<SessionInfo> &sessionInfo, int32_t userId = DEFAULT_INVAL_VALUE)
    {
        return 0;
    }

    enum Message : uint32_t {
        QUERY_SERVICE_INFOS = 0,
        QUERY_PURPOSE_INFOS = 1,
        START_UI_EXTENSION_ABILITY = 2,
        CONNECT_UI_EXTENSION_ABILITY = 3,
    };
};
}  // namespace AAFwk
}  // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_INCLUDE_SERVICE_ROUTER_MANAGER_H
