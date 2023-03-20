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

#include "iremote_broker.h"
#include "service_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
constexpr const char* SERVICE_ROUTER_MANAGER_SERVICE_NAME = "ServiceRouterMgrService";

/**
 * @class IServiceRouterManager
 * IServiceRouterManager interface is used to access service router manager services.
 */
class IServiceRouterManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.aafwk.ServiceRouterManager")

    using Want = OHOS::AAFwk::Want;

    /**
     * @brief Query the business ability info of list by the given filter.
     * @param filter Indicates the filter containing the business ability info to be queried.
     * @param businessAbilityInfos Indicates the obtained business ability info objects
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t QueryBusinessAbilityInfos(const BusinessAbilityFilter &filter,
        std::vector<BusinessAbilityInfo> &businessAbilityInfos) = 0;

    /**
     * @brief Query the PurposeInfo of list by the given Want.
     * @param want Indicates the information of the purpose.
     * @param purposeName Indicates the purposeName.
     * @param purposeInfos Indicates the obtained PurposeInfos object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t QueryPurposeInfos(const Want &want, const std::string purposeName,
        std::vector<PurposeInfo> &purposeInfos) = 0;

    enum Message : uint32_t {
        QUERY_BUSINESS_ABILITY_INFOS = 0,
        QUERY_PURPOSE_INFOS = 1,
    };
};
}  // namespace AAFwk
}  // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_INCLUDE_SERVICE_ROUTER_MANAGER_H
