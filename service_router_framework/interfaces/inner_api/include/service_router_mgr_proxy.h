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

#ifndef FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_INCLUDE_SERVICE_ROUTER_MGR_PROXY_H
#define FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_INCLUDE_SERVICE_ROUTER_MGR_PROXY_H

#include "iremote_proxy.h"
#include "service_router_mgr_interface.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class ServiceRouterMgrProxy
 * ServiceRouterMgrProxy.
 */
class ServiceRouterMgrProxy : public IRemoteProxy<IServiceRouterManager> {
public:
    explicit ServiceRouterMgrProxy(const sptr<IRemoteObject> &object);

    virtual ~ServiceRouterMgrProxy() override;

    /**
     * @brief Query the business ability info of list by the given filter.
     * @param filter Indicates the filter containing the business ability info to be queried.
     * @param businessAbilityInfos Indicates the obtained business ability info objects
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t QueryBusinessAbilityInfos(const BusinessAbilityFilter &filter,
        std::vector<BusinessAbilityInfo> &businessAbilityInfos) override;

    /**
     * @brief Query the PurposeInfo of list by the given Want.
     * @param want Indicates the information of the purpose.
     * @param purposeName Indicates the  purposeName.
     * @param purposeInfos Indicates the obtained PurposeInfos object.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t QueryPurposeInfos(const Want &want, const std::string purposeName,
        std::vector<PurposeInfo> &purposeInfos) override;

private:
    int32_t SendRequest(IServiceRouterManager::Message code, MessageParcel &data, MessageParcel &reply);

    template <typename T>
    int32_t GetParcelableInfos(IServiceRouterManager::Message code, MessageParcel &data,
        std::vector<T> &parcelableInfos);

    static inline BrokerDelegator<ServiceRouterMgrProxy> delegator_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif // namespace FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_INCLUDE_SERVICE_ROUTER_MGR_PROXY_H