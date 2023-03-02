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

#ifndef FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_SERVICE_ROUTER_MGR_SERVICE_H
#define FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_SERVICE_ROUTER_MGR_SERVICE_H

#include "event_runner.h"
#include "event_handler.h"
#include "service_info.h"
#include "service_router_mgr_stub.h"
#include "sr_common_event_subscriber.h"
#include "system_ability.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

/**
 * @class ServiceRouterMgrService
 * ServiceRouterMgrService provides a facility for managing ability life cycle.
 */
class ServiceRouterMgrService : public SystemAbility, public ServiceRouterMgrStub {
    DECLARE_DELAYED_SINGLETON(ServiceRouterMgrService)
    DECLEAR_SYSTEM_ABILITY(ServiceRouterMgrService)
public:
    /**
     * @brief Start the service router manager service.
     * @return
     */
    virtual void OnStart() override;
    /**
     * @brief Stop the service router service.
     * @return
     */
    virtual void OnStop() override;

    /**
     * @brief Check whether if the service router service is ready.
     * @return Returns true if the service router service is ready; returns false otherwise.
     */
    bool IsServiceReady() const;

    /**
     * @brief Query the ServiceInfo of list by the given Want.
     * @param want Indicates the information of the ability.
     * @param serviceType Indicates the type of the service.
     * @param serviceInfos Indicates the obtained ServiceInfos object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t QueryServiceInfos(const Want &want, const ExtensionServiceType &serviceType,
        std::vector<ServiceInfo> &serviceInfos) override;

    /**
     * @brief Query the IntentInfo of list by the given Want.
     * @param want Indicates the information of the want.
     * @param intentName Indicates the intentName.
     * @param intentInfos Indicates the obtained IntentInfos object.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t QueryIntentInfos(const Want &want, const std::string intentName,
        std::vector<IntentInfo> &intentInfos) override;

private:
    void Init();
    bool InitEventRunnerAndHandler();
    bool LoadAllBundleInfos();
    bool SubscribeCommonEvent();
    bool SubscribeBundleEvent();
    void DelayUnloadTask();

    std::shared_ptr<EventRunner> runner_ = nullptr;
    std::shared_ptr<EventHandler> handler_ = nullptr;
    std::mutex bundleMgrMutex_;
    std::mutex mutex_;
    std::shared_ptr<SrCommonEventSubscriber> eventSubscriber_ = nullptr;
    std::mutex delayTaskMutex_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_SERVICE_ROUTER_MGR_SERVICE_H
