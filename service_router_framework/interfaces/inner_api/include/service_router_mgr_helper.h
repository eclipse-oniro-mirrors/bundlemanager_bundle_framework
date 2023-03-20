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

#ifndef FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_INCLUDE_SERVICE_ROUTER_SA_HEALPER_H
#define FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_INCLUDE_SERVICE_ROUTER_SA_HEALPER_H

#include <condition_variable>
#include <mutex>
#include <singleton.h>

#include "service_router_death_recipient.h"
#include "service_router_mgr_interface.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

/**
 * @class SystemAbilityManager Helper
 * Bms helpler.
 */
class ServiceRouterMgrHelper final : public DelayedRefSingleton<ServiceRouterMgrHelper> {
    DECLARE_DELAYED_REF_SINGLETON(ServiceRouterMgrHelper)

public:
    DISALLOW_COPY_AND_MOVE(ServiceRouterMgrHelper);

    /**
     * @brief Acquire a service router manager, if it not existed,
     * @return returns the service router manager ipc object, or nullptr for failed.
     */
    sptr<IServiceRouterManager> GetServiceRouterMgr();

    void LoadSA();
    void FinishStartSAFail();
    void FinishStartSASuccess(const sptr<IRemoteObject> &remoteObject);
    void OnRemoteDiedHandle();

private:
    void SetServiceRouterMgr(const sptr<IServiceRouterManager> &serviceRouterMgr);
    sptr<IServiceRouterManager> InnerGetServiceRouterMgr();

    std::mutex mgrMutex_;
    std::mutex cvLock_;
    bool isReady = false;
    std::condition_variable mgrConn_;
    sptr<ServiceRouterDeathRecipient> serviceDeathObserver_;
    sptr<IServiceRouterManager> routerMgr_ = nullptr;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_INCLUDE_SERVICE_ROUTER_SA_HEALPER_H
