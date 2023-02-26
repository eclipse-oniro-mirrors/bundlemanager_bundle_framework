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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_SERVICE_ROUTER_INCLUDE_SERVICE_ROUTER_DATA_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_SERVICE_ROUTER_INCLUDE_SERVICE_ROUTER_DATA_MGR_H

#include <map>
#include <mutex>
#include <vector>
#include <string>
#include <singleton.h>

#include "bundle_info.h"
#include "bundle_mgr_interface.h"
#include "inner_service_info.h"
#include "want.h"
#include "uri.h"
#include "service_info.h"

namespace OHOS {
namespace AppExecFwk {
class ServiceRouterDataMgr : public DelayedRefSingleton<ServiceRouterDataMgr> {
public:
    using Want = OHOS::AAFwk::Want;
    using Uri = OHOS::Uri;

    ServiceRouterDataMgr();
    virtual ~ServiceRouterDataMgr();

    /**
     * @brief Load all installed bundle infos.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool LoadAllBundleInfos();

    /**
     * @brief Load bundle info by bundle name.
     * @param bundleName Indicates the bundle name.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool LoadBundleInfo(const std::string &bundleName);

    /**
     * @brief update BundleInfo.
     * @param bundleInfo Indicates the bundle info.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool UpdateBundleInfo(const BundleInfo &bundleInfo);

    /**
     * @brief Delete bundle info from an exist BundleInfo.
     * @param bundleName Indicates the bundle name.
     * @return Returns true if this function is successfully called; returns false otherwise.
     */
    bool DeleteBundleInfo(const std::string &bundleName);

    /**
     * @brief Query a ServiceInfo of list by the given Want.
     * @param want Indicates the information of the service.
     * @param serviceType Indicates the type of the service.
     * @param serviceInfos Indicates the obtained ServiceInfo of list.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t QueryServiceInfos(const Want &want, const ExtensionServiceType &serviceType,
        std::vector<ServiceInfo> &serviceInfos) const;

    /**
     * @brief Query a IntentInfo of list by the given Want.
     * @param want Indicates the information of the intentInfo.
     * @param intentName Indicates the intentName.
     * @param intentInfos Indicates the obtained IntentInfo of list.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t QueryIntentInfos(const Want &want, const std::string intentName,
        std::vector<IntentInfo> &intentInfos) const;

private:
    bool IsContainsForm(const std::vector<IntentInfo> &intentInfos);

    ExtensionServiceType GetExtensionServiceType(const Want &want, const ExtensionServiceType &serviceType) const;

private:
    mutable std::mutex bundleInfoMutex_;
    std::map<std::string, InnerServiceInfo> innerServiceInfos_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_SERVICE_ROUTER_INCLUDE_SERVICE_ROUTER_DATA_MGR_H
