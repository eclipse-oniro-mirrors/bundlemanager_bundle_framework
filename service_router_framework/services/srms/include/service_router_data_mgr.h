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

#ifndef FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_SERVICE_ROUTER_DATA_MGR_H
#define FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_SERVICE_ROUTER_DATA_MGR_H

#include <map>
#include <mutex>
#include <vector>
#include <string>
#include <singleton.h>

#include "bundle_info.h"
#include "bundle_mgr_interface.h"
#include "inner_service_info.h"
#include "service_info.h"
#include "uri.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
class ServiceRouterDataMgr : public DelayedRefSingleton<ServiceRouterDataMgr> {
public:
    using Want = OHOS::AAFwk::Want;
    using Uri = OHOS::Uri;

    ServiceRouterDataMgr() = default;
    ~ServiceRouterDataMgr() = default;

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
     */
    void UpdateBundleInfo(const BundleInfo &bundleInfo);

    /**
     * @brief Delete bundle info from an exist BundleInfo.
     * @param bundleName Indicates the bundle name.
     */
    void DeleteBundleInfo(const std::string &bundleName);

    /**
     * @brief Query the business ability info of list by the given filter.
     * @param filter Indicates the filter containing the business ability info to be queried.
     * @param businessAbilityInfos Indicates the obtained business ability info objects
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t QueryBusinessAbilityInfos(const BusinessAbilityFilter &filter,
        std::vector<BusinessAbilityInfo> &businessAbilityInfos) const;

    /**
     * @brief Query a PurposeInfo of list by the given Want.
     * @param want Indicates the information of the purposeInfo.
     * @param purposeName Indicates the purposeName.
     * @param purposeInfos Indicates the obtained PurposeInfo of list.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t QueryPurposeInfos(const Want &want, const std::string purposeName,
        std::vector<PurposeInfo> &purposeInfos) const;

private:
    BusinessType GetBusinessType(const BusinessAbilityFilter &filter) const;

private:
    mutable std::mutex bundleInfoMutex_;
    std::map<std::string, InnerServiceInfo> innerServiceInfos_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FFOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_SERVICE_ROUTER_DATA_MGR_H
