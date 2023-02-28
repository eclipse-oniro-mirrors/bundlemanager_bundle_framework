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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_BUNDLE_INFO_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_BUNDLE_INFO_H

#include "app_log_wrapper.h"
#include "nocopyable.h"
#include "service_info.h"
#include "want.h"
#include "bundle_info.h"
#include "application_info.h"

namespace OHOS {
namespace AppExecFwk {
class InnerServiceInfo {
public:
    InnerServiceInfo();
    ~InnerServiceInfo();
    /**
     * @brief Find serviceInfo of list by service type.
     * @param serviceType Indicates the service type.
     * @param serviceInfos Indicates the ServiceInfos to be find.
     * @return
     */
    void FindServiceInfos(const ExtensionServiceType &serviceType, std::vector<ServiceInfo> &serviceInfos) const;

    /**
     * @brief Find intentInfo by intentName.
     * @param intentName Indicates the intentName.
     * @param intentInfos Indicates the IntentInfos to be find.
     * @return Returns the IntentInfo object if find it; returns null otherwise.
     */
    void FindIntentInfos(const std::string &intentName, std::vector<IntentInfo> &intentInfos) const;

    /**
     * @brief Update inner service info.
     * @param bundelInfo Indicates the BundleInfo object to be update.
     * @param intentInfos Indicates the IntentInfos object to be update.
     * @param serviceInfos Indicates the ServiceInfos to be update.
     * @return
     */
    void UpdateInnerServiceInfo(const BundleInfo &bundleInfo, std::vector<IntentInfo> &intentInfos,
        std::vector<ServiceInfo> &serviceInfos)
    {
        UpdateIntentInfos(intentInfos);
        UpdateServiceInfos(serviceInfos);
    }

    /**
     * @brief Update app info.
     * @param applicationInfo Indicates the ApplicationInfo to be update.
     * @return
     */
    void UpdateAppInfo(const ApplicationInfo &applicationInfo)
    {
        appInfo_.name = applicationInfo.name;
        appInfo_.bundleName = applicationInfo.bundleName;
        appInfo_.iconId = applicationInfo.iconId;
        appInfo_.labelId = applicationInfo.labelId;
        appInfo_.descriptionId = applicationInfo.descriptionId;
    }

    /**
     * @brief Update service infos.
     * @param serviceInfos Indicates the ServiceInfos to be add.
     * @return
     */
    void UpdateServiceInfos(const std::vector<ServiceInfo> &serviceInfos)
    {
        serviceInfos_.clear();
        if (serviceInfos.size() == 0) {
            APP_LOGW("updateServiceInfos, serviceInfos.size is 0");
            return;
        }
        for (const auto &serviceInfo : serviceInfos) {
            serviceInfos_.emplace_back(serviceInfo);
        }
    }

    /**
     * @brief Update intentInfos.
     * @param serviceInfos Indicates the IntentInfos to be add.
     * @return
     */
    void UpdateIntentInfos(const std::vector<IntentInfo> &intentInfos)
    {
        intentInfos_.clear();
        if (intentInfos.size() == 0) {
            APP_LOGW("updateIntentInfos, intentInfos.size is 0");
            return;
        }
        for (const auto &intentInfo : intentInfos) {
            intentInfos_.emplace_back(intentInfo);
        }
    }

    /**
     * @brief clear inner bundle info.
     * @return
     */
    void lear()
    {
        serviceInfos_.clear();
        intentInfos_.clear();
    }

    /**
     * @brief Get bundle name.
     * @return Return bundle name
     */
    const AppInfo GetAppInfo() const
    {
        return appInfo_;
    }

    /**
     * @brief Get application name.
     * @return Return application name
     */
    std::string GetApplicationName() const
    {
        return appInfo_.name;
    }

    /**
     * @brief Get bundle name.
     * @return Return bundle name
     */
    const std::string GetBundleName() const
    {
        return appInfo_.bundleName;
    }
private:
    AppInfo appInfo_;
    std::vector<ServiceInfo> serviceInfos_;
    std::vector<IntentInfo> intentInfos_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_BUNDLE_INFO_H
