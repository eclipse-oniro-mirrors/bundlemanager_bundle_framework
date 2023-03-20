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

#ifndef FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_INNER_BUNDLE_INFO_H
#define FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_INNER_BUNDLE_INFO_H

#include "app_log_wrapper.h"
#include "application_info.h"
#include "bundle_info.h"
#include "nocopyable.h"
#include "service_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
class InnerServiceInfo {
public:
    InnerServiceInfo() = default;
    ~InnerServiceInfo() = default;
    /**
     * @brief Find serviceInfo of list by service type.
     * @param businessType Indicates the business type.
     * @param businessAbilityInfos Indicates the business ability infos to be find.
     * @return
     */
    void FindBusinessAbilityInfos(const BusinessType &businessType,
        std::vector<BusinessAbilityInfo> &businessAbilityInfos) const;

    /**
     * @brief Find purposeInfo by purposeName.
     * @param purposeName Indicates the purposeName.
     * @param purposeInfos Indicates the PurposeInfos to be find.
     * @return Returns the PurposeInfo object if find it; returns null otherwise.
     */
    void FindPurposeInfos(const std::string &purposeName, std::vector<PurposeInfo> &purposeInfos) const;

    /**
     * @brief Update inner service info.
     * @param purposeInfos Indicates the PurposeInfos object to be update.
     * @param businessAbilityInfos Indicates the business ability infos to be update.
     * @return
     */
    void UpdateInnerServiceInfo(std::vector<PurposeInfo> &purposeInfos,
        std::vector<BusinessAbilityInfo> &businessAbilityInfos)
    {
        UpdatePurposeInfos(purposeInfos);
        UpdateBusinessAbilityInfos(businessAbilityInfos);
    }

    /**
     * @brief Update app info.
     * @param applicationInfo Indicates the ApplicationInfo to be update.
     * @return
     */
    void UpdateAppInfo(const ApplicationInfo &applicationInfo)
    {
        appInfo_.bundleName = applicationInfo.bundleName;
        appInfo_.iconId = applicationInfo.iconId;
        appInfo_.labelId = applicationInfo.labelId;
        appInfo_.descriptionId = applicationInfo.descriptionId;
    }

    /**
     * @brief Update business ability infos.
     * @param businessAbilityInfos Indicates the business ability infos to be add.
     * @return
     */
    void UpdateBusinessAbilityInfos(const std::vector<BusinessAbilityInfo> &businessAbilityInfos)
    {
        if (businessAbilityInfos.size() == 0) {
            APP_LOGW("UpdateBusinessAbilityInfos, serviceInfos.size is 0");
            businessAbilityInfos_.clear();
            return;
        }
        businessAbilityInfos_.assign(businessAbilityInfos.begin(), businessAbilityInfos.end());
    }

    /**
     * @brief Update purposeInfos.
     * @param purposeInfos Indicates the PurposeInfos to be add.
     * @return
     */
    void UpdatePurposeInfos(const std::vector<PurposeInfo> &purposeInfos)
    {
        if (purposeInfos.size() == 0) {
            APP_LOGW("updatePurposeInfos, purposeInfos.size is 0");
            purposeInfos_.clear();
            return;
        }
        purposeInfos_.assign(purposeInfos.begin(), purposeInfos.end());
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
     * @brief Get bundle name.
     * @return Return bundle name
     */
    const std::string GetBundleName() const
    {
        return appInfo_.bundleName;
    }
private:
    AppInfo appInfo_;
    std::vector<BusinessAbilityInfo> businessAbilityInfos_;
    std::vector<PurposeInfo> purposeInfos_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_INNER_BUNDLE_INFO_H
