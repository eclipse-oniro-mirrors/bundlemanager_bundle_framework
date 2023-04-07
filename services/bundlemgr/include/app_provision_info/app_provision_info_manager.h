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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_PROVISION_INFO_MANAGER_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_PROVISION_INFO_MANAGER_H

#include <unordered_set>

#include "app_provision_info_rdb.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {
class AppProvisionInfoManager : public DelayedSingleton<AppProvisionInfoManager> {
public:
    AppProvisionInfoManager();
    ~AppProvisionInfoManager();
    bool AddAppProvisionInfo(const std::string &bundleName, const AppProvisionInfo &appProvisionInfo);
    bool DeleteAppProvisionInfo(const std::string &bundleName);
    bool GetAppProvisionInfo(const std::string &bundleName, AppProvisionInfo &appProvisionInfo);
    bool GetAllAppProvisionInfoBundleName(std::unordered_set<std::string> &bundleNames);

    bool SetSpecifiedDistributionType(const std::string &bundleName, const std::string &specifiedDistributionType);
    bool GetSpecifiedDistributionType(const std::string &bundleName, std::string &specifiedDistributionType);
    bool SetAdditionalInfo(const std::string &bundleName, const std::string &additionalInfo);
    bool GetAdditionalInfo(const std::string &bundleName, std::string &additionalInfo);

private:
    std::shared_ptr<AppProvisionInfoManagerRdb> AppProvisionInfoManagerDb_;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_PROVISION_INFO_MANAGER_H
