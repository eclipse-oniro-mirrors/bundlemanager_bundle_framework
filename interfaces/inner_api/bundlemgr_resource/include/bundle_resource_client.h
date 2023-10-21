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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACES_KITS_BUNDLE_RESOURCE_BUNDLE_RESOURCE_CLIENT_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACES_KITS_BUNDLE_RESOURCE_BUNDLE_RESOURCE_CLIENT_H

#include "appexecfwk_errors.h"
#include "bundle_resource_data_process.h"
#include "bundle_resource_info.h"
#include "launcher_ability_resource_info.h"

#include <string>
#include <vector>


namespace OHOS {
namespace AppExecFwk {
class BundleResourceClient {
public:
    BundleResourceClient();
    ~BundleResourceClient();

    ErrCode GetBundleResourceInfo(const std::string &bundleName, const uint32_t flags,
        BundleResourceInfo &bundleResourceInfo);

    ErrCode GetLauncherAbilityResourceInfo(const std::string &bundleName, const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos);

    ErrCode GetAllBundleResourceInfo(const uint32_t flags, std::vector<BundleResourceInfo> &bundleResourceInfos);

    ErrCode GetAllLauncherAbilityResourceInfo(const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos);

private:
    std::shared_ptr<BundleResourceDataProcess> dataProcess_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACES_KITS_BUNDLE_RESOURCE_BUNDLE_RESOURCE_CLIENT_H