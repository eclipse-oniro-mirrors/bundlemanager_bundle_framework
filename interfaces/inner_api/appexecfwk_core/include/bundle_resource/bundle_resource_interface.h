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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_RESOURCE_INTERFACE_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_RESOURCE_INTERFACE_H

#include "appexecfwk_errors.h"
#include "bundle_resource/bundle_resource_info.h"
#include "bundle_resource/launcher_ability_resource_info.h"
#include "extension_ability_info.h"
#include "iremote_broker.h"

namespace OHOS {
namespace AppExecFwk {
class IBundleResource : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.bundleManager.BundleResource");

    virtual ErrCode GetBundleResourceInfo(const std::string &bundleName, const uint32_t flags,
        BundleResourceInfo &bundleResourceInfo, const int32_t appIndex = 0)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode GetLauncherAbilityResourceInfo(const std::string &bundleName, const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfo, const int32_t appIndex = 0)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode GetAllBundleResourceInfo(const uint32_t flags,
        std::vector<BundleResourceInfo> &bundleResourceInfos)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode GetAllLauncherAbilityResourceInfo(const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode AddResourceInfoByBundleName(const std::string &bundleName, const int32_t userId)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode AddResourceInfoByAbility(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const int32_t userId)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode DeleteResourceInfo(const std::string &key)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode GetExtensionAbilityResourceInfo(const std::string &bundleName,
        const ExtensionAbilityType extensionAbilityType, const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &extensionAbilityResourceInfo, const int32_t appIndex = 0)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_RESOURCE_INTERFACE_H
