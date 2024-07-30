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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_RESOURCE_PROXY_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_RESOURCE_PROXY_H

#include "bundle_resource_interface.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AppExecFwk {
class BundleResourceProxy : public IRemoteProxy<IBundleResource> {
public:
    explicit BundleResourceProxy(const sptr<IRemoteObject>& object);
    virtual ~BundleResourceProxy() = default;

    virtual ErrCode GetBundleResourceInfo(const std::string &bundleName, const uint32_t flags,
        BundleResourceInfo &bundleResourceInfo, const int32_t appIndex = 0) override;

    virtual ErrCode GetLauncherAbilityResourceInfo(const std::string &bundleName, const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfo, const int32_t appIndex = 0) override;

    virtual ErrCode GetAllBundleResourceInfo(const uint32_t flags,
        std::vector<BundleResourceInfo> &bundleResourceInfos) override;

    virtual ErrCode GetAllLauncherAbilityResourceInfo(const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos) override;

    virtual ErrCode AddResourceInfoByBundleName(const std::string &bundleName, const int32_t userId) override;

    virtual ErrCode AddResourceInfoByAbility(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const int32_t userId) override;

    virtual ErrCode DeleteResourceInfo(const std::string &key) override;

private:
    template<typename T>
    ErrCode GetParcelInfo(BundleResourceInterfaceCode code, MessageParcel &data, T &parcelInfo);

    template<typename T>
    ErrCode GetVectorParcelInfo(
        BundleResourceInterfaceCode code, MessageParcel &data, std::vector<T> &parcelInfos);

    ErrCode GetParcelInfoFromAshMem(MessageParcel &reply, void *&data);

    void ClearAshmem(sptr<Ashmem> &optMem);

    bool SendRequest(BundleResourceInterfaceCode code, MessageParcel &data, MessageParcel &reply);

    static inline BrokerDelegator<BundleResourceProxy> delegator_;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_RESOURCE_PROXY_H
