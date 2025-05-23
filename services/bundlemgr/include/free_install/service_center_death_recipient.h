/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_FREE_INSTALL_SERVICE_CENTER_DEATH_RECIPIENT_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_FREE_INSTALL_SERVICE_CENTER_DEATH_RECIPIENT_H

#include "bundle_connect_ability_mgr.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {
class BundleConnectAbilityMgr;
class ServiceCenterDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    ServiceCenterDeathRecipient(const std::weak_ptr<BundleConnectAbilityMgr> connectAbilityMgr)
        : connectAbilityMgr_(connectAbilityMgr)
    {
    }
    void OnRemoteDied(const wptr<IRemoteObject> &wptrDeath) override;

private:
    std::weak_ptr<BundleConnectAbilityMgr> connectAbilityMgr_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  //  FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_FREE_INSTALL_SERVICE_CENTER_DEATH_RECIPIENT_H