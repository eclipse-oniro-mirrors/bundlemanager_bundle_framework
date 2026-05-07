/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_SKILL_SKILL_MANAGER_PROXY_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_SKILL_SKILL_MANAGER_PROXY_H

#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_skill/skill_manager_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AppExecFwk {
class BundleSkillManagerProxy : public IRemoteProxy<IBundleSkillManager> {
public:
    explicit BundleSkillManagerProxy(const sptr<IRemoteObject>& object);
    virtual ~BundleSkillManagerProxy() = default;

    virtual ErrCode GetSkillInfoForSelf(const std::string &moduleName, const std::string &skillName,
        uint32_t flags, SkillInfo &skillInfo) override;

    virtual ErrCode GetSkillInfosForSelf(uint32_t flags, std::vector<SkillInfo> &skillInfos) override;

    virtual ErrCode GetSkillInfo(const std::string &bundleName, const std::string &moduleName,
        const std::string &skillName, uint32_t flags, int32_t userId, SkillInfo &skillInfo) override;

    virtual ErrCode GetSkillInfos(const std::string &bundleName, uint32_t flags,
        int32_t userId, std::vector<SkillInfo> &skillInfos) override;

    virtual ErrCode GetAllSkillInfos(uint32_t flags, int32_t userId,
        std::vector<SkillInfo> &skillInfos) override;

private:
    bool SendRequest(SkillManagerInterfaceCode code, MessageParcel &data, MessageParcel &reply);

    static inline BrokerDelegator<BundleSkillManagerProxy> delegator_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_SKILL_SKILL_MANAGER_PROXY_H
