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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_SKILL_SKILL_MANAGER_INTERFACE_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_SKILL_SKILL_MANAGER_INTERFACE_H

#include "appexecfwk_errors.h"
#include "bundle_skill/skill_info.h"
#include "iremote_broker.h"

namespace OHOS {
namespace AppExecFwk {
class IBundleSkillManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.bundleManager.SkillManager");

    virtual ErrCode GetSkillInfoForSelf(const std::string &moduleName, const std::string &skillName,
        int32_t userId, uint32_t flags, SkillInfo &skillInfo)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode GetSkillInfosForSelf(uint32_t flags, int32_t userId,
        std::vector<SkillInfo> &skillInfos)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode GetSkillInfo(const std::string &bundleName, const std::string &moduleName,
        const std::string &skillName, uint32_t flags, int32_t userId, SkillInfo &skillInfo)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode GetSkillInfos(const std::string &bundleName, const uint32_t flags,
        int32_t userId, std::vector<SkillInfo> &skillInfos)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    virtual ErrCode GetAllSkillInfos(uint32_t flags, int32_t userId,
        std::vector<SkillInfo> &skillInfos)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_SKILL_SKILL_MANAGER_INTERFACE_H
