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

#ifndef OHOS_ABILITY_RUNTIME_ERMS_MGR_INTERFACE_H
#define OHOS_ABILITY_RUNTIME_ERMS_MGR_INTERFACE_H

#include <string>
#include <vector>

#include "iremote_broker.h"
#include "iremote_object.h"

#include "ability_info.h"
#include "erms_mgr_param.h"
#include "parcel.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
using AbilityInfo = OHOS::AppExecFwk::AbilityInfo;
using ExtensionAbilityInfo = OHOS::AppExecFwk::ExtensionAbilityInfo;

// when AG support the SA, this file needs to be removed.
class IEcologicalRuleManager : public OHOS::IRemoteBroker {
public:
    IEcologicalRuleManager() = default;
    virtual ~IEcologicalRuleManager() = default;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.IEcologicalRuleManagerService");

    virtual int32_t QueryFreeInstallExperience(const Want &want,
        const ErmsParams::CallerInfo &callerInfo, ErmsParams::ExperienceRule &rule)
    {
        return 0;
    }

    virtual int32_t EvaluateResolveInfos(const Want &want, const ErmsParams::CallerInfo &callerInfo, int32_t type,
        std::vector<AbilityInfo> &abilityInfos, std::vector<ExtensionAbilityInfo> extensionInfos)
    {
        return 0;
    }

    virtual int32_t QueryStartExperience(const Want &want,
        const ErmsParams::CallerInfo &callerInfo, ErmsParams::ExperienceRule &rule)
    {
        return 0;
    }

    virtual int32_t QueryPublishFormExperience(const Want &want, ErmsParams::ExperienceRule &rule)
    {
        return 0;
    }

    virtual int32_t IsSupportPublishForm(const Want &want, const ErmsParams::CallerInfo &callerInfo,
        ErmsParams::ExperienceRule &rule)
    {
        return 0;
    }

    virtual long QueryLastSyncTime()
    {
        return 0;
    }
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ERMS_MGR_INTERFACE_H
