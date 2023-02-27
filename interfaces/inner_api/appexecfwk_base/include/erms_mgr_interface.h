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
#include "parcel.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
using AbilityInfo = OHOS::AppExecFwk::AbilityInfo;
using ExtensionAbilityInfo = OHOS::AppExecFwk::ExtensionAbilityInfo;

namespace ErmsParams {
struct ExperienceRule : public Parcelable {
    bool isAllow = false;
    std::shared_ptr <Want> replaceWant = nullptr;
    int64_t sceneCode = 0L;
    std::vector <int64_t> allowTypes;

    bool ReadFromParcel(Parcel &parcel);

    virtual bool Marshalling(Parcel &parcel) const override;

    static ExperienceRule *Unmarshalling(Parcel &parcel);
};

struct CallerInfo : public Parcelable {
    std::string packageName;
    int64_t uid = 0L;
    int64_t pid = 0L;

    bool ReadFromParcel(Parcel &parcel);

    virtual bool Marshalling(Parcel &parcel) const override;

    static CallerInfo *Unmarshalling(Parcel &parcel);
};
}

// when AG support the SA, this file needs to be removed.
class IEcologicalRuleManager : public IRemoteBroker {
public:
    explicit IEcologicalRuleManager();
    virtual ~IEcologicalRuleManager() = default;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.bundlemanager.IEcologicalRuleManagerService");

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
