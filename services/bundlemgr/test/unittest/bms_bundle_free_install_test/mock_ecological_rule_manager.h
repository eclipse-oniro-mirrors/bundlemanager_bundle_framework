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

#ifndef OHOS_FORM_FWK_MOCK_ECOLOGICAL_RULE_MANAGER_H
#define OHOS_FORM_FWK_MOCK_ECOLOGICAL_RULE_MANAGER_H

#include <vector>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "erms_mgr_interface.h"
#include "erms_mgr_param.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

class EcologicalRuleMgrProxy : public OHOS::IRemoteProxy<IEcologicalRuleManager> {
public:
    explicit EcologicalRuleMgrProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IEcologicalRuleManager>(impl)
    {}
    virtual ~EcologicalRuleMgrProxy()
    {}

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

class EcologicalRuleMgrStub : public OHOS::IRemoteStub<IEcologicalRuleManager> {
public:
    EcologicalRuleMgrStub() {};
    virtual ~EcologicalRuleMgrStub() = default;

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

class EcologicalRuleMgrService : public EcologicalRuleMgrStub {
public:
    EcologicalRuleMgrService() {};
    virtual ~EcologicalRuleMgrService() override = default;

    MOCK_METHOD3(QueryFreeInstallExperience, int32_t(const Want &want,
        const ErmsParams::CallerInfo &callerInfo, ErmsParams::ExperienceRule &rule));
    MOCK_METHOD5(EvaluateResolveInfos, int32_t(const Want &want, const ErmsParams::CallerInfo &callerInfo,
        int32_t type, std::vector<AbilityInfo> &abilityInfos, std::vector<ExtensionAbilityInfo> extensionInfos));
    MOCK_METHOD3(QueryStartExperience, int32_t(const Want &want,
        const ErmsParams::CallerInfo &callerInfo, ErmsParams::ExperienceRule &rule));
    MOCK_METHOD2(QueryPublishFormExperience, int32_t(const Want &want, ErmsParams::ExperienceRule &rule));
    MOCK_METHOD3(IsSupportPublishForm, int32_t(const Want &want,
        const ErmsParams::CallerInfo &callerInfo, ErmsParams::ExperienceRule &rule));
    MOCK_METHOD0(QueryLastSyncTime, long());
};

class MockEcologicalRuleMgrService : public EcologicalRuleMgrService {
public:
    MockEcologicalRuleMgrService() = default;
    virtual ~MockEcologicalRuleMgrService() override = default;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_MOCK_ECOLOGICAL_RULE_MANAGER_H
