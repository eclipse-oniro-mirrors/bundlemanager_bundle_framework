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

#ifndef BMS_SERVICES_INCLUDE_ECOLOGICAL_RULE_MANAGER_SERVICE_CLIENT_H
#define BMS_SERVICES_INCLUDE_ECOLOGICAL_RULE_MANAGER_SERVICE_CLIENT_H
#include <mutex>
#include "iremote_proxy.h"
#include "bms_ecological_rule_mgr_service_interface.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {

using namespace std;
using Want = OHOS::AAFwk::Want;

class BmsEcologicalRuleMgrServiceDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    BmsEcologicalRuleMgrServiceDeathRecipient() {};
    ~BmsEcologicalRuleMgrServiceDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &object) override;

private:
    DISALLOW_COPY_AND_MOVE(BmsEcologicalRuleMgrServiceDeathRecipient);
};

class BmsEcologicalRuleMgrServiceProxy : public OHOS::IRemoteProxy<IBmsEcologicalRuleMgrService> {
public:
    explicit BmsEcologicalRuleMgrServiceProxy(const sptr<IRemoteObject> &object);
    ~BmsEcologicalRuleMgrServiceProxy() = default;
    DISALLOW_COPY_AND_MOVE(BmsEcologicalRuleMgrServiceProxy);

    int32_t QueryFreeInstallExperience(const Want &want, const BmsCallerInfo &callerInfo,
        BmsExperienceRule &rule) override;

private:
    template <typename T> bool ReadParcelableVector(vector<T> &parcelableVector, MessageParcel &reply);
    static inline BrokerDelegator<BmsEcologicalRuleMgrServiceProxy> delegator_;
};

class BmsEcologicalRuleMgrServiceClient : public DelayedSingleton<BmsEcologicalRuleMgrServiceClient> {
public:
    BmsEcologicalRuleMgrServiceClient();
    ~BmsEcologicalRuleMgrServiceClient();

    void OnRemoteSaDied(const wptr<IRemoteObject> &object);
    int32_t QueryFreeInstallExperience(const Want &want, const BmsCallerInfo &callerInfo, BmsExperienceRule &rule);

private:
    static sptr<IBmsEcologicalRuleMgrService> ConnectService();
    static bool CheckConnectService();

    static sptr<IBmsEcologicalRuleMgrService> bmsEcologicalRuleMgrServiceProxy_;
    static sptr<BmsEcologicalRuleMgrServiceDeathRecipient> deathRecipient_;

    static string ERMS_ORIGINAL_TARGET;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // BMS_SERVICES_INCLUDE_ECOLOGICAL_RULE_MANAGER_SERVICE_CLIENT_H
