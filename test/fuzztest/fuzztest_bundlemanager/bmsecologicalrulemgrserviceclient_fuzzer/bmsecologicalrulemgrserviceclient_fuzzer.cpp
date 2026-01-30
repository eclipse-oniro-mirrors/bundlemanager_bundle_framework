/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#define private public
#include <fuzzer/FuzzedDataProvider.h>
#include "bmsecologicalrulemgrserviceclient_fuzzer.h"
#include "bms_ecological_rule_mgr_service_client.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using Want = OHOS::AAFwk::Want;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    BmsEcologicalRuleMgrServiceDeathRecipient bmsEcologicalRuleMgrServiceDeathRecipient;
    wptr<IRemoteObject> object = nullptr;
    bmsEcologicalRuleMgrServiceDeathRecipient.OnRemoteDied(object);
    sptr<IRemoteObject> object1;
    BmsEcologicalRuleMgrServiceProxy bmsEcologicalRuleMgrServiceProxy(object1);
    Want want;
    BmsCallerInfo callerInfo;
    BmsExperienceRule rule;
    bmsEcologicalRuleMgrServiceProxy.QueryFreeInstallExperience(want, callerInfo, rule);
    FuzzedDataProvider fdp(data, size);
    int32_t userId = GenerateRandomUser(fdp);
    std::shared_ptr<BmsEcologicalRuleMgrServiceClient> bmsEcologicalRuleMgrServiceClient =
        DelayedSingleton<BmsEcologicalRuleMgrServiceClient>::GetInstance();
    if (bmsEcologicalRuleMgrServiceClient == nullptr) {
        return false;
    }
    bmsEcologicalRuleMgrServiceClient->CheckConnectService();
    return true;
}
} // namespace OHOS

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}