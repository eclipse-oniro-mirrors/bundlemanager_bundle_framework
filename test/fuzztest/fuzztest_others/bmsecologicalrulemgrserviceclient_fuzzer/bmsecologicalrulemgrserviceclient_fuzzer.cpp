/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "bmsecologicalrulemgrserviceclient_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#include "bms_ecological_rule_mgr_service_client.h"
#include "securec.h"

using Want = OHOS::AAFwk::Want;
using namespace OHOS::AppExecFwk;
namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t MESSAGE_SIZE = 4;
constexpr size_t DCAMERA_SHIFT_24 = 24;
constexpr size_t DCAMERA_SHIFT_16 = 16;
constexpr size_t DCAMERA_SHIFT_8 = 8;

uint32_t GetU32Data(const char* ptr)
{
    return (ptr[0] << DCAMERA_SHIFT_24) | (ptr[1] << DCAMERA_SHIFT_16) | (ptr[2] << DCAMERA_SHIFT_8) | (ptr[3]);
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
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
    int32_t userId = reinterpret_cast<uintptr_t>(data);
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
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }
    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}