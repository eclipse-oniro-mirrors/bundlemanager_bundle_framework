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
#include <fuzzer/FuzzedDataProvider.h>

#include "app_control_proxy.h"

#include "bmsaddappjumpcontrolrule_fuzzer.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
namespace {
void GetRandomAppJumpControlRule(FuzzedDataProvider& fdp, AppJumpControlRule& appJumpControlRule)
{
    appJumpControlRule.jumpMode =
        static_cast<AbilityJumpMode>(fdp.ConsumeIntegralInRange<int8_t>(0, 2));
    appJumpControlRule.callerPkg = fdp.ConsumeRandomLengthString(BMSFuzzTestUtil::STRING_MAX_LENGTH);
    appJumpControlRule.targetPkg = fdp.ConsumeRandomLengthString(BMSFuzzTestUtil::STRING_MAX_LENGTH);
    appJumpControlRule.controlMessage = fdp.ConsumeRandomLengthString(BMSFuzzTestUtil::STRING_MAX_LENGTH);
}
}
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        sptr<IRemoteObject> object;
        AppControlProxy appControl(object);

        FuzzedDataProvider fdp(data, size);
        size_t arraySize = fdp.ConsumeIntegralInRange<size_t>(0, BMSFuzzTestUtil::ARRAY_MAX_LENGTH);

        std::vector<AppJumpControlRule> controlRules;
        for (size_t i = 0; i < arraySize; i++) {
            AppJumpControlRule appJumpControlRule;
            GetRandomAppJumpControlRule(fdp, appJumpControlRule);
            controlRules.emplace_back(appJumpControlRule);
        }

        int32_t userId = BMSFuzzTestUtil::GenerateRandomUser(fdp);
        appControl.AddAppJumpControlRule(controlRules, userId);
        return true;
    }
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}