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

#include "bmsdeleteapprunningcontrolrule_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace {
void GetRandomAppRunningControlRule(FuzzedDataProvider& fdp, AppRunningControlRule& appRunningControlRule)
{
    appRunningControlRule.appId = fdp.ConsumeRandomLengthString(BMSFuzzTestUtil::STRING_MAX_LENGTH);
    appRunningControlRule.controlMessage = fdp.ConsumeRandomLengthString(BMSFuzzTestUtil::STRING_MAX_LENGTH);
}
}
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        sptr<IRemoteObject> object;
        AppControlProxy appControl(object);
        std::vector<AppRunningControlRule> controlRule;
        FuzzedDataProvider fdp(data, size);
        size_t arraySize = fdp.ConsumeIntegralInRange<size_t>(0, ARRAY_MAX_LENGTH);
        controlRule.reserve(arraySize);

        for (size_t i = 0; i < arraySize; ++i) {
            AppRunningControlRule rule;
            GetRandomAppRunningControlRule(fdp, rule);
            controlRule.emplace_back(rule);
        }
        int32_t userId = BMSFuzzTestUtil::GenerateRandomUser(fdp);

        appControl.DeleteAppRunningControlRule(controlRule, userId);
        appControl.DeleteAppRunningControlRule(userId);
        return true;
    }
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}