/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "app_running_control_rule.h"
#include "parcel.h"

#include "bmsapprunningcontrolrule_fuzzer.h"
#include "../../bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
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
        Parcel dataMessageParcel;
        AppRunningControlRule oldRule;

        FuzzedDataProvider fdp(data, size);
        GetRandomAppRunningControlRule(fdp, oldRule);
        if (!oldRule.Marshalling(dataMessageParcel)) {
            return false;
        }
        auto rulePtr = AppRunningControlRule::Unmarshalling(dataMessageParcel);
        if (rulePtr == nullptr) {
            return false;
        }
        delete rulePtr;
        rulePtr = nullptr;

        AppRunningControlRule readRule;
        GetRandomAppRunningControlRule(fdp, readRule);
        bool ret = readRule.ReadFromParcel(dataMessageParcel);
        return ret;
    }
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
