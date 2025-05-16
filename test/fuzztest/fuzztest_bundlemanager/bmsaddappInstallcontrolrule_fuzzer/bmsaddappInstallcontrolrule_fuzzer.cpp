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

#include "bmsaddappInstallcontrolrule_fuzzer.h"
#include "../../bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        sptr<IRemoteObject> object;
        AppControlProxy appControl(object);

        FuzzedDataProvider fdp(data, size);
        AppInstallControlRuleType controlRuleType =
            static_cast<AppInstallControlRuleType>(fdp.ConsumeIntegralInRange<int8_t>(0, 3));
        std::vector<std::string> appIds = BMSFuzzTestUtil::GenerateStringArray(fdp);
        int32_t userId = fdp.ConsumeIntegral<int32_t>();
        appControl.AddAppInstallControlRule(appIds, controlRuleType, userId);
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