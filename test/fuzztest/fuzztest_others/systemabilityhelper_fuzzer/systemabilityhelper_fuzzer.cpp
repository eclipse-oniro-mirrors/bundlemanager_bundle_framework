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
#include "systemabilityhelper_fuzzer.h"

#include <iostream>
#include <fuzzer/FuzzedDataProvider.h>

#include "bms_fuzztest_util.h"
#include "securec.h"
#include "system_ability_helper.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t ENABLE = 2;
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    SystemAbilityHelper helper;
    FuzzedDataProvider fdp(data, size);
    int32_t systemAbilityId = fdp.ConsumeIntegral<int32_t>();
    helper.GetSystemAbility(systemAbilityId);
    helper.RemoveSystemAbility(systemAbilityId);
    sptr<IRemoteObject> systemAbility;
    helper.AddSystemAbility(systemAbilityId, systemAbility);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t uid = fdp.ConsumeIntegral<int32_t>();
    helper.UninstallApp(bundleName, uid, systemAbilityId);
    helper.UpgradeApp(bundleName, uid, systemAbilityId);
    helper.UnloadSystemAbility(systemAbilityId);
    return true;
}
} // namespace OHOS

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}