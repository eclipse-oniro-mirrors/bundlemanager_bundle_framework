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
#define private public
#include "installd_load_callback.h"
#include "bmsinstalldloadcallback_fuzzer.h"
#include "system_ability_definition.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    auto installdloadcallback = std::make_shared<InstalldLoadCallback>();
    if (installdloadcallback == nullptr) {
        return false;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t systemAbilityId = fdp.ConsumeIntegral<int32_t>();
    sptr<IRemoteObject> remoteObject = nullptr;
    installdloadcallback->OnLoadSystemAbilitySuccess(systemAbilityId, remoteObject);
    installdloadcallback->OnLoadSystemAbilitySuccess(INSTALLD_SERVICE_ID, remoteObject);
    installdloadcallback->OnLoadSystemAbilityFail(systemAbilityId);
    installdloadcallback->OnLoadSystemAbilityFail(INSTALLD_SERVICE_ID);
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