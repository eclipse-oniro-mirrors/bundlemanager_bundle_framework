/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "bundle_framework_core_ipc_interface_code.h"
#include "get_largest_items_callback_host.h"

#include "bmsgetlargestitemscallbackhost_fuzzer.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr uint32_t CODE_MAX = 0;

class GetLargestItemsCallbackHostTest : public GetLargestItemsCallbackHost {
public:
    GetLargestItemsCallbackHostTest() = default;
    virtual ~GetLargestItemsCallbackHostTest() = default;

    void OnGetLargestItemsFinished(ErrCode errCode, const std::string &largestItems) override
    {
        (void)errCode;
        (void)largestItems;
        return;
    }
};

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    GetLargestItemsCallbackHostTest callbackHost;
    // Layer 1: Stub loop (correctly writes InterfaceToken via FuzzIpcStubLoop)
    FuzzIpcStubLoop(callbackHost, data, size, CODE_MAX);
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
