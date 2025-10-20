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
#include "bundle_framework_core_ipc_interface_code.h"
#include "clean_cache_callback_host.h"

#include "bmscleancachecallbackhost_fuzzer.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
class CleanCacheCallbackHostTest : public CleanCacheCallbackHost {
public:
    CleanCacheCallbackHostTest() = default;
    virtual ~CleanCacheCallbackHostTest() = default;
    void OnCleanCacheFinished(bool succeeded)
    {
        return;
    }
};
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    CleanCacheCallbackHostTest cleanCacheCallbackHost;
    uint32_t code = fdp.ConsumeIntegral<uint32_t>();
    MessageParcel datas;
    MessageParcel reply;
    MessageOption option;
    cleanCacheCallbackHost.OnRemoteRequest(code, datas, reply, option);
    cleanCacheCallbackHost.OnRemoteRequest(static_cast<uint32_t>
        (CleanCacheCallbackInterfaceCode::ON_CLEAN_CACHE_CALLBACK), datas, reply, option);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}