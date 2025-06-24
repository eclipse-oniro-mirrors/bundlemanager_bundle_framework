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

#define private public
#include <fuzzer/FuzzedDataProvider.h>

#include "aging_handler_chain.h"
#include "bmsaginghandlerchain_fuzzer.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    AgingRequest request;

    FuzzedDataProvider fdp(data, size);
    int64_t allBundleDataBytes = fdp.ConsumeIntegral<int64_t>();
    request.SetTotalDataBytes(allBundleDataBytes);
    AgingHandlerChain agingHandlerChain;
    std::shared_ptr<AgingHandler> handler;
    agingHandlerChain.AddHandler(handler);
    agingHandlerChain.Process(request);
    agingHandlerChain.InnerProcess(request);
    return true;
}
} // namespace OHOS

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}