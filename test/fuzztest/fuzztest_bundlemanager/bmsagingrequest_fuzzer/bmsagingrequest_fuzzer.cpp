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

#include "aging_request.h"
#include "bms_fuzztest_util.h"
#include "bmsagingrequest_fuzzer.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    AgingBundleInfo bundleInfo;
    AgingRequest agingRequest;
    agingRequest.IsReachStartAgingThreshold();
    agingRequest.IsReachEndAgingThreshold();
    agingRequest.SortAgingBundles();
    agingRequest.ResetRequest();
    agingRequest.Dump();
    agingRequest.AddAgingBundle(bundleInfo);
    agingRequest.GetAgingBundles();
    int64_t dataBytes = fdp.ConsumeIntegral<int64_t>();
    agingRequest.UpdateTotalDataBytesAfterUninstalled(dataBytes);
    agingRequest.GetTotalDataBytes();
    agingRequest.SetTotalDataBytes(dataBytes);
    AgingCleanType agingCleanType = static_cast<AgingCleanType>(fdp.ConsumeIntegral<uint8_t>() % CODE_MAX_TWO);
    agingRequest.SetAgingCleanType(agingCleanType);
    agingRequest.GetAgingCleanType();
    agingRequest.GetTotalDataBytesThreshold();
    agingRequest.GetOneDayTimeMs();
    agingRequest.InitAgingPolicySystemParameters();
    agingRequest.InitAgingDatasizeThreshold();
    agingRequest.InitAgingOneDayTimeMs();
    return true;
}
} // namespace OHOS

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}