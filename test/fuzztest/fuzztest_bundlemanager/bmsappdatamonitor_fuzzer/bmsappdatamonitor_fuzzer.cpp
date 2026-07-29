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
#define private public
#include "app_data_monitor/app_data_monitor.h"
#include "bmsappdatamonitor_fuzzer.h"
#undef private
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    int32_t userId = GenerateRandomUser(fdp);
    monitor->IsScanning();
    monitor->StartScan(userId);
    std::string reason = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    monitor->StopScan(reason);
    monitor->StartScan(userId);
    // Fuzz the LARGE_FILES truncation path with arbitrary bytes; it must never crash or throw,
    // regardless of malformed JSON or oversized input.
    std::string payload = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string truncated;
    monitor->TruncateLargeFilesJson(payload, truncated);
    return true;
}
} // namespace OHOS

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
