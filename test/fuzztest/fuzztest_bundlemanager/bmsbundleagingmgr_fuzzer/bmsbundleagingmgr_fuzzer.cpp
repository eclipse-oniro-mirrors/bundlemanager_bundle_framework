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
#include "bmsbundleagingmgr_fuzzer.h"
#include "bundle_aging_mgr.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    auto bundleAgingMgr = std::make_shared<BundleAgingMgr>();
    std::shared_ptr<BundleDataMgr> dataMgr = nullptr;
    bundleAgingMgr->Start(BundleAgingMgr::AgingTriggertype::FREE_INSTALL);
    bundleAgingMgr->Start(BundleAgingMgr::AgingTriggertype::UPDATE_REMOVABLE_FLAG);
    bundleAgingMgr->InitAgingtTimer();
    bundleAgingMgr->ResetRequest();
    bundleAgingMgr->IsReachStartAgingThreshold();
    std::vector<DeviceUsageStats::BundleActivePackageStats> results;
    bundleAgingMgr->QueryBundleStatsInfoByInterval(results);
    bundleAgingMgr->InitAgingRequest();
    bundleAgingMgr->Process(dataMgr);
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
