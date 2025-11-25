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

#include "aging/aging_constants.h"
#include "aging_bundle_info.h"
#include "aging_util.h"
#include "bmsagingutil_fuzzer.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    AgingBundleInfo agingBundleInfo1{
        fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH),
        fdp.ConsumeIntegral<int64_t>(),
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeBool()
    };

    AgingBundleInfo agingBundleInfo2{
        fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH),
        fdp.ConsumeIntegral<int64_t>(),
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeBool()
    };
    std::vector<AgingBundleInfo> bundles{agingBundleInfo1, agingBundleInfo2};
    AgingUtil::SortAgingBundles(bundles);
    AgingUtil::SortTwoAgingBundleInfos(agingBundleInfo1, agingBundleInfo2);
    AgingUtil::GetUnusedTimeMsBaseOnCurrentTime(
        fdp.ConsumeIntegral<int64_t>(),
        fdp.ConsumeIntegral<int32_t>()
    );
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
