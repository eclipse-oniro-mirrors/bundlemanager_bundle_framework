/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "bundle_mgr_proxy.h"

#include "bmsbatchsetenabled_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t userId = GenerateRandomUser(fdp);
    int32_t enableAppIndex = fdp.ConsumeIntegral<int32_t>();
    int32_t disableAppIndex = fdp.ConsumeIntegral<int32_t>();
    bool killProcess = fdp.ConsumeBool();
    bool needSendEvent = fdp.ConsumeBool();

    // Fuzz BatchSetApplicationEnabled via proxy (null remote, should return parcel error)
    sptr<IRemoteObject> object;
    BundleMgrProxy bundleMgrProxy(object);
    bundleMgrProxy.BatchSetApplicationEnabled(userId, enableAppIndex, disableAppIndex, killProcess, needSendEvent);

    // Fuzz with boundary appIndex values
    bundleMgrProxy.BatchSetApplicationEnabled(userId, -1, 1, true, true);
    bundleMgrProxy.BatchSetApplicationEnabled(userId, 1, -1, true, true);
    bundleMgrProxy.BatchSetApplicationEnabled(userId, 0, 0, false, false);
    bundleMgrProxy.BatchSetApplicationEnabled(userId, 1, 1, false, false);

    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
}
