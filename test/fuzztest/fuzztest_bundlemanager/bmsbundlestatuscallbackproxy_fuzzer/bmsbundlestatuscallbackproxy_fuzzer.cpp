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

#include "bundle_status_callback_proxy.h"

#include "bmsbundlestatuscallbackproxy_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        sptr<IRemoteObject> object;
        BundleStatusCallbackProxy callbackProxy(object);
        FuzzedDataProvider fdp(data, size);
        std::string resultMsg = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        uint8_t installType = fdp.ConsumeIntegral<uint8_t>();
        int32_t resultCode = fdp.ConsumeIntegral<int32_t>();
        int userId = fdp.ConsumeIntegral<int>();
        callbackProxy.OnBundleStateChanged(installType, resultCode, resultMsg, bundleName);
        callbackProxy.OnBundleAdded(bundleName, userId);
        int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
        callbackProxy.OnBundleAdded(bundleName, userId, appIndex);
        callbackProxy.OnBundleUpdated(bundleName, userId);
        callbackProxy.OnBundleUpdated(bundleName, userId, appIndex);
        callbackProxy.OnBundleRemoved(bundleName, userId);
        callbackProxy.OnBundleRemoved(bundleName, userId, appIndex);
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