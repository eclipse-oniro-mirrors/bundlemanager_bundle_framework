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
#include "ipc_object_stub.h"
#include "clean_cache_callback_proxy.h"

#include "bmscleanbundlecachefiles_fuzzer.h"
#include "bms_fuzztest_util.h"

using Want = OHOS::AAFwk::Want;

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        sptr<IRemoteObject> object = new (std::nothrow) IPCObjectStub(u"");
        if (object == nullptr) {
            return false;
        }
        BundleMgrProxy bundleMgrProxy(object);
        FuzzedDataProvider fdp(data, size);
        std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        sptr<IRemoteObject> callbackObj = new (std::nothrow) IPCObjectStub(u"");
        sptr<ICleanCacheCallback> cleanCacheCallback = iface_cast<ICleanCacheCallback>(callbackObj);
        int32_t userId = GenerateRandomUser(fdp);
        int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
        bundleMgrProxy.CleanBundleCacheFiles(bundleName, cleanCacheCallback, userId, appIndex);
        bundleMgrProxy.CleanBundleCacheFilesForSelf(cleanCacheCallback);
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