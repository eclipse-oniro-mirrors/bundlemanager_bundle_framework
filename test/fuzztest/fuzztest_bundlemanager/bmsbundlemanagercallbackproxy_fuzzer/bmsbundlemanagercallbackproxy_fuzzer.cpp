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
#include <set>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "bundle_manager_callback_proxy.h"
#include "bmsbundlemanagercallbackproxy_fuzzer.h"
#include "bms_fuzztest_util.h"

using Want = OHOS::AAFwk::Want;

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    sptr<IRemoteObject> impl = nullptr;
    std::shared_ptr<BundleManagerCallbackProxy> BundleDistributedManager_ =
        std::make_shared<BundleManagerCallbackProxy>(impl);
    if (BundleDistributedManager_ == nullptr) {
        return false;
    }
    FuzzedDataProvider fdp(data, size);
    std::string installResult = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    BundleDistributedManager_->OnQueryRpcIdFinished(installResult);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}