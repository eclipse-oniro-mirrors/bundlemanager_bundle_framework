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

#include "bundle_event_callback_proxy.h"

#include "bmsbundleeventcallbackproxy_fuzzer.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    sptr<IRemoteObject> object;
    BundleEventCallbackProxy bundleEventCallbackProxy(object);
    int32_t userId = GenerateRandomUser(fdp);
    std::string uid = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string action = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::vector<std::string> utdIdVec;
    OHOS::AAFwk::Want want;
    want.SetAction(action);
    want.SetParam(Constants::USER_ID, userId);
    want.SetParam(uid, utdIdVec);
    EventFwk::CommonEventData eventData { want };
    bundleEventCallbackProxy.OnReceiveEvent(eventData);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}