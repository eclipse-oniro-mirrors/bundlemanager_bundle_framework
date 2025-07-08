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
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "bundle_resource_event_subscriber.h"
#include "common_event_support.h"
#include "securec.h"

#include "bmsbundleresourceeventsubscriber_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    OHOS::EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto subscriberPtr = std::make_shared<BundleResourceEventSubscriber>(subscribeInfo);

    OHOS::EventFwk::CommonEventData commonEventData;
    subscriberPtr->OnReceiveEvent(commonEventData);

    OHOS::AAFwk::Want want;

    want.SetParam("oldId", Constants::DEFAULT_USERID);
    commonEventData.SetWant(want);
    subscriberPtr->OnReceiveEvent(commonEventData);

    want.SetParam("oldId", Constants::INVALID_USERID);
    commonEventData.SetWant(want);
    subscriberPtr->OnReceiveEvent(commonEventData);

    want.SetParam("oldId", Constants::U1);
    commonEventData.SetWant(want);
    subscriberPtr->OnReceiveEvent(commonEventData);

    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    want.SetParam("oldId", userId);
    commonEventData.SetWant(want);
    subscriberPtr->OnReceiveEvent(commonEventData);

    int32_t oldUserId = fdp.ConsumeIntegral<int32_t>();
    int32_t newUserId = fdp.ConsumeIntegral<int32_t>();
    subscriberPtr->OnUserIdChanged(oldUserId, newUserId);

    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}