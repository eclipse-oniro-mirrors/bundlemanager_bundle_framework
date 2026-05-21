/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "servicecenterconnection_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "bms_fuzztest_util.h"
#include "service_center_connection.h"
#include "securec.h"

using Want = OHOS::AAFwk::Want;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t MESSAGE_SIZE = 4;
constexpr size_t DCAMERA_SHIFT_24 = 24;
constexpr size_t DCAMERA_SHIFT_16 = 16;
constexpr size_t DCAMERA_SHIFT_8 = 8;

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    int32_t connectState = 0;
    std::condition_variable cv;
    const std::weak_ptr<BundleConnectAbilityMgr> connectAbilityMgr;
    ServiceCenterConnection serviceCenterConnection(connectState, cv, connectAbilityMgr);
    sptr<IRemoteObject> remoteObject = nullptr;
    ElementName element;
    FuzzedDataProvider fdp(data, size);
    int32_t resultCode = GenerateRandomUser(fdp);
    serviceCenterConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    serviceCenterConnection.OnAbilityDisconnectDone(element, resultCode);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}