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

#include "bmsbundleusermgrhost_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "bundle_user_mgr_host.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr uint32_t CODE_MAX = 1;

// HandleCreateNewUser: ReadInt32(userId), ReadInt32(vectorSize), loop ReadString(disallowList)
void FuzzCreateNewUser(BundleUserMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleUserMgrHost>(data);
    MessageParcel reply;
    WriteUserId(data, fdp);                            // userId
    int32_t vectorSize = fdp.ConsumeIntegral<int32_t>() % MAX_PATH_COUNT;
    data.WriteInt32(vectorSize);                                         // vectorSize
    WriteStringVectorField(data, fdp);                               // disallowList
    FinishParcel(data);
    host.HandleCreateNewUser(data, reply);
}

// HandleRemoveUser: ReadInt32(userId)
void FuzzRemoveUser(BundleUserMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleUserMgrHost>(data);
    MessageParcel reply;
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleRemoveUser(data, reply);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    FuzzedDataProvider fdp(data, size);
    static BundleUserMgrHost bundleUserMgrHost;

    // Layer 1: Stub loop
    FuzzIpcStubLoop(bundleUserMgrHost, data, size, CODE_MAX);

    // Layer 2: method layer - 2 methods with precise Parcel construction
enum BundleUserMgrMethod {
    FUZZCREATENEWUSER = 0,
    FUZZREMOVEUSER,
    BUNDLE_USER_MGR_METHOD_MAX,
};

    uint8_t methodSelector = fdp.ConsumeIntegral<uint8_t>();
    switch (methodSelector % BUNDLE_USER_MGR_METHOD_MAX) {
        case FUZZCREATENEWUSER: FuzzCreateNewUser(bundleUserMgrHost, fdp); break;
        case FUZZREMOVEUSER: FuzzRemoveUser(bundleUserMgrHost, fdp);    break;
    }
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
