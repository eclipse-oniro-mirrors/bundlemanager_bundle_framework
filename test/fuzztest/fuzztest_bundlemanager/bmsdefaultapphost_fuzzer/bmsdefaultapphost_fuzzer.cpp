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

#include "bmsdefaultapphost_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "default_app_host.h"
#include "want.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
using namespace OHOS::AAFwk;
namespace OHOS {
constexpr uint32_t CODE_MAX = 5;

// HandleIsDefaultApplication: ReadString(type), ReadInt32(userId)
void FuzzIsDefaultApplication(DefaultAppHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<DefaultAppHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // type
    WriteUserId(data, fdp);           // userId
    FinishParcel(data);
    host.HandleIsDefaultApplication(data, reply);
}

// HandleGetDefaultApplication: ReadString(type), ReadInt32(userId)
void FuzzGetDefaultApplication(DefaultAppHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<DefaultAppHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // type
    WriteUserId(data, fdp);           // userId
    FinishParcel(data);
    host.HandleGetDefaultApplication(data, reply);
}

// HandleSetDefaultApplication: ReadString(type), ReadParcelable<Want>, ReadInt32(userId)
void FuzzSetDefaultApplication(DefaultAppHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<DefaultAppHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // type
    WriteWant(data, fdp);             // Want
    WriteUserId(data, fdp);           // userId
    FinishParcel(data);
    host.HandleSetDefaultApplication(data, reply);
}

// HandleResetDefaultApplication: ReadString(type), ReadInt32(userId)
void FuzzResetDefaultApplication(DefaultAppHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<DefaultAppHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // type
    WriteUserId(data, fdp);           // userId
    FinishParcel(data);
    host.HandleResetDefaultApplication(data, reply);
}

// HandleSetDefaultApplicationForAppClone: ReadString(type), ReadParcelable<Want>, ReadInt32(userId)
void FuzzSetDefaultApplicationForAppClone(DefaultAppHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<DefaultAppHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // type
    WriteWant(data, fdp);             // Want
    WriteUserId(data, fdp);           // userId
    FinishParcel(data);
    host.HandleSetDefaultApplicationForAppClone(data, reply);
}

// HandleSetDefaultApplicationForCustom: ReadString(type), ReadParcelable<Want>, ReadInt32(userId)
void FuzzSetDefaultApplicationForCustom(DefaultAppHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<DefaultAppHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // type
    WriteWant(data, fdp);             // Want
    WriteUserId(data, fdp);           // userId
    FinishParcel(data);
    host.HandleSetDefaultApplicationForCustom(data, reply);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    FuzzedDataProvider fdp(data, size);
    static DefaultAppHost defaultAppHost;

    // Layer 1: Stub loop
    FuzzIpcStubLoop(defaultAppHost, data, size, CODE_MAX);

    // Layer 2: method layer - 6 methods with precise Parcel construction
enum DefaultAppMethod {
    FUZZISDEFAULTAPPLICATION = 0,
    FUZZGETDEFAULTAPPLICATION,
    FUZZSETDEFAULTAPPLICATION,
    FUZZRESETDEFAULTAPPLICATION,
    FUZZSETDEFAULTAPPLICATIONFORAPPCLONE,
    FUZZSETDEFAULTAPPLICATIONFORCUSTOM,
    DEFAULT_APP_METHOD_MAX,
};

    uint8_t methodSelector = fdp.ConsumeIntegral<uint8_t>();
    switch (methodSelector % DEFAULT_APP_METHOD_MAX) {
        case FUZZISDEFAULTAPPLICATION: FuzzIsDefaultApplication(defaultAppHost, fdp);             break;
        case FUZZGETDEFAULTAPPLICATION: FuzzGetDefaultApplication(defaultAppHost, fdp);            break;
        case FUZZSETDEFAULTAPPLICATION: FuzzSetDefaultApplication(defaultAppHost, fdp);            break;
        case FUZZRESETDEFAULTAPPLICATION: FuzzResetDefaultApplication(defaultAppHost, fdp);          break;
        case FUZZSETDEFAULTAPPLICATIONFORAPPCLONE: FuzzSetDefaultApplicationForAppClone(defaultAppHost, fdp); break;
        case FUZZSETDEFAULTAPPLICATIONFORCUSTOM: FuzzSetDefaultApplicationForCustom(defaultAppHost, fdp);   break;
    }
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
