/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "bmsquickfixmanagerhost_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "quick_fix/quick_fix_manager_host.h"
#include "ipc_object_stub.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr uint32_t CODE_MAX = 3;

// HandleDeployQuickFix: ReadStringVector(bundleFilePaths)
void FuzzDeployQuickFix(QuickFixManagerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<QuickFixManagerHost>(data);
    MessageParcel reply;
    WriteStringVectorField(data, fdp);
    FinishParcel(data);
    host.HandleDeployQuickFix(data, reply);
}

// HandleSwitchQuickFix: ReadString(bundleName), ReadBool(enable), ReadRemoteObject(object)
void FuzzSwitchQuickFix(QuickFixManagerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<QuickFixManagerHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteBoolField(data, fdp);                                   // enable
    WriteRemoteObject(data);                                      // object
    FinishParcel(data);
    host.HandleSwitchQuickFix(data, reply);
}

// HandleDeleteQuickFix: ReadString(bundleName), ReadRemoteObject(object)
void FuzzDeleteQuickFix(QuickFixManagerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<QuickFixManagerHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteRemoteObject(data);                                      // object
    FinishParcel(data);
    host.HandleDeleteQuickFix(data, reply);
}

// HandleCreateFd: ReadString(fileName)
void FuzzCreateFd(QuickFixManagerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<QuickFixManagerHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // fileName
    FinishParcel(data);
    host.HandleCreateFd(data, reply);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    FuzzedDataProvider fdp(data, size);
    static QuickFixManagerHost quickFixManagerHost;

    // Layer 1: Stub loop
    FuzzIpcStubLoop(quickFixManagerHost, data, size, CODE_MAX);

    // Layer 2: method layer - 4 methods with precise Parcel construction
enum QuickFixMgrMethod {
    FUZZDEPLOYQUICKFIX = 0,
    FUZZSWITCHQUICKFIX,
    FUZZDELETEQUICKFIX,
    FUZZCREATEFD,
    QUICK_FIX_MGR_METHOD_MAX,
};

    uint8_t methodSelector = fdp.ConsumeIntegral<uint8_t>();
    switch (methodSelector % QUICK_FIX_MGR_METHOD_MAX) {
        case FUZZDEPLOYQUICKFIX: FuzzDeployQuickFix(quickFixManagerHost, fdp);  break;
        case FUZZSWITCHQUICKFIX: FuzzSwitchQuickFix(quickFixManagerHost, fdp);  break;
        case FUZZDELETEQUICKFIX: FuzzDeleteQuickFix(quickFixManagerHost, fdp);  break;
        case FUZZCREATEFD: FuzzCreateFd(quickFixManagerHost, fdp);        break;
    }
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
