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

#include "bmsbundlestreaminstallerhost_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "bundle_stream_installer_host.h"
#include "message_parcel.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr uint32_t CODE_MAX = 5;

// HandleCreateStream: ReadString(fileName)
void FuzzCreateStream(BundleStreamInstallerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleStreamInstallerHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // fileName
    FinishParcel(data);
    host.HandleCreateStream(data, reply);
}

// HandleCreateSignatureFileStream: ReadString(moduleName), ReadString(fileName)
void FuzzCreateSignatureFileStream(BundleStreamInstallerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleStreamInstallerHost>(data);
    MessageParcel reply;
    WritePlainString(data, fdp);  // moduleName
    WriteStringField(data, fdp);  // fileName
    FinishParcel(data);
    host.HandleCreateSignatureFileStream(data, reply);
}

// HandleCreateSharedBundleStream: ReadString(hspName), ReadUint32(sharedBundleIdx)
void FuzzCreateSharedBundleStream(BundleStreamInstallerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleStreamInstallerHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // hspName
    WriteUint32Field(data, fdp);                   // sharedBundleIdx
    FinishParcel(data);
    host.HandleCreateSharedBundleStream(data, reply);
}

// HandleCreatePgoFileStream: ReadString(moduleName), ReadString(fileName)
void FuzzCreatePgoFileStream(BundleStreamInstallerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleStreamInstallerHost>(data);
    MessageParcel reply;
    WritePlainString(data, fdp);  // moduleName
    WriteStringField(data, fdp);  // fileName
    FinishParcel(data);
    host.HandleCreatePgoFileStream(data, reply);
}

// HandleCreateExtProfileFileStream: ReadString(fileName)
void FuzzCreateExtProfileFileStream(BundleStreamInstallerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleStreamInstallerHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // fileName
    FinishParcel(data);
    host.HandleCreateExtProfileFileStream(data, reply);
}

// HandleInstall: simplified - uses random data for complex InstallParam
void FuzzStreamInstall(BundleStreamInstallerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleStreamInstallerHost>(data);
    MessageParcel reply;
    auto remaining = fdp.ConsumeRemainingBytes<uint8_t>();
    data.WriteBuffer(remaining.data(), remaining.size());
    FinishParcel(data);
    host.HandleInstall(data, reply);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    FuzzedDataProvider fdp(data, size);
    static BundleStreamInstallerHost host;
    host.Init();

    // Layer 1: Stub loop
    FuzzIpcStubLoop(host, data, size, CODE_MAX);

    // Layer 2: method layer - 6 methods with precise Parcel construction
enum StreamInstallerMethod {
    FUZZCREATESTREAM = 0,
    FUZZCREATESIGNATUREFILESTREAM,
    FUZZCREATESHAREDBUNDLESTREAM,
    FUZZCREATEPGOFILESTREAM,
    FUZZCREATEEXTPROFILEFILESTREAM,
    FUZZSTREAMINSTALL,
    STREAM_INSTALLER_METHOD_MAX,
};

    uint8_t methodSelector = fdp.ConsumeIntegral<uint8_t>();
    switch (methodSelector % STREAM_INSTALLER_METHOD_MAX) {
        case FUZZCREATESTREAM: FuzzCreateStream(host, fdp);                break;
        case FUZZCREATESIGNATUREFILESTREAM: FuzzCreateSignatureFileStream(host, fdp);    break;
        case FUZZCREATESHAREDBUNDLESTREAM: FuzzCreateSharedBundleStream(host, fdp);    break;
        case FUZZCREATEPGOFILESTREAM: FuzzCreatePgoFileStream(host, fdp);          break;
        case FUZZCREATEEXTPROFILEFILESTREAM: FuzzCreateExtProfileFileStream(host, fdp);  break;
        case FUZZSTREAMINSTALL: FuzzStreamInstall(host, fdp);                break;
    }
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
