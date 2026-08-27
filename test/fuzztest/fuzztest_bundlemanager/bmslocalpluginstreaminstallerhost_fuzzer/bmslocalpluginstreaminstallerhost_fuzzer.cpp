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

#include "bmslocalpluginstreaminstallerhost_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "bundle_framework_core_ipc_interface_code.h"
#include "local_plugin_stream_installer_host.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr uint32_t CODE_MAX = 1;

// HandleCreatePluginFileStream: ReadString(pluginFilePath)
void FuzzCreatePluginFileStream(LocalPluginStreamInstallerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<LocalPluginStreamInstallerHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // pluginFilePath
    FinishParcel(data);
    host.HandleCreatePluginFileStream(data, reply);
}

// HandleCommitLocalPluginInstall: no parameters
void FuzzCommitLocalPluginInstall(LocalPluginStreamInstallerHost& host, FuzzedDataProvider& fdp)
{
    (void)fdp;
    MessageParcel data;
    PrepareParcel<LocalPluginStreamInstallerHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleCommitLocalPluginInstall(data, reply);
}

enum LocalPluginStreamInstallerMethod {
    FUZZCREATEPLUGINFILESTREAM = 0,
    FUZZCOMMITLOCALPLUGININSTALL,
    LOCAL_PLUGIN_STREAM_INSTALLER_METHOD_MAX,
};

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    FuzzedDataProvider fdp(data, size);
    static LocalPluginStreamInstallerHost host;

    // Layer 1: Stub loop (correctly writes InterfaceToken via FuzzIpcStubLoop)
    FuzzIpcStubLoop(host, data, size, CODE_MAX);

    // Layer 2: method layer - 2 methods with precise Parcel construction
    uint8_t methodSelector = fdp.ConsumeIntegral<uint8_t>();
    switch (methodSelector % LOCAL_PLUGIN_STREAM_INSTALLER_METHOD_MAX) {
        case FUZZCREATEPLUGINFILESTREAM:
            FuzzCreatePluginFileStream(host, fdp);
            break;
        case FUZZCOMMITLOCALPLUGININSTALL:
            FuzzCommitLocalPluginInstall(host, fdp);
            break;
    }
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
