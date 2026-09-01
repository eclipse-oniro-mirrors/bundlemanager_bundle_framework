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

#include "bmslocalplugininstallerhost_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "bundle_framework_core_ipc_interface_code.h"
#include "local_plugin_installer_host.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr uint32_t CODE_MAX = 3;

// HandleUninstallMessage: ReadString16(pluginBundleName), ReadRemoteObject(statusReceiver)
void FuzzUninstall(LocalPluginInstallerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<LocalPluginInstallerHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // pluginBundleName
    WriteRemoteObject(data);       // statusReceiver
    FinishParcel(data);
    host.HandleUninstallMessage(data, reply);
}

// HandleInternalUninstallMessage: ReadString16(bundleName), ReadString16(pluginBundleName), ReadInt32(userId)
void FuzzInternalUninstall(LocalPluginInstallerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<LocalPluginInstallerHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // bundleName
    WriteString16Field(data, fdp);  // pluginBundleName
    WriteUserId(data, fdp);         // userId
    FinishParcel(data);
    host.HandleInternalUninstallMessage(data, reply);
}

// HandleCreateLocalPluginStreamInstallerMessage: ReadRemoteObject(statusReceiver)
void FuzzCreateLocalPluginStreamInstaller(LocalPluginInstallerHost& host, FuzzedDataProvider& fdp)
{
    (void)fdp;
    MessageParcel data;
    PrepareParcel<LocalPluginInstallerHost>(data);
    MessageParcel reply;
    WriteRemoteObject(data);  // statusReceiver
    FinishParcel(data);
    host.HandleCreateLocalPluginStreamInstallerMessage(data, reply);
}

// HandleDestroyLocalPluginStreamInstallerMessage: ReadUint32(installerId)
void FuzzDestroyLocalPluginStreamInstaller(LocalPluginInstallerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<LocalPluginInstallerHost>(data);
    MessageParcel reply;
    WriteUint32Field(data, fdp);  // installerId
    FinishParcel(data);
    host.HandleDestroyLocalPluginStreamInstallerMessage(data, reply);
}

enum LocalPluginInstallerMethod {
    FUZZUNINSTALL = 0,
    FUZZINTERNALUNINSTALL,
    FUZZCREATELOCALPLUGINSTREAMINSTALLER,
    FUZZDESTROYLOCALPLUGINSTREAMINSTALLER,
    LOCAL_PLUGIN_INSTALLER_METHOD_MAX,
};

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    FuzzedDataProvider fdp(data, size);
    static LocalPluginInstallerHost host;

    // Layer 1: Stub loop (correctly writes InterfaceToken via FuzzIpcStubLoop)
    FuzzIpcStubLoop(host, data, size, CODE_MAX);

    // Layer 2: method layer - 4 methods with precise Parcel construction
    uint8_t methodSelector = fdp.ConsumeIntegral<uint8_t>();
    switch (methodSelector % LOCAL_PLUGIN_INSTALLER_METHOD_MAX) {
        case FUZZUNINSTALL:
            FuzzUninstall(host, fdp);
            break;
        case FUZZINTERNALUNINSTALL:
            FuzzInternalUninstall(host, fdp);
            break;
        case FUZZCREATELOCALPLUGINSTREAMINSTALLER:
            FuzzCreateLocalPluginStreamInstaller(host, fdp);
            break;
        case FUZZDESTROYLOCALPLUGINSTREAMINSTALLER:
            FuzzDestroyLocalPluginStreamInstaller(host, fdp);
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
