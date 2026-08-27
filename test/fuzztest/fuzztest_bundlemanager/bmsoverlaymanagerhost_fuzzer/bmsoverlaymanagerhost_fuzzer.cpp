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

#include "bmsoverlaymanagerhost_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "overlay/overlay_manager_host.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr uint32_t CODE_MAX = 8;

// HandleGetAllOverlayModuleInfo: ReadString(bundleName), ReadInt32(userId)
void FuzzGetAllOverlayModuleInfo(OverlayManagerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<OverlayManagerHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);
    WriteUserId(data, fdp);
    FinishParcel(data);
    host.HandleGetAllOverlayModuleInfo(data, reply);
}

// HandleGetOverlayBundleInfoForTarget: ReadString(targetBundleName), ReadInt32(userId)
void FuzzGetOverlayBundleInfoForTarget(OverlayManagerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<OverlayManagerHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);
    WriteUserId(data, fdp);
    FinishParcel(data);
    host.HandleGetOverlayBundleInfoForTarget(data, reply);
}

// HandleGetOverlayModuleInfo: ReadString(bundleName), ReadString(moduleName), ReadInt32(userId)
void FuzzGetOverlayModuleInfo(OverlayManagerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<OverlayManagerHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);
    WritePlainString(data, fdp);
    WriteUserId(data, fdp);
    FinishParcel(data);
    host.HandleGetOverlayModuleInfo(data, reply);
}

// HandleGetOverlayModuleInfoByBundleName: ReadString(bundleName), ReadInt32(userId)
void FuzzGetOverlayModuleInfoByBundleName(OverlayManagerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<OverlayManagerHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);
    WriteUserId(data, fdp);
    FinishParcel(data);
    host.HandleGetOverlayModuleInfoByBundleName(data, reply);
}

// HandleGetOverlayModuleInfoByName: ReadString(moduleName), ReadInt32(userId)
void FuzzGetOverlayModuleInfoByName(OverlayManagerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<OverlayManagerHost>(data);
    MessageParcel reply;
    WritePlainString(data, fdp);
    WriteUserId(data, fdp);
    FinishParcel(data);
    host.HandleGetOverlayModuleInfoByName(data, reply);
}

// HandleGetOverlayModuleInfoForTarget: ReadString(targetBundleName), ReadString(targetModuleName), ReadInt32(userId)
void FuzzGetOverlayModuleInfoForTarget(OverlayManagerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<OverlayManagerHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);
    WritePlainString(data, fdp);
    WriteUserId(data, fdp);
    FinishParcel(data);
    host.HandleGetOverlayModuleInfoForTarget(data, reply);
}

// HandleGetTargetOverlayModuleInfo: ReadString(bundleName), ReadString(moduleName), ReadInt32(userId)
void FuzzGetTargetOverlayModuleInfo(OverlayManagerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<OverlayManagerHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);
    WritePlainString(data, fdp);
    WriteUserId(data, fdp);
    FinishParcel(data);
    host.HandleGetTargetOverlayModuleInfo(data, reply);
}

// HandleSetOverlayEnabled: ReadString(bundleName), ReadString(moduleName), ReadBool(enable), ReadInt32(userId)
void FuzzSetOverlayEnabled(OverlayManagerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<OverlayManagerHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);
    WritePlainString(data, fdp);
    WriteBoolField(data, fdp);
    WriteUserId(data, fdp);
    FinishParcel(data);
    host.HandleSetOverlayEnabled(data, reply);
}

// HandleSetOverlayEnabledForSelf: ReadString(bundleName), ReadBool(enable)
void FuzzSetOverlayEnabledForSelf(OverlayManagerHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<OverlayManagerHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);
    WriteBoolField(data, fdp);
    FinishParcel(data);
    host.HandleSetOverlayEnabledForSelf(data, reply);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    FuzzedDataProvider fdp(data, size);
    static OverlayManagerHost overlayManagerHost;

    // Layer 1: Stub loop
    FuzzIpcStubLoop(overlayManagerHost, data, size, CODE_MAX);

    // Layer 2: method layer - 9 methods with precise Parcel construction
enum OverlayMgrMethod {
    FUZZGETALLOVERLAYMODULEINFO = 0,
    FUZZGETOVERLAYBUNDLEINFOFORTARGET,
    FUZZGETOVERLAYMODULEINFO,
    FUZZGETOVERLAYMODULEINFOBYBUNDLENAME,
    FUZZGETOVERLAYMODULEINFOBYNAME,
    FUZZGETOVERLAYMODULEINFOFORTARGET,
    FUZZGETTARGETOVERLAYMODULEINFO,
    FUZZSETOVERLAYENABLED,
    FUZZSETOVERLAYENABLEDFORSELF,
    OVERLAY_MGR_METHOD_MAX,
};

    uint8_t methodSelector = fdp.ConsumeIntegral<uint8_t>();
    switch (methodSelector % OVERLAY_MGR_METHOD_MAX) {
        case FUZZGETALLOVERLAYMODULEINFO: FuzzGetAllOverlayModuleInfo(overlayManagerHost, fdp);        break;
        case FUZZGETOVERLAYBUNDLEINFOFORTARGET: FuzzGetOverlayBundleInfoForTarget(overlayManagerHost, fdp);  break;
        case FUZZGETOVERLAYMODULEINFO: FuzzGetOverlayModuleInfo(overlayManagerHost, fdp);          break;
        case FUZZGETOVERLAYMODULEINFOBYBUNDLENAME: FuzzGetOverlayModuleInfoByBundleName(overlayManagerHost, fdp); break;
        case FUZZGETOVERLAYMODULEINFOBYNAME: FuzzGetOverlayModuleInfoByName(overlayManagerHost, fdp);    break;
        case FUZZGETOVERLAYMODULEINFOFORTARGET: FuzzGetOverlayModuleInfoForTarget(overlayManagerHost, fdp); break;
        case FUZZGETTARGETOVERLAYMODULEINFO: FuzzGetTargetOverlayModuleInfo(overlayManagerHost, fdp);   break;
        case FUZZSETOVERLAYENABLED: FuzzSetOverlayEnabled(overlayManagerHost, fdp);            break;
        case FUZZSETOVERLAYENABLEDFORSELF: FuzzSetOverlayEnabledForSelf(overlayManagerHost, fdp);     break;
    }
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
