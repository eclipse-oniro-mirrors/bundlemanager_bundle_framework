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

#include "bmsbundleresourcehost_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "bundle_resource_host.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr uint32_t CODE_MAX = 10;

// HandleGetBundleResourceInfo: ReadString(bundleName), ReadUint32(flags), ReadInt32(appIndex)
void FuzzGetBundleResourceInfo(BundleResourceHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleResourceHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUint32Field(data, fdp);                   // flags
    WriteInt32Field(data, fdp);                     // appIndex
    FinishParcel(data);
    host.HandleGetBundleResourceInfo(data, reply);
}

// HandleGetAllBundleResourceInfo: ReadUint32(flags)
void FuzzGetAllBundleResourceInfo(BundleResourceHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleResourceHost>(data);
    MessageParcel reply;
    WriteUint32Field(data, fdp);                   // flags
    FinishParcel(data);
    host.HandleGetAllBundleResourceInfo(data, reply);
}

// HandleGetLauncherAbilityResourceInfo: ReadUint32(flags)
void FuzzGetLauncherAbilityResourceInfo(BundleResourceHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleResourceHost>(data);
    MessageParcel reply;
    WriteUint32Field(data, fdp);                   // flags
    FinishParcel(data);
    host.HandleGetLauncherAbilityResourceInfo(data, reply);
}

// HandleGetAllLauncherAbilityResourceInfo: ReadUint32(flags)
void FuzzGetAllLauncherAbilityResourceInfo(BundleResourceHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleResourceHost>(data);
    MessageParcel reply;
    WriteUint32Field(data, fdp);                   // flags
    FinishParcel(data);
    host.HandleGetAllLauncherAbilityResourceInfo(data, reply);
}

// HandleGetAllUninstallBundleResourceInfo: ReadString(bundleName), ReadInt32(userId)
void FuzzGetAllUninstallBundleResourceInfo(BundleResourceHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleResourceHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleGetAllUninstallBundleResourceInfo(data, reply);
}

 // HandleAddResourceInfoByAbility: ReadString(bundleName), ReadString(moduleName), ReadString(abilityName),
// ReadInt32(userId)
void FuzzAddResourceInfoByAbility(BundleResourceHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleResourceHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    WritePlainString(data, fdp);  // abilityName
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleAddResourceInfoByAbility(data, reply);
}

// HandleAddResourceInfoByBundleName: ReadString(bundleName), ReadInt32(userId)
void FuzzAddResourceInfoByBundleName(BundleResourceHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleResourceHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleAddResourceInfoByBundleName(data, reply);
}

// HandleDeleteResourceInfo: ReadString(bundleName), ReadInt32(userId)
void FuzzDeleteResourceInfo(BundleResourceHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleResourceHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleDeleteResourceInfo(data, reply);
}

// HandleGetExtensionAbilityResourceInfo: ReadUint32(flags)
void FuzzGetExtensionAbilityResourceInfo(BundleResourceHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleResourceHost>(data);
    MessageParcel reply;
    WriteUint32Field(data, fdp);                   // flags
    FinishParcel(data);
    host.HandleGetExtensionAbilityResourceInfo(data, reply);
}

// HandleGetLauncherAbilityResourceInfoList: ReadUint32(flags)
void FuzzGetLauncherAbilityResourceInfoList(BundleResourceHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleResourceHost>(data);
    MessageParcel reply;
    WriteUint32Field(data, fdp);                   // flags
    FinishParcel(data);
    host.HandleGetLauncherAbilityResourceInfoList(data, reply);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    FuzzedDataProvider fdp(data, size);
    static BundleResourceHost bundleResourceHost;

    // Layer 1: Stub loop
    FuzzIpcStubLoop(bundleResourceHost, data, size, CODE_MAX);

    // Layer 2: method layer - 10 methods with precise Parcel construction
enum BundleResourceMethod {
    FUZZGETBUNDLERESOURCEINFO = 0,
    FUZZGETALLBUNDLERESOURCEINFO,
    FUZZGETLAUNCHERABILITYRESOURCEINFO,
    FUZZGETALLLAUNCHERABILITYRESOURCEINFO,
    FUZZGETALLUNINSTALLBUNDLERESOURCEINFO,
    FUZZADDRESOURCEINFOBYABILITY,
    FUZZADDRESOURCEINFOBYBUNDLENAME,
    FUZZDELETERESOURCEINFO,
    FUZZGETEXTENSIONABILITYRESOURCEINFO,
    FUZZGETLAUNCHERABILITYRESOURCEINFOLIST,
    BUNDLE_RESOURCE_METHOD_MAX,
};

    uint8_t methodSelector = fdp.ConsumeIntegral<uint8_t>();
    switch (methodSelector % BUNDLE_RESOURCE_METHOD_MAX) {
        case FUZZGETBUNDLERESOURCEINFO: FuzzGetBundleResourceInfo(bundleResourceHost, fdp);          break;
        case FUZZGETALLBUNDLERESOURCEINFO: FuzzGetAllBundleResourceInfo(bundleResourceHost, fdp);      break;
        case FUZZGETLAUNCHERABILITYRESOURCEINFO: FuzzGetLauncherAbilityResourceInfo(bundleResourceHost, fdp); break;
        case FUZZGETALLLAUNCHERABILITYRESOURCEINFO: FuzzGetAllLauncherAbilityResourceInfo(bundleResourceHost,
            fdp); break;
        case FUZZGETALLUNINSTALLBUNDLERESOURCEINFO: FuzzGetAllUninstallBundleResourceInfo(bundleResourceHost,
            fdp); break;
        case FUZZADDRESOURCEINFOBYABILITY: FuzzAddResourceInfoByAbility(bundleResourceHost, fdp);      break;
        case FUZZADDRESOURCEINFOBYBUNDLENAME: FuzzAddResourceInfoByBundleName(bundleResourceHost, fdp);  break;
        case FUZZDELETERESOURCEINFO: FuzzDeleteResourceInfo(bundleResourceHost, fdp);            break;
        case FUZZGETEXTENSIONABILITYRESOURCEINFO: FuzzGetExtensionAbilityResourceInfo(bundleResourceHost, fdp); break;
        case FUZZGETLAUNCHERABILITYRESOURCEINFOLIST: FuzzGetLauncherAbilityResourceInfoList(bundleResourceHost,
            fdp); break;
    }
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
