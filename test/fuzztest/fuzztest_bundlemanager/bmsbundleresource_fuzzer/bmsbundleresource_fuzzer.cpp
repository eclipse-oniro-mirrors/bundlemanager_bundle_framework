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

#include "bundle_resource/bundle_resource_configuration.h"
#include "bundle_resource/bundle_resource_rdb.h"
#include "bundle_resource/resource_info.h"

#include "bmsbundleresource_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    BundleResourceRdb rdb;
    FuzzedDataProvider fdp(data, size);

    ResourceInfo info;
    info.bundleName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    rdb.AddResourceInfo(info);
    info.moduleName_ = "";
    rdb.AddResourceInfo(info);

    std::vector<ResourceInfo> infos;
    rdb.AddResourceInfos(infos);
    infos.push_back(info);
    rdb.AddResourceInfos(infos);
    info.icon_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    infos.push_back(info);
    rdb.AddResourceInfos(infos);

    rdb.DeleteResourceInfo(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    rdb.DeleteResourceInfo("");
    rdb.DeleteResourceInfo("invalid_key");

    std::vector<std::string> keyNames;
    rdb.GetResourceNameByBundleName(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH),
        fdp.ConsumeIntegral<int32_t>(), keyNames);
    rdb.GetResourceNameByBundleName("", fdp.ConsumeIntegral<int32_t>(), keyNames);

    BundleResourceInfo bundleResourceInfo;
    rdb.GetBundleResourceInfo(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH),
        fdp.ConsumeIntegral<uint32_t>(), bundleResourceInfo, fdp.ConsumeIntegral<int32_t>());
    rdb.GetBundleResourceInfo("", fdp.ConsumeIntegral<uint32_t>(), bundleResourceInfo, fdp.ConsumeIntegral<int32_t>());

    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    rdb.GetLauncherAbilityResourceInfo(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH),
        fdp.ConsumeIntegral<uint32_t>(), launcherAbilityResourceInfos, fdp.ConsumeIntegral<int32_t>());
    rdb.GetLauncherAbilityResourceInfo("", fdp.ConsumeIntegral<uint32_t>(), launcherAbilityResourceInfos,
        fdp.ConsumeIntegral<int32_t>());

    rdb.ConvertToBundleResourceInfo(nullptr, fdp.ConsumeIntegral<uint32_t>(), bundleResourceInfo);

    LauncherAbilityResourceInfo launcherAbilityResourceInfo;
    rdb.ConvertToLauncherAbilityResourceInfo(nullptr, fdp.ConsumeIntegral<uint32_t>(), launcherAbilityResourceInfo);

    rdb.ConvertToExtensionAbilityResourceInfo(nullptr, fdp.ConsumeIntegral<uint32_t>(),
        launcherAbilityResourceInfo);

    std::string systemState;
    rdb.GetCurrentSystemState(systemState);

    rdb.GetExtensionAbilityResourceInfo(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH),
        ExtensionAbilityType::DRIVER, fdp.ConsumeIntegral<uint32_t>(), launcherAbilityResourceInfos,
        fdp.ConsumeIntegral<int32_t>());

    BundleResourceConfiguration cfg;

    cfg.InitResourceGlobalConfig(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH), nullptr);

    std::vector<std::string> overlayHaps;
    overlayHaps.push_back(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    cfg.InitResourceGlobalConfig(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH), overlayHaps, nullptr,
        fdp.ConsumeBool(), fdp.ConsumeBool());

    ResourceInfo resourceInfo;
    resourceInfo.abilityName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    resourceInfo.GetKey();

    resourceInfo.ConvertFromLauncherAbilityResourceInfo(launcherAbilityResourceInfo);
    resourceInfo.appIndex_ = CODE_MIN_ONE;
    resourceInfo.ConvertFromLauncherAbilityResourceInfo(launcherAbilityResourceInfo);

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
