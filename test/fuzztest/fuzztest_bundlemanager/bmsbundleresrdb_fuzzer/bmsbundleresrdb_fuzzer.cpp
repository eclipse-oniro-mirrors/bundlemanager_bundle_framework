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
#include "bundle_resource_rdb.h"
#include "bundle_resource_register.h"
#include "bmsbundleresrdb_fuzzer.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<BundleResourceRdb> bundleResourceRdb = std::make_shared<BundleResourceRdb>();
    ResourceInfo resourceInfo;
    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    resourceInfo.bundleName_ = bundleName;
    bundleResourceRdb->AddResourceInfo(resourceInfo);
    bundleResourceRdb->DeleteResourceInfo(resourceInfo.GetKey());
    std::vector<ResourceInfo> resourceInfos;
    resourceInfos.push_back(resourceInfo);
    bundleResourceRdb->AddResourceInfos(resourceInfos);
    bundleResourceRdb->DeleteAllResourceInfo();
    std::vector<std::string> keyNames;
    bundleResourceRdb->GetAllResourceName(keyNames);
    int32_t appIndex = 1;
    bundleResourceRdb->GetResourceNameByBundleName(bundleName, appIndex, keyNames);
    BundleResourceInfo info;
    bundleResourceRdb->GetBundleResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), info);
    std::vector<LauncherAbilityResourceInfo> launcherInfos;
    bundleResourceRdb->GetLauncherAbilityResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), launcherInfos);
    std::vector<BundleResourceInfo> infos;
    bundleResourceRdb->GetAllBundleResourceInfo(
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), infos);
    bundleResourceRdb->GetAllLauncherAbilityResourceInfo(
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), launcherInfos);
    bundleResourceRdb->UpdateResourceForSystemStateChanged(resourceInfos);
    std::string systemState = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleResourceRdb->GetCurrentSystemState(systemState);
    bundleResourceRdb->DeleteNotExistResourceInfo();
    bundleResourceRdb->ParseKey(resourceInfo.GetKey(), info);
    LauncherAbilityResourceInfo launcherInfo;
    bundleResourceRdb->ParseKey(resourceInfo.GetKey(), launcherInfo);
    BundleResourceRegister::RegisterConfigurationObserver();
    BundleResourceRegister::RegisterCommonEventSubscriber();
    resourceInfo.ConvertFromBundleResourceInfo(info);
    resourceInfo.ConvertFromLauncherAbilityResourceInfo(launcherInfo);
    resourceInfo.InnerParseAppIndex(resourceInfo.GetKey());
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}