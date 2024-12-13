/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "bundleresrdb_fuzzer.h"

#include "bundle_resource_rdb.h"
#include "bundle_resource_register.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr uint32_t CODE_MAX = 8;
const int32_t USERID = 100;
const std::string MODULE_NAME = "entry";
const std::string ABILITY_NAME = "com.example.bmsaccesstoken1.MainAbility";

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    std::string bundleName(data, size);
    resourceInfo.bundleName_ = bundleName;
    resourceRdb.AddResourceInfo(resourceInfo);
    resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    std::vector<ResourceInfo> resourceInfos;
    resourceInfos.push_back(resourceInfo);
    resourceRdb.AddResourceInfos(resourceInfos);
    resourceRdb.DeleteAllResourceInfo();
    std::vector<std::string> keyNames;
    resourceRdb.GetAllResourceName(keyNames);
    int32_t appIndex = 1;
    resourceRdb.GetResourceNameByBundleName(bundleName, appIndex, keyNames);
    BundleResourceInfo info;
    resourceRdb.GetBundleResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), info);
    std::vector<LauncherAbilityResourceInfo> launcherInfos;
    resourceRdb.GetLauncherAbilityResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), launcherInfos);
    std::vector<BundleResourceInfo> infos;
    resourceRdb.GetAllBundleResourceInfo(
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), infos);
    resourceRdb.GetAllLauncherAbilityResourceInfo(
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), launcherInfos);
    resourceRdb.UpdateResourceForSystemStateChanged(resourceInfos);
    std::string systemState(data, size);
    resourceRdb.GetCurrentSystemState(systemState);
    resourceRdb.DeleteNotExistResourceInfo();
    resourceRdb.ParseKey(resourceInfo.GetKey(), info);
    LauncherAbilityResourceInfo launcherInfo;
    resourceRdb.ParseKey(resourceInfo.GetKey(), launcherInfo);
    resourceRdb.BackupRdb();
    BundleResourceRegister::RegisterConfigurationObserver();
    BundleResourceRegister::RegisterCommonEventSubscriber();
    resourceInfo.ConvertFromBundleResourceInfo(info);
    resourceInfo.ConvertFromLauncherAbilityResourceInfo(launcherInfo);
    resourceInfo.InnerParseAppIndex(resourceInfo.GetKey());
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }
    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}