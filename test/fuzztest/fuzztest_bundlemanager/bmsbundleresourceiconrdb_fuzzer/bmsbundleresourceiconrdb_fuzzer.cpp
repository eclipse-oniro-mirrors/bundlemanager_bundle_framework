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
#include "bundle_resource_icon_rdb.h"
#include "bundle_resource/resource_info.h"

#include "bmsbundleresourceiconrdb_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    BundleResourceIconRdb rdb;
    FuzzedDataProvider fdp(data, size);
    int32_t userId = GenerateRandomUser(fdp);
    ResourceInfo resourceInfo;
    rdb.AddResourceIconInfo(userId, IconResourceType::DYNAMIC_ICON, resourceInfo);
    ResourceInfo info;
    info.bundleName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName_ = "";
    rdb.AddResourceIconInfo(userId, IconResourceType::DYNAMIC_ICON, info);

    std::vector<ResourceInfo> resourceInfos;
    resourceInfos.push_back(info);
    rdb.AddResourceIconInfos(userId, IconResourceType::DYNAMIC_ICON, resourceInfos);
    info.icon_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    resourceInfos.push_back(info);
    rdb.AddResourceIconInfos(userId, IconResourceType::DYNAMIC_ICON, resourceInfos);
    std::vector<ResourceInfo> infos;
    rdb.AddResourceIconInfos(userId, IconResourceType::DYNAMIC_ICON, infos);

    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
    rdb.DeleteResourceIconInfo("", userId, appIndex, IconResourceType::DYNAMIC_ICON);
    rdb.DeleteResourceIconInfo(bundleName, userId, appIndex, IconResourceType::DYNAMIC_ICON);
    rdb.DeleteResourceIconInfo(bundleName, userId, 1, IconResourceType::DYNAMIC_ICON);
    rdb.DeleteResourceIconInfos(bundleName, userId, IconResourceType::DYNAMIC_ICON);
    rdb.DeleteResourceIconInfos("", userId, IconResourceType::DYNAMIC_ICON);
    rdb.DeleteResourceIconInfos(bundleName, IconResourceType::DYNAMIC_ICON);

    std::set<std::string> resourceNames;
    rdb.GetAllResourceIconName(userId, resourceNames, IconResourceType::UNKNOWN);
    rdb.GetAllResourceIconName(userId, resourceNames, IconResourceType::DYNAMIC_ICON);

    std::string name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string resourceName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    rdb.ParseNameToResourceName(name, resourceName);

    uint32_t resourceFlag = fdp.ConsumeIntegral<uint32_t>();
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    rdb.GetResourceIconInfos(bundleName, userId, appIndex, resourceFlag, launcherAbilityResourceInfos,
        IconResourceType::UNKNOWN);
    rdb.GetResourceIconInfos(bundleName, userId, appIndex, resourceFlag, launcherAbilityResourceInfos,
        IconResourceType::THEME_ICON);
    rdb.GetResourceIconInfos("", userId, appIndex, resourceFlag, launcherAbilityResourceInfos,
        IconResourceType::UNKNOWN);
    rdb.GetAllResourceIconInfo(userId, resourceFlag, launcherAbilityResourceInfos);

    std::shared_ptr<NativeRdb::ResultSet> absSharedResultSet;
    std::shared_ptr<NativeRdb::ResultSet> resultSet = nullptr;
    LauncherAbilityResourceInfo launcherAbilityResourceInfo;
    IconResourceType type;
    rdb.ConvertToLauncherAbilityResourceInfo(absSharedResultSet, resourceFlag, launcherAbilityResourceInfo, type);
    rdb.ConvertToLauncherAbilityResourceInfo(resultSet, resourceFlag, launcherAbilityResourceInfo, type);
    std::string key = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    rdb.ParseKey(key, launcherAbilityResourceInfo);
    rdb.GetIsOnlineTheme(userId);
    bool isOnlineTheme = fdp.ConsumeBool();
    rdb.SetIsOnlineTheme(userId, isOnlineTheme);
    rdb.InnerProcessResourceIconInfos(launcherAbilityResourceInfo, IconResourceType::DYNAMIC_ICON, userId,
        launcherAbilityResourceInfos);
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
