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

#include <cstddef>
#include <cstdint>
#include <set>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "bmsbundleresourcehelpersecond_fuzzer.h"
#include "bundle_resource_helper.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
const int32_t USERID = 100;
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    #ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    int32_t userId = GenerateRandomUser(fdp);
    std::string key = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    BundleResourceHelper::BundleSystemStateInit();
    BundleResourceHelper::RegisterConfigurationObserver();
    BundleResourceHelper::RegisterCommonEventSubscriber();
    BundleResourceHelper::AddResourceInfoByBundleName(bundleName, USERID, ADD_RESOURCE_TYPE::INSTALL_BUNDLE, true);
    BundleResourceHelper::AddResourceInfoByBundleName(bundleName, userId, ADD_RESOURCE_TYPE::INSTALL_BUNDLE, true);
    BundleResourceHelper::DeleteAllResourceInfo();
    std::vector<std::string> resourceNames;
    BundleResourceHelper::GetAllBundleResourceName(resourceNames);
    BundleResourceHelper::ParseBundleName(bundleName);
    std::string moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    BundleResourceHelper::SetOverlayEnabled(bundleName, moduleName, true, userId);
    int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
    BundleResourceHelper::DeleteCloneBundleResourceInfo(bundleName, USERID, appIndex, true);
    BundleResourceHelper::DeleteCloneBundleResourceInfo(bundleName, userId, appIndex, false);
    BundleResourceHelper::DeleteNotExistResourceInfo();
    uint32_t flags = fdp.ConsumeIntegral<uint32_t>();
    BundleResourceInfo bundleResourceInfo;
    bundleResourceInfo.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleResourceInfo.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleResourceInfo.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    BundleResourceHelper::GetBundleResourceInfo(bundleName, flags, bundleResourceInfo, appIndex);
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfo;
    BundleResourceHelper::GetLauncherAbilityResourceInfo(bundleName, flags,
        launcherAbilityResourceInfo, appIndex);
    bool isExistInOtherUser = fdp.ConsumeBool();
    BundleResourceHelper::DeleteBundleResourceInfo(bundleName, userId, isExistInOtherUser);
    BundleResourceHelper::AddCloneBundleResourceInfo(bundleName, userId, appIndex, isExistInOtherUser);
    std::set<std::string> updateBundleNames;
    BundleResourceHelper::ProcessThemeAndDynamicIconWhenOta(updateBundleNames);
    BundleResourceHelper::ProcessBundleResourceChange();
    BundleResourceHelper::SetIsOnlineThemeWhenBoot();
    BundleResourceHelper::AddUninstallBundleResource(bundleName, userId, appIndex);
    BundleResourceHelper::DeleteUninstallBundleResource(bundleName, userId, appIndex);
    BundleResourceHelper::DeleteUninstallBundleResourceForUser(userId);
    #endif
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}