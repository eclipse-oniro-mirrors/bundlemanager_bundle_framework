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
#include "bundleresprocess_fuzzer.h"

#include "bundle_resource_process.h"
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
    std::string bundleName(data, size);
    std::vector<ResourceInfo> resourceInfos;
    BundleResourceProcess::GetResourceInfoByBundleName(bundleName, USERID, resourceInfos);
    ResourceInfo resourceInfo;
    BundleResourceProcess::GetLauncherResourceInfoByAbilityName(bundleName, MODULE_NAME, ABILITY_NAME,
        USERID, resourceInfo);
    std::map<std::string, std::vector<ResourceInfo>> resourceMapInfos;
    BundleResourceProcess::GetAllResourceInfo(USERID, resourceMapInfos);
    std::vector<std::string> resourceNames;
    BundleResourceProcess::GetResourceInfoByColorModeChanged(resourceNames, USERID, resourceInfos);
    std::string targetBundleName(data, size);
    BundleResourceProcess::GetTargetBundleName(bundleName, targetBundleName);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.bundleType = BundleType::APP;
    InnerBundleInfo bundleInfo;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleResourceProcess::GetBundleResourceInfo(bundleInfo, USERID, resourceInfo);
    BundleResourceProcess::GetLauncherAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
    bundleInfo.SetOverlayType(OverlayType::OVERLAY_INTERNAL_BUNDLE);
    BundleResourceProcess::GetAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
    BundleResourceProcess::ConvertToBundleResourceInfo(bundleInfo);
    BundleResourceProcess::InnerGetResourceInfo(bundleInfo, USERID, resourceInfos);
    BundleResourceProcess::OnGetResourceInfo(bundleInfo, USERID, resourceInfos);
    applicationInfo.hideDesktopIcon = false;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleResourceProcess::CheckIsNeedProcessAbilityResource(bundleInfo);
    InnerBundleUserInfo innerUserInfo;
    innerUserInfo.bundleUserInfo.userId = USERID;
    innerUserInfo.bundleUserInfo.overlayModulesState.push_back("1_overlay_1");
    innerUserInfo.bundleUserInfo.overlayModulesState.push_back("2_overlay_2");
    innerUserInfo.bundleName = bundleName;
    bundleInfo.AddInnerBundleUserInfo(innerUserInfo);
    std::vector<std::string> overlayHapPaths;
    BundleResourceProcess::GetOverlayModuleHapPaths(bundleInfo, MODULE_NAME, USERID, overlayHapPaths);
    BundleResourceProcess::ChangeDynamicIcon(resourceInfos, resourceInfo);
    BundleResourceProcess::GetDynamicIcon(bundleInfo, resourceInfo);
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