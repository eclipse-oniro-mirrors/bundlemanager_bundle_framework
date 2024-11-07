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
#include "bundlereshostimpl_fuzzer.h"

#include "bundle_resource_host_impl.h"
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
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    std::string bundleName(data, size);
    BundleResourceInfo info;
    bundleResourceHostImpl->GetBundleResourceInfo(bundleName, 0, info);
    std::vector<LauncherAbilityResourceInfo> launcherInfos;
    bundleResourceHostImpl->GetLauncherAbilityResourceInfo(bundleName, 0, launcherInfos);
    std::vector<BundleResourceInfo> infos;
    bundleResourceHostImpl->GetAllBundleResourceInfo(0, infos);
    bundleResourceHostImpl->GetAllLauncherAbilityResourceInfo(0, launcherInfos);
    bundleResourceHostImpl->AddResourceInfoByBundleName(bundleName, USERID);
    bundleResourceHostImpl->AddResourceInfoByAbility(bundleName, MODULE_NAME, ABILITY_NAME, USERID);
    std::string key(data, size);
    bundleResourceHostImpl->DeleteResourceInfo(key);
    int32_t appIndex = 1;
    bundleResourceHostImpl->CheckBundleNameValid(bundleName, appIndex);
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