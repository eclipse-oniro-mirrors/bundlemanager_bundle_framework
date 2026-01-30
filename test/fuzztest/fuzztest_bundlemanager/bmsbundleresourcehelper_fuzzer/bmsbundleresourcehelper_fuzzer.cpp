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
#include "bundle_resource_helper.h"
#include "bmsbundleresourcehelper_fuzzer.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    BundleResourceHelper::BundleSystemStateInit();
    BundleResourceHelper::RegisterConfigurationObserver();
    BundleResourceHelper::RegisterCommonEventSubscriber();
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t userId = GenerateRandomUser(fdp);
    BundleResourceHelper::AddResourceInfoByBundleName(bundleName, userId, ADD_RESOURCE_TYPE::INSTALL_BUNDLE, true);
    BundleResourceHelper::DeleteAllResourceInfo();
    std::vector<std::string> resourceNames;
    BundleResourceHelper::GetAllBundleResourceName(resourceNames);
    BundleResourceHelper::ParseBundleName(bundleName);
    std::string moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    BundleResourceHelper::SetOverlayEnabled(bundleName, moduleName, true, userId);
    int32_t appIndex = 0;
    BundleResourceHelper::AddCloneBundleResourceInfo(bundleName, userId, appIndex, true);
    BundleResourceHelper::DeleteCloneBundleResourceInfo(bundleName, userId, appIndex, false);
    BundleResourceHelper::DeleteNotExistResourceInfo();
    return true;
}
} // namespace OHOS

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
