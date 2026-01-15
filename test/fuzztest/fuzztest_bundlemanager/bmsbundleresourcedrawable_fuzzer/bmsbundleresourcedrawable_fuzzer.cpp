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
#include <fuzzer/FuzzedDataProvider.h>

#include "bundle_resource_drawable.h"
#include "bundle_resource_event_subscriber.h"
#include "resource_info.h"
#include "parcel.h"

#include "bmsbundleresourcedrawable_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    BundleResourceDrawable drawable;
    uint32_t iconId = fdp.ConsumeIntegral<uint32_t>();
    int32_t density = fdp.ConsumeIntegral<int32_t>();
    OHOS::AppExecFwk::ResourceInfo resourceInfo;
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
    drawable.GetIconResourceByTheme(iconId, density, nullptr, resourceInfo);
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    drawable.GetIconResourceByTheme(iconId, density, resourceManager, resourceInfo);
    resourceInfo.bundleName_ = "com.ohos.contacts";
    drawable.GetIconResourceByTheme(iconId, density, resourceManager, resourceInfo);
    drawable.GetIconResourceByHap(iconId, density, nullptr, resourceInfo);
    drawable.GetIconResourceByHap(iconId, density, resourceManager, resourceInfo);
    drawable.GetBadgedIconResource(nullptr, nullptr, resourceInfo);
    std::pair<std::unique_ptr<uint8_t[]>, size_t> foregroundInfo;
    drawable.ProcessForegroundIcon(foregroundInfo, resourceInfo);
    std::shared_ptr<Media::PixelMap> layeredPixelMap;
    std::shared_ptr<Media::PixelMap> badgedPixelMap;
    drawable.GetBadgedIconResource(layeredPixelMap, badgedPixelMap, resourceInfo);
#endif
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
