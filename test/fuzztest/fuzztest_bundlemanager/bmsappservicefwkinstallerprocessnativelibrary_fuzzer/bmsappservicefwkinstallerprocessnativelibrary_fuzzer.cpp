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

#include "app_service_fwk/app_service_fwk_installer.h"
#include "bmsappservicefwkinstallerprocessnativelibrary_fuzzer.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    AppServiceFwkInstaller appServicefwk;
    FuzzedDataProvider fdp(data, size);

    std::vector<std::string> hspPaths = GenerateStringArray(fdp);
    InstallParam installParam;
    appServicefwk.BeforeInstall(hspPaths, installParam);

    InnerBundleInfo newInfo;
    std::string bundlePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string moduleDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string versionDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bool copyHapToInstallPath = fdp.ConsumeBool();

    appServicefwk.ProcessNativeLibrary(bundlePath, moduleDir, moduleName, versionDir, newInfo, copyHapToInstallPath);
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