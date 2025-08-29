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
#include "quick_fix_boot_scanner.h"
#include "bmsquickfixbootscanner_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<QuickFixBootScanner> quickFixBootScanner =
        std::make_shared<QuickFixBootScanner>();
    if (quickFixBootScanner == nullptr) {
        return false;
    }
    FuzzedDataProvider fdp(data, size);
    quickFixBootScanner->ProcessQuickFixBootUp();
    std::shared_ptr<QuickFixState> state_ = nullptr;
    quickFixBootScanner->SetQuickFixState(state_);
    quickFixBootScanner->ProcessState();
    quickFixBootScanner->RestoreQuickFix();
    std::string bundlePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string realPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::vector<std::string> fileDir;
    fileDir.push_back(bundlePath);
    quickFixBootScanner->ProcessQuickFixDir(fileDir);
    quickFixBootScanner->ReprocessQuickFix(realPath, bundlePath);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string quickFixPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    ApplicationInfo info;
    quickFixBootScanner->GetApplicationInfo(bundleName, quickFixPath, info);
    int32_t quickFixVersion = fdp.ConsumeIntegral<int32_t>();
    int32_t fileVersion = fdp.ConsumeIntegral<int32_t>();
    quickFixBootScanner->ProcessWithBundleHasQuickFixInfo(bundleName, quickFixPath, quickFixVersion, fileVersion);
    quickFixBootScanner->RemoveInvalidDir();
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