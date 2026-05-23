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

#include <fuzzer/FuzzedDataProvider.h>

#include "bms_fuzztest_util.h"
#include "quickfixbootscanner_fuzzer.h"
#define private public
#include "quick_fix_boot_scanner.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t MESSAGE_SIZE = 4;
constexpr size_t DCAMERA_SHIFT_24 = 24;
constexpr size_t DCAMERA_SHIFT_16 = 16;
constexpr size_t DCAMERA_SHIFT_8 = 8;

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    QuickFixBootScanner quickFixBootScanner;
    quickFixBootScanner.ProcessQuickFixBootUp();
    std::shared_ptr<QuickFixState> state_ = nullptr;
    quickFixBootScanner.SetQuickFixState(state_);
    quickFixBootScanner.ProcessState();
    quickFixBootScanner.RestoreQuickFix();
    FuzzedDataProvider fdp(data, size);
    std::string bundlePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string realPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::vector<std::string> fileDir;
    fileDir.push_back(bundlePath);
    quickFixBootScanner.ProcessQuickFixDir(fileDir);
    quickFixBootScanner.ReprocessQuickFix(realPath, bundlePath);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string quickFixPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    ApplicationInfo info;
    quickFixBootScanner.GetApplicationInfo(bundleName, quickFixPath, info);
    int32_t quickFixVersion = fdp.ConsumeIntegral<int32_t>();
    int32_t fileVersion = fdp.ConsumeIntegral<int32_t>();
    quickFixBootScanner.ProcessWithBundleHasQuickFixInfo(bundleName, quickFixPath, quickFixVersion, fileVersion);
    quickFixBootScanner.RemoveInvalidDir();
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}