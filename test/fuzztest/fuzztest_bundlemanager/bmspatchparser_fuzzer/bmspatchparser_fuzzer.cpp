/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "bmspatchparser_fuzzer.h"
#include "quick_fix/patch_parser.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    PatchParser parser;

    // ParsePatchInfo(const std::string &pathName, AppQuickFix &appQuickFix)
    std::string pathName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    AppQuickFix appQuickFix;
    parser.ParsePatchInfo(pathName, appQuickFix);

    // ParsePatchInfo(const std::vector<std::string> &filePaths, ...)
    std::vector<std::string> filePaths = GenerateStringArray(fdp);
    std::unordered_map<std::string, AppQuickFix> appQuickFixes;
    parser.ParsePatchInfo(filePaths, appQuickFixes);

    // HasResourceFile(const std::string &filePath)
    std::string filePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    parser.HasResourceFile(filePath);

    // HasResourceFile(const std::vector<std::string> &filePaths)
    std::vector<std::string> filePathsForCheck = GenerateStringArray(fdp);
    parser.HasResourceFile(filePathsForCheck);

    // Test with empty path
    parser.ParsePatchInfo("", appQuickFix);
    parser.HasResourceFile("");

    // Test with empty vector
    std::vector<std::string> emptyPaths;
    parser.ParsePatchInfo(emptyPaths, appQuickFixes);
    parser.HasResourceFile(emptyPaths);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
