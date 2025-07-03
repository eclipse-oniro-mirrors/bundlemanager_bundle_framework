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

#include "bundle_file_util.h"

#include "bmsbundlefileutil_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        BundleFileUtil fileUtil;

        FuzzedDataProvider fdp(data, size);
        std::string bundlePath = fdp.ConsumeRandomLengthString(BMSFuzzTestUtil::STRING_MAX_LENGTH);
        std::string realPath = fdp.ConsumeRandomLengthString(BMSFuzzTestUtil::STRING_MAX_LENGTH);
        fileUtil.CheckFilePath(bundlePath, realPath);

        std::vector<std::string> bundlePaths = BMSFuzzTestUtil::GenerateStringArray(fdp);
        std::vector<std::string> realPaths = BMSFuzzTestUtil::GenerateStringArray(fdp);
        fileUtil.CheckFilePath(bundlePaths, realPaths);

        std::string fileName = fdp.ConsumeRandomLengthString(BMSFuzzTestUtil::STRING_MAX_LENGTH);
        std::string extensionName = fdp.ConsumeRandomLengthString(BMSFuzzTestUtil::STRING_MAX_LENGTH);
        fileUtil.CheckFileType(fileName, extensionName);
        fileUtil.CheckFileName(fileName);

        int64_t fileSize = fdp.ConsumeIntegral<int64_t>();
        fileUtil.CheckFileSize(bundlePath, fileSize);

        int64_t minFileSize = fdp.ConsumeIntegralInRange<int64_t>(0, 0);
        fileUtil.CheckFileSize(bundlePath, minFileSize);
        fileUtil.DeleteDir(bundlePath);
        fileUtil.IsExistFile(bundlePath);
        fileUtil.IsExistDir(bundlePath);
        fileUtil.IsReportDataPartitionUsageEvent(bundlePath);
        
        std::vector<std::string> hapFileList = BMSFuzzTestUtil::GenerateStringArray(fdp);;
        fileUtil.GetHapFilesFromBundlePath(bundlePath, hapFileList);
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