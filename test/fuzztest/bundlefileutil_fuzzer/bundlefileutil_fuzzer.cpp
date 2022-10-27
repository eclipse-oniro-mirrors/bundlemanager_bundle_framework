/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "bundle_file_util.h"

#include "bundlefileutil_fuzzer.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        BundleFileUtil fileUtil;
        std::string bundlePath (reinterpret_cast<const char*>(data), size);
        std::string realPath (reinterpret_cast<const char*>(data), size);
        std::vector<std::string> bundlePaths;
        bundlePaths.push_back(bundlePath);
        std::vector<std::string> realPaths;
        realPaths.push_back(realPath);
        fileUtil.CheckFilePath(bundlePath, realPath);
        fileUtil.CheckFilePath(bundlePaths, realPaths);
        std::string fileName (reinterpret_cast<const char*>(data), size);
        std::string extensionName (reinterpret_cast<const char*>(data), size);
        fileUtil.CheckFileType(fileName, extensionName);
        fileUtil.CheckFileName(fileName);
        fileUtil.CheckFileSize(bundlePath, reinterpret_cast<intptr_t>(data));
        std::string currentBundlePath (reinterpret_cast<const char*>(data), size);
        std::vector<std::string> hapFileList;
        hapFileList.push_back(currentBundlePath);
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