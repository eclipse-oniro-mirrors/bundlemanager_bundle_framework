/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_STANDARD_COMMON_LOG_INCLUDE_BUNDLE_FILE_UTIL_H
#define FOUNDATION_APPEXECFWK_STANDARD_COMMON_LOG_INCLUDE_BUNDLE_FILE_UTIL_H

#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {
class BundleFileUtil {
public:
    static bool CheckFilePath(const std::string &bundlePath, std::string &realPath);
    static bool CheckFilePath(const std::vector<std::string> &bundlePaths, std::vector<std::string> &realPaths);
    static bool CheckFileType(const std::string &fileName, const std::string &extensionName);
    static bool CheckFileName(const std::string &fileName);
    static bool CheckFileSize(const std::string &bundlePath, const int64_t fileSize);
    static bool GetHapFilesFromBundlePath(const std::string &currentBundlePath, std::vector<std::string> &hapFileList);
    static bool DeleteDir(const std::string &path);
    static bool IsExistFile(const std::string &filePath);
    static bool IsExistDir(const std::string &dirPath);
    static bool IsReportDataPartitionUsageEvent(const std::string &path);
};
} // AppExecFwk
} // OHOS

#endif // FOUNDATION_APPEXECFWK_STANDARD_COMMON_LOG_INCLUDE_BUNDLE_FILE_UTIL_H