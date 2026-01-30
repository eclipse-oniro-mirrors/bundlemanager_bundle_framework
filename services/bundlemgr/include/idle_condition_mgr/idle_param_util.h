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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IDLE_PARAM_UTIL_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IDLE_PARAM_UTIL_H

#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {
class IdleParamUtil {
public:
    static bool IsRelabelFeatureDisabled();
private:
    static std::string GetHigherVersionPath();
    static std::vector<int32_t> GetVersionNums(const std::string& filePath);
    static std::string CompareVersion(
        const std::vector<int32_t> &localVersion, const std::vector<int32_t> &cloudVersion);
    static std::vector<std::string> SplitString(const std::string& str, char pattern);
    static void Trim(std::string& inputStr);
    static bool IsNumber(const std::string &str);
};
}
}
#endif
