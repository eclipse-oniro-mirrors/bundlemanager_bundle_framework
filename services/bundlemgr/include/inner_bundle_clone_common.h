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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_BUNDLE_CLONE_COMMON_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_BUNDLE_CLONE_COMMON_H

#include <string>
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_service_constants.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* CLONE_DIR_PATH_PREFIX = "clone";
constexpr const char* PLUS_SIGN = "+";
constexpr const char* MINUS_SIGN = "-";
}

class BundleCloneCommonHelper {
public:
    static std::string GetCloneDataDir(const std::string &bundleName, const int32_t appIndex)
    {
        return std::string(PLUS_SIGN) + CLONE_DIR_PATH_PREFIX +
            MINUS_SIGN + std::to_string(appIndex) + PLUS_SIGN + bundleName;
    }

    static std::string GetCloneBundleIdKey(const std::string &bundleName, const int32_t appIndex)
    {
        return std::to_string(appIndex) + CLONE_DIR_PATH_PREFIX + Constants::FILE_UNDERLINE + bundleName;
    }

    static bool ParseCloneDataDir(const std::string &cloneDirName, std::string &bundleName, int32_t &appIndex)
    {
        if (cloneDirName.find(ServiceConstants::CLONE_PREFIX) != 0) {
            APP_LOGE("prefix invalid %{public}s", cloneDirName.c_str());
            return false;
        }
        std::string tempStr = cloneDirName.substr(strlen(ServiceConstants::CLONE_PREFIX));
        size_t plusPos = tempStr.find(PLUS_SIGN);
        if (plusPos == std::string::npos) {
            APP_LOGE("plus sign not found %{public}s", cloneDirName.c_str());
            return false;
        }
        if (!OHOS::StrToInt(tempStr.substr(0, plusPos), appIndex)) {
            APP_LOGE("StrToInt failed %{public}s", cloneDirName.c_str());
            return false;
        }
        bundleName = tempStr.substr(plusPos + 1);
        return true;
    }
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_BUNDLE_CLONE_COMMON_H