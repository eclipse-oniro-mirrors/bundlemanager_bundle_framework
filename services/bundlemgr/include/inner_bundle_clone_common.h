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
#include "bundle_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string CLONE_DIR_PATH_PREFIX = "clone";
}

class BundleCloneCommonHelper {
public:
    static std::string GetCloneDataDir(const std::string &bundleName, const int32_t appIndex)
    {
        return CLONE_DIR_PATH_PREFIX + Constants::FILE_SEPARATOR_CHAR
            + bundleName + Constants::FILE_SEPARATOR_CHAR + std::to_string(appIndex);
    }

    static std::string GetCloneBundleIdKey(const std::string &bundleName, const int32_t appIndex)
    {
        return std::to_string(appIndex) + CLONE_DIR_PATH_PREFIX + Constants::FILE_UNDERLINE + bundleName;
    }
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_BUNDLE_CLONE_COMMON_H