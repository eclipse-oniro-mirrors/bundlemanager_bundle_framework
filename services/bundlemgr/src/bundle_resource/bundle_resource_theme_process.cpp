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

#include "bundle_resource_theme_process.h"

#include "app_log_wrapper.h"
#include "bundle_util.h"
#include "directory_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* SYSTEM_THEME_PATH = "/data/service/el1/public/themes/";
constexpr const char* THEME_ICONS_A = "/a/app/icons/";
constexpr const char* THEME_ICONS_B = "/b/app/icons/";
constexpr const char* THEME_ICONS_A_FLAG = "/a/app/flag";
constexpr const char* THEME_ICONS_B_FLAG = "/b/app/flag";
constexpr const char* THEME_ICONS_CHAR = "/";
}

bool BundleResourceThemeProcess::IsBundleThemeExist(
    const std::string &bundleName,
    const int32_t userId)
{
    if (bundleName.empty()) {
        return false;
    }
    if (BundleUtil::IsExistFileNoLog(SYSTEM_THEME_PATH + std::to_string(userId) + THEME_ICONS_A_FLAG)) {
        return BundleUtil::IsExistDirNoLog(SYSTEM_THEME_PATH + std::to_string(userId) + THEME_ICONS_A + bundleName);
    }
    return BundleUtil::IsExistDirNoLog(SYSTEM_THEME_PATH + std::to_string(userId) + THEME_ICONS_B + bundleName);
}

bool BundleResourceThemeProcess::IsAbilityThemeExist(
    const std::string &bundleName,
    const std::string &moduleName,
    const std::string &abilityName,
    const int32_t userId)
{
    if (bundleName.empty() || moduleName.empty() || abilityName.empty()) {
        return false;
    }
    if (BundleUtil::IsExistFileNoLog(SYSTEM_THEME_PATH + std::to_string(userId) + THEME_ICONS_A_FLAG)) {
        return BundleUtil::IsExistDirNoLog(SYSTEM_THEME_PATH + std::to_string(userId) + THEME_ICONS_A + bundleName +
            THEME_ICONS_CHAR + moduleName + THEME_ICONS_CHAR + abilityName);
    }
    return BundleUtil::IsExistDirNoLog(SYSTEM_THEME_PATH + std::to_string(userId) + THEME_ICONS_B + bundleName +
        THEME_ICONS_CHAR + moduleName + THEME_ICONS_CHAR + abilityName);
}

bool BundleResourceThemeProcess::IsThemeExistInFlagA(const std::string &bundleName, const int32_t userId)
{
    return BundleUtil::IsExistDirNoLog(SYSTEM_THEME_PATH + std::to_string(userId) + THEME_ICONS_A + bundleName);
}

bool BundleResourceThemeProcess::IsThemeExistInFlagB(const std::string &bundleName, const int32_t userId)
{
    return BundleUtil::IsExistDirNoLog(SYSTEM_THEME_PATH + std::to_string(userId) + THEME_ICONS_B + bundleName);
}
} // AppExecFwk
} // OHOS