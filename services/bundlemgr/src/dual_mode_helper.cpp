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

#include "dual_mode_helper.h"

#include "application_info.h"
#include "app_log_tag_wrapper.h"
#include "bundle_service_constants.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {

// Static member initialization
std::string DualModeHelper::cachedMode_;
std::string DualModeHelper::cachedDeviceType_;
bool DualModeHelper::cacheInitialized_ = false;
std::mutex DualModeHelper::cacheMutex_;

std::string DualModeHelper::GetSysMode()
{
    return OHOS::system::GetParameter(ServiceConstants::DUAL_MODE_SYS_PARAM_KEY, "");
}

bool DualModeHelper::IsDualModeDevice()
{
    std::string mode = GetSysMode();
    // A dual-mode device must have a valid mode configured (pcmode or padmode)
    return !mode.empty() &&
           (mode == ServiceConstants::DUAL_MODE_PC || mode == ServiceConstants::DUAL_MODE_PAD);
}

void DualModeHelper::InitializeCache()
{
    cachedMode_ = GetSysMode();
    cachedDeviceType_ = OHOS::system::GetDeviceType();
    cacheInitialized_ = true;
    LOG_I(BMS_TAG_INSTALLER, "DualModeHelper cache initialized: mode=%{public}s, deviceType=%{public}s",
        cachedMode_.c_str(), cachedDeviceType_.c_str());
}

void DualModeHelper::UpdateModeCache()
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    cachedMode_ = GetSysMode();
    cachedDeviceType_ = OHOS::system::GetDeviceType();
    cacheInitialized_ = true;
    LOG_I(BMS_TAG_INSTALLER, "DualModeHelper cache updated: mode=%{public}s, deviceType=%{public}s",
        cachedMode_.c_str(), cachedDeviceType_.c_str());
}

bool DualModeHelper::IsSecondaryMode()
{
    std::string mode;
    std::string deviceType;

    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        if (!cacheInitialized_) {
            InitializeCache();
        }
        mode = cachedMode_;
        deviceType = cachedDeviceType_;
    }

    // Early return if mode is empty
    if (mode.empty()) {
        return false;
    }

    if (mode == ServiceConstants::DUAL_MODE_PC && deviceType == ServiceConstants::DUAL_MODE_DEVICE_TABLET) {
        return true;
    }
    if (mode == ServiceConstants::DUAL_MODE_PAD && deviceType == ServiceConstants::DUAL_MODE_DEVICE_2IN1) {
        return true;
    }
    return false;
}

bool DualModeHelper::IsDiffPackageCategory(uint32_t appCategory)
{
    return (appCategory & static_cast<uint32_t>(AppCategory::APP_CATEGORY_DIFF_PACKAGE)) != 0;
}

bool DualModeHelper::NeedDualModeHandle(uint32_t appCategory)
{
    return IsSecondaryMode() && IsDiffPackageCategory(appCategory);
}

std::string DualModeHelper::GetDualModeBundleName(const std::string &bundleName)
{
    return BundleCloneCommonHelper::GetCloneDataDir(bundleName, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

bool DualModeHelper::ParseDualModeBundleName(const std::string &name, std::string &bundleName)
{
    std::string originalName;
    int32_t appIndex = 0;
    if (!BundleCloneCommonHelper::ParseCloneDataDir(name, originalName, appIndex)) {
        return false;
    }
    // Only appIndex==10000 (dual-mode) names are recognized; clone apps (1..5) are excluded.
    if (appIndex != ServiceConstants::DUAL_MODE_CLONE_APP_INDEX) {
        LOG_D(BMS_TAG_INSTALLER, "not dual mode clone name, appIndex %{public}d", appIndex);
        return false;
    }
    bundleName = originalName;
    return true;
}

bool DualModeHelper::IsDualModeCloneKey(const std::string &key)
{
    // Dual mode keys have format: +clone-10000+{bundleName}
    // Regular clone apps (1-5) have format: +clone-{1-5}+{bundleName}
    std::string dualModePrefix = std::string(ServiceConstants::CLONE_PREFIX) +
        std::to_string(ServiceConstants::DUAL_MODE_CLONE_APP_INDEX) + "+";
    return key.find(dualModePrefix) == 0;
}

}  // namespace AppExecFwk
}  // namespace OHOS
