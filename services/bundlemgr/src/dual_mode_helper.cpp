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
int32_t DualModeHelper::cachedIspcmode_ = ServiceConstants::DUAL_MODE_VALUE_INVALID;
int32_t DualModeHelper::cachedMainmode_ = ServiceConstants::DUAL_MODE_VALUE_INVALID;
std::mutex DualModeHelper::cacheMutex_;

namespace {
// Test-injection params (kept in this file, not in ServiceConstants). When persist.bms.test_dual_mode
// is true, ispcmode/mainmode are read from persist.bms.ispcmode / persist.bms.mainmode instead of
// persist.sceneboard.*, so dual-mode logic can be exercised without dual-mode hardware.
// Production (unset/false) is fully unaffected.
constexpr const char *TEST_DUAL_MODE_PARAM = "persist.bms.test_dual_mode";
constexpr const char *TEST_ISPCMODE_PARAM = "persist.bms.ispcmode";
constexpr const char *TEST_MAINMODE_PARAM = "persist.bms.mainmode";

// Whether a mode value is valid (0=tablet or 1=2in1). -1 (not read) and any other value are invalid.
bool IsValidModeValue(int32_t v)
{
    return v == ServiceConstants::DUAL_MODE_VALUE_TABLET || v == ServiceConstants::DUAL_MODE_VALUE_2IN1;
}

// Read an int system parameter and validate it is 0 (tablet) or 1 (2in1).
// Returns DUAL_MODE_VALUE_INVALID (-1) if the parameter is missing, unreadable, or illegal.
int32_t ReadValidModeParam(const char *key)
{
    int32_t value = OHOS::system::GetIntParameter(key, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    if (!IsValidModeValue(value)) {
        LOG_D(BMS_TAG_INSTALLER, "dual mode param %{public}s invalid value %{public}d", key, value);
        return ServiceConstants::DUAL_MODE_VALUE_INVALID;
    }
    return value;
}

// Effective ispcmode param key: test key when the switch is on, real sceneboard key otherwise.
const char *GetIspcmodeParamKey()
{
    return DualModeHelper::IsTestDualMode() ? TEST_ISPCMODE_PARAM
                                            : ServiceConstants::DUAL_MODE_ISPCMODE_PARAM_KEY;
}

// Effective mainmode param key: test key when the switch is on, real sceneboard key otherwise.
const char *GetMainmodeParamKey()
{
    return DualModeHelper::IsTestDualMode() ? TEST_MAINMODE_PARAM
                                            : ServiceConstants::DUAL_MODE_MAINMODE_PARAM_KEY;
}
}  // namespace

int32_t DualModeHelper::GetSysMode()
{
    // Current mode = ispcmode (0=tablet, 1=2in1, -1=not read/illegal).
    return ReadValidModeParam(GetIspcmodeParamKey());
}

bool DualModeHelper::IsDualModeDevice()
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    // A dual-mode device requires both ispcmode and mainmode to be valid (0 or 1).
    return IsValidModeValue(cachedIspcmode_) && IsValidModeValue(cachedMainmode_);
}

void DualModeHelper::InitializeCache()
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    cachedIspcmode_ = ReadValidModeParam(GetIspcmodeParamKey());
    cachedMainmode_ = ReadValidModeParam(GetMainmodeParamKey());
    LOG_I(BMS_TAG_INSTALLER, "DualModeHelper cache initialized: ispcmode=%{public}d, mainmode=%{public}d",
        cachedIspcmode_, cachedMainmode_);
}

void DualModeHelper::UpdateModeCache()
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    cachedIspcmode_ = ReadValidModeParam(GetIspcmodeParamKey());
    cachedMainmode_ = ReadValidModeParam(GetMainmodeParamKey());
    LOG_I(BMS_TAG_INSTALLER, "DualModeHelper cache updated: ispcmode=%{public}d, mainmode=%{public}d",
        cachedIspcmode_, cachedMainmode_);
}

bool DualModeHelper::IsSecondaryMode()
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    // Non-dual-mode device (either param invalid) is never secondary.
    if (!IsValidModeValue(cachedIspcmode_) || !IsValidModeValue(cachedMainmode_)) {
        return false;
    }
    // Secondary mode: current mode differs from main mode.
    return cachedIspcmode_ != cachedMainmode_;
}

bool DualModeHelper::IsTestDualMode()
{
    return OHOS::system::GetBoolParameter(TEST_DUAL_MODE_PARAM, false);
}

bool DualModeHelper::IsDiffPackageCategory(DeviceModeDistributionPolicy policy)
{
    return policy == DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE ||
        policy == DeviceModeDistributionPolicy::PARTIAL_COMPATIBLE_DIFFERENT_PACKAGE ||
        policy == DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE;
}

bool DualModeHelper::NeedDualModeHandle(DeviceModeDistributionPolicy policy)
{
    return IsSecondaryMode() && IsDiffPackageCategory(policy);
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
