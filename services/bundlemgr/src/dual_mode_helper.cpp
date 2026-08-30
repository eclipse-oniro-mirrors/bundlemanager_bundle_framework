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

#include <dlfcn.h>
#include <unordered_map>
#include <vector>

#include "application_info.h"
#include "app_log_tag_wrapper.h"
#include "bundle_service_constants.h"
#include "parameters.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {

// Static member initialization
std::mutex DualModeHelper::ermsMutex_;
void *DualModeHelper::ermsHandle_ = nullptr;
ErmsGetPolicyFunc DualModeHelper::ermsGetPolicyFunc_ = nullptr;

namespace {
// Test-injection params (kept in this file, not in ServiceConstants). When persist.bms.test_dual_mode
// is true, ispcmode/mainmode are read from persist.bms.ispcmode / persist.bms.mainmode instead of
// the production sceneboard params (persist.sceneboard.ispcmode / const.sceneboard.mainmode), so
// dual-mode logic can be exercised without dual-mode hardware.
// The production ispcmode key is bool-typed (true=2in1, false=tablet); the test key is int-typed.
// Production (unset/false) is fully unaffected.
constexpr const char *TEST_DUAL_MODE_PARAM = "persist.bms.test_dual_mode";
constexpr const char *TEST_ISPCMODE_PARAM = "persist.bms.ispcmode";
constexpr const char *TEST_MAINMODE_PARAM = "persist.bms.mainmode";
// ERMS SDK library paths (try 64-bit first, then 32-bit).
constexpr const char *ERMS_LIB_PATH_64 = "/system/lib64/liberms_dual_mode_policy.z.so";
constexpr const char *ERMS_LIB_PATH_32 = "/system/lib/liberms_dual_mode_policy.z.so";
constexpr const char *ERMS_GET_POLICY_FUNC_NAME = "ErmsGetDeviceModelDistributionPolicy";

// Whether a mode value is valid (0=tablet or 1=2in1). -1 (not read) and any other value are invalid.
bool IsValidModeValue(int32_t v)
{
    return v == ServiceConstants::DUAL_MODE_VALUE_TABLET || v == ServiceConstants::DUAL_MODE_VALUE_2IN1;
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

// Read the ispcmode parameter. The production key (persist.sceneboard.ispcmode) is bool-typed
// (true=2in1, false=tablet); the test key (persist.bms.ispcmode) is int-typed (0/1/-1).
// Returns DUAL_MODE_VALUE_TABLET (0), DUAL_MODE_VALUE_2IN1 (1), or DUAL_MODE_VALUE_INVALID (-1).
int32_t ReadValidIspcmodeParam()
{
    const char *key = GetIspcmodeParamKey();
    if (DualModeHelper::IsTestDualMode()) {
        return ReadValidModeParam(key);
    }
    if (OHOS::system::GetParameter(key, "").empty()) {
        LOG_D(BMS_TAG_INSTALLER, "dual mode param %{public}s not present", key);
        return ServiceConstants::DUAL_MODE_VALUE_INVALID;
    }
    bool isPcMode = OHOS::system::GetBoolParameter(key, false);
    return isPcMode ? ServiceConstants::DUAL_MODE_VALUE_2IN1
                    : ServiceConstants::DUAL_MODE_VALUE_TABLET;
}
}  // namespace

int32_t DualModeHelper::GetSysMode()
{
    // Current mode = ispcmode (0=tablet, 1=2in1, -1=not read/illegal).
    return ReadValidIspcmodeParam();
}

bool DualModeHelper::IsDualModeDevice()
{
    // Read system parameters directly each call (no cache).
    // A dual-mode device requires both ispcmode and mainmode to be valid (0 or 1).
    int32_t ispcmode = ReadValidIspcmodeParam();
    int32_t mainmode = ReadValidModeParam(GetMainmodeParamKey());
    return IsValidModeValue(ispcmode) && IsValidModeValue(mainmode);
}

int32_t DualModeHelper::GetMainmode()
{
    // Read system parameter directly (no cache).
    return ReadValidModeParam(GetMainmodeParamKey());
}

int32_t DualModeHelper::MapDeviceTypeToMode(const std::string &deviceType)
{
    static const std::unordered_map<std::string, int32_t> DEVICE_TYPE_MAP = {
        { "tablet", ServiceConstants::DUAL_MODE_VALUE_TABLET },
        { "2in1", ServiceConstants::DUAL_MODE_VALUE_2IN1 },
    };
    auto it = DEVICE_TYPE_MAP.find(deviceType);
    if (it == DEVICE_TYPE_MAP.end()) {
        LOG_W(BMS_TAG_INSTALLER, "unknown deviceType %{public}s", deviceType.c_str());
        return ServiceConstants::DUAL_MODE_VALUE_INVALID;
    }
    return it->second;
}

bool DualModeHelper::IsSecondaryMode()
{
    // Read system parameters directly each call (no cache).
    // Non-dual-mode device (either param invalid) is never secondary.
    int32_t ispcmode = ReadValidIspcmodeParam();
    int32_t mainmode = ReadValidModeParam(GetMainmodeParamKey());
    if (!IsValidModeValue(ispcmode) || !IsValidModeValue(mainmode)) {
        return false;
    }
    // Secondary mode: current mode differs from main mode.
    return ispcmode != mainmode;
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

bool DualModeHelper::IsValidPolicySet(const std::set<DeviceModeDistributionPolicy> &policies)
{
    if (policies.empty()) {
        return false;
    }
    for (auto policy : policies) {
        if (static_cast<int32_t>(policy) < static_cast<int32_t>(DeviceModeDistributionPolicy::UNSPECIFIED)
            || static_cast<int32_t>(policy)
                > static_cast<int32_t>(DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE)) {
            return false;
        }
    }
    return policies.count(DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE) > 0
        && policies.count(DeviceModeDistributionPolicy::PARTIAL_COMPATIBLE_DIFFERENT_PACKAGE) > 0
        && policies.count(DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE) > 0;
}

bool DualModeHelper::ParsePersistedPolicies(const std::string &policiesStr,
    std::set<DeviceModeDistributionPolicy> &policySet)
{
    std::vector<std::string> tokens;
    OHOS::SplitStr(policiesStr, ServiceConstants::COMMA, tokens);
    for (const auto &token : tokens) {
        int32_t value = static_cast<int32_t>(DeviceModeDistributionPolicy::UNSPECIFIED) - 1;
        if (!OHOS::StrToInt(token, value)) {
            return false;
        }
        policySet.insert(static_cast<DeviceModeDistributionPolicy>(value));
    }
    return IsValidPolicySet(policySet);
}

std::string DualModeHelper::PoliciesToCsv(const std::set<DeviceModeDistributionPolicy> &policySet)
{
    std::string csv;
    for (auto policy : policySet) {
        if (!csv.empty()) {
            csv += ServiceConstants::COMMA;
        }
        csv += std::to_string(static_cast<int32_t>(policy));
    }
    return csv;
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

bool DualModeHelper::OpenErmsHandle()
{
    std::lock_guard<std::mutex> lock(ermsMutex_);
    if (ermsHandle_ != nullptr && ermsGetPolicyFunc_ != nullptr) {
        return true;
    }
    ermsHandle_ = dlopen(ERMS_LIB_PATH_64, RTLD_NOW | RTLD_GLOBAL);
    if (ermsHandle_ == nullptr) {
        LOG_NOFUNC_W(BMS_TAG_INSTALLER, "dlopen lib64 failed, try lib: %{public}s", dlerror());
        ermsHandle_ = dlopen(ERMS_LIB_PATH_32, RTLD_NOW | RTLD_GLOBAL);
    }
    if (ermsHandle_ == nullptr) {
        LOG_NOFUNC_W(BMS_TAG_INSTALLER, "dlopen liberms_sdk.z.so failed: %{public}s", dlerror());
        return false;
    }
    ermsGetPolicyFunc_ = reinterpret_cast<ErmsGetPolicyFunc>(dlsym(ermsHandle_, ERMS_GET_POLICY_FUNC_NAME));
    if (ermsGetPolicyFunc_ == nullptr) {
        LOG_NOFUNC_W(BMS_TAG_INSTALLER, "dlsym GetDeviceModelDistributionPolicy failed: %{public}s", dlerror());
        dlclose(ermsHandle_);
        ermsHandle_ = nullptr;
        return false;
    }
    return true;
}

bool DualModeHelper::GetDeviceModelDistributionPolicy(
    const std::string &bundleName,
    const std::string &bundleDir,
    const std::string &appDistributionType,
    int32_t &policy,
    std::map<std::string, std::vector<std::string>> &modeHapMap)
{
    if (!OpenErmsHandle()) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "OpenErmsHandle error");
        return false;
    }

    if (!ermsGetPolicyFunc_) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "ermsGetPolicyFunc_ null");
        return false;
    }

    int32_t err = ermsGetPolicyFunc_(bundleName, bundleDir, appDistributionType, policy, modeHapMap);
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "GetDeviceModelDistributionPolicy -n:%{public}s result:%{public}d,"
        "policy:%{public}d", bundleName.c_str(), err, policy);
    return err == 0;
}

}  // namespace AppExecFwk
}  // namespace OHOS
