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
#include "bundle_constants.h"
#include "bundle_data_mgr.h"
#include "bundle_service_constants.h"
#include "inner_bundle_info.h"
#include "parameters.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {

// Static member initialization
std::mutex DualModeHelper::ermsMutex_;
void *DualModeHelper::ermsHandle_ = nullptr;
ErmsGetPolicyFunc DualModeHelper::ermsGetPolicyFunc_ = nullptr;

std::once_flag DualModeHelper::dualModeCacheFlag_;
bool DualModeHelper::cachedIsDualMode_ = false;
int32_t DualModeHelper::cachedMainmode_ = ServiceConstants::DUAL_MODE_VALUE_INVALID;

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

// Whether an erms-returned policy is a valid DeviceModeDistributionPolicy value (0..8).
bool IsValidErmsPolicy(int32_t policy)
{
    return policy >= static_cast<int32_t>(DeviceModeDistributionPolicy::UNSPECIFIED) &&
        policy <= static_cast<int32_t>(DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE);
}

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

// Only plain "enterprise" counts as in-house (team decision): the enterprise_* / *testing variants
// are not erms-eligible unless the app is preinstalled.
bool IsInHouseDistributionType(const std::string &distributionType)
{
    return distributionType == Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE;
}

// Architect decision (2026-08-29): erms dir = hapPath minus the file name — the preset root for
// preinstall apps (installed in place), the install root for others. A preinstall app partially
// updated online prefers its first hap still outside BUNDLE_CODE_DIR (preset partition); falls
// back to the code path when no usable hapPath exists.
std::string GetErmsBundleDir(const InnerBundleInfo &info)
{
    std::string firstHap;
    std::string presetHap;  // first hap outside BUNDLE_CODE_DIR (still on a preset partition)
    for (const auto &hapPath : info.GetAllHapPaths()) {
        if (hapPath.empty()) {
            continue;
        }
        if (firstHap.empty()) {
            firstHap = hapPath;
        }
        if (presetHap.empty() && hapPath.rfind(Constants::BUNDLE_CODE_DIR, 0) != 0) {
            presetHap = hapPath;
        }
    }
    if (info.IsPreInstallApp() && !presetHap.empty()) {
        const auto pos = presetHap.find_last_of('/');
        return (pos == std::string::npos || pos == 0) ? info.GetAppCodePath()
                                                      : presetHap.substr(0, pos);
    }
    if (info.IsPreInstallApp() && !firstHap.empty()) {
        LOG_W(BMS_TAG_INSTALLER, "DualOTARefresh: preinstall app fully updated online, erms gets "
            "install root: %{public}s", info.GetBundleName().c_str());
    }
    const auto pos = firstHap.find_last_of('/');
    return (pos == std::string::npos || pos == 0) ? info.GetAppCodePath() : firstHap.substr(0, pos);
}

// Pass metrics for the summary log: already categorized / persisted / resolved default /
// vanished (concurrent uninstall).
struct StockRefreshStats {
    size_t alreadySetCnt = 0;
    size_t persistedCnt = 0;
    size_t defaultCnt = 0;
    size_t vanishedCnt = 0;
};

// Refresh one stock app's category (per-app step of DualModeHelper::RefreshStockAppCategories).
// Idempotent: only refresh apps with no policy yet; never overwrite AG/caller-set policy.
// Default (UNSPECIFIED) resolutions are NOT persisted — 0 is value-identical to the
// never-touched state; non-default resolutions persist immediately.
// Returns false only on a genuine persist failure (app still in map). A vanished app
// (concurrent uninstall) is a terminal state, not a retryable failure — skipping it must
// not fail the pass, else the marker never gets set.
bool RefreshOneStockApp(BundleDataMgr &dataMgr, const std::string &bundleName,
    const DualModeHelper::ErmsCategoryQueryFunc &ermsQuery, StockRefreshStats &stats)
{
    InnerBundleInfo info;
    if (!dataMgr.FetchInnerBundleInfo(bundleName, info)) {
        stats.vanishedCnt++;
        LOG_D(BMS_TAG_INSTALLER, "DualOTARefresh: app gone during pass, skip: %{public}s",
            bundleName.c_str());
        return true;
    }
    if (info.GetDeviceModeDistributionPolicy() != DeviceModeDistributionPolicy::UNSPECIFIED) {
        stats.alreadySetCnt++;
        return true;
    }
    DeviceModeDistributionPolicy category = DualModeHelper::ResolveStockAppCategory(info, ermsQuery);
    if (category == DeviceModeDistributionPolicy::UNSPECIFIED) {
        stats.defaultCnt++;
        LOG_D(BMS_TAG_INSTALLER, "DualOTARefresh: app resolved default, no persist: %{public}s",
            bundleName.c_str());
        return true;
    }
    if (dataMgr.UpdateAppCategoryAndPersist(bundleName, category)) {
        stats.persistedCnt++;
        LOG_I(BMS_TAG_INSTALLER, "DualOTARefresh: app categorized: %{public}s -> policy %{public}u",
            bundleName.c_str(), static_cast<uint32_t>(category));
        return true;
    }
    InnerBundleInfo probe;
    if (!dataMgr.FetchInnerBundleInfo(bundleName, probe)) {
        stats.vanishedCnt++;
        LOG_D(BMS_TAG_INSTALLER, "DualOTARefresh: app gone during persist, skip: %{public}s",
            bundleName.c_str());
        return true;
    }
    LOG_W(BMS_TAG_INSTALLER, "DualOTARefresh: persist fail: %{public}s -> policy %{public}u",
        bundleName.c_str(), static_cast<uint32_t>(category));
    return false;  // still in map -> genuine persist failure -> marker stays unset
}
}  // namespace

int32_t DualModeHelper::GetSysMode()
{
    // Current mode = ispcmode (0=tablet, 1=2in1, -1=not read/illegal).
    // Always read in real-time: the user can switch modes at runtime.
    return ReadValidIspcmodeParam();
}

void DualModeHelper::InitDualModeCache()
{
    // const.sceneboard.mainmode is a const parameter — never changes after boot.
    cachedMainmode_ = ReadValidModeParam(ServiceConstants::DUAL_MODE_MAINMODE_PARAM_KEY);
    // persist.sceneboard.ispcmode when present is always 0/1 (bool), so its validity never changes.
    int32_t ispcmode = ReadValidIspcmodeParam();
    cachedIsDualMode_ = IsValidModeValue(ispcmode) && IsValidModeValue(cachedMainmode_);
    LOG_D(BMS_TAG_INSTALLER, "InitDualModeCache isDualMode:%{public}d mainmode:%{public}d",
        cachedIsDualMode_, cachedMainmode_);
}

bool DualModeHelper::IsDualModeDevice()
{
    // Test mode: bypass cache so test cases can drive different values per case.
    if (IsTestDualMode()) {
        int32_t ispcmode = ReadValidIspcmodeParam();
        int32_t mainmode = ReadValidModeParam(GetMainmodeParamKey());
        return IsValidModeValue(ispcmode) && IsValidModeValue(mainmode);
    }
    // Production: result is stable after boot (mainmode is const, ispcmode validity unchanged).
    std::call_once(dualModeCacheFlag_, InitDualModeCache);
    return cachedIsDualMode_;
}

int32_t DualModeHelper::GetMainmode()
{
    // Test mode: bypass cache so test cases can drive different values per case.
    if (IsTestDualMode()) {
        return ReadValidModeParam(GetMainmodeParamKey());
    }
    // Production: const parameter, cached once at boot.
    std::call_once(dualModeCacheFlag_, InitDualModeCache);
    return cachedMainmode_;
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
    // Test mode: bypass cache so test cases can drive different values per case.
    if (IsTestDualMode()) {
        int32_t ispcmode = ReadValidIspcmodeParam();
        int32_t mainmode = ReadValidModeParam(GetMainmodeParamKey());
        if (!IsValidModeValue(ispcmode) || !IsValidModeValue(mainmode)) {
            return false;
        }
        return ispcmode != mainmode;
    }
    // Production: use cached dual-mode + cached mainmode; read ispcmode in real-time
    // because the user can switch modes at runtime. On non-dual-mode devices, skip the
    // ispcmode read entirely (most devices are non-dual-mode — this is the hot path).
    std::call_once(dualModeCacheFlag_, InitDualModeCache);
    if (!cachedIsDualMode_) {
        return false;
    }
    int32_t ispcmode = ReadValidIspcmodeParam();
    if (!IsValidModeValue(ispcmode)) {
        return false;
    }
    // Secondary mode: current mode differs from main mode.
    return ispcmode != cachedMainmode_;
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

bool DualModeHelper::IsSingleModePolicy(DeviceModeDistributionPolicy policy)
{
    return policy == DeviceModeDistributionPolicy::MAIN_ONLY ||
        policy == DeviceModeDistributionPolicy::SUB_ONLY;
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

DeviceModeDistributionPolicy DualModeHelper::ToDeviceModePolicy(int32_t ermsPolicy)
{
    if (!IsValidErmsPolicy(ermsPolicy)) {
        LOG_NOFUNC_W(BMS_TAG_INSTALLER, "DualOTARefresh: erms policy out of range: %{public}d",
            ermsPolicy);
        return DeviceModeDistributionPolicy::UNSPECIFIED;
    }
    return static_cast<DeviceModeDistributionPolicy>(ermsPolicy);
}

DeviceModeDistributionPolicy DualModeHelper::QueryAppCategoryFromErms(const std::string &bundleName,
    const std::string &bundleDir, const std::string &distributionType)
{
    // An installed eligible app always has both; empty input cannot produce a meaningful query.
    if (bundleName.empty() || bundleDir.empty()) {
        LOG_NOFUNC_W(BMS_TAG_INSTALLER, "DualOTARefresh: erms query skipped, empty bundleName/bundleDir");
        return DeviceModeDistributionPolicy::UNSPECIFIED;
    }
    int32_t policy = static_cast<int32_t>(DeviceModeDistributionPolicy::UNSPECIFIED);
    // Split-package info (modeHapMap) is not used by the stock-app category refresh.
    std::map<std::string, std::vector<std::string>> modeHapMap;
    LOG_NOFUNC_D(BMS_TAG_INSTALLER, "DualOTARefresh: erms query, bundle=%{public}s dir=%{public}s "
        "type=%{public}s", bundleName.c_str(), bundleDir.c_str(), distributionType.c_str());
    if (!GetDeviceModelDistributionPolicy(bundleName, bundleDir, distributionType, policy, modeHapMap)) {
        // Requirement: erms interface failure -> the app category defaults to 0 (UNSPECIFIED).
        LOG_NOFUNC_W(BMS_TAG_INSTALLER, "DualOTARefresh: erms call failed, use default policy, "
            "bundle=%{public}s", bundleName.c_str());
        return DeviceModeDistributionPolicy::UNSPECIFIED;
    }
    return ToDeviceModePolicy(policy);
}

DeviceModeDistributionPolicy DualModeHelper::ResolveStockAppCategory(const InnerBundleInfo &info)
{
    // Production wires the real erms query into the injectable core resolver.
    auto prodErms = [](const std::string &bundleName, const std::string &bundleDir,
        const std::string &distributionType) -> DeviceModeDistributionPolicy {
        return QueryAppCategoryFromErms(bundleName, bundleDir, distributionType);
    };
    return ResolveStockAppCategory(info, prodErms);
}

DeviceModeDistributionPolicy DualModeHelper::ResolveStockAppCategory(const InnerBundleInfo &info,
    const ErmsCategoryQueryFunc &ermsQuery)
{
    // Rule: preinstall/preload OR in-house -> ask erms; other -> UNSPECIFIED, no erms call.
    std::string distributionType = info.GetAppDistributionType();
    bool ermsEligible = info.IsPreInstallApp() || IsInHouseDistributionType(distributionType);
    if (!ermsEligible || !ermsQuery) {
        return DeviceModeDistributionPolicy::UNSPECIFIED;  // other app / no query -> default 0
    }
    // erms input "fileRootPath": hapPath parent dir — preset root for preinstall apps, install
    // root for in-house apps (architect decision, see GetErmsBundleDir).
    return ermsQuery(info.GetBundleName(), GetErmsBundleDir(info), distributionType);
}

void DualModeHelper::RefreshStockAppCategories(BundleDataMgr &dataMgr,
    const std::function<bool()> &isMarkerSet, const std::function<void()> &markDone,
    const ErmsCategoryQueryFunc &ermsQuery)
{
    // Non-dual-mode: skip and do NOT set marker (a future single->dual OTA still triggers it).
    if (!IsDualModeDevice()) {
        LOG_D(BMS_TAG_INSTALLER, "DualOTARefresh: not a dual-mode device, skip");
        return;
    }
    if (isMarkerSet && isMarkerSet()) {
        return;  // already refreshed (the caller's fast path logs this)
    }
    LOG_I(BMS_TAG_INSTALLER, "DualOTARefresh: pass start");
    bool allOk = true;
    StockRefreshStats stats;
    // Only iterate bundleInfos_; tempBundleInfos_ holds already-categorized apps.
    std::vector<std::string> bundleNames = dataMgr.GetAllBundleName();
    for (const auto &bundleName : bundleNames) {
        if (!RefreshOneStockApp(dataMgr, bundleName, ermsQuery, stats)) {
            allOk = false;  // genuine persist failure -> marker stays unset
        }
    }
    LOG_I(BMS_TAG_INSTALLER, "DualOTARefresh: pass end, total=%{public}zu alreadySet=%{public}zu "
        "persisted=%{public}zu default=%{public}zu vanished=%{public}zu",
        bundleNames.size(), stats.alreadySetCnt, stats.persistedCnt, stats.defaultCnt,
        stats.vanishedCnt);
    if (allOk && markDone) {
        markDone();
        LOG_I(BMS_TAG_INSTALLER, "DualOTARefresh: marker set, refresh complete");
    } else {
        LOG_W(BMS_TAG_INSTALLER, "DualOTARefresh: marker NOT set, will retry next boot");
    }
}

}  // namespace AppExecFwk
}  // namespace OHOS
