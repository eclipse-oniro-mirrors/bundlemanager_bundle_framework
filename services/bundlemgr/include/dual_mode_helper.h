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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DUAL_MODE_HELPER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DUAL_MODE_HELPER_H

#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "bundle_info.h"
#include "inner_bundle_clone_common.h"

namespace OHOS {
namespace AppExecFwk {

// Helper for dual-mode (PC/PAD) application installation.
// Only *_DIFFERENT_PACKAGE policy apps (same bundle name, different package body)
// need directory/key isolation in the secondary mode.
using ErmsGetPolicyFunc = int32_t (*)(std::string, std::string, std::string, int32_t &,
    std::map<std::string, std::vector<std::string>> &);

class DualModeHelper {
public:
    // Read current system mode from "persist.sceneboard.ispcmode" (bool: true=2in1, false=tablet).
    // Returns 0 (tablet), 1 (2in1), or -1 (param not exist / read failed / illegal).
    static int32_t GetSysMode();

    // Whether the device is a dual-mode device.
    // Reads system parameters directly each call (no cache); returns true only when both
    // ispcmode and mainmode are valid (0 or 1).
    static bool IsDualModeDevice();

    // Whether the device is currently in secondary mode.
    // Reads system parameters directly each call (no cache).
    // Secondary: isDualModeDevice && (ispcmode != mainmode). Other cases are primary / non-dual-mode.
    static bool IsSecondaryMode();

    // Read the main mode (const.sceneboard.mainmode) directly: 0=tablet, 1=2in1, -1=invalid.
    // Used by the dual-mode preinstall fan-out to tell the primary deviceType from the secondary one.
    static int32_t GetMainmode();

    // Map an ERMS-returned deviceType string to a mode value (0=tablet, 1=2in1).
    // Returns DUAL_MODE_VALUE_INVALID (-1) when the string is not a recognized device type.
    static int32_t MapDeviceTypeToMode(const std::string &deviceType);

    // Test-injection switch (persist.bms.test_dual_mode). When true, ispcmode/mainmode are read
    // from persist.bms.ispcmode / persist.bms.mainmode instead of the production sceneboard params
    // (persist.sceneboard.ispcmode / const.sceneboard.mainmode) for test
    // verification; production (unset/false) is unaffected. The production ispcmode key is
    // bool-typed (true=2in1, false=tablet); the test key is int-typed (0/1).
    static bool IsTestDualMode();

    // Whether the policy is a different-package category (UNIVERSAL/PARTIAL_COMPATIBLE/
    // FULL_COMPATIBLE_DIFFERENT_PACKAGE).
    static bool IsDiffPackageCategory(DeviceModeDistributionPolicy policy);

    // Whether a device-mode distribution policy set is valid (single validation source for the
    // runtime switch input and the persisted value). Rules: non-empty; every value a legal
    // DeviceModeDistributionPolicy (0~8); all different-package policies (4/6/8) present —
    // they must stay visible via mode-based variant selection. Deduplication is inherent
    // to the set.
    static bool IsValidPolicySet(const std::set<DeviceModeDistributionPolicy> &policies);

    // Parse the persisted policy CSV ("4,6,8,...") into a validated policy set. SplitStr/StrToInt
    // are no-throw (this build is -fno-exceptions); the persisted value may be corrupted, so on
    // any malformed token or rule violation (IsValidPolicySet) return false — the caller then
    // falls back to the requirement-1 degradation.
    static bool ParsePersistedPolicies(const std::string &policiesStr,
        std::set<DeviceModeDistributionPolicy> &policySet);

    // Canonical persisted form of a policy set: ascending unique decimal values joined by ",".
    static std::string PoliciesToCsv(const std::set<DeviceModeDistributionPolicy> &policySet);

    // Whether the current install needs dual-mode isolation handling.
    // True only when secondary mode AND different-package category.
    static bool NeedDualModeHandle(DeviceModeDistributionPolicy policy);

    // Build the dual-mode clone bundle name: "+clone-10000+{bundleName}".
    static std::string GetDualModeBundleName(const std::string &bundleName);

    // Parse a dual-mode clone name back to the original bundleName.
    // Returns false if the name is not a dual-mode (appIndex==10000) clone name.
    static bool ParseDualModeBundleName(const std::string &name, std::string &bundleName);

    // Whether the given db/storage key starts with the dual-mode clone prefix "+clone-".
    static bool IsDualModeCloneKey(const std::string &key);

    // Query ERMS for device model distribution policy via dlopen of liberms_sdk.z.so.
    // bundleName:          bundle name of the app to query
    // bundleDir:           absolute path of the pre-installed directory
    // appDistributionType: distribution type string (e.g. "os_integration")
    // policy:              output DeviceModeDistributionPolicy value
    // modeHapMap:          output map (key=deviceType, value=hap paths of that mode)
    // Returns true on success, false if the library/symbol is unavailable or the call fails.
    static bool GetDeviceModelDistributionPolicy(
        const std::string &bundleName,
        const std::string &bundleDir,
        const std::string &appDistributionType,
        int32_t &policy,
        std::map<std::string, std::vector<std::string>> &modeHapMap);

private:
    static std::mutex ermsMutex_;
    static void *ermsHandle_;
    static ErmsGetPolicyFunc ermsGetPolicyFunc_;
    static bool OpenErmsHandle();
};

}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DUAL_MODE_HELPER_H
