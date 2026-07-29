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

#include <mutex>
#include <string>

#include "application_info.h"
#include "inner_bundle_clone_common.h"

namespace OHOS {
namespace AppExecFwk {

// Helper for dual-mode (PC/PAD) application installation.
// Only APP_CATEGORY_DIFF_PACKAGE (same bundle name, different package body) apps
// need directory/key isolation in the secondary mode.
class DualModeHelper {
public:
    // Read current system mode from "persist.sys.mode" (pcmode/padmode/empty).
    static std::string GetSysMode();

    // Whether the device is a dual-mode device (supports pcmode or padmode).
    // Returns true if the cached system mode is configured (non-empty).
    static bool IsDualModeDevice();

    // Whether the device is currently in secondary mode.
    // Secondary: pcmode+tablet or padmode+2in1. Other cases (including invalid mode) are primary.
    static bool IsSecondaryMode();

    // Initialize the cached mode and device type by reading system parameters.
    // Called once at process startup (BundleMgrService::Init); no later re-init needed.
    static void InitializeCache();

    // Update the cached mode and device type by re-reading system parameters.
    // Should be called when system mode may have changed (e.g., device mode switch).
    static void UpdateModeCache();

    // Whether the appCategory contains APP_CATEGORY_DIFF_PACKAGE (category 7).
    static bool IsDiffPackageCategory(AppCategory appCategory);

    // Whether the current install needs dual-mode isolation handling.
    // True only when secondary mode AND category 7.
    static bool NeedDualModeHandle(AppCategory appCategory);

    // Build the dual-mode clone bundle name: "+clone-10000+{bundleName}".
    static std::string GetDualModeBundleName(const std::string &bundleName);

    // Parse a dual-mode clone name back to the original bundleName.
    // Returns false if the name is not a dual-mode (appIndex==10000) clone name.
    static bool ParseDualModeBundleName(const std::string &name, std::string &bundleName);

    // Whether the given db/storage key starts with the dual-mode clone prefix "+clone-".
    static bool IsDualModeCloneKey(const std::string &key);

private:
    // Cached system mode value (persist.sys.mode)
    static std::string cachedMode_;

    // Cached device type value
    static std::string cachedDeviceType_;

    // Mutex for thread-safe cache access
    static std::mutex cacheMutex_;
};

}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DUAL_MODE_HELPER_H
