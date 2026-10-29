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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_ATM_BUNDLE_RECOVERY_INFO_H
#define FOUNDATION_BUNDLE_FRAMEWORK_ATM_BUNDLE_RECOVERY_INFO_H

#include <cstdint>
#include <string>
#include <vector>

namespace OHOS::AppExecFwk {
struct AtmBundleRecoveryInfo {
    std::string bundleName;
    int32_t userId = -1;
    int32_t appIndex = 0;
    uint32_t accessTokenId = 0;
    uint64_t accessTokenIdEx = 0;
    int32_t uid = -1;
    std::vector<std::string> hapPaths;
    // Same-name different-package status: -1 = not applicable, 0 = primary, 1 = secondary.
    int32_t mode = -1;
    bool isPreInstallApp = false;
    bool isUninstalled = false;
};

struct AtmBundleRecoveryResult {
    int32_t code = 0;
    std::vector<AtmBundleRecoveryInfo> infos;
};

/**
 * Read persisted installation identities in the calling process, without IPC.
 * Requires ohos.permission.GET_BUNDLE_INFO_PRIVILEGED on the current process.
 * Success: 0; permission denied/unavailable: 8519925; database error: 8522306.
 * Invalid records are skipped. A nonempty database with no valid record fails.
 * A valid empty database succeeds. On error infos is empty. The caller owns all values.
 */
__attribute__((visibility("default"))) AtmBundleRecoveryResult QueryAtmBundleRecoveryInfo();
} // namespace OHOS::AppExecFwk
#endif
