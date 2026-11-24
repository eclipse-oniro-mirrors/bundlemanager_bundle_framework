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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_DEDUP_SO_HELPER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_DEDUP_SO_HELPER_H

#include <cstdint>
#include <limits>
#include <string>

#include "appexecfwk_errors.h"
#include "inner_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
// Self-contained copy of the musl so_dedup.h result contract (the Foundation
// process never links musl, installd passes the raw resultCode back over IPC);
// the RESULT prefix avoids collisions with the musl SO_DEDUP_* enum members.
constexpr uint32_t SO_DEDUP_RESULT_LINKED = 0;
constexpr uint32_t SO_DEDUP_RESULT_NO_MATCH = 1;
constexpr uint32_t SO_DEDUP_RESULT_ALREADY_LINKED = 2;
constexpr uint32_t SO_DEDUP_RESULT_CONFIG_UNAVAILABLE = 3;
constexpr uint32_t SO_DEDUP_RESULT_VERSION_MISMATCH = 4;
constexpr uint32_t SO_DEDUP_RESULT_ERROR = std::numeric_limits<uint32_t>::max();

/**
 * @brief Static helper orchestrating the dedup so link creation inside the install
 *        transaction: parse dedupfiles.json, filter the entries by cpuAbi, call the
 *        installd LinkDedupedSo per entry and map the musl result codes to install
 *        error codes. Pure static, no shared mutable state.
 */
class DedupSoHelper {
public:
    /**
     * @brief Link the dedupfiles.json entries matching the module cpu abi into
     *        targetSoPath through installd, still inside the staging transaction
     *        before the rename commit. FA-model and driver-type packages, and a
     *        HAP without the manifest, keep the normal install flow.
     * @param hapPath Indicates the path of the HAP file being installed.
     * @param newBundleInfo Indicates the parsed bundle info of the HAP.
     * @param targetSoPath Indicates the dir the native so files were extracted to.
     * @param cpuAbi Indicates the module cpu abi (the caller's FetchNativeSoAttrs
     *        value, not the bundle-level GetCpuAbi one): only entries under
     *        libs/<cpuAbi>/ are linked.
     * @return Returns ERR_OK when the flow may continue; PARSE_FAILED when the
     *         manifest is invalid; the mapped dedup so error codes on link failure.
     */
    static ErrCode ProcessDedupSoFiles(const std::string &hapPath, const InnerBundleInfo &newBundleInfo,
        const std::string &targetSoPath, const std::string &cpuAbi);

    /**
     * @brief Map the musl LinkDedupedSo result code to an install error code.
     * @param resultCode Indicates the musl result code (a SO_DEDUP_RESULT_* constant).
     * @return Returns ERR_OK for LINKED/ALREADY_LINKED, the mapped dedup so install
     *         error for NO_MATCH/CONFIG_UNAVAILABLE/VERSION_MISMATCH, and
     *         ERR_APPEXECFWK_INSTALL_DEDUP_SO_LINK_FAILED otherwise.
     */
    static ErrCode MapLinkResultCode(uint32_t resultCode);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_DEDUP_SO_HELPER_H
