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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_CLEAN_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_CLEAN_MGR_H

#include <memory>
#include <string>

#include "iremote_stub.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {

class RdbDataManager;

// Selective BMS data cleanup in BOPD mode.
// Dispatched via the SA clean framework OnExtension("clean") (see BundleMgrService::OnExtension). It accesses the
// mirror bmsdb.db under /mnt/data_mirror directly, deletes the bms_param KEY='fingerprint' row so that
// GetOldSystemFingerprint() returns empty and IsSystemFingerprintChanged() is true on normal boot (entering the
// existing system-upgrade path), and writes the bms_param flag bmsCleanRecovery=true. The flag is read by
// bundle_mgr_service_event_handler.cpp in the OTA same-version branch to force pre-install same-version reinstall.
// Constraints: do not delete the db file, drop tables, delete other KV rows, or modify installed_bundle; do not add
// privileged raw file operations in the Foundation process.
class BundleCleanMgr : public DelayedSingleton<BundleCleanMgr> {
public:
    BundleCleanMgr();
    ~BundleCleanMgr();

    // SA clean callback entry. The cleanup content is decided by BMS (delete the bms_param.fingerprint row and write
    // the bmsCleanRecovery flag) and does not depend on caller parcel args. Returns ERR_OK(0) on success.
    ErrCode OnClean();

private:
    // Delete the bms_param KEY='fingerprint' row on the mirror bmsdb. The row is deleted (not written empty, since
    // SaveBmsParam rejects empty values); the table, db file, and other rows are left intact.
    ErrCode CleanFingerprint();

    // Write KEY='bmsCleanRecovery' VALUE='true' to the bms_param table on the mirror bmsdb. Read by event_handler
    // on normal boot to force pre-install updateBundle in the same-version branch; cleared after the scan completes.
    ErrCode SetCleanupRecoveryFlag();

    // Build an isolated RdbDataManager instance on the mirror dbPath; tableName selects bms_param.
    std::shared_ptr<RdbDataManager> CreateMirrorRdbDataManager(const std::string &tableName);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_CLEAN_MGR_H
