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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_RDB_RECOVER_MANAGER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_RDB_RECOVER_MANAGER_H

#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <string>

#include "bms_rdb_config.h"
#include "rdb_helper.h"

namespace OHOS {
namespace AppExecFwk {
// Snapshot salvage recovery of the bms rdb databases, as a stateless utility
// in the BundleUtil style: export the readable tables of a corrupted db into a
// snapshot file, replay the snapshot into the rebuilt db, resume recoveries
// interrupted before the commit point and orchestrate the whole rebuild.
// RdbDataManager owns the rdb store, calls the two recovery entry points while
// opening the db and guards every data operation with RdbOpGuard below; the
// other entry points serve the cross-instance recovery coordination.
class RdbRecoverManager {
public:
    // Rebuild a corrupted db from a snapshot: export the readable data, delete and
    // re-open the db, replay the snapshot, then remove it on the commit point.
    static ErrCode RebuildDbWithSnapshot(const BmsRdbConfig &bmsRdbConfig,
        const NativeRdb::RdbStoreConfig &rdbStoreConfig,
        std::shared_ptr<NativeRdb::RdbStore> &rdbStore, int32_t rebuildCode);

    // Resume an interrupted salvage recovery: a leftover snapshot means the previous
    // rebuild was interrupted before its commit point, so the db must not be served
    // as-is regardless of being readable. When the replay keeps failing, the
    // snapshot is downgraded after a few attempts: kept as .recover.failed, the db
    // discarded and re-created empty so the boot scan can refill the core tables.
    // Returns an error only when the db cannot be served at all.
    static ErrCode RecoverFromLeftoverSnapshot(const BmsRdbConfig &bmsRdbConfig,
        const NativeRdb::RdbStoreConfig &rdbStoreConfig,
        std::shared_ptr<NativeRdb::RdbStore> &rdbStore);

    // Whether a salvage recovery is currently running on the db: other
    // RdbDataManager instances sharing the same db must not serve their cached
    // stores meanwhile, otherwise their writes interleave with the replay
    // transactions or land on deleted db files.
    static bool IsRecovering(const std::string &dbName);

    // Monotonic generation of the db file, bumped whenever a recovery deleted and
    // re-created it: cached stores opened on an older generation belong to a
    // deleted file and must be re-opened.
    static uint64_t GetDbGeneration(const std::string &dbName);

    // Shared per-db operation lock: data operations hold it shared while using
    // the store, a salvage recovery holds it exclusive while exporting, deleting
    // and replaying the db, so an in-flight operation can never interleave with
    // a recovery.
    static std::shared_mutex &GetDbOpMutex(const std::string &dbName);

    // Full path of the failed salvage snapshot of a db, shared by the recovery
    // side (writer) and BMSEventHandler (reader/cleaner).
    static std::string BuildFailedSnapshotPath(const std::string &dbPath, const std::string &dbName);

    // Sticky per-db "corruption detected" state, shared by all instances of the
    // db in this process: set when a salvage export failed, cleared when the
    // integrity check passes again or a rebuild succeeds. While set, every
    // instance refuses to serve the db, not just the one that detected it.
    static void MarkCorruptionDetected(const std::string &dbName);
    static void ClearCorruptionDetected(const std::string &dbName);
    static bool IsCorruptionDetected(const std::string &dbName);

private:
    // Salvage readable tables of a corrupted db into a snapshot file next to the db.
    // The snapshot is written to a tmp file first and atomically renamed, so it is
    // either complete on disk or absent. Tables that fail to be read fully are
    // exported partially and flagged incomplete in the snapshot. The header line
    // records the db name and schema version so a stale snapshot of another db
    // (or another schema era) is rejected instead of replayed.
    static bool WriteSnapshotFile(const BmsRdbConfig &bmsRdbConfig,
        const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &snapshotPath);

    // Replay the snapshot into the currently open (fresh) db. Every table is
    // restored in one transaction with explicit primary keys (DELETE then INSERT),
    // so replaying any number of times leaves the same final state and an
    // interrupted replay never leaves half a table behind.
    // Returns false only on db write failures (snapshot kept for retry), errCode
    // then carries the rdb error. snapshotInvalid is set when the snapshot itself
    // is structurally broken (or does not belong to this db/version).
    static bool RestoreFromSnapshotFile(const std::string &dbName, int32_t dbVersion,
        const std::shared_ptr<NativeRdb::RdbStore> &rdbStore, const std::string &snapshotPath,
        bool &snapshotInvalid, int32_t &errCode);

    // Delete framework leftovers that RdbHelper::DeleteRdbStore does not cover
    // (e.g. <db>_master_corrupted.db, stale slave markers, legacy .bak files).
    // Never follows symlinks and never touches snapshot artifacts or unrelated files.
    static void CleanDbLeftoverFiles(const std::string &dbFile);

    // When installed_bundle/preinstalled_bundle/app_provision_info may be incomplete
    // (or the snapshot is broken so it is unknown what was lost), persist
    // dbRebuildMark in bms_param so the boot path rebuilds them from install dirs
    // instead of trusting the partially restored db. Loss of other tables is
    // reported but never marked: the rescan cannot recover them.
    // Returns false when the mark could not be persisted.
    static bool MarkRebuildIfDataIncomplete(const std::string &dbName,
        const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);

    // Keep a structurally broken snapshot as .recover.failed for forensics and
    // report it; BMSEventHandler distrusts the db while that file exists.
    // Returns false when the rename failed.
    static bool RenameSnapshotToFailed(const std::string &dbName, const std::string &dbFile,
        const std::string &snapshotPath);

    // Delete the db files, re-open the db and re-create the manager's table;
    // bumps the db generation so other instances drop their stale handles.
    // Returns the re-open error code, rdbStore is null on failure.
    static int32_t DeleteAndReopenDb(const BmsRdbConfig &bmsRdbConfig,
        const NativeRdb::RdbStoreConfig &rdbStoreConfig,
        std::shared_ptr<NativeRdb::RdbStore> &rdbStore);

    // Bump the db generation after the db file was deleted and re-created.
    static void BumpDbGeneration(const std::string &dbName);
};

// RAII guard for one data operation on a db: takes the shared operation lock so
// a salvage recovery cannot delete or replay the db while the operation runs.
// IsUsable() is false when a recovery is running or the db was rebuilt while
// waiting for the lock, in that case the operation must fail fast and the next
// call re-evaluates the store.
class RdbOpGuard {
public:
    RdbOpGuard(const std::string &dbName, uint64_t openGeneration)
        : opLock_(RdbRecoverManager::GetDbOpMutex(dbName))
    {
        usable_ = !RdbRecoverManager::IsRecovering(dbName) &&
            openGeneration == RdbRecoverManager::GetDbGeneration(dbName);
    }

    ~RdbOpGuard() = default;

    bool IsUsable() const
    {
        return usable_;
    }

private:
    std::shared_lock<std::shared_mutex> opLock_;
    bool usable_ = false;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_RDB_RECOVER_MANAGER_H
