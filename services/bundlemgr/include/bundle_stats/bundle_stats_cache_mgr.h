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
#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_STATS_CACHE_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_STATS_CACHE_MGR_H

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "bundle_stats/bundle_stats_cache_rdb.h"

namespace OHOS {
namespace AppExecFwk {

class BundleStatsCacheMgr {
public:
    // Test switch: persist.bms.test.stats_cache_disabled (true = skip cache, always scan)
    static bool IsCacheEnabled();
    // Idle scan: scan all shared-uid apps and persist results
    static void ScanAllSharedUidApps(int32_t userId);
    // Precheck: device gate + cooldown, no side effects
    static bool ShouldStartIdleScan();
    // Lifecycle: interrupt flag for the idle scan
    static void SetNeedStop(bool needStop);
    static bool NeedStop();
    // -1 sentinel validity: a dim value is valid iff >= 0. Single decision
    // point for all merge checks.
    static bool IsValidDim(int64_t value) { return value >= 0; }
    // Cooldown state, exposed for unit testing the persisted-time parse
    static bool IsInCooldown();
    static void MarkScanCompleted();
    // Test support: forget the in-memory last scan time so cooldown
    // checks start from a clean state
    static void ResetForTest();

private:
    BundleStatsCacheMgr() = default;
    static std::atomic<bool> needStop_;
    static std::atomic<int64_t> lastScanTimeMs_;
    // protects the merge read-merge-write sequence against concurrent writers
    static std::mutex refreshMutex_;
    struct SharedUidEntry {
        std::string bundleName;
        int32_t appIndex;
        int32_t uid;
    };
    static std::shared_ptr<BundleStatsCacheRdb> GetRdb();
    static void CollectSharedUidEntries(int32_t userId, std::vector<SharedUidEntry> &entries);
    // Scan every entry and upsert its stats; returns false when interrupted
    // (NeedStop). Already-written entries are kept so the next idle window
    // resumes from where this one stopped.
    static bool ScanAndUpsertEntries(int32_t userId, const std::vector<SharedUidEntry> &entries);
    static void MergeAndWriteCache(const std::string &bundleName, int32_t userId,
        int32_t appIndex, const BundleStatsCacheData &newData);
    static bool IsPcLikeDevice();
    ~BundleStatsCacheMgr() = default;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_STATS_CACHE_MGR_H
