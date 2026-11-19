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
#include <set>
#include <string>
#include <vector>

#include "bundle_stats/bundle_stats_cache_rdb.h"

namespace OHOS {
namespace AppExecFwk {

class BundleStatsCacheMgr {
public:
    static bool GetCachedData(const std::string &bundleName, int32_t userId,
        int32_t appIndex, BundleStatsCacheData &data);
    static bool IsCacheEnabled();
    static void ScanAllSharedUidApps(int32_t userId);
    static bool ShouldStartIdleScan();
    // Lifecycle cleanup
    static void OnBundleUninstalled(const std::string &bundleName);
    static void OnUserRemoved(int32_t userId);
    static void SetNeedStop(bool needStop);
    static bool NeedStop();
    static bool ShouldWriteCache(int32_t uid, int32_t userId);
    static bool IsValidDim(int64_t value) { return value >= 0; }
    static void RefreshCacheAfterHit(const std::string &bundleName, int32_t userId,
        int32_t appIndex);
    static void PopulateCacheAfterMiss(const std::string &bundleName, int32_t userId,
        int32_t appIndex, int32_t uid, const std::vector<int64_t> &partialStats);
    static bool IsInCooldown();
    static void MarkScanCompleted();
    static void ResetForTest();
    static void MergeAndWriteCache(const std::string &bundleName, int32_t userId,
        int32_t appIndex, const BundleStatsCacheData &newData);

private:
    BundleStatsCacheMgr() = default;
    static std::atomic<bool> needStop_;
    static std::atomic<int64_t> lastScanTimeMs_;
    // protects the merge read-merge-write sequence against concurrent writers
    static std::mutex refreshMutex_;
    static std::set<std::string> refreshInFlight_;
    ~BundleStatsCacheMgr() = default;
    struct SharedUidEntry {
        std::string bundleName;
        int32_t appIndex;
        int32_t uid;
    };
    static std::shared_ptr<BundleStatsCacheRdb> GetRdb();
    static void CollectSharedUidEntries(int32_t userId, std::vector<SharedUidEntry> &entries);
    static bool ScanAndUpsertEntries(int32_t userId, const std::vector<SharedUidEntry> &entries);
    static bool IsPcLikeDevice();
    static void RefreshCacheTask(const std::string &bundleName, int32_t userId,
        int32_t appIndex);
    static bool MarkRefreshInFlight(const std::string &key);
    static void UnmarkRefreshInFlight(const std::string &key);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_STATS_CACHE_MGR_H
