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

#include <set>

#include "bundle_stats/bundle_stats_cache_mgr.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_mgr_service.h"
#include "bundle_service_constants.h"
#include "bundle_util.h"
#include "dual_mode_helper.h"
#include "idle_condition_mgr/idle_condition_mgr.h"
#include "inner_bundle_info.h"
#include "parameters.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int64_t SCAN_COOLDOWN_MS = 7LL * 24 * 60 * 60 * 1000; // 7 days
// the public GetBundleStats stats vector covers 5 dims; a scan result must
// fill all of them before it is cached (the cache row tolerates one spare
// dim for forward compatibility, see BundleStatsCacheRdb)
constexpr size_t BUNDLE_STATS_MIN_SIZE = 5;

// A scan entry is collected when it is a real shared-uid entry
// (uid == userId for the requested user), or for every installed entry in
// force-scan test mode.
bool ShouldCollectScanEntry(int32_t uid, int32_t responseUserId, bool forceScan)
{
    if (forceScan) {
        return uid >= 0;
    }
    return uid == responseUserId && uid >= Constants::START_USERID;
}
} // namespace

std::atomic<bool> BundleStatsCacheMgr::needStop_{false};
std::atomic<int64_t> BundleStatsCacheMgr::lastScanTimeMs_{0};
std::mutex BundleStatsCacheMgr::refreshMutex_;
std::set<std::string> BundleStatsCacheMgr::refreshInFlight_;

std::shared_ptr<BundleStatsCacheRdb> BundleStatsCacheMgr::GetRdb()
{
    // magic static: the cache table is created on first touch, not at boot
    static std::shared_ptr<BundleStatsCacheRdb> instance = std::make_shared<BundleStatsCacheRdb>();
    return instance;
}

bool BundleStatsCacheMgr::IsCacheEnabled()
{
    // Cache is enabled by default. Set persist.bms.test.stats_cache_disabled
    // to true to skip the cache and always scan (test mode).
    return !OHOS::system::GetBoolParameter(ServiceConstants::BMS_TEST_STATS_CACHE_DISABLED_PARAM, false);
}

void BundleStatsCacheMgr::CollectSharedUidEntries(int32_t userId,
    std::vector<SharedUidEntry> &entries)
{
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    auto dataMgr = (service != nullptr) ? service->GetDataMgr() : nullptr;
    if (dataMgr == nullptr) {
        APP_LOGE_NOFUNC("BundleStats DataMgr is null when collecting entries");
        return;
    }
    bool forceScan = OHOS::system::GetBoolParameter(
        ServiceConstants::BMS_TEST_SHARED_UID_PARAM, false);
    auto allInfos = dataMgr->GetAllInnerBundleInfos();
    for (const auto &item : allInfos) {
        const InnerBundleInfo &info = item.second;
        int32_t responseUserId = info.GetResponseUserId(userId);
        if (responseUserId == Constants::INVALID_USERID) {
            continue;
        }
        std::vector<int32_t> allAppIndexes = {0};
        if (info.GetApplicationBundleType() == BundleType::APP) {
            auto cloneIndexes = dataMgr->GetCloneAppIndexesByInnerBundleInfo(info, responseUserId);
            allAppIndexes.insert(allAppIndexes.end(), cloneIndexes.begin(), cloneIndexes.end());
            auto cliIndexes = dataMgr->GetCliSandboxAppIndexesByInnerBundleInfo(info, responseUserId);
            allAppIndexes.insert(allAppIndexes.end(), cliIndexes.begin(), cliIndexes.end());
        }
        for (int32_t appIndex : allAppIndexes) {
            int32_t uid = info.GetUid(responseUserId, appIndex);
            if (ShouldCollectScanEntry(uid, responseUserId, forceScan)) {
                entries.push_back({info.GetBundleName(), appIndex, uid});
            }
        }
    }
}

bool BundleStatsCacheMgr::ScanAndUpsertEntries(int32_t userId,
    const std::vector<SharedUidEntry> &entries)
{
    // Fail fast on a pending interrupt before touching the service, so an
    // interrupted scan reports false without any RDB/IPC side effects.
    if (NeedStop()) {
        APP_LOGI_NOFUNC("BundleStats interrupted before scan, stop");
        return false;
    }
    // Route every entry through BundleDataMgr::ScanBundleStats so the idle
    // scan writes with exactly the same parity as the query-miss and
    // hit-refresh paths (keepdata fallback, SA-uid merge, preinstall
    // compensation); a direct InstalldClient call would skip those and make
    // the same cache key alternate between two writers' calibers.
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    auto dataMgr = (service != nullptr) ? service->GetDataMgr() : nullptr;
    if (dataMgr == nullptr) {
        APP_LOGE_NOFUNC("BundleStats DataMgr is null when scanning entries");
        return false;
    }
    int64_t scanTime = BundleUtil::GetCurrentTimeMs();
    for (const auto &item : entries) {
        if (NeedStop()) {
            APP_LOGI_NOFUNC("BundleStats interrupted, stop scanning");
            return false;
        }
        std::vector<int64_t> stats;
        int32_t uid = Constants::INVALID_UID;
        int64_t inodeCount = -1;
        // ScanBundleStats resolves the effective name/uids internally; the
        // IPC returns bundleStats and inodeCount from a single directory
        // traversal. -1 = scan unavailable: a degraded 0 is never cached.
        if (!dataMgr->ScanBundleStats(item.bundleName, userId, stats, item.appIndex, uid,
            &inodeCount) || stats.size() < BUNDLE_STATS_MIN_SIZE || !IsValidDim(inodeCount)) {
            APP_LOGW_NOFUNC("BundleStats scan failed or unavailable -n:%{public}s -i:%{public}d",
                item.bundleName.c_str(), item.appIndex);
            continue;
        }

        BundleStatsCacheData data;
        data.uid = uid;
        data.scanTime = scanTime;
        data.bundleStats = stats;
        data.inodeCount = inodeCount;

        // Write via MergeAndWriteCache (not direct UpsertCache) so the
        // read-merge-write sequence is protected by refreshMutex_ and
        // dimensions from concurrent writers are not overwritten.
        MergeAndWriteCache(item.bundleName, userId, item.appIndex, data);
    }
    return true;
}

bool BundleStatsCacheMgr::IsPcLikeDevice()
{
    return OHOS::system::GetDeviceType() == "2in1" ||
        (DualModeHelper::IsDualModeDevice() &&
            DualModeHelper::GetSysMode() == ServiceConstants::DUAL_MODE_VALUE_2IN1);
}

bool BundleStatsCacheMgr::ShouldStartIdleScan()
{
    if (!IsPcLikeDevice()) {
        APP_LOGI_NOFUNC("BundleStats skip: not PC device or not in PC mode");
        return false;
    }
    return !IsInCooldown();
}

void BundleStatsCacheMgr::ScanAllSharedUidApps(int32_t userId)
{
    if (!ShouldStartIdleScan()) {
        return;
    }
    std::vector<SharedUidEntry> entries;
    CollectSharedUidEntries(userId, entries);
    bool completed = ScanAndUpsertEntries(userId, entries);
    if (completed) {
        APP_LOGI_NOFUNC("BundleStats done for userId %{public}d, entries %{public}zu",
            userId, entries.size());
    } else {
        APP_LOGI_NOFUNC("BundleStats interrupted for userId %{public}d", userId);
    }
    // Stamp the cooldown unconditionally (same pattern as FileCategory's
    // StampScanTime): once the scan attempt is made, the next retry waits
    // for the full cooldown regardless of whether the scan completed or was
    // interrupted.
    MarkScanCompleted();
}

bool BundleStatsCacheMgr::IsInCooldown()
{
    bool testMode = OHOS::system::GetBoolParameter(
        ServiceConstants::BMS_TEST_STATS_SCAN_COOLDOWN_DISABLED_PARAM, false);
    if (testMode) {
        APP_LOGI_NOFUNC("BundleStats test mode active, bypassing cooldown");
        return false;
    }
    int64_t lastScanTime = lastScanTimeMs_.load(std::memory_order_acquire);
    if (lastScanTime <= 0) {
        return false;
    }
    return BundleUtil::GetCurrentTimeMs() - lastScanTime < SCAN_COOLDOWN_MS;
}

void BundleStatsCacheMgr::MarkScanCompleted()
{
    lastScanTimeMs_.store(BundleUtil::GetCurrentTimeMs(), std::memory_order_release);
}

void BundleStatsCacheMgr::SetNeedStop(bool needStop)
{
    needStop_.store(needStop, std::memory_order_release);
}

bool BundleStatsCacheMgr::NeedStop()
{
    return needStop_.load(std::memory_order_acquire);
}

void BundleStatsCacheMgr::MergeAndWriteCache(const std::string &bundleName, int32_t userId,
    int32_t appIndex, const BundleStatsCacheData &newData)
{
    // Protect the read-merge-write sequence: without this lock, concurrent
    // writers (query miss write-back, refresh task, idle scan) could read the
    // same stale value and overwrite each other's merged dimensions.
    std::lock_guard<std::mutex> lock(refreshMutex_);
    BundleStatsCacheData merged = newData;
    BundleStatsCacheData existing;
    if (GetRdb()->GetCacheData(bundleName, userId, appIndex, existing)) {
        const size_t newSize = newData.bundleStats.size();
        const size_t oldSize = existing.bundleStats.size();
        const size_t maxSize = (newSize > oldSize) ? newSize : oldSize;
        merged.bundleStats.resize(maxSize, -1);
        for (size_t i = 0; i < maxSize; ++i) {
            int64_t newStat = (i < newSize) ? newData.bundleStats[i] : -1;
            int64_t oldStat = (i < oldSize) ? existing.bundleStats[i] : -1;
            if (IsValidDim(newStat)) {
                merged.bundleStats[i] = newStat;
            } else {
                merged.bundleStats[i] = oldStat;
            }
        }
        if (IsValidDim(newData.inodeCount)) {
            merged.inodeCount = newData.inodeCount;
        } else {
            merged.inodeCount = existing.inodeCount;
        }
    }
    GetRdb()->UpsertCache(bundleName, userId, appIndex, merged);
}

void BundleStatsCacheMgr::ResetForTest()
{
    lastScanTimeMs_.store(0, std::memory_order_release);
}
bool BundleStatsCacheMgr::GetCachedData(const std::string &bundleName, int32_t userId,
    int32_t appIndex, BundleStatsCacheData &data)
{
    if (!IsCacheEnabled()) {
        return false;
    }
    return GetRdb()->GetCacheData(bundleName, userId, appIndex, data);
}

void BundleStatsCacheMgr::OnBundleUninstalled(const std::string &bundleName)
{
    GetRdb()->DeleteBundle(bundleName);
}

void BundleStatsCacheMgr::OnUserRemoved(int32_t userId)
{
    GetRdb()->DeleteUser(userId);
}

bool BundleStatsCacheMgr::ShouldWriteCache(int32_t uid, int32_t userId)
{
    if (!IsCacheEnabled()) {
        return false;
    }
    bool forceScan = OHOS::system::GetBoolParameter(
        ServiceConstants::BMS_TEST_SHARED_UID_PARAM, false);
    if (forceScan) {
        return uid >= 0;
    }
    return uid == userId && uid >= Constants::START_USERID;
}

bool BundleStatsCacheMgr::MarkRefreshInFlight(const std::string &key)
{
    std::lock_guard<std::mutex> lock(refreshMutex_);
    if (refreshInFlight_.find(key) != refreshInFlight_.end()) {
        return false;
    }
    refreshInFlight_.insert(key);
    return true;
}

void BundleStatsCacheMgr::UnmarkRefreshInFlight(const std::string &key)
{
    std::lock_guard<std::mutex> lock(refreshMutex_);
    refreshInFlight_.erase(key);
}

void BundleStatsCacheMgr::RefreshCacheTask(const std::string &bundleName, int32_t userId,
    int32_t appIndex)
{
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    auto dataMgr = (service != nullptr) ? service->GetDataMgr() : nullptr;
    if (dataMgr == nullptr) {
        APP_LOGE_NOFUNC("DataMgr is null");
        return;
    }
    std::vector<int64_t> stats;
    int32_t uid = Constants::INVALID_UID;
    int64_t inodeCount = -1;
    if (!dataMgr->ScanBundleStats(bundleName, userId, stats, appIndex, uid, &inodeCount)) {
        APP_LOGD("refresh aborted: scan failed -n:%{public}s",
            bundleName.c_str());
        return;
    }
    // -1 = scan failed: keep the existing entry as is, it must never be
    // cached
    if (!IsValidDim(inodeCount)) {
        APP_LOGD("refresh skipped: scan unavailable -n:%{public}s",
            bundleName.c_str());
        return;
    }
    BundleStatsCacheData data;
    data.uid = uid;
    data.scanTime = BundleUtil::GetCurrentTimeMs();
    data.bundleStats = stats;
    data.inodeCount = inodeCount;
    MergeAndWriteCache(bundleName, userId, appIndex, data);
    APP_LOGD("refresh done -n:%{public}s", bundleName.c_str());
}

void BundleStatsCacheMgr::RefreshCacheAfterHit(const std::string &bundleName, int32_t userId,
    int32_t appIndex)
{
    auto idleMgr = DelayedSingleton<IdleConditionMgr>::GetInstance();
    if (idleMgr != nullptr && idleMgr->IsBundleStatsScanActive()) {
        APP_LOGD("skip refresh: idle scan active -n:%{public}s",
            bundleName.c_str());
        return;
    }
    std::string key = bundleName + ":" + std::to_string(userId) + ":"
        + std::to_string(appIndex);
    if (!MarkRefreshInFlight(key)) {
        APP_LOGD("skip refresh: already in flight -n:%{public}s",
            bundleName.c_str());
        return;
    }
    auto task = [bundleName, userId, appIndex, key] {
        ScopeGuard guard([key] { UnmarkRefreshInFlight(key); });
        RefreshCacheTask(bundleName, userId, appIndex);
    };
    ffrt::submit(task);
}

void BundleStatsCacheMgr::PopulateCacheAfterMiss(const std::string &bundleName, int32_t userId,
    int32_t appIndex, int32_t uid, const std::vector<int64_t> &partialStats)
{
    auto idleMgr = DelayedSingleton<IdleConditionMgr>::GetInstance();
    if (idleMgr != nullptr && idleMgr->IsBundleStatsScanActive()) {
        APP_LOGD("skip populate: idle scan active -n:%{public}s",
            bundleName.c_str());
        return;
    }
    std::string key = bundleName + ":" + std::to_string(userId) + ":"
        + std::to_string(appIndex);
    if (!MarkRefreshInFlight(key)) {
        APP_LOGD("skip populate: already in flight -n:%{public}s",
            bundleName.c_str());
        return;
    }
    auto task = [bundleName, userId, appIndex, uid, partialStats, key] {
        ScopeGuard guard([key] { UnmarkRefreshInFlight(key); });
        // Step 1: merge the batch-scanned partial dims first so they serve
        // aggregate hits while the completing scan runs. The caller marks the
        // cache size dim -1 (never computed by the batch path).
        if (partialStats.size() >= 2) {
            BundleStatsCacheData data;
            data.uid = uid;
            data.scanTime = BundleUtil::GetCurrentTimeMs();
            data.bundleStats = partialStats;
            data.inodeCount = -1;
            MergeAndWriteCache(bundleName, userId, appIndex, data);
        }
        // Step 2: complete the entry with a full scan (all dims + inode).
        RefreshCacheTask(bundleName, userId, appIndex);
        APP_LOGD("populate done -n:%{public}s", bundleName.c_str());
    };
    ffrt::submit(task);
}

} // namespace AppExecFwk
} // namespace OHOS
