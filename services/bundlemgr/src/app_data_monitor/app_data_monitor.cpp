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

#include "app_data_monitor/app_data_monitor.h"

#include <algorithm>
#include <thread>

#include "account_helper.h"
#include "app_log_wrapper.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_service_constants.h"
#include "bundle_storage_stats.h"
#include "event_report.h"
#include "inner_bundle_info.h"
#include "inner_bundle_user_info.h"
#include "installd_client.h"
#include "nlohmann/json.hpp"
#include "parameters.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {

AppDataMonitor::AppDataMonitor()
{
    APP_LOGI_NOFUNC("ScanSystemAppSize AppDataMonitor created");
}

bool AppDataMonitor::IsScanning() const
{
    return isScanning_.load();
}

bool AppDataMonitor::IsInCooldown() const
{
    if (lastScanTime_ == std::chrono::steady_clock::time_point{}) {
        return false;
    }
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastScanTime_).count();
    if (elapsed < COOLDOWN_SECONDS) {
        APP_LOGI_NOFUNC("ScanSystemAppSize scan in cooldown, elapsed=%{public}llds, need=%{public}llds",
            static_cast<long long>(elapsed), static_cast<long long>(COOLDOWN_SECONDS));
        return true;
    }
    return false;
}

void AppDataMonitor::StartScan(int32_t userId)
{
    if (isScanning_.exchange(true)) {
        APP_LOGI_NOFUNC("ScanSystemAppSize scan already in progress");
        return;
    }
    auto self = shared_from_this();
    ScopeGuard scanGuard([self] {
        self->isScanning_ = false;
        self->stopRequested_ = false;
    });

    bool testMode = OHOS::system::GetBoolParameter(
        ServiceConstants::SCAN_APP_DATA_TEST_PARAM, false);
    if (!testMode && IsInCooldown()) {
        return;
    }
    if (testMode) {
        APP_LOGI_NOFUNC("ScanSystemAppSize scan test mode active, bypassing cooldown");
    }
    if (stopRequested_.load()) {
        APP_LOGI_NOFUNC("ScanSystemAppSize scan aborted, stop requested before start");
        return;
    }
    APP_LOGI_NOFUNC("ScanSystemAppSize start scanning system app data, userId=%{public}d", userId);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE_NOFUNC("ScanSystemAppSize GetDataMgr is null");
        lastScanTime_ = std::chrono::steady_clock::now();
        return;
    }
    auto systemApps = dataMgr->GetSystemAppNames(userId);
    if (systemApps.empty()) {
        APP_LOGI_NOFUNC("ScanSystemAppSize no system apps found");
        lastScanTime_ = std::chrono::steady_clock::now();
        return;
    }

    std::vector<std::pair<std::string, int64_t>> sortedApps;
    if (!GetAndSortAppDataSize(userId, dataMgr, systemApps, sortedApps)) {
        lastScanTime_ = std::chrono::steady_clock::now();
        return;
    }

    ScanLargeApps(userId, sortedApps);

    lastScanTime_ = std::chrono::steady_clock::now();
    APP_LOGI_NOFUNC("ScanSystemAppSize scan completed, next scan allowed after 72h");
}

void AppDataMonitor::StopScan(const std::string &reason)
{
    APP_LOGI_NOFUNC("ScanSystemAppSize scan stop requested, reason: %{public}s", reason.c_str());
    stopRequested_ = true;
}

bool AppDataMonitor::GetAndSortAppDataSize(int32_t userId,
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    const std::vector<std::string> &bundleNames,
    std::vector<std::pair<std::string, int64_t>> &sortedApps)
{
    std::vector<BundleStorageStats> bundleStats;
    ErrCode ret = dataMgr->BatchGetBundleStats(bundleNames, userId, bundleStats);
    if (ret != ERR_OK) {
        APP_LOGE_NOFUNC("ScanSystemAppSize BatchGetBundleStats failed, ret=%{public}d", ret);
        return false;
    }

    for (const auto &stat : bundleStats) {
        if (stat.errCode != ERR_OK) {
            APP_LOGW_NOFUNC("ScanSystemAppSize skip %{public}s, errCode=%{public}d",
                stat.bundleName.c_str(), stat.errCode);
            continue;
        }
        if (static_cast<int32_t>(stat.bundleStats.size()) <= BUNDLE_DATA_SIZE_INDEX) {
            APP_LOGW_NOFUNC("ScanSystemAppSize skip %{public}s, bundleStats size too small", stat.bundleName.c_str());
            continue;
        }
        sortedApps.emplace_back(stat.bundleName, stat.bundleStats[BUNDLE_DATA_SIZE_INDEX]);
    }

    std::sort(sortedApps.begin(), sortedApps.end(),
        [](const auto &a, const auto &b) { return a.second > b.second; });
    return true;
}

void AppDataMonitor::ScanLargeApps(int32_t userId,
    const std::vector<std::pair<std::string, int64_t>> &sortedApps)
{
    // Base-app-only: this requirement scans only the base install (appIndex 0); clone apps are out
    // of scope.
    reportedCountInScan_ = 0;
    constexpr int32_t baseAppIndex = 0;
    for (const auto &[bundleName, dataSize] : sortedApps) {
        if (stopRequested_.load()) {
            APP_LOGI_NOFUNC("ScanSystemAppSize scan interrupted, bundle=%{public}s", bundleName.c_str());
            return;
        }

        if (dataSize < LARGE_APP_THRESHOLD) {
            APP_LOGI_NOFUNC("ScanSystemAppSize remaining apps all below 1GB threshold, stop scanning");
            return;
        }

        APP_LOGI_NOFUNC("ScanSystemAppSize scanning large app: %{public}s, dataSize=%{public}lld",
            bundleName.c_str(), static_cast<long long>(dataSize));

        auto installdClient = InstalldClient::GetInstance();
        if (installdClient == nullptr) {
            APP_LOGE_NOFUNC("ScanSystemAppSize InstalldClient is null, abort scan");
            return;
        }

        std::string largestItems;
        ErrCode ret = installdClient->GetTopNLargestItemsInAppDataDir(
            bundleName, baseAppIndex, userId, GET_TOP_N_TIMEOUT, largestItems);
        if (ret != ERR_OK) {
            APP_LOGW_NOFUNC("ScanSystemAppSize GetTopNLargestItemsInAppDataDir failed for %{public}s, ret=%{public}d",
                bundleName.c_str(), ret);
            continue;
        }

        ReportLargeFilesEvent(bundleName, userId, baseAppIndex, largestItems);
        // sortedApps is size-descending, so once the per-scan cap is reached the apps kept are the
        // largest ones; stop and skip the rest.
        ++reportedCountInScan_;
        if (reportedCountInScan_ >= MAX_REPORT_COUNT_PER_SCAN) {
            APP_LOGI_NOFUNC("ScanSystemAppSize reached per-scan report cap %{public}d, skip remaining apps",
                MAX_REPORT_COUNT_PER_SCAN);
            return;
        }
    }
    APP_LOGI_NOFUNC("ScanSystemAppSize all large apps scanned");
}

void AppDataMonitor::ReportLargeFilesEvent(const std::string &bundleName,
    int32_t userId, int32_t appIndex, const std::string &largestItems)
{
    APP_LOGI_NOFUNC("ScanSystemAppSize reporting large files: bundle=%{public}s, "
        "userId=%{public}d, appIndex=%{public}d", bundleName.c_str(), userId, appIndex);
    // Fast path: installd always emits valid compact JSON. If it already fits the HiSysEvent STRING
    // ceiling, send it verbatim and skip parse/sort/re-dump entirely; only oversized payloads pay
    // for truncation. Sanitization stays in TruncateLargeFilesJson for the over-limit branch and
    // direct callers (tests/fuzzer).
    if (largestItems.size() < MAX_LARGE_FILES_LENGTH) {
        EventReport::SendLargeFilesMonitorEvent(bundleName, userId, appIndex, largestItems);
        return;
    }
    std::string payload;
    TruncateLargeFilesJson(largestItems, payload);
    EventReport::SendLargeFilesMonitorEvent(bundleName, userId, appIndex, payload);
}

void AppDataMonitor::TruncateLargeFilesJson(const std::string &input, std::string &output)
{
    constexpr const char *EMPTY_ITEMS = R"({"items":[]})";
    // Exceptions are disabled in this target, so use nlohmann's no-throw parse (allow_exceptions =
    // false): invalid/empty input yields a discarded value instead of throwing. This is the same
    // pattern used elsewhere in the service (e.g. preinstall_data_storage_rdb.cpp).
    nlohmann::json parsed = nlohmann::json::parse(input, nullptr, false, true);
    if (parsed.is_discarded() || !parsed.is_object() ||
        !parsed.contains("items") || !parsed["items"].is_array()) {
        APP_LOGW_NOFUNC("ScanSystemAppSize largestItems is empty/not {\"items\":[...]}, fallback to empty");
        output = EMPTY_ITEMS;
        return;
    }

    nlohmann::json items = parsed["items"];
    // GetTopNLargestItemsInAppDataDir already returns items size-descending (see
    // GetLargestFilesRecursive final sort); re-sort defensively so trimming the tail always drops
    // the smallest entries regardless of any future change to input ordering.
    auto sizeOf = [](const nlohmann::json &item) -> uint64_t {
        // Read size only when it is an unsigned integer (the type installd emits). Any other shape
        // (missing/negative/float/out-of-range) is coerced to 0 and sorts last; get<> is never
        // called on a mismatched type, so this never throws/aborts under -fno-exceptions.
        if (item.is_object() && item.contains("size") && item["size"].is_number_unsigned()) {
            return item["size"].get<uint64_t>();
        }
        return 0;
    };
    std::sort(items.begin(), items.end(),
        [&sizeOf](const nlohmann::json &a, const nlohmann::json &b) { return sizeOf(a) > sizeOf(b); });

    nlohmann::json wrapped = nlohmann::json::object();
    wrapped["items"] = items;
    std::string dumped = wrapped.dump();
    // Drop the smallest items from the tail until the serialized payload fits; output is always a
    // complete, parseable object (worst case an empty items array).
    while (dumped.size() >= MAX_LARGE_FILES_LENGTH && !items.empty()) {
        items.erase(items.end() - 1);
        wrapped["items"] = items;
        dumped = wrapped.dump();
    }
    output = dumped;
}

} // namespace AppExecFwk
} // namespace OHOS
