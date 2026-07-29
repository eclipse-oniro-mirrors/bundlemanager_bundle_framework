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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_APP_DATA_MONITOR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_APP_DATA_MONITOR_H

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {

class BundleDataMgr;

class AppDataMonitor : public DelayedSingleton<AppDataMonitor>,
    public std::enable_shared_from_this<AppDataMonitor> {
public:
    AppDataMonitor();
    ~AppDataMonitor() override = default;

    void StartScan(int32_t userId);
    void StopScan(const std::string &reason);
    bool IsScanning() const;

private:
    bool IsInCooldown() const;
    bool GetAndSortAppDataSize(int32_t userId,
        const std::shared_ptr<BundleDataMgr> &dataMgr,
        const std::vector<std::string> &bundleNames,
        std::vector<std::pair<std::string, int64_t>> &sortedApps);
    void ScanLargeApps(int32_t userId,
        const std::vector<std::pair<std::string, int64_t>> &sortedApps);
    void ReportLargeFilesEvent(const std::string &bundleName,
        int32_t userId, int32_t appIndex, const std::string &largestItems);
    // Guarantee the reported LARGE_FILES payload is always valid JSON and never exceeds
    // MAX_LARGE_FILES_LENGTH, so the event can never be truncated by the framework into a
    // half, unparseable string. Items are kept largest-first (GetTopNLargestItemsInAppDataDir
    // already returns size-descending); when trimming is needed the smallest tail is dropped.
    static void TruncateLargeFilesJson(const std::string &input, std::string &output);

    std::atomic<bool> isScanning_{false};
    std::atomic<bool> stopRequested_{false};
    std::chrono::steady_clock::time_point lastScanTime_;
    // Count of events actually reported in the current scan (incremented per successful base-app
    // report). Reset at ScanLargeApps entry.
    int32_t reportedCountInScan_ = 0;

    static constexpr int64_t LARGE_APP_THRESHOLD = 1024LL * 1024 * 1024; // 1GB
    // One scan fires at most every 72h (idle-triggered). Combined with MAX_REPORT_COUNT_PER_SCAN
    // this keeps daily reported events of BUNDLE_LARGE_FILES_MONITOR_EVENT within the framework
    // per-event-per-day quota.
    static constexpr int64_t COOLDOWN_SECONDS = 72 * 60 * 60; // 72h
    // Hard cap on reported events per single scan (counted by event). Because a scan runs at most
    // once per COOLDOWN_SECONDS, this also bounds daily output and avoids the framework silently
    // dropping everything beyond its per-event-per-day quota.
    static constexpr int32_t MAX_REPORT_COUNT_PER_SCAN = 20;
    static constexpr int32_t BUNDLE_DATA_SIZE_INDEX = 1;
    static constexpr int32_t GET_TOP_N_TIMEOUT = 30; // 30 seconds
    // Safety ceiling for a single LARGE_FILES payload (HiSysEvent STRING field). The cap is
    // applied to the items JSON value reported in one event; output is always <= this and valid.
    static constexpr size_t MAX_LARGE_FILES_LENGTH = 380 * 1024; // 380K
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_APP_DATA_MONITOR_H
