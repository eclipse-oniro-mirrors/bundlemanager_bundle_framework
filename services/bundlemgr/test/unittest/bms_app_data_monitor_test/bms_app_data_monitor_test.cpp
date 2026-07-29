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

#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

// private access is only needed for AppDataMonitor internals (flags + helpers);
// every other header is included normally so their encapsulation is untouched.
#define private public
#include "app_data_monitor/app_data_monitor.h"
#undef private

#include "bundle_constants.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_service_constants.h"
#include "inner_bundle_info.h"
#include "inner_bundle_user_info.h"
#include "nlohmann/json.hpp"
#include "parameters.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr int32_t TEST_USER_ID = 100;
// Keep in sync with AppDataMonitor::LARGE_APP_THRESHOLD (1GB); duplicated here because the
// private constant cannot be referenced without coupling the assertion to a magic number.
constexpr int64_t ONE_GB = 1024LL * 1024 * 1024;
const std::string SYSTEM_APP_BUNDLE = "com.test.app_data_monitor.system";
} // namespace

class BmsAppDataMonitorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsAppDataMonitorTest::SetUpTestCase()
{}

void BmsAppDataMonitorTest::TearDownTestCase()
{}

void BmsAppDataMonitorTest::SetUp()
{
    // AppDataMonitor is a DelayedSingleton, state persists across cases; reset it each time.
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);
    monitor->isScanning_.store(false);
    monitor->stopRequested_.store(false);
    monitor->lastScanTime_ = std::chrono::steady_clock::time_point{};
    monitor->reportedCountInScan_ = 0;
    OHOS::system::SetParameter(ServiceConstants::SCAN_APP_DATA_TEST_PARAM, "false");
}

void BmsAppDataMonitorTest::TearDown()
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    if (monitor != nullptr) {
        monitor->isScanning_.store(false);
        monitor->stopRequested_.store(false);
        monitor->lastScanTime_ = std::chrono::steady_clock::time_point{};
        monitor->reportedCountInScan_ = 0;
    }
    OHOS::system::SetParameter(ServiceConstants::SCAN_APP_DATA_TEST_PARAM, "false");
    // Injection tests may swap in a real dataMgr; always restore the service default (nullptr)
    // so every other case still observes the dataMgr-null path it expects.
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    if (service != nullptr) {
        service->RegisterDataMgr(nullptr);
    }
}

// Build a fresh, lightweight BundleDataMgr (no DB restore) for direct private-method calls.
static std::shared_ptr<BundleDataMgr> MakeFreshDataMgr()
{
    return std::make_shared<BundleDataMgr>();
}

// Build a BundleDataMgr that exposes exactly one system app for TEST_USER_ID, so that
// GetSystemAppNames() returns non-empty while BatchGetBundleStats() still fails (no installd
// proxy in the test environment) — driving StartScan into the GetAndSort-failure branch.
static std::shared_ptr<BundleDataMgr> MakeDataMgrWithSystemApp()
{
    auto dataMgr = MakeFreshDataMgr();
    InnerBundleInfo bundleInfo;
    bundleInfo.SetAppType(Constants::AppType::SYSTEM_APP);
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    bundleInfo.AddInnerBundleUserInfo(userInfo);
    // checkStatus=false skips the install-state guard and just emplaces into bundleInfos_.
    dataMgr->AddInnerBundleInfo(SYSTEM_APP_BUNDLE, bundleInfo, false);
    return dataMgr;
}

/**
 * @tc.number: AppDataMonitor_IsScanning_0100
 * @tc.name: IsScanning reflects isScanning_ flag
 * @tc.desc: 1. default isScanning_ is false
 *           2. after setting isScanning_ true IsScanning returns true
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_IsScanning_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    EXPECT_FALSE(monitor->IsScanning());
    monitor->isScanning_.store(true);
    EXPECT_TRUE(monitor->IsScanning());
    monitor->isScanning_.store(false);
    EXPECT_FALSE(monitor->IsScanning());
}

/**
 * @tc.number: AppDataMonitor_StopScan_0100
 * @tc.name: StopScan sets stopRequested_ flag
 * @tc.desc: 1. stopRequested_ is false initially
 *           2. StopScan sets stopRequested_ to true
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_StopScan_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    EXPECT_FALSE(monitor->stopRequested_.load());
    monitor->StopScan("AppDataMonitor_StopScan_0100");
    EXPECT_TRUE(monitor->stopRequested_.load());
}

/**
 * @tc.number: AppDataMonitor_StopScan_0200
 * @tc.name: StopScan handles long reason string
 * @tc.desc: 1. feed a very long reason string
 *           2. should not crash and still set stopRequested_
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_StopScan_0200, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    monitor->StopScan(std::string(2048, 'x'));
    EXPECT_TRUE(monitor->stopRequested_.load());
}

/**
 * @tc.number: AppDataMonitor_IsInCooldown_0100
 * @tc.name: IsInCooldown when lastScanTime_ never set
 * @tc.desc: 1. lastScanTime_ is default epoch
 *           2. IsInCooldown should return false
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_IsInCooldown_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    monitor->lastScanTime_ = std::chrono::steady_clock::time_point{};
    EXPECT_FALSE(monitor->IsInCooldown());
}

/**
 * @tc.number: AppDataMonitor_IsInCooldown_0200
 * @tc.name: IsInCooldown right after a scan
 * @tc.desc: 1. lastScanTime_ set to now
 *           2. within 72h cooldown, IsInCooldown should return true
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_IsInCooldown_0200, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    monitor->lastScanTime_ = std::chrono::steady_clock::now();
    EXPECT_TRUE(monitor->IsInCooldown());
}

/**
 * @tc.number: AppDataMonitor_IsInCooldown_0300
 * @tc.name: IsInCooldown after cooldown expires
 * @tc.desc: 1. lastScanTime_ set to 73h ago
 *           2. cooldown (72h) expired, IsInCooldown should return false
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_IsInCooldown_0300, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    monitor->lastScanTime_ = std::chrono::steady_clock::now() - std::chrono::hours(73);
    EXPECT_FALSE(monitor->IsInCooldown());
}

/**
 * @tc.number: AppDataMonitor_StartScan_AlreadyScanning_0100
 * @tc.name: StartScan is a no-op when already scanning
 * @tc.desc: 1. isScanning_ already true
 *           2. StartScan returns immediately, isScanning_ stays true and lastScanTime_ untouched
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_StartScan_AlreadyScanning_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    monitor->isScanning_.store(true);
    auto before = monitor->lastScanTime_;
    monitor->StartScan(TEST_USER_ID);
    EXPECT_TRUE(monitor->isScanning_.load());
    EXPECT_EQ(monitor->lastScanTime_, before);
    monitor->isScanning_.store(false);
}

/**
 * @tc.number: AppDataMonitor_StartScan_CooldownSkip_0100
 * @tc.name: StartScan skips when in cooldown (non-test mode)
 * @tc.desc: 1. test mode off, lastScanTime_ set to now (in cooldown)
 *           2. StartScan returns at cooldown check, lastScanTime_ not updated, still in cooldown
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_StartScan_CooldownSkip_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    OHOS::system::SetParameter(ServiceConstants::SCAN_APP_DATA_TEST_PARAM, "false");
    monitor->lastScanTime_ = std::chrono::steady_clock::now();

    monitor->StartScan(TEST_USER_ID);

    // cooldown path returns before lastScanTime_ is touched, so still in cooldown
    EXPECT_TRUE(monitor->IsInCooldown());
    // the scan guard always resets isScanning_ on scope exit
    EXPECT_FALSE(monitor->isScanning_.load());
}

/**
 * @tc.number: AppDataMonitor_StartScan_StopRequestedAbort_0100
 * @tc.name: StartScan aborts when stop requested before start
 * @tc.desc: 1. test mode on (bypass cooldown), stopRequested_ true
 *           2. StartScan aborts before fetching dataMgr, lastScanTime_ stays epoch
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_StartScan_StopRequestedAbort_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    OHOS::system::SetParameter(ServiceConstants::SCAN_APP_DATA_TEST_PARAM, "true");
    monitor->stopRequested_.store(true);
    monitor->lastScanTime_ = std::chrono::steady_clock::time_point{};

    monitor->StartScan(TEST_USER_ID);

    // aborted before dataMgr path, lastScanTime_ not set
    EXPECT_EQ(monitor->lastScanTime_, std::chrono::steady_clock::time_point{});
    EXPECT_FALSE(monitor->isScanning_.load());
}

/**
 * @tc.number: AppDataMonitor_StartScan_TestModeBypass_0100
 * @tc.name: StartScan bypasses cooldown in test mode
 * @tc.desc: 1. test mode on, lastScanTime_ in cooldown, stopRequested_ false
 *           2. bypasses cooldown and proceeds; lastScanTime_ gets updated to ~now
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_StartScan_TestModeBypass_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    OHOS::system::SetParameter(ServiceConstants::SCAN_APP_DATA_TEST_PARAM, "true");
    monitor->stopRequested_.store(false);
    monitor->lastScanTime_ = std::chrono::steady_clock::now() - std::chrono::hours(1); // would be cooldown

    monitor->StartScan(TEST_USER_ID);

    EXPECT_FALSE(monitor->isScanning_.load());
    // bypassed cooldown and reached dataMgr path (null dataMgr / empty systemApps in test env),
    // both of which stamp lastScanTime_ to now
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - monitor->lastScanTime_).count();
    EXPECT_LE(elapsed, 30);
}

/**
 * @tc.number: AppDataMonitor_StartScan_NormalProceed_0100
 * @tc.name: StartScan proceeds when cooldown expired (non-test mode)
 * @tc.desc: 1. test mode off, cooldown expired (lastScanTime_ 73h ago)
 *           2. proceeds past cooldown; lastScanTime_ updated to ~now
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_StartScan_NormalProceed_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    OHOS::system::SetParameter(ServiceConstants::SCAN_APP_DATA_TEST_PARAM, "false");
    monitor->stopRequested_.store(false);
    monitor->lastScanTime_ = std::chrono::steady_clock::now() - std::chrono::hours(73); // cooldown expired

    monitor->StartScan(TEST_USER_ID);

    EXPECT_FALSE(monitor->isScanning_.load());
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - monitor->lastScanTime_).count();
    EXPECT_LE(elapsed, 30);
}

/**
 * @tc.number: AppDataMonitor_StartScan_FuzzedUserId_0100
 * @tc.name: StartScan does not crash with arbitrary userId
 * @tc.desc: 1. call StartScan with various userIds including edge values
 *           2. should not crash, isScanning_ reset after each call
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_StartScan_FuzzedUserId_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    OHOS::system::SetParameter(ServiceConstants::SCAN_APP_DATA_TEST_PARAM, "true");
    const std::vector<int32_t> userIds = {0, -1, 100, 101, 10000, 2147483647, -2147483648};
    for (int32_t userId : userIds) {
        monitor->StartScan(userId);
        // StartScan is synchronous: isScanning_ is already reset on return, no wait needed.
        EXPECT_FALSE(monitor->isScanning_.load());
    }
}

/**
 * @tc.number: AppDataMonitor_StartScan_StopDuringScan_0100
 * @tc.name: StopScan after StartScan sets stopRequested_
 * @tc.desc: 1. StartScan is synchronous and already returned before StopScan is called, so this does
 *              NOT exercise mid-scan interruption (that would need test-mode delay injection)
 *           2. verifies StopScan sets stopRequested_ and isScanning_ is false after StartScan returns
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_StartScan_StopDuringScan_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    OHOS::system::SetParameter(ServiceConstants::SCAN_APP_DATA_TEST_PARAM, "true");
    // StartScan runs synchronously and returns here (dataMgr null in test env); isScanning_ already false.
    monitor->StartScan(TEST_USER_ID);
    monitor->StopScan("AppDataMonitor_StartScan_StopDuringScan_0100");

    EXPECT_TRUE(monitor->stopRequested_.load());
    EXPECT_FALSE(monitor->isScanning_.load());
}

/**
 * @tc.number: AppDataMonitor_StartScan_EmptySystemApps_0100
 * @tc.name: StartScan with an injected dataMgr that has no system apps
 * @tc.desc: 1. inject a real (empty) BundleDataMgr, test mode on to bypass cooldown
 *           2. GetSystemAppNames returns empty -> StartScan stamps lastScanTime_ to now and returns
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_StartScan_EmptySystemApps_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    ASSERT_NE(service, nullptr);

    auto savedDataMgr = service->GetDataMgr();
    service->RegisterDataMgr(MakeFreshDataMgr());
    OHOS::system::SetParameter(ServiceConstants::SCAN_APP_DATA_TEST_PARAM, "true");
    monitor->stopRequested_.store(false);
    monitor->lastScanTime_ = std::chrono::steady_clock::time_point{};

    monitor->StartScan(TEST_USER_ID);

    // empty system-apps branch updates lastScanTime_ to ~now
    EXPECT_FALSE(monitor->isScanning_.load());
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - monitor->lastScanTime_).count();
    EXPECT_LE(elapsed, 30);

    service->RegisterDataMgr(savedDataMgr);
}

/**
 * @tc.number: AppDataMonitor_StartScan_GetAndSortFail_0100
 * @tc.name: StartScan reaches GetAndSort then aborts when stats fetch fails
 * @tc.desc: 1. inject a dataMgr that exposes one system app but whose BatchGetBundleStats fails
 *              (no installd proxy), test mode on
 *           2. systemApps is non-empty so StartScan calls GetAndSortAppDataSize, which returns false;
 *              lastScanTime_ is stamped to ~now and the scan returns
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_StartScan_GetAndSortFail_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    ASSERT_NE(service, nullptr);

    auto savedDataMgr = service->GetDataMgr();
    service->RegisterDataMgr(MakeDataMgrWithSystemApp());
    OHOS::system::SetParameter(ServiceConstants::SCAN_APP_DATA_TEST_PARAM, "true");
    monitor->stopRequested_.store(false);
    monitor->lastScanTime_ = std::chrono::steady_clock::time_point{};

    monitor->StartScan(TEST_USER_ID);

    // GetAndSort-failure branch stamps lastScanTime_ to ~now
    EXPECT_FALSE(monitor->isScanning_.load());
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - monitor->lastScanTime_).count();
    EXPECT_LE(elapsed, 30);

    service->RegisterDataMgr(savedDataMgr);
}

/**
 * @tc.number: AppDataMonitor_GetAndSortAppDataSize_0100
 * @tc.name: GetAndSortAppDataSize returns false when stats fetch fails
 * @tc.desc: 1. a fresh dataMgr has no such user; BatchGetBundleStats returns a non-OK error
 *           2. GetAndSortAppDataSize returns false and leaves sortedApps empty
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_GetAndSortAppDataSize_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);
    auto dataMgr = MakeFreshDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<std::string> bundleNames = {"com.test.a", "com.test.b"};
    std::vector<std::pair<std::string, int64_t>> sortedApps;
    bool ret = monitor->GetAndSortAppDataSize(TEST_USER_ID, dataMgr, bundleNames, sortedApps);

    EXPECT_FALSE(ret);
    EXPECT_TRUE(sortedApps.empty());
}

/**
 * @tc.number: AppDataMonitor_ScanLargeApps_Empty_0100
 * @tc.name: ScanLargeApps is a no-op with an empty sorted list
 * @tc.desc: 1. sortedApps is empty, the loop body never runs
 *           2. ScanLargeApps must not touch the lifecycle flags owned by StartScan
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_ScanLargeApps_Empty_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);
    auto dataMgr = MakeFreshDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<std::pair<std::string, int64_t>> sortedApps;
    monitor->stopRequested_.store(false);
    monitor->ScanLargeApps(TEST_USER_ID, sortedApps);

    // ScanLargeApps is a lifecycle-agnostic sub-routine: it must neither start a scan
    // (isScanning_) nor clear the stop flag (stopRequested_) — those belong to StartScan.
    EXPECT_FALSE(monitor->isScanning_.load());
    EXPECT_FALSE(monitor->stopRequested_.load());
}

/**
 * @tc.number: AppDataMonitor_ScanLargeApps_BelowThreshold_0100
 * @tc.name: ScanLargeApps stops at the first sub-1GB app
 * @tc.desc: 1. a single app below the 1GB threshold
 *           2. the descending-sorted entry triggers the threshold early-return
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_ScanLargeApps_BelowThreshold_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);
    auto dataMgr = MakeFreshDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<std::pair<std::string, int64_t>> sortedApps = {{SYSTEM_APP_BUNDLE, 0}};
    monitor->stopRequested_.store(false);
    monitor->ScanLargeApps(TEST_USER_ID, sortedApps);

    EXPECT_FALSE(monitor->isScanning_.load());
    EXPECT_FALSE(monitor->stopRequested_.load());
}

/**
 * @tc.number: AppDataMonitor_ScanLargeApps_AboveThreshold_0100
 * @tc.name: ScanLargeApps scans a large app and tolerates installd failure
 * @tc.desc: 1. a single app at/above the 1GB threshold
 *           2. installd GetTopNLargest fails (no proxy) -> failure is skipped, scan completes
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_ScanLargeApps_AboveThreshold_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);
    auto dataMgr = MakeFreshDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<std::pair<std::string, int64_t>> sortedApps = {{SYSTEM_APP_BUNDLE, ONE_GB}};
    monitor->stopRequested_.store(false);
    monitor->ScanLargeApps(TEST_USER_ID, sortedApps);

    EXPECT_FALSE(monitor->isScanning_.load());
    EXPECT_FALSE(monitor->stopRequested_.load());
}

/**
 * @tc.number: AppDataMonitor_ScanLargeApps_MixedSizes_0100
 * @tc.name: ScanLargeApps scans a large app then stops at a smaller one
 * @tc.desc: 1. sorted list with one large app (>=1GB) followed by a small one (<1GB)
 *           2. processes the large app, then the small entry triggers the threshold early-return
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_ScanLargeApps_MixedSizes_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);
    auto dataMgr = MakeFreshDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<std::pair<std::string, int64_t>> sortedApps = {
        {SYSTEM_APP_BUNDLE, ONE_GB * 2},
        {"com.test.small", 0},
    };
    monitor->stopRequested_.store(false);
    monitor->ScanLargeApps(TEST_USER_ID, sortedApps);

    EXPECT_FALSE(monitor->isScanning_.load());
    EXPECT_FALSE(monitor->stopRequested_.load());
}

/**
 * @tc.number: AppDataMonitor_ScanLargeApps_OuterStop_0100
 * @tc.name: ScanLargeApps aborts at the outer loop when stop is requested
 * @tc.desc: 1. stopRequested_ set true before the call, with a large app present
 *           2. the outer-loop stop guard fires before any app is processed; stop flag preserved
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_ScanLargeApps_OuterStop_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);
    auto dataMgr = MakeFreshDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<std::pair<std::string, int64_t>> sortedApps = {{SYSTEM_APP_BUNDLE, ONE_GB}};
    monitor->stopRequested_.store(true);
    monitor->ScanLargeApps(TEST_USER_ID, sortedApps);

    // outer guard returns early; ScanLargeApps must NOT clear the caller's stop flag
    EXPECT_TRUE(monitor->stopRequested_.load());
    EXPECT_FALSE(monitor->isScanning_.load());
}

/**
 * @tc.number: AppDataMonitor_ReportLargeFilesEvent_0100
 * @tc.name: ReportLargeFilesEvent forwards to EventReport without throwing
 * @tc.desc: 1. invoke the private reporter directly with sample args
 *           2. event dispatch is a hisysevent no-op in the test build, so the only observable
 *              contract is that the reporter does not throw
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_ReportLargeFilesEvent_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    EXPECT_NO_THROW(
        monitor->ReportLargeFilesEvent(SYSTEM_APP_BUNDLE, TEST_USER_ID, 0, "[{\"path\":\"/data/a\"}]"));
}

/**
 * @tc.number: AppDataMonitor_ReportLargeFilesEvent_0200
 * @tc.name: ReportLargeFilesEvent takes the truncation branch on an oversized payload
 * @tc.desc: 1. build a valid {"items":[...]} larger than MAX_LARGE_FILES_LENGTH
 *           2. ReportLargeFilesEvent must route it through TruncateLargeFilesJson and not throw
 *              (the small-input fast path is covered by _0100; this covers the over-limit branch)
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_ReportLargeFilesEvent_0200, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    constexpr int itemCount = 2000;
    std::string input = R"({"items":[)";
    for (int i = 0; i < itemCount; ++i) {
        input += R"({"path":"/)" + std::string(200, 'x') + R"(","size":)" + std::to_string(itemCount - i) + R"(},)";
    }
    input.pop_back(); // drop trailing comma
    input += R"(]})";
    ASSERT_GT(input.size(), AppDataMonitor::MAX_LARGE_FILES_LENGTH);

    EXPECT_NO_THROW(monitor->ReportLargeFilesEvent(SYSTEM_APP_BUNDLE, TEST_USER_ID, 0, input));
}

// Build an items JSON whose total size exceeds MAX_LARGE_FILES_LENGTH so the truncation path runs.
// Each entry carries a long path (~230B/entry) and a size-descending size value.
static std::string BuildOversizedItemsJson(int count)
{
    const std::string longPath(200, 'x');
    nlohmann::json items = nlohmann::json::array();
    for (int i = 0; i < count; ++i) {
        nlohmann::json item;
        item["path"] = longPath;
        item["size"] = static_cast<uint64_t>((count - i) * 1024LL * 1024LL); // size-descending
        items.push_back(item);
    }
    nlohmann::json wrapped;
    wrapped["items"] = items;
    return wrapped.dump();
}

/**
 * @tc.number: AppDataMonitor_TruncateLargeFilesJson_0100
 * @tc.name: a small valid payload is kept, re-sorted size-descending
 * @tc.desc: 1. a valid {"items":[...]} smaller than the cap
 *           2. output is valid JSON, items preserved, sorted by size desc regardless of input order
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_TruncateLargeFilesJson_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    std::string input = R"({"items":[{"path":"/a","size":50},{"path":"/b","size":100}]})";
    std::string output;
    monitor->TruncateLargeFilesJson(input, output);

    ASSERT_FALSE(output.empty());
    nlohmann::json parsed = nlohmann::json::parse(output);
    ASSERT_TRUE(parsed.is_object());
    ASSERT_TRUE(parsed.contains("items") && parsed["items"].is_array());
    const auto &items = parsed["items"];
    ASSERT_EQ(items.size(), 2u);
    EXPECT_EQ(items[0]["size"].get<uint64_t>(), 100u);
    EXPECT_EQ(items[1]["size"].get<uint64_t>(), 50u);
}

/**
 * @tc.number: AppDataMonitor_TruncateLargeFilesJson_0200
 * @tc.name: an oversized payload is trimmed to valid JSON under MAX_LARGE_FILES_LENGTH
 * @tc.desc: 1. build a payload larger than the 380K cap
 *           2. output < cap, still valid JSON, items non-empty and size-descending
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_TruncateLargeFilesJson_0200, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    std::string input = BuildOversizedItemsJson(2000); // ~460KB > 380KB
    ASSERT_GT(input.size(), AppDataMonitor::MAX_LARGE_FILES_LENGTH);

    std::string output;
    monitor->TruncateLargeFilesJson(input, output);

    EXPECT_LT(output.size(), AppDataMonitor::MAX_LARGE_FILES_LENGTH);
    nlohmann::json parsed = nlohmann::json::parse(output);
    ASSERT_TRUE(parsed.is_object());
    ASSERT_TRUE(parsed.contains("items") && parsed["items"].is_array());
    const auto &items = parsed["items"];
    ASSERT_GT(items.size(), 0u);
    bool sortedDesc = true;
    for (size_t i = 1; i < items.size(); ++i) {
        if (items[i]["size"].get<uint64_t>() > items[i - 1]["size"].get<uint64_t>()) {
            sortedDesc = false;
            break;
        }
    }
    EXPECT_TRUE(sortedDesc);
}

/**
 * @tc.number: AppDataMonitor_TruncateLargeFilesJson_0300
 * @tc.name: malformed JSON falls back to a valid empty-items object
 * @tc.desc: 1. input is not parseable JSON
 *           2. output is a complete {"items":[]} object (never a truncated half-string)
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_TruncateLargeFilesJson_0300, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    std::string output;
    monitor->TruncateLargeFilesJson("not-a-json{", output);
    EXPECT_EQ(output, R"({"items":[]})");
}

/**
 * @tc.number: AppDataMonitor_TruncateLargeFilesJson_0400
 * @tc.name: empty input and a valid-but-wrong-shape input both fall back to valid empty items
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_TruncateLargeFilesJson_0400, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    std::string output;
    monitor->TruncateLargeFilesJson("", output);
    EXPECT_EQ(output, R"({"items":[]})");

    monitor->TruncateLargeFilesJson("[1,2,3]", output); // valid JSON, but not {"items":[...]}
    EXPECT_EQ(output, R"({"items":[]})");
}

/**
 * @tc.number: AppDataMonitor_TruncateLargeFilesJson_0500
 * @tc.name: adversarial sizes (negative/float) never throw and are coerced to sort last
 * @tc.desc: 1. a valid {"items":[...]} carrying a negative and a float size (would make the sort
 *              comparator throw before the try/catch guard)
 *           2. TruncateLargeFilesJson must not throw; output is valid JSON, entries kept and the
 *              well-formed size sorts first while malformed sizes (coerced to 0) sort last
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_TruncateLargeFilesJson_0500, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);

    std::string input =
        R"({"items":[{"path":"/neg","size":-1},{"path":"/flt","size":1.5},{"path":"/ok","size":100}]})";
    std::string output;
    EXPECT_NO_THROW(monitor->TruncateLargeFilesJson(input, output));

    ASSERT_FALSE(output.empty());
    nlohmann::json parsed = nlohmann::json::parse(output);
    ASSERT_TRUE(parsed.is_object());
    ASSERT_TRUE(parsed.contains("items") && parsed["items"].is_array());
    const auto &items = parsed["items"];
    ASSERT_EQ(items.size(), 3u);
    // the only well-formed size (100) must be first; the two malformed sizes (coerced to 0) follow
    EXPECT_EQ(items[0]["path"].get<std::string>(), "/ok");
    std::string tail1 = items[1]["path"].get<std::string>();
    std::string tail2 = items[2]["path"].get<std::string>();
    EXPECT_TRUE((tail1 == "/neg" && tail2 == "/flt") || (tail1 == "/flt" && tail2 == "/neg"));
}

/**
 * @tc.number: AppDataMonitor_ScanLargeApps_ReportCap_0100
 * @tc.name: more large apps than the cap reports exactly MAX_REPORT_COUNT_PER_SCAN
 * @tc.desc: 1. SCAN_APP_DATA_TEST_PARAM on so the installd mock returns a sample payload (reports fire)
 *           2. 25 size-descending large apps; scan stops after the 20th report (count by event)
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_ScanLargeApps_ReportCap_0100, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);
    auto dataMgr = MakeFreshDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    OHOS::system::SetParameter(ServiceConstants::SCAN_APP_DATA_TEST_PARAM, "true");
    monitor->stopRequested_.store(false);
    monitor->reportedCountInScan_ = 0;

    std::vector<std::pair<std::string, int64_t>> sortedApps;
    for (int i = 0; i < 25; ++i) {
        sortedApps.emplace_back("com.test.large" + std::to_string(i), ONE_GB * (25 - i)); // desc
    }
    monitor->ScanLargeApps(TEST_USER_ID, sortedApps);

    EXPECT_EQ(monitor->reportedCountInScan_, AppDataMonitor::MAX_REPORT_COUNT_PER_SCAN);
    EXPECT_FALSE(monitor->isScanning_.load());
    EXPECT_FALSE(monitor->stopRequested_.load());

    OHOS::system::SetParameter(ServiceConstants::SCAN_APP_DATA_TEST_PARAM, "false");
}

/**
 * @tc.number: AppDataMonitor_ScanLargeApps_ReportCap_0200
 * @tc.name: fewer large apps than the cap reports all of them
 * @tc.desc: 1. SCAN_APP_DATA_TEST_PARAM on
 *           2. 5 large apps, below the cap; all reported, scan completes normally
 */
HWTEST_F(BmsAppDataMonitorTest, AppDataMonitor_ScanLargeApps_ReportCap_0200, Function | SmallTest | Level0)
{
    auto monitor = DelayedSingleton<AppDataMonitor>::GetInstance();
    ASSERT_NE(monitor, nullptr);
    auto dataMgr = MakeFreshDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    OHOS::system::SetParameter(ServiceConstants::SCAN_APP_DATA_TEST_PARAM, "true");
    monitor->stopRequested_.store(false);
    monitor->reportedCountInScan_ = 0;

    std::vector<std::pair<std::string, int64_t>> sortedApps;
    for (int i = 0; i < 5; ++i) {
        sortedApps.emplace_back("com.test.few" + std::to_string(i), ONE_GB * (5 - i)); // desc
    }
    monitor->ScanLargeApps(TEST_USER_ID, sortedApps);

    EXPECT_EQ(monitor->reportedCountInScan_, 5);
    EXPECT_FALSE(monitor->isScanning_.load());
    EXPECT_FALSE(monitor->stopRequested_.load());

    OHOS::system::SetParameter(ServiceConstants::SCAN_APP_DATA_TEST_PARAM, "false");
}
} // namespace OHOS
