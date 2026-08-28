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

// Unit tests for the requirement-2 runtime visibility switch (FEAT-20260803-001, TASK-6) and the
// switch <-> install/update/uninstall mutual exclusion (TASK-7, L-1 / L-9):
// BundleDataMgr::FilterBundleListByDeviceModeDistributionPolicies (including the dualModeSwitchMutex_
// busy/fast-fail semantics — r13: both sides reject immediately, no waiting), the synchronous
// direct-connection IPC entries in BundleInstallerHost (0991~0993: the host-entry guard over
// BundleDataMgr::TryLockForBundleOperation), and the reboot-classification policy branch
// (ClassifyDualModeAppsNoLock).
// Follows the bms_dual_mode_install_test paradigm:
// #define private public exposes the DualModeHelper mode cache (cachedIspcmode_/cachedMainmode_)
// and the BundleDataMgr maps. Mode is driven through the mocked parameter map (SeedModeParams:
// persist.bms.test_dual_mode switches DualModeHelper to the persist.bms.* test keys, and the
// cache is refreshed via the production UpdateModeCache path — the switch itself no longer
// refreshes the cache, so seeding is the only refresh); the device-gate cases keep
// writing the cache directly via SetDualModeCache. No real system parameter is touched.
// Persistence goes through the mocked BmsParam (test/mock/src/bms_param.cpp, swapped
// in by this suite's BUILD.gn): a static in-memory map that lives for the whole test binary, so
// SetUp deletes the policy key first and cases cannot leak into each other.
// Input semantics (policy array, not a bitwise-or flag): elements are DeviceModeDistributionPolicy
// enum values (0~8); all different-package policies {4,6,8} must be included; filterable policies
// are {1,2,3,5,7}; UNSPECIFIED(0) is always visible.
// The DualModeHelper public policy utilities (IsValidPolicySet / ParsePersistedPolicies /
// PoliciesToCsv — the single validation/serialization source shared by the runtime switch input
// and the persisted-value parse) are covered directly as pure statics (1000-series cases).

#define private public
#define protected public
#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "appexecfwk_errors.h"
#include "application_info.h"
#include "bms_param.h"
#include "bundle_data_mgr.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_host_impl.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_service.h"
#include "bundle_service_constants.h"
#include "dual_mode_helper.h"
#include "inner_bundle_info.h"
#include "parameters.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
namespace {

constexpr int32_t TEST_USERID = 100;
const std::string BUNDLE_NAME_MAIN = "com.example.mainonly";
const std::string BUNDLE_NAME_SUB = "com.example.subonly";
const std::string BUNDLE_NAME_DIFF = "com.example.diffpkg";
// Single-variant different-package app (only the primary installed, no clone counterpart).
const std::string BUNDLE_NAME_DIFFONLY = "com.example.diffonly";
const std::string BUNDLE_NAME_GENERIC = "com.example.generic";
// Dual-mode clone install key: "+clone-10000+" + original bundle name.
const std::string PREFIXED_NAME_DIFF = std::string(ServiceConstants::CLONE_PREFIX) +
    std::to_string(ServiceConstants::DUAL_MODE_CLONE_APP_INDEX) + "+" + BUNDLE_NAME_DIFF;

// Dual-mode system parameter keys for the mocked parameter map (same values as the
// anonymous-namespace constants in dual_mode_helper.cpp): with persist.bms.test_dual_mode=true,
// DualModeHelper reads ispcmode/mainmode from the persist.bms.* test keys instead of the
// production sceneboard params, so mode behavior is driven without dual-mode hardware.
constexpr const char *TEST_DUAL_MODE_PARAM = "persist.bms.test_dual_mode";
constexpr const char *TEST_ISPCMODE_PARAM = "persist.bms.ispcmode";
constexpr const char *TEST_MAINMODE_PARAM = "persist.bms.mainmode";

// Valid policy set examples (must contain 4/6/8):
// all visible: {1,2,3,4,5,6,7,8}; mandatory-only (hide all filterable policies 1/2/3/5/7): {4,6,8};
// main-mode set (hide SUB_ONLY=2): {1,3,4,5,6,7,8}.
const std::vector<int32_t> POLICIES_VALID_ALL = {1, 2, 3, 4, 5, 6, 7, 8};
const std::vector<int32_t> POLICIES_VALID_MINIMAL = {4, 6, 8};
const std::vector<int32_t> POLICIES_VALID_MAIN_SET = {1, 3, 4, 5, 6, 7, 8};  // persisted CSV "1,3,4,5,6,7,8"
// Invalid examples: missing different-package policies / out-of-range value / empty array.
const std::vector<int32_t> POLICIES_INVALID_MISSING_DIFF = {1, 2, 3, 5, 7};  // missing 4/6/8
const std::vector<int32_t> POLICIES_INVALID_OUT_OF_RANGE = {4, 6, 8, 9};    // 9 is illegal
const std::vector<int32_t> POLICIES_INVALID_EMPTY = {};

}  // namespace

// Write the int mode cache directly (no system parameter). Only for the device-gate cases
// (non-dual-mode device): they are rejected before the switch's own param refresh, so no
// parameter state is involved. ispcmode: 0=tablet, 1=2in1 (current mode); mainmode: 0=main
// tablet, 1=main 2in1; -1=invalid. A dual-mode device requires BOTH values valid.
static void SetDualModeCache(int32_t ispcmode, int32_t mainmode)
{
    DualModeHelper::cachedIspcmode_ = ispcmode;
    DualModeHelper::cachedMainmode_ = mainmode;
}

// Seed the mode params in the mocked parameter map and refresh the cache through the
// production path (UpdateModeCache) — the switch itself does not refresh the cache, so this
// seeding is what keeps the cache and params aligned for the switch cases
// (cf. bms_data_mgr_test.cpp SetBundleFirstLaunch_0003).
static void SeedModeParams(int32_t ispcmode, int32_t mainmode)
{
    OHOS::system::SetParameter(TEST_DUAL_MODE_PARAM, "true");
    OHOS::system::SetParameter(TEST_ISPCMODE_PARAM, std::to_string(ispcmode));
    OHOS::system::SetParameter(TEST_MAINMODE_PARAM, std::to_string(mainmode));
    DualModeHelper::UpdateModeCache();
}

// Primary mode: ispcmode == mainmode (both tablet) -> IsDualModeDevice() true, IsSecondaryMode() false.
static void EnablePrimaryMode()
{
    SeedModeParams(ServiceConstants::DUAL_MODE_VALUE_TABLET, ServiceConstants::DUAL_MODE_VALUE_TABLET);
}

// Secondary mode: ispcmode=2in1, mainmode=tablet -> IsDualModeDevice() true, IsSecondaryMode() true.
static void EnableSecondaryMode()
{
    SeedModeParams(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
}

// int vector -> policy set (std::set dedups and orders ascending, as the IPC layer's set does).
static std::set<DeviceModeDistributionPolicy> ToPolicySet(const std::vector<int32_t> &values)
{
    std::set<DeviceModeDistributionPolicy> policies;
    for (int32_t value : values) {
        policies.insert(static_cast<DeviceModeDistributionPolicy>(value));
    }
    return policies;
}

// Build an InnerBundleInfo carrying a distribution policy (and the dual-mode clone flag when
// isClone), with bundleName set so map contents stay identifiable in failure dumps.
static InnerBundleInfo MakePolicyInfo(const std::string &name,
    DeviceModeDistributionPolicy policy, bool isClone = false)
{
    InnerBundleInfo info;
    ApplicationInfo appInfo;
    appInfo.bundleName = name;
    info.SetBaseApplicationInfo(appInfo);
    info.SetDeviceModeDistributionPolicy(policy);
    if (isClone) {
        info.SetDualModeCloneApp(true);
    }
    return info;
}

// Post-switch placement: visible = in bundleInfos_ (queryable), hidden = in tempBundleInfos_.
static bool IsVisible(const BundleDataMgr &dataMgr, const std::string &name)
{
    return dataMgr.bundleInfos_.count(name) > 0;
}

static bool IsHidden(const BundleDataMgr &dataMgr, const std::string &name)
{
    return dataMgr.tempBundleInfos_.count(name) > 0;
}

class BmsDualModeSwitchTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override;
    void TearDown() override {}

    // Run one switch call from an int policy vector (mirrors the IPC set semantics).
    ErrCode Switch(const std::vector<int32_t> &policies)
    {
        return dataMgr_->FilterBundleListByDeviceModeDistributionPolicies(ToPolicySet(policies));
    }

    std::shared_ptr<BundleMgrService> service_;
    std::shared_ptr<BundleDataMgr> dataMgr_;
};

void BmsDualModeSwitchTest::SetUp()
{
    // Default to a non-dual-mode device (both mode params invalid); cases opt in via
    // EnablePrimaryMode/EnableSecondaryMode. Also clear the seeded mode params from the static
    // mock parameter map so a previous case's seeds cannot leak into this one.
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    OHOS::system::RemoveParameter(TEST_DUAL_MODE_PARAM);
    OHOS::system::RemoveParameter(TEST_ISPCMODE_PARAM);
    OHOS::system::RemoveParameter(TEST_MAINMODE_PARAM);

    // Fresh data manager + mocked BmsParam installed into the global BundleMgrService singleton.
    // The mock's map is static (shared across cases in this binary), so delete the policy key
    // first — a previous case's persistence must not leak into this one.
    service_ = DelayedSingleton<BundleMgrService>::GetInstance();
    service_->bmsParam_ = std::make_shared<BmsParam>();
    ASSERT_NE(service_->bmsParam_, nullptr);
    service_->bmsParam_->DeleteBmsParam(ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY);
    dataMgr_ = std::make_shared<BundleDataMgr>();
    dataMgr_->multiUserIdsSet_.insert(TEST_USERID);
    service_->dataMgr_ = dataMgr_;
}

// Legal policy set -> apps with filterable policies in the set enter bundleInfos_ (accessible)
HWTEST_F(BmsDualModeSwitchTest, FilterBundleListByDeviceModeDistributionPolicies_0100_LegalSetMigrates,
    TestSize.Level1)
{
    // Given: tempBundleInfos_ holds a MAIN_ONLY(1) policy app; policies = POLICIES_VALID_MAIN_SET (contains 1)
    EnablePrimaryMode();
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_MAIN] = MakePolicyInfo(
        BUNDLE_NAME_MAIN, DeviceModeDistributionPolicy::MAIN_ONLY);

    // When: FilterBundleListByDeviceModeDistributionPolicies(policies)
    // Then: returns ERR_OK; the app moves into bundleInfos_ (accessible)
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_MAIN));
    EXPECT_FALSE(IsHidden(*dataMgr_, BUNDLE_NAME_MAIN));
}

// Filterable policy not in the set -> moves into tempBundleInfos_ (inaccessible)
HWTEST_F(BmsDualModeSwitchTest, FilterBundleListByDeviceModeDistributionPolicies_0200_NotInSetMovesToTemp,
    TestSize.Level1)
{
    // Given: bundleInfos_ holds a SUB_ONLY(2) policy app; policies = POLICIES_VALID_MAIN_SET (excludes 2)
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);

    // When/Then: returns ERR_OK; the app moves into tempBundleInfos_ (not queryable)
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_FALSE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
}

// Toggle back (a previously hidden app's policy returns to the set -> accessible again)
HWTEST_F(BmsDualModeSwitchTest, FilterBundleListByDeviceModeDistributionPolicies_0300_ToggleBackRestores,
    TestSize.Level1)
{
    // Given: the app was previously hidden (in temp); switch again with POLICIES_VALID_ALL so its
    //        policy returns to the set
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));

    // When/Then: the app moves back from tempBundleInfos_ into bundleInfos_
    EXPECT_EQ(Switch(POLICIES_VALID_ALL), ERR_OK);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_FALSE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
}

// Different-package policy variant pair: the switch rotates the pair on every call regardless
// of the current device mode — the hidden (temp) variant swaps in, the visible one goes to
// temp; exactly one variant stays visible under the same name
HWTEST_F(BmsDualModeSwitchTest, FilterBundleListByDeviceModeDistributionPolicies_0400_DiffPackagePairRotates,
    TestSize.Level1)
{
    // Given: a different-package policy app (FULL_COMPATIBLE_DIFFERENT_PACKAGE=8) has its primary
    //        variant in bundleInfos_ and its clone variant in tempBundleInfos_ (same-name key);
    //        the mode params say primary — the rotation must not depend on them
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE);
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE, true);

    // When: FilterBundleListByDeviceModeDistributionPolicies(POLICIES_VALID_MINIMAL)
    // Then: the pair rotates — the clone becomes visible, the primary goes to temp
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_TRUE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_FALSE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
}

// The rotation repeats on EVERY call: a second switch rotates the pair back. The caller
// triggers one switch per device-mode flip, so the rotation tracks the mode without this
// code sensing it (no idempotency — an extra call flips the pair again)
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0450_PairRotatesAgainOnNextCall,
    TestSize.Level1)
{
    // Given: the pair with the primary variant visible and the clone hidden in tempBundleInfos_
    //        (mode params only feed the device gate; the rotation itself is mode-free)
    EnableSecondaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE);
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE, true);

    // When: the first switch Then: the clone rotates in (exactly one variant visible)
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_TRUE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_FALSE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());

    // When: the second switch Then: the pair rotates back — the primary is visible again
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
}

// Single different-package variant with NO counterpart follows the per-call rotation
// (2026-08-26 design change: different-package entries rotate once per call regardless of
// side) — a hidden-side single variant rotates into bundleInfos_ on the next switch, and a
// visible-side one rotates out; exactly one move per call, in either mode
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0460_SingleDiffPackageVariantMigratesByPolicy,
    TestSize.Level1)
{
    // Given: primary mode; only the clone variant exists (in tempBundleInfos_, no primary)
    EnablePrimaryMode();
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE, true);

    // When/Then: the hidden-side single variant rotates in alone and becomes visible under
    //            that name (no counterpart needed)
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_FALSE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_TRUE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());

    // Given: secondary mode with only the primary variant on the hidden side (mirror setup)
    EnableSecondaryMode();
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFFONLY] = MakePolicyInfo(
        BUNDLE_NAME_DIFFONLY, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE);

    // When/Then: the primary variant rotates in alone as well — same rule, either variant
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFFONLY));
    EXPECT_FALSE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFFONLY));
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFFONLY].IsDualModeCloneApp());

    // Given: only the primary variant exists, on the VISIBLE side this time (reset DIFFONLY —
    //        the block above left it visible in bundleInfos_)
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFFONLY] = MakePolicyInfo(
        BUNDLE_NAME_DIFFONLY, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE);
    dataMgr_->tempBundleInfos_.erase(BUNDLE_NAME_DIFFONLY);

    // When/Then: the visible-side single variant rotates OUT (exactly one move — it must not
    //            bounce back within the same call), and the next switch rotates it in again
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFFONLY));
    EXPECT_FALSE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFFONLY));
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFFONLY));
    EXPECT_FALSE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFFONLY));
}

// Inconsistent same-name pairing on the hide pass: a filterable bundle entry whose policy left
// the set cannot legitimately have a same-name temp entry — the migration is skipped and BOTH
// entries keep their sides (defensive branch; no variant swap)
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0470_InconsistentPairingKeepsBoth,
    TestSize.Level1)
{
    // Given: a SUB_ONLY(2) app is visible while a same-name entry (stray clone-flagged variant)
    //        already sits in tempBundleInfos_; the set excludes 2
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY, true);

    // When: FilterBundleListByDeviceModeDistributionPolicies(POLICIES_VALID_MAIN_SET)
    // Then: the pairing is inconsistent — no swap, both entries keep their sides
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_SUB].IsDualModeCloneApp());
    EXPECT_TRUE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_SUB].IsDualModeCloneApp());
}

// Show pass with a non-variant bundle occupant: the rotation is uniform policy-driven
// (2026-08-26 design change) — a same-name temp entry whose policy is in the set swaps with
// the occupant regardless of the occupant's policy category, so an anomalous in-set occupant
// is rotated out to tempBundleInfos_ and back on the next call (one switch per mode flip
// tracks the mode; the former no-swap anti-oscillation guard was removed with the design
// change)
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0480_AnyOccupantSwappedByPolicy,
    TestSize.Level1)
{
    // Given: secondary mode; an in-set diff-package clone waits in tempBundleInfos_ while the
    //        same-name bundle slot is occupied by an in-set MAIN_ONLY app (anomalous pairing)
    EnableSecondaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::MAIN_ONLY);
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE, true);

    // When/Then: the clone swaps in (its policy is in the set) and the MAIN_ONLY occupant is
    //            rotated out to tempBundleInfos_
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_TRUE(dataMgr_->bundleInfos_[BUNDLE_NAME_SUB].IsDualModeCloneApp());
    EXPECT_FALSE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_SUB].IsDualModeCloneApp());

    // When: the switch runs again Then: the pair rotates back — the MAIN_ONLY app is visible
    //       again (per-call rotation, no anti-oscillation guard)
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_SUB].IsDualModeCloneApp());
    EXPECT_TRUE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_SUB].IsDualModeCloneApp());
}

// Device mode flipped between switches: the switch itself no longer re-reads the mode params
// (the UpdateModeCache call was removed from the flow), so the mode cache keeps the value from
// the last explicit refresh (boot init / test seeding) — install-time dual-mode handling
// (NeedDualModeHandle) only sees the new mode after that next refresh (known gap, spec L-7).
// The migration body stays mode-free: the pair rotates on every call regardless of the mode,
// and a single-variant different-package app rotates with it — out on one call, back in on the
// next
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0490_ModeFlipCacheStalePairStillRotates,
    TestSize.Level1)
{
    // Given: primary mode; a paired diff-package app (primary visible / clone hidden) plus a
    //        single-variant diff-package app (primary only, visible)
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE);
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE, true);
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFFONLY] = MakePolicyInfo(
        BUNDLE_NAME_DIFFONLY, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE);

    // When: the first switch Then: the pair rotates (the clone becomes visible) — the rotation
    //       is mode-free; the single-variant app rotates out (one move, no bounce-back)
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_FALSE(DualModeHelper::IsSecondaryMode());
    EXPECT_TRUE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_FALSE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFFONLY));

    // When: the mode params flip to secondary (as the mode switcher does) and the switch runs
    //       again — only the params changed; the cache still holds the primary-mode value
    OHOS::system::SetParameter(TEST_ISPCMODE_PARAM,
        std::to_string(ServiceConstants::DUAL_MODE_VALUE_2IN1));

    // Then: the switch does not refresh the mode cache (stale primary value kept — the refresh
    //       call was removed from the flow), while the migration keeps rotating every
    //       diff-package name per call — the pair flips back (primary visible) and the
    //       single-variant app rotates in again
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_FALSE(DualModeHelper::IsSecondaryMode());
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFFONLY));
    EXPECT_FALSE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFFONLY));
}

// UNSPECIFIED(0) apps never migrate in either direction: a visible one stays visible whatever
// the set, and a stray UNSPECIFIED entry in tempBundleInfos_ (anomalous state only — the boot
// classification never hides UNSPECIFIED) stays hidden instead of being rotated in
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0500_UnspecifiedNeverMigrates,
    TestSize.Level1)
{
    // Given: an UNSPECIFIED app is visible; another UNSPECIFIED entry sits in tempBundleInfos_
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_GENERIC] = MakePolicyInfo(
        BUNDLE_NAME_GENERIC, DeviceModeDistributionPolicy::UNSPECIFIED);
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::UNSPECIFIED);

    // When/Then: neither pass touches UNSPECIFIED entries — the visible one keeps its side
    //            (even under the minimal set that hides every filterable policy), the
    //            hidden-side one is not rotated in
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_GENERIC));
    EXPECT_FALSE(IsHidden(*dataMgr_, BUNDLE_NAME_GENERIC));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_FALSE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));

    // And: repeated calls keep both sides stable (no rotation accumulates for UNSPECIFIED)
    EXPECT_EQ(Switch(POLICIES_VALID_ALL), ERR_OK);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_GENERIC));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
}

// All three different-package policy values (4/6/8) rotate per call — not just
// FULL_COMPATIBLE(8) used by the other cases: a UNIVERSAL(4) pair swaps, a
// PARTIAL_COMPATIBLE(6) single variant crosses over, on every call
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0510_AllDiffPackageValuesRotate,
    TestSize.Level1)
{
    // Given: a UNIVERSAL(4) pair (primary visible / clone hidden) plus a PARTIAL(6)
    //        single-variant app on the visible side
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE, true);
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFFONLY] = MakePolicyInfo(
        BUNDLE_NAME_DIFFONLY, DeviceModeDistributionPolicy::PARTIAL_COMPATIBLE_DIFFERENT_PACKAGE);

    // When/Then: the UNIVERSAL pair rotates (clone visible) and the PARTIAL single variant
    //            rotates out — same per-call rotation as FULL_COMPATIBLE(8)
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_TRUE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_FALSE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFFONLY));

    // When/Then: the next call rotates them all again — the pair swaps back and the single
    //            variant crosses back in
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFFONLY));
    EXPECT_FALSE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFFONLY));
}

// One call over a mixed topology — every kind of entry at once, each name moving exactly once:
// filterable excluded -> hidden (idempotent across calls), filterable included and UNSPECIFIED
// -> stay put, different-package pair -> swap, different-package single variant -> rotates out
// and back in on the next call (per-call rotation, no bounce-back within a call)
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0520_MixedTopologiesOneMovePerName,
    TestSize.Level1)
{
    // Given: SUB_ONLY(2, excluded by the main set), MAIN_ONLY(1, included), UNSPECIFIED, a
    //        FULL(8) pair, and a FULL(8) single variant — all visible except the pair's clone
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);
    dataMgr_->bundleInfos_[BUNDLE_NAME_MAIN] = MakePolicyInfo(
        BUNDLE_NAME_MAIN, DeviceModeDistributionPolicy::MAIN_ONLY);
    dataMgr_->bundleInfos_[BUNDLE_NAME_GENERIC] = MakePolicyInfo(
        BUNDLE_NAME_GENERIC, DeviceModeDistributionPolicy::UNSPECIFIED);
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE);
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE, true);
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFFONLY] = MakePolicyInfo(
        BUNDLE_NAME_DIFFONLY, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE);

    // When: the first switch with the same set
    // Then: each of the 6 names appears exactly once across the two maps (3 visible / 3
    //       hidden): SUB hidden, MAIN and UNSPECIFIED stay, the pair swaps (clone visible),
    //       the single variant rotates out
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_EQ(dataMgr_->bundleInfos_.size(), 3u);
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 3u);
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_MAIN));
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_GENERIC));
    EXPECT_TRUE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_FALSE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFFONLY));

    // When: the switch runs again with the SAME set
    // Then: filterable placement is idempotent (SUB stays hidden, MAIN stays visible) while
    //       every different-package name rotates once more (pair swaps back, single variant
    //       crosses back in)
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_EQ(dataMgr_->bundleInfos_.size(), 4u);
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 2u);
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_MAIN));
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_GENERIC));
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFFONLY));
    EXPECT_FALSE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFFONLY));
}

// Success -> policy set is synchronously written to bms_param (normalized ascending CSV)
HWTEST_F(BmsDualModeSwitchTest, FilterBundleListByDeviceModeDistributionPolicies_0600_PersistsPoliciesCsv,
    TestSize.Level1)
{
    // Given/When: FilterBundleListByDeviceModeDistributionPolicies({8,6,4,1,3,5,7}) succeeds (unordered input)
    EnablePrimaryMode();
    EXPECT_EQ(Switch({8, 6, 4, 1, 3, 5, 7}), ERR_OK);

    // Then: GetBmsParam("DualModeDeviceModeDistributionPolicies") returns the normalized CSV "1,3,4,5,6,7,8"
    std::string persisted;
    EXPECT_TRUE(service_->bmsParam_->GetBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, persisted));
    EXPECT_EQ(persisted, "1,3,4,5,6,7,8");
}

// SaveBmsParam failure entry condition -> PERSIST_FAILED (8519945) with memory untouched:
// the null-param branch returns before the migration (migrate-first order). The rollback
// replay itself is pinned by _0750 — the mocked BmsParam's SaveBmsParam never fails for a
// non-empty key, so the real save-failure branch is not reachable in unit tests
HWTEST_F(BmsDualModeSwitchTest, FilterBundleListByDeviceModeDistributionPolicies_0700_PersistFailedRollsBack,
    TestSize.Level1)
{
    // Given: persistence unavailable (service bmsParam_ null); a SUB_ONLY app is visible.
    EnablePrimaryMode();
    service_->bmsParam_ = nullptr;
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);

    // When/Then: returns ERR_APPEXECFWK_DUAL_MODE_PERSIST_FAILED (8519945) before any
    //            migration — bundleInfos_/tempBundleInfos_ remain as before the switch
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_APPEXECFWK_DUAL_MODE_PERSIST_FAILED);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 0u);
}

// Persist-failure rollback replay (2026-08-26 migrate-first order): on SaveBmsParam failure
// the wrapper re-runs the migration body with the previously persisted baseline set. The
// mocked BmsParam never fails a save (_0700 drives only the null-param entry), so this case
// performs the exact two calls the rollback makes — migrate to the new set, then replay the
// baseline — and pins that the result is the pre-switch state: filterable policies re-place
// by set membership and the different-package per-call rotation is an involution (the two
// calls cancel: the pair swaps back, the single variant crosses back)
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0750_RollbackReplayRestoresPreSwitchState,
    TestSize.Level1)
{
    // Given: the persisted baseline is the main set; memory sits in the state that baseline
    //        produces (SUB hidden, MAIN/UNSPECIFIED/single-variant DIFFONLY visible, pair's
    //        primary visible / clone hidden)
    EnablePrimaryMode();
    EXPECT_TRUE(service_->bmsParam_->SaveBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, "1,3,4,5,6,7,8"));
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);
    dataMgr_->bundleInfos_[BUNDLE_NAME_MAIN] = MakePolicyInfo(
        BUNDLE_NAME_MAIN, DeviceModeDistributionPolicy::MAIN_ONLY);
    dataMgr_->bundleInfos_[BUNDLE_NAME_GENERIC] = MakePolicyInfo(
        BUNDLE_NAME_GENERIC, DeviceModeDistributionPolicy::UNSPECIFIED);
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE);
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE, true);
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFFONLY] = MakePolicyInfo(
        BUNDLE_NAME_DIFFONLY, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE);

    // When: the switch migrated memory to the minimal set (hide every filterable policy) and
    //       the save then failed -> the rollback replays the baseline set (the two NoLock
    //       calls below are exactly the wrapper's migrate + rollback pair)
    dataMgr_->FilterBundleListByDeviceModeDistributionPoliciesNoLock(ToPolicySet(POLICIES_VALID_MINIMAL));
    dataMgr_->FilterBundleListByDeviceModeDistributionPoliciesNoLock(ToPolicySet(POLICIES_VALID_MAIN_SET));

    // Then: exactly the pre-switch state — every name back on its original side with its
    //       original variant (4 visible / 2 hidden)
    EXPECT_EQ(dataMgr_->bundleInfos_.size(), 4u);
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 2u);
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_MAIN));
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_GENERIC));
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFFONLY));
}

// Corrupted persisted baseline (migrate-first order): the pre-switch persisted value fails
// ParsePersistedPolicies (out-of-range token "999" — the boot classification would already have
// fallen back to requirement-1 logic), so no rollback baseline exists. The switch is NOT
// blocked: it still migrates and succeeds, and the successful persist heals the stored value
// to the new normalized CSV (replacing the corrupted one). The no-baseline trade-off only
// surfaces on a later save failure (single-mode apps fall back to the mode-based placement
// while the other entries stay switched — pinned by _0780), which the mock cannot drive
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0760_CorruptedBaselineSwitchSucceedsAndHealsValue,
    TestSize.Level1)
{
    // Given: the persisted key holds a corrupted CSV; a SUB_ONLY app is visible (would be
    //        hidden by the main set)
    EnablePrimaryMode();
    EXPECT_TRUE(service_->bmsParam_->SaveBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, "999"));
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);

    // When/Then: the baseline read yields no valid rollback set, but the switch proceeds —
    //             ERR_OK, memory migrated, persisted value replaced by the normalized CSV
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
    std::string persisted;
    EXPECT_TRUE(service_->bmsParam_->GetBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, persisted));
    EXPECT_EQ(persisted, "1,3,4,5,6,7,8");
}

// Every successful switch overwrites the persisted value with the latest set (the baseline the
// NEXT switch would roll back to is always the previous switch's set), and memory re-places
// filterable policies according to that latest set
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0770_PersistedCsvTracksLatestSwitch,
    TestSize.Level1)
{
    // Given: MAIN_ONLY(1) and SUB_ONLY(2) apps are visible
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_MAIN] = MakePolicyInfo(
        BUNDLE_NAME_MAIN, DeviceModeDistributionPolicy::MAIN_ONLY);
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);

    // When: the first switch uses the minimal set Then: both filterable apps hide (1/2 not in
    //       {4,6,8}) and the persisted CSV is "4,6,8"
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_MAIN));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
    std::string persisted;
    EXPECT_TRUE(service_->bmsParam_->GetBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, persisted));
    EXPECT_EQ(persisted, "4,6,8");

    // When: the second switch uses the main set Then: memory re-places by the LATEST set
    //       (MAIN visible again, SUB stays hidden) and the persisted CSV is replaced, not
    //       appended — it now carries exactly the main set
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_MAIN));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_TRUE(service_->bmsParam_->GetBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, persisted));
    EXPECT_EQ(persisted, "1,3,4,5,6,7,8");
}

// No-baseline save-failure fallback (r16): with no valid persisted baseline the rollback
// cannot replay the migration body, so single-mode apps converge to the initialization-time
// mode-based placement instead of keeping the failed switch's set placement. The mocked
// BmsParam never fails a save (_0700 drives only the null-param entry), so — like _0750 —
// this case performs the exact two calls the rollback makes: migrate to the new set, then
// the mode-based fallback. Different-package/filterable entries are NOT restored (they keep
// the failed switch's placement; full convergence needs the next successful switch/reboot).
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0780_NoBaselineFallbackConvergesSingleModeByMode,
    TestSize.Level1)
{
    // Given: secondary mode; no persisted baseline (SetUp deleted the key); memory sits in the
    //        no-param boot state for secondary mode — MAIN_ONLY hidden, SUB_ONLY/UNSPECIFIED
    //        visible, the different-package pair's clone visible / primary hidden (Step 2
    //        swap), the single variant hidden
    EnableSecondaryMode();
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_MAIN] = MakePolicyInfo(
        BUNDLE_NAME_MAIN, DeviceModeDistributionPolicy::MAIN_ONLY);
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);
    dataMgr_->bundleInfos_[BUNDLE_NAME_GENERIC] = MakePolicyInfo(
        BUNDLE_NAME_GENERIC, DeviceModeDistributionPolicy::UNSPECIFIED);
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE, true);
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE);
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFFONLY] = MakePolicyInfo(
        BUNDLE_NAME_DIFFONLY, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE);

    // When: the switch migrated memory to the main set (MAIN_ONLY in-set -> shown, SUB_ONLY
    //       excluded -> hidden, pair swapped, single variant rotated in) and the save then
    //       failed with no valid baseline -> the r16 fallback (the two NoLock calls below are
    //       exactly the wrapper's migrate + no-baseline rollback pair; the mode argument is
    //       read exactly as the production rollback reads it)
    dataMgr_->FilterBundleListByDeviceModeDistributionPoliciesNoLock(ToPolicySet(POLICIES_VALID_MAIN_SET));
    dataMgr_->ClassifyDualModeAppsByDeviceModeNoLock(DualModeHelper::IsSecondaryMode());

    // Then: single-mode apps return to the mode-based placement — MAIN_ONLY hidden again
    //       (secondary mode) even though the failed set contained it, SUB_ONLY visible again
    //       even though the failed set excluded it; UNSPECIFIED stays. The different-package
    //       entries keep the failed switch's placement (partial convergence by design).
    EXPECT_EQ(dataMgr_->bundleInfos_.size(), 4u);
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 2u);
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_MAIN));
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_GENERIC));
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFFONLY));
}

// Missing any different-package policy (4/6/8) -> POLICY_INVALID (dual-mode param error)
HWTEST_F(BmsDualModeSwitchTest, FilterBundleListByDeviceModeDistributionPolicies_0800_MissingDiffRejected,
    TestSize.Level1)
{
    EnablePrimaryMode();
    EXPECT_EQ(Switch(POLICIES_INVALID_MISSING_DIFF), ERR_APPEXECFWK_DUAL_MODE_POLICY_INVALID);
    std::string persisted;
    EXPECT_FALSE(service_->bmsParam_->GetBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, persisted));
}

// Out-of-range value (not in [0,8]) or empty array -> POLICY_INVALID (dual-mode param error)
HWTEST_F(BmsDualModeSwitchTest, FilterBundleListByDeviceModeDistributionPolicies_0900_IllegalValuesRejected,
    TestSize.Level1)
{
    EnablePrimaryMode();
    EXPECT_EQ(Switch(POLICIES_INVALID_OUT_OF_RANGE), ERR_APPEXECFWK_DUAL_MODE_POLICY_INVALID);
    EXPECT_EQ(Switch(POLICIES_INVALID_EMPTY), ERR_APPEXECFWK_DUAL_MODE_POLICY_INVALID);
}

// Non-dual-mode device -> rejected with ERR_APPEXECFWK_DUAL_MODE_DEVICE_NOT_SUPPORTED (8519946)
// before param validation, the busy check, and persistence (device capability gate comes first)
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0950_NotDualModeDeviceRejected, TestSize.Level1)
{
    // Given: SetUp leaves both mode params invalid (non-dual-mode device); a SUB_ONLY app is visible
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);

    // When/Then: valid set, device idle -> rejected by the device gate alone
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_APPEXECFWK_DUAL_MODE_DEVICE_NOT_SUPPORTED);

    // One-sided cache (only ispcmode valid, mainmode invalid) is still a non-dual-mode device
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_TABLET, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_APPEXECFWK_DUAL_MODE_DEVICE_NOT_SUPPORTED);

    // The device gate precedes validation and the busy check: invalid policies + an operation
    // holding the lock still yield DEVICE_NOT_SUPPORTED (not POLICY_INVALID / SWITCH_BUSY)
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    EXPECT_EQ(Switch(POLICIES_INVALID_MISSING_DIFF), ERR_APPEXECFWK_DUAL_MODE_DEVICE_NOT_SUPPORTED);

    // Nothing migrated, nothing persisted
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 0u);
    std::string persisted;
    EXPECT_FALSE(service_->bmsParam_->GetBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, persisted));
}

// The switch no longer touches the mode cache (the UpdateModeCache call was removed from the
// flow): a transient mode-param read failure (here the ispcmode param disappears) can neither
// block the switch nor poison the cache — the entry device gate reads the pre-existing cache
// only and nothing inside the flow overwrites it, so the cache stays valid for install-time
// dual-mode handling. Replaces the former refresh-failure fail-closed pin (that path is gone)
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0960_SwitchDoesNotTouchModeCache,
    TestSize.Level1)
{
    // Given: a valid primary-mode device (params seeded, cache valid); the ispcmode param then
    //        disappears; a SUB_ONLY app is visible (hidden once the migration runs)
    EnablePrimaryMode();
    OHOS::system::RemoveParameter(TEST_ISPCMODE_PARAM);
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);

    // When/Then: the entry gate passes on the intact cache and the flow never re-reads the
    //             params — the switch succeeds, hides the SUB_ONLY app and persists the set
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));

    // And: the cache was left untouched (still reporting the seeded primary mode) — no
    //      unconditional overwrite anywhere in the flow
    EXPECT_TRUE(DualModeHelper::IsDualModeDevice());
    EXPECT_FALSE(DualModeHelper::IsSecondaryMode());
}

// === Switch <-> install/update/uninstall mutual exclusion (TASK-7, L-1 / L-9, r13 fast-fail) ===
// The switch takes the exclusive side of dualModeSwitchMutex_ with try_to_lock after the device
// and parameter gates; queued bundle-operation tasks and the synchronous direct-connection IPC
// entries TRY the shared side without blocking (BundleInstallerManager::AddTask wrapper /
// DualModeSwitchGuard -> BundleDataMgr::TryLockForBundleOperation) — an in-flight switch makes
// them fail fast with ERR_APPEXECFWK_DUAL_MODE_SWITCH_BUSY, never wait. try_to_lock cannot
// distinguish holder threads, so a same-thread lock stand-in for the in-flight
// operation/switch is behaviorally identical.

// A queued bundle operation holds the shared side (AC-8): the switch fails fast with
// ERR_APPEXECFWK_DUAL_MODE_SWITCH_BUSY (8519944) before any migration or persist — memory and
// the persisted value are untouched. Once the operation releases the lock the same switch
// succeeds, proving the busy verdict was about the lock alone
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0970_BusyWhileBundleOperationRunning,
    TestSize.Level0)
{
    // Given: dual-mode device; a SUB_ONLY app visible; a persisted set from a previous switch;
    //        a queued-task body in flight (main thread holds the shared side, as the AddTask
    //        wrapper does)
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);
    EXPECT_TRUE(service_->bmsParam_->SaveBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, "4,6,8"));
    std::shared_lock<std::shared_mutex> operationGuard(dataMgr_->dualModeSwitchMutex_);

    // When: a switch arrives with a set that would migrate and persist
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_APPEXECFWK_DUAL_MODE_SWITCH_BUSY);

    // Then: nothing changed — the app stays visible, temp stays empty, the persisted set is intact
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 0u);
    std::string persisted;
    EXPECT_TRUE(service_->bmsParam_->GetBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, persisted));
    EXPECT_EQ(persisted, "4,6,8");

    // And: after the operation finishes (shared side released) the same switch succeeds
    operationGuard.unlock();
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
}

// A switch is already in flight (AC-21): a second switch is rejected with BUSY — the exclusive
// side is single-entry — before any state change or persistence
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0980_BusyWhileSwitchInFlight,
    TestSize.Level0)
{
    // Given: dual-mode device; a SUB_ONLY app visible; an in-flight switch holds the exclusive
    //        side (main-thread stand-in)
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);
    std::unique_lock<std::shared_mutex> switchGuard(dataMgr_->dualModeSwitchMutex_);

    // When/Then: the second switch call fails fast with BUSY and nothing changed
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_APPEXECFWK_DUAL_MODE_SWITCH_BUSY);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 0u);
    std::string persisted;
    EXPECT_FALSE(service_->bmsParam_->GetBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, persisted));
}

// Primitive fast-fail semantics (AC-20, r13): a bundle operation's shared-side try fails
// immediately (nullptr, never waits) while a switch holds the exclusive side, and a try after
// the switch completes acquires — no waiting state exists on the operation side. Integration
// through the BundleInstallerManager::AddTask wrapper is covered by the installer-manager suite
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0990_OperationTryFailsFastWhileSwitchInFlight,
    TestSize.Level0)
{
    // Given: an in-flight switch (exclusive side held)
    std::unique_lock<std::shared_mutex> switchGuard(dataMgr_->dualModeSwitchMutex_);

    // When/Then: the operation-side try the AddTask wrapper / host guard makes fails fast —
    //             nullptr, no blocking, regardless of scheduling progress
    EXPECT_EQ(dataMgr_->TryLockForBundleOperation(), nullptr);

    // When: the switch completes (exclusive side released)
    switchGuard.unlock();

    // Then: the same try acquires the shared side
    EXPECT_NE(dataMgr_->TryLockForBundleOperation(), nullptr);
}

// A synchronous direct-connection entry holds the shared side (AC-8, direct-entry widening;
// L-9): TryLockForBundleOperation() is the guard the BundleInstallerHost entries take — while
// it is held the switch fails fast with BUSY before any migration or persist, and the same
// switch succeeds once the entry returns (guard released)
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0991_DirectEntryGuardBlocksSwitch,
    TestSize.Level0)
{
    // Given: dual-mode device; a SUB_ONLY app visible; a persisted set from a previous switch;
    //        a direct-connection entry in flight (its guard owns the shared side)
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);
    EXPECT_TRUE(service_->bmsParam_->SaveBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, "4,6,8"));
    auto entryGuard = dataMgr_->TryLockForBundleOperation();
    ASSERT_NE(entryGuard, nullptr);

    // When: a switch arrives with a set that would migrate and persist
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_APPEXECFWK_DUAL_MODE_SWITCH_BUSY);

    // Then: nothing changed — the app stays visible, temp stays empty, the persisted set is intact
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 0u);
    std::string persisted;
    EXPECT_TRUE(service_->bmsParam_->GetBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, persisted));
    EXPECT_EQ(persisted, "4,6,8");

    // And: after the entry finishes (guard released) the same switch succeeds
    entryGuard.reset();
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
}

// A switch is in flight: the synchronous direct-connection IPC entries in BundleInstallerHost
// (AC-22, L-9, r13 — clone create/delete 123/126, sandbox install/uninstall 108/111, plugin
// install/uninstall 132/135, installExisted 129, preinstall uninstall 147, cli sandbox
// create/destroy 150/153 all run on the calling thread and bypass the installer queue) FAIL
// FAST with ERR_APPEXECFWK_DUAL_MODE_SWITCH_BUSY: the guard tries the shared side without
// blocking, the try fails while the exclusive side is held, and the entry returns before
// running any body (memory untouched). Once the switch completes the same entry passes the
// guard and reaches its own deterministic appIndex-range rejection, proving the earlier
// verdict was the guard alone. The 10 host call sites share the single guard helper
// (grep-verified); this case drives one entry end-to-end
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0992_SwitchInFlightDirectEntryFailsFast,
    TestSize.Level0)
{
    // Given: dual-mode device; an in-flight switch holds the exclusive side
    EnablePrimaryMode();
    std::unique_lock<std::shared_mutex> switchGuard(dataMgr_->dualModeSwitchMutex_);
    BundleInstallerHost host;
    DestroyAppCloneParam destroyParam;

    // When/Then: the entry returns BUSY immediately — no wait, no body ran (maps untouched)
    EXPECT_EQ(host.UninstallCloneApp(BUNDLE_NAME_GENERIC, TEST_USERID, 0, destroyParam),
        ERR_APPEXECFWK_DUAL_MODE_SWITCH_BUSY);
    EXPECT_EQ(dataMgr_->bundleInfos_.size(), 0u);
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 0u);

    // And: once the switch completes the same entry passes the guard and reaches its own
    //      deterministic appIndex-range rejection (appIndex 0 < CLONE_APP_INDEX_MIN)
    switchGuard.unlock();
    EXPECT_EQ(host.UninstallCloneApp(BUNDLE_NAME_GENERIC, TEST_USERID, 0, destroyParam),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_APP_INDEX);
}

// Non-dual-mode device (AC-23): the host-entry guard is a zero-overhead early-out — the entry
// never consults dualModeSwitchMutex_ (here held exclusively, an impossible state on such a
// device kept only to prove the skip), so the call runs exactly as before the mutual exclusion
// existed and its verdict comes from behind the guard, not from it
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0993_NonDualModeEntrySkipsGuard,
    TestSize.Level0)
{
    // Given: non-dual-mode device (SetUp's default: both mode params invalid); an exclusive
    //        stand-in holds the mutex
    ASSERT_FALSE(DualModeHelper::IsDualModeDevice());
    std::unique_lock<std::shared_mutex> switchGuard(dataMgr_->dualModeSwitchMutex_);
    BundleInstallerHost host;
    DestroyAppCloneParam destroyParam;

    // When/Then: the entry proceeds past the guard to its own deterministic appIndex-range
    //             rejection — the held lock is never consulted
    EXPECT_EQ(host.UninstallCloneApp(BUNDLE_NAME_GENERIC, TEST_USERID, 0, destroyParam),
        ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_APP_INDEX);
}

// Reboot with no persisted policy set -> fall back to requirement-1 original logic
// (different-package policies by system mode), zero regression
HWTEST_F(BmsDualModeSwitchTest, ClassifyDualModeAppsNoPolicies_0100_FallsBackToReq1,
    TestSize.Level0)
{
    // Given: dual-mode device (primary mode), no persisted policy set; raw post-install state has
    //        the diff-package primary (original name) and its prefixed clone side-by-side in
    //        bundleInfos_, plus a filterable non-mode-exclusive app (UNIVERSAL_IDENTICAL_PACKAGE)
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    dataMgr_->bundleInfos_[PREFIXED_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE, true);
    dataMgr_->bundleInfos_[BUNDLE_NAME_GENERIC] = MakePolicyInfo(
        BUNDLE_NAME_GENERIC, DeviceModeDistributionPolicy::UNIVERSAL_IDENTICAL_PACKAGE);

    // When: ClassifyDualModeAppsNoLock()
    dataMgr_->ClassifyDualModeAppsNoLock();

    // Then: requirement-1 original logic — prefixed clone key disappears (moved to temp under the
    //       original name), primary variant stays visible, clone hidden; without a policy set a
    //       non-mode-exclusive filterable app is NOT hidden (the mode-exclusive fallback binding
    //       is pinned separately in ClassifyDualModeAppsFallback_0500)
    EXPECT_EQ(dataMgr_->bundleInfos_.count(PREFIXED_NAME_DIFF), 0u);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_TRUE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_FALSE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
}

// Reboot with a persisted policy set -> classify by the set (independent of device mode)
HWTEST_F(BmsDualModeSwitchTest, ClassifyDualModeAppsWithPolicies_0100_ClassifiesByPolicies,
    TestSize.Level0)
{
    // Given: persisted set "1,3,4,5,6,7,8" (excludes SUB_ONLY=2); apps of each policy visible
    EnablePrimaryMode();
    EXPECT_TRUE(service_->bmsParam_->SaveBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, "1,3,4,5,6,7,8"));
    dataMgr_->bundleInfos_[BUNDLE_NAME_MAIN] = MakePolicyInfo(
        BUNDLE_NAME_MAIN, DeviceModeDistributionPolicy::MAIN_ONLY);
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);
    dataMgr_->bundleInfos_[BUNDLE_NAME_GENERIC] = MakePolicyInfo(
        BUNDLE_NAME_GENERIC, DeviceModeDistributionPolicy::UNSPECIFIED);

    // When: ClassifyDualModeAppsNoLock()
    dataMgr_->ClassifyDualModeAppsNoLock();

    // Then: filterable policy in the set -> bundleInfos_; not in the set -> tempBundleInfos_;
    //       UNSPECIFIED always visible
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_MAIN));
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_GENERIC));
    EXPECT_FALSE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
}

// Different-package policies (mandatory in the set) -> select primary/clone variant by system mode
HWTEST_F(BmsDualModeSwitchTest, ClassifyDualModeAppsWithPolicies_0200_DiffPackageBySystemMode,
    TestSize.Level0)
{
    // Given: dual-mode device in SECONDARY mode; a diff-package app's primary (original name) and
    //        prefixed clone variants sit side-by-side in bundleInfos_
    EnableSecondaryMode();
    EXPECT_TRUE(service_->bmsParam_->SaveBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, "1,3,4,5,6,7,8"));
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    dataMgr_->bundleInfos_[PREFIXED_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE, true);

    // When: ClassifyDualModeAppsNoLock()
    dataMgr_->ClassifyDualModeAppsNoLock();

    // Then: the current-mode (secondary -> clone) variant is visible, the other-mode variant is in
    //       temp under the same original-name key (requirement-1 logic preserved)
    EXPECT_EQ(dataMgr_->bundleInfos_.count(PREFIXED_NAME_DIFF), 0u);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_TRUE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_FALSE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
}

// Reboot with corrupted persisted value (illegal CSV / out of range / missing 4,6,8) -> fall back to
// requirement-1, do not classify by the set
HWTEST_F(BmsDualModeSwitchTest, ClassifyDualModeAppsWithPolicies_0300_CorruptedValueFallsBack,
    TestSize.Level0)
{
    // Given: a filterable SUB_ONLY app is visible; persisted value is corrupted
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);

    // When: value "1,2,9" (out-of-range token) Then: parse fails -> no policy-based hiding
    EXPECT_TRUE(service_->bmsParam_->SaveBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, "1,2,9"));
    dataMgr_->ClassifyDualModeAppsNoLock();
    EXPECT_FALSE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));

    // When: value "1,2,x" (non-numeric token) Then: same fallback, zero hiding
    EXPECT_TRUE(service_->bmsParam_->SaveBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, "1,2,x"));
    dataMgr_->ClassifyDualModeAppsNoLock();
    EXPECT_FALSE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 1u);
}

// Reboot classification meets an inconsistent same-name pairing (filterable bundle entry not in
// the set + stray temp entry): the guard mirrors the runtime switch path — keep BOTH entries
// instead of silently overwriting the temp one (codecheck INP-06)
HWTEST_F(BmsDualModeSwitchTest, ClassifyDualModeAppsWithPolicies_0400_InconsistentPairingKeepsBoth,
    TestSize.Level0)
{
    // Given: persisted set "1,3,4,5,6,7,8" (excludes SUB_ONLY=2); a SUB_ONLY app is visible
    //        while a same-name entry (stray clone-flagged variant) already sits in tempBundleInfos_
    EnablePrimaryMode();
    EXPECT_TRUE(service_->bmsParam_->SaveBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, "1,3,4,5,6,7,8"));
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY, true);

    // When: ClassifyDualModeAppsNoLock()
    dataMgr_->ClassifyDualModeAppsNoLock();

    // Then: the pairing is inconsistent — the migration is skipped and BOTH entries keep their
    //       sides (no silent overwrite of the temp entry by the hidden bundle entry)
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_SUB].IsDualModeCloneApp());
    EXPECT_TRUE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_SUB].IsDualModeCloneApp());
}

// === ClassifyDualModeAppsByPolicyNoLock direct contract (requirement-2 boot classification body) ===
// Called directly (not through ClassifyDualModeAppsNoLock) to pin the function's own return value
// and each branch, independent of the requirement-1 Step1/Step2 mode classification.

// Valid set: returns true; the set loop hides only filterable policies not in the set; UNSPECIFIED
// always visible; different-package policies are skipped (left to the mode-based classification —
// a direct call does not run the Step1/Step2 clone swap)
HWTEST_F(BmsDualModeSwitchTest, ClassifyDualModeAppsByPolicy_0100_ValidSetReturnsTrueAndClassifies,
    TestSize.Level0)
{
    // Given: persisted set "1,3,4,5,6,7,8" (excludes SUB_ONLY=2); primary mode
    EnablePrimaryMode();
    EXPECT_TRUE(service_->bmsParam_->SaveBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, "1,3,4,5,6,7,8"));
    dataMgr_->bundleInfos_[BUNDLE_NAME_MAIN] = MakePolicyInfo(
        BUNDLE_NAME_MAIN, DeviceModeDistributionPolicy::MAIN_ONLY);
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);
    dataMgr_->bundleInfos_[BUNDLE_NAME_GENERIC] = MakePolicyInfo(
        BUNDLE_NAME_GENERIC, DeviceModeDistributionPolicy::UNSPECIFIED);
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);

    // When: ClassifyDualModeAppsByPolicyNoLock() directly
    EXPECT_TRUE(dataMgr_->ClassifyDualModeAppsByPolicyNoLock());

    // Then: SUB_ONLY not in the set -> hidden; MAIN_ONLY in the set, UNSPECIFIED and the
    //       diff-package entry stay in bundleInfos_ untouched
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_MAIN));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_GENERIC));
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 1u);
}

// Valid set: the mode-exclusive rotation does NOT run on the valid-set path — a set containing
// both MAIN_ONLY and SUB_ONLY keeps both visible even in a mismatched live mode (the set itself
// encodes per-policy visibility; mode binding is fallback-only, 2026-08-26)
HWTEST_F(BmsDualModeSwitchTest, ClassifyDualModeAppsByPolicy_0200_ValidSetSkipsModeExclusiveBinding,
    TestSize.Level0)
{
    // Given: persisted set "1,2,3,4,5,6,7,8" contains both mode-exclusive policies; SECONDARY mode
    EnableSecondaryMode();
    EXPECT_TRUE(service_->bmsParam_->SaveBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, "1,2,3,4,5,6,7,8"));
    dataMgr_->bundleInfos_[BUNDLE_NAME_MAIN] = MakePolicyInfo(
        BUNDLE_NAME_MAIN, DeviceModeDistributionPolicy::MAIN_ONLY);
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);

    // When: ClassifyDualModeAppsByPolicyNoLock() directly
    EXPECT_TRUE(dataMgr_->ClassifyDualModeAppsByPolicyNoLock());

    // Then: both stay visible — zero movement on the valid-set path
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_MAIN));
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 0u);
}

// Fallback pass meets an inconsistent same-name pairing (mode-exclusive bundle entry + stray temp
// entry): guard mirrors the set loop — keep BOTH instead of overwriting the temp entry
HWTEST_F(BmsDualModeSwitchTest, ClassifyDualModeAppsByPolicy_0600_FallbackSameNameGuardKeepsBoth,
    TestSize.Level0)
{
    // Given: no persisted set; SECONDARY mode; a MAIN_ONLY app is visible while a same-name stray
    //        (clone-flagged) entry already sits in tempBundleInfos_
    EnableSecondaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_MAIN] = MakePolicyInfo(
        BUNDLE_NAME_MAIN, DeviceModeDistributionPolicy::MAIN_ONLY);
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_MAIN] = MakePolicyInfo(
        BUNDLE_NAME_MAIN, DeviceModeDistributionPolicy::MAIN_ONLY, true);

    // When: ClassifyDualModeAppsByPolicyNoLock() directly
    EXPECT_FALSE(dataMgr_->ClassifyDualModeAppsByPolicyNoLock());

    // Then: the pairing is inconsistent — the fallback move is skipped and BOTH entries keep
    //       their sides (no silent overwrite of the temp entry)
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_MAIN));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_MAIN));
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_MAIN].IsDualModeCloneApp());
    EXPECT_TRUE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_MAIN].IsDualModeCloneApp());
}

// === DualModeHelper public policy utilities (single validation/serialization source) ===
// Pure static helpers — no device-mode state, no persistence, no maps involved.

// Valid sets: mandatory-only {4,6,8}, full {1..8}, and sets containing UNSPECIFIED(0) (legal value)
HWTEST_F(BmsDualModeSwitchTest, DualModeHelperIsValidPolicySet_1000_ValidSetsAccepted,
    TestSize.Level1)
{
    EXPECT_TRUE(DualModeHelper::IsValidPolicySet(ToPolicySet(POLICIES_VALID_MINIMAL)));
    EXPECT_TRUE(DualModeHelper::IsValidPolicySet(ToPolicySet(POLICIES_VALID_ALL)));
    EXPECT_TRUE(DualModeHelper::IsValidPolicySet(ToPolicySet(POLICIES_VALID_MAIN_SET)));
    // UNSPECIFIED(0) is inside the legal value range [0,8]: {0,4,6,8} passes the value rules
    EXPECT_TRUE(DualModeHelper::IsValidPolicySet(ToPolicySet({0, 4, 6, 8})));
    // Input order is irrelevant (set semantics)
    EXPECT_TRUE(DualModeHelper::IsValidPolicySet(ToPolicySet({8, 6, 4})));
}

// Invalid sets: empty / missing any of 4,6,8 / value out of [0,8] (over- and underflow)
HWTEST_F(BmsDualModeSwitchTest, DualModeHelperIsValidPolicySet_1010_InvalidSetsRejected,
    TestSize.Level1)
{
    EXPECT_FALSE(DualModeHelper::IsValidPolicySet(ToPolicySet(POLICIES_INVALID_EMPTY)));
    EXPECT_FALSE(DualModeHelper::IsValidPolicySet(ToPolicySet(POLICIES_INVALID_MISSING_DIFF)));
    EXPECT_FALSE(DualModeHelper::IsValidPolicySet(ToPolicySet({4, 6})));      // missing 8
    EXPECT_FALSE(DualModeHelper::IsValidPolicySet(ToPolicySet(POLICIES_INVALID_OUT_OF_RANGE)));  // 9
    EXPECT_FALSE(DualModeHelper::IsValidPolicySet(ToPolicySet({-1, 4, 6, 8})));                  // -1
}

// Valid persisted CSV parses into the exact policy set (duplicated/unsorted tokens tolerated)
HWTEST_F(BmsDualModeSwitchTest, DualModeHelperParsePersistedPolicies_1020_ValidCsvParsesToSet,
    TestSize.Level1)
{
    std::set<DeviceModeDistributionPolicy> policySet;
    EXPECT_TRUE(DualModeHelper::ParsePersistedPolicies("1,3,4,5,6,7,8", policySet));
    EXPECT_TRUE(DualModeHelper::ParsePersistedPolicies("4,6,8", policySet));
    // Duplicated tokens dedup via the set; no ordering requirement on the persisted form
    EXPECT_TRUE(DualModeHelper::ParsePersistedPolicies("8,4,6,4", policySet));
}

// Corrupted persisted value: whole parse rejected (no partial adoption) — the caller then falls
// back to the requirement-1 logic (AC-18)
HWTEST_F(BmsDualModeSwitchTest, DualModeHelperParsePersistedPolicies_1030_CorruptCsvRejected,
    TestSize.Level1)
{
    std::set<DeviceModeDistributionPolicy> policySet;
    EXPECT_FALSE(DualModeHelper::ParsePersistedPolicies("1,2,x", policySet));    // non-numeric token
    EXPECT_FALSE(DualModeHelper::ParsePersistedPolicies("1,2,9", policySet));    // out-of-range token
    EXPECT_FALSE(DualModeHelper::ParsePersistedPolicies("-1,4,6,8", policySet)); // below-range token
    EXPECT_FALSE(DualModeHelper::ParsePersistedPolicies("4,6", policySet));      // missing mandatory 8
    EXPECT_FALSE(DualModeHelper::ParsePersistedPolicies("", policySet));         // empty value
}

// Canonical serialization: ascending unique decimal values joined by "," (set ordering makes the
// output deterministic regardless of construction order)
HWTEST_F(BmsDualModeSwitchTest, DualModeHelperPoliciesToCsv_1040_CanonicalAscendingCsv,
    TestSize.Level1)
{
    EXPECT_EQ(DualModeHelper::PoliciesToCsv(ToPolicySet(POLICIES_VALID_MINIMAL)), "4,6,8");
    EXPECT_EQ(DualModeHelper::PoliciesToCsv(ToPolicySet(POLICIES_VALID_ALL)), "1,2,3,4,5,6,7,8");
    EXPECT_EQ(DualModeHelper::PoliciesToCsv(ToPolicySet({8, 6, 1, 4})), "1,4,6,8");
    EXPECT_EQ(DualModeHelper::PoliciesToCsv(ToPolicySet({4})), "4");
    EXPECT_EQ(DualModeHelper::PoliciesToCsv(ToPolicySet(POLICIES_INVALID_EMPTY)), "");
}

// host_impl without a data manager: ERR_BUNDLE_MANAGER_INTERNAL_ERROR before any switch logic
// (SetUp rebuilds service_->dataMgr_ for every case, so nulling it here leaks nowhere)
HWTEST_F(BmsDualModeSwitchTest, FilterBundleListIpcLink_1300_HostImplWithoutDataMgr,
    TestSize.Level1)
{
    EnablePrimaryMode();
    service_->dataMgr_ = nullptr;
    sptr<BundleMgrHostImpl> hostImpl = new (std::nothrow) BundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    EXPECT_EQ(hostImpl->FilterBundleListByDeviceModeDistributionPolicies(ToPolicySet(POLICIES_VALID_MINIMAL)),
        ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

}  // namespace AppExecFwk
}  // namespace OHOS
