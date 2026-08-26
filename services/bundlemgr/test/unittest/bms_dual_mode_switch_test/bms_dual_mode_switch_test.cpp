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

// Unit tests for the requirement-2 runtime visibility switch (FEAT-20260803-001, TASK-6):
// BundleDataMgr::FilterBundleListByDeviceModeDistributionPolicies and the reboot-classification
// policy branch (ClassifyDualModeAppsNoLock). Follows the bms_dual_mode_install_test paradigm:
// #define private public exposes the DualModeHelper mode cache (cachedIspcmode_/cachedMainmode_)
// and the BundleDataMgr maps. Mode is driven through the mocked parameter map (SeedModeParams:
// persist.bms.test_dual_mode switches DualModeHelper to the persist.bms.* test keys, and the
// cache is refreshed via the production UpdateModeCache path, so the switch's own post-persist
// refresh is really exercised); the device-gate cases (rejected before that refresh) keep
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
#include <set>
#include <string>
#include <vector>

#include "appexecfwk_errors.h"
#include "application_info.h"
#include "bms_param.h"
#include "bundle_data_mgr.h"
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
// production path (UpdateModeCache) — the same refresh the switch performs after persisting,
// so the switch cases exercise the real param-read path and the cache and params never
// diverge (codecheck R3 INP-06 paradigm, cf. bms_data_mgr_test.cpp SetBundleFirstLaunch_0003).
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

// Single different-package variant with NO counterpart in bundleInfos_: the migration is a
// rotation and rotation needs a pair — a temp-side diff-package entry never migrates in alone,
// regardless of the current mode (its mode-based placement converges on the reboot
// classification, spec L-7)
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0460_SingleDiffPackageVariantNeverMigratesAlone,
    TestSize.Level1)
{
    // Given: primary mode; only the clone variant exists (in tempBundleInfos_, no primary)
    EnablePrimaryMode();
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE, true);

    // When/Then: its policy is in the set, but it has no counterpart to rotate with — it stays
    //            in tempBundleInfos_ and nothing becomes visible under that name
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_FALSE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_TRUE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());

    // Given: secondary mode with only the primary variant on the hidden side (mirror setup)
    EnableSecondaryMode();
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE);

    // When/Then: the primary variant has no counterpart either — same invariant
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_FALSE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_FALSE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
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

// Show pass with a non-variant bundle occupant: a mode-visible diff-package variant may only
// swap with its diff-package counterpart. When the same-name bundle slot is occupied by an
// in-set filterable app (must stay visible), the swap is skipped — no oscillation on repeated
// switches (codecheck LOG-06)
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0480_NonVariantOccupantNotSwappedOut,
    TestSize.Level1)
{
    // Given: secondary mode; the mode-visible clone variant waits in tempBundleInfos_ while the
    //        same-name bundle slot is occupied by an in-set MAIN_ONLY app (anomalous pairing)
    EnableSecondaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::MAIN_ONLY);
    dataMgr_->tempBundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::FULL_COMPATIBLE_DIFFERENT_PACKAGE, true);

    // When/Then: the clone never swaps out the visible MAIN_ONLY entry; both keep their sides,
    //            and repeating the switch changes nothing (no flip-flop)
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_SUB].IsDualModeCloneApp());
    EXPECT_TRUE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_SUB].IsDualModeCloneApp());

    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_SUB].IsDualModeCloneApp());
    EXPECT_TRUE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_SUB].IsDualModeCloneApp());
}

// Device mode flipped between switches (spec L-7): the switch re-reads the mode params itself
// (UpdateModeCache after persisting), so install-time dual-mode handling (NeedDualModeHandle)
// sees the new mode without a reboot. The migration body stays mode-free: the pair rotates on
// every call regardless of the mode, and a single-variant different-package app (no counterpart
// to rotate with) does NOT move at runtime — its mode-based placement converges on the reboot
// classification (spec L-7, by-design)
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0490_ModeFlipRefreshesCachePairRotates,
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
    //       is mode-free; the single-variant app has no counterpart and stays visible
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_FALSE(DualModeHelper::IsSecondaryMode());
    EXPECT_TRUE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_FALSE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFFONLY));

    // When: the mode params flip to secondary (as the mode switcher does) and the switch runs
    //       again — only the params changed; the cache still holds the primary-mode value
    OHOS::system::SetParameter(TEST_ISPCMODE_PARAM,
        std::to_string(ServiceConstants::DUAL_MODE_VALUE_2IN1));

    // Then: the switch's own param refresh updates the mode cache (secondary visible to
    //       install-time handling without a reboot) while the migration keeps rotating the pair
    //       per call — the primary variant is visible again; the single-variant app is NOT
    //       hidden at runtime (reboot convergence, spec L-7)
    EXPECT_EQ(Switch(POLICIES_VALID_MINIMAL), ERR_OK);
    EXPECT_TRUE(DualModeHelper::IsSecondaryMode());
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

// SaveBmsParam failure -> PERSIST_FAILED (8519945) + memory not migrated (rolled back)
HWTEST_F(BmsDualModeSwitchTest, FilterBundleListByDeviceModeDistributionPolicies_0700_PersistFailedRollsBack,
    TestSize.Level1)
{
    // Given: persistence unavailable (service bmsParam_ null); a SUB_ONLY app is visible.
    // (The mocked BmsParam's SaveBmsParam never fails for a non-empty key, so the save-failure
    // branch itself is not reachable in unit tests; this drives the equivalent null-param branch.)
    EnablePrimaryMode();
    service_->bmsParam_ = nullptr;
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);

    // When/Then: returns ERR_APPEXECFWK_DUAL_MODE_PERSIST_FAILED (8519945); bundleInfos_/
    //            tempBundleInfos_ remain as before the switch
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_APPEXECFWK_DUAL_MODE_PERSIST_FAILED);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 0u);
}

// Missing any different-package policy (4/6/8) -> INVALID_PARAMETER
HWTEST_F(BmsDualModeSwitchTest, FilterBundleListByDeviceModeDistributionPolicies_0800_MissingDiffRejected,
    TestSize.Level1)
{
    EnablePrimaryMode();
    EXPECT_EQ(Switch(POLICIES_INVALID_MISSING_DIFF), ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    std::string persisted;
    EXPECT_FALSE(service_->bmsParam_->GetBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, persisted));
}

// Out-of-range value (not in [0,8]) or empty array -> INVALID_PARAMETER
HWTEST_F(BmsDualModeSwitchTest, FilterBundleListByDeviceModeDistributionPolicies_0900_IllegalValuesRejected,
    TestSize.Level1)
{
    EnablePrimaryMode();
    EXPECT_EQ(Switch(POLICIES_INVALID_OUT_OF_RANGE), ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    EXPECT_EQ(Switch(POLICIES_INVALID_EMPTY), ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
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
    // holding the lock still yield DEVICE_NOT_SUPPORTED (not INVALID_PARAMETER / SWITCH_BUSY)
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_INVALID, ServiceConstants::DUAL_MODE_VALUE_INVALID);
    EXPECT_EQ(Switch(POLICIES_INVALID_MISSING_DIFF), ERR_APPEXECFWK_DUAL_MODE_DEVICE_NOT_SUPPORTED);

    // Nothing migrated, nothing persisted
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 0u);
    std::string persisted;
    EXPECT_FALSE(service_->bmsParam_->GetBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, persisted));
}

// Mode param refresh failure after a successful persist (transient read failure — here the
// ispcmode param disappears): UpdateModeCache overwrites the cache unconditionally (its
// implementation is kept as-is by decision), so the cache stops reporting a dual-mode device
// until the next successful refresh; the switch fails closed — migration skipped, caller gets
// DEVICE_NOT_SUPPORTED to retry, persisted policies stay in place (codecheck R3 INP-06,
// post-refresh gate re-verification)
HWTEST_F(BmsDualModeSwitchTest,
    FilterBundleListByDeviceModeDistributionPolicies_0960_ModeRefreshFailureFailsClosed,
    TestSize.Level1)
{
    // Given: a valid primary-mode device (params seeded, cache valid); the ispcmode param then
    //        disappears; a SUB_ONLY app is visible (would be hidden if the migration ran)
    EnablePrimaryMode();
    OHOS::system::RemoveParameter(TEST_ISPCMODE_PARAM);
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);

    // When/Then: the device gate still passes on the pre-refresh cache and persistence
    //             succeeds, but the refresh invalidates the gate -> 8519946 and no migration
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_APPEXECFWK_DUAL_MODE_DEVICE_NOT_SUPPORTED);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 0u);

    // And: the cache is invalid until the next successful refresh (unconditional overwrite —
    //      accepted residual of keeping UpdateModeCache as-is); the migration body is mode-free
    //      so a poisoned cache cannot misdirect it, and the gate rejects further switches
    EXPECT_FALSE(DualModeHelper::IsDualModeDevice());
    EXPECT_FALSE(DualModeHelper::IsSecondaryMode());
    EnablePrimaryMode();
    EXPECT_EQ(Switch(POLICIES_VALID_MAIN_SET), ERR_OK);
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_SUB));
}

// Reboot with no persisted policy set -> fall back to requirement-1 original logic
// (different-package policies by system mode), zero regression
HWTEST_F(BmsDualModeSwitchTest, ClassifyDualModeAppsNoPolicies_0100_FallsBackToReq1,
    TestSize.Level0)
{
    // Given: dual-mode device (primary mode), no persisted policy set; raw post-install state has
    //        the diff-package primary (original name) and its prefixed clone side-by-side in
    //        bundleInfos_, plus a filterable SUB_ONLY app
    EnablePrimaryMode();
    dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    dataMgr_->bundleInfos_[PREFIXED_NAME_DIFF] = MakePolicyInfo(
        BUNDLE_NAME_DIFF, DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE, true);
    dataMgr_->bundleInfos_[BUNDLE_NAME_SUB] = MakePolicyInfo(
        BUNDLE_NAME_SUB, DeviceModeDistributionPolicy::SUB_ONLY);

    // When: ClassifyDualModeAppsNoLock()
    dataMgr_->ClassifyDualModeAppsNoLock();

    // Then: requirement-1 original logic — prefixed clone key disappears (moved to temp under the
    //       original name), primary variant stays visible, clone hidden; without a policy set the
    //       filterable app is NOT hidden (all visible)
    EXPECT_EQ(dataMgr_->bundleInfos_.count(PREFIXED_NAME_DIFF), 0u);
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_FALSE(dataMgr_->bundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(IsHidden(*dataMgr_, BUNDLE_NAME_DIFF));
    EXPECT_TRUE(dataMgr_->tempBundleInfos_[BUNDLE_NAME_DIFF].IsDualModeCloneApp());
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
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
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));

    // When: value "1,2,x" (non-numeric token) Then: same fallback, zero hiding
    EXPECT_TRUE(service_->bmsParam_->SaveBmsParam(
        ServiceConstants::DUAL_MODE_DEVICE_MODE_DISTRIBUTION_POLICIES_KEY, "1,2,x"));
    dataMgr_->ClassifyDualModeAppsNoLock();
    EXPECT_TRUE(IsVisible(*dataMgr_, BUNDLE_NAME_SUB));
    EXPECT_EQ(dataMgr_->tempBundleInfos_.size(), 0u);
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
