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

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>  // NOLINT
#include <thread>  // NOLINT

#define private public
#include "app_clone_preference_data_mgr.h"
#include "app_clone_preference_storage.h"
#undef private

#include "bundle_mgr_service.h"

using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace testing;
using namespace testing::ext;

// In the mock test env, DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr() always
// returns nullptr (see services/bundlemgr/test/mock/src/bundle_mgr_service.cpp), so the dataMgr-null
// branch in Get/Set is the only reachable past parameter validation. Tests below pin the exact
// ErrCode for each branch instead of accepting any of several alternatives — that precision is
// what makes a "covered branch" actually covered from the branch-coverage tool's perspective.

namespace {
constexpr int32_t TEST_USER_ID = 100;
const std::string TEST_BUNDLE = "com.example.app_clone_pref_datamgr";
}

class BmsAppClonePreferenceDataMgrTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override
    {
        // Clean any records seeded into the shared bmsdb.db so tests don't bleed into each other.
        auto cleanup = std::make_shared<AppClonePreferenceStorage>();
        if (cleanup != nullptr) {
            cleanup->Delete(TEST_BUNDLE, TEST_USER_ID);
            cleanup->Delete(TEST_BUNDLE, TEST_USER_ID + 1);
        }
    }
};

// -------------------- Construction --------------------

HWTEST_F(BmsAppClonePreferenceDataMgrTest, Construct_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    EXPECT_NE(dataMgr->storage_, nullptr);
    // Repeated construction must yield independent instances each with its own storage — the
    // underlying RdbDataManager opens a fresh handle to bmsdb.db rather than sharing state.
    auto dataMgr2 = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr2, nullptr);
    EXPECT_NE(dataMgr2->storage_, nullptr);
    EXPECT_NE(dataMgr->storage_.get(), dataMgr2->storage_.get());
}

// -------------------- GetAppClonePreference parameter validation --------------------

HWTEST_F(BmsAppClonePreferenceDataMgrTest, GetAppClonePreference_EmptyBundleName_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;  // pre-set; must remain untouched
    // The empty-name check fires before any BundleDataMgr lookup, so the result is the same
    // regardless of which userId is supplied.
    EXPECT_EQ(dataMgr->GetAppClonePreference("", TEST_USER_ID, preference),
        ERR_BUNDLE_MANAGER_BUNDLE_NAME_IS_EMPTY);
    EXPECT_EQ(dataMgr->GetAppClonePreference("", 0, preference),
        ERR_BUNDLE_MANAGER_BUNDLE_NAME_IS_EMPTY);
    EXPECT_EQ(dataMgr->GetAppClonePreference("", -1, preference),
        ERR_BUNDLE_MANAGER_BUNDLE_NAME_IS_EMPTY);
    EXPECT_EQ(preference.mode, AppClonePreferenceMode::MAIN_APP);
}

// dataMgr is nullptr in mock env → SERVICE_INTERNAL_ERROR is the only reachable terminal.
// The dataMgr-null branch sits past the empty-name check but before the storage-null check,
// so any non-empty bundleName with any userId lands here in the mock env.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, GetAppClonePreference_DataMgrNull_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    AppClonePreference preference;
    EXPECT_EQ(dataMgr->GetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    EXPECT_EQ(dataMgr->GetAppClonePreference(TEST_BUNDLE, 0, preference),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    EXPECT_EQ(dataMgr->GetAppClonePreference("any.other.bundle", TEST_USER_ID, preference),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// storage_ == nullptr is checked AFTER dataMgr; both must be nullptr-reachable. The dataMgr-null
// branch returns first, so we verify the storage_-null path is shadowed (deferred to integration).
HWTEST_F(BmsAppClonePreferenceDataMgrTest, GetAppClonePreference_StorageNull_ShadowedByDataMgrNull_001,
    TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto saved = std::move(dataMgr->storage_);
    dataMgr->storage_ = nullptr;
    AppClonePreference preference;
    auto ret = dataMgr->GetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    dataMgr->storage_ = std::move(saved);
}

// -------------------- SetAppClonePreference parameter validation --------------------

// Empty bundleName short-circuits BEFORE the type-range check, so even an invalid type
// combined with an empty name yields BUNDLE_NAME_IS_EMPTY (not PARAM_ERROR). Verified with
// both a valid MAIN_APP type and an out-of-range type to pin the short-circuit ordering.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_EmptyBundleName_BeforeType_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    AppClonePreference validType;
    validType.mode = AppClonePreferenceMode::MAIN_APP;
    EXPECT_EQ(dataMgr->SetAppClonePreference("", TEST_USER_ID, validType),
        ERR_BUNDLE_MANAGER_BUNDLE_NAME_IS_EMPTY);
    AppClonePreference invalidType;
    invalidType.mode = static_cast<AppClonePreferenceMode>(99);
    EXPECT_EQ(dataMgr->SetAppClonePreference("", TEST_USER_ID, invalidType),
        ERR_BUNDLE_MANAGER_BUNDLE_NAME_IS_EMPTY);
    EXPECT_EQ(dataMgr->SetAppClonePreference("", 0, invalidType),
        ERR_BUNDLE_MANAGER_BUNDLE_NAME_IS_EMPTY);
}

// Invalid type values (above max, far above max, negative) all yield PARAM_ERROR. The range
// check rejects anything outside [ALWAYS_ASK=0, CLONE_APP=2] before any other validation.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_InvalidType_OutOfRange_001, TestSize.Level1)
{
    const std::vector<int32_t> invalidTypes = {3, 99, -1};
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    for (int32_t rawType : invalidTypes) {
        AppClonePreference preference;
        preference.mode = static_cast<AppClonePreferenceMode>(rawType);
        auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR)
            << "rawType=" << rawType << " should be rejected";
    }
}

// Boundary: ALWAYS_ASK (0) and MAIN_APP (1) must NOT be rejected by the type-range check.
// They reach the dataMgr-null branch instead (SERVICE_INTERNAL_ERROR in mock env).
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_BoundaryType_ReachesDataMgrNull_001,
    TestSize.Level1)
{
    const std::vector<AppClonePreferenceMode> boundaryTypes = {
        AppClonePreferenceMode::ALWAYS_ASK,
        AppClonePreferenceMode::MAIN_APP,
    };
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    for (auto mode : boundaryTypes) {
        AppClonePreference preference;
        preference.mode = mode;
        auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
        EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR)
            << "boundary type should reach dataMgr-null branch";
    }
}

HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_CloneAppIndex_Zero_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::CLONE_APP;
    preference.appIndex = 0;
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_APPINDEX_NOT_EXIST);
}

// CLONE_APP appIndex range check rejects everything outside [1,5].
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_CloneAppIndex_Negative_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::CLONE_APP;
    preference.appIndex = -1;
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_APPINDEX_NOT_EXIST);
}

HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_CloneAppIndex_AboveMax_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::CLONE_APP;
    preference.appIndex = 6;
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_APPINDEX_NOT_EXIST);
}

HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_CloneAppIndex_Huge_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::CLONE_APP;
    preference.appIndex = 99999;
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_APPINDEX_NOT_EXIST);
}

// Boundary: appIndex=1 (MIN) and appIndex=5 (MAX) must NOT be rejected by the range check.
// They reach the dataMgr-null branch instead.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_CloneAppIndex_MinBoundary_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::CLONE_APP;
    preference.appIndex = 1;
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_CloneAppIndex_MaxBoundary_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::CLONE_APP;
    preference.appIndex = 5;
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// MAIN_APP and ALWAYS_ASK bypass the appIndex range check entirely (verified by reaching
// the dataMgr-null branch rather than APPINDEX_NOT_EXIST).
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_MainApp_BypassesAppIndexCheck_001,
    TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;
    preference.appIndex = 999;  // would fail the range check if MAIN_APP didn't bypass
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_AlwaysAsk_BypassesAppIndexCheck_001,
    TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::ALWAYS_ASK;
    preference.appIndex = 999;
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// ALWAYS_ASK mode must not be rejected by the disabled-app branch. The disabled branch sits
// behind dataMgr and is exercised in integration tests; here we verify ALWAYS_ASK reaches the
// dataMgr-null branch (never APPLICATION_DISABLED).
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_AlwaysAsk_BypassesDisabledCheck_001,
    TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::ALWAYS_ASK;
    preference.appIndex = 0;
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// -------------------- DeleteAppClonePreference --------------------

// DeleteAppClonePreference returns ERR_OK on every no-op path: empty bundleName short-circuit,
// nonexistent row (DeleteData on empty predicate set), and repeated calls (idempotency).
HWTEST_F(BmsAppClonePreferenceDataMgrTest, DeleteAppClonePreference_NoOpPaths_ReturnOk_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    EXPECT_EQ(dataMgr->DeleteAppClonePreference("", TEST_USER_ID), ERR_OK);
    EXPECT_EQ(dataMgr->DeleteAppClonePreference("com.example.nonexistent.delete", TEST_USER_ID), ERR_OK);
    const std::string bundle = "com.example.delete_idempotent";
    EXPECT_EQ(dataMgr->DeleteAppClonePreference(bundle, TEST_USER_ID), ERR_OK);
    EXPECT_EQ(dataMgr->DeleteAppClonePreference(bundle, TEST_USER_ID), ERR_OK);
    EXPECT_EQ(dataMgr->DeleteAppClonePreference(bundle, TEST_USER_ID), ERR_OK);
}

// Storage null path: Delete must short-circuit to SERVICE_INTERNAL_ERROR.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, DeleteAppClonePreference_NullStorage_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto saved = std::move(dataMgr->storage_);
    dataMgr->storage_ = nullptr;
    EXPECT_EQ(dataMgr->DeleteAppClonePreference(TEST_BUNDLE, TEST_USER_ID),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    dataMgr->storage_ = std::move(saved);
}

// -------------------- HandleAppCloneUninstalled --------------------

// HandleAppCloneUninstalled returns ERR_OK on every no-op path: empty bundleName short-circuit,
// and a nonexistent bundle with no preference record (storage Query returns false → early return).
HWTEST_F(BmsAppClonePreferenceDataMgrTest, HandleAppCloneUninstalled_NoOpPaths_ReturnOk_001,
    TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    EXPECT_EQ(dataMgr->HandleAppCloneUninstalled("", TEST_USER_ID, 1), ERR_OK);
    EXPECT_EQ(dataMgr->HandleAppCloneUninstalled("com.example.no_record", TEST_USER_ID, 1), ERR_OK);
    EXPECT_EQ(dataMgr->HandleAppCloneUninstalled("com.example.no_record", TEST_USER_ID, 2), ERR_OK);
    EXPECT_EQ(dataMgr->HandleAppCloneUninstalled("com.example.other_missing", 0, 1), ERR_OK);
}

HWTEST_F(BmsAppClonePreferenceDataMgrTest, HandleAppCloneUninstalled_NullStorage_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto saved = std::move(dataMgr->storage_);
    dataMgr->storage_ = nullptr;
    EXPECT_EQ(dataMgr->HandleAppCloneUninstalled(TEST_BUNDLE, TEST_USER_ID, 1),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    dataMgr->storage_ = std::move(saved);
}

// Tests below seed storage directly (bypassing Set, which needs BundleDataMgr) to exercise
// HandleAppCloneUninstalled's match-and-switch-to-always-ask branch and its preservation branches.

HWTEST_F(BmsAppClonePreferenceDataMgrTest, HandleAppCloneUninstalled_PreferredCloneMatch_SwitchesToAlwaysAsk_001,
    TestSize.Level1)
{
    const std::string bundle = "com.example.handle_match";
    auto seed = std::make_shared<AppClonePreferenceStorage>();
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::CLONE_APP;
    pref.appIndex = 2;
    ASSERT_TRUE(seed->InsertOrReplace(bundle, TEST_USER_ID, pref));

    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    EXPECT_EQ(dataMgr->HandleAppCloneUninstalled(bundle, TEST_USER_ID, 2), ERR_OK);

    AppClonePreference verify;
    EXPECT_TRUE(seed->Query(bundle, TEST_USER_ID, verify));
    EXPECT_EQ(verify.mode, AppClonePreferenceMode::ALWAYS_ASK);
    EXPECT_EQ(verify.appIndex, 0);
    seed->Delete(bundle, TEST_USER_ID);
}

// CLONE_APP preference but appIndex doesn't match uninstalledAppIndex → preserve.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, HandleAppCloneUninstalled_Clone_AppIndexMismatch_Preserved_001,
    TestSize.Level1)
{
    const std::string bundle = "com.example.handle_nonmatch";
    auto seed = std::make_shared<AppClonePreferenceStorage>();
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::CLONE_APP;
    pref.appIndex = 2;
    ASSERT_TRUE(seed->InsertOrReplace(bundle, TEST_USER_ID, pref));

    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    EXPECT_EQ(dataMgr->HandleAppCloneUninstalled(bundle, TEST_USER_ID, 3), ERR_OK);

    AppClonePreference verify;
    EXPECT_TRUE(seed->Query(bundle, TEST_USER_ID, verify));
    EXPECT_EQ(verify.mode, AppClonePreferenceMode::CLONE_APP);
    EXPECT_EQ(verify.appIndex, 2);
    seed->Delete(bundle, TEST_USER_ID);
}

// MAIN_APP preference: the CLONE_APP+appIndex match is false → preserve.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, HandleAppCloneUninstalled_MainPreference_Preserved_001,
    TestSize.Level1)
{
    const std::string bundle = "com.example.handle_main";
    auto seed = std::make_shared<AppClonePreferenceStorage>();
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::MAIN_APP;
    ASSERT_TRUE(seed->InsertOrReplace(bundle, TEST_USER_ID, pref));

    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    EXPECT_EQ(dataMgr->HandleAppCloneUninstalled(bundle, TEST_USER_ID, 1), ERR_OK);

    AppClonePreference verify;
    EXPECT_TRUE(seed->Query(bundle, TEST_USER_ID, verify));
    EXPECT_EQ(verify.mode, AppClonePreferenceMode::MAIN_APP);
    seed->Delete(bundle, TEST_USER_ID);
}

// ALWAYS_ASK preference: never matches CLONE_APP+appIndex → preserve.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, HandleAppCloneUninstalled_AlwaysAsk_Preserved_001,
    TestSize.Level1)
{
    const std::string bundle = "com.example.handle_alwaysask";
    auto seed = std::make_shared<AppClonePreferenceStorage>();
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::ALWAYS_ASK;
    ASSERT_TRUE(seed->InsertOrReplace(bundle, TEST_USER_ID, pref));

    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    EXPECT_EQ(dataMgr->HandleAppCloneUninstalled(bundle, TEST_USER_ID, 2), ERR_OK);

    AppClonePreference verify;
    EXPECT_TRUE(seed->Query(bundle, TEST_USER_ID, verify));
    EXPECT_EQ(verify.mode, AppClonePreferenceMode::ALWAYS_ASK);
    seed->Delete(bundle, TEST_USER_ID);
}

// MAIN_APP preference with appIndex set to uninstalledAppIndex — still must NOT match because
// mode != CLONE_APP. Verifies the `current.mode == CLONE_APP` short-circuit.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, HandleAppCloneUninstalled_MainPreference_MatchingIdx_Preserved_001,
    TestSize.Level1)
{
    const std::string bundle = "com.example.handle_main_matchidx";
    auto seed = std::make_shared<AppClonePreferenceStorage>();
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::MAIN_APP;
    pref.appIndex = 2;  // matching idx but wrong mode
    ASSERT_TRUE(seed->InsertOrReplace(bundle, TEST_USER_ID, pref));

    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    EXPECT_EQ(dataMgr->HandleAppCloneUninstalled(bundle, TEST_USER_ID, 2), ERR_OK);

    AppClonePreference verify;
    EXPECT_TRUE(seed->Query(bundle, TEST_USER_ID, verify));
    EXPECT_EQ(verify.mode, AppClonePreferenceMode::MAIN_APP);
    seed->Delete(bundle, TEST_USER_ID);
}

// Storage InsertOrReplace fails (rdbDataManager_ null) on match-and-switch-to-always-ask path:
// data_mgr logs but still returns ERR_OK. The original record remains because InsertOrReplace was rejected.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, HandleAppCloneUninstalled_StorageInsertOrReplaceFails_ReturnsOk_001,
    TestSize.Level1)
{
    const std::string bundle = "com.example.handle_delfail";
    auto seed = std::make_shared<AppClonePreferenceStorage>();
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::CLONE_APP;
    pref.appIndex = 2;
    ASSERT_TRUE(seed->InsertOrReplace(bundle, TEST_USER_ID, pref));

    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    // Force data_mgr's storage InsertOrReplace to fail by nulling its rdbDataManager_.
    auto innerStorage = dataMgr->storage_;
    ASSERT_NE(innerStorage, nullptr);
    auto savedRdb = std::move(innerStorage->rdbDataManager_);
    innerStorage->rdbDataManager_ = nullptr;

    EXPECT_EQ(dataMgr->HandleAppCloneUninstalled(bundle, TEST_USER_ID, 2), ERR_OK);

    innerStorage->rdbDataManager_ = std::move(savedRdb);
    seed->Delete(bundle, TEST_USER_ID);
}

// Delete with storage Delete failing (rdbDataManager_ null): data_mgr logs but returns ERR_OK.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, DeleteAppClonePreference_StorageDeleteFails_ReturnsOk_001,
    TestSize.Level1)
{
    const std::string bundle = "com.example.delete_delfail";
    auto seed = std::make_shared<AppClonePreferenceStorage>();
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::MAIN_APP;
    ASSERT_TRUE(seed->InsertOrReplace(bundle, TEST_USER_ID, pref));

    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto innerStorage = dataMgr->storage_;
    ASSERT_NE(innerStorage, nullptr);
    auto savedRdb = std::move(innerStorage->rdbDataManager_);
    innerStorage->rdbDataManager_ = nullptr;

    EXPECT_EQ(dataMgr->DeleteAppClonePreference(bundle, TEST_USER_ID), ERR_OK);

    innerStorage->rdbDataManager_ = std::move(savedRdb);
    seed->Delete(bundle, TEST_USER_ID);
}

// MAIN_APP with default appIndex (0) reaches the dataMgr-null branch — verifies MAIN_APP
// selects MAIN_APP_INDEX as target without consulting preference.appIndex.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_MainApp_DefaultIdx_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;
    preference.appIndex = 0;
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// ALWAYS_ASK with non-zero appIndex — appIndex should be ignored, reaches dataMgr-null branch.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_AlwaysAsk_NonZeroIdx_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::ALWAYS_ASK;
    preference.appIndex = 3;  // ignored — ALWAYS_ASK doesn't reference a specific app
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// GetAppClonePreference with various userIds (boundary: 0 and large) — dataMgr-null branch.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, GetAppClonePreference_UserBoundary_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    AppClonePreference preference;
    EXPECT_EQ(dataMgr->GetAppClonePreference(TEST_BUNDLE, 0, preference),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    EXPECT_EQ(dataMgr->GetAppClonePreference(TEST_BUNDLE, 1, preference),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    EXPECT_EQ(dataMgr->GetAppClonePreference(TEST_BUNDLE, 999, preference),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// GetAppClonePreference with negative userId — there is no userId validation; the call lands
// in the dataMgr-null branch (mock env). Same terminal for any negative userId value.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, GetAppClonePreference_NegativeUserId_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    AppClonePreference preference;
    EXPECT_EQ(dataMgr->GetAppClonePreference(TEST_BUNDLE, -1, preference),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    EXPECT_EQ(dataMgr->GetAppClonePreference(TEST_BUNDLE, -100, preference),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    EXPECT_EQ(dataMgr->GetAppClonePreference(TEST_BUNDLE, INT32_MIN, preference),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// SetAppClonePreference with negative userId — no userId validation; MAIN_APP passes the type
// check, then the dataMgr-null branch fires. Verifies the negative userId does not trigger any
// upstream rejection that would mask the dataMgr-null terminal.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_NegativeUserId_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;
    EXPECT_EQ(dataMgr->SetAppClonePreference(TEST_BUNDLE, -1, preference),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    EXPECT_EQ(dataMgr->SetAppClonePreference(TEST_BUNDLE, -100, preference),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// -------------------- Concurrency --------------------
// Concurrency tests verify eventual consistency under interleaving — DataMgr is intentionally
// lock-free (matches AppControlManagerRdb convention).

HWTEST_F(BmsAppClonePreferenceDataMgrTest, Concurrent_HandleAppCloneUninstalled_SameRow_001, TestSize.Level1)
{
    const std::string bundle = "com.example.concurrent_handle";
    auto seed = std::make_shared<AppClonePreferenceStorage>();
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::CLONE_APP;
    pref.appIndex = 2;
    ASSERT_TRUE(seed->InsertOrReplace(bundle, TEST_USER_ID, pref));

    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    constexpr int threadCount = 8;
    std::vector<std::thread> threads;
    for (int i = 0; i < threadCount; ++i) {
        threads.emplace_back([dataMgr, bundle]() {
            dataMgr->HandleAppCloneUninstalled(bundle, TEST_USER_ID, 2);
        });
    }
    for (auto &t : threads) {
        t.join();
    }
    AppClonePreference verify;
    EXPECT_TRUE(seed->Query(bundle, TEST_USER_ID, verify));
    EXPECT_EQ(verify.mode, AppClonePreferenceMode::ALWAYS_ASK);
    seed->Delete(bundle, TEST_USER_ID);
}

HWTEST_F(BmsAppClonePreferenceDataMgrTest, Concurrent_HandleAppCloneUninstalled_MixedIndexes_001,
    TestSize.Level1)
{
    const std::string bundle = "com.example.concurrent_mixed";
    auto seed = std::make_shared<AppClonePreferenceStorage>();
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::CLONE_APP;
    pref.appIndex = 2;
    ASSERT_TRUE(seed->InsertOrReplace(bundle, TEST_USER_ID, pref));

    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([dataMgr, bundle, i]() {
            dataMgr->HandleAppCloneUninstalled(bundle, TEST_USER_ID, i + 10);
        });
    }
    threads.emplace_back([dataMgr, bundle]() {
        dataMgr->HandleAppCloneUninstalled(bundle, TEST_USER_ID, 2);
    });
    for (auto &t : threads) {
        t.join();
    }
    AppClonePreference verify;
    EXPECT_TRUE(seed->Query(bundle, TEST_USER_ID, verify));
    EXPECT_EQ(verify.mode, AppClonePreferenceMode::ALWAYS_ASK);
    seed->Delete(bundle, TEST_USER_ID);
}

HWTEST_F(BmsAppClonePreferenceDataMgrTest, Concurrent_SetAppClonePreference_InvalidType_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    constexpr int threadCount = 16;
    std::atomic<int> paramErrorCount{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < threadCount; ++i) {
        threads.emplace_back([dataMgr, &paramErrorCount]() {
            AppClonePreference preference;
            preference.mode = static_cast<AppClonePreferenceMode>(99);
            auto ret = dataMgr->SetAppClonePreference("com.example.concurrent_bad_type", TEST_USER_ID,
                preference);
            if (ret == ERR_BUNDLE_MANAGER_PARAM_ERROR) {
                paramErrorCount.fetch_add(1);
            }
        });
    }
    for (auto &t : threads) {
        t.join();
    }
    EXPECT_EQ(paramErrorCount.load(), threadCount);
}

HWTEST_F(BmsAppClonePreferenceDataMgrTest, Concurrent_Delete_And_Handle_NoCrash_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    auto seed = std::make_shared<AppClonePreferenceStorage>();
    const std::string bundle = "com.example.concurrent_del_handle";
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::MAIN_APP;
    ASSERT_TRUE(seed->InsertOrReplace(bundle, TEST_USER_ID, pref));

    std::vector<std::thread> threads;
    for (int i = 0; i < 5; ++i) {
        threads.emplace_back([dataMgr, bundle]() {
            dataMgr->DeleteAppClonePreference(bundle, TEST_USER_ID);
        });
        threads.emplace_back([dataMgr, bundle, i]() {
            dataMgr->HandleAppCloneUninstalled(bundle, TEST_USER_ID, i);
        });
    }
    for (auto &t : threads) {
        t.join();
    }
    // After the storm, InsertOrReplace + Query must still work (DB not corrupted).
    AppClonePreference verify;
    EXPECT_TRUE(seed->InsertOrReplace(bundle, TEST_USER_ID, pref));
    EXPECT_TRUE(seed->Query(bundle, TEST_USER_ID, verify));
    seed->Delete(bundle, TEST_USER_ID);
}

// -------------------- Branch-coverage extensions for Set/Get --------------------

// SetAppClonePreference storage_-null path is shadowed by the dataMgr-null branch in mock env,
// mirroring the Get side. Setting storage_=nullptr must NOT change the terminal ErrCode.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_StorageNull_ShadowedByDataMgrNull_001,
    TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto saved = std::move(dataMgr->storage_);
    dataMgr->storage_ = nullptr;
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    dataMgr->storage_ = std::move(saved);
}

// SetAppClonePreference storage_-null with CLONE_APP — same shadow: storage_ null cannot change
// the terminal because dataMgr-null returns first. Verifies shadow holds across preference types.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_StorageNull_CloneApp_Shadowed_001,
    TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto saved = std::move(dataMgr->storage_);
    dataMgr->storage_ = nullptr;
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::CLONE_APP;
    preference.appIndex = 2;
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    dataMgr->storage_ = std::move(saved);
}

// GetAppClonePreference with a seeded storage record — verifies that the dataMgr-null check fires
// BEFORE the storage Query, so even an existing record cannot short-circuit the dataMgr-null
// terminal. Confirms the check ordering documented in the source.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, GetAppClonePreference_WithSeededStorage_HitsDataMgrNull_001,
    TestSize.Level1)
{
    const std::string bundle = "com.example.get_seeded";
    auto seed = std::make_shared<AppClonePreferenceStorage>();
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::MAIN_APP;
    ASSERT_TRUE(seed->InsertOrReplace(bundle, TEST_USER_ID, pref));

    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    AppClonePreference out;
    auto ret = dataMgr->GetAppClonePreference(bundle, TEST_USER_ID, out);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    seed->Delete(bundle, TEST_USER_ID);
}

// SetAppClonePreference with a seeded storage record — same ordering check: the existing record
// cannot make the dataMgr-null branch reachable-past. Output storage remains untouched.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_WithSeededStorage_HitsDataMgrNull_001,
    TestSize.Level1)
{
    const std::string bundle = "com.example.set_seeded";
    auto seed = std::make_shared<AppClonePreferenceStorage>();
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::MAIN_APP;
    ASSERT_TRUE(seed->InsertOrReplace(bundle, TEST_USER_ID, pref));

    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    AppClonePreference newPref;
    newPref.mode = AppClonePreferenceMode::ALWAYS_ASK;
    auto ret = dataMgr->SetAppClonePreference(bundle, TEST_USER_ID, newPref);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);

    // Original record must remain unchanged because Set never reached storage.
    AppClonePreference verify;
    EXPECT_TRUE(seed->Query(bundle, TEST_USER_ID, verify));
    EXPECT_EQ(verify.mode, AppClonePreferenceMode::MAIN_APP);
    seed->Delete(bundle, TEST_USER_ID);
}

// SetAppClonePreference CLONE_APP middle in-range appIndex values (2, 3, 4) — these are between
// MIN=1 and MAX=5; they must all bypass the range check and reach the dataMgr-null branch.
// Existing tests cover only the boundary values 1 and 5; this fills the middle of the range.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_CloneApp_MiddleIndexes_001,
    TestSize.Level1)
{
    const std::vector<int32_t> middleIndexes = {2, 3, 4};
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    for (int32_t idx : middleIndexes) {
        AppClonePreference preference;
        preference.mode = AppClonePreferenceMode::CLONE_APP;
        preference.appIndex = idx;
        auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
        EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR)
            << "appIndex=" << idx << " should bypass range check and reach dataMgr-null";
    }
}

// Validation ordering: CLONE_APP with both invalid type AND invalid appIndex must return
// PARAM_ERROR (type check fires first). Verifies the short-circuit order between Branch A
// (type range) and Branch B (appIndex range for CLONE_APP).
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_InvalidType_ShadowsInvalidAppIndex_001,
    TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    AppClonePreference preference;
    preference.mode = static_cast<AppClonePreferenceMode>(99);  // invalid type
    preference.appIndex = 0;  // would fail CLONE_APP range check if mode were valid
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

// Validation ordering: empty bundleName + invalid type + invalid appIndex must return
// BUNDLE_NAME_IS_EMPTY (name check fires first). Verifies the short-circuit order between
// the empty-name check and the type/appIndex checks.
HWTEST_F(BmsAppClonePreferenceDataMgrTest,
    SetAppClonePreference_EmptyName_ShadowsInvalidTypeAndAppIndex_001, TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    AppClonePreference preference;
    preference.mode = static_cast<AppClonePreferenceMode>(99);
    preference.appIndex = 0;
    auto ret = dataMgr->SetAppClonePreference("", TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NAME_IS_EMPTY);
}

// GetAppClonePreference with valid range types (ALWAYS_ASK, MAIN_APP, CLONE_APP) — verifies Get
// has no type validation (unlike Set); all mode values pass through to dataMgr-null uniformly.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, GetAppClonePreference_AllModes_ReachDataMgrNull_001,
    TestSize.Level1)
{
    const std::vector<AppClonePreferenceMode> modes = {
        AppClonePreferenceMode::ALWAYS_ASK,
        AppClonePreferenceMode::MAIN_APP,
        AppClonePreferenceMode::CLONE_APP,
    };
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    for (auto mode : modes) {
        AppClonePreference preference;
        preference.mode = mode;
        auto ret = dataMgr->GetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
        EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR)
            << "Get has no type validation; mode=" << static_cast<int32_t>(mode)
            << " should reach dataMgr-null";
    }
}

// GetAppClonePreference with seeded storage + storage_=nullptr — verifies that even when a
// record exists, nulling storage_ does NOT change the dataMgr-null terminal. Confirms the
// storage_ check is unreachable past dataMgr-null in mock env, regardless of seeded state.
HWTEST_F(BmsAppClonePreferenceDataMgrTest,
    GetAppClonePreference_SeededRecord_StorageNull_Shadowed_001, TestSize.Level1)
{
    const std::string bundle = "com.example.get_seeded_storage_null";
    auto seed = std::make_shared<AppClonePreferenceStorage>();
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::CLONE_APP;
    pref.appIndex = 2;
    ASSERT_TRUE(seed->InsertOrReplace(bundle, TEST_USER_ID, pref));

    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto saved = std::move(dataMgr->storage_);
    dataMgr->storage_ = nullptr;
    AppClonePreference out;
    auto ret = dataMgr->GetAppClonePreference(bundle, TEST_USER_ID, out);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    dataMgr->storage_ = std::move(saved);
    seed->Delete(bundle, TEST_USER_ID);
}

// GetAppClonePreference dataMgr-null terminal with multiple distinct bundleNames in one call
// sequence — verifies the dataMgr-null branch is consistent across bundleName identities.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, GetAppClonePreference_MultipleBundles_DataMgrNull_001,
    TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    const std::vector<std::string> bundles = {
        "com.example.a", "com.example.b", "com.example.c", "com.example.d",
    };
    for (const auto &bundle : bundles) {
        AppClonePreference preference;
        auto ret = dataMgr->GetAppClonePreference(bundle, TEST_USER_ID, preference);
        EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR)
            << "bundle=" << bundle << " should reach dataMgr-null";
    }
}

// SetAppClonePreference ALWAYS_ASK with negative appIndex — the appIndex range check applies
// only to CLONE_APP; ALWAYS_ASK must bypass it regardless of appIndex value.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_AlwaysAsk_NegativeAppIndex_001,
    TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::ALWAYS_ASK;
    preference.appIndex = -1;
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// SetAppClonePreference MAIN_APP with negative appIndex — same bypass: MAIN_APP does not
// consult appIndex in the range check.
HWTEST_F(BmsAppClonePreferenceDataMgrTest, SetAppClonePreference_MainApp_NegativeAppIndex_001,
    TestSize.Level1)
{
    auto dataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;
    preference.appIndex = -100;
    auto ret = dataMgr->SetAppClonePreference(TEST_BUNDLE, TEST_USER_ID, preference);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}
