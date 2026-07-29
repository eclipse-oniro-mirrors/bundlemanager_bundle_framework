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

#define private public
#include "app_clone_preference_storage.h"
#undef private

using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace testing;
using namespace testing::ext;

namespace {
constexpr int32_t MAIN_USER_ID = 100;
constexpr int32_t SECONDARY_USER_ID = 101;
}

class BmsAppClonePreferenceStorageTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        storage_ = std::make_shared<AppClonePreferenceStorage>();
    }
    void TearDown() override
    {
        if (storage_ != nullptr) {
            for (const auto &name : cleanupList_) {
                storage_->Delete(name, MAIN_USER_ID);
                storage_->Delete(name, SECONDARY_USER_ID);
            }
        }
    }
    std::shared_ptr<AppClonePreferenceStorage> storage_;
    std::vector<std::string> cleanupList_ = {
        "com.example.app_st01", "com.example.app_st02",
        "com.example.app_st03", "com.example.app_st05", "com.example.app_st07",
        "com.example.app_st08", "com.example.app_st09", "com.example.app_st_overwrite",
        "com.example.app_st_seq",
        "com.example.app_st07b", "com.example.app_st08b", "com.example.app_st09b",
        "com.example.app_st15a", "com.example.app_st16",
        "com.example.app_st_neg_uid", "com.example.app_st_zero_uid",
        "com.example.app_st_idempotent", "com.example.app_st_clone_overwrite",
        "com.example.app_st_crossmode", "com.example.app_st_other_row",
        "",  // empty-key InsertOrReplace_EmptyBundleName_Persists_001
    };
};

// -------------------- InsertOrReplace happy paths --------------------

HWTEST_F(BmsAppClonePreferenceStorageTest, InsertOrReplace_NewRow_Main_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st01";
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;
    preference.appIndex = 0;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, preference));

    AppClonePreference result;
    EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, result));
    EXPECT_EQ(result.mode, AppClonePreferenceMode::MAIN_APP);
    EXPECT_EQ(result.appIndex, 0);
}

HWTEST_F(BmsAppClonePreferenceStorageTest, InsertOrReplace_Replace_ChangesModeAndIndex_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st02";
    AppClonePreference first;
    first.mode = AppClonePreferenceMode::MAIN_APP;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, first));

    AppClonePreference second;
    second.mode = AppClonePreferenceMode::CLONE_APP;
    second.appIndex = 2;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, second));

    AppClonePreference result;
    EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, result));
    EXPECT_EQ(result.mode, AppClonePreferenceMode::CLONE_APP);
    EXPECT_EQ(result.appIndex, 2);
}

HWTEST_F(BmsAppClonePreferenceStorageTest, InsertOrReplace_SequentialReplacements_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st_seq";
    AppClonePreference p1; p1.mode = AppClonePreferenceMode::MAIN_APP;
    AppClonePreference p2; p2.mode = AppClonePreferenceMode::ALWAYS_ASK;
    AppClonePreference p3; p3.mode = AppClonePreferenceMode::CLONE_APP; p3.appIndex = 3;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, p1));
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, p2));
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, p3));

    AppClonePreference result;
    EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, result));
    EXPECT_EQ(result.mode, AppClonePreferenceMode::CLONE_APP);
    EXPECT_EQ(result.appIndex, 3);
}

HWTEST_F(BmsAppClonePreferenceStorageTest, InsertOrReplace_OverwriteAlwaysAsk_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st_overwrite";
    AppClonePreference first;
    first.mode = AppClonePreferenceMode::ALWAYS_ASK;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, first));
    AppClonePreference second;
    second.mode = AppClonePreferenceMode::CLONE_APP;
    second.appIndex = 4;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, second));
    AppClonePreference result;
    EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, result));
    EXPECT_EQ(result.mode, AppClonePreferenceMode::CLONE_APP);
    EXPECT_EQ(result.appIndex, 4);
}

// -------------------- Query paths --------------------

HWTEST_F(BmsAppClonePreferenceStorageTest, Query_Hit_Clone_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st03";
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::CLONE_APP;
    preference.appIndex = 3;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, preference));

    AppClonePreference result;
    EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, result));
    EXPECT_EQ(result.mode, AppClonePreferenceMode::CLONE_APP);
    EXPECT_EQ(result.appIndex, 3);
}

// Query on never-inserted bundleName returns false (count==0 branch). Multiple nonexistent
// keys are checked to ensure the count==0 branch is robust to key shape (dotted, plain, etc.).
HWTEST_F(BmsAppClonePreferenceStorageTest, Query_NotHit_NonexistentBundle_001, TestSize.Level1)
{
    AppClonePreference result;
    result.mode = AppClonePreferenceMode::MAIN_APP;  // pre-set; Query must NOT overwrite on miss
    EXPECT_FALSE(storage_->Query("com.example.app_st04_nonexistent", MAIN_USER_ID, result));
    EXPECT_FALSE(storage_->Query("nonexistent", MAIN_USER_ID, result));
    EXPECT_FALSE(storage_->Query("com.example.app_st04_other", MAIN_USER_ID, result));
    EXPECT_EQ(result.mode, AppClonePreferenceMode::MAIN_APP);  // unchanged on miss
}

// Query with different bundleName same user returns false (PK bundleName column).
HWTEST_F(BmsAppClonePreferenceStorageTest, Query_NotHit_DifferentBundleName_001, TestSize.Level1)
{
    const std::string bundleA = "com.example.app_st15a";
    const std::string bundleB = "com.example.app_st15b";  // not in cleanup list intentionally
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::MAIN_APP;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleA, MAIN_USER_ID, pref));
    AppClonePreference result;
    EXPECT_FALSE(storage_->Query(bundleB, MAIN_USER_ID, result));
    storage_->Delete(bundleB, MAIN_USER_ID);
}

// -------------------- Delete paths --------------------

HWTEST_F(BmsAppClonePreferenceStorageTest, Delete_Existing_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st05";
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, preference));

    EXPECT_TRUE(storage_->Delete(bundleName, MAIN_USER_ID));
    AppClonePreference result;
    EXPECT_FALSE(storage_->Query(bundleName, MAIN_USER_ID, result));
}

// Delete on nonexistent rows is idempotent — DeleteData on empty predicate set succeeds.
// Repeated calls on the same nonexistent key, on different nonexistent keys, and on the
// empty-bundleName key all return true (no rows touched, no PK violation).
HWTEST_F(BmsAppClonePreferenceStorageTest, Delete_Nonexistent_Idempotent_001, TestSize.Level1)
{
    const std::string key = "com.example.app_st06_nonexistent";
    EXPECT_TRUE(storage_->Delete(key, MAIN_USER_ID));
    EXPECT_TRUE(storage_->Delete(key, MAIN_USER_ID));
    EXPECT_TRUE(storage_->Delete("com.example.app_st06_other_missing", MAIN_USER_ID));
    EXPECT_TRUE(storage_->Delete("", MAIN_USER_ID));
    AppClonePreference result;
    EXPECT_FALSE(storage_->Query(key, MAIN_USER_ID, result));
}

// -------------------- User isolation --------------------

HWTEST_F(BmsAppClonePreferenceStorageTest, UserIsolation_InsertQuery_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st07";
    AppClonePreference prefA;
    prefA.mode = AppClonePreferenceMode::MAIN_APP;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, prefA));

    AppClonePreference resultB;
    EXPECT_FALSE(storage_->Query(bundleName, SECONDARY_USER_ID, resultB));

    AppClonePreference prefB;
    prefB.mode = AppClonePreferenceMode::CLONE_APP;
    prefB.appIndex = 1;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, SECONDARY_USER_ID, prefB));

    AppClonePreference resultA;
    EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, resultA));
    EXPECT_EQ(resultA.mode, AppClonePreferenceMode::MAIN_APP);

    EXPECT_TRUE(storage_->Query(bundleName, SECONDARY_USER_ID, resultB));
    EXPECT_EQ(resultB.mode, AppClonePreferenceMode::CLONE_APP);
}

HWTEST_F(BmsAppClonePreferenceStorageTest, UserIsolation_DeleteOne_PreservesOther_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st07b";
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::MAIN_APP;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, pref));
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, SECONDARY_USER_ID, pref));

    EXPECT_TRUE(storage_->Delete(bundleName, MAIN_USER_ID));
    AppClonePreference result;
    EXPECT_FALSE(storage_->Query(bundleName, MAIN_USER_ID, result));
    EXPECT_TRUE(storage_->Query(bundleName, SECONDARY_USER_ID, result));
}

// -------------------- Boundary coverage --------------------

HWTEST_F(BmsAppClonePreferenceStorageTest, AppIndex_Boundary_MinMax_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st08";
    for (int32_t idx : {1, 5}) {
        AppClonePreference preference;
        preference.mode = AppClonePreferenceMode::CLONE_APP;
        preference.appIndex = idx;
        EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, preference));
        AppClonePreference result;
        EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, result));
        EXPECT_EQ(result.appIndex, idx);
    }
}

HWTEST_F(BmsAppClonePreferenceStorageTest, AppIndex_Zero_ForNonClone_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st08b";
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;
    preference.appIndex = 0;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, preference));
    AppClonePreference result;
    EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, result));
    EXPECT_EQ(result.appIndex, 0);
}

HWTEST_F(BmsAppClonePreferenceStorageTest, AllEnumTypes_Roundtrip_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st09";
    const std::vector<std::pair<AppClonePreferenceMode, int32_t>> cases = {
        {AppClonePreferenceMode::ALWAYS_ASK, 0},
        {AppClonePreferenceMode::MAIN_APP, 0},
        {AppClonePreferenceMode::CLONE_APP, 2},
    };
    for (const auto &c : cases) {
        AppClonePreference preference;
        preference.mode = c.first;
        preference.appIndex = c.second;
        EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, preference));
        AppClonePreference result;
        EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, result));
        EXPECT_EQ(result.mode, c.first);
        EXPECT_EQ(result.appIndex, c.second);
    }
}

HWTEST_F(BmsAppClonePreferenceStorageTest, AllCloneIndices_Roundtrip_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st09b";
    for (int32_t idx = 1; idx <= 5; ++idx) {
        AppClonePreference preference;
        preference.mode = AppClonePreferenceMode::CLONE_APP;
        preference.appIndex = idx;
        EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, preference));
        AppClonePreference result;
        EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, result));
        EXPECT_EQ(result.mode, AppClonePreferenceMode::CLONE_APP);
        EXPECT_EQ(result.appIndex, idx);
    }
}

// -------------------- Full CRUD sequence --------------------

HWTEST_F(BmsAppClonePreferenceStorageTest, FullCRUDSequence_CloneBoundary_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st16";
    AppClonePreference insert;
    insert.mode = AppClonePreferenceMode::CLONE_APP;
    insert.appIndex = 5;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, insert));

    AppClonePreference query;
    EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, query));
    EXPECT_EQ(query.mode, AppClonePreferenceMode::CLONE_APP);
    EXPECT_EQ(query.appIndex, 5);

    EXPECT_TRUE(storage_->Delete(bundleName, MAIN_USER_ID));
    EXPECT_FALSE(storage_->Query(bundleName, MAIN_USER_ID, query));
}

// -------------------- Null rdbDataManager branches --------------------
// Each method must degrade gracefully when rdbDataManager_ is missing. We inject nullptr
// via `#define private public`.

HWTEST_F(BmsAppClonePreferenceStorageTest, InsertOrReplace_NullRdbDataManager_001, TestSize.Level1)
{
    auto storage = std::make_shared<AppClonePreferenceStorage>();
    ASSERT_NE(storage, nullptr);
    auto saved = std::move(storage->rdbDataManager_);
    storage->rdbDataManager_ = nullptr;
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;
    EXPECT_FALSE(storage->InsertOrReplace("com.example.app_st12", MAIN_USER_ID, preference));
    storage->rdbDataManager_ = std::move(saved);
}

HWTEST_F(BmsAppClonePreferenceStorageTest, Query_NullRdbDataManager_001, TestSize.Level1)
{
    auto storage = std::make_shared<AppClonePreferenceStorage>();
    ASSERT_NE(storage, nullptr);
    auto saved = std::move(storage->rdbDataManager_);
    storage->rdbDataManager_ = nullptr;
    AppClonePreference result;
    EXPECT_FALSE(storage->Query("com.example.app_st13", MAIN_USER_ID, result));
    storage->rdbDataManager_ = std::move(saved);
}

HWTEST_F(BmsAppClonePreferenceStorageTest, Delete_NullRdbDataManager_001, TestSize.Level1)
{
    auto storage = std::make_shared<AppClonePreferenceStorage>();
    ASSERT_NE(storage, nullptr);
    auto saved = std::move(storage->rdbDataManager_);
    storage->rdbDataManager_ = nullptr;
    EXPECT_FALSE(storage->Delete("com.example.app_st14", MAIN_USER_ID));
    storage->rdbDataManager_ = std::move(saved);
}

// -------------------- Additional edge-case branches --------------------

// Insert with empty bundleName — InsertOrReplace succeeds (no PK violation on empty key),
// the row is queryable by the same empty key. Demonstrates that storage does no input
// validation; that responsibility belongs to DataMgr.
HWTEST_F(BmsAppClonePreferenceStorageTest, InsertOrReplace_EmptyBundleName_Persists_001, TestSize.Level1)
{
    const std::string bundleName = "";  // empty key
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, preference));
    AppClonePreference result;
    EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, result));
    EXPECT_EQ(result.mode, AppClonePreferenceMode::MAIN_APP);
    EXPECT_TRUE(storage_->Delete(bundleName, MAIN_USER_ID));
}

// Insert with negative userId — storage has no userId validation; the row is queryable.
HWTEST_F(BmsAppClonePreferenceStorageTest, InsertOrReplace_NegativeUserId_Persists_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st_neg_uid";
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, -1, preference));
    AppClonePreference result;
    EXPECT_TRUE(storage_->Query(bundleName, -1, result));
    EXPECT_EQ(result.mode, AppClonePreferenceMode::MAIN_APP);
    EXPECT_TRUE(storage_->Delete(bundleName, -1));
}

// Insert with userId=0 — boundary; storage accepts it (no validation).
HWTEST_F(BmsAppClonePreferenceStorageTest, InsertOrReplace_ZeroUserId_Persists_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st_zero_uid";
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::CLONE_APP;
    preference.appIndex = 1;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, 0, preference));
    AppClonePreference result;
    EXPECT_TRUE(storage_->Query(bundleName, 0, result));
    EXPECT_EQ(result.mode, AppClonePreferenceMode::CLONE_APP);
    EXPECT_EQ(result.appIndex, 1);
    EXPECT_TRUE(storage_->Delete(bundleName, 0));
}

// InsertOrReplace is idempotent: same payload written twice yields one row with same content.
HWTEST_F(BmsAppClonePreferenceStorageTest, InsertOrReplace_SamePayload_Idempotent_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st_idempotent";
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, preference));
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, preference));
    AppClonePreference result;
    EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, result));
    EXPECT_EQ(result.mode, AppClonePreferenceMode::MAIN_APP);
    EXPECT_TRUE(storage_->Delete(bundleName, MAIN_USER_ID));
}

// Overwrite CLONE_APP at same bundleName+userId with different appIndex — Query returns the
// most-recent appIndex (the row is replaced, not appended).
HWTEST_F(BmsAppClonePreferenceStorageTest, InsertOrReplace_CloneAppIndex_Overwritten_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st_clone_overwrite";
    AppClonePreference first;
    first.mode = AppClonePreferenceMode::CLONE_APP;
    first.appIndex = 1;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, first));
    AppClonePreference second;
    second.mode = AppClonePreferenceMode::CLONE_APP;
    second.appIndex = 4;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, second));
    AppClonePreference result;
    EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, result));
    EXPECT_EQ(result.appIndex, 4);
    EXPECT_TRUE(storage_->Delete(bundleName, MAIN_USER_ID));
}

// Cross-mode transition: MAIN_APP → ALWAYS_ASK → CLONE_APP(3). Query returns the latest state.
HWTEST_F(BmsAppClonePreferenceStorageTest, InsertOrReplace_CrossModeTransitions_001, TestSize.Level1)
{
    const std::string bundleName = "com.example.app_st_crossmode";
    AppClonePreference main; main.mode = AppClonePreferenceMode::MAIN_APP;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, main));
    AppClonePreference alwaysAsk; alwaysAsk.mode = AppClonePreferenceMode::ALWAYS_ASK;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, alwaysAsk));
    AppClonePreference verify1;
    EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, verify1));
    EXPECT_EQ(verify1.mode, AppClonePreferenceMode::ALWAYS_ASK);
    AppClonePreference clone;
    clone.mode = AppClonePreferenceMode::CLONE_APP;
    clone.appIndex = 3;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleName, MAIN_USER_ID, clone));
    AppClonePreference verify2;
    EXPECT_TRUE(storage_->Query(bundleName, MAIN_USER_ID, verify2));
    EXPECT_EQ(verify2.mode, AppClonePreferenceMode::CLONE_APP);
    EXPECT_EQ(verify2.appIndex, 3);
    EXPECT_TRUE(storage_->Delete(bundleName, MAIN_USER_ID));
}

// Empty-bundleName Delete after a non-empty insert does NOT clear the non-empty row.
HWTEST_F(BmsAppClonePreferenceStorageTest, Delete_EmptyBundleName_DoesNotClearOtherRows_001, TestSize.Level1)
{
    const std::string bundleA = "com.example.app_st_other_row";
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::MAIN_APP;
    EXPECT_TRUE(storage_->InsertOrReplace(bundleA, MAIN_USER_ID, pref));
    EXPECT_TRUE(storage_->Delete("", MAIN_USER_ID));
    AppClonePreference result;
    EXPECT_TRUE(storage_->Query(bundleA, MAIN_USER_ID, result));
    EXPECT_EQ(result.mode, AppClonePreferenceMode::MAIN_APP);
    EXPECT_TRUE(storage_->Delete(bundleA, MAIN_USER_ID));
}
