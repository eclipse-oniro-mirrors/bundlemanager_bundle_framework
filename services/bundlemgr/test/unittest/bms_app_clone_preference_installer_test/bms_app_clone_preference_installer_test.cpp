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

#define private public

#include <gtest/gtest.h>

#include "app_clone_preference_storage.h"
#include "bundle_clone_installer.h"
#include "system_bundle_installer.h"

#include "appexecfwk_errors.h"
#include "bundle_mgr_service.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

// In the mock test env, BundleMgrService::GetAppClonePreferenceDataMgr() returns nullptr
// (see services/bundlemgr/test/mock/src/bundle_mgr_service.cpp), so HandleAppClonePreferenceOnUninstall
// and RemoveAppClonePreference both hit the null-safe early-return. Tests below seed bmsdb.db
// via an external AppClonePreferenceStorage to verify that, with prefDataMgr null, the seeded
// record is PRESERVED (i.e. the null branch is taken and no DB action happens).

namespace {
constexpr int32_t TEST_USERID = 100;
constexpr int32_t TEST_CLONE_APP_INDEX = 2;
const std::string TEST_BUNDLE_NAME = "com.example.app_clone_pref_installer";
}

class BmsAppClonePreferenceInstallerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override
    {
        auto storage = std::make_shared<AppClonePreferenceStorage>();
        if (storage != nullptr) {
            storage->Delete(TEST_BUNDLE_NAME, TEST_USERID);
        }
    }
};

// -------------------- BundleCloneInstaller::HandleAppClonePreferenceOnUninstall --------------------

// HandleAppClonePreferenceOnUninstall must not throw on any null-safe path: with the mock env's
// null prefDataMgr (general case), and with an empty bundleName (short-circuit path). Both
// branches return without touching the DB.
HWTEST_F(BmsAppClonePreferenceInstallerTest, HandleAppClonePreference_NullDataMgr_NoThrow_001,
    TestSize.Level1)
{
    auto installer = std::make_unique<BundleCloneInstaller>();
    ASSERT_NE(installer, nullptr);
    EXPECT_NO_THROW(installer->HandleAppClonePreferenceOnUninstall(TEST_BUNDLE_NAME, TEST_USERID,
        TEST_CLONE_APP_INDEX));
    EXPECT_NO_THROW(installer->HandleAppClonePreferenceOnUninstall("", TEST_USERID,
        TEST_CLONE_APP_INDEX));
    EXPECT_NO_THROW(installer->HandleAppClonePreferenceOnUninstall("", 0, TEST_CLONE_APP_INDEX));
}

// Mock env: prefDataMgr is nullptr → null-safe branch returns without touching DB.
// Verify the seeded record survives (no cleanup happened).
HWTEST_F(BmsAppClonePreferenceInstallerTest, HandleAppClonePreference_NullDataMgr_PreservesSeed_001,
    TestSize.Level1)
{
    auto seed = std::make_shared<AppClonePreferenceStorage>();
    ASSERT_NE(seed, nullptr);
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::CLONE_APP;
    pref.appIndex = TEST_CLONE_APP_INDEX;
    ASSERT_TRUE(seed->InsertOrReplace(TEST_BUNDLE_NAME, TEST_USERID, pref));

    auto installer = std::make_unique<BundleCloneInstaller>();
    ASSERT_NE(installer, nullptr);
    EXPECT_NO_THROW(installer->HandleAppClonePreferenceOnUninstall(TEST_BUNDLE_NAME, TEST_USERID,
        TEST_CLONE_APP_INDEX));

    AppClonePreference verify;
    EXPECT_TRUE(seed->Query(TEST_BUNDLE_NAME, TEST_USERID, verify));
    EXPECT_EQ(verify.mode, AppClonePreferenceMode::CLONE_APP);
    EXPECT_EQ(verify.appIndex, TEST_CLONE_APP_INDEX);
}

// -------------------- BaseBundleInstaller::RemoveAppClonePreference --------------------

// RemoveAppClonePreference must not throw on any null-safe path: with the mock env's null
// prefDataMgr (general case), and with an empty bundleName (short-circuit path).
HWTEST_F(BmsAppClonePreferenceInstallerTest, RemoveAppClonePreference_NullDataMgr_NoThrow_001,
    TestSize.Level1)
{
    auto installer = std::make_unique<SystemBundleInstaller>();
    ASSERT_NE(installer, nullptr);
    EXPECT_NO_THROW(installer->RemoveAppClonePreference(TEST_BUNDLE_NAME, TEST_USERID));
    EXPECT_NO_THROW(installer->RemoveAppClonePreference("", TEST_USERID));
    EXPECT_NO_THROW(installer->RemoveAppClonePreference("", 0));
    EXPECT_NO_THROW(installer->RemoveAppClonePreference(TEST_BUNDLE_NAME, 0));
}

// Mock env: prefDataMgr is nullptr → null-safe branch returns without touching DB.
// Verify the seeded MAIN_APP record survives.
HWTEST_F(BmsAppClonePreferenceInstallerTest, RemoveAppClonePreference_NullDataMgr_PreservesSeed_001,
    TestSize.Level1)
{
    auto seed = std::make_shared<AppClonePreferenceStorage>();
    ASSERT_NE(seed, nullptr);
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::MAIN_APP;
    ASSERT_TRUE(seed->InsertOrReplace(TEST_BUNDLE_NAME, TEST_USERID, pref));

    auto installer = std::make_unique<SystemBundleInstaller>();
    ASSERT_NE(installer, nullptr);
    EXPECT_NO_THROW(installer->RemoveAppClonePreference(TEST_BUNDLE_NAME, TEST_USERID));

    AppClonePreference verify;
    EXPECT_TRUE(seed->Query(TEST_BUNDLE_NAME, TEST_USERID, verify));
    EXPECT_EQ(verify.mode, AppClonePreferenceMode::MAIN_APP);
}
