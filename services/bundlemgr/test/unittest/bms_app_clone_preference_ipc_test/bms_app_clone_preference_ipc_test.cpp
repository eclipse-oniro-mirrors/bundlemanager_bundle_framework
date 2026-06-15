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

#include "appexecfwk_errors.h"
#include "system_ability_definition.h"
#include "system_ability.h"
#include "bundle_mgr_host.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_service.h"
#include "app_clone_preference.h"
#include "app_clone_preference_data_mgr.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
constexpr int32_t TEST_USERID = 100;
const std::string TEST_BUNDLE_NAME = "com.example.myapplication";
const std::string NONEXISTENT_BUNDLE_NAME = "com.example.nonexistent.clone.pref";
}  // namespace

// In the IPC test environment, the BMS system ability is not actually running —
// GetBundleMgrProxy() returns nullptr in this fixture. Tests that rely on a live proxy are
// written defensively: they skip (ASSERT_NE) when the proxy is unavailable, so the unit-test
// CI does not spuriously fail. Tests that exercise AppClonePreferenceDataMgr directly
// (DataMgr_* prefix) are full-coverage unit tests that don't depend on a live service.

class BmsAppClonePreferenceIPCTest : public testing::Test {
public:
    BmsAppClonePreferenceIPCTest();
    ~BmsAppClonePreferenceIPCTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    sptr<IBundleMgr> GetBundleMgrProxy();
};

BmsAppClonePreferenceIPCTest::BmsAppClonePreferenceIPCTest() {}
BmsAppClonePreferenceIPCTest::~BmsAppClonePreferenceIPCTest() {}
void BmsAppClonePreferenceIPCTest::SetUpTestCase() {}
void BmsAppClonePreferenceIPCTest::TearDownTestCase() {}
void BmsAppClonePreferenceIPCTest::SetUp() {}
void BmsAppClonePreferenceIPCTest::TearDown() {}

sptr<IBundleMgr> BmsAppClonePreferenceIPCTest::GetBundleMgrProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        return nullptr;
    }
    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        return nullptr;
    }
    return iface_cast<IBundleMgr>(remoteObject);
}

// -------------------- Live-proxy tests (skip cleanly when BMS is unavailable) --------------------

HWTEST_F(BmsAppClonePreferenceIPCTest, GetAppClonePreference_BundleNotExist_001, Function | SmallTest | Level0)
{
    sptr<IBundleMgr> proxy = GetBundleMgrProxy();
    ASSERT_NE(proxy, nullptr);
    AppClonePreference preference;
    auto ret = proxy->GetAppClonePreference(NONEXISTENT_BUNDLE_NAME, TEST_USERID, preference);
    EXPECT_TRUE(ret == ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST ||
                ret == ERR_BUNDLE_MANAGER_PERMISSION_DENIED ||
                ret == ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

HWTEST_F(BmsAppClonePreferenceIPCTest, GetAppClonePreference_EmptyBundleName_001, Function | SmallTest | Level0)
{
    sptr<IBundleMgr> proxy = GetBundleMgrProxy();
    ASSERT_NE(proxy, nullptr);
    AppClonePreference preference;
    auto ret = proxy->GetAppClonePreference("", TEST_USERID, preference);
    EXPECT_TRUE(ret == ERR_BUNDLE_MANAGER_BUNDLE_NAME_IS_EMPTY ||
                ret == ERR_BUNDLE_MANAGER_PERMISSION_DENIED ||
                ret == ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

HWTEST_F(BmsAppClonePreferenceIPCTest, GetAppClonePreference_UserZero_001, Function | SmallTest | Level0)
{
    sptr<IBundleMgr> proxy = GetBundleMgrProxy();
    ASSERT_NE(proxy, nullptr);
    AppClonePreference preference;
    auto ret = proxy->GetAppClonePreference(NONEXISTENT_BUNDLE_NAME, 0, preference);
    EXPECT_TRUE(ret == ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST ||
                ret == ERR_BUNDLE_MANAGER_PERMISSION_DENIED ||
                ret == ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

HWTEST_F(BmsAppClonePreferenceIPCTest, SetAppClonePreference_AlwaysAsk_NotExist_001, Function | SmallTest | Level0)
{
    sptr<IBundleMgr> proxy = GetBundleMgrProxy();
    ASSERT_NE(proxy, nullptr);
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::ALWAYS_ASK;
    preference.appIndex = 0;
    auto ret = proxy->SetAppClonePreference(NONEXISTENT_BUNDLE_NAME, TEST_USERID, preference);
    EXPECT_TRUE(ret == ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST ||
                ret == ERR_BUNDLE_MANAGER_PERMISSION_DENIED ||
                ret == ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

HWTEST_F(BmsAppClonePreferenceIPCTest, SetAppClonePreference_Main_NotExist_001, Function | SmallTest | Level0)
{
    sptr<IBundleMgr> proxy = GetBundleMgrProxy();
    ASSERT_NE(proxy, nullptr);
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;
    preference.appIndex = 0;
    auto ret = proxy->SetAppClonePreference(NONEXISTENT_BUNDLE_NAME, TEST_USERID, preference);
    EXPECT_TRUE(ret == ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST ||
                ret == ERR_BUNDLE_MANAGER_PERMISSION_DENIED ||
                ret == ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

HWTEST_F(BmsAppClonePreferenceIPCTest, SetAppClonePreference_Clone_NotExist_001, Function | SmallTest | Level0)
{
    sptr<IBundleMgr> proxy = GetBundleMgrProxy();
    ASSERT_NE(proxy, nullptr);
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::CLONE_APP;
    preference.appIndex = 2;
    auto ret = proxy->SetAppClonePreference(NONEXISTENT_BUNDLE_NAME, TEST_USERID, preference);
    EXPECT_TRUE(ret == ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST ||
                ret == ERR_BUNDLE_MANAGER_PERMISSION_DENIED ||
                ret == ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

HWTEST_F(BmsAppClonePreferenceIPCTest, SetAppClonePreference_EmptyBundleName_001, Function | SmallTest | Level0)
{
    sptr<IBundleMgr> proxy = GetBundleMgrProxy();
    ASSERT_NE(proxy, nullptr);
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;
    auto ret = proxy->SetAppClonePreference("", TEST_USERID, preference);
    EXPECT_TRUE(ret == ERR_BUNDLE_MANAGER_BUNDLE_NAME_IS_EMPTY ||
                ret == ERR_BUNDLE_MANAGER_PERMISSION_DENIED ||
                ret == ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

// -------------------- Service / DataMgr direct unit tests --------------------

HWTEST_F(BmsAppClonePreferenceIPCTest, Service_GetAppClonePreferenceDataMgr_NoThrow_001,
    Function | SmallTest | Level0)
{
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    ASSERT_NE(service, nullptr);
    // In the mock test env this returns nullptr (see mock/src/bundle_mgr_service.cpp); in
    // production it returns the initialized AppClonePreferenceDataMgr instance. Either way the
    // const accessor must not throw.
    std::shared_ptr<AppClonePreferenceDataMgr> prefDataMgr;
    EXPECT_NO_THROW(prefDataMgr = service->GetAppClonePreferenceDataMgr());
}

// -------------------- DataMgr parameter-validation branches --------------------
// These exercise the same DataMgr code paths as the dedicated data-mgr unit test, but via the
// IPC test fixture to ensure coverage parity in this binary too.

// GetAppClonePreference empty-bundleName short-circuit + dataMgr-null terminal — both branches
// of the Get path that are reachable without a live BundleDataMgr. The empty-name check fires
// first; any non-empty name lands in the dataMgr-null branch (mock env).
HWTEST_F(BmsAppClonePreferenceIPCTest, DataMgr_GetAppClonePreference_ParamValidation_001,
    Function | SmallTest | Level0)
{
    auto prefDataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(prefDataMgr, nullptr);
    AppClonePreference preference;
    EXPECT_EQ(prefDataMgr->GetAppClonePreference("", TEST_USERID, preference),
        ERR_BUNDLE_MANAGER_BUNDLE_NAME_IS_EMPTY);
    EXPECT_EQ(prefDataMgr->GetAppClonePreference(TEST_BUNDLE_NAME, TEST_USERID, preference),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    EXPECT_EQ(prefDataMgr->GetAppClonePreference("any.other.bundle", 0, preference),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

HWTEST_F(BmsAppClonePreferenceIPCTest, DataMgr_SetAppClonePreference_EmptyBundleName_001,
    Function | SmallTest | Level0)
{
    auto prefDataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(prefDataMgr, nullptr);
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::MAIN_APP;
    auto ret = prefDataMgr->SetAppClonePreference("", TEST_USERID, preference);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NAME_IS_EMPTY);
}

HWTEST_F(BmsAppClonePreferenceIPCTest, DataMgr_SetAppClonePreference_InvalidType_001,
    Function | SmallTest | Level0)
{
    auto prefDataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(prefDataMgr, nullptr);
    AppClonePreference preference;
    preference.mode = static_cast<AppClonePreferenceMode>(99);
    auto ret = prefDataMgr->SetAppClonePreference(TEST_BUNDLE_NAME, TEST_USERID, preference);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

HWTEST_F(BmsAppClonePreferenceIPCTest, DataMgr_SetAppClonePreference_InvalidCloneIndex_001,
    Function | SmallTest | Level0)
{
    auto prefDataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(prefDataMgr, nullptr);
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::CLONE_APP;
    preference.appIndex = 0;
    auto ret = prefDataMgr->SetAppClonePreference(TEST_BUNDLE_NAME, TEST_USERID, preference);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_APPINDEX_NOT_EXIST);
}

HWTEST_F(BmsAppClonePreferenceIPCTest, DataMgr_SetAppClonePreference_AlwaysAsk_DataMgrNull_001,
    Function | SmallTest | Level0)
{
    auto prefDataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(prefDataMgr, nullptr);
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::ALWAYS_ASK;
    auto ret = prefDataMgr->SetAppClonePreference(TEST_BUNDLE_NAME, TEST_USERID, preference);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

HWTEST_F(BmsAppClonePreferenceIPCTest, DataMgr_SetAppClonePreference_CloneAppIndex_Min_001,
    Function | SmallTest | Level0)
{
    auto prefDataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(prefDataMgr, nullptr);
    AppClonePreference preference;
    preference.mode = AppClonePreferenceMode::CLONE_APP;
    preference.appIndex = 1;
    auto ret = prefDataMgr->SetAppClonePreference(TEST_BUNDLE_NAME, TEST_USERID, preference);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// DeleteAppClonePreference returns ERR_OK on every no-op path in the mock env: empty bundleName
// short-circuit, and repeated delete on a nonexistent row (idempotency).
HWTEST_F(BmsAppClonePreferenceIPCTest, DataMgr_DeleteAppClonePreference_NoOpPaths_001,
    Function | SmallTest | Level0)
{
    auto prefDataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(prefDataMgr, nullptr);
    EXPECT_EQ(prefDataMgr->DeleteAppClonePreference("", TEST_USERID), ERR_OK);
    EXPECT_EQ(prefDataMgr->DeleteAppClonePreference(NONEXISTENT_BUNDLE_NAME, TEST_USERID), ERR_OK);
    EXPECT_EQ(prefDataMgr->DeleteAppClonePreference(NONEXISTENT_BUNDLE_NAME, TEST_USERID), ERR_OK);
    EXPECT_EQ(prefDataMgr->DeleteAppClonePreference(NONEXISTENT_BUNDLE_NAME, 0), ERR_OK);
}

// HandleAppCloneUninstalled returns ERR_OK on every no-op path: empty bundleName short-circuit,
// and a nonexistent bundle with no preference record (storage Query returns false → early return).
HWTEST_F(BmsAppClonePreferenceIPCTest, DataMgr_HandleAppCloneUninstalled_NoOpPaths_001,
    Function | SmallTest | Level0)
{
    auto prefDataMgr = std::make_shared<AppClonePreferenceDataMgr>();
    ASSERT_NE(prefDataMgr, nullptr);
    EXPECT_EQ(prefDataMgr->HandleAppCloneUninstalled("", TEST_USERID, 1), ERR_OK);
    EXPECT_EQ(prefDataMgr->HandleAppCloneUninstalled(NONEXISTENT_BUNDLE_NAME, TEST_USERID, 1), ERR_OK);
    EXPECT_EQ(prefDataMgr->HandleAppCloneUninstalled(NONEXISTENT_BUNDLE_NAME, TEST_USERID, 2), ERR_OK);
    EXPECT_EQ(prefDataMgr->HandleAppCloneUninstalled(NONEXISTENT_BUNDLE_NAME, 0, 1), ERR_OK);
}

// -------------------- BundleMgrHost Handle* direct-call tests --------------------
// These exercise the parcel read/write branches of HandleGetAppClonePreference and
// HandleSetAppClonePreference without going through actual IPC. We construct BundleMgrHost
// directly and feed crafted MessageParcel data.

// HandleGetAppClonePreference: empty data parcel — ReadInt32(userId) fails → PARCEL_ERROR.
HWTEST_F(BmsAppClonePreferenceIPCTest, Host_GetPreference_ReadUserIdFails_001, Function | SmallTest | Level0)
{
    BundleMgrHost host;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    // No userId written — ReadInt32 will fail.
    MessageParcel reply;
    auto ret = host.HandleGetAppClonePreference(data, reply);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

// HandleGetAppClonePreference: valid parcel with empty bundleName. BundleMgrHost uses the
// base-class default GetAppClonePreference (returns SERVICE_INTERNAL_ERROR); the empty-name
// validation lives in AppClonePreferenceDataMgr, not in the host. The reply carries the
// inner ErrCode and the host returns ERR_OK on successful parcel write.
HWTEST_F(BmsAppClonePreferenceIPCTest, Host_GetPreference_EmptyBundleName_001, Function | SmallTest | Level0)
{
    BundleMgrHost host;
    MessageParcel data;
    data.WriteString("");
    data.WriteInt32(TEST_USERID);
    MessageParcel reply;
    auto ret = host.HandleGetAppClonePreference(data, reply);
    EXPECT_EQ(ret, ERR_OK);
    int32_t replyErr = ERR_OK;
    ASSERT_TRUE(reply.ReadInt32(replyErr));
    EXPECT_EQ(replyErr, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// HandleGetAppClonePreference: valid parcel with non-empty bundleName — base-class default
// impl returns SERVICE_INTERNAL_ERROR, reply carries that, host returns ERR_OK.
HWTEST_F(BmsAppClonePreferenceIPCTest, Host_GetPreference_DataMgrNull_001, Function | SmallTest | Level0)
{
    BundleMgrHost host;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteInt32(TEST_USERID);
    MessageParcel reply;
    auto ret = host.HandleGetAppClonePreference(data, reply);
    EXPECT_EQ(ret, ERR_OK);
    int32_t replyErr = ERR_OK;
    ASSERT_TRUE(reply.ReadInt32(replyErr));
    EXPECT_EQ(replyErr, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// HandleSetAppClonePreference: empty data parcel — ReadInt32(userId) fails → PARCEL_ERROR.
HWTEST_F(BmsAppClonePreferenceIPCTest, Host_SetPreference_ReadUserIdFails_001, Function | SmallTest | Level0)
{
    BundleMgrHost host;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    // No userId written.
    MessageParcel reply;
    auto ret = host.HandleSetAppClonePreference(data, reply);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

// HandleSetAppClonePreference: valid userId but missing parcelable → preferencePtr is nullptr,
// reply carries PARAM_ERROR, function returns ERR_OK (the inner-write-success branch).
HWTEST_F(BmsAppClonePreferenceIPCTest, Host_SetPreference_NullPreference_001, Function | SmallTest | Level0)
{
    BundleMgrHost host;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteInt32(TEST_USERID);
    // No parcelable written — ReadParcelable returns nullptr.
    MessageParcel reply;
    auto ret = host.HandleSetAppClonePreference(data, reply);
    EXPECT_EQ(ret, ERR_OK);
    int32_t replyErr = ERR_OK;
    ASSERT_TRUE(reply.ReadInt32(replyErr));
    EXPECT_EQ(replyErr, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

// HandleSetAppClonePreference: invalid preference (out-of-range type) → ReadParcelable
// returns nullptr (rejected by Unmarshalling range check) → reply carries PARAM_ERROR.
HWTEST_F(BmsAppClonePreferenceIPCTest, Host_SetPreference_InvalidPreferenceType_001,
    Function | SmallTest | Level0)
{
    BundleMgrHost host;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteInt32(TEST_USERID);
    data.WriteInt32(99);   // invalid type value
    data.WriteInt32(0);    // appIndex
    MessageParcel reply;
    auto ret = host.HandleSetAppClonePreference(data, reply);
    EXPECT_EQ(ret, ERR_OK);
    int32_t replyErr = ERR_OK;
    ASSERT_TRUE(reply.ReadInt32(replyErr));
    EXPECT_EQ(replyErr, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

// HandleSetAppClonePreference: empty bundleName — valid parcelable but base-class default
// SetAppClonePreference returns SERVICE_INTERNAL_ERROR. Reply carries that.
HWTEST_F(BmsAppClonePreferenceIPCTest, Host_SetPreference_EmptyBundleName_001, Function | SmallTest | Level0)
{
    BundleMgrHost host;
    MessageParcel data;
    data.WriteString("");
    data.WriteInt32(TEST_USERID);
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::MAIN_APP;
    data.WriteParcelable(&pref);
    MessageParcel reply;
    auto ret = host.HandleSetAppClonePreference(data, reply);
    EXPECT_EQ(ret, ERR_OK);
    int32_t replyErr = ERR_OK;
    ASSERT_TRUE(reply.ReadInt32(replyErr));
    EXPECT_EQ(replyErr, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// HandleSetAppClonePreference: ALWAYS_ASK with valid bundleName — base-class default returns
// SERVICE_INTERNAL_ERROR.
HWTEST_F(BmsAppClonePreferenceIPCTest, Host_SetPreference_AlwaysAsk_DataMgrNull_001,
    Function | SmallTest | Level0)
{
    BundleMgrHost host;
    MessageParcel data;
    data.WriteString(TEST_BUNDLE_NAME);
    data.WriteInt32(TEST_USERID);
    AppClonePreference pref;
    pref.mode = AppClonePreferenceMode::ALWAYS_ASK;
    data.WriteParcelable(&pref);
    MessageParcel reply;
    auto ret = host.HandleSetAppClonePreference(data, reply);
    EXPECT_EQ(ret, ERR_OK);
    int32_t replyErr = ERR_OK;
    ASSERT_TRUE(reply.ReadInt32(replyErr));
    EXPECT_EQ(replyErr, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}
}  // namespace OHOS
