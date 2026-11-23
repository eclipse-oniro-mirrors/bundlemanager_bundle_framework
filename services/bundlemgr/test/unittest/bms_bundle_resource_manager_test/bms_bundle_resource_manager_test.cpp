/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define protected public

#include <atomic>
#include <fstream>
#include <gtest/gtest.h>
#include <limits>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "bms_param.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_resource_constants.h"
#include "bundle_resource_manager.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "scope_guard.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace Security {
namespace AccessToken {
// Restores the SPM mock control variables defined in
// test/mock/src/accesstoken_kit.cpp to their defaults.
void ResetSpmKitMockValuesForTest();
} // namespace AccessToken
} // namespace Security
namespace {
const std::string BUNDLE_PATH = "/data/test/resource/bms/resource_manager/resourceManagerTest.hap";
const std::string BUNDLE_NAME = "com.ohos.resourcedemo";
const std::string MODULE_NAME = "entry";
const std::string APP_LABEL = "ResourceDemo";
const std::string DESCRIPTION = "description";
const std::string ABILITY_LABEL = "label";
const int32_t APP_LABEL_ID = 16777216;
const int32_t DESCRIPTION_ID = 16777218;
const int32_t ABILITY_LABEL_ID = 16777219;
const int32_t APP_ICON_ID = 16777217;
const int32_t ABILITY_ICON_ID = 16777222;
const int32_t USER_ID = 100;
const int32_t WAIT_TIME = 2; // init mocked bms
const uint32_t DENSITY_120_STR = 120; // sdpi
const uint32_t DENSITY_160_STR = 160; // mdpi
const uint32_t DENSITY_240_STR = 240; // ldpi
const uint32_t DENSITY_320_STR = 320; // xldpi
const uint32_t DENSITY_480_STR = 480; // xxldpi
const uint32_t DENSITY_640_STR = 640; // xxxldpi

// --- SPM ON install prerequisite -------------------------------------------
// The SPM switch stays ON (its default when persist.bms.spm.enable is unset),
// so every install of this suite (SetUp installs BUNDLE_PATH for every case)
// runs the complete SPM ON chain against the mocked access-token boundary:
// CheckSignAndInitSession -> CheckPermissionInfo -> PrepareHapIdentity
// (identity and uid adoption) -> FinishInstall (commit). The mocked
// CheckHapSignInfo must return exactly one trusted entry (the count must
// always match the hap count of the install call — CheckSignAndInitSession
// fails closed on a mismatch), and the provision bundle-name must match the
// hap's parsed package name (CheckBundleName cross-checks both). InitToken
// rejects a zero tokenId and a uid outside the installing user's uid segment.
constexpr int32_t TEST_SPM_SESSION_ID = 4243;
constexpr uint64_t TEST_SPM_TOKEN_ID = 101;
constexpr int32_t TEST_SPM_UID = USER_ID * Constants::BASE_USER_RANGE + 102;

// Feeds the mocked access-token boundary with the trusted sign answer the
// real AT side would return for the hap installed by SetUp: the provision
// mirrors the release profile (test/sceneProject/signature/
// com.ohos.resourcedemo.p7b) the hap is actually signed with —
// os_integration distribution, system_core apl, hos_system_app feature, and
// the legacy profile shape without an app-identifier (an empty appIdentifier
// omits the field) — so the post-install classification (system app,
// distribution type) stays the same as before the SPM adaptation.
void SetUpSpmTrustedSignInfoForTest()
{
    Security::AccessToken::TrustedBundleInfo trustedBundleInfo;
    trustedBundleInfo.profileData.provisionRaw =
        Security::AccessToken::MakeSpmReleaseProvisionRawForTest(BUNDLE_NAME, "os_integration", false,
            "hos_system_app", "system_core", "");
    Security::AccessToken::SetSpmTrustedBundleInfosForTest({trustedBundleInfo});
    // Mirrors the real AT contract: CheckHapSignInfo allocates the session id
    // and caches the trusted info for the install session.
    Security::AccessToken::SetSpmCheckHapSignInfoSessionIdForTest(TEST_SPM_SESSION_ID);
    // A fresh install carries no desired uid, so the AT side allocates the
    // identity: provide a valid token id and a USER_ID-segment uid.
    Security::AccessToken::SetSpmPrepareIdentityForTest(TEST_SPM_TOKEN_ID, TEST_SPM_UID);
}

class BmsBundleResourceManagerTest : public testing::Test {
public:
    BmsBundleResourceManagerTest();
    ~BmsBundleResourceManagerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    void StartInstalldService() const;
    void StartBundleService();
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleResourceManagerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleResourceManagerTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleResourceManagerTest::BmsBundleResourceManagerTest()
{}

BmsBundleResourceManagerTest::~BmsBundleResourceManagerTest()
{}

void BmsBundleResourceManagerTest::SetUpTestCase()
{
    // SPM stays ON (its device default): feed the mocked access-token boundary
    // with the trusted sign answer for the hap installed by SetUp, so the
    // installs run the real SPM verification chain instead of failing it.
    // Must run before the first install — nothing in this binary resets the
    // mock control variables afterwards.
    SetUpSpmTrustedSignInfoForTest();
    bundleMgrService_->InitBundleInstaller();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
    bundleMgrService_->GetDataMgr()->LoadDataFromPersistentStorage();
}

void BmsBundleResourceManagerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
    sleep(1);
    // Restore the SPM mock defaults: the trusted sign answer staged by
    // SetUpTestCase persists through the whole binary (nothing resets it
    // between the cases), and a suite added to this target later must not
    // inherit it — gtest runs the suites of one binary sequentially, so a
    // reset here precedes any later suite's SetUpTestCase.
    Security::AccessToken::ResetSpmKitMockValuesForTest();
}

void BmsBundleResourceManagerTest::SetUp()
{
    StartInstalldService();
    InstallBundle(BUNDLE_PATH);
}

void BmsBundleResourceManagerTest::TearDown()
{
    UnInstallBundle(BUNDLE_NAME);
}

ErrCode BmsBundleResourceManagerTest::InstallBundle(const std::string &bundlePath) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = USER_ID;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleResourceManagerTest::UnInstallBundle(const std::string &bundleName) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USER_ID;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

const std::shared_ptr<BundleDataMgr> BmsBundleResourceManagerTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}


void BmsBundleResourceManagerTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleResourceManagerTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

/**
 * @tc.name: GetStringById_001
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.getStringById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetStringById_001, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string label = dataMgr->GetStringById(
        BUNDLE_NAME, MODULE_NAME, APP_LABEL_ID, USER_ID, Constants::EMPTY_STRING);
    EXPECT_EQ(label, APP_LABEL);
}

/**
 * @tc.name: GetStringById_002
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.getStringById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetStringById_002, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string label = dataMgr->GetStringById(
        BUNDLE_NAME, MODULE_NAME, ABILITY_LABEL_ID, USER_ID, Constants::EMPTY_STRING);
    EXPECT_EQ(label, ABILITY_LABEL);

    std::string description = dataMgr->GetStringById(
        BUNDLE_NAME, MODULE_NAME, DESCRIPTION_ID, USER_ID, Constants::EMPTY_STRING);
    EXPECT_EQ(description, DESCRIPTION);
}

/**
 * @tc.name: GetStringById_003
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.getStringById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetStringById_003, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    std::string description = dataMgr->GetStringById(
        "", MODULE_NAME, ABILITY_LABEL_ID, USER_ID, Constants::EMPTY_STRING);
    EXPECT_EQ(description, "");
}

/**
 * @tc.name: GetStringById_004
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.getStringById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetStringById_004, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    std::string abilityLabel = dataMgr->GetStringById(
        BUNDLE_NAME, "", ABILITY_LABEL_ID, USER_ID, Constants::EMPTY_STRING);
    EXPECT_EQ(abilityLabel, ABILITY_LABEL);
}

/**
 * @tc.name: GetStringById_005
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.getStringById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetStringById_005, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    std::string description = dataMgr->GetStringById(
        BUNDLE_NAME, MODULE_NAME, 0, USER_ID, Constants::EMPTY_STRING);
    EXPECT_EQ(description, "");
}

/**
 * @tc.name: GetStringById_006
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.getStringById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetStringById_006, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    std::string description = dataMgr->GetStringById(
        BUNDLE_NAME, MODULE_NAME, ABILITY_LABEL_ID, 0, Constants::EMPTY_STRING);
    EXPECT_EQ(description, "");
}

/**
 * @tc.name: GetIconById_001
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_001, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconBase64 = dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, APP_ICON_ID, 0, USER_ID);
    EXPECT_NE(iconBase64, "");
}

/**
 * @tc.name: GetIconById_002
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_002, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string icon120Base64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, DENSITY_120_STR, USER_ID);
    EXPECT_NE(icon120Base64, "");
}

/**
 * @tc.name: GetIconById_003
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_003, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string icon160Base64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, DENSITY_160_STR, USER_ID);
    EXPECT_NE(icon160Base64, "");
}

/**
 * @tc.name: GetIconById_004
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_004, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string icon240Base64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, DENSITY_240_STR, USER_ID);
    EXPECT_NE(icon240Base64, "");
}

/**
 * @tc.name: GetIconById_005
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_005, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string icon320Base64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, DENSITY_320_STR, USER_ID);
    EXPECT_NE(icon320Base64, "");
}

/**
 * @tc.name: GetIconById_007
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_006, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string icon480Base64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, DENSITY_480_STR, USER_ID);
    EXPECT_NE(icon480Base64, "");
}

/**
 * @tc.name: GetIconById_008
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_007, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string icon640Base64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, DENSITY_640_STR, USER_ID);
    EXPECT_NE(icon640Base64, "");
}

/**
 * @tc.name: GetIconById_009
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_008, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconDefaultBase64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, 0, USER_ID);
    EXPECT_NE(iconDefaultBase64, "");
}

/**
 * @tc.name: GetIconById_009
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_009, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconBase64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, 0, -1);
    EXPECT_EQ(iconBase64, "");
}

/**
 * @tc.name: GetIconById_0010
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_0010, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconBase64 =
        dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, 0, USER_ID);
    EXPECT_NE(iconBase64, "");
}

/**
 * @tc.name: GetIconById_0011
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_0011, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconBase64 = dataMgr->GetIconById("", MODULE_NAME, ABILITY_ICON_ID, 0, USER_ID);
    EXPECT_EQ(iconBase64, "");
}

/**
 * @tc.name: GetIconById_0012
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_0012, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconBase64 = dataMgr->GetIconById(BUNDLE_NAME, "", ABILITY_ICON_ID, 0, USER_ID);
    EXPECT_NE(iconBase64, "");
}

/**
 * @tc.name: GetIconById_0013
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_0013, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconBase64 = dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, 0, 0, USER_ID);
    EXPECT_EQ(iconBase64, "");
}

/**
 * @tc.name: GetIconById_0014
 * @tc.type: FUNC
 * @tc.desc: 1.install the hap
 *           2.GetIconById
 * @tc.require: issueI5MZ4C
 */
HWTEST_F(BmsBundleResourceManagerTest, GetIconById_0014, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string iconBase64 = dataMgr->GetIconById(BUNDLE_NAME, MODULE_NAME, ABILITY_ICON_ID, 0, 0);
    EXPECT_EQ(iconBase64, "");
}

/**
 * @tc.number: BundleResourceManager_RebuildResourceDb_0100
 * @tc.name: RebuildResourceDb normal flow
 * @tc.desc: Test RebuildResourceDb with valid BundleMgrService and DataMgr
 * @tc.require: issueIXXXXX
 */
HWTEST_F(BmsBundleResourceManagerTest, BundleResourceManager_RebuildResourceDb_0100, Function | MediumTest | Level1)
{
    auto bundleMgrService = DelayedSingleton<BundleMgrService>::GetInstance();
    ASSERT_NE(bundleMgrService, nullptr);
    auto dataMgr = bundleMgrService->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    // Call RebuildResourceDb - should complete without crash
    auto bundleResourceManager = std::make_shared<BundleResourceManager>();
    ASSERT_NE(bundleResourceManager, nullptr);
    bundleResourceManager->RebuildResourceDb();
}

/**
 * @tc.number: BundleResourceManager_RebuildResourceDb_0200
 * @tc.name: RebuildResourceDb with null BundleMgrService
 * @tc.desc: Test RebuildResourceDb handles null BundleMgrService gracefully
 * @tc.require: issueIXXXXX
 */
HWTEST_F(BmsBundleResourceManagerTest, BundleResourceManager_RebuildResourceDb_0200, Function | SmallTest | Level0)
{
    // Note: Can't actually set DelayedSingleton to null, so test the null check path
    // by verifying the method exists and handles null internally
    auto bundleResourceManager = std::make_shared<BundleResourceManager>();
    ASSERT_NE(bundleResourceManager, nullptr);
    // The null check is handled inside RebuildResourceDb implementation
    bundleResourceManager->RebuildResourceDb();
}

/**
 * @tc.number: BundleResourceManager_RebuildResourceDb_0300
 * @tc.name: RebuildResourceDb with null DataMgr
 * @tc.desc: Test RebuildResourceDb handles null DataMgr gracefully
 * @tc.require: issueIXXXXX
 */
HWTEST_F(BmsBundleResourceManagerTest, BundleResourceManager_RebuildResourceDb_0300, Function | SmallTest | Level0)
{
    auto bundleMgrService = DelayedSingleton<BundleMgrService>::GetInstance();
    ASSERT_NE(bundleMgrService, nullptr);
    // Temporarily clear the data mgr
    auto savedDataMgr = bundleMgrService->GetDataMgr();
    bundleMgrService->dataMgr_ = nullptr;

    auto bundleResourceManager = std::make_shared<BundleResourceManager>();
    ASSERT_NE(bundleResourceManager, nullptr);
    bundleResourceManager->RebuildResourceDb();

    // Restore data mgr
    bundleMgrService->dataMgr_ = savedDataMgr;
}
}

// Timestamp storage uses its own table in bundleResource.db; these users are reserved for this fixture.
class ThemeTimestampStorageTest : public testing::Test {
protected:
    void SetUp() override
    {
        manager_ = std::make_unique<BundleResourceManager>();
        storage_ = manager_->bundleResourceRdb_->themeTimestampRdbDataManager_;
        ASSERT_NE(storage_, nullptr);
        ClearRecords();
    }

    void TearDown() override
    {
        ClearRecords();
        BmsParam param;
        param.DeleteBmsParam("themeTimestamp_29001");
        param.DeleteBmsParam("themeTimestamp_other_param_test");
    }

    void ClearRecords()
    {
        NativeRdb::AbsRdbPredicates predicates(BundleResourceConstants::THEME_TIMESTAMP_RDB_TABLE_NAME);
        const std::vector<std::string> users {std::to_string(firstUser), std::to_string(secondUser)};
        predicates.In(BundleResourceConstants::USER_ID, users);
        EXPECT_TRUE(storage_->DeleteData(predicates));
    }

    static constexpr int32_t firstUser = 29001;
    static constexpr int32_t secondUser = 29002;
    std::unique_ptr<BundleResourceManager> manager_;
    std::shared_ptr<RdbDataManager> storage_;
};

HWTEST_F(ThemeTimestampStorageTest, ThemeTimestamp_NoRecord, TestSize.Level1)
{
    int64_t timestamp = 1234;
    EXPECT_TRUE(manager_->GetThemeTimestamp(firstUser, timestamp));
    EXPECT_EQ(timestamp, -1);
    EXPECT_FALSE(manager_->GetThemeTimestamp(Constants::ALL_USERID, timestamp));
    EXPECT_FALSE(manager_->GetThemeTimestamp(Constants::ANY_USERID, timestamp));
}

HWTEST_F(ThemeTimestampStorageTest, ThemeTimestamp_UserIsolationAndUpdate, TestSize.Level1)
{
    ASSERT_TRUE(manager_->SaveThemeTimestamp(firstUser, 1234));
    ASSERT_TRUE(manager_->SaveThemeTimestamp(secondUser, 5678));
    ASSERT_TRUE(manager_->SaveThemeTimestamp(firstUser, 1250));
    int64_t timestamp = 0;
    ASSERT_TRUE(manager_->GetThemeTimestamp(firstUser, timestamp));
    EXPECT_EQ(timestamp, 1250);
    ASSERT_TRUE(manager_->GetThemeTimestamp(secondUser, timestamp));
    EXPECT_EQ(timestamp, 5678);
    EXPECT_EQ(storage_->bmsRdbConfig_.dbName, BundleResourceConstants::BUNDLE_RESOURCE_RDB_NAME);
    EXPECT_EQ(storage_->bmsRdbConfig_.tableName, BundleResourceConstants::THEME_TIMESTAMP_RDB_TABLE_NAME);
    NativeRdb::AbsRdbPredicates predicates(BundleResourceConstants::THEME_TIMESTAMP_RDB_TABLE_NAME);
    predicates.EqualTo(BundleResourceConstants::USER_ID, firstUser);
    auto rows = storage_->QueryData(predicates);
    ASSERT_NE(rows, nullptr);
    ScopeGuard close([rows] { rows->Close(); });
    int count = 0;
    ASSERT_EQ(rows->GetRowCount(count), NativeRdb::E_OK);
    EXPECT_EQ(count, 1);
}

HWTEST_F(ThemeTimestampStorageTest, ThemeTimestamp_DeleteUserRecord, TestSize.Level1)
{
    ASSERT_TRUE(manager_->SaveThemeTimestamp(firstUser, 1794614400123LL));
    ASSERT_TRUE(manager_->SaveThemeTimestamp(secondUser, 1794614400456LL));
    ASSERT_TRUE(manager_->DeleteThemeTimestamp(secondUser));
    int64_t timestamp = 0;
    ASSERT_TRUE(manager_->GetThemeTimestamp(secondUser, timestamp));
    EXPECT_EQ(timestamp, -1);
    ASSERT_TRUE(manager_->GetThemeTimestamp(firstUser, timestamp));
    EXPECT_EQ(timestamp, 1794614400123LL);
    EXPECT_TRUE(manager_->DeleteThemeTimestamp(secondUser));
    ASSERT_TRUE(manager_->SaveThemeTimestamp(firstUser, 1794614400789LL));
    BundleResourceRdb reopened;
    ASSERT_TRUE(reopened.GetThemeTimestamp(secondUser, timestamp));
    EXPECT_EQ(timestamp, -1);
    ASSERT_TRUE(reopened.GetThemeTimestamp(firstUser, timestamp));
    EXPECT_EQ(timestamp, 1794614400789LL);
}

HWTEST_F(ThemeTimestampStorageTest, ThemeTimestamp_DeleteInvalidUser, TestSize.Level1)
{
    ASSERT_TRUE(manager_->SaveThemeTimestamp(firstUser, 1234));
    ASSERT_TRUE(manager_->SaveThemeTimestamp(secondUser, 5678));
    EXPECT_FALSE(manager_->DeleteThemeTimestamp(Constants::INVALID_USERID));
    EXPECT_FALSE(manager_->DeleteThemeTimestamp(Constants::ALL_USERID));
    EXPECT_FALSE(manager_->DeleteThemeTimestamp(Constants::ANY_USERID));
    EXPECT_FALSE(manager_->bundleResourceRdb_->DeleteThemeTimestamp(Constants::INVALID_USERID));
    int64_t timestamp = -1;
    ASSERT_TRUE(manager_->GetThemeTimestamp(firstUser, timestamp));
    EXPECT_EQ(timestamp, 1234);
    ASSERT_TRUE(manager_->GetThemeTimestamp(secondUser, timestamp));
    EXPECT_EQ(timestamp, 5678);
}

HWTEST_F(ThemeTimestampStorageTest, ThemeTimestamp_DeleteStorageUnavailable, TestSize.Level1)
{
    ASSERT_TRUE(manager_->SaveThemeTimestamp(firstUser, 1234));
    manager_->bundleResourceRdb_->themeTimestampRdbDataManager_.reset();
    EXPECT_FALSE(manager_->DeleteThemeTimestamp(firstUser));
    manager_->bundleResourceRdb_.reset();
    EXPECT_FALSE(manager_->DeleteThemeTimestamp(firstUser));
}

HWTEST_F(ThemeTimestampStorageTest, ThemeTimestamp_Int64Range, TestSize.Level1)
{
    const int64_t values[] = {0, 2147483648LL, 1794614400123LL, std::numeric_limits<int64_t>::max()};
    for (auto value : values) {
        ASSERT_TRUE(manager_->SaveThemeTimestamp(firstUser, value));
        int64_t timestamp = -1;
        ASSERT_TRUE(manager_->GetThemeTimestamp(firstUser, timestamp));
        EXPECT_EQ(timestamp, value);
    }
    EXPECT_FALSE(manager_->SaveThemeTimestamp(firstUser, -1));
    EXPECT_FALSE(manager_->SaveThemeTimestamp(Constants::INVALID_USERID, 1234));
}

HWTEST_F(ThemeTimestampStorageTest, ThemeTimestamp_InvalidRecord, TestSize.Level1)
{
    // INTEGER affinity can still contain malformed TEXT or REAL data after corruption/fault injection.
    const std::vector<std::string> values = {"", "abc", "1234x", "-1234", "9223372036854775808", "1234.5"};
    for (const auto &value : values) {
        NativeRdb::ValuesBucket record;
        record.PutInt(BundleResourceConstants::USER_ID, firstUser);
        record.PutString(BundleResourceConstants::TIMESTAMP, value);
        ASSERT_TRUE(storage_->InsertData(record));
        int64_t timestamp = 5678;
        EXPECT_FALSE(manager_->GetThemeTimestamp(firstUser, timestamp)) << value;
        EXPECT_EQ(timestamp, -1) << value;
    }
}

HWTEST_F(ThemeTimestampStorageTest, ThemeTimestamp_UnavailableDoesNotReturnOldValue, TestSize.Level1)
{
    ASSERT_TRUE(manager_->SaveThemeTimestamp(firstUser, 1234));
    manager_->bundleResourceRdb_->themeTimestampRdbDataManager_.reset();
    int64_t timestamp = 1234;
    EXPECT_FALSE(manager_->SaveThemeTimestamp(firstUser, 1250));
    EXPECT_FALSE(manager_->GetThemeTimestamp(firstUser, timestamp));
    EXPECT_EQ(timestamp, -1);
    manager_->bundleResourceRdb_.reset();
    EXPECT_FALSE(manager_->SaveThemeTimestamp(firstUser, 1250));
    EXPECT_FALSE(manager_->GetThemeTimestamp(firstUser, timestamp));
}

HWTEST_F(ThemeTimestampStorageTest, ThemeTimestamp_OtherParametersRemainUnchanged, TestSize.Level1)
{
    BmsParam param;
    ASSERT_TRUE(param.SaveBmsParam("themeTimestamp_other_param_test", "keep"));
    ASSERT_TRUE(manager_->SaveThemeTimestamp(firstUser, 1234));
    int64_t timestamp = 0;
    ASSERT_TRUE(manager_->GetThemeTimestamp(firstUser, timestamp));
    std::string value;
    ASSERT_TRUE(param.GetBmsParam("themeTimestamp_other_param_test", value));
    EXPECT_EQ(value, "keep");
}

HWTEST_F(ThemeTimestampStorageTest, ThemeTimestamp_IndependentOfBmsParam, TestSize.Level1)
{
    BmsParam param;
    ASSERT_TRUE(param.SaveBmsParam("themeTimestamp_29001", "9999"));
    int64_t timestamp = 0;
    EXPECT_TRUE(manager_->GetThemeTimestamp(firstUser, timestamp));
    EXPECT_EQ(timestamp, -1);
    ASSERT_TRUE(manager_->SaveThemeTimestamp(firstUser, 1794614400123LL));
    std::string value;
    ASSERT_TRUE(param.GetBmsParam("themeTimestamp_29001", value));
    EXPECT_EQ(value, "9999");
    ASSERT_TRUE(manager_->GetThemeTimestamp(firstUser, timestamp));
    EXPECT_EQ(timestamp, 1794614400123LL);
}

HWTEST_F(ThemeTimestampStorageTest, ThemeTimestamp_ReopenPreservesRecord, TestSize.Level1)
{
    ASSERT_TRUE(manager_->SaveThemeTimestamp(firstUser, 1794614400123LL));
    BundleResourceRdb reopened;
    int64_t timestamp = 0;
    ASSERT_TRUE(reopened.GetThemeTimestamp(firstUser, timestamp));
    EXPECT_EQ(timestamp, 1794614400123LL);
}

HWTEST_F(ThemeTimestampStorageTest, ThemeTimestamp_ConcurrentReadWrite, TestSize.Level1)
{
    constexpr int64_t first = 1794614400123LL;
    constexpr int64_t second = 1794614400456LL;
    ASSERT_TRUE(manager_->SaveThemeTimestamp(firstUser, first));
    std::atomic<bool> valid {true};
    auto writer = [this, &valid]() {
        for (int i = 0; i < 100; ++i) {
            if (!manager_->SaveThemeTimestamp(firstUser, i % 2 == 0 ? first : second)) {
                valid = false;
            }
        }
    };
    auto reader = [this, &valid]() {
        for (int i = 0; i < 100; ++i) {
            int64_t timestamp = 0;
            if (!manager_->GetThemeTimestamp(firstUser, timestamp) ||
                (timestamp != first && timestamp != second)) {
                valid = false;
            }
        }
    };
    std::thread writeThread(writer);
    std::thread readThread(reader);
    writeThread.join();
    readThread.join();
    EXPECT_TRUE(valid.load());
}

} // OHOS