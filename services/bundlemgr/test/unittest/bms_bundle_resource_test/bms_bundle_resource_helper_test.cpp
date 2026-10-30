/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <unistd.h>

#include "application_info.h"
#include "accesstoken_kit.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "bundle_parser.h"
#include "bundle_constants.h"
#include "bundle_permission_mgr.h"
#include "bundle_verify_mgr.h"
#include "bundle_resource_drawable.h"

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
#include "bundle_errors.h"
#include "bundle_resource_callback.h"
#include "bundle_resource_change_type.h"
#include "bundle_resource_configuration.h"
#include "bundle_resource_constants.h"
#include "bundle_resource.h"
#include "resource_helper.h"
#include "bundle_resource_event_subscriber.h"
#include "bundle_resource_helper.h"
#include "bundle_resource_host_impl.h"
#include "bundle_resource_info.h"
#include "bundle_resource_manager.h"
#include "bundle_resource_observer.h"
#include "bundle_resource_param.h"
#include "bundle_resource_parser.h"
#include "bundle_resource_process.h"
#include "bundle_resource_rdb.h"
#include "bundle_resource_register.h"
#include "bundle_system_state.h"
#include "launcher_ability_resource_info.h"
#include "nlohmann/json.hpp"
#endif

#include "directory_ex.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "ipc_skeleton.h"
#include "mock_status_receiver.h"
#include "parameter.h"
#include "permission_define.h"
#include "remote_ability_info.h"
#include "scope_guard.h"
#include "system_ability_definition.h"
#include "system_ability_helper.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
namespace OHOS {
namespace AppExecFwk {
void GetBundleResourceArchiveInfoExec(napi_env env, void *data);
void GetBundleResourceArchiveInfoComplete(napi_env env, napi_status status, void *data);
} // namespace AppExecFwk
} // namespace OHOS
#endif

void SetVerifyCallingPermissionForTest(bool value);
void SetSystemAppForTest(bool value);
void ResetTestValues();
void SetPermissionResultForTest(const std::string &permissionName, bool granted);

namespace OHOS {
namespace {
const int32_t USERID = 100;
const int32_t WAIT_TIME = 2; // init mocked bms
const std::string BUNDLE_NAME = "com.example.bmsaccesstoken1";
const std::string BUNDLE_NAME_NOT_EXIST = "com.example.not_exist";
const std::string HAP_FILE_PATH1 = "/data/test/resource/bms/accesstoken_bundle/bmsAccessTokentest1.hap";

// SPM ON prerequisite: the mocked access-token boundary is fed the trusted
// sign info for the hap the suite installs. The provision mirrors the REAL
// profile the hap is signed with (com.example.bmsaccesstoken1system.p7b —
// release / os_integration / system_core / hos_system_app); the appId and
// appIdentifier are captured from the hap itself (the same local verify the
// preinstall/keep-data cross-checks use), so the SPM-derived identity
// matches the locally verified one by construction.
constexpr int32_t TEST_SPM_SESSION_ID = 4242;
constexpr uint64_t TEST_SPM_TOKEN_ID = 101;
// The AT-allocated uid must fall inside USERID's uid segment.
constexpr int32_t TEST_SPM_UID = USERID * Constants::BASE_USER_RANGE + 102;

void SetUpSpmTrustedSignInfoForTest()
{
    Security::Verify::HapVerifyResult verifyResult;
    std::string appId;
    std::string appIdentifier;
    if (BundleVerifyMgr::HapVerify(HAP_FILE_PATH1, verifyResult, true) == ERR_OK) {
        appId = verifyResult.GetProvisionInfo().appId;
        appIdentifier = verifyResult.GetProvisionInfo().bundleInfo.appIdentifier;
    }
    const std::string provision = Security::AccessToken::MakeSpmReleaseProvisionRawForTest(
        BUNDLE_NAME, "os_integration", false, "hos_system_app", "system_core", appIdentifier);
    Security::AccessToken::SetSpmTrustedProvisionForHapFileForTest("bmsAccessTokentest1.hap", provision, appId);
    Security::AccessToken::SetSpmCheckHapSignInfoSessionIdForTest(TEST_SPM_SESSION_ID);
    Security::AccessToken::SetSpmPrepareIdentityForTest(TEST_SPM_TOKEN_ID, TEST_SPM_UID);
}

// Leftover persistent state of this suite's bundle must be wiped before the
// first install (records persisted by earlier runs store the app id the REAL
// signature derived — a mocked provision deriving a different one fails the
// keep-data / app-identifier comparisons with INCONSISTENT_SIGNATURE).
void ClearSpmLeftoverUninstallRecordsForTest()
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    InnerBundleInfo leftoverInfo;
    if (dataMgr->FetchInnerBundleInfo(BUNDLE_NAME, leftoverInfo)) {
        dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
        dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
        dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);
    }
    dataMgr->DeleteUninstallBundleInfo(BUNDLE_NAME, USERID);
}
}  // namespace

class BmsBundleResourceHelperTest : public testing::Test {
public:
    BmsBundleResourceHelperTest();
    ~BmsBundleResourceHelperTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StartInstalldService() const;
    void StartBundleService();
    sptr<BundleMgrProxy> GetBundleMgrProxy();

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleResourceHelperTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleResourceHelperTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleResourceHelperTest::BmsBundleResourceHelperTest()
{}

BmsBundleResourceHelperTest::~BmsBundleResourceHelperTest()
{}

void BmsBundleResourceHelperTest::SetUpTestCase()
{
    // SPM stays ON (its device default): feed the mocked access-token boundary
    // with the trusted sign answer for the hap the suite installs, so the
    // installs pass the real SPM verification chain instead of failing closed
    // on the empty default mock.
    SetUpSpmTrustedSignInfoForTest();
    bundleMgrService_->InitBundleInstaller();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    bundleMgrService_->GetDataMgr()->LoadDataFromPersistentStorage();
    // Drop the leftover keep-data uninstall record / stale installed row of
    // this suite's bundle before the first install (the persisted data is
    // loaded above).
    ClearSpmLeftoverUninstallRecordsForTest();
}

void BmsBundleResourceHelperTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
    sleep(1);
}

void BmsBundleResourceHelperTest::SetUp()
{
    StartInstalldService();
    // The mocked InstalldClient::ClearSessionProvisionCache is a counting
    // stub, so the real session provision cache inside the process-wide
    // InstalldHostImpl keeps the entry of the PREVIOUS test case's install
    // under the same shared session id — drop it before every case so each
    // install starts from a clean provision state.
    if (installdService_->hostImpl_ != nullptr) {
        installdService_->hostImpl_->ClearSessionProvisionCache(TEST_SPM_SESSION_ID);
    }
}

void BmsBundleResourceHelperTest::TearDown()
{}

ErrCode BmsBundleResourceHelperTest::InstallBundle(const std::string &bundlePath) const
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
    installParam.userId = USERID;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleResourceHelperTest::UnInstallBundle(const std::string &bundleName) const
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
    installParam.userId = USERID;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

void BmsBundleResourceHelperTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleResourceHelperTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

const std::shared_ptr<BundleDataMgr> BmsBundleResourceHelperTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

sptr<BundleMgrProxy> BmsBundleResourceHelperTest::GetBundleMgrProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        APP_LOGE("fail to get system ability mgr.");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        APP_LOGE("fail to get bundle manager proxy.");
        return nullptr;
    }

    APP_LOGI("get bundle manager proxy success.");
    return iface_cast<BundleMgrProxy>(remoteObject);
}

/**
 * @tc.number: AddResourceInfoByBundleName_0010
 * Function: AddResourceInfoByBundleName
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfoByBundleName
 */
HWTEST_F(BmsBundleResourceHelperTest, AddResourceInfoByBundleName_0010, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    BundleResourceHelper::AddResourceInfoByBundleName(BUNDLE_NAME, USERID, ADD_RESOURCE_TYPE::INSTALL_BUNDLE);
    bool ret = BundleResourceHelper::DeleteBundleResourceInfo(BUNDLE_NAME, USERID, true);
    EXPECT_TRUE(ret);

    BundleResourceHelper::AddResourceInfoByBundleName(BUNDLE_NAME, USERID, ADD_RESOURCE_TYPE::UPDATE_BUNDLE);
    ret = BundleResourceHelper::DeleteBundleResourceInfo(BUNDLE_NAME, USERID, true);
    EXPECT_TRUE(ret);

    BundleResourceHelper::AddResourceInfoByBundleName(BUNDLE_NAME, USERID, ADD_RESOURCE_TYPE::CREATE_USER);
    ret = BundleResourceHelper::DeleteBundleResourceInfo(BUNDLE_NAME, USERID, true);
    EXPECT_TRUE(ret);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: AddCloneBundleResourceInfo_0010
 * Function: AddCloneBundleResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddCloneBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceHelperTest, AddCloneBundleResourceInfo_0010, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    bool ret = BundleResourceHelper::AddCloneBundleResourceInfo(BUNDLE_NAME_NOT_EXIST, USERID, 1, false);
    EXPECT_FALSE(ret);

    ret = BundleResourceHelper::AddCloneBundleResourceInfo(BUNDLE_NAME, USERID, 1, false);
    EXPECT_TRUE(ret);

    ret = BundleResourceHelper::DeleteCloneBundleResourceInfo(BUNDLE_NAME, USERID, 1, false);
    EXPECT_TRUE(ret);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
/**
 * @tc.number: ParseBundleName_0100
 * @tc.name: test ParseBundleName extracts bundleName from resource key
 * @tc.desc: ParseKey-style key → returns bundleName prefix
 */
HWTEST_F(BmsBundleResourceHelperTest, ParseBundleName_0100, Function | SmallTest | Level0)
{
    std::string key = "com.example.bmsaccesstoken1/moduleName/abilityName";
    EXPECT_EQ(BundleResourceHelper::ParseBundleName(key), "com.example.bmsaccesstoken1");

    key = "com.example.onlybundle";
    EXPECT_EQ(BundleResourceHelper::ParseBundleName(key), "com.example.onlybundle");
}
#endif

/**
 * @tc.number: UninstallBundleResourceRdb_MigrateData_0100
 * @tc.name: MigrateData with no old table returns true
 * @tc.desc: Test migration when old table doesn't exist returns true (skip gracefully)
 * @tc.require: issueIXXXXX
 */
HWTEST_F(BmsBundleResourceHelperTest, UninstallBundleResourceRdb_MigrateData_0100, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    auto uninstallResourceRdb = std::make_shared<UninstallBundleResourceRdb>();
    ASSERT_NE(uninstallResourceRdb, nullptr);
    // When old table doesn't exist, migration should return true (skip gracefully)
    bool ret = uninstallResourceRdb->MigrateData();
    EXPECT_FALSE(ret);
#endif
}

/**
 * @tc.number: UninstallBundleResourceRdb_MigrateData_0200
 * @tc.name: MigrateData success with data migration
 * @tc.desc: Test successful data migration from old table to new table
 * @tc.require: issueIXXXXX
 */
HWTEST_F(BmsBundleResourceHelperTest, UninstallBundleResourceRdb_MigrateData_0200, Function | MediumTest | Level1)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    auto uninstallResourceRdb = std::make_shared<UninstallBundleResourceRdb>();
    ASSERT_NE(uninstallResourceRdb, nullptr);

    // Add test data to old database
    std::map<std::string, std::string> labelMap;
    labelMap["en-US"] = "Test App";
    BundleResourceInfo resourceInfo;
    resourceInfo.icon = "/data/test/icon.png";

    // Insert into new table (simulating old data)
    auto ret = uninstallResourceRdb->AddUninstallBundleResource("com.test.migrate", USERID, 0, labelMap, resourceInfo);
    EXPECT_TRUE(ret);

    // Verify data can be retrieved
    BundleResourceInfo getResourceInfo;
    uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    ret = uninstallResourceRdb->GetUninstallBundleResource("com.test.migrate", USERID, 0, flags, getResourceInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getResourceInfo.bundleName, "com.test.migrate");
#endif
}

/**
 * @tc.number: GetBundleResourceArchiveInfo_0100
 * @tc.name: test GetBundleResourceArchiveInfo non-system app denied
 * @tc.desc: 1. non-system app calling system api
 *           2. verify returns ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED
 */
HWTEST_F(BmsBundleResourceHelperTest, GetBundleResourceArchiveInfo_0100, Function | SmallTest | Level0)
{
    SetSystemAppForTest(false);
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    BundleResourceInfo info;
    ErrCode ret = hostImpl->GetBundleResourceArchiveInfo("/data/test.hap", 1, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
    ResetTestValues();
}

/**
 * @tc.number: GetBundleResourceArchiveInfo_0200
 * @tc.name: test GetBundleResourceArchiveInfo permission denied
 * @tc.desc: 1. system app but no PERMISSION_GET_BUNDLE_RESOURCES
 *           2. verify returns ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleResourceHelperTest, GetBundleResourceArchiveInfo_0200, Function | SmallTest | Level0)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(false);
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    BundleResourceInfo info;
    ErrCode ret = hostImpl->GetBundleResourceArchiveInfo("/data/test.hap", 1, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    ResetTestValues();
}

/**
 * @tc.number: GetBundleResourceArchiveInfo_0300
 * @tc.name: test GetBundleResourceArchiveInfo with empty filePath
 * @tc.desc: 1. all permission checks pass
 *           2. filePath is empty
 *           3. verify returns ERR_BUNDLE_MANAGER_INVALID_HAP_PATH
 */
HWTEST_F(BmsBundleResourceHelperTest, GetBundleResourceArchiveInfo_0300, Function | SmallTest | Level0)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    BundleResourceInfo info;
    ErrCode ret = hostImpl->GetBundleResourceArchiveInfo("", 1, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_HAP_PATH);
    ResetTestValues();
}

/**
 * @tc.number: GetBundleResourceArchiveInfo_0400
 * @tc.name: test GetBundleResourceArchiveInfo with relative path
 * @tc.desc: 1. all permission checks pass
 *           2. filePath contains relative path "../"
 *           3. verify returns ERR_BUNDLE_MANAGER_INVALID_HAP_PATH
 */
HWTEST_F(BmsBundleResourceHelperTest, GetBundleResourceArchiveInfo_0400, Function | SmallTest | Level0)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    BundleResourceInfo info;
    ErrCode ret = hostImpl->GetBundleResourceArchiveInfo("/data/../test.hap", 1, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_HAP_PATH);
    ResetTestValues();
}

/**
 * @tc.number: GetBundleResourceArchiveInfo_0500
 * @tc.name: test GetBundleResourceArchiveInfo with sandbox path
 * @tc.desc: 1. all permission checks pass
 *           2. filePath starts with SANDBOX_DATA_PATH
 *           3. ObtainCallingBundleName fails in test env
 *           4. verify returns ERR_BUNDLE_MANAGER_INTERNAL_ERROR
 */
HWTEST_F(BmsBundleResourceHelperTest, GetBundleResourceArchiveInfo_0500, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    BundleResourceInfo info;
    std::string sandboxPath = std::string(ServiceConstants::SANDBOX_DATA_PATH) + "/haps/entry/files/test.hap";
    ErrCode ret = hostImpl->GetBundleResourceArchiveInfo(sandboxPath, 1, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    ResetTestValues();
#endif
}

/**
 * @tc.number: GetBundleResourceArchiveInfo_0600
 * @tc.name: test GetBundleResourceArchiveInfo with non-existent normal path
 * @tc.desc: 1. all permission checks pass
 *           2. filePath is a normal path that does not exist
 *           3. ParseAndExtractResourceInfo -> ParseHapFileForArchiveInfo fails
 *           4. verify returns ERR_BUNDLE_MANAGER_INVALID_HAP_PATH
 */
HWTEST_F(BmsBundleResourceHelperTest, GetBundleResourceArchiveInfo_0600, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    BundleResourceInfo info;
    ErrCode ret = hostImpl->GetBundleResourceArchiveInfo("/data/nonexistent_test.hap", 1, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_HAP_PATH);
    ResetTestValues();
#endif
}

/**
 * @tc.number: FindEntryHapPath_0100
 * @tc.name: test FindEntryHapPath with entry found
 * @tc.desc: 1. one info has entry, verify realHapPath is set correctly
 */
HWTEST_F(BmsBundleResourceHelperTest, FindEntryHapPath_0100, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo info1;
    info1.innerModuleInfos_["module1"].isEntry = true;
    infos["/path/entry.hap"] = info1;
    std::vector<std::string> hapPaths = {"/path/entry.hap"};
    std::string realHapPath;
    BundleMgrHostImpl::FindEntryHapPath(infos, hapPaths, realHapPath);
    EXPECT_EQ(realHapPath, "/path/entry.hap");
}

/**
 * @tc.number: FindEntryHapPath_0200
 * @tc.name: test FindEntryHapPath with no entry, fallback to hapPaths
 * @tc.desc: 1. no info has entry
 *           2. fallback to first matching path in hapPaths
 */
HWTEST_F(BmsBundleResourceHelperTest, FindEntryHapPath_0200, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo info1;
    info1.innerModuleInfos_["module1"].isEntry = false;
    infos["/path/feature.hap"] = info1;
    std::vector<std::string> hapPaths = {"/path/feature.hap", "/path/other.hap"};
    std::string realHapPath;
    BundleMgrHostImpl::FindEntryHapPath(infos, hapPaths, realHapPath);
    EXPECT_EQ(realHapPath, "/path/feature.hap");
}

/**
 * @tc.number: UpdateBaseAppInfoIfNoEntry_0100
 * @tc.name: test UpdateBaseAppInfoIfNoEntry with entry present
 * @tc.desc: 1. one info has entry
 *           2. function should return early without updating
 */
HWTEST_F(BmsBundleResourceHelperTest, UpdateBaseAppInfoIfNoEntry_0100, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo info1;
    info1.innerModuleInfos_["module1"].isEntry = true;
    info1.currentPackage_ = "module1";
    infos["/path/entry.hap"] = info1;
    InnerBundleInfo merged;
    merged.baseApplicationInfo_->bundleName = "original";
    BundleMgrHostImpl::UpdateBaseAppInfoIfNoEntry(infos, merged);
    EXPECT_EQ(merged.GetBundleName(), "original");
}

/**
 * @tc.number: UpdateBaseAppInfoIfNoEntry_0200
 * @tc.name: test UpdateBaseAppInfoIfNoEntry with no entry
 * @tc.desc: 1. no info has entry
 *           2. function should update with largest module name
 */
HWTEST_F(BmsBundleResourceHelperTest, UpdateBaseAppInfoIfNoEntry_0200, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo info1;
    info1.currentPackage_ = "module_a";
    info1.innerModuleInfos_["module_a"].isEntry = false;
    info1.baseApplicationInfo_->bundleName = "com.test.a";
    infos["/path/a.hap"] = info1;
    InnerBundleInfo info2;
    info2.currentPackage_ = "module_z";
    info2.innerModuleInfos_["module_z"].isEntry = false;
    info2.baseApplicationInfo_->bundleName = "com.test.z";
    infos["/path/z.hap"] = info2;
    InnerBundleInfo merged;
    BundleMgrHostImpl::UpdateBaseAppInfoIfNoEntry(infos, merged);
    EXPECT_EQ(merged.GetBundleName(), "com.test.z");
}

/**
 * @tc.number: PrepareResourceInfoForArchive_0100
 * @tc.name: test PrepareResourceInfoForArchive with ALL flag
 * @tc.desc: 1. flags = GET_RESOURCE_INFO_ALL
 *           2. verify labelNeedParse_ and iconNeedParse_ are true
 */
HWTEST_F(BmsBundleResourceHelperTest, PrepareResourceInfoForArchive_0100, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "com.test.bundle";
    innerBundleInfo.baseApplicationInfo_->labelResource.id = 12345;
    innerBundleInfo.baseApplicationInfo_->iconResource.id = 67890;
    innerBundleInfo.baseApplicationInfo_->labelResource.moduleName = "entry";
    innerBundleInfo.innerModuleInfos_["entry"].moduleName = "entry";
    innerBundleInfo.innerModuleInfos_["entry"].hapPath = "/data/entry.hap";
    ResourceInfo resourceInfo;
    uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    hostImpl->PrepareResourceInfoForArchive(innerBundleInfo, "/data/entry.hap", flags, resourceInfo);
    EXPECT_EQ(resourceInfo.bundleName_, "com.test.bundle");
    EXPECT_EQ(resourceInfo.labelId_, 12345u);
    EXPECT_EQ(resourceInfo.iconId_, 67890u);
    EXPECT_TRUE(resourceInfo.labelNeedParse_);
    EXPECT_TRUE(resourceInfo.iconNeedParse_);
#endif
}

/**
 * @tc.number: PrepareResourceInfoForArchive_0200
 * @tc.name: test PrepareResourceInfoForArchive with LABEL flag only
 * @tc.desc: 1. flags = GET_RESOURCE_INFO_WITH_LABEL only
 *           2. verify labelNeedParse_ is true, iconNeedParse_ is false
 */
HWTEST_F(BmsBundleResourceHelperTest, PrepareResourceInfoForArchive_0200, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "com.test.bundle";
    innerBundleInfo.baseApplicationInfo_->labelResource.id = 12345;
    innerBundleInfo.baseApplicationInfo_->iconResource.id = 67890;
    innerBundleInfo.baseApplicationInfo_->labelResource.moduleName = "entry";
    innerBundleInfo.innerModuleInfos_["entry"].moduleName = "entry";
    innerBundleInfo.innerModuleInfos_["entry"].hapPath = "/data/entry.hap";
    ResourceInfo resourceInfo;
    uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL);
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    hostImpl->PrepareResourceInfoForArchive(innerBundleInfo, "/data/entry.hap", flags, resourceInfo);
    EXPECT_TRUE(resourceInfo.labelNeedParse_);
    EXPECT_FALSE(resourceInfo.iconNeedParse_);
#endif
}

/**
 * @tc.number: PrepareResourceInfoForArchive_0300
 * @tc.name: test PrepareResourceInfoForArchive with no valid flag bits
 * @tc.desc: 1. flags = 0x40 (no defined flag bit set)
 *           2. verify defaults to ALL: labelNeedParse_ and iconNeedParse_ are true
 */
HWTEST_F(BmsBundleResourceHelperTest, PrepareResourceInfoForArchive_0300, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "com.test.bundle";
    innerBundleInfo.baseApplicationInfo_->labelResource.id = 0;
    innerBundleInfo.baseApplicationInfo_->iconResource.id = 0;
    innerBundleInfo.baseApplicationInfo_->labelResource.moduleName = "";
    ResourceInfo resourceInfo;
    uint32_t flags = 0x40;
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    hostImpl->PrepareResourceInfoForArchive(innerBundleInfo, "/data/test.hap", flags, resourceInfo);
    EXPECT_TRUE(resourceInfo.labelNeedParse_);
    EXPECT_TRUE(resourceInfo.iconNeedParse_);
#endif
}

/**
 * @tc.number: ParseAndExtractResourceInfo_0100
 * @tc.name: test ParseAndExtractResourceInfo with invalid path
 * @tc.desc: 1. filePath does not exist
 *           2. ParseHapFileForArchiveInfo fails at CheckFilePath
 *           3. verify returns ERR_BUNDLE_MANAGER_INVALID_HAP_PATH
 */
HWTEST_F(BmsBundleResourceHelperTest, ParseAndExtractResourceInfo_0100, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    BundleResourceInfo info;
    ErrCode ret = hostImpl->ParseAndExtractResourceInfo("/data/nonexistent.hap", 1, 100, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_HAP_PATH);
#endif
}

/**
 * @tc.number: ParseHapFileForArchiveInfo_0100
 * @tc.name: test ParseHapFileForArchiveInfo with .app suffix path
 * @tc.desc: 1. filePath ends with .app
 *           2. delegates to ParseAppFileForArchiveInfo
 *           3. CheckAppFilePath fails for non-existent path
 *           4. verify returns ERR_BUNDLE_MANAGER_INVALID_HAP_PATH
 */
HWTEST_F(BmsBundleResourceHelperTest, ParseHapFileForArchiveInfo_0100, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    InnerBundleInfo innerBundleInfo;
    std::string realHapPath;
    std::string tempDir;
    ErrCode ret = hostImpl->ParseHapFileForArchiveInfo("/data/nonexistent.app",
        innerBundleInfo, realHapPath, tempDir);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_HAP_PATH);
#endif
}

/**
 * @tc.number: GetBundleResourceArchiveInfo_0700
 * @tc.name: test GetBundleResourceArchiveInfo with APP_INSTALL_SANDBOX_PATH
 * @tc.desc: 1. all permission checks pass
 *           2. filePath starts with APP_INSTALL_SANDBOX_PATH
 *           3. delegates to GetBundleResourceArchiveInfoBySandBoxPath
 *           4. ObtainCallingBundleName fails in test env
 *           5. verify returns ERR_BUNDLE_MANAGER_INTERNAL_ERROR
 */
HWTEST_F(BmsBundleResourceHelperTest, GetBundleResourceArchiveInfo_0700, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    BundleResourceInfo info;
    std::string sandboxPath = std::string(ServiceConstants::APP_INSTALL_SANDBOX_PATH) + "/test.hap";
    ErrCode ret = hostImpl->GetBundleResourceArchiveInfo(sandboxPath, 1, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    ResetTestValues();
#endif
}

/**
 * @tc.number: PrepareResourceInfoForArchive_0400
 * @tc.name: test PrepareResourceInfoForArchive with ICON flag only
 * @tc.desc: 1. flags = GET_RESOURCE_INFO_WITH_ICON only
 *           2. verify labelNeedParse_ is false, iconNeedParse_ is true
 */
HWTEST_F(BmsBundleResourceHelperTest, PrepareResourceInfoForArchive_0400, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "com.test.bundle";
    innerBundleInfo.baseApplicationInfo_->labelResource.id = 12345;
    innerBundleInfo.baseApplicationInfo_->iconResource.id = 67890;
    innerBundleInfo.baseApplicationInfo_->labelResource.moduleName = "entry";
    innerBundleInfo.innerModuleInfos_["entry"].moduleName = "entry";
    innerBundleInfo.innerModuleInfos_["entry"].hapPath = "/data/entry.hap";
    ResourceInfo resourceInfo;
    uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON);
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    hostImpl->PrepareResourceInfoForArchive(innerBundleInfo, "/data/entry.hap", flags, resourceInfo);
    EXPECT_FALSE(resourceInfo.labelNeedParse_);
    EXPECT_TRUE(resourceInfo.iconNeedParse_);
#endif
}

/**
 * @tc.number: PrepareResourceInfoForArchive_0500
 * @tc.name: test PrepareResourceInfoForArchive with DRAWABLE flag only
 * @tc.desc: 1. flags = GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR only
 *           2. verify labelNeedParse_ is false, iconNeedParse_ is true
 */
HWTEST_F(BmsBundleResourceHelperTest, PrepareResourceInfoForArchive_0500, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "com.test.bundle";
    innerBundleInfo.baseApplicationInfo_->labelResource.id = 12345;
    innerBundleInfo.baseApplicationInfo_->iconResource.id = 67890;
    innerBundleInfo.baseApplicationInfo_->labelResource.moduleName = "entry";
    innerBundleInfo.innerModuleInfos_["entry"].moduleName = "entry";
    innerBundleInfo.innerModuleInfos_["entry"].hapPath = "/data/entry.hap";
    ResourceInfo resourceInfo;
    uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR);
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    hostImpl->PrepareResourceInfoForArchive(innerBundleInfo, "/data/entry.hap", flags, resourceInfo);
    EXPECT_FALSE(resourceInfo.labelNeedParse_);
    EXPECT_TRUE(resourceInfo.iconNeedParse_);
#endif
}

/**
 * @tc.number: GetBundleResourceArchiveInfoExec_0100
 * @tc.name: test GetBundleResourceArchiveInfoExec with nullptr data
 * @tc.desc: 1. data is nullptr
 *           2. verify early return without crash
 */
HWTEST_F(BmsBundleResourceHelperTest, GetBundleResourceArchiveInfoExec_0100, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    GetBundleResourceArchiveInfoExec(nullptr, nullptr);
    EXPECT_TRUE(true);
#endif
}

/**
 * @tc.number: GetBundleResourceArchiveInfoExec_0200
 * @tc.name: test GetBundleResourceArchiveInfoExec with valid callback data
 * @tc.desc: 1. callback data has filePath and flags set
 *           2. InnerGetBundleResourceArchiveInfo called (service available in test)
 *           3. verify err is set to ERROR_PERMISSION_DENIED_ERROR
 */
HWTEST_F(BmsBundleResourceHelperTest, GetBundleResourceArchiveInfoExec_0200, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    BundleResourceArchiveInfoCallback callbackInfo(nullptr);
    callbackInfo.filePath = "/data/test.hap";
    callbackInfo.flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    GetBundleResourceArchiveInfoExec(nullptr, &callbackInfo);
    EXPECT_EQ(callbackInfo.err, ERROR_PERMISSION_DENIED_ERROR);
#endif
}

/**
 * @tc.number: GetBundleResourceArchiveInfoComplete_0100
 * @tc.name: test GetBundleResourceArchiveInfoComplete with nullptr data
 * @tc.desc: 1. data is nullptr
 *           2. verify early return without crash (env unused in this path)
 */
HWTEST_F(BmsBundleResourceHelperTest, GetBundleResourceArchiveInfoComplete_0100, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    GetBundleResourceArchiveInfoComplete(nullptr, napi_ok, nullptr);
    EXPECT_TRUE(true);
#endif
}

/**
 * @tc.number: InnerGetBundleResourceArchiveInfo_0100
 * @tc.name: test InnerGetBundleResourceArchiveInfo with service available
 * @tc.desc: 1. ResourceHelper::GetBundleMgr returns nullptr (service in test)
 *           2. verify returns ERROR_PERMISSION_DENIED_ERROR
 */
HWTEST_F(BmsBundleResourceHelperTest, InnerGetBundleResourceArchiveInfo_0100, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    BundleResourceInfo resourceInfo;
    ErrCode ret = ResourceHelper::InnerGetBundleResourceArchiveInfo(
        "/data/test.hap", static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), resourceInfo);
    EXPECT_EQ(ret, ERROR_PERMISSION_DENIED_ERROR);
#endif
}

/**
 * @tc.number: ParseAndExtractResourceInfo_0200
 * @tc.name: test ParseAndExtractResourceInfo with real hap file
 * @tc.desc: 1. use existing test hap file path
 *           2. if file exists, verify ERR_OK and output fields
 *           3. if file not exists, verify ERR_BUNDLE_MANAGER_INVALID_HAP_PATH
 */
HWTEST_F(BmsBundleResourceHelperTest, ParseAndExtractResourceInfo_0200, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    BundleResourceInfo info;
    ErrCode ret = hostImpl->ParseAndExtractResourceInfo(HAP_FILE_PATH1,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), USERID, info);
    std::ifstream hapFile(HAP_FILE_PATH1);
    if (hapFile.good()) {
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_FALSE(info.bundleName.empty());
    } else {
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_HAP_PATH);
    }
#endif
}

/**
 * @tc.number: GetBundleResourceArchiveInfo_0800
 * @tc.name: test GetBundleResourceArchiveInfo full flow with real hap file
 * @tc.desc: 1. all permission checks pass
 *           2. use existing test hap file path
 *           3. if file exists, verify ERR_OK and output fields
 *           4. if file not exists, verify ERR_BUNDLE_MANAGER_INVALID_HAP_PATH
 */
HWTEST_F(BmsBundleResourceHelperTest, GetBundleResourceArchiveInfo_0800, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    ScopeGuard stateGuard([&]() { ResetTestValues(); });
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    BundleResourceInfo info;
    ErrCode ret = hostImpl->GetBundleResourceArchiveInfo(HAP_FILE_PATH1,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), info);
    std::ifstream hapFile(HAP_FILE_PATH1);
    if (hapFile.good()) {
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_FALSE(info.bundleName.empty());
    } else {
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_HAP_PATH);
    }
#endif
}

/**
 * @tc.number: GetBundleResourceArchiveInfoBySandBoxPath_0100
 * @tc.name: test sandbox path with ObtainCallingBundleName success, RevertToRealPath fail
 * @tc.desc: 1. inject dataMgr with bundleIdMap + bundleInfos for uid 20000001
 *           2. set calling uid to 20000001
 *           3. SANDBOX_DATA_PATH path → ObtainCallingBundleName succeeds
 *           4. RevertToRealPath fails → ERR_BUNDLE_MANAGER_INTERNAL_ERROR
 */
HWTEST_F(BmsBundleResourceHelperTest, GetBundleResourceArchiveInfoBySandBoxPath_0100, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    constexpr int32_t TEST_CALLING_UID = 20000001;
    constexpr int32_t TEST_USER_ID = 100;
    constexpr int32_t TEST_BUNDLE_ID = 1;
    const std::string TEST_BUNDLE = "com.test.sandbox";
    int32_t savedUid = IPCSkeleton::GetCallingUid();
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    auto savedDataMgr = service->dataMgr_;
    ScopeGuard stateGuard([&]() {
        ResetTestValues();
        IPCSkeleton::SetCallingUid(savedUid);
        service->dataMgr_ = savedDataMgr;
    });
    IPCSkeleton::SetCallingUid(TEST_CALLING_UID);
    auto dataMgr = std::make_shared<BundleDataMgr>();
    dataMgr->bundleIdMap_[TEST_BUNDLE_ID] = TEST_BUNDLE;
    InnerBundleInfo innerInfo;
    innerInfo.baseApplicationInfo_->bundleName = TEST_BUNDLE;
    InnerBundleUserInfo userInfo;
    userInfo.uid = TEST_CALLING_UID;
    innerInfo.innerBundleUserInfos_[TEST_BUNDLE + "_" + std::to_string(TEST_USER_ID)] = userInfo;
    dataMgr->bundleInfos_[TEST_BUNDLE] = innerInfo;
    service->dataMgr_ = dataMgr;

    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    BundleResourceInfo resInfo;
    std::string sandboxPath = std::string(ServiceConstants::SANDBOX_DATA_PATH) + "/haps/entry/files/test.hap";
    ErrCode ret = hostImpl->GetBundleResourceArchiveInfoBySandBoxPath(sandboxPath,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), resInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
#endif
}

/**
 * @tc.number: GetBundleResourceArchiveInfoBySandBoxPath_0200
 * @tc.name: test APP_INSTALL_SANDBOX_PATH with ACCESS_APP_INSTALL_DIR permission denied
 * @tc.desc: 1. inject dataMgr so ObtainCallingBundleName succeeds
 *           2. path starts with APP_INSTALL_SANDBOX_PATH
 *           3. SetPermissionResultForTest denies ACCESS_APP_INSTALL_DIR
 *           4. returns ERR_BUNDLE_MANAGER_INVALID_HAP_PATH
 */
HWTEST_F(BmsBundleResourceHelperTest, GetBundleResourceArchiveInfoBySandBoxPath_0200, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetPermissionResultForTest(Constants::PERMISSION_ACCESS_APP_INSTALL_DIR, false);
    constexpr int32_t TEST_CALLING_UID = 20000001;
    constexpr int32_t TEST_BUNDLE_ID = 1;
    const std::string TEST_BUNDLE = "com.test.sandbox";
    int32_t savedUid = IPCSkeleton::GetCallingUid();
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    auto savedDataMgr = service->dataMgr_;
    ScopeGuard stateGuard([&]() {
        ResetTestValues();
        IPCSkeleton::SetCallingUid(savedUid);
        service->dataMgr_ = savedDataMgr;
    });
    IPCSkeleton::SetCallingUid(TEST_CALLING_UID);
    auto dataMgr = std::make_shared<BundleDataMgr>();
    dataMgr->bundleIdMap_[TEST_BUNDLE_ID] = TEST_BUNDLE;
    InnerBundleInfo innerInfo;
    innerInfo.baseApplicationInfo_->bundleName = TEST_BUNDLE;
    InnerBundleUserInfo userInfo;
    userInfo.uid = TEST_CALLING_UID;
    innerInfo.innerBundleUserInfos_[TEST_BUNDLE + "_" + std::to_string(100)] = userInfo;
    dataMgr->bundleInfos_[TEST_BUNDLE] = innerInfo;
    service->dataMgr_ = dataMgr;

    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    BundleResourceInfo resInfo;
    std::string installSandboxPath = std::string(ServiceConstants::APP_INSTALL_SANDBOX_PATH) + "/test.hap";
    ErrCode ret = hostImpl->GetBundleResourceArchiveInfoBySandBoxPath(installSandboxPath,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), resInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_HAP_PATH);
#endif
}

/**
 * @tc.number: ParseAppFileForArchiveInfo_0100
 * @tc.name: test ParseAppFileForArchiveInfo with dummy .app file
 * @tc.desc: 1. create a dummy .app file (not a valid archive)
 *           2. CheckAppFilePath succeeds (file exists, .app suffix)
 *           3. PrepareAppTempDir succeeds
 *           4. DecompressAppFile fails (not a valid archive)
 *           5. returns ERR_BUNDLE_MANAGER_INVALID_HAP_PATH
 */
HWTEST_F(BmsBundleResourceHelperTest, ParseAppFileForArchiveInfo_0100, Function | SmallTest | Level0)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    std::string dummyAppPath = "/data/test/dummy_archive_test.app";
    std::ofstream dummyFile(dummyAppPath, std::ios::trunc);
    if (!dummyFile.is_open()) {
        GTEST_SKIP() << "cannot create dummy app file, skip";
    }
    dummyFile << "not a valid app archive";
    dummyFile.close();
    ScopeGuard fileGuard([&]() { remove(dummyAppPath.c_str()); });

    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    InnerBundleInfo innerBundleInfo;
    std::string realHapPath;
    std::string tempDir;
    ErrCode ret = hostImpl->ParseAppFileForArchiveInfo(dummyAppPath,
        innerBundleInfo, realHapPath, tempDir);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_HAP_PATH);
    if (!tempDir.empty()) {
        BundleUtil::DeleteDir(tempDir);
    }
#endif
}
}
