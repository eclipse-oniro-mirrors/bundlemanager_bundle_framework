/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include <chrono>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "bundle_constants.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "install_param.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "parameters.h"
#include "system_bundle_installer.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using namespace OHOS;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.l3jsdemo";
const std::string BUNDLE_NAME_2 = "com.example.bmstest.demo";
const std::string ABILITY_NAME_TEST = "EntryAbility";
const std::string PROCESS_NAME_1 = ":A";
const std::string PROCESS_NAME_2 = ":B";
const std::string PROCESS_NAME_3 = ":C";
const std::string SERVICE_BUNDLE_NAME = "com.example.myapplication.hmservice";
const std::string RESOURCE_ROOT_PATH = "/data/test/resource/bms/install_bundle/";
const std::string RESOURCE_TEST_PATH = "/data/test/resource/bms/install_bundle/test/";
const std::string RESOURCE_TEST1_PATH = "/data/test/resource/bms/install_bundle/test1/";
const std::string RESOURCE_TEST2_PATH = "/data/test/resource/bms/install_bundle/test2/";
const std::string RESOURCE_TEST3_PATH = "/data/test/resource/bms/install_bundle/test3/";
const std::string RESOURCE_TEST4_PATH = "/data/test/resource/bms/install_bundle/test4/";
const std::string INVALID_PATH = "/install_bundle/";
const std::string RIGHT_BUNDLE = "right.hap";
const std::string RIGHT_BUNDLE_FIRST = "first_right.hap";
const std::string RIGHT_BUNDLE_SECOND = "second_right.hap";
const std::string RIGHT_BUNDLE_THIRD = "third_right.hap";
const std::string RIGHT_BUNDLE_FOURTH = "fourth_right.hap";
const std::string RIGHT_BUNDLE_FIFTH = "fifth_right.hap";
const std::string RIGHT_BUNDLE_SIXTH = "sixth_right.hap";
const std::string RIGHT_BUNDLE_SEVENTH = "seventh_right.hap";
const std::string RIGHT_BUNDLE_EIGHTH = "eighth_right.hap";
const std::string RIGHT_BUNDLE_NINTH = "ninth_right.hap";
const std::string RIGHT_BUNDLE_TENTH = "tenth_right.hap";
const std::string RIGHT_BUNDLE_ELEVENTH = "eleventh_right.hap";
const std::string RIGHT_BUNDLE_SECOND_BACKUP = "second_backup_right.hap";
const std::string RIGHT_BUNDLE_TEST = "test_right.hap";
const std::string RIGHT_BUNDLE_THIRTEENTH = "thirteenth_right.hap";
const std::string RIGHT_BUNDLE_FOURTEENTH = "fourteenth_right.hap";
const std::string RIGHT_BUNDLE_FIFTEENTH = "fifteenth_right.hap";
const std::string RIGHT_BUNDLE_SIXTEENTH = "sixteenth_right.hap";
const std::string RIGHT_BUNDLE_TWELFTH = "twelfth_right.hap";
const std::string INVALID_BUNDLE = "nonfile.hap";
const std::string WRONG_BUNDLE_NAME = "wrong_bundle_name.ha";
const std::string RIGHT_DIFFERENT_RELEASE_TYPE = "first_diff_release_type.hap";
const std::string RIGHT_COMPATIBLE_VERSION_CODE = "first_right_compCode.hap";
const std::string RIGHT_DIFFERENT_COMPATIBLE_VERSION_CODE = "first_diff_minCompCode.hap";
const std::string RIGHT_DIFFERENT_MODULE_TYPE = "first_right_with_diff_moduleType.hap";
const std::string TEST_HAP_DEMO = "testhapdemo.hap";
const std::string TEST_HAP_DEMO_2 = "testhapdemo2.hap";
const std::string TEST_HAP_DEMO_3 = "testhapdemo3.hap";

const std::string BUNDLE_DATA_DIR = "/data/app/el2/100/base/com.example.l3jsdemo";
const std::string BUNDLE_CODE_DIR = "/data/app/el1/bundle/public/com.example.l3jsdemo";
const std::string PACKAGE_NAME_FIRST = "entry";
const std::string PACKAGE_NAME_SECOND = "l2jsdemo";
const std::string PACKAGE_NAME_THIRD = "com.example.l1jsdemo";
const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
const std::vector<std::string> BUNDLE_DATA_DIR_PAGENAME = {
    "cache",
    "files",
    "temp",
    "preferences",
    "haps",
};

// --- SPM ON install prerequisite -------------------------------------------
// The suite keeps the SPM switch ON (the device default, see
// BundleSpmManager::IsEnabled) and solves the hap sign verification
// positively: the mocked access-token boundary is fed the per-hap data the
// real AT side would return for the installed haps, so every install runs
// the complete SPM ON chain (CheckSignAndInitSession -> provision parse ->
// CheckProvisionInfoIsValid -> CheckPermissionInfo -> PrepareHapIdentity ->
// installd provision query -> FinishInstall). This suite installs many
// single haps, multi-hap arrays and whole directories (whose hap enumeration
// order is not deterministic), and covers three bundles — so every hap file
// is registered by file name with a provision matching its package name
// (CheckBundleName cross-checks the provision against the hap's parsed
// package name).
// The provisions mirror the fields of the REAL profiles the haps are signed
// with (sceneProject/signature/*.p7b): the l3jsdemo family (first_right and
// siblings, right, third_right's heihei profile) is signed with the legacy
// OpenHarmony system profile — release / os_integration / apl system_core /
// hos_system_app / NO app-identifier — so the parsed ProvisionInfo carries
// the same SYSTEM_APP identity and the same empty appIdentifier as under
// SPM OFF (a fabricated appIdentifier would surface in the keep-data
// CheckAppIdentifier comparison). testhapdemo's real profile
// (com.example.bmstest.demo.p7b) is release / app_gallery / normal /
// hos_normal_app with its real app-identifier. seventh_right.hap keeps the
// semantics of its real signature (com.example.l3jsdemoerror.p7b — the same
// profile JSON but a DIFFERENT signing certificate): the mock cannot
// reproduce a signature-block-derived app id from the provision raw alone,
// so its entry carries an explicit odd profileData.appId, which makes
// MultipleHapsInstall_2600 still fail the cross-hap appId consistency check
// (CheckProvisionInfoIsValid) exactly like under SPM OFF.
constexpr int32_t TEST_SPM_SESSION_ID = 4242;
constexpr uint64_t TEST_SPM_TOKEN_ID = 101;
// InitToken rejects a uid outside the installing user's uid segment, so the
// AT-allocated identity must be valid for USERID.
constexpr int32_t TEST_SPM_UID = USERID * Constants::BASE_USER_RANGE + 102;
const std::string BUNDLE_NAME_THIRD = "com.example.heiheiApplication";
// The signature-block-derived app id handed back for seventh_right.hap: any
// value different from the JSON-derived app id of the other l3jsdemo haps
// triggers the odd-one-out branch of CheckProvisionInfoIsValid.
const std::string ODD_SPM_APP_ID = "bms-spm-test-odd-app-id";

void SetUpSpmTrustedSignInfoForTest()
{
    // Mirrors the legacy OpenHarmony system profile of com.example.l3jsdemo.p7b
    // (and third_right's com.example.heiheiApplication.p7b): no app-identifier
    // field, apl system_core, hos_system_app.
    const std::string provision = Security::AccessToken::MakeSpmReleaseProvisionRawForTest(
        BUNDLE_NAME, "os_integration", false, "hos_system_app", "system_core", "");
    const std::string provisionThird = Security::AccessToken::MakeSpmReleaseProvisionRawForTest(
        BUNDLE_NAME_THIRD, "os_integration", false, "hos_system_app", "system_core", "");
    // Mirrors com.example.bmstest.demo.p7b: app_gallery with its real
    // app-identifier.
    const std::string provisionDemo = Security::AccessToken::MakeSpmReleaseProvisionRawForTest(
        BUNDLE_NAME_2, "app_gallery", false, "hos_normal_app", "normal", "5765880207856214783");
    for (const auto &hapName : std::vector<std::string> {
        RIGHT_BUNDLE_FIRST, RIGHT_BUNDLE_SECOND, RIGHT_BUNDLE, RIGHT_BUNDLE_FOURTH,
        RIGHT_BUNDLE_FIFTH, RIGHT_BUNDLE_SIXTH, RIGHT_BUNDLE_EIGHTH, RIGHT_BUNDLE_NINTH,
        RIGHT_BUNDLE_TENTH, RIGHT_BUNDLE_ELEVENTH, RIGHT_BUNDLE_TWELFTH, RIGHT_BUNDLE_THIRTEENTH,
        RIGHT_BUNDLE_FOURTEENTH, RIGHT_BUNDLE_FIFTEENTH, RIGHT_BUNDLE_SIXTEENTH,
        RIGHT_BUNDLE_SECOND_BACKUP, RIGHT_DIFFERENT_RELEASE_TYPE, RIGHT_COMPATIBLE_VERSION_CODE,
        RIGHT_DIFFERENT_COMPATIBLE_VERSION_CODE, RIGHT_DIFFERENT_MODULE_TYPE,
        "version1.hap", "version2.hap", "version3.hap", "right1.hap",
    }) {
        Security::AccessToken::SetSpmTrustedProvisionForHapFileForTest(hapName, provision);
    }
    Security::AccessToken::SetSpmTrustedProvisionForHapFileForTest(RIGHT_BUNDLE_THIRD, provisionThird);
    Security::AccessToken::SetSpmTrustedProvisionForHapFileForTest(RIGHT_BUNDLE_SEVENTH,
        provision, ODD_SPM_APP_ID);
    Security::AccessToken::SetSpmTrustedProvisionForHapFileForTest(TEST_HAP_DEMO, provisionDemo);
    Security::AccessToken::SetSpmTrustedProvisionForHapFileForTest(TEST_HAP_DEMO_2, provisionDemo);
    Security::AccessToken::SetSpmTrustedProvisionForHapFileForTest(TEST_HAP_DEMO_3, provisionDemo);
    Security::AccessToken::SetSpmCheckHapSignInfoSessionIdForTest(TEST_SPM_SESSION_ID);
    Security::AccessToken::SetSpmPrepareIdentityForTest(TEST_SPM_TOKEN_ID, TEST_SPM_UID);
    // The mock parameter map makes const.bms.supportAppTypes read empty (on a
    // real device it is a non-empty device-type list): testhapdemo.hap is an
    // old-toolchain product without rpcid.sc and with deviceTypes that miss
    // the "default" entry, so CheckSysCap fails with PARSE_RPCID_FAILED and
    // the install drops into CheckDeviceType, where only the non-empty
    // supportAppTypes fast path (the device behavior this suite has always
    // relied on) lets it through. Mirror a full device-type list so every
    // non-empty hap deviceTypes vector intersects it.
    OHOS::system::SetParameter("const.bms.supportAppTypes", "default,phone,tablet,2in1");
}

void ClearSpmLeftoverUninstallRecordsForTest()
{
    // Leftover persistent state of this suite's bundles must be wiped before
    // the first install, or the fresh installs are rejected with
    // INCONSISTENT_SIGNATURE (8519755) through two paths:
    // - a leftover keep-data uninstall record (from earlier runs or sibling
    //   suites on a shared device) stores the app id the REAL signature
    //   derived; the mocked provision derives a different one, so
    //   CheckInstallOnKeepData fails the comparison;
    // - a leftover installed bundle-info record (e.g. persisted by an
    //   earlier run of a PREVIOUS mock-provision revision, whose
    //   app-identifier/provision id differ from the current one) makes the
    //   first install run the update branch, where CheckAppIdentifier
    //   compares the stored values against the freshly derived ones and
    //   fails on the cross-revision mismatch. Run the full
    //   INSTALL_START -> UNINSTALL_START -> UNINSTALL_SUCCESS chain (the
    //   plain UNINSTALL_START of ClearBundleInfo cannot transfer without a
    //   state entry, which a cold-reloaded record has) so DeleteBundleInfo
    //   wipes BOTH the in-memory info and the RDB row.
    // The installs of this suite never keep data, so a clean state is the
    // only behavior the suite has ever asserted.
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    for (const auto &bundleName : {BUNDLE_NAME, BUNDLE_NAME_THIRD, BUNDLE_NAME_2}) {
        InnerBundleInfo leftoverInfo;
        if (dataMgr->FetchInnerBundleInfo(bundleName, leftoverInfo)) {
            dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
            dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START);
            dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS);
        }
        dataMgr->DeleteUninstallBundleInfo(bundleName, USERID);
    }
}
}  // namespace

class BmsMultipleInstallerTest : public testing::Test {
public:
    BmsMultipleInstallerTest();
    ~BmsMultipleInstallerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallThirdPartyBundle(const std::string &filePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName, int32_t userId) const;
    ErrCode UpdateThirdPartyBundle(const std::string &filePath) const;
    ErrCode InstallThirdPartyMultipleBundles(const std::vector<std::string> &filePaths, bool &&flag) const;
    void CheckFileExist() const;
    void CheckFileNonExist() const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StopInstalldService() const;
    void StopBundleService();
    void ClearBundleInfo(const std::string &bundleName) const;
    void CheckModuleFileExist() const;
    void CheckModuleFileNonExist(const std::string &packageName) const;
    void IsContainModuleInfo(const BundleInfo &info, const std::string &packageName1) const;

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsMultipleInstallerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsMultipleInstallerTest::installdService_ =
    std::make_shared<InstalldService>();

BmsMultipleInstallerTest::BmsMultipleInstallerTest()
{}

BmsMultipleInstallerTest::~BmsMultipleInstallerTest()
{}

ErrCode BmsMultipleInstallerTest::InstallThirdPartyBundle(const std::string &filePath) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
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
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.withCopyHaps = true;
    bool result = installer->Install(filePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsMultipleInstallerTest::UnInstallBundle(const std::string &bundleName, int32_t userId) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
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
    installParam.userId = userId;
    installParam.installFlag = InstallFlag::NORMAL;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsMultipleInstallerTest::InstallThirdPartyMultipleBundles(const std::vector<std::string> &filePaths,
    bool &&flag) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
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
    installParam.userId = USERID;
    installParam.installFlag = flag ? InstallFlag::NORMAL : InstallFlag::REPLACE_EXISTING;
    installParam.withCopyHaps = true;
    bool result = installer->Install(filePaths, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsMultipleInstallerTest::UpdateThirdPartyBundle(const std::string &filePath) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
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
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.withCopyHaps = true;
    bool result = installer->Install(filePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

void BmsMultipleInstallerTest::SetUpTestCase()
{
    // SPM stays ON (its device default): feed the mocked access-token
    // boundary with the per-hap trusted sign answer for every hap of this
    // suite, so the installs pass the real SPM verification chain instead of
    // failing closed on the empty default mock. Must run before the first
    // install — nothing in this binary resets the mock control variables
    // afterwards.
    SetUpSpmTrustedSignInfoForTest();
    bundleMgrService_->InitBundleInstaller();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    bundleMgrService_->GetDataMgr()->LoadDataFromPersistentStorage();
    // Drop leftover keep-data uninstall records of this suite's bundles (a
    // shared device accumulates them from earlier runs or sibling suites):
    // they store the app id the real signature derived, and the mocked
    // provision derives a different one, so CheckInstallOnKeepData would
    // reject the fresh installs with INCONSISTENT_SIGNATURE (8519755). The
    // installs of this suite never keep data, so a clean state is the only
    // behavior the suite has ever asserted.
    ClearSpmLeftoverUninstallRecordsForTest();
}

void BmsMultipleInstallerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsMultipleInstallerTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    // The mocked InstalldClient::ClearSessionProvisionCache is a counting
    // stub, so the real session provision cache inside the process-wide
    // InstalldHostImpl keeps the entry of the PREVIOUS test case's install
    // under the same shared session id. The next install of a DIFFERENT
    // bundle would then hit that stale entry in GetResolvedApl and fail the
    // apl cross-check with INSTALLD_PARAM_ERROR (e.g. a leftover
    // system_core entry vs a normal-profile install). Drop the cache entry
    // before every case so each install starts from a clean provision state.
    if (installdService_->hostImpl_ != nullptr) {
        installdService_->hostImpl_->ClearSessionProvisionCache(TEST_SPM_SESSION_ID);
    }
}

void BmsMultipleInstallerTest::TearDown()
{
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_CODE_DIR);
}

void BmsMultipleInstallerTest::CheckFileExist() const
{
    int bundleCodeExist = access(BUNDLE_CODE_DIR.c_str(), F_OK);
    EXPECT_EQ(bundleCodeExist, 0) << "the bundle code dir does not exists: " << BUNDLE_CODE_DIR;

    int bundleDataExist = access(BUNDLE_DATA_DIR.c_str(), F_OK);
    EXPECT_EQ(bundleDataExist, 0) << "the bundle data dir does not exists: " << BUNDLE_DATA_DIR;
}

void BmsMultipleInstallerTest::CheckFileNonExist() const
{
    int bundleCodeExist = access(BUNDLE_CODE_DIR.c_str(), F_OK);
    EXPECT_NE(bundleCodeExist, 0) << "the bundle code dir exists: " << BUNDLE_CODE_DIR;

    int bundleDataExist = access(BUNDLE_DATA_DIR.c_str(), F_OK);
    EXPECT_NE(bundleDataExist, 0) << "the bundle data dir exists: " << BUNDLE_DATA_DIR;
}

void BmsMultipleInstallerTest::CheckModuleFileExist() const
{
    for (unsigned long i = 0; i < BUNDLE_DATA_DIR_PAGENAME.size(); i++)
    {
        auto moduleDataExist = access((BUNDLE_DATA_DIR + "/" + BUNDLE_DATA_DIR_PAGENAME[i]).c_str(), F_OK);
        EXPECT_EQ(moduleDataExist, 0);
    }
    int codeDirExist = access((BUNDLE_CODE_DIR).c_str(), F_OK);
    EXPECT_EQ(codeDirExist, 0);
}

void BmsMultipleInstallerTest::CheckModuleFileNonExist(const std::string &packageName) const
{
    int moduleCodeExist = access((BUNDLE_CODE_DIR + "/" + packageName).c_str(), F_OK);
    int moduleDataExist = access((BUNDLE_DATA_DIR + "/" + packageName).c_str(), F_OK);
    EXPECT_NE(moduleCodeExist, 0);
    EXPECT_NE(moduleDataExist, 0);
}


void BmsMultipleInstallerTest::IsContainModuleInfo(const BundleInfo &info, const std::string &packageName1) const
{
    EXPECT_NE(info.hapModuleNames.size(), 0);

    auto ret = std::any_of(info.hapModuleNames.begin(), info.hapModuleNames.end(),
        [&](const auto &package)->decltype(auto) {
        return package == packageName1;
    });
    EXPECT_TRUE(ret);
}

const std::shared_ptr<BundleDataMgr> BmsMultipleInstallerTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

void BmsMultipleInstallerTest::StopInstalldService() const
{
    if (installdService_->IsServiceReady()) {
        installdService_->Stop();
        InstalldClient::GetInstance()->ResetInstalldProxy();
    }
}

void BmsMultipleInstallerTest::StopBundleService()
{
    if (bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStop();
        bundleMgrService_.reset();
    }
}

void BmsMultipleInstallerTest::ClearBundleInfo(const std::string &bundleName) const
{
    if (bundleMgrService_ == nullptr) {
        return;
    }
    auto dataMgt = bundleMgrService_->GetDataMgr();
    if (dataMgt == nullptr) {
        return;
    }
    auto dataStorage = dataMgt->GetDataStorage();
    if (dataStorage == nullptr) {
        return;
    }

    // clear innerBundleInfo from data manager
    dataMgt->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START);
    dataMgt->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS);

    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    // clear innerBundleInfo from data storage
    bool result = dataStorage->DeleteStorageBundleInfo(innerBundleInfo);
    EXPECT_TRUE(result) << "the bundle info in db clear fail: " << bundleName;
}

/**
 * @tc.number: ThirdPartyInstall_0100
 * @tc.name: test the right third party bundle file can be installed
 * @tc.desc: 1.the third party bundle file exists
 *           2.the third party bundle can be installed successfully and can get the bundle info
 */
HWTEST_F(BmsMultipleInstallerTest, ThirdPartyInstall_0100, Function | SmallTest | Level0)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    ErrCode result = InstallThirdPartyBundle(bundleFile);
    EXPECT_EQ(result, ERR_OK);
    CheckFileExist();
    std::string hapPath = BUNDLE_CODE_DIR + "/entry.hap";
    int ret = access(hapPath.c_str(), F_OK);
    EXPECT_EQ(ret, 0);
    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: ThirdPartyInstall_0200
 * @tc.name: test the wrong third party bundle file can't be installed
 * @tc.desc: 1.the third party bundle file don't exists
 *           2.the third party bundle can't be installed and the result is fail
 */
HWTEST_F(BmsMultipleInstallerTest, ThirdPartyInstall_0200, Function | SmallTest | Level0)
{
    std::string nonExistFile = RESOURCE_ROOT_PATH + INVALID_BUNDLE;
    ErrCode result = InstallThirdPartyBundle(nonExistFile);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_STAT_FILE_FAILED);
    CheckFileNonExist();
}

/**
 * @tc.number: ThirdPartyInstall_0300
 * @tc.name: test the empty path can't be installed
 * @tc.desc: 1.the third party bundle file path is empty
 *           2.the third party bundle can't be installed and the result is fail
 * @tc.require: issueI56WGB
 */
HWTEST_F(BmsMultipleInstallerTest, ThirdPartyInstall_0300, Function | SmallTest | Level0)
{
    ErrCode result = InstallThirdPartyBundle("");
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_STAT_FILE_FAILED);
    CheckFileNonExist();
}

/**
 * @tc.number: ThirdPartyInstall_0500
 * @tc.name: test the bundle file with invalid path will cause the result of install failure
 * @tc.desc: 1.the bundle file has invalid path
 *           2.the third party bundle can't be installed and the result is fail
 */
HWTEST_F(BmsMultipleInstallerTest, ThirdPartyInstall_0500, Function | SmallTest | Level0)
{
    std::string bundleFile = INVALID_PATH + RIGHT_BUNDLE;
    ErrCode result = InstallThirdPartyBundle(bundleFile);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_STAT_FILE_FAILED);
    CheckFileNonExist();
}

/**
 * @tc.number: ThirdPartyInstall_0600
 * @tc.name: test the install will fail when installd service has error
 * @tc.desc: 1.the installd service has error
 *           2.the install result is fail
 */
HWTEST_F(BmsMultipleInstallerTest, ThirdPartyInstall_0600, Function | SmallTest | Level0)
{
    StopInstalldService();
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    ErrCode result = InstallThirdPartyBundle(bundleFile);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_GET_PROXY_ERROR);
}

/**
 * @tc.number: ThirdPartyUpdateData_0100
 * @tc.name: test the right bundle file can be installed and update its info to bms
 * @tc.desc: 1.the ThirdParty bundle is available
 *           2.the right bundle can be installed and update its info to bms
 */
HWTEST_F(BmsMultipleInstallerTest, ThirdPartyUpdateData_0100, Function | SmallTest | Level0)
{
    ApplicationInfo info;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_FALSE(result);
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    ErrCode installResult = InstallThirdPartyBundle(bundleFile);
    EXPECT_EQ(installResult, ERR_OK);
    result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);
    EXPECT_EQ(info.name, BUNDLE_NAME);
    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: ThirdPartyUpdateData_0300
 * @tc.name: test the already installed bundle can't be reinstalled and update its info to bms
 * @tc.desc: 1.the bundle is already installed
 *           2.the already installed  bundle can't be reinstalled and update its info to bms
 */
HWTEST_F(BmsMultipleInstallerTest, ThirdPartyUpdateData_0300, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    // prepare already install information.
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    ErrCode firstInstall = InstallThirdPartyBundle(bundleFile);
    EXPECT_EQ(firstInstall, ERR_OK);
    ApplicationInfo info;
    auto result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);
    EXPECT_EQ(info.name, BUNDLE_NAME);
    ErrCode secondInstall = InstallThirdPartyBundle(bundleFile);
    EXPECT_EQ(secondInstall, ERR_APPEXECFWK_INSTALL_ALREADY_EXIST);
    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: ThirdPartyUpdateData_0400
 * @tc.name: test the already installed bundle can be reinstalled and update its info to bms
 * @tc.desc: 1.the bundle is already installed
 *           2.the already installed  bundle can be reinstalled and update its info to bms
 */
HWTEST_F(BmsMultipleInstallerTest, ThirdPartyUpdateData_0400, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    // prepare already install information.
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    ErrCode firstInstall = InstallThirdPartyBundle(bundleFile);
    EXPECT_EQ(firstInstall, ERR_OK);
    ApplicationInfo info;
    auto result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);
    EXPECT_EQ(info.name, BUNDLE_NAME);
    ErrCode secondInstall = UpdateThirdPartyBundle(bundleFile);
    EXPECT_EQ(secondInstall, ERR_OK);
    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: ThirdPartyUpdateData_0500
 * @tc.name: test the already installing bundle can't be reinstalled and update its info to bms
 * @tc.desc: 1.the bundle is already installing
 *           2.the already installing bundle can't be reinstalled and update its info to bms
 */
HWTEST_F(BmsMultipleInstallerTest, ThirdPartyUpdateData_0500, Function | SmallTest | Level0)
{
    // prepare already install information.
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    // begin to  reinstall package
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    ErrCode installResult = InstallThirdPartyBundle(bundleFile);
    EXPECT_EQ(installResult, ERR_APPEXECFWK_INSTALL_STATE_ERROR);
    // reset the install state
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_FAIL);
}

/**
 * @tc.number: MultipleHapsInstall_0100
 * @tc.name: test the input array of the input file paths is empty, the installation is failed.
 * @tc.desc: 1.the input array is empty.
 *           2 the installation is failed.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_0100, Function | SmallTest | Level0)
{
    std::vector<std::string> filePaths;
    auto installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_FILE_PATH_EMPTY) << "installation is successful";
}

/**
 * @tc.number: MultipleHapsInstall_0200
 * @tc.name: test the input array of the input file paths has some empty paths, the installation is failed.
 * @tc.desc: 1.there is empty path in the input file path array.
 *           2.the installation result is failed.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_0200, Function | SmallTest | Level0)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    filePaths.emplace_back("");
    auto installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_FILE_PATH_EMPTY) << "installation is successful";
}

/**
 * @tc.number: MultipleHapsInstall_0300
 * @tc.name: test the input array only has one valid file path
 * @tc.desc: 1.only one valid path in the input file path array
 *           2.the installation result is successful
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_0300, Function | SmallTest | Level0)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK) << "installation is failed";
    CheckFileExist();
    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsInstall_0400
 * @tc.name: test the wrong third party bundle file can't be installed
 * @tc.desc: 1.the third party bundle file don't exists
 *           2.the third party bundle can't be installed and the result is fail
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_0400, Function | SmallTest | Level0)
{
    std::vector<std::string> filePaths;
    std::string nonExistFile = RESOURCE_ROOT_PATH + INVALID_BUNDLE;
    filePaths.emplace_back(nonExistFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_STAT_FILE_FAILED) << "installation is successful";
    CheckFileNonExist();
}

/**
 * @tc.number: MultipleHapsInstall_0600
 * @tc.name: test the bundle file with invalid path will cause the result of install failure
 * @tc.desc: 1.the bundle file has invalid path
 *           2.the third party bundle can't be installed and the result is fail
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_0600, Function | SmallTest | Level0)
{
    std::vector<std::string> filePaths;
    std::string bundleFile = INVALID_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_STAT_FILE_FAILED);
    CheckFileNonExist();
}

/**
 * @tc.number: MultipleHapsInstall_0700
 * @tc.name: test the install will fail when installd service has error
 * @tc.desc: 1.the installd service has error
 *           2.the installation result is fail
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_0700, Function | SmallTest | Level0)
{
    StopInstalldService();
    std::vector<std::string> filePaths;
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALLD_GET_PROXY_ERROR);
    CheckFileNonExist();
}

/**
 * @tc.number: MultipleHapsInstall_0800
 * @tc.name: test to install haps with different bundleName in the input file path array
 * @tc.desc: 1.the bundleName is differnet in the input file path array
 *           2.the installation result is fail
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_0800, Function | SmallTest | Level0)
{
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_THIRD;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_BUNDLENAME_NOT_SAME);
    CheckFileNonExist();
}

/**
 * @tc.number: MultipleHapsInstall_0900
 * @tc.name: test to install haps with different version code in the input file path array
 * @tc.desc: 1.the version code is differnet in the input file path array
 *           2.the installation result is fail
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_0900, Function | SmallTest | Level0)
{
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FOURTH;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_VERSIONCODE_NOT_SAME);
    CheckFileNonExist();
}

/**
 * @tc.number: MultipleHapsInstall_1100
 * @tc.name: test to install haps with different releaseType target in the input file path array
 * @tc.desc: 1.the releaseType target is differnet in the input file path array
 *           2.the installation result is fail
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_1100, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_NINTH;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsInstall_1200
 * @tc.name: test to install haps with different releaseType compatible in the input file path array
 * @tc.desc: 1.the releaseType compatible is differnet in the input file path array
 *           2.the installation result is successful
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_1200, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_TENTH;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsInstall_1400
 * @tc.name: test to install haps which contain more than one entry hap in the array
 * @tc.desc: 1.there are more than one entry hap in the array
 *           2.the installation is failed
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_1400, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIFTH;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_INVALID_NUMBER_OF_ENTRY_HAP);
}

/**
 * @tc.number: MultipleHapsInstall_1500
 * @tc.name: test to install haps which contain same feature hap in the array
 * @tc.desc: 1.there are two same feature haps in the array
 *           2.the installation is failed
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_1500, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND_BACKUP;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, false);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_NOT_UNIQUE_DISTRO_MODULE_NAME);
}

/**
 * @tc.number: MultipleHapsInstall_1600
 * @tc.name: test to install haps with valid paths in the input file path array
 * @tc.desc: 1.the vaild paths in the input file path array
 *           2.the installation result is successful
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_1600, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, false);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();

    CheckModuleFileExist();

    BundleInfo info;
    auto result = dataMgr->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, info, USERID);
    EXPECT_TRUE(result);
    IsContainModuleInfo(info, PACKAGE_NAME_FIRST);
    IsContainModuleInfo(info, PACKAGE_NAME_SECOND);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsInstall_1700
 * @tc.name: test to install haps which contain some feature haps in the array
 * @tc.desc: 1.there are two different feature haps in the array
 *           2.the installation is failed
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_1700, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_TWELFTH;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();

    CheckModuleFileExist();

    BundleInfo info;
    auto result = dataMgr->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, info, USERID);
    EXPECT_TRUE(result);
    IsContainModuleInfo(info, PACKAGE_NAME_SECOND);
    IsContainModuleInfo(info, PACKAGE_NAME_THIRD);


    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsInstall_1800
 * @tc.name: test to install haps which contain invalid path in the array.
 * @tc.desc: 1.there is an invalid path in the array.
 *           2.the installation is failed.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_1800, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_TEST;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_FILE_PATH_IS_NOT_REAL);
    CheckFileNonExist();
}

/**
 * @tc.number: MultipleHapsInstall_1900
 * @tc.name: test to install haps when one direction in the array.
 * @tc.desc: 1.the haps are placed under a same direction and put the direction in the array.
 *           2.the hap files under this direction are valid.
 *           3.there are entry and feature haps under the direction.
 *           4.the installation result is successful.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_1900, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    std::vector<std::string> filePaths;
    filePaths.emplace_back(RESOURCE_TEST_PATH);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    BundleInfo info;
    auto result = dataMgr->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, info, USERID);
    EXPECT_TRUE(result);
    IsContainModuleInfo(info, PACKAGE_NAME_FIRST);
    IsContainModuleInfo(info, PACKAGE_NAME_SECOND);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsInstall_2000
 * @tc.name: test to install haps when one direction in the array.
 * @tc.desc: 1.the haps are placed under a same direction and put the direction in the array.
 *           2.the hap files under this direction are valid.
 *           3.there are only feature haps under the direction.
 *           4.the installation result is successful.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_2000, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    std::vector<std::string> filePaths;
    filePaths.emplace_back(RESOURCE_TEST1_PATH);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    BundleInfo info;
    auto result = dataMgr->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, info, USERID);
    EXPECT_TRUE(result);
    IsContainModuleInfo(info, PACKAGE_NAME_SECOND);
    IsContainModuleInfo(info, PACKAGE_NAME_THIRD);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsInstall_2100
 * @tc.name: test to install haps when one valid hap path and one direction in the array
 * @tc.desc: 1.one hap path and one direction are placed in the array
 *           2.the installation result is failed
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_2100, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    std::string secondBundleFile = RESOURCE_TEST1_PATH;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_INVALID_HAP_NAME);
    CheckFileNonExist();
}

/**
 * @tc.number: MultipleHapsInstall_2300
 * @tc.name: test to install haps when one direction in the array
 * @tc.desc: 1.more than one entry hap under the direction.
 *           2.the installation result is failed.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_2300, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_TEST3_PATH;
    filePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_INVALID_NUMBER_OF_ENTRY_HAP);
    CheckFileNonExist();
}

/**
 * @tc.number: MultipleHapsInstall_2400
 * @tc.name: test to install haps when one direction in the array
 * @tc.desc: 1.same feature haps under the direction.
 *           2.the installation result is failed.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_2400, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_TEST4_PATH;
    filePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, false);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_NOT_UNIQUE_DISTRO_MODULE_NAME);
}

/**
 * @tc.number: MultipleHapsInstall_2500
 * @tc.name: test to install haps with some of them having no sign info
 * @tc.desc: 1.sixth_rigth.hap has no sign info in the haps
 *           2.the installation result is failed
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_2500, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SIXTH;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_VERSIONCODE_NOT_SAME);
    CheckFileNonExist();

    ApplicationInfo info;
    auto result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: MultipleHapsInstall_2600
 * @tc.name: test to install haps with different sign info in the input file path array
 * @tc.desc: 1.the sign info is differnet in the input file path array
 *           2.the installation result is fail
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_2600, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SEVENTH;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE);
    CheckFileNonExist();
}

/**
 * @tc.number: MultipleHapsInstall_4800
 * @tc.name: test to install haps with different minCompatibleVersionCode in the input file path array
 * @tc.desc: 1.the minCompatibleVersionCode is differnet in the input file path array
 *           2.the installation result is fail
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_4800, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_COMPATIBLE_VERSION_CODE;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_DIFFERENT_COMPATIBLE_VERSION_CODE;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsInstall_4900
 * @tc.name: test to install haps with different minCompatibleVersionCode in the different input file path array
 * @tc.desc: 1.the minCompatibleVersionCode is differnet in the different input file path array
 *           2.the installation result is fail
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_4900, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_COMPATIBLE_VERSION_CODE;
    filePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_DIFFERENT_COMPATIBLE_VERSION_CODE;
    filePaths.clear();
    filePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsInstall_5100
 * @tc.name: test to install haps with different releaseType target in the different input file path array
 * @tc.desc: 1.the releaseType target is differnet in the different input file path array
 *           2.the installation result is fail
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_5100, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_NINTH;
    filePaths.clear();
    filePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsInstall_5200
 * @tc.name: test to install haps with different releaseType compatible in the different input file path array
 * @tc.desc: 1.the releaseType compatible is differnet in the different input file path array
 *           2.the installation result is successful
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_5200, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_TENTH;
    filePaths.clear();
    filePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsInstall_5400
 * @tc.name: test to install haps with same moduelName
 * @tc.desc: 1.the moduleType is different in the same packageName hap
 *           2.the installation result is fail
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsInstall_5400, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_DIFFERENT_MODULE_TYPE;
    filePaths.clear();
    filePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_INCONSISTENT_MODULE_NAME);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_0100
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install an entry hap of a bundle.
 *           2.to install a feature hap of this bundle, the feature hap has the same version
 *             code with the entry hap.
 *           3.the installation result is successful.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_0200
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install an entry hap of a bundle.
 *           2.to install a feature hap of this bundle, the feature hap has the higher version
 *             code than the entry hap.
 *           3.the installation result is failed.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_0200, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FOURTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_VERSION_NOT_COMPATIBLE);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_0300
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install an entry hap of a bundle.
 *           2.to install a feature hap of this bundle, the feature hap has the lower version
 *             code than the entry hap.
 *           3.the installation result is failed.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_0300, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_THIRTEENTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_0400
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install an entry hap of a bundle.
 *           2.to install a same entry hap of this bundle.
 *           3.the installation result is successful.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_0400, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, false);
    EXPECT_EQ(installRes, ERR_OK);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_0500
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install an entry hap of a bundle.
 *           2.to install an entry hap of this bundle, the entry hap has the higher version
 *             code than the entry hap.
 *           3.the installation result is successful.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_0500, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FOURTEENTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_0600
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install an entry hap of a bundle.
 *           2.to install an entry hap of this bundle, the entry hap has the lower version
 *             code than the entry hap.
 *           3.the installation result is failed.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_0600, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIFTEENTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, false);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_0700
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap of a bundle.
 *           2.to install an entry hap of this bundle, the entry hap has the same version
 *             code than the feature hap.
 *           3.the installation result is successful.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_0700, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_0800
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap of a bundle.
 *           2.to install an entry hap of this bundle, the entry hap has the higher version
 *             code than the feature hap.
 *           3.the installation result is successful.
 *           4.the feature hap has been uninstalled after finishing the installation procedure.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_0800, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FOURTEENTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileNonExist(PACKAGE_NAME_SECOND);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_0900
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap of a bundle.
 *           2.to install an entry hap of this bundle, the entry hap has the lower version
 *             code than the feature hap.
 *           3.the installation result is failed.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_0900, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIFTEENTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_1000
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap of a bundle.
 *           2.to install a same feature hap of this bundle, this feature hap has the same version
 *             code than the feature hap installed previously.
 *           3.the installation result is successful.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_1000, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, false);
    EXPECT_EQ(installRes, ERR_OK);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_1100
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap of a bundle.
 *           2.to install a same feature hap of this bundle, this feature hap has the higher version
 *             code than the feature hap installed previously.
 *           3.the installation result is successful.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_1100, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FOURTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_1200
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap of a bundle.
 *           2.to install a same feature hap of this bundle, this feature hap has the lower version
 *             code than the feature hap installed previously.
 *           3.the installation result is failed.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_1200, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_THIRTEENTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_1300
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap of a bundle.
 *           2.to install another feature hap of this bundle, this feature hap has the same version
 *             code than the feature hap installed previously.
 *           3.the installation result is successful.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_1300, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_TWELFTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckModuleFileExist();

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_1400
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap of a bundle.
 *           2.to install another feature hap of this bundle, this feature hap has the higher version
 *             code than the feature hap installed previously.
 *           3.the installation result is successful.
 *           4.the feature with lower version code has been uninstalled after finishing the installation.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_1400, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SIXTEENTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckModuleFileNonExist(PACKAGE_NAME_SECOND);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_1500
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap of a bundle.
 *           2.to install another feature hap of this bundle, this feature hap has the lower version
 *             code than the feature hap installed previously.
 *           3.the installation result is failed.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_1500, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_THIRTEENTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_1600
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap A and an entry hap B of a bundle.
 *           2.to install a entry hap B of this bundle.
 *           3.the installation result is successfully.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_1600, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_TEST_PATH;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, false);
    EXPECT_EQ(installRes, ERR_OK);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_1700
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap A and an entry hap B of a bundle.
 *           2.to install a entry hap C of this bundle, hap C has the higher version
 *             code than the hap B installed previously.
 *           3.the installation result is successfully.
 *           4. hap A has been uninstalled after finishing installation.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_1700, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_TEST_PATH;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FOURTEENTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckModuleFileNonExist(PACKAGE_NAME_SECOND);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_1800
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap A and an entry hap B of a bundle.
 *           2.to install hap A.
 *           3.the installation result is successfully.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_1800, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_TEST_PATH;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, false);
    EXPECT_EQ(installRes, ERR_OK);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_1900
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap A and an entry hap B of a bundle.
 *           2.to install a feature hap C which has same package name with hap A, but higher version code.
 *           3.the installation result is failed.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_1900, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_TEST_PATH;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FOURTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_VERSION_NOT_COMPATIBLE);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_2000
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap A and an entry hap B of a bundle.
 *           2.to install a feature hap C which has same package name and version code with hap A.
 *           3.the installation result is successfully.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_2000, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_TEST_PATH;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_TWELFTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckModuleFileExist();

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_2100
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap A and an entry hap B of a bundle.
 *           2.to install another feature hap C which has higher version code than hap A.
 *           3.the installation result is failed.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_2100, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_TEST_PATH;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SIXTEENTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_VERSION_NOT_COMPATIBLE);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_2200
 * @tc.name: test to update hap.
 * @tc.desc: 1.to install a feature hap A and an entry hap B of a bundle.
 *           2.to install another feature hap C which has lower version code than hap A.
 *           3.the installation result is failed.
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_2200, Function | SmallTest | Level1)
{
    std::vector<std::string> firstFilePaths;
    std::string firstBundleFile = RESOURCE_TEST_PATH;
    firstFilePaths.emplace_back(firstBundleFile);
    ErrCode installRes = InstallThirdPartyMultipleBundles(firstFilePaths, true);
    EXPECT_EQ(installRes, ERR_OK);
    CheckFileExist();
    CheckModuleFileExist();

    std::vector<std::string> secondFilePaths;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_THIRTEENTH;
    secondFilePaths.emplace_back(secondBundleFile);
    installRes = InstallThirdPartyMultipleBundles(secondFilePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_2300
 * @tc.name: test the hap files can be installed and update their info to bms
 * @tc.desc: 1.the ThirdParty bundles are available
 *           2.the haps can be installed and update their info to bms
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_2300, Function | SmallTest | Level1)
{
    ApplicationInfo info;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_FALSE(result);

    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);

    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    BundleInfo bundleInfo;
    result = dataMgr->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
    EXPECT_TRUE(result);

    IsContainModuleInfo(bundleInfo, PACKAGE_NAME_FIRST);
    IsContainModuleInfo(bundleInfo, PACKAGE_NAME_SECOND);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_2400
 * @tc.name: test the input array containing wrong bundle file which can't be installed and
 *           their info will not updated to bms
 * @tc.desc: 1.the ThirdParty bundle is wrong
 *           2.the wrong bundle can't be installed and its info will not updated to bms
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_2400, Function | SmallTest | Level1)
{
    ApplicationInfo info;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_FALSE(result);

    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    std::string wrongBundleName = RESOURCE_ROOT_PATH + WRONG_BUNDLE_NAME;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(wrongBundleName);

    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, false);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_INVALID_HAP_NAME);

    result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: MultipleHapsUpdateData_2500
 * @tc.name: test the already installed bundle can't be reinstalled and update its info to bms
 * @tc.desc: 1.the bundle is already installed
 *           2.the already installed  bundle can't be reinstalled and update its info to bms
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_2500, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ApplicationInfo info;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_FALSE(result);

    // prepare already install information.
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);

    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    BundleInfo bundleInfo;
    result = dataMgr->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
    EXPECT_TRUE(result);

    IsContainModuleInfo(bundleInfo, PACKAGE_NAME_FIRST);
    IsContainModuleInfo(bundleInfo, PACKAGE_NAME_SECOND);

    installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_APPEXECFWK_INSTALL_ALREADY_EXIST);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_2600
 * @tc.name: test the already installed bundle can be reinstalled and update its info to bms
 * @tc.desc: 1.the bundle is already installed
 *           2.the already installed  bundle can be reinstalled and update its info to bms
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_2600, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ApplicationInfo info;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_FALSE(result);

    // prepare already install information.
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);

    ErrCode installRes = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    BundleInfo bundleInfo;
    result = dataMgr->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
    EXPECT_TRUE(result);

    IsContainModuleInfo(bundleInfo, PACKAGE_NAME_FIRST);
    IsContainModuleInfo(bundleInfo, PACKAGE_NAME_SECOND);

    installRes = InstallThirdPartyMultipleBundles(filePaths, false);
    EXPECT_EQ(installRes, ERR_OK);

    ClearBundleInfo(BUNDLE_NAME);
}

/**
 * @tc.number: MultipleHapsUpdateData_2700
 * @tc.name: test the installation is failed when install status is incorrect
 * @tc.desc: 1.install status is incorrect
 *           2.the haps are installed failed and their info will not update to bms
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_2700, Function | SmallTest | Level1)
{
    // prepare already install information.
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    // begin to  reinstall package
    std::vector<std::string> filePaths;
    std::string firstBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    std::string secondBundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_SECOND;
    filePaths.emplace_back(firstBundleFile);
    filePaths.emplace_back(secondBundleFile);

    ErrCode installResult = InstallThirdPartyMultipleBundles(filePaths, true);
    EXPECT_EQ(installResult, ERR_APPEXECFWK_INSTALL_STATE_ERROR);
    // reset the install state

    ApplicationInfo info;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_FALSE(result);

    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_FAIL);
}

/**
 * @tc.number: MultipleHapsUpdateData_2800
 * @tc.name: test get ability.prcess
 * @tc.desc: 1.install test hap and compare ability.prcess
 */
HWTEST_F(BmsMultipleInstallerTest, MultipleHapsUpdateData_2800, Function | SmallTest | Level1)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + TEST_HAP_DEMO;
    ErrCode result = InstallThirdPartyBundle(bundleFile);
    EXPECT_EQ(result, ERR_OK);
    // prepare already install information.
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AbilityInfo abilityInfo;
    Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME_TEST);
    name.SetBundleName(BUNDLE_NAME_2);
    want.SetElement(name);
    bool ret = dataMgr->QueryAbilityInfo(want, 0, USERID, abilityInfo, 0);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(abilityInfo.process, PROCESS_NAME_1);

    bundleFile = RESOURCE_ROOT_PATH + TEST_HAP_DEMO_2;
    UpdateThirdPartyBundle(bundleFile);
    ret = dataMgr->QueryAbilityInfo(want, 0, USERID, abilityInfo, 0);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(abilityInfo.process, PROCESS_NAME_2);

    bundleFile = RESOURCE_ROOT_PATH + TEST_HAP_DEMO_3;
    UpdateThirdPartyBundle(bundleFile);
    ret = dataMgr->QueryAbilityInfo(want, 0, USERID, abilityInfo, 0);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(abilityInfo.process, PROCESS_NAME_3);
    UnInstallBundle(BUNDLE_NAME_2, USERID);
}
} // OHOS