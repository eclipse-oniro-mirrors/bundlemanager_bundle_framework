/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
#include "app_control_manager_host_impl.h"
#include "app_control_constants.h"
#endif
#ifdef APP_DOMAIN_VERIFY_ENABLED
#include "app_domain_verify_mgr_client.h"
#endif
#include "app_service_fwk/app_service_fwk_installer.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "hmp_bundle_installer.h"
#include "install_param.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "scope_guard.h"
#include "shared/shared_bundle_installer.h"
#include "system_bundle_installer.h"
#include "utd_handler.h"
#include "want.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const std::string SYSTEMFIEID_NAME = "com.query.test";
const std::string SYSTEMFIEID_BUNDLE = "system_module.hap";
const std::string SYSTEMFIEID_HAP_PATH = "/data/app/el1/bundle/public/com.query.test/module01.hap";
const std::string BUNDLE_NAME = "com.example.l3jsdemo";
const std::string MODULE_NAME_TEST = "moduleName";
const std::string RESOURCE_ROOT_PATH = "/data/test/resource/bms/install_bundle/";
const std::string TEST_CREATE_DIR_PATH = "/data/test/resource/bms/install_bundle/test_create_dir";
const std::string TEST_CREATE_FILE_PATH = "/data/test/resource/bms/install_bundle/test_create_dir/test.hap";
const std::string INVALID_PATH = "/install_bundle/";
const std::string RIGHT_BUNDLE = "right.hap";
const std::string TYPE_BUNDLE = "devicetype_error.hap";
const std::string INVALID_BUNDLE = "nonfile.hap";
const std::string WRONG_BUNDLE_NAME = "wrong_bundle_name.ha";
const std::string BUNDLE_DATA_DIR = "/data/app/el2/100/base/com.example.l3jsdemo";
const std::string BUNDLE_CODE_DIR = "/data/app/el1/bundle/public/com.example.l3jsdemo";
const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
const std::string BUNDLE_BACKUP_TEST = "backup.hap";
const std::string BUNDLE_MODULEJSON_TEST = "moduleJsonTest.hap";
const std::string BUNDLE_PREVIEW_TEST = "preview.hap";
const std::string BUNDLE_THUMBNAIL_TEST = "thumbnail.hap";
const std::string BUNDLE_BACKUP_NAME = "com.example.backuptest";
const std::string BUNDLE_MODULEJSON_NAME = "com.test.modulejsontest";
const std::string BUNDLE_PREVIEW_NAME = "com.example.previewtest";
const std::string BUNDLE_THUMBNAIL_NAME = "com.example.thumbnailtest";
const std::string MODULE_NAME = "entry";
const std::string EXTENSION_ABILITY_NAME = "extensionAbility_A";
const std::string TEST_STRING = "test.string";
const std::string TEST_PACK_AGE = "entry";
const std::string NOEXIST = "noExist";
const std::string CURRENT_PATH = "/data/service/el2/100/hmdfs/account/data/test_max";
const size_t NUMBER_ONE = 1;
const int32_t INVAILD_CODE = -1;
const int32_t ZERO_CODE = 0;
const uint32_t COMPATIBLE_VERSION = 11;
const std::string LOG = "log";
const int32_t EDM_UID = 3057;
const uint32_t INSTALLER_ID = 1;
const uint32_t INDEX = 1;
const uint32_t TARGET_VERSION_FOURTEEN = 14;
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
const std::string EMPTY_STRING = "";
const std::string APPID_INPUT = "com.third.hiworld.example1";
const std::string APPID = "com.third.hiworld.example1_BNtg4JBClbl92Rgc3jm/"
    "RfcAdrHXaM8F0QOiwVEhnV5ebE5jNIYnAx+weFRT3QTyUjRNdhmc2aAzWyi+5t5CoBM=";
const std::string NORMAL_BUNDLE_NAME = "bundleName";
const std::string FIRST_RIGHT_HAP = "first_right.hap";
#endif
const std::string BUNDLE_LIBRARY_PATH_DIR = "/data/app/el1/bundle/public/com.example.l3jsdemo/libs/arm";
const std::string BUNDLE_NAME_TEST = "bundleNameTest";
const std::string BUNDLE_NAME_TEST1 = "bundleNameTest1";
const std::string DEVICE_ID = "PHONE-001";
const std::string TEST_CPU_ABI = "arm64";
constexpr const char* BMS_SERVICE_PATH = "/data/service";
const int64_t FIVE_MB = 1024 * 1024 * 5; // 5MB
}  // namespace

class BmsBundleInstallerTest : public testing::Test {
public:
    BmsBundleInstallerTest();
    ~BmsBundleInstallerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    bool InstallSystemBundle(const std::string &filePath) const;
    bool OTAInstallSystemBundle(const std::string &filePath) const;
    ErrCode InstallThirdPartyBundle(const std::string &filePath) const;
    ErrCode UpdateThirdPartyBundle(const std::string &filePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    void CheckFileExist() const;
    void CheckFileNonExist() const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    const std::shared_ptr<BundleInstallerManager> GetBundleInstallerManager() const;
    void StopInstalldService() const;
    void StopBundleService();
    void CreateInstallerManager();
    void ClearBundleInfo();
    void ClearDataMgr();
    void ResetDataMgr();

private:
    std::shared_ptr<BundleInstallerManager> manager_ = nullptr;
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleInstallerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleInstallerTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleInstallerTest::BmsBundleInstallerTest()
{}

BmsBundleInstallerTest::~BmsBundleInstallerTest()
{}

bool BmsBundleInstallerTest::InstallSystemBundle(const std::string &filePath) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    auto installer = std::make_unique<SystemBundleInstaller>();
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.isPreInstallApp = true;
    setuid(Constants::FOUNDATION_UID);
    installParam.SetKillProcess(false);
    setuid(Constants::ROOT_UID);
    installParam.needSendEvent = false;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    return installer->InstallSystemBundle(
        filePath, installParam, Constants::AppType::SYSTEM_APP) == ERR_OK;
}

bool BmsBundleInstallerTest::OTAInstallSystemBundle(const std::string &filePath) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    auto installer = std::make_unique<SystemBundleInstaller>();
    std::vector<std::string> filePaths;
    filePaths.push_back(filePath);
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.isPreInstallApp = true;
    setuid(Constants::FOUNDATION_UID);
    installParam.SetKillProcess(false);
    setuid(Constants::ROOT_UID);
    installParam.needSendEvent = false;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    return installer->OTAInstallSystemBundle(
        filePaths, installParam, Constants::AppType::SYSTEM_APP) == ERR_OK;
}

ErrCode BmsBundleInstallerTest::InstallThirdPartyBundle(const std::string &filePath) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
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
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    bool result = installer->Install(filePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleInstallerTest::UpdateThirdPartyBundle(const std::string &filePath) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
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
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    bool result = installer->Install(filePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleInstallerTest::UnInstallBundle(const std::string &bundleName) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
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
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

void BmsBundleInstallerTest::SetUpTestCase()
{
}

void BmsBundleInstallerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleInstallerTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleInstallerTest::TearDown()
{
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_CODE_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_LIBRARY_PATH_DIR);
}

void BmsBundleInstallerTest::CheckFileExist() const
{
    int bundleCodeExist = access(BUNDLE_CODE_DIR.c_str(), F_OK);
    EXPECT_EQ(bundleCodeExist, 0) << "the bundle code dir does not exists: " << BUNDLE_CODE_DIR;

    int bundleDataExist = access(BUNDLE_DATA_DIR.c_str(), F_OK);
    EXPECT_EQ(bundleDataExist, 0) << "the bundle data dir does not exists: " << BUNDLE_DATA_DIR;
}

void BmsBundleInstallerTest::CheckFileNonExist() const
{
    int bundleCodeExist = access(BUNDLE_CODE_DIR.c_str(), F_OK);
    EXPECT_NE(bundleCodeExist, 0) << "the bundle code dir exists: " << BUNDLE_CODE_DIR;

    int bundleDataExist = access(BUNDLE_DATA_DIR.c_str(), F_OK);
    EXPECT_NE(bundleDataExist, 0) << "the bundle data dir exists: " << BUNDLE_DATA_DIR;
}

const std::shared_ptr<BundleDataMgr> BmsBundleInstallerTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

const std::shared_ptr<BundleInstallerManager> BmsBundleInstallerTest::GetBundleInstallerManager() const
{
    return manager_;
}

void BmsBundleInstallerTest::ClearDataMgr()
{
    bundleMgrService_->dataMgr_ = nullptr;
}

void BmsBundleInstallerTest::ResetDataMgr()
{
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(bundleMgrService_->dataMgr_, nullptr);
}

void BmsBundleInstallerTest::StopInstalldService() const
{
    if (installdService_->IsServiceReady()) {
        installdService_->Stop();
        InstalldClient::GetInstance()->ResetInstalldProxy();
    }
}

void BmsBundleInstallerTest::StopBundleService()
{
    if (bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStop();
        bundleMgrService_.reset();
    }
}

void BmsBundleInstallerTest::CreateInstallerManager()
{
    if (manager_ != nullptr) {
        return;
    }
    manager_ = std::make_shared<BundleInstallerManager>();
    EXPECT_NE(nullptr, manager_);
}

void BmsBundleInstallerTest::ClearBundleInfo()
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
    dataMgt->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    dataMgt->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);

    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    // clear innerBundleInfo from data storage
    bool result = dataStorage->DeleteStorageBundleInfo(innerBundleInfo);
    EXPECT_TRUE(result) << "the bundle info in db clear fail: " << BUNDLE_NAME;
}


/**
 * @tc.number: SetEncryptionDirPolicy_0100
 * @tc.name: test SetEncryptionDirPolicy
 * @tc.desc: test SetEncryptionDirPolicy of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, SetEncryptionDirPolicy_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;
    bool ret = installer.SetEncryptionDirPolicy(info);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: PrepareSkillUri_0100
 * @tc.name: test PrepareSkillUri
 * @tc.desc: test PrepareSkillUri of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, PrepareSkillUri_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::vector<Skill> skills;
    Skill skill;
    OHOS::AppExecFwk::SkillUri uri;
    uri.scheme = "https";
    uri.host = "host";
    uri.port = "port";
    uri.path = "path";
    uri.pathStartWith = "pathStartWith";
    uri.pathRegex = "pathRegex";
    uri.type = "type";
    skill.domainVerify = true;
    skill.uris.push_back(uri);
    skills.push_back(skill);
    std::vector<AppDomainVerify::SkillUri> skillUris;
    installer.PrepareSkillUri(skills, skillUris);
    EXPECT_EQ(skills.at(0).uris.size(), skillUris.size());
}

/**
 * @tc.number: SystemInstall_0100
 * @tc.name: test the right system bundle file can be installed
 * @tc.desc: 1.the system bundle file exists
 *           2.the system bundle can be installed successfully and can get the bundle info
 */
HWTEST_F(BmsBundleInstallerTest, SystemInstall_0100, Function | SmallTest | Level0)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    bool result = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(result) << "the bundle file install failed: " << bundleFile;
    CheckFileExist();
    ClearBundleInfo();
}

/**
 * @tc.number: SystemInstall_0200
 * @tc.name: test the wrong system bundle file can't be installed
 * @tc.desc: 1.the system bundle file don't exists
 *           2.the system bundle can't be installed and the result is fail
 */
HWTEST_F(BmsBundleInstallerTest, SystemInstall_0200, Function | SmallTest | Level0)
{
    std::string nonExistFile = RESOURCE_ROOT_PATH + INVALID_BUNDLE;
    bool result = InstallSystemBundle(nonExistFile);
    EXPECT_FALSE(result) << "the bundle file install success: " << nonExistFile;
    CheckFileNonExist();
}

/**
 * @tc.number: SystemInstall_0300
 * @tc.name: test the empty path can't be installed
 * @tc.desc: 1.the system bundle file path is empty
 *           2.the system bundle can't be installed and the result is fail
 */
HWTEST_F(BmsBundleInstallerTest, SystemInstall_0300, Function | SmallTest | Level0)
{
    bool result = InstallSystemBundle("");
    EXPECT_FALSE(result) << "the empty path install success";
    CheckFileNonExist();
}

/**
 * @tc.number: SystemInstall_0400
 * @tc.name: test the illegal bundleName file can't be installed
 * @tc.desc: 1.the system bundle name is illegal
 *           2.the system bundle can't be installed and the result is fail
 */
HWTEST_F(BmsBundleInstallerTest, SystemInstall_0400, Function | SmallTest | Level0)
{
    std::string wrongBundleName = RESOURCE_ROOT_PATH + WRONG_BUNDLE_NAME;
    bool result = InstallSystemBundle(wrongBundleName);
    EXPECT_FALSE(result) << "the wrong bundle file install success";
    CheckFileNonExist();
}

/**
 * @tc.number: SystemInstall_0500
 * @tc.name: test the bundle file with invalid path will cause the result of install failure
 * @tc.desc: 1.the bundle file has invalid path
 *           2.the system bundle can't be installed and the result is fail
 */
HWTEST_F(BmsBundleInstallerTest, SystemInstall_0500, Function | SmallTest | Level0)
{
    std::string bundleFile = INVALID_PATH + RIGHT_BUNDLE;
    bool result = InstallSystemBundle(bundleFile);
    EXPECT_FALSE(result) << "the invalid path install success";
    CheckFileNonExist();
}

/**
 * @tc.number: SystemInstall_0600
 * @tc.name: test the install will fail when installd service has error
 * @tc.desc: 1.the installd service has error
 *           2.the install result is fail
 */
HWTEST_F(BmsBundleInstallerTest, SystemInstall_0600, Function | SmallTest | Level0)
{
    StopInstalldService();
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    bool result = InstallSystemBundle(bundleFile);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: ThirdPartyInstall_0100
 * @tc.name: test the install will fail when installd service has error
 * @tc.desc: 1.the installd service has error
 *           2.the install result is fail
 */
HWTEST_F(BmsBundleInstallerTest, ThirdPartyInstall_0100, Function | SmallTest | Level0)
{
    StopInstalldService();
    std::string bundleFile = RESOURCE_ROOT_PATH + TYPE_BUNDLE;
    auto result = InstallThirdPartyBundle(bundleFile);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_GET_PROXY_ERROR);
}

/**
 * @tc.number: SystemUpdateData_0100
 * @tc.name: test the right bundle file can be installed and update its info to bms
 * @tc.desc: 1.the system bundle is available
 *           2.the right bundle can be installed and update its info to bms
 */
HWTEST_F(BmsBundleInstallerTest, SystemUpdateData_0100, Function | SmallTest | Level0)
{
    ApplicationInfo info;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_FALSE(result);
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    bool installResult = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(installResult);
    result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);
    EXPECT_EQ(info.name, BUNDLE_NAME);
    ClearBundleInfo();
}

/**
 * @tc.number: SystemUpdateData_0200
 * @tc.name: test the wrong bundle file can't be installed and its info will not updated to bms
 * @tc.desc: 1.the system bundle is wrong
 *           2.the wrong bundle can't be installed and its info will not updated to bms
 */
HWTEST_F(BmsBundleInstallerTest, SystemUpdateData_0200, Function | SmallTest | Level0)
{
    ApplicationInfo info;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_FALSE(result);
    std::string wrongBundleName = RESOURCE_ROOT_PATH + WRONG_BUNDLE_NAME;
    bool installResult = InstallSystemBundle(wrongBundleName);
    EXPECT_FALSE(installResult);
    result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: SystemUpdateData_0300
 * @tc.name: test the already installed bundle can't be reinstalled and update its info to bms
 * @tc.desc: 1.the bundle is already installed
 *           2.the already installed  bundle can't be reinstalled and update its info to bms
 */
HWTEST_F(BmsBundleInstallerTest, SystemUpdateData_0300, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    // prepare already install information.
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    bool firstInstall = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(firstInstall);
    ApplicationInfo info;
    auto result = dataMgr->GetApplicationInfo(BUNDLE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);
    EXPECT_EQ(info.name, BUNDLE_NAME);
    bool secondInstall = InstallSystemBundle(bundleFile);
    EXPECT_FALSE(secondInstall);
    ClearBundleInfo();
}

/**
 * @tc.number: SystemUpdateData_0400
 * @tc.name: test the already installing bundle can't be reinstalled and update its info to bms
 * @tc.desc: 1.the bundle is already installing.
 *           2.the already installing bundle can't be reinstalled and update its info to bms
 */
HWTEST_F(BmsBundleInstallerTest, SystemUpdateData_0400, Function | SmallTest | Level0)
{
    // prepare already install information.
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    // begin to  reinstall package
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    bool installResult = InstallSystemBundle(bundleFile);
    EXPECT_FALSE(installResult);
    // reset the install state
    dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_FAIL);
    ClearBundleInfo();
}

/**
 * @tc.number: CreateInstallTask_0100
 * @tc.name: test the installer manager can create task
 * @tc.desc: 1.the bundle file exists
 *           2.the bundle can be installed successfully
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTask_0100, Function | SmallTest | Level0)
{
    CreateInstallerManager();
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(receiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    GetBundleInstallerManager()->CreateInstallTask(bundleFile, installParam, receiver);
    ErrCode result = receiver->GetResultCode();
    EXPECT_EQ(ERR_OK, result);
    ClearBundleInfo();
}

/**
 * @tc.number: CreateInstallTask_0200
 * @tc.name: test the installer manager can not create task while bundle invalid
 * @tc.desc: 1.the invalid bundle file exists
 *           2.install the invalid bundle failed
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTask_0200, Function | SmallTest | Level0)
{
    CreateInstallerManager();
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(receiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;
    std::string bundleFile = RESOURCE_ROOT_PATH + INVALID_BUNDLE;
    GetBundleInstallerManager()->CreateInstallTask(bundleFile, installParam, receiver);
    ErrCode result = receiver->GetResultCode();
    EXPECT_NE(ERR_OK, result);
}

/**
 * @tc.number: CreateUninstallTask_0200
 * @tc.name: test the installer manager can not create task while bundle invalid
 * @tc.desc: 1.the invalid bundle file exists
 *           2.uninstall the bundle failed
 */
HWTEST_F(BmsBundleInstallerTest, CreateUninstallTask_0200, Function | SmallTest | Level0)
{
    CreateInstallerManager();
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(receiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;
    std::string bundleFile = RESOURCE_ROOT_PATH + INVALID_BUNDLE;
    GetBundleInstallerManager()->CreateUninstallTask(bundleFile, installParam, receiver);
    ErrCode result = receiver->GetResultCode();
    EXPECT_NE(ERR_OK, result);
}

/**
 * @tc.number: ParseModuleJson_0100
 * @tc.name: parse module json
 * @tc.desc: 1.the bundle is already installing.
 *           2.You can query the related moudle.json information
 *           3.The system field tested is the configured field
 */
HWTEST_F(BmsBundleInstallerTest, ParseModuleJson_0100, Function | SmallTest | Level0)
{
    ApplicationInfo info;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string bundleFile = RESOURCE_ROOT_PATH + SYSTEMFIEID_BUNDLE;
    ErrCode installResult = InstallThirdPartyBundle(bundleFile);
    EXPECT_EQ(installResult, ERR_OK);
    bool result =
        dataMgr->GetApplicationInfo(SYSTEMFIEID_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);
    if (result) {
        EXPECT_EQ(info.name, "com.query.test");
        EXPECT_EQ(info.description, "$string:description_application");
        EXPECT_EQ(info.descriptionId, 16777217);
        EXPECT_EQ(info.label, "$string:app_name");
        EXPECT_EQ(info.labelId, 16777216);
        EXPECT_EQ(info.iconPath, "$media:app_icon");
        EXPECT_EQ(info.iconId, 16777229);
        EXPECT_EQ(static_cast<uint32_t>(info.versionCode), 1);
        EXPECT_EQ(info.versionName, "1.0");
        EXPECT_EQ(info.minCompatibleVersionCode, 1);
        EXPECT_EQ(info.apiCompatibleVersion, 8);
        EXPECT_EQ(info.apiTargetVersion, 8);
        EXPECT_EQ(info.gwpAsanEnabled, false);
        EXPECT_EQ(info.tsanEnabled, false);
        EXPECT_EQ(info.hwasanEnabled, false);
        EXPECT_EQ(info.ubsanEnabled, false);
        AbilityInfo abilityInfo;
        abilityInfo.bundleName = SYSTEMFIEID_NAME;
        abilityInfo.package = "module01";
        HapModuleInfo hapModuleInfo;
        bool ret = dataMgr->GetHapModuleInfo(abilityInfo, hapModuleInfo);
        EXPECT_TRUE(ret);
        EXPECT_EQ(hapModuleInfo.name, "module01");
        EXPECT_EQ(hapModuleInfo.description, "$string:description_application");
        EXPECT_EQ(hapModuleInfo.mainAbility, "MainAbility");
        EXPECT_EQ(hapModuleInfo.process, "bba");
        EXPECT_EQ(hapModuleInfo.virtualMachine, "ark");
        EXPECT_EQ(hapModuleInfo.uiSyntax, "hml");
        EXPECT_EQ(hapModuleInfo.pages, "$profile:page_config");
        EXPECT_EQ(hapModuleInfo.deliveryWithInstall, true);
        EXPECT_EQ(hapModuleInfo.installationFree, false);
        EXPECT_EQ(hapModuleInfo.srcEntrance, "./MyAbilityStage.ts");
        EXPECT_EQ(hapModuleInfo.isolationMode, IsolationMode::NONISOLATION_FIRST);

        auto abilityInfos = hapModuleInfo.abilityInfos.front();
        EXPECT_EQ(abilityInfos.name, "MainAbility");
        EXPECT_EQ(abilityInfos.srcEntrance, "./login/MyLoginAbility.ts");
        EXPECT_EQ(abilityInfos.description, "$string:description_main_ability");
        EXPECT_EQ(abilityInfos.descriptionId, 16777219);
        EXPECT_EQ(abilityInfos.isolationProcess, true);
        EXPECT_EQ(hapModuleInfo.label, "Login");

        auto metadata = abilityInfos.metadata.front();
        EXPECT_EQ(metadata.name, "a01");
        EXPECT_EQ(metadata.value, "v01");
        EXPECT_EQ(metadata.resource, "hello");

        auto extensionInfos = hapModuleInfo.extensionInfos.front();
        EXPECT_EQ(extensionInfos.name, "FormName");
        EXPECT_EQ(extensionInfos.srcEntrance, "./form/MyForm.ts");
        EXPECT_EQ(extensionInfos.description, "$string:form_description");
        EXPECT_EQ(extensionInfos.descriptionId, 16777221);
        EXPECT_EQ(extensionInfos.visible, true);
        EXPECT_EQ(extensionInfos.icon, "$media:icon");
        EXPECT_EQ(extensionInfos.iconId, 16777229);
        EXPECT_EQ(extensionInfos.label, "$string:extension_name");
        EXPECT_EQ(extensionInfos.labelId, 16777220);

        EXPECT_EQ(hapModuleInfo.packageName, "packageNameTest");
    }
    UnInstallBundle(SYSTEMFIEID_NAME);
}

/**
 * @tc.number: BackupExtension_0100
 * @tc.name: test the backup type
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 */
HWTEST_F(BmsBundleInstallerTest, BackupExtension_0100, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", "");
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, 0, USERID, infos);
    EXPECT_TRUE(result);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    if (infos.size() > 0) {
        EXPECT_EQ(infos[0].bundleName, BUNDLE_BACKUP_NAME);
        EXPECT_EQ(infos[0].type, ExtensionAbilityType::BACKUP);
    }
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.name: PREVIEWExtension_0100
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleInstallerTest, PREVIEWExtension_0100, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_PREVIEW_NAME, "", "");
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, 0, USERID, infos);
    EXPECT_TRUE(result);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    if (infos.size() > 0) {
        EXPECT_EQ(infos[0].bundleName, BUNDLE_PREVIEW_NAME);
        EXPECT_EQ(infos[0].type, ExtensionAbilityType::PREVIEW);
    }
    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.name: THUMBNAILExtension_0100
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleInstallerTest, THUMBNAILExtension_0100, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_THUMBNAIL_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_THUMBNAIL_NAME, "", "");
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, 0, USERID, infos);
    EXPECT_TRUE(result);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    if (infos.size() > 0) {
        EXPECT_EQ(infos[0].bundleName, BUNDLE_THUMBNAIL_NAME);
        EXPECT_EQ(infos[0].type, ExtensionAbilityType::THUMBNAIL);
    }
    UnInstallBundle(BUNDLE_THUMBNAIL_NAME);
}

/**
 * @tc.number: QueryExtensionAbilityInfos_0100
 * @tc.name: test the backup type
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 */
HWTEST_F(BmsBundleInstallerTest, QueryExtensionAbilityInfos_0100, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, 0, USERID, infos);
    EXPECT_TRUE(result);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    if (infos.size() > 0) {
        EXPECT_EQ(infos[0].bundleName, BUNDLE_BACKUP_NAME);
        EXPECT_EQ(infos[0].moduleName, MODULE_NAME);
        EXPECT_EQ(infos[0].type, ExtensionAbilityType::BACKUP);
    }
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: QueryExtensionAbilityInfos_0200
 * @tc.name: test the backup type
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 */
HWTEST_F(BmsBundleInstallerTest, QueryExtensionAbilityInfos_0200, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, 0, USERID, infos);
    EXPECT_FALSE(result);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: QueryExtensionAbilityInfos_0300
 * @tc.name: test the backup type
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 */
HWTEST_F(BmsBundleInstallerTest, QueryExtensionAbilityInfos_0300, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_BACKUP_NAME, EXTENSION_ABILITY_NAME, "");
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, 0, USERID, infos);
    EXPECT_TRUE(result);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    if (infos.size() > 0) {
        EXPECT_EQ(infos[0].bundleName, BUNDLE_BACKUP_NAME);
        EXPECT_EQ(infos[0].name, EXTENSION_ABILITY_NAME);
        EXPECT_EQ(infos[0].type, ExtensionAbilityType::BACKUP);
    }
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: QueryExtensionAbilityInfos_0400
 * @tc.name: test the backup type
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 */
HWTEST_F(BmsBundleInstallerTest, QueryExtensionAbilityInfos_0400, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_BACKUP_NAME, EXTENSION_ABILITY_NAME, MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, 0, USERID, infos);
    EXPECT_TRUE(result);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    if (infos.size() > 0) {
        EXPECT_EQ(infos[0].bundleName, BUNDLE_BACKUP_NAME);
        EXPECT_EQ(infos[0].moduleName, MODULE_NAME);
        EXPECT_EQ(infos[0].name, EXTENSION_ABILITY_NAME);
        EXPECT_EQ(infos[0].type, ExtensionAbilityType::BACKUP);
    }
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfos_0500
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleInstallerTest, QueryExtensionAbilityInfos_0500, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_PREVIEW_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, 0, USERID, infos);
    EXPECT_TRUE(result);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    if (infos.size() > 0) {
        EXPECT_EQ(infos[0].bundleName, BUNDLE_PREVIEW_NAME);
        EXPECT_EQ(infos[0].moduleName, MODULE_NAME);
        EXPECT_EQ(infos[0].type, ExtensionAbilityType::PREVIEW);
    }
    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfos_0600
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleInstallerTest, QueryExtensionAbilityInfos_0600, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_PREVIEW_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, 0, USERID, infos);
    EXPECT_FALSE(result);
    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfos_0700
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleInstallerTest, QueryExtensionAbilityInfos_0700, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_PREVIEW_NAME, EXTENSION_ABILITY_NAME, "");
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, 0, USERID, infos);
    EXPECT_TRUE(result);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    if (infos.size() > 0) {
        EXPECT_EQ(infos[0].bundleName, BUNDLE_PREVIEW_NAME);
        EXPECT_EQ(infos[0].name, EXTENSION_ABILITY_NAME);
        EXPECT_EQ(infos[0].type, ExtensionAbilityType::PREVIEW);
    }
    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfos_0800
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleInstallerTest, QueryExtensionAbilityInfos_0800, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_PREVIEW_NAME, EXTENSION_ABILITY_NAME, MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, 0, USERID, infos);
    EXPECT_TRUE(result);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    if (infos.size() > 0) {
        EXPECT_EQ(infos[0].bundleName, BUNDLE_PREVIEW_NAME);
        EXPECT_EQ(infos[0].moduleName, MODULE_NAME);
        EXPECT_EQ(infos[0].name, EXTENSION_ABILITY_NAME);
        EXPECT_EQ(infos[0].type, ExtensionAbilityType::PREVIEW);
    }
    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfos_0900
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleInstallerTest, QueryExtensionAbilityInfos_0900, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_THUMBNAIL_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_THUMBNAIL_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, 0, USERID, infos);
    EXPECT_TRUE(result);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    if (infos.size() > 0) {
        EXPECT_EQ(infos[0].bundleName, BUNDLE_THUMBNAIL_NAME);
        EXPECT_EQ(infos[0].moduleName, MODULE_NAME);
        EXPECT_EQ(infos[0].type, ExtensionAbilityType::THUMBNAIL);
    }
    UnInstallBundle(BUNDLE_THUMBNAIL_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfos_1000
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleInstallerTest, QueryExtensionAbilityInfos_1000, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_THUMBNAIL_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_THUMBNAIL_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, 0, USERID, infos);
    EXPECT_FALSE(result);
    UnInstallBundle(BUNDLE_THUMBNAIL_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfos_1100
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleInstallerTest, QueryExtensionAbilityInfos_1100, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_THUMBNAIL_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_THUMBNAIL_NAME, EXTENSION_ABILITY_NAME, "");
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, 0, USERID, infos);
    EXPECT_TRUE(result);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    if (infos.size() > 0) {
        EXPECT_EQ(infos[0].bundleName, BUNDLE_THUMBNAIL_NAME);
        EXPECT_EQ(infos[0].name, EXTENSION_ABILITY_NAME);
        EXPECT_EQ(infos[0].type, ExtensionAbilityType::THUMBNAIL);
    }
    UnInstallBundle(BUNDLE_THUMBNAIL_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfos_1200
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleInstallerTest, QueryExtensionAbilityInfos_1200, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_THUMBNAIL_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_THUMBNAIL_NAME, EXTENSION_ABILITY_NAME, MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, 0, USERID, infos);
    EXPECT_TRUE(result);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    if (infos.size() > 0) {
        EXPECT_EQ(infos[0].bundleName, BUNDLE_THUMBNAIL_NAME);
        EXPECT_EQ(infos[0].moduleName, MODULE_NAME);
        EXPECT_EQ(infos[0].name, EXTENSION_ABILITY_NAME);
        EXPECT_EQ(infos[0].type, ExtensionAbilityType::THUMBNAIL);
    }
    UnInstallBundle(BUNDLE_THUMBNAIL_NAME);
}

/**
 * @tc.number: QueryExtensionAbilityInfos_1300
 * @tc.name: test implicit query extensionAbilityInfos with skill flag
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos with skill flag by implicit query
 */
HWTEST_F(BmsBundleInstallerTest, QueryExtensionAbilityInfos_1300, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, GET_EXTENSION_INFO_WITH_SKILL, USERID, infos);
    EXPECT_TRUE(result);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: QueryExtensionAbilityInfos_1400
 * @tc.name: test explicit query extensionAbilityInfos with skill flag
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos with skill flag by explicit query
 */
HWTEST_F(BmsBundleInstallerTest, QueryExtensionAbilityInfos_1400, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + SYSTEMFIEID_BUNDLE;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName(SYSTEMFIEID_NAME, "FormName");
    std::vector<ExtensionAbilityInfo> infos;
    bool result = dataMgr->QueryExtensionAbilityInfos(want, GET_EXTENSION_INFO_WITH_SKILL, USERID, infos);
    EXPECT_TRUE(result);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    UnInstallBundle(SYSTEMFIEID_NAME);
}

/**
 * @tc.number: GetBundleStats_001
 * @tc.name: test the GetBundleStats
 * @tc.desc: 1.install the hap
 *           2.GetBundleStats
 */
HWTEST_F(BmsBundleInstallerTest, GetBundleStats_001, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    std::vector<int64_t> bundleStats;
    auto ret = InstalldClient::GetInstance()->GetBundleStats(BUNDLE_BACKUP_NAME, USERID, bundleStats, 0);
    EXPECT_EQ(ret, ERR_OK);
    if (!bundleStats.empty()) {
        EXPECT_NE(bundleStats[0], 0);
        EXPECT_NE(bundleStats[1], 0);
        for (size_t index = 2; index < bundleStats.size(); index++) {
            EXPECT_EQ(bundleStats[index], 0);
        }
    }
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: CreateInstallTempDir_0100
 * @tc.name: test CreateInstallTempDir
 * @tc.desc: 1.create install temp dir success
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_0100, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    const int32_t installId = 2022;
    std::string res = bundleUtil.CreateInstallTempDir(installId, DirType::STREAM_INSTALL_DIR);
    EXPECT_NE(res, "");
}

/**
 * @tc.number: CreateInstallTempDir_0200
 * @tc.name: test CreateInstallTempDir
 * @tc.desc: 1.create install temp dir success
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_0200, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    const int32_t installId = 2023;
    std::string res = bundleUtil.CreateInstallTempDir(installId, DirType::QUICK_FIX_DIR);
    EXPECT_NE(res, "");

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: CreateInstallTempDir_0300
 * @tc.name: test CreateInstallTempDir
 * @tc.desc: 1.create install temp dir failed
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_0300, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    const int32_t installId = 2023;
    std::string res = bundleUtil.CreateInstallTempDir(installId, DirType::UNKNOWN);
    EXPECT_EQ(res, "");

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: CreateInstallTempDir_0400
 * @tc.name: test CheckFileName, the name max size is 256
 * @tc.desc: 1.test CheckFileName of BundleUtil
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_0400, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    std::string maxFileName = std::string(256, 'a');
    bool res = bundleUtil.CheckFileName(maxFileName);
    EXPECT_EQ(res, true);
    maxFileName.append(".txt");
    res = bundleUtil.CheckFileName(maxFileName);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: CreateInstallTempDir_0500
 * @tc.name: test CheckFileSize, size is not right
 * @tc.desc: 1.test CheckFileSize of BundleUtil
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_0500, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    bool res = bundleUtil.CheckFileSize(BUNDLE_NAME, 0);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: CreateInstallTempDir_0600
 * @tc.name: test GetHapFilesFromBundlePath, current path is empty or failed
 * @tc.desc: 1.test GetHapFilesFromBundlePath of BundleUtil
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_0600, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    std::string currentPath = "";
    std::vector<std::string> fileList = {"test1.hap"};
    bool res = bundleUtil.GetHapFilesFromBundlePath(currentPath, fileList);
    EXPECT_EQ(res, false);
    currentPath = "/data/test/test2.hap";
    res = bundleUtil.GetHapFilesFromBundlePath(currentPath, fileList);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: CreateInstallTempDir_0700
 * @tc.name: test DeviceAndNameToKey, key is id and name
 * @tc.desc: 1.test DeviceAndNameToKey of BundleUtil
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_0700, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    std::string key = "";
    bundleUtil.DeviceAndNameToKey(
        ServiceConstants::CURRENT_DEVICE_ID, BUNDLE_NAME, key);
    EXPECT_EQ(key, "PHONE-001_com.example.l3jsdemo");
}

/**
 * @tc.number: CreateInstallTempDir_0800
 * @tc.name: test KeyToDeviceAndName, split with underline
 * @tc.desc: 1.test KeyToDeviceAndName of BundleUtil
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_0800, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    std::string underline = "_";
    std::string deviceId = ServiceConstants::CURRENT_DEVICE_ID;
    std::string bundleName = "com.split.underline";
    std::string key = deviceId + underline + bundleName;
    bool ret = bundleUtil.KeyToDeviceAndName(key, deviceId, bundleName);
    EXPECT_EQ(ret, true);
    key = deviceId + bundleName;
    ret = bundleUtil.KeyToDeviceAndName(key, deviceId, bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: CreateInstallTempDir_0900
 * @tc.name: test CreateFileDescriptorForReadOnly, path is file
 * @tc.desc: 1.test CreateFileDescriptorForReadOnly of BundleUtil
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_0900, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleUtil bundleUtil;
    long long offset = 0;
    auto ret = bundleUtil.CreateFileDescriptorForReadOnly(bundlePath, offset);
    EXPECT_NE(ret, ERR_OK);
    bundlePath.append(std::string(256, '/'));
    ret = bundleUtil.CreateFileDescriptorForReadOnly(bundlePath, offset);
    EXPECT_NE(ret, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: CreateInstallTempDir_1000
 * @tc.name: test RenameFile, oldPath or newPath is empty
 * @tc.desc: 1.test RenameFile of BundleUtil
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_1000, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    bool ret = bundleUtil.RenameFile("", "");
    EXPECT_EQ(ret, false);
    ret = bundleUtil.RenameFile("oldPath", "");
    EXPECT_EQ(ret, false);
    ret = bundleUtil.RenameFile("", "newPath");
    EXPECT_EQ(ret, false);
    ret = bundleUtil.RenameFile("", "newPath");
    EXPECT_EQ(ret, false);
    ret = bundleUtil.RenameFile("oldPath", "newPath");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: CreateInstallTempDir_1100
 * @tc.name: test CopyFile, source or destination file is empty
 * @tc.desc: 1.test CopyFile of BundleUtil
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_1100, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    bool ret = bundleUtil.CopyFile("", "");
    EXPECT_EQ(ret, false);
    ret = bundleUtil.CopyFile("source", "");
    EXPECT_EQ(ret, false);
    ret = bundleUtil.CopyFile("", "destinationFile");
    EXPECT_EQ(ret, false);
    ret = bundleUtil.CopyFile("source", "destinationFile");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: CreateInstallTempDir_1200
 * @tc.name: test CreateDir, param is empty return false
 * @tc.desc: 1.test CreateDir of BundleUtil
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_1200, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    bool ret = bundleUtil.CreateDir("");
    EXPECT_EQ(ret, false);
    ret = bundleUtil.CreateDir(BUNDLE_CODE_DIR);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: CreateInstallTempDir_1300
 * @tc.name: test RevertToRealPath, one param is empty return false
 * @tc.desc: 1.test RevertToRealPath of BundleUtil
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_1300, Function | SmallTest | Level0)
{
    BundleUtil util;
    std::string empty = "";
    bool ret = util.RevertToRealPath(empty, empty, empty);
    EXPECT_EQ(ret, false);
    ret = util.RevertToRealPath("/data/storage/el2/base", empty, empty);
    EXPECT_EQ(ret, false);
    ret = util.RevertToRealPath("/data/storage/el2/base", "com.ohos.test", empty);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: CreateInstallTempDir_1400
 * @tc.name: test StartWith, one of param is empty return false
 * @tc.desc: 1.test StartWith of BundleUtil
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_1400, Function | SmallTest | Level0)
{
    BundleUtil util;
    bool ret = util.StartWith("", BUNDLE_DATA_DIR);
    EXPECT_EQ(ret, false);
    ret = util.StartWith(BUNDLE_DATA_DIR, "");
    EXPECT_EQ(ret, false);
    ret = util.StartWith(BUNDLE_DATA_DIR, BUNDLE_DATA_DIR);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: CreateInstallTempDir_1500
 * @tc.name: test EndWith, one of param is empty return false
 * @tc.desc: 1.test EndWith of BundleUtil
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_1500, Function | SmallTest | Level0)
{
    BundleUtil util;
    bool ret = util.EndWith("", BUNDLE_DATA_DIR);
    EXPECT_EQ(ret, false);
    ret = util.EndWith(BUNDLE_DATA_DIR, "");
    EXPECT_EQ(ret, false);
    ret = util.EndWith(BUNDLE_DATA_DIR, BUNDLE_CODE_DIR);
    EXPECT_EQ(ret, false);
    ret = util.EndWith(BUNDLE_DATA_DIR, BUNDLE_DATA_DIR);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: CreateInstallTempDir_1600
 * @tc.name: test file size
 * @tc.desc: 1.test GetFileSize of BundleUtil
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_1600, Function | SmallTest | Level0)
{
    BundleUtil util;
    int64_t ret = util.GetFileSize("");
    EXPECT_EQ(ret, 0);
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;

    bool installResult = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(installResult);
    ret = util.GetFileSize(bundleFile);
    EXPECT_NE(ret, 0);
    CheckFileExist();
    ClearBundleInfo();
}

/**
 * @tc.number: GetBaseSharedBundleInfosTest
 * @tc.name: Test use different param with GetBaseSharedBundleInfos
 * @tc.desc: 1.Test the GetBaseSharedBundleInfos with BundleDataMgr
*/
HWTEST_F(BmsBundleInstallerTest, GetBaseSharedBundleInfosTest, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    std::vector<BaseSharedBundleInfo> infos;
    auto ret = dataMgr->GetBaseSharedBundleInfos("", infos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetBaseSharedBundleInfosTest_0010
 * @tc.name: Test use different param with GetBaseSharedBundleInfos
 * @tc.desc: 1.Test the GetBaseSharedBundleInfos with BundleDataMgr
*/
HWTEST_F(BmsBundleInstallerTest, GetBaseSharedBundleInfosTest_0010, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    std::vector<BaseSharedBundleInfo> infos;
    auto ret = dataMgr->GetBaseSharedBundleInfos("", infos, GetDependentBundleInfoFlag::GET_APP_CROSS_HSP_BUNDLE_INFO);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetBaseSharedBundleInfosTest_0020
 * @tc.name: Test use different param with GetBaseSharedBundleInfos
 * @tc.desc: 1.Test the GetBaseSharedBundleInfos with BundleDataMgr
*/
HWTEST_F(BmsBundleInstallerTest, GetBaseSharedBundleInfosTest_0020, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    std::vector<BaseSharedBundleInfo> infos;
    auto ret = dataMgr->GetBaseSharedBundleInfos(BUNDLE_NAME, infos,
        GetDependentBundleInfoFlag::GET_APP_SERVICE_HSP_BUNDLE_INFO);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetBaseSharedBundleInfosTest_0030
 * @tc.name: Test use different param with GetBaseSharedBundleInfos
 * @tc.desc: 1.Test the GetBaseSharedBundleInfos with BundleDataMgr
*/
HWTEST_F(BmsBundleInstallerTest, GetBaseSharedBundleInfosTest_0030, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    std::vector<BaseSharedBundleInfo> infos;
    auto ret = dataMgr->GetBaseSharedBundleInfos(BUNDLE_NAME, infos,
        GetDependentBundleInfoFlag::GET_ALL_DEPENDENT_BUNDLE_INFO);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetBaseSharedBundleInfoTest
 * @tc.name: Test use different param with GetBaseSharedBundleInfos
 * @tc.desc: 1.Test the GetBaseSharedBundleInfo with BundleDataMgr
*/
HWTEST_F(BmsBundleInstallerTest, GetBaseSharedBundleInfoTest, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    Dependency dependency;
    BaseSharedBundleInfo info;
    auto ret = dataMgr->GetBaseSharedBundleInfo(dependency, info);
    EXPECT_EQ(ret, false);
    dependency.bundleName = BUNDLE_NAME;
    InnerBundleInfo innerBundleInfo;
    dataMgr->bundleInfos_[BUNDLE_NAME] = innerBundleInfo;
    ret = dataMgr->GetBaseSharedBundleInfo(dependency, info);
    EXPECT_EQ(ret, false);
    dataMgr->bundleInfos_.clear();
    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::SHARED;
    dataMgr->bundleInfos_[BUNDLE_NAME] = innerBundleInfo;
    ret = dataMgr->GetBaseSharedBundleInfo(dependency, info);
    EXPECT_EQ(ret, true);
    dataMgr->bundleInfos_.clear();
}

/**
 * @tc.number: OTASystemInstall_0100
 * @tc.name: test the right system bundle file can be installed
 * @tc.desc: 1.the system bundle file exists
 *           2.the system bundle can be installed successfully and can get the bundle info
 */
HWTEST_F(BmsBundleInstallerTest, OTASystemInstall_0100, Function | SmallTest | Level0)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    bool result = OTAInstallSystemBundle(bundleFile);
    EXPECT_TRUE(result) << "the bundle file install failed: " << bundleFile;
    CheckFileExist();
    ClearBundleInfo();
}

/**
 * @tc.number: baseBundleInstaller_0100
 * @tc.name: test BuildTempNativeLibraryPath, needSendEvent is true
 * @tc.desc: 1.Test the BuildTempNativeLibraryPath of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();
    InstallParam installParam;
    installParam.needSendEvent = true;
    ErrCode ret = installer.InstallBundleByBundleName(
        BUNDLE_NAME, installParam);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_0200
 * @tc.name: test Recover, needSendEvent is true
 * @tc.desc: 1.Test the Recover of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_0200, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();
    installer.bundleName_ = BUNDLE_NAME;
    installer.modulePackage_ = "entry";
    InstallParam installParam;
    installParam.needSendEvent = true;
    ErrCode ret = installer.Recover(BUNDLE_NAME, installParam);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_0300
 * @tc.name: test ProcessBundleInstall
 * @tc.desc: 1.Test the ProcessBundleInstall of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_0300, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::vector<std::string> inBundlePaths;
    InstallParam installParam;
    auto appType = Constants::AppType::THIRD_PARTY_APP;
    int32_t uid = 0;
    ErrCode ret = installer.ProcessBundleInstall(
        inBundlePaths, installParam, appType, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    installer.dataMgr_ = GetBundleDataMgr();

    installParam.userId = Constants::INVALID_USERID;
    ret = installer.ProcessBundleInstall(
        inBundlePaths, installParam, appType, uid);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_0400
 * @tc.name: test CheckVersionCompatibilityForHmService
 * @tc.desc: 1.Test the CheckVersionCompatibilityForHmService of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_0400, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.versionCode_ = 1;
    InnerBundleInfo oldInfo;
    oldInfo.baseBundleInfo_->versionCode = 2;
    auto ret = installer.CheckVersionCompatibilityForHmService(oldInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);

    installer.versionCode_ = 3;
    ret = installer.CheckVersionCompatibilityForHmService(oldInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_0500
 * @tc.name: test CreateBundleUserData, user id is different
 * @tc.desc: 1.Test the CreateBundleUserData of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_0500, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo innerBundleInfo;
    auto ret = installer.CreateBundleUserData(innerBundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_USER_NOT_EXIST);
}

/**
 * @tc.number: baseBundleInstaller_0600
 * @tc.name: test RemoveBundleUserData, InnerBundleInfo id is different
 * @tc.desc: 1.Test the RemoveBundleUserData of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_0600, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo userInfo;
    bool needRemoveData = false;
    auto ret = installer.RemoveBundleUserData(innerBundleInfo, needRemoveData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_USER_NOT_EXIST);
    innerBundleInfo.innerBundleUserInfos_.emplace("key", userInfo);
    installer.userId_ = Constants::ALL_USERID;
    installer.dataMgr_ = GetBundleDataMgr();
    ret = installer.RemoveBundleUserData(innerBundleInfo, needRemoveData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR);
}

/**
 * @tc.number: baseBundleInstaller_0800
 * @tc.name: test ProcessInstallBundleByBundleName
 * @tc.desc: 1.Test the ProcessInstallBundleByBundleName of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_0800, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo innerBundleInfo;
    InstallParam installParam;
    int32_t uid = 0;
    ErrCode ret = installer.ProcessInstallBundleByBundleName(
        BUNDLE_NAME, installParam, uid);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_0900
 * @tc.name: test ProcessRecover
 * @tc.desc: 1.Test the ProcessRecover of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_0900, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo innerBundleInfo;
    InstallParam installParam;
    int32_t uid = 0;
    ErrCode ret = installer.ProcessRecover(
        BUNDLE_NAME, installParam, uid);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_1000
 * @tc.name: test InnerProcessInstallByPreInstallInfo
 * @tc.desc: 1.Test the InnerProcessInstallByPreInstallInfo of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_1000, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();
    InnerBundleInfo innerBundleInfo;
    int32_t uid = 0;
    InstallParam installParam;
    installParam.userId = Constants::INVALID_USERID;
    ErrCode ret = installer.InnerProcessInstallByPreInstallInfo(
        BUNDLE_NAME_TEST1, installParam, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: baseBundleInstaller_1100
 * @tc.name: test ProcessDeployedHqfInfo
 * @tc.desc: 1.Test the ProcessDeployedHqfInfo of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_1100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();
    std::string nativeLibraryPath = "X86";
    std::string cpuAbi = "armeabi";
    InnerBundleInfo newInfo;
    AppQuickFix oldAppQuickFix;
    ErrCode ret = installer.ProcessDeployedHqfInfo(
        nativeLibraryPath, cpuAbi, newInfo, oldAppQuickFix);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_1200
 * @tc.name: test ProcessDeployingHqfInfo
 * @tc.desc: 1.Test the ProcessDeployingHqfInfo of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_1200, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string nativeLibraryPath = "X86";
    std::string cpuAbi = "armeabi";
    InnerBundleInfo newInfo;
    ErrCode ret = installer.ProcessDeployingHqfInfo(
        nativeLibraryPath, cpuAbi, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_1300
 * @tc.name: test UpdateLibAttrs
 * @tc.desc: 1.Test the UpdateLibAttrs of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_1300, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string nativeLibraryPath = "X86";
    std::string cpuAbi = "armeabi";
    InnerBundleInfo newInfo;
    AppqfInfo appQfInfo;
    ErrCode ret = installer.UpdateLibAttrs(
        newInfo, cpuAbi, nativeLibraryPath, appQfInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_1400
 * @tc.name: test CheckHapLibsWithPatchLibs
 * @tc.desc: 1.Test the CheckHapLibsWithPatchLibs of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_1400, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string nativeLibraryPath = "";
    std::string hqfLibraryPath = "a.hqf";
    bool ret = installer.CheckHapLibsWithPatchLibs(
        nativeLibraryPath, hqfLibraryPath);
    EXPECT_EQ(ret, false);

    hqfLibraryPath = "/data/storage/el1/a.hqf";
    ret = installer.CheckHapLibsWithPatchLibs(
        nativeLibraryPath, hqfLibraryPath);
    EXPECT_EQ(ret, false);

    nativeLibraryPath = hqfLibraryPath;
    ret = installer.CheckHapLibsWithPatchLibs(
        nativeLibraryPath, hqfLibraryPath);
    EXPECT_EQ(ret, true);

    ret = installer.CheckHapLibsWithPatchLibs(
        nativeLibraryPath, "");
    EXPECT_EQ(ret, true);

    ret = installer.CheckHapLibsWithPatchLibs(
        nativeLibraryPath, hqfLibraryPath);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: baseBundleInstaller_1500
 * @tc.name: test ProcessDiffFiles
 * @tc.desc: 1.Test the ProcessDiffFiles of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_1500, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.modulePackage_ = "entry";
    std::vector<HqfInfo> hqfInfos;
    HqfInfo info;
    info.moduleName = "entry";
    hqfInfos.emplace_back(info);
    AppqfInfo appQfInfo;
    appQfInfo.hqfInfos = hqfInfos;
    std::string nativeLibraryPath = "libs/armeabi-v7a/";
    std::string cpuAbi = "arm";
    ErrCode ret = installer.ProcessDiffFiles(
        appQfInfo, nativeLibraryPath, cpuAbi);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST);
}

/**
 * @tc.number: baseBundleInstaller_1600
 * @tc.name: test SaveOldRemovableInfo
 * @tc.desc: 1.Test the SaveOldRemovableInfo of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_1600, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerModuleInfo info;
    info.isRemovable.try_emplace("removeInfo1", false);
    info.isRemovable.try_emplace("removeInfo2", true);
    oldInfo.innerModuleInfos_.try_emplace("entry", info);
    InnerModuleInfo newModuleInfo;
    bool existModule = true;
    installer.SaveOldRemovableInfo(newModuleInfo, oldInfo, existModule);
    newModuleInfo.modulePackage = "entry";
    installer.SaveOldRemovableInfo(newModuleInfo, oldInfo, existModule);
    EXPECT_EQ(newModuleInfo.isRemovable["removeInfo1"], false);
    EXPECT_EQ(newModuleInfo.isRemovable["removeInfo2"], true);
}

/**
 * @tc.number: baseBundleInstaller_1700
 * @tc.name: test ExtractArkNativeFile
 * @tc.desc: 1.Test the ExtractArkNativeFile of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_1700, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;
    std::string modulePath;
    ErrCode ret = installer.ExtractArkNativeFile(info, modulePath);
    EXPECT_EQ(ret, ERR_OK);

    info.baseApplicationInfo_->arkNativeFilePath = "";
    info.baseApplicationInfo_->arkNativeFileAbi = "errorType";
    ret = installer.ExtractArkNativeFile(info, modulePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_AN_FAILED);

    info.baseApplicationInfo_->arkNativeFileAbi = "x86";
    ret = installer.ExtractArkNativeFile(info, modulePath);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_1800
 * @tc.name: test DeleteOldArkNativeFile
 * @tc.desc: 1.Test the DeleteOldArkNativeFile of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_1800, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    oldInfo.baseApplicationInfo_->arkNativeFilePath = "/an/x86/x86.so";
    ErrCode ret = installer.DeleteOldArkNativeFile(oldInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_2100
 * @tc.name: test baseBundleInstaller
 * @tc.desc: 1.Test the dataMgr_ is nullptr
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = nullptr;
    ClearDataMgr();
    std::vector<std::string> inBundlePaths;
    InstallParam installParam;
    auto appType = Constants::AppType::THIRD_PARTY_APP;
    int32_t uid = 0;
    bool recoverMode = true;
    ErrCode ret = installer.ProcessBundleInstall(
        inBundlePaths, installParam, appType, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);
    ret = installer.ProcessBundleUninstall(
        "bundleName", installParam, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);
    ret = installer.ProcessBundleUninstall(
        "bundleName", "modulePackage", installParam, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);
    ret = installer.InnerProcessInstallByPreInstallInfo(
        "bundleName", installParam, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);
    InnerBundleInfo info;
    bool res = installer.GetInnerBundleInfoWithDisable(info, recoverMode);
    EXPECT_EQ(res, false);
    ResetDataMgr();

    installParam.userId = Constants::INVALID_USERID;
    ret = installer.ProcessBundleUninstall(
        "bundleName", installParam, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
    ret = installer.ProcessBundleUninstall(
        "bundleName", "modulePackage", installParam, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: baseBundleInstaller_2200
 * @tc.name: test RemoveBundle
 * @tc.desc: 1.Test the RemoveBundle
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2200, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;
    installer.InitDataMgr();
    ErrCode res = installer.RemoveBundle(info, false);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR);

    res = installer.RemoveBundle(info, true);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR);
}

/**
 * @tc.number: baseBundleInstaller_2300
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.Test the ProcessBundleUpdateStatus
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2300, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    installer.isFeatureNeedUninstall_ = true;
    ErrCode res = installer.ProcessBundleUpdateStatus(oldInfo, newInfo, false, false);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: baseBundleInstaller_2400
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.Test the ProcessBundleUpdateStatus
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2400, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();
    installer.userId_ = USERID;
    InnerBundleInfo info;
    ErrCode res = installer.CreateBundleDataDir(info);
    EXPECT_EQ(res, ERR_APPEXECFWK_USER_NOT_EXIST);

    installer.userId_ = Constants::INVALID_USERID;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    info.SetBaseApplicationInfo(applicationInfo);
    res = installer.CreateBundleDataDir(info);
    EXPECT_EQ(res, ERR_APPEXECFWK_USER_NOT_EXIST);
}

/**
 * @tc.number: baseBundleInstaller_2600
 * @tc.name: test ProcessBundleUninstall
 * @tc.desc: 1.Test the ProcessBundleUninstall of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2600, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string bundleName = SYSTEMFIEID_NAME;
    std::string modulePackage = MODULE_NAME;
    InstallParam installParam;
    installParam.userId = -1;
    int32_t uid = USERID;

    auto res = installer.ProcessBundleUninstall(bundleName, installParam, uid);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
    res = installer.ProcessBundleUninstall(bundleName, modulePackage, installParam, uid);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: baseBundleInstaller_2700
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.Test the ProcessBundleUpdateStatus of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2700, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = "";
    bool isReplace = false;
    bool killProcess = false;

    auto res = installer.ProcessBundleUpdateStatus(oldInfo, newInfo, isReplace, killProcess);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: baseBundleInstaller_2800
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.Test the ProcessBundleUpdateStatus of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2800, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    oldInfo.baseApplicationInfo_->singleton = true;
    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = MODULE_NAME;
    bool isReplace = false;
    bool killProcess = false;

    auto res = installer.ProcessBundleUpdateStatus(oldInfo, newInfo, isReplace, killProcess);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_SINGLETON_INCOMPATIBLE);
}

/**
 * @tc.number: baseBundleInstaller_2900
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.Test the ProcessBundleUpdateStatus of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2900, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = MODULE_NAME;
    newInfo.baseApplicationInfo_->singleton = true;
    bool isReplace = false;
    bool killProcess = false;

    auto res = installer.ProcessBundleUpdateStatus(oldInfo, newInfo, isReplace, killProcess);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_SINGLETON_INCOMPATIBLE);

    installer.modulePackage_ = MODULE_NAME;
    InnerModuleInfo moduleInfo;
    moduleInfo.isLibIsolated = true;
    moduleInfo.cpuAbi = "123";
    moduleInfo.nativeLibraryPath = "/data/test";
    newInfo.innerModuleInfos_.insert(pair<std::string, InnerModuleInfo>(MODULE_NAME, moduleInfo));
    installer.ProcessHqfInfo(oldInfo, newInfo);
}

/**
 * @tc.number: baseBundleInstaller_3000
 * @tc.name: test ProcessDeployedHqfInfo
 * @tc.desc: 1.Test the ProcessDeployedHqfInfo of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_3000, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();
    installer.isFeatureNeedUninstall_ = false;
    std::string nativeLibraryPath = "/data/test";
    std::string cpuAbi = "123";
    InnerBundleInfo newInfo;
    AppQuickFix oldAppQuickFix;
    HqfInfo hqfInfo;
    oldAppQuickFix.deployedAppqfInfo.hqfInfos.push_back(hqfInfo);

    auto res = installer.ProcessDeployedHqfInfo(nativeLibraryPath, cpuAbi, newInfo, oldAppQuickFix);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST);

    hqfInfo.moduleName = MODULE_NAME;
    installer.modulePackage_ = "123";
    res = installer.ProcessDeployedHqfInfo(nativeLibraryPath, cpuAbi, newInfo, oldAppQuickFix);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_3100
 * @tc.name: test UpdateLibAttrs
 * @tc.desc: 1.Test the UpdateLibAttrs of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_3100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = MODULE_NAME;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;
    newInfo.innerModuleInfos_.insert(pair<std::string, InnerModuleInfo>(MODULE_NAME, moduleInfo));
    std::string cpuAbi = "123";
    std::string nativeLibraryPath = "/data/test";
    AppqfInfo appQfInfo;

    auto res = installer.UpdateLibAttrs(newInfo, cpuAbi, nativeLibraryPath, appQfInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_3200
 * @tc.name: test InstallAppControl
 * @tc.desc: 1.Test the InstallAppControl of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_3200, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string installAppId;
    int32_t userId = Constants::DEFAULT_USERID;;
    OHOS::ErrCode ret = installer.InstallNormalAppControl(installAppId, userId);
    EXPECT_EQ(ret, OHOS::ERR_OK);
}

/**
 * @tc.number: BundleInstaller_3300
 * @tc.name: test InstallAppControl
 * @tc.desc: 1.Test the InstallAppControl of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, BundleInstaller_3300, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_MODULEJSON_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    UnInstallBundle(BUNDLE_MODULEJSON_NAME);
}

/**
 * @tc.number: baseBundleInstaller_3600
 * @tc.name: test ProcessNewModuleInstall
 * @tc.desc: 1.Test the ProcessNewModuleInstall
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_3600, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = true;
    newInfo.InsertInnerModuleInfo("", innerModuleInfo);
    oldInfo.InsertInnerModuleInfo("", innerModuleInfo);
    ErrCode res = installer.ProcessNewModuleInstall(newInfo, oldInfo);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_ENTRY_ALREADY_EXIST);
}

/**
 * @tc.number: baseBundleInstaller_3700
 * @tc.name: test ProcessModuleUpdate
 * @tc.desc: 1.Test the ProcessModuleUpdate
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_3700, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = true;
    newInfo.InsertInnerModuleInfo("", innerModuleInfo);
    oldInfo.InsertInnerModuleInfo("", innerModuleInfo);
    installer.modulePackage_ = NOEXIST;
    ErrCode res = installer.ProcessModuleUpdate(newInfo, oldInfo, false, false);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_ENTRY_ALREADY_EXIST);
}

/**
 * @tc.number: baseBundleInstaller_3800
 * @tc.name: test UpdateLibAttrs
 * @tc.desc: 1.Test the UpdateLibAttrs of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_3800, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string nativeLibraryPath = "X86";
    std::string cpuAbi = "armeabi";
    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = MODULE_NAME_TEST;
    AppqfInfo appQfInfo;
    ErrCode ret = installer.UpdateLibAttrs(
        newInfo, cpuAbi, nativeLibraryPath, appQfInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_3900
 * @tc.name: test UpdateLibAttrs
 * @tc.desc: 1.Test the UpdateLibAttrs of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_3900, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = MODULE_NAME_TEST;
    ErrCode ret = installer.SetDirApl(newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_4000
 * @tc.name: test CreateBundleDataDir
 * @tc.desc: 1.Test the CreateBundleDataDir
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_4000, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();
    installer.userId_ = USERID;
    InnerBundleInfo info;
    ErrCode res = installer.CreateBundleDataDir(info);
    EXPECT_EQ(res, ERR_APPEXECFWK_USER_NOT_EXIST);
}

/**
 * @tc.number: baseBundleInstaller_4100
 * @tc.name: test ExtractArkNativeFile
 * @tc.desc: 1.Test the ExtractArkNativeFile of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_4100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;
    std::string modulePath;
    info.SetArkNativeFilePath("///");
    ErrCode ret = installer.ExtractArkNativeFile(info, modulePath);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_4200
 * @tc.name: test GetModuleNames
 * @tc.desc: 1.Test the GetModuleNames of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_4200, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::string ret = installer.GetModuleNames(infos);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}

/**
 * @tc.number: baseBundleInstaller_6100
 * @tc.name: test ProcessBundleInstallNative
 * @tc.desc: 1.Test the ProcessBundleInstallNative
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_6100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;
    int32_t userId = USERID;
    ErrCode res = installer.ProcessBundleInstallNative(info, userId);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_6200
 * @tc.name: test ProcessBundleUnInstallNative
 * @tc.desc: 1.Test the ProcessBundleUnInstallNative
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_6200, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;
    int32_t userId = USERID;
    std::string bundleName = "com.example.test";
    ErrCode res = installer.ProcessBundleUnInstallNative(info, userId, bundleName);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_0100
 * @tc.name: test CheckArkNativeFileWithOldInfo
 * @tc.desc: 1.Test the CreateBundleDir of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    auto ret = impl.CreateBundleDir("");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_0200
 * @tc.name: test CheckArkNativeFileWithOldInfo
 * @tc.desc: 1.Test the ExtractModuleFiles of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_0200, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    auto ret = impl.ExtractModuleFiles("", "", TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.ExtractModuleFiles("", TEST_STRING, TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.ExtractModuleFiles(TEST_STRING, "", TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.ExtractModuleFiles("wrong", TEST_STRING, "wrong", "wrong");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT);
}

/**
 * @tc.number: InstalldHostImpl_0300
 * @tc.name: test CheckArkNativeFileWithOldInfo
 * @tc.desc: 1.Test the RenameModuleDir of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_0300, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    auto ret = impl.RenameModuleDir("", "");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.RenameModuleDir("", TEST_STRING);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.RenameModuleDir(TEST_STRING, " ");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_RNAME_DIR_FAILED);

    ret = impl.RenameModuleDir("wrong", "wrong");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_RNAME_DIR_FAILED);

    ret = impl.RenameModuleDir(TEST_STRING, TEST_STRING);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_RNAME_DIR_FAILED);
}

/**
 * @tc.number: InstalldHostImpl_0400
 * @tc.name: test CheckArkNativeFileWithOldInfo
 * @tc.desc: 1.Test the CreateBundleDataDir of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_0400, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    CreateDirParam createDirParam;
    createDirParam.bundleName = "";
    createDirParam.userId = INVAILD_CODE;
    createDirParam.uid = INVAILD_CODE;
    createDirParam.gid = INVAILD_CODE;
    createDirParam.apl = TEST_STRING;
    createDirParam.isPreInstallApp = false;
    auto ret = impl.CreateBundleDataDir(createDirParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    CreateDirParam createDirParam2;
    createDirParam2.bundleName = TEST_STRING;
    createDirParam2.userId = 99;
    createDirParam2.uid = ZERO_CODE;
    createDirParam2.gid = ZERO_CODE;
    createDirParam2.apl = TEST_STRING;
    createDirParam2.isPreInstallApp = false;
    ret = impl.CreateBundleDataDir(createDirParam2);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_0500
 * @tc.name: test CheckArkNativeFileWithOldInfo
 * @tc.desc: 1.Test the RemoveBundleDataDir of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_0500, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;

    auto ret = impl.RemoveBundleDataDir("", USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.RemoveBundleDataDir(TEST_STRING, INVAILD_CODE);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.RemoveBundleDataDir("", INVAILD_CODE);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.RemoveBundleDataDir(TEST_STRING, USERID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_0600
 * @tc.name: test CheckArkNativeFileWithOldInfo
 * @tc.desc: 1.Test the RemoveModuleDataDir of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_0600, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    auto ret = impl.RemoveModuleDataDir(TEST_STRING, INVAILD_CODE);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.RemoveModuleDataDir("", USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.RemoveModuleDataDir("", INVAILD_CODE);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.RemoveModuleDataDir(TEST_STRING, USERID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_0700
 * @tc.name: test CheckArkNativeFileWithOldInfo
 * @tc.desc: 1.Test the GetBundleCachePath of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_0700, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> vec;
    auto ret = impl.GetBundleCachePath(TEST_STRING, vec);
    EXPECT_EQ(ret, ERR_OK);

    ret = impl.GetBundleCachePath("", vec);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_0800
 * @tc.name: test CheckArkNativeFileWithOldInfo
 * @tc.desc: 1.Test the Mkdir of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_0800, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    auto ret = impl.Mkdir("", ZERO_CODE, ZERO_CODE, ZERO_CODE);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_0900
 * @tc.name: test CheckArkNativeFileWithOldInfo
 * @tc.desc: 1.Test the ExtractFiles of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_0900, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;

    ExtractParam extractParam;
    auto ret = impl.ExtractFiles(extractParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    extractParam.srcPath = "/data/app/el1/bundle/public/com.example.test/entry.hap";
    extractParam.targetPath = "/data/app/el1/bundle/public/com.example.test/";
    extractParam.cpuAbi = "arm64";
    extractParam.extractFileType = ExtractFileType::AN;

    ret = impl.ExtractFiles(extractParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT);
}

/**
 * @tc.number: InstalldHostImpl_1000
 * @tc.name: test Install
 * @tc.desc: 1.Test the Install of BundleInstallerHost
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_1000, Function | SmallTest | Level0)
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
    InstallParam installParam;
    bool ret = installer->Install("", installParam, nullptr);
    EXPECT_EQ(ret, false);
    std::vector<std::string> bundleFilePaths;
    ret = installer->Install(bundleFilePaths, installParam, nullptr);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InstalldHostImpl_1100
 * @tc.name: test Install
 * @tc.desc: 1.Test the Uninstall of BundleInstallerHost
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_1100, Function | SmallTest | Level0)
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
    InstallParam installParam;
    bool ret = installer->Uninstall("", "", installParam, nullptr);
    EXPECT_EQ(ret, false);
    ret = installer->InstallByBundleName("", installParam, nullptr);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InstalldHostImpl_1200
 * @tc.name: test Install
 * @tc.desc: 1.Test the CheckBundleInstallerManager of BundleInstallerHost
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_1200, Function | SmallTest | Level0)
{
    BundleInstallerHost bundleInstallerHost;
    sptr<IStatusReceiver> statusReceiver;
    bundleInstallerHost.manager_ = nullptr;
    bool ret = bundleInstallerHost.CheckBundleInstallerManager(statusReceiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InstalldHostImpl_1300
 * @tc.name: test Install
 * @tc.desc: 1.Test the RemoveDir of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_1300, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode ret = impl.RemoveDir("");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_1400
 * @tc.name: test Install
 * @tc.desc: 1.Test the CleanBundleDataDir of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_1400, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode ret = impl.CleanBundleDataDir("");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_1500
 * @tc.name: test Install
 * @tc.desc: 1.Test the GetBundleStats of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_1500, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<int64_t> bundleStats;
    ErrCode ret = impl.GetBundleStats("", USERID, bundleStats, 0);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_1600
 * @tc.name: test Install
 * @tc.desc: 1.Test the GetBundleStats of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_1600, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths;
    ErrCode ret = impl.ScanDir(
        "", ScanMode::SUB_FILE_ALL, ResultMode::ABSOLUTE_PATH, paths);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.ScanDir(
        BUNDLE_DATA_DIR, ScanMode::SUB_FILE_ALL, ResultMode::ABSOLUTE_PATH, paths);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_1700
 * @tc.name: test Install
 * @tc.desc: 1.Test the CopyFile of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_1700, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths;
    ErrCode ret = impl.CopyFile("", "");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_COPY_FILE_FAILED);
}

/**
 * @tc.number: InstalldHostImpl_1800
 * @tc.name: test Install
 * @tc.desc: 1.Test the ExtractHnpFiles of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_1800, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::string hnpPackageInfo;
    ExtractParam extractParam;
    auto ret = impl.ExtractHnpFiles(hnpPackageInfo, extractParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_1900
 * @tc.name: test Install
 * @tc.desc: 1.Test the ProcessBundleInstallNative of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_1900, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::string userId = std::to_string(USERID);
    std::string hnpRootPath = "/data/app/el1/bundle/public/com.example.test/entry_tmp/hnp_tmp_extract_dir/";
    std::string hapPath = "/system/app/module01/module01.hap";
    std::string cpuAbi = "arm64";
    std::string packageName = "com.example.test";
    auto ret = impl.ProcessBundleInstallNative(userId, hnpRootPath, hapPath, cpuAbi, packageName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NATIVE_INSTALL_FAILED);
}

/**
 * @tc.number: InstalldHostImpl_2000
 * @tc.name: test Install
 * @tc.desc: 1.Test the ProcessBundleInstallNative of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InstalldHostImpl_2000, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::string userId = std::to_string(USERID);
    std::string packageName = "com.example.test";
    auto ret = impl.ProcessBundleUnInstallNative(userId, packageName);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ZipFile_0100
 * @tc.name: Test ZipFile
 * @tc.desc: 1.Test ParseEndDirectory of ZipFile
 */
HWTEST_F(BmsBundleInstallerTest, ZipFile_0100, Function | SmallTest | Level1)
{
    ZipFile file("/test.zip");
    ZipPos start = 0;
    size_t length = 0;
    file.SetContentLocation(start, length);
    bool ret = file.ParseEndDirectory();
    EXPECT_EQ(ret, false);

    std::string maxFileName = std::string(256, 'a');
    maxFileName.append(".zip");
    file.pathName_ = maxFileName;
    ret = file.Open();
    EXPECT_EQ(ret, false);

    file.pathName_ = "/test.zip";
    file.isOpen_ = true;
    ret = file.Open();
    EXPECT_EQ(ret, true);

    ret = file.IsDirExist("");
    EXPECT_EQ(ret, false);

    ret = file.IsDirExist("/test.zip");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: ZipFile_0200
 * @tc.name: Test ZipFile
 * @tc.desc: 1.Test open file, file name is bigger than PATH_MAX
 */
HWTEST_F(BmsBundleInstallerTest, ZipFile_0200, Function | SmallTest | Level1)
{
    ZipFile file("/test.zip");
    ZipPos start = 0;
    size_t length = 0;
    file.SetContentLocation(start, length);
    bool ret = file.ParseEndDirectory();
    EXPECT_EQ(ret, false);

    std::string maxFileName = std::string(4096, 'a');
    maxFileName.append(".zip");
    file.pathName_ = maxFileName;
    ret = file.Open();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: ZipFile_0300
 * @tc.name: Test ZipFile
 * @tc.desc: 1.Test CheckCoherencyLocalHeader
 */
HWTEST_F(BmsBundleInstallerTest, ZipFile_0300, Function | SmallTest | Level1)
{
    ZipFile file("/test.zip");
    ZipEntry zipEntry;
    zipEntry.localHeaderOffset = -1;
    uint16_t extraSize = 0;
    bool ret = file.CheckCoherencyLocalHeader(zipEntry, extraSize);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: ZipFile_0400
 * @tc.name: Test ZipFile
 * @tc.desc: 1.Test SeekToEntryStart
 */
HWTEST_F(BmsBundleInstallerTest, ZipFile_0400, Function | SmallTest | Level1)
{
    ZipFile file("/test.zip");
    ZipEntry zipEntry;
    zipEntry.localHeaderOffset = 1;
    uint16_t extraSize = 0;
    bool ret = file.SeekToEntryStart(zipEntry, extraSize);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: ZipFile_0500
 * @tc.name: Test ZipFile
 * @tc.desc: 1.Test GetAllEntries
 */
HWTEST_F(BmsBundleInstallerTest, ZipFile_0500, Function | SmallTest | Level1)
{
    ZipFile file("/test.zip");
    ZipEntryMap ret = file.GetAllEntries();
    EXPECT_EQ(ret.size(), 0);
}

/**
 * @tc.number: ZipFile_0600
 * @tc.name: Test ZipFile
 * @tc.desc: 1.Test HasEntry
 */
HWTEST_F(BmsBundleInstallerTest, ZipFile_0600, Function | SmallTest | Level1)
{
    ZipFile file("/test.zip");

    std::string entryName = "entryName";
    bool ret = file.HasEntry(entryName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: ZipFile_0700
 * @tc.name: Test ZipFile
 * @tc.desc: 1.Test GetEntry
 */
HWTEST_F(BmsBundleInstallerTest, ZipFile_0700, Function | SmallTest | Level1)
{
    ZipFile file("/test.zip");

    std::string entryName = "entryName";
    ZipEntry resultEntry;
    bool ret = file.GetEntry(entryName, resultEntry);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: ZipFile_0800
 * @tc.name: Test ZipFile
 * @tc.desc: 1.Test GetDataOffsetRelative
 */
HWTEST_F(BmsBundleInstallerTest, ZipFile_0800, Function | SmallTest | Level1)
{
    ZipFile file("/test.zip");

    std::string f = "test.file";
    ZipPos offset;
    uint32_t length = 100;
    bool ret = file.GetDataOffsetRelative(f, offset, length);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: ZipFile_0900
 * @tc.name: Test ZipFile
 * @tc.desc: 1.Test CheckEndDir
 */
HWTEST_F(BmsBundleInstallerTest, ZipFile_0900, Function | SmallTest | Level1)
{
    ZipFile file("/test.zip");

    EndDir endDir;
    bool ret = file.CheckEndDir(endDir);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: ZipFile_1000
 * @tc.name: Test ZipFile
 * @tc.desc: 1.Test ParseAllEntries
 */
HWTEST_F(BmsBundleInstallerTest, ZipFile_1000, Function | SmallTest | Level1)
{
    ZipFile file("/test.zip");

    bool ret = file.ParseAllEntries();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: ZipFile_1100
 * @tc.name: Test ZipFile
 * @tc.desc: 1.Test GetLocalHeaderSize
 */
HWTEST_F(BmsBundleInstallerTest, ZipFile_1100, Function | SmallTest | Level1)
{
    ZipFile file("/test.zip");

    uint16_t nameSize = 100;
    uint16_t extraSize = 100;
    size_t ret = file.GetLocalHeaderSize(nameSize, extraSize);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.number: ZipFile_1200
 * @tc.name: Test ZipFile
 * @tc.desc: 1.Test GetEntryDataOffset
 */
HWTEST_F(BmsBundleInstallerTest, ZipFile_1200, Function | SmallTest | Level1)
{
    ZipFile file("/test.zip");

    ZipEntry zipEntry;
    uint16_t extraSize = 100;
    ZipPos ret = file.GetEntryDataOffset(zipEntry, extraSize);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.number: ZipFile_1300
 * @tc.name: Test ZipFile
 * @tc.desc: 1.Test CheckDataDesc
 */
HWTEST_F(BmsBundleInstallerTest, ZipFile_1300, Function | SmallTest | Level1)
{
    ZipFile file("/test.zip");

    ZipEntry zipEntry;
    LocalHeader localHeader;
    bool ret = file.CheckDataDesc(zipEntry, localHeader);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: ZipFile_1400
 * @tc.name: Test ZipFile
 * @tc.desc: 1.Test InitZStream
 */
HWTEST_F(BmsBundleInstallerTest, ZipFile_1400, Function | SmallTest | Level1)
{
    ZipFile file("/test.zip");

    z_stream zstream;
    bool ret = file.InitZStream(zstream);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BaseExtractor_0100
 * @tc.name: Test HasEntry
 * @tc.desc: 1.Test HasEntry of BaseExtractor
 */
HWTEST_F(BmsBundleInstallerTest, BaseExtractor_0100, Function | SmallTest | Level1)
{
    BaseExtractor extractor("file.zip");
    extractor.initial_ = false;
    bool ret = extractor.HasEntry("entry");
    EXPECT_EQ(ret, false);

    extractor.initial_ = true;
    ret = extractor.HasEntry("");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BaseExtractor_0200
 * @tc.name: Test HasEntry
 * @tc.desc: 1.Test HasEntry of BaseExtractor
 */
HWTEST_F(BmsBundleInstallerTest, BaseExtractor_0200, Function | SmallTest | Level1)
{
    BaseExtractor extractor("file.zip");
    bool ret = extractor.ExtractFile("entry", "/data/test");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BaseExtractor_0300
 * @tc.name: Test HasEntry
 * @tc.desc: 1.Test HasEntry of BaseExtractor
 */
HWTEST_F(BmsBundleInstallerTest, BaseExtractor_0300, Function | SmallTest | Level1)
{
    BaseExtractor extractor("file.zip");
    uint32_t offset = 1;
    uint32_t length = 10;
    bool ret = extractor.GetFileInfo("bootpic.zip", offset, length);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BaseExtractor_0400
 * @tc.name: Test HasEntry
 * @tc.desc: 1.Test HasEntry of BaseExtractor
 */
HWTEST_F(BmsBundleInstallerTest, BaseExtractor_0400, Function | SmallTest | Level1)
{
    BaseExtractor extractor("/system/etc/graphic/bootpic.zip");
    extractor.initial_ = true;
    uint32_t offset = 1;
    uint32_t length = 10;
    bool ret = extractor.GetFileInfo("bootpic.zip", offset, length);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BaseExtractor_0500
 * @tc.name: Test Init
 * @tc.desc: 1.Test Init of BaseExtractor
 */
HWTEST_F(BmsBundleInstallerTest, BaseExtractor_0500, Function | SmallTest | Level1)
{
    BaseExtractor extractor("/system/etc/graphic/bootpic.zip");

    bool ret = extractor.Init();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BaseExtractor_0600
 * @tc.name: Test GetZipFileNames
 * @tc.desc: 1.Test GetZipFileNames of BaseExtractor
 */
HWTEST_F(BmsBundleInstallerTest, BaseExtractor_0600, Function | SmallTest | Level1)
{
    BaseExtractor extractor("/system/etc/graphic/bootpic.zip");

    std::vector<std::string> fileNames;
    fileNames.push_back("test1.zip");
    fileNames.push_back("test2.zip");
    bool ret = extractor.GetZipFileNames(fileNames);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BaseExtractor_0700
 * @tc.name: Test IsDirExist
 * @tc.desc: 1.Test IsDirExist of BaseExtractor
 */
HWTEST_F(BmsBundleInstallerTest, BaseExtractor_0700, Function | SmallTest | Level1)
{
    BaseExtractor extractor("/system/etc/graphic/bootpic.zip");
    extractor.initial_ = false;

    std::string dir = "/data";
    bool ret = extractor.IsDirExist(dir);
    EXPECT_FALSE(ret);

    dir = "";
    ret = extractor.IsDirExist(dir);
    EXPECT_FALSE(ret);

    extractor.initial_ = true;
    dir = "/data";
    ret = extractor.IsDirExist(dir);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BaseExtractor_0800
 * @tc.name: Test IsStageBasedModel
 * @tc.desc: 1.Test IsStageBasedModel of BaseExtractor
 */
HWTEST_F(BmsBundleInstallerTest, BaseExtractor_0800, Function | SmallTest | Level1)
{
    BaseExtractor extractor("/system/etc/graphic/bootpic.zip");
    extractor.initial_ = false;

    std::string abilityName = "EntryAbility";
    bool ret = extractor.IsStageBasedModel(abilityName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BaseExtractor_0900
 * @tc.name: Test IsNewVersion
 * @tc.desc: 1.Test IsNewVersion of BaseExtractor
 */
HWTEST_F(BmsBundleInstallerTest, BaseExtractor_0900, Function | SmallTest | Level1)
{
    BaseExtractor extractor("/system/etc/graphic/bootpic.zip");

    bool ret = extractor.IsNewVersion();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstallFailed_0100
 * @tc.name: Test CheckHapHashParams
 * @tc.desc: 1.Test CheckHapHashParams of BundleInstallChecker
 */
HWTEST_F(BmsBundleInstallerTest, InstallFailed_0100, Function | SmallTest | Level1)
{
    BundleInstallChecker installChecker;
    std::vector<std::string> bundlePaths;
    ErrCode ret = installChecker.CheckSysCap(bundlePaths);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);

    std::map<std::string, std::string> hashParams;
    hashParams.try_emplace("entry", "hashValue");
    std::unordered_map<std::string, InnerBundleInfo> infos;
    ret = installChecker.CheckHapHashParams(infos, hashParams);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_CHECK_HAP_HASH_PARAM);

    InnerBundleInfo innerBundleInfo;
    infos.try_emplace("hashParam", innerBundleInfo);
    ret = installChecker.CheckHapHashParams(infos, hashParams);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_MODULE_NAME_EMPTY);

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "entry";
    innerBundleInfo.innerModuleInfos_.clear();
    innerBundleInfo.innerModuleInfos_.try_emplace("module1", innerModuleInfo);
    innerBundleInfo.innerModuleInfos_.try_emplace("module1", innerModuleInfo);
    infos.clear();
    infos.try_emplace("hashParam", innerBundleInfo);
    ret = installChecker.CheckHapHashParams(infos, hashParams);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstallChecker_0100
 * @tc.name: test the start function of CheckSysCap
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_0100, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    std::vector<std::string> bundlePaths;
    bundlePaths.push_back(bundlePath);
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckSysCap(bundlePaths);
    EXPECT_EQ(ret, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: InstallChecker_0200
 * @tc.name: test the start function of CheckSysCap
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_0200, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST + "rpcid.sc";
    std::vector<std::string> bundlePaths;
    bundlePaths.push_back(bundlePath);
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckSysCap(bundlePaths);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_UNEXPECTED);
}

/**
 * @tc.number: InstallChecker_0300
 * @tc.name: test the start function of CheckMultipleHapsSignInfo
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_0300, Function | SmallTest | Level0)
{
    std::vector<std::string> bundlePaths;
    bundlePaths.push_back("data");
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult;
    hapVerifyResult.GetProvisionInfo().appId = "8519754";
    hapVerifyRes.emplace_back(hapVerifyResult);
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckMultipleHapsSignInfo(bundlePaths, hapVerifyRes);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_INVALID_SIGNATURE_FILE_PATH);
}

/**
 * @tc.number: InstallChecker_0400
 * @tc.name: test the start function of CheckDependency
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_0400, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckDependency(infos);
    EXPECT_EQ(ret, ERR_OK);

    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = "moduleName";
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "moduleName";
    Dependency dependency;
    dependency.moduleName = "moduleName";
    dependency.bundleName = "bundleName";
    innerModuleInfo.dependencies.push_back(dependency);
    innerBundleInfo.innerModuleInfos_.insert(
        pair<std::string, InnerModuleInfo>("moduleName", innerModuleInfo));
    infos.insert(pair<std::string, InnerBundleInfo>("moduleName", innerBundleInfo));

    ret = installChecker.CheckDependency(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstallChecker_0500
 * @tc.name: test the start function of NeedCheckDependency
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_0500, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = "bundleName1";
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    Dependency dependency;
    dependency.bundleName = "bundleName2";
    auto ret = installChecker.NeedCheckDependency(dependency, innerBundleInfo);
    EXPECT_EQ(ret, false);
    BundlePackInfo bundlePackInfo;
    PackageModule packageModule;
    bundlePackInfo.summary.modules.push_back(packageModule);
    innerBundleInfo.SetBundlePackInfo(bundlePackInfo);
    ret = installChecker.NeedCheckDependency(dependency, innerBundleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InstallChecker_0600
 * @tc.name: test the start function of FindModuleInInstallingPackage
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_0600, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;

    BundleInstallChecker installChecker;
    auto ret = installChecker.FindModuleInInstallingPackage("moduleName", "bundleName", infos);
    EXPECT_EQ(ret, false);

    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = "bundleName";
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "moduleName";
    innerBundleInfo.innerModuleInfos_.insert(
        pair<std::string, InnerModuleInfo>("moduleName", innerModuleInfo));
    infos.insert(pair<std::string, InnerBundleInfo>("moduleName", innerBundleInfo));
    ret = installChecker.FindModuleInInstallingPackage("moduleName", "bundleName", infos);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: InstallChecker_0700
 * @tc.name: test the start function of FindModuleInInstalledPackage
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_0700, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    auto ret = installChecker.FindModuleInInstalledPackage("", "", 0);
    EXPECT_EQ(ret, false);
    ret = installChecker.FindModuleInInstalledPackage("moduleName", "moduleName", 0);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InstallChecker_0800
 * @tc.name: test the start function of ParseBundleInfo
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_0800, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo info;
    BundlePackInfo packInfo;
    auto ret = installChecker.ParseBundleInfo("", info, packInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_UNEXPECTED);
}

/**
 * @tc.number: InstallChecker_0900
 * @tc.name: test the start function of CheckDeviceType
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_0900, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos.clear();
    auto ret = installChecker.CheckDeviceType(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstallChecker_1000
 * @tc.name: test the start function of CheckBundleName
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_1000, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::string provisionBundleName;
    auto ret = installChecker.CheckBundleName("", "");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
}

/**
 * @tc.number: InstallChecker_1100
 * @tc.name: test the start function of CheckBundleName
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_1100, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::string provisionBundleName = BUNDLE_NAME;
    auto ret = installChecker.CheckBundleName(provisionBundleName, "");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
}

/**
 * @tc.number: InstallChecker_1200
 * @tc.name: test the start function of CheckBundleName
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_1200, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::string provisionBundleName = BUNDLE_NAME;
    auto ret = installChecker.CheckBundleName(provisionBundleName, BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstallChecker_1300
 * @tc.name: test the start function of CheckBundleName
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_1300, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckBundleName("", BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
}

/**
 * @tc.number: InstallChecker_1400
 * @tc.name: test the start function of VaildInstallPermission
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_1400, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InstallParam installParam;
    installParam.isCallByShell = true;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    bool ret = installChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: InstallChecker_1500
 * @tc.name: test the start function of VaildInstallPermission
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_1500, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InstallParam installParam;
    installParam.isCallByShell = false;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    bool ret = installChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_EQ(ret, true);
    installParam.installBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    ret = installChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_EQ(ret, true);
    installParam.installEnterpriseBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    ret = installChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: InstallChecker_1600
 * @tc.name: test the start function of VaildInstallPermission
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_1600, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InstallParam installParam;
    installParam.isCallByShell = true;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult result;
    Security::Verify::ProvisionInfo info;
    info.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    info.type = Security::Verify::ProvisionType::DEBUG;
    result.SetProvisionInfo(info);
    bool ret = installChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: InstallChecker_1700
 * @tc.name: test the start function of VaildInstallPermission
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_1700, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InstallParam installParam;
    installParam.isCallByShell = true;
    installParam.installEnterpriseBundlePermissionStatus = PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult result;
    Security::Verify::ProvisionInfo info;
    info.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    info.type = Security::Verify::ProvisionType::RELEASE;
    result.SetProvisionInfo(info);
    hapVerifyRes.emplace_back(result);
    bool ret = installChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InstallChecker_1800
 * @tc.name: test the start function of VaildInstallPermission
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_1800, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InstallParam installParam;
    installParam.isCallByShell = true;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult result;
    hapVerifyRes.emplace_back(result);
    bool ret = installChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InstallChecker_1900
 * @tc.name: test the start function of VaildInstallPermission
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_1900, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InstallParam installParam;
    installParam.isCallByShell = false;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult result;
    Security::Verify::ProvisionInfo info;
    info.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    result.SetProvisionInfo(info);
    hapVerifyRes.emplace_back(result);
    bool ret = installChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InstallChecker_2000
 * @tc.name: test the start function of ParseHapFiles
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_2000, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::vector<std::string> bundlePaths;
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    bundlePaths.push_back(bundlePath);

    InstallCheckParam checkParam;

    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult result;
    Security::Verify::ProvisionInfo info;
    info.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    info.type = Security::Verify::ProvisionType::RELEASE;
    info.bundleInfo.appFeature = "hos_system_app";
    info.bundleInfo.bundleName = BUNDLE_BACKUP_NAME;
    result.SetProvisionInfo(info);
    hapVerifyRes.emplace_back(result);

    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_BACKUP_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "moduleName";
    innerBundleInfo.innerModuleInfos_.insert(
        pair<std::string, InnerModuleInfo>("moduleName", innerModuleInfo));
    infos.insert(pair<std::string, InnerBundleInfo>("moduleName", innerBundleInfo));

    auto ret = installChecker.ParseHapFiles(bundlePaths, checkParam, hapVerifyRes, infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstallChecker_2100
 * @tc.name: test the start function of ParseHapFiles
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallerTest, InstallChecker_2100, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::vector<std::string> bundlePaths;
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    bundlePaths.push_back(bundlePath);

    InstallCheckParam checkParam;

    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult result;
    Security::Verify::ProvisionInfo info;
    info.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    info.type = Security::Verify::ProvisionType::RELEASE;
    info.bundleInfo.appFeature = "hos_normal_app";
    info.bundleInfo.bundleName = BUNDLE_BACKUP_NAME;
    result.SetProvisionInfo(info);
    hapVerifyRes.emplace_back(result);

    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_BACKUP_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "moduleName";
    innerBundleInfo.innerModuleInfos_.insert(
        pair<std::string, InnerModuleInfo>("moduleName", innerModuleInfo));
    infos.insert(pair<std::string, InnerBundleInfo>("moduleName", innerBundleInfo));

    auto ret = installChecker.ParseHapFiles(bundlePaths, checkParam, hapVerifyRes, infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleSignatureType_0100
 * @tc.name: test signed name is not the same
 * @tc.desc: 1. system running normally
 *           2. install a hap failed
 */
HWTEST_F(BmsBundleInstallerTest, BmsBundleSignatureType_0100, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + "signatureTest.hap";
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
}

/**
 * @tc.number: ExtractArkProfileFile_0100
 * @tc.name: test ExtractArkProfileFile
 * @tc.desc: 1.Test ExtractArkProfileFile
*/
HWTEST_F(BmsBundleInstallerTest, ExtractArkProfileFile_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string modulePath = "";
    std::string bundleName = "";
    auto ret = installer.ExtractArkProfileFile(modulePath, bundleName, USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: ExtractArkProfileFile_0200
 * @tc.name: test ExtractArkProfileFile
 * @tc.desc: 1.Test ExtractArkProfileFile
*/
HWTEST_F(BmsBundleInstallerTest, ExtractArkProfileFile_0200, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string modulePath = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    std::string bundleName = BUNDLE_NAME;
    auto ret = installer.ExtractArkProfileFile(modulePath, bundleName, USERID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ExtractAllArkProfileFile_0100
 * @tc.name: test ExtractAllArkProfileFile
 * @tc.desc: 1.Test ExtractAllArkProfileFile
*/
HWTEST_F(BmsBundleInstallerTest, ExtractAllArkProfileFile_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    BaseBundleInstaller installer;
    auto ret = installer.ExtractAllArkProfileFile(innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ExtractAllArkProfileFile_0200
 * @tc.name: test ExtractAllArkProfileFile
 * @tc.desc: 1.Test ExtractAllArkProfileFile
*/
HWTEST_F(BmsBundleInstallerTest, ExtractAllArkProfileFile_0200, Function | SmallTest | Level0)
{
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = MODULE_NAME;
    innerModuleInfo.modulePackage = MODULE_NAME;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsNewVersion(true);
    innerBundleInfo.InsertInnerModuleInfo(MODULE_NAME, innerModuleInfo);
    BaseBundleInstaller installer;
    auto ret = installer.ExtractAllArkProfileFile(innerBundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: ExtractAllArkProfileFile_0300
 * @tc.name: test ExtractAllArkProfileFile
 * @tc.desc: 1.Test ExtractAllArkProfileFile
*/
HWTEST_F(BmsBundleInstallerTest, ExtractAllArkProfileFile_0300, Function | SmallTest | Level0)
{
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = MODULE_NAME;
    innerModuleInfo.modulePackage = MODULE_NAME;
    innerModuleInfo.hapPath = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_NAME, innerModuleInfo);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.name = BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetIsNewVersion(true);
    BaseBundleInstaller installer;
    auto ret = installer.ExtractAllArkProfileFile(innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ExtractAllArkProfileFile_0400
 * @tc.name: test ExtractAllArkProfileFile
 * @tc.desc: 1.Test ExtractAllArkProfileFile
*/
HWTEST_F(BmsBundleInstallerTest, ExtractAllArkProfileFile_0400, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsNewVersion(false);
    BaseBundleInstaller installer;
    auto ret = installer.ExtractAllArkProfileFile(innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckArkProfileDir_0100
 * @tc.name: test CheckArkProfileDir
 * @tc.desc: 1.Test CheckArkProfileDir
*/
HWTEST_F(BmsBundleInstallerTest, CheckArkProfileDir_0100, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    bundleInfo.versionCode = 100;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetIsNewVersion(false);
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    installer.userId_ = USERID;
    InnerBundleInfo oldInnerBundleInfo;
    BundleInfo oldBundleInfo;
    oldBundleInfo.versionCode = 101;
    oldInnerBundleInfo.SetBaseBundleInfo(oldBundleInfo);
    auto ret = installer.CheckArkProfileDir(innerBundleInfo, oldInnerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckArkProfileDir_0200
 * @tc.name: test CheckArkProfileDir
 * @tc.desc: 1.Test CheckArkProfileDir
*/
HWTEST_F(BmsBundleInstallerTest, CheckArkProfileDir_0200, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    bundleInfo.versionCode = 101;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetIsNewVersion(false);
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    installer.userId_ = USERID;
    InnerBundleInfo oldInnerBundleInfo;
    BundleInfo oldBundleInfo;
    oldBundleInfo.versionCode = 100;
    oldInnerBundleInfo.SetBaseBundleInfo(oldBundleInfo);
    auto ret = installer.CheckArkProfileDir(innerBundleInfo, oldInnerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckArkProfileDir_0300
 * @tc.name: test CheckArkProfileDir
 * @tc.desc: 1.Test CheckArkProfileDir
*/
HWTEST_F(BmsBundleInstallerTest, CheckArkProfileDir_0300, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    bundleInfo.versionCode = 101;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetIsNewVersion(false);
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    installer.userId_ = USERID;
    InnerBundleInfo oldInnerBundleInfo;
    BundleInfo oldBundleInfo;
    oldBundleInfo.versionCode = 100;
    oldInnerBundleInfo.SetBaseBundleInfo(oldBundleInfo);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    oldInnerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    auto ret = installer.CheckArkProfileDir(innerBundleInfo, oldInnerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
    ret = installer.DeleteArkProfile(installer.bundleName_, installer.userId_);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckArkProfileDir_0400
 * @tc.name: test CheckArkProfileDir
 * @tc.desc: 1.Test CheckArkProfileDir
*/
HWTEST_F(BmsBundleInstallerTest, CheckArkProfileDir_0400, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    bundleInfo.versionCode = 101;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetIsNewVersion(true);
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    installer.userId_ = USERID;
    InnerBundleInfo oldInnerBundleInfo;
    BundleInfo oldBundleInfo;
    oldBundleInfo.versionCode = 100;
    oldInnerBundleInfo.SetBaseBundleInfo(oldBundleInfo);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    oldInnerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    auto ret = installer.CheckArkProfileDir(innerBundleInfo, oldInnerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
    ret = installer.DeleteArkProfile(installer.bundleName_, installer.userId_);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: asanEnabled_0100
 * @tc.name: test checkAsanEnabled when asanEnabled is set to be ture
 * @tc.desc: 1.Test checkAsanEnabled
*/
HWTEST_F(BmsBundleInstallerTest, checkAsanEnabled_0100, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);
    ApplicationInfo info;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool result = dataMgr->GetApplicationInfo(BUNDLE_BACKUP_NAME,
        ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);
    EXPECT_TRUE(info.asanEnabled);
    std::string asanLogPath = LOG;
    EXPECT_EQ(asanLogPath, info.asanLogPath);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

HWTEST_F(BmsBundleInstallerTest, checkAsanEnabled_0200, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ApplicationInfo info;
    bool result = dataMgr->GetApplicationInfo(BUNDLE_PREVIEW_NAME,
        ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);
    EXPECT_FALSE(info.asanEnabled);
    std::string asanLogPath = "";
    EXPECT_EQ(asanLogPath, info.asanLogPath);
    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

#ifdef BUNDLE_FRAMEWORK_APP_CONTROL

/**
 * @tc.number: baseBundleInstaller_4400
 * @tc.name: test InstallNormalAppControl
 * @tc.desc: 1.Test the InstallNormalAppControl of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_4400, Function | SmallTest | Level0)
{
    std::string installAppId = APPID;
    BaseBundleInstaller installer;
    int32_t userId = Constants::DEFAULT_USERID;
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);

    auto resultAddAppInstallAppControlDisallow = DelayedSingleton<AppControlManager>::GetInstance()->
        AddAppInstallControlRule(AppControlConstants::EDM_CALLING,
        appIds, AppControlConstants::APP_DISALLOWED_INSTALL, userId);
    EXPECT_EQ(resultAddAppInstallAppControlDisallow, OHOS::ERR_OK);

    auto ret = installer.InstallNormalAppControl(installAppId, userId);
    EXPECT_EQ(ret, OHOS::ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_INSTALL);

    auto resultDeleteAppInstallAppControlDisallow = DelayedSingleton<AppControlManager>::GetInstance()->
        DeleteAppInstallControlRule(AppControlConstants::EDM_CALLING,
        AppControlConstants::APP_DISALLOWED_INSTALL, appIds, userId);
    EXPECT_EQ(resultDeleteAppInstallAppControlDisallow, OHOS::ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_4500
 * @tc.name: test InstallNormalAppControl
 * @tc.desc: 1.Test the InstallNormalAppControl of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_4500, Function | SmallTest | Level0)
{
    std::string installAppId = APPID;
    BaseBundleInstaller installer;
    int32_t userId = Constants::DEFAULT_USERID;
    std::vector<std::string> appIds;
    appIds.emplace_back(SYSTEMFIEID_NAME);

    auto resultAddAppInstallAppControlAllow = DelayedSingleton<AppControlManager>::GetInstance()->
        AddAppInstallControlRule(AppControlConstants::EDM_CALLING,
        appIds, AppControlConstants::APP_DISALLOWED_INSTALL, userId);
    EXPECT_EQ(resultAddAppInstallAppControlAllow, OHOS::ERR_OK);

    auto ret = installer.InstallNormalAppControl(installAppId, userId);
    EXPECT_EQ(ret, OHOS::ERR_OK);

    auto resultDeleteAppInstallAppControlAllow = DelayedSingleton<AppControlManager>::GetInstance()->
        DeleteAppInstallControlRule(AppControlConstants::EDM_CALLING,
        AppControlConstants::APP_DISALLOWED_INSTALL, appIds, userId);
    EXPECT_EQ(resultDeleteAppInstallAppControlAllow, OHOS::ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_4600
 * @tc.name: test InstallNormalAppControl
 * @tc.desc: 1.Test the InstallNormalAppControl of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_4600, Function | SmallTest | Level0)
{
    std::string installAppId = APPID;
    BaseBundleInstaller installer;
    int32_t userId = Constants::DEFAULT_USERID;
    std::vector<std::string> appIds;
    appIds.emplace_back(APPID);
    seteuid(EDM_UID);
    auto resultAddAppInstallAppControlAllow = DelayedSingleton<AppControlManager>::GetInstance()->
        AddAppInstallControlRule(AppControlConstants::EDM_CALLING,
        appIds, AppControlConstants::APP_ALLOWED_INSTALL, userId);
    EXPECT_EQ(resultAddAppInstallAppControlAllow, OHOS::ERR_OK);

    auto resultAddAppInstallAppControlDisallow = DelayedSingleton<AppControlManager>::GetInstance()->
        AddAppInstallControlRule(AppControlConstants::EDM_CALLING,
        appIds, AppControlConstants::APP_DISALLOWED_INSTALL, userId);
    EXPECT_EQ(resultAddAppInstallAppControlDisallow, OHOS::ERR_OK);

    auto ret = installer.InstallNormalAppControl(installAppId, userId);
    EXPECT_EQ(ret, OHOS::ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_INSTALL);

    auto resultDeleteAppInstallAppControlAllow = DelayedSingleton<AppControlManager>::GetInstance()->
        DeleteAppInstallControlRule(AppControlConstants::EDM_CALLING,
        AppControlConstants::APP_ALLOWED_INSTALL, appIds, userId);
    EXPECT_EQ(resultDeleteAppInstallAppControlAllow, OHOS::ERR_OK);

    auto resultDeleteAppInstallAppControlDisallow = DelayedSingleton<AppControlManager>::GetInstance()->
        DeleteAppInstallControlRule(AppControlConstants::EDM_CALLING,
        AppControlConstants::APP_DISALLOWED_INSTALL, appIds, userId);
    EXPECT_EQ(resultDeleteAppInstallAppControlDisallow, OHOS::ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_4700
 * @tc.name: test InstallNormalAppControl
 * @tc.desc: 1.Test the InstallNormalAppControl of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_4700, Function | SmallTest | Level0)
{
    std::string installAppId = APPID;
    BaseBundleInstaller installer;
    int32_t userId = Constants::DEFAULT_USERID;
    std::vector<std::string> appIds;
    std::vector<std::string> appIdsAllow;
    appIds.emplace_back(APPID);
    appIdsAllow.emplace_back(SYSTEMFIEID_NAME);
    seteuid(EDM_UID);
    auto resultAddAppInstallAppControlAllow = DelayedSingleton<AppControlManager>::GetInstance()->
        AddAppInstallControlRule(AppControlConstants::EDM_CALLING,
        appIdsAllow, AppControlConstants::APP_ALLOWED_INSTALL, userId);
    EXPECT_EQ(resultAddAppInstallAppControlAllow, OHOS::ERR_OK);

    auto resultAddAppInstallAppControlDisallow = DelayedSingleton<AppControlManager>::GetInstance()->
        AddAppInstallControlRule(AppControlConstants::EDM_CALLING,
        appIds, AppControlConstants::APP_DISALLOWED_INSTALL, userId);
    EXPECT_EQ(resultAddAppInstallAppControlDisallow, OHOS::ERR_OK);

    auto ret = installer.InstallNormalAppControl(installAppId, userId);
    EXPECT_EQ(ret, OHOS::ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_INSTALL);

    auto resultDeleteAppInstallAppControlAllow = DelayedSingleton<AppControlManager>::GetInstance()->
        DeleteAppInstallControlRule(AppControlConstants::EDM_CALLING,
        AppControlConstants::APP_ALLOWED_INSTALL, appIdsAllow, userId);
    EXPECT_EQ(resultDeleteAppInstallAppControlAllow, OHOS::ERR_OK);

    auto resultDeleteAppInstallAppControlDisallow = DelayedSingleton<AppControlManager>::GetInstance()->
        DeleteAppInstallControlRule(AppControlConstants::EDM_CALLING,
        AppControlConstants::APP_DISALLOWED_INSTALL, appIds, userId);
    EXPECT_EQ(resultDeleteAppInstallAppControlDisallow, OHOS::ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_4800
 * @tc.name: test InstallNormalAppControl
 * @tc.desc: 1.Test the InstallNormalAppControl of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_4800, Function | SmallTest | Level0)
{
    std::string installAppId = APPID;
    BaseBundleInstaller installer;
    int32_t userId = Constants::DEFAULT_USERID;
    std::vector<std::string> appIds;
    std::vector<std::string> appIdsAllow;
    appIds.emplace_back(APPID);
    appIdsAllow.emplace_back(SYSTEMFIEID_NAME);
    seteuid(EDM_UID);
    auto resultAddAppInstallAppControlAllow = DelayedSingleton<AppControlManager>::GetInstance()->
        AddAppInstallControlRule(AppControlConstants::EDM_CALLING,
        appIds, AppControlConstants::APP_ALLOWED_INSTALL, userId);
    EXPECT_EQ(resultAddAppInstallAppControlAllow, OHOS::ERR_OK);

    auto resultAddAppInstallAppControlDisallow = DelayedSingleton<AppControlManager>::GetInstance()->
        AddAppInstallControlRule(AppControlConstants::EDM_CALLING,
        appIdsAllow, AppControlConstants::APP_DISALLOWED_INSTALL, userId);
    EXPECT_EQ(resultAddAppInstallAppControlDisallow, OHOS::ERR_OK);

    auto ret = installer.InstallNormalAppControl(installAppId, userId);
    EXPECT_EQ(ret, OHOS::ERR_OK);

    auto resultDeleteAppInstallAppControlAllow = DelayedSingleton<AppControlManager>::GetInstance()->
        DeleteAppInstallControlRule(AppControlConstants::EDM_CALLING,
        AppControlConstants::APP_ALLOWED_INSTALL, appIds, userId);
    EXPECT_EQ(resultDeleteAppInstallAppControlAllow, OHOS::ERR_OK);

    auto resultDeleteAppInstallAppControlDisallow = DelayedSingleton<AppControlManager>::GetInstance()->
        DeleteAppInstallControlRule(AppControlConstants::EDM_CALLING,
        AppControlConstants::APP_DISALLOWED_INSTALL, appIdsAllow, userId);
    EXPECT_EQ(resultDeleteAppInstallAppControlDisallow, OHOS::ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_4900
 * @tc.name: test InstallNormalAppControl
 * @tc.desc: 1.Test the InstallNormalAppControl of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_4900, Function | SmallTest | Level0)
{
    std::string installAppId = APPID;
    BaseBundleInstaller installer;
    int32_t userId = Constants::DEFAULT_USERID;
    std::vector<std::string> appIds;
    std::vector<std::string> appIdsAllow;
    appIds.emplace_back(SYSTEMFIEID_NAME);
    seteuid(EDM_UID);
    auto resultAddAppInstallAppControlAllow = DelayedSingleton<AppControlManager>::GetInstance()->
        AddAppInstallControlRule(AppControlConstants::EDM_CALLING,
        appIds, AppControlConstants::APP_ALLOWED_INSTALL, userId);
    EXPECT_EQ(resultAddAppInstallAppControlAllow, OHOS::ERR_OK);

    auto resultAddAppInstallAppControlDisallow = DelayedSingleton<AppControlManager>::GetInstance()->
        AddAppInstallControlRule(AppControlConstants::EDM_CALLING,
        appIds, AppControlConstants::APP_DISALLOWED_INSTALL, userId);
    EXPECT_EQ(resultAddAppInstallAppControlDisallow, OHOS::ERR_OK);

    auto ret = installer.InstallNormalAppControl(installAppId, userId);
    EXPECT_EQ(ret, OHOS::ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_INSTALL);

    auto resultDeleteAppInstallAppControlAllow = DelayedSingleton<AppControlManager>::GetInstance()->
        DeleteAppInstallControlRule(AppControlConstants::EDM_CALLING,
        AppControlConstants::APP_ALLOWED_INSTALL, appIds, userId);
    EXPECT_EQ(resultDeleteAppInstallAppControlAllow, OHOS::ERR_OK);

    auto resultDeleteAppInstallAppControlDisallow = DelayedSingleton<AppControlManager>::GetInstance()->
        DeleteAppInstallControlRule(AppControlConstants::EDM_CALLING,
        AppControlConstants::APP_DISALLOWED_INSTALL, appIds, userId);
    EXPECT_EQ(resultDeleteAppInstallAppControlDisallow, OHOS::ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_5000
 * @tc.name: test ProcessBundleInstall
 * @tc.desc: 1.Test the ProcessBundleInstall of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_5000, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::vector<std::string> inBundlePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + FIRST_RIGHT_HAP;
    inBundlePaths.emplace_back(bundleFile);
    InstallParam installParam;
    installParam.isPreInstallApp = false;
    auto appType = Constants::AppType::THIRD_PARTY_APP;
    int32_t uid = 0;
    ErrCode ret = installer.ProcessBundleInstall(
        inBundlePaths, installParam, appType, uid);
    EXPECT_EQ(ret, ERR_OK);
    ClearBundleInfo();
}

/**
 * @tc.number: baseBundleInstaller_5100
 * @tc.name: test InnerProcessInstallByPreInstallInfo
 * @tc.desc: 1.Test the InnerProcessInstallByPreInstallInfo of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_5100, Function | SmallTest | Level0)
{
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    BaseBundleInstaller installer;
    installer.dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    installer.dataMgr_->AddUserId(100);
    InstallParam installParam;
    installParam.isPreInstallApp = false;
    installParam.userId = 100;
    installer.userId_ = 100;
    int32_t uid = 100;
    auto ret = installer.InnerProcessInstallByPreInstallInfo(BUNDLE_MODULEJSON_TEST, installParam, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_RECOVER_INVALID_BUNDLE_NAME);
    ClearBundleInfo();
}

/**
 * @tc.number: baseBundleInstaller_5200
 * @tc.name: test InnerProcessInstallByPreInstallInfo
 * @tc.desc: 1.Test the InnerProcessInstallByPreInstallInfo of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_5200, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    UninstallParam uninstallParam;
    uninstallParam.bundleName = "";
    auto ret = installer.UninstallBundleByUninstallParam(uninstallParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_SHARE_APP_LIBRARY_IS_NOT_EXIST);
}

/**
 * @tc.number: baseBundleInstaller_5300
 * @tc.name: test InnerProcessInstallByPreInstallInfo
 * @tc.desc: 1.Test the InnerProcessInstallByPreInstallInfo of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_5300, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    UninstallParam uninstallParam;
    uninstallParam.bundleName = BUNDLE_NAME;
    ClearDataMgr();
    auto ret = installer.UninstallBundleByUninstallParam(uninstallParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);
    ResetDataMgr();
}

/**
 * @tc.number: appControlManagerHostImpl_0100
 * @tc.name: test GetControlRuleType
 * @tc.desc: 1.Test the GetControlRuleType of AppControlManagerHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, appControlManagerHostImpl_0100, Function | SmallTest | Level0)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    auto ret = impl->GetControlRuleType(AppInstallControlRuleType::DISALLOWED_UNINSTALL);
    EXPECT_EQ(ret, AppControlConstants::APP_DISALLOWED_UNINSTALL);
}

/**
 * @tc.number: appControlManagerHostImpl_0200
 * @tc.name: test GetControlRuleType
 * @tc.desc: 1.Test the GetControlRuleType of AppControlManagerHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, appControlManagerHostImpl_0200, Function | SmallTest | Level0)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    auto ret = impl->GetControlRuleType(AppInstallControlRuleType::UNSPECIFIED);
    EXPECT_EQ(ret, EMPTY_STRING);
}
#endif

/**
 * @tc.number: baseBundleInstaller_5400
 * @tc.name: test checkAsanEnabled when asanEnabled is set to be ture
 * @tc.desc: 1.Test checkAsanEnabled
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_5400, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    int32_t uid = USERID;

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret = GetBundleDataMgr()->UpdateBundleInstallState(BUNDLE_BACKUP_NAME, InstallState::UNINSTALL_START);
    EXPECT_EQ(ret, true);

    auto res = installer.ProcessBundleUninstall(BUNDLE_BACKUP_NAME, installParam, uid);
    EXPECT_EQ(res, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);

    ret = GetBundleDataMgr()->UpdateBundleInstallState(BUNDLE_BACKUP_NAME, InstallState::UNINSTALL_SUCCESS);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: baseBundleInstaller_5500
 * @tc.name: test ProcessBundleUninstall
 * @tc.desc: 1.Test ProcessBundleUninstall
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_5500, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.userId = 999;
    installParam.installFlag = InstallFlag::NORMAL;
    int32_t uid = USERID;

    auto res = installer.ProcessBundleUninstall(BUNDLE_BACKUP_NAME, TEST_PACK_AGE, installParam, uid);
    EXPECT_EQ(res, ERR_APPEXECFWK_USER_NOT_EXIST);
}

/**
 * @tc.number: baseBundleInstaller_5600
 * @tc.name: test ProcessBundleUninstall
 * @tc.desc: 1.Test ProcessBundleUninstall
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_5600, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    int32_t uid = USERID;

    auto res = installer.ProcessBundleUninstall(BUNDLE_BACKUP_NAME, WRONG_BUNDLE_NAME, installParam, uid);
    EXPECT_EQ(res, ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_MODULE);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: baseBundleInstaller_5700
 * @tc.name: test ProcessBundleUninstall
 * @tc.desc: 1.Test ProcessBundleUninstall
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_5700, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    int32_t uid = USERID;

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool ret = GetBundleDataMgr()->UpdateBundleInstallState(BUNDLE_BACKUP_NAME, InstallState::UNINSTALL_START);
    EXPECT_EQ(ret, true);

    auto res = installer.ProcessBundleUninstall(BUNDLE_BACKUP_NAME, TEST_PACK_AGE, installParam, uid);
    EXPECT_EQ(res, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);

    ret = GetBundleDataMgr()->UpdateBundleInstallState(BUNDLE_BACKUP_NAME, InstallState::UNINSTALL_SUCCESS);
    EXPECT_EQ(ret, false);
}

#ifdef BUNDLE_FRAMEWORK_QUICK_FIX

/**
 * @tc.number: baseBundleInstaller_5800
 * @tc.name: test UpdateLibAttrs
 * @tc.desc: 1.Test the UpdateLibAttrs of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_5800, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo newInfo;
    newInfo.SetCurrentModulePackage(MODULE_NAME_TEST);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = MODULE_NAME_TEST;
    innerModuleInfo.isLibIsolated = true;
    newInfo.innerModuleInfos_.insert(
        std::pair<std::string, InnerModuleInfo>(MODULE_NAME_TEST, innerModuleInfo));
    AppqfInfo appQfInfo;
    auto ret = installer.UpdateLibAttrs(newInfo, TEST_CPU_ABI, BUNDLE_LIBRARY_PATH_DIR, appQfInfo);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_MODULE_NAME_NOT_EXIST);
}

/**
 * @tc.number: baseBundleInstaller_5900
 * @tc.name: test UpdateLibAttrs
 * @tc.desc: 1.Test the UpdateLibAttrs of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_5900, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo newInfo;
    newInfo.SetCurrentModulePackage(MODULE_NAME_TEST);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = MODULE_NAME_TEST;
    innerModuleInfo.isLibIsolated = false;
    AppqfInfo appQfInfo;
    auto ret = installer.UpdateLibAttrs(newInfo, TEST_CPU_ABI, BUNDLE_LIBRARY_PATH_DIR, appQfInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_6000
 * @tc.name: test UpdateLibAttrs
 * @tc.desc: 1.Test the UpdateLibAttrs of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_6000, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo newInfo;
    newInfo.SetCurrentModulePackage(MODULE_NAME_TEST);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = MODULE_NAME_TEST;
    innerModuleInfo.isLibIsolated = true;
    newInfo.innerModuleInfos_.insert(
        std::pair<std::string, InnerModuleInfo>(MODULE_NAME_TEST, innerModuleInfo));
    AppqfInfo appQfInfo;
    std::vector<HqfInfo> hqfInfos;
    HqfInfo info;
    info.moduleName = MODULE_NAME;
    hqfInfos.emplace_back(info);
    info.moduleName = MODULE_NAME_TEST;
    info.nativeLibraryPath = BUNDLE_LIBRARY_PATH_DIR;
    info.cpuAbi = TEST_CPU_ABI;
    hqfInfos.emplace_back(info);
    appQfInfo.hqfInfos = hqfInfos;
    auto ret = installer.UpdateLibAttrs(newInfo, TEST_CPU_ABI, BUNDLE_LIBRARY_PATH_DIR, appQfInfo);
    EXPECT_EQ(ret, ERR_OK);
}

#endif

/**
 * @tc.number: ParseFiles_0100
 * @tc.name: test the start function of ParseFiles
 * @tc.desc: 1.Test ParseFiles
*/
HWTEST_F(BmsBundleInstallerTest, ParseFiles_0100, Function | SmallTest | Level0)
{
    InstallParam installParam;
    auto appType = Constants::AppType::THIRD_PARTY_APP;
    SharedBundleInstaller installer(installParam, appType);
    installer.installParam_.sharedBundleDirPaths.clear();
    auto res = installer.ParseFiles();
    EXPECT_EQ(res, ERR_OK);
    bool result = installer.NeedToInstall();
    EXPECT_FALSE(result);
}

/**
 * @tc.number: ParseFiles_0200
 * @tc.name: test the start function of ParseFiles
 * @tc.desc: 1.Test ParseFiles
*/
HWTEST_F(BmsBundleInstallerTest, ParseFiles_0200, Function | SmallTest | Level0)
{
    InstallParam installParam;
    auto appType = Constants::AppType::THIRD_PARTY_APP;
    SharedBundleInstaller installer(installParam, appType);
    installParam.sharedBundleDirPaths = {"/path/to/test1", "/path/to/test2"};
    installer.installParam_.sharedBundleDirPaths = installParam.sharedBundleDirPaths;
    auto ret = installer.ParseFiles();
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: CheckDependency_0100
 * @tc.name: test the start function of CheckDependency
 * @tc.desc: 1.Test CheckDependency
*/
HWTEST_F(BmsBundleInstallerTest, CheckDependency_0100, Function | SmallTest | Level0)
{
    InstallParam installParam;
    auto appType = Constants::AppType::THIRD_PARTY_APP;
    SharedBundleInstaller installer(installParam, appType);
    Dependency dependency;
    dependency.bundleName = "";
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.dependencies.push_back(dependency);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "";
    innerBundleInfo.innerModuleInfos_.insert(pair<std::string, InnerModuleInfo>("1", innerModuleInfo));
    auto res = installer.CheckDependency(innerBundleInfo);
    EXPECT_TRUE(res);

    innerBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    res = installer.CheckDependency(innerBundleInfo);
    EXPECT_TRUE(res);

    Dependency dependency1;
    dependency1.bundleName = BUNDLE_NAME;
    InnerModuleInfo innerModuleInfo1;
    innerModuleInfo1.dependencies.push_back(dependency1);
    innerBundleInfo.innerModuleInfos_.insert(pair<std::string, InnerModuleInfo>("2", innerModuleInfo1));
    res = installer.CheckDependency(innerBundleInfo);
    EXPECT_TRUE(res);

    innerBundleInfo.baseApplicationInfo_->bundleName = WRONG_BUNDLE_NAME;
    res = installer.CheckDependency(innerBundleInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: CheckDependency_0100
 * @tc.name: test the start function of CheckDependency
 * @tc.desc: 1.Test CheckDependency
*/
HWTEST_F(BmsBundleInstallerTest, CheckDependency_0200, Function | SmallTest | Level0)
{
    InstallParam installParam;
    auto appType = Constants::AppType::THIRD_PARTY_APP;
    SharedBundleInstaller installer(installParam, appType);
    Dependency dependency;
    dependency.bundleName = BUNDLE_NAME;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.dependencies.push_back(dependency);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = WRONG_BUNDLE_NAME;
    innerBundleInfo.innerModuleInfos_.insert(pair<std::string, InnerModuleInfo>("1", innerModuleInfo));
    std::string path = BUNDLE_DATA_DIR;
    std::shared_ptr<InnerSharedBundleInstaller> innerSharedBundleInstaller =
        std::make_shared<InnerSharedBundleInstaller>(path);
    innerSharedBundleInstaller->bundleName_ = WRONG_BUNDLE_NAME;
    installer.innerInstallers_.insert(pair<std::string,
        std::shared_ptr<InnerSharedBundleInstaller>>(WRONG_BUNDLE_NAME, innerSharedBundleInstaller));
    auto res = installer.CheckDependency(innerBundleInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetNativeLibraryFileNames_0001
 * @tc.name: test GetNativeLibraryFileNames
 * @tc.desc: 1.Test the GetNativeLibraryFileNames of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, GetNativeLibraryFileNames_0001, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> fileNames;
    auto ret = impl.GetNativeLibraryFileNames("", "", fileNames);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.GetNativeLibraryFileNames("/data/test/xxx.hap", "libs/arm", fileNames);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(fileNames.empty());
}

/**
 * @tc.number: BmsBundleInstallerTest_0010
 * @tc.name: InnerProcessNativeLibs
 * @tc.desc: test InnerProcessNativeLibs isLibIsolated false
 */
HWTEST_F(BmsBundleInstallerTest, BmsBundleInstallerTest_0010, TestSize.Level1)
{
    InnerBundleInfo info;
    info.currentPackage_ = MODULE_NAME_TEST;
    InnerModuleInfo moduleInfo;
    moduleInfo.name = MODULE_NAME_TEST;
    moduleInfo.moduleName = MODULE_NAME_TEST;
    moduleInfo.modulePackage = MODULE_NAME_TEST;
    moduleInfo.isLibIsolated = false;
    moduleInfo.compressNativeLibs = true;
    info.innerModuleInfos_[MODULE_NAME_TEST] = moduleInfo;
    info.baseApplicationInfo_->cpuAbi = "";
    info.baseApplicationInfo_->nativeLibraryPath = "";

    BaseBundleInstaller installer;
    installer.modulePackage_ = MODULE_NAME_TEST;
    installer.modulePath_ = "";
    std::string modulePath = "";
    // nativeLibraryPath empty, compressNativeLibs true
    ErrCode ret = installer.InnerProcessNativeLibs(info, modulePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    info.innerModuleInfos_[MODULE_NAME_TEST].compressNativeLibs = false;
    // nativeLibraryPath empty, compressNativeLibs false
    ret = installer.InnerProcessNativeLibs(info, modulePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    // nativeLibraryPath not empty, compressNativeLibs true
    info.baseApplicationInfo_->cpuAbi = "libs/arm";
    info.baseApplicationInfo_->nativeLibraryPath = "libs/arm";
    modulePath = "package_tmp";
    info.innerModuleInfos_[MODULE_NAME_TEST].compressNativeLibs = true;
    ret = installer.InnerProcessNativeLibs(info, modulePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    // nativeLibraryPath not empty, compressNativeLibs false
    info.innerModuleInfos_[MODULE_NAME_TEST].compressNativeLibs = false;
    ret = installer.InnerProcessNativeLibs(info, modulePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    modulePath = "/data/test/bms_bundle_installer";
    installer.modulePath_ = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    ret = installer.InnerProcessNativeLibs(info, modulePath);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InnerProcessNativeLibs_0100
 * @tc.name: InnerProcessNativeLibs
 * @tc.desc: test InnerProcessNativeLibs of BaseBundleInstaller with api13
 */
HWTEST_F(BmsBundleInstallerTest, InnerProcessNativeLibs_0100, TestSize.Level1)
{
    InnerBundleInfo info;
    info.currentPackage_ = MODULE_NAME_TEST;
    InnerModuleInfo moduleInfo;
    moduleInfo.name = MODULE_NAME_TEST;
    moduleInfo.moduleName = MODULE_NAME_TEST;
    moduleInfo.modulePackage = MODULE_NAME_TEST;
    moduleInfo.cpuAbi = "libs/arm";
    moduleInfo.nativeLibraryPath = "libs/arm";
    moduleInfo.isLibIsolated = true;
    moduleInfo.compressNativeLibs = false;
    info.baseBundleInfo_->targetVersion = TARGET_VERSION_FOURTEEN;
    info.innerModuleInfos_[MODULE_NAME_TEST] = moduleInfo;
    info.baseApplicationInfo_->cpuAbi = "";
    info.baseApplicationInfo_->nativeLibraryPath = "";

    BaseBundleInstaller installer;
    installer.modulePackage_ = MODULE_NAME_TEST;
    std::string modulePath = "/data/test/bms_bundle_installer";
    installer.modulePath_ = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    ErrCode ret = installer.InnerProcessNativeLibs(info, modulePath);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleInstallerTest_0020
 * @tc.name: InnerProcessNativeLibs
 * @tc.desc: test InnerProcessNativeLibs isLibIsolated true
 */
HWTEST_F(BmsBundleInstallerTest, BmsBundleInstallerTest_0020, TestSize.Level1)
{
    InnerBundleInfo info;
    info.currentPackage_ = MODULE_NAME_TEST;
    InnerModuleInfo moduleInfo;
    moduleInfo.name = MODULE_NAME_TEST;
    moduleInfo.moduleName = MODULE_NAME_TEST;
    moduleInfo.modulePackage = MODULE_NAME_TEST;
    moduleInfo.cpuAbi = "libs/arm";
    moduleInfo.nativeLibraryPath = "libs/arm";
    moduleInfo.isLibIsolated = true;
    moduleInfo.compressNativeLibs = true;
    info.innerModuleInfos_[MODULE_NAME_TEST] = moduleInfo;
    info.baseApplicationInfo_->cpuAbi = "";
    info.baseApplicationInfo_->nativeLibraryPath = "";

    BaseBundleInstaller installer;
    installer.modulePackage_ = MODULE_NAME_TEST;
    installer.modulePath_ = "";
    std::string modulePath = "";
    // nativeLibraryPath empty, compressNativeLibs true
    ErrCode ret = installer.InnerProcessNativeLibs(info, modulePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    modulePath = "package_tmp";
    ret = installer.InnerProcessNativeLibs(info, modulePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    modulePath = "/data/test/bms_bundle_installer";
    installer.modulePath_ = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    ret = installer.InnerProcessNativeLibs(info, modulePath);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleInstallerTest_0030
 * @tc.name: ExtractSoFiles
 * @tc.desc: test ExtractSoFiles
 */
HWTEST_F(BmsBundleInstallerTest, BmsBundleInstallerTest_0030, TestSize.Level1)
{
    BaseBundleInstaller installer;
    auto ret = installer.ExtractSoFiles("/data/test", "libs/arm");
    EXPECT_FALSE(ret);

    installer.modulePath_ = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    ret = installer.ExtractSoFiles("/data/test", "libs/arm");
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: ProcessOldNativeLibraryPath_0010
 * @tc.name: ExtractSoFiles
 * @tc.desc: test ProcessOldNativeLibraryPath
 */
HWTEST_F(BmsBundleInstallerTest, ProcessOldNativeLibraryPath_0010, TestSize.Level1)
{
    bool ret = OHOS::ForceCreateDirectory(BUNDLE_LIBRARY_PATH_DIR);
    EXPECT_TRUE(ret);

    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    int32_t oldVersionCode = 1000;
    std::string nativeLibraryPath = "";
    installer.ProcessOldNativeLibraryPath(newInfos, oldVersionCode, nativeLibraryPath);
    auto exist = access(BUNDLE_LIBRARY_PATH_DIR.c_str(), F_OK);
    EXPECT_EQ(exist, 0);

    nativeLibraryPath = "libs/arm";
    installer.ProcessOldNativeLibraryPath(newInfos, oldVersionCode, nativeLibraryPath);
    exist = access(BUNDLE_LIBRARY_PATH_DIR.c_str(), F_OK);
    EXPECT_EQ(exist, 0);

    installer.versionCode_ = 2000;
    nativeLibraryPath = "";
    installer.ProcessOldNativeLibraryPath(newInfos, oldVersionCode, nativeLibraryPath);
    exist = access(BUNDLE_LIBRARY_PATH_DIR.c_str(), F_OK);
    EXPECT_EQ(exist, 0);

    nativeLibraryPath = "libs/arm";
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.compressNativeLibs = true;
    innerBundleInfo.innerModuleInfos_["aaa"] = moduleInfo;
    moduleInfo.compressNativeLibs = false;
    innerBundleInfo.innerModuleInfos_["bbb"] = moduleInfo;
    newInfos["a"] = innerBundleInfo;
    installer.ProcessOldNativeLibraryPath(newInfos, oldVersionCode, nativeLibraryPath);
    exist = access(BUNDLE_LIBRARY_PATH_DIR.c_str(), F_OK);
    EXPECT_EQ(exist, 0);

    moduleInfo.compressNativeLibs = false;
    innerBundleInfo.innerModuleInfos_["aaa"] = moduleInfo;
    newInfos["a"] = innerBundleInfo;

    installer.ProcessOldNativeLibraryPath(newInfos, oldVersionCode, nativeLibraryPath);
    exist = access(BUNDLE_LIBRARY_PATH_DIR.c_str(), F_OK);
    EXPECT_NE(exist, 0);
}

/**
 * @tc.number: UninstallHspVersion_0010
 * @tc.name: UninstallHspVersion
 * @tc.desc: test UninstallHspVersion
 */
HWTEST_F(BmsBundleInstallerTest, UninstallHspVersion_0010, TestSize.Level1)
{
    BaseBundleInstaller installer;
    int32_t versionCode = 9;
    InnerBundleInfo info;
    std::string uninstallDir;
    installer.InitDataMgr();
    auto ret = installer.UninstallHspVersion(uninstallDir, versionCode, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR);
}

/**
 * @tc.number: CheckEnableRemovable_0010
 * @tc.name: CheckEnableRemovable
 * @tc.desc: test CheckEnableRemovable
 */
HWTEST_F(BmsBundleInstallerTest, CheckEnableRemovable_0010, TestSize.Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo newInfo;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.emplace("", newInfo);
    InnerBundleInfo oldInfo;
    bool isFreeInstallFlag = true;
    bool isAppExist = false;
    int32_t userId = 100;
    installer.CheckEnableRemovable(newInfos, oldInfo, userId, isFreeInstallFlag, isAppExist);

    bool existModule = oldInfo.FindModule(MODULE_NAME);
    EXPECT_EQ(existModule, false);
}

/**
 * @tc.number: CheckEnableRemovable_0020
 * @tc.name: CheckEnableRemovable
 * @tc.desc: test CheckEnableRemovable
 */
HWTEST_F(BmsBundleInstallerTest, CheckEnableRemovable_0020, TestSize.Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo newInfo;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.emplace("", newInfo);
    InnerBundleInfo oldInfo;
    bool isFreeInstallFlag = true;
    bool isAppExist = false;
    int32_t userId = 100;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = MODULE_NAME;
    innerModuleInfo.modulePackage = MODULE_NAME;
    newInfo.InsertInnerModuleInfo(MODULE_NAME, innerModuleInfo);
    oldInfo.InsertInnerModuleInfo(MODULE_NAME, innerModuleInfo);

    installer.CheckEnableRemovable(newInfos, oldInfo, userId, isFreeInstallFlag, isAppExist);
    bool existModule = oldInfo.FindModule(MODULE_NAME);
    EXPECT_EQ(existModule, true);
}

/**
 * @tc.number: CheckEnableRemovable_0030
 * @tc.name: CheckEnableRemovable
 * @tc.desc: test CheckEnableRemovable
 */
HWTEST_F(BmsBundleInstallerTest, CheckEnableRemovable_0030, TestSize.Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo newInfo;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.emplace("", newInfo);
    InnerBundleInfo oldInfo;
    bool isFreeInstallFlag = true;
    bool isAppExist = true;
    int32_t userId = 100;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = MODULE_NAME;
    innerModuleInfo.modulePackage = MODULE_NAME;
    newInfo.InsertInnerModuleInfo(MODULE_NAME, innerModuleInfo);
    oldInfo.InsertInnerModuleInfo(MODULE_NAME, innerModuleInfo);
    installer.CheckEnableRemovable(newInfos, oldInfo, userId, isFreeInstallFlag, isAppExist);

    bool existModule = oldInfo.FindModule(MODULE_NAME);
    EXPECT_EQ(existModule, true);
}

/**
 * @tc.number: CheckEnableRemovable_0040
 * @tc.name: CheckEnableRemovable
 * @tc.desc: test CheckEnableRemovable
 */
HWTEST_F(BmsBundleInstallerTest, CheckEnableRemovable_0040, TestSize.Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo newInfo;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo oldInfo;
    int32_t userId = USERID;
    installer.CheckEnableRemovable(newInfos, oldInfo, userId, true, true);
    bool existModule = oldInfo.FindModule(MODULE_NAME);
    EXPECT_EQ(existModule, false);
}

/**
 * @tc.number: CheckEnableRemovable_0050
 * @tc.name: CheckEnableRemovable
 * @tc.desc: test CheckEnableRemovable
 */
HWTEST_F(BmsBundleInstallerTest, CheckEnableRemovable_0050, TestSize.Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo newInfo;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.emplace("", newInfo);
    InnerBundleInfo oldInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    std::string key = BUNDLE_NAME + "_100";
    oldInfo.innerBundleUserInfos_.insert(pair<std::string, InnerBundleUserInfo>(key, innerBundleUserInfo));
    int32_t userId = USERID;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = MODULE_NAME;
    innerModuleInfo.modulePackage = MODULE_NAME;
    newInfo.InsertInnerModuleInfo(MODULE_NAME, innerModuleInfo);
    oldInfo.InsertInnerModuleInfo(MODULE_NAME, innerModuleInfo);
    installer.CheckEnableRemovable(newInfos, oldInfo, userId, true, true);

    bool existModule = oldInfo.FindModule(MODULE_NAME);
    EXPECT_EQ(existModule, true);
}

/**
 * @tc.number: InnerProcessBundleInstall_0010
 * @tc.name: CheckEnableRemovable
 * @tc.desc: test CheckEnableRemovable
 */
HWTEST_F(BmsBundleInstallerTest, InnerProcessBundleInstall_0010, TestSize.Level1)
{
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetSingleton(false);
    newInfos.insert(pair<std::string, InnerBundleInfo>());
    InnerBundleInfo oldInfo;
    InstallParam installParam;
    installParam.needSavePreInstallInfo = false;
    int32_t uid = EDM_UID;
    installer.isAppExist_ = true;
    ClearDataMgr();
    auto res = installer.InnerProcessBundleInstall(newInfos, oldInfo, installParam, uid);
    installer.RollBack(newInfos, oldInfo);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR);
    ResetDataMgr();
}

/**
 * @tc.number: InnerProcessBundleInstall_0020
 * @tc.name: CheckEnableRemovable
 * @tc.desc: test CheckEnableRemovable
 */
HWTEST_F(BmsBundleInstallerTest, InnerProcessBundleInstall_0020, TestSize.Level1)
{
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetSingleton(false);
    newInfos.insert(std::pair<std::string, InnerBundleInfo>(BUNDLE_NAME_TEST, innerBundleInfo));
    int32_t uid = EDM_UID;
    InnerBundleInfo oldInfo;
    InstallParam installParam;
    installParam.needSavePreInstallInfo = false;
    installer.isAppExist_ = true;
    oldInfo.SetApplicationBundleType(BundleType::SHARED);
    auto res = installer.InnerProcessBundleInstall(newInfos, oldInfo, installParam, uid);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_STATE_ERROR);
}

/**
 * @tc.number: ProcessModuleUpdate_0020
 * @tc.name: test ProcessBundleInstallStatus
 * @tc.desc: 1.Test the ProcessBundleInstallStatus
*/
HWTEST_F(BmsBundleInstallerTest, ProcessModuleUpdate_0020, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo innerBundleInfo;
    InnerBundleInfo oldInfo;
    bool isReplace = true;
    bool killProcess = false;
    innerBundleInfo.userId_ = USERID;
    ErrCode res = installer.ProcessModuleUpdate(innerBundleInfo, oldInfo, isReplace, killProcess);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_INCONSISTENT_MODULE_NAME);
}

/**
 * @tc.number: CreateBundleDataDir_0010
 * @tc.name: test CreateBundleDataDir
 * @tc.desc: 1.Test the CreateBundleDataDir
*/
HWTEST_F(BmsBundleInstallerTest, CreateBundleDataDir_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.userId_ = ServiceConstants::NOT_EXIST_USERID;
    InnerBundleInfo info;
    installer.InitDataMgr();
    ErrCode res = installer.CreateBundleDataDir(info);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_GENERATE_UID_ERROR);
}

/**
 * @tc.number: CreateBundleDataDir_0020
 * @tc.name: test CreateBundleDataDir
 * @tc.desc: 1.Test the CreateBundleDataDir
*/
HWTEST_F(BmsBundleInstallerTest, CreateBundleDataDir_0020, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME_TEST;
    bundleInfo.applicationInfo.name = BUNDLE_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME_TEST;
    applicationInfo.deviceId = DEVICE_ID;
    applicationInfo.bundleName = BUNDLE_NAME_TEST;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    info.SetAppType(Constants::AppType::SYSTEM_APP);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = 0;
    innerBundleUserInfo.bundleName = BUNDLE_NAME_TEST;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->installStates_.clear();
    dataMgr->bundleInfos_.clear();
    bool ret1 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME_TEST, InstallState::INSTALL_START);
    bool ret2 = dataMgr->AddInnerBundleInfo(BUNDLE_NAME_TEST, info);
    bool ret3 = dataMgr->GenerateUidAndGid(innerBundleUserInfo);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(ret3);

    BaseBundleInstaller installer;
    installer.InitDataMgr();
    installer.userId_ = ServiceConstants::NOT_EXIST_USERID;
    ErrCode res = installer.CreateBundleDataDir(info);
    EXPECT_NE(res, ERR_OK);

    ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME_TEST, InstallState::UNINSTALL_START);
    EXPECT_TRUE(ret3);
    ret3 = dataMgr->UpdateBundleInstallState(BUNDLE_NAME_TEST, InstallState::UNINSTALL_SUCCESS);
    EXPECT_TRUE(ret3);
}

/**
 * @tc.number: ExtractModule_0010
 * @tc.name: test ExtractModule
 * @tc.desc: 1.Test the ExtractModule
*/
HWTEST_F(BmsBundleInstallerTest, ExtractModule_0010, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.currentPackage_ = MODULE_NAME_TEST;
    InnerModuleInfo moduleInfo;
    moduleInfo.name = MODULE_NAME_TEST;
    moduleInfo.moduleName = MODULE_NAME_TEST;
    moduleInfo.modulePackage = MODULE_NAME_TEST;
    moduleInfo.isLibIsolated = false;
    moduleInfo.compressNativeLibs = true;
    info.innerModuleInfos_[MODULE_NAME_TEST] = moduleInfo;
    info.baseApplicationInfo_->cpuAbi = TEST_CPU_ABI;
    info.baseApplicationInfo_->nativeLibraryPath = "";

    BaseBundleInstaller installer;
    installer.modulePackage_ = MODULE_NAME_TEST;
    std::string modulePath = "/data/test/bms_bundle_installer";
    installer.modulePath_ = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    ErrCode ret = installer.InnerProcessNativeLibs(info, modulePath);
    EXPECT_EQ(ret, ERR_OK);

    info.SetIsNewVersion(true);
    ErrCode res = installer.ExtractModule(info, modulePath);
    EXPECT_EQ(res, ERR_OK);

    info.baseApplicationInfo_->arkNativeFilePath = "";
    info.baseApplicationInfo_->arkNativeFileAbi = "errorType";
    res = installer.ExtractModule(info, modulePath);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARSE_AN_FAILED);
}

/**
 * @tc.number: RenameModuleDir_0010
 * @tc.name: test RenameModuleDir
 * @tc.desc: 1.Test the RenameModuleDir
*/
HWTEST_F(BmsBundleInstallerTest, RenameModuleDir_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;
    info.currentPackage_ = BUNDLE_NAME_TEST;
    ErrCode res = installer.RenameModuleDir(info);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALLD_RNAME_DIR_FAILED);
}

/**
 * @tc.number: CheckApiInfo_0010
 * @tc.name: test CheckApiInfo
 * @tc.desc: 1.Test the CheckApiInfo
*/
HWTEST_F(BmsBundleInstallerTest, CheckApiInfo_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.singletonState_ = AppExecFwk::BaseBundleInstaller::SingletonState::SINGLETON_TO_NON;
    bool killProcess = false;
    std::unordered_map<std::string, InnerBundleInfo> info;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->compileSdkType = "OpenHarmony";
    installer.OnSingletonChange(killProcess);
    info.try_emplace("OpenHarmony", innerBundleInfo);

    bool res = installer.CheckApiInfo(info);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: CheckApiInfo_0030
 * @tc.name: test CheckApiInfo
 * @tc.desc: 1.Test the CheckApiInfo
*/
HWTEST_F(BmsBundleInstallerTest, CheckApiInfo_0030, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.singletonState_ = AppExecFwk::BaseBundleInstaller::SingletonState::NON_TO_SINGLETON;
    bool killProcess = false;
    std::unordered_map<std::string, InnerBundleInfo> info;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->compileSdkType = "OpenHarmony1";
    innerBundleInfo.baseBundleInfo_->compatibleVersion = COMPATIBLE_VERSION;
    installer.OnSingletonChange(killProcess);
    info.try_emplace("OpenHarmony2", innerBundleInfo);

    bool res = installer.CheckApiInfo(info);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: UninstallLowerVersionFeature_0010
 * @tc.name: test UninstallLowerVersionFeature
 * @tc.desc: 1.Test the UninstallLowerVersionFeature
*/
HWTEST_F(BmsBundleInstallerTest, UninstallLowerVersionFeature_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();
    std::vector<std::string> packageVec;
    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    ErrCode res = installer.UninstallLowerVersionFeature(packageVec);
    EXPECT_EQ(res, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);
}

/**
 * @tc.number: UninstallLowerVersionFeature_0020
 * @tc.name: test UninstallLowerVersionFeature
 * @tc.desc: 1.Test the UninstallLowerVersionFeature
*/
HWTEST_F(BmsBundleInstallerTest, UninstallLowerVersionFeature_0020, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::vector<std::string> packageVec;
    installer.bundleName_ = "";
    ErrCode res = installer.UninstallLowerVersionFeature(packageVec);
    EXPECT_EQ(res, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);
}

/**
 * @tc.number: GetUserId_0010
 * @tc.name: test GetUserId
 * @tc.desc: 1.Test the GetUserId
*/
HWTEST_F(BmsBundleInstallerTest, GetUserId_0010, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    int32_t res = installer.GetUserId(Constants::INVALID_USERID);
    EXPECT_EQ(res, Constants::INVALID_USERID);
}

/**
 * @tc.number: CheckAppLabel_0020
 * @tc.name: test CheckAppLabel
 * @tc.desc: 1.Test the CheckAppLabel
*/
HWTEST_F(BmsBundleInstallerTest, CheckAppLabel_0020, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.baseBundleInfo_->minCompatibleVersionCode = USERID;
    ErrCode res = installer.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: CheckAppLabel_0040
 * @tc.name: test CheckAppLabel
 * @tc.desc: 1.Test the CheckAppLabel
*/
HWTEST_F(BmsBundleInstallerTest, CheckAppLabel_0040, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.baseBundleInfo_->targetVersion = USERID;
    ErrCode res = installer.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: CheckAppLabel_0050
 * @tc.name: test CheckAppLabel
 * @tc.desc: 1.Test the CheckAppLabel
*/
HWTEST_F(BmsBundleInstallerTest, CheckAppLabel_0050, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.baseBundleInfo_->compatibleVersion = USERID;
    ErrCode res = installer.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: ExecuteAOT_0100
 * @tc.name: test CheckAppLabel
 * @tc.desc: 1.Test the CheckAppLabel
*/
HWTEST_F(BmsBundleInstallerTest, ExecuteAOT_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    AOTArgs aotArgs;
    std::vector<uint8_t> pendSignData;
    auto ret = impl.ExecuteAOT(aotArgs, pendSignData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: SetDirApl_0100
 * @tc.name: test CheckAppLabel
 * @tc.desc: 1.Test the CheckAppLabel
*/
HWTEST_F(BmsBundleInstallerTest, SetDirApl_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    bool isPreInstallApp = false;
    bool debug = false;
    auto ret = impl.SetDirApl("", BUNDLE_NAME, "", isPreInstallApp, debug);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.SetDirApl(BUNDLE_DATA_DIR, "", "", isPreInstallApp, debug);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.SetDirApl("", "", "", isPreInstallApp, debug);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = impl.SetDirApl(BUNDLE_DATA_DIR, BUNDLE_NAME, "", isPreInstallApp, debug);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_SET_SELINUX_LABEL_FAILED);
}

/**
 * @tc.number: GetHapFilesFromBundlePath_0100
 * @tc.name: test GetHapFilesFromBundlePath, reach the max hap number 128, stop to add more
 * @tc.desc: 1.test GetHapFilesFromBundlePath of BundleUtil
 */
HWTEST_F(BmsBundleInstallerTest, GetHapFilesFromBundlePath_0100, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    auto ret = bundleUtil.CreateTempDir(CURRENT_PATH);
    EXPECT_EQ(ret, CURRENT_PATH);
    std::vector<std::string> fileList;
    for (int i = 0; i < ServiceConstants::MAX_HAP_NUMBER + 1; i++) {
        std::string tmpFile = CURRENT_PATH + ServiceConstants::PATH_SEPARATOR + "test" + std::to_string(i) + ".hap";
        bool ret2 = SaveStringToFile(tmpFile, tmpFile);
        EXPECT_EQ(ret2, true);
        fileList.emplace_back(tmpFile);
    }
    bundleUtil.MakeFsConfig("testWrong.hap", 1, "/data/testWrong");
    bool res = bundleUtil.GetHapFilesFromBundlePath(CURRENT_PATH, fileList);
    EXPECT_EQ(res, false);
    bundleUtil.DeleteTempDirs(fileList);
}

/**
 * @tc.number: CreateInstallTempDir_1700
 * @tc.name: test CreateInstallTempDir
 * @tc.desc: 1.test type == DirType::SIG_FILE_DIR
 */
HWTEST_F(BmsBundleInstallerTest, CreateInstallTempDir_1700, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    const int32_t installId = 2022;
    std::string res = bundleUtil.CreateInstallTempDir(installId, DirType::SIG_FILE_DIR);
    EXPECT_NE(res, "");
    auto ret = bundleUtil.DeleteDir(res);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: CreateFileDescriptor_100
 * @tc.name: test CreateFileDescriptor
 * @tc.desc: 1.test the length of the bundlePath exceeds maximum limitation
 */
HWTEST_F(BmsBundleInstallerTest, CreateFileDescriptor_100, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    bundlePath.append(std::string(256, '/'));
    long long offset = 0;
    auto ret = bundleUtil.CreateFileDescriptor(bundlePath, offset);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.number: CreateFileDescriptor_200
 * @tc.name: test CreateFileDescriptor
 * @tc.desc: 1.test offset > 0
 */
HWTEST_F(BmsBundleInstallerTest, CreateFileDescriptor_200, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    BundleUtil bundleUtil;
    long long offset = 1;
    auto ret = bundleUtil.CreateFileDescriptor(bundlePath, offset);
    EXPECT_NE(ret, -1);
}

/**
 * @tc.number: CreateFileDescriptorForReadOnly_100
 * @tc.name: test CreateFileDescriptorForReadOnly
 * @tc.desc: 1.file is not real path
 */
HWTEST_F(BmsBundleInstallerTest, CreateFileDescriptorForReadOnly_100, Function | SmallTest | Level0)
{
    std::string bundlePath = "/testWrong/testWrong.hap";
    BundleUtil bundleUtil;
    long long offset = 1;
    auto ret = bundleUtil.CreateFileDescriptorForReadOnly(bundlePath, offset);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.number: CreateFileDescriptorForReadOnly_200
 * @tc.name: test CreateFileDescriptorForReadOnly
 * @tc.desc: 1.test offset > 0
 */
HWTEST_F(BmsBundleInstallerTest, CreateFileDescriptorForReadOnly_200, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    BundleUtil bundleUtil;
    long long offset = 1;
    auto ret = bundleUtil.CreateFileDescriptorForReadOnly(bundlePath, offset);
    EXPECT_NE(ret, -1);
}

/**
 * @tc.number: CreateDir_DeleteDir_100
 * @tc.name: test CreateDir and DeleteDir
 * @tc.desc: 1.file exist
 */
HWTEST_F(BmsBundleInstallerTest, CreateDir_DeleteDir_100, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    auto ret = bundleUtil.CreateDir(TEST_CREATE_FILE_PATH);
    EXPECT_EQ(ret, true);
    auto ret2 = bundleUtil.CreateDir(TEST_CREATE_FILE_PATH);
    EXPECT_EQ(ret2, true);
    auto ret3 = bundleUtil.DeleteDir(TEST_CREATE_FILE_PATH);
    EXPECT_EQ(ret3, true);
}

/**
 * @tc.number: CopyFileToSecurityDir_100
 * @tc.name: test CopyFileToSecurityDir
 * @tc.desc: 1.CopyFileToSecurityDir
 */
HWTEST_F(BmsBundleInstallerTest, CopyFileToSecurityDir_100, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    std::vector<std::string> toDeletePaths;
    auto ret = bundleUtil.CopyFileToSecurityDir("", DirType::STREAM_INSTALL_DIR, toDeletePaths);
    EXPECT_EQ(ret, "");
    EXPECT_EQ(toDeletePaths.size(), 0);
}

/**
 * @tc.number: CopyFileToSecurityDir_200
 * @tc.name: test CopyFileToSecurityDir
 * @tc.desc: 1.CopyFileToSecurityDir
 */
HWTEST_F(BmsBundleInstallerTest, CopyFileToSecurityDir_200, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    std::vector<std::string> toDeletePaths;
    bool res1 = bundleUtil.CreateDir(TEST_CREATE_DIR_PATH);
    EXPECT_TRUE(res1);
    bool res2 = SaveStringToFile(TEST_CREATE_FILE_PATH, TEST_CREATE_FILE_PATH);
    EXPECT_TRUE(res2);
    bundleUtil.CopyFileToSecurityDir(TEST_CREATE_FILE_PATH, DirType::SIG_FILE_DIR, toDeletePaths);
    bool res3 = bundleUtil.DeleteDir(TEST_CREATE_DIR_PATH);
    EXPECT_TRUE(res3);
    ASSERT_GT(toDeletePaths.size(), 0);
    bundleUtil.DeleteTempDirs(toDeletePaths);
}

/**
 * @tc.number: CopyFileToSecurityDir_300
 * @tc.name: test CopyFileToSecurityDir
 * @tc.desc: 1.CopyFileToSecurityDir
 */
HWTEST_F(BmsBundleInstallerTest, CopyFileToSecurityDir_300, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    std::vector<std::string> toDeletePaths;
    std::string sourcePath = TEST_CREATE_DIR_PATH + ServiceConstants::PATH_SEPARATOR
        + ServiceConstants::SIGNATURE_FILE_PATH;
    auto ret = bundleUtil.CopyFileToSecurityDir(sourcePath, DirType::SIG_FILE_DIR, toDeletePaths);
    EXPECT_EQ(ret, "");
    EXPECT_EQ(toDeletePaths.size(), 0);
}

/**
 * @tc.number: CopyFileToSecurityDir_400
 * @tc.name: test CopyFileToSecurityDir
 * @tc.desc: 1.CopyFileToSecurityDir
 */
HWTEST_F(BmsBundleInstallerTest, CopyFileToSecurityDir_400, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    std::vector<std::string> toDeletePaths;
    std::string sourcePath = TEST_CREATE_DIR_PATH + ServiceConstants::PATH_SEPARATOR +
        ServiceConstants::SIGNATURE_FILE_PATH + ServiceConstants::PATH_SEPARATOR;
    auto ret = bundleUtil.CopyFileToSecurityDir(sourcePath, DirType::SIG_FILE_DIR, toDeletePaths);
    EXPECT_EQ(ret, "");
    EXPECT_EQ(toDeletePaths.size(), 0);
}

/**
 * @tc.number: CopyFileToSecurityDir_500
 * @tc.name: test CopyFileToSecurityDir
 * @tc.desc: 1.CopyFileToSecurityDir
 */
HWTEST_F(BmsBundleInstallerTest, CopyFileToSecurityDir_500, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    std::vector<std::string> toDeletePaths;
    std::string sourcePath = TEST_CREATE_DIR_PATH + ServiceConstants::PATH_SEPARATOR +
        ServiceConstants::SIGNATURE_FILE_PATH + ServiceConstants::PATH_SEPARATOR;
    sourcePath.append("test");
    auto ret1 = bundleUtil.CopyFileToSecurityDir(sourcePath, DirType::SIG_FILE_DIR, toDeletePaths);
    EXPECT_EQ(ret1, "");
    EXPECT_EQ(toDeletePaths.size(), 0);
    sourcePath.append(ServiceConstants::PATH_SEPARATOR);
    auto ret2 = bundleUtil.CopyFileToSecurityDir(sourcePath, DirType::SIG_FILE_DIR, toDeletePaths);
    EXPECT_EQ(ret2, "");
    EXPECT_EQ(toDeletePaths.size(), 0);
}

/**
 * @tc.number: CopyFileToSecurityDir_600
 * @tc.name: test CopyFileToSecurityDir
 * @tc.desc: 1.CopyFileToSecurityDir
 */
HWTEST_F(BmsBundleInstallerTest, CopyFileToSecurityDir_600, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    std::vector<std::string> toDeletePaths;
    std::string sourcePath = TEST_CREATE_DIR_PATH + ServiceConstants::PATH_SEPARATOR +
        ServiceConstants::SIGNATURE_FILE_PATH + ServiceConstants::PATH_SEPARATOR + "test" +
        ServiceConstants::PATH_SEPARATOR + "testSourcePath";
    bool ret1 = bundleUtil.CreateDir(sourcePath);
    EXPECT_TRUE(ret1);
    std::string sourceFile = sourcePath.append(ServiceConstants::PATH_SEPARATOR).append("testSourceFile.hap");
    bool ret2 = SaveStringToFile(sourceFile, sourceFile);
    EXPECT_TRUE(ret2);
    bundleUtil.CopyFileToSecurityDir(sourcePath, DirType::SIG_FILE_DIR, toDeletePaths);
    bool ret3 = bundleUtil.DeleteDir(sourcePath);
    EXPECT_TRUE(ret3);
    ASSERT_GT(toDeletePaths.size(), 0);
    bundleUtil.DeleteTempDirs(toDeletePaths);
}

/**
 * @tc.number: CheckDependency_0010
 * @tc.name: test CheckDependency
 * @tc.desc: 1.CheckDependency
 */
HWTEST_F(BmsBundleInstallerTest, CheckDependency_0010, Function | SmallTest | Level0)
{
    InstallParam installParam;
    auto appType = Constants::AppType::THIRD_PARTY_APP;
    SharedBundleInstaller bundleInstaller(installParam, appType);

    Dependency dependency;
    dependency.bundleName = BUNDLE_NAME;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.dependencies.push_back(dependency);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.innerModuleInfos_.insert(std::pair<std::string, InnerModuleInfo>(BUNDLE_NAME, innerModuleInfo));
    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    auto res = bundleInstaller.CheckDependency(innerBundleInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: FindDependencyInInstalledBundles_0010
 * @tc.name: test FindDependencyInInstalledBundles
 * @tc.desc: 1.FindDependencyInInstalledBundles
 */
HWTEST_F(BmsBundleInstallerTest, FindDependencyInInstalledBundles_0010, Function | SmallTest | Level0)
{
    InstallParam installParam;
    auto appType = Constants::AppType::THIRD_PARTY_APP;
    SharedBundleInstaller bundleInstaller(installParam, appType);

    Dependency dependency;
    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    auto res = bundleInstaller.FindDependencyInInstalledBundles(dependency);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetCallingEventInfo_0010
 * @tc.name: test GetCallingEventInfo
 * @tc.desc: 1.GetCallingEventInfo
 */
HWTEST_F(BmsBundleInstallerTest, GetCallingEventInfo_0010, Function | SmallTest | Level0)
{
    InstallParam installParam;
    auto appType = Constants::AppType::THIRD_PARTY_APP;
    SharedBundleInstaller bundleInstaller(installParam, appType);

    EventInfo eventInfo;
    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    bundleInstaller.GetCallingEventInfo(eventInfo);
    EXPECT_EQ(eventInfo.callingBundleName, EMPTY_STRING);
}

/**
 * @tc.number: baseBundleInstaller_0100
 * @tc.name: test CheckAppIdentifier
 * @tc.desc: 1.Test the CheckAppIdentifier
*/
HWTEST_F(BmsBundleInstallerTest, CheckAppIdentifier_0100, Function | SmallTest | Level0)
{
    BundleInfo oldBundleInfo;
    oldBundleInfo.signatureInfo.appIdentifier = "appIdentifier";
    InnerBundleInfo oldInfo;
    oldInfo.SetBaseBundleInfo(oldBundleInfo);

    BundleInfo newBundleInfo;
    newBundleInfo.signatureInfo.appIdentifier = "appIdentifier";
    InnerBundleInfo newInfo;
    newInfo.SetBaseBundleInfo(newBundleInfo);

    BaseBundleInstaller installer;
    bool res = installer.CheckAppIdentifier(newInfo, oldInfo);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: baseBundleInstaller_0200
 * @tc.name: test CheckAppIdentifier
 * @tc.desc: 1.Test the CheckAppIdentifier
*/
HWTEST_F(BmsBundleInstallerTest, CheckAppIdentifier_0200, Function | SmallTest | Level0)
{
    BundleInfo oldBundleInfo;
    oldBundleInfo.signatureInfo.appIdentifier = "oldappIdentifier";
    InnerBundleInfo oldInfo;
    oldInfo.SetBaseBundleInfo(oldBundleInfo);
    oldInfo.SetProvisionId("9AED2A79925ECA050CD2BB9D2A7F694E49E5E135D28EBDCE53836DE76B5080ED");

    BundleInfo newBundleInfo;
    newBundleInfo.signatureInfo.appIdentifier = "newappIdentifier";
    InnerBundleInfo newInfo;
    newInfo.SetBaseBundleInfo(newBundleInfo);
    newInfo.SetProvisionId("9AED2A79925ECA050CD2BB9D2A7F694E49E5E135D28EBDCE53836DE76B5080EDXXXX");

    BaseBundleInstaller installer;
    bool res = installer.CheckAppIdentifier(newInfo, oldInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: baseBundleInstaller_0300
 * @tc.name: test CheckAppIdentifier
 * @tc.desc: 1.Test the CheckAppIdentifier
*/
HWTEST_F(BmsBundleInstallerTest, CheckAppIdentifier_0300, Function | SmallTest | Level0)
{
    BundleInfo oldBundleInfo;
    oldBundleInfo.name = "com.example.baseApplication";
    oldBundleInfo.versionCode = 1000000;
    InnerBundleInfo oldInfo;
    oldInfo.SetBaseBundleInfo(oldBundleInfo);
    oldInfo.SetProvisionId("9AED2A79925ECA050CD2BB9D2A7F694E49E5E135D28EBDCE53836DE76B5080ED");

    BundleInfo newBundleInfo;
    newBundleInfo.signatureInfo.appIdentifier = "newappIdentifier";
    newBundleInfo.versionCode = 2000000;
    newBundleInfo.name = "com.example.baseApplication";
    InnerBundleInfo newInfo;
    newInfo.SetBaseBundleInfo(newBundleInfo);
    newInfo.SetProvisionId("9AED2A79925ECA050CD2BB9D2A7F694E49E5E135D28EBDCE53836DE76B5080ED");

    BaseBundleInstaller installer;
    bool res = installer.CheckAppIdentifier(newInfo, oldInfo);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: CheckAppIdentifier_0400
 * @tc.name: test CheckAppIdentifier
 * @tc.desc: 1.Test the CheckAppIdentifier
*/
HWTEST_F(BmsBundleInstallerTest, CheckAppIdentifier_0400, Function | SmallTest | Level0)
{
    BundleInfo oldBundleInfo;
    oldBundleInfo.signatureInfo.appIdentifier = "oldappIdentifier";
    oldBundleInfo.name = "com.example.baseApplication";
    InnerBundleInfo oldInfo;
    oldInfo.SetBaseBundleInfo(oldBundleInfo);
    oldInfo.SetProvisionId("9AED2A79925ECA050CD2BB9D2A7F694E49E5E135D28EBDCE53836DE76B5080ED");

    BundleInfo newBundleInfo;
    newBundleInfo.name = "com.example.baseApplication";
    InnerBundleInfo newInfo;
    newInfo.SetBaseBundleInfo(newBundleInfo);
    newInfo.SetProvisionId("E64B13B84E6D2167F73B46530C6E02E323DA43C9C2DA251D7C64D20E091B936F");

    BaseBundleInstaller installer;
    bool res = installer.CheckAppIdentifier(newInfo, oldInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: CheckAppIdentifier_0500
 * @tc.name: test CheckAppIdentifier
 * @tc.desc: 1.Test the CheckAppIdentifier
*/
HWTEST_F(BmsBundleInstallerTest, CheckAppIdentifier_0500, Function | SmallTest | Level0)
{
    BundleInfo oldBundleInfo;
    oldBundleInfo.name = "com.example.baseApplication";
    InnerBundleInfo oldInfo;
    oldInfo.SetBaseBundleInfo(oldBundleInfo);
    oldInfo.SetProvisionId("9AED2A79925ECA050CD2BB9D2A7F694E49E5E135D28EBDCE53836DE76B5080ED");

    BundleInfo newBundleInfo;
    newBundleInfo.name = "com.example.baseApplication";
    InnerBundleInfo newInfo;
    newInfo.SetBaseBundleInfo(newBundleInfo);
    newInfo.SetProvisionId("9AED2A79925ECA050CD2BB9D2A7F694E49E5E135D28EBDCE53836DE76B5080ED");

    BaseBundleInstaller installer;
    bool res = installer.CheckAppIdentifier(newInfo, oldInfo);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: BeforeInstall_0100
 * @tc.name: test BeforeInstall
 * @tc.desc: 1.Test the BeforeInstall
*/
HWTEST_F(BmsBundleInstallerTest, BeforeInstall_0100, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    std::vector<std::string> hspPaths;
    hspPaths.push_back(TEST_CREATE_FILE_PATH);
    InstallParam installParam;
    installParam.isPreInstallApp = false;

    auto res = appServiceFwkInstaller.BeforeInstall(hspPaths, installParam);
    EXPECT_EQ(res, ERR_OK);

    installParam.isPreInstallApp = true;
    res = appServiceFwkInstaller.BeforeInstall(hspPaths, installParam);
    EXPECT_EQ(res, ERR_OK);

    ClearDataMgr();
    res = appServiceFwkInstaller.BeforeInstall(hspPaths, installParam);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR);
    ResetDataMgr();
}

/**
 * @tc.number: BeforeInstall_0200
 * @tc.name: test BeforeInstall
 * @tc.desc: 1.Test the BeforeInstall
*/
HWTEST_F(BmsBundleInstallerTest, BeforeInstall_0200, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    std::vector<std::string> hspPaths;
    InstallParam installParam;
    installParam.isPreInstallApp = false;

    ErrCode res = appServiceFwkInstaller.BeforeInstall(hspPaths, installParam);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: CheckFileType_0100
 * @tc.name: test CheckFileType
 * @tc.desc: 1.Test the CheckFileType
*/
HWTEST_F(BmsBundleInstallerTest, CheckFileType_0100, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    std::vector<std::string> hspPaths;
    auto res = appServiceFwkInstaller.CheckFileType(hspPaths);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);

    hspPaths.push_back(TEST_CREATE_FILE_PATH);
    res = appServiceFwkInstaller.CheckFileType(hspPaths);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_INVALID_HAP_NAME);
}

/**
 * @tc.number: CheckAppLabelInfo_0100
 * @tc.name: test CheckAppLabelInfo
 * @tc.desc: 1.Test the CheckAppLabelInfo
*/
HWTEST_F(BmsBundleInstallerTest, CheckAppLabelInfo_0100, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos.emplace(TEST_CREATE_FILE_PATH, innerBundleInfo);
    auto res = appServiceFwkInstaller.CheckAppLabelInfo(infos);
    EXPECT_EQ(res, ERR_APP_SERVICE_FWK_INSTALL_TYPE_FAILED);

    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP_SERVICE_FWK;
    res = appServiceFwkInstaller.CheckAppLabelInfo(infos);
    EXPECT_EQ(res, ERR_OK);

    innerBundleInfo.currentPackage_ = MODULE_NAME_TEST;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = MODULE_NAME_TEST;
    innerBundleInfo.innerModuleInfos_.emplace(MODULE_NAME_TEST, innerModuleInfo);
    res = appServiceFwkInstaller.CheckAppLabelInfo(infos);
    EXPECT_EQ(res, ERR_OK);

    innerModuleInfo.bundleType = BundleType::SHARED;
    res = appServiceFwkInstaller.CheckAppLabelInfo(infos);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: InstalldOperatorTest_7600
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling VerifyCodeSignature of InstalldHostImpl
 *           2. return false
 * @tc.require: issueI6PNQX
*/
HWTEST_F(BmsBundleInstallerTest, InstalldOperatorTest_7600, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = "";
    auto ret = hostImpl.VerifyCodeSignature(codeSignatureParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldOperatorTest_7700
 * @tc.name: test function of CheckEncryption
 * @tc.desc: 1. calling CheckEncryption
*/
HWTEST_F(BmsBundleInstallerTest, InstalldOperatorTest_7700, Function | SmallTest | Level0)
{
    InstalldHostImpl hostImpl;
    CheckEncryptionParam checkEncryptionParam;
    checkEncryptionParam.modulePath = "";
    bool isEncrypted = false;
    ErrCode res = hostImpl.CheckEncryption(checkEncryptionParam, isEncrypted);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldOperatorTest_7800
 * @tc.name: test RegisterBundleStatusCallback
 * @tc.desc: 1.system run normally
 *           2.RegisterBundleStatusCallback failed
 */
HWTEST_F(BmsBundleInstallerTest, InstalldOperatorTest_7800, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::vector<std::string> fileNames;
    auto ret = hostImpl.MoveFiles("", "");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = hostImpl.MoveFiles(TEST_STRING, "");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    ret = hostImpl.MoveFiles("", TEST_STRING);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldOperatorTest_7800
 * @tc.name: test RegisterBundleStatusCallback
 * @tc.desc: 1.system run normally
 *           2.RegisterBundleStatusCallback failed
 */
HWTEST_F(BmsBundleInstallerTest, InstalldOperatorTest_7900, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::unordered_multimap<std::string, std::string> dirMap;
    auto ret = hostImpl.ExtractDriverSoFiles("", dirMap);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldOperatorTest_8000
 * @tc.name: test CheckPathValid
 * @tc.desc: 1.system run normally
 *           2.CheckPathValid failed
 */
HWTEST_F(BmsBundleInstallerTest, InstalldOperatorTest_8000, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    auto ret = hostImpl.CheckPathValid("", "");
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: InstalldOperatorTest_8100
 * @tc.name: test CheckPathValid
 * @tc.desc: 1.system run normally
 *           2.CheckPathValid failed
 */
HWTEST_F(BmsBundleInstallerTest, InstalldOperatorTest_8100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::string path = "../";
    auto ret = hostImpl.CheckPathValid(path, "");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InstalldOperatorTest_8200
 * @tc.name: test CheckPathValid
 * @tc.desc: 1.system run normally
 *           2.CheckPathValid failed
 */
HWTEST_F(BmsBundleInstallerTest, InstalldOperatorTest_8200, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::string path = "./";
    std::string prefix = "npos";
    auto ret = hostImpl.CheckPathValid(path, prefix);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InstalldOperatorTest_8300
 * @tc.name: test CheckPathValid
 * @tc.desc: 1.system run normally
 *           2.CheckPathValid failed
 */
HWTEST_F(BmsBundleInstallerTest, InstalldOperatorTest_8300, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::string path = "./npos";
    std::string prefix = "npos";
    auto ret = hostImpl.CheckPathValid(path, prefix);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: DeleteOldNativeLibraryPath_0010
 * @tc.name: DeleteOldNativeLibraryPath
 * @tc.desc: test DeleteOldNativeLibraryPath
 */
HWTEST_F(BmsBundleInstallerTest, DeleteOldNativeLibraryPath_0010, TestSize.Level1)
{
    bool ret = OHOS::ForceCreateDirectory(BUNDLE_LIBRARY_PATH_DIR);
    EXPECT_TRUE(ret);
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    installer.DeleteOldNativeLibraryPath();
    auto exist = access(BUNDLE_LIBRARY_PATH_DIR.c_str(), F_OK);
    EXPECT_NE(exist, 0);
}

/**
 * @tc.number: DeleteOldNativeLibraryPath_0020
 * @tc.name: NeedDeleteOldNativeLib
 * @tc.desc: test NeedDeleteOldNativeLib
 */
HWTEST_F(BmsBundleInstallerTest, DeleteOldNativeLibraryPath_0020, TestSize.Level1)
{
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;

    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    InnerModuleInfo innerModuleInfo;
    oldInfo.InsertInnerModuleInfo("module1", innerModuleInfo);
    newInfo.InsertInnerModuleInfo("module2", innerModuleInfo);
    // 1. NewInfos is null, return false
    std::unordered_map<std::string, InnerBundleInfo> newInfo1;
    bool ret = installer.NeedDeleteOldNativeLib(newInfo1, oldInfo);
    EXPECT_FALSE(ret);

    // 2. No old app, return false
    newInfo1.insert(std::pair<std::string, InnerBundleInfo>(BUNDLE_NAME_TEST, newInfo));
    ret = installer.NeedDeleteOldNativeLib(newInfo1, oldInfo);
    EXPECT_FALSE(ret);

    // 3. Old app no library, return false
    installer.isAppExist_ = true;
    ret = installer.NeedDeleteOldNativeLib(newInfo1, oldInfo);
    EXPECT_FALSE(ret);

    // 4. Not all module update, return false
    oldInfo.SetNativeLibraryPath("libs/arm");
    ret = installer.NeedDeleteOldNativeLib(newInfo1, oldInfo);
    EXPECT_FALSE(ret);

    // 5. Higher versionCode, return true
    BundleInfo oldBundleInfo;
    oldBundleInfo.versionCode = 900;
    oldInfo.UpdateBaseBundleInfo(oldBundleInfo, true);
    BundleInfo newBundleInfo;
    newBundleInfo.versionCode = 1000;
    newInfo.UpdateBaseBundleInfo(newBundleInfo, true);
    std::unordered_map<std::string, InnerBundleInfo> newInfo2;
    newInfo2.insert(std::pair<std::string, InnerBundleInfo>(BUNDLE_NAME_TEST, newInfo));
    ret = installer.NeedDeleteOldNativeLib(newInfo2, oldInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: DeleteOldNativeLibraryPath_0030
 * @tc.name: NeedDeleteOldNativeLib
 * @tc.desc: test NeedDeleteOldNativeLib multihap
 */
HWTEST_F(BmsBundleInstallerTest, DeleteOldNativeLibraryPath_0030, TestSize.Level1)
{
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    installer.isAppExist_ = true;

    InnerModuleInfo innerModuleInfo;

    InnerBundleInfo oldInfo;
    oldInfo.SetNativeLibraryPath("libs/arm");
    oldInfo.InsertInnerModuleInfo("module1", innerModuleInfo);
    oldInfo.InsertInnerModuleInfo("module2", innerModuleInfo);

    InnerBundleInfo newInfo1;
    newInfo1.InsertInnerModuleInfo("module1", innerModuleInfo);
    InnerBundleInfo newInfo2;
    newInfo2.InsertInnerModuleInfo("module2", innerModuleInfo);
    InnerBundleInfo newInfo3;
    newInfo2.InsertInnerModuleInfo("module3", innerModuleInfo);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.insert(std::pair<std::string, InnerBundleInfo>("hap1", newInfo1));
    bool ret = installer.NeedDeleteOldNativeLib(newInfos, oldInfo);
    EXPECT_FALSE(ret);

    newInfos.insert(std::pair<std::string, InnerBundleInfo>("hap3", newInfo3));
    ret = installer.NeedDeleteOldNativeLib(newInfos, oldInfo);
    EXPECT_FALSE(ret);

    newInfos.insert(std::pair<std::string, InnerBundleInfo>("hap2", newInfo2));
    ret = installer.NeedDeleteOldNativeLib(newInfos, oldInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: DeleteOldNativeLibraryPath_0040
 * @tc.name: NeedDeleteOldNativeLib
 * @tc.desc: test NeedDeleteOldNativeLib multihap IsOnlyCreateBundleUser
 */
HWTEST_F(BmsBundleInstallerTest, DeleteOldNativeLibraryPath_0040, TestSize.Level1)
{
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    installer.isAppExist_ = true;

    InnerModuleInfo innerModuleInfo;
    InnerBundleInfo oldInfo;
    oldInfo.SetNativeLibraryPath("arm");
    oldInfo.InsertInnerModuleInfo("module1", innerModuleInfo);
    oldInfo.InsertInnerModuleInfo("module2", innerModuleInfo);

    InnerBundleInfo newInfo1;
    newInfo1.InsertInnerModuleInfo("module1", innerModuleInfo);
    InnerBundleInfo newInfo2;
    newInfo2.InsertInnerModuleInfo("module2", innerModuleInfo);
    InnerBundleInfo newInfo3;
    newInfo3.SetOnlyCreateBundleUser(true);
    newInfo2.InsertInnerModuleInfo("module3", innerModuleInfo);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.insert(std::pair<std::string, InnerBundleInfo>("hap1", newInfo1));
    newInfos.insert(std::pair<std::string, InnerBundleInfo>("hap2", newInfo2));
    newInfos.insert(std::pair<std::string, InnerBundleInfo>("hap3", newInfo3));
    bool ret = installer.NeedDeleteOldNativeLib(newInfos, oldInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: DeleteOldNativeLibraryPath_0050
 * @tc.name: NeedDeleteOldNativeLib
 * @tc.desc: test NeedDeleteOldNativeLib multihap otaInstall
 */
HWTEST_F(BmsBundleInstallerTest, DeleteOldNativeLibraryPath_0050, TestSize.Level1)
{
    BaseBundleInstaller installer;
    installer.bundleName_ = BUNDLE_NAME;
    installer.isAppExist_ = true;

    InnerModuleInfo innerModuleInfo;

    InnerBundleInfo oldInfo;
    oldInfo.SetNativeLibraryPath("libs/arm");
    oldInfo.InsertInnerModuleInfo("module1", innerModuleInfo);
    oldInfo.InsertInnerModuleInfo("module2", innerModuleInfo);

    InnerBundleInfo newInfo1;
    newInfo1.InsertInnerModuleInfo("module1", innerModuleInfo);
    InnerBundleInfo newInfo2;
    newInfo2.InsertInnerModuleInfo("module2", innerModuleInfo);
    InnerBundleInfo newInfo3;
    newInfo2.InsertInnerModuleInfo("module3", innerModuleInfo);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.insert(std::pair<std::string, InnerBundleInfo>("hap1", newInfo1));
    bool ret = installer.NeedDeleteOldNativeLib(newInfos, oldInfo);
    EXPECT_FALSE(ret);

    newInfos.insert(std::pair<std::string, InnerBundleInfo>("hap3", newInfo3));
    ret = installer.NeedDeleteOldNativeLib(newInfos, oldInfo);
    EXPECT_FALSE(ret);

    installer.otaInstall_ = true;
    ret = installer.NeedDeleteOldNativeLib(newInfos, oldInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: RemoveOldHapIfOTA_0010
 * @tc.name: RemoveOldHapIfOTANotOTA
 * @tc.desc: test RemoveOldHapIfOTA not OTA
 */
HWTEST_F(BmsBundleInstallerTest, RemoveOldHapIfOTA_0010, Function | SmallTest | Level1)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + SYSTEMFIEID_BUNDLE;
    ErrCode installResult = InstallThirdPartyBundle(bundleFile);
    EXPECT_EQ(installResult, ERR_OK);

    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = MODULE_NAME;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.try_emplace(bundleFile, newInfo);

    InnerBundleInfo oldInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.hapPath = SYSTEMFIEID_HAP_PATH;
    oldInfo.innerModuleInfos_.insert(pair<std::string, InnerModuleInfo>(MODULE_NAME, innerModuleInfo));

    InstallParam installParam;
    installParam.isOTA = false;
    installParam.copyHapToInstallPath = true;
    BaseBundleInstaller installer;
    installer.RemoveOldHapIfOTA(installParam, newInfos, oldInfo);
    auto exist = access(SYSTEMFIEID_HAP_PATH.c_str(), F_OK);
    EXPECT_EQ(exist, 0);
    UnInstallBundle(SYSTEMFIEID_NAME);
}

/**
 * @tc.number: RemoveOldHapIfOTA_0020
 * @tc.name: RemoveOldHapIfOTANoHapInData
 * @tc.desc: test RemoveOldHapIfOTA no hap in data
 */
HWTEST_F(BmsBundleInstallerTest, RemoveOldHapIfOTA_0020, Function | SmallTest | Level1)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + SYSTEMFIEID_BUNDLE;
    ErrCode installResult = InstallThirdPartyBundle(bundleFile);
    EXPECT_EQ(installResult, ERR_OK);

    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = MODULE_NAME;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.try_emplace(bundleFile, newInfo);

    InnerBundleInfo oldInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.hapPath = "/system/app/module01/module01.hap";
    oldInfo.innerModuleInfos_.insert(pair<std::string, InnerModuleInfo>(MODULE_NAME, innerModuleInfo));

    InstallParam installParam;
    installParam.isOTA = true;
    installParam.copyHapToInstallPath = false;
    BaseBundleInstaller installer;
    installer.RemoveOldHapIfOTA(installParam, newInfos, oldInfo);
    auto exist = access(SYSTEMFIEID_HAP_PATH.c_str(), F_OK);
    EXPECT_EQ(exist, 0);
    UnInstallBundle(SYSTEMFIEID_NAME);
}

/**
 * @tc.number: RemoveOldHapIfOTA_0030
 * @tc.name: RemoveOldHapIfOTASuccess
 * @tc.desc: test RemoveOldHapIfOTA success
 */
HWTEST_F(BmsBundleInstallerTest, RemoveOldHapIfOTA_0030, Function | SmallTest | Level1)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + SYSTEMFIEID_BUNDLE;
    ErrCode installResult = InstallThirdPartyBundle(bundleFile);
    EXPECT_EQ(installResult, ERR_OK);

    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = MODULE_NAME;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.try_emplace(bundleFile, newInfo);

    InnerBundleInfo oldInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.hapPath = SYSTEMFIEID_HAP_PATH;
    oldInfo.innerModuleInfos_.insert(pair<std::string, InnerModuleInfo>(MODULE_NAME, innerModuleInfo));

    InstallParam installParam;
    installParam.isOTA = true;
    installParam.copyHapToInstallPath = false;
    BaseBundleInstaller installer;
    installer.RemoveOldHapIfOTA(installParam, newInfos, oldInfo);
    auto exist = access(SYSTEMFIEID_HAP_PATH.c_str(), F_OK);
    EXPECT_EQ(exist, -1);
    UnInstallBundle(SYSTEMFIEID_NAME);
}

/**
 * @tc.number: RemoveOldHapIfOTA_0040
 * @tc.name: RemoveOldHapIfOTAQuickFix
 * @tc.desc: test RemoveOldHapIfOTA when quickfix
 */
HWTEST_F(BmsBundleInstallerTest, RemoveOldHapIfOTA_0040, Function | SmallTest | Level1)
{
    std::string bundleFile = RESOURCE_ROOT_PATH + SYSTEMFIEID_BUNDLE;
    ErrCode installResult = InstallThirdPartyBundle(bundleFile);
    EXPECT_EQ(installResult, ERR_OK);

    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = MODULE_NAME;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.try_emplace(bundleFile, newInfo);

    InnerBundleInfo oldInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.hapPath = SYSTEMFIEID_HAP_PATH;
    oldInfo.innerModuleInfos_.insert(pair<std::string, InnerModuleInfo>(MODULE_NAME, innerModuleInfo));

    InstallParam installParam;
    installParam.isOTA = true;
    installParam.copyHapToInstallPath = true;
    BaseBundleInstaller installer;
    installer.RemoveOldHapIfOTA(installParam, newInfos, oldInfo);
    auto exist = access(SYSTEMFIEID_HAP_PATH.c_str(), F_OK);
    EXPECT_EQ(exist, 0);
    UnInstallBundle(SYSTEMFIEID_NAME);
}

/**
 * @tc.number: PrepareSkillUri_0010
 * @tc.name: PrepareSkillUriNotDomainVerify
 * @tc.desc: test PrepareSkillUri without domainVerify
 */
HWTEST_F(BmsBundleInstallerTest, PrepareSkillUri_0010, Function | SmallTest | Level1)
{
    std::vector<Skill> skills;
    Skill skill;
    SkillUri skillUri;
    skillUri.scheme = "https";
    skillUri.host = "www.test.com";
    skill.uris.push_back(skillUri);
    skill.domainVerify = false;
    skills.push_back(skill);
    std::vector<AppDomainVerify::SkillUri> skillUris;

    BaseBundleInstaller installer;
    installer.PrepareSkillUri(skills, skillUris);
    EXPECT_EQ(skillUris.size(), 0);
}

/**
 * @tc.number: PrepareSkillUri_0020
 * @tc.name: PrepareSkillUriNotHttps
 * @tc.desc: test PrepareSkillUri without https
 */
HWTEST_F(BmsBundleInstallerTest, PrepareSkillUri_0020, Function | SmallTest | Level1)
{
    std::vector<Skill> skills;
    Skill skill;
    SkillUri skillUri;
    skillUri.scheme = "http";
    skillUri.host = "www.test.com";
    skill.uris.push_back(skillUri);
    skill.domainVerify = true;
    skills.push_back(skill);
    std::vector<AppDomainVerify::SkillUri> skillUris;

    BaseBundleInstaller installer;
    installer.PrepareSkillUri(skills, skillUris);
    EXPECT_EQ(skillUris.size(), 0);
}

/**
 * @tc.number: PrepareSkillUri_0030
 * @tc.name: PrepareSkillUriSuccess
 * @tc.desc: test PrepareSkillUri success
 */
HWTEST_F(BmsBundleInstallerTest, PrepareSkillUri_0030, Function | SmallTest | Level1)
{
    std::vector<Skill> skills;
    Skill skill;
    SkillUri skillUri;
    skillUri.scheme = "https";
    skillUri.host = "www.test.com";
    skill.uris.push_back(skillUri);
    skill.domainVerify = true;
    skills.push_back(skill);
    std::vector<AppDomainVerify::SkillUri> skillUris;

    BaseBundleInstaller installer;
    installer.PrepareSkillUri(skills, skillUris);
    EXPECT_EQ(skillUris.size(), 1);
}

/**
 * @tc.number: UpdateBundleForSelf_0100
 * @tc.name: test Install
 * @tc.desc: test UpdateBundleForSelf of BundleInstallerHost
*/
HWTEST_F(BmsBundleInstallerTest, UpdateBundleForSelf_0100, Function | SmallTest | Level0)
{
    BundleInstallerHost bundleInstallerHost;
    std::vector<std::string> bundleFilePaths;
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver;
    bool ret = bundleInstallerHost.UpdateBundleForSelf(bundleFilePaths, installParam, statusReceiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: ExtractEncryptedSoFiles_0100
 * @tc.name: test ExtractEncryptedSoFiles
 * @tc.desc: test ExtractEncryptedSoFiles of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, ExtractEncryptedSoFiles_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;
    std::string tmpSoPath = "";
    int32_t uid = -1;
    bool ret = installer.ExtractEncryptedSoFiles(info, tmpSoPath, uid);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: ExtractEncryptedSoFiles_0200
 * @tc.name: test ExtractEncryptedSoFiles
 * @tc.desc: test ExtractEncryptedSoFiles of BaseBundleInstaller with api13
 */
HWTEST_F(BmsBundleInstallerTest, ExtractEncryptedSoFiles_0200, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.compressNativeLibs = true;
    innerBundleInfo.innerModuleInfos_["aaa"] = moduleInfo;
    innerBundleInfo.baseBundleInfo_->targetVersion = TARGET_VERSION_FOURTEEN;
    std::string tmpSoPath = "";
    int32_t uid = -1;
    bool ret = installer.ExtractEncryptedSoFiles(innerBundleInfo, tmpSoPath, uid);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: CopyPgoFile_0100
 * @tc.name: test CopyPgoFile
 * @tc.desc: test CopyPgoFile of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, CopyPgoFile_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    auto ret = installer.CopyPgoFile("", "", "", USERID);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: UninstallBundleFromBmsExtension_0100
 * @tc.name: test UninstallBundleFromBmsExtension
 * @tc.desc: test UninstallBundleFromBmsExtension of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, UninstallBundleFromBmsExtension_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    auto ret = installer.UninstallBundleFromBmsExtension("");
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: UninstallBundleFromBmsExtension_0200
 * @tc.name: test UninstallBundleFromBmsExtension_0100
 * @tc.desc: test UninstallBundleFromBmsExtension_0100 of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, UninstallBundleFromBmsExtension_0200, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BaseBundleInstaller installer;
    auto ret = installer.UninstallBundleFromBmsExtension(BUNDLE_BACKUP_NAME);
    EXPECT_NE(ret, ERR_OK);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: CheckBundleInBmsExtension_0100
 * @tc.name: test CheckBundleInBmsExtension
 * @tc.desc: test CheckBundleInBmsExtension of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, CheckBundleInBmsExtension, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BaseBundleInstaller installer;
    auto ret = installer.CheckBundleInBmsExtension(BUNDLE_BACKUP_NAME, USERID);
    EXPECT_EQ(ret, ERR_OK);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: UpdateHapToken_0100
 * @tc.name: test UpdateHapToken
 * @tc.desc: test UpdateHapToken of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, UpdateHapToken_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo newInfo;
    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo info;
    info.accessTokenId = 0;
    innerBundleUserInfos.try_emplace(BUNDLE_NAME, info);
    info.accessTokenId = -1;
    innerBundleUserInfos.try_emplace(BUNDLE_NAME, info);
    newInfo.innerBundleUserInfos_ = innerBundleUserInfos;
    BaseBundleInstaller installer;
    installer.InitDataMgr();
    auto ret = installer.UpdateHapToken(true, newInfo);
    EXPECT_NE(ret, ERR_OK);

    ret = installer.UpdateHapToken(false, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AllowSingletonChange_0100
 * @tc.name: test AllowSingletonChange
 * @tc.desc: test AllowSingletonChange of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, AllowSingletonChange_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string bundleName = "com.acts.example";
    bool ret = installer.AllowSingletonChange(bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: ExtractHnpFileDir_0100
 * @tc.name: test ExtractHnpFileDir
 * @tc.desc: test ExtractHnpFileDir of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, ExtractHnpFileDir_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::string cpuAbi;
    std::string hnpPackageInfoString;
    std::string modulePath;
    ErrCode ret = installer.ExtractHnpFileDir(cpuAbi, hnpPackageInfoString, modulePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NATIVE_HNP_EXTRACT_FAILED);
}

/**
 * @tc.number: AddBundleStatus_0100
 * @tc.name: test AddBundleStatus
 * @tc.desc: test AddBundleStatus of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, AddBundleStatus_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    NotifyBundleEvents installRes;
    installRes.abilityName = "testAbilityName";
    installer.AddBundleStatus(installRes);
    EXPECT_NE(installer.bundleEvents_.end().base()->abilityName.c_str(),
        installRes.abilityName.c_str());
}

/**
 * @tc.number: CreateBundleDataDirWithVector_0100
 * @tc.name: test CreateBundleDataDirWithVector
 * @tc.desc: test CreateBundleDataDirWithVector of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, CreateBundleDataDirWithVector_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::vector<CreateDirParam> createDirParams;
    auto ret = hostImpl.CreateBundleDataDirWithVector(createDirParams);
    EXPECT_EQ(ret, ERR_OK);

    CreateDirParam createDirParam;
    createDirParams.push_back(createDirParam);
    ret = hostImpl.CreateBundleDataDirWithVector(createDirParams);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetAllBundleStats_0100
 * @tc.name: test GetAllBundleStats
 * @tc.desc: test GetAllBundleStats of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, GetAllBundleStats_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::vector<int64_t> bundleStats = { 0 };
    std::vector<int32_t> uids;
    uids.push_back(EDM_UID);
    auto ret = hostImpl.GetAllBundleStats(EDM_UID, bundleStats, uids);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: RollbackHmpCommonInfo_0100
 * @tc.name: test RollbackHmpCommonInfo
 * @tc.desc: test RollbackHmpCommonInfo of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, RollbackHmpCommonInfo_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;

    InnerBundleInfo info;
    std::string dir;
    installer.CreateScreenLockProtectionExistDirs(info, dir);

    std::vector<std::string> extensionDataGroupIds;
    std::vector<std::string> bundleDataGroupIds;
    std::vector<std::string> validGroupIds;
    installer.GetValidDataGroupIds(extensionDataGroupIds, bundleDataGroupIds, validGroupIds);

    installer.CreateDataGroupDir(info);

    std::unordered_map<std::string, InnerBundleInfo> infos;
    installer.SetAppDistributionType(infos);

    EventInfo eventInfo;
    installer.GetInstallEventInfo(info, eventInfo);

    NotifyBundleEvents notifyBundleEvents;
    installer.AddNotifyBundleEvents(notifyBundleEvents);

    std::string bundleName;
    ErrCode ret = installer.RollbackHmpUserInfo(bundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_INVALID_NAME);

    ret = installer.RollbackHmpCommonInfo(bundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_INVALID_NAME);

    bundleName = "com.ohos.settings";
    ret = installer.RollbackHmpUserInfo(bundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_BUNDLE);

    ret = installer.RollbackHmpCommonInfo(bundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_BUNDLE);
}

/**
 * @tc.number: IsExistApFile_0100
 * @tc.name: test IsExistApFile
 * @tc.desc: test IsExistApFile of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, IsExistApFile_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    bool isExist = true;
    auto ret = hostImpl.IsExistApFile(TEST_STRING, isExist);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: Install_0001
 * @tc.name: test the start function of Install
*/
HWTEST_F(BmsBundleInstallerTest, Install_0001, Function | SmallTest | Level0)
{
    InstallParam installParam;
    auto appType = Constants::AppType::THIRD_PARTY_APP;
    SharedBundleInstaller bundleInstaller(installParam, appType);

    EventInfo eventTemplate;

    ErrCode ret = bundleInstaller.Install(eventTemplate);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckSystemFreeSizeAndClean_0100
 * @tc.name: test CheckSystemFreeSizeAndClean
 * @tc.desc: test CheckSystemFreeSizeAndClean of bundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, CheckSystemFreeSizeAndClean_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    installer.CheckSystemFreeSizeAndClean();
    bool ret = BundleUtil::CheckSystemFreeSize(BMS_SERVICE_PATH, FIVE_MB);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: SendBundleSystemEvent_0010
 * @tc.name: test SendBundleSystemEvent
 * @tc.desc: 1.SendBundleSystemEvent
 */
HWTEST_F(BmsBundleInstallerTest, SendBundleSystemEvent_0010, Function | SmallTest | Level0)
{
    InstallParam installParam;
    auto appType = Constants::AppType::THIRD_PARTY_APP;
    SharedBundleInstaller bundleInstaller(installParam, appType);
    EventInfo eventTemplate;
    ErrCode errCode = 0;
    string path = "test";
    bundleInstaller.innerInstallers_["test"] = std::make_shared<InnerSharedBundleInstaller>(path);
    bundleInstaller.SendBundleSystemEvent(eventTemplate, errCode);
    ASSERT_FALSE(bundleInstaller.innerInstallers_["test"]->isBundleExist_);
}

/**
 * @tc.number: CreateSharedBundleTempDir_0100
 * @tc.name: test CreateSharedBundleTempDir
 * @tc.desc: 1.test CreateSharedBundleTempDir of BundleUtil
 */
HWTEST_F(BmsBundleInstallerTest, CreateSharedBundleTempDir_0100, Function | SmallTest | Level0)
{
    BundleUtil bundleUtil;
    auto ret = bundleUtil.CreateSharedBundleTempDir(INSTALLER_ID, INDEX);
    EXPECT_FALSE(ret.empty());
}

/**
 * @tc.number: LoadExtensionNeedCreateSandbox_0100
 * @tc.name: test LoadExtensionNeedCreateSandbox
 * @tc.desc: test LoadExtensionNeedCreateSandbox of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, LoadExtensionNeedCreateSandbox_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    nlohmann::json object;
    std::vector<std::string> typeList;
    hostImpl.LoadNeedCreateSandbox(object, typeList);
    std::string extensionTypeName;
    bool ret = hostImpl.LoadExtensionNeedCreateSandbox(object, extensionTypeName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InnerRemoveAtomicServiceBundleDataDir_0100
 * @tc.name: test InnerRemoveAtomicServiceBundleDataDir
 * @tc.desc: test InnerRemoveAtomicServiceBundleDataDir of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, InnerRemoveAtomicServiceBundleDataDir_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::string bundleName = BUNDLE_NAME;
    int32_t userId = USERID;
    ErrCode ret = hostImpl.InnerRemoveAtomicServiceBundleDataDir(bundleName, userId);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ReadFileIntoJson_0100
 * @tc.name: test ReadFileIntoJson
 * @tc.desc: test ReadFileIntoJson of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, ReadFileIntoJson_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::string filePath;
    filePath.resize(PATH_MAX + 1);
    nlohmann::json jsonBuf;
    bool ret = hostImpl.ReadFileIntoJson(filePath, jsonBuf);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: VerifyCodeSignatureForNativeFiles_0100
 * @tc.name: test VerifyCodeSignatureForNativeFiles
 * @tc.desc: test VerifyCodeSignatureForNativeFiles of BundleInstallerManager
*/
HWTEST_F(BmsBundleInstallerTest, VerifyCodeSignatureForNativeFiles_0100, Function | SmallTest | Level1)
{
    AppServiceFwkInstaller appServiceFwkInstaller;

    std::string bundlePath;
    std::string cpuAbi;
    std::string targetSoPath;
    ErrCode ret = appServiceFwkInstaller.VerifyCodeSignatureForNativeFiles(bundlePath, cpuAbi, targetSoPath);

    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: GetFileStat_0100
 * @tc.name: test GetFileStat
 * @tc.desc: test GetFileStat of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, GetFileStat_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::string file;
    FileStat fileStat;
    ErrCode ret = hostImpl.GetFileStat(file, fileStat);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: ExtractDiffFiles_0100
 * @tc.name: test ExtractDiffFiles
 * @tc.desc: test ExtractDiffFiles of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, ExtractDiffFiles_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::string filePath = "test.path";
    std::string targetPath = "test.target.path";
    std::string cpuAbi;
    ErrCode  ret = hostImpl.ExtractDiffFiles(filePath, targetPath, cpuAbi);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_EXTRACT_DIFF_FILES_FAILED);
}

/**
 * @tc.number: SetEncryptionPolicy_0100
 * @tc.name: test SetEncryptionPolicy
 * @tc.desc: test SetEncryptionPolicy of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, SetEncryptionPolicy_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    int32_t uid = EDM_UID;
    std::string bundleName = "";
    int32_t userId = USERID;
    std::string keyId;
    ErrCode ret = hostImpl.SetEncryptionPolicy(uid, bundleName, userId, keyId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    bundleName = BUNDLE_NAME;
    ret = hostImpl.SetEncryptionPolicy(uid, bundleName, userId, keyId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_GENERATE_KEY_FAILED);
}

/**
 * @tc.number: DeleteEncryptionKeyId_0100
 * @tc.name: test DeleteEncryptionKeyId
 * @tc.desc: test DeleteEncryptionKeyId of InstalldHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, DeleteEncryptionKeyId_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::string bundleName = "";
    int32_t userId = USERID;
    ErrCode ret = hostImpl.DeleteEncryptionKeyId(bundleName, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    bundleName = BUNDLE_NAME;
    ret = hostImpl.DeleteEncryptionKeyId(bundleName, userId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_DELETE_KEY_FAILED);
}

/**
 * @tc.number: ExtractModule_0100
 * @tc.name: test ExtractModule
 * @tc.desc: 1.Test the ExtractModule
*/
HWTEST_F(BmsBundleInstallerTest, ExtractModule_0100, Function | SmallTest | Level0)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    InnerBundleInfo newInfo;
    std::string bundlePath;

    appServiceFwkInstaller.newInnerBundleInfo_.baseApplicationInfo_->bundleName = "com.acts.example";
    appServiceFwkInstaller.MergeBundleInfos(newInfo);

    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;

    appServiceFwkInstaller.GenerateOdid(infos, hapVerifyRes);

    Security::Verify::HapVerifyResult hapVerifyResult;
    Security::Verify::ProvisionInfo provisionInfo;
    hapVerifyResult.SetProvisionInfo(provisionInfo);
    hapVerifyRes.push_back(hapVerifyResult);

    appServiceFwkInstaller.GenerateOdid(infos, hapVerifyRes);

    ErrCode ret = appServiceFwkInstaller.ExtractModule(newInfo, bundlePath);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AddNotifyBundleEvents_0100
 * @tc.name: test AddNotifyBundleEvents
 * @tc.desc: test AddNotifyBundleEvents of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, AddNotifyBundleEvents_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    NotifyBundleEvents installRes;
    installer.AddNotifyBundleEvents(installRes);
    installRes.abilityName = "testAbilityName";
    installer.AddBundleStatus(installRes);
    bool ret = installer.NotifyAllBundleStatus();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: HmpBundleInstaller_0100
 * @tc.name: test InstallSystemHspInHmp
 * @tc.desc: 1.Test InstallSystemHspInHmp the HmpBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, HmpBundleInstaller_0100, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;
    ErrCode ret = installer.InstallSystemHspInHmp("/data");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: HmpBundleInstaller_0200
 * @tc.name: test InstallNormalAppInHmp
 * @tc.desc: 1.Test InstallNormalAppInHmp the HmpBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, HmpBundleInstaller_0200, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;
    ErrCode ret = installer.InstallNormalAppInHmp("/data");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: HmpBundleInstaller_0300
 * @tc.name: test GetRequiredUserIds
 * @tc.desc: 1.Test GetRequiredUserIds the HmpBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, HmpBundleInstaller_0300, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;
    std::set<int32_t> userIds;
    bool ret = installer.GetRequiredUserIds("/data", userIds);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetInstallEventInfo_0100
 * @tc.name: test GetInstallEventInfo
 * @tc.desc: test GetInstallEventInfo of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, GetInstallEventInfo_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo bundleInfo;
    EventInfo eventInfo;
    installer.GetInstallEventInfo(bundleInfo, eventInfo);
    EXPECT_EQ(eventInfo.hideDesktopIcon, bundleInfo.IsHideDesktopIcon());

    std::string appDistributionType = "hos_normal_type";
    bundleInfo.SetAppDistributionType(appDistributionType);
    installer.GetInstallEventInfo(bundleInfo, eventInfo);
    EXPECT_EQ(eventInfo.appDistributionType, appDistributionType);
}

/**
 * @tc.number: SetAppDistributionType_0100
 * @tc.name: test SetAppDistributionType
 * @tc.desc: test SetAppDistributionType of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, SetAppDistributionType_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    std::unordered_map<std::string, InnerBundleInfo> innerBundleInfos;
    installer.SetAppDistributionType(innerBundleInfos);

    ApplicationInfo applicationInfo;
    InnerBundleInfo info;
    info.SetBaseApplicationInfo(applicationInfo);
    std::string appDistributionType = "hos_normal_type";
    info.SetAppDistributionType(appDistributionType);
    innerBundleInfos.try_emplace("so", info);
    installer.SetAppDistributionType(innerBundleInfos);
    EXPECT_EQ(installer.appDistributionType_, appDistributionType);
}

/**
 * @tc.number: RemoveOldExtensionDirs_0100
 * @tc.name: test RemoveOldExtensionDirs
 * @tc.desc: test RemoveOldExtensionDirs of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, RemoveOldExtensionDirs_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    installer.removeExtensionDirs_.clear();
    installer.RemoveOldExtensionDirs();
    EXPECT_TRUE(installer.removeExtensionDirs_.empty());

    installer.createExtensionDirs_.clear();
    installer.RemoveCreatedExtensionDirsForException();
    EXPECT_TRUE(installer.createExtensionDirs_.empty());
}

/**
 * @tc.number: GetValidDataGroupIds_0100
 * @tc.name: test GetValidDataGroupIds
 * @tc.desc: test GetValidDataGroupIds of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, GetValidDataGroupIds_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    std::vector<std::string> extensionDataGroupIds;
    std::vector<std::string> bundleDataGroupIds;
    std::vector<std::string> validGroupIds;
    installer.GetValidDataGroupIds(extensionDataGroupIds, bundleDataGroupIds, validGroupIds);

    extensionDataGroupIds.push_back(TEST_STRING);
    installer.GetValidDataGroupIds(extensionDataGroupIds, bundleDataGroupIds, validGroupIds);

    bundleDataGroupIds.push_back(TEST_STRING);
    installer.GetValidDataGroupIds(extensionDataGroupIds, bundleDataGroupIds, validGroupIds);
    std::string dataGroupId = validGroupIds.back();
    EXPECT_EQ(dataGroupId, TEST_STRING);
}

/**
 * @tc.number: SendStartInstallNotify_0100
 * @tc.name: test SendStartInstallNotify
 * @tc.desc: test SendStartInstallNotify of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, SendStartInstallNotify_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.isPreInstallApp = true;
    installParam.needSendEvent = false;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    installer.bundleName_.clear();
    installer.SendStartInstallNotify(installParam, infos);
    EXPECT_TRUE(installer.bundleName_.empty());
}

/**
 * @tc.number: RollbackHmpUserInfo_0100
 * @tc.name: test RollbackHmpUserInfo
 * @tc.desc: test RollbackHmpUserInfo of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, RollbackHmpUserInfo_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    std::string bundleName;
    ErrCode ret = installer.RollbackHmpUserInfo(bundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_INVALID_NAME);

    bundleName = NORMAL_BUNDLE_NAME;
    ret = installer.RollbackHmpUserInfo(bundleName);
    EXPECT_NE(ret, ERR_APPEXECFWK_UNINSTALL_INVALID_NAME);
}

/**
 * @tc.number: RemoveTempSoDir_0100
 * @tc.name: test RemoveTempSoDir
 * @tc.desc: test RemoveTempSoDir of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, RemoveTempSoDir_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    std::string tempSoDir;
    installer.RemoveTempSoDir(tempSoDir);

    tempSoDir += ServiceConstants::TMP_SUFFIX;
    installer.RemoveTempSoDir(tempSoDir);

    tempSoDir += ServiceConstants::PATH_SEPARATOR;
    installer.RemoveTempSoDir(tempSoDir);

    tempSoDir += " ";
    tempSoDir += ServiceConstants::PATH_SEPARATOR;
    installer.RemoveTempSoDir(tempSoDir);
    EXPECT_FALSE(tempSoDir.empty());
}

/**
 * @tc.number: MoveFileToRealInstallationDir_0100
 * @tc.name: test MoveFileToRealInstallationDir
 * @tc.desc: test MoveFileToRealInstallationDir of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, MoveFileToRealInstallationDir_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> innerBundleInfos;
    ApplicationInfo applicationInfo;
    InnerBundleInfo info;
    info.SetBaseApplicationInfo(applicationInfo);
    std::string appDistributionType = "hos_normal_type";
    info.SetAppDistributionType(appDistributionType);
    innerBundleInfos.try_emplace("so", info);
    ErrCode ret = installer.MoveFileToRealInstallationDir(innerBundleInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED);
}

/**
 * @tc.number: CreateExtensionDataDir_0100
 * @tc.name: test CreateExtensionDataDir
 * @tc.desc: test CreateExtensionDataDir of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, CreateExtensionDataDir_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;
    std::vector<std::string> createExtensionDirs;
    installer.createExtensionDirs_.push_back("test.extension.dir");
    installer.CreateExtensionDataDir(info);
    installer.CreateDataGroupDir(info);
    EXPECT_FALSE(installer.createExtensionDirs_.empty());
}

/**
 * @tc.number: ProcessBundleInstallNative_0100
 * @tc.name: test ProcessBundleInstallNative
 * @tc.desc: test ProcessBundleInstallNative of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, ProcessBundleInstallNative_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo info;
    std::string moduleName = "test.moduleName";
    info.moduleName = moduleName;
    HnpPackage hnpPackage;
    std::string package = "test.package";
    hnpPackage.package = package;
    info.hnpPackages.push_back(hnpPackage);
    innerModuleInfos.try_emplace(moduleName, info);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.AddInnerModuleInfo(innerModuleInfos);
    innerBundleInfo.currentPackage_ = moduleName;
    int32_t userId = USERID;
    ErrCode ret = installer.ProcessBundleInstallNative(innerBundleInfo, userId);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: ProcessBundleUnInstallNative_0100
 * @tc.name: test ProcessBundleUnInstallNative
 * @tc.desc: test ProcessBundleUnInstallNative of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, ProcessBundleUnInstallNative_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo info;
    std::string moduleName = "test.moduleName.uninstall";
    info.moduleName = moduleName;
    HnpPackage hnpPackage;
    std::string package = "test.package";
    hnpPackage.package = package;
    info.hnpPackages.push_back(hnpPackage);
    innerModuleInfos.try_emplace(moduleName, info);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.AddInnerModuleInfo(innerModuleInfos);
    int32_t userId = USERID;
    std::string bundleName;
    ErrCode ret = installer.ProcessBundleUnInstallNative(innerBundleInfo, userId, bundleName);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CopyHapsToSecurityDir_0100
 * @tc.name: test CopyHapsToSecurityDir
 * @tc.desc: test CopyHapsToSecurityDir of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, CopyHapsToSecurityDir_0100, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.withCopyHaps = true;
    std::vector<std::string> bundlePaths;
    installer.bundlePaths_.push_back("test.bundle.path");
    ErrCode ret = installer.CopyHapsToSecurityDir(installParam, bundlePaths);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: HmpBundleInstaller_0400
 * @tc.name: test GetHmpBundleList
 * @tc.desc: 1.Test GetHmpBundleList the HmpBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, HmpBundleInstaller_0400, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;

    std::string bundleName = "com.ohos.photos";
    std::unordered_map<std::string, InnerBundleInfo> infos;
    installer.UpdateInnerBundleInfo(bundleName, infos);

    std::string bundleDir = "/data";
    const std::string hspDir = "/data";
    installer.ParseInfos(bundleDir, hspDir, infos);

    std::set<std::string> systemHspList = {"com.ohos.settings", "com.ohos.photos"};
    std::set<std::string> hapList = {"com.ohos.settings", "com.ohos.photos"};
    installer.RollbackHmpBundle(systemHspList, hapList);

    installer.UpdateBundleInfo(bundleName, bundleDir, hspDir);

    std::string path = "/data";
    std::set<std::string> ret = installer.GetHmpBundleList(path);
    EXPECT_TRUE(ret.size() > 0);
}

/**
 * @tc.number: HmpBundleInstaller_0500
 * @tc.name: test ParseHapFiles
 * @tc.desc: 1.Test ParseHapFiles the HmpBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, HmpBundleInstaller_0500, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;

    std::string hapFilePath = "/data/test.hap";
    std::unordered_map<std::string, InnerBundleInfo> infos;
    bool ret = installer.ParseHapFiles(hapFilePath, infos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: HmpBundleInstaller_0600
 * @tc.name: test UninstallSystemBundle
 * @tc.desc: 1.Test UninstallSystemBundle the HmpBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, HmpBundleInstaller_0600, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;

    std::string bundleName = "com.acts.example";
    installer.CheckUninstallSystemHsp(bundleName);

    std::string filePath = "/data/com.acts.example";
    std::set<std::string> hapList = {"com.acts.example"};
    std::set<std::string> systemHspList = {"com.acts.example"};
    installer.UpdateBundleInfoForHmp(filePath, hapList, systemHspList);

    std::unordered_map<std::string, InnerBundleInfo> Infos;
    installer.UpdatePreInfoInDb(bundleName, Infos);

    std::string modulePackage = "/data/";
    bool ret = installer.UninstallSystemBundle(bundleName, modulePackage);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: HmpBundleInstaller_0700
 * @tc.name: test GetIsRemovable
 * @tc.desc: 1.Test GetIsRemovable the HmpBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, HmpBundleInstaller_0700, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;

    std::string bundleName = "com.acts.example";
    bool ret = installer.GetIsRemovable(bundleName);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: HmpBundleInstaller_0800
 * @tc.name: test InitDataMgr
 * @tc.desc: 1.Test InitDataMgr the HmpBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, HmpBundleInstaller_0800, Function | MediumTest | Level1)
{
    HmpBundleInstaller installer;

    bool ret = installer.InitDataMgr();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BundleUserMgrHostImpl_0100
 * @tc.name: test GetAllPreInstallBundleInfos
 * @tc.desc: 1.Test GetAllPreInstallBundleInfos the UserReceiverImpl
*/
HWTEST_F(BmsBundleInstallerTest, BundleUserMgrHostImpl_0100, Function | MediumTest | Level1)
{
    BundleUserMgrHostImpl host;

    int32_t userId = 100;
    std::vector<std::string> disallowList;
    std::vector<BundleInfo> bundleInfos;
    std::set<PreInstallBundleInfo> preInstallBundleInfos;
    host.RemoveArkProfile(userId);
    host.RemoveAsanLogDirectory(userId);
    host.BeforeCreateNewUser(userId);
    host.AfterCreateNewUser(userId);
    host.InnerUninstallBundle(userId, bundleInfos);
    host.ClearBundleEvents();
    host.HandleNotifyBundleEventsAsync();
    host.HandleNotifyBundleEvents();
    host.UninstallBackupUninstallList(userId);

    bool ret = host.GetAllPreInstallBundleInfos(disallowList, userId, preInstallBundleInfos);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BundleStreamInstallerHostImpl_0100
 * @tc.name: test CreateSignatureFileStream
 * @tc.desc: 1.Test CreateSignatureFileStream the BundleStreamInstallerHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, BundleStreamInstallerHostImpl_0100, Function | MediumTest | Level1)
{
    BundleStreamInstallerHostImpl installer(0, 0);

    std::string moduleName;
    std::string fileName;
    int32_t ret = installer.CreateSignatureFileStream(moduleName, fileName);
    EXPECT_EQ(ret, Constants::DEFAULT_STREAM_FD);
}

/**
 * @tc.number: BundleStreamInstallerHostImpl_0200
 * @tc.name: test CreateSignatureFileStream
 * @tc.desc: 1.Test CreateSignatureFileStream the BundleStreamInstallerHostImpl
*/
HWTEST_F(BmsBundleInstallerTest, BundleStreamInstallerHostImpl_0200, Function | MediumTest | Level1)
{
    BundleStreamInstallerHostImpl installer(0, 0);

    std::string moduleName = "moduleName";
    std::string fileName = "test.file";
    int32_t ret = installer.CreateSignatureFileStream(moduleName, fileName);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.number: SystemBundleInstaller_0100
 * @tc.name: test InstallSystemSharedBundle
 * @tc.desc: 1.Test InstallSystemSharedBundle the SystemBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, SystemBundleInstaller_0100, Function | MediumTest | Level1)
{
    SystemBundleInstaller installer;

    InstallParam installParam;
    bool isOTA = false;
    Constants::AppType appType = Constants::AppType::SYSTEM_APP;
    bool ret = installer.InstallSystemSharedBundle(installParam, isOTA, appType);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SystemBundleInstaller_0200
 * @tc.name: test UninstallSystemBundle
 * @tc.desc: 1.Test UninstallSystemBundle the SystemBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, SystemBundleInstaller_0200, Function | MediumTest | Level1)
{
    SystemBundleInstaller installer;

    std::string bundleName = "com.acts.example";
    InstallParam installParam;
    bool ret = installer.UninstallSystemBundle(bundleName, installParam);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: PreInstallBundleInfo_0100
 * @tc.name: test ToJson
 * @tc.desc: 1.Test ToJson the PreInstallBundleInfo
*/
HWTEST_F(BmsBundleInstallerTest, PreInstallBundleInfo_0100, Function | MediumTest | Level1)
{
    PreInstallBundleInfo preInstallBundleInfo;

    preInstallBundleInfo.CalculateHapTotalSize();

    preInstallBundleInfo.SetBundleName("com.acts.example");
    preInstallBundleInfo.SetModuleName("example_example");
    nlohmann::json jsonObject;
    preInstallBundleInfo.ToJson(jsonObject);
    EXPECT_EQ(jsonObject["bundleName"], "com.acts.example");
}

/**
 * @tc.number: UtdHandler_0100
 * @tc.name: test UtdHandler
 * @tc.desc: 1.call GetEntryHapPath, if exist entry then return entry path, otherwise return empty string
 */
HWTEST_F(BmsBundleInstallerTest, UtdHandler_0100, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    std::string entryHapPath;
    entryHapPath = UtdHandler::GetEntryHapPath(BUNDLE_BACKUP_NAME, USERID);
    EXPECT_NE(entryHapPath, EMPTY_STRING);

    entryHapPath = UtdHandler::GetEntryHapPath(EMPTY_STRING, USERID);
    EXPECT_EQ(entryHapPath, EMPTY_STRING);

    int32_t invalidUserId = -200;
    entryHapPath = UtdHandler::GetEntryHapPath(BUNDLE_BACKUP_NAME, invalidUserId);
    EXPECT_EQ(entryHapPath, EMPTY_STRING);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: UtdHandler_0200
 * @tc.name: test UtdHandler
 * @tc.desc: 1.call GetUtdProfileFromHap, if exist utd.json5 then return content, otherwise return empty string
 */
HWTEST_F(BmsBundleInstallerTest, UtdHandler_0200, Function | SmallTest | Level0)
{
    std::string utdProfile;
    std::string withUtdHapPath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    utdProfile = UtdHandler::GetUtdProfileFromHap(withUtdHapPath);
    EXPECT_NE(utdProfile, EMPTY_STRING);

    std::string noUtdHapPath = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    utdProfile = UtdHandler::GetUtdProfileFromHap(noUtdHapPath);
    EXPECT_EQ(utdProfile, EMPTY_STRING);

    utdProfile = UtdHandler::GetUtdProfileFromHap(EMPTY_STRING);
    EXPECT_EQ(utdProfile, EMPTY_STRING);
}
} // OHOS
