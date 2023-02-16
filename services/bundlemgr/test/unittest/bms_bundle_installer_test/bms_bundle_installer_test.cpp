/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "bundle_info.h"
#include "bundle_data_storage_database.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "install_param.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "system_bundle_installer.h"
#include "want.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using namespace OHOS::DistributedKv;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const std::string SYSTEMFIEID_NAME = "com.query.test";
const std::string SYSTEMFIEID_BUNDLE = "system_module.hap";
const std::string BUNDLE_NAME = "com.example.l3jsdemo";
const std::string RESOURCE_ROOT_PATH = "/data/test/resource/bms/install_bundle/";
const std::string INVALID_PATH = "/install_bundle/";
const std::string RIGHT_BUNDLE = "right.hap";
const std::string TYPE_BUNDLE = "devicetype_error.hap";
const std::string INVALID_BUNDLE = "nonfile.hap";
const std::string WRONG_BUNDLE_NAME = "wrong_bundle_name.ha";
const std::string BUNDLE_DATA_DIR = "/data/app/el2/100/base/com.example.l3jsdemo";
const std::string BUNDLE_CODE_DIR = "/data/app/el1/bundle/public/com.example.l3jsdemo";
const int32_t USERID = 100;
const std::string INSTALL_THREAD = "TestInstall";
const int32_t WAIT_TIME = 5; // init mocked bms
const std::string BUNDLE_BACKUP_TEST = "backup.hap";
const std::string BUNDLE_PREVIEW_TEST = "preview.hap";
const std::string BUNDLE_THUMBNAIL_TEST = "thumbnail.hap";
const std::string BUNDLE_BACKUP_NAME = "com.example.backuptest";
const std::string BUNDLE_PREVIEW_NAME = "com.example.previewtest";
const std::string BUNDLE_THUMBNAIL_NAME = "com.example.thumbnailtest";
const std::string MODULE_NAME = "entry";
const std::string EXTENSION_ABILITY_NAME = "extensionAbility_A";
const std::string TEST_STRING = "test.string";
const int32_t INVAILD_CODE = -1;
const int32_t ZERO_CODE = 0;
const size_t NUMBER_ONE = 1;
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
    void SetDataMgr();

private:
    std::shared_ptr<BundleInstallerManager> manager_ = nullptr;
    std::shared_ptr<InstalldService> installdService_ = std::make_shared<InstalldService>();
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
    const std::shared_ptr<BundleDataMgr> dataMgrInfo_ =
        DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_;
};

BmsBundleInstallerTest::BmsBundleInstallerTest()
{}

BmsBundleInstallerTest::~BmsBundleInstallerTest()
{}

bool BmsBundleInstallerTest::InstallSystemBundle(const std::string &filePath) const
{
    auto installer = std::make_unique<SystemBundleInstaller>();
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.isPreInstallApp = true;
    installParam.noSkipsKill = false;
    installParam.needSendEvent = false;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    return installer->InstallSystemBundle(filePath, installParam, Constants::AppType::SYSTEM_APP);
}

bool BmsBundleInstallerTest::OTAInstallSystemBundle(const std::string &filePath) const
{
    auto installer = std::make_unique<SystemBundleInstaller>();
    std::vector<std::string> filePaths;
    filePaths.push_back(filePath);
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.isPreInstallApp = true;
    installParam.noSkipsKill = false;
    installParam.needSendEvent = false;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    return installer->OTAInstallSystemBundle(filePaths, installParam, Constants::AppType::SYSTEM_APP);
}

ErrCode BmsBundleInstallerTest::InstallThirdPartyBundle(const std::string &filePath) const
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
    bool result = installer->Install(filePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleInstallerTest::UpdateThirdPartyBundle(const std::string &filePath) const
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
    bool result = installer->Install(filePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleInstallerTest::UnInstallBundle(const std::string &bundleName) const
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
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

void BmsBundleInstallerTest::SetUpTestCase()
{
}

void BmsBundleInstallerTest::TearDownTestCase()
{
}

void BmsBundleInstallerTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleInstallerTest::TearDown()
{
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_CODE_DIR);
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

void BmsBundleInstallerTest::SetDataMgr()
{
    EXPECT_NE(dataMgrInfo_, nullptr);
    bundleMgrService_->dataMgr_ = dataMgrInfo_;
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
    auto installRunner = EventRunner::Create(INSTALL_THREAD);
    if (!installRunner) {
        return;
    }
    manager_ = std::make_shared<BundleInstallerManager>(installRunner);
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
 * @tc.require: AR000GHLL7
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
 * @tc.require: AR000GHLL7
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
 * @tc.require: AR000GHLL7
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
 * @tc.require: AR000GHLL7
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
 * @tc.require: AR000GHLL7
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
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_DEVICE_TYPE_NOT_SUPPORTED);
}

/**
 * @tc.number: SystemUpdateData_0100
 * @tc.name: test the right bundle file can be installed and update its info to bms
 * @tc.desc: 1.the system bundle is available
 *           2.the right bundle can be installed and update its info to bms
 * @tc.require: AR000GHLL7
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
 * @tc.require: AR000GHLL7
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
 * @tc.require: AR000GHLL7
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
 * @tc.require: AR000GHLL7
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
}

/**
 * @tc.number: CreateInstallTask_0100
 * @tc.name: test the installer manager can create task
 * @tc.desc: 1.the bundle file exists
 *           2.the bundle can be installed successfully
 * @tc.require: AR000GHLL7
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
 * @tc.require: AR000GHLL7
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
 * @tc.require: AR000GHLL7
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
 * @tc.require: AR000GHLL7
 */
HWTEST_F(BmsBundleInstallerTest, ParseModuleJson_0100, Function | SmallTest | Level0)
{
    ApplicationInfo info;
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string bundleFile = RESOURCE_ROOT_PATH + SYSTEMFIEID_BUNDLE;
    bool installResult = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(installResult);
    bool result =
        dataMgr->GetApplicationInfo(SYSTEMFIEID_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    EXPECT_TRUE(result);
    EXPECT_EQ(info.name, "com.query.test");
    EXPECT_EQ(info.description, "$string:description_application");
    EXPECT_EQ(info.descriptionId, 16777217);
    EXPECT_EQ(info.label, "$string:app_name");
    EXPECT_EQ(info.labelId, 16777216);
    EXPECT_EQ(info.iconPath, "$media:app_icon");
    EXPECT_EQ(info.iconId, 16777228);
    EXPECT_EQ(static_cast<uint32_t>(info.versionCode), 1);
    EXPECT_EQ(info.versionName, "1.0");
    EXPECT_EQ(info.minCompatibleVersionCode, 1);
    EXPECT_EQ(info.apiCompatibleVersion, 8);
    EXPECT_EQ(info.apiTargetVersion, 8);
    EXPECT_EQ(info.keepAlive, true);
    EXPECT_EQ(info.removable, false);
    EXPECT_EQ(info.userDataClearable, false);
    EXPECT_EQ(info.accessible, true);
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
    EXPECT_EQ(hapModuleInfo.virtualMachine, "");
    EXPECT_EQ(hapModuleInfo.uiSyntax, "hml");
    EXPECT_EQ(hapModuleInfo.pages, "$profile:page_config");
    EXPECT_EQ(hapModuleInfo.deliveryWithInstall, true);
    EXPECT_EQ(hapModuleInfo.installationFree, false);
    EXPECT_EQ(hapModuleInfo.srcEntrance, "./MyAbilityStage.ts");

    auto abilityInfos = hapModuleInfo.abilityInfos.front();
    EXPECT_EQ(abilityInfos.name, "MainAbility");
    EXPECT_EQ(abilityInfos.srcEntrance, "./login/MyLoginAbility.ts");
    EXPECT_EQ(abilityInfos.description, "$string:description_main_ability");
    EXPECT_EQ(abilityInfos.descriptionId, 16777219);
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
    EXPECT_EQ(extensionInfos.readPermission, "readPermission---");
    EXPECT_EQ(extensionInfos.writePermission, "writePermission---");

    UnInstallBundle(SYSTEMFIEID_NAME);
}

/**
 * @tc.number: BackupExtension_0100
 * @tc.name: test the backup type
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.require: AR000H035G
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
 * @tc.require: SR000H0383
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
 * @tc.require: AR000H035G
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
 * @tc.require: AR000H035G
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
 * @tc.require: AR000H035G
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
 * @tc.number: GetBundleStats_001
 * @tc.name: test the GetBundleStats
 * @tc.desc: 1.install the hap
 *           2.GetBundleStats
 * @tc.require: AR000H035G
 */
HWTEST_F(BmsBundleInstallerTest, GetBundleStats_001, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    std::vector<int64_t> bundleStats;
    auto ret = InstalldClient::GetInstance()->GetBundleStats(BUNDLE_BACKUP_NAME, USERID, bundleStats);
    EXPECT_EQ(ret, ERR_OK);
    if (!bundleStats.empty()) {
        EXPECT_NE(bundleStats[0], 0);
        for (size_t index = NUMBER_ONE; index < bundleStats.size(); index++) {
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
        Constants::CURRENT_DEVICE_ID, BUNDLE_NAME, key);
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
    std::string deviceId = Constants::CURRENT_DEVICE_ID;
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
    auto appType = Constants::AppType::THIRD_SYSTEM_APP;
    int32_t uid = 0;
    ErrCode ret = installer.ProcessBundleInstall(
        inBundlePaths, installParam, appType, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    installer.dataMgr_ = GetBundleDataMgr();

    installParam.userId = Constants::INVALID_USERID;
    ret = installer.ProcessBundleInstall(
        inBundlePaths, installParam, appType, uid);
    EXPECT_NE(ret, ERR_OK);

    installParam.userId = Constants::DEFAULT_USERID;
    installer.dataMgr_->multiUserIdsSet_.insert(installParam.userId);
    ret = installer.ProcessBundleInstall(
        inBundlePaths, installParam, appType, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
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
    ret = installer.RemoveBundleUserData(innerBundleInfo, needRemoveData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: baseBundleInstaller_0700
 * @tc.name: test VerifyUriPrefix, InnerBundleInfo id is different
 * @tc.desc: 1.Test the VerifyUriPrefix of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_0700, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();
    InnerBundleInfo innerBundleInfo;
    bool isUpdate = false;
    bool ret = installer.VerifyUriPrefix(
        innerBundleInfo, Constants::ALL_USERID, isUpdate);
    EXPECT_EQ(ret, true);

    AbilityInfo info;
    info.uri = "dataability://";
    innerBundleInfo.baseAbilityInfos_.emplace("key", info);
    ret = installer.VerifyUriPrefix(
        innerBundleInfo, Constants::ALL_USERID, isUpdate);
    EXPECT_EQ(ret, false);

    info.uri = "dataability://com.ohos.test";
    ret = installer.VerifyUriPrefix(
        innerBundleInfo, Constants::ALL_USERID, isUpdate);
    EXPECT_EQ(ret, false);
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
    bool recoverMode = true;
    int32_t uid = 0;
    InstallParam installParam;
    installParam.userId = Constants::INVALID_USERID;
    ErrCode ret = installer.InnerProcessInstallByPreInstallInfo(
        BUNDLE_NAME, installParam, uid, recoverMode);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);

    installParam.userId = Constants::DEFAULT_USERID;
    installer.dataMgr_->multiUserIdsSet_.insert(Constants::DEFAULT_USERID);
    ret = installer.InnerProcessInstallByPreInstallInfo(
        BUNDLE_NAME, installParam, uid, recoverMode);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON);
}

/**
 * @tc.number: baseBundleInstaller_1100
 * @tc.name: test ProcessDeployedHqfInfo
 * @tc.desc: 1.Test the ProcessDeployedHqfInfo of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_1100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
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
    std::string nativeLibraryPath = "/an/x86/x86.so";
    ErrCode ret = installer.ProcessDiffFiles(
        appQfInfo, nativeLibraryPath);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_QUICK_FIX_EXTRACT_DIFF_FILES_FAILED);
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
 * @tc.number: baseBundleInstaller_1900
 * @tc.name: test CheckArkNativeFileWithOldInfo
 * @tc.desc: 1.Test the CheckArkNativeFileWithOldInfo of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_1900, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    ApplicationInfo applicationInfo;
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    oldInfo.SetArkNativeFileAbi("x86");
    InnerBundleInfo info;
    info.SetBaseApplicationInfo(applicationInfo);
    info.SetArkNativeFileAbi("");
    newInfos.try_emplace("so", info);
    ErrCode ret = installer.CheckArkNativeFileWithOldInfo(oldInfo, newInfos);
    EXPECT_EQ(ret, ERR_OK);

    newInfos.clear();
    info.SetArkNativeFileAbi("arm");
    newInfos.try_emplace("so", info);
    ret = installer.CheckArkNativeFileWithOldInfo(oldInfo, newInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_AN_INCOMPATIBLE);

    newInfos.clear();
    info.SetArkNativeFileAbi("x86");
    newInfos.try_emplace("so", info);
    ret = installer.CheckArkNativeFileWithOldInfo(oldInfo, newInfos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_2000
 * @tc.name: test CheckNativeSoWithOldInfo
 * @tc.desc: 1.Test the CheckNativeSoWithOldInfo of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2000, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    ApplicationInfo applicationInfo;
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    oldInfo.SetNativeLibraryPath("/an/x86/x86.so");
    InnerBundleInfo info;
    info.SetBaseApplicationInfo(applicationInfo);
    info.SetNativeLibraryPath("/an/arm/arm.so");
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.try_emplace("so", info);
    ErrCode ret = installer.CheckNativeSoWithOldInfo(oldInfo, newInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_SO_INCOMPATIBLE);

    newInfos.clear();
    info.SetNativeLibraryPath("/an/x86/x86.so");
    oldInfo.SetCpuAbi("arm");
    info.SetCpuAbi("x86");
    newInfos.try_emplace("so", info);
    ret = installer.CheckNativeSoWithOldInfo(oldInfo, newInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_SO_INCOMPATIBLE);

    newInfos.clear();
    info.SetNativeLibraryPath("");
    oldInfo.SetCpuAbi("x86");
    newInfos.try_emplace("so", info);
    ret = installer.CheckNativeSoWithOldInfo(oldInfo, newInfos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_2100
 * @tc.name: test UpdateDefineAndRequestPermissions
 * @tc.desc: 1.Test the UpdateDefineAndRequestPermissions of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    InnerBundleUserInfo userInfo;
    userInfo.accessTokenId = 0;
    newInfo.innerBundleUserInfos_.insert(pair<std::string, InnerBundleUserInfo>("1", userInfo));

    auto res = installer.UpdateDefineAndRequestPermissions(oldInfo, newInfo);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_2200
 * @tc.name: test ProcessBundleUninstall
 * @tc.desc: 1.Test the ProcessBundleUninstall of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2200, Function | SmallTest | Level0)
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
 * @tc.number: baseBundleInstaller_2300
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.Test the ProcessBundleUpdateStatus of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2300, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = "";
    bool isReplace = false;
    bool noSkipsKill = false;

    auto res = installer.ProcessBundleUpdateStatus(oldInfo, newInfo, isReplace, noSkipsKill);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: baseBundleInstaller_2400
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.Test the ProcessBundleUpdateStatus of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2400, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    oldInfo.baseApplicationInfo_->singleton = true;
    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = MODULE_NAME;
    bool isReplace = false;
    bool noSkipsKill = false;

    auto res = installer.ProcessBundleUpdateStatus(oldInfo, newInfo, isReplace, noSkipsKill);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_STATE_ERROR);
}

/**
 * @tc.number: baseBundleInstaller_2500
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.Test the ProcessBundleUpdateStatus of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2500, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = MODULE_NAME;
    newInfo.baseApplicationInfo_->singleton = true;
    bool isReplace = false;
    bool noSkipsKill = false;

    auto res = installer.ProcessBundleUpdateStatus(oldInfo, newInfo, isReplace, noSkipsKill);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_STATE_ERROR);

    installer.modulePackage_ = MODULE_NAME;
    InnerModuleInfo moduleInfo;
    moduleInfo.isLibIsolated = true;
    moduleInfo.cpuAbi = "123";
    moduleInfo.nativeLibraryPath = "/data/test";
    newInfo.innerModuleInfos_.insert(pair<std::string, InnerModuleInfo>(MODULE_NAME, moduleInfo));
    installer.ProcessHqfInfo(oldInfo, newInfo);
}

/**
 * @tc.number: baseBundleInstaller_2600
 * @tc.name: test ProcessDeployedHqfInfo
 * @tc.desc: 1.Test the ProcessDeployedHqfInfo of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2600, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.isFeatureNeedUninstall_ = false;
    std::string nativeLibraryPath = "/data/test";
    std::string cpuAbi = "123";
    InnerBundleInfo newInfo;
    AppQuickFix oldAppQuickFix;
    HqfInfo hqfInfo;
    oldAppQuickFix.deployedAppqfInfo.hqfInfos.push_back(hqfInfo);

    auto res = installer.ProcessDeployedHqfInfo(nativeLibraryPath, cpuAbi, newInfo, oldAppQuickFix);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_QUICK_FIX_EXTRACT_DIFF_FILES_FAILED);

    hqfInfo.moduleName = MODULE_NAME;
    installer.modulePackage_ = "123";
    res = installer.ProcessDeployedHqfInfo(nativeLibraryPath, cpuAbi, newInfo, oldAppQuickFix);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: baseBundleInstaller_2700
 * @tc.name: test UpdateLibAttrs
 * @tc.desc: 1.Test the UpdateLibAttrs of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2700, Function | SmallTest | Level0)
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
 * @tc.number: baseBundleInstaller_2800
 * @tc.name: test baseBundleInstaller
 * @tc.desc: 1.Test the dataMgr_ is nullptr
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2800, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = nullptr;
    ClearDataMgr();
    std::vector<std::string> inBundlePaths;
    InstallParam installParam;
    auto appType = Constants::AppType::THIRD_SYSTEM_APP;
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
        "bundleName", installParam, uid, recoverMode);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);
    InnerBundleInfo info;
    bool res = installer.GetInnerBundleInfo(info, recoverMode);
    EXPECT_EQ(res, false);
    SetDataMgr();

    installParam.userId = Constants::INVALID_USERID;
    ret = installer.ProcessBundleUninstall(
        "bundleName", installParam, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
    ret = installer.ProcessBundleUninstall(
        "bundleName", "modulePackage", installParam, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: baseBundleInstaller_2900
 * @tc.name: test RemoveBundle
 * @tc.desc: 1.Test the RemoveBundle
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_2900, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;
    ErrCode res = installer.RemoveBundle(info, false);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: baseBundleInstaller_3000
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.Test the ProcessBundleUpdateStatus
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_3000, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    installer.isFeatureNeedUninstall_ = true;
    ErrCode res = installer.ProcessBundleUpdateStatus(oldInfo, newInfo, false, false);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: baseBundleInstaller_3100
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1.Test the ProcessBundleUpdateStatus
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_3100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
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
 * @tc.number: baseBundleInstaller_3200
 * @tc.name: test InstallAppControl
 * @tc.desc: 1.Test the InstallAppControl of BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallerTest, baseBundleInstaller_3200, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    std::vector<std::string> installAppIds;
    int32_t userId = Constants::DEFAULT_USERID;;
    OHOS::ErrCode ret = installer.InstallAppControl(installAppIds, userId);
    EXPECT_EQ(ret, OHOS::ERR_OK);
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

    ret = impl.RenameModuleDir("wrong", "wrong");
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
    auto ret = impl.CreateBundleDataDir("", INVAILD_CODE, INVAILD_CODE, INVAILD_CODE, TEST_STRING);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = impl.CreateBundleDataDir(TEST_STRING, 99, ZERO_CODE, ZERO_CODE, TEST_STRING);
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
    auto ret = impl.RemoveBundleDataDir("", INVAILD_CODE);
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
    auto ret = impl.RemoveModuleDataDir("", INVAILD_CODE);
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
    ErrCode ret = impl.GetBundleStats("", USERID, bundleStats);
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
} // OHOS
