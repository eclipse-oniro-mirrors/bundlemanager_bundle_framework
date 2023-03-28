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

#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bundle_info.h"
#include "bundle_data_storage_database.h"
#include "bundle_file_util.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "install_param.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "inner_bundle_info.h"
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
const std::string INVALID_BUNDLE = "nonfile.hap";
const std::string WRONG_BUNDLE_NAME = "wrong_bundle_name.ha";
const std::string BUNDLE_DATA_DIR = "/data/app/el2/100/base/com.example.l3jsdemo";
const std::string BUNDLE_CODE_DIR = "/data/app/el1/bundle/public/com.example.l3jsdemo";
const int32_t USERID = 100;
const int32_t WRONG_UID = -1;
const std::string INSTALL_THREAD = "TestInstall";
const int32_t WAIT_TIME = 5; // init mocked bms
const std::string BUNDLE_BACKUP_TEST = "backup.hap";
const std::string BUNDLE_PREVIEW_TEST = "preview.hap";
const std::string BUNDLE_THUMBNAIL_TEST = "thumbnail.hap";
const std::string BUNDLE_BACKUP_NAME = "com.example.backuptest";
const std::string ABILITY_BACKUP_NAME = "MainAbility";
const std::string BUNDLE_PREVIEW_NAME = "com.example.previewtest";
const std::string BUNDLE_THUMBNAIL_NAME = "com.example.thumbnailtest";
const std::string MODULE_NAME = "entry";
const std::string EXTENSION_ABILITY_NAME = "extensionAbility_A";
const std::string OVER_MAX_SIZE(300, 'x');
const size_t NUMBER_ONE = 1;
}  // namespace

class BmsBundleManagerTest : public testing::Test {
public:
    BmsBundleManagerTest();
    ~BmsBundleManagerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    bool InstallSystemBundle(const std::string &filePath) const;
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

BmsBundleManagerTest::BmsBundleManagerTest()
{}

BmsBundleManagerTest::~BmsBundleManagerTest()
{}

bool BmsBundleManagerTest::InstallSystemBundle(const std::string &filePath) const
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

ErrCode BmsBundleManagerTest::InstallThirdPartyBundle(const std::string &filePath) const
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

ErrCode BmsBundleManagerTest::UpdateThirdPartyBundle(const std::string &filePath) const
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

ErrCode BmsBundleManagerTest::UnInstallBundle(const std::string &bundleName) const
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

void BmsBundleManagerTest::SetUpTestCase()
{
}

void BmsBundleManagerTest::TearDownTestCase()
{
}

void BmsBundleManagerTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleManagerTest::TearDown()
{
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_CODE_DIR);
}

void BmsBundleManagerTest::CheckFileExist() const
{
    int bundleCodeExist = access(BUNDLE_CODE_DIR.c_str(), F_OK);
    EXPECT_EQ(bundleCodeExist, 0) << "the bundle code dir does not exists: " << BUNDLE_CODE_DIR;

    int bundleDataExist = access(BUNDLE_DATA_DIR.c_str(), F_OK);
    EXPECT_EQ(bundleDataExist, 0) << "the bundle data dir does not exists: " << BUNDLE_DATA_DIR;
}

void BmsBundleManagerTest::CheckFileNonExist() const
{
    int bundleCodeExist = access(BUNDLE_CODE_DIR.c_str(), F_OK);
    EXPECT_NE(bundleCodeExist, 0) << "the bundle code dir exists: " << BUNDLE_CODE_DIR;

    int bundleDataExist = access(BUNDLE_DATA_DIR.c_str(), F_OK);
    EXPECT_NE(bundleDataExist, 0) << "the bundle data dir exists: " << BUNDLE_DATA_DIR;
}

const std::shared_ptr<BundleDataMgr> BmsBundleManagerTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

const std::shared_ptr<BundleInstallerManager> BmsBundleManagerTest::GetBundleInstallerManager() const
{
    return manager_;
}

void BmsBundleManagerTest::ClearDataMgr()
{
    bundleMgrService_->dataMgr_ = nullptr;
}

void BmsBundleManagerTest::SetDataMgr()
{
    EXPECT_NE(dataMgrInfo_, nullptr);
    bundleMgrService_->dataMgr_ = dataMgrInfo_;
    EXPECT_NE(bundleMgrService_->dataMgr_, nullptr);
}

void BmsBundleManagerTest::StopInstalldService() const
{
    if (installdService_->IsServiceReady()) {
        installdService_->Stop();
        InstalldClient::GetInstance()->ResetInstalldProxy();
    }
}

void BmsBundleManagerTest::StopBundleService()
{
    if (bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStop();
        bundleMgrService_.reset();
    }
}

void BmsBundleManagerTest::CreateInstallerManager()
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

void BmsBundleManagerTest::ClearBundleInfo()
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
 * @tc.number: QueryExtensionAbilityInfosV9_0100
 * @tc.name: test the backup type
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_0100, Function | SmallTest | Level0)
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
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    if (infos.size() > 0) {
        EXPECT_EQ(infos[0].bundleName, BUNDLE_BACKUP_NAME);
        EXPECT_EQ(infos[0].moduleName, MODULE_NAME);
        EXPECT_EQ(infos[0].type, ExtensionAbilityType::BACKUP);
    }
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0200
 * @tc.name: test the backup type
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_0200, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0300
 * @tc.name: test the backup type
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_0300, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_BACKUP_NAME, EXTENSION_ABILITY_NAME, "");
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(infos.size(), NUMBER_ONE);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0400
 * @tc.name: test the backup type
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_0400, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_BACKUP_NAME, EXTENSION_ABILITY_NAME, MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_EQ(result, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_0500
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_0500, Function | SmallTest | Level0)
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
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_EQ(result, ERR_OK);

    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_0600
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_0600, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_PREVIEW_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);

    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_0700
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_0700, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_PREVIEW_NAME, EXTENSION_ABILITY_NAME, "");
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_EQ(result, ERR_OK);

    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_0800
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_0800, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_PREVIEW_NAME, EXTENSION_ABILITY_NAME, MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_EQ(result, ERR_OK);

    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_0900
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_0900, Function | SmallTest | Level0)
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
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_EQ(result, ERR_OK);

    UnInstallBundle(BUNDLE_THUMBNAIL_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_1000
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_1000, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_THUMBNAIL_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_THUMBNAIL_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);

    UnInstallBundle(BUNDLE_THUMBNAIL_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_1100
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_1100, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_THUMBNAIL_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_THUMBNAIL_NAME, EXTENSION_ABILITY_NAME, "");
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_EQ(result, ERR_OK);

    UnInstallBundle(BUNDLE_THUMBNAIL_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_1200
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_1200, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_THUMBNAIL_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_THUMBNAIL_NAME, EXTENSION_ABILITY_NAME, MODULE_NAME);
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_EQ(result, ERR_OK);

    UnInstallBundle(BUNDLE_THUMBNAIL_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_1300
 * @tc.desc: 1.query extensionAbilityInfos with invalid userId
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_1300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    int32_t userId = -1;
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, userId, infos);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_1400
 * @tc.desc: 1.query extensionAbilityInfos with not exist action
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_1400, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.not.exist.xxx");
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_NE(result, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_1500
 * @tc.desc: 1.explicit query extensionAbilityInfos
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_1500, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_BACKUP_NAME, "extensionAbility_A", "");
    want.SetElement(elementName);
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_EQ(result, ERR_OK);

    int32_t flags =
        static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION) |
        static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION) |
        static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_METADATA);
    result = dataMgr->QueryExtensionAbilityInfosV9(want, flags, USERID, infos);
    EXPECT_EQ(result, ERR_OK);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_1600
 * @tc.desc: 1.explicit query extensionAbilityInfos, which not exists
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_1600, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_BACKUP_NAME, "NotExist", "");
    want.SetElement(elementName);
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_NE(result, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_1700
 * @tc.desc: 1.query extensionAbilityInfos with empty want
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_1700, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_1800
 * @tc.desc: 1.query extensionAbilityInfos in all scope
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_1800, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_EQ(result, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_1900
 * @tc.desc: 1.query extensionAbilityInfos with more than one target
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_1900, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.hello");
    want.AddEntity("entity.hello");
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, 0, USERID, infos);
    EXPECT_EQ(result, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.name: QueryExtensionAbilityInfosV9_2000
 * @tc.desc: 1.query extensionAbilityInfos with flags
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest, QueryExtensionAbilityInfosV9_2000, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.hello");
    want.AddEntity("entity.hello");
    int32_t flags =
        static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION) |
        static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION) |
        static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_METADATA);
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode result = dataMgr->QueryExtensionAbilityInfosV9(want, flags, USERID, infos);
    EXPECT_EQ(result, ERR_OK);

    ElementName elementName("", BUNDLE_BACKUP_NAME, "", "");
    want.SetElement(elementName);
    result = dataMgr->QueryExtensionAbilityInfosV9(want, flags, USERID, infos);
    EXPECT_EQ(result, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: QueryAbilityInfosV9_0100
 * @tc.name: test QueryAbilityInfosV9 proxy
 * @tc.desc: 1.query ability infos
 */
HWTEST_F(BmsBundleManagerTest, QueryAbilityInfosV9_0100, Function | MediumTest | Level1)
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

    std::vector<AbilityInfo> AbilityInfo;
    ErrCode ret = dataMgr->QueryAbilityInfosV9(want, 0, USERID, AbilityInfo);
    EXPECT_EQ(ret, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: QueryAbilityInfosV9_0200
 * @tc.name: test QueryAbilityInfosV9 proxy
 * @tc.desc: 1.query ability infos with invalid userId
 */
HWTEST_F(BmsBundleManagerTest, QueryAbilityInfosV9_0200, Function | MediumTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    int32_t userId = -1;
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = dataMgr->QueryAbilityInfosV9(want, 0, userId, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: QueryAbilityInfosV9_0300
 * @tc.name: test QueryAbilityInfosV9 proxy
 * @tc.desc: 1.query ability infos with not exist action
 */
HWTEST_F(BmsBundleManagerTest, QueryAbilityInfosV9_0300, Function | MediumTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.not.exist.xxx");
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = dataMgr->QueryAbilityInfosV9(want, 0, USERID, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: QueryAbilityInfosV9_0400
 * @tc.name: test QueryAbilityInfosV9 proxy
 * @tc.desc: 1.explicit query ability infos
 */
HWTEST_F(BmsBundleManagerTest, QueryAbilityInfosV9_0400, Function | MediumTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_BACKUP_NAME, "MainAbility", "");
    want.SetElement(elementName);

    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = dataMgr->QueryAbilityInfosV9(want, 0, USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);

    int32_t flags =
        static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_PERMISSION) |
        static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION) |
        static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_METADATA) |
        static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_DISABLE);
    ret = dataMgr->QueryAbilityInfosV9(want, flags, USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: QueryAbilityInfosV9_0500
 * @tc.name: test QueryAbilityInfosV9 proxy
 * @tc.desc: 1.explicit query ability infos, which not exists
 */
HWTEST_F(BmsBundleManagerTest, QueryAbilityInfosV9_0500, Function | MediumTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    ElementName elementName("", BUNDLE_BACKUP_NAME, "NotExist", "");
    want.SetElement(elementName);

    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = dataMgr->QueryAbilityInfosV9(want, 0, USERID, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: QueryAbilityInfosV9_0600
 * @tc.name: test QueryAbilityInfosV9 proxy
 * @tc.desc: 1.query ability infos with empty want
 */
HWTEST_F(BmsBundleManagerTest, QueryAbilityInfosV9_0600, Function | MediumTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = dataMgr->QueryAbilityInfosV9(want, 0, USERID, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: QueryAbilityInfosV9_0700
 * @tc.name: test QueryAbilityInfosV9 proxy
 * @tc.desc: 1.implicit query ability infos in all scope
 */
HWTEST_F(BmsBundleManagerTest, QueryAbilityInfosV9_0700, Function | MediumTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");

    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = dataMgr->QueryAbilityInfosV9(want, 0, USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: QueryAbilityInfosV9_0800
 * @tc.name: test QueryAbilityInfosV9 proxy
 * @tc.desc: 1.implicit query ability infos with more than one target
 */
HWTEST_F(BmsBundleManagerTest, QueryAbilityInfosV9_0800, Function | MediumTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.hello");
    want.AddEntity("entity.hello");

    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = dataMgr->QueryAbilityInfosV9(want, 0, USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);

    ElementName elementName("", BUNDLE_BACKUP_NAME, "", "");
    want.SetElement(elementName);
    ret = dataMgr->QueryAbilityInfosV9(want, 0, USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: QueryAbilityInfosV9_0900
 * @tc.name: test QueryAbilityInfosV9 proxy
 * @tc.desc: 1.implicit query ability infos with flags
 */
HWTEST_F(BmsBundleManagerTest, QueryAbilityInfosV9_0900, Function | MediumTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.hello");
    want.AddEntity("entity.hello");

    std::vector<AbilityInfo> abilityInfos;
    int32_t flags =
        static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_PERMISSION) |
        static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION) |
        static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_METADATA) |
        static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_DISABLE);
    ErrCode ret = dataMgr->QueryAbilityInfosV9(want, flags, USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);

    ElementName elementName("", BUNDLE_BACKUP_NAME, "", "");
    want.SetElement(elementName);
    ret = dataMgr->QueryAbilityInfosV9(want, flags, USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: QueryAbilityInfosV9_1000
 * @tc.name: test QueryAbilityInfosV9
 * @tc.desc: 1.query ability infos failed
 */
HWTEST_F(BmsBundleManagerTest, QueryAbilityInfosV9_1000, Function | MediumTest | Level1)
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

    std::vector<AbilityInfo> AbilityInfo;
    ErrCode ret = dataMgr->QueryAbilityInfosV9(want, 0, USERID, AbilityInfo);
    EXPECT_EQ(ret, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: QueryAbilityInfosV9_1100
 * @tc.name: test QueryAbilityInfosV9
 * @tc.desc: 1.query ability infos failed
 */
HWTEST_F(BmsBundleManagerTest, QueryAbilityInfosV9_1100, Function | MediumTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", "", "", "");

    std::vector<AbilityInfo> AbilityInfo;
    ErrCode ret = dataMgr->QueryAbilityInfosV9(want, 0, USERID, AbilityInfo);
    EXPECT_EQ(ret, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetApplicationInfoV9_0100
 * @tc.name: test GetApplicationInfoV9 proxy
 * @tc.desc: 1.query ability infos
 */
HWTEST_F(BmsBundleManagerTest, GetApplicationInfoV9_0100, Function | MediumTest | Level1)
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

    ApplicationInfo appInfo;
    auto ret = dataMgr->GetApplicationInfoV9(BUNDLE_BACKUP_NAME, 0, USERID, appInfo);
    EXPECT_EQ(ret, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetApplicationInfoV9_0100
 * @tc.name: test GetApplicationInfoV9 proxy
 * @tc.desc: 1.query ability infos failed by empty bundle name
 */
HWTEST_F(BmsBundleManagerTest, GetApplicationInfoV9_0200, Function | MediumTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ApplicationInfo appInfo;
    auto ret = dataMgr->GetApplicationInfoV9("", 0, USERID, appInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetApplicationInfosV9_0100
 * @tc.name: test GetApplicationInfosV9 proxy
 * @tc.desc: 1.query ability infos success
 */
HWTEST_F(BmsBundleManagerTest, GetApplicationInfosV9_0100, Function | MediumTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    std::vector<ApplicationInfo> appInfos;
    auto ret = dataMgr->GetApplicationInfosV9(0, USERID, appInfos);
    EXPECT_EQ(ret, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: FindAbilityInfoV9_0100
 * @tc.name: test FindAbilityInfoV9 proxy
 * @tc.desc: 1.find ability info success
 */
HWTEST_F(BmsBundleManagerTest, FindAbilityInfoV9_0100, Function | MediumTest | Level1)
{
    InnerBundleInfo info;
    AbilityInfo abilityInfo;
    std::string bundleName = "com.example.test";
    std::string moduleName = "module";
    std::string abilityName = "mainAbility";
    abilityInfo.bundleName = bundleName;
    abilityInfo.moduleName = moduleName;
    abilityInfo.name = abilityName;
    info.InsertAbilitiesInfo("key", abilityInfo);
    auto ret = info.FindAbilityInfoV9(bundleName, "", "");
    EXPECT_EQ(ret, std::nullopt);

    ret = info.FindAbilityInfoV9(bundleName, moduleName, abilityName);
    EXPECT_EQ((*ret).bundleName, "com.example.test");
}

/**
 * @tc.number: GetApplicationInfosV9_0200
 * @tc.name: Test GetApplicationInfoV9
 * @tc.desc: 1.Test the GetApplicationInfoV9 of InnerBundleInfo
 */
HWTEST_F(BmsBundleManagerTest, GetApplicationInfosV9_0200, Function | MediumTest | Level1)
{
    InnerBundleInfo info;
    ApplicationInfo appInfo;
    auto permissionFlag =
        static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION);
    int32_t allUserId = Constants::ALL_USERID;
    auto ret = info.GetApplicationInfoV9(permissionFlag, allUserId, appInfo);
    EXPECT_NE(ret, ERR_OK);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "entry";
    innerModuleInfo.modulePath = "/data/app/el1/bundle/public/com.ohos.test";
    innerModuleInfo.isModuleJson = true;
    std::vector<Metadata> data;
    Metadata data1;
    data1.name = "ohos.extension.forms";
    data.emplace_back(data1);
    innerModuleInfo.metadata = data;
    info.InsertInnerModuleInfo("module", innerModuleInfo);
    int32_t notExistUserId = Constants::NOT_EXIST_USERID;
    ret = info.GetApplicationInfoV9(permissionFlag, notExistUserId, appInfo);
    EXPECT_EQ(ret, ERR_OK);
    auto metaDataFlag =
        static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_METADATA);
    ret = info.GetApplicationInfoV9(metaDataFlag, notExistUserId, appInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckFilePath_0001
 * @tc.name: Test CheckFilePath
 * @tc.desc: 1.Test the CheckFilePath
 */
HWTEST_F(BmsBundleManagerTest, CheckFilePath_0001, Function | MediumTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);
    const int64_t fileSize = -1;
    const std::vector<std::string> bundlePaths;
    std::vector<std::string> realPaths;
    std::vector<std::string> hapFileList;
    bool res = BundleFileUtil::CheckFilePath(bundlePaths, realPaths);
    bool res1 = BundleFileUtil::CheckFileType("", "");
    bool res2 = BundleFileUtil::CheckFileName(OVER_MAX_SIZE);
    bool res3 = BundleFileUtil::CheckFileSize("data/test", fileSize);
    bool res4 = BundleFileUtil::GetHapFilesFromBundlePath("", hapFileList);
    bool res5 = BundleFileUtil::GetHapFilesFromBundlePath(
        "/data/service/el2/100/hmdfs/account/data/com.example.backuptest", hapFileList);
    EXPECT_EQ(res, false);
    EXPECT_EQ(res1, false);
    EXPECT_EQ(res2, false);
    EXPECT_EQ(res3, false);
    EXPECT_EQ(res4, false);
    EXPECT_EQ(res5, true);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: bundleInfosFalse_0001
 * @tc.name: test QueryLauncherAbilityInfos
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0001, Function | SmallTest | Level1)
{
    Want want;
    std::vector<AbilityInfo> abilityInfos;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->QueryLauncherAbilityInfos(want, 100, abilityInfos);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0002
 * @tc.name: test ImplicitQueryAbilityInfos
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0002, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<AbilityInfo> abilityInfos;
    int32_t appIndex = 1;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->ImplicitQueryAbilityInfos(
        want, 0, 100, abilityInfos, appIndex);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0003
 * @tc.name: test QueryAbilityInfoByUri
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0003, Function | SmallTest | Level1)
{
    AbilityInfo abilityInfo;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->QueryAbilityInfoByUri(
        Constants::DATA_ABILITY_URI_PREFIX, 100, abilityInfo);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0004
 * @tc.name: test QueryAbilityInfosByUri
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0004, Function | SmallTest | Level1)
{
    std::vector<AbilityInfo> abilityInfos;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->QueryAbilityInfosByUri(
        Constants::DATA_ABILITY_URI_PREFIX, abilityInfos);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0005
 * @tc.name: test GetApplicationInfos
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0005, Function | SmallTest | Level1)
{
    std::vector<ApplicationInfo> appInfos;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetApplicationInfos(
        0, USERID, appInfos);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0006
 * @tc.name: test GetApplicationInfosV9
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0006, Function | SmallTest | Level1)
{
    std::vector<ApplicationInfo> appInfos;
    GetBundleDataMgr()->bundleInfos_.clear();
    ErrCode testRet = GetBundleDataMgr()->GetApplicationInfosV9(
        0, USERID, appInfos);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0007
 * @tc.name: test GetBundleInfosByMetaData
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0007, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> Info;
    std::string metaData = "data/test";
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetBundleInfosByMetaData(
        metaData, Info);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0008
 * @tc.name: test GetBundleInfosByMetaData
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0008, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> Info;
    std::string metaData = "data/test";
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetBundleInfosByMetaData(
        metaData, Info);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0009
 * @tc.name: test ImplicitQueryAbilityInfosV9
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0009, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<AbilityInfo> abilityInfos;
    int32_t appIndex = 1;
    GetBundleDataMgr()->bundleInfos_.clear();
    ErrCode testRet = GetBundleDataMgr()->ImplicitQueryAbilityInfosV9(
        want, 0, 100, abilityInfos, appIndex);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0010
 * @tc.name: test GetBundleList
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0010, Function | SmallTest | Level1)
{
    std::vector<std::string> info;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetBundleList(
        info, USERID);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0011
 * @tc.name: test GetBundleInfos
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0011, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetBundleInfos(
        0, bundleInfos, USERID);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0012
 * @tc.name: test GetAllBundleInfos
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0012, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetAllBundleInfos(
        0, bundleInfos);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0013
 * @tc.name: test GetBundleInfosV9
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0013, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;
    GetBundleDataMgr()->bundleInfos_.clear();
    ErrCode testRet = GetBundleDataMgr()->GetBundleInfosV9(
        0, bundleInfos, USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0014
 * @tc.name: test GetInnerBundleInfoByUid
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0014, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    GetBundleDataMgr()->bundleInfos_.clear();
    ErrCode testRet = GetBundleDataMgr()->GetInnerBundleInfoByUid(
        2, innerBundleInfo);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0015
 * @tc.name: test QueryKeepAliveBundleInfos
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0015, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->QueryKeepAliveBundleInfos(
        bundleInfos);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0016
 * @tc.name: test GetHapModuleInfo
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0016, Function | SmallTest | Level1)
{
    AbilityInfo abilityInfo;
    HapModuleInfo hapModuleInfo;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetHapModuleInfo(
        abilityInfo, hapModuleInfo, USERID);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0017
 * @tc.name: test GetInnerBundleInfoWithFlags
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0017, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetInnerBundleInfoWithFlags(
        "bundleName", 0, info, USERID);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0018
 * @tc.name: test GetInnerBundleInfoWithFlagsV9
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0018, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    GetBundleDataMgr()->bundleInfos_.clear();
    ErrCode testRet = GetBundleDataMgr()->GetInnerBundleInfoWithFlagsV9(
        "bundleName", 0, info, USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0019
 * @tc.name: test GetInnerBundleInfoWithBundleFlagsV9
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0019, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    GetBundleDataMgr()->bundleInfos_.clear();
    ErrCode testRet = GetBundleDataMgr()->GetInnerBundleInfoWithBundleFlagsV9(
        "bundleName", 0, info, USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0020
 * @tc.name: test GetAllFormsInfo
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0020, Function | SmallTest | Level1)
{
    std::vector<FormInfo> formInfos;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetAllFormsInfo(
        formInfos);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0021
 * @tc.name: test GetFormsInfoByModule
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0021, Function | SmallTest | Level1)
{
    std::vector<FormInfo> formInfos;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetFormsInfoByModule(
        "bundleName", "moduleName", formInfos);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0022
 * @tc.name: test GetFormsInfoByApp
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0022, Function | SmallTest | Level1)
{
    std::vector<FormInfo> formInfos;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetFormsInfoByApp(
        "bundleName", formInfos);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0023
 * @tc.name: test GetAllCommonEventInfo
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0023, Function | SmallTest | Level1)
{
    std::string eventKey = "eventKey";
    std::vector<CommonEventInfo> commonEventInfos;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetAllCommonEventInfo(
        eventKey, commonEventInfos);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0024
 * @tc.name: test GetFormsInfoByApp
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0024, Function | SmallTest | Level1)
{
    std::vector<FormInfo> formInfos;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetFormsInfoByApp(
        "bundleName", formInfos);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0025
 * @tc.name: test GetInnerBundleUserInfos
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0025, Function | SmallTest | Level1)
{
    std::vector<FormInfo> formInfos;
    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetInnerBundleUserInfos(
        "bundleName", innerBundleUserInfos);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0026
 * @tc.name: test GetAccessibleAppCodePaths
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0026, Function | SmallTest | Level1)
{
    GetBundleDataMgr()->bundleInfos_.clear();
    std::vector<std::string> testRet = GetBundleDataMgr()->GetAccessibleAppCodePaths(
        USERID);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0027
 * @tc.name: test QueryExtensionAbilityInfoByUri
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0027, Function | SmallTest | Level1)
{
    ExtensionAbilityInfo extensionAbilityInfo;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->QueryExtensionAbilityInfoByUri(
        "dataability://com.example.hiworld.himusic.UserADataAbility", USERID, extensionAbilityInfo);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0028
 * @tc.name: test GetAllUriPrefix
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0028, Function | SmallTest | Level1)
{
    std::vector<std::string> uriPrefixList;
    std::string excludeModule;
    GetBundleDataMgr()->bundleInfos_.clear();
    GetBundleDataMgr()->GetAllUriPrefix(
        uriPrefixList, USERID, excludeModule);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0029
 * @tc.name: test GetRemovableBundleNameVec
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0029, Function | SmallTest | Level1)
{
    std::map<std::string, int> bundlenameAndUids;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetRemovableBundleNameVec(
        bundlenameAndUids);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: SkillFalse_0001
 * @tc.name: test MatchUriAndType
 * @tc.desc: 1.system run normally
 *           2.uris is empty
*/
HWTEST_F(BmsBundleManagerTest, SkillFalse_0001, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back("action001");
    skill.uris.clear();
    bool ret = skill.MatchUriAndType("uriString", "type");
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: SkillFalse_0002
 * @tc.name: test MatchUri
 * @tc.desc: 1.system run normally
 *           2.uris is empty
*/
HWTEST_F(BmsBundleManagerTest, SkillFalse_0002, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back("action001");
    SkillUri skillUri;
    skillUri.scheme = "scheme";
    skillUri.host = "hovst";
    skillUri.port = "port";
    skillUri.path = "";
    skillUri.pathStartWith = "";
    skillUri.pathRegex = "";
    bool ret = skill.MatchUri("uriString", skillUri);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: SkillFalse_0003
 * @tc.name: test MatchType
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, SkillFalse_0003, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back("action001");
    bool ret = skill.MatchType("*/*", "");
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: InnerBundleInfoFalse_0001
 * @tc.name: test InnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, InnerBundleInfoFalse_0001, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    InnerBundleInfo newInfo;
    bool ret = info.AddModuleInfo(newInfo);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: InnerBundleInfoFalse_0002
 * @tc.name: test InnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, InnerBundleInfoFalse_0002, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bool ret = info.GetBundleInfo(0, bundleInfo, Constants::INVALID_USERID);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: InnerBundleInfoFalse_0003
 * @tc.name: test InnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, InnerBundleInfoFalse_0003, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    int32_t flags = 0;
    ErrCode ret = info.GetBundleInfoV9(flags, bundleInfo, Constants::INVALID_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: InnerBundleInfoFalse_0004
 * @tc.name: test InnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, InnerBundleInfoFalse_0004, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    int32_t flags = 0;
    ErrCode ret = info.GetBundleInfo(flags, bundleInfo, 100);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InnerBundleInfoFalse_0005
 * @tc.name: test InnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, InnerBundleInfoFalse_0005, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.isNewVersion_ = true;
    std::string metaData = "metaData";
    bool ret = info.CheckSpecialMetaData(metaData);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InnerBundleInfoFalse_0006
 * @tc.name: test InnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, InnerBundleInfoFalse_0006, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::vector<ShortcutInfo> shortcutInfos;
    info.GetShortcutInfos(shortcutInfos);
    EXPECT_EQ(shortcutInfos.size(), 0);
}

/**
 * @tc.number: InnerBundleInfoFalse_0007
 * @tc.name: test InnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, InnerBundleInfoFalse_0007, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    AbilityInfo abilityInfo;
    bool isEnable;
    ErrCode ret = info.IsAbilityEnabledV9(abilityInfo, Constants::NOT_EXIST_USERID, isEnable);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InnerBundleInfoFalse_0008
 * @tc.name: test InnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, InnerBundleInfoFalse_0008, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    AbilityInfo abilityInfo;
    bool isEnable;
    ErrCode ret = info.IsAbilityEnabledV9(abilityInfo, USERID, isEnable);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: InnerBundleInfoFalse_0009
 * @tc.name: test InnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, InnerBundleInfoFalse_0009, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    bool isEnabled = true;
    ErrCode ret = info.SetAbilityEnabled(
        Constants::BUNDLE_NAME, Constants::MODULE_NAME,
            Constants::ABILITY_NAME, isEnabled, Constants::NOT_EXIST_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: InnerBundleInfoFalse_0010
 * @tc.name: test InnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, InnerBundleInfoFalse_0010, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.innerBundleUserInfos_.clear();
    bool enabled = true;
    ErrCode ret = info.SetApplicationEnabled(enabled, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: InnerBundleInfoFalse_0011
 * @tc.name: test InnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, InnerBundleInfoFalse_0011, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    bool ret = info.IsUserExistModule("invailed", USERID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InnerBundleInfoFalse_0012
 * @tc.name: test InnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, InnerBundleInfoFalse_0012, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::vector<std::string> uriPrefixList;
    info.GetUriPrefixList(uriPrefixList, USERID);
    EXPECT_EQ(uriPrefixList.size(), 0);
}

/**
 * @tc.number: InnerBundleInfoFalse_0013
 * @tc.name: test InnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, InnerBundleInfoFalse_0013, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::string packageName = "packageName";
    info.innerBundleUserInfos_.clear();
    std::string ret = info.GetModuleNameByPackage(packageName);
    std::string ret1 = info.GetModuleTypeByPackage(packageName);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
    EXPECT_EQ(ret1, Constants::EMPTY_STRING);
}

/**
 * @tc.number: InnerBundleInfoFalse_0014
 * @tc.name: test InnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, InnerBundleInfoFalse_0014, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::string requestPackage;
    info.innerBundleUserInfos_.clear();
    std::string cpuAbi = "";
    std::string nativeLibraryPath = "";
    bool ret = info.FetchNativeSoAttrs(requestPackage, cpuAbi, nativeLibraryPath);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InnerBundleInfoFalse_0015
 * @tc.name: test InnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, InnerBundleInfoFalse_0015, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    bool ret = info.IsLibIsolated("");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_0100
 * @tc.name: test GetBundleInfosV9 proxy
 * @tc.desc: 1.query bundle infos success
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_0100, Function | MediumTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    int32_t flags = 0;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<BundleInfo> bundleInfos;
    ErrCode ret = hostImpl->GetBundleInfosV9(
        flags, bundleInfos, USERID);
    EXPECT_EQ(ret, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: BundleMgrHostImpl_0200
 * @tc.name: test CheckIsSystemAppByUid proxy
 * @tc.desc: 1.CheckIsSystemAppByUid failed
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_0200, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    bool ret = hostImpl->CheckIsSystemAppByUid(WRONG_UID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_0300
 * @tc.name: test QueryAbilityInfos proxy
 * @tc.desc: 1.query ability infos success
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_0300, Function | MediumTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;

    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<AbilityInfo> abilityInfos;
    bool ret = hostImpl->QueryAbilityInfos(
        want, abilityInfos);
    EXPECT_EQ(ret, false);
    std::vector<AbilityInfo> abilityInfos1;
    ret = hostImpl->QueryAbilityInfos(
        want, flags, USERID, abilityInfos1);
    EXPECT_EQ(ret, true);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: BundleMgrHostImpl_0400
 * @tc.name: test QueryAllAbilityInfos proxy
 * @tc.desc: 1.query ability infos success
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_0400, Function | MediumTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;

    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<AbilityInfo> abilityInfos;
    bool ret = hostImpl->QueryAllAbilityInfos(
        want, USERID, abilityInfos);
    EXPECT_EQ(ret, true);
    std::vector<AbilityInfo> abilityInfos1;
    ret = hostImpl->QueryAbilityInfosV9(
        want, flags, USERID, abilityInfos1);
    EXPECT_EQ(ret, false);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: BundleMgrHostImpl_0500
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query ability infos success
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_0500, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<std::u16string> args;
    int fd = 8;
    int res = hostImpl->Dump(fd, args);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: BundleMgrHostImpl_0600
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query ability infos success
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_0600, Function | MediumTest | Level1)
{
    SetDataMgr();
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::set<int32_t> ret = hostImpl->GetExistsCommonUserIs();

    EXPECT_EQ(ret.size(), 1);
    ClearDataMgr();
    ret = hostImpl->GetExistsCommonUserIs();
    EXPECT_EQ(ret.size(), 0);

    SetDataMgr();
}

/**
 * @tc.number: BundleMgrHostImpl_0700
 * @tc.name: BundleMgrHostImpl
 * @tc.desc: 1.Test the interface of ConvertResourcePath
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_0700, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t appIndex = -1;
    BundleInfo info;
    ErrCode ret = hostImpl->GetSandboxBundleInfo("", appIndex, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    ret = hostImpl->GetSandboxBundleInfo("bundleName", appIndex, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    appIndex = 101;
    ret = hostImpl->GetSandboxBundleInfo("bundleName", appIndex, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    appIndex = 1;
    ret = hostImpl->GetSandboxBundleInfo(
        "bundleName", appIndex, Constants::INVALID_USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_QUERY_INVALID_USER_ID);
    ClearDataMgr();
    ret = hostImpl->GetSandboxBundleInfo("bundleName", appIndex, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR);
    SetDataMgr();
}

/**
 * @tc.number: BundleMgrHostImpl_0900
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_0900, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;
    ApplicationInfo appInfo;
    std::vector<ApplicationInfo> appInfos;

    ClearDataMgr();
    bool retBool = hostImpl->GetApplicationInfo("", flags, USERID, appInfo);
    EXPECT_EQ(retBool, false);

    ErrCode retCode = hostImpl->GetApplicationInfoV9("", flags, USERID, appInfo);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    retBool = hostImpl->GetApplicationInfos(flags, USERID, appInfos);
    EXPECT_EQ(retBool, false);

    retCode = hostImpl->GetApplicationInfosV9(flags, USERID, appInfos);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    SetDataMgr();
}

/**
 * @tc.number: BundleMgrHostImpl_1000
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_1000, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;
    int uid = -1;
    BundleInfo bundleInfo;
    BundlePackInfo bundlePackInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    std::string bundleName;
    std::vector<std::string> bundleNames;
    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    std::vector<BundleInfo> bundleInfos;

    ClearDataMgr();
    bool retBool = hostImpl->GetBundleInfo("", flags, bundleInfo, USERID);
    EXPECT_EQ(retBool, false);

    ErrCode retCode = hostImpl->GetBundleInfoV9("", flags, bundleInfo, USERID);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    retCode = hostImpl->GetBundlePackInfo("", flags, bundlePackInfo, USERID);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);

    retBool = hostImpl->GetBundleUserInfo("", USERID, innerBundleUserInfo);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->GetBundleUserInfos("", innerBundleUserInfos);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->GetBundleInfos(flags, bundleInfos, USERID);
    EXPECT_EQ(retBool, false);

    retCode = hostImpl->GetBundleInfosV9(flags, bundleInfos, USERID);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    retBool = hostImpl->GetBundleNameForUid(uid, bundleName);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->GetBundlesForUid(uid, bundleNames);
    EXPECT_EQ(retBool, false);

    sptr<IBundleEventCallback> bundleEventCallback;
    retBool = hostImpl->UnregisterBundleEventCallback(bundleEventCallback);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->RegisterBundleEventCallback(bundleEventCallback);
    EXPECT_EQ(retBool, false);

    sptr<IBundleStatusCallback> bundleStatusCallback;
    retBool = hostImpl->ClearBundleStatusCallback(bundleStatusCallback);
    EXPECT_EQ(retBool, false);

    SetDataMgr();
}

/**
 * @tc.number: BundleMgrHostImpl_1100
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_1100, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int uid = -1;
    std::string bundleName;
    std::vector<int> gids;
    std::vector<BundleInfo> bundleInfos;

    ClearDataMgr();
    ErrCode retCode = hostImpl->GetNameForUid(uid, bundleName);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    bool retBool = hostImpl->GetBundleGids("", gids);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->GetBundleGidsByUid("", uid, gids);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->CheckIsSystemAppByUid(uid);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->GetBundleInfosByMetaData("", bundleInfos);
    EXPECT_EQ(retBool, false);

    SetDataMgr();
}

/**
 * @tc.number: BundleMgrHostImpl_1200
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_1200, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;
    std::vector<AbilityInfo> abilityInfos;
    Want want;
    AbilityInfo abilityInfo;

    ClearDataMgr();
    bool retBool = hostImpl->QueryAbilityInfo(want, flags, USERID, abilityInfo);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->QueryAbilityInfos(want, flags, USERID, abilityInfos);
    EXPECT_EQ(retBool, false);

    ErrCode retCode = hostImpl->QueryAbilityInfosV9(want, flags, USERID, abilityInfos);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    retBool = hostImpl->QueryAllAbilityInfos(want, USERID, abilityInfos);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->QueryAbilityInfoByUri("", abilityInfo);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->QueryAbilityInfosByUri("", abilityInfos);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->QueryAbilityInfoByUri("", USERID, abilityInfo);
    EXPECT_EQ(retBool, false);

    SetDataMgr();
}

/**
 * @tc.number: BundleMgrHostImpl_1300
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_1300, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string label;
    std::vector<BundleInfo> bundleInfos;
    Want want;
    HapModuleInfo hapModuleInfo;
    AbilityInfo abilityInfo;
    abilityInfo.bundleName = "bundleName";
    abilityInfo.package = "package";

    ClearDataMgr();
    bool retBool = hostImpl->QueryKeepAliveBundleInfos(bundleInfos);
    EXPECT_EQ(retBool, false);

    std::string retString = hostImpl->GetAbilityLabel("", "");
    EXPECT_EQ(retString, Constants::EMPTY_STRING);

    ErrCode retCode = hostImpl->GetAbilityLabel("", "", "", label);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_SERVICE_NOT_READY);

    retBool = hostImpl->GetHapModuleInfo(abilityInfo, USERID, hapModuleInfo);
    EXPECT_EQ(retBool, false);

    retCode = hostImpl->GetLaunchWantForBundle("", want, USERID);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    SetDataMgr();
}

/**
 * @tc.number: BundleMgrHostImpl_1200
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_1400, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t upgradeFlag = 0;
    std::string result;
    bool isRemovable = true;

    ClearDataMgr();
    bool retBool = hostImpl->UnregisterBundleStatusCallback();
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->DumpAllBundleInfoNamesByUserId(USERID, result);
    EXPECT_EQ(retBool, false);

    ErrCode retCode = hostImpl->IsModuleRemovable("", "", isRemovable);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);

    retBool = hostImpl->SetModuleRemovable("", "", isRemovable);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->GetModuleUpgradeFlag("", "");
    EXPECT_EQ(retBool, false);

    retCode = hostImpl->SetModuleUpgradeFlag("", "", upgradeFlag);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);

    SetDataMgr();
}

/**
 * @tc.number: BundleMgrHostImpl_1500
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_1500, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool isRemovable = true;
    std::vector<FormInfo> formInfos;
    std::vector<ShortcutInfo> shortcutInfos;
    std::vector<CommonEventInfo> commonEventInfos;
    AbilityInfo abilityInfo;

    ClearDataMgr();
    ErrCode retCode = hostImpl->IsApplicationEnabled("", isRemovable);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_SERVICE_NOT_READY);

    retCode = hostImpl->SetApplicationEnabled("", isRemovable, USERID);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_SERVICE_NOT_READY);

    retCode = hostImpl->IsAbilityEnabled(abilityInfo, isRemovable);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_SERVICE_NOT_READY);

    bool retBool = hostImpl->GetAllFormsInfo(formInfos);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->GetFormsInfoByApp("", formInfos);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->GetShortcutInfos("", USERID, shortcutInfos);
    EXPECT_EQ(retBool, false);

    retCode = hostImpl->GetShortcutInfoV9("", shortcutInfos);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    retBool = hostImpl->GetAllCommonEventInfo("", commonEventInfos);
    EXPECT_EQ(retBool, false);

    SetDataMgr();
}

/**
 * @tc.number: BundleMgrHostImpl_1600
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_1600, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    Want want;

    ClearDataMgr();
    bool retBool = hostImpl->QueryExtensionAbilityInfos(want, flags, USERID, extensionInfos);
    EXPECT_EQ(retBool, false);

    ErrCode retCode = hostImpl->QueryExtensionAbilityInfosV9(want, flags, USERID, extensionInfos);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    retBool = hostImpl->QueryExtensionAbilityInfos(
        want, ExtensionAbilityType::BACKUP, flags, USERID, extensionInfos);
    EXPECT_EQ(retBool, false);

    retCode = hostImpl->QueryExtensionAbilityInfosV9(
        want, ExtensionAbilityType::BACKUP, flags, USERID, extensionInfos);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    retBool = hostImpl->QueryExtensionAbilityInfos(ExtensionAbilityType::BACKUP, USERID, extensionInfos);
    EXPECT_EQ(retBool, false);

    SetDataMgr();
}

/**
 * @tc.number: BundleMgrHostImpl_1600
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_1700, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ExtensionAbilityInfo extensionAbilityInfo;

    ClearDataMgr();
    hostImpl->GetAccessibleAppCodePaths(USERID);
    std::string retString = hostImpl->GetAppPrivilegeLevel("", USERID);
    EXPECT_EQ(retString, Constants::EMPTY_STRING);

    bool retBool = hostImpl->QueryExtensionAbilityInfoByUri("", USERID, extensionAbilityInfo);
    EXPECT_EQ(retBool, false);

    retString = hostImpl->GetAppIdByBundleName("", USERID);
    EXPECT_EQ(retString, Constants::EMPTY_STRING);

    retString = hostImpl->GetAppType("");
    EXPECT_EQ(retString, Constants::EMPTY_STRING);

    auto res = hostImpl->GetUidByBundleName("", USERID);
    EXPECT_EQ(res, Constants::INVALID_UID);

    SetDataMgr();
}

/**
 * @tc.number: BundleMgrHostImpl_1800
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_1800, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    std::vector<std::string> dependentModuleNames;
    Want want;
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;

    ClearDataMgr();
    bool retBool = hostImpl->ImplicitQueryInfoByPriority(
        want, flags, USERID, abilityInfo, extensionInfo);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->ImplicitQueryInfos(
        want, flags, USERID, abilityInfos, extensionInfos);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->GetAllDependentModuleNames(
        "", "", dependentModuleNames);
    EXPECT_EQ(retBool, false);

    SetDataMgr();
}

/**
 * @tc.number: BundleMgrHostImpl_1900
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_1900, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t status = 0;
    uint32_t resId = 0;
    int32_t appIndex = 1;
    size_t len = 1;
    bool isEnabled = true;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    std::unique_ptr<uint8_t[]> mediaDataPtr;
    Want want;
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    HapModuleInfo hapModuleInfo;

    ClearDataMgr();
    bool retBool = hostImpl->SetDisposedStatus("", status);
    EXPECT_EQ(retBool, false);

    int32_t retInt = hostImpl->GetDisposedStatus("");
    EXPECT_EQ(retInt, Constants::DEFAULT_DISPOSED_STATUS);

    std::string retString = hostImpl->GetStringById("", "", resId, USERID, "");
    EXPECT_EQ(retString, Constants::EMPTY_STRING);

    retString = hostImpl->GetIconById("", "", resId, resId, USERID);
    EXPECT_EQ(retString, Constants::EMPTY_STRING);

    ErrCode retCode = hostImpl->GetSandboxAbilityInfo(
        want, appIndex, status, USERID, abilityInfo);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR);

    retCode = hostImpl->GetSandboxExtAbilityInfos(
        want, appIndex, status, USERID, extensionInfos);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR);

    retCode = hostImpl->GetSandboxHapModuleInfo(
        abilityInfo, appIndex, USERID, hapModuleInfo);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR);

    retCode = hostImpl->GetMediaData(
        "", "", "", mediaDataPtr, len, USERID);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    int res1 = hostImpl->CheckPublicKeys("", "");
    EXPECT_EQ(res1, false);

    retCode = hostImpl->SetApplicationEnabled("", isEnabled, USERID);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_SERVICE_NOT_READY);

    retCode = hostImpl->SetAbilityEnabled(abilityInfo, isEnabled, USERID);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_SERVICE_NOT_READY);

    std::vector<FormInfo> formInfos;
    retBool = hostImpl->GetFormsInfoByModule(
        "bundleName", "moduleName", formInfos);
    EXPECT_EQ(retBool, false);
    SetDataMgr();
}

/**
 * @tc.number: BundleMgrHostImpl_2000
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetBundleArchiveInfoV9
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_2000, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;
    BundleInfo bundleInfo;
    ErrCode retCode = hostImpl->GetBundleArchiveInfoV9("", flags, bundleInfo);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INVALID_HAP_PATH);
    retCode = hostImpl->GetBundleArchiveInfoV9("/data/storage/el2/base/noExist", flags, bundleInfo);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    retCode = hostImpl->GetBundleArchiveInfoV9("/data/storage/el2/base", flags, bundleInfo);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BundleMgrHostImpl_2100
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetBundleArchiveInfoBySandBoxPath
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_2100, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;
    BundleInfo bundleInfo;
    ErrCode retCode = hostImpl->GetBundleArchiveInfoBySandBoxPath("", flags, bundleInfo, true);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    retCode = hostImpl->GetBundleArchiveInfoBySandBoxPath("/data/storage/el2/base/", flags, bundleInfo, true);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    retCode = hostImpl->GetBundleArchiveInfoBySandBoxPath("/data/storage/el2/base", flags, bundleInfo, false);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BundleMgrHostImpl_2200
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test BundleMgrHostImpl
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_2200, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    AbilityInfo abilityInfo;
    HapModuleInfo hapModuleInfo;
    abilityInfo.bundleName = "";
    abilityInfo.package = "";
    bool ret = hostImpl->GetHapModuleInfo(abilityInfo, USERID, hapModuleInfo);
    EXPECT_EQ(ret, false);

    abilityInfo.bundleName = "bundleName";
    ret = hostImpl->GetHapModuleInfo(abilityInfo, USERID, hapModuleInfo);
    EXPECT_EQ(ret, false);

    abilityInfo.bundleName = "";
    abilityInfo.package = "package";
    ret = hostImpl->GetHapModuleInfo(abilityInfo, USERID, hapModuleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_2300
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test CleanBundleCacheFiles
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_2300, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ErrCode ret = hostImpl->CleanBundleCacheFiles("", nullptr, Constants::INVALID_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: BundleMgrHostImpl_2400
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test DumpBundleInfo
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_2400, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string result;
    bool ret = hostImpl->DumpBundleInfo("", Constants::ALL_USERID, result);
    EXPECT_EQ(ret, false);
    ret = hostImpl->DumpBundleInfo("bundleName", Constants::ALL_USERID, result);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_2500
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test DumpShortcutInfo
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_2500, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string result;
    bool ret = hostImpl->DumpShortcutInfo("", Constants::ALL_USERID, result);
    EXPECT_EQ(ret, false);
    ret = hostImpl->DumpShortcutInfo("bundleName", Constants::ALL_USERID, result);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_2600
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetAppType
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_2600, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    DistributedBundleInfo distributedBundleInfo;
    bool ret = hostImpl->GetDistributedBundleInfo("", "", distributedBundleInfo);
    EXPECT_EQ(ret, false);
    std::string retString = hostImpl->GetAppType("");
    EXPECT_EQ(retString, Constants::EMPTY_STRING);
}

/**
 * @tc.number: BundleMgrHostImpl_2700
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test BundleMgrHostImpl
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_2700, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string bundleName;
    bool ret = hostImpl->ObtainCallingBundleName(bundleName);
    EXPECT_EQ(ret, false);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    ret = hostImpl->QueryExtensionAbilityInfos(
        ExtensionAbilityType::BACKUP, Constants::INVALID_USERID, extensionInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_2800
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test BundleMgrHostImpl
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_2800, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<int64_t> bundleStats;
    bool ret = hostImpl->GetBundleStats("", Constants::INVALID_USERID, bundleStats);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_2900
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetUdidByNetworkId
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_2900, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string udid;
    int32_t ret = hostImpl->GetUdidByNetworkId("", udid);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.number: BundleMgrHostImpl_3000
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test QueryAbilityInfo
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_3000, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    AAFwk::Want want;
    AbilityInfo abilityInfo;
    sptr<IRemoteObject> callBack;
    bool ret = hostImpl->QueryAbilityInfo(
        want, 0, Constants::INVALID_USERID, abilityInfo, callBack);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_3100
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test CheckAbilityEnableInstall
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_3100, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    AAFwk::Want want;
    AbilityInfo abilityInfo;
    sptr<IRemoteObject> callBack;
    bool ret = hostImpl->CheckAbilityEnableInstall(want, 0, 0, callBack);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_3200
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetBundleArchiveInfoV9
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_3200, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;
    BundleInfo bundleInfo;
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode retCode = hostImpl->GetBundleArchiveInfoV9(bundlePath, flags, bundleInfo);
    EXPECT_EQ(retCode, ERR_OK);
}

/**
 * @tc.number: BundleMgrHostImpl_3300
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetPermissionDef
 */
HWTEST_F(BmsBundleManagerTest, BundleMgrHostImpl_3300, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    PermissionDef permissionDef;
    ErrCode retCode = hostImpl->GetPermissionDef("", permissionDef);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_QUERY_PERMISSION_DEFINE_FAILED);
    retCode = hostImpl->GetPermissionDef("permissionDef", permissionDef);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_QUERY_PERMISSION_DEFINE_FAILED);
}

/**
 * @tc.number: TestMgrByUserId_0001
 * @tc.name: test ImplicitQueryAbilityInfos
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0001, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", "", "", MODULE_NAME);
    std::vector<AbilityInfo> abilityInfos;
    int32_t appIndex = 1;
    bool testRet = GetBundleDataMgr()->ImplicitQueryAbilityInfos(
        want, 0, 100, abilityInfos, appIndex);
    EXPECT_EQ(testRet, true);
    testRet = GetBundleDataMgr()->ImplicitQueryAbilityInfos(
        want, 0, Constants::INVALID_USERID, abilityInfos, appIndex);
    EXPECT_EQ(testRet, false);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: TestMgrByUserId_0002
 * @tc.name: test ImplicitQueryAbilityInfosV9
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0002, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", "", "", MODULE_NAME);
    std::vector<AbilityInfo> abilityInfos;
    int32_t appIndex = 1;
    ErrCode testRet = GetBundleDataMgr()->ImplicitQueryAbilityInfosV9(
        want, 0, 100, abilityInfos, appIndex);
    EXPECT_EQ(testRet, ERR_OK);
    testRet = GetBundleDataMgr()->ImplicitQueryAbilityInfosV9(
        want, 0, Constants::INVALID_USERID, abilityInfos, appIndex);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: TestMgrByUserId_0003
 * @tc.name: test QueryLauncherAbilityInfos
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0003, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", "", "", MODULE_NAME);
    std::vector<AbilityInfo> abilityInfos;
    bool testRet = GetBundleDataMgr()->QueryLauncherAbilityInfos(want, 100, abilityInfos);
    EXPECT_EQ(testRet, true);
    testRet = GetBundleDataMgr()->QueryLauncherAbilityInfos(want, Constants::INVALID_USERID, abilityInfos);
    EXPECT_EQ(testRet, false);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: TestMgrByUserId_0004
 * @tc.name: test IsAppOrAbilityInstalled
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0004, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    bool testRet = GetBundleDataMgr()->IsAppOrAbilityInstalled("");
    EXPECT_EQ(testRet, false);
    testRet = GetBundleDataMgr()->IsAppOrAbilityInstalled(BUNDLE_BACKUP_NAME);
    EXPECT_EQ(testRet, true);
    testRet = GetBundleDataMgr()->IsAppOrAbilityInstalled("bundlename");
    EXPECT_EQ(testRet, false);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: TestMgrByUserId_0005
 * @tc.name: test StoreSandboxPersistentInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0005, Function | SmallTest | Level1)
{
    SandboxAppPersistentInfo info;

    GetBundleDataMgr()->StoreSandboxPersistentInfo("", info);
    EXPECT_EQ(info.appIndex, 0);
    GetBundleDataMgr()->DeleteSandboxPersistentInfo("", info);
    EXPECT_EQ(info.appIndex, 0);
}

/**
 * @tc.number: TestMgrByUserId_0006
 * @tc.name: test CheckPublicKeys
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0006, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);
    std::string bundlePath1 = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult1 = InstallThirdPartyBundle(bundlePath1);
    EXPECT_EQ(installResult1, ERR_OK);

    int res = GetBundleDataMgr()->CheckPublicKeys("", "secondBundleName");
    int res1 = GetBundleDataMgr()->CheckPublicKeys("firstBundleName", "");
    int res2 = GetBundleDataMgr()->CheckPublicKeys("", "");
    int res3 = GetBundleDataMgr()->CheckPublicKeys(BUNDLE_BACKUP_NAME, BUNDLE_PREVIEW_NAME);
    EXPECT_EQ(res, Constants::SIGNATURE_UNKNOWN_BUNDLE);
    EXPECT_EQ(res1, Constants::SIGNATURE_UNKNOWN_BUNDLE);
    EXPECT_EQ(res2, Constants::SIGNATURE_UNKNOWN_BUNDLE);
    EXPECT_EQ(res3, 0);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.number: TestMgrByUserId_0007
 * @tc.name: test GetPreInstallBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0007, Function | SmallTest | Level1)
{
    PreInstallBundleInfo preInstallBundleInfo;
    bool res = GetBundleDataMgr()->GetPreInstallBundleInfo("", preInstallBundleInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: TestMgrByUserId_0008
 * @tc.name: test GetInnerBundleUserInfos
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0008, Function | SmallTest | Level1)
{
    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    bool res = GetBundleDataMgr()->GetInnerBundleUserInfos("", innerBundleUserInfos);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: TestMgrByUserId_0009
 * @tc.name: test GetInnerBundleUserInfos
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0009, Function | SmallTest | Level1)
{
    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    bool res = GetBundleDataMgr()->GetInnerBundleUserInfos("", innerBundleUserInfos);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: TestMgrByUserId_0010
 * @tc.name: test ImplicitQueryExtensionInfosV9
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0010, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", "", "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t appIndex = 1;
    bool testRet = GetBundleDataMgr()->ImplicitQueryExtensionInfos(
        want, 0, 100, extensionInfos, appIndex);
    EXPECT_EQ(testRet, true);
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    testRet = GetBundleDataMgr()->ImplicitQueryExtensionInfos(
        want, 0, Constants::INVALID_USERID, extensionInfos, appIndex);
    EXPECT_EQ(testRet, false);
    ErrCode testRet1 = GetBundleDataMgr()->ImplicitQueryExtensionInfosV9(
        want, 0, Constants::INVALID_USERID, extensionInfos, appIndex);
    EXPECT_EQ(testRet1, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    testRet1 = GetBundleDataMgr()->ImplicitQueryExtensionInfosV9(
        want, 0, 100, extensionInfos, appIndex);
    EXPECT_NE(testRet1, ERR_OK);
}

/**
 * @tc.number: TestMgrByUserId_0011
 * @tc.name: test UpdatePrivilegeCapability and UpdateRemovable
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0011, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    ApplicationInfo appInfo;
    GetBundleDataMgr()->UpdateRemovable("", true);
    GetBundleDataMgr()->UpdatePrivilegeCapability("", appInfo);
    EXPECT_EQ(appInfo.bundleName, "");

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: TestMgrByUserId_0012
 * @tc.name: test FetchInnerBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0012, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    bool res = GetBundleDataMgr()->FetchInnerBundleInfo("", innerBundleInfo);
    EXPECT_EQ(res, false);
    res = GetBundleDataMgr()->FetchInnerBundleInfo("", innerBundleInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: TestMgrByUserId_0013
 * @tc.name: test ExplicitQueryAbilityInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0013, Function | SmallTest | Level1)
{
    Want want;
    int32_t flags = 0;
    std::vector<AbilityInfo> abilityInfos;
    InnerBundleInfo innerBundleInfo;
    GetBundleDataMgr()->GetMatchLauncherAbilityInfos(want, innerBundleInfo, abilityInfos, Constants::INVALID_USERID);
    bool res = GetBundleDataMgr()->QueryAbilityInfos(
        want, flags, Constants::INVALID_USERID, abilityInfos);
    EXPECT_EQ(res, false);
    AbilityInfo abilityInfo;
    int32_t appIndex = 1;
    res = GetBundleDataMgr()->ExplicitQueryAbilityInfo(
        want, flags, Constants::INVALID_USERID, abilityInfo, appIndex);
    EXPECT_EQ(res, false);
    ErrCode ret = GetBundleDataMgr()->ExplicitQueryAbilityInfoV9(
        want, flags, Constants::INVALID_USERID, abilityInfo, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: TestMgrByUserId_0014
 * @tc.name: test QueryAbilityInfoByUri
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0014, Function | SmallTest | Level1)
{
    AbilityInfo abilityInfo;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfoByUri(
        Constants::DATA_ABILITY_URI_PREFIX, Constants::INVALID_USERID, abilityInfo);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: TestMgrByUserId_0015
 * @tc.name: test GetApplicationInfos
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0015, Function | SmallTest | Level1)
{
    ApplicationInfo appInfo;
    std::vector<ApplicationInfo> appInfos;
    bool testRet = GetBundleDataMgr()->GetApplicationInfo(
        "bundleName", 0, Constants::INVALID_USERID, appInfo);
    EXPECT_EQ(testRet, false);
    testRet = GetBundleDataMgr()->GetApplicationInfos(
        0, Constants::INVALID_USERID, appInfos);
    EXPECT_EQ(testRet, false);
    ErrCode testRet1 = GetBundleDataMgr()->GetApplicationInfosV9(
        0, Constants::INVALID_USERID, appInfos);
    EXPECT_EQ(testRet1, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: TestMgrByUserId_0016
 * @tc.name: test GetBundleInfoV9
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0016, Function | SmallTest | Level1)
{
    BundleInfo bundleInfo;
    std::vector<ApplicationInfo> appInfos;
    bool testRet = GetBundleDataMgr()->GetBundleInfo(
        "bundleName", 0, bundleInfo, Constants::INVALID_USERID);
    EXPECT_EQ(testRet, false);
    ErrCode testRet1 = GetBundleDataMgr()->GetBundleInfoV9(
        "bundleName", 0, bundleInfo, Constants::INVALID_USERID);
    EXPECT_EQ(testRet1, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    testRet1 = GetBundleDataMgr()->GetBundleInfoV9(
        "bundleName", 0, bundleInfo, Constants::ANY_USERID);
    EXPECT_EQ(testRet1, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: TestMgrByUserId_0017
 * @tc.name: test GetBundleInfos
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0017, Function | SmallTest | Level1)
{
    std::vector<std::string> appInfos;
    std::vector<BundleInfo> bundleInfos;
    bool testRet = GetBundleDataMgr()->GetBundleList(
        appInfos, Constants::INVALID_USERID);
    EXPECT_EQ(testRet, false);
    testRet = GetBundleDataMgr()->GetBundleInfos(
        0, bundleInfos, Constants::ALL_USERID);
    bool testRet1 = GetBundleDataMgr()->GetAllBundleInfos(
        0, bundleInfos);
    EXPECT_EQ(testRet, testRet1);
}

/**
 * @tc.number: TestMgrByUserId_0018
 * @tc.name: test GetBundleInfosV9
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0018, Function | SmallTest | Level1)
{
    std::vector<std::string> appInfos;
    std::vector<BundleInfo> bundleInfos;
    ErrCode testRet = GetBundleDataMgr()->GetBundleInfosV9(
        0, bundleInfos, Constants::ALL_USERID);
    ErrCode testRet1 = GetBundleDataMgr()->GetAllBundleInfosV9(
        0, bundleInfos);
    EXPECT_EQ(testRet, testRet1);
    testRet = GetBundleDataMgr()->GetBundleInfosV9(
        0, bundleInfos, Constants::INVALID_USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: TestMgrByUserId_0020
 * @tc.name: test GetInnerBundleInfoWithBundleFlagsV9
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0020, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    ErrCode testRet = GetBundleDataMgr()->GetInnerBundleInfoWithFlagsV9(
        "bundleName", 0, info, Constants::INVALID_USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    testRet = GetBundleDataMgr()->GetInnerBundleInfoWithBundleFlagsV9(
        "bundleName", 0, info, Constants::INVALID_USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: TestMgrByUserId_0021
 * @tc.name: test SetAbilityEnabled
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0021, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    ErrCode testRet = GetBundleDataMgr()->SetApplicationEnabled(
        "bundleName", false, Constants::INVALID_USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    AbilityInfo abilityInfo;
    testRet = GetBundleDataMgr()->SetAbilityEnabled(
        abilityInfo, false, Constants::INVALID_USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    testRet = GetBundleDataMgr()->SetAbilityEnabled(
        abilityInfo, false, Constants::UNSPECIFIED_USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: TestMgrByUserId_0022
 * @tc.name: test GetShortcutInfoV9
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0022, Function | SmallTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    bool testRet = GetBundleDataMgr()->GetShortcutInfos(
        "bundleName", Constants::INVALID_USERID, shortcutInfos);
    EXPECT_EQ(testRet, false);
    ErrCode testRet1 = GetBundleDataMgr()->GetShortcutInfoV9(
        "bundleName", Constants::INVALID_USERID, shortcutInfos);
    EXPECT_EQ(testRet1, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: TestMgrByUserId_0023
 * @tc.name: test GetInnerBundleUserInfoByUserId
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0023, Function | SmallTest | Level1)
{
    InnerBundleUserInfo innerBundleUserInfo;
    bool testRet = GetBundleDataMgr()->GetInnerBundleUserInfoByUserId(
        "bundleName", Constants::INVALID_USERID, innerBundleUserInfo);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: TestMgrByUserId_0024
 * @tc.name: test ExplicitQueryExtensionInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0024, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", "", "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t appIndex = 1;
    bool testRet = GetBundleDataMgr()->QueryExtensionAbilityInfos(
        want, 0, Constants::INVALID_USERID, extensionInfos, appIndex);
    EXPECT_EQ(testRet, false);
    testRet = GetBundleDataMgr()->QueryExtensionAbilityInfos(
        want, 0, USERID, extensionInfos, appIndex);
    EXPECT_EQ(testRet, false);
    ExtensionAbilityInfo extensionInfo;
    testRet = GetBundleDataMgr()->ExplicitQueryExtensionInfo(
        want, 0, Constants::INVALID_USERID, extensionInfo, appIndex);
    EXPECT_EQ(testRet, false);
    ErrCode testRet1 = GetBundleDataMgr()->ExplicitQueryExtensionInfoV9(
        want, 0, Constants::INVALID_USERID, extensionInfo, appIndex);
    EXPECT_EQ(testRet1, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: TestMgrByUserId_0025
 * @tc.name: test ImplicitQueryInfoByPriority
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0025, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    bool testRet = GetBundleDataMgr()->ImplicitQueryInfoByPriority(
        want, 0, Constants::INVALID_USERID, abilityInfo, extensionInfo);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: TestMgrByUserId_0026
 * @tc.name: test QueryExtensionAbilityInfoByUri
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0026, Function | SmallTest | Level1)
{
    ExtensionAbilityInfo extensionAbilityInfo;
    bool testRet = GetBundleDataMgr()->QueryExtensionAbilityInfoByUri(
        "dataability://com.example.hiworld.himusic.UserADataAbility",
            USERID, extensionAbilityInfo);
    EXPECT_EQ(testRet, false);
    testRet = GetBundleDataMgr()->QueryExtensionAbilityInfoByUri(
        "", USERID, extensionAbilityInfo);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: TestMgrByUserId_0027
 * @tc.name: test CheckInnerBundleInfoWithFlags
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, TestMgrByUserId_0027, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ErrCode testRet = GetBundleDataMgr()->CheckInnerBundleInfoWithFlags(
        innerBundleInfo, ApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE, USERID);
    EXPECT_EQ(testRet, ERR_OK);
    testRet = GetBundleDataMgr()->CheckInnerBundleInfoWithFlags(
        innerBundleInfo,
            ApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE, Constants::INVALID_USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0001
 * @tc.name: test QueryLauncherAbilityInfos
 * @tc.desc: 1.system run normally
 *           2.bundle is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0001, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<AbilityInfo> abilityInfos;
    bool testRet = GetBundleDataMgr()->QueryLauncherAbilityInfos(
        want, USERID, abilityInfos);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0002
 * @tc.name: test GetHapModuleInfo
 * @tc.desc: 1.system run normally
 *           2.bundle is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0002, Function | SmallTest | Level1)
{
    AbilityInfo abilityInfo;
    HapModuleInfo hapModuleInfo;
    bool testRet = GetBundleDataMgr()->GetHapModuleInfo(
        abilityInfo, hapModuleInfo, USERID);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0004
 * @tc.name: test GetInnerBundleInfoWithFlags
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0004, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    bool testRet = GetBundleDataMgr()->GetInnerBundleInfoWithFlags(
        "bundleName", 0, info, USERID);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0005
 * @tc.name: test GetInnerBundleInfoWithFlagsV9
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0005, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    ErrCode testRet = GetBundleDataMgr()->GetInnerBundleInfoWithFlagsV9(
        "bundleName", 0, info, USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0006
 * @tc.name: test GetInnerBundleInfoWithBundleFlagsV9
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0006, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    ErrCode testRet = GetBundleDataMgr()->GetInnerBundleInfoWithBundleFlagsV9(
        "bundleName", 0, info, USERID);
    EXPECT_NE(testRet, ERR_OK);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0007
 * @tc.name: test GetInnerBundleInfo
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0007, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    bool testRet = GetBundleDataMgr()->GetInnerBundleInfo(
        "bundleName", info);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0008
 * @tc.name: test EnableBundle
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0008, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    bool testRet = GetBundleDataMgr()->EnableBundle(
        "bundleName");
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0009
 * @tc.name: test SetApplicationEnabled
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0009, Function | SmallTest | Level1)
{
    bool isEnable = true;
    ErrCode testRet = GetBundleDataMgr()->SetApplicationEnabled(
        "bundleName", isEnable, USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0010
 * @tc.name: test IsModuleRemovable
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0010, Function | SmallTest | Level1)
{
    bool isRemovable;
    ErrCode testRet = GetBundleDataMgr()->IsModuleRemovable(
        "bundleName", MODULE_NAME, isRemovable);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0011
 * @tc.name: test IsAbilityEnabled and SetAbilityEnabled
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0011, Function | SmallTest | Level1)
{
    bool isEnable = true;
    AbilityInfo abilityInfo;
    ErrCode testRet = GetBundleDataMgr()->IsAbilityEnabled(
        abilityInfo, isEnable);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    testRet = GetBundleDataMgr()->SetAbilityEnabled(
        abilityInfo, isEnable, USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0012
 * @tc.name: test SetModuleUpgradeFlag
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0012, Function | SmallTest | Level1)
{
    int32_t upgradeFlag = 1;
    ErrCode testRet = GetBundleDataMgr()->SetModuleUpgradeFlag(
        "bundleName", MODULE_NAME, upgradeFlag);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0013
 * @tc.name: test GetModuleUpgradeFlag
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0013, Function | SmallTest | Level1)
{
    int32_t testRet = GetBundleDataMgr()->GetModuleUpgradeFlag(
        "bundleName", MODULE_NAME);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0014
 * @tc.name: test GetInnerBundleUserInfoByUserId
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0014, Function | SmallTest | Level1)
{
    InnerBundleUserInfo info;
    bool testRet = GetBundleDataMgr()->GetInnerBundleUserInfoByUserId(
        "bundleName", USERID, info);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0015
 * @tc.name: test GetInnerBundleUserInfos
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0015, Function | SmallTest | Level1)
{
    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    bool testRet = GetBundleDataMgr()->GetInnerBundleUserInfos(
        "bundleName", innerBundleUserInfos);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0016
 * @tc.name: test GetAllDependentModuleNames
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0016, Function | SmallTest | Level1)
{
    std::vector<std::string> dependentModuleNames;
    bool testRet = GetBundleDataMgr()->GetAllDependentModuleNames(
        "bundleName", MODULE_NAME, dependentModuleNames);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0017
 * @tc.name: test SetDisposedStatus and GetDisposedStatus
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0017, Function | SmallTest | Level1)
{
    int32_t status = 1;
    bool testRet = GetBundleDataMgr()->SetDisposedStatus(
        "", status);
    EXPECT_EQ(testRet, false);
    testRet = GetBundleDataMgr()->GetDisposedStatus(
        "");
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0018
 * @tc.name: test FetchInnerBundleInfo
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetMgrFalseByNoBundle_0018, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    bool testRet = GetBundleDataMgr()->FetchInnerBundleInfo(
        "bundleName", innerBundleInfo);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetBundleDataMgr_0001
 * @tc.name: test ExplicitQueryAbilityInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0001, Function | SmallTest | Level1)
{
    Want want;
    int32_t flags = 0;
    AbilityInfo abilityInfo;
    int32_t appIndex = 1;
    bool res = GetBundleDataMgr()->ExplicitQueryAbilityInfo(
        want, flags, USERID, abilityInfo, appIndex);
    EXPECT_EQ(res, false);
    GetBundleDataMgr()->sandboxAppHelper_ = nullptr;
    res = GetBundleDataMgr()->ExplicitQueryAbilityInfo(
        want, flags, USERID, abilityInfo, appIndex);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetBundleDataMgr_0002
 * @tc.name: test ExplicitQueryAbilityInfoV9
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0002, Function | SmallTest | Level1)
{
    Want want;
    int32_t flags = 0;
    AbilityInfo abilityInfo;
    int32_t appIndex = 1;
    ErrCode res = GetBundleDataMgr()->ExplicitQueryAbilityInfoV9(
        want, flags, USERID, abilityInfo, appIndex);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    GetBundleDataMgr()->sandboxAppHelper_ = nullptr;
    res = GetBundleDataMgr()->ExplicitQueryAbilityInfoV9(
        want, flags, USERID, abilityInfo, appIndex);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: GetBundleDataMgr_0003
 * @tc.name: test ImplicitQueryCurAbilityInfos
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0003, Function | SmallTest | Level1)
{
    Want want;
    int32_t flags = 0;
    std::vector<AbilityInfo> abilityInfo;
    int32_t appIndex = 0;
    bool res = GetBundleDataMgr()->ImplicitQueryCurAbilityInfos(
        want, flags, USERID, abilityInfo, appIndex);
    EXPECT_EQ(res, false);
    appIndex = 1;
    res = GetBundleDataMgr()->ImplicitQueryCurAbilityInfos(
        want, flags, USERID, abilityInfo, appIndex);
    EXPECT_EQ(res, false);
    GetBundleDataMgr()->sandboxAppHelper_ = nullptr;
    res = GetBundleDataMgr()->ImplicitQueryCurAbilityInfos(
        want, flags, USERID, abilityInfo, appIndex);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetBundleDataMgr_0004
 * @tc.name: test ImplicitQueryCurAbilityInfosV9
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0004, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    int32_t flags = 0;
    std::vector<AbilityInfo> abilityInfo;
    int32_t appIndex = 0;
    ErrCode res = GetBundleDataMgr()->ImplicitQueryCurAbilityInfosV9(
        want, flags, USERID, abilityInfo, appIndex);
    EXPECT_EQ(res, ERR_OK);
    appIndex = 1;
    res = GetBundleDataMgr()->ImplicitQueryCurAbilityInfosV9(
        want, flags, USERID, abilityInfo, appIndex);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    GetBundleDataMgr()->sandboxAppHelper_ = nullptr;
    res = GetBundleDataMgr()->ImplicitQueryCurAbilityInfosV9(
        want, flags, USERID, abilityInfo, appIndex);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetBundleDataMgr_0005
 * @tc.name: test ImplicitQueryAllAbilityInfos
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0005, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);

    int32_t flags = 0;
    std::vector<AbilityInfo> abilityInfo;
    int32_t appIndex = 1;
    GetBundleDataMgr()->ImplicitQueryAllAbilityInfos(
        want, flags, USERID, abilityInfo, appIndex);
    GetBundleDataMgr()->ImplicitQueryAllAbilityInfos(
        want, flags, USERID, abilityInfo, appIndex);
    EXPECT_EQ(abilityInfo.size(), 0);
    GetBundleDataMgr()->sandboxAppHelper_ = nullptr;
    GetBundleDataMgr()->ImplicitQueryAllAbilityInfos(
        want, flags, USERID, abilityInfo, appIndex);
    EXPECT_EQ(abilityInfo.size(), 0);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetBundleDataMgr_0006
 * @tc.name: test ImplicitQueryAllAbilityInfosV9
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0006, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);

    int32_t flags = 0;
    std::vector<AbilityInfo> abilityInfo;
    int32_t appIndex = 1;
    GetBundleDataMgr()->ImplicitQueryAllAbilityInfosV9(
        want, flags, USERID, abilityInfo, appIndex);
    GetBundleDataMgr()->ImplicitQueryAllAbilityInfosV9(
        want, flags, USERID, abilityInfo, appIndex);
    EXPECT_EQ(abilityInfo.size(), 0);
    GetBundleDataMgr()->sandboxAppHelper_ = nullptr;
    GetBundleDataMgr()->ImplicitQueryAllAbilityInfosV9(
        want, flags, USERID, abilityInfo, appIndex);
    EXPECT_EQ(abilityInfo.size(), 0);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetBundleDataMgr_0007
 * @tc.name: test QueryAbilityInfosByUri
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0007, Function | SmallTest | Level1)
{
    std::vector<AbilityInfo> abilityInfos;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfosByUri(
        "", abilityInfos);
    EXPECT_EQ(testRet, false);
    testRet = GetBundleDataMgr()->QueryAbilityInfosByUri(
        "dataability://com.example.hiworld.himusic.UserADataAbility", abilityInfos);
    EXPECT_EQ(testRet, false);
    testRet = GetBundleDataMgr()->QueryAbilityInfosByUri(
        "UserADataAbility", abilityInfos);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetBundleDataMgr_0008
 * @tc.name: test GetAllBundleInfosV9
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0008, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> Info;
    int32_t flags = 1;
    GetBundleDataMgr()->bundleInfos_.clear();
    ErrCode testRet = GetBundleDataMgr()->GetAllBundleInfosV9(
        flags, Info);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: GetBundleDataMgr_0009
 * @tc.name: test GetBundleNameForUid
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0009, Function | SmallTest | Level1)
{
    std::string bundleName;
    std::vector<ApplicationInfo> appInfos;
    bool ret = GetBundleDataMgr()->GetBundleNameForUid(1, bundleName);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: GetBundleDataMgr_0010
 * @tc.name: test GetBundleNameForUid
 * @tc.desc: 1.system run normally
 *           2.sandboxAppHelper_ is empty
*/
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0010, Function | SmallTest | Level1)
{
    std::string bundleName;
    bool testRet = GetBundleDataMgr()->GetBundleNameForUid(
        1, bundleName);
    EXPECT_EQ(testRet, false);
    GetBundleDataMgr()->sandboxAppHelper_ = nullptr;
    testRet = GetBundleDataMgr()->GetBundleNameForUid(
        1, bundleName);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetBundleDataMgr_0011
 * @tc.name: test GetNameForUid
 * @tc.desc: 1.system run normally
 *           2.sandboxAppHelper_ is empty
 */
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0011, Function | SmallTest | Level1)
{
    std::string bundlenName;
    bool testRet = GetBundleDataMgr()->GetNameForUid(
        1, bundlenName);
    EXPECT_EQ(testRet, true);
    GetBundleDataMgr()->sandboxAppHelper_ = nullptr;
    testRet = GetBundleDataMgr()->GetNameForUid(
        1, bundlenName);
    EXPECT_EQ(testRet, true);
}

/**
 * @tc.number: GetBundleDataMgr_0012
 * @tc.name: test CheckIsSystemAppByUid
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0012, Function | SmallTest | Level1)
{
    bool testRet = GetBundleDataMgr()->CheckIsSystemAppByUid(Constants::ROOT_UID);
    EXPECT_EQ(testRet, true);
    testRet = GetBundleDataMgr()->CheckIsSystemAppByUid(Constants::BMS_UID);
    EXPECT_EQ(testRet, true);
}

/**
 * @tc.number: GetBundleDataMgr_0013
 * @tc.name: test CheckIsSystemAppByUid
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0013, Function | SmallTest | Level1)
{
    bool testRet = GetBundleDataMgr()->IsDisableState(InstallState::UPDATING_START);
    EXPECT_EQ(testRet, true);
    testRet = GetBundleDataMgr()->IsDisableState(InstallState::UNINSTALL_START);
    EXPECT_EQ(testRet, true);
    testRet = GetBundleDataMgr()->IsDisableState(InstallState::ROLL_BACK);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetBundleDataMgr_0014
 * @tc.name: test ExplicitQueryExtensionInfo
 * @tc.desc: 1.system run normally
 *           2.sandboxAppHelper_ is empty
 */
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0014, Function | SmallTest | Level1)
{
    Want want;
    int32_t appIndex = 1;
    ExtensionAbilityInfo extensionInfo;
    GetBundleDataMgr()->sandboxAppHelper_ = nullptr;
    bool testRet = GetBundleDataMgr()->ExplicitQueryExtensionInfo(
        want, 0, USERID, extensionInfo, appIndex);
    EXPECT_EQ(testRet, false);
    ErrCode testRet1 = GetBundleDataMgr()->ExplicitQueryExtensionInfoV9(
        want, 0, USERID, extensionInfo, appIndex);
    EXPECT_EQ(testRet1, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: GetBundleDataMgr_0015
 * @tc.name: test ImplicitQueryExtensionInfos
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0015, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t appIndex = 0;
    bool testRet = GetBundleDataMgr()->ImplicitQueryExtensionInfos(
        want, 0, USERID, extensionInfos, appIndex);
    EXPECT_EQ(testRet, true);
    ExtensionAbilityInfo info;
    info.bundleName = BUNDLE_BACKUP_NAME;
    info.moduleName = MODULE_NAME;
    extensionInfos.push_back(info);
    appIndex = 2;
    testRet = GetBundleDataMgr()->ImplicitQueryExtensionInfos(
        want, 0, USERID, extensionInfos, appIndex);
    EXPECT_EQ(testRet, false);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetBundleDataMgr_0016
 * @tc.name: test ImplicitQueryCurExtensionInfos
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0016, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t appIndex = 0;
    bool testRet = GetBundleDataMgr()->ImplicitQueryCurExtensionInfos(
        want, 0, USERID, extensionInfos, appIndex);
    EXPECT_EQ(testRet, true);
    appIndex = 2;
    testRet = GetBundleDataMgr()->ImplicitQueryCurExtensionInfos(
        want, 0, USERID, extensionInfos, appIndex);
    EXPECT_EQ(testRet, false);
    GetBundleDataMgr()->sandboxAppHelper_ = nullptr;
    testRet = GetBundleDataMgr()->ImplicitQueryCurExtensionInfos(
        want, 0, USERID, extensionInfos, appIndex);
    EXPECT_EQ(testRet, false);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetBundleDataMgr_0017
 * @tc.name: test ImplicitQueryCurExtensionInfosV9
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0017, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t appIndex = 2;
    GetBundleDataMgr()->sandboxAppHelper_ = nullptr;
    ErrCode testRet = GetBundleDataMgr()->ImplicitQueryCurExtensionInfosV9(
        want, 0, USERID, extensionInfos, appIndex);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: GetBundleDataMgr_0018
 * @tc.name: test ImplicitQueryAllExtensionInfos
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0018, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t appIndex = 2;
    GetBundleDataMgr()->ImplicitQueryAllExtensionInfos(
        want, 0, USERID, extensionInfos, appIndex);
    EXPECT_EQ(extensionInfos.size(), 0);
    GetBundleDataMgr()->sandboxAppHelper_ = nullptr;
    GetBundleDataMgr()->ImplicitQueryAllExtensionInfos(
        want, 0, USERID, extensionInfos, appIndex);
    EXPECT_EQ(extensionInfos.size(), 0);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetBundleDataMgr_0019
 * @tc.name: test ImplicitQueryAllExtensionInfosV9
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0019, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t appIndex = 2;
    GetBundleDataMgr()->ImplicitQueryAllExtensionInfosV9(
        want, 0, USERID, extensionInfos, appIndex);
    EXPECT_EQ(extensionInfos.size(), 0);
    GetBundleDataMgr()->sandboxAppHelper_ = nullptr;
    GetBundleDataMgr()->ImplicitQueryAllExtensionInfosV9(
        want, 0, USERID, extensionInfos, appIndex);
    EXPECT_EQ(extensionInfos.size(), 0);
}

/**
 * @tc.number: GetBundleDataMgr_0020
 * @tc.name: test QueryAllDeviceIds
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0020, Function | SmallTest | Level1)
{
    std::vector<std::string> deviceIds;
    bool res = GetBundleDataMgr()->QueryAllDeviceIds(deviceIds);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: GetBundleDataMgr_0021
 * @tc.name: test AddInnerBundleUserInfo
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0021, Function | SmallTest | Level1)
{
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = "bundleName";
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleUserInfo.bundleUserInfo.userId = Constants::INVALID_USERID;
    innerBundleUserInfo.uid = 65535;
    bool res = GetBundleDataMgr()->AddInnerBundleUserInfo(
        "bundleName", innerBundleUserInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetBundleDataMgr_0022
 * @tc.name: test ImplicitQueryAllExtensionInfos
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest, GetBundleDataMgr_0022, Function | SmallTest | Level1)
{
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = "bundleName";
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleUserInfo.bundleUserInfo.userId = Constants::INVALID_USERID;
    bool res = GetBundleDataMgr()->RemoveInnerBundleUserInfo(
        "bundleName", Constants::INVALID_USERID);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: RegisterBundleEventCallback_0001
 * @tc.name: test RegisterBundleEventCallback
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest, RegisterBundleEventCallback_0001, Function | SmallTest | Level1)
{
    bool res = GetBundleDataMgr()->RegisterBundleEventCallback(nullptr);
    EXPECT_EQ(res, false);
    res = GetBundleDataMgr()->UnregisterBundleEventCallback(nullptr);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetDataStorage_0001
 * @tc.name: test LoadAllData
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest, GetDataStorage_0001, Function | SmallTest | Level1)
{
    auto dataStorage = GetBundleDataMgr()->GetDataStorage();
    EXPECT_NE(dataStorage, nullptr);
    std::map<std::string, InnerBundleInfo> infos;
    bool res = dataStorage->LoadAllData(infos);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: BundleFreeInstall_0100
 * @tc.name: test CheckAbilityEnableInstall
 * @tc.desc: 1.check ability infos
 */
HWTEST_F(BmsBundleManagerTest, BundleFreeInstall_0100, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL

    AAFwk::Want want;
    int32_t missionId = 0;
    int32_t userId = 100;
    bool ret = hostImpl->CheckAbilityEnableInstall(want, missionId, userId, nullptr);
    EXPECT_EQ(ret, false);

    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    ret = hostImpl->CheckAbilityEnableInstall(want, missionId, userId, nullptr);
    EXPECT_EQ(ret, false);
#endif
}

/**
 * @tc.number: DataMgrFailedScene_0100
 * @tc.name: test failed scene when bundle info is not existed
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest, DataMgrFailedScene_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    InnerBundleInfo oldInfo;
    bool ret = dataMgr->AddNewModuleInfo(BUNDLE_NAME, info, oldInfo);
    EXPECT_EQ(ret, false);

    ret = dataMgr->RemoveModuleInfo(BUNDLE_NAME, "", oldInfo);
    EXPECT_EQ(ret, false);

    ret = dataMgr->UpdateInnerBundleInfo(BUNDLE_NAME, info, oldInfo);
    EXPECT_EQ(ret, false);

    ret = dataMgr->DisableBundle(BUNDLE_NAME);
    EXPECT_EQ(ret, false);

    std::string provisionId = "100";
    ret = dataMgr->GetProvisionId(BUNDLE_NAME, provisionId);
    EXPECT_EQ(ret, false);

    std::string appFeature = "ohos_system_app";
    ret = dataMgr->GetAppFeature(BUNDLE_NAME, appFeature);
    EXPECT_EQ(ret, false);

    int res = dataMgr->CheckPublicKeys(BUNDLE_NAME, BUNDLE_NAME);
    EXPECT_EQ(res, Constants::SIGNATURE_UNKNOWN_BUNDLE);

    ret = dataMgr->UpdateQuickFixInnerBundleInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, false);

    dataMgr->bundleInfos_.try_emplace(BUNDLE_NAME, info);
    ret = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: DataMgrFailedScene_0200
 * @tc.name: test failed scene when save info fail or app is not updated
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest, DataMgrFailedScene_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    InnerBundleInfo oldInfo;
    dataMgr->bundleInfos_.try_emplace(BUNDLE_NAME, info);
    bool ret = dataMgr->AddNewModuleInfo(BUNDLE_NAME, info, oldInfo);
    EXPECT_EQ(ret, false);

    ret = dataMgr->UpdateInnerBundleInfo(BUNDLE_NAME, info, oldInfo);
    EXPECT_EQ(ret, false);

    ret = dataMgr->UpdateQuickFixInnerBundleInfo("", info);
    EXPECT_EQ(ret, false);

    dataMgr->bundleInfos_.clear();
    ret = dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, false);

    int res = dataMgr->CheckPublicKeys(BUNDLE_NAME, BUNDLE_BACKUP_NAME);
    EXPECT_EQ(res, Constants::SIGNATURE_UNKNOWN_BUNDLE);
}

/**
 * @tc.number: DataMgrFailedScene_0300
 * @tc.name: test failed scene when preInstallDataStorage is null
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest, DataMgrFailedScene_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->preInstallDataStorage_ = nullptr;
    PreInstallBundleInfo preInstallBundleInfo;
    bool ret = dataMgr->SavePreInstallBundleInfo(BUNDLE_NAME, preInstallBundleInfo);
    EXPECT_EQ(ret, false);

    ret = dataMgr->DeletePreInstallBundleInfo(BUNDLE_NAME, preInstallBundleInfo);
    EXPECT_EQ(ret, false);

    std::vector<PreInstallBundleInfo> preInstallBundleInfos;
    ret = dataMgr->LoadAllPreInstallBundleInfos(preInstallBundleInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: DataMgrFailedScene_0400
 * @tc.name: test failed scene when userId or bundleInfos failed
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest, DataMgrFailedScene_0400, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string uri = "dataability:///com.example.FileShare/person/10";
    int32_t userId = Constants::INVALID_USERID;
    ExtensionAbilityInfo info;
    bool ret = dataMgr->QueryExtensionAbilityInfoByUri(uri, userId, info);
    EXPECT_EQ(ret, false);

    userId = Constants::ALL_USERID;
    ret = dataMgr->QueryExtensionAbilityInfoByUri(uri, userId, info);
    EXPECT_EQ(ret, false);
}
} // OHOS
