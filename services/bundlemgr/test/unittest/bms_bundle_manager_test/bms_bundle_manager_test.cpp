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
const std::string ABILITY_BACKUP_NAME = "MainAbility";
const std::string BUNDLE_PREVIEW_NAME = "com.example.previewtest";
const std::string BUNDLE_THUMBNAIL_NAME = "com.example.thumbnailtest";
const std::string MODULE_NAME = "entry";
const std::string EXTENSION_ABILITY_NAME = "extensionAbility_A";
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

private:
    std::shared_ptr<BundleInstallerManager> manager_ = nullptr;
    std::shared_ptr<InstalldService> installdService_ = std::make_shared<InstalldService>();
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
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
 * @tc.require: SR000H0383
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
 * @tc.require: AR000H035G
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
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0300
 * @tc.name: test the backup type
 * @tc.desc: 1.install the hap
 *           2.query extensionAbilityInfos
 * @tc.require: AR000H035G
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
 * @tc.require: AR000H035G
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
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_PARAM_ERROR);

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
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_PARAM_ERROR);

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

    int32_t flags = GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION_V9 |
        GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION_V9 | GET_EXTENSION_ABILITY_INFO_WITH_METADATA_V9;
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
    int32_t flags = GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION_V9 |
        GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION_V9 | GET_EXTENSION_ABILITY_INFO_WITH_METADATA_V9;
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

    int32_t flags = GET_ABILITY_INFO_WITH_PERMISSION_V9 | GET_ABILITY_INFO_WITH_APPLICATION_V9 |
        GET_ABILITY_INFO_WITH_METADATA_V9 | GET_ABILITY_INFO_WITH_DISABLE_V9;
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
    int32_t flags = GET_ABILITY_INFO_WITH_PERMISSION_V9 | GET_ABILITY_INFO_WITH_APPLICATION_V9 |
        GET_ABILITY_INFO_WITH_METADATA_V9 | GET_ABILITY_INFO_WITH_DISABLE_V9;
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
 * @tc.number: OnRemoteRequest_0100
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_APPLICATION_INFO_WITH_INT_FLAGS
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_0100, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);
    data.WriteInt32(0);
    data.WriteInt32(USERID);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_APPLICATION_INFO_WITH_INT_FLAGS, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_0200
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_APPLICATION_INFOS_WITH_INT_FLAGS_V9
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_0200, Function | SmallTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteInt32(0);
    data.WriteInt32(USERID);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_APPLICATION_INFOS_WITH_INT_FLAGS_V9, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_0300
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is DUMP_INFOS
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_0300, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);
    std::vector<std::string> dumpInfos;

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    reply.WriteBool(true);
    reply.ReadStringVector(&dumpInfos);
    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);
    data.WriteInt32(0);
    data.WriteInt32(USERID);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::DUMP_INFOS, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_0400
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_APPLICATION_INFOS_WITH_INT_FLAGS
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_0400, Function | SmallTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    reply.WriteBool(true);
    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteInt32(0);
    data.WriteInt32(USERID);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_APPLICATION_INFOS_WITH_INT_FLAGS, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_0500
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_APPLICATION_INFOS_WITH_INT_FLAGS_V9
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_0500, Function | SmallTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteInt32(0);
    data.WriteInt32(USERID);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_APPLICATION_INFOS_WITH_INT_FLAGS_V9, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_0600
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_BUNDLE_INFO_WITH_INT_FLAGS
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_0600, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);
    data.WriteInt32(0);
    data.WriteInt32(USERID);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_BUNDLE_INFO_WITH_INT_FLAGS, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_0700
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_BUNDLE_INFO_WITH_INT_FLAGS_V9
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_0700, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);
    data.WriteInt32(0);
    data.WriteInt32(USERID);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_BUNDLE_INFO_WITH_INT_FLAGS_V9, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_0800
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_BUNDLE_PACK_INFO
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_0800, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);
    data.WriteInt32(0);
    data.WriteInt32(USERID);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_BUNDLE_PACK_INFO, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_0900
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_BUNDLE_PACK_INFO_WITH_INT_FLAGS
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_0900, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);
    data.WriteInt32(0);
    data.WriteInt32(USERID);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_BUNDLE_PACK_INFO_WITH_INT_FLAGS, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_1000
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_NAME_FOR_UID
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_1000, Function | SmallTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteInt32(0);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_NAME_FOR_UID, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_1100
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_BUNDLE_GIDS
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_1100, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    std::vector<int> gids;

    reply.WriteBool(true);
    reply.ReadInt32Vector(&gids);
    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_BUNDLE_GIDS, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_1200
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_BUNDLE_INFOS_BY_METADATA
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_1200, Function | SmallTest | Level1)
{
    std::string metadata = "string";

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(metadata);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_BUNDLE_INFOS_BY_METADATA, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_1300
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is QUERY_ABILITY_INFO
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_1300, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_BACKUP_NAME, EXTENSION_ABILITY_NAME, "");

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteParcelable(&want);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::QUERY_ABILITY_INFO, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_1400
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is QUERY_ABILITY_INFOS
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_1400, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_BACKUP_NAME, EXTENSION_ABILITY_NAME, "");

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteParcelable(&want);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::QUERY_ABILITY_INFOS, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_1500
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is QUERY_ABILITY_INFOS_MUTI_PARAM
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_1500, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_BACKUP_NAME, EXTENSION_ABILITY_NAME, "");

    reply.WriteBool(true);
    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteParcelable(&want);
    data.WriteInt32(0);
    data.WriteInt32(USERID);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::QUERY_ABILITY_INFOS_MUTI_PARAM, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_1600
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is QUERY_ABILITY_INFOS_V9
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_1600, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_BACKUP_NAME, EXTENSION_ABILITY_NAME, "");

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteParcelable(&want);
    data.WriteInt32(0);
    data.WriteInt32(USERID);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::QUERY_ABILITY_INFOS_V9, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_1700
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is QUERY_ABILITY_INFOS_V9
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_1700, Function | SmallTest | Level1)
{
    std::string abilityUri = "invalid";

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(abilityUri);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::QUERY_ABILITY_INFOS_BY_URI, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_1800
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_ABILITY_LABEL
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_1800, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);
    data.WriteString(EXTENSION_ABILITY_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_ABILITY_LABEL, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_1900
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_ABILITY_LABEL_WITH_MODULE_NAME
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_1900, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);
    data.WriteString(EXTENSION_ABILITY_NAME);
    data.WriteString(MODULE_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_ABILITY_LABEL_WITH_MODULE_NAME, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_2000
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_BUNDLE_ARCHIVE_INFO
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_2000, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(bundlePath);
    data.WriteInt32(0);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_BUNDLE_ARCHIVE_INFO, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_2100
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is CHECK_PUBLICKEYS
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_2100, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    std::string bundlePath1 = RESOURCE_ROOT_PATH + BUNDLE_THUMBNAIL_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    ErrCode installResult1 = InstallThirdPartyBundle(bundlePath1);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_EQ(installResult1, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_TEST);
    data.WriteString(RIGHT_BUNDLE);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::CHECK_PUBLICKEYS, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
    UnInstallBundle(BUNDLE_THUMBNAIL_NAME);
}

/**
 * @tc.number: OnRemoteRequest_2200
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_PERMISSION_DEF
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_2200, Function | SmallTest | Level1)
{
    std::string permissionName = "ohos.permission.READ_CALENDAR";

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(permissionName);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_PERMISSION_DEF, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_2300
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is HAS_SYSTEM_CAPABILITY
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_2300, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(EXTENSION_ABILITY_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::HAS_SYSTEM_CAPABILITY, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_2400
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_SYSTEM_AVAILABLE_CAPABILITIES
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_2400, Function | SmallTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_SYSTEM_AVAILABLE_CAPABILITIES, data, reply, option);
    reply.WriteBool(false);
    EXPECT_EQ(res, NO_ERROR);
}


/**
 * @tc.number: OnRemoteRequest_2500
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is UNREGISTER_BUNDLE_STATUS_CALLBACK
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_2500, Function | SmallTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::UNREGISTER_BUNDLE_STATUS_CALLBACK, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}

/**
 * @tc.number: OnRemoteRequest_2600
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is IS_APPLICATION_ENABLED
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_2600, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::IS_APPLICATION_ENABLED, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_2700
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is SET_APPLICATION_ENABLED
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_2700, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);
    data.WriteBool(true);
    data.WriteInt32(USERID);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::SET_APPLICATION_ENABLED, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_2800
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is SET_ABILITY_ENABLED
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_2800, Function | SmallTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    AbilityInfo abilityInfo;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteParcelable(&abilityInfo);
    data.WriteInt32(USERID);
    data.WriteBool(true);
    reply.WriteInt32(0);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::SET_ABILITY_ENABLED, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}


/**
 * @tc.number: OnRemoteRequest_2900
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_ABILITY_INFO
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_2900, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    AbilityInfo info;

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);
    data.WriteString(ABILITY_BACKUP_NAME);
    data.WriteString(MODULE_NAME);
    reply.WriteBool(true);
    reply.WriteParcelable(&info);

    auto res1 = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_ABILITY_INFO, data, reply, option);

    EXPECT_EQ(res1, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_3000
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_FORMS_INFO_BY_APP
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_3000, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_FORMS_INFO_BY_APP, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_3100
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_APPLICATION_PRIVILEGE_LEVEL
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_3100, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_APPLICATION_PRIVILEGE_LEVEL, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_3200
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is QUERY_EXTENSION_INFO_WITHOUT_TYPE_V9
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_3200, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::QUERY_EXTENSION_INFO_WITHOUT_TYPE_V9, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_3300
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is QUERY_EXTENSION_INFO
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_3300, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::QUERY_EXTENSION_INFO, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_3400
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is QUERY_EXTENSION_INFO_V9
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_3400, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::QUERY_EXTENSION_INFO_V9, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_3500
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is VERIFY_CALLING_PERMISSION
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_3500, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::VERIFY_CALLING_PERMISSION, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_3600
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_ACCESSIBLE_APP_CODE_PATH
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_3600, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_ACCESSIBLE_APP_CODE_PATH, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_3700
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_APPID_BY_BUNDLE_NAME
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_3700, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_APPID_BY_BUNDLE_NAME, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_3800
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_APP_TYPE
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_3800, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_APP_TYPE, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_3900
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is IS_MODULE_REMOVABLE
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_3900, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::IS_MODULE_REMOVABLE, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_4000
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is SET_MODULE_REMOVABLE
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_4000, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::SET_MODULE_REMOVABLE, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_4100
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is IS_MODULE_NEED_UPDATE
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_4100, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::IS_MODULE_NEED_UPDATE, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_4200
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is SET_MODULE_NEED_UPDATE
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_4200, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::SET_MODULE_NEED_UPDATE, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_4300
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is IMPLICIT_QUERY_INFOS
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_4300, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::IMPLICIT_QUERY_INFOS, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_4400
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_ALL_DEPENDENT_MODULE_NAMES
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_4400, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_ALL_DEPENDENT_MODULE_NAMES, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_4500
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_SANDBOX_APP_BUNDLE_INFO
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_4500, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_SANDBOX_APP_BUNDLE_INFO, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_4600
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is SET_DISPOSED_STATUS
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_4600, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::SET_DISPOSED_STATUS, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_4700
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is QUERY_CALLING_BUNDLE_NAME
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_4700, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::QUERY_CALLING_BUNDLE_NAME, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_4800
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is CHECK_ABILITY_ENABLE_INSTALL
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_4800, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::CHECK_ABILITY_ENABLE_INSTALL, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_4900
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_STRING_BY_ID
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_4900, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);
    data.WriteString(MODULE_NAME);
    data.WriteString(Constants::EMPTY_STRING);
    data.WriteUint32(16777220);
    data.WriteUint32(USERID);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_STRING_BY_ID, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_5000
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_ICON_BY_ID
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_5000, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);
    data.WriteString(MODULE_NAME);
    data.WriteString(Constants::EMPTY_STRING);
    data.WriteUint32(16777220);
    data.WriteUint32(16777221);
    data.WriteUint32(USERID);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_ICON_BY_ID, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_5100
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_UDID_BY_NETWORK_ID
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_5100, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_UDID_BY_NETWORK_ID, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_5200
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_SANDBOX_APP_ABILITY_INFO
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_5200, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_SANDBOX_APP_ABILITY_INFO, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_5300
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_SANDBOX_APP_EXTENSION_INFOS
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_5300, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_SANDBOX_APP_EXTENSION_INFOS, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_5400
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is QUERY_ABILITY_INFO_WITH_CALLBACK
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_5400, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::QUERY_ABILITY_INFO_WITH_CALLBACK, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_5500
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is UPGRADE_ATOMIC_SERVICE
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_5500, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::UPGRADE_ATOMIC_SERVICE, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_5600
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_BUNDLE_STATS
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_5600, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_BUNDLE_STATS, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_5700
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is SET_DEBUG_MODE
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_5700, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(BUNDLE_BACKUP_NAME);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::SET_DEBUG_MODE, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_5800
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_5800, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(bundlePath);
    data.WriteInt32(0);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_5900
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS_V9
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_5900, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    data.WriteString(bundlePath);
    data.WriteInt32(0);

    auto res = bundleMgrHost.OnRemoteRequest(
        IBundleMgr::Message::GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS_V9, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: OnRemoteRequest_6000
 * @tc.name: test OnRemoteRequest
 * @tc.desc: 1.system run normally
 *           2.test code is IS_SAFE_MODE
 */
HWTEST_F(BmsBundleManagerTest, OnRemoteRequest_6000, Function | SmallTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    data.WriteInterfaceToken(BundleMgrHost::GetDescriptor());
    reply.WriteBool(false);

    auto res = bundleMgrHost.OnRemoteRequest(IBundleMgr::Message::IS_SAFE_MODE, data, reply, option);
    EXPECT_EQ(res, NO_ERROR);
}
} // OHOS
