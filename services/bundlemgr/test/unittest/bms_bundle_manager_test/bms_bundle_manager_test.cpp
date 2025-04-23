/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bundle_info.h"
#include "bundle_file_util.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "install_param.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "inner_bundle_info.h"
#include "mime_type_mgr.h"
#include "mock_status_receiver.h"
#include "parameters.h"
#include "preinstall_data_storage_rdb.h"
#include "scope_guard.h"
#include "system_bundle_installer.h"
#include "want.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
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
const int32_t FLAG = 0;
const int32_t WRONG_UID = -1;
const int32_t WAIT_TIME = 5; // init mocked bms
const std::string BUNDLE_BACKUP_TEST = "backup.hap";
const std::string BUNDLE_PREVIEW_TEST = "preview.hap";
const std::string BUNDLE_THUMBNAIL_TEST = "thumbnail.hap";
const std::string BUNDLE_BACKUP_NAME = "com.example.backuptest";
const std::string ABILITY_BACKUP_NAME = "com.example.backuptest.entry.MainAbility";
const std::string BUNDLE_PREVIEW_NAME = "com.example.previewtest";
const std::string BUNDLE_THUMBNAIL_NAME = "com.example.thumbnailtest";
const std::string MODULE_NAME = "entry";
const std::string EXTENSION_ABILITY_NAME = "extensionAbility_A";
const std::string TYPE_001 = "type001";
const std::string TYPE_002 = "VIDEO";
const std::string TEST_BUNDLE_NAME = "bundleName";
const std::string OVER_MAX_SIZE(300, 'x');
const std::string ABILITY_NAME = "com.example.l3jsdemo.entry.EntryAbility";
const std::string EMPTY_STRING = "";
const std::string MENU_VALUE = "value";
constexpr const char* TYPE_ONLY_MATCH_WILDCARD = "reserved/wildcard";
const size_t NUMBER_ONE = 1;
const uint32_t BUNDLE_BACKUP_VERSION = 1000000;
const uint32_t BUNDLE_BACKUP_LABEL_ID = 16777218;
const uint32_t BUNDLE_BACKUP_ICON_ID = 16777221;
const std::string CALLER_NAME_UT = "ut";
const std::string DEVICETYPE = "deviceType";
const int32_t APPINDEX = 10;
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
    void ResetDataMgr();
    void ClearConnectAbilityMgr();
    void ResetConnectAbilityMgr();

private:
    std::shared_ptr<BundleInstallerManager> manager_ = nullptr;
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleManagerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleManagerTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleManagerTest::BmsBundleManagerTest()
{}

BmsBundleManagerTest::~BmsBundleManagerTest()
{}

bool BmsBundleManagerTest::InstallSystemBundle(const std::string &filePath) const
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

ErrCode BmsBundleManagerTest::InstallThirdPartyBundle(const std::string &filePath) const
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
    installParam.withCopyHaps = true;
    bool result = installer->Install(filePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleManagerTest::UpdateThirdPartyBundle(const std::string &filePath) const
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
    installParam.withCopyHaps = true;
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
    bundleMgrService_->OnStop();
}

void BmsBundleManagerTest::SetUp()
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
    EXPECT_NE(bundleMgrService_->GetDataMgr(), nullptr);
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

void BmsBundleManagerTest::ResetDataMgr()
{
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(bundleMgrService_->dataMgr_, nullptr);
}

void BmsBundleManagerTest::ClearConnectAbilityMgr()
{
    bundleMgrService_->connectAbilityMgr_.clear();
}

void BmsBundleManagerTest::ResetConnectAbilityMgr()
{
    auto ptr = bundleMgrService_->GetConnectAbility();
    EXPECT_FALSE(bundleMgrService_->connectAbilityMgr_.empty());
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
    manager_ = std::make_shared<BundleInstallerManager>();
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
 * @tc.number: BundleStreamInstallerHostImpl_0100
 * @tc.name: test Init
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, BundleStreamInstallerHostImpl_0100, Function | SmallTest | Level1)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(statusReceiver, nullptr);
    const std::vector<std::string> originHapPaths;
    bool ret = impl.Init(installParam, statusReceiver, originHapPaths);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BundleStreamInstallerHostImpl_0200
 * @tc.name: test UnInit
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, BundleStreamInstallerHostImpl_0200, Function | SmallTest | Level1)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    impl.installParam_.sharedBundleDirPaths = {"pata1", "path2"};
    InstallParam installParam;
    impl.UnInit();
    EXPECT_EQ(impl.installParam_.sharedBundleDirPaths.empty(), false);
}

/**
 * @tc.number: BundleStreamInstallerHostImpl_0300
 * @tc.name: test UnInit
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, BundleStreamInstallerHostImpl_0300, Function | SmallTest | Level1)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    impl.installParam_.sharedBundleDirPaths = {"pata1", "path2"};
    impl.UnInit();
    EXPECT_EQ(impl.installParam_.sharedBundleDirPaths.empty(), false);
}

/**
 * @tc.number: BundleStreamInstallerHostImpl_0400
 * @tc.name: test Install
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, BundleStreamInstallerHostImpl_0400, Function | SmallTest | Level1)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(statusReceiver, nullptr);
    impl.receiver_ = statusReceiver;
    bool ret = impl.Install();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BundleStreamInstallerHostImpl_0500
 * @tc.name: test CreateStream
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, BundleStreamInstallerHostImpl_0500, Function | SmallTest | Level0)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    int ret = impl.CreateStream(BUNDLE_NAME);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BundleStreamInstallerHostImpl_0600
 * @tc.name: test CreateSharedBundleStream
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, BundleStreamInstallerHostImpl_0600, Function | SmallTest | Level0)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    impl.installParam_.sharedBundleDirPaths.push_back(OVER_MAX_SIZE);
    auto ret = impl.CreateSharedBundleStream(BUNDLE_NAME, USERID);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BundleStreamInstallerHostImpl_0700
 * @tc.name: test CreateSharedBundleStream
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, BundleStreamInstallerHostImpl_0700, Function | SmallTest | Level0)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    bool ret = impl.Install();
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BundleStreamInstallerHostImpl_0800
 * @tc.name: test CreateStream
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, BundleStreamInstallerHostImpl_0800, Function | SmallTest | Level0)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    std::string hapName = BUNDLE_NAME;
    auto ret = impl.CreateStream(hapName);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BundleStreamInstallerHostImpl_0900
 * @tc.name: test CreateStream
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, BundleStreamInstallerHostImpl_0900, Function | SmallTest | Level0)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    impl.isInstallSharedBundlesOnly_ = false;
    auto ret = impl.Install();
    EXPECT_EQ(ret, false);
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
 * @tc.number: QueryAbilityInfosV9_1200
 * @tc.name: test QueryAbilityInfosV9 proxy
 * @tc.desc: 1.implicit query ability infos with flags GET_ABILITY_INFO_WITH_SKILL_URI
 */
HWTEST_F(BmsBundleManagerTest, QueryAbilityInfosV9_1200, Function | MediumTest | Level1)
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
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_SKILL_URI);
    ErrCode ret = dataMgr->QueryAbilityInfosV9(want, flags, USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);

    ElementName elementName("", BUNDLE_BACKUP_NAME, "", "");
    want.SetElement(elementName);
    ret = dataMgr->QueryAbilityInfosV9(want, flags, USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(abilityInfos[0].skillUri.size(), 1);
    EXPECT_EQ(abilityInfos[0].skillUri[0].scheme, "");
    EXPECT_EQ(abilityInfos[0].skillUri[0].host, "example.com");
    EXPECT_EQ(abilityInfos[0].skillUri[0].port, "80");
    EXPECT_EQ(abilityInfos[0].skillUri[0].path, "path");
    EXPECT_EQ(abilityInfos[0].skillUri[0].type, "");
    EXPECT_EQ(abilityInfos[0].skillUri[0].linkFeature, "test");
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
    auto ret = info.FindAbilityInfoV9("", "");
    EXPECT_EQ(ret, std::nullopt);

    ret = info.FindAbilityInfoV9(moduleName, abilityName);
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
    int32_t notExistUserId = ServiceConstants::NOT_EXIST_USERID;
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
    AAFwk::Want want;
    std::vector<AbilityInfo> abilityInfos;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->QueryLauncherAbilityInfos(want, 100, abilityInfos) == ERR_OK;
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
        ServiceConstants::DATA_ABILITY_URI_PREFIX, 100, abilityInfo);
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
        ServiceConstants::DATA_ABILITY_URI_PREFIX, abilityInfos);
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
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_INVALID_UID);
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
        TEST_BUNDLE_NAME, 0, info, USERID);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: GetInnerBundleInfoWithFlags2_0001
 * @tc.name: test GetInnerBundleInfoWithFlags
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetInnerBundleInfoWithFlags2_0001, Function | SmallTest | Level1)
{
    bool testRet = GetBundleDataMgr()->GetInnerBundleInfoWithFlags(
        TEST_BUNDLE_NAME, 0, USERID);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetInnerBundleInfoWithFlags2_0002
 * @tc.name: test GetInnerBundleInfoWithFlagsForAms
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, GetInnerBundleInfoWithFlags2_0002, Function | SmallTest | Level1)
{
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetInnerBundleInfoWithFlags(
        TEST_BUNDLE_NAME, 0, USERID);
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
        TEST_BUNDLE_NAME, 0, info, USERID);
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
        TEST_BUNDLE_NAME, 0, info, USERID);
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
        TEST_BUNDLE_NAME, "moduleName", formInfos);
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
        TEST_BUNDLE_NAME, formInfos);
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
        TEST_BUNDLE_NAME, formInfos);
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
        TEST_BUNDLE_NAME, innerBundleUserInfos);
    EXPECT_EQ(testRet, false);
    EXPECT_EQ(GetBundleDataMgr()->bundleInfos_.empty(), true);
}

/**
 * @tc.number: bundleInfosFalse_0026
 * @tc.name: test GetDebugBundleList
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0026, Function | SmallTest | Level1)
{
    std::vector<std::string> info;
    GetBundleDataMgr()->bundleInfos_.clear();
    bool testRet = GetBundleDataMgr()->GetDebugBundleList(info, USERID);
    EXPECT_EQ(testRet, false);
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
 * @tc.number: bundleInfosFalse_0029
 * @tc.name: test IsPreInstallApp
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest, bundleInfosFalse_0029, Function | SmallTest | Level1)
{
    bool testRet = GetBundleDataMgr()->IsPreInstallApp("");
    EXPECT_EQ(testRet, false);
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
 * @tc.number: SkillFalse_0004
 * @tc.name: test MatchType
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, SkillFalse_0004, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back("action001");
    bool ret = skill.MatchType(TYPE_ONLY_MATCH_WILDCARD, "*/*");
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: SkillFalse_0005
 * @tc.name: test MatchMimeType
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, SkillFalse_0005, Function | SmallTest | Level1)
{
    struct Skill skill;
    bool ret = skill.MatchMimeType(".notatype");
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: SkillFalse_0006
 * @tc.name: test MatchMimeType
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, SkillFalse_0006, Function | SmallTest | Level1)
{
    struct Skill skill;
    bool ret = skill.MatchMimeType(".jpg");
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: SkillFalse_0007
 * @tc.name: test MatchMimeType
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, SkillFalse_0007, Function | SmallTest | Level1)
{
    struct Skill skill;
    SkillUri skillUri;
    skillUri.type = "image/*";
    skill.uris.emplace_back(skillUri);
    bool ret = skill.MatchMimeType(".jpg");
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: SkillFalse_0008
 * @tc.name: test MatchMimeType
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest, SkillFalse_0008, Function | SmallTest | Level1)
{
    struct Skill skill;
    SkillUri skillUri;
    skillUri.type = "image/*";
    skill.uris.emplace_back(skillUri);
    size_t matchUriIndex = 0;
    bool ret = skill.MatchMimeType(".jpg", matchUriIndex);
    EXPECT_EQ(true, ret);
    EXPECT_EQ(matchUriIndex, 0);
}

/**
 * @tc.number: MatchUri_0100
 * @tc.name: test MatchUri
 * @tc.desc: 1.system run normally
 *           2.skill uri not has host.
*/
HWTEST_F(BmsBundleManagerTest, MatchUri_0100, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back("action001");
    SkillUri skillUri;
    skillUri.scheme = "myscheme";
    skillUri.port = "888";
    skillUri.path = "test";
    skillUri.pathStartWith = "";
    skillUri.pathRegex = "";
    std::string uriString = "mySCHEME";
    bool ret = skill.MatchUri(uriString, skillUri);
    EXPECT_EQ(true, ret);

    std::string uriString1 = "mySCHEME:";
    bool ret1 = skill.MatchUri(uriString1, skillUri);
    EXPECT_EQ(true, ret1);

    std::string uriString2 = "mySCHEME:/";
    bool ret2 = skill.MatchUri(uriString2, skillUri);
    EXPECT_EQ(true, ret2);

    std::string uriString3 = "mySCHEME://";
    bool ret3 = skill.MatchUri(uriString3, skillUri);
    EXPECT_EQ(true, ret3);

    std::string uriString4 = "myscheme";
    bool ret4 = skill.MatchUri(uriString4, skillUri);
    EXPECT_EQ(true, ret4);

    std::string uriString5 = "myscheme:";
    bool ret5 = skill.MatchUri(uriString5, skillUri);
    EXPECT_EQ(true, ret5);

    std::string uriString6 = "myscheme:/";
    bool ret6 = skill.MatchUri(uriString6, skillUri);
    EXPECT_EQ(true, ret6);

    std::string uriString7 = "myscheme://";
    bool ret7 = skill.MatchUri(uriString7, skillUri);
    EXPECT_EQ(true, ret7);

    std::string uriString8 = "MYSCHEME";
    bool ret8 = skill.MatchUri(uriString8, skillUri);
    EXPECT_EQ(true, ret8);

    std::string uriString9 = "MYSCHEME:";
    bool ret9 = skill.MatchUri(uriString9, skillUri);
    EXPECT_EQ(true, ret9);

    std::string uriString10 = "MYSCHEME:/";
    bool ret10 = skill.MatchUri(uriString10, skillUri);
    EXPECT_EQ(true, ret10);

    std::string uriString11 = "MYSCHEME://";
    bool ret11 = skill.MatchUri(uriString11, skillUri);
    EXPECT_EQ(true, ret11);
}

/**
 * @tc.number: MatchUri_0200
 * @tc.name: test MatchUri
 * @tc.desc: 1.system run normally
 *           2.skill uri not has host.
*/
HWTEST_F(BmsBundleManagerTest, MatchUri_0200, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back("action001");
    SkillUri skillUri;
    skillUri.scheme = "MYSCHEME";
    skillUri.port = "888";
    skillUri.path = "test";
    skillUri.pathStartWith = "";
    skillUri.pathRegex = "";
    std::string uriString = "mySCHEME";
    bool ret = skill.MatchUri(uriString, skillUri);
    EXPECT_EQ(true, ret);

    std::string uriString1 = "mySCHEME:";
    bool ret1 = skill.MatchUri(uriString1, skillUri);
    EXPECT_EQ(true, ret1);

    std::string uriString2 = "mySCHEME:/";
    bool ret2 = skill.MatchUri(uriString2, skillUri);
    EXPECT_EQ(true, ret2);

    std::string uriString3 = "mySCHEME://";
    bool ret3 = skill.MatchUri(uriString3, skillUri);
    EXPECT_EQ(true, ret3);

    std::string uriString4 = "myscheme";
    bool ret4 = skill.MatchUri(uriString4, skillUri);
    EXPECT_EQ(true, ret4);

    std::string uriString5 = "myscheme:";
    bool ret5 = skill.MatchUri(uriString5, skillUri);
    EXPECT_EQ(true, ret5);

    std::string uriString6 = "myscheme:/";
    bool ret6 = skill.MatchUri(uriString6, skillUri);
    EXPECT_EQ(true, ret6);

    std::string uriString7 = "myscheme://";
    bool ret7 = skill.MatchUri(uriString7, skillUri);
    EXPECT_EQ(true, ret7);

    std::string uriString8 = "MYSCHEME";
    bool ret8 = skill.MatchUri(uriString8, skillUri);
    EXPECT_EQ(true, ret8);

    std::string uriString9 = "MYSCHEME:";
    bool ret9 = skill.MatchUri(uriString9, skillUri);
    EXPECT_EQ(true, ret9);

    std::string uriString10 = "MYSCHEME:/";
    bool ret10 = skill.MatchUri(uriString10, skillUri);
    EXPECT_EQ(true, ret10);

    std::string uriString11 = "MYSCHEME://";
    bool ret11 = skill.MatchUri(uriString11, skillUri);
    EXPECT_EQ(true, ret11);
}

/**
 * @tc.number: MatchUri_0300
 * @tc.name: test MatchUri
 * @tc.desc: 1.system run normally
 *           2.skill uri not has host.
*/
HWTEST_F(BmsBundleManagerTest, MatchUri_0300, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back("action001");
    SkillUri skillUri;
    skillUri.scheme = "MYscheme";
    skillUri.port = "888";
    skillUri.path = "test";
    skillUri.pathStartWith = "";
    skillUri.pathRegex = "";
    std::string uriString = "mySCHEME";
    bool ret = skill.MatchUri(uriString, skillUri);
    EXPECT_EQ(true, ret);

    std::string uriString1 = "mySCHEME:";
    bool ret1 = skill.MatchUri(uriString1, skillUri);
    EXPECT_EQ(true, ret1);

    std::string uriString2 = "mySCHEME:/";
    bool ret2 = skill.MatchUri(uriString2, skillUri);
    EXPECT_EQ(true, ret2);

    std::string uriString3 = "mySCHEME://";
    bool ret3 = skill.MatchUri(uriString3, skillUri);
    EXPECT_EQ(true, ret3);

    std::string uriString4 = "myscheme";
    bool ret4 = skill.MatchUri(uriString4, skillUri);
    EXPECT_EQ(true, ret4);

    std::string uriString5 = "myscheme:";
    bool ret5 = skill.MatchUri(uriString5, skillUri);
    EXPECT_EQ(true, ret5);

    std::string uriString6 = "myscheme:/";
    bool ret6 = skill.MatchUri(uriString6, skillUri);
    EXPECT_EQ(true, ret6);

    std::string uriString7 = "myscheme://";
    bool ret7 = skill.MatchUri(uriString7, skillUri);
    EXPECT_EQ(true, ret7);

    std::string uriString8 = "MYSCHEME";
    bool ret8 = skill.MatchUri(uriString8, skillUri);
    EXPECT_EQ(true, ret8);

    std::string uriString9 = "MYSCHEME:";
    bool ret9 = skill.MatchUri(uriString9, skillUri);
    EXPECT_EQ(true, ret9);

    std::string uriString10 = "MYSCHEME:/";
    bool ret10 = skill.MatchUri(uriString10, skillUri);
    EXPECT_EQ(true, ret10);

    std::string uriString11 = "MYSCHEME://";
    bool ret11 = skill.MatchUri(uriString11, skillUri);
    EXPECT_EQ(true, ret11);
}

/**
 * @tc.number: MatchUri_0400
 * @tc.name: test MatchUri
 * @tc.desc: 1.system run normally
 *           2.test scheme and host case-sensitivity match.
*/
HWTEST_F(BmsBundleManagerTest, MatchUri_0400, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back("action001");
    SkillUri skillUri;
    skillUri.scheme = "myscheme";
    skillUri.host = "www.test.host";
    skillUri.port = "888";
    skillUri.path = "test";
    skillUri.pathStartWith = "";
    skillUri.pathRegex = "";
    std::string uriString1 = "myscheme://www.test.host:888/test";
    bool ret1 = skill.MatchUri(uriString1, skillUri);
    EXPECT_EQ(true, ret1);

    std::string uriString2 = "MYSCHEME://www.test.host:888/test";
    bool ret2 = skill.MatchUri(uriString2, skillUri);
    EXPECT_EQ(true, ret2);

    std::string uriString3 = "myscheme://WWW.TEST.HOST:888/test";
    bool ret3 = skill.MatchUri(uriString3, skillUri);
    EXPECT_EQ(true, ret3);

    std::string uriString4 = "MYSCHEME://WWW.TEST.HOST:888/test";
    bool ret4 = skill.MatchUri(uriString4, skillUri);
    EXPECT_EQ(true, ret4);

    std::string uriString5 = "MYSCHEME://WWW.TEST.HOST:888/test";
    bool ret5 = skill.MatchUri(uriString5, skillUri);
    EXPECT_EQ(true, ret5);

    std::string uriString6 = "mySCHEME://WWW.TEST.HOST:888/test";
    bool ret6 = skill.MatchUri(uriString6, skillUri);
    EXPECT_EQ(true, ret6);

    std::string uriString7 = "mySCHEME://WWW.test.HOST:888/test";
    bool ret7 = skill.MatchUri(uriString7, skillUri);
    EXPECT_EQ(true, ret7);

    std::string uriString8 = "MYSCHEME://WWW.test.HOST:888/test";
    bool ret8 = skill.MatchUri(uriString8, skillUri);
    EXPECT_EQ(true, ret8);
}

/**
 * @tc.number: MatchUri_0500
 * @tc.name: test MatchUri
 * @tc.desc: 1.system run normally
 *           2.test scheme and host case-sensitivity match.
*/
HWTEST_F(BmsBundleManagerTest, MatchUri_0500, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back("action001");
    SkillUri skillUri;
    skillUri.scheme = "MYSCHEME";
    skillUri.host = "www.test.host";
    skillUri.port = "888";
    skillUri.path = "test";
    skillUri.pathStartWith = "";
    skillUri.pathRegex = "";
    std::string uriString1 = "myscheme://www.test.host:888/test";
    bool ret1 = skill.MatchUri(uriString1, skillUri);
    EXPECT_EQ(true, ret1);

    std::string uriString2 = "MYSCHEME://www.test.host:888/test";
    bool ret2 = skill.MatchUri(uriString2, skillUri);
    EXPECT_EQ(true, ret2);

    std::string uriString3 = "myscheme://WWW.TEST.HOST:888/test";
    bool ret3 = skill.MatchUri(uriString3, skillUri);
    EXPECT_EQ(true, ret3);

    std::string uriString4 = "MYSCHEME://WWW.TEST.HOST:888/test";
    bool ret4 = skill.MatchUri(uriString4, skillUri);
    EXPECT_EQ(true, ret4);

    std::string uriString5 = "MYSCHEME://WWW.TEST.HOST:888/test";
    bool ret5 = skill.MatchUri(uriString5, skillUri);
    EXPECT_EQ(true, ret5);

    std::string uriString6 = "mySCHEME://WWW.TEST.HOST:888/test";
    bool ret6 = skill.MatchUri(uriString6, skillUri);
    EXPECT_EQ(true, ret6);

    std::string uriString7 = "mySCHEME://WWW.test.HOST:888/test";
    bool ret7 = skill.MatchUri(uriString7, skillUri);
    EXPECT_EQ(true, ret7);

    std::string uriString8 = "MYSCHEME://WWW.test.HOST:888/test";
    bool ret8 = skill.MatchUri(uriString8, skillUri);
    EXPECT_EQ(true, ret8);
}

/**
 * @tc.number: MatchUri_0600
 * @tc.name: test MatchUri
 * @tc.desc: 1.system run normally
 *           2.test scheme and host case-sensitivity match.
*/
HWTEST_F(BmsBundleManagerTest, MatchUri_0600, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back("action001");
    SkillUri skillUri;
    skillUri.scheme = "MYSCHEME";
    skillUri.host = "WWW.TEST.HOST";
    skillUri.port = "888";
    skillUri.path = "test";
    skillUri.pathStartWith = "";
    skillUri.pathRegex = "";
    std::string uriString1 = "myscheme://www.test.host:888/test";
    bool ret1 = skill.MatchUri(uriString1, skillUri);
    EXPECT_EQ(true, ret1);

    std::string uriString2 = "MYSCHEME://www.test.host:888/test";
    bool ret2 = skill.MatchUri(uriString2, skillUri);
    EXPECT_EQ(true, ret2);

    std::string uriString3 = "myscheme://WWW.TEST.HOST:888/test";
    bool ret3 = skill.MatchUri(uriString3, skillUri);
    EXPECT_EQ(true, ret3);

    std::string uriString4 = "MYSCHEME://WWW.TEST.HOST:888/test";
    bool ret4 = skill.MatchUri(uriString4, skillUri);
    EXPECT_EQ(true, ret4);

    std::string uriString5 = "MYSCHEME://WWW.TEST.HOST:888/test";
    bool ret5 = skill.MatchUri(uriString5, skillUri);
    EXPECT_EQ(true, ret5);

    std::string uriString6 = "mySCHEME://WWW.TEST.HOST:888/test";
    bool ret6 = skill.MatchUri(uriString6, skillUri);
    EXPECT_EQ(true, ret6);

    std::string uriString7 = "mySCHEME://WWW.test.HOST:888/test";
    bool ret7 = skill.MatchUri(uriString7, skillUri);
    EXPECT_EQ(true, ret7);

    std::string uriString8 = "MYSCHEME://WWW.test.HOST:888/test";
    bool ret8 = skill.MatchUri(uriString8, skillUri);
    EXPECT_EQ(true, ret8);
}

/**
 * @tc.number: MatchUri_0700
 * @tc.name: test MatchUri
 * @tc.desc: 1.system run normally
 *           2.test scheme and host case-sensitivity match.
*/
HWTEST_F(BmsBundleManagerTest, MatchUri_0700, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back("action001");
    SkillUri skillUri;
    skillUri.scheme = "myscheme";
    skillUri.host = "WWW.TEST.HOST";
    skillUri.port = "888";
    skillUri.path = "test";
    skillUri.pathStartWith = "";
    skillUri.pathRegex = "";
    std::string uriString1 = "myscheme://www.test.host:888/test";
    bool ret1 = skill.MatchUri(uriString1, skillUri);
    EXPECT_EQ(true, ret1);

    std::string uriString2 = "MYSCHEME://www.test.host:888/test";
    bool ret2 = skill.MatchUri(uriString2, skillUri);
    EXPECT_EQ(true, ret2);

    std::string uriString3 = "myscheme://WWW.TEST.HOST:888/test";
    bool ret3 = skill.MatchUri(uriString3, skillUri);
    EXPECT_EQ(true, ret3);

    std::string uriString4 = "MYSCHEME://WWW.TEST.HOST:888/test";
    bool ret4 = skill.MatchUri(uriString4, skillUri);
    EXPECT_EQ(true, ret4);

    std::string uriString5 = "MYSCHEME://WWW.TEST.HOST:888/test";
    bool ret5 = skill.MatchUri(uriString5, skillUri);
    EXPECT_EQ(true, ret5);

    std::string uriString6 = "mySCHEME://WWW.TEST.HOST:888/test";
    bool ret6 = skill.MatchUri(uriString6, skillUri);
    EXPECT_EQ(true, ret6);

    std::string uriString7 = "mySCHEME://WWW.test.HOST:888/test";
    bool ret7 = skill.MatchUri(uriString7, skillUri);
    EXPECT_EQ(true, ret7);

    std::string uriString8 = "MYSCHEME://WWW.test.HOST:888/test";
    bool ret8 = skill.MatchUri(uriString8, skillUri);
    EXPECT_EQ(true, ret8);
}

/**
 * @tc.number: MatchUri_0800
 * @tc.name: test MatchUri
 * @tc.desc: 1.system run normally
 *           2.test scheme and host case-sensitivity match.
*/
HWTEST_F(BmsBundleManagerTest, MatchUri_0800, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back("action001");
    SkillUri skillUri;
    skillUri.scheme = "mySCHEME";
    skillUri.host = "www.test.HOST";
    skillUri.port = "888";
    skillUri.path = "test";
    skillUri.pathStartWith = "";
    skillUri.pathRegex = "";
    std::string uriString1 = "myscheme://www.test.host:888/test";
    bool ret1 = skill.MatchUri(uriString1, skillUri);
    EXPECT_EQ(true, ret1);

    std::string uriString2 = "MYSCHEME://www.test.host:888/test";
    bool ret2 = skill.MatchUri(uriString2, skillUri);
    EXPECT_EQ(true, ret2);

    std::string uriString3 = "myscheme://WWW.TEST.HOST:888/test";
    bool ret3 = skill.MatchUri(uriString3, skillUri);
    EXPECT_EQ(true, ret3);

    std::string uriString4 = "MYSCHEME://WWW.TEST.HOST:888/test";
    bool ret4 = skill.MatchUri(uriString4, skillUri);
    EXPECT_EQ(true, ret4);

    std::string uriString5 = "MYSCHEME://WWW.TEST.HOST:888/test";
    bool ret5 = skill.MatchUri(uriString5, skillUri);
    EXPECT_EQ(true, ret5);

    std::string uriString6 = "mySCHEME://WWW.TEST.HOST:888/test";
    bool ret6 = skill.MatchUri(uriString6, skillUri);
    EXPECT_EQ(true, ret6);

    std::string uriString7 = "mySCHEME://WWW.test.HOST:888/test";
    bool ret7 = skill.MatchUri(uriString7, skillUri);
    EXPECT_EQ(true, ret7);

    std::string uriString8 = "MYSCHEME://WWW.test.HOST:888/test";
    bool ret8 = skill.MatchUri(uriString8, skillUri);
    EXPECT_EQ(true, ret8);
}

/**
 * @tc.number: MatchUri_0900
 * @tc.name: test MatchUri
 * @tc.desc: 1.system run normally
 *           2.test scheme and host case-sensitivity match.
*/
HWTEST_F(BmsBundleManagerTest, MatchUri_0900, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back("action001");
    SkillUri skillUri;
    skillUri.scheme = "myscheme";
    skillUri.host = "www.test.HOST";
    skillUri.port = "888";
    skillUri.path = "test";
    skillUri.pathStartWith = "";
    skillUri.pathRegex = "";
    std::string uriString1 = "myscheme://www.test.host:888/test";
    bool ret1 = skill.MatchUri(uriString1, skillUri);
    EXPECT_EQ(true, ret1);

    std::string uriString2 = "MYSCHEME://www.test.host:888/test";
    bool ret2 = skill.MatchUri(uriString2, skillUri);
    EXPECT_EQ(true, ret2);

    std::string uriString3 = "myscheme://WWW.TEST.HOST:888/test";
    bool ret3 = skill.MatchUri(uriString3, skillUri);
    EXPECT_EQ(true, ret3);

    std::string uriString4 = "MYSCHEME://WWW.TEST.HOST:888/test";
    bool ret4 = skill.MatchUri(uriString4, skillUri);
    EXPECT_EQ(true, ret4);

    std::string uriString5 = "MYSCHEME://WWW.TEST.HOST:888/test";
    bool ret5 = skill.MatchUri(uriString5, skillUri);
    EXPECT_EQ(true, ret5);

    std::string uriString6 = "mySCHEME://WWW.TEST.HOST:888/test";
    bool ret6 = skill.MatchUri(uriString6, skillUri);
    EXPECT_EQ(true, ret6);

    std::string uriString7 = "mySCHEME://WWW.test.HOST:888/test";
    bool ret7 = skill.MatchUri(uriString7, skillUri);
    EXPECT_EQ(true, ret7);

    std::string uriString8 = "MYSCHEME://WWW.test.HOST:888/test";
    bool ret8 = skill.MatchUri(uriString8, skillUri);
    EXPECT_EQ(true, ret8);
}

/**
 * @tc.number: MatchUri_1000
 * @tc.name: test MatchUri
 * @tc.desc: 1.system run normally
 *           2.test scheme and host case-sensitivity match.
*/
HWTEST_F(BmsBundleManagerTest, MatchUri_1000, Function | SmallTest | Level1)
{
    SkillUri skillUri;
    skillUri.scheme = "myscheme";
    skillUri.host = "www.test.com/testPath";
    std::string uriString = "myscheme://www.test.com/testPath";
    struct Skill skill;
    bool ret = skill.MatchUri(uriString, skillUri);
    EXPECT_EQ(true, ret);
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
    ErrCode ret = info.IsAbilityEnabledV9(abilityInfo, ServiceConstants::NOT_EXIST_USERID, isEnable);
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
        Constants::MODULE_NAME, Constants::ABILITY_NAME, isEnabled, ServiceConstants::NOT_EXIST_USERID);
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
    ErrCode ret = info.SetApplicationEnabled(enabled, CALLER_NAME_UT, USERID);
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
    int fd = 2;
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::set<int32_t> ret = hostImpl->GetExistsCommonUserIs();
    EXPECT_EQ(ret.size(), 1);
    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    ret = hostImpl->GetExistsCommonUserIs();
    EXPECT_EQ(ret.size(), 0);
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

    ret = hostImpl->GetSandboxBundleInfo(TEST_BUNDLE_NAME, appIndex, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    appIndex = 1 + Constants::MAX_SANDBOX_APP_INDEX;
    ret = hostImpl->GetSandboxBundleInfo(TEST_BUNDLE_NAME, appIndex, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    appIndex = Constants::INITIAL_SANDBOX_APP_INDEX + 1;
    ret = hostImpl->GetSandboxBundleInfo(
        TEST_BUNDLE_NAME, appIndex, Constants::INVALID_USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_QUERY_INVALID_USER_ID);
    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    ret = hostImpl->GetSandboxBundleInfo(TEST_BUNDLE_NAME, appIndex, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR);
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
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    bool retBool = hostImpl->GetApplicationInfo("", flags, USERID, appInfo);
    EXPECT_EQ(retBool, false);

    ErrCode retCode = hostImpl->GetApplicationInfoV9("", flags, USERID, appInfo);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    retBool = hostImpl->GetApplicationInfos(flags, USERID, appInfos);
    EXPECT_EQ(retBool, false);

    retCode = hostImpl->GetApplicationInfosV9(flags, USERID, appInfos);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}
} // OHOS