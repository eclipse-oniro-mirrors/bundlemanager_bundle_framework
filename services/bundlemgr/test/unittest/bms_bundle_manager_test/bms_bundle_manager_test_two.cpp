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

class BmsBundleManagerTest2 : public testing::Test {
public:
    BmsBundleManagerTest2();
    ~BmsBundleManagerTest2();
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

std::shared_ptr<BundleMgrService> BmsBundleManagerTest2::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleManagerTest2::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleManagerTest2::BmsBundleManagerTest2()
{}

BmsBundleManagerTest2::~BmsBundleManagerTest2()
{}

bool BmsBundleManagerTest2::InstallSystemBundle(const std::string &filePath) const
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

ErrCode BmsBundleManagerTest2::InstallThirdPartyBundle(const std::string &filePath) const
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

ErrCode BmsBundleManagerTest2::UpdateThirdPartyBundle(const std::string &filePath) const
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

ErrCode BmsBundleManagerTest2::UnInstallBundle(const std::string &bundleName) const
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

void BmsBundleManagerTest2::SetUpTestCase()
{
}

void BmsBundleManagerTest2::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleManagerTest2::SetUp()
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

void BmsBundleManagerTest2::TearDown()
{
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_CODE_DIR);
}

void BmsBundleManagerTest2::CheckFileExist() const
{
    int bundleCodeExist = access(BUNDLE_CODE_DIR.c_str(), F_OK);
    EXPECT_EQ(bundleCodeExist, 0) << "the bundle code dir does not exists: " << BUNDLE_CODE_DIR;

    int bundleDataExist = access(BUNDLE_DATA_DIR.c_str(), F_OK);
    EXPECT_EQ(bundleDataExist, 0) << "the bundle data dir does not exists: " << BUNDLE_DATA_DIR;
}

void BmsBundleManagerTest2::CheckFileNonExist() const
{
    int bundleCodeExist = access(BUNDLE_CODE_DIR.c_str(), F_OK);
    EXPECT_NE(bundleCodeExist, 0) << "the bundle code dir exists: " << BUNDLE_CODE_DIR;

    int bundleDataExist = access(BUNDLE_DATA_DIR.c_str(), F_OK);
    EXPECT_NE(bundleDataExist, 0) << "the bundle data dir exists: " << BUNDLE_DATA_DIR;
}

const std::shared_ptr<BundleDataMgr> BmsBundleManagerTest2::GetBundleDataMgr() const
{
    EXPECT_NE(bundleMgrService_->GetDataMgr(), nullptr);
    return bundleMgrService_->GetDataMgr();
}

const std::shared_ptr<BundleInstallerManager> BmsBundleManagerTest2::GetBundleInstallerManager() const
{
    return manager_;
}

void BmsBundleManagerTest2::ClearDataMgr()
{
    bundleMgrService_->dataMgr_ = nullptr;
}

void BmsBundleManagerTest2::ResetDataMgr()
{
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(bundleMgrService_->dataMgr_, nullptr);
}

void BmsBundleManagerTest2::ClearConnectAbilityMgr()
{
    bundleMgrService_->connectAbilityMgr_.clear();
}

void BmsBundleManagerTest2::ResetConnectAbilityMgr()
{
    auto ptr = bundleMgrService_->GetConnectAbility();
    EXPECT_FALSE(bundleMgrService_->connectAbilityMgr_.empty());
}

void BmsBundleManagerTest2::StopInstalldService() const
{
    if (installdService_->IsServiceReady()) {
        installdService_->Stop();
        InstalldClient::GetInstance()->ResetInstalldProxy();
    }
}

void BmsBundleManagerTest2::StopBundleService()
{
    if (bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStop();
        bundleMgrService_.reset();
    }
}

void BmsBundleManagerTest2::CreateInstallerManager()
{
    if (manager_ != nullptr) {
        return;
    }
    manager_ = std::make_shared<BundleInstallerManager>();
    EXPECT_NE(nullptr, manager_);
}

void BmsBundleManagerTest2::ClearBundleInfo()
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
 * @tc.number: BundleMgrHostImpl_1000
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_1000, Function | MediumTest | Level1)
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
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
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
}

/**
 * @tc.number: BundleMgrHostImpl_1100
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_1100, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int uid = -1;
    std::string bundleName;
    std::vector<int> gids;
    std::vector<BundleInfo> bundleInfos;
    std::vector<int64_t> bundleStats;
    std::vector<Metadata> provisionMetadatas;
    AppProvisionInfo appProvisionInfo;

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
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

    int retInt = hostImpl->GetUidByDebugBundleName("", USERID);
    EXPECT_EQ(retInt, Constants::INVALID_UID);

    retBool = hostImpl->GetBundleStats("", USERID, bundleStats);
    EXPECT_EQ(retBool, false);

    retCode = hostImpl->GetAppProvisionInfo("", USERID, appProvisionInfo);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    retCode = hostImpl->GetProvisionMetadata("", USERID, provisionMetadatas);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BundleMgrHostImpl_1200
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_1200, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<SharedBundleInfo> sharedBundles;
    std::vector<Dependency> dependencies;
    AAFwk::Want want;
    AbilityInfo abilityInfo;
    SharedBundleInfo sharedBundleInfo;
    std::vector<PluginBundleInfo> pluginBundleInfos;

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
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

    retCode = hostImpl->GetAllSharedBundleInfo(sharedBundles);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    retCode = hostImpl->GetSharedBundleInfo("", "", sharedBundles);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    retCode = hostImpl->GetSharedBundleInfoBySelf("", sharedBundleInfo);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    retCode = hostImpl->GetSharedDependencies("", "", dependencies);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    retBool = hostImpl->VerifyDependency("");
    EXPECT_EQ(retBool, false);

    retCode = hostImpl->QueryLauncherAbilityInfos(want, USERID, abilityInfos);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    retCode = hostImpl->GetLauncherAbilityInfoSync("", USERID, abilityInfos);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    retCode = hostImpl->GetAllPluginInfo("", USERID, pluginBundleInfos);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_NULL_PTR);

    retCode = hostImpl->GetPluginInfosForSelf(pluginBundleInfos);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_NULL_PTR);

    retBool = hostImpl->IsPreInstallApp("");
    EXPECT_EQ(retBool, false);
}

/**
 * @tc.number: BundleMgrHostImpl_1300
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_1300, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string label;
    std::vector<BundleInfo> bundleInfos;
    AAFwk::Want want;
    HapModuleInfo hapModuleInfo;
    AbilityInfo abilityInfo;
    abilityInfo.bundleName = TEST_BUNDLE_NAME;
    abilityInfo.package = "package";

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
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
}

/**
 * @tc.number: BundleMgrHostImpl_1200
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_1400, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t upgradeFlag = 0;
    std::string result;
    bool isRemovable = true;

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
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
}

/**
 * @tc.number: BundleMgrHostImpl_1500
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_1500, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool isRemovable = true;
    std::vector<FormInfo> formInfos;
    std::vector<ShortcutInfo> shortcutInfos;
    std::vector<CommonEventInfo> commonEventInfos;
    AbilityInfo abilityInfo;

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
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
}

/**
 * @tc.number: BundleMgrHostImpl_1600
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_1600, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    AAFwk::Want want;

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
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
}

/**
 * @tc.number: BundleMgrHostImpl_1600
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_1700, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ExtensionAbilityInfo extensionAbilityInfo;

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
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
}

/**
 * @tc.number: BundleMgrHostImpl_1800
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_1800, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    std::vector<BaseSharedBundleInfo> baseSharedBundleInfos;
    std::vector<std::string> dependentModuleNames;
    AAFwk::Want want;
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    bool findDefaultApp = false;

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    bool retBool = hostImpl->ImplicitQueryInfoByPriority(
        want, flags, USERID, abilityInfo, extensionInfo);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->ImplicitQueryInfos(
        want, flags, USERID, false, abilityInfos, extensionInfos, findDefaultApp);
    EXPECT_EQ(retBool, false);

    retBool = hostImpl->GetAllDependentModuleNames(
        "", "", dependentModuleNames);
    EXPECT_EQ(retBool, false);

    ErrCode retCode = hostImpl->GetBaseSharedBundleInfos(
        "", baseSharedBundleInfos);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BundleMgrHostImpl_1900
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_1900, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t status = 0;
    uint32_t resId = 0;
    int32_t appIndex = Constants::INITIAL_SANDBOX_APP_INDEX + 1;
    size_t len = 1;
    bool isEnabled = true;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    std::unique_ptr<uint8_t[]> mediaDataPtr;
    AAFwk::Want want;
    AbilityInfo abilityInfo;
    BundleInfo bundleInfo;
    ExtensionAbilityInfo extensionInfo;
    HapModuleInfo hapModuleInfo;

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });

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

    retCode = hostImpl->SetApplicationEnabled("", isEnabled, USERID);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_SERVICE_NOT_READY);

    retCode = hostImpl->SetAbilityEnabled(abilityInfo, isEnabled, USERID);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_SERVICE_NOT_READY);

    retCode = hostImpl->GetBundleInfoForSelf(appIndex, bundleInfo);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    std::vector<FormInfo> formInfos;
    bool retBool = hostImpl->GetFormsInfoByModule(
        TEST_BUNDLE_NAME, "moduleName", formInfos);
    EXPECT_EQ(retBool, false);
}

/**
 * @tc.number: BundleMgrHostImpl_1901
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.query infos failed by data mgr is empty
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_1901, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool isEnabled = true;

    auto retCode = hostImpl->SetApplicationEnabled("", isEnabled, USERID);
    EXPECT_NE(retCode, ERR_OK);
}

/**
 * @tc.number: BundleMgrHostImpl_2000
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetBundleArchiveInfoV9
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_2000, Function | MediumTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_2100, Function | MediumTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_2200, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    AbilityInfo abilityInfo;
    HapModuleInfo hapModuleInfo;
    abilityInfo.bundleName = "";
    abilityInfo.package = "";
    bool ret = hostImpl->GetHapModuleInfo(abilityInfo, USERID, hapModuleInfo);
    EXPECT_EQ(ret, false);

    abilityInfo.bundleName = TEST_BUNDLE_NAME;
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
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_2300, Function | MediumTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_2400, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string result;
    bool ret = hostImpl->DumpBundleInfo("", Constants::ALL_USERID, result);
    EXPECT_EQ(ret, false);
    ret = hostImpl->DumpBundleInfo(TEST_BUNDLE_NAME, Constants::ALL_USERID, result);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_2500
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test DumpShortcutInfo
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_2500, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string result;
    bool ret = hostImpl->DumpShortcutInfo("", Constants::ALL_USERID, result);
    EXPECT_EQ(ret, false);
    ret = hostImpl->DumpShortcutInfo(TEST_BUNDLE_NAME, Constants::ALL_USERID, result);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_2600
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetAppType
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_2600, Function | MediumTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_2700, Function | MediumTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_2800, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<int64_t> bundleStats;
    bool ret = hostImpl->GetBundleStats("", Constants::INVALID_USERID, bundleStats);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleMgrHostImpl_2900
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test CleanBundleCacheFilesAutomatic
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_2900, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    uint64_t cacheSize = 0;
    ErrCode ret = hostImpl->CleanBundleCacheFilesAutomatic(cacheSize);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
/**
 * @tc.number: BundleMgrHostImpl_3000
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test QueryAbilityInfo
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_3000, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    AAFwk::Want want;
    AbilityInfo abilityInfo;
    sptr<IRemoteObject> callBack;
    bool ret = hostImpl->QueryAbilityInfo(
        want, 0, Constants::INVALID_USERID, abilityInfo, callBack);
    EXPECT_EQ(ret, false);
}
#endif

/**
 * @tc.number: BundleMgrHostImpl_3100
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test CheckAbilityEnableInstall
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_3100, Function | MediumTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_3200, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;
    BundleInfo bundleInfo;
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode retCode = hostImpl->GetBundleArchiveInfoV9(bundlePath, flags, bundleInfo);
    EXPECT_EQ(retCode, ERR_OK);
}

/**
 * @tc.number: BundleMgrHostImpl_3201
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetBundleArchiveInfoV9
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_3201, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;
    BundleInfo bundleInfo;
    std::string bundlePath = "/data/storage/el2/base/../../bundle";
    ErrCode retCode = hostImpl->GetBundleArchiveInfoV9(bundlePath, flags, bundleInfo);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INVALID_HAP_PATH);
}

/**
 * @tc.number: BundleMgrHostImpl_3300
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetPermissionDef
 */
HWTEST_F(BmsBundleManagerTest2, BundleMgrHostImpl_3300, Function | MediumTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0001, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0002, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0003, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", "", "", MODULE_NAME);
    std::vector<AbilityInfo> abilityInfos;
    bool testRet = GetBundleDataMgr()->QueryLauncherAbilityInfos(want, 100, abilityInfos) == ERR_OK;
    EXPECT_EQ(testRet, true);
    testRet = GetBundleDataMgr()->QueryLauncherAbilityInfos(want, Constants::INVALID_USERID, abilityInfos) == ERR_OK;
    EXPECT_EQ(testRet, false);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: TestMgrByUserId_0007
 * @tc.name: test GetPreInstallBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0007, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0008, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0009, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0010, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0011, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0012, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0013, Function | SmallTest | Level1)
{
    AAFwk::Want want;
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
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0014, Function | SmallTest | Level1)
{
    AbilityInfo abilityInfo;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfoByUri(
        ServiceConstants::DATA_ABILITY_URI_PREFIX, Constants::INVALID_USERID, abilityInfo);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: TestMgrByUserId_0015
 * @tc.name: test GetApplicationInfos
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0015, Function | SmallTest | Level1)
{
    ApplicationInfo appInfo;
    std::vector<ApplicationInfo> appInfos;
    bool testRet = GetBundleDataMgr()->GetApplicationInfo(
        TEST_BUNDLE_NAME, 0, Constants::INVALID_USERID, appInfo);
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
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0016, Function | SmallTest | Level1)
{
    BundleInfo bundleInfo;
    std::vector<ApplicationInfo> appInfos;
    bool testRet = GetBundleDataMgr()->GetBundleInfo(
        TEST_BUNDLE_NAME, 0, bundleInfo, Constants::INVALID_USERID);
    EXPECT_EQ(testRet, false);
    ErrCode testRet1 = GetBundleDataMgr()->GetBundleInfoV9(
        TEST_BUNDLE_NAME, 0, bundleInfo, Constants::INVALID_USERID);
    EXPECT_EQ(testRet1, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    testRet1 = GetBundleDataMgr()->GetBundleInfoV9(
        TEST_BUNDLE_NAME, 0, bundleInfo, Constants::ANY_USERID);
    EXPECT_EQ(testRet1, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: TestMgrByUserId_0017
 * @tc.name: test GetBundleInfos
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0017, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0018, Function | SmallTest | Level1)
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
 * @tc.number: TestMgrByUserId_0019
 * @tc.name: test GetDebugBundleList
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0019, Function | SmallTest | Level1)
{
    std::vector<std::string> appInfos;
    std::vector<BundleInfo> bundleInfos;
    bool testRet = GetBundleDataMgr()->GetDebugBundleList(appInfos, Constants::INVALID_USERID);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: TestMgrByUserId_0020
 * @tc.name: test GetInnerBundleInfoWithBundleFlagsV9
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0020, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    ErrCode testRet = GetBundleDataMgr()->GetInnerBundleInfoWithFlagsV9(
        TEST_BUNDLE_NAME, 0, info, Constants::INVALID_USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    testRet = GetBundleDataMgr()->GetInnerBundleInfoWithBundleFlagsV9(
        TEST_BUNDLE_NAME, 0, info, Constants::INVALID_USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: TestMgrByUserId_0021
 * @tc.name: test SetAbilityEnabled
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0021, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    ErrCode testRet = GetBundleDataMgr()->SetApplicationEnabled(
        TEST_BUNDLE_NAME, 0, false, CALLER_NAME_UT, Constants::INVALID_USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    AbilityInfo abilityInfo;
    testRet = GetBundleDataMgr()->SetAbilityEnabled(
        abilityInfo, 0, false, Constants::INVALID_USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    testRet = GetBundleDataMgr()->SetAbilityEnabled(
        abilityInfo, 0, false, Constants::UNSPECIFIED_USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: TestMgrByUserId_0022
 * @tc.name: test GetShortcutInfoV9
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0022, Function | SmallTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    bool testRet = GetBundleDataMgr()->GetShortcutInfos(
        TEST_BUNDLE_NAME, Constants::INVALID_USERID, shortcutInfos);
    EXPECT_EQ(testRet, false);
    ErrCode testRet1 = GetBundleDataMgr()->GetShortcutInfoV9(
        TEST_BUNDLE_NAME, Constants::INVALID_USERID, shortcutInfos);
    EXPECT_EQ(testRet1, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: TestMgrByUserId_0023
 * @tc.name: test GetInnerBundleUserInfoByUserId
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0023, Function | SmallTest | Level1)
{
    InnerBundleUserInfo innerBundleUserInfo;
    bool testRet = GetBundleDataMgr()->GetInnerBundleUserInfoByUserId(
        TEST_BUNDLE_NAME, Constants::INVALID_USERID, innerBundleUserInfo);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: TestMgrByUserId_0024
 * @tc.name: test ExplicitQueryExtensionInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0024, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0025, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    bool testRet = GetBundleDataMgr()->ImplicitQueryInfoByPriority(
        want, FLAG, Constants::INVALID_USERID, abilityInfo, extensionInfo);
    EXPECT_EQ(testRet, false);

    testRet = GetBundleDataMgr()->ImplicitQueryInfoByPriority(
        want, FLAG, USERID, abilityInfo, extensionInfo);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: TestMgrByUserId_0026
 * @tc.name: test QueryExtensionAbilityInfoByUri
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0026, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, TestMgrByUserId_0027, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ErrCode testRet = GetBundleDataMgr()->CheckInnerBundleInfoWithFlags(
        innerBundleInfo, ApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE, USERID);
    EXPECT_EQ(testRet, ERR_OK);
    testRet = GetBundleDataMgr()->CheckInnerBundleInfoWithFlags(
        innerBundleInfo,
            ApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE, Constants::INVALID_USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    testRet = GetBundleDataMgr()->CheckInnerBundleInfoWithFlags(
        innerBundleInfo, ApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE, USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_DISABLED);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0001
 * @tc.name: test QueryLauncherAbilityInfos
 * @tc.desc: 1.system run normally
 *           2.bundle is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0001, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<AbilityInfo> abilityInfos;
    ErrCode testRet = hostImpl->QueryLauncherAbilityInfos(
        want, USERID, abilityInfos);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetAllPluginInfo_0001
 * @tc.name: test GetAllPluginInfo
 * @tc.desc: 1.system run normally
 *           2.bundle not exist
 */
HWTEST_F(BmsBundleManagerTest2, GetAllPluginInfo_0001, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<PluginBundleInfo> pluginBundleInfos;
    ErrCode retCode = hostImpl->GetAllPluginInfo("", USERID, pluginBundleInfos);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetPluginInfosForSelf_0001
 * @tc.name: test GetPluginInfosForSelf
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest2, GetPluginInfosForSelf_0001, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<PluginBundleInfo> pluginBundleInfos;
    ErrCode retCode = hostImpl->GetPluginInfosForSelf(pluginBundleInfos);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_INVALID_UID);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0002
 * @tc.name: test GetHapModuleInfo
 * @tc.desc: 1.system run normally
 *           2.bundle is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0002, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0004, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    bool testRet = GetBundleDataMgr()->GetInnerBundleInfoWithFlags(
        TEST_BUNDLE_NAME, 0, info, USERID);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0005
 * @tc.name: test GetInnerBundleInfoWithFlagsV9
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0005, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    ErrCode testRet = GetBundleDataMgr()->GetInnerBundleInfoWithFlagsV9(
        TEST_BUNDLE_NAME, 0, info, USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0006
 * @tc.name: test GetInnerBundleInfoWithBundleFlagsV9
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0006, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    ErrCode testRet = GetBundleDataMgr()->GetInnerBundleInfoWithBundleFlagsV9(
        TEST_BUNDLE_NAME, 0, info, USERID);
    EXPECT_NE(testRet, ERR_OK);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0007
 * @tc.name: test GetInnerBundleInfoWithDisable
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0007, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    bool testRet = GetBundleDataMgr()->GetInnerBundleInfoWithDisable(
        TEST_BUNDLE_NAME, info);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0008
 * @tc.name: test EnableBundle
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0008, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    bool testRet = GetBundleDataMgr()->EnableBundle(
        TEST_BUNDLE_NAME);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0009
 * @tc.name: test SetApplicationEnabled
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0009, Function | SmallTest | Level1)
{
    bool isEnable = true;
    ErrCode testRet = GetBundleDataMgr()->SetApplicationEnabled(
        TEST_BUNDLE_NAME, 0, isEnable, CALLER_NAME_UT, USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0010
 * @tc.name: test IsModuleRemovable
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0010, Function | SmallTest | Level1)
{
    bool isRemovable;
    ErrCode testRet = GetBundleDataMgr()->IsModuleRemovable(
        TEST_BUNDLE_NAME, MODULE_NAME, isRemovable);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0011
 * @tc.name: test IsAbilityEnabled and SetAbilityEnabled
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0011, Function | SmallTest | Level1)
{
    bool isEnable = true;
    AbilityInfo abilityInfo;
    ErrCode testRet = GetBundleDataMgr()->IsAbilityEnabled(
        abilityInfo, 0, isEnable);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    testRet = GetBundleDataMgr()->SetAbilityEnabled(
        abilityInfo, 0, isEnable, USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0012
 * @tc.name: test SetModuleUpgradeFlag
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0012, Function | SmallTest | Level1)
{
    int32_t upgradeFlag = 1;
    ErrCode testRet = GetBundleDataMgr()->SetModuleUpgradeFlag(
        TEST_BUNDLE_NAME, MODULE_NAME, upgradeFlag);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0013
 * @tc.name: test GetModuleUpgradeFlag
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0013, Function | SmallTest | Level1)
{
    int32_t testRet = GetBundleDataMgr()->GetModuleUpgradeFlag(
        TEST_BUNDLE_NAME, MODULE_NAME);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0014
 * @tc.name: test GetInnerBundleUserInfoByUserId
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0014, Function | SmallTest | Level1)
{
    InnerBundleUserInfo info;
    bool testRet = GetBundleDataMgr()->GetInnerBundleUserInfoByUserId(
        TEST_BUNDLE_NAME, USERID, info);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0015
 * @tc.name: test GetInnerBundleUserInfos
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0015, Function | SmallTest | Level1)
{
    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    bool testRet = GetBundleDataMgr()->GetInnerBundleUserInfos(
        TEST_BUNDLE_NAME, innerBundleUserInfos);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0016
 * @tc.name: test GetAllDependentModuleNames
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0016, Function | SmallTest | Level1)
{
    std::vector<std::string> dependentModuleNames;
    bool testRet = GetBundleDataMgr()->GetAllDependentModuleNames(
        TEST_BUNDLE_NAME, MODULE_NAME, dependentModuleNames);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0018
 * @tc.name: test FetchInnerBundleInfo
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0018, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    bool testRet = GetBundleDataMgr()->FetchInnerBundleInfo(
        TEST_BUNDLE_NAME, innerBundleInfo);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetMgrFalseByNoBundle_0020
 * @tc.name: test GetLauncherAbilityInfoSync
 * @tc.desc: 1.system run normally
 *           2.bundle is empty
*/
HWTEST_F(BmsBundleManagerTest2, GetMgrFalseByNoBundle_0020, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string bundleName = "action.system.home";
    std::vector<AbilityInfo> abilityInfos;
    ErrCode testRet = hostImpl->GetLauncherAbilityInfoSync(
        bundleName, USERID, abilityInfos);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetBundleDataMgr_0001
 * @tc.name: test ExplicitQueryAbilityInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0001, Function | SmallTest | Level1)
{
    AAFwk::Want want;
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0002, Function | SmallTest | Level1)
{
    AAFwk::Want want;
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0003, Function | SmallTest | Level1)
{
    AAFwk::Want want;
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0004, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0005, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0006, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0007, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0008, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0009, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0010, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0011, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0012, Function | SmallTest | Level1)
{
    bool testRet = GetBundleDataMgr()->CheckIsSystemAppByUid(Constants::ROOT_UID);
    EXPECT_EQ(testRet, true);
    testRet = GetBundleDataMgr()->CheckIsSystemAppByUid(ServiceConstants::BMS_UID);
    EXPECT_EQ(testRet, true);
}

/**
 * @tc.number: GetBundleDataMgr_0013
 * @tc.name: test CheckIsSystemAppByUid
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0013, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0014, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    int32_t appIndex = Constants::INITIAL_SANDBOX_APP_INDEX + 1;
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0015, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0016, Function | SmallTest | Level1)
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
    appIndex = Constants::INITIAL_SANDBOX_APP_INDEX + 1;
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0017, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_BACKUP_NAME, "", MODULE_NAME);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t appIndex = Constants::INITIAL_SANDBOX_APP_INDEX + 2;
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0018, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0019, Function | SmallTest | Level1)
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
 * @tc.number: GetBundleDataMgr_0021
 * @tc.name: test AddInnerBundleUserInfo
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0021, Function | SmallTest | Level1)
{
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = TEST_BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleUserInfo.bundleUserInfo.userId = Constants::INVALID_USERID;
    innerBundleUserInfo.uid = 65535;
    bool res = GetBundleDataMgr()->AddInnerBundleUserInfo(
        TEST_BUNDLE_NAME, innerBundleUserInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetBundleDataMgr_0022
 * @tc.name: test ImplicitQueryAllExtensionInfos
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest2, GetBundleDataMgr_0022, Function | SmallTest | Level1)
{
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = TEST_BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleUserInfo.bundleUserInfo.userId = Constants::INVALID_USERID;
    bool res = GetBundleDataMgr()->RemoveInnerBundleUserInfo(
        TEST_BUNDLE_NAME, Constants::INVALID_USERID);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: RegisterBundleEventCallback_0001
 * @tc.name: test RegisterBundleEventCallback
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest2, RegisterBundleEventCallback_0001, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, GetDataStorage_0001, Function | SmallTest | Level1)
{
    auto dataStorage = GetBundleDataMgr()->GetDataStorage();
    EXPECT_NE(dataStorage, nullptr);
    std::map<std::string, InnerBundleInfo> infos;
    bool res = dataStorage->LoadAllData(infos);
    EXPECT_EQ(res, true);
}

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
/**
 * @tc.number: BundleFreeInstall_0100
 * @tc.name: test CheckAbilityEnableInstall
 * @tc.desc: 1.check ability infos
 */
HWTEST_F(BmsBundleManagerTest2, BundleFreeInstall_0100, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    int32_t missionId = 0;
    AAFwk::Want want;
    ElementName name;
    name.SetBundleName(BUNDLE_BACKUP_NAME);
    name.SetAbilityName(ABILITY_BACKUP_NAME);
    name.SetDeviceID("100");
    want.SetElement(name);

    auto bundleDistributedManager = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleDistributedManager();
    DelayedSingleton<BundleMgrService>::GetInstance()->bundleDistributedManager_ =
        std::make_shared<BundleDistributedManager>();
    bool ret = hostImpl->CheckAbilityEnableInstall(want, missionId, USERID, nullptr);
    EXPECT_EQ(ret, false);

    DelayedSingleton<BundleMgrService>::GetInstance()->bundleDistributedManager_ = nullptr;
    ret = hostImpl->CheckAbilityEnableInstall(want, missionId, USERID, nullptr);
    EXPECT_EQ(ret, false);

    name.SetBundleName("");
    want.SetElement(name);
    ret = hostImpl->CheckAbilityEnableInstall(want, missionId, USERID, nullptr);
    EXPECT_EQ(ret, false);

    name.SetAbilityName("");
    want.SetElement(name);
    ret = hostImpl->CheckAbilityEnableInstall(want, missionId, USERID, nullptr);
    EXPECT_EQ(ret, false);

    name.SetDeviceID("");
    want.SetElement(name);
    ret = hostImpl->CheckAbilityEnableInstall(want, missionId, USERID, nullptr);
    EXPECT_EQ(ret, false);

    DelayedSingleton<BundleMgrService>::GetInstance()->bundleDistributedManager_ = bundleDistributedManager;
}

/**
 * @tc.number: BundleFreeInstall_0200
 * @tc.name: test CheckAbilityEnableInstall
 * @tc.desc: 1.check ability infos
 */
HWTEST_F(BmsBundleManagerTest2, BundleFreeInstall_0200, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    int32_t missionId = 0;
    AAFwk::Want want;
    ElementName name;
    name.SetBundleName(BUNDLE_BACKUP_NAME);
    name.SetDeviceID("100");
    want.SetElement(name);

    bool ret = hostImpl->CheckAbilityEnableInstall(want, missionId, USERID, nullptr);
    EXPECT_EQ(ret, false);

    name.SetAbilityName(ABILITY_BACKUP_NAME);
    name.SetDeviceID("");
    want.SetElement(name);
    ret = hostImpl->CheckAbilityEnableInstall(want, missionId, USERID, nullptr);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleFreeInstall_0300
 * @tc.name: test QueryAbilityInfo
 * @tc.desc: 1.check ability infos
 */
HWTEST_F(BmsBundleManagerTest2, BundleFreeInstall_0300, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    ClearConnectAbilityMgr();
    ScopeGuard stateGuard([&] { ResetConnectAbilityMgr(); });

    AAFwk::Want want;
    int32_t flags = 1;
    AbilityInfo abilityInfo;
    sptr<IRemoteObject> callBack = nullptr;
    bool ret = hostImpl->QueryAbilityInfo(want, flags, USERID, abilityInfo, callBack);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleFreeInstall_0500
 * @tc.name: test ProcessPreload
 * @tc.desc: 1.check ability infos
 */
HWTEST_F(BmsBundleManagerTest2, BundleFreeInstall_0500, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    ClearConnectAbilityMgr();
    ScopeGuard stateGuard([&] { ResetConnectAbilityMgr(); });

    AAFwk::Want want;
    bool ret = hostImpl->ProcessPreload(want);
    hostImpl->UpgradeAtomicService(want, USERID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: SilentInstall_0100
 * @tc.name: test SilentInstall
 * @tc.desc: 1.check ability infos
 */
HWTEST_F(BmsBundleManagerTest2, SilentInstall_0100, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    AAFwk::Want want;
    bool ret = hostImpl->SilentInstall(want, USERID, nullptr);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: SilentInstall_0200
 * @tc.name: test SilentInstall
 * @tc.desc: 1.check ability infos
 */
HWTEST_F(BmsBundleManagerTest2, SilentInstall_0200, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    ClearConnectAbilityMgr();
    ScopeGuard stateGuard([&] { ResetConnectAbilityMgr(); });

    AAFwk::Want want;
    bool ret = hostImpl->SilentInstall(want, USERID, nullptr);
    EXPECT_EQ(ret, false);
}
#endif

/**
 * @tc.number: DataMgrFailedScene_0100
 * @tc.name: test failed scene when bundle info is not existed
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest2, DataMgrFailedScene_0100, Function | SmallTest | Level1)
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

    std::string appFeature = "hos_system_app";
    ret = dataMgr->GetAppFeature(BUNDLE_NAME, appFeature);
    EXPECT_EQ(ret, false);

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
HWTEST_F(BmsBundleManagerTest2, DataMgrFailedScene_0200, Function | SmallTest | Level1)
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
}

/**
 * @tc.number: DataMgrFailedScene_0300
 * @tc.name: test failed scene when preInstallDataStorage is null
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest2, DataMgrFailedScene_0300, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleManagerTest2, DataMgrFailedScene_0400, Function | SmallTest | Level1)
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

/**
 * @tc.name: HasUserInstallInBundle_0100
 * @tc.desc: 1.install the hap
 *           2.check if it is a user installation
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest2, HasUserInstallInBundle_0100, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    bool result = dataMgr->HasUserInstallInBundle(BUNDLE_PREVIEW_NAME, USERID);
    EXPECT_EQ(result, true);

    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.name: HasUserInstallInBundle_0200
 * @tc.desc: 1.install the hap
 *           2.check if it is a user installation
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest2, HasUserInstallInBundle_0200, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    bool result = dataMgr->HasUserInstallInBundle("wrong", USERID);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: GetBundleStats_0100
 * @tc.desc: 1.install the hap
 *           2.query bundle stats
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest2, GetBundleStats_0100, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::vector<int64_t> bundleStats;

    bool result = dataMgr->GetBundleStats(BUNDLE_PREVIEW_NAME, USERID, bundleStats);
    EXPECT_EQ(result, true);

    result = dataMgr->GetBundleStats(BUNDLE_PREVIEW_NAME, Constants::INVALID_USERID, bundleStats);
    EXPECT_EQ(result, true);

    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.name: GetBundleStats_0200
 * @tc.desc: 1.query bundle stats
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest2, GetBundleStats_0200, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::vector<int64_t> bundleStats;

    bool result = dataMgr->GetBundleStats("wrong", USERID, bundleStats);
    EXPECT_EQ(result, false);
}


/**
 * @tc.name: GetBundleGids_0100
 * @tc.desc: 1.install the hap
 *           2.query bundle gids
 * @tc.type: FUNC
 * @tc.require: issueI5MZ33
 */
HWTEST_F(BmsBundleManagerTest2, GetBundleGids_0100, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::vector<int> gids;

    bool result = dataMgr->GetBundleGids(BUNDLE_PREVIEW_NAME, gids);
    EXPECT_EQ(result, false);
}

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
/**
 * @tc.number: GetBundleSpaceSize_0100
 * @tc.name: test GetBundleSpaceSize
 * @tc.desc: 1.check ability infos
 */
HWTEST_F(BmsBundleManagerTest2, GetBundleSpaceSize_0100, Function | MediumTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    int64_t size = 0;
    int64_t ret = dataMgr->GetBundleSpaceSize(BUNDLE_PREVIEW_NAME);
    EXPECT_EQ(ret, size);
}

/**
 * @tc.number: GetBundleSpaceSize_0200
 * @tc.name: test GetAllFreeInstallBundleSpaceSize
 * @tc.desc: 1.check ability infos
 */
HWTEST_F(BmsBundleManagerTest2, GetBundleSpaceSize_0200, Function | MediumTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    int64_t size = 0;
    int64_t ret = dataMgr->GetAllFreeInstallBundleSpaceSize();
    EXPECT_EQ(ret, size);
}

/**
 * @tc.number: GetBundleSpaceSize_0300
 * @tc.name: test GetFreeInstallModules
 * @tc.desc: 1.check ability infos
 */
HWTEST_F(BmsBundleManagerTest2, GetBundleSpaceSize_0300, Function | MediumTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    std::map<std::string, std::vector<std::string>> freeInstallModules;
    bool ret = dataMgr->GetFreeInstallModules(freeInstallModules);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: GetBundleSpaceSize_0400
 * @tc.name: test GetBundleSpaceSize
 * @tc.desc: 1.check ability infos
 */
HWTEST_F(BmsBundleManagerTest2, GetBundleSpaceSize_0400, Function | MediumTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    int64_t size = 0;
    int64_t ret = dataMgr->GetBundleSpaceSize(BUNDLE_PREVIEW_NAME, USERID);
    EXPECT_EQ(ret, size);
}
#endif

} // OHOS