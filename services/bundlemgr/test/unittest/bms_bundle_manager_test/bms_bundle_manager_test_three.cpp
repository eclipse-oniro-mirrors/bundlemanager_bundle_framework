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

class BmsBundleManagerTest3 : public testing::Test {
public:
    BmsBundleManagerTest3();
    ~BmsBundleManagerTest3();
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

std::shared_ptr<BundleMgrService> BmsBundleManagerTest3::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleManagerTest3::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleManagerTest3::BmsBundleManagerTest3()
{}

BmsBundleManagerTest3::~BmsBundleManagerTest3()
{}

bool BmsBundleManagerTest3::InstallSystemBundle(const std::string &filePath) const
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

ErrCode BmsBundleManagerTest3::InstallThirdPartyBundle(const std::string &filePath) const
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

ErrCode BmsBundleManagerTest3::UpdateThirdPartyBundle(const std::string &filePath) const
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

ErrCode BmsBundleManagerTest3::UnInstallBundle(const std::string &bundleName) const
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

void BmsBundleManagerTest3::SetUpTestCase()
{
}

void BmsBundleManagerTest3::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleManagerTest3::SetUp()
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

void BmsBundleManagerTest3::TearDown()
{
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_CODE_DIR);
}

void BmsBundleManagerTest3::CheckFileExist() const
{
    int bundleCodeExist = access(BUNDLE_CODE_DIR.c_str(), F_OK);
    EXPECT_EQ(bundleCodeExist, 0) << "the bundle code dir does not exists: " << BUNDLE_CODE_DIR;

    int bundleDataExist = access(BUNDLE_DATA_DIR.c_str(), F_OK);
    EXPECT_EQ(bundleDataExist, 0) << "the bundle data dir does not exists: " << BUNDLE_DATA_DIR;
}

void BmsBundleManagerTest3::CheckFileNonExist() const
{
    int bundleCodeExist = access(BUNDLE_CODE_DIR.c_str(), F_OK);
    EXPECT_NE(bundleCodeExist, 0) << "the bundle code dir exists: " << BUNDLE_CODE_DIR;

    int bundleDataExist = access(BUNDLE_DATA_DIR.c_str(), F_OK);
    EXPECT_NE(bundleDataExist, 0) << "the bundle data dir exists: " << BUNDLE_DATA_DIR;
}

const std::shared_ptr<BundleDataMgr> BmsBundleManagerTest3::GetBundleDataMgr() const
{
    EXPECT_NE(bundleMgrService_->GetDataMgr(), nullptr);
    return bundleMgrService_->GetDataMgr();
}

const std::shared_ptr<BundleInstallerManager> BmsBundleManagerTest3::GetBundleInstallerManager() const
{
    return manager_;
}

void BmsBundleManagerTest3::ClearDataMgr()
{
    bundleMgrService_->dataMgr_ = nullptr;
}

void BmsBundleManagerTest3::ResetDataMgr()
{
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(bundleMgrService_->dataMgr_, nullptr);
}

void BmsBundleManagerTest3::ClearConnectAbilityMgr()
{
    bundleMgrService_->connectAbilityMgr_.clear();
}

void BmsBundleManagerTest3::ResetConnectAbilityMgr()
{
    auto ptr = bundleMgrService_->GetConnectAbility();
    EXPECT_FALSE(bundleMgrService_->connectAbilityMgr_.empty());
}

void BmsBundleManagerTest3::StopInstalldService() const
{
    if (installdService_->IsServiceReady()) {
        installdService_->Stop();
        InstalldClient::GetInstance()->ResetInstalldProxy();
    }
}

void BmsBundleManagerTest3::StopBundleService()
{
    if (bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStop();
        bundleMgrService_.reset();
    }
}

void BmsBundleManagerTest3::CreateInstallerManager()
{
    if (manager_ != nullptr) {
        return;
    }
    manager_ = std::make_shared<BundleInstallerManager>();
    EXPECT_NE(nullptr, manager_);
}

void BmsBundleManagerTest3::ClearBundleInfo()
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
HWTEST_F(BmsBundleManagerTest3, BundleStreamInstallerHostImpl_0100, Function | SmallTest | Level1)
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
 * @tc.number: FindAbilityInfo_0100
 * @tc.name: test FindAbilityInfo proxy
 * @tc.desc: 1.find ability info success
 */
HWTEST_F(BmsBundleManagerTest3, FindAbilityInfo_0100, Function | MediumTest | Level1)
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
    ErrCode ret = info.FindAbilityInfo("", "", abilityInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);

    ret = info.FindAbilityInfo(moduleName, abilityName, abilityInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: FindAbilityInfo_0200
 * @tc.name: test FindAbilityInfo proxy
 * @tc.desc: 1.find ability info success
 */
HWTEST_F(BmsBundleManagerTest3, FindAbilityInfo_0200, Function | MediumTest | Level1)
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

    ErrCode ret = info.FindAbilityInfo(moduleName, "", abilityInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: FindAbilityInfo_0200
 * @tc.name: test FindAbilityInfo proxy
 * @tc.desc: 1.find ability info success
 */
HWTEST_F(BmsBundleManagerTest3, FindAbilityInfo_0300, Function | MediumTest | Level1)
{
    InnerBundleInfo info;
    std::optional<std::vector<AbilityInfo>> ret =
        info.FindAbilityInfos(Constants::INVALID_USERID);
    EXPECT_EQ(ret, std::nullopt);
}

/**
 * @tc.number: WantParamTest_0001
 * @tc.name: test ImplicitQueryAbilityInfos
 * @tc.desc: 1.system run normally
 *           2.want param is empty
*/
HWTEST_F(BmsBundleManagerTest3, WantParamTest_0001, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    want.SetUri("");
    want.SetType("");
    std::vector<AbilityInfo> abilityInfos;
    int32_t appIndex = 1;
    bool testRet = GetBundleDataMgr()->ImplicitQueryAbilityInfos(
        want, 0, USERID, abilityInfos, appIndex);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: WantParamTest_0002
 * @tc.name: test ImplicitQueryAbilityInfosV9
 * @tc.desc: 1.system run normally
 *           2.want param is empty
*/
HWTEST_F(BmsBundleManagerTest3, WantParamTest_0002, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    want.SetType("");
    want.SetUri("");
    std::vector<AbilityInfo> abilityInfos;
    int32_t appIndex = 1;
    ErrCode testRet = GetBundleDataMgr()->ImplicitQueryAbilityInfosV9(
        want, 0, USERID, abilityInfos, appIndex);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: WantParamTest_0003
 * @tc.name: test ImplicitQueryExtensionInfos
 * @tc.desc: 1.system run normally
 *           2.want param is empty
*/
HWTEST_F(BmsBundleManagerTest3, WantParamTest_0003, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    want.SetType("");
    want.SetUri("");
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t appIndex = 1;
    bool testRet = GetBundleDataMgr()->ImplicitQueryExtensionInfos(
        want, 0, USERID, extensionInfos, appIndex);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: WantParamTest_0004
 * @tc.name: test ImplicitQueryExtensionInfosV9
 * @tc.desc: 1.system run normally
 *           2.want param is empty
*/
HWTEST_F(BmsBundleManagerTest3, WantParamTest_0004, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    want.SetType("");
    want.SetUri("");
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t appIndex = 1;
    ErrCode testRet = GetBundleDataMgr()->ImplicitQueryExtensionInfosV9(
        want, 0, USERID, extensionInfos, appIndex);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: GetBundleInfoForSelf_0100
 * @tc.name: test GetBundleInfoForSelf
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetBundleInfoForSelf_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 0;
    BundleInfo info;
    ErrCode ret = hostImpl->GetBundleInfoForSelf(flags, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetBundleInfoForSelf_0200
 * @tc.name: test GetBundleInfoForSelf
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetBundleInfoForSelf_0200, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo info;

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });

    ErrCode ret = hostImpl->GetBundleInfoForSelf(BundleFlag::GET_BUNDLE_WITH_ABILITIES, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}


/**
 * @tc.number: VerifyDependency_0100
 * @tc.name: test VerifyDependency
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, VerifyDependency_0100, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    bool retBool = hostImpl->VerifyDependency("");
    EXPECT_EQ(retBool, false);
}

/**
 * @tc.number: ImplicitQueryInfoByPriority_0001
 * @tc.name: test ImplicitQueryInfoByPriority
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest3, ImplicitQueryInfoByPriority_0001, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", "", "", MODULE_NAME);
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    bool testRet = GetBundleDataMgr()->ImplicitQueryInfoByPriority(
        want, FLAG, USERID, abilityInfo, extensionInfo);
    EXPECT_EQ(testRet, true);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetAllSharedBundleInfo_0001
 * @tc.name: test GetAllSharedBundleInfo
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest3, GetAllSharedBundleInfo_0001, Function | SmallTest | Level1)
{
    std::vector<SharedBundleInfo> sharedBundles;
    ErrCode testRet = GetBundleDataMgr()->GetAllSharedBundleInfo(sharedBundles);
    EXPECT_EQ(testRet, ERR_OK);
}

/**
 * @tc.number: SharedBundleInfoTest_0001
 * @tc.name: test Marshalling
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest3, SharedBundleInfoTest_0001, Function | SmallTest | Level1)
{
    SharedBundleInfo sharedBundle;
    std::vector<SharedModuleInfo> sharedModuleInfos;
    SharedModuleInfo sharedModuleInfo;
    sharedModuleInfo.name = MODULE_NAME;
    sharedModuleInfos.emplace_back(sharedModuleInfo);
    sharedBundle.sharedModuleInfos = sharedModuleInfos;
    Parcel parcel;
    bool ret = sharedBundle.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: SharedBundleInfoTest_0002
 * @tc.name: test Unmarshalling
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest3, SharedBundleInfoTest_0002, Function | SmallTest | Level1)
{
    SharedBundleInfo sharedBundle;
    std::vector<SharedModuleInfo> sharedModuleInfos;
    SharedModuleInfo sharedModuleInfo;
    sharedModuleInfo.name = MODULE_NAME;
    sharedModuleInfos.emplace_back(sharedModuleInfo);
    sharedBundle.sharedModuleInfos = sharedModuleInfos;
    Parcel parcel;
    sharedBundle.Marshalling(parcel);
    auto ret = sharedBundle.Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.number: SharedModuleInfoTest_001
 * @tc.name: test Marshalling
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest3, SharedModuleInfoTest_001, Function | SmallTest | Level1)
{
    SharedModuleInfo sharedModuleInfo;
    sharedModuleInfo.name = MODULE_NAME;
    Parcel parcel;
    bool ret = sharedModuleInfo.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: SharedModuleInfoTest_002
 * @tc.name: test Marshalling
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest3, SharedModuleInfoTest_002, Function | SmallTest | Level1)
{
    SharedModuleInfo sharedModuleInfo;
    sharedModuleInfo.name = MODULE_NAME;
    Parcel parcel;
    sharedModuleInfo.Marshalling(parcel);
    auto ret = sharedModuleInfo.Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
    EXPECT_EQ(sharedModuleInfo.name, MODULE_NAME);
}

/**
 * @tc.number: InstallParamTest_001
 * @tc.name: test Marshalling
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest3, InstallParamTest_001, Function | SmallTest | Level1)
{
    InstallParam installParam;
    std::map<std::string, std::string> hashParams;
    hashParams.insert(pair<string, string>("1", "2"));
    installParam.hashParams = hashParams;
    installParam.sharedBundleDirPaths = std::vector<std::string>{INVALID_PATH};
    Parcel parcel;
    bool ret = installParam.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: InstallParamTest_002
 * @tc.name: test Unmarshalling
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest3, InstallParamTest_002, Function | SmallTest | Level1)
{
    InstallParam installParam;
    Parcel parcel;
    installParam.userId = USERID;
    installParam.Marshalling(parcel);
    auto ret = installParam.Unmarshalling(parcel);
    EXPECT_NE(ret, nullptr);
    EXPECT_EQ(installParam.userId, USERID);
}

/**
 * @tc.number: AgingUtilTest_0001
 * @tc.name: test SortTwoAgingBundleInfos
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest3, AgingUtilTest_0001, Function | SmallTest | Level1)
{
    AgingUtil util;
    AgingBundleInfo bundle1;
    AgingBundleInfo bundle2;
    bundle2.recentlyUsedTime_ = NUMBER_ONE;
    bool ret = util.SortTwoAgingBundleInfos(bundle1, bundle2);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: AgingUtilTest_0002
 * @tc.name: test GetNowSysTimeMs
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest3, AgingUtilTest_0002, Function | SmallTest | Level1)
{
    std::vector<AgingBundleInfo> bundles;
    AgingBundleInfo bundle1("bundle1", 0, 0);
    AgingBundleInfo bundle2("bundle2", 0, 0);
    bundles.push_back(bundle1);
    bundles.push_back(bundle2);
    AgingUtil::SortAgingBundles(bundles);

    int64_t ret = AgingUtil::GetNowSysTimeMs();
    EXPECT_NE(ret, 0);
}

/**
 * @tc.number: AgingUtilTest_0003
 * @tc.name: test GetUnusedTimeMsBaseOnCurrentTime
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest3, AgingUtilTest_0003, Function | SmallTest | Level1)
{
    int64_t currentTimeMs = 1722583028;
    int32_t days = 10;
    int64_t ret = AgingUtil::GetUnusedTimeMsBaseOnCurrentTime(currentTimeMs, days);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.number: GetInstallerIdTest_001
 * @tc.name: test Marshalling
 * @tc.desc: 1.system run normally
*/
HWTEST_F(BmsBundleManagerTest3, GetInstallerIdTest_001, Function | SmallTest | Level1)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    impl.SetInstallerId(USERID);
    installedUid = impl.GetInstallerId();
    EXPECT_EQ(installedUid, USERID);
}

/**
 * @tc.number: GetUidByDebugBundleName_0100
 * @tc.name: test GetUidByDebugBundleName
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetUidByDebugBundleName_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int ret = hostImpl->GetUidByDebugBundleName(BUNDLE_NAME, USERID);
    EXPECT_EQ(ret, Constants::INVALID_UID);
}

/**
 * @tc.number: GetProxyDataInfos_0100
 * @tc.name: test GetProxyDataInfos
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetProxyDataInfos_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<ProxyData> proxyDatas;
    ErrCode ret = hostImpl->GetProxyDataInfos(INVALID_BUNDLE, MODULE_NAME, proxyDatas, Constants::INVALID_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: GetProxyDataInfos_0200
 * @tc.name: test GetProxyDataInfos
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetProxyDataInfos_0200, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<ProxyData> proxyDatas;

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });

    ErrCode ret = hostImpl->GetProxyDataInfos(BUNDLE_NAME, MODULE_NAME, proxyDatas, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetProxyDataInfos_0300
 * @tc.name: test GetProxyDataInfos
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetProxyDataInfos_0300, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<ProxyData> proxyDatas;
    ErrCode ret = hostImpl->GetProxyDataInfos(BUNDLE_BACKUP_NAME, MODULE_NAME, proxyDatas, USERID);
    EXPECT_EQ(ret, ERR_OK);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetAllProxyDataInfos_0100
 * @tc.name: test GetAllProxyDataInfos
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetAllProxyDataInfos_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<ProxyData> proxyDatas;
    ErrCode ret = hostImpl->GetAllProxyDataInfos(proxyDatas, Constants::INVALID_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: GetAllProxyDataInfos_0200
 * @tc.name: test GetAllProxyDataInfos
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetAllProxyDataInfos_0200, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<ProxyData> proxyDatas;

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });

    ErrCode ret = hostImpl->GetAllProxyDataInfos(proxyDatas, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetAllProxyDataInfos_0300
 * @tc.name: test GetAllProxyDataInfos
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetAllProxyDataInfos_0300, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<ProxyData> proxyDatas;
    ErrCode ret = hostImpl->GetAllProxyDataInfos(proxyDatas, USERID);
    EXPECT_EQ(ret, ERR_OK);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetSpecifiedDistributionType_0100
 * @tc.name: test GetSpecifiedDistributionType
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetSpecifiedDistributionType_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string specifiedDistributionType;
    ErrCode ret = hostImpl->GetSpecifiedDistributionType(BUNDLE_NAME, specifiedDistributionType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetSpecifiedDistributionType_0200
 * @tc.name: test GetSpecifiedDistributionType
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetSpecifiedDistributionType_0200, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string specifiedDistributionType;

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });

    ErrCode ret = hostImpl->GetSpecifiedDistributionType(BUNDLE_NAME, specifiedDistributionType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetAdditionalInfo_0100
 * @tc.name: test GetAdditionalInfo
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetAdditionalInfo_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string additionalInfo;
    ErrCode ret = hostImpl->GetAdditionalInfo(BUNDLE_NAME, additionalInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetAdditionalInfo_0200
 * @tc.name: test GetAdditionalInfo
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetAdditionalInfo_0200, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string additionalInfo;

    ClearDataMgr();
    ScopeGuard stateGuard([&] { ResetDataMgr(); });

    ErrCode ret = hostImpl->GetAdditionalInfo(BUNDLE_NAME, additionalInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetBundleArchiveInfoBySandBoxPath_0100
 * @tc.name: test GetBundleArchiveInfoBySandBoxPath
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetBundleArchiveInfoBySandBoxPath_0100, Function | SmallTest | Level1)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t flags = 1;
    BundleInfo bundleInfo;
    ErrCode ret = hostImpl->GetBundleArchiveInfoBySandBoxPath(bundlePath, flags, bundleInfo, false);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    ret = hostImpl->GetBundleArchiveInfoBySandBoxPath(bundlePath, flags, bundleInfo, true);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: DumpAllBundleInfoNamesByUserId_0100
 * @tc.name: test DumpAllBundleInfoNamesByUserId
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, DumpAllBundleInfoNamesByUserId_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string result;

    bool ret = hostImpl->DumpAllBundleInfoNamesByUserId(Constants::INVALID_USERID, result);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: GetSandboxExtAbilityInfos_0100
 * @tc.name: test GetSandboxExtAbilityInfos
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetSandboxExtAbilityInfos_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    Want want;
    int32_t appIndex = -1;
    int32_t flags = 0;
    std::vector<ExtensionAbilityInfo> infos;

    ErrCode ret = hostImpl->GetSandboxExtAbilityInfos(want, appIndex, flags, USERID, infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    appIndex = 101;
    ret = hostImpl->GetSandboxExtAbilityInfos(want, appIndex, flags, USERID, infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: GetSandboxHapModuleInfo_0100
 * @tc.name: test DumpAllBundleInfoNamesByUserId
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetSandboxHapModuleInfo_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    AbilityInfo abilityInfo;
    HapModuleInfo info;
    int32_t appIndex = -1;

    ErrCode ret = hostImpl->GetSandboxHapModuleInfo(abilityInfo, appIndex, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    appIndex = 101;
    ret = hostImpl->GetSandboxHapModuleInfo(abilityInfo, appIndex, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: GetMimeTypeByUri_0100
 * @tc.name: test GetMimeTypeByUri
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetMimeTypeByUri_0100, Function | SmallTest | Level1)
{
    std::string wrongUri = "wrong";
    std::vector<std::string> types;
    bool ret = MimeTypeMgr::GetMimeTypeByUri(wrongUri, types);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: GetMimeTypeByUri_0200
 * @tc.name: test GetMimeTypeByUri
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetMimeTypeByUri_0200, Function | SmallTest | Level1)
{
    std::string wrongUri = "wrong.wongtype";
    std::vector<std::string> types;
    bool ret = MimeTypeMgr::GetMimeTypeByUri(wrongUri, types);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: GetMimeTypeByUri_0300
 * @tc.name: test GetMimeTypeByUri
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, GetMimeTypeByUri_0300, Function | SmallTest | Level1)
{
    std::string rightUri = "right.jpg";
    std::vector<std::string> types;
    bool ret = MimeTypeMgr::GetMimeTypeByUri(rightUri, types);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: SetExtName_0100
 * @tc.name: test SetExtName
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, SetExtName_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    AbilityInfo abilityInfo;
    abilityInfo.moduleName = MODULE_NAME;
    abilityInfo.name = ABILITY_NAME;
    std::map<std::string, AbilityInfo> abilityInfoMap;
    abilityInfoMap.emplace(ABILITY_NAME, abilityInfo);
    innerBundleInfo.AddModuleAbilityInfo(abilityInfoMap);
    std::string extName = "jpg";
    auto ret = innerBundleInfo.SetExtName(MODULE_NAME, ABILITY_NAME, extName);
    EXPECT_EQ(ret, ERR_OK);
    ret = innerBundleInfo.DelExtName(MODULE_NAME, ABILITY_NAME, extName);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: SetExtName_0200
 * @tc.name: test SetMimeType
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, SetExtName_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    AbilityInfo abilityInfo;
    abilityInfo.moduleName = MODULE_NAME;
    abilityInfo.name = ABILITY_NAME;
    std::map<std::string, AbilityInfo> abilityInfoMap;
    abilityInfoMap.emplace(ABILITY_NAME, abilityInfo);
    innerBundleInfo.AddModuleAbilityInfo(abilityInfoMap);
    std::string mimeType = "image/jpeg";
    auto ret = innerBundleInfo.SetMimeType(MODULE_NAME, ABILITY_NAME, mimeType);
    EXPECT_EQ(ret, ERR_OK);
    ret = innerBundleInfo.DelMimeType(MODULE_NAME, ABILITY_NAME, mimeType);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: SetExtName_0300
 * @tc.name: test SetExtName
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, SetExtName_0300, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    std::string extName = "jpg";
    auto ret = innerBundleInfo.SetExtName(MODULE_NAME, ABILITY_NAME, extName);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    ret = innerBundleInfo.DelExtName(MODULE_NAME, ABILITY_NAME, extName);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);

    AbilityInfo abilityInfo;
    abilityInfo.moduleName = MODULE_NAME;
    abilityInfo.name = ABILITY_NAME;
    std::map<std::string, AbilityInfo> abilityInfoMap;
    abilityInfoMap.emplace(ABILITY_NAME, abilityInfo);
    innerBundleInfo.AddModuleAbilityInfo(abilityInfoMap);
    std::string wrongModuleName = "wrong";
    ret = innerBundleInfo.SetExtName(wrongModuleName, ABILITY_NAME, extName);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
    ret = innerBundleInfo.DelExtName(wrongModuleName, ABILITY_NAME, extName);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: SetExtName_0400
 * @tc.name: test SetMimeType
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleManagerTest3, SetExtName_0400, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    std::string mimeType = "image/jpeg";
    auto ret = innerBundleInfo.SetMimeType(MODULE_NAME, ABILITY_NAME, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    ret = innerBundleInfo.DelMimeType(MODULE_NAME, ABILITY_NAME, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);

    AbilityInfo abilityInfo;
    abilityInfo.moduleName = MODULE_NAME;
    abilityInfo.name = ABILITY_NAME;
    std::map<std::string, AbilityInfo> abilityInfoMap;
    abilityInfoMap.emplace(ABILITY_NAME, abilityInfo);
    innerBundleInfo.AddModuleAbilityInfo(abilityInfoMap);
    std::string wrongModuleName = "wrong";
    ret = innerBundleInfo.SetMimeType(wrongModuleName, ABILITY_NAME, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
    ret = innerBundleInfo.DelMimeType(wrongModuleName, ABILITY_NAME, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: SetExtNameOrMIMEToApp_0001
 * @tc.name: SetExtNameOrMIMEToApp
 * @tc.desc: 1. SetExtNameToApp
 */
HWTEST_F(BmsBundleManagerTest3, SetExtNameOrMIMEToApp_0001, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string extName = "ext";
    auto ret = dataMgr->SetExtNameOrMIMEToApp(
        BUNDLE_BACKUP_NAME, MODULE_NAME, ABILITY_BACKUP_NAME, extName, EMPTY_STRING);
    EXPECT_EQ(ret, ERR_OK);
    Want want;
    want.SetUri("/test/test.ext");
    std::vector<AbilityInfo> abilityInfos;
    ret = dataMgr->QueryAbilityInfosV9(want, 1, USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    ret = dataMgr->DelExtNameOrMIMEToApp(BUNDLE_BACKUP_NAME, MODULE_NAME, ABILITY_BACKUP_NAME, extName, EMPTY_STRING);
    EXPECT_EQ(ret, ERR_OK);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: SetExtNameOrMIMEToApp_0002
 * @tc.name: SetExtNameOrMIMEToApp
 * @tc.desc: 1. SetMimeTypeToApp
 */
HWTEST_F(BmsBundleManagerTest3, SetExtNameOrMIMEToApp_0002, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string mimeType = "application/x-maker";
    auto ret = dataMgr->SetExtNameOrMIMEToApp(
        BUNDLE_BACKUP_NAME, MODULE_NAME, ABILITY_BACKUP_NAME, EMPTY_STRING, mimeType);
    EXPECT_EQ(ret, ERR_OK);
    Want want;
    want.SetUri("/test/test.book");
    std::vector<AbilityInfo> abilityInfos;
    ret = dataMgr->QueryAbilityInfosV9(want, 1, USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    ret = dataMgr->DelExtNameOrMIMEToApp(BUNDLE_BACKUP_NAME, MODULE_NAME, ABILITY_BACKUP_NAME, EMPTY_STRING, mimeType);
    EXPECT_EQ(ret, ERR_OK);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: SetExtNameOrMIMEToApp_0003
 * @tc.name: SetExtNameOrMIMEToApp
 * @tc.desc: 1. SetMimeTypeToApp
 */
HWTEST_F(BmsBundleManagerTest3, SetExtNameOrMIMEToApp_0003, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string wrongName = "wrong";
    std::string mimeType = "application/x-maker";
    auto ret = dataMgr->SetExtNameOrMIMEToApp(wrongName, MODULE_NAME, ABILITY_BACKUP_NAME, EMPTY_STRING, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    ret = dataMgr->SetExtNameOrMIMEToApp(BUNDLE_BACKUP_NAME, wrongName, ABILITY_BACKUP_NAME, EMPTY_STRING, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
    ret = dataMgr->SetExtNameOrMIMEToApp(BUNDLE_BACKUP_NAME, MODULE_NAME, wrongName, EMPTY_STRING, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: SetExtNameOrMIMEToApp_0003
 * @tc.name: SetExtNameOrMIMEToApp
 * @tc.desc: 1. SetMimeTypeToApp
 */
HWTEST_F(BmsBundleManagerTest3, SetExtNameOrMIMEToApp_0004, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string wrongName = "wrong";
    std::string mimeType = "application/x-maker";
    auto ret = dataMgr->DelExtNameOrMIMEToApp(wrongName, MODULE_NAME, ABILITY_BACKUP_NAME, EMPTY_STRING, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    ret = dataMgr->DelExtNameOrMIMEToApp(BUNDLE_BACKUP_NAME, wrongName, ABILITY_BACKUP_NAME, EMPTY_STRING, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
    ret = dataMgr->DelExtNameOrMIMEToApp(BUNDLE_BACKUP_NAME, MODULE_NAME, wrongName, EMPTY_STRING, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetJsonProfile_0001
 * @tc.name: GetJsonProfile
 * @tc.desc: 1. GetJsonProfile with wrong bundle name
 *           2. GetJsonProfile failed, return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST
 */
HWTEST_F(BmsBundleManagerTest3, GetJsonProfile_0001, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ProfileType profileType = AppExecFwk::ProfileType::INTENT_PROFILE;
    std::string wrongName = "wrong";
    std::string profile;

    auto ret = dataMgr->GetJsonProfile(profileType, wrongName, MODULE_NAME, profile, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetJsonProfile_0002
 * @tc.name: GetJsonProfile
 * @tc.desc: 1. GetJsonProfile with wrong module name
 *           2. GetJsonProfile failed, return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST
 */
HWTEST_F(BmsBundleManagerTest3, GetJsonProfile_0002, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ProfileType profileType = AppExecFwk::ProfileType::INTENT_PROFILE;
    std::string wrongName = "wrong";
    std::string profile;

    auto ret = dataMgr->GetJsonProfile(profileType, BUNDLE_BACKUP_NAME, wrongName, profile, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetJsonProfile_0003
 * @tc.name: GetJsonProfile
 * @tc.desc: 1. GetJsonProfile in hap without specified profile
 *           2. GetJsonProfile failed, return ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST
 */
HWTEST_F(BmsBundleManagerTest3, GetJsonProfile_0003, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ProfileType profileType = AppExecFwk::ProfileType::INTENT_PROFILE;
    std::string wrongName = "wrong";
    std::string profile;

    auto ret = dataMgr->GetJsonProfile(profileType, BUNDLE_BACKUP_NAME, MODULE_NAME, profile, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetJsonProfile_0004
 * @tc.name: GetJsonProfile
 * @tc.desc: 1. GetJsonProfile in disabled app
 *           2. GetJsonProfile failed, return ERR_BUNDLE_MANAGER_APPLICATION_DISABLED
 */
HWTEST_F(BmsBundleManagerTest3, GetJsonProfile_0004, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ProfileType profileType = AppExecFwk::ProfileType::INTENT_PROFILE;
    std::string wrongName = "wrong";
    std::string profile;

    auto ret = dataMgr->SetApplicationEnabled(BUNDLE_BACKUP_NAME, 0, false, CALLER_NAME_UT, USERID);
    EXPECT_EQ(ret, ERR_OK);
    ret = dataMgr->GetJsonProfile(profileType, BUNDLE_BACKUP_NAME, MODULE_NAME, profile, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_APPLICATION_DISABLED);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetJsonProfile_0005
 * @tc.name: GetJsonProfile
 * @tc.desc: 1. GetJsonProfile successfully
 */
HWTEST_F(BmsBundleManagerTest3, GetJsonProfile_0005, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ProfileType profileType = AppExecFwk::ProfileType::INTENT_PROFILE;
    std::string profile;

    auto ret = dataMgr->GetJsonProfile(profileType, BUNDLE_PREVIEW_NAME, MODULE_NAME, profile, USERID);
    EXPECT_EQ(ret, ERR_OK);
    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.number: GetJsonProfile_0006
 * @tc.name: GetJsonProfile
 * @tc.desc: 1. GetJsonProfile with empty module name
 *           2. GetJsonProfile successfully, get profile in entry module
 */
HWTEST_F(BmsBundleManagerTest3, GetJsonProfile_0006, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ProfileType profileType = AppExecFwk::ProfileType::INTENT_PROFILE;
    std::string profile;

    auto ret = dataMgr->GetJsonProfile(profileType, BUNDLE_PREVIEW_NAME, EMPTY_STRING, profile, USERID);
    EXPECT_EQ(ret, ERR_OK);
    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.number: GetJsonProfile_0007
 * @tc.name: GetJsonProfile
 * @tc.desc: 1. GetJsonProfile with empty module name
 *           2. GetJsonProfile successfully, get profile in entry module
 */
HWTEST_F(BmsBundleManagerTest3, GetJsonProfile_0007, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ProfileType profileType = AppExecFwk::ProfileType::ADDITION_PROFILE;
    std::string profile;

    auto ret = dataMgr->GetJsonProfile(profileType, BUNDLE_PREVIEW_NAME, EMPTY_STRING, profile, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST);
    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.number: GetBundleInfoWithMenu_0001
 * @tc.name: GetBundleInfoWithMenu
 * @tc.desc: 1. GetBundleMenu successfully
 */
HWTEST_F(BmsBundleManagerTest3, GetBundleInfoWithMenu_0001, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    BundleInfo info;
    int32_t flag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_MENU);
    auto ret = dataMgr->GetBundleInfoV9(BUNDLE_PREVIEW_NAME, flag, info, USERID);
    EXPECT_EQ(ret, ERR_OK);
    auto pos = info.hapModuleInfos[0].fileContextMenu.find(MENU_VALUE);
    EXPECT_NE(pos, std::string::npos);

    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.number: GetBundleInfoWithMenu_0002
 * @tc.name: GetBundleInfoWithMenu
 * @tc.desc: 1. GetBundleMenu with menu, but no menu in bundleInfo
 */
HWTEST_F(BmsBundleManagerTest3, GetBundleInfoWithMenu_0002, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    BundleInfo info;
    int32_t flag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_MENU);
    auto ret = dataMgr->GetBundleInfoV9(BUNDLE_BACKUP_NAME, flag, info, USERID);
    EXPECT_EQ(ret, ERR_OK);

    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetBundleInfoWithMenu_0003
 * @tc.name: GetBundleInfoWithMenu
 * @tc.desc: 1. GetBundleMenu with menu, but no menu flag
 */
HWTEST_F(BmsBundleManagerTest3, GetBundleInfoWithMenu_0003, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    BundleInfo info;
    int32_t flag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE);
    auto ret = dataMgr->GetBundleInfoV9(BUNDLE_PREVIEW_NAME, flag, info, USERID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(info.hapModuleInfos[0].fileContextMenu.empty());

    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.number: GetAllBundleInfoWithMenu_0001
 * @tc.name: GetBundleInfoWithMenu
 * @tc.desc: 1. GetBundleMenu successfully
 */
HWTEST_F(BmsBundleManagerTest3, GetAllBundleInfoWithMenu_0001, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    std::vector<BundleInfo> infos;
    int32_t flag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_MENU);
    auto ret = dataMgr->GetBundleInfosV9(flag, infos, USERID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(infos.size(), NUMBER_ONE);
    auto pos = infos[0].hapModuleInfos[0].fileContextMenu.find(MENU_VALUE);
    EXPECT_NE(pos, std::string::npos);

    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.number: GetAllBundleInfoWithMenu_0001
 * @tc.name: GetBundleInfoWithMenu
 * @tc.desc: 1. GetBundleMenu with menu, but no menu in bundleInfo
 */
HWTEST_F(BmsBundleManagerTest3, GetAllBundleInfoWithMenu_0002, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    std::vector<BundleInfo> infos;
    int32_t flag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_MENU);
    auto ret = dataMgr->GetBundleInfosV9(flag, infos, USERID);
    EXPECT_EQ(ret, ERR_OK);
    UnInstallBundle(BUNDLE_BACKUP_NAME);
}

/**
 * @tc.number: GetAllBundleInfoWithMenu_0001
 * @tc.name: GetBundleInfoWithMenu
 * @tc.desc: 1. GetBundleMenu with menu, but no menu flag
 */
HWTEST_F(BmsBundleManagerTest3, GetAllBundleInfoWithMenu_0003, Function | SmallTest | Level0)
{
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_PREVIEW_TEST;
    ErrCode installResult = InstallThirdPartyBundle(bundlePath);
    EXPECT_EQ(installResult, ERR_OK);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    std::vector<BundleInfo> infos;
    int32_t flag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE);
    auto ret = dataMgr->GetBundleInfosV9(flag, infos, USERID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(infos[0].hapModuleInfos[0].fileContextMenu.empty());

    UnInstallBundle(BUNDLE_PREVIEW_NAME);
}

/**
 * @tc.number: SetAdditionalInfo_0100
 * @tc.name: test SetAdditionalInfo
 * @tc.desc: 1.system run normally
 *           2.set additionalInfo failed
 */
HWTEST_F(BmsBundleManagerTest3, SetAdditionalInfo_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string additionalInfo = "additionalInfo";
    ErrCode ret = hostImpl->SetAdditionalInfo(BUNDLE_NAME, additionalInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_NOT_APP_GALLERY_CALL);
}

/**
 * @tc.number: GetDependentBundleInfo_0001
 * @tc.name: test GetDependentBundleInfo proxy
 * @tc.desc: 1.query bundle infos
 */
HWTEST_F(BmsBundleManagerTest3, GetDependentBundleInfo_0001, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo bundleInfo;
    ErrCode ret = hostImpl->GetDependentBundleInfo(BUNDLE_NAME, bundleInfo,
        GetDependentBundleInfoFlag::GET_APP_CROSS_HSP_BUNDLE_INFO);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);

    auto ret1 = hostImpl->GetDependentBundleInfo(BUNDLE_NAME, bundleInfo,
        GetDependentBundleInfoFlag::GET_APP_SERVICE_HSP_BUNDLE_INFO);
    EXPECT_EQ(ret1, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    auto ret2 = hostImpl->GetDependentBundleInfo(BUNDLE_NAME, bundleInfo,
        GetDependentBundleInfoFlag::GET_ALL_DEPENDENT_BUNDLE_INFO);
    EXPECT_EQ(ret2, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetDependentBundleInfo_0002
 * @tc.name: test GetDependentBundleInfo proxy
 * @tc.desc: 1.query bundle infos
 */
HWTEST_F(BmsBundleManagerTest3, GetDependentBundleInfo_0002, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    auto dataService = hostImpl->GetDataMgrFromService();
    std::shared_ptr<BundleDataMgr> empty;
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    DelayedSingleton<BundleMgrService>::GetInstance()->RegisterDataMgr(empty);
    BundleInfo bundleInfo;
    ErrCode ret = hostImpl->GetDependentBundleInfo(BUNDLE_NAME, bundleInfo,
        GetDependentBundleInfoFlag::GET_APP_CROSS_HSP_BUNDLE_INFO);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);

    DelayedSingleton<BundleMgrService>::GetInstance()->RegisterDataMgr(savedDataMgr);
}

/**
 * @tc.number: GetDependentBundleInfo_0003
 * @tc.name: test GetDependentBundleInfo proxy
 * @tc.desc: 1.query bundle infos
 */
HWTEST_F(BmsBundleManagerTest3, GetDependentBundleInfo_0003, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    BundleInfo bundleInfo;
    ErrCode ret = hostImpl->GetDependentBundleInfo(BUNDLE_NAME, bundleInfo,
        static_cast<GetDependentBundleInfoFlag>(0x1000));
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
* @tc.number: GetBundleNameForUid_0010
* @tc.name: test GetBundleNameForUid
*/
HWTEST_F(BmsBundleManagerTest3, GetBundleNameForUid_0010, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    auto dataService = hostImpl->GetDataMgrFromService();
    std::shared_ptr<BundleDataMgr> empty;
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    DelayedSingleton<BundleMgrService>::GetInstance()->RegisterDataMgr(empty);

    std::string bundleName;
    bool testRet = hostImpl->GetBundleNameForUid(1, bundleName);
    EXPECT_EQ(testRet, false);

    DelayedSingleton<BundleMgrService>::GetInstance()->RegisterDataMgr(savedDataMgr);
}

/**
 * @tc.number: GetRecoverableApplicationInfo_0100
 * @tc.name: test GetRecoverableApplicationInfo proxy
 * @tc.desc: 1.query recoverable application infos
 */
HWTEST_F(BmsBundleManagerTest3, GetRecoverableApplicationInfo_0100, Function | MediumTest | Level1)
{
    std::unique_ptr<IPreInstallDataStorage> preInstallDataStorage =
        std::make_unique<PreInstallDataStorageRdb>();
    PreInstallBundleInfo preInstallBundleInfo;
    std::string bundlePath = RESOURCE_ROOT_PATH + BUNDLE_BACKUP_TEST;
    preInstallBundleInfo.SetBundleName(BUNDLE_BACKUP_NAME);
    preInstallBundleInfo.SetModuleName(MODULE_NAME);
    preInstallBundleInfo.SetLabelId(BUNDLE_BACKUP_LABEL_ID);
    preInstallBundleInfo.SetIconId(BUNDLE_BACKUP_ICON_ID);
    preInstallBundleInfo.SetSystemApp(true);
    preInstallBundleInfo.SetBundleType(BundleType::APP);
    preInstallBundleInfo.SetVersionCode(BUNDLE_BACKUP_VERSION);
    preInstallBundleInfo.AddBundlePath(bundlePath);
    preInstallBundleInfo.SetRemovable(true);
    bool ret = preInstallDataStorage->SavePreInstallStorageBundleInfo(preInstallBundleInfo);
    EXPECT_TRUE(ret);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<RecoverableApplicationInfo> recoverableApplications;
    ErrCode retCode = hostImpl->GetRecoverableApplicationInfo(recoverableApplications);
    EXPECT_EQ(retCode, ERR_OK);
    EXPECT_EQ(recoverableApplications.empty(), false);
    if (!recoverableApplications.empty()) {
        RecoverableApplicationInfo info = recoverableApplications[0];
        EXPECT_EQ(info.bundleName, BUNDLE_BACKUP_NAME);
        EXPECT_EQ(info.moduleName, MODULE_NAME);
        EXPECT_EQ(info.labelId, BUNDLE_BACKUP_LABEL_ID);
        EXPECT_EQ(info.iconId, BUNDLE_BACKUP_ICON_ID);
        EXPECT_EQ(info.systemApp, true);
        EXPECT_EQ(info.bundleType, BundleType::APP);
        EXPECT_EQ(info.codePaths[0], bundlePath);
    }
    ret = preInstallDataStorage->DeletePreInstallStorageBundleInfo(preInstallBundleInfo);
    EXPECT_TRUE(ret);
}

/**
* @tc.number: InitVerifyManager_0010
* @tc.name: test InitVerifyManager
* @tc.desc: 1.test initialize the verify manager
*/
HWTEST_F(BmsBundleManagerTest3, InitVerifyManager_0010, Function | SmallTest | Level1)
{
    bool ret = DelayedSingleton<BundleMgrService>::GetInstance()->InitVerifyManager();
    EXPECT_EQ(ret, true);
    auto result = DelayedSingleton<BundleMgrService>::GetInstance()->GetVerifyManager();
    EXPECT_NE(result, nullptr);
}

/**
* @tc.number: InitExtendResourceManager_0010
* @tc.name: test InitExtendResourceManager
* @tc.desc: 1.test initialize the extended resource manager
*/
HWTEST_F(BmsBundleManagerTest3, InitExtendResourceManager_0010, Function | SmallTest | Level1)
{
    bool ret = DelayedSingleton<BundleMgrService>::GetInstance()->InitExtendResourceManager();
    EXPECT_EQ(ret, true);
    int32_t systemAbilityId = COMMON_EVENT_SERVICE_ID;
    std::string deviceId;
    DelayedSingleton<BundleMgrService>::GetInstance()->OnAddSystemAbility(systemAbilityId, deviceId);
    auto result = DelayedSingleton<BundleMgrService>::GetInstance()->GetExtendResourceManager();
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.number: GetBundleNamesForNewUser_0100
 * @tc.name: test GetBundleNamesForNewUser without driver bundle
 */
HWTEST_F(BmsBundleManagerTest3, GetBundleNamesForNewUser_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    std::vector<std::string> ret = dataMgr->GetBundleNamesForNewUser();
    EXPECT_EQ(ret.size(), 0);

    InnerBundleInfo sharedInfo;
    sharedInfo.SetApplicationBundleType(BundleType::SHARED);
    dataMgr->bundleInfos_.try_emplace("sharedBundle", sharedInfo);
    InnerBundleInfo preInstallInfo;
    preInstallInfo.SetIsPreInstallApp(true);
    dataMgr->bundleInfos_.try_emplace("preInstallBundle", preInstallInfo);
    ret = dataMgr->GetBundleNamesForNewUser();
    EXPECT_EQ(ret.size(), 0);
    dataMgr->bundleInfos_.clear();
}

/**
 * @tc.number: GetBundleNamesForNewUser_0200
 * @tc.name: test GetBundleNamesForNewUser within driver bundle
 */
HWTEST_F(BmsBundleManagerTest3, GetBundleNamesForNewUser_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    ExtensionAbilityInfo abilityInfo;
    abilityInfo.type = ExtensionAbilityType::DRIVER;
    info.InsertExtensionInfo("key", abilityInfo);
    dataMgr->bundleInfos_.try_emplace(BUNDLE_NAME, info);
    std::vector<std::string> ret = dataMgr->GetBundleNamesForNewUser();
    EXPECT_EQ(ret.size(), 1);
    dataMgr->bundleInfos_.clear();
}

/**
 * @tc.number: GetBundleNamesForNewUser_0300
 * @tc.name: test GetBundleNamesForNewUser
 */
HWTEST_F(BmsBundleManagerTest3, GetBundleNamesForNewUser_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.SetInstalledForAllUser(true);
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "true");
    dataMgr->bundleInfos_.try_emplace(BUNDLE_NAME, info);
    std::vector<std::string> ret = dataMgr->GetBundleNamesForNewUser();
    EXPECT_EQ(ret.size(), 1);
    dataMgr->bundleInfos_.clear();
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "false");
}

/**
* @tc.number: PreInstallDataStorageRdb_0100
* @tc.name: test LoadAllPreInstallBundleInfos
* @tc.desc: 1.test LoadAllPreInstallBundleInfos the PreInstallDataStorageRdb
*/
HWTEST_F(BmsBundleManagerTest3, PreInstallDataStorageRdb_0100, Function | SmallTest | Level1)
{
    std::unique_ptr<PreInstallDataStorageRdb> preInstallDataStorage =
        std::make_unique<PreInstallDataStorageRdb>();
    ASSERT_NE(preInstallDataStorage, nullptr);

    preInstallDataStorage->rdbDataManager_ = nullptr;
    std::string bundleName = "com.acts.example";
    std::vector<PreInstallBundleInfo> preInstallBundleInfos;
    std::map<std::string, PreInstallBundleInfo> infos;
    PreInstallBundleInfo preInstallBundleInfo;

    bool ret = preInstallDataStorage->LoadAllPreInstallBundleInfos(preInstallBundleInfos);
    EXPECT_FALSE(ret);

    preInstallDataStorage->UpdateDataBase(infos);
    ret = preInstallDataStorage->SavePreInstallStorageBundleInfo(preInstallBundleInfo);
    EXPECT_FALSE(ret);

    ret = preInstallDataStorage->DeletePreInstallStorageBundleInfo(preInstallBundleInfo);
    EXPECT_FALSE(ret);

    ret = preInstallDataStorage->LoadPreInstallBundleInfo(bundleName, preInstallBundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BundleMgrHostImpl_3400
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetCompatibleDeviceType
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_3400, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    std::string bundleName = BUNDLE_NAME;
    std::string deviceType = DEVICETYPE;
    ErrCode retCode = hostImpl->GetCompatibleDeviceType(bundleName, deviceType);
    EXPECT_EQ(retCode, ERR_OK);
}

/**
 * @tc.number: BundleMgrHostImpl_3500
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetCompatibleDeviceTypeNative
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_3500, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    std::string deviceType = DEVICETYPE;
    ErrCode retCode = hostImpl->GetCompatibleDeviceTypeNative(deviceType);
    EXPECT_EQ(retCode, ERR_OK);
}

/**
 * @tc.number: BundleMgrHostImpl_3600
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetBundleInfosForContinuation
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_3600, Function | MediumTest | Level1)
{
    BundleInfo bundleInfo;
    std::vector<BundleInfo> bundleInfos;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    ErrCode retCode = hostImpl->GetBundleInfosForContinuation(FLAG, bundleInfos, USERID);
    EXPECT_FALSE(retCode);
}

/**
 * @tc.number: BundleMgrHostImpl_3700
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetOdidByBundleName
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_3700, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    std::string odid = "odid";
    ErrCode retCode = hostImpl->GetOdidByBundleName(BUNDLE_NAME, odid);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: BundleMgrHostImpl_3800
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test SetProvisionInfoToInnerBundleInfo
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_3800, Function | MediumTest | Level1)
{
    std::string hapPath;
    InnerBundleInfo info;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    hostImpl->SetProvisionInfoToInnerBundleInfo(hapPath, info);
    Security::Verify::HapVerifyResult hapVerifyResult;
    ErrCode verifyRes = BundleVerifyMgr::HapVerify(hapPath, hapVerifyResult);
    EXPECT_EQ(verifyRes, ERR_APPEXECFWK_INSTALL_FAILED_INVALID_SIGNATURE_FILE_PATH);
}

/**
 * @tc.number: BundleMgrHostImpl_3900
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetOdid
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_3900, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    std::string odid = "odid";
    ErrCode retCode = hostImpl->GetOdid(odid);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: BundleMgrHostImpl_4000
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetPreferableBundleInfoFromHapPaths
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_4000, Function | MediumTest | Level1)
{
    std::vector<std::string> hapPaths;
    hapPaths.emplace_back(BUNDLE_NAME);
    BundleInfo bundleInfo;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    ErrCode retCode = hostImpl->GetPreferableBundleInfoFromHapPaths(hapPaths, bundleInfo);
    EXPECT_FALSE(retCode);
}

/**
 * @tc.number: BundleMgrHostImpl_4100
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test UpdateAppEncryptedStatus
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_4100, Function | MediumTest | Level1)
{
    std::string bundleName = BUNDLE_NAME;
    bool isExisted = false;
    int32_t appIndex = APPINDEX;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    ErrCode retCode = hostImpl->UpdateAppEncryptedStatus(bundleName, isExisted, appIndex);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_4200
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test UpdateAppEncryptedStatus
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_4200, Function | MediumTest | Level1)
{
    std::string bundleName = BUNDLE_NAME;
    bool isExisted = false;
    int32_t appIndex = APPINDEX;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    ErrCode retCode = hostImpl->UpdateAppEncryptedStatus(bundleName, isExisted, appIndex);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleMgrHostImpl_4300
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetAppControlProxy
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_4300, Function | MediumTest | Level1)
{
    DelayedSingleton<BundleMgrService>::GetInstance()->appControlManagerHostImpl_ = nullptr;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    EXPECT_EQ(hostImpl->GetAppControlProxy(), nullptr);
}

/**
 * @tc.number: BundleMgrHostImpl_4400
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetAllBundleStats
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_4400, Function | MediumTest | Level1)
{
    std::vector<int64_t> bundleStats;
    bundleStats.emplace_back(WAIT_TIME);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    auto result = hostImpl->GetAllBundleStats(USERID, bundleStats);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: BundleMgrHostImpl_4500
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetExtendResourceManager
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_4500, Function | MediumTest | Level1)
{
    DelayedSingleton<BundleMgrService>::GetInstance()->extendResourceManager_ = nullptr;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    EXPECT_EQ(hostImpl->GetExtendResourceManager(), nullptr);
}

/**
 * @tc.number: BundleMgrHostImpl_4600
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetVerifyManager
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_4600, Function | MediumTest | Level1)
{
    DelayedSingleton<BundleMgrService>::GetInstance()->verifyManager_ = nullptr;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    EXPECT_EQ(hostImpl->GetVerifyManager(), nullptr);
}

/**
 * @tc.number: BundleMgrHostImpl_4700
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test SetCloneApplicationEnabled
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_4700, Function | MediumTest | Level1)
{
    std::string bundleName = BUNDLE_NAME;
    bool isEnable = false;
    int32_t appIndex = APPINDEX;
    int userId = USERID;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    EXPECT_NE(hostImpl, nullptr);
    ErrCode retCode = hostImpl->SetCloneApplicationEnabled(bundleName, appIndex, isEnable, userId);
    EXPECT_EQ(retCode, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: BundleMgrHostImpl_4800
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test GetBundleNameByAppId
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_4800, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string appId;
    std::string bundleName;
    ErrCode retCode = hostImpl->GetBundleNameByAppId(appId, bundleName);
    EXPECT_EQ(retCode, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: BundleMgrHostImpl_4900
 * @tc.name: test BundleMgrHostImpl
 * @tc.desc: 1.test SetAppDistributionTypes
 */
HWTEST_F(BmsBundleManagerTest3, BundleMgrHostImpl_4900, Function | MediumTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::set<AppDistributionTypeEnum> appDistributionTypeEnums{
        AppDistributionTypeEnum::APP_DISTRIBUTION_TYPE_APP_GALLERY,
        AppDistributionTypeEnum::APP_DISTRIBUTION_TYPE_ENTERPRISE,
        AppDistributionTypeEnum::APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL,
        AppDistributionTypeEnum::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM,
        AppDistributionTypeEnum::APP_DISTRIBUTION_TYPE_INTERNALTESTING,
        AppDistributionTypeEnum::APP_DISTRIBUTION_TYPE_CROWDTESTING
    };
    ErrCode retCode = hostImpl->SetAppDistributionTypes(appDistributionTypeEnums);
    EXPECT_EQ(retCode, ERR_OK);
}
} // OHOS