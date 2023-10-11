/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "application_info.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
#include "bundle_resource_configuration.h"
#include "bundle_resource_manager.h"
#include "bundle_resource_param.h"
#include "bundle_resource_parser.h"
#include "bundle_resource_process.h"
#include "bundle_resource_rdb.h"
#include "bundle_system_state.h"
#endif

#include "bundle_verify_mgr.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "parameter.h"
#include "permission_define.h"
#include "remote_ability_info.h"
#include "scope_guard.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {
const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
const std::string BUNDLE_NAME = "com.example.bmsaccesstoken1";
const std::string MODULE_NAME = "entry";
const std::string ABILITY_NAME = "com.example.bmsaccesstoken1.MainAbility";
const std::string HAP_FILE_PATH1 = "/data/test/resource/bms/accesstoken_bundle/bmsAccessTokentest1.hap";
const std::string HAP_NOT_EXIST = "not exist";
}  // namespace

class BmsBundleResourceTest : public testing::Test {
public:
    BmsBundleResourceTest();
    ~BmsBundleResourceTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UpdateBundle(const std::string &bundlePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StartInstalldService() const;
    void StartBundleService();

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleResourceTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleResourceTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleResourceTest::BmsBundleResourceTest()
{}

BmsBundleResourceTest::~BmsBundleResourceTest()
{}

void BmsBundleResourceTest::SetUpTestCase()
{}

void BmsBundleResourceTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleResourceTest::SetUp()
{
    StartInstalldService();
    StartBundleService();
}

void BmsBundleResourceTest::TearDown()
{}

ErrCode BmsBundleResourceTest::InstallBundle(const std::string &bundlePath) const
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
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USERID;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleResourceTest::UpdateBundle(const std::string &bundlePath) const
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
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleResourceTest::UnInstallBundle(const std::string &bundleName) const
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

void BmsBundleResourceTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleResourceTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

const std::shared_ptr<BundleDataMgr> BmsBundleResourceTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
/**
 * @tc.number: BmsBundleResourceTest_0001
 * Function: GetKey
 * @tc.name: test GetKey
 * @tc.desc: 1. system running normally
 *           2. test ResourceInfo GetKey
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0001, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    std::string key = resourceInfo.GetKey();
    EXPECT_EQ(key, "bundleName");

    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.abilityName_ = "abilityName";
    key = resourceInfo.GetKey();
    EXPECT_EQ(key, "bundleName/moduleName/abilityName");
}

/**
 * @tc.number: BmsBundleResourceTest_0002
 * Function: ParseKey
 * @tc.name: test ParseKey
 * @tc.desc: 1. system running normally
 *           2. test ResourceInfo ParseKey
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0002, Function | SmallTest | Level0)
{
    std::string key = "bundleName";
    ResourceInfo resourceInfo;
    resourceInfo.ParseKey(key);
    EXPECT_EQ(resourceInfo.bundleName_, "bundleName");
    EXPECT_EQ(resourceInfo.moduleName_, "");
    EXPECT_EQ(resourceInfo.abilityName_, "");

    key = "bundleName/";
    resourceInfo.ParseKey(key);
    EXPECT_EQ(resourceInfo.bundleName_, "bundleName");
    EXPECT_EQ(resourceInfo.moduleName_, "");
    EXPECT_EQ(resourceInfo.abilityName_, "");

    key = "bundleName/abilityName";
    resourceInfo.ParseKey(key);
    EXPECT_EQ(resourceInfo.bundleName_, "bundleName");
    EXPECT_EQ(resourceInfo.moduleName_, "");
    EXPECT_EQ(resourceInfo.abilityName_, "abilityName");

    key = "bundleName/moduleName/abilityName";
    resourceInfo.ParseKey(key);
    EXPECT_EQ(resourceInfo.bundleName_, "bundleName");
    EXPECT_EQ(resourceInfo.moduleName_, "moduleName");
    EXPECT_EQ(resourceInfo.abilityName_, "abilityName");
}

/**
 * @tc.number: BmsBundleResourceTest_0003
 * Function: GetKey ParseKey
 * @tc.name: test GetKey and ParseKey
 * @tc.desc: 1. system running normally
 *           2. test ResourceInfo GetKey and ParseKey
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0003, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.abilityName_ = "abilityName";
    std::string key = resourceInfo.GetKey();

    ResourceInfo newResourceInfo;
    newResourceInfo.ParseKey(key);

    EXPECT_EQ(resourceInfo.bundleName_, newResourceInfo.bundleName_);
    EXPECT_EQ(resourceInfo.moduleName_, newResourceInfo.moduleName_);
    EXPECT_EQ(resourceInfo.abilityName_, newResourceInfo.abilityName_);
}

/**
 * @tc.number: BmsBundleResourceTest_0004
 * Function: BundleSystemState
 * @tc.name: test BundleSystemState
 * @tc.desc: 1. system running normally
 *           2. test BundleSystemState
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0004, Function | SmallTest | Level0)
{
    std::string oldColorMode = BundleSystemState::GetInstance().GetSystemColorMode();
    std::string oldLanguage = BundleSystemState::GetInstance().GetSystemLanguage();

    std::string colorMode = "light";
    BundleSystemState::GetInstance().SetSystemColorMode(colorMode);
    EXPECT_EQ(colorMode, BundleSystemState::GetInstance().GetSystemColorMode());
    BundleSystemState::GetInstance().SetSystemColorMode(oldColorMode);

    std::string language = "zh-Hans";
    BundleSystemState::GetInstance().SetSystemLanguage(language);
    EXPECT_EQ(language, BundleSystemState::GetInstance().GetSystemLanguage());
    BundleSystemState::GetInstance().SetSystemLanguage(oldLanguage);

    std::string key = BundleSystemState::GetInstance().ToString();
    EXPECT_NE(key, "");
    bool ans = BundleSystemState::GetInstance().FromString("{");
    EXPECT_FALSE(ans);
    ans = BundleSystemState::GetInstance().FromString(key);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0005
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0005, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_FALSE(ans);
    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_FALSE(ans);

    resourceInfo.bundleName_ = "bundleName";
    ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);
    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0006
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfos
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0006, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    std::vector<ResourceInfo> resourceInfos;
    bool ans = resourceRdb.AddResourceInfos(resourceInfos);
    EXPECT_FALSE(ans);

    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfos.push_back(resourceInfo);

    ans = resourceRdb.AddResourceInfos(resourceInfos);
    EXPECT_TRUE(ans);
    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);

    resourceInfos.clear();
    ResourceInfo resourceInfo_2;
    resourceInfos.push_back(resourceInfo_2);
    ans = resourceRdb.AddResourceInfos(resourceInfos);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0007
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetAllResourceName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0007, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;

    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";

    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    std::vector<std::string> keyNames;
    ans = resourceRdb.GetAllResourceName(keyNames);
    EXPECT_TRUE(ans);
    EXPECT_TRUE(std::find(keyNames.begin(), keyNames.end(), resourceInfo.GetKey()) != keyNames.end());

    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0008
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test IsCurrentColorModeExist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0008, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    ans = resourceRdb.IsCurrentColorModeExist();
    EXPECT_TRUE(ans);

    std::string oldColorMode = BundleSystemState::GetInstance().GetSystemColorMode();
    BundleSystemState::GetInstance().SetSystemColorMode("aaaaaa");
    ans = resourceRdb.IsCurrentColorModeExist();
    EXPECT_FALSE(ans);
    BundleSystemState::GetInstance().SetSystemColorMode(oldColorMode);

    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0009
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfo, bundle not exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0009, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    InnerBundleInfo bundleInfo;
    // userId not exist
    bool ans = manager->AddResourceInfo(bundleInfo, 103);
    EXPECT_FALSE(ans);

    // bundle not exist
    ans = manager->AddResourceInfo(bundleInfo, USERID);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0010
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfo, bundle exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0010, Function | SmallTest | Level0)
{
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.bundleType = BundleType::SHARED;
    InnerBundleInfo bundleInfo;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    // bundle exist but userId not exist
    bool ans = manager->AddResourceInfo(bundleInfo, USERID);
    EXPECT_FALSE(ans);
    ans = manager->AddResourceInfo(bundleInfo, USERID, HAP_FILE_PATH1);
    EXPECT_FALSE(ans);

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    userInfo.bundleName = BUNDLE_NAME;
    bundleInfo.AddInnerBundleUserInfo(userInfo);
    // bundle exist, userId exist, SHARED resourceInfo is empty
    ans = manager->AddResourceInfo(bundleInfo, USERID);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0011
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfo, bundle exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0011, Function | SmallTest | Level0)
{
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    InnerBundleInfo bundleInfo;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    // bundle exist but userId not exist
    bool ans = manager->AddResourceInfo(bundleInfo, USERID);
    EXPECT_FALSE(ans);
    // bundle exist but userId not exist
    ans = manager->AddResourceInfo(bundleInfo, USERID, HAP_FILE_PATH1);
    EXPECT_FALSE(ans);

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    userInfo.bundleName = BUNDLE_NAME;
    bundleInfo.AddInnerBundleUserInfo(userInfo);
    // bundle exist, userId  exist
    ans = manager->AddResourceInfo(bundleInfo, USERID);
    EXPECT_TRUE(ans);

    manager->AddResourceInfo(bundleInfo, USERID, HAP_FILE_PATH1);
    EXPECT_TRUE(ans);

    ans = manager->DeleteResourceInfo(BUNDLE_NAME);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0012
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test AddAllResourceInfo, userId not exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0012, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    // userId not exist, no resourceInfo
    bool ans = manager->AddAllResourceInfo(200);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0013
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfoByBundleName, bundle not exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0013, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    // bundle not exist
    bool ans = manager->AddResourceInfoByBundleName(BUNDLE_NAME, USERID);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0014
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfoByBundleName, bundle exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0014, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    // bundle exist, userId not exist
    bool ans = manager->AddResourceInfoByBundleName(BUNDLE_NAME, 200);
    EXPECT_FALSE(ans);

    // bundle exist, userId exist
    ans = manager->AddResourceInfoByBundleName(BUNDLE_NAME, USERID);
    EXPECT_TRUE(ans);

    // delete key
    ans = manager->DeleteResourceInfo(BUNDLE_NAME);
    EXPECT_TRUE(ans);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0015
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfoByAbility, bundle exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0015, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    // bundle not exist
    bool ans = manager->AddResourceInfoByAbility(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME, USERID);
    EXPECT_FALSE(ans);

    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    // bundle exist, moduleName or abilityName not exist
    ans = manager->AddResourceInfoByAbility(BUNDLE_NAME, "xxx", "yyy", USERID);
    EXPECT_FALSE(ans);

    // bundle  moduleName exist, abilityName not exist
    ans = manager->AddResourceInfoByAbility(BUNDLE_NAME, MODULE_NAME, "yyy", USERID);
    EXPECT_FALSE(ans);

    // bundle  moduleName exist, abilityName exist
    ans = manager->AddResourceInfoByAbility(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME, USERID);
    EXPECT_TRUE(ans);

    // delete key
    ans = manager->DeleteResourceInfo(BUNDLE_NAME);
    EXPECT_TRUE(ans);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0016
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetAllResourceName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0016, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    std::vector<std::string> keyNames;
    ans = manager->GetAllResourceName(keyNames);
    EXPECT_TRUE(ans);

    EXPECT_TRUE(std::find(keyNames.begin(), keyNames.end(), resourceInfo.GetKey()) != keyNames.end());
    // delete key
    ans = manager->DeleteResourceInfo(BUNDLE_NAME);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0050
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0050, Function | SmallTest | Level0)
{
    InnerBundleInfo bundleInfo;
    std::vector<ResourceInfo> resourceInfos;
    // bundleName empty
    bool ans = BundleResourceProcess::GetLauncherAbilityResourceInfo(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.bundleType = BundleType::SHARED;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    // bundle type is shared
    ans = BundleResourceProcess::GetLauncherAbilityResourceInfo(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    applicationInfo.bundleType = BundleType::APP;
    applicationInfo.hideDesktopIcon = true;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    // hideDesktopIcon is true
    ans = BundleResourceProcess::GetLauncherAbilityResourceInfo(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    applicationInfo.hideDesktopIcon = false;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo info;
    info.entryInstallationFree = true;
    bundleInfo.SetBaseBundleInfo(info);
    // entryInstallationFree is true
    ans = BundleResourceProcess::GetLauncherAbilityResourceInfo(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    info.entryInstallationFree = false;
    bundleInfo.SetBaseBundleInfo(info);
    // abilityInfos is empty
    ans = BundleResourceProcess::GetLauncherAbilityResourceInfo(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());
}

/**
 * @tc.number: BmsBundleResourceTest_0051
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0051, Function | SmallTest | Level0)
{
    InnerBundleInfo bundleInfo;
    ResourceInfo resourceInfo;
    // bundleName empty
    bool ans = BundleResourceProcess::GetBundleResourceInfo(bundleInfo, USERID, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");


    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.bundleType = BundleType::SHARED;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    // bundle type is shared
    ans = BundleResourceProcess::GetBundleResourceInfo(bundleInfo, USERID, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");

    applicationInfo.bundleType = BundleType::APP;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    ans = BundleResourceProcess::GetBundleResourceInfo(bundleInfo, USERID, resourceInfo);
    EXPECT_TRUE(ans);
    EXPECT_EQ(resourceInfo.bundleName_, BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleResourceTest_0052
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0052, Function | SmallTest | Level0)
{
    InnerBundleInfo bundleInfo;
    ResourceInfo resourceInfo;
    // bundleName empty
    bool ans = BundleResourceProcess::GetBundleResourceInfo(bundleInfo, USERID, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");


    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.bundleType = BundleType::SHARED;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    // bundle type is shared
    ans = BundleResourceProcess::GetBundleResourceInfo(bundleInfo, USERID, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");

    applicationInfo.bundleType = BundleType::APP;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    ans = BundleResourceProcess::GetBundleResourceInfo(bundleInfo, USERID, resourceInfo);
    EXPECT_TRUE(ans);
    EXPECT_EQ(resourceInfo.bundleName_, BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleResourceTest_0053
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0053, Function | SmallTest | Level0)
{
    InnerBundleInfo bundleInfo;
    std::vector<ResourceInfo> resourceInfos;
    // bundleName not exist
    bool ans = BundleResourceProcess::GetResourceInfo(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    // bundleName not exist
    ans = BundleResourceProcess::GetResourceInfo(bundleInfo, 0, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    // userId not exist
    ans = BundleResourceProcess::GetResourceInfo(bundleInfo, 200, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    userInfo.bundleName = BUNDLE_NAME;
    bundleInfo.AddInnerBundleUserInfo(userInfo);
    // bundle and userId exist
    ans = BundleResourceProcess::GetResourceInfo(bundleInfo, USERID, resourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(resourceInfos.empty());
}

/**
 * @tc.number: BmsBundleResourceTest_0054
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetResourceInfoByBundleName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0054, Function | SmallTest | Level0)
{
    std::vector<ResourceInfo> resourceInfos;
    // bundleName not exist
    bool ans = BundleResourceProcess::GetResourceInfoByBundleName(BUNDLE_NAME, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    // userId exist
    ans = BundleResourceProcess::GetResourceInfoByBundleName(BUNDLE_NAME, 200, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    ans = BundleResourceProcess::GetResourceInfoByBundleName(BUNDLE_NAME, USERID, resourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(resourceInfos.empty());

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0055
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetResourceInfoByAbilityName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0055, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    // bundle not exist
    bool ans = BundleResourceProcess::GetResourceInfoByAbilityName(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME,
        USERID, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");

    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    // userId not exist
    ans = BundleResourceProcess::GetResourceInfoByAbilityName(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME,
        200, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");

    // bundle exist, moduleName or abilityName not exist
    ans = BundleResourceProcess::GetResourceInfoByAbilityName(BUNDLE_NAME, "xxx", "yyy", USERID, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");

    // bundle  moduleName exist, abilityName not exist
    ans = BundleResourceProcess::GetResourceInfoByAbilityName(BUNDLE_NAME, MODULE_NAME, "yyy", USERID, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");

    // bundle  moduleName exist, abilityName exist
    ans = BundleResourceProcess::GetResourceInfoByAbilityName(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME,
        USERID, resourceInfo);
    EXPECT_TRUE(ans);
    EXPECT_EQ(resourceInfo.bundleName_, BUNDLE_NAME);
    EXPECT_EQ(resourceInfo.moduleName_, MODULE_NAME);
    EXPECT_EQ(resourceInfo.abilityName_, ABILITY_NAME);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0056
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetAllResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0056, Function | SmallTest | Level0)
{
    std::vector<ResourceInfo> resourceInfos;
    // userId not exist
    bool ans = BundleResourceProcess::GetAllResourceInfo(200, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    // userId exist
    ans = BundleResourceProcess::GetAllResourceInfo(USERID, resourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(resourceInfos.empty());
}

/**
 * @tc.number: BmsBundleResourceTest_0060
 * Function: BundleResourceParam
 * @tc.name: test BundleResourceParam
 * @tc.desc: 1. system running normally
 *           2. test GetSystemLanguage and GetSystemColorMode
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0060, Function | SmallTest | Level0)
{
    std::string language = BundleResourceParam::GetSystemLanguage();
    EXPECT_FALSE(language.empty());

    std::string colorMode = BundleResourceParam::GetSystemColorMode();
    EXPECT_FALSE(colorMode.empty());
}

/**
 * @tc.number: BmsBundleResourceTest_0061
 * Function: BundleResourceConfiguration
 * @tc.name: test BundleResourceConfiguration
 * @tc.desc: 1. system running normally
 *           2. test InitResourceGlobalConfig
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0061, Function | SmallTest | Level0)
{
    bool ans = BundleResourceConfiguration::InitResourceGlobalConfig(nullptr);
    EXPECT_FALSE(ans);

    ans = BundleResourceConfiguration::InitResourceGlobalConfig("", nullptr);
    EXPECT_FALSE(ans);

    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());

    ans = BundleResourceConfiguration::InitResourceGlobalConfig(resourceManager);
    EXPECT_TRUE(ans);

    ans = BundleResourceConfiguration::InitResourceGlobalConfig(HAP_NOT_EXIST, resourceManager);
    EXPECT_FALSE(ans);

    ans = BundleResourceConfiguration::InitResourceGlobalConfig(HAP_FILE_PATH1, resourceManager);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0062
 * Function: BundleResourceParser
 * @tc.name: test BundleResourceParser
 * @tc.desc: 1. system running normally
 *           2. test ParseResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0062, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = BUNDLE_NAME;
    resourceInfo.label_ = BUNDLE_NAME;
    resourceInfo.labelId_ = 0;
    resourceInfo.iconId_ = 0;
    BundleResourceParser parser;
    bool ans = parser.ParseResourceInfo(resourceInfo);
    EXPECT_FALSE(ans);

    resourceInfo.defaultIconHapPath_ = HAP_NOT_EXIST;
    ans = parser.ParseResourceInfo(resourceInfo);
    EXPECT_FALSE(ans);

    resourceInfo.hapPath_ = HAP_NOT_EXIST;
    resourceInfo.defaultIconHapPath_ = "";
    ans = parser.ParseResourceInfo(resourceInfo);
    EXPECT_FALSE(ans);

    resourceInfo.hapPath_ = HAP_FILE_PATH1;
    ans = parser.ParseResourceInfo(resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.label_, BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleResourceTest_0063
 * Function: BundleResourceParser
 * @tc.name: test BundleResourceParser
 * @tc.desc: 1. system running normally
 *           2. test ParseResourceInfos
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0063, Function | SmallTest | Level0)
{
    std::vector<ResourceInfo> resourceInfos;
    BundleResourceParser parser;
    bool ans = parser.ParseResourceInfos(resourceInfos);
    EXPECT_FALSE(ans);

    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = BUNDLE_NAME;
    resourceInfo.label_ = BUNDLE_NAME;
    resourceInfo.labelId_ = 0;
    resourceInfo.iconId_ = 0;
    resourceInfos.push_back(resourceInfo);

    ans = parser.ParseResourceInfos(resourceInfos);
    EXPECT_FALSE(ans);
}
#endif
} // OHOS
