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
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "bundle_permission_mgr.h"

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
#include "bundle_resource_callback.h"
#include "bundle_resource_configuration.h"
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
#endif

#include "bundle_verify_mgr.h"
#include "common_event_support.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
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

namespace OHOS {
namespace {
const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
const std::string BUNDLE_NAME = "com.example.bmsaccesstoken1";
const std::string BUNDLE_NAME_NOT_EXIST = "com.example.not_exist";
const std::string MODULE_NAME = "entry";
const std::string ABILITY_NAME = "com.example.bmsaccesstoken1.MainAbility";
const std::string HAP_FILE_PATH1 = "/data/test/resource/bms/accesstoken_bundle/bmsAccessTokentest1.hap";
const std::string HAP_NOT_EXIST = "not exist";
const std::string HAP_NO_ICON = "/data/test/resource/bms/accesstoken_bundle/bmsThirdBundle2.hap";
const std::string BUNDLE_NAME_NO_ICON = "com.third.hiworld.example1";
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
    bool OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data);
    sptr<BundleMgrProxy> GetBundleMgrProxy();

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

bool BmsBundleResourceTest::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    OHOS::EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    auto subscriberPtr = std::make_shared<BundleResourceEventSubscriber>(subscribeInfo);
    subscriberPtr->OnReceiveEvent(data);
#endif
    std::string action = data.GetWant().GetAction();
    return action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED;
}

sptr<BundleMgrProxy> BmsBundleResourceTest::GetBundleMgrProxy()
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
    resourceInfo.icon_ = "data:image/png";

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
    // bundle exist, userId exist
    ans = manager->AddResourceInfo(bundleInfo, USERID);
    EXPECT_TRUE(ans);

    ans = manager->AddResourceInfo(bundleInfo, USERID, HAP_FILE_PATH1);
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
    resourceInfo.icon_ = "data:image/png";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    std::vector<std::string> keyNames;
    ans = manager->GetAllResourceName(keyNames);
    EXPECT_TRUE(ans);

    EXPECT_TRUE(std::find(keyNames.begin(), keyNames.end(), resourceInfo.GetKey()) != keyNames.end());
    // delete key
    ans = manager->DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0017
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0017, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    BundleResourceInfo info;
    ans = resourceRdb.GetBundleResourceInfo("", 0, info);
    EXPECT_FALSE(ans);

    ans = resourceRdb.GetBundleResourceInfo(BUNDLE_NAME_NOT_EXIST,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), info);
    EXPECT_FALSE(ans);

    ans = resourceRdb.GetBundleResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), info);
    EXPECT_TRUE(ans);
    EXPECT_EQ(info.bundleName, resourceInfo.bundleName_);
    EXPECT_EQ(info.label, resourceInfo.label_);
    EXPECT_TRUE(info.icon.empty());

    BundleResourceInfo info2;
    ans = resourceRdb.GetBundleResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON), info2);
    EXPECT_TRUE(ans);
    EXPECT_EQ(info2.bundleName, resourceInfo.bundleName_);
    EXPECT_EQ(info2.icon, resourceInfo.icon_);
    EXPECT_TRUE(info2.label.empty());

    BundleResourceInfo info3;
    ans = resourceRdb.GetBundleResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), info3);
    EXPECT_TRUE(ans);
    EXPECT_EQ(info3.bundleName, resourceInfo.bundleName_);
    EXPECT_EQ(info3.icon, resourceInfo.icon_);
    EXPECT_EQ(info3.label, resourceInfo.label_);

    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0018
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0018, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    BundleResourceInfo info;
    ans = resourceRdb.GetBundleResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL), info);
    EXPECT_TRUE(ans);
    EXPECT_EQ(info.bundleName, resourceInfo.bundleName_);
    EXPECT_EQ(info.label, resourceInfo.label_);
    EXPECT_EQ(info.icon, resourceInfo.icon_);

    BundleResourceInfo info2;
    ans = resourceRdb.GetBundleResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON), info2);
    EXPECT_TRUE(ans);
    EXPECT_EQ(info2.bundleName, resourceInfo.bundleName_);
    EXPECT_EQ(info2.icon, resourceInfo.icon_);
    EXPECT_EQ(info2.label, resourceInfo.label_);

    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0019
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0019, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.abilityName_ = "abilityName";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    std::vector<LauncherAbilityResourceInfo> infos;
    ans = resourceRdb.GetLauncherAbilityResourceInfo("", 0, infos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(infos.empty());

    ans = resourceRdb.GetLauncherAbilityResourceInfo(BUNDLE_NAME_NOT_EXIST,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), infos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(infos.empty());

    ans = resourceRdb.GetLauncherAbilityResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), infos);
    EXPECT_TRUE(ans);
    EXPECT_TRUE(infos.size() == 1);
    if (!infos.empty()) {
        EXPECT_EQ(infos[0].bundleName, resourceInfo.bundleName_);
        EXPECT_EQ(infos[0].moduleName, resourceInfo.moduleName_);
        EXPECT_EQ(infos[0].abilityName, resourceInfo.abilityName_);
        EXPECT_EQ(infos[0].label, resourceInfo.label_);
        EXPECT_TRUE(infos[0].icon.empty());
    }
    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0020
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0020, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.abilityName_ = "abilityName";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    std::vector<LauncherAbilityResourceInfo> infos;
    ans = resourceRdb.GetLauncherAbilityResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON), infos);
    EXPECT_TRUE(ans);
    EXPECT_TRUE(infos.size() == 1);
    if (!infos.empty()) {
        EXPECT_EQ(infos[0].bundleName, resourceInfo.bundleName_);
        EXPECT_EQ(infos[0].moduleName, resourceInfo.moduleName_);
        EXPECT_EQ(infos[0].abilityName, resourceInfo.abilityName_);
        EXPECT_EQ(infos[0].icon, resourceInfo.icon_);
        EXPECT_TRUE(infos[0].label.empty());
    }
    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0021
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0021, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.abilityName_ = "abilityName";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    std::vector<LauncherAbilityResourceInfo> infos;
    ans = resourceRdb.GetLauncherAbilityResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL), infos);
    EXPECT_TRUE(ans);
    EXPECT_TRUE(infos.size() == 1);
    if (!infos.empty()) {
        EXPECT_EQ(infos[0].bundleName, resourceInfo.bundleName_);
        EXPECT_EQ(infos[0].moduleName, resourceInfo.moduleName_);
        EXPECT_EQ(infos[0].abilityName, resourceInfo.abilityName_);
        EXPECT_EQ(infos[0].icon, resourceInfo.icon_);
        EXPECT_EQ(infos[0].label, resourceInfo.label_);
    }
    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0022
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0022, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);
    ResourceInfo resourceInfo2;
    resourceInfo2.bundleName_ = "bundleName";
    resourceInfo2.moduleName_ = "moduleName";
    resourceInfo2.abilityName_ = "abilityName";
    resourceInfo2.label_ = "label2";
    resourceInfo2.icon_ = "icon2";
    ans = resourceRdb.AddResourceInfo(resourceInfo2);
    EXPECT_TRUE(ans);

    std::vector<BundleResourceInfo> infos;
    ans = resourceRdb.GetAllBundleResourceInfo(
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), infos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(infos.empty());
    auto iter = std::find_if(infos.begin(), infos.end(), [resourceInfo](BundleResourceInfo info) {
        return resourceInfo.bundleName_ == info.bundleName;
    });
    EXPECT_TRUE(iter != infos.end());

    if (iter != infos.end()) {
        EXPECT_EQ(iter->bundleName, resourceInfo.bundleName_);
        EXPECT_EQ(iter->label, resourceInfo.label_);
        EXPECT_TRUE(iter->icon.empty());
    }
    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
    ans = resourceRdb.DeleteResourceInfo(resourceInfo2.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0023
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetAllLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0023, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);
    ResourceInfo resourceInfo2;
    resourceInfo2.bundleName_ = "bundleName";
    resourceInfo2.moduleName_ = "moduleName";
    resourceInfo2.abilityName_ = "abilityName";
    resourceInfo2.label_ = "label2";
    resourceInfo2.icon_ = "icon2";
    ans = resourceRdb.AddResourceInfo(resourceInfo2);
    EXPECT_TRUE(ans);

    std::vector<LauncherAbilityResourceInfo> infos;
    ans = resourceRdb.GetAllLauncherAbilityResourceInfo(
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), infos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(infos.empty());
    auto iter = std::find_if(infos.begin(), infos.end(), [resourceInfo2](LauncherAbilityResourceInfo info) {
        return resourceInfo2.bundleName_ == info.bundleName;
    });
    EXPECT_TRUE(iter != infos.end());

    if (iter != infos.end()) {
        EXPECT_EQ(iter->bundleName, resourceInfo2.bundleName_);
        EXPECT_EQ(iter->moduleName, resourceInfo2.moduleName_);
        EXPECT_EQ(iter->abilityName, resourceInfo2.abilityName_);
        EXPECT_EQ(iter->label, resourceInfo2.label_);
        EXPECT_TRUE(iter->icon.empty());
    }

    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
    ans = resourceRdb.DeleteResourceInfo(resourceInfo2.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0050
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetAbilityResourceInfos
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0050, Function | SmallTest | Level0)
{
    InnerBundleInfo bundleInfo;
    std::vector<ResourceInfo> resourceInfos;
    // bundleName empty
    bool ans = BundleResourceProcess::GetAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.bundleType = BundleType::SHARED;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    // bundle type is shared
    ans = BundleResourceProcess::GetAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    applicationInfo.bundleType = BundleType::APP;
    applicationInfo.hideDesktopIcon = true;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    // hideDesktopIcon is true
    ans = BundleResourceProcess::GetAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    applicationInfo.hideDesktopIcon = false;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo info;
    info.entryInstallationFree = true;
    bundleInfo.SetBaseBundleInfo(info);
    // entryInstallationFree is true
    ans = BundleResourceProcess::GetAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    info.entryInstallationFree = false;
    bundleInfo.SetBaseBundleInfo(info);
    // abilityInfos is empty
    ans = BundleResourceProcess::GetAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
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
    bool ans = BundleResourceProcess::GetBundleResourceInfo(bundleInfo, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");


    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.bundleType = BundleType::SHARED;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    // bundle type is shared
    ans = BundleResourceProcess::GetBundleResourceInfo(bundleInfo, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");

    applicationInfo.bundleType = BundleType::APP;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    ans = BundleResourceProcess::GetBundleResourceInfo(bundleInfo, resourceInfo);
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
    bool ans = BundleResourceProcess::GetBundleResourceInfo(bundleInfo, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");


    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.bundleType = BundleType::SHARED;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    // bundle type is shared
    ans = BundleResourceProcess::GetBundleResourceInfo(bundleInfo, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");

    applicationInfo.bundleType = BundleType::APP;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    ans = BundleResourceProcess::GetBundleResourceInfo(bundleInfo, resourceInfo);
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
    std::map<std::string, std::vector<ResourceInfo>> resourceInfos;
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

/**
 * @tc.number: BmsBundleResourceTest_0064
 * Function: BundleResourceParser
 * @tc.name: test BundleResourceParser
 * @tc.desc: 1. system running normally
 *           2. test ParseLabelResourceByPath
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0064, Function | SmallTest | Level0)
{
    std::string label;
    BundleResourceParser parser;
    bool ans = parser.ParseLabelResourceByPath("", 0, label);
    EXPECT_FALSE(ans);

    ans = parser.ParseLabelResourceByPath(HAP_NOT_EXIST, 0, label);
    EXPECT_TRUE(ans); // allow labelId is 0, then label is bundleName

    ans = parser.ParseLabelResourceByPath(HAP_FILE_PATH1, 0, label);
    EXPECT_TRUE(ans);

    ans = parser.ParseLabelResourceByPath(HAP_FILE_PATH1, 1, label); // labelId not exist
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0065
 * Function: BundleResourceParser
 * @tc.name: test BundleResourceParser
 * @tc.desc: 1. system running normally
 *           2. test ParseLabelResourceByResourceManager
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0065, Function | SmallTest | Level0)
{
    std::string label;
    BundleResourceParser parser;
    bool ans = parser.ParseLabelResourceByResourceManager(nullptr, 0, label);
    EXPECT_FALSE(ans);

    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    ans = parser.ParseLabelResourceByResourceManager(resourceManager, 0, label);
    EXPECT_TRUE(ans);

    ans = parser.ParseLabelResourceByResourceManager(resourceManager, 1, label); // labelId not exist
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0066
 * Function: BundleResourceParser
 * @tc.name: test BundleResourceParser
 * @tc.desc: 1. system running normally
 *           2. test ParseIconResourceByPath
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0066, Function | SmallTest | Level0)
{
    std::string icon;
    BundleResourceParser parser;
    bool ans = parser.ParseIconResourceByPath("", 0, icon);
    EXPECT_FALSE(ans);

    ans = parser.ParseIconResourceByPath(HAP_NOT_EXIST, 0, icon);
    EXPECT_FALSE(ans);

    ans = parser.ParseIconResourceByPath(HAP_FILE_PATH1, 0, icon);
    EXPECT_FALSE(ans);

    ans = parser.ParseIconResourceByPath(HAP_FILE_PATH1, 1, icon); // iconId not exist
    EXPECT_FALSE(ans);
    EXPECT_EQ(icon, "");
}

/**
 * @tc.number: BmsBundleResourceTest_0067
 * Function: BundleResourceParser
 * @tc.name: test BundleResourceParser
 * @tc.desc: 1. system running normally
 *           2. test ParseIconResourceByResourceManager
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0067, Function | SmallTest | Level0)
{
    std::string icon;
    BundleResourceParser parser;
    bool ans = parser.ParseIconResourceByResourceManager(nullptr, 0, icon);
    EXPECT_FALSE(ans);

    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    ans = parser.ParseIconResourceByResourceManager(resourceManager, 0, icon);
    EXPECT_FALSE(ans);

    ans = parser.ParseIconResourceByResourceManager(resourceManager, 1, icon); // iconId not exist
    EXPECT_FALSE(ans);
    EXPECT_EQ(icon, "");
}

/**
 * @tc.number: BmsBundleResourceTest_0068
 * Function: BundleResourceParser
 * @tc.name: test BundleResourceParser
 * @tc.desc: 1. system running normally
 *           2. test ParseLabelResourceByPath and ParseIconResourceByPath, bundle exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0068, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    std::vector<ResourceInfo> resourceInfos;
    bool ans = BundleResourceProcess::GetResourceInfoByBundleName(BUNDLE_NAME, USERID, resourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(resourceInfos.empty());

    if (!resourceInfos.empty()) {
        std::string label;
        BundleResourceParser parser;
        ans = parser.ParseLabelResourceByPath(resourceInfos[0].hapPath_, resourceInfos[0].labelId_, label);
        EXPECT_TRUE(ans);
        EXPECT_FALSE(label.empty());

        std::string icon;
        ans = parser.ParseIconResourceByPath(resourceInfos[0].hapPath_, resourceInfos[0].iconId_, icon);
        EXPECT_TRUE(ans);
        EXPECT_FALSE(icon.empty());
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0069
 * Function: BundleResourceParser
 * @tc.name: test BundleResourceParser
 * @tc.desc: 1. system running normally
 *           2. test ParseResourceInfo, bundle exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0069, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    std::vector<ResourceInfo> resourceInfos;
    bool ans = BundleResourceProcess::GetResourceInfoByBundleName(BUNDLE_NAME, USERID, resourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(resourceInfos.empty());

    if (!resourceInfos.empty()) {
        ResourceInfo resourceInfo;
        BundleResourceParser parser;
        ans = parser.ParseResourceInfo(resourceInfos[0]);
        EXPECT_TRUE(ans);
        EXPECT_NE(resourceInfos[0].label_, "");
        EXPECT_NE(resourceInfos[0].icon_, "");

        ans = parser.ParseResourceInfos(resourceInfos);
        EXPECT_TRUE(ans);
        for (const auto &info : resourceInfos) {
            EXPECT_NE(info.label_, "");
            EXPECT_NE(info.icon_, "");
        }
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0070
 * Function: BundleResourceParser
 * @tc.name: test BundleResourceParser
 * @tc.desc: 1. system running normally
 *           2. test ParseResourceInfo, bundle exist, no icon, use default icon
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0070, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_NO_ICON);
    EXPECT_EQ(installResult, ERR_OK);

    std::vector<ResourceInfo> resourceInfos;
    bool ans = BundleResourceProcess::GetResourceInfoByBundleName(BUNDLE_NAME_NO_ICON, USERID, resourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_EQ(resourceInfos.size(), 2);

    if (!resourceInfos.empty()) {
        ResourceInfo resourceInfo;
        BundleResourceParser parser;
        ans = parser.ParseResourceInfo(resourceInfos[0]);
        EXPECT_TRUE(ans);
        EXPECT_NE(resourceInfos[0].label_, "");
        EXPECT_NE(resourceInfos[0].icon_, "");

        ans = parser.ParseResourceInfos(resourceInfos);
        EXPECT_TRUE(ans);
        for (const auto &info : resourceInfos) {
            EXPECT_NE(info.label_, "");
            EXPECT_NE(info.icon_, "");
        }
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_NO_ICON);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0071
 * Function: BundleResourceEventSubscriber
 * @tc.name: test BundleResourceEventSubscriber
 * @tc.desc: 1. system running normally
 *           2. test BundleResourceEventSubscriber
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0071, Function | SmallTest | Level0)
{
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    OHOS::EventFwk::CommonEventData commonData { want };
    bool ans = OnReceiveEvent(commonData);
    EXPECT_FALSE(ans);

    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    OHOS::EventFwk::CommonEventData commonData2 { want };
    commonData2.SetCode(2000); // userId not exist
    ans = OnReceiveEvent(commonData2);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0072
 * Function: BundleResourceObserver
 * @tc.name: test BundleResourceObserver
 * @tc.desc: 1. system running normally
 *           2. test BundleResourceObserver
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0072, Function | SmallTest | Level0)
{
#ifdef ABILITY_RUNTIME_ENABLE
    std::string oldColorMode = BundleSystemState::GetInstance().GetSystemColorMode();
    std::string oldLanguage = BundleSystemState::GetInstance().GetSystemLanguage();

    BundleResourceObserver observer;
    AppExecFwk::Configuration configuration;
    observer.OnConfigurationUpdated(configuration);
    EXPECT_EQ(BundleSystemState::GetInstance().GetSystemColorMode(), oldColorMode);
    EXPECT_EQ(BundleSystemState::GetInstance().GetSystemLanguage(), oldLanguage);

    configuration.AddItem(OHOS::AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, oldLanguage);
    configuration.AddItem(OHOS::AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE, oldColorMode);
    observer.OnConfigurationUpdated(configuration);
    EXPECT_EQ(BundleSystemState::GetInstance().GetSystemLanguage(), oldLanguage);
    EXPECT_EQ(BundleSystemState::GetInstance().GetSystemColorMode(), oldColorMode);

    std::string newLanguage = "test";
    std::string newColorMode = "test";
    configuration.AddItem(OHOS::AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, newLanguage);
    configuration.AddItem(OHOS::AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE, newColorMode);
    observer.OnConfigurationUpdated(configuration);
    EXPECT_EQ(BundleSystemState::GetInstance().GetSystemLanguage(), newLanguage);
    EXPECT_EQ(BundleSystemState::GetInstance().GetSystemColorMode(), newColorMode);

    configuration.AddItem(OHOS::AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE, oldLanguage);
    configuration.AddItem(OHOS::AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE, oldColorMode);
    observer.OnConfigurationUpdated(configuration);
    BundleSystemState::GetInstance().SetSystemLanguage(oldLanguage);
    BundleSystemState::GetInstance().SetSystemColorMode(oldColorMode);
#endif
}

/**
 * @tc.number: BmsBundleResourceTest_0073
 * Function: BundleResourceCallback
 * @tc.name: test BundleResourceCallback
 * @tc.desc: 1. system running normally
 *           2. test BundleResourceCallback.OnUserIdSwitched
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0073, Function | SmallTest | Level0)
{
    BundleResourceCallback callback;
    bool ans = callback.OnUserIdSwitched(200);
    EXPECT_FALSE(ans);

    ans = callback.OnUserIdSwitched(100);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0074
 * Function: BundleResourceCallback
 * @tc.name: test BundleResourceCallback
 * @tc.desc: 1. system running normally
 *           2. test BundleResourceCallback.OnSystemColorModeChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0074, Function | SmallTest | Level0)
{
    BundleResourceCallback callback;
    std::string oldColorMode = BundleSystemState::GetInstance().GetSystemColorMode();

    bool ans = callback.OnSystemColorModeChanged(oldColorMode);
    EXPECT_TRUE(ans);

    std::string colorMode = "dark";
    ans = callback.OnSystemColorModeChanged(colorMode);
    EXPECT_TRUE(ans);

    BundleSystemState::GetInstance().SetSystemColorMode(oldColorMode);
}

/**
 * @tc.number: BmsBundleResourceTest_0075
 * Function: BundleResourceCallback
 * @tc.name: test BundleResourceCallback
 * @tc.desc: 1. system running normally
 *           2. test BundleResourceCallback.OnSystemLanguageChange
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0075, Function | SmallTest | Level0)
{
    BundleResourceCallback callback;
    std::string oldLanguage = BundleSystemState::GetInstance().GetSystemLanguage();

    bool ans = callback.OnSystemLanguageChange(oldLanguage);
    EXPECT_TRUE(ans);

    std::string language = "test";
    ans = callback.OnSystemLanguageChange(language);
    EXPECT_TRUE(ans);

    ans = callback.OnSystemLanguageChange(oldLanguage);
    EXPECT_TRUE(ans);
    BundleSystemState::GetInstance().SetSystemLanguage(oldLanguage);
}

/**
 * @tc.number: BmsBundleResourceTest_0076
 * Function: BundleResourceCallback
 * @tc.name: test BundleResourceCallback
 * @tc.desc: 1. system running normally
 *           2. test BundleResourceCallback.OnBundleStatusChanged, bundle not exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0076, Function | SmallTest | Level0)
{
    BundleResourceCallback callback;
    std::string bundleName;
    bool ans = callback.OnBundleStatusChanged(bundleName, true, USERID);
    EXPECT_FALSE(ans);

    bundleName = "bundleName";
    ans = callback.OnBundleStatusChanged(bundleName, true, 200);
    EXPECT_FALSE(ans);

    ans = callback.OnBundleStatusChanged(bundleName, true, USERID); // bundleName not exist
    EXPECT_FALSE(ans);

    ans = callback.OnBundleStatusChanged(bundleName, false, USERID);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0077
 * Function: BundleResourceCallback
 * @tc.name: test BundleResourceCallback
 * @tc.desc: 1. system running normally
 *           2. test BundleResourceCallback.OnBundleStatusChanged, bundle exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0077, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    BundleResourceCallback callback;
    bool ans = callback.OnBundleStatusChanged(BUNDLE_NAME, true, USERID);
    EXPECT_TRUE(ans);

    ans = callback.OnBundleStatusChanged(BUNDLE_NAME, false, USERID); // bundleName exist
    EXPECT_TRUE(ans);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0078
 * Function: BundleResourceCallback
 * @tc.name: test BundleResourceCallback
 * @tc.desc: 1. system running normally
 *           2. test BundleResourceCallback.OnAbilityStatusChanged bundle not exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0078, Function | SmallTest | Level0)
{
    BundleResourceCallback callback;
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    bool ans = callback.OnAbilityStatusChanged(bundleName, moduleName, abilityName, true, USERID);
    EXPECT_FALSE(ans);

    ans = callback.OnAbilityStatusChanged(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME, true, 200);
    EXPECT_FALSE(ans);
    // bundleName not exist
    ans = callback.OnAbilityStatusChanged(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME, true, USERID);
    EXPECT_FALSE(ans);

    ans = callback.OnAbilityStatusChanged(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME, false, USERID);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0079
 * Function: BundleResourceCallback
 * @tc.name: test BundleResourceCallback
 * @tc.desc: 1. system running normally
 *           2. test BundleResourceCallback.OnAbilityStatusChanged, bundle exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0079, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    BundleResourceCallback callback;
    bool ans  = callback.OnAbilityStatusChanged(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME, true, USERID);
    EXPECT_TRUE(ans);

    ans = callback.OnAbilityStatusChanged(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME, false, USERID);
    EXPECT_TRUE(ans);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0088
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetResourceInfoByColorModeChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0088, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    std::vector<std::string> resourceNames;
    std::vector<ResourceInfo> resourceInfos;
    bool ans = BundleResourceProcess::GetResourceInfoByColorModeChanged(resourceNames, resourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_NE(resourceInfos.size(), 0);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0089
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetResourceInfoByColorModeChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0089, Function | SmallTest | Level0)
{
    std::vector<std::string> resourceNames;
    std::vector<ResourceInfo> resourceInfos;
    bool ans = BundleResourceProcess::GetResourceInfoByColorModeChanged(resourceNames, resourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_NE(resourceInfos.size(), 0);
}

/**
 * @tc.number: BmsBundleResourceTest_0090
 * Function: BundleResourceInfo
 * @tc.name: test BundleResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test BundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0090, Function | SmallTest | Level0)
{
    BundleResourceInfo info;
    info.bundleName = "bundleName";
    info.label = "label";
    info.icon = "icon";

    Parcel parcel;
    bool ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);

    BundleResourceInfo info_2;
    ret = info_2.ReadFromParcel(parcel);
    EXPECT_EQ(info_2.bundleName, info.bundleName);
    EXPECT_EQ(info_2.label, info.label);
    EXPECT_EQ(info_2.icon, info.icon);

    Parcel parcel_2;
    ret = info.Marshalling(parcel_2);
    EXPECT_TRUE(ret);
    std::shared_ptr<BundleResourceInfo> infoPtr(BundleResourceInfo::Unmarshalling(parcel_2));
    EXPECT_NE(infoPtr, nullptr);
    if (infoPtr != nullptr) {
        EXPECT_EQ(infoPtr->bundleName, info.bundleName);
        EXPECT_EQ(infoPtr->label, info.label);
        EXPECT_EQ(infoPtr->icon, info.icon);
    }

    Parcel parcel_3;
    ret = info_2.ReadFromParcel(parcel_3);
    EXPECT_FALSE(ret);
    std::shared_ptr<BundleResourceInfo> infoPtr_2(BundleResourceInfo::Unmarshalling(parcel_3));
    EXPECT_EQ(infoPtr_2, nullptr);
}

/**
 * @tc.number: BmsBundleResourceTest_0091
 * Function: LauncherAbilityResourceInfo
 * @tc.name: test LauncherAbilityResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test LauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0091, Function | SmallTest | Level0)
{
    LauncherAbilityResourceInfo info;
    info.bundleName = "bundleName";
    info.moduleName = "moduleName";
    info.abilityName = "abilityName";
    info.label = "label";
    info.icon = "icon";

    Parcel parcel;
    bool ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);

    LauncherAbilityResourceInfo info_2;
    ret = info_2.ReadFromParcel(parcel);
    EXPECT_EQ(info_2.bundleName, info.bundleName);
    EXPECT_EQ(info_2.moduleName, info.moduleName);
    EXPECT_EQ(info_2.abilityName, info.abilityName);
    EXPECT_EQ(info_2.label, info.label);
    EXPECT_EQ(info_2.icon, info.icon);

    Parcel parcel_2;
    ret = info.Marshalling(parcel_2);
    EXPECT_TRUE(ret);

    std::shared_ptr<LauncherAbilityResourceInfo> infoPtr(LauncherAbilityResourceInfo::Unmarshalling(parcel_2));
    EXPECT_NE(infoPtr, nullptr);
    if (infoPtr != nullptr) {
        EXPECT_EQ(infoPtr->bundleName, info.bundleName);
        EXPECT_EQ(infoPtr->moduleName, info.moduleName);
        EXPECT_EQ(infoPtr->abilityName, info.abilityName);
        EXPECT_EQ(infoPtr->label, info.label);
        EXPECT_EQ(infoPtr->icon, info.icon);
    }

    Parcel parcel_3;
    ret = info_2.ReadFromParcel(parcel_3);
    EXPECT_FALSE(ret);
    std::shared_ptr<LauncherAbilityResourceInfo> infoPtr_2(LauncherAbilityResourceInfo::Unmarshalling(parcel_3));
    EXPECT_EQ(infoPtr_2, nullptr);
}

/**
 * @tc.number: BmsBundleResourceTest_0092
 * Function: Install
 * @tc.name: test Install
 * @tc.desc: 1. system running normally
 *           2. test Install
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0092, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        BundleResourceInfo info;
        bool ret = manager->GetBundleResourceInfo(BUNDLE_NAME, 0, info);
        EXPECT_TRUE(ret);
        EXPECT_EQ(info.bundleName, BUNDLE_NAME);
        EXPECT_FALSE(info.label.empty());
        EXPECT_FALSE(info.icon.empty());

        BundleResourceInfo info2;
        ret = manager->GetBundleResourceInfo(BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), info2);
        EXPECT_TRUE(ret);
        EXPECT_EQ(info2.bundleName, BUNDLE_NAME);
        EXPECT_FALSE(info2.label.empty());
        EXPECT_FALSE(info2.icon.empty());

        BundleResourceInfo info3;
        ret = manager->GetBundleResourceInfo(BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), info3);
        EXPECT_TRUE(ret);
        EXPECT_EQ(info3.bundleName, BUNDLE_NAME);
        EXPECT_FALSE(info3.label.empty());
        EXPECT_TRUE(info3.icon.empty());

        BundleResourceInfo info4;
        ret = manager->GetBundleResourceInfo(BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON), info4);
        EXPECT_TRUE(ret);
        EXPECT_EQ(info4.bundleName, BUNDLE_NAME);
        EXPECT_TRUE(info4.label.empty());
        EXPECT_FALSE(info4.icon.empty());
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
    if (manager != nullptr) {
        BundleResourceInfo info;
        bool ret = manager->GetBundleResourceInfo(BUNDLE_NAME, 0, info);
        EXPECT_FALSE(ret);
        EXPECT_TRUE(info.bundleName.empty());
        EXPECT_TRUE(info.label.empty());
        EXPECT_TRUE(info.icon.empty());
    }
}

/**
 * @tc.number: BmsBundleResourceTest_0093
 * Function: Install
 * @tc.name: test Install
 * @tc.desc: 1. system running normally
 *           2. test Install
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0093, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::vector<LauncherAbilityResourceInfo> info;
        bool ret = manager->GetLauncherAbilityResourceInfo(BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), info);
        EXPECT_TRUE(ret);
        EXPECT_TRUE(info.size() == 1);
        if (!info.empty()) {
            EXPECT_EQ(info[0].bundleName, BUNDLE_NAME);
            EXPECT_EQ(info[0].moduleName, MODULE_NAME);
            EXPECT_EQ(info[0].abilityName, ABILITY_NAME);
            EXPECT_FALSE(info[0].label.empty());
            EXPECT_FALSE(info[0].icon.empty());
        }

        std::vector<LauncherAbilityResourceInfo> info2;
        ret = manager->GetLauncherAbilityResourceInfo(BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), info2);
        EXPECT_TRUE(ret);
        EXPECT_TRUE(info.size() == 1);
        if (!info.empty()) {
            EXPECT_EQ(info2[0].bundleName, BUNDLE_NAME);
            EXPECT_EQ(info2[0].moduleName, MODULE_NAME);
            EXPECT_EQ(info2[0].abilityName, ABILITY_NAME);
            EXPECT_FALSE(info2[0].label.empty());
            EXPECT_TRUE(info2[0].icon.empty());
        }

        std::vector<LauncherAbilityResourceInfo> info3;
        ret = manager->GetLauncherAbilityResourceInfo(BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON), info3);
        EXPECT_TRUE(ret);
        EXPECT_TRUE(info.size() == 1);
        if (!info.empty()) {
            EXPECT_EQ(info3[0].bundleName, BUNDLE_NAME);
            EXPECT_EQ(info3[0].moduleName, MODULE_NAME);
            EXPECT_EQ(info3[0].abilityName, ABILITY_NAME);
            EXPECT_TRUE(info3[0].label.empty());
            EXPECT_FALSE(info3[0].icon.empty());
        }
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0094
 * Function: GetBundleResourceInfo
 * @tc.name: test Install
 * @tc.desc: 1. system running normally
 *           2. test GetBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0094, Function | SmallTest | Level0)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto resourceProxy = bundleMgrProxy->GetBundleResourceProxy();
        EXPECT_NE(resourceProxy, nullptr);
        if (resourceProxy != nullptr) {
            BundleResourceInfo info;
            auto ret = resourceProxy->GetBundleResourceInfo("", 0, info);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
            ret = resourceProxy->GetBundleResourceInfo(BUNDLE_NAME, 0, info);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
        }
    }
}

/**
 * @tc.number: BmsBundleResourceTest_0095
 * Function: GetLauncherAbilityResourceInfo
 * @tc.name: test Install
 * @tc.desc: 1. system running normally
 *           2. test GetBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0095, Function | SmallTest | Level0)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto resourceProxy = bundleMgrProxy->GetBundleResourceProxy();
        EXPECT_NE(resourceProxy, nullptr);
        if (resourceProxy != nullptr) {
            std::vector<LauncherAbilityResourceInfo> info;
            auto ret = resourceProxy->GetLauncherAbilityResourceInfo("", 0, info);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
            EXPECT_TRUE(info.size() == 0);

            ret = resourceProxy->GetLauncherAbilityResourceInfo(BUNDLE_NAME, 0, info);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
            EXPECT_TRUE(info.size() == 0);
        }
    }
}

/**
 * @tc.number: BmsBundleResourceTest_0096
 * Function: GetAllBundleResourceInfo
 * @tc.name: test Install
 * @tc.desc: 1. system running normally
 *           2. test GetAllBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0096, Function | SmallTest | Level0)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto resourceProxy = bundleMgrProxy->GetBundleResourceProxy();
        EXPECT_NE(resourceProxy, nullptr);
        if (resourceProxy != nullptr) {
            std::vector<BundleResourceInfo> infos;
            auto ret = resourceProxy->GetAllBundleResourceInfo(0, infos);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
            EXPECT_TRUE(infos.empty());
        }
    }
}

/**
 * @tc.number: BmsBundleResourceTest_0097
 * Function: GetAllLauncherAbilityResourceInfo
 * @tc.name: test Install
 * @tc.desc: 1. system running normally
 *           2. test GetAllLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0097, Function | SmallTest | Level0)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto resourceProxy = bundleMgrProxy->GetBundleResourceProxy();
        EXPECT_NE(resourceProxy, nullptr);
        if (resourceProxy != nullptr) {
            std::vector<LauncherAbilityResourceInfo> infos;
            auto ret = resourceProxy->GetAllLauncherAbilityResourceInfo(0, infos);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
            EXPECT_TRUE(infos.empty());
        }
    }
}

/**
 * @tc.number: BmsBundleResourceTest_0098
 * Function: GetBundleResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0098, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    BundleResourceInfo info;
    auto ret = bundleResourceHostImpl->GetBundleResourceInfo("", 0, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    ret = bundleResourceHostImpl->GetBundleResourceInfo(BUNDLE_NAME, 0, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    ret = bundleResourceHostImpl->GetBundleResourceInfo(BUNDLE_NAME, 0, info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(info.bundleName, BUNDLE_NAME);
    EXPECT_FALSE(info.icon.empty());
    EXPECT_FALSE(info.label.empty());
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0099
 * Function: GetLauncherAbilityResourceInfo
 * @tc.name: test Install
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0099, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    std::vector<LauncherAbilityResourceInfo> info;
    auto ret = bundleResourceHostImpl->GetLauncherAbilityResourceInfo("", 0, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_TRUE(info.size() == 0);

    ret = bundleResourceHostImpl->GetLauncherAbilityResourceInfo(BUNDLE_NAME, 0, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_TRUE(info.size() == 0);

    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    ret = bundleResourceHostImpl->GetLauncherAbilityResourceInfo(BUNDLE_NAME, 0, info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(info.size() == 1);
    if (!info.empty()) {
        EXPECT_EQ(info[0].bundleName, BUNDLE_NAME);
        EXPECT_EQ(info[0].moduleName, MODULE_NAME);
        EXPECT_EQ(info[0].abilityName, ABILITY_NAME);
        EXPECT_FALSE(info[0].label.empty());
        EXPECT_FALSE(info[0].icon.empty());
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0100
 * Function: GetAllBundleResourceInfo
 * @tc.name: test Install
 * @tc.desc: 1. system running normally
 *           2. test GetAllBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_00100, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    std::vector<BundleResourceInfo> infos;
    auto ret = bundleResourceHostImpl->GetAllBundleResourceInfo(0, infos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(infos.empty());
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0101
 * Function: GetAllLauncherAbilityResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetAllLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0101, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    std::vector<LauncherAbilityResourceInfo> infos;
    auto ret = bundleResourceHostImpl->GetAllLauncherAbilityResourceInfo(0, infos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(infos.empty());
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0102
 * Function: GetBundleResourceInfo
 * @tc.name: test disable and enable
 * @tc.desc: 1. system running normally
 *           2. test GetBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0102, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    BundleResourceInfo info;
    auto ret = bundleResourceHostImpl->GetBundleResourceInfo(BUNDLE_NAME, 0, info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(info.bundleName, BUNDLE_NAME);
    EXPECT_FALSE(info.icon.empty());
    EXPECT_FALSE(info.label.empty());

    // disable
    BundleResourceHelper::SetApplicationEnabled(BUNDLE_NAME, false, USERID);
    auto code = GetBundleDataMgr()->SetApplicationEnabled(BUNDLE_NAME, false, USERID);
    EXPECT_EQ(code, ERR_OK);
    ret = bundleResourceHostImpl->GetBundleResourceInfo(BUNDLE_NAME, 0, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    // enable
    BundleResourceHelper::SetApplicationEnabled(BUNDLE_NAME, true, USERID);
    code = GetBundleDataMgr()->SetApplicationEnabled(BUNDLE_NAME, true, USERID);
    EXPECT_EQ(code, ERR_OK);
    ret = bundleResourceHostImpl->GetBundleResourceInfo(BUNDLE_NAME, 0, info);
    EXPECT_EQ(ret, ERR_OK);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0103
 * Function: GetBundleResourceInfo
 * @tc.name: test disable and enable
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0103, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    std::vector<LauncherAbilityResourceInfo> info;
    auto ret = bundleResourceHostImpl->GetLauncherAbilityResourceInfo(BUNDLE_NAME, 0, info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(info.size() == 1);

    AbilityInfo abilityInfo;
    abilityInfo.bundleName = BUNDLE_NAME;
    abilityInfo.moduleName = MODULE_NAME;
    abilityInfo.name = ABILITY_NAME;
    // disable
    BundleResourceHelper::SetAbilityEnabled(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME, false, USERID);
    auto code = GetBundleDataMgr()->SetAbilityEnabled(abilityInfo, false, USERID);
    EXPECT_EQ(code, ERR_OK);
    ret = bundleResourceHostImpl->GetLauncherAbilityResourceInfo(BUNDLE_NAME, 0, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    // enable
    BundleResourceHelper::SetAbilityEnabled(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME, true, USERID);
    code = GetBundleDataMgr()->SetAbilityEnabled(abilityInfo, true, USERID);
    EXPECT_EQ(code, ERR_OK);
    ret = bundleResourceHostImpl->GetLauncherAbilityResourceInfo(BUNDLE_NAME, 0, info);
    EXPECT_EQ(ret, ERR_OK);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0104
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfoByColorModeChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0104, Function | SmallTest | Level0)
{
    std::string oldColorMode = BundleSystemState::GetInstance().GetSystemColorMode();
    std::string colorMode = "dark";
    BundleSystemState::GetInstance().SetSystemColorMode(colorMode);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    bool ans = manager->AddResourceInfoByColorModeChanged(200);
    EXPECT_FALSE(ans);

    ans = manager->AddResourceInfoByColorModeChanged(USERID);
    EXPECT_TRUE(ans);

    BundleSystemState::GetInstance().SetSystemColorMode(oldColorMode);
    ans = manager->AddResourceInfoByColorModeChanged(USERID);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: ProcessBundleResourceInfo_0001
 * @tc.name: test the start function of ProcessBundleResourceInfo
 * @tc.desc: 1. test ProcessBundleResourceInfo
 *           2. all bundleName exist
 */
HWTEST_F(BmsBundleResourceTest, ProcessBundleResourceInfo_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        BundleResourceInfo info;
        bool ans = manager->GetBundleResourceInfo(BUNDLE_NAME, 0, info);
        EXPECT_TRUE(ans);
        ans = manager->DeleteResourceInfo(BUNDLE_NAME);
        EXPECT_TRUE(ans);
    }
    if ((handler != nullptr) && (manager != nullptr)) {
        handler->ProcessBundleResourceInfo();
        BundleResourceInfo info2;
        bool ans = manager->GetBundleResourceInfo(BUNDLE_NAME, 0, info2);
        EXPECT_TRUE(ans);
        EXPECT_EQ(info2.bundleName, BUNDLE_NAME);
        EXPECT_FALSE(info2.icon.empty());
        EXPECT_FALSE(info2.label.empty());
    }
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}
#endif
} // OHOS
