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
#include "bundle_resource_change_type.h"
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
#include "nlohmann/json.hpp"
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
// test layered image
const std::string BUNDLE_NAME_LAYERED_IMAGE = "com.example.thumbnailtest";
const std::string LAYERED_IMAGE_HAP_PATH = "/data/test/resource/bms/accesstoken_bundle/thumbnail.hap";
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
    resourceInfo.label_ = "xxx";
    resourceInfo.foreground_.push_back(1);

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
    bool ans = manager->AddAllResourceInfo(200,
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_USER_ID_CHANGE));
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
    resourceInfo.foreground_.push_back(1);
    resourceInfo.label_ = "xxxx";
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
 * @tc.number: BmsBundleResourceTest_0024
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetAllResourceName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0024, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.icon_ = "data:image/xxxx";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    std::vector<std::string> keyNames;
    ans = manager->GetAllResourceName(keyNames);
    EXPECT_TRUE(ans);
    EXPECT_TRUE(std::find(keyNames.begin(), keyNames.end(), resourceInfo.GetKey()) == keyNames.end());
    // delete key
    ans = manager->DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0025
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetAllResourceName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0025, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.icon_ = "data:image/png";
    resourceInfo.foreground_.push_back(1);
    resourceInfo.label_ = "$string";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    std::vector<std::string> keyNames;
    ans = manager->GetAllResourceName(keyNames);
    EXPECT_TRUE(ans);
    EXPECT_TRUE(std::find(keyNames.begin(), keyNames.end(), resourceInfo.GetKey()) == keyNames.end());
    // delete key
    ans = manager->DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0026
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetAllResourceName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0026, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.icon_ = "data:image/png";
    resourceInfo.foreground_.push_back(1);
    resourceInfo.label_ = "bundleName";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    std::vector<std::string> keyNames;
    ans = manager->GetAllResourceName(keyNames);
    EXPECT_TRUE(ans);
    EXPECT_TRUE(std::find(keyNames.begin(), keyNames.end(), resourceInfo.GetKey()) == keyNames.end());
    // delete key
    ans = manager->DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0027
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetAllResourceName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0027, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.icon_ = "data:image/png";
    resourceInfo.foreground_.push_back(1);
    resourceInfo.label_ = "";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    std::vector<std::string> keyNames;
    ans = manager->GetAllResourceName(keyNames);
    EXPECT_TRUE(ans);
    EXPECT_TRUE(std::find(keyNames.begin(), keyNames.end(), resourceInfo.GetKey()) == keyNames.end());
    // delete key
    ans = manager->DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}


/**
 * @tc.number: BmsBundleResourceTest_0028
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetAllResourceName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0028, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName/moduleName/abilityName";
    resourceInfo.icon_ = "data:image/png";
    resourceInfo.foreground_.push_back(1);
    resourceInfo.label_ = "xxxx";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    std::vector<std::string> keyNames;
    ans = manager->GetAllResourceName(keyNames);
    EXPECT_TRUE(ans);
    EXPECT_TRUE(std::find(keyNames.begin(), keyNames.end(), resourceInfo.GetKey()) == keyNames.end());
    // delete key
    ans = manager->DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0029
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetAllResourceName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0029, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName/moduleName/abilityName";
    resourceInfo.icon_ = "";
    resourceInfo.label_ = "xxxx";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    std::vector<std::string> keyNames;
    ans = manager->GetAllResourceName(keyNames);
    EXPECT_TRUE(ans);
    EXPECT_TRUE(std::find(keyNames.begin(), keyNames.end(), resourceInfo.GetKey()) == keyNames.end());
    // delete key
    ans = manager->DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0050
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfos
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0050, Function | SmallTest | Level0)
{
    InnerBundleInfo bundleInfo;
    std::vector<ResourceInfo> resourceInfos;
    // bundleName empty
    bool ans = BundleResourceProcess::GetLauncherAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.bundleType = BundleType::SHARED;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    // bundle type is shared
    ans = BundleResourceProcess::GetLauncherAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    applicationInfo.bundleType = BundleType::APP;
    applicationInfo.hideDesktopIcon = true;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    // hideDesktopIcon is true
    ans = BundleResourceProcess::GetLauncherAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    applicationInfo.hideDesktopIcon = false;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo info;
    info.entryInstallationFree = true;
    bundleInfo.SetBaseBundleInfo(info);
    // entryInstallationFree is true
    ans = BundleResourceProcess::GetLauncherAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    info.entryInstallationFree = false;
    bundleInfo.SetBaseBundleInfo(info);
    // abilityInfos is empty
    ans = BundleResourceProcess::GetLauncherAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
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
 *           2. test GetLauncherResourceInfoByAbilityName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0055, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    // bundle not exist
    bool ans = BundleResourceProcess::GetLauncherResourceInfoByAbilityName(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME,
        USERID, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");

    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    // userId not exist
    ans = BundleResourceProcess::GetLauncherResourceInfoByAbilityName(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME,
        200, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");

    // bundle exist, moduleName or abilityName not exist
    ans = BundleResourceProcess::GetLauncherResourceInfoByAbilityName(BUNDLE_NAME, "xxx", "yyy", USERID, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");

    // bundle  moduleName exist, abilityName not exist
    ans = BundleResourceProcess::GetLauncherResourceInfoByAbilityName(BUNDLE_NAME, MODULE_NAME, "yyy",
        USERID, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");

    // bundle  moduleName exist, abilityName exist
    ans = BundleResourceProcess::GetLauncherResourceInfoByAbilityName(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME,
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
 * @tc.number: BmsBundleResourceTest_0057
 * Function: ProcessResourceInfoWhenParseFailed
 * @tc.name: test ProcessResourceInfoWhenParseFailed
 * @tc.desc: 1. system running normally
 *           2. test ProcessResourceInfoWhenParseFailed
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0057, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        ResourceInfo info;
        info.bundleName_ = "bundleName";
        info.label_ = "label";
        info.icon_ = "icon";
        manager->ProcessResourceInfoWhenParseFailed(info);
        EXPECT_NE(info.label_, info.bundleName_);

        info.label_ = "";
        info.icon_ = "";
        manager->ProcessResourceInfoWhenParseFailed(info);
        EXPECT_EQ(info.label_, info.bundleName_);
        EXPECT_FALSE(info.icon_.empty());

        info.bundleName_ = "ohos.global.systemres";
        info.label_ = "";
        info.icon_ = "";
        manager->ProcessResourceInfoWhenParseFailed(info);
        EXPECT_EQ(info.label_, info.bundleName_);
        EXPECT_TRUE(info.icon_.empty());
    }
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

    std::vector<std::string> overlayHaps;
    ans = BundleResourceConfiguration::InitResourceGlobalConfig(HAP_FILE_PATH1, overlayHaps, resourceManager);
    EXPECT_TRUE(ans);

    overlayHaps.emplace_back(HAP_FILE_PATH1);
    ans = BundleResourceConfiguration::InitResourceGlobalConfig(HAP_FILE_PATH1, overlayHaps, resourceManager);
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
    bool ans = parser.ParseResourceInfo(USERID, resourceInfo);
    EXPECT_FALSE(ans);

    resourceInfo.hapPath_ = HAP_FILE_PATH1;
    ans = parser.ParseResourceInfo(USERID, resourceInfo);
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
    bool ans = parser.ParseResourceInfos(USERID, resourceInfos);
    EXPECT_FALSE(ans);

    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = BUNDLE_NAME;
    resourceInfo.label_ = BUNDLE_NAME;
    resourceInfo.labelId_ = 0;
    resourceInfo.iconId_ = 0;
    resourceInfos.push_back(resourceInfo);

    ans = parser.ParseResourceInfos(USERID, resourceInfos);
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
    EXPECT_FALSE(ans);

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
    ResourceInfo info;
    BundleResourceParser parser;
    bool ans = parser.ParseIconResourceByPath("", 0, info);
    EXPECT_FALSE(ans);

    ans = parser.ParseIconResourceByPath(HAP_NOT_EXIST, 0, info);
    EXPECT_FALSE(ans);

    ans = parser.ParseIconResourceByPath(HAP_FILE_PATH1, 0, info);
    EXPECT_FALSE(ans);

    ans = parser.ParseIconResourceByPath(HAP_FILE_PATH1, 1, info); // iconId not exist
    EXPECT_FALSE(ans);
    EXPECT_EQ(info.icon_, "");
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
    ResourceInfo info;
    info.iconId_ = 0;
    BundleResourceParser parser;
    bool ans = parser.ParseIconResourceByResourceManager(nullptr, info);
    EXPECT_FALSE(ans);

    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    ans = parser.ParseIconResourceByResourceManager(resourceManager, info);
    EXPECT_FALSE(ans);

    info.iconId_ = 1;
    ans = parser.ParseIconResourceByResourceManager(resourceManager, info); // iconId not exist
    EXPECT_FALSE(ans);
    EXPECT_EQ(info.icon_, "");
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

        ResourceInfo info;
        ans = parser.ParseIconResourceByPath(resourceInfos[0].hapPath_, resourceInfos[0].iconId_, info);
        EXPECT_TRUE(ans);
        EXPECT_FALSE(info.icon_.empty());
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
        ans = parser.ParseResourceInfo(USERID, resourceInfos[0]);
        EXPECT_TRUE(ans);
        EXPECT_NE(resourceInfos[0].label_, "");
        EXPECT_NE(resourceInfos[0].icon_, "");

        ans = parser.ParseResourceInfos(USERID, resourceInfos);
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
    EXPECT_FALSE(resourceInfos.empty());

    if (!resourceInfos.empty()) {
        ResourceInfo resourceInfo;
        BundleResourceParser parser;
        ans = parser.ParseResourceInfo(USERID, resourceInfos[0]); // labelId and iconId = 0
        EXPECT_FALSE(ans);
        EXPECT_EQ(resourceInfos[0].label_, "");
        EXPECT_EQ(resourceInfos[0].icon_, "");

        ans = parser.ParseResourceInfos(USERID, resourceInfos);
        EXPECT_FALSE(ans);
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
    bool ans = callback.OnUserIdSwitched(100, 200);
    EXPECT_FALSE(ans);

    ans = callback.OnUserIdSwitched(200, 100);
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
 * @tc.number: BmsBundleResourceTest_0080
 * Function: GetAbilityResourceInfos
 * @tc.name: test GetAbilityResourceInfos
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0080, Function | SmallTest | Level0)
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
    ans = BundleResourceProcess::GetAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    applicationInfo.bundleType = BundleType::APP;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    ans = BundleResourceProcess::GetAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());
}

/**
 * @tc.number: BmsBundleResourceTest_0081
 * Function: GetAbilityResourceInfos
 * @tc.name: test GetAbilityResourceInfos
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0081, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    InnerBundleInfo bundleInfo;
    bool ans = GetBundleDataMgr()->FetchInnerBundleInfo(BUNDLE_NAME, bundleInfo);
    EXPECT_TRUE(ans);
    bundleInfo.SetOverlayType(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    std::vector<ResourceInfo> resourceInfos;
    ans = BundleResourceProcess::GetAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(resourceInfos.empty());

    auto code = bundleInfo.SetAbilityEnabled(MODULE_NAME, ABILITY_NAME, false, USERID);
    EXPECT_EQ(code, ERR_OK);

    std::vector<ResourceInfo> resourceInfos_2;
    ans = BundleResourceProcess::GetAbilityResourceInfos(bundleInfo, USERID, resourceInfos_2);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos_2.empty());

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
    bool ans = BundleResourceProcess::GetResourceInfoByColorModeChanged(resourceNames, USERID, resourceInfos);
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
    bool ans = BundleResourceProcess::GetResourceInfoByColorModeChanged(resourceNames, USERID, resourceInfos);
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
    info.appIndex = 1;

    Parcel parcel;
    bool ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);

    BundleResourceInfo info_2;
    ret = info_2.ReadFromParcel(parcel);
    EXPECT_EQ(info_2.bundleName, info.bundleName);
    EXPECT_EQ(info_2.label, info.label);
    EXPECT_EQ(info_2.icon, info.icon);
    EXPECT_EQ(info_2.appIndex, info.appIndex);

    Parcel parcel_2;
    ret = info.Marshalling(parcel_2);
    EXPECT_TRUE(ret);
    std::shared_ptr<BundleResourceInfo> infoPtr(BundleResourceInfo::Unmarshalling(parcel_2));
    EXPECT_NE(infoPtr, nullptr);
    if (infoPtr != nullptr) {
        EXPECT_EQ(infoPtr->bundleName, info.bundleName);
        EXPECT_EQ(infoPtr->label, info.label);
        EXPECT_EQ(infoPtr->icon, info.icon);
        EXPECT_EQ(infoPtr->appIndex, info.appIndex);
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
    info.appIndex = 1;

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
    EXPECT_EQ(info_2.appIndex, info.appIndex);

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
        EXPECT_EQ(infoPtr->appIndex, info.appIndex);
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

    ret = bundleResourceHostImpl->GetBundleResourceInfo(BUNDLE_NAME, 0, info, -1);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX);

    ret = bundleResourceHostImpl->GetBundleResourceInfo(BUNDLE_NAME, 0, info, 1);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    ret = bundleResourceHostImpl->GetBundleResourceInfo(BUNDLE_NAME, 0, info, 100);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX);

    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    ret = bundleResourceHostImpl->GetBundleResourceInfo(BUNDLE_NAME, 0, info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(info.bundleName, BUNDLE_NAME);
    EXPECT_FALSE(info.icon.empty());
    EXPECT_FALSE(info.label.empty());

    ret = bundleResourceHostImpl->GetBundleResourceInfo(BUNDLE_NAME, 0, info, 1);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX);
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

    ret = bundleResourceHostImpl->GetLauncherAbilityResourceInfo(BUNDLE_NAME, 0, info, -1);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX);
    EXPECT_TRUE(info.size() == 0);

    ret = bundleResourceHostImpl->GetLauncherAbilityResourceInfo(BUNDLE_NAME, 0, info, 1);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_TRUE(info.size() == 0);

    ret = bundleResourceHostImpl->GetLauncherAbilityResourceInfo(BUNDLE_NAME, 0, info, 100);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX);
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

    ret = bundleResourceHostImpl->GetLauncherAbilityResourceInfo(BUNDLE_NAME, 0, info, 1);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX);

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
    auto code = GetBundleDataMgr()->SetApplicationEnabled(BUNDLE_NAME, 0, false, USERID);
    EXPECT_EQ(code, ERR_OK);
    ret = bundleResourceHostImpl->GetBundleResourceInfo(BUNDLE_NAME, 0, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    // enable
    BundleResourceHelper::SetApplicationEnabled(BUNDLE_NAME, true, USERID);
    code = GetBundleDataMgr()->SetApplicationEnabled(BUNDLE_NAME, 0, true, USERID);
    EXPECT_EQ(code, ERR_OK);

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
    auto code = GetBundleDataMgr()->SetAbilityEnabled(abilityInfo, 0, false, USERID);
    EXPECT_EQ(code, ERR_OK);
    ret = bundleResourceHostImpl->GetLauncherAbilityResourceInfo(BUNDLE_NAME, 0, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    // enable
    BundleResourceHelper::SetAbilityEnabled(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME, true, USERID);
    code = GetBundleDataMgr()->SetAbilityEnabled(abilityInfo, 0, true, USERID);
    EXPECT_EQ(code, ERR_OK);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
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

/**
 * @tc.number: ProcessResourceInfo_0001
 * @tc.name: test the start function of ProcessResourceInfo
 * @tc.desc: 1. test ProcessResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, ProcessResourceInfo_0001, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::vector<ResourceInfo> resourceInfos;
        ResourceInfo info;
        info.label_ = "xxx";
        info.icon_ = "yyy";
        manager->ProcessResourceInfo(resourceInfos, info);
        EXPECT_FALSE(info.label_.empty());
        EXPECT_FALSE(info.icon_.empty());

        info.label_ = "";
        info.icon_ = "";
        info.bundleName_ = "aaa";
        manager->ProcessResourceInfo(resourceInfos, info);
        EXPECT_FALSE(info.label_.empty());
        EXPECT_FALSE(info.icon_.empty());

        resourceInfos.emplace_back(info);
        info.icon_ = "";
        manager->ProcessResourceInfo(resourceInfos, info);
        EXPECT_FALSE(info.label_.empty());
        EXPECT_FALSE(info.icon_.empty());
    }
}

/**
 * @tc.number: AddResourceInfos_0001
 * @tc.name: test the start function of AddResourceInfos
 * @tc.desc: 1. test AddResourceInfos
 */
HWTEST_F(BmsBundleResourceTest, AddResourceInfos_0001, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_NO_ICON);
    EXPECT_EQ(installResult, ERR_OK);

    std::vector<ResourceInfo> resourceInfos;
    bool ans = BundleResourceProcess::GetResourceInfoByBundleName(BUNDLE_NAME_NO_ICON, USERID, resourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(resourceInfos.empty());

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::map<std::string, std::vector<ResourceInfo>> resourceInfosMap;
        bool ret = manager->AddResourceInfosByMap(resourceInfosMap, 0, 0, USERID, USERID);
        EXPECT_FALSE(ret);
        resourceInfosMap[BUNDLE_NAME_NO_ICON] = resourceInfos;
        ret = manager->AddResourceInfosByMap(resourceInfosMap, manager->currentTaskNum_,
            static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE), USERID, USERID);
        EXPECT_TRUE(ret);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_NO_ICON);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0105
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0105, Function | SmallTest | Level0)
{
    InnerBundleInfo bundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    bundleInfo.SetOverlayType(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    ResourceInfo resourceInfo;
    bool ans = BundleResourceProcess::GetBundleResourceInfo(bundleInfo, USERID, resourceInfo);
    EXPECT_TRUE(ans);
    EXPECT_NE(resourceInfo.GetKey(), "");
}

/**
 * @tc.number: BmsBundleResourceTest_0106
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfos
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0106, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    InnerBundleInfo bundleInfo;
    bool ans = GetBundleDataMgr()->FetchInnerBundleInfo(BUNDLE_NAME, bundleInfo);
    EXPECT_TRUE(ans);
    bundleInfo.SetOverlayType(OverlayType::OVERLAY_INTERNAL_BUNDLE);

    std::vector<ResourceInfo> resourceInfos;
    ans = BundleResourceProcess::GetLauncherAbilityResourceInfos(bundleInfo, USERID, resourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(resourceInfos.empty());

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0107
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test CheckIsNeedProcessAbilityResource
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0107, Function | SmallTest | Level0)
{
    InnerBundleInfo bundleInfo;
    bool ans = BundleResourceProcess::CheckIsNeedProcessAbilityResource(bundleInfo);
    EXPECT_FALSE(ans);
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.bundleType = BundleType::SHARED;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    ans = BundleResourceProcess::CheckIsNeedProcessAbilityResource(bundleInfo);
    EXPECT_FALSE(ans);

    applicationInfo.bundleType = BundleType::APP;
    applicationInfo.hideDesktopIcon = true;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    ans = BundleResourceProcess::CheckIsNeedProcessAbilityResource(bundleInfo);
    EXPECT_FALSE(ans);

    applicationInfo.hideDesktopIcon = false;
    bundleInfo.SetBaseApplicationInfo(applicationInfo);
    ans = BundleResourceProcess::CheckIsNeedProcessAbilityResource(bundleInfo);
    EXPECT_TRUE(ans);

    BundleInfo info;
    info.entryInstallationFree = true;
    bundleInfo.SetBaseBundleInfo(info);
    ans = BundleResourceProcess::CheckIsNeedProcessAbilityResource(bundleInfo);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0108
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetOverlayModuleHapPaths
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0108, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    std::vector<std::string> overlayHapPaths;
    bool ans = BundleResourceProcess::GetOverlayModuleHapPaths(info, MODULE_NAME, USERID, overlayHapPaths);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0109
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test OnOverlayStatusChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0109, Function | SmallTest | Level0)
{
    BundleResourceCallback callback;
    bool ans = callback.OnOverlayStatusChanged(BUNDLE_NAME_NOT_EXIST, true, 0);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0110
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test OnOverlayStatusChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0110, Function | SmallTest | Level0)
{
    BundleResourceCallback callback;
    bool ans = callback.OnOverlayStatusChanged(BUNDLE_NAME_NOT_EXIST, true, USERID);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0111
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test OnOverlayStatusChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0111, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    BundleResourceCallback callback;
    bool ans = callback.OnOverlayStatusChanged(BUNDLE_NAME, true, USERID);
    EXPECT_TRUE(ans);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0112
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test OnApplicationThemeChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0112, Function | SmallTest | Level0)
{
    BundleResourceCallback callback;
    bool ans = callback.OnApplicationThemeChanged("");
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0113
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test OnApplicationThemeChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0113, Function | SmallTest | Level0)
{
    BundleResourceCallback callback;
    bool ans = callback.OnApplicationThemeChanged("xxxxx");
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0114
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test OnApplicationThemeChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0114, Function | SmallTest | Level0)
{
    BundleResourceCallback callback;
    nlohmann::json theme = R"(
        {
            "icons": 0,
            "skin": 0,
            "font": 0
        }
    )"_json;
    bool ans = callback.OnApplicationThemeChanged(theme.dump());
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0115
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test OnApplicationThemeChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0115, Function | SmallTest | Level0)
{
    BundleResourceCallback callback;
    nlohmann::json theme = R"(
        {
            "icons": 1,
            "skin": 0,
            "font": 0
        }
    )"_json;
    bool ans = callback.OnApplicationThemeChanged(theme.dump());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0116
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test OnApplicationThemeChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0116, Function | SmallTest | Level0)
{
    BundleResourceCallback callback;
    nlohmann::json theme = R"(
        {
            "icons": 1,
            "skin": 1,
            "font": 1
        }
    )"_json;
    bool ans = callback.OnApplicationThemeChanged(theme.dump());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0117
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetOverlayModuleHapPaths
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0117, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);

    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    info.SetBaseApplicationInfo(applicationInfo);

    InnerModuleInfo moduleInfo;
    moduleInfo.name = MODULE_NAME;
    moduleInfo.moduleName = MODULE_NAME;
    moduleInfo.modulePackage = MODULE_NAME;
    std::map<std::string, InnerModuleInfo> moduleInfos;
    moduleInfos[MODULE_NAME] = moduleInfo;
    info.AddInnerModuleInfo(moduleInfos);
    std::vector<std::string> overlayHapPaths;
    // overlay moduleInfo is empty
    bool ans = BundleResourceProcess::GetOverlayModuleHapPaths(info, MODULE_NAME, USERID, overlayHapPaths);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(overlayHapPaths.empty());
}

/**
 * @tc.number: BmsBundleResourceTest_0118
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetOverlayModuleHapPaths
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0118, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);

    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    info.SetBaseApplicationInfo(applicationInfo);

    InnerModuleInfo moduleInfo;
    moduleInfo.name = MODULE_NAME;
    moduleInfo.moduleName = MODULE_NAME;
    moduleInfo.modulePackage = MODULE_NAME;
    OverlayModuleInfo overlayModuleInfo;
    overlayModuleInfo.bundleName = BUNDLE_NAME;
    overlayModuleInfo.moduleName = "1_overlay";
    overlayModuleInfo.targetModuleName = MODULE_NAME;
    overlayModuleInfo.hapPath = "hapPath";
    overlayModuleInfo.priority = 1;

    OverlayModuleInfo overlayModuleInfo_2;
    overlayModuleInfo_2.bundleName = BUNDLE_NAME;
    overlayModuleInfo_2.moduleName = "2_overlay";
    overlayModuleInfo_2.targetModuleName = MODULE_NAME;
    overlayModuleInfo_2.hapPath = "hapPath2";
    overlayModuleInfo_2.priority = 2;

    moduleInfo.overlayModuleInfo.push_back(overlayModuleInfo);
    moduleInfo.overlayModuleInfo.push_back(overlayModuleInfo_2);
    std::map<std::string, InnerModuleInfo> moduleInfos;
    moduleInfos[MODULE_NAME] = moduleInfo;
    info.AddInnerModuleInfo(moduleInfos);
    std::vector<std::string> overlayHapPaths;
    // overlay state is empty
    bool ans = BundleResourceProcess::GetOverlayModuleHapPaths(info, MODULE_NAME, USERID, overlayHapPaths);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(overlayHapPaths.empty());

    InnerBundleUserInfo innerUserInfo;
    innerUserInfo.bundleUserInfo.userId = USERID;
    innerUserInfo.bundleUserInfo.overlayModulesState.push_back("1_overlay_1");
    innerUserInfo.bundleUserInfo.overlayModulesState.push_back("2_overlay_2");
    innerUserInfo.bundleName = BUNDLE_NAME;

    info.AddInnerBundleUserInfo(innerUserInfo);
    ans = BundleResourceProcess::GetOverlayModuleHapPaths(info, MODULE_NAME, USERID, overlayHapPaths);
    EXPECT_TRUE(ans);
    EXPECT_EQ(overlayHapPaths.size(), 1);
}

/**
 * @tc.number: BmsBundleResourceTest_0119
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0119, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";
    resourceInfo.foreground_.emplace_back(1);
    resourceInfo.background_.emplace_back(2);
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    BundleResourceInfo info;
    ans = resourceRdb.GetBundleResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR), info);
    EXPECT_TRUE(ans);
    EXPECT_EQ(info.bundleName, resourceInfo.bundleName_);
    EXPECT_TRUE(info.icon.empty());
    EXPECT_TRUE(info.label.empty());
    EXPECT_FALSE(info.foreground.empty());
    if (!info.foreground.empty()) {
        EXPECT_EQ(info.foreground[0], resourceInfo.foreground_[0]);
    }
    EXPECT_FALSE(info.background.empty());
    if (!info.background.empty()) {
        EXPECT_EQ(info.background[0], resourceInfo.background_[0]);
    }
    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0120
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0120, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";
    resourceInfo.foreground_.emplace_back(1);
    resourceInfo.background_.emplace_back(2);
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    BundleResourceInfo info;
    ans = resourceRdb.GetBundleResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR),
        info);
    EXPECT_TRUE(ans);
    EXPECT_EQ(info.bundleName, resourceInfo.bundleName_);
    EXPECT_EQ(info.icon, resourceInfo.icon_);
    EXPECT_EQ(info.label, resourceInfo.label_);
    EXPECT_FALSE(info.foreground.empty());
    if (!info.foreground.empty()) {
        EXPECT_EQ(info.foreground[0], resourceInfo.foreground_[0]);
    }
    EXPECT_FALSE(info.background.empty());
    if (!info.background.empty()) {
        EXPECT_EQ(info.background[0], resourceInfo.background_[0]);
    }
    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0121
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0121, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.abilityName_ = "abilityName";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";
    resourceInfo.foreground_.emplace_back(1);
    resourceInfo.background_.emplace_back(2);
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    std::vector<LauncherAbilityResourceInfo> infos;
    ans = resourceRdb.GetLauncherAbilityResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR), infos);
    EXPECT_TRUE(ans);
    EXPECT_TRUE(infos.size() == 1);
    if (!infos.empty()) {
        EXPECT_EQ(infos[0].bundleName, resourceInfo.bundleName_);
        EXPECT_EQ(infos[0].moduleName, resourceInfo.moduleName_);
        EXPECT_EQ(infos[0].abilityName, resourceInfo.abilityName_);
        EXPECT_TRUE(infos[0].icon.empty());
        EXPECT_TRUE(infos[0].label.empty());

        EXPECT_FALSE(infos[0].foreground.empty());
        if (!infos[0].foreground.empty()) {
            EXPECT_EQ(infos[0].foreground[0], resourceInfo.foreground_[0]);
        }
        EXPECT_FALSE(infos[0].background.empty());
        if (!infos[0].background.empty()) {
            EXPECT_EQ(infos[0].background[0], resourceInfo.background_[0]);
        }
    }
    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0122
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0122, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.abilityName_ = "abilityName";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";
    resourceInfo.foreground_.emplace_back(1);
    resourceInfo.background_.emplace_back(2);
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    std::vector<LauncherAbilityResourceInfo> infos;
    ans = resourceRdb.GetLauncherAbilityResourceInfo(resourceInfo.bundleName_,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR), infos);
    EXPECT_TRUE(ans);
    EXPECT_TRUE(infos.size() == 1);
    if (!infos.empty()) {
        EXPECT_EQ(infos[0].bundleName, resourceInfo.bundleName_);
        EXPECT_EQ(infos[0].moduleName, resourceInfo.moduleName_);
        EXPECT_EQ(infos[0].abilityName, resourceInfo.abilityName_);
        EXPECT_EQ(infos[0].icon, resourceInfo.icon_);
        EXPECT_EQ(infos[0].label, resourceInfo.label_);

        EXPECT_FALSE(infos[0].foreground.empty());
        if (!infos[0].foreground.empty()) {
            EXPECT_EQ(infos[0].foreground[0], resourceInfo.foreground_[0]);
        }
        EXPECT_FALSE(infos[0].background.empty());
        if (!infos[0].background.empty()) {
            EXPECT_EQ(infos[0].background[0], resourceInfo.background_[0]);
        }
    }
    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0123
 * Function: GetBundleResourceInfo
 * @tc.name: test disable and enable
 * @tc.desc: 1. system running normally
 *           2. test ParseThemeIcon
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0123, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    BundleResourceParser parser;
    bool ans = parser.ParseThemeIcon(nullptr, 0, resourceInfo);
    EXPECT_FALSE(ans);

    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    ans = parser.ParseThemeIcon(nullptr, 0, resourceInfo);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0124
 * Function: GetBundleResourceInfo
 * @tc.name: test disable and enable
 * @tc.desc: 1. system running normally
 *           2. test ParseIconIdFromJson
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0124, Function | SmallTest | Level0)
{
    nlohmann::json layeredImagedJson = R"(
        {
            "layered-image" : {
                "background" : "$media:1",
                "foreground" : "$media:2"
            }
        }
    )"_json;

    std::string jsonBuff(layeredImagedJson.dump());
    uint32_t foregroundId = 0;
    uint32_t backgroundId = 0;
    BundleResourceParser parser;
    bool ans = parser.ParseIconIdFromJson(jsonBuff, foregroundId, backgroundId);
    EXPECT_TRUE(ans);
    EXPECT_EQ(foregroundId, 2);
    EXPECT_EQ(backgroundId, 1);
}

/**
 * @tc.number: BmsBundleResourceTest_0125
 * Function: GetBundleResourceInfo
 * @tc.name: test disable and enable
 * @tc.desc: 1. system running normally
 *           2. test ParseIconIdFromJson
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0125, Function | SmallTest | Level0)
{
    // error format
    nlohmann::json layeredImagedJson = R"(
        {}
    )"_json;

    std::string jsonBuff(layeredImagedJson.dump());
    uint32_t foregroundId = 0;
    uint32_t backgroundId = 0;
    BundleResourceParser parser;
    bool ans = parser.ParseIconIdFromJson(jsonBuff, foregroundId, backgroundId);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0126
 * Function: GetBundleResourceInfo
 * @tc.name: test disable and enable
 * @tc.desc: 1. system running normally
 *           2. test ParseIconIdFromJson
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0126, Function | SmallTest | Level0)
{
    // error format
    nlohmann::json layeredImagedJson = R"(
        {
            "error-key" : {
                "background" : "$media:1",
                "foreground" : "$media:2"
            }
        }
    )"_json;

    std::string jsonBuff(layeredImagedJson.dump());
    uint32_t foregroundId = 0;
    uint32_t backgroundId = 0;
    BundleResourceParser parser;
    bool ans = parser.ParseIconIdFromJson(jsonBuff, foregroundId, backgroundId);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0127
 * Function: GetBundleResourceInfo
 * @tc.name: test disable and enable
 * @tc.desc: 1. system running normally
 *           2. test ParseIconIdFromJson
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0127, Function | SmallTest | Level0)
{
    // error format
    nlohmann::json layeredImagedJson = R"(
        {
            "layered-image" : {
                "background" : "",
                "foreground" : ""
            }
        }
    )"_json;

    std::string jsonBuff(layeredImagedJson.dump());
    uint32_t foregroundId = 0;
    uint32_t backgroundId = 0;
    BundleResourceParser parser;
    bool ans = parser.ParseIconIdFromJson(jsonBuff, foregroundId, backgroundId);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0128
 * Function: GetBundleResourceInfo
 * @tc.name: test disable and enable
 * @tc.desc: 1. system running normally
 *           2. test ParseIconIdFromJson
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0128, Function | SmallTest | Level0)
{
    nlohmann::json layeredImagedJson = R"(
        {
            "layered-image" : {
                "background" : "$media",
                "foreground" : "$media"
            }
        }
    )"_json;

    std::string jsonBuff(layeredImagedJson.dump());
    uint32_t foregroundId = 0;
    uint32_t backgroundId = 0;
    BundleResourceParser parser;
    bool ans = parser.ParseIconIdFromJson(jsonBuff, foregroundId, backgroundId);
    EXPECT_TRUE(ans);
    EXPECT_EQ(foregroundId, 0);
    EXPECT_EQ(backgroundId, 0);
}

/**
 * @tc.number: BmsBundleResourceTest_0129
 * Function: GetBundleResourceInfo
 * @tc.name: test disable and enable
 * @tc.desc: 1. system running normally
 *           2. test ParseForegroundAndBackgroundResource
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0129, Function | SmallTest | Level0)
{
    // error format
    nlohmann::json layeredImagedJson_1 = R"(
        {
            "layered-image" : {
                "background" : "$media:1",
                "foreground" : "$media:2"
            }
        }
    )"_json;
    std::string jsonBuff(layeredImagedJson_1.dump());
    ResourceInfo resourceInfo;
    BundleResourceParser parser;
    bool ans = parser.ParseForegroundAndBackgroundResource(nullptr, jsonBuff, 0, resourceInfo);
    EXPECT_FALSE(ans);

    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    ans = parser.ParseForegroundAndBackgroundResource(resourceManager, jsonBuff, 0, resourceInfo);
    EXPECT_FALSE(ans);

    nlohmann::json layeredImagedJson_2 = R"(
        {
            "layered-image" : {
                "background" : "$media:1",
                "foreground" : "$media:2"
            }
        }
    )"_json;

    std::string jsonBuff_2(layeredImagedJson_1.dump());
    ans = parser.ParseForegroundAndBackgroundResource(resourceManager, jsonBuff_2, 0, resourceInfo);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0130
 * @tc.name: test GetLauncherAbilityResourceInfo
 * @tc.desc: 1. test parse layered image
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0130, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(LAYERED_IMAGE_HAP_PATH);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::vector<LauncherAbilityResourceInfo> infos;
        bool ret = manager->GetLauncherAbilityResourceInfo(BUNDLE_NAME_LAYERED_IMAGE,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR), infos);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(infos.empty());
        if (!infos.empty()) {
            EXPECT_EQ(infos[0].bundleName, BUNDLE_NAME_LAYERED_IMAGE);
            EXPECT_FALSE(infos[0].foreground.empty());
            EXPECT_FALSE(infos[0].background.empty());
        }
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME_LAYERED_IMAGE);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0140
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test UpdateBundleIcon
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0140, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        ResourceInfo info;
        info.bundleName_ = BUNDLE_NAME;
        info.label_ = BUNDLE_NAME;
        bool ret = manager->UpdateBundleIcon(BUNDLE_NAME, info);
        EXPECT_TRUE(ret);

        BundleResourceInfo bundleResourceInfo;
        ret = manager->GetBundleResourceInfo(BUNDLE_NAME, 1, bundleResourceInfo);
        EXPECT_TRUE(ret);
        EXPECT_EQ(info.bundleName_, bundleResourceInfo.bundleName);
        EXPECT_EQ(info.label_, bundleResourceInfo.label);
        EXPECT_TRUE(bundleResourceInfo.icon.empty());

        ret = manager->DeleteResourceInfo(BUNDLE_NAME);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: BmsBundleResourceTest_0141
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test UpdateBundleIcon
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0141, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        BundleResourceInfo oldBundleResourceInfo;
        bool ret = manager->GetBundleResourceInfo(BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR),
            oldBundleResourceInfo);
        EXPECT_TRUE(ret);
        EXPECT_EQ(oldBundleResourceInfo.bundleName, BUNDLE_NAME);

        ResourceInfo resourceInfo;
        resourceInfo.icon_ = "icon";
        resourceInfo.foreground_.push_back(1);
        resourceInfo.background_.push_back(1);
        ret = manager->UpdateBundleIcon(BUNDLE_NAME, resourceInfo);
        EXPECT_TRUE(ret);

        BundleResourceInfo newBundleResourceInfo;
        ret = manager->GetBundleResourceInfo(BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR),
            newBundleResourceInfo);
        EXPECT_TRUE(ret);
        EXPECT_EQ(newBundleResourceInfo.bundleName, oldBundleResourceInfo.bundleName);
        EXPECT_EQ(newBundleResourceInfo.label, oldBundleResourceInfo.label);
        EXPECT_EQ(newBundleResourceInfo.icon, resourceInfo.icon_);
        EXPECT_EQ(newBundleResourceInfo.foreground.size(), resourceInfo.foreground_.size());
        EXPECT_FALSE(newBundleResourceInfo.foreground.empty());
        if (!newBundleResourceInfo.foreground.empty() && !resourceInfo.foreground_.empty()) {
            EXPECT_EQ(newBundleResourceInfo.foreground[0], resourceInfo.foreground_[0]);
        }
        EXPECT_EQ(newBundleResourceInfo.background.size(), resourceInfo.background_.size());
        EXPECT_FALSE(newBundleResourceInfo.background.empty());
        if (!newBundleResourceInfo.background.empty() && !resourceInfo.background_.empty()) {
            EXPECT_EQ(newBundleResourceInfo.background[0], resourceInfo.background_[0]);
        }
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0142
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test UpdateBundleIcon
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0142, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::vector<LauncherAbilityResourceInfo> oldLauncherAbilityResourceInfos;
        bool ret = manager->GetLauncherAbilityResourceInfo(BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR),
            oldLauncherAbilityResourceInfos);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(oldLauncherAbilityResourceInfos.empty());

        ResourceInfo resourceInfo;
        resourceInfo.icon_ = "icon";
        resourceInfo.foreground_.push_back(1);
        resourceInfo.background_.push_back(1);
        ret = manager->UpdateBundleIcon(BUNDLE_NAME, resourceInfo);
        EXPECT_TRUE(ret);

        std::vector<LauncherAbilityResourceInfo> newLauncherAbilityResourceInfos;
        ret = manager->GetLauncherAbilityResourceInfo(BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR),
            newLauncherAbilityResourceInfos);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(newLauncherAbilityResourceInfos.empty());
        if (!newLauncherAbilityResourceInfos.empty() && !oldLauncherAbilityResourceInfos.empty()) {
            EXPECT_EQ(newLauncherAbilityResourceInfos[0].bundleName, oldLauncherAbilityResourceInfos[0].bundleName);
            EXPECT_EQ(newLauncherAbilityResourceInfos[0].moduleName, oldLauncherAbilityResourceInfos[0].moduleName);
            EXPECT_EQ(newLauncherAbilityResourceInfos[0].abilityName, oldLauncherAbilityResourceInfos[0].abilityName);
            EXPECT_EQ(newLauncherAbilityResourceInfos[0].label, oldLauncherAbilityResourceInfos[0].label);
            EXPECT_EQ(newLauncherAbilityResourceInfos[0].icon, resourceInfo.icon_);
            EXPECT_EQ(newLauncherAbilityResourceInfos[0].foreground.size(), resourceInfo.foreground_.size());
            EXPECT_FALSE(newLauncherAbilityResourceInfos[0].foreground.empty());
            if (!newLauncherAbilityResourceInfos[0].foreground.empty() && !resourceInfo.foreground_.empty()) {
                EXPECT_EQ(newLauncherAbilityResourceInfos[0].foreground[0], resourceInfo.foreground_[0]);
            }
            EXPECT_EQ(newLauncherAbilityResourceInfos[0].background.size(), resourceInfo.background_.size());
            EXPECT_FALSE(newLauncherAbilityResourceInfos[0].background.empty());
            if (!newLauncherAbilityResourceInfos[0].background.empty() && !resourceInfo.background_.empty()) {
                EXPECT_EQ(newLauncherAbilityResourceInfos[0].background[0], resourceInfo.background_[0]);
            }
        }
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0143
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test AddCloneBundleResourceInfo, bundleName not exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0143, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        bool ret = manager->AddCloneBundleResourceInfo(BUNDLE_NAME, 1);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: BmsBundleResourceTest_0144
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test AddCloneBundleResourceInfo, bundleName exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0144, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        BundleResourceInfo bundleResourceInfo;
        bool ret = manager->GetBundleResourceInfo(BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR),
            bundleResourceInfo);
        EXPECT_TRUE(ret);
        // add clone bundle resource
        int32_t appIndex = 1;
        ret = manager->AddCloneBundleResourceInfo(BUNDLE_NAME, appIndex);
        EXPECT_TRUE(ret);
        BundleResourceInfo cloneBundleResourceInfo;
        ret = manager->GetBundleResourceInfo(BUNDLE_NAME, static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR),
            cloneBundleResourceInfo, appIndex);
        EXPECT_TRUE(ret);
        EXPECT_EQ(cloneBundleResourceInfo.bundleName, bundleResourceInfo.bundleName);
        EXPECT_EQ(cloneBundleResourceInfo.appIndex, appIndex);
        EXPECT_EQ(cloneBundleResourceInfo.label, bundleResourceInfo.label + std::to_string(appIndex));
        EXPECT_FALSE(cloneBundleResourceInfo.icon.empty());
        EXPECT_FALSE(cloneBundleResourceInfo.foreground.empty());
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0145
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test AddCloneBundleResourceInfo, bundleName exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0145, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
        bool ret = manager->GetLauncherAbilityResourceInfo(BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR),
            launcherAbilityResourceInfos);
        EXPECT_TRUE(ret);
        // add clone bundle resource
        int32_t appIndex = 1;
        ret = manager->AddCloneBundleResourceInfo(BUNDLE_NAME, appIndex);
        EXPECT_TRUE(ret);

        std::vector<LauncherAbilityResourceInfo> cloneLauncherAbilityResourceInfos;
        ret = manager->GetLauncherAbilityResourceInfo(BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR),
            cloneLauncherAbilityResourceInfos, appIndex);
        EXPECT_TRUE(ret);
        EXPECT_EQ(launcherAbilityResourceInfos.size(), cloneLauncherAbilityResourceInfos.size());
        if (!launcherAbilityResourceInfos.empty() && !cloneLauncherAbilityResourceInfos.empty()) {
            EXPECT_EQ(cloneLauncherAbilityResourceInfos[0].bundleName, launcherAbilityResourceInfos[0].bundleName);
            EXPECT_EQ(cloneLauncherAbilityResourceInfos[0].moduleName, launcherAbilityResourceInfos[0].moduleName);
            EXPECT_EQ(cloneLauncherAbilityResourceInfos[0].abilityName, launcherAbilityResourceInfos[0].abilityName);
            EXPECT_EQ(cloneLauncherAbilityResourceInfos[0].label,
                launcherAbilityResourceInfos[0].label + std::to_string(appIndex));
            EXPECT_EQ(cloneLauncherAbilityResourceInfos[0].appIndex, appIndex);
            EXPECT_FALSE(cloneLauncherAbilityResourceInfos[0].icon.empty());
            EXPECT_FALSE(cloneLauncherAbilityResourceInfos[0].foreground.empty());
        }
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0146
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test ResourceInfo ParseKey
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0146, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = BUNDLE_NAME;
    resourceInfo.appIndex_ = 0;
    std::string key = resourceInfo.GetKey();
    EXPECT_EQ(key, BUNDLE_NAME);

    resourceInfo.appIndex_ = 1;
    key = resourceInfo.GetKey();
    EXPECT_EQ(key, "1_" + BUNDLE_NAME);

    ResourceInfo newInfo;
    newInfo.ParseKey(key);
    EXPECT_EQ(newInfo.bundleName_, resourceInfo.bundleName_);
    EXPECT_EQ(newInfo.appIndex_, resourceInfo.appIndex_);
    EXPECT_EQ(newInfo.appIndex_, 1);
}

/**
 * @tc.number: BmsBundleResourceTest_0147
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test ResourceInfo ParseKey
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0147, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    std::string key = "1_" + BUNDLE_NAME;
    resourceInfo.InnerParseAppIndex(key);
    EXPECT_EQ(resourceInfo.bundleName_, BUNDLE_NAME);
    EXPECT_EQ(resourceInfo.appIndex_, 1);

    key = "_" + BUNDLE_NAME;
    resourceInfo.InnerParseAppIndex(key);
    EXPECT_EQ(resourceInfo.bundleName_, key);
    EXPECT_EQ(resourceInfo.appIndex_, 0);

    key = "a1_" + BUNDLE_NAME;
    resourceInfo.InnerParseAppIndex(key);
    EXPECT_EQ(resourceInfo.bundleName_, key);
    EXPECT_EQ(resourceInfo.appIndex_, 0);

    key = "a1" + BUNDLE_NAME;
    resourceInfo.InnerParseAppIndex(key);
    EXPECT_EQ(resourceInfo.bundleName_, key);
    EXPECT_EQ(resourceInfo.appIndex_, 0);

    key = "100_" + BUNDLE_NAME;
    resourceInfo.InnerParseAppIndex(key);
    EXPECT_EQ(resourceInfo.bundleName_, BUNDLE_NAME);
    EXPECT_EQ(resourceInfo.appIndex_, 100);
}

/**
 * @tc.number: BmsBundleResourceTest_0148
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetAllResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0148, Function | SmallTest | Level0)
{
    std::map<std::string, std::vector<ResourceInfo>> resourceInfos;
    bundleMgrService_->RegisterDataMgr(nullptr);
    bool ans = BundleResourceProcess::GetAllResourceInfo(USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());
}

/**
 * @tc.number: BmsBundleResourceTest_0149
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherResourceInfoByAbilityName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0149, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    bundleMgrService_->RegisterDataMgr(nullptr);
    bool ans = BundleResourceProcess::GetLauncherResourceInfoByAbilityName(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME,
        USERID, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");
}

/**
 * @tc.number: BmsBundleResourceTest_0150
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetResourceInfoByColorModeChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0150, Function | SmallTest | Level0)
{
    std::vector<std::string> resourceNames;
    std::vector<ResourceInfo> resourceInfos;
    bundleMgrService_->RegisterDataMgr(nullptr);
    bool ans = BundleResourceProcess::GetResourceInfoByColorModeChanged(resourceNames, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfos.size(), 0);
}

/**
 * @tc.number: BmsBundleResourceTest_0151
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetTargetBundleName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0151, Function | SmallTest | Level0)
{
    std::string targetBundleName;
    bundleMgrService_->RegisterDataMgr(nullptr);
    BundleResourceProcess::GetTargetBundleName(BUNDLE_NAME, targetBundleName);
    EXPECT_TRUE(BUNDLE_NAME == targetBundleName);
}

/**
 * @tc.number: BmsBundleResourceTest_0152
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetResourceInfoByBundleName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0152, Function | SmallTest | Level0)
{
    std::vector<ResourceInfo> resourceInfos;
    bundleMgrService_->RegisterDataMgr(nullptr);
    bool ans = BundleResourceProcess::GetResourceInfoByBundleName(BUNDLE_NAME, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());
}

/**
 * @tc.number: BmsBundleResourceTest_0153
 * Function: BundleResourceParser
 * @tc.name: test BundleResourceParser
 * @tc.desc: 1. system running normally
 *           2. test ParseResourceInfoWithSameHap
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0153, Function | SmallTest | Level0)
{
    BundleResourceParser parser;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = BUNDLE_NAME;
    resourceInfo.label_ = BUNDLE_NAME;
    resourceInfo.labelId_ = 10;
    resourceInfo.iconId_ = 10;
    bool ans = parser.ParseResourceInfoWithSameHap(USERID, resourceInfo);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0154
 * Function: BundleResourceParser
 * @tc.name: test BundleResourceParser
 * @tc.desc: 1. system running normally
 *           2. test ParseResourceInfoWithSameHap
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0154, Function | SmallTest | Level0)
{
    BundleResourceParser parser;
    ResourceInfo resourceInfo;
    resourceInfo.hapPath_ = HAP_FILE_PATH1;
    resourceInfo.moduleName_ = MODULE_NAME;
    resourceInfo.overlayHapPaths_ = {HAP_FILE_PATH1, HAP_NO_ICON};
    resourceInfo.label_ = BUNDLE_NAME;
    resourceInfo.labelId_ = 10;
    resourceInfo.iconId_ = 10;
    bool ans = parser.ParseResourceInfoWithSameHap(USERID, resourceInfo);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0155
 * Function: BundleResourceParser
 * @tc.name: test BundleResourceParser
 * @tc.desc: 1. system running normally
 *           2. test ParseResourceInfoByResourceManager
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0155, Function | SmallTest | Level0)
{
    BundleResourceParser parser;
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager = nullptr;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = BUNDLE_NAME;
    resourceInfo.moduleName_ = MODULE_NAME;
    resourceInfo.label_ = BUNDLE_NAME;
    bool ans = parser.ParseResourceInfoByResourceManager(resourceManager, resourceInfo);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0156
 * Function: BundleResourceParser
 * @tc.name: test BundleResourceParser
 * @tc.desc: 1. system running normally
 *           2. test ParseResourceInfoByResourceManager
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0156, Function | SmallTest | Level0)
{
    BundleResourceParser parser;
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = BUNDLE_NAME;
    resourceInfo.moduleName_ = MODULE_NAME;
    resourceInfo.label_ = BUNDLE_NAME;
    resourceInfo.labelNeedParse_ = false;
    resourceInfo.iconNeedParse_  = false;
    bool ans = parser.ParseResourceInfoByResourceManager(resourceManager, resourceInfo);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0157
 * Function: BundleResourceParser
 * @tc.name: test BundleResourceParser
 * @tc.desc: 1. system running normally
 *           2. test GetMediaDataById
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0157, Function | SmallTest | Level0)
{
    BundleResourceParser parser;
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager = nullptr;
    uint32_t iconId = 1;
    int32_t density = 0;
    std::vector<uint8_t> data;
    bool ans = parser.GetMediaDataById(resourceManager, iconId, density, data);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0158
 * Function: GetBundleResourceInfo
 * @tc.name: test disable and enable
 * @tc.desc: 1. system running normally
 *           2. test ParseForegroundAndBackgroundResource
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0158, Function | SmallTest | Level0)
{
    BundleResourceParser parser;
    ResourceInfo resourceInfo;
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    std::string jsonBuff;
    bool ans = parser.ParseForegroundAndBackgroundResource(resourceManager, jsonBuff, 0, resourceInfo);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0159
 * Function: GetBundleResourceInfo
 * @tc.name: test disable and enable
 * @tc.desc: 1. system running normally
 *           2. test ParseThemeIcon
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0159, Function | SmallTest | Level0)
{
    BundleResourceParser parser;
    ResourceInfo resourceInfo;
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    bool ans = parser.ParseThemeIcon(resourceManager, 0, resourceInfo);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0160
 * Function: GetBundleResourceInfo
 * @tc.name: test disable and enable
 * @tc.desc: 1. system running normally
 *           2. test ProcessResourceInfoWhenParseFailed
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0160, Function | SmallTest | Level0)
{
    BundleResourceParser parser;
    ResourceInfo oldResourceInfo;
    oldResourceInfo.label_ = "oldlabel";
    oldResourceInfo.icon_ = "oldicon";
    oldResourceInfo.foreground_.push_back(1);
    oldResourceInfo.background_.push_back(1);
    ResourceInfo newResourceInfo;
    parser.ProcessResourceInfoWhenParseFailed(oldResourceInfo, newResourceInfo);
    EXPECT_EQ(oldResourceInfo.label_, newResourceInfo.label_);
    EXPECT_EQ(oldResourceInfo.icon_, newResourceInfo.icon_);
    EXPECT_EQ(oldResourceInfo.foreground_, newResourceInfo.foreground_);
    EXPECT_EQ(oldResourceInfo.background_, newResourceInfo.background_);
}

/**
 * @tc.number: BmsBundleResourceTest_0161
 * Function: GetBundleResourceInfo
 * @tc.name: test disable and enable
 * @tc.desc: 1. system running normally
 *           2. test ProcessResourceInfoWhenParseFailed
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0161, Function | SmallTest | Level0)
{
    BundleResourceParser parser;
    ResourceInfo oldResourceInfo;
    oldResourceInfo.label_ = "oldlabel";
    oldResourceInfo.icon_ = "oldicon";
    oldResourceInfo.foreground_.push_back(1);
    oldResourceInfo.background_.push_back(1);
    ResourceInfo newResourceInfo;
    newResourceInfo.label_ = "newlabel";
    newResourceInfo.icon_ = "newicon";
    newResourceInfo.foreground_.push_back(2);
    newResourceInfo.background_.push_back(2);
    parser.ProcessResourceInfoWhenParseFailed(oldResourceInfo, newResourceInfo);
    EXPECT_FALSE(newResourceInfo.label_.empty());
    EXPECT_FALSE(newResourceInfo.icon_.empty());
    EXPECT_FALSE(newResourceInfo.foreground_.empty());
    EXPECT_FALSE(newResourceInfo.background_.empty());
}
#endif
} // OHOS
