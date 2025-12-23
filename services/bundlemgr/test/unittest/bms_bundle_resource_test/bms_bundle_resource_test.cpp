/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "bms_extension_client.h"
#include "bundle_info.h"
#include "bundle_option.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "bundle_parser.h"
#include "bundle_permission_mgr.h"
#include "bundle_resource_drawable.h"

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
#include "bundle_resource_callback.h"
#include "bundle_resource_change_type.h"
#include "bundle_resource_configuration.h"
#include "bundle_resource_constants.h"
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
#include "directory_ex.h"
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
const int32_t WAIT_TIME = 2; // init mocked bms
const int32_t APP_INDEX = 1;
const std::string BUNDLE_NAME = "com.example.bmsaccesstoken1";
const std::string BUNDLE_NAME_NOT_EXIST = "com.example.not_exist";
const std::string MODULE_NAME = "entry";
const std::string ABILITY_NAME = "com.example.bmsaccesstoken1.MainAbility";
const std::string HAP_FILE_PATH1 = "/data/test/resource/bms/accesstoken_bundle/bmsAccessTokentest1.hap";
const std::string HAP_NOT_EXIST = "not exist";
const std::string HAP_NO_ICON = "/data/test/resource/bms/accesstoken_bundle/bmsThirdBundle2.hap";
const std::string BUNDLE_NAME_NO_ICON = "com.third.hiworld.example1";
const std::string THEME_FILE_PATH = "/data/test/resource/bms/theme_description_test.json";
const std::string THEME_A_FLAG = "/data/service/el1/public/themes/100/a/app/flag";
const std::string THEME_A_ICON_MMS = "/data/service/el1/public/themes/100/a/app/icons/com.ohos.mms";
const std::string THEME_B_ICON_MMS = "/data/service/el1/public/themes/100/b/app/icons/com.ohos.mms";
const std::string THEME_TEST_BUNDLE_NAME = "com.ohos.mms";
const std::string THEME_A_ICON_BUNDLE_NAME =
    "/data/service/el1/public/themes/20000/a/app/icons/com.example.bmsaccesstoken1";
const std::string THEME_B_ICON_BUNDLE_NAME  =
    "/data/service/el1/public/themes/20000/b/app/icons/com.example.bmsaccesstoken1";
const std::string THEME_A_FLAG_BUNDLE_NAME =
    "/data/service/el1/public/themes/20000/a/app/flag";
const std::string THEME_BUNDLE_NAME_PATH =
    "/data/service/el1/public/themes/20000";
const std::string THEME_A_ICON_JSON_BUNDLE_NAME =
    "/data/service/el1/public/themes/20000/a/app/icons/description.json";
const std::string THEME_B_ICON_JSON_BUNDLE_NAME =
    "/data/service/el1/public/themes/20000/b/app/icons/description.json";
const int32_t THEME_TEST_USERID = 20000;
const std::string THEME_A_OTHER_ICONS = "/data/service/el1/public/themes/20000/a/app/icons/other_icons";
const std::string THEME_B_OTHER_ICONS = "/data/service/el1/public/themes/20000/b/app/icons/other_icons";
// test layered image
const std::string BUNDLE_NAME_LAYERED_IMAGE = "com.example.thumbnailtest";
const std::string LAYERED_IMAGE_HAP_PATH = "/data/test/resource/bms/accesstoken_bundle/thumbnail.hap";
const std::string TEST_BUNDLE_NAME = "testBundleName";
const int32_t U1 = 1;
const int32_t INVALID_INDEX = 6;
const std::string INVALID_ABILITY_NAME = "com.example.bmsaccesstoken.Ability";
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
    ErrCode UnInstallBundle(const std::string &bundleName, bool keepData = false) const;
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
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = USERID;
    installParam.withCopyHaps = true;
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
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleResourceTest::UnInstallBundle(const std::string &bundleName, bool keepData) const
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
    installParam.isKeepData = keepData;
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
 * @tc.number: OnReceiveEvent_0010
 * Function: OnReceiveEvent
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test OnReceiveEvent
 */
HWTEST_F(BmsBundleResourceTest, OnReceiveEvent_0010, Function | SmallTest | Level0)
{
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    OHOS::EventFwk::CommonEventData commonData2 { want };
    commonData2.SetCode(U1); // userId not exist
    bool ans = OnReceiveEvent(commonData2);
    EXPECT_TRUE(ans);
}

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

    std::string param = BundleResourceParam::GetSystemParam("aaa_not_exist");
    EXPECT_TRUE(param.empty());

    language = BundleResourceParam::GetSystemLocale();
    EXPECT_FALSE(language.empty());

    param = BundleResourceParam::GetSystemParam("const.global.language");
    EXPECT_FALSE(param.empty());
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

    info.iconId_ = 1;
    ans = parser.ParseIconResourceByResourceManager(resourceManager, info, false);
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

        resourceInfos[0].label_ = "";
        resourceInfos[0].icon_ = "";
        ans = parser.ParseResourceInfos(USERID, resourceInfos);
        EXPECT_TRUE(ans);
        EXPECT_NE(resourceInfos[0].label_, "");
        EXPECT_NE(resourceInfos[0].icon_, "");
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
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
    EXPECT_TRUE(ans);

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
    EXPECT_TRUE(ans);
    EXPECT_FALSE(resourceInfos_2.empty());

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0082
 * Function: GetAbilityResourceInfos
 * @tc.name: test GetAbilityResourceInfos
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0082, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    InnerExtensionInfo innerExtensionInfo;

    innerExtensionInfo.type = ExtensionAbilityType::INPUTMETHOD;
    innerBundleInfo.baseExtensionInfos_.emplace("inputmethod_key", innerExtensionInfo);
    innerExtensionInfo.type = ExtensionAbilityType::SHARE;
    innerBundleInfo.baseExtensionInfos_.emplace("share_key", innerExtensionInfo);
    innerExtensionInfo.type = ExtensionAbilityType::ACTION;
    innerBundleInfo.baseExtensionInfos_.emplace("action_key", innerExtensionInfo);
    innerExtensionInfo.type = ExtensionAbilityType::DRIVER;
    innerBundleInfo.baseExtensionInfos_.emplace("driver_key", innerExtensionInfo);

    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.bundleType = BundleType::APP;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    std::vector<ResourceInfo> resourceInfos;
    auto ans = BundleResourceProcess::GetAbilityResourceInfos(innerBundleInfo, USERID, resourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_EQ(resourceInfos.size(), 3);
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

        BundleResourceInfo info5;
        ret = manager->GetBundleResourceInfo(TEST_BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON), info5);
        EXPECT_FALSE(ret);
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
 * Function: GetExtensionAbilityResourceInfo
 * @tc.name: test Install
 * @tc.desc: 1. system running normally
 *           2. test GetExtensionAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0102, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    std::vector<LauncherAbilityResourceInfo> info;

    auto ret = bundleResourceHostImpl->GetExtensionAbilityResourceInfo(BUNDLE_NAME, ExtensionAbilityType::FORM,
        0, info, 100);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX);
    EXPECT_TRUE(info.empty());

    ret = bundleResourceHostImpl->GetExtensionAbilityResourceInfo(BUNDLE_NAME, ExtensionAbilityType::FORM, 0, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_EQ(info.size(), 0);
    if (!info.empty()) {
        EXPECT_EQ(info[0].bundleName, BUNDLE_NAME);
        EXPECT_EQ(info[0].moduleName, MODULE_NAME);
        EXPECT_EQ(info[0].abilityName, ABILITY_NAME);
        EXPECT_FALSE(info[0].label.empty());
        EXPECT_FALSE(info[0].icon.empty());
    }

    ret = bundleResourceHostImpl->GetExtensionAbilityResourceInfo(BUNDLE_NAME, ExtensionAbilityType::FORM, 0, info, 1);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: BmsBundleResourceTest_0103
 * Function: CheckExtensionAbilityValid
 * @tc.name: test CheckExtensionAbilityValid with appIndex 0
 * @tc.desc: 1. system running normally
 *           2. test CheckExtensionAbilityValid when appIndex is 0
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0103, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    std::vector<LauncherAbilityResourceInfo> info;
    auto ret = bundleResourceHostImpl->GetExtensionAbilityResourceInfo(BUNDLE_NAME, ExtensionAbilityType::INPUTMETHOD,
        0, info, 0);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
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
            "layered" : {
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
                "background0" : "$media:1",
                "foreground0" : "$media:2"
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
 * @tc.number: BmsBundleResourceTest_0175
 * Function: DeleteResourceInfo
 * @tc.name: test DeleteResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0175, Function | SmallTest | Level0)
{
    bool ret = BundleResourceHelper::DeleteAllResourceInfo();
    EXPECT_TRUE(ret);
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        ret = manager->AddAllResourceInfo(USERID, 0);
        EXPECT_TRUE(ret);
    }
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
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    bundleMgrService_->RegisterDataMgr(nullptr);
    bool ans = BundleResourceProcess::GetAllResourceInfo(USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());
    bundleMgrService_->RegisterDataMgr(savedDataMgr);
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
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    bundleMgrService_->RegisterDataMgr(nullptr);
    bool ans = BundleResourceProcess::GetLauncherResourceInfoByAbilityName(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME,
        USERID, resourceInfo);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfo.GetKey(), "");
    bundleMgrService_->RegisterDataMgr(savedDataMgr);
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
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    bundleMgrService_->RegisterDataMgr(nullptr);
    bool ans = BundleResourceProcess::GetResourceInfoByColorModeChanged(resourceNames, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_EQ(resourceInfos.size(), 0);
    bundleMgrService_->RegisterDataMgr(savedDataMgr);
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
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    bundleMgrService_->RegisterDataMgr(nullptr);
    BundleResourceProcess::GetTargetBundleName(BUNDLE_NAME, targetBundleName);
    EXPECT_TRUE(BUNDLE_NAME == targetBundleName);
    bundleMgrService_->RegisterDataMgr(savedDataMgr);
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
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    bundleMgrService_->RegisterDataMgr(nullptr);
    bool ans = BundleResourceProcess::GetResourceInfoByBundleName(BUNDLE_NAME, USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());
    bundleMgrService_->RegisterDataMgr(savedDataMgr);
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
 * Function: InnerProcessResourceInfoBySystemLanguageChanged
 * @tc.name: test system language change
 * @tc.desc: 1. system running normally
 *           2. test InnerProcessResourceInfoBySystemLanguageChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0159, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::map<std::string, std::vector<ResourceInfo>> resourceInfosMap;
        ResourceInfo info;
        info.iconNeedParse_ = true;
        resourceInfosMap[BUNDLE_NAME].emplace_back(info);
        manager->InnerProcessResourceInfoBySystemLanguageChanged(resourceInfosMap);
        EXPECT_FALSE(resourceInfosMap[BUNDLE_NAME][0].iconNeedParse_);
    }
}

/**
 * @tc.number: BmsBundleResourceTest_0160
 * Function: InnerProcessResourceInfoBySystemThemeChanged
 * @tc.name: test system theme change
 * @tc.desc: 1. system running normally
 *           2. test InnerProcessResourceInfoBySystemThemeChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0160, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::map<std::string, std::vector<ResourceInfo>> resourceInfosMap;
        ResourceInfo info;
        info.bundleName_ = BUNDLE_NAME;
        info.iconNeedParse_ = true;
        resourceInfosMap[BUNDLE_NAME].emplace_back(info);
        manager->InnerProcessResourceInfoBySystemThemeChanged(resourceInfosMap, THEME_TEST_USERID);
        EXPECT_TRUE(resourceInfosMap.empty()); // theme not exist
    }
}

/**
 * @tc.number: BmsBundleResourceTest_0166
 * Function: AddResourceInfoByAbility
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfoByAbility
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0166, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(bundleResourceHostImpl, nullptr);
    auto ret = bundleResourceHostImpl->AddResourceInfoByAbility("", "", "", USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    ret = bundleResourceHostImpl->AddResourceInfoByAbility(BUNDLE_NAME, "", "", USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    ret = bundleResourceHostImpl->AddResourceInfoByAbility(BUNDLE_NAME, MODULE_NAME, "", USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    ret = bundleResourceHostImpl->AddResourceInfoByAbility(BUNDLE_NAME, MODULE_NAME, ABILITY_NAME, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsBundleResourceTest_0167
 * Function: DeleteResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test DeleteResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0167, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(bundleResourceHostImpl, nullptr);
    std::string key = "test_key";
    auto ret = bundleResourceHostImpl->DeleteResourceInfo("");
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    ret = bundleResourceHostImpl->DeleteResourceInfo(key);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsBundleResourceTest_0168
 * Function: CheckBundleNameValid
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test CheckBundleNameValid
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0168, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ASSERT_NE(bundleResourceHostImpl, nullptr);
    int32_t appIndex = 1;
    auto ret = bundleResourceHostImpl->CheckBundleNameValid(BUNDLE_NAME, 0);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    ret = bundleResourceHostImpl->CheckBundleNameValid(BUNDLE_NAME, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: BmsBundleResourceTest_0169
 * Function: GetIconResourceByHap
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetIconResourceByHap
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0169, Function | SmallTest | Level0)
{
    BundleResourceDrawable drawable;
    uint32_t iconId = 1;
    int32_t density = 1;
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    ResourceInfo resourceInfo;
    bool ret = drawable.GetIconResourceByHap(iconId, density, resourceManager, resourceInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BmsBundleResourceTest_0170
 * Function: OnUserIdChanged
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test OnUserIdChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0170, Function | SmallTest | Level0)
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    OHOS::EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    auto subscriberPtr = std::make_shared<BundleResourceEventSubscriber>(subscribeInfo);
    ASSERT_NE(subscriberPtr, nullptr);
    int32_t oldUserId = 1;
    int32_t newUserId = 2;
    subscriberPtr->OnUserIdChanged(oldUserId, newUserId);
    EXPECT_NE(subscriberPtr, nullptr);
}

/**
 * @tc.number: BmsBundleResourceTest_0172
 * Function: ProcessResourceInfoNoNeedToParseOtherIcon
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test ProcessResourceInfoNoNeedToParseOtherIcon
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0172, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    std::vector<ResourceInfo> resourceInfos;
    resourceInfos.push_back(resourceInfo);
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    ASSERT_NE(manager, nullptr);
    manager->ProcessResourceInfoNoNeedToParseOtherIcon(resourceInfos);
    EXPECT_FALSE(resourceInfos[0].labelNeedParse_);
    EXPECT_EQ(resourceInfos[0].label_, "");
}

/**
 * @tc.number: BmsBundleResourceTest_0173
 * Function: SetThemeParamForThemeChanged
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test SetThemeParamForThemeChanged
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0173, Function | SmallTest | Level0)
{
    int32_t themeId = 0;
    int32_t themeIcon = 0;
    BundleResourceCallback bundleResourceCallback;
    bool ret = bundleResourceCallback.SetThemeParamForThemeChanged(themeId, themeIcon);
    EXPECT_FALSE(ret);
    themeId = 1000;
    ret = bundleResourceCallback.SetThemeParamForThemeChanged(themeId, themeIcon);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsBundleResourceTest_0176
 * Function: DeleteResourceInfo
 * @tc.name: test DeleteResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0176, Function | SmallTest | Level0)
{
    std::vector<std::string> resourceNames;
    BundleResourceHelper::GetAllBundleResourceName(resourceNames);
    BundleResourceHelper::SetOverlayEnabled(BUNDLE_NAME, "ModuleName", true, 100);
    BundleResourceHelper::DeleteNotExistResourceInfo();
    std::string ret = BundleResourceHelper::ParseBundleName("keyName");
    EXPECT_EQ(ret, "keyName");
}

/**
 * @tc.number: BmsBundleResourceTest_0177
 * Function: GetLauncherAbilityResourceInfo
 * @tc.name: test Install
 * @tc.desc: 1. system running normally
 *           2. test GetBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0177, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::vector<LauncherAbilityResourceInfo> infos;
        bool ret = manager->GetLauncherAbilityResourceInfo(TEST_BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), infos);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: BmsBundleResourceTest_0186
 * Function: GetIconResourceByTheme
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetIconResourceByTheme
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0186, Function | SmallTest | Level0)
{
    BundleResourceDrawable drawable;
    uint32_t iconId = 1;
    int32_t density = 1;
    ResourceInfo resourceInfo;
    bool ret = drawable.GetIconResourceByTheme(iconId, density, nullptr, resourceInfo);
    EXPECT_FALSE(ret);
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    ret = drawable.GetIconResourceByTheme(iconId, density, resourceManager, resourceInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BmsBundleResourceTest_0188
 * Function: ChangeDynamicIcon
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test ChangeDynamicIcon
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0188, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    std::vector<ResourceInfo> resourceInfos;
    resourceInfos.push_back(resourceInfo);
    BundleResourceProcess::ChangeDynamicIcon(resourceInfos, resourceInfo);
    EXPECT_FALSE(resourceInfos[0].iconNeedParse_);
}

/**
 * @tc.number: BmsBundleResourceTest_0189
 * Function: GetAppIndexByBundleName
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetAppIndexByBundleName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0189, Function | SmallTest | Level0)
{
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    bundleMgrService_->RegisterDataMgr(nullptr);
    auto index = BundleResourceProcess::GetAppIndexByBundleName(BUNDLE_NAME);
    EXPECT_TRUE(index.empty());
    bundleMgrService_->RegisterDataMgr(savedDataMgr);
}

/**
 * @tc.number: BmsBundleResourceTest_0190
 * Function: GetAppIndexByBundleName
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetAppIndexByBundleName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0190, Function | SmallTest | Level0)
{
    auto index = BundleResourceProcess::GetAppIndexByBundleName(BUNDLE_NAME);
    EXPECT_TRUE(index.empty());
}

/**
 * @tc.number: BmsBundleResourceTest_0191
 * Function: GetAppIndexByBundleName
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetAppIndexByBundleName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0191, Function | SmallTest | Level0)
{
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.appIndex = 1;
    InnerBundleUserInfo userInfo;
    userInfo.cloneInfos["1"] = cloneInfo;
    InnerBundleInfo bundleInfo;
    bundleInfo.innerBundleUserInfos_["100"] = userInfo;
    savedDataMgr->bundleInfos_[BUNDLE_NAME_NOT_EXIST] = bundleInfo;
    auto index = BundleResourceProcess::GetAppIndexByBundleName(BUNDLE_NAME_NOT_EXIST);
    EXPECT_FALSE(index.empty());

    auto iter = savedDataMgr->bundleInfos_.find(BUNDLE_NAME_NOT_EXIST);
    if (iter != savedDataMgr->bundleInfos_.end()) {
        savedDataMgr->bundleInfos_.erase(iter);
    }
}

/**
 * @tc.number: BmsBundleResourceTest_0196
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetCurDynamicIconModule, dataMgr is nullptr
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0196, Function | SmallTest | Level0)
{
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    bundleMgrService_->RegisterDataMgr(nullptr);
    std::string dynamicIcon = BundleResourceProcess::GetCurDynamicIconModule(BUNDLE_NAME, USERID, 0);
    EXPECT_TRUE(dynamicIcon.empty());
    bundleMgrService_->RegisterDataMgr(savedDataMgr);
}

/**
 * @tc.number: BmsBundleResourceTest_0197
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetCurDynamicIconModule
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0197, Function | SmallTest | Level0)
{
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    userInfo.curDynamicIconModule = BUNDLE_NAME;
    InnerBundleInfo bundleInfo;
    bundleInfo.innerBundleUserInfos_["_100"] = userInfo;
    savedDataMgr->bundleInfos_[BUNDLE_NAME_NOT_EXIST] = bundleInfo;

    std::string dynamicIcon = BundleResourceProcess::GetCurDynamicIconModule(BUNDLE_NAME, USERID, 0);
    EXPECT_TRUE(dynamicIcon.empty());
    dynamicIcon = BundleResourceProcess::GetCurDynamicIconModule(BUNDLE_NAME_NOT_EXIST, USERID, 0);
    EXPECT_EQ(dynamicIcon, BUNDLE_NAME);
    auto iter = savedDataMgr->bundleInfos_.find(BUNDLE_NAME_NOT_EXIST);
    if (iter != savedDataMgr->bundleInfos_.end()) {
        savedDataMgr->bundleInfos_.erase(iter);
    }
}

/**
 * @tc.number: BmsBundleResourceTest_0198
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetExtendResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0198, Function | SmallTest | Level0)
{
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    bundleMgrService_->RegisterDataMgr(nullptr);
    ExtendResourceInfo extendResourceInfo;
    bool ret = BundleResourceProcess::GetExtendResourceInfo(BUNDLE_NAME, BUNDLE_NAME, extendResourceInfo);
    EXPECT_FALSE(ret);
    bundleMgrService_->RegisterDataMgr(savedDataMgr);
}

/**
 * @tc.number: BmsBundleResourceTest_0199
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetExtendResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0199, Function | SmallTest | Level0)
{
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    userInfo.curDynamicIconModule = BUNDLE_NAME;
    InnerBundleInfo bundleInfo;
    bundleInfo.innerBundleUserInfos_["_100"] = userInfo;
    ExtendResourceInfo resourceInfo;
    resourceInfo.moduleName = BUNDLE_NAME;
    bundleInfo.extendResourceInfos_[BUNDLE_NAME] = resourceInfo;
    savedDataMgr->bundleInfos_[BUNDLE_NAME_NOT_EXIST] = bundleInfo;

    ExtendResourceInfo extendResourceInfo;
    bool ret = BundleResourceProcess::GetExtendResourceInfo(BUNDLE_NAME, "", extendResourceInfo);
    EXPECT_FALSE(ret);

    ret = BundleResourceProcess::GetExtendResourceInfo(BUNDLE_NAME_NOT_EXIST,
        BUNDLE_NAME_NOT_EXIST, extendResourceInfo);
    EXPECT_FALSE(ret);

    ret = BundleResourceProcess::GetExtendResourceInfo(BUNDLE_NAME_NOT_EXIST,
        BUNDLE_NAME, extendResourceInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(extendResourceInfo.moduleName, BUNDLE_NAME);

    auto iter = savedDataMgr->bundleInfos_.find(BUNDLE_NAME_NOT_EXIST);
    if (iter != savedDataMgr->bundleInfos_.end()) {
        savedDataMgr->bundleInfos_.erase(iter);
    }
}

/**
 * @tc.number: BmsBundleResourceTest_0200
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetDynamicIcon
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0200, Function | SmallTest | Level0)
{
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    InnerBundleInfo bundleInfo;
    bundleInfo.innerBundleUserInfos_["_100"] = userInfo;

    ResourceInfo resourceInfo;
    resourceInfo.appIndex_ = 1;
    bool ret = BundleResourceProcess::GetDynamicIcon(bundleInfo, USERID, resourceInfo);
    EXPECT_FALSE(ret);

    resourceInfo.appIndex_ = 0;
    ret = BundleResourceProcess::GetDynamicIcon(bundleInfo, USERID, resourceInfo);
    EXPECT_FALSE(ret);

    bundleInfo.innerBundleUserInfos_["_100"].curDynamicIconModule = BUNDLE_NAME;
    ret = BundleResourceProcess::GetDynamicIcon(bundleInfo, USERID, resourceInfo);
    EXPECT_FALSE(ret);

    ExtendResourceInfo extendResourceInfo;
    extendResourceInfo.moduleName = BUNDLE_NAME;
    bundleInfo.extendResourceInfos_[BUNDLE_NAME] = extendResourceInfo;
    ret = BundleResourceProcess::GetDynamicIcon(bundleInfo, USERID, resourceInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BmsBundleResourceTest_0207
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetExtensionAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0207, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.extensionAbilityType_ = static_cast<int32_t>(ExtensionAbilityType::INPUTMETHOD);
    resourceInfo.abilityName_ = "abilityName";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";
    bool ans = manager->bundleResourceRdb_->AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);

    std::vector<LauncherAbilityResourceInfo> infos;
    ans = manager->GetExtensionAbilityResourceInfo(resourceInfo.bundleName_, ExtensionAbilityType::INPUTMETHOD,
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
 * @tc.number: BmsBundleResourceTest_0208
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetExtensionAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0208, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    std::vector<LauncherAbilityResourceInfo> infos;
    bool ans = manager->GetExtensionAbilityResourceInfo("bundleName", ExtensionAbilityType::INPUTMETHOD, 0, infos, 0);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.number: BmsBundleResourceTest_0209
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetExtensionAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0209, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.extensionAbilityType_ = static_cast<int32_t>(ExtensionAbilityType::INPUTMETHOD);
    resourceInfo.abilityName_ = "abilityName";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);
    
    std::vector<LauncherAbilityResourceInfo> infos;
    ans = resourceRdb.GetExtensionAbilityResourceInfo(resourceInfo.bundleName_, ExtensionAbilityType::INPUTMETHOD,
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
 * @tc.number: BmsBundleResourceTest_0210
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetExtensionAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0210, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.extensionAbilityType_ = static_cast<int32_t>(ExtensionAbilityType::INPUTMETHOD);
    resourceInfo.abilityName_ = "SettingsForm";
    resourceInfo.label_ = "Settings";
    
    ResourceInfo resourceInfo2;
    resourceInfo2.bundleName_ = "bundleName";
    resourceInfo.moduleName_ = "moduleName2";
    resourceInfo2.extensionAbilityType_ = static_cast<int32_t>(ExtensionAbilityType::SERVICE);
    resourceInfo2.abilityName_ = "abilityName";
    resourceInfo2.label_ = "label";
    
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);
    ans = resourceRdb.AddResourceInfo(resourceInfo2);
    EXPECT_TRUE(ans);

    std::vector<LauncherAbilityResourceInfo> infos;
    ans = resourceRdb.GetExtensionAbilityResourceInfo("bundleName", ExtensionAbilityType::INPUTMETHOD, 0, infos, 0);
    EXPECT_TRUE(ans);
    EXPECT_EQ(infos.size(), 1);

    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
    ans = resourceRdb.DeleteResourceInfo(resourceInfo2.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0211
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetExtensionAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0211, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    std::vector<LauncherAbilityResourceInfo> infos;
    bool ans = resourceRdb.GetExtensionAbilityResourceInfo("bundleName", ExtensionAbilityType::INPUTMETHOD,
        0, infos, 0);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.number: BmsBundleResourceTest_0212
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetExtensionAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0212, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo info;
    info.bundleName_ = "bundleName";
    info.moduleName_ = "moduleName";
    info.extensionAbilityType_ = static_cast<int32_t>(ExtensionAbilityType::INPUTMETHOD);
    info.abilityName_ = "ZService";
    info.label_ = "Z";
    info.icon_ = "Zicon";

    ResourceInfo info2;
    info2.bundleName_ = "bundleName";
    info2.moduleName_ = "moduleName2";
    info2.extensionAbilityType_ = static_cast<int32_t>(ExtensionAbilityType::INPUTMETHOD);
    info2.abilityName_ = "AService";
    info2.label_ = "A";
    info2.icon_ = "Aicon";

    bool ans = resourceRdb.AddResourceInfo(info);
    EXPECT_TRUE(ans);
    ans = resourceRdb.AddResourceInfo(info2);
    EXPECT_TRUE(ans);

    std::vector<LauncherAbilityResourceInfo> infos;
    uint32_t sortFlag = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL);
    ans = resourceRdb.GetExtensionAbilityResourceInfo(info.bundleName_, ExtensionAbilityType::INPUTMETHOD,
        sortFlag, infos, 0);
    EXPECT_TRUE(ans);
    EXPECT_EQ(infos.size(), 2);
    EXPECT_EQ(infos[0].label, "A");
    EXPECT_EQ(infos[1].label, "Z");

    ans = resourceRdb.DeleteResourceInfo(info.GetKey());
    EXPECT_TRUE(ans);
    ans = resourceRdb.DeleteResourceInfo(info2.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0213
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetExtensionAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0213, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;

    ResourceInfo info;
    info.bundleName_ = "bundleName";
    info.moduleName_ = "moduleName";
    info.extensionAbilityType_ = static_cast<int32_t>(ExtensionAbilityType::INPUTMETHOD);
    info.abilityName_ = "MainService";
    info.label_ = "0";

    ResourceInfo info2;
    info2.bundleName_ = "bundleName";
    info2.moduleName_ = "moduleName2";
    info2.extensionAbilityType_ = static_cast<int32_t>(ExtensionAbilityType::INPUTMETHOD);
    info2.abilityName_ = "SecondService";
    info2.label_ = "1";

    bool ans = resourceRdb.AddResourceInfo(info);
    EXPECT_TRUE(ans);
    ans = resourceRdb.AddResourceInfo(info2);
    EXPECT_TRUE(ans);

    std::vector<LauncherAbilityResourceInfo> infos;
    ans = resourceRdb.GetExtensionAbilityResourceInfo(info.bundleName_, ExtensionAbilityType::INPUTMETHOD, 0, infos, 0);
    EXPECT_TRUE(ans);
    EXPECT_EQ(infos.size(), 2);
    if (!infos.empty()) {
        EXPECT_EQ(infos[0].abilityName, "MainService");
    }
    ans = resourceRdb.DeleteResourceInfo(info.GetKey());
    EXPECT_TRUE(ans);
    ans = resourceRdb.DeleteResourceInfo(info2.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0214
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetAllExtensionAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0214, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.extensionAbilityType_ = static_cast<int32_t>(ExtensionAbilityType::INPUTMETHOD);
    resourceInfo.abilityName_ = "MainService";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);
    ASSERT_TRUE(ans);

    std::vector<LauncherAbilityResourceInfo> infos;
    uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL);
    ans = resourceRdb.GetAllExtensionAbilityResourceInfo(resourceInfo.bundleName_, flags, infos, 0);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(infos.empty());
    EXPECT_EQ(infos.size(), 1);
    EXPECT_EQ(infos[0].bundleName, resourceInfo.bundleName_);
    EXPECT_EQ(infos[0].moduleName, "moduleName");
    EXPECT_EQ(infos[0].label, "label");

    ans = resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0215
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetAllExtensionAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0215, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.extensionAbilityType_ = -1;
    resourceInfo.abilityName_ = "MainService";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";
    bool ans = resourceRdb.AddResourceInfo(resourceInfo);

    std::vector<LauncherAbilityResourceInfo> infos;
    ans = resourceRdb.GetAllExtensionAbilityResourceInfo(resourceInfo.bundleName_, 0, infos, 0);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(infos.empty());
    resourceRdb.DeleteResourceInfo(resourceInfo.GetKey());
}

/**
 * @tc.number: BmsBundleResourceTest_0216
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test ConvertToExtensionAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0216, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo info;
    info.bundleName_ = "bundleName";
    info.moduleName_ = "moduleName";
    info.extensionAbilityType_ = static_cast<int32_t>(ExtensionAbilityType::INPUTMETHOD);
    info.abilityName_ = "ZService";
    info.label_ = "Z";
    info.icon_ = "Zicon";

    ResourceInfo info2;
    info2.bundleName_ = "bundleName";
    info2.moduleName_ = "moduleName2";
    info2.extensionAbilityType_ = static_cast<int32_t>(ExtensionAbilityType::INPUTMETHOD);
    info2.abilityName_ = "AService";
    info2.label_ = "A";
    info2.icon_ = "Aicon";

    bool ans = resourceRdb.AddResourceInfo(info);
    EXPECT_TRUE(ans);
    ans = resourceRdb.AddResourceInfo(info2);
    EXPECT_TRUE(ans);

    std::vector<LauncherAbilityResourceInfo> infos;
    ans = resourceRdb.GetExtensionAbilityResourceInfo(info.bundleName_, ExtensionAbilityType::INPUTMETHOD, 0, infos, 0);
    EXPECT_TRUE(ans);
    EXPECT_EQ(infos.size(), 2);
    EXPECT_EQ(infos[0].bundleName, "bundleName");
    EXPECT_EQ(infos[0].moduleName, "moduleName");
    EXPECT_EQ(infos[0].abilityName, "ZService");
    EXPECT_EQ(infos[0].label, "");
    EXPECT_EQ(infos[0].icon, "");
    EXPECT_EQ(infos[1].bundleName, "bundleName");
    EXPECT_EQ(infos[1].moduleName, "moduleName2");
    EXPECT_EQ(infos[1].abilityName, "AService");
    EXPECT_EQ(infos[1].label, "");
    EXPECT_EQ(infos[1].icon, "");

    ans = resourceRdb.DeleteResourceInfo(info.GetKey());
    EXPECT_TRUE(ans);
    ans = resourceRdb.DeleteResourceInfo(info2.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0217
 * Function: BundleResourceRdb
 * @tc.name: test BundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test ConvertToExtensionAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0217, Function | SmallTest | Level0)
{
    BundleResourceRdb resourceRdb;
    ResourceInfo info;
    info.bundleName_ = "bundleName";
    info.moduleName_ = "moduleName";
    info.extensionAbilityType_ = static_cast<int32_t>(ExtensionAbilityType::INPUTMETHOD);
    info.abilityName_ = "ZService";
    info.label_ = "Z";
    info.icon_ = "Zicon";

    ResourceInfo info2;
    info2.bundleName_ = "bundleName";
    info2.moduleName_ = "moduleName2";
    info2.extensionAbilityType_ = static_cast<int32_t>(ExtensionAbilityType::INPUTMETHOD);
    info2.abilityName_ = "AService";
    info2.label_ = "A";
    info2.icon_ = "Aicon";

    bool ans = resourceRdb.AddResourceInfo(info);
    EXPECT_TRUE(ans);
    ans = resourceRdb.AddResourceInfo(info2);
    EXPECT_TRUE(ans);

    std::vector<LauncherAbilityResourceInfo> infos;
    uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    ans = resourceRdb.GetExtensionAbilityResourceInfo(info.bundleName_, ExtensionAbilityType::INPUTMETHOD,
        flags, infos, 0);
    EXPECT_TRUE(ans);
    EXPECT_EQ(infos.size(), 2);
    EXPECT_EQ(infos[0].bundleName, "bundleName");
    EXPECT_EQ(infos[0].moduleName, "moduleName");
    EXPECT_EQ(infos[0].abilityName, "ZService");
    EXPECT_EQ(infos[0].label, "Z");
    EXPECT_EQ(infos[0].icon, "Zicon");
    EXPECT_EQ(infos[1].bundleName, "bundleName");
    EXPECT_EQ(infos[1].moduleName, "moduleName2");
    EXPECT_EQ(infos[1].abilityName, "AService");
    EXPECT_EQ(infos[1].label, "A");
    EXPECT_EQ(infos[1].icon, "Aicon");

    ans = resourceRdb.DeleteResourceInfo(info.GetKey());
    EXPECT_TRUE(ans);
    ans = resourceRdb.DeleteResourceInfo(info2.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0218
 * Function: CheckExtensionAbilityValid
 * @tc.name: test CheckExtensionAbilityValid with non-existent bundle
 * @tc.desc: 1. system running normally
 *           2. test CheckExtensionAbilityValid when bundle does not exist
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0218, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    std::vector<LauncherAbilityResourceInfo> info;
    auto ret = bundleResourceHostImpl->GetExtensionAbilityResourceInfo("non.existent.bundle",
        ExtensionAbilityType::INPUTMETHOD, 0, info, 1);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: BmsBundleResourceTest_0219
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test CheckResourceFlags
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0219, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    uint32_t flag = manager->CheckResourceFlags(
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY));
    EXPECT_EQ(flag, static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY));
}

/**
 * @tc.number: BmsBundleResourceTest_0220
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test IsLauncherAbility
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0220, Function | SmallTest | Level0)
{
    LauncherAbilityResourceInfo resourceInfo;
    resourceInfo.bundleName = "bundleName";
    resourceInfo.moduleName = "moduleName";
    resourceInfo.abilityName = "abilityName";
    AbilityInfo abilityInfo;
    abilityInfo.bundleName = "bundleName";
    abilityInfo.moduleName = "moduleName";
    abilityInfo.name = "abilityName";
    std::vector<AbilityInfo> abilityInfos;
    abilityInfos.push_back(abilityInfo);
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    bool ret = manager->IsLauncherAbility(resourceInfo, abilityInfos);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsBundleResourceTest_0221
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test IsLauncherAbility
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0221, Function | SmallTest | Level0)
{
    LauncherAbilityResourceInfo resourceInfo;
    resourceInfo.bundleName = "";
    resourceInfo.moduleName = "";
    resourceInfo.abilityName = "";
    AbilityInfo abilityInfo;
    abilityInfo.bundleName = "bundleName";
    abilityInfo.moduleName = "moduleName";
    abilityInfo.name = "abilityName";
    std::vector<AbilityInfo> abilityInfos;
    abilityInfos.push_back(abilityInfo);
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    bool ret = manager->IsLauncherAbility(resourceInfo, abilityInfos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BmsBundleResourceTest_0222
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityInfos
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0222, Function | SmallTest | Level0)
{
    std::string bundleName = "";
    std::vector<AbilityInfo> abilityInfos;
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    bool ret = manager->GetLauncherAbilityInfos(bundleName, abilityInfos);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(abilityInfos.size() > 0);
}

/**
 * @tc.number: BmsBundleResourceTest_0223
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityInfos
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0223, Function | SmallTest | Level0)
{
    std::string bundleName = "bundleName";
    std::vector<AbilityInfo> abilityInfos;
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    bool ret = manager->GetLauncherAbilityInfos(bundleName, abilityInfos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BmsBundleResourceTest_0224
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityInfos
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0224, Function | MediumTest | Level1)
{
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    bundleMgrService_->RegisterDataMgr(nullptr);
    std::string bundleName;
    std::vector<AbilityInfo> abilityInfos;
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    bool ret = manager->GetLauncherAbilityInfos(bundleName, abilityInfos);
    EXPECT_FALSE(ret);
    bundleMgrService_->RegisterDataMgr(savedDataMgr);
}

/**
 * @tc.number: BmsBundleResourceTest_0225
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test FilterLauncherAbilityResourceInfoWithFlag
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0225, Function | SmallTest | Level0)
{
    uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    std::string bundleName = "bundleName";
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    bool ret = manager->FilterLauncherAbilityResourceInfoWithFlag(flags, bundleName, launcherAbilityResourceInfos);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsBundleResourceTest_0226
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test FilterLauncherAbilityResourceInfoWithFlag
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0226, Function | SmallTest | Level0)
{
    uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY);
    std::string bundleName = "bundleName";
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    bool ret = manager->FilterLauncherAbilityResourceInfoWithFlag(flags, bundleName, launcherAbilityResourceInfos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BmsBundleResourceTest_0227
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test FilterLauncherAbilityResourceInfoWithFlag
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0227, Function | SmallTest | Level0)
{
    uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY);
    std::string bundleName = "";
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    bool ret = manager->FilterLauncherAbilityResourceInfoWithFlag(flags, bundleName, launcherAbilityResourceInfos);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsBundleResourceTest_0228
 * Function: BundleResourceHostImpl
 * @tc.name: test BundleResourceHostImpl
 * @tc.desc: 1. system running normally
 *           2. test GetAllLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0228, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.abilityName_ = "abilityName";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";

    std::vector<LauncherAbilityResourceInfo> infos;
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    bool ans = manager->bundleResourceRdb_->AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    ans = bundleResourceHostImpl->GetAllLauncherAbilityResourceInfo(
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY), infos);
    EXPECT_EQ(ans, ERR_OK);

    ans = manager->bundleResourceRdb_->DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: BmsBundleResourceTest_0229
 * Function: BundleResourceHostImpl
 * @tc.name: test BundleResourceHostImpl
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0229, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.abilityName_ = "abilityName";
    resourceInfo.label_ = "label";
    resourceInfo.icon_ = "icon";

    std::vector<LauncherAbilityResourceInfo> infos;
    std::string bundleName = "bundleName";
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    bool ans = manager->bundleResourceRdb_->AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ans);
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    setuid(currentUserId * Constants::BASE_USER_RANGE);
    ans = bundleResourceHostImpl->GetLauncherAbilityResourceInfo(bundleName,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY), infos, 0);
    EXPECT_EQ(ans, ERR_OK);
    setuid(Constants::ROOT_UID);
    ans = manager->bundleResourceRdb_->DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: ProcessForegroundIcon_0010
 * Function: ProcessForegroundIcon
 * @tc.name: test ProcessForegroundIcon
 * @tc.desc: 1. system running normally
 *           2. test ProcessForegroundIcon
 */
HWTEST_F(BmsBundleResourceTest, ProcessForegroundIcon_0010, Function | SmallTest | Level0)
{
    std::pair<std::unique_ptr<uint8_t[]>, size_t> foregroundInfo;
    ResourceInfo resourceInfo;
    BundleResourceDrawable drawable;
    bool ret = drawable.ProcessForegroundIcon(foregroundInfo, resourceInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsOnlineTheme_0010
 * Function: IsOnlineTheme
 * @tc.name: test IsOnlineTheme
 * @tc.desc: 1. system running normally
 *           2. test IsOnlineTheme
 */
HWTEST_F(BmsBundleResourceTest, IsOnlineTheme_0010, Function | SmallTest | Level0)
{
    bool isOnlineTheme = BundleResourceProcess::IsOnlineTheme("");
    EXPECT_FALSE(isOnlineTheme);

    std::ofstream file;
    file.open(THEME_FILE_PATH, ios::out);
    file << "{}" << endl;
    file.close();

    isOnlineTheme = BundleResourceProcess::IsOnlineTheme(THEME_FILE_PATH);
    EXPECT_FALSE(isOnlineTheme);
}

/**
 * @tc.number: IsOnlineTheme_0020
 * Function: IsOnlineTheme
 * @tc.name: test IsOnlineTheme
 * @tc.desc: 1. system running normally
 *           2. test IsOnlineTheme
 */
HWTEST_F(BmsBundleResourceTest, IsOnlineTheme_0020, Function | SmallTest | Level0)
{
    std::ofstream file;
    file.open(THEME_FILE_PATH, ios::out);
    file << "{\"origin\":\"preset\"}" << endl;
    file.close();

    bool isOnlineTheme = BundleResourceProcess::IsOnlineTheme(THEME_FILE_PATH);
    EXPECT_FALSE(isOnlineTheme);
}

/**
 * @tc.number: IsOnlineTheme_0030
 * Function: IsOnlineTheme
 * @tc.name: test IsOnlineTheme
 * @tc.desc: 1. system running normally
 *           2. test IsOnlineTheme
 */
HWTEST_F(BmsBundleResourceTest, IsOnlineTheme_0030, Function | SmallTest | Level0)
{
    std::ofstream file;
    file.open(THEME_FILE_PATH, ios::out);
    file << "{\"origin\":\"online\"}" << endl;
    file.close();

    bool isOnlineTheme = BundleResourceProcess::IsOnlineTheme(THEME_FILE_PATH);
    EXPECT_TRUE(isOnlineTheme);
}

/**
 * @tc.number: IsOnlineTheme_0040
 * Function: IsOnlineTheme
 * @tc.name: test IsOnlineTheme
 * @tc.desc: 1. system running normally
 *           2. test IsOnlineTheme
 */
HWTEST_F(BmsBundleResourceTest, IsOnlineTheme_0040, Function | SmallTest | Level0)
{
    std::ofstream file;
    file.open(THEME_FILE_PATH, ios::out);
    file << "{origin" << endl;
    file.close();

    bool isOnlineTheme = BundleResourceProcess::IsOnlineTheme(THEME_FILE_PATH);
    EXPECT_FALSE(isOnlineTheme);
}

/**
 * @tc.number: CheckThemeType_0010
 * Function: CheckThemeType
 * @tc.name: test CheckThemeType
 * @tc.desc: 1. system running normally
 *           2. test CheckThemeType
 */
HWTEST_F(BmsBundleResourceTest, CheckThemeType_0010, Function | SmallTest | Level0)
{
    bool isOnlineTheme = false;
    // theme not exist
    bool ret = BundleResourceProcess::CheckThemeType(BUNDLE_NAME_NOT_EXIST, USERID, isOnlineTheme);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(isOnlineTheme);
}

/**
 * @tc.number: CheckThemeType_0020
 * Function: CheckThemeType
 * @tc.name: test CheckThemeType
 * @tc.desc: 1. system running normally
 *           2. test CheckThemeType
 */
HWTEST_F(BmsBundleResourceTest, CheckThemeType_0020, Function | SmallTest | Level0)
{
    bool isOnlineTheme = false;
    // theme not exist
    bool ret = BundleResourceProcess::CheckThemeType(BUNDLE_NAME_NOT_EXIST, -1, isOnlineTheme);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(isOnlineTheme);
}

/**
 * @tc.number: CheckThemeType_0030
 * Function: CheckThemeType
 * @tc.name: test CheckThemeType
 * @tc.desc: 1. system running normally
 *           2. test CheckThemeType
 */
HWTEST_F(BmsBundleResourceTest, CheckThemeType_0030, Function | SmallTest | Level0)
{
    bool isOnlineTheme = false;
    bool ret = BundleResourceProcess::CheckThemeType(THEME_TEST_BUNDLE_NAME, USERID, isOnlineTheme);
    if (access(THEME_A_FLAG.c_str(), F_OK) == 0) {
        if (access(THEME_A_ICON_MMS.c_str(), F_OK) == 0) {
            EXPECT_TRUE(ret);
        } else {
            EXPECT_FALSE(ret);
        }
    } else {
        if (access(THEME_A_ICON_MMS.c_str(), F_OK) == 0) {
            EXPECT_TRUE(ret);
        } else {
            EXPECT_FALSE(ret);
        }
    }
}

/**
 * @tc.number: CheckThemeType_0040
 * Function: CheckThemeType
 * @tc.name: test CheckThemeType
 * @tc.desc: 1. system running normally
 *           2. test CheckThemeType
 */
HWTEST_F(BmsBundleResourceTest, CheckThemeType_0040, Function | SmallTest | Level0)
{
    OHOS::ForceCreateDirectory(THEME_A_ICON_BUNDLE_NAME);
    OHOS::ForceCreateDirectory(THEME_B_ICON_BUNDLE_NAME);
    // flag not exist
    bool isOnlineTheme = false;
    // theme exist, not exist description.json
    bool ret = BundleResourceProcess::CheckThemeType(BUNDLE_NAME, THEME_TEST_USERID, isOnlineTheme);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(isOnlineTheme);
    OHOS::ForceRemoveDirectory(THEME_BUNDLE_NAME_PATH);
}

/**
 * @tc.number: CheckThemeType_0050
 * Function: CheckThemeType
 * @tc.name: test CheckThemeType
 * @tc.desc: 1. system running normally
 *           2. test CheckThemeType
 */
HWTEST_F(BmsBundleResourceTest, CheckThemeType_0050, Function | SmallTest | Level0)
{
    OHOS::ForceCreateDirectory(THEME_A_ICON_BUNDLE_NAME);
    std::ofstream file;
    file.open(THEME_A_FLAG_BUNDLE_NAME, ios::out);
    file << "" << endl;
    file.close();
    // flag  exist
    bool isOnlineTheme = false;
    // theme exist, not exist description.json
    bool ret = BundleResourceProcess::CheckThemeType(BUNDLE_NAME, THEME_TEST_USERID, isOnlineTheme);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(isOnlineTheme);
    OHOS::ForceRemoveDirectory(THEME_BUNDLE_NAME_PATH);
}

/**
 * @tc.number: CheckThemeType_0060
 * Function: CheckThemeType
 * @tc.name: test CheckThemeType
 * @tc.desc: 1. system running normally
 *           2. test CheckThemeType
 */
HWTEST_F(BmsBundleResourceTest, CheckThemeType_0060, Function | SmallTest | Level0)
{
    OHOS::ForceCreateDirectory(THEME_A_ICON_BUNDLE_NAME);
    std::ofstream file;
    file.open(THEME_A_FLAG_BUNDLE_NAME, ios::out);
    file << "" << endl;
    file.close();
    // flag exist

    // description.json exist
    std::ofstream file2;
    file2.open(THEME_A_ICON_JSON_BUNDLE_NAME, ios::out);
    file2 << "{origin" << endl;
    file2.close();

    bool isOnlineTheme = false;
    // theme exist, description.json exist
    bool ret = BundleResourceProcess::CheckThemeType(BUNDLE_NAME, THEME_TEST_USERID, isOnlineTheme);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(isOnlineTheme);

    file2.open(THEME_A_ICON_JSON_BUNDLE_NAME, ios::out);
    file2 << "{\"origin\":\"online\"}" << endl;
    file2.close();
    OHOS::ForceCreateDirectory(THEME_A_OTHER_ICONS);

    ret = BundleResourceProcess::CheckThemeType(BUNDLE_NAME, THEME_TEST_USERID, isOnlineTheme);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(isOnlineTheme);

    OHOS::ForceRemoveDirectory(THEME_BUNDLE_NAME_PATH);
}

/**
 * @tc.number: CheckThemeType_0070
 * Function: CheckThemeType
 * @tc.name: test CheckThemeType
 * @tc.desc: 1. system running normally
 *           2. test CheckThemeType
 */
HWTEST_F(BmsBundleResourceTest, CheckThemeType_0070, Function | SmallTest | Level0)
{
    OHOS::ForceCreateDirectory(THEME_B_ICON_BUNDLE_NAME);
    // description.json exist
    std::ofstream file2;
    file2.open(THEME_B_ICON_JSON_BUNDLE_NAME, ios::out);
    file2 << "{origin" << endl;
    file2.close();

    bool isOnlineTheme = false;
    // theme exist, description.json exist
    bool ret = BundleResourceProcess::CheckThemeType(BUNDLE_NAME, THEME_TEST_USERID, isOnlineTheme);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(isOnlineTheme);

    file2.open(THEME_B_ICON_JSON_BUNDLE_NAME, ios::out);
    file2 << "{\"origin\":\"online\"}" << endl;
    file2.close();
    isOnlineTheme = false;
    OHOS::ForceCreateDirectory(THEME_B_OTHER_ICONS);
    ret = BundleResourceProcess::CheckThemeType(BUNDLE_NAME, THEME_TEST_USERID, isOnlineTheme);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(isOnlineTheme);

    OHOS::ForceRemoveDirectory(THEME_BUNDLE_NAME_PATH);
}

/**
 * @tc.number: CheckThemeType_0080
 * Function: CheckThemeType
 * @tc.name: test CheckThemeType
 * @tc.desc: 1. system running normally
 *           2. test CheckThemeType
 */
HWTEST_F(BmsBundleResourceTest, CheckThemeType_0080, Function | SmallTest | Level0)
{
    OHOS::ForceCreateDirectory(THEME_B_ICON_BUNDLE_NAME);
    // description.json exist
    std::ofstream file2;
    file2.open(THEME_B_ICON_JSON_BUNDLE_NAME, ios::out);
    file2 << "{origin" << endl;
    file2.close();

    bool isOnlineTheme = false;
    // theme exist, description.json exist
    bool ret = BundleResourceProcess::CheckThemeType(BUNDLE_NAME, THEME_TEST_USERID, isOnlineTheme);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(isOnlineTheme);

    file2.open(THEME_B_ICON_JSON_BUNDLE_NAME, ios::out);
    file2 << "{\"origin\":\"preset\"}" << endl;
    file2.close();

    ret = BundleResourceProcess::CheckThemeType(BUNDLE_NAME, THEME_TEST_USERID, isOnlineTheme);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(isOnlineTheme);

    OHOS::ForceRemoveDirectory(THEME_BUNDLE_NAME_PATH);
}

/**
 * @tc.number: GetDynamicIcon_0010
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test GetDynamicIcon
 */
HWTEST_F(BmsBundleResourceTest, GetDynamicIcon_0010, Function | SmallTest | Level0)
{
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = THEME_TEST_USERID;
    userInfo.curDynamicIconModule = BUNDLE_NAME;
    InnerBundleInfo bundleInfo;
    bundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    bundleInfo.AddInnerBundleUserInfo(userInfo);
    ExtendResourceInfo extendResourceInfo;
    extendResourceInfo.moduleName = BUNDLE_NAME;
    bundleInfo.extendResourceInfos_[BUNDLE_NAME] = extendResourceInfo;

    ResourceInfo resourceInfo;
    resourceInfo.appIndex_ = 0;
    bool ret = BundleResourceProcess::GetDynamicIcon(bundleInfo, THEME_TEST_USERID, resourceInfo);
    EXPECT_FALSE(ret);

    OHOS::ForceCreateDirectory(THEME_A_ICON_BUNDLE_NAME);
    std::ofstream file;
    file.open(THEME_A_FLAG_BUNDLE_NAME, ios::out);
    file << "" << endl;
    file.close();
    ret = BundleResourceProcess::GetDynamicIcon(bundleInfo, THEME_TEST_USERID, resourceInfo);
    EXPECT_FALSE(ret);

    // description.json exist
    std::ofstream file2;
    file2.open(THEME_A_ICON_JSON_BUNDLE_NAME, ios::out);
    file2 << "{\"origin\":\"preset\"}" << endl;
    file2.close();
    ret = BundleResourceProcess::GetDynamicIcon(bundleInfo, THEME_TEST_USERID, resourceInfo);
    EXPECT_FALSE(ret);

    // description.json exist
    file2.open(THEME_A_ICON_JSON_BUNDLE_NAME, ios::out);
    file2 << "{\"origin\":\"online\"}" << endl;
    file2.close();
    ret = BundleResourceProcess::GetDynamicIcon(bundleInfo, THEME_TEST_USERID, resourceInfo);
    EXPECT_FALSE(ret);
    OHOS::ForceRemoveDirectory(THEME_BUNDLE_NAME_PATH);
}

/**
 * @tc.number: IsDynamicIconModuleExist_0010
 * Function: BundleResourceManager
 * @tc.name: test BundleResourceManager
 * @tc.desc: 1. system running normally
 *           2. test IsDynamicIconModuleExist
 */
HWTEST_F(BmsBundleResourceTest, IsDynamicIconModuleExist_0010, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    bool ret = innerBundleInfo.IsDynamicIconModuleExist();
    EXPECT_FALSE(ret);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleInfo.innerBundleUserInfos_["100"] = innerBundleUserInfo;
    ret = innerBundleInfo.IsDynamicIconModuleExist();
    EXPECT_FALSE(ret);

    InnerBundleCloneInfo cloneInfo;
    innerBundleUserInfo.cloneInfos["1"] = cloneInfo;
    innerBundleInfo.innerBundleUserInfos_["100"] = innerBundleUserInfo;
    ret = innerBundleInfo.IsDynamicIconModuleExist();
    EXPECT_FALSE(ret);

    cloneInfo.curDynamicIconModule = "dynamic_icon";
    innerBundleUserInfo.cloneInfos["1"] = cloneInfo;
    innerBundleInfo.innerBundleUserInfos_["100"] = innerBundleUserInfo;
    ret = innerBundleInfo.IsDynamicIconModuleExist();
    EXPECT_TRUE(ret);

    innerBundleUserInfo.curDynamicIconModule = "dynamic_icon";
    innerBundleInfo.innerBundleUserInfos_["100"] = innerBundleUserInfo;
    ret = innerBundleInfo.IsDynamicIconModuleExist();
    EXPECT_TRUE(ret);
}
#endif

/**
 * @tc.number: BmsBundleResourceTest_0178
 * @tc.name: GetBundleResourceInfo
 * @tc.desc: test GetBundleResourceInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0178, Function | SmallTest | Level0)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    EXPECT_NE(bmsExtensionClient, nullptr);

    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    BundleResourceInfo bundleResourceInfo;
    auto ret = bmsExtensionClient->GetBundleResourceInfo(TEST_BUNDLE_NAME,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), bundleResourceInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0179
 * @tc.name: GetLauncherAbilityResourceInfo
 * @tc.desc: test GetLauncherAbilityResourceInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0179, Function | SmallTest | Level0)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    EXPECT_NE(bmsExtensionClient, nullptr);

    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    std::vector<LauncherAbilityResourceInfo> infos;
    auto ret = bmsExtensionClient->GetLauncherAbilityResourceInfo(TEST_BUNDLE_NAME,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), infos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0180
 * @tc.name: GetAllBundleResourceInfo
 * @tc.desc: test GetAllBundleResourceInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0180, Function | SmallTest | Level0)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    EXPECT_NE(bmsExtensionClient, nullptr);

    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    std::vector<BundleResourceInfo> infos;
    auto ret = bmsExtensionClient->GetAllBundleResourceInfo(static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL),
        infos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0181
 * @tc.name: GetBundleResourceInfo
 * @tc.desc: test GetBundleResourceInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0181, Function | SmallTest | Level0)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    EXPECT_NE(bmsExtensionClient, nullptr);

    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    std::vector<LauncherAbilityResourceInfo> infos;
    auto ret = bmsExtensionClient->GetAllLauncherAbilityResourceInfo(
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), infos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0182
 * @tc.name: GetBundleResourceInfo
 * @tc.desc: test GetBundleResourceInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0182, Function | SmallTest | Level0)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    EXPECT_NE(bmsExtensionClient, nullptr);

    BundleResourceInfo bundleResourceInfo;
    auto ret = bmsExtensionClient->GetBundleResourceInfo(TEST_BUNDLE_NAME,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), bundleResourceInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0183
 * @tc.name: GetLauncherAbilityResourceInfo
 * @tc.desc: test GetLauncherAbilityResourceInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0183, Function | SmallTest | Level0)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    EXPECT_NE(bmsExtensionClient, nullptr);

    std::vector<LauncherAbilityResourceInfo> infos;
    auto ret = bmsExtensionClient->GetLauncherAbilityResourceInfo(TEST_BUNDLE_NAME,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), infos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0184
 * @tc.name: GetAllBundleResourceInfo
 * @tc.desc: test GetAllBundleResourceInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0184, Function | SmallTest | Level0)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    EXPECT_NE(bmsExtensionClient, nullptr);

    std::vector<BundleResourceInfo> infos;
    auto ret = bmsExtensionClient->GetAllBundleResourceInfo(static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL),
        infos);
#ifdef USE_EXTENSION_DATA
    EXPECT_EQ(ret, ERR_OK);
#else
    EXPECT_NE(ret, ERR_OK);
#endif
}

/**
 * @tc.number: BmsBundleResourceTest_0185
 * @tc.name: GetAllLauncherAbilityResourceInfo
 * @tc.desc: test GetAllLauncherAbilityResourceInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0185, Function | SmallTest | Level0)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    EXPECT_NE(bmsExtensionClient, nullptr);

    std::vector<LauncherAbilityResourceInfo> infos;
    auto ret = bmsExtensionClient->GetAllLauncherAbilityResourceInfo(
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), infos);
#ifdef USE_EXTENSION_DATA
    EXPECT_EQ(ret, ERR_OK);
#else
    EXPECT_NE(ret, ERR_OK);
#endif
}

/**
 * @tc.number: BmsBundleResourceTest_0252
 * @tc.name: GetLauncherAbilityResourceInfo
 * @tc.desc: 1. test GetLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0252, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    ASSERT_NE(manager, nullptr);

    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    setuid(currentUserId * Constants::BASE_USER_RANGE);

    uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR);
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfo;
    auto ret = manager->GetLauncherAbilityResourceInfo(BUNDLE_NAME, flags,
        launcherAbilityResourceInfo, 0);
    EXPECT_TRUE(ret);

    setuid(Constants::ROOT_UID);
    ret = manager->GetLauncherAbilityResourceInfo(BUNDLE_NAME, flags,
        launcherAbilityResourceInfo, 0);
    EXPECT_TRUE(ret);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0253
 * @tc.name: SetUserId
 * @tc.desc: 1. test SetUserId
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0253, Function | SmallTest | Level0)
{
    BundleResourceCallback callback;
    callback.SetUserId(100);
    std::string path = std::string(BundleResourceConstants::BUNDLE_RESOURCE_RDB_PATH) +
        std::string(BundleResourceConstants::USER_FILE_NAME);
    auto ret = access(path.c_str(), F_OK);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: BmsBundleResourceTest_0254
 * @tc.name: CheckUserSwitchWhenReboot
 * @tc.desc: 1. test CheckUserSwitchWhenReboot
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0254, Function | SmallTest | Level0)
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    OHOS::EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    auto subscriberPtr = std::make_shared<BundleResourceEventSubscriber>(subscribeInfo);
    ASSERT_NE(subscriberPtr, nullptr);

    BundleResourceCallback callback;
    callback.SetUserId(100);

    int32_t oldUserId = 0;
    int32_t userId = 200;
    subscriberPtr->CheckUserSwitchWhenReboot(userId, oldUserId);
    EXPECT_EQ(oldUserId, 100);

    userId = 100;
    bool ret = subscriberPtr->CheckUserSwitchWhenReboot(userId, oldUserId);
    EXPECT_EQ(ret, false);
    std::string path = std::string(BundleResourceConstants::BUNDLE_RESOURCE_RDB_PATH) +
        std::string(BundleResourceConstants::USER_FILE_NAME);
    OHOS::ForceRemoveDirectory(path);
    ret = subscriberPtr->CheckUserSwitchWhenReboot(userId, oldUserId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundleResourceTest_0255
 * @tc.name: DeleteConfigInFile and SetConfigInFile
 * @tc.desc: 1. test DeleteConfigInFile and SetConfigInFile
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0255, Function | SmallTest | Level0)
{
    std::string path = std::string(BundleResourceConstants::BUNDLE_RESOURCE_RDB_PATH) +
        std::string(BundleResourceConstants::USER_FILE_NAME);
    OHOS::RemoveFile(path);

    BundleResourceCallback callback;
    int32_t userId = AccountHelper::GetCurrentActiveUserId();
    callback.DeleteConfigInFile(userId, 0);
    BundleResourceHelper::ProcessBundleResourceChange();

    std::string language = BundleSystemState::GetInstance().GetSystemLanguage();
    callback.SetConfigInFile(language, "", 0, 0, 1, userId);
    BundleResourceHelper::ProcessBundleResourceChange();
    callback.DeleteConfigInFile(userId + 1, 1);
    callback.DeleteConfigInFile(userId, 1);

    nlohmann::json jsonBuf;
    if (!BundleParser::ReadFileIntoJson(path, jsonBuf)) {
        APP_LOGW("read user file failed, errno %{public}d", errno);
    }
    EXPECT_TRUE(jsonBuf.empty());

    callback.SetConfigInFile("", "theme", 1, 1, 16, userId);
    BundleResourceHelper::ProcessBundleResourceChange();
    callback.DeleteConfigInFile(userId, 16);
    if (!BundleParser::ReadFileIntoJson(path, jsonBuf)) {
        APP_LOGW("read user file failed, errno %{public}d", errno);
    }
    EXPECT_TRUE(jsonBuf.empty());
    callback.SetConfigInFile("", "", 0, 0, 0, userId);
    callback.DeleteConfigInFile(userId, 0);
}

/**
 * @tc.number: BmsBundleResourceTest_0256
 * Function: BundleResourceProcess
 * @tc.name: test BundleResourceProcess
 * @tc.desc: 1. system running normally
 *           2. test GetResourceInfoByBundleName
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0256, Function | SmallTest | Level0)
{
    std::vector<ResourceInfo> resourceInfos;
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    InnerBundleInfo bundleInfo;
    bundleInfo.innerBundleUserInfos_["_100"] = userInfo;
    bundleInfo.SetApplicationBundleType(BundleType::ATOMIC_SERVICE);
    savedDataMgr->bundleInfos_["bundle_test"] = bundleInfo;

    bool ans = BundleResourceProcess::GetResourceInfoByBundleName("bundle_test", USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());

    bundleInfo.SetApplicationBundleType(BundleType::SHARED);
    savedDataMgr->bundleInfos_["bundle_test"] = bundleInfo;
    ans = BundleResourceProcess::GetResourceInfoByBundleName("bundle_test", USERID, resourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(resourceInfos.empty());
    auto iter = savedDataMgr->bundleInfos_.find("bundle_test");
    if (iter != savedDataMgr->bundleInfos_.end()) {
        savedDataMgr->bundleInfos_.erase(iter);
    }
}

/**
 * @tc.number: BmsBundleResourceTest_0257
 * Function: GetAllResourceInfo
 * @tc.name: test GetAllResourceInfo
 * @tc.desc: 1. system running normally
 *           2. test GetAllResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0257, Function | SmallTest | Level0)
{
    std::map<std::string, std::vector<ResourceInfo>> resourceInfosMap;
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    InnerBundleInfo bundleInfo;
    bundleInfo.innerBundleUserInfos_["_100"] = userInfo;
    bundleInfo.SetApplicationBundleType(BundleType::ATOMIC_SERVICE);
    savedDataMgr->bundleInfos_["bundle_test"] = bundleInfo;

    bool ans = BundleResourceProcess::GetAllResourceInfo(USERID, resourceInfosMap);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(resourceInfosMap.empty());
    auto iter = savedDataMgr->bundleInfos_.find("bundle_test");
    if (iter != savedDataMgr->bundleInfos_.end()) {
        savedDataMgr->bundleInfos_.erase(iter);
    }
}

/**
 * @tc.number: BmsBundleResourceTest_0258
 * Function: SetConfigInFile
 * @tc.name: test SetConfigInFile
 * @tc.desc: 1. system running normally
 *           2. test SetConfigInFile
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0258, Function | SmallTest | Level0)
{
    std::string path = std::string(BundleResourceConstants::BUNDLE_RESOURCE_RDB_PATH) +
        std::string(BundleResourceConstants::USER_FILE_NAME);
    OHOS::RemoveFile(path);

    BundleResourceCallback callback;
    callback.SetConfigInFile("", "", 0, 0, 0, 0);
    nlohmann::json jsonBuf;
    if (!BundleParser::ReadFileIntoJson(path, jsonBuf)) {
        APP_LOGW("read user file failed, errno %{public}d", errno);
    }
    EXPECT_TRUE(jsonBuf.is_null());

    std::string notJson = R"({"test1": "123", "test2":})";
    std::ofstream file;
    file.open(path, ios::out);
    file << notJson;
    file.close();
    callback.SetConfigInFile("", "", 0, 0, 0, 0);
    if (!BundleParser::ReadFileIntoJson(path, jsonBuf)) {
        APP_LOGW("read user file failed, errno %{public}d", errno);
    }
    EXPECT_TRUE(jsonBuf.is_discarded());
    OHOS::RemoveFile(path);
}

/**
 * @tc.number: GetExtendResourceInfo_0001
 * Function: GetExtendResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetExtendResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, GetExtendResourceInfo_0001, Function | SmallTest | Level0)
{
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ExtendResourceInfo resourceInfo;
    ErrCode ret = savedDataMgr->GetExtendResourceInfo(BUNDLE_NAME_NOT_EXIST, BUNDLE_NAME_NOT_EXIST, resourceInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    InnerBundleInfo bundleInfo;
    savedDataMgr->bundleInfos_[BUNDLE_NAME_NOT_EXIST] = bundleInfo;
    ret = savedDataMgr->GetExtendResourceInfo(BUNDLE_NAME_NOT_EXIST, BUNDLE_NAME_NOT_EXIST, resourceInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);

    ExtendResourceInfo extendResourceInfo;
    extendResourceInfo.iconId = 100;
    bundleInfo.extendResourceInfos_[BUNDLE_NAME_NOT_EXIST] = extendResourceInfo;
    savedDataMgr->bundleInfos_[BUNDLE_NAME_NOT_EXIST] = bundleInfo;
    ret = savedDataMgr->GetExtendResourceInfo(BUNDLE_NAME_NOT_EXIST, BUNDLE_NAME_NOT_EXIST, resourceInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(resourceInfo.iconId, extendResourceInfo.iconId);

    auto iter = savedDataMgr->bundleInfos_.find(BUNDLE_NAME_NOT_EXIST);
    if (iter != savedDataMgr->bundleInfos_.end()) {
        savedDataMgr->bundleInfos_.erase(iter);
    }
}

/**
 * @tc.number: GetDynamicIconResourceInfo_0001
 * Function: GetDynamicIconResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetDynamicIconResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, GetDynamicIconResourceInfo_0001, Function | SmallTest | Level0)
{
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    DelayedSingleton<BundleMgrService>::GetInstance()->RegisterDataMgr(nullptr);
    ResourceInfo resourceInfo;
    bool ret = BundleResourceProcess::GetDynamicIconResourceInfo(BUNDLE_NAME_NOT_EXIST, BUNDLE_NAME_NOT_EXIST,
        resourceInfo);
    EXPECT_FALSE(ret);
    DelayedSingleton<BundleMgrService>::GetInstance()->RegisterDataMgr(savedDataMgr);
    ret = BundleResourceProcess::GetDynamicIconResourceInfo(BUNDLE_NAME_NOT_EXIST, BUNDLE_NAME_NOT_EXIST,
        resourceInfo);
    EXPECT_FALSE(ret);

    ExtendResourceInfo extendResourceInfo;
    extendResourceInfo.iconId = 100;
    InnerBundleInfo bundleInfo;
    bundleInfo.extendResourceInfos_[BUNDLE_NAME_NOT_EXIST] = extendResourceInfo;
    savedDataMgr->bundleInfos_[BUNDLE_NAME_NOT_EXIST] = bundleInfo;
    ret = BundleResourceProcess::GetDynamicIconResourceInfo(BUNDLE_NAME_NOT_EXIST, BUNDLE_NAME_NOT_EXIST,
        resourceInfo);
    EXPECT_FALSE(ret);
    auto iter = savedDataMgr->bundleInfos_.find(BUNDLE_NAME_NOT_EXIST);
    if (iter != savedDataMgr->bundleInfos_.end()) {
        savedDataMgr->bundleInfos_.erase(iter);
    }
}

/**
 * @tc.number: ParseResourceInfosNoTheme_0010
 * Function: ParseResourceInfosNoTheme
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test ParseResourceInfosNoTheme
 */
HWTEST_F(BmsBundleResourceTest, ParseResourceInfosNoTheme_0010, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    std::vector<ResourceInfo> resourceInfos;
    bool ans = BundleResourceProcess::GetResourceInfoByBundleName(BUNDLE_NAME, USERID, resourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(resourceInfos.empty());

    if (!resourceInfos.empty()) {
        BundleResourceParser parser;
        resourceInfos[0].label_ = "";
        resourceInfos[0].icon_ = "";
        ans = parser.ParseResourceInfosNoTheme(USERID, resourceInfos);
        EXPECT_TRUE(ans);
        EXPECT_NE(resourceInfos[0].label_, "");
        EXPECT_NE(resourceInfos[0].icon_, "");
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: ParseResourceInfosNoTheme_0020
 * Function: ParseResourceInfosNoTheme
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test ParseResourceInfosNoTheme
 */
HWTEST_F(BmsBundleResourceTest, ParseResourceInfosNoTheme_0020, Function | SmallTest | Level0)
{
    std::vector<ResourceInfo> resourceInfos;
    BundleResourceParser parser;
    bool ans = parser.ParseResourceInfosNoTheme(USERID, resourceInfos);
    EXPECT_FALSE(ans);
    ResourceInfo resourceInfo;
    resourceInfo.labelNeedParse_ = false;
    resourceInfo.iconNeedParse_ = false;
    resourceInfos.push_back(resourceInfo);
    ans = parser.ParseResourceInfosNoTheme(USERID, resourceInfos);
    EXPECT_TRUE(ans);
    resourceInfo.labelNeedParse_ = true;
    resourceInfos.clear();
    resourceInfos.push_back(resourceInfo);
    ans = parser.ParseResourceInfosNoTheme(USERID, resourceInfos);
    EXPECT_FALSE(ans);
    resourceInfo.iconNeedParse_ = true;
    resourceInfos.clear();
    resourceInfos.push_back(resourceInfo);
    ans = parser.ParseResourceInfosNoTheme(USERID, resourceInfos);
    EXPECT_FALSE(ans);

    resourceInfos.push_back(resourceInfo);
    ans = parser.ParseResourceInfosNoTheme(USERID, resourceInfos);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: ParseResourceInfosWithTheme_0010
 * Function: ParseResourceInfosWithTheme
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test ParseResourceInfosWithTheme
 */
HWTEST_F(BmsBundleResourceTest, ParseResourceInfosWithTheme_0010, Function | SmallTest | Level0)
{
    std::vector<ResourceInfo> resourceInfos;
    BundleResourceParser parser;
    bool ans = parser.ParseIconResourceInfosWithTheme(USERID, resourceInfos);
    EXPECT_FALSE(ans);

    ResourceInfo resourceInfo;
    resourceInfos.push_back(resourceInfo);
    ans = parser.ParseIconResourceInfosWithTheme(USERID, resourceInfos);
    EXPECT_FALSE(ans);

    resourceInfo.icon_ = "icon";
    resourceInfos.push_back(resourceInfo);
    ans = parser.ParseIconResourceInfosWithTheme(USERID, resourceInfos);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: InnerGetResourceInfo_0010
 * Function: InnerGetResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test InnerGetResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, InnerGetResourceInfo_0010, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    std::vector<ResourceInfo> resourceInfos;
    bool ret = BundleResourceProcess::InnerGetResourceInfo(innerBundleInfo, USERID, resourceInfos, 0, true);
    EXPECT_FALSE(ret);

    innerBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    ret = BundleResourceProcess::InnerGetResourceInfo(innerBundleInfo, USERID, resourceInfos, 0, true);
    EXPECT_TRUE(ret);

    std::vector<ResourceInfo> resourceInfos2;
    ret = BundleResourceProcess::InnerGetResourceInfo(innerBundleInfo, USERID, resourceInfos2, 0, false);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetBundleResourceInfoForCloneBundle_0010
 * Function: GetBundleResourceInfoForCloneBundle
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetBundleResourceInfoForCloneBundle
 */
HWTEST_F(BmsBundleResourceTest, GetBundleResourceInfoForCloneBundle_0010, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::vector<ResourceInfo> resourceInfos;
        bool ans = manager->GetBundleResourceInfoForCloneBundle(BUNDLE_NAME_NOT_EXIST, 1,
            static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE), resourceInfos);
        EXPECT_FALSE(ans);
        ResourceInfo info;
        info.bundleName_ = BUNDLE_NAME_NOT_EXIST;
        info.label_ = "label";
        info.icon_ = "icon";
        BundleResourceRdb resourceRdb;
        ans = resourceRdb.AddResourceInfo(info);
        EXPECT_TRUE(ans);
        std::vector<ResourceInfo> resourceInfos2;
        ans = manager->GetBundleResourceInfoForCloneBundle(BUNDLE_NAME_NOT_EXIST, 1,
            static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE), resourceInfos2);
        EXPECT_TRUE(ans);
        EXPECT_EQ(resourceInfos2.size(), 1);

        info.moduleName_ = BUNDLE_NAME_NOT_EXIST;
        info.abilityName_ = BUNDLE_NAME_NOT_EXIST;
        info.label_ = "label";
        info.icon_ = "icon";
        ans = resourceRdb.AddResourceInfo(info);
        EXPECT_TRUE(ans);
        std::vector<ResourceInfo> resourceInfos3;
        ans = manager->GetBundleResourceInfoForCloneBundle(BUNDLE_NAME_NOT_EXIST, 1,
            static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE), resourceInfos3);
        EXPECT_TRUE(ans);
        EXPECT_EQ(resourceInfos3.size(), 2);

        ans = resourceRdb.DeleteResourceInfo(BUNDLE_NAME_NOT_EXIST);
        EXPECT_TRUE(ans);
    }
}

/**
 * @tc.number: AddResourceInfoByBundleNameWhenInstall_0010
 * Function: AddResourceInfoByBundleNameWhenInstall
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfoByBundleNameWhenInstall
 */
HWTEST_F(BmsBundleResourceTest, AddResourceInfoByBundleNameWhenInstall_0010, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        bool ret = manager->AddResourceInfoByBundleNameWhenInstall(BUNDLE_NAME_NOT_EXIST, USERID, true);
        EXPECT_FALSE(ret);
        ret = manager->AddResourceInfoByBundleNameWhenInstall(BUNDLE_NAME, USERID, true);
        EXPECT_TRUE(ret);
        ret = manager->AddResourceInfoByBundleNameWhenInstall(BUNDLE_NAME, USERID, false);
        EXPECT_TRUE(ret);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: AddResourceInfoByBundleNameWhenUpdate_0010
 * Function: AddResourceInfoByBundleNameWhenUpdate
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfoByBundleNameWhenUpdate
 */
HWTEST_F(BmsBundleResourceTest, AddResourceInfoByBundleNameWhenUpdate_0010, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        bool ret = manager->AddResourceInfoByBundleNameWhenUpdate(BUNDLE_NAME_NOT_EXIST, USERID);
        EXPECT_FALSE(ret);
        ret = manager->AddResourceInfoByBundleNameWhenUpdate(BUNDLE_NAME, USERID);
        EXPECT_TRUE(ret);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: ProcessCloneBundleResourceInfo_0010
 * Function: ProcessCloneBundleResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test ProcessCloneBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, ProcessCloneBundleResourceInfo_0010, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        bool ret = manager->ProcessCloneBundleResourceInfo(BUNDLE_NAME_NOT_EXIST, 1);
        EXPECT_FALSE(ret);
        ret = manager->ProcessCloneBundleResourceInfo(BUNDLE_NAME, 1);
        EXPECT_TRUE(ret);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: AddResourceInfoByBundleNameWhenCreateUser_0010
 * Function: AddResourceInfoByBundleNameWhenCreateUser
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfoByBundleNameWhenCreateUser
 */
HWTEST_F(BmsBundleResourceTest, AddResourceInfoByBundleNameWhenCreateUser_0010, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        bool ret = manager->AddResourceInfoByBundleNameWhenCreateUser(BUNDLE_NAME_NOT_EXIST, 100);
        EXPECT_TRUE(ret);
        OHOS::ForceCreateDirectory(THEME_B_ICON_BUNDLE_NAME);
        ret = manager->AddResourceInfoByBundleNameWhenCreateUser(BUNDLE_NAME, THEME_TEST_USERID);
        EXPECT_FALSE(ret);
        OHOS::ForceRemoveDirectory(THEME_BUNDLE_NAME_PATH);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: AddResourceInfoByBundleNameWhenCreateUser_0020
 * Function: AddResourceInfoByBundleNameWhenCreateUser
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfoByBundleNameWhenCreateUser
 */
HWTEST_F(BmsBundleResourceTest, AddResourceInfoByBundleNameWhenCreateUser_0020, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        OHOS::ForceCreateDirectory(THEME_B_ICON_BUNDLE_NAME);
        bool ret = manager->AddResourceInfoByBundleNameWhenCreateUser(BUNDLE_NAME, THEME_TEST_USERID);
        EXPECT_FALSE(ret);
        OHOS::ForceRemoveDirectory(THEME_BUNDLE_NAME_PATH);
    }
}

/**
 * @tc.number: DeleteBundleResourceInfo_0010
 * Function: DeleteBundleResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test DeleteBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, DeleteBundleResourceInfo_0010, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        bool ret = manager->DeleteBundleResourceInfo(BUNDLE_NAME_NOT_EXIST, USERID, false);
        EXPECT_TRUE(ret);
        ret = manager->DeleteBundleResourceInfo(BUNDLE_NAME_NOT_EXIST, USERID, true);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: AddDynamicIconResource_0010
 * Function: AddDynamicIconResource
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddDynamicIconResource
 */
HWTEST_F(BmsBundleResourceTest, AddDynamicIconResource_0010, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        ResourceInfo resourceInfo;
        bool ret = manager->AddDynamicIconResource(BUNDLE_NAME_NOT_EXIST, USERID, 0, resourceInfo);
        EXPECT_TRUE(ret);
        ret = manager->DeleteDynamicIconResource(BUNDLE_NAME_NOT_EXIST, USERID, 0);
        EXPECT_TRUE(ret);

        ret = manager->AddDynamicIconResource(BUNDLE_NAME_NOT_EXIST, Constants::UNSPECIFIED_USERID, 0, resourceInfo);
        EXPECT_TRUE(ret);
        ret = manager->DeleteDynamicIconResource(BUNDLE_NAME_NOT_EXIST, Constants::UNSPECIFIED_USERID, 0);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: AddDynamicIconResource_0020
 * Function: AddDynamicIconResource
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddDynamicIconResource
 */
HWTEST_F(BmsBundleResourceTest, AddDynamicIconResource_0020, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        ResourceInfo resourceInfo;
        resourceInfo.icon_ = "111";
        bool ret = manager->AddDynamicIconResource(BUNDLE_NAME_NOT_EXIST, USERID, 1, resourceInfo);
        EXPECT_TRUE(ret);
        ret = manager->DeleteDynamicIconResource(BUNDLE_NAME_NOT_EXIST, USERID, 1);
        EXPECT_TRUE(ret);

        BundleResourceRdb resourceRdb;
        BundleResourceInfo info;
        ret = manager->GetBundleResourceInfo(BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), info);
        EXPECT_TRUE(ret);
        resourceInfo.icon_ = info.icon;
        ret = manager->AddDynamicIconResource(BUNDLE_NAME_NOT_EXIST, USERID, 2, resourceInfo);
        EXPECT_TRUE(ret);
        ret = manager->DeleteDynamicIconResource(BUNDLE_NAME_NOT_EXIST, USERID, 2);
        EXPECT_TRUE(ret);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: AddDynamicIconResource_0030
 * Function: AddDynamicIconResource
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddDynamicIconResource
 */
HWTEST_F(BmsBundleResourceTest, AddDynamicIconResource_0030, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    InnerBundleCloneInfo innerBundleCloneInfo;
    innerBundleCloneInfo.appIndex = 1;
    innerBundleCloneInfo.userId = USERID;
    innerBundleUserInfo.cloneInfos["1"] = innerBundleCloneInfo;
    InnerBundleInfo bundleInfo;
    bundleInfo.innerBundleUserInfos_["_100"] = innerBundleUserInfo;
    savedDataMgr->bundleInfos_[BUNDLE_NAME_NOT_EXIST] = bundleInfo;
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        ResourceInfo resourceInfo;
        resourceInfo.icon_ = "111";
        bool ret = manager->AddDynamicIconResource(BUNDLE_NAME_NOT_EXIST, Constants::UNSPECIFIED_USERID, 0,
            resourceInfo);
        EXPECT_TRUE(ret);
        ret = manager->DeleteDynamicIconResource(BUNDLE_NAME_NOT_EXIST, Constants::UNSPECIFIED_USERID, 0);
        EXPECT_TRUE(ret);

        BundleResourceRdb resourceRdb;
        BundleResourceInfo info;
        ret = manager->GetBundleResourceInfo(BUNDLE_NAME,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), info);
        EXPECT_TRUE(ret);
        resourceInfo.icon_ = info.icon;
        ret = manager->AddDynamicIconResource(BUNDLE_NAME_NOT_EXIST, Constants::UNSPECIFIED_USERID, 0, resourceInfo);
        EXPECT_TRUE(ret);
        ret = manager->DeleteDynamicIconResource(BUNDLE_NAME_NOT_EXIST, Constants::UNSPECIFIED_USERID, 0);
        EXPECT_TRUE(ret);
    }

    auto iter = savedDataMgr->bundleInfos_.find(BUNDLE_NAME_NOT_EXIST);
    if (iter != savedDataMgr->bundleInfos_.end()) {
        savedDataMgr->bundleInfos_.erase(iter);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: ParserCloneResourceInfo_0010
 * Function: ParserCloneResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test ParserCloneResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, ParserCloneResourceInfo_0010, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    ResourceInfo resourceInfo;
    BundleResourceParser bundleResourceParser;
    bool ret = bundleResourceParser.ParserCloneResourceInfo(0, resourceInfo);
    EXPECT_FALSE(ret);

    resourceInfo.icon_ = "111";
    ret = bundleResourceParser.ParserCloneResourceInfo(1, resourceInfo);
    EXPECT_FALSE(ret);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        BundleResourceInfo info;
        ret = manager->GetBundleResourceInfo(BUNDLE_NAME,
                static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), info);
        EXPECT_TRUE(ret);
        resourceInfo.icon_ = info.icon;
    }

    ret = bundleResourceParser.ParserCloneResourceInfo(2, resourceInfo);
    EXPECT_TRUE(ret);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: AddAllResourceInfo_0010
 * Function: AddAllResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddAllResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, AddAllResourceInfo_0010, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        bool ret = manager->AddAllResourceInfo(THEME_TEST_USERID, 0);
        EXPECT_FALSE(ret);

        ret = manager->AddAllResourceInfo(USERID, 0);
        EXPECT_TRUE(ret);

        ret = manager->AddAllResourceInfo(USERID,
            static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE));
        EXPECT_TRUE(ret);

        ret = manager->AddAllResourceInfo(USERID,
            static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE));
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: AddResourceInfosWhenSystemLanguageChanged_0010
 * Function: AddResourceInfosWhenSystemLanguageChanged
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfosWhenSystemLanguageChanged
 */
HWTEST_F(BmsBundleResourceTest, AddResourceInfosWhenSystemLanguageChanged_0010, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::map<std::string, std::vector<ResourceInfo>> resourceInfosMap;
        bool ret = manager->AddResourceInfosWhenSystemLanguageChanged(resourceInfosMap, USERID, 0);
        EXPECT_FALSE(ret);
        ResourceInfo resourceInfo;
        resourceInfosMap[BUNDLE_NAME].push_back(resourceInfo);
        manager->currentTaskNum_ = 100;
        manager->currentChangeType_ = static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE);
        ret = manager->AddResourceInfosWhenSystemLanguageChanged(resourceInfosMap, USERID, 6000000);
        EXPECT_FALSE(ret);

        manager->currentChangeType_ = static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE);
        ret = manager->AddResourceInfosWhenSystemLanguageChanged(resourceInfosMap, USERID, 6000000);
        EXPECT_TRUE(ret);

        ret = manager->AddResourceInfosWhenSystemLanguageChanged(resourceInfosMap, USERID, 100);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: ProcessCloneBundleResourceInfoWhenSystemLanguageChanged_0010
 * Function: ProcessCloneBundleResourceInfoWhenSystemLanguageChanged
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test ProcessCloneBundleResourceInfoWhenSystemLanguageChanged
 */
HWTEST_F(BmsBundleResourceTest, ProcessCloneBundleResourceInfoWhenSystemLanguageChanged_0010,
    Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        bool ret = manager->ProcessCloneBundleResourceInfoWhenSystemLanguageChanged(BUNDLE_NAME, USERID, 0);
        EXPECT_FALSE(ret);

        ret = manager->ProcessCloneBundleResourceInfoWhenSystemLanguageChanged(BUNDLE_NAME_NOT_EXIST, USERID, 1);
        EXPECT_FALSE(ret);

        ret = manager->ProcessCloneBundleResourceInfoWhenSystemLanguageChanged(BUNDLE_NAME, USERID, 1);
        EXPECT_TRUE(ret);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: AddResourceInfosWhenSystemThemeChanged_0010
 * Function: AddResourceInfosWhenSystemThemeChanged
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfosWhenSystemThemeChanged
 */
HWTEST_F(BmsBundleResourceTest, AddResourceInfosWhenSystemThemeChanged_0010, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::map<std::string, std::vector<ResourceInfo>> resourceInfosMap;
        bool ret = manager->AddResourceInfosWhenSystemThemeChanged(resourceInfosMap, USERID, 0);
        EXPECT_FALSE(ret);
        OHOS::ForceCreateDirectory(THEME_B_ICON_BUNDLE_NAME);
        ResourceInfo resourceInfo;
        resourceInfosMap[BUNDLE_NAME].push_back(resourceInfo);
        manager->currentTaskNum_ = 100;
        manager->currentChangeType_ = static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE);
        ret = manager->AddResourceInfosWhenSystemThemeChanged(resourceInfosMap, THEME_TEST_USERID, 1000000);
        EXPECT_FALSE(ret);

        manager->currentChangeType_ = static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE);
        ret = manager->AddResourceInfosWhenSystemThemeChanged(resourceInfosMap, THEME_TEST_USERID, 1000000);
        EXPECT_TRUE(ret);

        ret = manager->AddResourceInfosWhenSystemThemeChanged(resourceInfosMap, THEME_TEST_USERID, 100);
        EXPECT_TRUE(ret);
        OHOS::ForceRemoveDirectory(THEME_BUNDLE_NAME_PATH);
    }
}

/**
 * @tc.number: ProcessCloneBundleResourceInfoWhenSystemThemeChanged_0010
 * Function: ProcessCloneBundleResourceInfoWhenSystemThemeChanged
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test ProcessCloneBundleResourceInfoWhenSystemThemeChanged
 */
HWTEST_F(BmsBundleResourceTest, ProcessCloneBundleResourceInfoWhenSystemThemeChanged_0010,
    Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        bool ret = manager->ProcessCloneBundleResourceInfoWhenSystemThemeChanged(BUNDLE_NAME_NOT_EXIST, USERID, 1);
        EXPECT_FALSE(ret);

        ret = manager->ProcessCloneBundleResourceInfoWhenSystemThemeChanged(BUNDLE_NAME, USERID, 1);
        EXPECT_FALSE(ret);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: InnerProcessResourceInfoBySystemThemeChanged_0010
 * Function: InnerProcessResourceInfoBySystemThemeChanged
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test InnerProcessResourceInfoBySystemThemeChanged
 */
HWTEST_F(BmsBundleResourceTest, InnerProcessResourceInfoBySystemThemeChanged_0010, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::map<std::string, std::vector<ResourceInfo>> resourceInfosMap;
        ResourceInfo resourceInfo;
        resourceInfosMap[BUNDLE_NAME_NOT_EXIST].push_back(resourceInfo);
        resourceInfosMap[BUNDLE_NAME].push_back(resourceInfo);
        resourceInfosMap[MODULE_NAME].clear();
        OHOS::ForceCreateDirectory(THEME_B_ICON_BUNDLE_NAME);
        manager->InnerProcessResourceInfoBySystemThemeChanged(resourceInfosMap, THEME_TEST_USERID);
        EXPECT_EQ(resourceInfosMap.size(), 1);
        OHOS::ForceRemoveDirectory(THEME_BUNDLE_NAME_PATH);
    }
}

/**
 * @tc.number: AddCloneBundleResourceInfoWhenInstall_0010
 * Function: AddCloneBundleResourceInfoWhenInstall
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddCloneBundleResourceInfoWhenInstall
 */
HWTEST_F(BmsBundleResourceTest, AddCloneBundleResourceInfoWhenInstall_0010, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        bool ret = manager->AddCloneBundleResourceInfoWhenInstall(BUNDLE_NAME_NOT_EXIST, USERID, 1, false);
        EXPECT_FALSE(ret);
        ret = manager->AddCloneBundleResourceInfoWhenInstall(BUNDLE_NAME, USERID, 1, false);
        EXPECT_TRUE(ret);
        ret = manager->DeleteCloneBundleResourceInfoWhenUninstall(BUNDLE_NAME, USERID, 1, false);
        EXPECT_TRUE(ret);
        OHOS::ForceCreateDirectory(THEME_B_ICON_BUNDLE_NAME);
        ret = manager->AddCloneBundleResourceInfoWhenInstall(BUNDLE_NAME, USERID, 2, false);
        EXPECT_TRUE(ret);
        ret = manager->DeleteCloneBundleResourceInfoWhenUninstall(BUNDLE_NAME, USERID, 2, false);
        EXPECT_TRUE(ret);
        OHOS::ForceRemoveDirectory(THEME_BUNDLE_NAME_PATH);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: DeleteCloneBundleResourceInfoWhenUninstall_0010
 * Function: DeleteCloneBundleResourceInfoWhenUninstall
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test DeleteCloneBundleResourceInfoWhenUninstall
 */
HWTEST_F(BmsBundleResourceTest, DeleteCloneBundleResourceInfoWhenUninstall_0010, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        bool ret = manager->DeleteCloneBundleResourceInfoWhenUninstall(BUNDLE_NAME_NOT_EXIST, USERID, 1, false);
        EXPECT_TRUE(ret);
        ret = manager->DeleteCloneBundleResourceInfoWhenUninstall(BUNDLE_NAME_NOT_EXIST, USERID, 1, true);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: IsNeedProcessResourceIconInfo_0010
 * Function: IsNeedProcessResourceIconInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test IsNeedProcessResourceIconInfo
 */
HWTEST_F(BmsBundleResourceTest, IsNeedProcessResourceIconInfo_0010, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        uint32_t resourceFlags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
        bool ret = manager->IsNeedProcessResourceIconInfo(resourceFlags);
        EXPECT_TRUE(ret);

        resourceFlags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL);
        ret = manager->IsNeedProcessResourceIconInfo(resourceFlags);
        EXPECT_FALSE(ret);

        resourceFlags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON);
        ret = manager->IsNeedProcessResourceIconInfo(resourceFlags);
        EXPECT_TRUE(ret);

        resourceFlags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR);
        ret = manager->IsNeedProcessResourceIconInfo(resourceFlags);
        EXPECT_TRUE(ret);

        resourceFlags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_SORTED_BY_LABEL);
        ret = manager->IsNeedProcessResourceIconInfo(resourceFlags);
        EXPECT_FALSE(ret);

        resourceFlags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY);
        ret = manager->IsNeedProcessResourceIconInfo(resourceFlags);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: GetUserId_0010
 * Function: GetUserId
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetUserId
 */
HWTEST_F(BmsBundleResourceTest, GetUserId_0010, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        auto userId = manager->GetUserId();
        EXPECT_EQ(userId, USERID);
    }
}

/**
 * @tc.number: SetIsOnlineThemeWhenBoot_0020
 * Function: SetIsOnlineThemeWhenBoot
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test SetIsOnlineThemeWhenBoot
 */
HWTEST_F(BmsBundleResourceTest, SetIsOnlineThemeWhenBoot_0020, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        bundleMgrService_->RegisterDataMgr(nullptr);
        manager->SetIsOnlineThemeWhenBoot();
        bundleMgrService_->RegisterDataMgr(savedDataMgr);
        manager->SetIsOnlineThemeWhenBoot();
        bool ret = manager->bundleResourceIconRdb_->GetIsOnlineTheme(THEME_TEST_USERID);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: InnerProcessThemeIconWhenOta_0010
 * Function: InnerProcessThemeIconWhenOta
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test InnerProcessThemeIconWhenOta
 */
HWTEST_F(BmsBundleResourceTest, InnerProcessThemeIconWhenOta_0010, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::set<int32_t> userIds;
        userIds.insert(USERID);
        bool ret = manager->InnerProcessThemeIconWhenOta(BUNDLE_NAME, userIds);
        EXPECT_TRUE(ret);

        auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        bundleMgrService_->RegisterDataMgr(nullptr);
        OHOS::ForceCreateDirectory(THEME_B_ICON_BUNDLE_NAME);
        userIds.insert(THEME_TEST_USERID);
        ret = manager->InnerProcessThemeIconWhenOta(BUNDLE_NAME, userIds);
        EXPECT_FALSE(ret);
        bundleMgrService_->RegisterDataMgr(savedDataMgr);
        ret = manager->InnerProcessThemeIconWhenOta(BUNDLE_NAME, userIds);
        EXPECT_TRUE(ret);
        OHOS::ForceRemoveDirectory(THEME_BUNDLE_NAME_PATH);
    }
}

/**
 * @tc.number: InnerProcessThemeIconWhenOta_0020
 * Function: InnerProcessThemeIconWhenOta
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test InnerProcessThemeIconWhenOta
 */
HWTEST_F(BmsBundleResourceTest, InnerProcessThemeIconWhenOta_0020, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        OHOS::ForceCreateDirectory(THEME_B_ICON_BUNDLE_NAME);
        std::set<int32_t> userIds;
        userIds.insert(THEME_TEST_USERID);
        InnerBundleUserInfo userInfo;
        userInfo.bundleUserInfo.userId = THEME_TEST_USERID;
        InnerBundleInfo bundleInfo;
        bundleInfo.innerBundleUserInfos_["_20000"] = userInfo;
        auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        savedDataMgr->bundleInfos_[BUNDLE_NAME] = bundleInfo;
        bool ret = manager->InnerProcessThemeIconWhenOta(BUNDLE_NAME, userIds, false);
        EXPECT_TRUE(ret);
        ret = manager->InnerProcessThemeIconWhenOta(BUNDLE_NAME, userIds, true);
        EXPECT_TRUE(ret);
        OHOS::ForceRemoveDirectory(THEME_BUNDLE_NAME_PATH);
        auto iter = savedDataMgr->bundleInfos_.find(BUNDLE_NAME);
        if (iter != savedDataMgr->bundleInfos_.end()) {
            savedDataMgr->bundleInfos_.erase(iter);
        }
    }
}

/**
 * @tc.number: InnerProcessDynamicIconWhenOta_0010
 * Function: InnerProcessDynamicIconWhenOta
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test InnerProcessDynamicIconWhenOta
 */
HWTEST_F(BmsBundleResourceTest, InnerProcessDynamicIconWhenOta_0010, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        bundleMgrService_->RegisterDataMgr(nullptr);
        bool ret = manager->InnerProcessDynamicIconWhenOta(BUNDLE_NAME);
        EXPECT_FALSE(ret);
        bundleMgrService_->RegisterDataMgr(savedDataMgr);

        ret = manager->InnerProcessDynamicIconWhenOta(BUNDLE_NAME_NOT_EXIST);
        EXPECT_FALSE(ret);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: ProcessThemeAndDynamicIconWhenOta_0010
 * Function: ProcessThemeAndDynamicIconWhenOta
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test ProcessThemeAndDynamicIconWhenOta
 */
HWTEST_F(BmsBundleResourceTest, ProcessThemeAndDynamicIconWhenOta_0010, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::set<std::string> updateBundleNames;
        auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        bundleMgrService_->RegisterDataMgr(nullptr);
        bool ret = manager->ProcessThemeAndDynamicIconWhenOta(updateBundleNames);
        EXPECT_FALSE(ret);
        bundleMgrService_->RegisterDataMgr(savedDataMgr);

        ret = manager->ProcessThemeAndDynamicIconWhenOta(updateBundleNames);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: IsNeedInterrupted_0010
 * Function: IsNeedInterrupted
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test IsNeedInterrupted
 */
HWTEST_F(BmsBundleResourceTest, IsNeedInterrupted_0010, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        manager->currentTaskNum_ = 100;
        manager->currentChangeType_ = static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE);
        bool ret = manager->IsNeedInterrupted(manager->currentTaskNum_,
            BundleResourceChangeType::SYSTEM_LANGUE_CHANGE);
        EXPECT_FALSE(ret);

        ret = manager->IsNeedInterrupted(manager->currentTaskNum_ + 100,
            BundleResourceChangeType::SYSTEM_LANGUE_CHANGE);
        EXPECT_TRUE(ret);

        ret = manager->IsNeedInterrupted(manager->currentTaskNum_ + 100,
            BundleResourceChangeType::SYSTEM_THEME_CHANGE);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: AddUninstallBundleResource_0010
 * Function: AddUninstallBundleResource
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddUninstallBundleResource
 */
HWTEST_F(BmsBundleResourceTest, AddUninstallBundleResource_0010, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        bool ret = manager->AddUninstallBundleResource(MODULE_NAME, USERID, 0);
        EXPECT_FALSE(ret);

        ret = manager->AddUninstallBundleResource(BUNDLE_NAME, USERID, 0);
        EXPECT_TRUE(ret);
        BundleResourceInfo bundleResourceInfo;
        ret = manager->GetUninstallBundleResource(BUNDLE_NAME, USERID, APP_INDEX, 1, bundleResourceInfo);
        EXPECT_FALSE(ret);

        ret = manager->GetUninstallBundleResource(BUNDLE_NAME, USERID, 0, 1, bundleResourceInfo);
        EXPECT_TRUE(ret);
        EXPECT_EQ(bundleResourceInfo.bundleName, BUNDLE_NAME);

        ret = manager->DeleteUninstallBundleResource(BUNDLE_NAME, USERID, 0);
        EXPECT_TRUE(ret);
    }

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: AddUninstallBundleResource_0020
 * Function: AddUninstallBundleResource
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddUninstallBundleResource
 */
HWTEST_F(BmsBundleResourceTest, AddUninstallBundleResource_0020, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME, true);
    EXPECT_EQ(unInstallResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        BundleResourceInfo bundleResourceInfo;
        bool ret = manager->GetUninstallBundleResource(BUNDLE_NAME, USERID, 0, 1, bundleResourceInfo);
        EXPECT_TRUE(ret);
        EXPECT_EQ(bundleResourceInfo.bundleName, BUNDLE_NAME);
    }

    unInstallResult = UnInstallBundle(BUNDLE_NAME, false);
    EXPECT_EQ(unInstallResult, ERR_OK);
    if (manager != nullptr) {
        BundleResourceInfo bundleResourceInfo;
        bool ret = manager->GetUninstallBundleResource(BUNDLE_NAME, USERID, 0, 1, bundleResourceInfo);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: GetAllUninstallBundleResourceInfo_0010
 * Function: AddUninstallBundleResource
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetAllUninstallBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, GetAllUninstallBundleResourceInfo_0010, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);
    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME, true);
    EXPECT_EQ(unInstallResult, ERR_OK);

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        std::vector<BundleResourceInfo> bundleResourceInfos;
        bool ret = manager->GetAllUninstallBundleResourceInfo(USERID, 1, bundleResourceInfos);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(bundleResourceInfos.empty());

        std::vector<BundleResourceInfo> bundleResourceInfos2;
        ret = manager->GetAllUninstallBundleResourceInfo(0, 1, bundleResourceInfos2);
        EXPECT_TRUE(ret);
        EXPECT_FALSE(bundleResourceInfos2.empty());
    }

    unInstallResult = UnInstallBundle(BUNDLE_NAME, false);
    EXPECT_EQ(unInstallResult, ERR_OK);
    if (manager != nullptr) {
        BundleResourceInfo bundleResourceInfo;
        bool ret = manager->GetUninstallBundleResource(BUNDLE_NAME, USERID, 0, 1, bundleResourceInfo);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: GetAllUninstallBundleResourceInfo_0020
 * Function: GetAllBundleResourceInfo
 * @tc.name: test Install
 * @tc.desc: 1. system running normally
 *           2. test GetAllBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, GetAllUninstallBundleResourceInfo_0020, Function | SmallTest | Level0)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    EXPECT_NE(bundleMgrProxy, nullptr);
    if (bundleMgrProxy != nullptr) {
        auto resourceProxy = bundleMgrProxy->GetBundleResourceProxy();
        EXPECT_NE(resourceProxy, nullptr);
        if (resourceProxy != nullptr) {
            std::vector<BundleResourceInfo> infos;
            auto ret = resourceProxy->GetAllUninstallBundleResourceInfo(0, 1, infos);
            EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
            EXPECT_TRUE(infos.empty());
        }
    }
}

/**
 * @tc.number: GetSingleLauncherAbilityResourceInfo_0001
 * Function: GetSingleLauncherAbilityResourceInfo
 * @tc.name: test
 * @tc.desc: test GetSingleLauncherAbilityResourceInfo_0001
 */
HWTEST_F(BmsBundleResourceTest, GetSingleLauncherAbilityResourceInfo_0001, Function | SmallTest | Level0)
{
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    if (manager != nullptr) {
        uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR);
        std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfo;
        bool ret = manager->GetSingleLauncherAbilityResourceInfo("", flags, launcherAbilityResourceInfo, APP_INDEX);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: GetSingleLauncherAbilityResourceInfo_0002
 * Function: GetSingleLauncherAbilityResourceInfo
 * @tc.name: test
 * @tc.desc: test GetSingleLauncherAbilityResourceInfo_0002
 */
HWTEST_F(BmsBundleResourceTest, GetSingleLauncherAbilityResourceInfo_0002, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = BUNDLE_NAME;
    resourceInfo.moduleName_ = MODULE_NAME;
    resourceInfo.abilityName_ = ABILITY_NAME;
    resourceInfo.appIndex_ = APP_INDEX;
    std::vector<LauncherAbilityResourceInfo> infos;
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    bool ret = manager->bundleResourceRdb_->AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ret);
    if (manager != nullptr) {
        uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR);
        std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfo;
        ret = manager->GetSingleLauncherAbilityResourceInfo(
            BUNDLE_NAME, flags, launcherAbilityResourceInfo, APP_INDEX);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: GetLauncherAbilityResourceInfoList_0001
 * Function: GetLauncherAbilityResourceInfoList
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfoList
 */
HWTEST_F(BmsBundleResourceTest, GetLauncherAbilityResourceInfoList_0001, Function | SmallTest | Level0)
{
    std::vector<BundleOptionInfo> optiontList;
    BundleOptionInfo optiont;
    optiont.bundleName = BUNDLE_NAME;
    optiont.abilityName = ABILITY_NAME;
    optiont.appIndex = INVALID_INDEX;
    optiontList.push_back(optiont);

    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfo;
    auto ret = bundleResourceHostImpl->GetLauncherAbilityResourceInfoList(optiontList,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY), launcherAbilityResourceInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX);
}

/**
 * @tc.number: GetLauncherAbilityResourceInfoList_0002
 * Function: GetLauncherAbilityResourceInfoList
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfoList
 */
HWTEST_F(BmsBundleResourceTest, GetLauncherAbilityResourceInfoList_0002, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = BUNDLE_NAME;
    resourceInfo.moduleName_ = MODULE_NAME;
    resourceInfo.abilityName_ = ABILITY_NAME;
    std::vector<LauncherAbilityResourceInfo> infos;
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    bool ret = manager->bundleResourceRdb_->AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ret);

    std::vector<BundleOptionInfo> optiontList;
    BundleOptionInfo optiont;
    optiont.bundleName = BUNDLE_NAME;
    optiont.moduleName = MODULE_NAME;
    optiont.abilityName = ABILITY_NAME;
    optiontList.push_back(optiont);
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    setuid(currentUserId * Constants::BASE_USER_RANGE);
    auto result = bundleResourceHostImpl->GetLauncherAbilityResourceInfoList(optiontList,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY), infos);
    EXPECT_EQ(result, ERR_OK);
    setuid(Constants::ROOT_UID);
    ret = manager->bundleResourceRdb_->DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetLauncherAbilityResourceInfoList_0003
 * Function: GetLauncherAbilityResourceInfoList
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfoList
 */
HWTEST_F(BmsBundleResourceTest, GetLauncherAbilityResourceInfoList_0003, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = BUNDLE_NAME;
    resourceInfo.moduleName_ = MODULE_NAME;
    resourceInfo.abilityName_ = ABILITY_NAME;
    std::vector<LauncherAbilityResourceInfo> infos;
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    bool ret = manager->bundleResourceRdb_->AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ret);

    std::vector<BundleOptionInfo> optiontList;
    BundleOptionInfo optiont;
    optiont.bundleName = "";
    optiont.abilityName = ABILITY_NAME;
    optiontList.push_back(optiont);
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    setuid(currentUserId * Constants::BASE_USER_RANGE);
    auto result = bundleResourceHostImpl->GetLauncherAbilityResourceInfoList(optiontList,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY), infos);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    setuid(Constants::ROOT_UID);
    ret = manager->bundleResourceRdb_->DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetLauncherAbilityResourceInfoList_0004
 * Function: GetLauncherAbilityResourceInfoList
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetLauncherAbilityResourceInfoList
 */
HWTEST_F(BmsBundleResourceTest, GetLauncherAbilityResourceInfoList_0004, Function | SmallTest | Level0)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = BUNDLE_NAME;
    resourceInfo.moduleName_ = MODULE_NAME;
    resourceInfo.abilityName_ = ABILITY_NAME;
    std::vector<LauncherAbilityResourceInfo> infos;
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    EXPECT_NE(manager, nullptr);
    bool ret = manager->bundleResourceRdb_->AddResourceInfo(resourceInfo);
    EXPECT_TRUE(ret);

    std::vector<BundleOptionInfo> optiontList;
    BundleOptionInfo optiont;
    optiont.bundleName = BUNDLE_NAME;
    optiont.moduleName = MODULE_NAME;
    optiont.abilityName = INVALID_ABILITY_NAME;
    optiontList.push_back(optiont);
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    setuid(currentUserId * Constants::BASE_USER_RANGE);
    auto result = bundleResourceHostImpl->GetLauncherAbilityResourceInfoList(optiontList,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY), infos);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    setuid(Constants::ROOT_UID);
    ret = manager->bundleResourceRdb_->DeleteResourceInfo(resourceInfo.GetKey());
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetElementLauncherAbilityResourceInfo_0001
 * Function: GetElementLauncherAbilityResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetElementLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, GetElementLauncherAbilityResourceInfo_0001, Function | SmallTest | Level0)
{
    LauncherAbilityResourceInfo launcherAbilityResourceInfo;
    LauncherAbilityResourceInfo resourceInfo;
    std::vector<LauncherAbilityResourceInfo> allResources;
    resourceInfo.bundleName = BUNDLE_NAME;
    resourceInfo.moduleName = MODULE_NAME;
    resourceInfo.abilityName = ABILITY_NAME;
    resourceInfo.appIndex = APP_INDEX;
    allResources.push_back(resourceInfo);

    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    auto ret = bundleResourceHostImpl->GetElementLauncherAbilityResourceInfo(
        allResources, MODULE_NAME, ABILITY_NAME, APP_INDEX, launcherAbilityResourceInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetElementLauncherAbilityResourceInfo_0002
 * Function: GetElementLauncherAbilityResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetElementLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, GetElementLauncherAbilityResourceInfo_0002, Function | SmallTest | Level0)
{
    LauncherAbilityResourceInfo launcherAbilityResourceInfo;
    LauncherAbilityResourceInfo resourceInfo;
    std::vector<LauncherAbilityResourceInfo> allResources;
    resourceInfo.bundleName = BUNDLE_NAME;
    resourceInfo.moduleName = MODULE_NAME;
    resourceInfo.abilityName = ABILITY_NAME;
    resourceInfo.appIndex = APP_INDEX;
    allResources.push_back(resourceInfo);

    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    auto ret = bundleResourceHostImpl->GetElementLauncherAbilityResourceInfo(
        allResources, "", ABILITY_NAME, APP_INDEX, launcherAbilityResourceInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: GetElementLauncherAbilityResourceInfo_0003
 * Function: GetElementLauncherAbilityResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetElementLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, GetElementLauncherAbilityResourceInfo_0003, Function | SmallTest | Level0)
{
    LauncherAbilityResourceInfo launcherAbilityResourceInfo;
    LauncherAbilityResourceInfo resourceInfo;
    std::vector<LauncherAbilityResourceInfo> allResources;
    resourceInfo.bundleName = BUNDLE_NAME;
    resourceInfo.moduleName = MODULE_NAME;
    resourceInfo.abilityName = ABILITY_NAME;
    resourceInfo.appIndex = APP_INDEX;
    allResources.push_back(resourceInfo);

    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    auto ret = bundleResourceHostImpl->GetElementLauncherAbilityResourceInfo(
        allResources, MODULE_NAME, "", APP_INDEX, launcherAbilityResourceInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: GetElementLauncherAbilityResourceInfo_0004
 * Function: GetElementLauncherAbilityResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test GetElementLauncherAbilityResourceInfo
 */
HWTEST_F(BmsBundleResourceTest, GetElementLauncherAbilityResourceInfo_0004, Function | SmallTest | Level0)
{
    LauncherAbilityResourceInfo launcherAbilityResourceInfo;
    LauncherAbilityResourceInfo resourceInfo;
    std::vector<LauncherAbilityResourceInfo> allResources;
    resourceInfo.bundleName = BUNDLE_NAME;
    resourceInfo.moduleName = MODULE_NAME;
    resourceInfo.abilityName = ABILITY_NAME;
    resourceInfo.appIndex = APP_INDEX;
    allResources.push_back(resourceInfo);

    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    auto ret = bundleResourceHostImpl->GetElementLauncherAbilityResourceInfo(
        allResources, MODULE_NAME, ABILITY_NAME, INVALID_INDEX, launcherAbilityResourceInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_APPINDEX_NOT_EXIST);
}

/**
 * @tc.number: BmsBundleResourceTest_0259
 * @tc.name: GetLauncherAbilityResourceInfo
 * @tc.desc: test GetLauncherAbilityResourceInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0259, Function | SmallTest | Level0)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    EXPECT_NE(bmsExtensionClient, nullptr);

    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    LauncherAbilityResourceInfo launcherAbilityResourceInfo;
    BundleOptionInfo optiont;
    optiont.bundleName = BUNDLE_NAME;
    optiont.abilityName = ABILITY_NAME;
    auto ret = bmsExtensionClient->GetLauncherAbilityResourceInfo(optiont,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), launcherAbilityResourceInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BmsBundleResourceTest_0260
 * @tc.name: GetLauncherAbilityResourceInfo
 * @tc.desc: test GetLauncherAbilityResourceInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleResourceTest, BmsBundleResourceTest_0260, Function | SmallTest | Level0)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    EXPECT_NE(bmsExtensionClient, nullptr);

    bmsExtensionClient->bmsExtensionImpl_ = std::make_shared<BmsExtensionDataMgr>();
    LauncherAbilityResourceInfo launcherAbilityResourceInfo;
    BundleOptionInfo optiont;
    optiont.bundleName = BUNDLE_NAME;
    optiont.abilityName = ABILITY_NAME;
    auto ret = bmsExtensionClient->GetLauncherAbilityResourceInfo(optiont,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), launcherAbilityResourceInfo);
    EXPECT_NE(ret, ERR_OK);
}


/**
 * @tc.number: FilterUninstallResource_0001
 * Function: FilterUninstallResource
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test FilterUninstallResource
 */
HWTEST_F(BmsBundleResourceTest, FilterUninstallResource_0001, Function | SmallTest | Level0)
{
    std::vector<BundleResourceInfo> resourceList;
    BundleResourceInfo res;
    resourceList.emplace_back(res);
    std::shared_ptr<BundleResourceHostImpl> bundleResourceHostImpl = std::make_shared<BundleResourceHostImpl>();
    bundleResourceHostImpl->FilterUninstallResource(100, resourceList);
    EXPECT_EQ(true, resourceList.empty());
}
} // OHOS
