/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <thread>
#include <gtest/gtest.h>

#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "installd/installd_service.h"
#include "bundle_manager_callback.h"
#include "bundle_manager_callback_stub.h"
#include "mock_bundle_manager_callback_stub.h"
#include "bundle_distributed_manager.h"
#include "bundle_manager_callback_proxy.h"
#define private public

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using OHOS::AAFwk::Want;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME_TEST = "com.example.bundlekit.test";
const std::string MODULE_NAME_TEST = "com.example.bundlekit.test.entry";
const std::string MODULE_NAME_TEST_1 = "com.example.bundlekit.test.entry_A";
const std::string MODULE_NAME_TEST_2 = "com.example.bundlekit.test.entry_B";
const std::string MODULE_NAME_TEST_3 = "com.example.bundlekit.test.entry_C";
const std::string ABILITY_NAME_TEST1 = ".Reading1";
const std::string ABILITY_NAME_TEST = ".Reading";
const std::string BUNDLE_LABEL = "Hello, OHOS";
const std::string BUNDLE_DESCRIPTION = "example helloworld";
const std::string BUNDLE_VENDOR = "example";
const std::string BUNDLE_VERSION_NAME = "1.0.0.1";
const std::string BUNDLE_MAIN_ABILITY = "com.example.bundlekit.test.entry";
const std::string BUNDLE_JOINT_USERID = "3";
const std::string BUNDLE_NAME_TEST1 = "com.example.bundlekit.test1";
const std::string BUNDLE_NAME_DEMO = "com.example.bundlekit.demo";
const std::string MODULE_NAME_DEMO = "com.example.bundlekit.demo.entry";
const std::string ABILITY_NAME_DEMO = ".Writing";
const std::string PACKAGE_NAME = "com.example.bundlekit.test.entry";
const std::string PROCESS_TEST = "test.process";
const std::string DEVICE_ID = "PHONE-001";
const std::string LABEL = "hello";
const std::string DESCRIPTION = "mainEntry";
const std::string THEME = "mytheme";
const std::string ICON_PATH = "/data/data/icon.png";
const std::string KIND = "test";
const std::string ACTION = "action.system.home";
const std::string ENTITY = "entity.system.home";
const std::string TARGET_ABILITY = "MockTargetAbility";
const AbilityType ABILITY_TYPE = AbilityType::PAGE;
const DisplayOrientation ORIENTATION = DisplayOrientation::PORTRAIT;
const LaunchMode LAUNCH_MODE = LaunchMode::SINGLETON;
const std::vector<std::string> CONFIG_CHANGES = {"locale"};
const int DEFAULT_FORM_HEIGHT = 100;
const int DEFAULT_FORM_WIDTH = 200;
const std::string META_DATA_DESCRIPTION = "description";
const std::string META_DATA_NAME = "name";
const std::string META_DATA_TYPE = "type";
const std::string META_DATA_VALUE = "value";
const std::string META_DATA_EXTRA = "extra";
const ModuleColorMode COLOR_MODE = ModuleColorMode::AUTO;
const std::string CODE_PATH = "/data/app/el1/bundle/public/com.example.bundlekit.test";
const std::string RESOURCE_PATH = "/data/app/el1/bundle/public/com.example.bundlekit.test/res";
const std::string LIB_PATH = "/data/app/el1/bundle/public/com.example.bundlekit.test/lib";
const bool VISIBLE = true;
const std::string MAIN_ENTRY = "com.example.bundlekit.test.entry";
const std::string EMPTY_STRING = "";
const std::string ABILITY_URI = "dataability:///com.example.hiworld.himusic.UserADataAbility/person/10";
const std::string URI = "dataability://com.example.hiworld.himusic.UserADataAbility";
const std::string ERROR_URI = "dataability://";
const std::string HAP_FILE_PATH = "/data/test/resource/bms/bundle_kit/test.hap";
const std::string HAP_FILE_PATH1 = "/data/test/resource/bms/bundle_kit/test1.hap";
const std::string ERROR_HAP_FILE_PATH = "/data/test/resource/bms/bundle_kit/error.hap";
const std::string META_DATA = "name";
const std::string ERROR_META_DATA = "String";
const std::string BUNDLE_DATA_DIR = "/data/app/el2/100/base/com.example.bundlekit.test";
const std::string FILES_DIR = "/data/app/el2/100/base/com.example.bundlekit.test/files";
const std::string TEST_FILE_DIR = "/data/app/el2/100/base/com.example.bundlekit.test/files";
const std::string DATA_BASE_DIR = "/data/app/el2/100/database/com.example.bundlekit.test";
const std::string TEST_DATA_BASE_DIR = "/data/app/el2/100/database/com.example.bundlekit.test";
const std::string CACHE_DIR = "/data/app/el2/100/base/com.example.bundlekit.test/cache";
const std::string TEST_CACHE_DIR = "/data/app/el2/100/base/com.example.bundlekit.test/cache/cache";
const std::string SERVICES_NAME = "d-bms";
const std::string FORM_NAME = "form_js";
const std::string FORM_PATH = "data/app";
const std::string FORM_JS_COMPONENT_NAME = "JS";
const std::string FORM_DESCRIPTION = "description";
const std::string FORM_SCHEDULED_UPDATE_TIME = "11:00";
const std::string FORM_CUSTOMIZE_DATAS_NAME = "customizeDataName";
const std::string FORM_CUSTOMIZE_DATAS_VALUE = "customizeDataValue";
const std::string FORM_PORTRAIT_LAYOUTS1 = "port1";
const std::string FORM_PORTRAIT_LAYOUTS2 = "port2";
const std::string FORM_LANDSCAPE_LAYOUTS1 = "land1";
const std::string FORM_LANDSCAPE_LAYOUTS2 = "land2";
const std::string FORM_SRC = "page/card/index";
const std::string SHORTCUT_TEST_ID = "shortcutTestId";
const std::string SHORTCUT_DEMO_ID = "shortcutDemoId";
const std::string SHORTCUT_HOST_ABILITY = "hostAbility";
const std::string SHORTCUT_ICON = "/data/test/bms_bundle";
const std::string SHORTCUT_LABEL = "shortcutLabel";
const std::string SHORTCUT_DISABLE_MESSAGE = "shortcutDisableMessage";
const std::string SHORTCUT_INTENTS_TARGET_BUNDLE = "targetBundle";
const std::string SHORTCUT_INTENTS_TARGET_MODULE = "targetModule";
const std::string SHORTCUT_INTENTS_TARGET_CLASS = "targetClass";
const std::string COMMON_EVENT_NAME = ".MainAbililty";
const std::string COMMON_EVENT_PERMISSION = "permission";
const std::string COMMON_EVENT_DATA = "data";
const std::string COMMON_EVENT_TYPE = "type";
const std::string COMMON_EVENT_EVENT = "usual.event.PACKAGE_ADDED";
const std::string COMMON_EVENT_EVENT_ERROR_KEY = "usual.event.PACKAGE_ADDED_D";
const std::string COMMON_EVENT_EVENT_NOT_EXISTS_KEY = "usual.event.PACKAGE_REMOVED";
const std::string ACTION_001 = "action001";
const std::string ACTION_002 = "action002";
const std::string ENTITY_001 = "entity001";
const std::string ENTITY_002 = "entity002";
const std::string TYPE_001 = "type001";
const std::string TYPE_002 = "type002";
const std::string TYPE_IMG_REGEX = "img/*";
const std::string TYPE_IMG_JPEG = "img/jpeg";
const std::string SCHEME_SEPARATOR = "://";
const std::string PORT_SEPARATOR = ":";
const std::string PATH_SEPARATOR = "/";
const std::string SCHEME_001 = "scheme001";
const std::string SCHEME_002 = "scheme002";
const std::string HOST_001 = "host001";
const std::string HOST_002 = "host002";
const std::string PORT_001 = "port001";
const std::string PORT_002 = "port002";
const std::string PATH_001 = "path001";
const std::string PATH_REGEX_001 = ".*";
const std::string CONTROLMESSAGE = "controlMessage";
const std::string URI_PATH_001 = SCHEME_001 + SCHEME_SEPARATOR + HOST_001 +
    PORT_SEPARATOR + PORT_001 + PATH_SEPARATOR + PATH_001;
const std::string URI_PATH_DUPLICATE_001 = SCHEME_001 + SCHEME_SEPARATOR +
    HOST_001 + PORT_SEPARATOR + PORT_001 + PATH_SEPARATOR + PATH_001 + PATH_001;
const std::string URI_PATH_REGEX_001 = SCHEME_001 + SCHEME_SEPARATOR + HOST_001 +
    PORT_SEPARATOR + PORT_001 + PATH_SEPARATOR + PATH_REGEX_001;
const std::string BUNDLE_NAME = "bundleName";
const std::string MODULE_NAME = "moduleName";
const std::string ABILITY_NAME = "abilityName";
const std::string SHORTCUT_ID_KEY = "shortcutId";
const std::string ICON_KEY = "icon";
const std::string ICON_ID_KEY = "iconId";
const std::string LABEL_KEY = "label";
const std::string LABEL_ID_KEY = "labelId";
const std::string SHORTCUT_WANTS_KEY = "wants";
const std::string SHORTCUTS_KEY = "shortcuts";
const int32_t BASE_TEST_UID = 65535;
const int32_t DEFAULT_USERID = 100;
const int32_t TEST_UID = 20065535;
const int APPLICATION_INFO_FLAGS = 1;
}  // namespace

class BmsBundleKitServiceBaseTest : public testing::Test {
public:
    using Want = OHOS::AAFwk::Want;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void MockInstallBundle(
        const std::string &bundleName, const std::string &moduleName, const std::string &abilityName,
        bool userDataClearable, bool isSystemApp) const;
    void MockUninstallBundle(const std::string &bundleName) const;
    InnerModuleInfo MockModuleInfo(const std::string &moduleName) const;
    AbilityInfo MockAbilityInfo(
        const std::string &bundleName, const std::string &module, const std::string &abilityName) const;
    std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void SaveToDatabase(const std::string &bundleName, InnerBundleInfo &innerBundleInfo,
        bool userDataClearable, bool isSystemApp) const;
    void AddApplicationInfo(const std::string &bundleName, ApplicationInfo &appInfo,
        bool userDataClearable = true, bool isSystemApp = false) const;
public:
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
    std::shared_ptr<InstalldService> service_ = std::make_shared<InstalldService>();
    NotifyBundleEvents installRes_;
    const std::shared_ptr<BundleDataMgr> dataMgrInfo_ =
        DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_;
};

void BmsBundleKitServiceBaseTest::SetUpTestCase()
{}

void BmsBundleKitServiceBaseTest::TearDownTestCase()
{}

void BmsBundleKitServiceBaseTest::SetUp()
{
    if (!service_->IsServiceReady()) {
        service_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
    }
}

void BmsBundleKitServiceBaseTest::TearDown()
{}

void BmsBundleKitServiceBaseTest::MockInstallBundle(
    const std::string &bundleName, const std::string &moduleName, const std::string &abilityName,
    bool userDataClearable, bool isSystemApp) const
{
    InnerModuleInfo moduleInfo = MockModuleInfo(moduleName);
    std::string keyName = bundleName + "." + moduleName + "." + abilityName;
    moduleInfo.entryAbilityKey = keyName;
    AbilityInfo abilityInfo = MockAbilityInfo(bundleName, moduleName, abilityName);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertAbilitiesInfo(keyName, abilityInfo);
    innerBundleInfo.InsertInnerModuleInfo(moduleName, moduleInfo);
    Skill skill {{ACTION}, {ENTITY}};
    std::vector<Skill> skills;
    skills.emplace_back(skill);
    innerBundleInfo.InsertSkillInfo(keyName, skills);
    SaveToDatabase(bundleName, innerBundleInfo, userDataClearable, isSystemApp);
}

AbilityInfo BmsBundleKitServiceBaseTest::MockAbilityInfo(
    const std::string &bundleName, const std::string &moduleName, const std::string &abilityName) const
{
    AbilityInfo abilityInfo;
    abilityInfo.package = PACKAGE_NAME;
    abilityInfo.name = abilityName;
    abilityInfo.bundleName = bundleName;
    abilityInfo.moduleName = moduleName;
    abilityInfo.deviceId = DEVICE_ID;
    abilityInfo.label = LABEL;
    abilityInfo.labelId = 0;
    abilityInfo.description = DESCRIPTION;
    abilityInfo.theme = THEME;
    abilityInfo.iconPath = ICON_PATH;
    abilityInfo.visible = VISIBLE;
    abilityInfo.kind = KIND;
    abilityInfo.type = ABILITY_TYPE;
    abilityInfo.orientation = ORIENTATION;
    abilityInfo.launchMode = LAUNCH_MODE;
    abilityInfo.configChanges = {"locale"};
    abilityInfo.backgroundModes = 1;
    abilityInfo.formEntity = 1;
    abilityInfo.defaultFormHeight = DEFAULT_FORM_HEIGHT;
    abilityInfo.defaultFormWidth = DEFAULT_FORM_WIDTH;
    abilityInfo.codePath = CODE_PATH;
    abilityInfo.resourcePath = RESOURCE_PATH;
    abilityInfo.libPath = LIB_PATH;
    abilityInfo.uri = URI;
    abilityInfo.enabled = true;
    abilityInfo.supportPipMode = false;
    abilityInfo.targetAbility = TARGET_ABILITY;
    AppExecFwk::CustomizeData customizeData {
        "name",
        "value",
        "extra"
    };
    MetaData metaData {
        {customizeData}
    };
    abilityInfo.metaData = metaData;
    abilityInfo.permissions = {"abilityPerm001", "abilityPerm002"};
    return abilityInfo;
}

InnerModuleInfo BmsBundleKitServiceBaseTest::MockModuleInfo(const std::string &moduleName) const
{
    InnerModuleInfo moduleInfo;
    RequestPermission reqPermission1;
    reqPermission1.name = "permission1";
    RequestPermission reqPermission2;
    reqPermission2.name = "permission2";
    moduleInfo.requestPermissions = {reqPermission1, reqPermission2};
    moduleInfo.name = MODULE_NAME_TEST;
    moduleInfo.icon = ICON_PATH;
    moduleInfo.modulePackage = PACKAGE_NAME;
    moduleInfo.moduleName = moduleName;
    moduleInfo.description = BUNDLE_DESCRIPTION;
    moduleInfo.colorMode = COLOR_MODE;
    moduleInfo.label = LABEL;

    AppExecFwk::CustomizeData customizeData {"name", "value", "extra"};
    MetaData metaData {{customizeData}};
    moduleInfo.metaData = metaData;
    return moduleInfo;
}

void BmsBundleKitServiceBaseTest::SaveToDatabase(const std::string &bundleName,
    InnerBundleInfo &innerBundleInfo, bool userDataClearable, bool isSystemApp) const
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleUserInfo.bundleUserInfo.userId = Constants::DEFAULT_USERID;
    innerBundleUserInfo.uid = BASE_TEST_UID;

    InnerBundleUserInfo innerBundleUserInfo1;
    innerBundleUserInfo1.bundleName = bundleName;
    innerBundleUserInfo1.bundleUserInfo.enabled = true;
    innerBundleUserInfo1.bundleUserInfo.userId = DEFAULT_USERID;
    innerBundleUserInfo1.uid = TEST_UID;

    ApplicationInfo appInfo;
    AddApplicationInfo(bundleName, appInfo, userDataClearable, isSystemApp);
    BundleInfo bundleInfo;
    innerBundleInfo.SetBaseApplicationInfo(appInfo);
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo1);
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    auto moduleNameVec = innerBundleInfo.GetModuleNameVec();
    auto abilityNameVec = innerBundleInfo.GetAbilityNames();
    bool startRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bool addRet = dataMgr->AddInnerBundleInfo(bundleName, innerBundleInfo);
    bool endRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_SUCCESS);

    EXPECT_TRUE(startRet);
    EXPECT_TRUE(addRet);
    EXPECT_TRUE(endRet);
}

void BmsBundleKitServiceBaseTest::AddApplicationInfo(const std::string &bundleName, ApplicationInfo &appInfo,
    bool userDataClearable, bool isSystemApp) const
{
    appInfo.bundleName = bundleName;
    appInfo.name = bundleName;
    appInfo.deviceId = DEVICE_ID;
    appInfo.process = PROCESS_TEST;
    appInfo.label = BUNDLE_LABEL;
    appInfo.description = BUNDLE_DESCRIPTION;
    appInfo.codePath = CODE_PATH;
    appInfo.dataDir = FILES_DIR;
    appInfo.dataBaseDir = DATA_BASE_DIR;
    appInfo.cacheDir = CACHE_DIR;
    appInfo.flags = APPLICATION_INFO_FLAGS;
    appInfo.enabled = true;
    appInfo.userDataClearable = userDataClearable;
    appInfo.isSystemApp = isSystemApp;
}

std::shared_ptr<BundleDataMgr> BmsBundleKitServiceBaseTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

void BmsBundleKitServiceBaseTest::MockUninstallBundle(const std::string &bundleName) const
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool startRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START);
    bool finishRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS);

    EXPECT_TRUE(startRet);
    EXPECT_TRUE(finishRet);
}

/**
 * @tc.number: BundleManagerCallback_0100
 * @tc.name: Test OnQueryRpcIdFinished
 * @tc.desc: Verify the OnQueryRpcIdFinished return NO_ERROR.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleManagerCallback_0100, Function | MediumTest | Level1)
{
    auto server = std::make_shared<BundleDistributedManager>();
    std::weak_ptr<BundleDistributedManager> server_ = server;
    BundleManagerCallback bmcb(server_);
    std::string null_string = "";
    auto result = bmcb.OnQueryRpcIdFinished(null_string);
    EXPECT_EQ(result, NO_ERROR);
    sleep(1);
}

/**
 * @tc.number: BundleManagerCallback_0200
 * @tc.name: Test OnQueryRpcIdFinished
 * @tc.desc: Verify the OnQueryRpcIdFinished return NO_ERROR.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleManagerCallback_0200, Function | MediumTest | Level1)
{
    auto server = std::make_shared<BundleDistributedManager>();
    std::weak_ptr<BundleDistributedManager> server_ = server;
    BundleManagerCallback bmcb(server_);
    std::string installResult = "installResult";
    auto result = bmcb.OnQueryRpcIdFinished(installResult);
    EXPECT_EQ(result, NO_ERROR);
    sleep(1);
}

/**
 * @tc.number: BundleManagerCallback_0300
 * @tc.name: Test OnQueryRpcIdFinished
 * @tc.desc: Verify the OnQueryRpcIdFinished return ERR_INVALID_VALUE.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleManagerCallback_0300, Function | MediumTest | Level1)
{
    std::weak_ptr<BundleDistributedManager> server_; 
    BundleManagerCallback bmcb(server_);
    std::string queryRpcIdResult = "queryRpcIdResult";
    auto result = bmcb.OnQueryRpcIdFinished(queryRpcIdResult);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    sleep(1);
}

/**
 * @tc.number: BundleManagerCallback_0400
 * @tc.name: Test OnQueryRpcIdFinished
 * @tc.desc: Verify the OnQueryRpcIdFinished return ERR_INVALID_VALUE.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleManagerCallback_0400, Function | MediumTest | Level1)
{
    std::weak_ptr<BundleDistributedManager> server_; 
    BundleManagerCallback bmcb(server_);
    std::string null_string = "";
    auto result = bmcb.OnQueryRpcIdFinished(null_string);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    sleep(1);
}


/**
 * @tc.number: BundleManagerCallbackProxy_0100
 * @tc.name: Test OnQueryRpcIdFinished
 * @tc.desc: Verify the OnQueryRpcIdFinished return 0.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleManagerCallbackProxy_0100, Function | MediumTest | Level1)
{
    BundleManagerCallbackProxy proxy_(nullptr);
    std::string installResult = "installResult";
    auto result = proxy_.OnQueryRpcIdFinished(installResult);
    EXPECT_EQ(result, 0);
    sleep(1);
}

/**
 * @tc.number: BundleManagerCallbackProxy_0200
 * @tc.name: Test OnQueryRpcIdFinished
 * @tc.desc: Verify the OnQueryRpcIdFinished return 0.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleManagerCallbackProxy_0200, Function | MediumTest | Level1)
{
    BundleManagerCallbackProxy proxy_(nullptr);
    std::string null_string = "";
    auto result = proxy_.OnQueryRpcIdFinished(null_string);
    EXPECT_EQ(result, 0);
    sleep(1);
}

/**
 * @tc.number: BundleManagerCallbackStub_0100
 * @tc.name: Test OnRemoteRequest
 * @tc.desc: Verify the OnRemoteRequest return OBJECT_NULL.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleManagerCallbackStub_0100, Function | MediumTest | Level1)
{
    MockBundleManagerCallbackStub stub_;
    uint32_t code = IBundleManagerCallback::Message::QUERY_RPC_ID_CALLBACK;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto result = stub_.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, OBJECT_NULL);
    sleep(1);
}

/**
 * @tc.number: BundleManagerCallbackStub_0100
 * @tc.name: Test OnRemoteRequest
 * @tc.desc: Verify the OnRemoteRequest return OBJECT_NULL.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleManagerCallbackStub_0200, Function | MediumTest | Level1)
{
    MockBundleManagerCallbackStub stub_;
    uint32_t code = -1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto result = stub_.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, OBJECT_NULL);
    sleep(1);
}

/**
 * @tc.number: BundleManagerCallbackStub_0300
 * @tc.name: Test OnRemoteRequest
 * @tc.desc: Verify the OnRemoteRequest return 305.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleManagerCallbackStub_0300, Function | MediumTest | Level1)
{
    MockBundleManagerCallbackStub stub_;
    uint32_t code = -1;
    MessageParcel data;
    data.WriteInterfaceToken(BundleManagerCallbackStub::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    auto result = stub_.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, 305);
    sleep(1);
}

/**
 * @tc.number: BundleManagerCallbackStub_0400
 * @tc.name: Test OnRemoteRequest
 * @tc.desc: Verify the OnRemoteRequest return 0.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleManagerCallbackStub_0400, Function | MediumTest | Level1)
{
    MockBundleManagerCallbackStub stub_;
    uint32_t code = 0;
    MessageParcel data;
    data.WriteInterfaceToken(BundleManagerCallbackStub::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    auto result = stub_.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, 0);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_0100
 * @tc.name: Test Init
 * @tc.desc: Verify the Init.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_0100, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    mgr_.Init();
    EXPECT_TRUE(mgr_.handler_ != nullptr);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_0200
 * @tc.name: Test ConvertTargetAbilityInfo
 * @tc.desc: Verify the ConvertTargetAbilityInfo return true.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_0200, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    ElementName element;
    std::string deviceId = "deviceId";
    std::string bundleName = "com.example.MyApplication";
    std::string moduleName = "com.example.MyModuleName";
    std::string abilityName = "com.example.MyApplication.MainAbility";
    want.SetElementName(deviceId, bundleName, abilityName, moduleName);
    TargetAbilityInfo targetAbilityInfo;
    auto ret = mgr_.ConvertTargetAbilityInfo(want, targetAbilityInfo);
    EXPECT_EQ(targetAbilityInfo.targetInfo.bundleName, bundleName);
    EXPECT_EQ(targetAbilityInfo.targetInfo.moduleName, moduleName);
    EXPECT_EQ(targetAbilityInfo.targetInfo.abilityName, abilityName);
    EXPECT_TRUE(ret);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_0300
 * @tc.name: Test ConvertTargetAbilityInfo
 * @tc.desc: Verify the ConvertTargetAbilityInfo return true.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_0300, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    ElementName element;
    std::string nullString = "";
    TargetAbilityInfo targetAbilityInfo;
    auto ret = mgr_.ConvertTargetAbilityInfo(want, targetAbilityInfo);
    EXPECT_EQ(targetAbilityInfo.targetInfo.bundleName, nullString);
    EXPECT_EQ(targetAbilityInfo.targetInfo.moduleName, nullString);
    EXPECT_EQ(targetAbilityInfo.targetInfo.abilityName, nullString);
    EXPECT_TRUE(ret);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_0400
 * @tc.name: Test ComparePcIdString
 * @tc.desc: Verify the ComparePcIdString return DECODE_SYS_CAP_FAILED.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_0400, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    RpcIdResult rpcIdResult;
    ElementName element;
    std::string deviceId = "deviceId";
    std::string bundleName = "com.example.MyApplication";
    std::string moduleName = "com.example.MyModuleName";
    std::string abilityName = "com.example.MyApplication.MainAbility";
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    rpcIdResult.abilityInfo.rpcId.emplace_back("rpcId");
    auto ret = mgr_.ComparePcIdString(want, rpcIdResult);
    EXPECT_EQ(ret, DECODE_SYS_CAP_FAILED);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_0500
 * @tc.name: Test ComparePcIdString
 * @tc.desc: Verify the ComparePcIdString return DECODE_SYS_CAP_FAILED.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_0500, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    RpcIdResult rpcIdResult;
    ElementName element;
    std::string deviceId = "deviceId";
    std::string bundleName = "com.example.MyApplication";
    std::string moduleName = "com.example.MyModuleName";
    std::string abilityName = "com.example.MyApplication.MainAbility";
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    auto ret = mgr_.ComparePcIdString(want, rpcIdResult);
    EXPECT_EQ(ret, DECODE_SYS_CAP_FAILED);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_0600
 * @tc.name: Test ComparePcIdString
 * @tc.desc: Verify the ComparePcIdString return GET_DEVICE_PROFILE_FAILED.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_0600, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    RpcIdResult rpcIdResult;
    rpcIdResult.abilityInfo.rpcId.emplace_back("rpcId");
    auto ret = mgr_.ComparePcIdString(want, rpcIdResult);
    EXPECT_EQ(ret, GET_DEVICE_PROFILE_FAILED);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_0700
 * @tc.name: Test CheckAbilityEnableInstall
 * @tc.desc: Verify the CheckAbilityEnableInstall return false.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_0700, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    int32_t missionId = 0;
    int32_t userId = 0;
    auto ret = mgr_.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
    EXPECT_FALSE(ret);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_0800
 * @tc.name: Test CheckAbilityEnableInstall
 * @tc.desc: Verify the CheckAbilityEnableInstall return false.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_0800, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    ElementName element;
    std::string deviceId = "deviceId";
    std::string bundleName = "com.example.MyApplication";
    std::string moduleName = "com.example.MyModuleName";
    std::string abilityName = "com.example.MyApplication.MainAbility";
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 0;
    int32_t userId = 0;
    auto ret = mgr_.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
    EXPECT_FALSE(ret);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_0900
 * @tc.name: Test CheckAbilityEnableInstall
 * @tc.desc: Verify the CheckAbilityEnableInstall return true.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_0900, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    ElementName element;
    std::string deviceId = "deviceId";
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = "com.example.MyModuleName";
    std::string abilityName = "com.example.MyApplication.MainAbility";
    MockInstallBundle(bundleName, moduleName, abilityName, false, false);
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 100;
    auto ret = mgr_.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
    EXPECT_TRUE(ret);
    MockUninstallBundle(bundleName);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_1000
 * @tc.name: Test CheckAbilityEnableInstall
 * @tc.desc: Verify the CheckAbilityEnableInstall return false.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_1000, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    ElementName element;
    std::string deviceId = "";
    std::string bundleName = "";
    std::string moduleName = "com.example.MyModuleName";
    std::string abilityName = "com.example.MyApplication.MainAbility";
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 0;
    auto ret = mgr_.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
    EXPECT_FALSE(ret);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_1100
 * @tc.name: Test CheckAbilityEnableInstall
 * @tc.desc: Verify the CheckAbilityEnableInstall return false.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_1100, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    ElementName element;
    std::string deviceId = "";
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = "com.example.MyModuleName";
    std::string abilityName = "com.example.MyApplication.MainAbility";
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 200;
    auto ret = mgr_.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
    EXPECT_FALSE(ret);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_1200
 * @tc.name: Test CheckAbilityEnableInstall
 * @tc.desc: Verify the CheckAbilityEnableInstall return true.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_1200, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    ElementName element;
    std::string deviceId = "";
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = "";
    std::string abilityName = "";
    MockInstallBundle(bundleName, moduleName, abilityName, true, false);
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 100;
    auto ret = mgr_.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
    EXPECT_TRUE(ret);
    MockUninstallBundle(bundleName);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_1300
 * @tc.name: Test CheckAbilityEnableInstall
 * @tc.desc: Verify the CheckAbilityEnableInstall return false.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_1300, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    ElementName element;
    std::string deviceId = "";
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = "";
    std::string abilityName = "";
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 200;
    auto ret = mgr_.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
    EXPECT_FALSE(ret);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_1400
 * @tc.name: Test CheckAbilityEnableInstall
 * @tc.desc: Verify the CheckAbilityEnableInstall return true.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_1400, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    ElementName element;
    std::string deviceId = "";
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = "";
    std::string abilityName = "";
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 0;
    auto ret = mgr_.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
    EXPECT_FALSE(ret);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_1500
 * @tc.name: Test CheckAbilityEnableInstall
 * @tc.desc: Verify the CheckAbilityEnableInstall return true.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_1500, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    ElementName element;
    std::string deviceId = "deviceId";
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = "com.example.MyModuleName";
    std::string abilityName = "com.example.MyApplication.MainAbility";
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 0;
    auto ret = mgr_.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
    EXPECT_FALSE(ret);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_1600
 * @tc.name: Test CheckAbilityEnableInstall
 * @tc.desc: Verify the CheckAbilityEnableInstall return true.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_1600, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    ElementName element;
    std::string deviceId = "";
    std::string bundleName = BUNDLE_NAME_TEST1;
    std::string moduleName = "";
    std::string abilityName = "";
    MockInstallBundle(BUNDLE_NAME_TEST, moduleName, abilityName, false, false);
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 0;
    int32_t userId = 200;
    auto ret = mgr_.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    EXPECT_FALSE(ret);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_1700
 * @tc.name: Test CheckAbilityEnableInstall
 * @tc.desc: Verify the CheckAbilityEnableInstall return true.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_1700, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    ElementName element;
    std::string deviceId = "deviceId";
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = "com.example.MyModuleName";
    std::string abilityName = "com.example.MyApplication.MainAbility";
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 0;
    int32_t userId = 0;
    auto ret = mgr_.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
    EXPECT_FALSE(ret);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_0900
 * @tc.name: Test CheckAbilityEnableInstall
 * @tc.desc: Verify the CheckAbilityEnableInstall return false.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_1800, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    Want want;
    ElementName element;
    std::string deviceId = "deviceId";
    std::string bundleName = "com.example.MyModuleName";
    std::string moduleName = "com.example.MyModuleName";
    std::string abilityName = "com.example.MyApplication.MainAbility";
    MockInstallBundle(BUNDLE_NAME_TEST, moduleName, abilityName, false, false);
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 100;
    auto ret = mgr_.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
    EXPECT_FALSE(ret);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    sleep(1);
}
/**
 * @tc.number: BundleDistributedManager_1900
 * @tc.name: Test QueryRpcIdByAbilityToServiceCenter
 * @tc.desc: Verify the QueryRpcIdByAbilityToServiceCenter return true.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_1900, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    std::string bundleName = "com.example.MyApplication";
    std::string moduleName = "com.example.MyModuleName";
    std::string abilityName = "com.example.MyApplication.MainAbility";
    TargetAbilityInfo targetAbilityInfo;
    targetAbilityInfo.targetInfo.abilityName = abilityName;
    targetAbilityInfo.targetInfo.moduleName = moduleName;
    targetAbilityInfo.targetInfo.bundleName = bundleName;
    auto ret = mgr_.QueryRpcIdByAbilityToServiceCenter(targetAbilityInfo);
    EXPECT_FALSE(ret);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2000
 * @tc.name: Test QueryRpcIdByAbilityToServiceCenter
 * @tc.desc: Verify the QueryRpcIdByAbilityToServiceCenter return true.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2000, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = "com.example.MyModuleName";
    std::string abilityName = "com.example.MyApplication.MainAbility";
    TargetAbilityInfo targetAbilityInfo;
    targetAbilityInfo.targetInfo.abilityName = abilityName;
    targetAbilityInfo.targetInfo.moduleName = moduleName;
    targetAbilityInfo.targetInfo.bundleName = bundleName;
    auto ret = mgr_.QueryRpcIdByAbilityToServiceCenter(targetAbilityInfo);
    EXPECT_FALSE(ret);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2100
 * @tc.name: Test QueryRpcIdByAbilityToServiceCenter
 * @tc.desc: Verify the QueryRpcIdByAbilityToServiceCenter return true.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2100, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    TargetAbilityInfo targetAbilityInfo;
    auto ret = mgr_.QueryRpcIdByAbilityToServiceCenter(targetAbilityInfo);
    EXPECT_FALSE(ret);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2200
 * @tc.name: Test OutTimeMonitor
 * @tc.desc: Verify the OutTimeMonitor.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2200, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    mgr_.handler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>();
    std::string transactId = "transactId";
    mgr_.OutTimeMonitor(transactId);
    EXPECT_FALSE(mgr_.handler_ == nullptr);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2300
 * @tc.name: Test OutTimeMonitor
 * @tc.desc: Verify the OutTimeMonitor.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2300, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    mgr_.handler_ = nullptr;
    std::string transactId = "transactId";
    mgr_.OutTimeMonitor(transactId);
    EXPECT_FALSE(mgr_.handler_ != nullptr);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2400
 * @tc.name: Test OutTimeMonitor
 * @tc.desc: Verify the OutTimeMonitor.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2400, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    mgr_.handler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>();
    std::string transactId = "";
    mgr_.OutTimeMonitor(transactId);
    EXPECT_FALSE(mgr_.handler_ == nullptr);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2500
 * @tc.name: Test OutTimeMonitor
 * @tc.desc: Verify the OutTimeMonitor.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2500, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    mgr_.handler_ = nullptr;
    std::string transactId = "";
    mgr_.OutTimeMonitor(transactId);
    EXPECT_FALSE(mgr_.handler_ != nullptr);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2600
 * @tc.name: Test OnQueryRpcIdFinished
 * @tc.desc: Verify the OnQueryRpcIdFinished.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2600, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    std::string queryRpcIdResult = "{\"appQuickFix\":{\"bundleName\":\"\",\"deployedAppqfInfo\":{\"cpuAbi\":\"\",\"hqfInfos\":[],\"nativeLibraryPath\":\"\",\"type\":0,\"versionCode\":0,\"versionName\":\"\"}}";
    mgr_.OnQueryRpcIdFinished(queryRpcIdResult);
    EXPECT_TRUE(mgr_.queryAbilityParamsMap_.size() == 0);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2700
 * @tc.name: Test OnQueryRpcIdFinished
 * @tc.desc: Verify the OnQueryRpcIdFinished.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2700, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    std::string queryRpcIdResult = "";
    mgr_.OnQueryRpcIdFinished(queryRpcIdResult);
    EXPECT_TRUE(mgr_.queryAbilityParamsMap_.size() == 0);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2800
 * @tc.name: Test SendCallbackRequest
 * @tc.desc: Verify the SendCallbackRequest.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2800, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    QueryRpcIdParams param;
    param.missionId = 0;
    mgr_.queryAbilityParamsMap_.emplace("transactId", param);
    std::string transactId = "";
    int32_t resultCode = 0;
    mgr_.SendCallbackRequest(resultCode, transactId);
    EXPECT_FALSE(mgr_.queryAbilityParamsMap_.size() == 0);
    mgr_.queryAbilityParamsMap_.erase("transactId");
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2900
 * @tc.name: Test SendCallbackRequest
 * @tc.desc: Verify the SendCallbackRequest.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2900, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    QueryRpcIdParams param;
    param.missionId = 0;
    mgr_.queryAbilityParamsMap_.emplace("transactId", param);
    std::string transactId = "transactId";
    int32_t resultCode = 0;
    mgr_.SendCallbackRequest(resultCode, transactId);
    EXPECT_TRUE(mgr_.queryAbilityParamsMap_.size() == 0);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_3000
 * @tc.name: Test SendCallback
 * @tc.desc: Verify the SendCallback.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_3000, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr_;
    QueryRpcIdParams param;
    int32_t resultCode = 0;
    mgr_.SendCallback(resultCode, param);
    EXPECT_TRUE(param.callback == nullptr);
    sleep(1);
}
}