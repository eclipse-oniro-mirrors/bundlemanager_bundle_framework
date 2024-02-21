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
#include "bundle_framework_services_ipc_interface_code.h"
#include "bundle_mgr_service.h"
#include "installd/installd_service.h"
#include "bundle_manager_callback.h"
#include "bundle_manager_callback_stub.h"
#include "mock_bundle_manager_callback_stub.h"
#include "bundle_distributed_manager.h"
#include "bundle_manager_callback_proxy.h"
#include "scope_guard.h"
#define private public

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using OHOS::AAFwk::Want;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME_TEST = "com.example.bundlekit.test";
const std::string MODULE_NAME_TEST = "com.example.bundlekit.test.entry";
const std::string BUNDLE_LABEL = "Hello, OHOS";
const std::string BUNDLE_DESCRIPTION = "example helloworld";
const std::string BUNDLE_NAME_TEST1 = "com.example.bundlekit.test1";
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
const int DEFAULT_FORM_HEIGHT = 100;
const int DEFAULT_FORM_WIDTH = 200;
const ModuleColorMode COLOR_MODE = ModuleColorMode::AUTO;
const std::string CODE_PATH = "/data/app/el1/bundle/public/com.example.bundlekit.test";
const std::string RESOURCE_PATH = "/data/app/el1/bundle/public/com.example.bundlekit.test/res";
const std::string LIB_PATH = "/data/app/el1/bundle/public/com.example.bundlekit.test/lib";
const bool VISIBLE = true;
const std::string EMPTY_STRING = "";
const std::string URI = "dataability://com.example.hiworld.himusic.UserADataAbility";
const std::string FILES_DIR = "/data/app/el2/100/base/com.example.bundlekit.test/files";
const std::string DATA_BASE_DIR = "/data/app/el2/100/database/com.example.bundlekit.test";
const std::string CACHE_DIR = "/data/app/el2/100/base/com.example.bundlekit.test/cache";
const std::string SCHEME_SEPARATOR = "://";
const std::string PORT_SEPARATOR = ":";
const std::string PATH_SEPARATOR = "/";
const std::string SCHEME_001 = "scheme001";
const std::string HOST_001 = "host001";
const std::string PORT_001 = "port001";
const std::string PATH_001 = "path001";
const std::string PATH_REGEX_001 = ".*";
const std::string PATH_REGEX_002 = ".";
const int32_t BASE_TEST_UID = 65535;
const int32_t DEFAULT_USERID = 100;
const int32_t TEST_UID = 20065535;
const int APPLICATION_INFO_FLAGS = 1;
const std::string LOCALE = "locale";
const std::string NAME = "name";
const std::string VALUE = "value";
const std::string EXTRA = "extra";
std::string ABILITY_PERM_001 = "abilityPerm001";
std::string ABILITY_PERM_002 = "abilityPerm002";
std::string MY_APPLICATION_PERMISSION_TEST = "com.example.MyApplication.permissiontest";
std::string MY_APPLICATION_PERMISSION_BASE = "com.example.MyApplication.permissionbase";
std::string INSTALL_RESULT = "installResult";
std::string DEVICE_ID_NORMAL = "deviceId";
std::string QUERY_RPC_ID_RESULT = "queryRpcIdResult";
std::string BUNDLE_NAME_MY_APPLICATION = "com.example.MyApplication";
std::string MODULE_NAME_MY_APPLICATION = "com.example.MyModuleName";
std::string ABILITY_NAME_MY_APPLICATION = "com.example.MyApplication.MainAbility";
std::string RPC_ID = "rpcId";
std::string TRANSACT_ID = "transactId";
std::string QUERY_RET_PERFIX = "{\"appQuickFix\":{\"bundleName\":\"\",\"deployedAppqfInfo\EMPTY_STRING";
std::string QUERY_RET = ":{\"cpuAbi\":\"\",\"hqfInfos\":[],";
std::string QUERY_RET_SUFFIX = "\"nativeLibraryPath\":\"\",\"type\":0,\"versionCode\":0,\"versionName\":\"\"}}";
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
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    NotifyBundleEvents installRes_;
};

std::shared_ptr<BundleMgrService> BmsBundleKitServiceBaseTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleKitServiceBaseTest::installdService_ =
    std::make_shared<InstalldService>();

void BmsBundleKitServiceBaseTest::SetUpTestCase()
{}

void BmsBundleKitServiceBaseTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleKitServiceBaseTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(DEFAULT_USERID);
    }
}

void BmsBundleKitServiceBaseTest::TearDown()
{}

void BmsBundleKitServiceBaseTest::MockInstallBundle(
    const std::string &bundleName, const std::string &moduleName, const std::string &abilityName,
    bool userDataClearable, bool isSystemApp) const
{
    InnerModuleInfo moduleInfo = MockModuleInfo(moduleName);
    std::string keyName = bundleName + PATH_REGEX_002 + moduleName + PATH_REGEX_002 + abilityName;
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
    abilityInfo.configChanges = {LOCALE};
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
        NAME,
        VALUE,
        EXTRA
    };
    MetaData metaData {
        {customizeData}
    };
    abilityInfo.metaData = metaData;
    abilityInfo.permissions = {ABILITY_PERM_001, ABILITY_PERM_002};
    return abilityInfo;
}

InnerModuleInfo BmsBundleKitServiceBaseTest::MockModuleInfo(const std::string &moduleName) const
{
    InnerModuleInfo moduleInfo;
    RequestPermission reqPermissionTest;
    reqPermissionTest.name = MY_APPLICATION_PERMISSION_TEST;
    RequestPermission reqPermissionBase;
    reqPermissionBase.name = MY_APPLICATION_PERMISSION_BASE;
    moduleInfo.requestPermissions = {reqPermissionTest, reqPermissionBase};
    moduleInfo.name = MODULE_NAME_TEST;
    moduleInfo.icon = ICON_PATH;
    moduleInfo.modulePackage = PACKAGE_NAME;
    moduleInfo.moduleName = moduleName;
    moduleInfo.description = BUNDLE_DESCRIPTION;
    moduleInfo.colorMode = COLOR_MODE;
    moduleInfo.label = LABEL;

    AppExecFwk::CustomizeData customizeData {NAME, VALUE, EXTRA};
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

    InnerBundleUserInfo innerBundleUserInfoTest;
    innerBundleUserInfoTest.bundleName = bundleName;
    innerBundleUserInfoTest.bundleUserInfo.enabled = true;
    innerBundleUserInfoTest.bundleUserInfo.userId = DEFAULT_USERID;
    innerBundleUserInfoTest.uid = TEST_UID;

    ApplicationInfo appInfo;
    AddApplicationInfo(bundleName, appInfo, userDataClearable, isSystemApp);
    BundleInfo bundleInfo;
    innerBundleInfo.SetBaseApplicationInfo(appInfo);
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfoTest);
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
    std::weak_ptr<BundleDistributedManager> serverWptr = server;
    BundleManagerCallback bmcb(serverWptr);
    std::string nullString = EMPTY_STRING;
    auto result = bmcb.OnQueryRpcIdFinished(nullString);
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
    std::weak_ptr<BundleDistributedManager> serverWptr = server;
    BundleManagerCallback bmcb(serverWptr);
    std::string installResult = INSTALL_RESULT;
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
    std::weak_ptr<BundleDistributedManager> serverWptr;
    BundleManagerCallback bmcb(serverWptr);
    std::string queryRpcIdResult = QUERY_RPC_ID_RESULT;
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
    std::weak_ptr<BundleDistributedManager> serverWptr;
    BundleManagerCallback bmcb(serverWptr);
    std::string nullString = EMPTY_STRING;
    auto result = bmcb.OnQueryRpcIdFinished(nullString);
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
    BundleManagerCallbackProxy proxy(nullptr);
    std::string installResult = INSTALL_RESULT;
    auto result = proxy.OnQueryRpcIdFinished(installResult);
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
    BundleManagerCallbackProxy proxy(nullptr);
    std::string nullString = EMPTY_STRING;
    auto result = proxy.OnQueryRpcIdFinished(nullString);
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
    MockBundleManagerCallbackStub stub;
    uint32_t code = static_cast<uint32_t>(BundleManagerCallbackInterfaceCode::QUERY_RPC_ID_CALLBACK);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto result = stub.OnRemoteRequest(code, data, reply, option);
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
    MockBundleManagerCallbackStub stub;
    uint32_t code = -1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto result = stub.OnRemoteRequest(code, data, reply, option);
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
    MockBundleManagerCallbackStub stub;
    uint32_t code = -1;
    MessageParcel data;
    data.WriteInterfaceToken(BundleManagerCallbackStub::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    auto result = stub.OnRemoteRequest(code, data, reply, option);
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
    MockBundleManagerCallbackStub stub;
    uint32_t code = 0;
    MessageParcel data;
    data.WriteInterfaceToken(BundleManagerCallbackStub::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    auto result = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, 0);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_0200
 * @tc.name: Test ConvertTargetAbilityInfo
 * @tc.desc: Verify the ConvertTargetAbilityInfo return true.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_0200, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr;
    Want want;
    ElementName element;
    std::string deviceId = DEVICE_ID_NORMAL;
    std::string bundleName = BUNDLE_NAME_MY_APPLICATION;
    std::string moduleName = MODULE_NAME_MY_APPLICATION;
    std::string abilityName = ABILITY_NAME_MY_APPLICATION;
    want.SetElementName(deviceId, bundleName, abilityName, moduleName);
    TargetAbilityInfo targetAbilityInfo;
    auto ret = mgr.ConvertTargetAbilityInfo(want, targetAbilityInfo);
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
    BundleDistributedManager mgr;
    Want want;
    ElementName element;
    std::string nullString = EMPTY_STRING;
    TargetAbilityInfo targetAbilityInfo;
    auto ret = mgr.ConvertTargetAbilityInfo(want, targetAbilityInfo);
    EXPECT_EQ(targetAbilityInfo.targetInfo.bundleName, nullString);
    EXPECT_EQ(targetAbilityInfo.targetInfo.moduleName, nullString);
    EXPECT_EQ(targetAbilityInfo.targetInfo.abilityName, nullString);
    EXPECT_TRUE(ret);
    sleep(1);
}

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
/**
 * @tc.number: BundleDistributedManager_0400
 * @tc.name: Test ComparePcIdString
 * @tc.desc: Verify the ComparePcIdString return DECODE_SYS_CAP_FAILED.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_0400, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr;
    Want want;
    RpcIdResult rpcIdResult;
    ElementName element;
    std::string deviceId = DEVICE_ID_NORMAL;
    std::string bundleName = BUNDLE_NAME_MY_APPLICATION;
    std::string moduleName = MODULE_NAME_MY_APPLICATION;
    std::string abilityName = ABILITY_NAME_MY_APPLICATION;
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    rpcIdResult.abilityInfo.rpcId.emplace_back(RPC_ID);
    auto ret = mgr.ComparePcIdString(want, rpcIdResult);
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
    BundleDistributedManager mgr;
    Want want;
    RpcIdResult rpcIdResult;
    ElementName element;
    std::string deviceId = DEVICE_ID_NORMAL;
    std::string bundleName = BUNDLE_NAME_MY_APPLICATION;
    std::string moduleName = MODULE_NAME_MY_APPLICATION;
    std::string abilityName = ABILITY_NAME_MY_APPLICATION;
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    auto ret = mgr.ComparePcIdString(want, rpcIdResult);
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
    BundleDistributedManager mgr;
    Want want;
    RpcIdResult rpcIdResult;
    rpcIdResult.abilityInfo.rpcId.emplace_back(RPC_ID);
    auto ret = mgr.ComparePcIdString(want, rpcIdResult);
    EXPECT_EQ(ret, GET_DEVICE_PROFILE_FAILED);
    sleep(1);
}
#endif

/**
 * @tc.number: BundleDistributedManager_0700
 * @tc.name: Test CheckAbilityEnableInstall
 * @tc.desc: Verify the CheckAbilityEnableInstall return false.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_0700, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr;
    Want want;
    int32_t missionId = 0;
    int32_t userId = 0;
    auto ret = mgr.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
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
    BundleDistributedManager mgr;
    Want want;
    ElementName element;
    std::string deviceId = DEVICE_ID_NORMAL;
    std::string bundleName = BUNDLE_NAME_MY_APPLICATION;
    std::string moduleName = MODULE_NAME_MY_APPLICATION;
    std::string abilityName = ABILITY_NAME_MY_APPLICATION;
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 0;
    int32_t userId = 0;
    auto ret = mgr.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
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
    BundleDistributedManager mgr;
    Want want;
    ElementName element;
    std::string deviceId = DEVICE_ID_NORMAL;
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = MODULE_NAME_MY_APPLICATION;
    std::string abilityName = ABILITY_NAME_MY_APPLICATION;
    MockInstallBundle(bundleName, moduleName, abilityName, false, false);
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 100;
    auto ret = mgr.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
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
    BundleDistributedManager mgr;
    Want want;
    ElementName element;
    std::string deviceId = EMPTY_STRING;
    std::string bundleName = EMPTY_STRING;
    std::string moduleName = MODULE_NAME_MY_APPLICATION;
    std::string abilityName = ABILITY_NAME_MY_APPLICATION;
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 0;
    auto ret = mgr.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
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
    BundleDistributedManager mgr;
    Want want;
    ElementName element;
    std::string deviceId = EMPTY_STRING;
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = MODULE_NAME_MY_APPLICATION;
    std::string abilityName = ABILITY_NAME_MY_APPLICATION;
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 200;
    auto ret = mgr.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
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
    BundleDistributedManager mgr;
    Want want;
    ElementName element;
    std::string deviceId = EMPTY_STRING;
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = EMPTY_STRING;
    std::string abilityName = EMPTY_STRING;
    MockInstallBundle(bundleName, moduleName, abilityName, true, false);
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 100;
    auto ret = mgr.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
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
    BundleDistributedManager mgr;
    Want want;
    ElementName element;
    std::string deviceId = EMPTY_STRING;
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = EMPTY_STRING;
    std::string abilityName = EMPTY_STRING;
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 200;
    auto ret = mgr.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
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
    BundleDistributedManager mgr;
    Want want;
    ElementName element;
    std::string deviceId = EMPTY_STRING;
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = EMPTY_STRING;
    std::string abilityName = EMPTY_STRING;
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 0;
    auto ret = mgr.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
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
    BundleDistributedManager mgr;
    Want want;
    ElementName element;
    std::string deviceId = DEVICE_ID_NORMAL;
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = MODULE_NAME_MY_APPLICATION;
    std::string abilityName = ABILITY_NAME_MY_APPLICATION;
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 0;
    auto ret = mgr.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
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
    BundleDistributedManager mgr;
    Want want;
    ElementName element;
    std::string deviceId = EMPTY_STRING;
    std::string bundleName = BUNDLE_NAME_TEST1;
    std::string moduleName = EMPTY_STRING;
    std::string abilityName = EMPTY_STRING;
    MockInstallBundle(BUNDLE_NAME_TEST, moduleName, abilityName, false, false);
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 0;
    int32_t userId = 200;
    auto ret = mgr.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
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
    BundleDistributedManager mgr;
    Want want;
    ElementName element;
    std::string deviceId = DEVICE_ID_NORMAL;
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = MODULE_NAME_MY_APPLICATION;
    std::string abilityName = ABILITY_NAME_MY_APPLICATION;
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 0;
    int32_t userId = 0;
    auto ret = mgr.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
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
    BundleDistributedManager mgr;
    Want want;
    ElementName element;
    std::string deviceId = DEVICE_ID_NORMAL;
    std::string bundleName = MODULE_NAME_MY_APPLICATION;
    std::string moduleName = MODULE_NAME_MY_APPLICATION;
    std::string abilityName = ABILITY_NAME_MY_APPLICATION;
    MockInstallBundle(BUNDLE_NAME_TEST, moduleName, abilityName, false, false);
    want.SetElementName(deviceId, bundleName, moduleName, abilityName);
    int32_t missionId = 100;
    int32_t userId = 100;
    auto ret = mgr.CheckAbilityEnableInstall(want, missionId, userId, nullptr);
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
    BundleDistributedManager mgr;
    std::string bundleName = BUNDLE_NAME_MY_APPLICATION;
    std::string moduleName = MODULE_NAME_MY_APPLICATION;
    std::string abilityName = ABILITY_NAME_MY_APPLICATION;
    TargetAbilityInfo targetAbilityInfo;
    targetAbilityInfo.targetInfo.abilityName = abilityName;
    targetAbilityInfo.targetInfo.moduleName = moduleName;
    targetAbilityInfo.targetInfo.bundleName = bundleName;
    setuid(Constants::FOUNDATION_UID);
    ScopeGuard uidGuard([&] { setuid(Constants::ROOT_UID); });
    auto ret = mgr.QueryRpcIdByAbilityToServiceCenter(targetAbilityInfo);
#ifdef USE_ARM64
    EXPECT_TRUE(ret);
#else
    EXPECT_TRUE(ret);
#endif
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2000
 * @tc.name: Test QueryRpcIdByAbilityToServiceCenter
 * @tc.desc: Verify the QueryRpcIdByAbilityToServiceCenter return true.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2000, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr;
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = MODULE_NAME_MY_APPLICATION;
    std::string abilityName = ABILITY_NAME_MY_APPLICATION;
    TargetAbilityInfo targetAbilityInfo;
    targetAbilityInfo.targetInfo.abilityName = abilityName;
    targetAbilityInfo.targetInfo.moduleName = moduleName;
    targetAbilityInfo.targetInfo.bundleName = bundleName;
    setuid(Constants::FOUNDATION_UID);
    ScopeGuard uidGuard([&] { setuid(Constants::ROOT_UID); });
    auto ret = mgr.QueryRpcIdByAbilityToServiceCenter(targetAbilityInfo);
#ifdef USE_ARM64
    EXPECT_TRUE(ret);
#else
    EXPECT_TRUE(ret);
#endif
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2100
 * @tc.name: Test QueryRpcIdByAbilityToServiceCenter
 * @tc.desc: Verify the QueryRpcIdByAbilityToServiceCenter return true.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2100, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr;
    TargetAbilityInfo targetAbilityInfo;
    setuid(Constants::FOUNDATION_UID);
    ScopeGuard uidGuard([&] { setuid(Constants::ROOT_UID); });
    auto ret = mgr.QueryRpcIdByAbilityToServiceCenter(targetAbilityInfo);
#ifdef USE_ARM64
    EXPECT_TRUE(ret);
#else
    EXPECT_TRUE(ret);
#endif
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2600
 * @tc.name: Test OnQueryRpcIdFinished
 * @tc.desc: Verify the OnQueryRpcIdFinished.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2600, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr;
    std::string queryRetPerfix = QUERY_RET_PERFIX;
    std::string queryRet = QUERY_RET;
    std::string queryRetSuffix = QUERY_RET_SUFFIX;
    std::string queryRpcIdResult = queryRetPerfix + queryRet + queryRetSuffix;
    mgr.OnQueryRpcIdFinished(queryRpcIdResult);
    EXPECT_TRUE(mgr.queryAbilityParamsMap_.size() == 0);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2700
 * @tc.name: Test OnQueryRpcIdFinished
 * @tc.desc: Verify the OnQueryRpcIdFinished.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2700, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr;
    std::string queryRpcIdResult = EMPTY_STRING;
    mgr.OnQueryRpcIdFinished(queryRpcIdResult);
    EXPECT_TRUE(mgr.queryAbilityParamsMap_.size() == 0);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2800
 * @tc.name: Test SendCallbackRequest
 * @tc.desc: Verify the SendCallbackRequest.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2800, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr;
    QueryRpcIdParams param;
    param.missionId = 0;
    mgr.queryAbilityParamsMap_.emplace(TRANSACT_ID, param);
    std::string transactId = EMPTY_STRING;
    int32_t resultCode = 0;
    mgr.SendCallbackRequest(resultCode, transactId);
    EXPECT_FALSE(mgr.queryAbilityParamsMap_.size() == 0);
    mgr.queryAbilityParamsMap_.erase(TRANSACT_ID);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_2900
 * @tc.name: Test SendCallbackRequest
 * @tc.desc: Verify the SendCallbackRequest.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_2900, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr;
    QueryRpcIdParams param;
    param.missionId = 0;
    mgr.queryAbilityParamsMap_.emplace(TRANSACT_ID, param);
    std::string transactId = TRANSACT_ID;
    int32_t resultCode = 0;
    mgr.SendCallbackRequest(resultCode, transactId);
    EXPECT_TRUE(mgr.queryAbilityParamsMap_.size() == 0);
    sleep(1);
}

/**
 * @tc.number: BundleDistributedManager_3000
 * @tc.name: Test SendCallback
 * @tc.desc: Verify the SendCallback.
 */
HWTEST_F(BmsBundleKitServiceBaseTest, BundleDistributedManager_3000, Function | MediumTest | Level1)
{
    BundleDistributedManager mgr;
    QueryRpcIdParams param;
    int32_t resultCode = 0;
    mgr.SendCallback(resultCode, param);
    EXPECT_TRUE(param.callback == nullptr);
    sleep(1);
}
}