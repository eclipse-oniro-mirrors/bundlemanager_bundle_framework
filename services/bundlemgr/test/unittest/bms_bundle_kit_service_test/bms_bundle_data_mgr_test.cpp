/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <chrono>
#include <fstream>
#include <thread>
#include <gtest/gtest.h>

#include "ability_manager_client.h"
#include "ability_info.h"
#include "app_provision_info.h"
#include "app_provision_info_manager.h"
#include "bms_extension_client.h"
#include "bms_extension_profile.h"
#include "bundle_data_mgr.h"
#include "bundle_info.h"
#include "bundle_permission_mgr.h"
#include "bundle_mgr_ext.h"
#include "bundle_mgr_ext_register.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "bundle_mgr_host.h"
#include "bundle_mgr_proxy.h"
#include "bundle_status_callback_proxy.h"
#include "bundle_stream_installer_host_impl.h"
#include "bundle_exception_handler.h"
#include "clean_cache_callback_proxy.h"
#include "directory_ex.h"
#include "hidump_helper.h"
#include "install_param.h"
#include "extension_ability_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "inner_bundle_info.h"
#include "launcher_service.h"
#include "mock_clean_cache.h"
#include "mock_bundle_status.h"
#include "nlohmann/json.hpp"
#include "perf_profile.h"
#include "plugin/plugin_bundle_info.h"
#include "pre_bundle_profile.h"
#include "scope_guard.h"
#include "service_control.h"
#include "system_ability_helper.h"
#include "want.h"
#include "user_unlocked_event_subscriber.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using OHOS::AAFwk::Want;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME_TEST = "com.example.bundlekit.test";
const std::string MODULE_NAME_TEST = "com.example.bundlekit.test.entry";
const std::string MODULE_NAME_TEST1 = "com.example.bundlekit.test.entry1";
const std::string ABILITY_NAME_TEST = ".Reading";
const std::string BUNDLE_TEST1 = "bundleName1";
const std::string BUNDLE_TEST2 = "bundleName2";
const std::string BUNDLE_TEST3 = "bundleName3";
const std::string BUNDLE_TEST4 = "bundleName4";
const std::string BUNDLE_TEST5 = "bundleName5";
const std::string MODULE_TEST = "moduleNameTest";
const std::string ABILITY_NAME_TEST1 = ".Reading1";
const int32_t BASE_TEST_UID = 65535;
const int32_t TEST_UID = 20065535;
const int32_t TEST_MAX_UID = 20065534;
const std::string BUNDLE_LABEL = "Hello, OHOS";
const std::string BUNDLE_DESCRIPTION = "example helloworld";
const std::string BUNDLE_VENDOR = "example";
const std::string BUNDLE_VERSION_NAME = "1.0.0.1";
const int32_t BUNDLE_MAX_SDK_VERSION = 0;
const int32_t BUNDLE_MIN_SDK_VERSION = 0;
const std::string BUNDLE_JOINT_USERID = "3";
const uint32_t BUNDLE_VERSION_CODE = 1001;
const std::string BUNDLE_NAME_DEMO = "com.example.bundlekit.demo";
const std::string MODULE_NAME_DEMO = "com.example.bundlekit.demo.entry";
const std::string MODULE_NAME1 = "moduleName1";
const std::string ABILITY_NAME_DEMO = ".Writing";
const std::string PACKAGE_NAME = "com.example.bundlekit.test.entry";
const std::string PROCESS_TEST = "test.process";
const std::string DEVICE_ID = "PHONE-001";
const int APPLICATION_INFO_FLAGS = 1;
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
const std::string MAIN_ENTRY = "com.example.bundlekit.test.entry";
const std::string URI = "dataability://com.example.hiworld.himusic.UserADataAbility";
const std::string HAP_FILE_PATH = "/data/test/resource/bms/bundle_kit/test.hap";
const std::string FILES_DIR = "/data/app/el2/100/base/com.example.bundlekit.test/files";
const std::string DATA_BASE_DIR = "/data/app/el2/100/database/com.example.bundlekit.test";
const std::string CACHE_DIR = "/data/app/el2/100/base/com.example.bundlekit.test/cache";
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
constexpr int32_t FORM_JS_WINDOW_DESIGNWIDTH = 720;
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
const std::string EXT_NAME = "extName";
const std::string MIME_TYPE = "application/x-maker";
const std::string EMPTY_STRING = "";
const std::string TEST_DATA_GROUP_ID = "1";
const std::string TEST_URI_HTTPS = "https://www.test.com";
const std::string TEST_URI_HTTP = "http://www.test.com";
const std::string META_DATA_SHORTCUTS_NAME = "ohos.ability.shortcuts";
constexpr int32_t MOCK_BUNDLE_MGR_EXT_FLAG = 10;
const std::string BMS_EXTENSION_PATH = "/system/etc/app/bms-extensions.json";
const nlohmann::json APP_LIST0 = R"(
{
    "app_list": [
        {
            "app_dir":"/data/preload/app/app_dir",
            "appIdentifier":"5765880207853134833"
        }
    ]
}
)"_json;
const nlohmann::json APP_LIST1 = R"(
{
    "app_list": [
        {
            "app_dir":"app_dir",
            "appIdentifier":"5765880207853134833"
        }
    ]
}
)"_json;
const nlohmann::json APP_LIST2 = R"(
{
    "app_list": [
        {
            "app_dir1":"app_dir",
            "appIdentifier":""
        }
    ]
}
)"_json;
const nlohmann::json APP_LIST3 = R"(
{
    "app_list":
        {
            "app_dir1":"app_dir",
            "appIdentifier1":"5765880207853134833"
        }
}
)"_json;
const nlohmann::json INSTALL_LIST = R"(
{
    "install_list": [
        {
            "app_dir":"app_dir",
            "removable":true
        }
    ]
}
)"_json;
const nlohmann::json INSTALL_LIST1 = R"(
{
    "install_list1": [
        {
            "app_dir":"app_dir",
            "removable":true
        }
    ]
}
)"_json;
const nlohmann::json INSTALL_LIST2 = R"(
{
    "install_list":
        {
            "app_dir":"app_dir",
            "removable":true
        }
}
)"_json;
const nlohmann::json INSTALL_LIST3 = R"(
{
    "install_list":
        [{
            "bundleName":"bundleName",
            "keepAlive":true,
            "singleton":true,
            "allowCommonEvent":[],
            "app_signature":[],
            "runningResourcesApply":true,
            "associatedWakeUp":true,
            "allowAppDataNotCleared":true,
            "allowAppMultiProcess":true,
            "allowAppDesktopIconHide":true,
            "allowAbilityPriorityQueried":true,
            "allowAbilityExcludeFromMissions":true,
            "allowMissionNotCleared":true,
            "allowAppUsePrivilegeExtension":true,
            "allowFormVisibleNotify":true,
            "allowAppShareLibrary":true,
            "resourceApply":[0, 1]
        }]
}
)"_json;
const nlohmann::json INSTALL_LIST4 = R"(
{
    "install_list": [
        {
            "1":"app_dir",
            "1":true
        }
    ]
}
)"_json;
const nlohmann::json INSTALL_LIST5 = R"(
{
    "install_list": [
        {
            "app_dir":1,
            "removable":1
        }
    ]
}
)"_json;
const nlohmann::json INSTALL_LIST6 = R"(
{
    "install_list": [
        {
            "bundleName":true,
            "removable":"none"
        }
    ]
}
)"_json;
const nlohmann::json EXTENSION_TYPE_LIST = R"(
{
    "extensionType": [
        {
            "name":"test"
        }
    ]
}
)"_json;
const nlohmann::json EXTENSION_TYPE_LIST1 = R"(
{
    "extensionType1": [
        {
            "name":"test"
        }
    ]
}
)"_json;
const nlohmann::json EXTENSION_TYPE_LIST2 = R"(
{
    "extensionType":
        {
            "name":"test"
        }
}
)"_json;
const int FORMINFO_DESCRIPTIONID = 123;
const int ABILITYINFOS_SIZE_1 = 1;
const int ABILITYINFOS_SIZE_2 = 2;
const int32_t USERID = 100;
const int32_t MULTI_USERID = 101;
const int32_t WAIT_TIME = 5; // init mocked bms
const int32_t ICON_ID = 16777258;
const int32_t LABEL_ID = 16777257;
const int32_t SPACE_SIZE = 0;
const int32_t GET_ABILITY_INFO_WITH_APP_LINKING = 0x00000040;
constexpr int32_t MAX_APP_UID = 65535;
constexpr uint32_t TYPE_HARMONEY_INVALID_VALUE = 0;
constexpr uint32_t TYPE_HARMONEY_SERVICE_VALUE = 2;
constexpr uint32_t CALLING_TYPE_HARMONY_VALUE = 2;
constexpr uint32_t BIT_ZERO_COMPATIBLE_VALUE = 0;
const std::vector<std::string> &DISALLOWLIST = {"com.example.actsregisterjserrorrely"};
const std::string ENTRY = "entry";
const std::string FEATURE = "feature";
constexpr const char* OVERLAY_STATE = "overlayState";
const std::string CALLER_NAME_UT = "ut";
}  // namespace

struct Param {
    std::string moduleType;
    int32_t maxChildProcess = 0;
};

class MockBundleMgrExt : public BundleMgrExt {
public:
    bool CheckApiInfo(const BundleInfo& bundleInfo) override
    {
        return true;
    }

    ErrCode QueryAbilityInfosWithFlag(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos, bool isNewVersion = false) override
    {
        std::string Test{ "TEST" };
        if (want.GetElement().GetBundleName() == Test || flags == MOCK_BUNDLE_MGR_EXT_FLAG) {
            AbilityInfo info;
            abilityInfos.emplace_back(info);
        }
        return ERR_OK;
    }

    ErrCode GetBundleInfo(const std::string &bundleName, int32_t flags, int32_t userId,
        BundleInfo &bundleInfo, bool isNewVersion = false) override
    {
        return ERR_OK;
    }
};

class BmsBundleDataMgrTest : public testing::Test {
public:
    using Want = OHOS::AAFwk::Want;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
    const std::shared_ptr<BundleDistributedManager> GetBundleDistributedManager() const;
#endif
    static sptr<BundleMgrProxy> GetBundleMgrProxy();
    std::shared_ptr<LauncherService> GetLauncherService() const;
    void MockInnerBundleInfo(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const std::vector<Dependency> &dependencies,
        InnerBundleInfo &innerBundleInfo) const;
    void MockInnerBundleInfo(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, Param param, InnerBundleInfo &innerBundleInfo) const;
    void MockInstallBundle(
        const std::string &bundleName, const std::string &moduleName, const std::string &abilityName,
        bool userDataClearable = true, bool isSystemApp = false) const;
    void MockInstallExtension(
        const std::string &bundleName, const std::string &moduleName, const std::string &extensionName) const;
    void MockInstallBundle(
        const std::string &bundleName, const std::vector<std::string> &moduleNameList, const std::string &abilityName,
        bool userDataClearable = true, bool isSystemApp = false) const;
    void MockUninstallBundle(const std::string &bundleName) const;
    AbilityInfo MockAbilityInfo(
        const std::string &bundleName, const std::string &module, const std::string &abilityName) const;
    ExtensionAbilityInfo MockExtensionInfo(
        const std::string &bundleName, const std::string &module, const std::string &extensionName) const;
    InnerModuleInfo MockModuleInfo(const std::string &moduleName) const;
    FormInfo MockFormInfo(
        const std::string &bundleName, const std::string &module, const std::string &abilityName) const;
    ShortcutInfo MockShortcutInfo(const std::string &bundleName, const std::string &shortcutId) const;
    ShortcutIntent MockShortcutIntent() const;
    ShortcutWant MockShortcutWant() const;
    Shortcut MockShortcut() const;
    CommonEventInfo MockCommonEventInfo(const std::string &bundleName, const int uid) const;

    void AddBundleInfo(const std::string &bundleName, BundleInfo &bundleInfo) const;
    void AddApplicationInfo(const std::string &bundleName, ApplicationInfo &appInfo,
        bool userDataClearable = true, bool isSystemApp = false) const;
    void AddInnerBundleInfoByTest(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, InnerBundleInfo &innerBundleInfo) const;
    void SaveToDatabase(const std::string &bundleName, InnerBundleInfo &innerBundleInfo,
        bool userDataClearable, bool isSystemApp) const;
    void ClearDataMgr();
    void ResetDataMgr();
    void RemoveBundleinfo(const std::string &bundleName);
    ShortcutInfo InitShortcutInfo();
    bool CheckBmsExtensionProfile();

public:
    static std::shared_ptr<InstalldService> installdService_;
    std::shared_ptr<BundleMgrHostImpl> bundleMgrHostImpl_ = std::make_unique<BundleMgrHostImpl>();
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    std::shared_ptr<LauncherService> launcherService_ = std::make_shared<LauncherService>();
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr_ = std::make_shared<BundleCommonEventMgr>();
    std::shared_ptr<BundleUserMgrHostImpl> bundleUserMgrHostImpl_ = std::make_shared<BundleUserMgrHostImpl>();
    NotifyBundleEvents installRes_;
};

std::shared_ptr<BundleMgrService> BmsBundleDataMgrTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleDataMgrTest::installdService_ =
    std::make_shared<InstalldService>();

void BmsBundleDataMgrTest::SetUpTestCase()
{}

void BmsBundleDataMgrTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleDataMgrTest::SetUp()
{
    installRes_ = {
        .bundleName = HAP_FILE_PATH,
        .modulePackage = HAP_FILE_PATH,
        .abilityName = ABILITY_NAME_DEMO,
        .resultCode = ERR_OK,
        .type = NotifyType::INSTALL,
        .uid = Constants::INVALID_UID,
    };
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleDataMgrTest::TearDown()
{}

void BmsBundleDataMgrTest::ClearDataMgr()
{
    bundleMgrService_->dataMgr_ = nullptr;
}

void BmsBundleDataMgrTest::ResetDataMgr()
{
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(bundleMgrService_->dataMgr_, nullptr);
}

void BmsBundleDataMgrTest::RemoveBundleinfo(const std::string &bundleName)
{
    auto iterator = bundleMgrService_->GetDataMgr()->bundleInfos_.find(bundleName);
    if (iterator != bundleMgrService_->GetDataMgr()->bundleInfos_.end()) {
        bundleMgrService_->GetDataMgr()->bundleInfos_.erase(iterator);
    }
}
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
const std::shared_ptr<BundleDistributedManager> BmsBundleDataMgrTest::GetBundleDistributedManager() const
{
    return bundleMgrService_->GetBundleDistributedManager();
}
#endif

std::shared_ptr<BundleDataMgr> BmsBundleDataMgrTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

std::shared_ptr<LauncherService> BmsBundleDataMgrTest::GetLauncherService() const
{
    return launcherService_;
}

sptr<BundleMgrProxy> BmsBundleDataMgrTest::GetBundleMgrProxy()
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

void BmsBundleDataMgrTest::AddBundleInfo(const std::string &bundleName, BundleInfo &bundleInfo) const
{
    bundleInfo.name = bundleName;
    bundleInfo.label = BUNDLE_LABEL;
    bundleInfo.description = BUNDLE_DESCRIPTION;
    bundleInfo.vendor = BUNDLE_VENDOR;
    bundleInfo.versionCode = BUNDLE_VERSION_CODE;
    bundleInfo.versionName = BUNDLE_VERSION_NAME;
    bundleInfo.minSdkVersion = BUNDLE_MIN_SDK_VERSION;
    bundleInfo.maxSdkVersion = BUNDLE_MAX_SDK_VERSION;
    bundleInfo.mainEntry = MAIN_ENTRY;
    bundleInfo.isKeepAlive = true;
    bundleInfo.isDifferentName = true;
    bundleInfo.jointUserId = BUNDLE_JOINT_USERID;
    bundleInfo.singleton = true;
}

void BmsBundleDataMgrTest::AddApplicationInfo(const std::string &bundleName, ApplicationInfo &appInfo,
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

void BmsBundleDataMgrTest::AddInnerBundleInfoByTest(const std::string &bundleName,
    const std::string &moduleName, const std::string &abilityName, InnerBundleInfo &innerBundleInfo) const
{
    std::string keyName = bundleName + "." + moduleName + "." + abilityName;
    FormInfo form = MockFormInfo(bundleName, moduleName, abilityName);
    std::vector<FormInfo> formInfos;
    formInfos.emplace_back(form);
    if (bundleName == BUNDLE_NAME_TEST) {
        ShortcutInfo shortcut = MockShortcutInfo(bundleName, SHORTCUT_TEST_ID);
        std::string shortcutKey = bundleName + moduleName + SHORTCUT_TEST_ID;
        innerBundleInfo.InsertShortcutInfos(shortcutKey, shortcut);
    } else {
        ShortcutInfo shortcut = MockShortcutInfo(bundleName, SHORTCUT_DEMO_ID);
        std::string shortcutKey = bundleName + moduleName + SHORTCUT_DEMO_ID;
        innerBundleInfo.InsertShortcutInfos(shortcutKey, shortcut);
    }
    innerBundleInfo.InsertFormInfos(keyName, formInfos);
    std::string commonEventKey = bundleName + moduleName + abilityName;
    CommonEventInfo eventInfo = MockCommonEventInfo(bundleName, innerBundleInfo.GetUid(USERID));
    innerBundleInfo.InsertCommonEvents(commonEventKey, eventInfo);
}

void BmsBundleDataMgrTest::MockInstallBundle(
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
    Skill skill;
    skill.actions = {ACTION};
    skill.entities = {ENTITY};
    std::vector<Skill> skills;
    skills.emplace_back(skill);
    innerBundleInfo.InsertSkillInfo(keyName, skills);
    SaveToDatabase(bundleName, innerBundleInfo, userDataClearable, isSystemApp);
}

void BmsBundleDataMgrTest::MockInstallExtension(const std::string &bundleName,
    const std::string &moduleName, const std::string &extensionName) const
{
    InnerModuleInfo moduleInfo = MockModuleInfo(moduleName);
    std::string keyName = bundleName + "." + moduleName + "." + extensionName;
    std::string keyName02 = bundleName + "." + moduleName + "." + extensionName + "02";
    ExtensionAbilityInfo extensionInfo = MockExtensionInfo(bundleName, moduleName, extensionName);
    ExtensionAbilityInfo extensionInfo02 = MockExtensionInfo(bundleName, moduleName, extensionName + "02");
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertExtensionInfo(keyName, extensionInfo);
    innerBundleInfo.InsertExtensionInfo(keyName02, extensionInfo02);
    innerBundleInfo.InsertInnerModuleInfo(moduleName, moduleInfo);
    Skill skill;
    skill.actions = {ACTION};
    skill.entities = {ENTITY};
    std::vector<Skill> skills;
    skills.emplace_back(skill);
    innerBundleInfo.InsertExtensionSkillInfo(keyName, skills);
    innerBundleInfo.InsertExtensionSkillInfo(keyName02, skills);
    SaveToDatabase(bundleName, innerBundleInfo, false, false);
}

InnerModuleInfo BmsBundleDataMgrTest::MockModuleInfo(const std::string &moduleName) const
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

void BmsBundleDataMgrTest::SaveToDatabase(const std::string &bundleName,
    InnerBundleInfo &innerBundleInfo, bool userDataClearable, bool isSystemApp) const
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    innerBundleUserInfo.uid = BASE_TEST_UID;

    InnerBundleUserInfo innerBundleUserInfo1;
    innerBundleUserInfo1.bundleName = bundleName;
    innerBundleUserInfo1.bundleUserInfo.enabled = true;
    innerBundleUserInfo1.bundleUserInfo.userId = USERID;
    innerBundleUserInfo1.uid = TEST_UID;

    ApplicationInfo appInfo;
    AddApplicationInfo(bundleName, appInfo, userDataClearable, isSystemApp);
    BundleInfo bundleInfo;
    AddBundleInfo(bundleName, bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(appInfo);
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo1);
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    Security::AccessToken::AccessTokenIDEx accessTokenId;
    accessTokenId.tokenIDEx = 1;
    innerBundleInfo.SetAccessTokenIdEx(accessTokenId, USERID);
    auto moduleNameVec = innerBundleInfo.GetModuleNameVec();
    auto abilityNameVec = innerBundleInfo.GetAbilityNames();
    if (!moduleNameVec.empty() && !abilityNameVec.empty()) {
        AddInnerBundleInfoByTest(bundleName, moduleNameVec[0], abilityNameVec[0], innerBundleInfo);
    }
    bool startRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    bool addRet = dataMgr->AddInnerBundleInfo(bundleName, innerBundleInfo);
    bool endRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_SUCCESS);

    EXPECT_TRUE(startRet);
    EXPECT_TRUE(addRet);
    EXPECT_TRUE(endRet);
}

void BmsBundleDataMgrTest::MockInstallBundle(
    const std::string &bundleName, const std::vector<std::string> &moduleNameList, const std::string &abilityName,
    bool userDataClearable, bool isSystemApp) const
{
    if (moduleNameList.empty()) {
        return;
    }
    InnerBundleInfo innerBundleInfo;
    for (const auto &moduleName : moduleNameList) {
        InnerModuleInfo moduleInfo = MockModuleInfo(moduleName);
        std::string keyName = bundleName + "." + moduleName + "." + abilityName;
        AbilityInfo abilityInfo = MockAbilityInfo(bundleName, moduleName, abilityName);
        innerBundleInfo.InsertAbilitiesInfo(keyName, abilityInfo);
        innerBundleInfo.InsertInnerModuleInfo(moduleName, moduleInfo);
        Skill skill;
        skill.actions = {ACTION};
        skill.entities = {ENTITY};
        std::vector<Skill> skills;
        skills.emplace_back(skill);
        innerBundleInfo.InsertSkillInfo(keyName, skills);
    }
    SaveToDatabase(bundleName, innerBundleInfo, userDataClearable, isSystemApp);
}

FormInfo BmsBundleDataMgrTest::MockFormInfo(
    const std::string &bundleName, const std::string &moduleName, const std::string &abilityName) const
{
    FormInfo formInfo;
    formInfo.name = FORM_NAME;
    formInfo.bundleName = bundleName;
    formInfo.abilityName = abilityName;
    formInfo.moduleName = moduleName;
    formInfo.package = PACKAGE_NAME;
    formInfo.descriptionId = FORMINFO_DESCRIPTIONID;
    formInfo.formConfigAbility = FORM_PATH;
    formInfo.description = FORM_DESCRIPTION;
    formInfo.defaultFlag = false;
    formInfo.type = FormType::JS;
    formInfo.colorMode = FormsColorMode::LIGHT_MODE;
    formInfo.supportDimensions = {1, 2};
    formInfo.portraitLayouts = {FORM_PORTRAIT_LAYOUTS1, FORM_PORTRAIT_LAYOUTS2};
    formInfo.landscapeLayouts = {FORM_LANDSCAPE_LAYOUTS1, FORM_LANDSCAPE_LAYOUTS2};
    formInfo.defaultDimension = 1;
    formInfo.updateDuration = 0;
    formInfo.formVisibleNotify = true;
    formInfo.deepLink = FORM_PATH;
    formInfo.scheduledUpdateTime = FORM_SCHEDULED_UPDATE_TIME;
    formInfo.updateEnabled = true;
    formInfo.jsComponentName = FORM_JS_COMPONENT_NAME;
    formInfo.src = FORM_SRC;
    formInfo.window.autoDesignWidth = true;
    formInfo.window.designWidth = FORM_JS_WINDOW_DESIGNWIDTH;
    for (auto &info : formInfo.customizeDatas) {
        info.name = FORM_CUSTOMIZE_DATAS_NAME;
        info.value = FORM_CUSTOMIZE_DATAS_VALUE;
    }
    return formInfo;
}

ShortcutInfo BmsBundleDataMgrTest::MockShortcutInfo(
    const std::string &bundleName, const std::string &shortcutId) const
{
    ShortcutInfo shortcutInfos;
    shortcutInfos.id = shortcutId;
    shortcutInfos.bundleName = bundleName;
    shortcutInfos.hostAbility = SHORTCUT_HOST_ABILITY;
    shortcutInfos.icon = SHORTCUT_ICON;
    shortcutInfos.label = SHORTCUT_LABEL;
    shortcutInfos.disableMessage = SHORTCUT_DISABLE_MESSAGE;
    shortcutInfos.isStatic = true;
    shortcutInfos.isHomeShortcut = true;
    shortcutInfos.isEnables = true;
    ShortcutIntent shortcutIntent;
    shortcutIntent.targetBundle = SHORTCUT_INTENTS_TARGET_BUNDLE;
    shortcutIntent.targetModule = SHORTCUT_INTENTS_TARGET_MODULE;
    shortcutIntent.targetClass = SHORTCUT_INTENTS_TARGET_CLASS;
    shortcutInfos.intents.push_back(shortcutIntent);
    return shortcutInfos;
}

ShortcutIntent BmsBundleDataMgrTest::MockShortcutIntent() const
{
    ShortcutIntent shortcutIntent;
    shortcutIntent.targetBundle = SHORTCUT_INTENTS_TARGET_BUNDLE;
    shortcutIntent.targetModule = SHORTCUT_INTENTS_TARGET_MODULE;
    shortcutIntent.targetClass = SHORTCUT_INTENTS_TARGET_CLASS;
    return shortcutIntent;
}

ShortcutWant BmsBundleDataMgrTest::MockShortcutWant() const
{
    ShortcutWant shortcutWant;
    shortcutWant.bundleName = BUNDLE_NAME_DEMO;
    shortcutWant.moduleName = MODULE_NAME_DEMO;
    shortcutWant.abilityName = ABILITY_NAME_DEMO;
    return shortcutWant;
}

Shortcut BmsBundleDataMgrTest::MockShortcut() const
{
    Shortcut shortcut;
    shortcut.shortcutId = SHORTCUT_TEST_ID;
    shortcut.icon = SHORTCUT_ICON;
    shortcut.iconId = ICON_ID;
    shortcut.label = SHORTCUT_LABEL;
    shortcut.labelId = LABEL_ID;
    ShortcutWant want = MockShortcutWant();
    shortcut.wants.push_back(want);
    return shortcut;
}

CommonEventInfo BmsBundleDataMgrTest::MockCommonEventInfo(
    const std::string &bundleName, const int uid) const
{
    CommonEventInfo CommonEventInfo;
    CommonEventInfo.name = COMMON_EVENT_NAME;
    CommonEventInfo.bundleName = bundleName;
    CommonEventInfo.uid = uid;
    CommonEventInfo.permission = COMMON_EVENT_PERMISSION;
    CommonEventInfo.data.emplace_back(COMMON_EVENT_DATA);
    CommonEventInfo.type.emplace_back(COMMON_EVENT_TYPE);
    CommonEventInfo.events.emplace_back(COMMON_EVENT_EVENT);
    return CommonEventInfo;
}

void BmsBundleDataMgrTest::MockUninstallBundle(const std::string &bundleName) const
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool startRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START);
    bool finishRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS);

    EXPECT_TRUE(startRet);
    EXPECT_TRUE(finishRet);
}

AbilityInfo BmsBundleDataMgrTest::MockAbilityInfo(
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

ExtensionAbilityInfo BmsBundleDataMgrTest::MockExtensionInfo(
    const std::string &bundleName, const std::string &moduleName, const std::string &extensionName) const
{
    ExtensionAbilityInfo extensionInfo;
    extensionInfo.name = extensionName;
    extensionInfo.bundleName = bundleName;
    extensionInfo.moduleName = moduleName;
    return extensionInfo;
}

void BmsBundleDataMgrTest::MockInnerBundleInfo(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, const std::vector<Dependency> &dependencies,
    InnerBundleInfo &innerBundleInfo) const
{
    ApplicationInfo appInfo;
    appInfo.bundleName = bundleName;
    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.modulePackage = moduleName;
    moduleInfo.moduleName = moduleName;
    moduleInfo.description = BUNDLE_DESCRIPTION;
    moduleInfo.dependencies = dependencies;
    innerBundleInfo.InsertInnerModuleInfo(moduleName, moduleInfo);
    AbilityInfo abilityInfo = MockAbilityInfo(bundleName, moduleName, abilityName);
    std::string keyName = bundleName + "." + moduleName + "." + abilityName;
    innerBundleInfo.InsertAbilitiesInfo(keyName, abilityInfo);
    innerBundleInfo.SetBaseApplicationInfo(appInfo);
}

void BmsBundleDataMgrTest::MockInnerBundleInfo(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, Param param, InnerBundleInfo &innerBundleInfo) const
{
    ApplicationInfo appInfo;
    appInfo.bundleName = bundleName;
    appInfo.maxChildProcess = param.maxChildProcess;
    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    InnerModuleInfo moduleInfo;
    moduleInfo.modulePackage = moduleName;
    moduleInfo.moduleName = moduleName;
    moduleInfo.description = BUNDLE_DESCRIPTION;
    moduleInfo.distro.moduleType = param.moduleType;
    innerBundleInfo.InsertInnerModuleInfo(moduleName, moduleInfo);
    AbilityInfo abilityInfo = MockAbilityInfo(bundleName, moduleName, abilityName);
    std::string keyName = bundleName + "." + moduleName + "." + abilityName;
    innerBundleInfo.InsertAbilitiesInfo(keyName, abilityInfo);
    innerBundleInfo.SetBaseApplicationInfo(appInfo);
}

class IBundleEventCallbackTest : public IBundleEventCallback {
public:
    void OnReceiveEvent(const EventFwk::CommonEventData eventData);
    sptr<IRemoteObject> AsObject();
};

void IBundleEventCallbackTest::OnReceiveEvent(const EventFwk::CommonEventData eventData)
{}

sptr<IRemoteObject> IBundleEventCallbackTest::AsObject()
{
    return nullptr;
}

class ICleanCacheCallbackTest : public ICleanCacheCallback {
public:
    void OnCleanCacheFinished(bool succeeded);
    sptr<IRemoteObject> AsObject();
};

void ICleanCacheCallbackTest::OnCleanCacheFinished(bool succeeded)
{}

sptr<IRemoteObject> ICleanCacheCallbackTest::AsObject()
{
    return nullptr;
}

ShortcutInfo BmsBundleDataMgrTest::InitShortcutInfo()
{
    ShortcutInfo shortcutInfos;
    shortcutInfos.id = "id_test1";
    shortcutInfos.bundleName = "com.ohos.hello";
    shortcutInfos.hostAbility = "hostAbility";
    shortcutInfos.icon = "$media:16777224";
    shortcutInfos.label = "shortcutLabel";
    shortcutInfos.disableMessage = "shortcutDisableMessage";
    shortcutInfos.isStatic = true;
    shortcutInfos.isHomeShortcut = true;
    shortcutInfos.isEnables = true;
    return shortcutInfos;
}

bool BmsBundleDataMgrTest::CheckBmsExtensionProfile()
{
    BmsExtensionProfile bmsExtensionProfile;
    BmsExtension bmsExtension;
    auto res = bmsExtensionProfile.ParseBmsExtension(BMS_EXTENSION_PATH, bmsExtension);
    if (res != ERR_OK) {
        return false;
    }
    return true;
}

class IBundleStatusCallbackTest : public IBundleStatusCallback {
public:
    void OnBundleStateChanged(const uint8_t installType, const int32_t resultCode, const std::string &resultMsg,
        const std::string &bundleName);
    void OnBundleAdded(const std::string &bundleName, const int userId);
    void OnBundleUpdated(const std::string &bundleName, const int userId);
    void OnBundleRemoved(const std::string &bundleName, const int userId);
    sptr<IRemoteObject> AsObject();
};

void IBundleStatusCallbackTest::OnBundleStateChanged(const uint8_t installType,
    const int32_t resultCode, const std::string &resultMsg, const std::string &bundleName)
{}

void IBundleStatusCallbackTest::OnBundleAdded(const std::string &bundleName, const int userId)
{}

void IBundleStatusCallbackTest::OnBundleUpdated(const std::string &bundleName, const int userId)
{}

void IBundleStatusCallbackTest::OnBundleRemoved(const std::string &bundleName, const int userId)
{}

sptr<IRemoteObject> IBundleStatusCallbackTest::AsObject()
{
    return nullptr;
}

/**
 * @tc.number: AddInnerBundleInfo_0100
 * @tc.name: test LoadDataFromPersistentStorage
 * @tc.desc: 1.system run normally
 *           2.check LoadDataFromPersistentStorage failed
 */
HWTEST_F(BmsBundleDataMgrTest, AddInnerBundleInfo_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    GetBundleDataMgr()->installStates_.emplace(BUNDLE_TEST2, InstallState::INSTALL_SUCCESS);
    bool testRet = GetBundleDataMgr()->AddInnerBundleInfo(BUNDLE_TEST2, innerBundleInfo);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: QueryAbilityInfo_0100
 * @tc.name: test QueryAbilityInfo
 * @tc.desc: 1.system run normally
 *           2.check QueryAbilityInfo failed
 */
HWTEST_F(BmsBundleDataMgrTest, QueryAbilityInfo_0100, Function | SmallTest | Level1)
{
    Want want;
    AbilityInfo abilityInfo;
    int32_t appIndex = 1;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    bool testRet = GetBundleDataMgr()->QueryAbilityInfo(want, GET_ABILITY_INFO_DEFAULT, USERID, abilityInfo, appIndex);
    EXPECT_EQ(testRet, false);

    want.SetElementName("", ABILITY_NAME_TEST);
    testRet = GetBundleDataMgr()->QueryAbilityInfo(want, GET_ABILITY_INFO_DEFAULT, USERID, abilityInfo, appIndex);
    EXPECT_EQ(testRet, false);

    want.SetElementName(BUNDLE_NAME_TEST, "");
    testRet = GetBundleDataMgr()->QueryAbilityInfo(want, GET_ABILITY_INFO_DEFAULT, USERID, abilityInfo, appIndex);
    EXPECT_EQ(testRet, false);

    want.SetElementName("", "");
    testRet = GetBundleDataMgr()->QueryAbilityInfo(want, GET_ABILITY_INFO_DEFAULT, USERID, abilityInfo, appIndex);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: ExplicitQueryAbilityInfoV9_0100
 * @tc.name: test ExplicitQueryAbilityInfoV9
 * @tc.desc: 1.system run normally
 *           2.check ExplicitQueryAbilityInfoV9 failed
 */
HWTEST_F(BmsBundleDataMgrTest, ExplicitQueryAbilityInfoV9_0100, Function | SmallTest | Level1)
{
    Want want;
    AbilityInfo abilityInfo;
    int32_t appIndex = 1;
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->sandboxAppHelper_ = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    ErrCode testRet = GetBundleDataMgr()->ExplicitQueryAbilityInfoV9(
        want, GET_ABILITY_INFO_DEFAULT, USERID, abilityInfo, appIndex);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: ExplicitQueryAbilityInfoV9_0200
 * @tc.name: test ExplicitQueryAbilityInfoV9
 * @tc.desc: 1.system run normally
 *           2.check ExplicitQueryAbilityInfoV9 failed
 */
HWTEST_F(BmsBundleDataMgrTest, ExplicitQueryAbilityInfoV9_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    Want want;
    AbilityInfo abilityInfo;
    int32_t appIndex = 1;
    GetBundleDataMgr()->sandboxAppHelper_ = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    ErrCode testRet = GetBundleDataMgr()->ExplicitQueryAbilityInfoV9(
        want, GET_ABILITY_INFO_DEFAULT, USERID, abilityInfo, appIndex);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    GetBundleDataMgr()->multiUserIdsSet_.clear();

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: ImplicitQueryCurAbilityInfos_0100
 * @tc.name: test ImplicitQueryCurAbilityInfos
 * @tc.desc: 1.system run normally
 *           2.check ImplicitQueryCurAbilityInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, ImplicitQueryCurAbilityInfos_0100, Function | SmallTest | Level1)
{
    Want want;
    std::vector<AbilityInfo> abilityInfo;
    int32_t appIndex = 1;
    GetBundleDataMgr()->sandboxAppHelper_ = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    bool testRet = GetBundleDataMgr()->ImplicitQueryCurAbilityInfos(
        want, GET_ABILITY_INFO_DEFAULT, Constants::INVALID_UID, abilityInfo, appIndex);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: ImplicitQueryCurAbilityInfos_0100
 * @tc.name: test ImplicitQueryCurAbilityInfosV9
 * @tc.desc: 1.system run normally
 *           2.check ImplicitQueryCurAbilityInfosV9 failed
 */
HWTEST_F(BmsBundleDataMgrTest, ImplicitQueryCurAbilityInfosV9_0100, Function | SmallTest | Level1)
{
    Want want;
    std::vector<AbilityInfo> abilityInfo;
    int32_t appIndex = 1;
    GetBundleDataMgr()->sandboxAppHelper_ = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    want.SetElementName(BUNDLE_TEST1, ABILITY_NAME_TEST);
    bool testRet = GetBundleDataMgr()->ImplicitQueryCurAbilityInfos(
        want, GET_ABILITY_INFO_DEFAULT, Constants::INVALID_UID, abilityInfo, appIndex);
    EXPECT_EQ(testRet, false);

    appIndex = 0;
    int64_t installTime = 0;
    InnerBundleInfo innerBundleInfo;
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    GetBundleDataMgr()->GetMatchLauncherAbilityInfos(want,
        innerBundleInfo, abilityInfo, installTime, Constants::INVALID_USERID);
    GetBundleDataMgr()->ImplicitQueryAllAbilityInfos(
        want, GET_ABILITY_INFO_DEFAULT, USERID, abilityInfo, appIndex);
    int32_t responseUserId = GetBundleDataMgr()->GetUserId(USERID);
    testRet = GetBundleDataMgr()->CheckInnerBundleInfoWithFlags(
        innerBundleInfo, GET_ABILITY_INFO_DEFAULT, responseUserId);
    EXPECT_NE(testRet, ERR_OK);
}

/**
 * @tc.number: GetAllLauncherAbility_0100
 * @tc.name: test GetAllLauncherAbility
 * @tc.desc: 1.system run normally
 *           2.check GetAllLauncherAbility failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllLauncherAbility_0100, Function | SmallTest | Level1)
{
    Want want;
    want.SetElementName(BUNDLE_TEST1, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> abilityInfo;
    InnerBundleInfo innerBundleInfo;
    BundleInfo bundleInfo;
    bundleInfo.entryInstallationFree = true;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    GetBundleDataMgr()->GetAllLauncherAbility(
        want, abilityInfo, USERID, USERID);
    bool res = innerBundleInfo.GetBaseBundleInfo().entryInstallationFree;
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: GetLauncherAbilityByBundleName_0200
 * @tc.name: test GetLauncherAbilityByBundleName
 * @tc.desc: 1.system run normally
 *           2.check GetLauncherAbilityByBundleName failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetLauncherAbilityByBundleName_0200, Function | SmallTest | Level1)
{
    Want want;
    want.SetElementName(BUNDLE_TEST1, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> abilityInfo;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.hideDesktopIcon = true;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetLauncherAbilityByBundleName(
        want, abilityInfo, USERID, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetLauncherAbilityByBundleName_0300
 * @tc.name: test GetLauncherAbilityByBundleName
 * @tc.desc: 1.system run normally
 *           2.check GetLauncherAbilityByBundleName failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetLauncherAbilityByBundleName_0300, Function | SmallTest | Level1)
{
    Want want;
    want.SetElementName(BUNDLE_TEST1, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> abilityInfo;
    InnerBundleInfo innerBundleInfo;
    BundleInfo bundleInfo;
    bundleInfo.entryInstallationFree = true;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetLauncherAbilityByBundleName(
        want, abilityInfo, USERID, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetLauncherAbilityInfoSync_0100
 * @tc.name: test GetLauncherAbilityInfoSync
 * @tc.desc: 1.system run normally
 *           2.check GetLauncherAbilityInfoSync true
 */
HWTEST_F(BmsBundleDataMgrTest, GetLauncherAbilityInfoSync_0100, Function | SmallTest | Level1)
{
    Want want;
    want.SetElementName(BUNDLE_TEST1, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> abilityInfo;
    InnerBundleInfo innerBundleInfo;
    BundleInfo bundleInfo;
    bundleInfo.entryInstallationFree = true;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetLauncherAbilityInfoSync(want, USERID, abilityInfo);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: GetLauncherAbilityInfoSync_0200
 * @tc.name: test GetLauncherAbilityInfoSync
 * @tc.desc: 1.system run normally
 *           2.check GetLauncherAbilityInfoSync failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetLauncherAbilityInfoSync_0200, Function | SmallTest | Level1)
{
    Want want;
    want.SetElementName(BUNDLE_TEST1, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> abilityInfo;
    InnerBundleInfo innerBundleInfo;
    GetBundleDataMgr()->bundleInfos_.emplace("", innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetLauncherAbilityInfoSync(want, USERID, abilityInfo);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: GetLauncherAbilityInfoSync_0300
 * @tc.name: test GetLauncherAbilityInfoSync
 * @tc.desc: 1.system run normally
 *           2.check GetLauncherAbilityInfoSync failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetLauncherAbilityInfoSync_0300, Function | SmallTest | Level1)
{
    Want want;
    want.SetElementName(BUNDLE_TEST1, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> abilityInfo;
    InnerBundleInfo innerBundleInfo;
    BundleInfo bundleInfo;
    bundleInfo.entryInstallationFree = true;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetLauncherAbilityInfoSync(want, -1, abilityInfo);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: GetLauncherAbilityInfoSync_0400
 * @tc.name: test GetLauncherAbilityInfoSync
 * @tc.desc: 1.system run normally
 *           2.check GetLauncherAbilityInfoSync true
 */
HWTEST_F(BmsBundleDataMgrTest, GetLauncherAbilityInfoSync_0400, Function | SmallTest | Level1)
{
    Want want;
    want.SetElementName(BUNDLE_TEST1, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> abilityInfo;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.hideDesktopIcon = true;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetLauncherAbilityInfoSync(want, USERID, abilityInfo);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: GetLauncherAbilityInfoSync_0500
 * @tc.name: test GetLauncherAbilityInfoSync
 * @tc.desc: 1.system run normally
 *           2.check GetLauncherAbilityInfoSync true
 */
HWTEST_F(BmsBundleDataMgrTest, GetLauncherAbilityInfoSync_0500, Function | SmallTest | Level1)
{
    Want want;
    want.SetElementName(BUNDLE_TEST1, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> abilityInfo;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.hideDesktopIcon = false;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    bundleInfo.entryInstallationFree = false;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetLauncherAbilityInfoSync(want, USERID, abilityInfo);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: QueryAbilityInfoByUri_0100
 * @tc.name: test QueryAbilityInfoByUri
 * @tc.desc: 1.system run normally
 *           2.check QueryAbilityInfoByUri failed
 */
HWTEST_F(BmsBundleDataMgrTest, QueryAbilityInfoByUri_0100, Function | SmallTest | Level1)
{
    AbilityInfo abilityInfo;
    bool res = GetBundleDataMgr()->QueryAbilityInfoByUri(BUNDLE_TEST1, USERID, abilityInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: QueryAbilityInfoByUri_0200
 * @tc.name: test QueryAbilityInfoByUri
 * @tc.desc: 1.system run normally
 *           2.check QueryAbilityInfoByUri failed
 */
HWTEST_F(BmsBundleDataMgrTest, QueryAbilityInfoByUri_0200, Function | SmallTest | Level1)
{
    AbilityInfo abilityInfo;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    bool res = GetBundleDataMgr()->QueryAbilityInfoByUri(ServiceConstants::DATA_ABILITY_URI_PREFIX +
        ServiceConstants::FILE_SEPARATOR_CHAR, Constants::ALL_USERID, abilityInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: QueryAbilityInfoByUri_0200
 * @tc.name: test QueryAbilityInfoByUri
 * @tc.desc: 1.system run normally
 *           2.check QueryAbilityInfoByUri failed
 */
HWTEST_F(BmsBundleDataMgrTest, QueryAbilityInfoByUri_0300, Function | SmallTest | Level1)
{
    AbilityInfo abilityInfo;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    bool res = bundleMgrHostImpl_->QueryAbilityInfoByUri(ServiceConstants::DATA_ABILITY_URI_PREFIX
        + ServiceConstants::FILE_SEPARATOR_CHAR, Constants::ALL_USERID, abilityInfo);
    EXPECT_EQ(res, false);
}
/**
 * @tc.number: QueryAbilityInfosByUri_0100
 * @tc.name: test QueryAbilityInfosByUri
 * @tc.desc: 1.system run normally
 *           2.check QueryAbilityInfosByUri failed
 */
HWTEST_F(BmsBundleDataMgrTest, QueryAbilityInfosByUri_0100, Function | SmallTest | Level1)
{
    std::vector<AbilityInfo> abilityInfo;
    bool res = GetBundleDataMgr()->QueryAbilityInfosByUri(ServiceConstants::DATA_ABILITY_URI_PREFIX, abilityInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: QueryAbilityInfosByUri_0200
 * @tc.name: test QueryAbilityInfosByUri
 * @tc.desc: 1.system run normally
 *           2.check QueryAbilityInfosByUri failed
 */
HWTEST_F(BmsBundleDataMgrTest, QueryAbilityInfosByUri_0200, Function | SmallTest | Level1)
{
    std::vector<AbilityInfo> abilityInfo;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    bool res = GetBundleDataMgr()->QueryAbilityInfosByUri(
        ServiceConstants::DATA_ABILITY_URI_PREFIX + ServiceConstants::FILE_SEPARATOR_CHAR, abilityInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetApplicationInfos_0100
 * @tc.name: test GetApplicationInfos
 * @tc.desc: 1.system run normally
 *           2.check GetApplicationInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetApplicationInfos_0100, Function | SmallTest | Level1)
{
    std::vector<ApplicationInfo> abilityInfo;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetApplicationInfos(GET_ABILITY_INFO_DEFAULT, USERID, abilityInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetApplicationInfos_0200
 * @tc.name: test GetApplicationInfos
 * @tc.desc: 1.system run normally
 *           2.check GetApplicationInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetApplicationInfos_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::vector<ApplicationInfo> abilityInfo;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME_TEST;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetApplicationInfos(GET_ABILITY_INFO_DEFAULT, USERID, abilityInfo);
    EXPECT_EQ(res, true);
    GetBundleDataMgr()->multiUserIdsSet_.clear();

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetApplicationInfosV9_0100
 * @tc.name: test GetApplicationInfosV9
 * @tc.desc: 1.system run normally
 *           2.check GetApplicationInfosV9 failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetApplicationInfosV9_0100, Function | SmallTest | Level1)
{
    std::vector<ApplicationInfo> abilityInfo;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    ErrCode res = GetBundleDataMgr()->GetApplicationInfosV9(GET_ABILITY_INFO_DEFAULT, USERID, abilityInfo);
    EXPECT_EQ(res, ERR_OK);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: GetBundleInfoV9_0100
 * @tc.name: test GetBundleInfoV9
 * @tc.desc: 1.system run normally
 *           2.check GetBundleInfoV9 failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleInfoV9_0100, Function | SmallTest | Level1)
{
    std::vector<ApplicationInfo> abilityInfo;
    BundleInfo bundleInfo;
    ErrCode res = GetBundleDataMgr()->GetBundleInfoV9(
        "", GET_ABILITY_INFO_DEFAULT, bundleInfo, Constants::ANY_USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: GetBundleInfoV9_0200
 * @tc.name: test GetBundleInfoV9
 * @tc.desc: 1.system run normally
 *           2.check GetBundleInfoV9 failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleInfoV9_0200, Function | SmallTest | Level1)
{
    std::vector<ApplicationInfo> abilityInfo;
    BundleInfo bundleInfo;
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    ErrCode res = GetBundleDataMgr()->GetBundleInfoV9(
        "", GET_ABILITY_INFO_DEFAULT, bundleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: GetBaseSharedBundleInfo_0100
 * @tc.name: test GetBaseSharedBundleInfo
 * @tc.desc: 1.system run normally
 *           2.check GetBaseSharedBundleInfo failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetBaseSharedBundleInfo_0100, Function | SmallTest | Level1)
{
    std::vector<ApplicationInfo> abilityInfo;
    Dependency dependency;
    BaseSharedBundleInfo baseSharedBundleInfo;

    bool res = GetBundleDataMgr()->GetBaseSharedBundleInfo(dependency, baseSharedBundleInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetBaseSharedBundleInfo_0300
 * @tc.name: test GetBaseSharedBundleInfo
 * @tc.desc: 1.system run normally
 *           2.check GetBaseSharedBundleInfo failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetBaseSharedBundleInfo_0300, Function | SmallTest | Level1)
{
    Dependency dependency;
    BaseSharedBundleInfo baseSharedBundleInfo;
    dependency.bundleName = BUNDLE_TEST1;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetApplicationBundleType(BundleType::APP);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetBaseSharedBundleInfo(dependency, baseSharedBundleInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: DeleteSharedBundleInfo_0100
 * @tc.name: test DeleteSharedBundleInfo
 * @tc.desc: 1.system run normally
 *           2.check DeleteSharedBundleInfo failed
 */
HWTEST_F(BmsBundleDataMgrTest, DeleteSharedBundleInfo_0100, Function | SmallTest | Level1)
{
    bool res = GetBundleDataMgr()->DeleteSharedBundleInfo(BUNDLE_TEST1);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: DeleteSharedBundleInfo_0200
 * @tc.name: test DeleteSharedBundleInfo
 * @tc.desc: 1.system run normally
 *           2.check DeleteSharedBundleInfo failed
 */
HWTEST_F(BmsBundleDataMgrTest, DeleteSharedBundleInfo_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    bool res = GetBundleDataMgr()->DeleteSharedBundleInfo(BUNDLE_TEST1);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetBundleInfosByMetaData_0100
 * @tc.name: test GetBundleInfosByMetaData
 * @tc.desc: 1.system run normally
 *           2.check GetBundleInfosByMetaData failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleInfosByMetaData_0100, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;

    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetBundleInfosByMetaData(BUNDLE_TEST1, bundleInfos);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetBundleInfos_0100
 * @tc.name: test GetBaseSharedBundleInfo
 * @tc.desc: 1.system run normally
 *           2.check GetBaseSharedBundleInfo failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleInfos_0100, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetApplicationBundleType(BundleType::SHARED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetBundleInfos(GET_ABILITY_INFO_DEFAULT, bundleInfos, USERID);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetAllBundleInfos_0100
 * @tc.name: test GetAllBundleInfos
 * @tc.desc: 1.system run normally
 *           2.check GetAllBundleInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllBundleInfos_0100, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetAllBundleInfos(GET_ABILITY_INFO_DEFAULT, bundleInfos);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: GetAllBundleInfos_0200
 * @tc.name: test GetAllBundleInfos
 * @tc.desc: 1.system run normally
 *           2.check GetAllBundleInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllBundleInfos_0200, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetApplicationBundleType(BundleType::SHARED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetAllBundleInfos(GET_ABILITY_INFO_DEFAULT, bundleInfos);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: GetAllBundleInfos_0300
 * @tc.name: test GetAllBundleInfos
 * @tc.desc: 1.system run normally
 *           2.check GetAllBundleInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllBundleInfos_0300, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetApplicationBundleType(BundleType::SHARED);
    BundleInfo bundleInfo;
    bundleInfo.singleton = true;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);

    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    OHOS::EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    auto subscriberPtr = std::make_shared<UserUnlockedEventSubscriber>(subscribeInfo);
    UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel(Constants::ALL_USERID);

    bool res = GetBundleDataMgr()->GetAllBundleInfos(GET_ABILITY_INFO_DEFAULT, bundleInfos);
    EXPECT_EQ(res, true);

    RemoveBundleinfo(BUNDLE_TEST1);
}

/**
 * @tc.number: GetAllBundleInfos_0400
 * @tc.name: test GetAllBundleInfos
 * @tc.desc: 1.system run normally
 *           2.check GetAllBundleInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllBundleInfos_0400, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetApplicationBundleType(BundleType::SHARED);
    BundleInfo bundleInfo;
    bundleInfo.singleton = false;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);

    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    OHOS::EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    auto subscriberPtr = std::make_shared<UserUnlockedEventSubscriber>(subscribeInfo);
    UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel(Constants::ALL_USERID);

    bool res = GetBundleDataMgr()->GetAllBundleInfos(GET_ABILITY_INFO_DEFAULT, bundleInfos);
    EXPECT_EQ(res, true);

    RemoveBundleinfo(BUNDLE_TEST1);
}

/**
 * @tc.number: GetBundleInfosV9_0100
 * @tc.name: test GetBundleInfosV9
 * @tc.desc: 1.system run normally
 *           2.check GetBundleInfosV9 failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleInfosV9_0100, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetApplicationBundleType(BundleType::SHARED);
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetBundleInfosV9(GET_ABILITY_INFO_DEFAULT, bundleInfos, USERID);
    EXPECT_EQ(res, ERR_OK);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: GetAllBundleInfosV9_0100
 * @tc.name: test GetAllBundleInfosV9
 * @tc.desc: 1.system run normally
 *           2.check GetAllBundleInfosV9 failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllBundleInfosV9_0100, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetAllBundleInfosV9(GET_ABILITY_INFO_DEFAULT, bundleInfos);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetAllBundleInfosV9_0200
 * @tc.name: test GetAllBundleInfos
 * @tc.desc: 1.system run normally
 *           2.check GetAllBundleInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllBundleInfosV9_0200, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetApplicationBundleType(BundleType::SHARED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetAllBundleInfosV9(GET_ABILITY_INFO_DEFAULT, bundleInfos);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetBundleStats_0100
 * @tc.name: test GetBundleStats
 * @tc.desc: 1.system run normally
 *           2.check GetBundleStats failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleStats_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    std::vector<int64_t> bundleStats { 1 };
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetBundleStats(BUNDLE_NAME_TEST, USERID, bundleStats);
    EXPECT_EQ(res, true);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleStats_0200
 * @tc.name: GetBundleStats
 * @tc.desc: test GetBundleStats of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleStats_0200, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    EXPECT_NE(bmsExtensionClient, nullptr);

    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    std::vector<int64_t> bundleStats;
    auto ret = bmsExtensionClient->GetBundleStats(BUNDLE_NAME_TEST, Constants::ALL_USERID, bundleStats);
    EXPECT_NE(ret, ERR_OK);

    bmsExtensionClient->bmsExtensionImpl_ = std::make_shared<BmsExtensionDataMgr>();
    ret = bmsExtensionClient->GetBundleStats(BUNDLE_NAME_TEST, Constants::ALL_USERID, bundleStats);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: QueryAbilityInfos_0400
 * @tc.name: GetBundleStats
 * @tc.desc: test GetBundleStats of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, QueryAbilityInfos_0400, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    ResetDataMgr();
    Want want;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    auto ret = bmsExtensionClient->QueryAbilityInfos(want, 0, userId, abilityInfos, false);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: QueryAbilityInfos_0500
 * @tc.name: GetBundleStats
 * @tc.desc: test GetBundleStats of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, QueryAbilityInfos_0500, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    InnerBundleInfo innerBundleInfo;
    EXPECT_TRUE(GetBundleDataMgr());
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);

    Want want;
    ElementName ele;
    ele.SetBundleName(BUNDLE_NAME_TEST);
    ele.SetModuleName(MODULE_NAME_TEST);
    ele.SetAbilityName(ABILITY_NAME_TEST);
    want.SetElement(ele);
    int32_t userId = -3;
    std::vector<AbilityInfo> abilityInfos;
    auto ret = bmsExtensionClient->QueryAbilityInfos(want, 0, userId, abilityInfos, false);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: QueryAbilityInfos_0600
 * @tc.name: GetBundleStats
 * @tc.desc: test GetBundleStats of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, QueryAbilityInfos_0600, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    bmsExtensionClient->bmsExtensionImpl_ = nullptr;

    Want want;
    int32_t userId = -3;
    std::vector<AbilityInfo> abilityInfos;
    auto ret = bmsExtensionClient->QueryAbilityInfos(want, 0, userId, abilityInfos, false);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: QueryAbilityInfos_0700
 * @tc.name: GetBundleStats
 * @tc.desc: test GetBundleStats of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, QueryAbilityInfos_0700, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    ResetDataMgr();

    bmsExtensionClient->bmsExtensionImpl_ = std::make_shared<BmsExtensionDataMgr>();
    ASSERT_NE(bmsExtensionClient->bmsExtensionImpl_, nullptr);
    Want want;
    ElementName ele;
    ele.SetBundleName(BUNDLE_NAME_TEST);
    ele.SetModuleName(MODULE_NAME_TEST);
    ele.SetAbilityName(ABILITY_NAME_TEST);
    want.SetElement(ele);
    int32_t userId = -3;
    std::vector<AbilityInfo> abilityInfos;
    auto ret = bmsExtensionClient->QueryAbilityInfos(want, 0, userId, abilityInfos, false);
    if (CheckBmsExtensionProfile()) {
        EXPECT_EQ(ret, ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY);
    } else {
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    }
}

/**
 * @tc.number: QueryAbilityInfos_0800
 * @tc.name: GetBundleStats
 * @tc.desc: test GetBundleStats of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, QueryAbilityInfos_0800, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });

    void* mockHandler = static_cast<void*>(malloc(sizeof(char)));
    BmsExtensionBundleMgr bmsExtensionBundleMgr;
    bmsExtensionBundleMgr.extensionName = "extension-name";
    bmsExtensionBundleMgr.libPath = "/data/test/";
    auto extensionDataMgr = std::make_shared<BmsExtensionDataMgr>();
    ASSERT_NE(extensionDataMgr, nullptr);
    extensionDataMgr->bmsExtension_.bmsExtensionBundleMgr = bmsExtensionBundleMgr;
    extensionDataMgr->handler_ = mockHandler;

    bmsExtensionClient->bmsExtensionImpl_ = extensionDataMgr;

    BundleMgrExtRegister::GetInstance().RegisterBundleMgrExt("extension-name", []() ->std::shared_ptr<BundleMgrExt> {
        return std::make_shared<MockBundleMgrExt>();
    });

    Want want;
    ElementName ele;
    ele.SetBundleName(BUNDLE_NAME_TEST);
    ele.SetModuleName(MODULE_NAME_TEST);
    ele.SetAbilityName(ABILITY_NAME_TEST);
    want.SetElement(ele);
    int32_t userId = -3;
    std::vector<AbilityInfo> abilityInfos;
    auto ret = bmsExtensionClient->QueryAbilityInfos(want, 0, userId, abilityInfos, false);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);

    if (mockHandler) {
        delete static_cast<char*>(mockHandler);
    }

    BmsExtensionBundleMgr non;
    BmsExtensionDataMgr::bmsExtension_.bmsExtensionBundleMgr = non;
    BmsExtensionDataMgr::handler_ = nullptr;
}

/**
 * @tc.number: QueryAbilityInfos_0900
 * @tc.name: GetBundleStats
 * @tc.desc: test GetBundleStats of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, QueryAbilityInfos_0900, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    void* mockHandler = static_cast<void*>(malloc(sizeof(char)));
    BmsExtensionBundleMgr bmsExtensionBundleMgr;
    bmsExtensionBundleMgr.extensionName = "extension-name";
    bmsExtensionBundleMgr.libPath = "/data/test/";
    auto extensionDataMgr = std::make_shared<BmsExtensionDataMgr>();
    ASSERT_NE(extensionDataMgr, nullptr);
    extensionDataMgr->bmsExtension_.bmsExtensionBundleMgr = bmsExtensionBundleMgr;
    extensionDataMgr->handler_ = mockHandler;

    bmsExtensionClient->bmsExtensionImpl_ = extensionDataMgr;

    Want want;
    ElementName ele;
    ele.SetBundleName("TEST");
    ele.SetModuleName(MODULE_NAME_TEST);
    ele.SetAbilityName(ABILITY_NAME_TEST);
    want.SetElement(ele);
    int32_t userId = -3;
    std::vector<AbilityInfo> abilityInfos;
    auto ret = bmsExtensionClient->QueryAbilityInfos(want, 0, userId, abilityInfos, false);
    EXPECT_EQ(ret, ERR_OK);

    if (mockHandler) {
        delete static_cast<char*>(mockHandler);
    }

    BmsExtensionBundleMgr non;
    BmsExtensionDataMgr::bmsExtension_.bmsExtensionBundleMgr = non;
    BmsExtensionDataMgr::handler_ = nullptr;
}

/**
 * @tc.number: BatchQueryAbilityInfos_0010
 * @tc.name: BatchQueryAbilityInfos
 * @tc.desc: test BatchQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, BatchQueryAbilityInfos_0010, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::vector<Want> wants;
    int32_t flags = 0;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->BatchQueryAbilityInfos(wants, flags, userId, abilityInfos, isNewVersion);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: BatchQueryAbilityInfos_0020
 * @tc.name: BatchQueryAbilityInfos
 * @tc.desc: test BatchQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, BatchQueryAbilityInfos_0020, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    InnerBundleInfo innerBundleInfo;
    EXPECT_TRUE(GetBundleDataMgr());
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);

    Want want;
    ElementName ele;
    ele.SetBundleName(BUNDLE_NAME_TEST);
    ele.SetModuleName(MODULE_NAME_TEST);
    ele.SetAbilityName(ABILITY_NAME_TEST);
    want.SetElement(ele);
    int32_t userId = -3;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<Want> wants{ want };
    ErrCode res = bmsExtensionClient->BatchQueryAbilityInfos(wants, 0, userId, abilityInfos, false);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: BatchQueryAbilityInfos_0030
 * @tc.name: BatchQueryAbilityInfos
 * @tc.desc: test BatchQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, BatchQueryAbilityInfos_0030, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    bmsExtensionClient->bmsExtensionImpl_ = nullptr;

    Want want;
    int32_t userId = -3;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<Want> wants{ want };
    ErrCode res = bmsExtensionClient->BatchQueryAbilityInfos(wants, 0, userId, abilityInfos, false);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BatchQueryAbilityInfos_0040
 * @tc.name: BatchQueryAbilityInfos
 * @tc.desc: test BatchQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, BatchQueryAbilityInfos_0040, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });

    bmsExtensionClient->bmsExtensionImpl_ = std::make_shared<BmsExtensionDataMgr>();
    ASSERT_NE(bmsExtensionClient->bmsExtensionImpl_, nullptr);

    Want want;
    ElementName ele;
    ele.SetBundleName("BUNDLE");
    ele.SetModuleName(MODULE_NAME_TEST);
    ele.SetAbilityName(ABILITY_NAME_TEST);
    want.SetElement(ele);
    int32_t userId = -3;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<Want> wants{ want };
    ErrCode res = bmsExtensionClient->BatchQueryAbilityInfos(wants, 0, userId, abilityInfos, false);
    if (CheckBmsExtensionProfile()) {
        EXPECT_EQ(res, ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY);
    } else {
        EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    }
}

/**
 * @tc.number: BatchQueryAbilityInfos_0050
 * @tc.name: BatchQueryAbilityInfos
 * @tc.desc: test BatchQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, BatchQueryAbilityInfos_0050, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });

    void* mockHandler = static_cast<void*>(malloc(sizeof(char)));
    BmsExtensionBundleMgr bmsExtensionBundleMgr;
    bmsExtensionBundleMgr.extensionName = "extension-name";
    bmsExtensionBundleMgr.libPath = "/data/test/";
    auto extensionDataMgr = std::make_shared<BmsExtensionDataMgr>();
    extensionDataMgr->bmsExtension_.bmsExtensionBundleMgr = bmsExtensionBundleMgr;
    extensionDataMgr->handler_ = mockHandler;

    bmsExtensionClient->bmsExtensionImpl_ = extensionDataMgr;

    Want want;
    ElementName ele;
    ele.SetBundleName(BUNDLE_NAME_TEST);
    ele.SetModuleName(MODULE_NAME_TEST);
    ele.SetAbilityName(ABILITY_NAME_TEST);
    want.SetElement(ele);
    int32_t userId = -3;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<Want> wants{ want };
    auto ret = bmsExtensionClient->BatchQueryAbilityInfos(wants, 0, userId, abilityInfos, false);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);

    if (mockHandler) {
        delete static_cast<char*>(mockHandler);
    }

    BmsExtensionBundleMgr non;
    BmsExtensionDataMgr::bmsExtension_.bmsExtensionBundleMgr = non;
    BmsExtensionDataMgr::handler_ = nullptr;
}

/**
 * @tc.number: BatchQueryAbilityInfos_0060
 * @tc.name: BatchQueryAbilityInfos
 * @tc.desc: test BatchQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, BatchQueryAbilityInfos_0060, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });

    void* mockHandler = static_cast<void*>(malloc(sizeof(char)));
    BmsExtensionBundleMgr bmsExtensionBundleMgr;
    bmsExtensionBundleMgr.extensionName = "extension-name";
    bmsExtensionBundleMgr.libPath = "/data/test/";
    auto extensionDataMgr = std::make_shared<BmsExtensionDataMgr>();
    extensionDataMgr->bmsExtension_.bmsExtensionBundleMgr = bmsExtensionBundleMgr;
    extensionDataMgr->handler_ = mockHandler;

    bmsExtensionClient->bmsExtensionImpl_ = extensionDataMgr;

    Want want;
    ElementName ele;
    ele.SetBundleName("TEST");
    ele.SetModuleName(MODULE_NAME_TEST);
    ele.SetAbilityName(ABILITY_NAME_TEST);
    want.SetElement(ele);
    int32_t userId = -3;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<Want> wants{ want };
    auto ret = bmsExtensionClient->BatchQueryAbilityInfos(wants, 0, userId, abilityInfos, false);
    EXPECT_EQ(ret, ERR_OK);

    if (mockHandler) {
        delete static_cast<char*>(mockHandler);
    }

    BmsExtensionBundleMgr non;
    BmsExtensionDataMgr::bmsExtension_.bmsExtensionBundleMgr = non;
    BmsExtensionDataMgr::handler_ = nullptr;
}

/**
 * @tc.number: GetBundleInfo_0010
 * @tc.name: GetBundleInfo
 * @tc.desc: test GetBundleInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleInfo_0010, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    std::string bundleName = BUNDLE_NAME_TEST;
    int32_t userId = 100;
    BundleInfo bundleInfo;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->GetBundleInfo(bundleName, 0, bundleInfo, userId, isNewVersion);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: GetBundleInfo_0020
 * @tc.name: GetBundleInfo
 * @tc.desc: test GetBundleInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleInfo_0020, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    InnerBundleInfo innerBundleInfo;
    ASSERT_NE(GetBundleDataMgr(), nullptr);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);

    std::string bundleName = BUNDLE_NAME_TEST;
    int32_t userId = -3;
    BundleInfo bundleInfo;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->GetBundleInfo(bundleName, 0, bundleInfo, userId, isNewVersion);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    GetBundleDataMgr()->bundleInfos_.erase(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleInfo_0030
 * @tc.name: GetBundleInfo
 * @tc.desc: test GetBundleInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleInfo_0030, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    bmsExtensionClient->bmsExtensionImpl_ = nullptr;

    std::string bundleName = BUNDLE_NAME_TEST;
    int32_t userId = -3;
    BundleInfo bundleInfo;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->GetBundleInfo(bundleName, 0, bundleInfo, userId, isNewVersion);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetBundleInfo_0040
 * @tc.name: GetBundleInfo
 * @tc.desc: test GetBundleInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleInfo_0040, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    void* mockHandler = static_cast<void*>(malloc(sizeof(char)));
    BmsExtensionBundleMgr bmsExtensionBundleMgr;
    bmsExtensionBundleMgr.extensionName = "extension-bundle";
    bmsExtensionBundleMgr.libPath = "/data/test/";
    auto extensionDataMgr = std::make_shared<BmsExtensionDataMgr>();
    ASSERT_NE(extensionDataMgr, nullptr);
    extensionDataMgr->bmsExtension_.bmsExtensionBundleMgr = bmsExtensionBundleMgr;
    extensionDataMgr->handler_ = mockHandler;

    bmsExtensionClient->bmsExtensionImpl_ = extensionDataMgr;

    std::string bundleName = BUNDLE_NAME_TEST;
    int32_t userId = -3;
    BundleInfo bundleInfo;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->GetBundleInfo(bundleName, 0, bundleInfo, userId, isNewVersion);
    EXPECT_EQ(res, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: GetBundleInfo_0050
 * @tc.name: GetBundleInfo
 * @tc.desc: test GetBundleInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleInfo_0050, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    void* mockHandler = static_cast<void*>(malloc(sizeof(char)));
    BmsExtensionBundleMgr bmsExtensionBundleMgr;
    bmsExtensionBundleMgr.extensionName = "extension-bundle";
    bmsExtensionBundleMgr.libPath = "/data/test/";
    auto extensionDataMgr = std::make_shared<BmsExtensionDataMgr>();
    ASSERT_NE(extensionDataMgr, nullptr);
    extensionDataMgr->bmsExtension_.bmsExtensionBundleMgr = bmsExtensionBundleMgr;
    extensionDataMgr->handler_ = mockHandler;

    bmsExtensionClient->bmsExtensionImpl_ = extensionDataMgr;

    BundleMgrExtRegister::GetInstance().RegisterBundleMgrExt("extension-bundle", []() ->std::shared_ptr<BundleMgrExt> {
        return std::make_shared<MockBundleMgrExt>();
    });

    std::string bundleName = BUNDLE_NAME_TEST;
    int32_t userId = -3;
    BundleInfo bundleInfo;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->GetBundleInfo(bundleName, 0, bundleInfo, userId, isNewVersion);
    EXPECT_EQ(res, ERR_OK);

    if (mockHandler) {
        delete static_cast<char*>(mockHandler);
    }

    BmsExtensionBundleMgr non;
    BmsExtensionDataMgr::bmsExtension_.bmsExtensionBundleMgr = non;
    BmsExtensionDataMgr::handler_ = nullptr;
}

/**
 * @tc.number: BatchGetBundleInfo_0010
 * @tc.name: BatchGetBundleInfo
 * @tc.desc: test BatchGetBundleInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, BatchGetBundleInfo_0010, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    std::vector<std::string> bundleNames{ BUNDLE_NAME_TEST };
    int32_t userId = 100;
    std::vector<BundleInfo> bundleInfos;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->BatchGetBundleInfo(bundleNames, 0, bundleInfos, userId, isNewVersion);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: BatchGetBundleInfo_0020
 * @tc.name: BatchGetBundleInfo
 * @tc.desc: test BatchGetBundleInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, BatchGetBundleInfo_0020, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    std::vector<std::string> bundleNames{ BUNDLE_NAME_TEST };
    int32_t userId = -3;
    std::vector<BundleInfo> bundleInfos;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->BatchGetBundleInfo(bundleNames, 0, bundleInfos, userId, isNewVersion);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: BatchGetBundleInfo_0030
 * @tc.name: GetBundleInfo
 * @tc.desc: test GetBundleInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, BatchGetBundleInfo_0030, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    void* mockHandler = static_cast<void*>(malloc(sizeof(char)));
    BmsExtensionBundleMgr bmsExtensionBundleMgr;
    bmsExtensionBundleMgr.extensionName = "extension-bundle";
    bmsExtensionBundleMgr.libPath = "/data/test/";
    auto extensionDataMgr = std::make_shared<BmsExtensionDataMgr>();
    ASSERT_NE(extensionDataMgr, nullptr);
    extensionDataMgr->bmsExtension_.bmsExtensionBundleMgr = bmsExtensionBundleMgr;
    extensionDataMgr->handler_ = mockHandler;

    bmsExtensionClient->bmsExtensionImpl_ = extensionDataMgr;
    std::vector<std::string> bundleNames{ BUNDLE_NAME_TEST };
    int32_t userId = -3;
    std::vector<BundleInfo> bundleInfos;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->BatchGetBundleInfo(bundleNames, 0, bundleInfos, userId, isNewVersion);
    EXPECT_EQ(res, ERR_OK);

    if (mockHandler) {
        delete static_cast<char*>(mockHandler);
    }

    BmsExtensionBundleMgr non;
    BmsExtensionDataMgr::bmsExtension_.bmsExtensionBundleMgr = non;
    BmsExtensionDataMgr::handler_ = nullptr;
}

/**
 * @tc.number: ImplicitQueryAbilityInfos_0010
 * @tc.name: ImplicitQueryAbilityInfos
 * @tc.desc: test ImplicitQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, ImplicitQueryAbilityInfos_0010, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    Want want;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->ImplicitQueryAbilityInfos(want, 0, userId, abilityInfos, isNewVersion);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: ImplicitQueryAbilityInfos_0020
 * @tc.name: ImplicitQueryAbilityInfos
 * @tc.desc: test ImplicitQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, ImplicitQueryAbilityInfos_0020, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    Want want;
    ElementName ele;
    ele.SetBundleName(BUNDLE_NAME_TEST);
    ele.SetModuleName(MODULE_NAME_TEST);
    ele.SetAbilityName(ABILITY_NAME_TEST);
    want.SetElement(ele);
    int32_t userId = -3;
    std::vector<AbilityInfo> abilityInfos;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->ImplicitQueryAbilityInfos(want, 0, userId, abilityInfos, isNewVersion);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: ImplicitQueryAbilityInfos_0030
 * @tc.name: ImplicitQueryAbilityInfos
 * @tc.desc: test ImplicitQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, ImplicitQueryAbilityInfos_0030, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    Want want;
    ElementName ele;
    ele.SetBundleName("");
    ele.SetModuleName("");
    ele.SetAbilityName("");
    want.SetElement(ele);
    int32_t userId = -3;
    std::vector<AbilityInfo> abilityInfos;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->ImplicitQueryAbilityInfos(want, 0, userId, abilityInfos, isNewVersion);
    if (CheckBmsExtensionProfile()) {
        EXPECT_EQ(res, ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY);
    } else {
        EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    }
}


/**
 * @tc.number: ImplicitQueryAbilityInfos_0040
 * @tc.name: ImplicitQueryAbilityInfos
 * @tc.desc: test ImplicitQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, ImplicitQueryAbilityInfos_0040, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    void* mockHandler = static_cast<void*>(malloc(sizeof(char)));
    BmsExtensionBundleMgr bmsExtensionBundleMgr;
    bmsExtensionBundleMgr.extensionName = "extension-bundle";
    bmsExtensionBundleMgr.libPath = "/data/test/";
    auto extensionDataMgr = std::make_shared<BmsExtensionDataMgr>();
    ASSERT_NE(extensionDataMgr, nullptr);
    extensionDataMgr->bmsExtension_.bmsExtensionBundleMgr = bmsExtensionBundleMgr;
    extensionDataMgr->handler_ = mockHandler;

    Want want;
    ElementName ele;
    ele.SetBundleName("");
    ele.SetModuleName("");
    ele.SetAbilityName("");
    want.SetElement(ele);
    int32_t userId = -3;
    std::vector<AbilityInfo> abilityInfos;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->ImplicitQueryAbilityInfos(want, 0, userId, abilityInfos, isNewVersion);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);

    if (mockHandler) {
        delete static_cast<char*>(mockHandler);
    }

    BmsExtensionBundleMgr non;
    BmsExtensionDataMgr::bmsExtension_.bmsExtensionBundleMgr = non;
    BmsExtensionDataMgr::handler_ = nullptr;
}

/**
 * @tc.number: ImplicitQueryAbilityInfos_0050
 * @tc.name: ImplicitQueryAbilityInfos
 * @tc.desc: test ImplicitQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, ImplicitQueryAbilityInfos_0050, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);

    void* mockHandler = static_cast<void*>(malloc(sizeof(char)));
    BmsExtensionBundleMgr bmsExtensionBundleMgr;
    bmsExtensionBundleMgr.extensionName = "extension-bundle";
    bmsExtensionBundleMgr.libPath = "/data/test/";
    auto extensionDataMgr = std::make_shared<BmsExtensionDataMgr>();
    ASSERT_NE(extensionDataMgr, nullptr);
    extensionDataMgr->bmsExtension_.bmsExtensionBundleMgr = bmsExtensionBundleMgr;
    extensionDataMgr->handler_ = mockHandler;

    Want want;
    ElementName ele;
    ele.SetBundleName("");
    ele.SetModuleName("");
    ele.SetAbilityName("");
    want.SetElement(ele);
    int32_t userId = -3;
    std::vector<AbilityInfo> abilityInfos;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->ImplicitQueryAbilityInfos(
        want, MOCK_BUNDLE_MGR_EXT_FLAG, userId, abilityInfos, isNewVersion);
    EXPECT_EQ(res, ERR_OK);

    if (mockHandler) {
        delete static_cast<char*>(mockHandler);
    }

    BmsExtensionBundleMgr non;
    BmsExtensionDataMgr::bmsExtension_.bmsExtensionBundleMgr = non;
    BmsExtensionDataMgr::handler_ = nullptr;
}


/**
 * @tc.number: GetBundleSpaceSize_0100
 * @tc.name: test GetBundleSpaceSize
 * @tc.desc: 1.system run normally
 *           2.check GetBundleSpaceSize failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleSpaceSize_0100, Function | SmallTest | Level1)
{
    std::vector<int64_t> bundleStats;
    int64_t res = GetBundleDataMgr()->GetBundleSpaceSize("", USERID);
    EXPECT_EQ(res, SPACE_SIZE);
}

/**
 * @tc.number: GetBundleSpaceSize_0200
 * @tc.name: test GetBundleSpaceSize
 * @tc.desc: 1.system run normally
 *           2.check GetBundleSpaceSize failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleSpaceSize_0200, Function | SmallTest | Level1)
{
    std::vector<int64_t> bundleStats;
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    int64_t res = GetBundleDataMgr()->GetBundleSpaceSize("", Constants::ALL_USERID);
    EXPECT_EQ(res, SPACE_SIZE);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: GetAllFreeInstallBundleSpaceSize_0100
 * @tc.name: test GetAllFreeInstallBundleSpaceSize
 * @tc.desc: 1.system run normally
 *           2.check GetAllFreeInstallBundleSpaceSize failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllFreeInstallBundleSpaceSize_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    InnerBundleInfo innerBundleInfo;
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    int64_t res = GetBundleDataMgr()->GetAllFreeInstallBundleSpaceSize();
    EXPECT_EQ(res, SPACE_SIZE);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryKeepAliveBundleInfos_0100
 * @tc.name: test QueryKeepAliveBundleInfos
 * @tc.desc: 1.system run normally
 *           2.check QueryKeepAliveBundleInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, QueryKeepAliveBundleInfos_0100, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    bool res = GetBundleDataMgr()->QueryKeepAliveBundleInfos(bundleInfos);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetHapModuleInfo_0100
 * @tc.name: test GetHapModuleInfo
 * @tc.desc: 1.system run normally
 *           2.check GetHapModuleInfo failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetHapModuleInfo_0100, Function | SmallTest | Level1)
{
    AbilityInfo abilityInfo;
    HapModuleInfo hapModuleInfo;
    InnerBundleInfo innerBundleInfo;
    abilityInfo.bundleName = BUNDLE_NAME_TEST;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME_TEST;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetHapModuleInfo(abilityInfo, hapModuleInfo, USERID);
    EXPECT_EQ(res, false);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: GetHapModuleInfo_0200
 * @tc.name: test GetHapModuleInfo
 * @tc.desc: 1.check ModuleInfo infos
 */
HWTEST_F(BmsBundleDataMgrTest, GetHapModuleInfo_0200, Function | MediumTest | Level1)
{
    AbilityInfo abilityInfo;
    abilityInfo.bundleName = BUNDLE_NAME_TEST;
    abilityInfo.package = BUNDLE_NAME_TEST;
    HapModuleInfo hapModuleInfo;
    bool ret = bundleMgrHostImpl_->GetHapModuleInfo(abilityInfo, USERID, hapModuleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: GetInnerBundleInfoWithFlags_0100
 * @tc.name: test GetInnerBundleInfoWithFlags
 * @tc.desc: 1.system run normally
 *           2.check GetInnerBundleInfoWithFlags failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetInnerBundleInfoWithFlags_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME_TEST;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetInnerBundleInfoWithFlags(
        BUNDLE_NAME_TEST, GET_ABILITY_INFO_DEFAULT, innerBundleInfo, USERID);
    EXPECT_EQ(res, false);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: GetInnerBundleInfoWithFlagsForAms_0100
 * @tc.name: test GetInnerBundleInfoWithFlagsForAms
 * @tc.desc: 1.system run normally
 *           2.check GetInnerBundleInfoWithFlagsForAms failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetInnerBundleInfoWithFlagsForAms_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME_TEST;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetInnerBundleInfoWithFlags(
        BUNDLE_NAME_TEST, GET_ABILITY_INFO_DEFAULT, USERID);
    EXPECT_EQ(res, false);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: GetInnerBundleInfoWithFlagsV9_0100
 * @tc.name: test GetInnerBundleInfoWithFlagsV9
 * @tc.desc: 1.system run normally
 *           2.check GetInnerBundleInfoWithFlagsV9 failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetInnerBundleInfoWithFlagsV9_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME_TEST;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetInnerBundleInfoWithFlagsV9(
        BUNDLE_NAME_TEST, GET_ABILITY_INFO_DEFAULT, innerBundleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_DISABLED);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: GetInnerBundleInfoWithBundleFlagsV9_0100
 * @tc.name: test GetInnerBundleInfoWithBundleFlagsV9
 * @tc.desc: 1.system run normally
 *           2.check GetInnerBundleInfoWithBundleFlagsV9 failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetInnerBundleInfoWithBundleFlagsV9_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME_TEST;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetInnerBundleInfoWithBundleFlagsV9(
        BUNDLE_NAME_TEST, GET_ABILITY_INFO_DEFAULT, innerBundleInfo, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_DISABLED);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: GetInnerBundleInfoWithBundleFlagsV9_0200
 * @tc.name: test GetInnerBundleInfoWithBundleFlagsV9
 * @tc.desc: 1.system run normally
 *           2.check GetInnerBundleInfoWithBundleFlagsV9 failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetInnerBundleInfoWithBundleFlagsV9_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME_TEST;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetInnerBundleInfoWithBundleFlagsV9(
        BUNDLE_NAME_TEST, GET_ABILITY_INFO_DEFAULT, innerBundleInfo, ServiceConstants::NOT_EXIST_USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: IsApplicationEnabled_0100
 * @tc.name: test IsApplicationEnabled
 * @tc.desc: 1.system run normally
 *           2.check IsApplicationEnabled failed
 */
HWTEST_F(BmsBundleDataMgrTest, IsApplicationEnabled_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    bool isEnabled = false;
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::ALL_USERID);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->IsApplicationEnabled(BUNDLE_NAME_TEST, 0, isEnabled);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: SetApplicationEnabled_0100
 * @tc.name: test SetApplicationEnabled
 * @tc.desc: 1.system run normally
 *           2.check SetApplicationEnabled failed
 */
HWTEST_F(BmsBundleDataMgrTest, SetApplicationEnabled_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    bool isEnabled = false;
    applicationInfo.bundleName = BUNDLE_NAME_TEST;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->SetApplicationEnabled(
        BUNDLE_NAME_TEST, 0, isEnabled, CALLER_NAME_UT, Constants::ALL_USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: SetModuleRemovable_0100
 * @tc.name: test SetModuleRemovable
 * @tc.desc: 1.system run normally
 *           2.check SetModuleRemovable failed
 */
HWTEST_F(BmsBundleDataMgrTest, SetModuleRemovable_0100, Function | SmallTest | Level1)
{
    bool isEnabled = false;
    bool res = GetBundleDataMgr()->SetModuleRemovable(
        BUNDLE_NAME_TEST, BUNDLE_NAME_TEST, isEnabled);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: SetModuleRemovable_0200
 * @tc.name: test SetModuleRemovable
 * @tc.desc: 1.system run normally
 *           2.check SetModuleRemovable failed
 */
HWTEST_F(BmsBundleDataMgrTest, SetModuleRemovable_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    bool isEnabled = false;
    applicationInfo.bundleName = BUNDLE_NAME_TEST;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    bool res = GetBundleDataMgr()->SetModuleRemovable(
        BUNDLE_NAME_TEST, BUNDLE_NAME_TEST, isEnabled);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GenerateUidAndGid_0100
 * @tc.name: test GenerateUidAndGid
 * @tc.desc: 1.system run normally
 *           2.check GenerateUidAndGid failed
 */
HWTEST_F(BmsBundleDataMgrTest, GenerateUidAndGid_0100, Function | SmallTest | Level1)
{
    InnerBundleUserInfo innerBundleUserInfo;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME_TEST;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    GetBundleDataMgr()->bundleIdMap_.emplace(MAX_APP_UID, BUNDLE_TEST1);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    bool res = GetBundleDataMgr()->GenerateUidAndGid(innerBundleUserInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetAllFormsInfo_0100
 * @tc.name: test GetAllFormsInfo
 * @tc.desc: 1.system run normally
 *           2.check GetAllFormsInfo failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllFormsInfo_0100, Function | SmallTest | Level1)
{
    std::vector<FormInfo> formInfos;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    ASSERT_NE(GetBundleDataMgr(), nullptr);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetAllFormsInfo(formInfos);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetFormsInfoByModule_0100
 * @tc.name: test GetFormsInfoByModule
 * @tc.desc: 1.system run normally
 *           2.check GetFormsInfoByModule failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetFormsInfoByModule_0100, Function | SmallTest | Level1)
{
    std::vector<FormInfo> formInfos;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetFormsInfoByModule(BUNDLE_NAME_TEST, BUNDLE_NAME_TEST, formInfos);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetFormsInfoByApp_0100
 * @tc.name: test GetFormsInfoByApp
 * @tc.desc: 1.system run normally
 *           2.check GetFormsInfoByApp failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetFormsInfoByApp_0100, Function | SmallTest | Level1)
{
    std::vector<FormInfo> formInfos;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetFormsInfoByApp(BUNDLE_NAME_TEST, formInfos);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetShortcutInfoV9_0100
 * @tc.name: test GetShortcutInfoV9
 * @tc.desc: 1.system run normally
 *           2.check GetShortcutInfoV9 failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetShortcutInfoV9_0100, Function | SmallTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    ErrCode res = GetBundleDataMgr()->GetShortcutInfoV9("", USERID, shortcutInfos);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: GetAllCommonEventInfo_0100
 * @tc.name: test GetAllCommonEventInfo
 * @tc.desc: 1.system run normally
 *           2.check GetAllCommonEventInfo failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllCommonEventInfo_0100, Function | SmallTest | Level1)
{
    std::vector<CommonEventInfo> commonEventInfos;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetAllCommonEventInfo(BUNDLE_NAME_TEST, commonEventInfos);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetInnerBundleUserInfoByUserId_0100
 * @tc.name: test GetInnerBundleUserInfoByUserId
 * @tc.desc: 1.system run normally
 *           2.check GetInnerBundleUserInfoByUserId failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetInnerBundleUserInfoByUserId_0100, Function | SmallTest | Level1)
{
    InnerBundleUserInfo innerBundleUserInfo;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetInnerBundleUserInfoByUserId(BUNDLE_NAME_TEST, USERID, innerBundleUserInfo);
    EXPECT_EQ(res, false);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
    GetBundleDataMgr()->RemoveUserId(USERID);
}

/**
 * @tc.number: GetInnerBundleUserInfos_0100
 * @tc.name: test GetInnerBundleUserInfos
 * @tc.desc: 1.system run normally
 *           2.check GetInnerBundleUserInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetInnerBundleUserInfos_0100, Function | SmallTest | Level1)
{
    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    bool res = GetBundleDataMgr()->GetInnerBundleUserInfos(BUNDLE_NAME_TEST, innerBundleUserInfos);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetAppPrivilegeLevel_0100
 * @tc.name: test GetAppPrivilegeLevel
 * @tc.desc: 1.system run normally
 *           2.check GetAppPrivilegeLevel failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetAppPrivilegeLevel_0100, Function | SmallTest | Level1)
{
    std::string res = GetBundleDataMgr()->GetAppPrivilegeLevel("", USERID);
    EXPECT_EQ(res, Constants::EMPTY_STRING);
}

/**
 * @tc.number: QueryExtensionAbilityInfos_0200
 * @tc.name: test QueryExtensionAbilityInfos
 * @tc.desc: 1.system run normally
 *           2.check QueryExtensionAbilityInfos true
 */
HWTEST_F(BmsBundleDataMgrTest, QueryExtensionAbilityInfos_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    std::vector<ExtensionAbilityInfo> extensionInfo;
    bool ret = GetBundleDataMgr()->QueryExtensionAbilityInfos(
        ExtensionAbilityType::FORM, USERID, extensionInfo);
    EXPECT_EQ(ret, true);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: QueryExtensionAbilityInfos_0300
 * @tc.name: test QueryExtensionAbilityInfos
 * @tc.desc: 1.system run normally
 *           2.check QueryExtensionAbilityInfos true
 */
HWTEST_F(BmsBundleDataMgrTest, QueryExtensionAbilityInfos_0300, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    std::vector<ExtensionAbilityInfo> extensionInfo;
    bool ret = GetBundleDataMgr()->QueryExtensionAbilityInfos(
        ExtensionAbilityType::FORM, USERID, extensionInfo);
    EXPECT_EQ(ret, true);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: QueryExtensionAbilityInfos_0400
 * @tc.name: test QueryExtensionAbilityInfos
 * @tc.desc: 1.system run normally
 *           2.check QueryExtensionAbilityInfos false
 */
HWTEST_F(BmsBundleDataMgrTest, QueryExtensionAbilityInfos_0400, Function | SmallTest | Level1)
{
    Want want;
    std::vector<ExtensionAbilityInfo> extensionInfo;
    bool ret = bundleMgrHostImpl_->QueryExtensionAbilityInfos(want, 0, Constants::INVALID_USERID, extensionInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: ExplicitQueryExtensionInfo_0100
 * @tc.name: test ExplicitQueryExtensionInfo
 * @tc.desc: 1.system run normally
 *           2.check ExplicitQueryExtensionInfo failed
 */
HWTEST_F(BmsBundleDataMgrTest, ExplicitQueryExtensionInfo_0100, Function | SmallTest | Level1)
{
    Want want;
    ExtensionAbilityInfo extensionInfo;
    int32_t appIndex = 1;
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->sandboxAppHelper_ = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    bool testRet = GetBundleDataMgr()->ExplicitQueryExtensionInfo(
        want, GET_ABILITY_INFO_DEFAULT, Constants::INVALID_UID, extensionInfo, appIndex);
    EXPECT_EQ(testRet, false);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: ImplicitQueryCurExtensionInfos_0100
 * @tc.name: test ImplicitQueryCurExtensionInfos
 * @tc.desc: 1.system run normally
 *           2.check ImplicitQueryCurExtensionInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, ImplicitQueryCurExtensionInfos_0100, Function | SmallTest | Level1)
{
    Want want;
    std::vector<ExtensionAbilityInfo> infos;
    int32_t appIndex = 0;
    GetBundleDataMgr()->sandboxAppHelper_ = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    bool testRet = GetBundleDataMgr()->ImplicitQueryCurExtensionInfos(
        want, GET_ABILITY_INFO_DEFAULT, USERID, infos, appIndex);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: ImplicitQueryCurExtensionInfos_0200
 * @tc.name: test ImplicitQueryCurExtensionInfos
 * @tc.desc: 1.system run normally
 *           2.check ImplicitQueryCurExtensionInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, ImplicitQueryCurExtensionInfos_0200, Function | SmallTest | Level1)
{
    Want want;
    std::vector<ExtensionAbilityInfo> infos;
    int32_t appIndex = Constants::INITIAL_SANDBOX_APP_INDEX + 1;
    GetBundleDataMgr()->ImplicitQueryAllExtensionInfos(
        want, GET_ABILITY_INFO_DEFAULT, Constants::INVALID_UID, infos, appIndex);
    GetBundleDataMgr()->sandboxAppHelper_ = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    bool testRet = GetBundleDataMgr()->ImplicitQueryCurExtensionInfos(
        want, GET_ABILITY_INFO_DEFAULT, Constants::INVALID_UID, infos, appIndex);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: ImplicitQueryCurExtensionInfos_0300
 * @tc.name: test ImplicitQueryCurExtensionInfos
 * @tc.desc: 1.system run normally
 *           2.check ImplicitQueryCurExtensionInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, ImplicitQueryCurExtensionInfos_0300, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME_TEST;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);

    Want want;
    std::vector<ExtensionAbilityInfo> infos;
    int32_t appIndex = 0;
    GetBundleDataMgr()->ImplicitQueryAllExtensionInfos(
        want, GET_ABILITY_INFO_DEFAULT, USERID, infos, appIndex);
    GetBundleDataMgr()->sandboxAppHelper_ = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    bool testRet = GetBundleDataMgr()->ImplicitQueryCurExtensionInfos(
        want, GET_ABILITY_INFO_DEFAULT, USERID, infos, appIndex);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: ImplicitQueryCurExtensionInfos_0400
 * @tc.name: test ImplicitQueryCurExtensionInfos
 * @tc.desc: 1.system run normally
 *           2.check ImplicitQueryCurExtensionInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, ImplicitQueryCurExtensionInfos_0400, Function | SmallTest | Level1)
{
    GetBundleDataMgr()->bundleInfos_.clear();

    Want want;
    std::vector<ExtensionAbilityInfo> infos;
    int32_t appIndex = 0;
    GetBundleDataMgr()->ImplicitQueryAllExtensionInfos(
        want, GET_ABILITY_INFO_DEFAULT, USERID, infos, appIndex);
    GetBundleDataMgr()->sandboxAppHelper_ = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    bool testRet = GetBundleDataMgr()->ImplicitQueryCurExtensionInfos(
        want, GET_ABILITY_INFO_DEFAULT, USERID, infos, appIndex);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: ImplicitQueryCurExtensionInfos_0500
 * @tc.name: test ImplicitQueryCurExtensionInfos
 * @tc.desc: 1.system run normally
 *           2.check ImplicitQueryCurExtensionInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, ImplicitQueryCurExtensionInfos_0500, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME_TEST;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);

    Want want;
    std::vector<ExtensionAbilityInfo> infos;
    int32_t appIndex = 0;
    GetBundleDataMgr()->ImplicitQueryAllExtensionInfos(
        want, GET_ABILITY_INFO_DEFAULT, USERID, infos, appIndex);
    GetBundleDataMgr()->sandboxAppHelper_ = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    bool testRet = GetBundleDataMgr()->ImplicitQueryCurExtensionInfos(
        want, GET_ABILITY_INFO_DEFAULT, USERID, infos, appIndex);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: QueryExtensionAbilityInfoByUri_0100
 * @tc.name: test QueryExtensionAbilityInfoByUri
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleDataMgrTest, QueryExtensionAbilityInfoByUri_0100, Function | SmallTest | Level1)
{
    std::string uri = "/:4///";
    ExtensionAbilityInfo extensionAbilityInfo;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME_TEST;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);

    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    bool testRet = GetBundleDataMgr()->QueryExtensionAbilityInfoByUri(
        uri, USERID, extensionAbilityInfo);
    EXPECT_EQ(false, testRet);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: QueryExtensionAbilityInfoByUri_0200
 * @tc.name: test QueryExtensionAbilityInfoByUri
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleDataMgrTest, QueryExtensionAbilityInfoByUri_0200, Function | SmallTest | Level1)
{
    std::string uri = "/:4///";
    ExtensionAbilityInfo extensionAbilityInfo;
    InnerBundleInfo innerBundleInfo;

    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    bool testRet = GetBundleDataMgr()->QueryExtensionAbilityInfoByUri(
        uri, USERID, extensionAbilityInfo);
    EXPECT_EQ(false, testRet);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: QueryExtensionAbilityInfoByUri_0300
 * @tc.name: test QueryExtensionAbilityInfoByUri
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleDataMgrTest, QueryExtensionAbilityInfoByUri_0300, Function | SmallTest | Level1)
{
    ExtensionAbilityInfo extensionAbilityInfo;
    bool testRet = bundleMgrHostImpl_->QueryExtensionAbilityInfoByUri(
        HAP_FILE_PATH, USERID, extensionAbilityInfo);
    EXPECT_EQ(false, testRet);
}

/**
 * @tc.number: UpdateQuickFixInnerBundleInfo_0100
 * @tc.name: test UpdateQuickFixInnerBundleInfo
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleDataMgrTest, UpdateQuickFixInnerBundleInfo_0100, Function | SmallTest | Level1)
{
    bool removable = false;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_TEST3;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);

    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST3, innerBundleInfo);
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->UpdateRemovable(BUNDLE_TEST3, removable);
    GetBundleDataMgr()->UpdatePrivilegeCapability(BUNDLE_TEST3, applicationInfo);
        bool res = GetBundleDataMgr()->UpdateQuickFixInnerBundleInfo(BUNDLE_TEST3, innerBundleInfo);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: GetAppProvisionInfo_0100
 * @tc.name: test GetAppProvisionInfo
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleDataMgrTest, GetAppProvisionInfo_0100, Function | SmallTest | Level1)
{
    AppProvisionInfo appProvisionInfo;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_TEST1;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetApplicationBundleType(BundleType::APP);
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::INVALID_USERID);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetAppProvisionInfo(
        BUNDLE_TEST1, Constants::INVALID_USERID, appProvisionInfo);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: GetSharedBundleInfo_0100
 * @tc.name: Test GetSharedBundleInfo
 * @tc.desc: Test GetSharedBundleInfo with InnerBundleInfo
 */
HWTEST_F(BmsBundleDataMgrTest, GetSharedBundleInfo_0100, Function | SmallTest | Level1)
{
    std::vector<SharedBundleInfo> sharedBundles;
    auto ret = GetBundleDataMgr()->GetSharedBundleInfo(BUNDLE_TEST3, BUNDLE_TEST3, sharedBundles);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: GetSharedBundleInfo_0200
 * @tc.name: Test GetSharedBundleInfo
 * @tc.desc: Test GetSharedBundleInfo
 */
HWTEST_F(BmsBundleDataMgrTest, GetSharedBundleInfo_0200, Function | SmallTest | Level1)
{
    BundleInfo bundleInfo;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_TEST1;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode ret = GetBundleDataMgr()->GetSharedBundleInfo(BUNDLE_TEST1, GET_ABILITY_INFO_DEFAULT, bundleInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetSharedBundleInfo_0300
 * @tc.name: Test GetSharedBundleInfo
 * @tc.desc: Test GetSharedBundleInfo
 */
HWTEST_F(BmsBundleDataMgrTest, GetSharedBundleInfo_0300, Function | SmallTest | Level1)
{
    BundleInfo bundleInfo;
    GetBundleDataMgr()->bundleInfos_.clear();
    ErrCode ret = GetBundleDataMgr()->GetSharedBundleInfo(BUNDLE_TEST1, GET_ABILITY_INFO_DEFAULT, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetSharedBundleInfo_0400
 * @tc.name: Test GetSharedBundleInfo
 * @tc.desc: Test GetSharedBundleInfo
 */
HWTEST_F(BmsBundleDataMgrTest, GetSharedBundleInfo_0400, Function | SmallTest | Level1)
{
    BundleInfo bundleInfo;
    ErrCode ret = GetBundleDataMgr()->GetSharedBundleInfo("", GET_ABILITY_INFO_DEFAULT, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: GetSharedBundleInfo_0500
 * @tc.name: Test GetSharedBundleInfo
 * @tc.desc: Test GetSharedBundleInfo
 */
HWTEST_F(BmsBundleDataMgrTest, GetSharedBundleInfo_0500, Function | SmallTest | Level1)
{
    std::vector<SharedBundleInfo> sharedBundles;
    ErrCode ret = bundleMgrHostImpl_->GetSharedBundleInfo("", "", sharedBundles);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: GetSharedDependencies_0100
 * @tc.name: test GetSharedDependencies
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleDataMgrTest, GetSharedDependencies_0100, Function | SmallTest | Level1)
{
    std::vector<Dependency> dependencies;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_TEST1;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetSharedDependencies(
        BUNDLE_TEST1, BUNDLE_TEST1, dependencies);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: CheckHspVersionIsRelied_0100
 * @tc.name: test CheckHspVersionIsRelied
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleDataMgrTest, CheckHspVersionIsRelied_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    bool res = GetBundleDataMgr()->CheckHspVersionIsRelied(ServiceConstants::API_VERSION_NINE, innerBundleInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetSpecifiedDistributionType_0100
 * @tc.name: test GetSpecifiedDistributionType
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleDataMgrTest, GetSpecifiedDistributionType_0100, Function | SmallTest | Level1)
{
    std::string specifiedDistributionType = "";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_TEST1;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetApplicationBundleType(BundleType::APP);
    innerBundleInfo.innerBundleUserInfos_.clear();
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetSpecifiedDistributionType(
        BUNDLE_TEST1, specifiedDistributionType);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetAdditionalInfo_0100
 * @tc.name: test GetAdditionalInfo
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleDataMgrTest, GetAdditionalInfo_0100, Function | SmallTest | Level1)
{
    std::string additionalInfo = "";
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_TEST1;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetApplicationBundleType(BundleType::APP);
    innerBundleInfo.innerBundleUserInfos_.clear();
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->GetAdditionalInfo(
        BUNDLE_TEST1, additionalInfo);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: BundleFreeInstall_0200
 * @tc.name: test CheckAbilityEnableInstall
 * @tc.desc: 1.check ability infos
 */
HWTEST_F(BmsBundleDataMgrTest, CheckAbilityEnableInstall_0100, Function | MediumTest | Level1)
{
    AAFwk::Want want;
    int32_t missionId = 0;
    ElementName name;
    want.SetElementName("", BUNDLE_NAME_TEST, ABILITY_NAME_TEST, MODULE_NAME_TEST);
    name.SetDeviceID("100");
    want.SetElement(name);
    bool ret = bundleMgrHostImpl_->CheckAbilityEnableInstall(want, missionId, USERID, nullptr);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: UpgradeAtomicService_0100
 * @tc.name: test UpgradeAtomicService
 * @tc.desc: 1.test UpgradeAtomicService
 */
HWTEST_F(BmsBundleDataMgrTest, UpgradeAtomicService_0100, Function | MediumTest | Level1)
{
    AAFwk::Want want;
    DelayedSingleton<BundleMgrService>::GetInstance()->InitFreeInstall();
    auto ret = DelayedSingleton<BundleMgrService>::GetInstance()->connectAbilityMgr_;
    bundleMgrHostImpl_->UpgradeAtomicService(want, USERID);
    ASSERT_TRUE(ret.empty());
}

/**
 * @tc.number: CheckAbilityEnableInstall_0200
 * @tc.name: test CheckAbilityEnableInstall
 * @tc.desc: 1.check ability infos
 */
HWTEST_F(BmsBundleDataMgrTest, CheckAbilityEnableInstall_0200, Function | MediumTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    AAFwk::Want want;
    ElementName name;
    int32_t missionId = 0;
    want.SetElementName("", BUNDLE_NAME_TEST, ABILITY_NAME_TEST, MODULE_NAME_TEST);
    name.SetDeviceID("100");
    want.SetElement(name);

    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    DelayedSingleton<BundleMgrService>::GetInstance()->InitFreeInstall();
    bool ret = bundleMgrHostImpl_->CheckAbilityEnableInstall(want, missionId, USERID, remoteObject);
    EXPECT_EQ(ret, false);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: ProcessPreload_0100
 * @tc.name: test ProcessPreload
 * @tc.desc: 1.test ProcessPreload
 */
HWTEST_F(BmsBundleDataMgrTest, ProcessPreload_0100, Function | MediumTest | Level1)
{
    AAFwk::Want want;
    DelayedSingleton<BundleMgrService>::GetInstance()->InitFreeInstall();
    bool res = bundleMgrHostImpl_->ProcessPreload(want);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: ProcessPreload_0200
 * @tc.name: test ProcessPreload
 * @tc.desc: 1.test ProcessPreload
 */
HWTEST_F(BmsBundleDataMgrTest, ProcessPreload_0200, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    EXPECT_NE(bundleConnectAbility, nullptr);
    Want want;
    bool res = bundleConnectAbility->ProcessPreload(want);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: CheckIsModuleNeedUpdateWrap_0100
 * @tc.name: CheckIsModuleNeedUpdateWrap
 * @tc.desc: test CheckIsModuleNeedUpdateWrap of BundleConnectAbilityMgr
 */
HWTEST_F(BmsBundleDataMgrTest, CheckIsModuleNeedUpdateWrap_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    EXPECT_NE(bundleConnectAbility, nullptr);
    InnerBundleInfo innerBundleInfo;
    Want want;
    bool res = bundleConnectAbility->CheckIsModuleNeedUpdateWrap(innerBundleInfo, want, USERID, nullptr);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: IsObtainAbilityInfo_0100
 * @tc.name: IsObtainAbilityInfo
 * @tc.desc: test IsObtainAbilityInfo of BundleConnectAbilityMgr
 */
HWTEST_F(BmsBundleDataMgrTest, IsObtainAbilityInfo_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    EXPECT_NE(bundleConnectAbility, nullptr);
    Want want;
    want.SetElementName("", "", ABILITY_NAME_TEST, MODULE_NAME_TEST);
    int32_t flags = 0;
    AbilityInfo abilityInfo;
    InnerBundleInfo innerBundleInfo;
    bool res = bundleConnectAbility->IsObtainAbilityInfo(want, flags, USERID, abilityInfo, nullptr, innerBundleInfo);
    EXPECT_EQ(res, false);

    want.SetElementName("", BUNDLE_NAME_TEST, ABILITY_NAME_TEST, MODULE_NAME_TEST);
    res = bundleConnectAbility->IsObtainAbilityInfo(want, flags, USERID, abilityInfo, nullptr, innerBundleInfo);
    EXPECT_EQ(res, false);

    want.SetElementName("", BUNDLE_NAME_TEST, ABILITY_NAME_TEST, "");
    res = bundleConnectAbility->IsObtainAbilityInfo(want, flags, USERID, abilityInfo, nullptr, innerBundleInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: UnregisterBundleStatusCallback_0100
 * @tc.name: test UnregisterBundleStatusCallback
 * @tc.desc: test UnregisterBundleStatusCallback
 */
HWTEST_F(BmsBundleDataMgrTest, UnregisterBundleStatusCallback_0100, Function | MediumTest | Level1)
{
    bool retBool = bundleMgrHostImpl_->UnregisterBundleStatusCallback();
    EXPECT_EQ(retBool, true);
}

/**
 * @tc.number: GetAbilityInfo_0100
 * @tc.name: test GetAbilityInfo
 * @tc.desc: test GetAbilityInfo
 */
HWTEST_F(BmsBundleDataMgrTest, GetAbilityInfo_0100, Function | MediumTest | Level1)
{
    AbilityInfo abilityInfo;
    bool retBool = bundleMgrHostImpl_->GetAbilityInfo(
        BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, abilityInfo);
    EXPECT_EQ(retBool, false);
}

/**
 * @tc.number: ImplicitQueryInfoByPriority_0100
 * @tc.name: test ImplicitQueryInfoByPriority
 * @tc.desc: 1.check ability infos
 */
HWTEST_F(BmsBundleDataMgrTest, ImplicitQueryInfoByPriority_0100, Function | MediumTest | Level1)
{
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_NAME_TEST, ABILITY_NAME_TEST, MODULE_NAME_TEST);
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;

    bool ret = bundleMgrHostImpl_->ImplicitQueryInfoByPriority(want, 0, USERID, abilityInfo, extensionInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: ImplicitQueryInfos_0100
 * @tc.name: test ImplicitQueryInfos
 * @tc.desc: 1.check Implicit infos
 */
HWTEST_F(BmsBundleDataMgrTest, ImplicitQueryInfos_0100, Function | MediumTest | Level1)
{
    AAFwk::Want want;
    want.SetElementName("", BUNDLE_NAME_TEST, ABILITY_NAME_TEST, MODULE_NAME_TEST);
    std::vector<AbilityInfo> abilityInfo;
    std::vector<ExtensionAbilityInfo> extensionInfo;
    bool findDefaultApp = false;
    bool ret = bundleMgrHostImpl_->ImplicitQueryInfos(want, 0, USERID, USERID, abilityInfo, extensionInfo,
        findDefaultApp);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(findDefaultApp, false);
}

/**
 * @tc.number: GetAllDependentModuleNames_0100
 * @tc.name: test GetAllDependentModuleNames
 * @tc.desc: 1.Get DependentModuleName
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllDependentModuleNames_0100, Function | MediumTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::vector<std::string> dependentModuleNames;
    bool ret = bundleMgrHostImpl_->GetAllDependentModuleNames(BUNDLE_NAME_TEST, MODULE_NAME_TEST, dependentModuleNames);
    EXPECT_EQ(ret, true);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetSandboxBundleInfo_0100
 * @tc.name: test GetSandboxBundleInfo
 * @tc.desc: 1.GetSandboxBundleInfo
 */
HWTEST_F(BmsBundleDataMgrTest, GetSandboxBundleInfo_0100, Function | MediumTest | Level1)
{
    int32_t appIndex = Constants::INITIAL_SANDBOX_APP_INDEX + 1;
    BundleInfo info;
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->sandboxAppHelper_ = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    ErrCode ret = bundleMgrHostImpl_->GetSandboxBundleInfo(BUNDLE_NAME_TEST, appIndex, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_APP_NOT_SUPPORTED);
}

/**
 * @tc.number: GetSandboxAbilityInfo_0100
 * @tc.name: test GetSandboxAbilityInfo
 * @tc.desc: 1.GetSandboxAbilityInfo
 */
HWTEST_F(BmsBundleDataMgrTest, GetSandboxAbilityInfo_0100, Function | MediumTest | Level1)
{
    int32_t appIndex = -1;
    Want want;
    AbilityInfo info;
    ErrCode ret = bundleMgrHostImpl_->GetSandboxAbilityInfo(want, appIndex, 0, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    appIndex = 101;
    bundleMgrHostImpl_->GetSandboxAbilityInfo(want, appIndex, 0, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: GetStringById_0100
 * @tc.name: test GetStringById
 * @tc.desc: test GetStringById
 */
HWTEST_F(BmsBundleDataMgrTest, GetStringById_0100, Function | MediumTest | Level1)
{
    uint32_t resId = 1;
    std::string retBool = bundleMgrHostImpl_->GetStringById(BUNDLE_NAME_TEST, MODULE_NAME_TEST, resId, USERID, "");
    EXPECT_EQ(retBool, Constants::EMPTY_STRING);
}

/**
 * @tc.number: GetSandboxHapModuleInfo_0100
 * @tc.name: test GetSandboxHapModuleInfo
 * @tc.desc: 1.GetSandboxHapModuleInfo
 */
HWTEST_F(BmsBundleDataMgrTest, GetSandboxHapModuleInfo_0100, Function | MediumTest | Level1)
{
    int32_t appIndex = 1 + Constants::INITIAL_SANDBOX_APP_INDEX;
    HapModuleInfo hapModuleInfo;
    AbilityInfo info;
    GetBundleDataMgr()->sandboxAppHelper_ = nullptr;
    ErrCode ret = bundleMgrHostImpl_->GetSandboxHapModuleInfo(info, appIndex, USERID, hapModuleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR);
}

/**
 * @tc.number: GetSandboxHapModuleInfo_0200
 * @tc.name: test GetSandboxHapModuleInfo
 * @tc.desc: 1.GetSandboxHapModuleInfo
 */
HWTEST_F(BmsBundleDataMgrTest, GetSandboxHapModuleInfo_0200, Function | MediumTest | Level1)
{
    int32_t appIndex = 1 + Constants::INITIAL_SANDBOX_APP_INDEX;
    HapModuleInfo hapModuleInfo;
    AbilityInfo info;
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->sandboxAppHelper_ = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    ErrCode ret = bundleMgrHostImpl_->GetSandboxHapModuleInfo(
        info, appIndex, Constants::INVALID_USERID, hapModuleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_QUERY_INVALID_USER_ID);
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: GetMediaData_0100
 * @tc.name: test GetMediaData
 * @tc.desc: 1.GetMediaData
 */
HWTEST_F(BmsBundleDataMgrTest, GetMediaData_0100, Function | MediumTest | Level1)
{
    std::unique_ptr<uint8_t[]> mediaDataPtr;
    size_t len = 7;
    ErrCode ret = bundleMgrHostImpl_->GetMediaData(
        BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, mediaDataPtr, len, USERID);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetProvisionMetadata_0100
 * @tc.name: test GetProvisionMetadata
 * @tc.desc: 1.GetProvisionMetadata
 */
HWTEST_F(BmsBundleDataMgrTest, GetProvisionMetadata_0100, Function | MediumTest | Level1)
{
    std::vector<Metadata> provisionMetadatas;
    ErrCode ret = bundleMgrHostImpl_->GetProvisionMetadata(BUNDLE_NAME_TEST, USERID, provisionMetadatas);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: TestAOTCompileStatus_0100
 * @tc.name: test SetAOTCompileStatus
 * @tc.desc: 1.AOTCompileStatus
 */
HWTEST_F(BmsBundleDataMgrTest, TestAOTCompileStatus_0100, Function | MediumTest | Level1)
{
    InnerBundleInfo info;
    info.SetAOTCompileStatus(MODULE_NAME1, AOTCompileStatus::COMPILE_SUCCESS);
    AOTCompileStatus ret = info.GetAOTCompileStatus(MODULE_NAME1);
    EXPECT_EQ(ret, AOTCompileStatus::NOT_COMPILED);
}

/**
 * @tc.number: TestAOTCompileStatus_0200
 * @tc.name: test SetAOTCompileStatus
 * @tc.desc: 1.AOTCompileStatus
 */
HWTEST_F(BmsBundleDataMgrTest, TestAOTCompileStatus_0200, Function | MediumTest | Level1)
{
    InnerBundleInfo info;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME1;
    info.innerModuleInfos_.try_emplace(MODULE_NAME1, moduleInfo);
    info.SetAOTCompileStatus(MODULE_NAME1, AOTCompileStatus::COMPILE_SUCCESS);

    AOTCompileStatus ret = info.GetAOTCompileStatus(MODULE_NAME1);
    EXPECT_EQ(ret, AOTCompileStatus::COMPILE_SUCCESS);
}

/**
 * @tc.number: TestFindAbilityInfos_0100
 * @tc.name: test FindAbilityInfos
 * @tc.desc: 1.FindAbilityInfos
 */
HWTEST_F(BmsBundleDataMgrTest, TestFindAbilityInfos_0100, Function | MediumTest | Level1)
{
    InnerBundleInfo info;
    info.innerModuleInfos_.clear();
    std::optional<std::vector<AbilityInfo>> ret =
        info.FindAbilityInfos(Constants::ALL_USERID);
    EXPECT_EQ(ret, std::nullopt);
}
} // OHOS