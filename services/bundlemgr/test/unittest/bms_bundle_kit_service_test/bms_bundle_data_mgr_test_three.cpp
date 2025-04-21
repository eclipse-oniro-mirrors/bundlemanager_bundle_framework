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

class BmsBundleDataMgrTest3 : public testing::Test {
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

std::shared_ptr<BundleMgrService> BmsBundleDataMgrTest3::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleDataMgrTest3::installdService_ =
    std::make_shared<InstalldService>();

void BmsBundleDataMgrTest3::SetUpTestCase()
{}

void BmsBundleDataMgrTest3::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleDataMgrTest3::SetUp()
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

void BmsBundleDataMgrTest3::TearDown()
{}

void BmsBundleDataMgrTest3::ClearDataMgr()
{
    bundleMgrService_->dataMgr_ = nullptr;
}

void BmsBundleDataMgrTest3::ResetDataMgr()
{
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(bundleMgrService_->dataMgr_, nullptr);
}

void BmsBundleDataMgrTest3::RemoveBundleinfo(const std::string &bundleName)
{
    auto iterator = bundleMgrService_->GetDataMgr()->bundleInfos_.find(bundleName);
    if (iterator != bundleMgrService_->GetDataMgr()->bundleInfos_.end()) {
        bundleMgrService_->GetDataMgr()->bundleInfos_.erase(iterator);
    }
}
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
const std::shared_ptr<BundleDistributedManager> BmsBundleDataMgrTest3::GetBundleDistributedManager() const
{
    return bundleMgrService_->GetBundleDistributedManager();
}
#endif

std::shared_ptr<BundleDataMgr> BmsBundleDataMgrTest3::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

std::shared_ptr<LauncherService> BmsBundleDataMgrTest3::GetLauncherService() const
{
    return launcherService_;
}

sptr<BundleMgrProxy> BmsBundleDataMgrTest3::GetBundleMgrProxy()
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

void BmsBundleDataMgrTest3::AddBundleInfo(const std::string &bundleName, BundleInfo &bundleInfo) const
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

void BmsBundleDataMgrTest3::AddApplicationInfo(const std::string &bundleName, ApplicationInfo &appInfo,
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

void BmsBundleDataMgrTest3::AddInnerBundleInfoByTest(const std::string &bundleName,
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

void BmsBundleDataMgrTest3::MockInstallBundle(
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

void BmsBundleDataMgrTest3::MockInstallExtension(const std::string &bundleName,
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

InnerModuleInfo BmsBundleDataMgrTest3::MockModuleInfo(const std::string &moduleName) const
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

void BmsBundleDataMgrTest3::SaveToDatabase(const std::string &bundleName,
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

void BmsBundleDataMgrTest3::MockInstallBundle(
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

FormInfo BmsBundleDataMgrTest3::MockFormInfo(
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

ShortcutInfo BmsBundleDataMgrTest3::MockShortcutInfo(
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

ShortcutIntent BmsBundleDataMgrTest3::MockShortcutIntent() const
{
    ShortcutIntent shortcutIntent;
    shortcutIntent.targetBundle = SHORTCUT_INTENTS_TARGET_BUNDLE;
    shortcutIntent.targetModule = SHORTCUT_INTENTS_TARGET_MODULE;
    shortcutIntent.targetClass = SHORTCUT_INTENTS_TARGET_CLASS;
    return shortcutIntent;
}

ShortcutWant BmsBundleDataMgrTest3::MockShortcutWant() const
{
    ShortcutWant shortcutWant;
    shortcutWant.bundleName = BUNDLE_NAME_DEMO;
    shortcutWant.moduleName = MODULE_NAME_DEMO;
    shortcutWant.abilityName = ABILITY_NAME_DEMO;
    return shortcutWant;
}

Shortcut BmsBundleDataMgrTest3::MockShortcut() const
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

CommonEventInfo BmsBundleDataMgrTest3::MockCommonEventInfo(
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

void BmsBundleDataMgrTest3::MockUninstallBundle(const std::string &bundleName) const
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool startRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START);
    bool finishRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS);

    EXPECT_TRUE(startRet);
    EXPECT_TRUE(finishRet);
}

AbilityInfo BmsBundleDataMgrTest3::MockAbilityInfo(
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

ExtensionAbilityInfo BmsBundleDataMgrTest3::MockExtensionInfo(
    const std::string &bundleName, const std::string &moduleName, const std::string &extensionName) const
{
    ExtensionAbilityInfo extensionInfo;
    extensionInfo.name = extensionName;
    extensionInfo.bundleName = bundleName;
    extensionInfo.moduleName = moduleName;
    return extensionInfo;
}

void BmsBundleDataMgrTest3::MockInnerBundleInfo(const std::string &bundleName, const std::string &moduleName,
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

void BmsBundleDataMgrTest3::MockInnerBundleInfo(const std::string &bundleName, const std::string &moduleName,
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

ShortcutInfo BmsBundleDataMgrTest3::InitShortcutInfo()
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

bool BmsBundleDataMgrTest3::CheckBmsExtensionProfile()
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
 * @tc.number: GetDataMgr_0100
 * @tc.name: GetDataMgr
 * @tc.desc: test GetDataMgr of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, GetDataMgr_0100, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    const std::shared_ptr<BundleDataMgr> ptr = bmsExtensionClient->GetDataMgr();
    EXPECT_NE(ptr, nullptr);
}

/**
 * @tc.number: ImplicitQueryAbilityInfos_0100
 * @tc.name: ImplicitQueryAbilityInfos
 * @tc.desc: test ImplicitQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, ImplicitQueryAbilityInfos_0100, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    Want want;
    int32_t flags = 0;
    int32_t userId = -1;
    std::vector<AbilityInfo> abilityInfos;
    ErrCode res = bmsExtensionClient->ImplicitQueryAbilityInfos(want, flags, userId, abilityInfos, true);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: ImplicitQueryAbilityInfos_0200
 * @tc.name: ImplicitQueryAbilityInfos
 * @tc.desc: test ImplicitQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, ImplicitQueryAbilityInfos_0200, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    Want want;
    want.SetElementName("", "com.ohos.settings",  "MainAbility", "");
    int32_t flags = 0;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    ErrCode res = bmsExtensionClient->ImplicitQueryAbilityInfos(want, flags, userId, abilityInfos, true);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: ImplicitQueryAbilityInfos_0300
 * @tc.name: ImplicitQueryAbilityInfos
 * @tc.desc: test ImplicitQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, ImplicitQueryAbilityInfos_0300, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    Want want;
    int32_t flags = 0;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    ErrCode res = bmsExtensionClient->ImplicitQueryAbilityInfos(want, flags, userId, abilityInfos, true);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
}

/**
 * @tc.number: GetBundleStats_0300
 * @tc.name: GetBundleStats
 * @tc.desc: test GetBundleStats of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, GetBundleStats_0300, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::string bundleName;
    int32_t userId = 100;
    std::vector<int64_t> bundleStats;
    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    ErrCode res = bmsExtensionClient->GetBundleStats(bundleName, userId, bundleStats);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetBundleStats_0400
 * @tc.name: GetBundleStats
 * @tc.desc: test GetBundleStats of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, GetBundleStats_0400, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::string bundleName;
    int32_t userId = 100;
    std::vector<int64_t> bundleStats;
    bmsExtensionClient->bmsExtensionImpl_ = std::shared_ptr<BmsExtensionDataMgr>();
    ErrCode res = bmsExtensionClient->GetBundleStats(bundleName, userId, bundleStats);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: ClearData_0200
 * @tc.name: ClearData
 * @tc.desc: test ClearData of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, ClearData_0200, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::string bundleName;
    int32_t userId = 100;
    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    ErrCode res = bmsExtensionClient->ClearData(bundleName, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: ClearData_0300
 * @tc.name: ClearData
 * @tc.desc: test ClearData of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, ClearData_0300, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::string bundleName;
    int32_t userId = 100;
    ErrCode res = bmsExtensionClient->ClearData(bundleName, userId);
    if (CheckBmsExtensionProfile()) {
        EXPECT_EQ(res, ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY);
    } else {
        EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
    }
}

/**
 * @tc.number: BatchQueryAbilityInfos_0100
 * @tc.name: BatchQueryAbilityInfos
 * @tc.desc: test BatchQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BatchQueryAbilityInfos_0100, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::vector<Want> wants;
    int32_t flags = 1;
    int32_t userId = -3;
    std::vector<AbilityInfo> abilityInfos;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->BatchQueryAbilityInfos(wants, flags, userId, abilityInfos, isNewVersion);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: BatchQueryAbilityInfos_0200
 * @tc.name: BatchQueryAbilityInfos
 * @tc.desc: test BatchQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BatchQueryAbilityInfos_0200, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::vector<Want> wants;
    int32_t flags = 1;
    int32_t userId = 100;
    std::vector<AbilityInfo> abilityInfos;
    bool isNewVersion = true;
    ErrCode res = bmsExtensionClient->BatchQueryAbilityInfos(wants, flags, userId, abilityInfos, isNewVersion);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: GetCloneBundleInfos_0001
 * @tc.name: GetCloneBundleInfos
 * @tc.desc: test GetCloneBundleInfos
 */
HWTEST_F(BmsBundleDataMgrTest3, GetCloneBundleInfos_0001, Function | MediumTest | Level1)
{
    ResetDataMgr();
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME_DEMO;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME_DEMO;
    bundleInfo.applicationInfo.bundleName = BUNDLE_NAME_DEMO;
    std::vector<BundleInfo> bundleInfos;
    int32_t flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    GetBundleDataMgr()->GetCloneBundleInfos(innerBundleInfo, flags, USERID, bundleInfo, bundleInfos);
    EXPECT_TRUE(bundleInfos.empty());

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    userInfo.bundleName = BUNDLE_NAME_DEMO;
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.userId = USERID;
    cloneInfo.uid = 1001;
    cloneInfo.appIndex = 1;
    cloneInfo.accessTokenId = 20000;
    innerBundleInfo.AddCloneBundle(cloneInfo);
    GetBundleDataMgr()->GetCloneBundleInfos(innerBundleInfo, flags, USERID, bundleInfo, bundleInfos);
    EXPECT_FALSE(bundleInfos.empty());

    if (!bundleInfos.empty()) {
        EXPECT_EQ(bundleInfos[0].appIndex, cloneInfo.appIndex);
        EXPECT_EQ(bundleInfos[0].uid, cloneInfo.uid);
        EXPECT_EQ(bundleInfos[0].applicationInfo.accessTokenId, cloneInfo.accessTokenId);
        EXPECT_EQ(bundleInfos[0].applicationInfo.appIndex, cloneInfo.appIndex);
    }
}

/**
 * @tc.number: FilterAbilityInfosByAppLinking_0010
 * @tc.name: FilterAbilityInfosByAppLinkingEmptyAbilityInfos
 * @tc.desc: test FilterAbilityInfosByAppLinking with empty abilityInfos.
 */
HWTEST_F(BmsBundleDataMgrTest3, FilterAbilityInfosByAppLinking_0010, Function | SmallTest | Level1)
{
    Want want;
    want.SetUri(TEST_URI_HTTPS);
    int32_t flags = GET_ABILITY_INFO_WITH_APP_LINKING;
    std::vector<AbilityInfo> abilityInfos;
    GetBundleDataMgr()->FilterAbilityInfosByAppLinking(want, flags, abilityInfos);
    EXPECT_EQ(abilityInfos.size(), 0);
}

/**
 * @tc.number: FilterAbilityInfosByAppLinking_0020
 * @tc.name: FilterAbilityInfosByAppLinkingWithoutFlag
 * @tc.desc: test FilterAbilityInfosByAppLinking without flag.
 */
HWTEST_F(BmsBundleDataMgrTest3, FilterAbilityInfosByAppLinking_0020, Function | SmallTest | Level1)
{
    Want want;
    want.SetUri(TEST_URI_HTTPS);
    int32_t flags = 0;
    std::vector<AbilityInfo> abilityInfos;
    AbilityInfo abilityInfo;
    abilityInfos.emplace_back(abilityInfo);
    GetBundleDataMgr()->FilterAbilityInfosByAppLinking(want, flags, abilityInfos);
    EXPECT_EQ(abilityInfos.size(), 1);
}

/**
 * @tc.number: FilterAbilityInfosByAppLinking_0030
 * @tc.name: FilterAbilityInfosByAppLinkingUriNotHttps
 * @tc.desc: test FilterAbilityInfosByAppLinking with uri not start with https.
 */
HWTEST_F(BmsBundleDataMgrTest3, FilterAbilityInfosByAppLinking_0030, Function | SmallTest | Level1)
{
    Want want;
    want.SetUri(TEST_URI_HTTP);
    int32_t flags = GET_ABILITY_INFO_WITH_APP_LINKING;
    std::vector<AbilityInfo> abilityInfos;
    AbilityInfo abilityInfo;
    abilityInfos.emplace_back(abilityInfo);
    GetBundleDataMgr()->FilterAbilityInfosByAppLinking(want, flags, abilityInfos);
    EXPECT_EQ(abilityInfos.size(), 0);
}

/**
 * @tc.number: FilterAbilityInfosByAppLinking_0040
 * @tc.name: FilterAbilityInfosByAppLinkingSuccess
 * @tc.desc: test FilterAbilityInfosByAppLinking success.
 */
HWTEST_F(BmsBundleDataMgrTest3, FilterAbilityInfosByAppLinking_0040, Function | SmallTest | Level1)
{
    Want want;
    want.SetUri(TEST_URI_HTTPS);
    int32_t flags = GET_ABILITY_INFO_WITH_APP_LINKING;
    std::vector<AbilityInfo> abilityInfos;
    AbilityInfo abilityInfo;
    abilityInfos.emplace_back(abilityInfo);
    GetBundleDataMgr()->FilterAbilityInfosByAppLinking(want, flags, abilityInfos);
    EXPECT_EQ(abilityInfos.size(), 0);
}

/**
 * @tc.number: GetModuleName_0100
 * @tc.name: test GetModuleName
 * @tc.desc: 1.test get moduleName from innerBundleInfo
 */
HWTEST_F(BmsBundleDataMgrTest3, GetModuleName_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    ASSERT_NE(bundleConnectAbility, nullptr);
    Want want;
    InnerBundleInfo innerBundleInfo;
    std::string moduleName = "";
    bool res = bundleConnectAbility->GetModuleName(innerBundleInfo, want, moduleName);
    EXPECT_EQ(res, false);

    std::string bundleName = BUNDLE_NAME_TEST;
    std::string abilityName = ABILITY_NAME_TEST;
    want.SetElementName(bundleName, abilityName);
    std::string targetModuleName = MODULE_NAME1;
    AbilityInfo abilityInfo = MockAbilityInfo(bundleName, targetModuleName, abilityName);
    std::string keyName = bundleName + "." + targetModuleName + "." + abilityName;
    innerBundleInfo.InsertAbilitiesInfo(keyName, abilityInfo);
    res = bundleConnectAbility->GetModuleName(innerBundleInfo, want, moduleName);
    EXPECT_EQ(moduleName, targetModuleName);
    EXPECT_EQ(res, true);

    moduleName = BUNDLE_NAME_TEST;
    res = bundleConnectAbility->GetModuleName(innerBundleInfo, want, moduleName);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number:CheckIsOnDemandLoad_0100
 * @tc.name: test CheckIsOnDemandLoad
 * @tc.desc: 1.test check targetAbilityInfo is loaded as needed
 */
HWTEST_F(BmsBundleDataMgrTest3, CheckIsOnDemandLoad_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    ASSERT_NE(bundleConnectAbility, nullptr);
    TargetAbilityInfo targetAbilityInfo;
    bool res = bundleConnectAbility->CheckIsOnDemandLoad(targetAbilityInfo);
    EXPECT_EQ(res, false);

    targetAbilityInfo.targetInfo.callingBundleNames.emplace_back(BUNDLE_NAME_TEST);
    res = bundleConnectAbility->CheckIsOnDemandLoad(targetAbilityInfo);
    EXPECT_EQ(res, false);

    targetAbilityInfo.targetInfo.bundleName = BUNDLE_NAME_TEST;
    res = bundleConnectAbility->CheckIsOnDemandLoad(targetAbilityInfo);
    EXPECT_EQ(res, false);
}


/**
 * @tc.number:GetEcologicalCallerInfo_0100
 * @tc.name: test GetEcologicalCallerInfo
 * @tc.desc: 1.test obtain ecological caller information
 */
HWTEST_F(BmsBundleDataMgrTest3, GetEcologicalCallerInfo_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    ASSERT_NE(bundleConnectAbility, nullptr);
    Want want;
    ErmsCallerInfo callerInfo;
    InnerBundleInfo innerBundleInfo;
    bundleConnectAbility->GetEcologicalCallerInfo(want, callerInfo, USERID);
    EXPECT_EQ(callerInfo.targetAppType, TYPE_HARMONEY_SERVICE_VALUE);
    EXPECT_EQ(callerInfo.callerAppType, TYPE_HARMONEY_INVALID_VALUE);
}

/**
 * @tc.number:CheckEcologicalRule_0100
 * @tc.name: test CheckEcologicalRule
 * @tc.desc: 1.test check ecological rules
 */
HWTEST_F(BmsBundleDataMgrTest3, CheckEcologicalRule_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    ASSERT_NE(bundleConnectAbility, nullptr);
    Want want;
    ErmsCallerInfo callerInfo;
    bundleConnectAbility->GetEcologicalCallerInfo(want, callerInfo, USERID);
    BmsExperienceRule rule;
    bool ret = bundleConnectAbility->CheckEcologicalRule(want, callerInfo, rule);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: SilentInstall_0100
 * @tc.name: test SilentInstall
 * @tc.desc: 1.test silent Install
 */
HWTEST_F(BmsBundleDataMgrTest3, SilentInstall_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    ASSERT_NE(bundleConnectAbility, nullptr);
    Want want;
    IBundleEventCallbackTest iBundleEventCallback;
    sptr<IRemoteObject> callBack = iBundleEventCallback.AsObject();
    bool ret = bundleConnectAbility->SilentInstall(want, USERID, callBack);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: ConnectQueryAbilityInfo_0100
 * @tc.name: test QueryAbilityInfo
 * @tc.desc: 1.test QueryAbilityInfo
 */
HWTEST_F(BmsBundleDataMgrTest3, ConnectQueryAbilityInfo_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    ASSERT_NE(bundleConnectAbility, nullptr);
    Want want;
    int32_t flags = GET_ABILITY_INFO_WITH_APP_LINKING;
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string abilityName = ABILITY_NAME_TEST;
    std::string moduleName = MODULE_NAME1;
    AbilityInfo abilityInfo = MockAbilityInfo(bundleName, moduleName, abilityName);
    IBundleEventCallbackTest iBundleEventCallback;
    sptr<IRemoteObject> callBack = iBundleEventCallback.AsObject();
    bool abilityInfoResult = bundleConnectAbility->QueryAbilityInfo(want, flags, USERID, abilityInfo, callBack);
    EXPECT_EQ(abilityInfoResult, false);
}

/**
 * @tc.number: GetTargetAbilityInfo_0100
 * @tc.name: test GetTargetAbilityInfo
 * @tc.desc: 1.test obtain target capability information
 */
HWTEST_F(BmsBundleDataMgrTest3, GetTargetAbilityInfo_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    ASSERT_NE(bundleConnectAbility, nullptr);
    Want want;
    InnerBundleInfo innerBundleInfo;
    sptr<TargetAbilityInfo> targetAbilityInfo = nullptr;
    bundleConnectAbility->GetTargetAbilityInfo(want, USERID, innerBundleInfo, targetAbilityInfo);

    targetAbilityInfo = new(std::nothrow) TargetAbilityInfo();
    ASSERT_NE(targetAbilityInfo, nullptr);
    bundleConnectAbility->GetTargetAbilityInfo(want, USERID, innerBundleInfo, targetAbilityInfo);
    EXPECT_EQ(targetAbilityInfo->targetInfo.callingAppType, CALLING_TYPE_HARMONY_VALUE);

    std::string bundleName = BUNDLE_NAME_TEST;
    std::string abilityName = ABILITY_NAME_TEST;
    want.SetElementName(bundleName, abilityName);
    std::string moduleName = MODULE_NAME1;
    AbilityInfo abilityInfo = MockAbilityInfo(bundleName, moduleName, abilityName);
    std::string keyName = bundleName + "." + moduleName + "." + abilityName;
    innerBundleInfo.InsertAbilitiesInfo(keyName, abilityInfo);
    bundleConnectAbility->GetTargetAbilityInfo(want, USERID, innerBundleInfo, targetAbilityInfo);
    EXPECT_EQ(targetAbilityInfo->targetInfo.callingAppType, CALLING_TYPE_HARMONY_VALUE);
}

/**
 * @tc.number: GetPreloadFlag_0100
 * @tc.name: test GetPreloadFlag
 * @tc.desc: 1.test get preload flag
 */
HWTEST_F(BmsBundleDataMgrTest3, GetPreloadFlag_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    ASSERT_NE(bundleConnectAbility, nullptr);
    Want want;
    bool res = bundleConnectAbility->ProcessPreload(want);
    EXPECT_EQ(res, false);

    TargetAbilityInfo targetAbilityInfo;
    bool ret = bundleConnectAbility->ProcessPreloadCheck(targetAbilityInfo);
    EXPECT_EQ(ret, true);
    int32_t preloadFlag = bundleConnectAbility->GetPreloadFlag();
    EXPECT_NE(preloadFlag, BIT_ZERO_COMPATIBLE_VALUE);
}

/**
 * @tc.number: GetPreloadList_0100
 * @tc.name: test GetPreloadList
 * @tc.desc: 1.test get preload list
 */
HWTEST_F(BmsBundleDataMgrTest3, GetPreloadList_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    ASSERT_NE(bundleConnectAbility, nullptr);
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = MODULE_NAME1;
    sptr<TargetAbilityInfo> targetAbilityInfo = new(std::nothrow) TargetAbilityInfo();
    ASSERT_NE(targetAbilityInfo, nullptr);
    bool preloadList = bundleConnectAbility->GetPreloadList(bundleName, moduleName, USERID, targetAbilityInfo);
    EXPECT_EQ(preloadList, false);
}

/**
 * @tc.number: UpgradeCheck_0100
 * @tc.name: test UpgradeCheck
 * @tc.desc: 1.test upgrade check
 */
HWTEST_F(BmsBundleDataMgrTest3, UpgradeCheck_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    ASSERT_NE(bundleConnectAbility, nullptr);
    Want want;
    bundleConnectAbility->UpgradeAtomicService(want, USERID);
    TargetAbilityInfo targetAbilityInfo;
    sptr<FreeInstallParams> freeInstallParams = new(std::nothrow) FreeInstallParams();
    ASSERT_NE(freeInstallParams, nullptr);
    freeInstallParams->want = want;
    freeInstallParams->userId = USERID;
    bool ret = bundleConnectAbility->UpgradeCheck(targetAbilityInfo, want, *freeInstallParams, USERID);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: UpgradeInstall_0100
 * @tc.name: test UpgradeInstall
 * @tc.desc: 1.test upgrade install, return true
 */
HWTEST_F(BmsBundleDataMgrTest3, UpgradeInstall_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    ASSERT_NE(bundleConnectAbility, nullptr);
    Want want;
    bundleConnectAbility->UpgradeAtomicService(want, USERID);
    sptr<FreeInstallParams> freeInstallParams = new(std::nothrow) FreeInstallParams();
    ASSERT_NE(freeInstallParams, nullptr);
    TargetAbilityInfo targetAbilityInfo;
    freeInstallParams->want = want;
    freeInstallParams->userId = USERID;
    bool ret = bundleConnectAbility->UpgradeInstall(targetAbilityInfo, want, *freeInstallParams, USERID);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: SendRequestToServiceCenter_0100
 * @tc.name: test SendRequestToServiceCenter
 * @tc.desc: 1.test send request to the service center
 */
HWTEST_F(BmsBundleDataMgrTest3, SendRequestToServiceCenter_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    ASSERT_NE(bundleConnectAbility, nullptr);
    int32_t flag = 0;
    Want want;
    sptr<FreeInstallParams> freeInstallParams = new(std::nothrow) FreeInstallParams();
    ASSERT_NE(freeInstallParams, nullptr);
    freeInstallParams->want = want;
    freeInstallParams->userId = USERID;
    TargetAbilityInfo abilityInfo;
    bool ret = bundleConnectAbility->SendRequestToServiceCenter(flag, abilityInfo, want, USERID, *freeInstallParams);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: DeathRecipientSendCallback_0100
 * @tc.name: test DeathRecipientSendCallback
 * @tc.desc: 1.test DeathRecipientSendCallback
 */
HWTEST_F(BmsBundleDataMgrTest3, DeathRecipientSendCallback_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    ASSERT_NE(bundleConnectAbility, nullptr);
    sptr<FreeInstallParams> freeInstallParams = new(std::nothrow) FreeInstallParams();
    ASSERT_NE(freeInstallParams, nullptr);
    Want want;
    freeInstallParams->want = want;
    freeInstallParams->userId = USERID;
    int transactId = 0;
    std::string transactIdStr = std::to_string(transactId);
    bundleConnectAbility->SendCallBack(transactIdStr, *freeInstallParams);
    bundleConnectAbility->DeathRecipientSendCallback();
    bundleConnectAbility->DisconnectDelay();
    EXPECT_EQ(bundleConnectAbility->connectState_, ServiceCenterConnectState::DISCONNECTED);
}

/**
 * @tc.number: CheckIsModuleNeedUpdate_0100
 * @tc.name: test CheckIsModuleNeedUpdate
 * @tc.desc: 1.test check the module needs to be updated
 */
HWTEST_F(BmsBundleDataMgrTest3, CheckIsModuleNeedUpdate_0100, Function | MediumTest | Level1)
{
    auto bundleConnectAbility = std::make_shared<BundleConnectAbilityMgr>();
    ASSERT_NE(bundleConnectAbility, nullptr);
    int32_t flags = 0;
    AbilityInfo abilityInfo;
    InnerBundleInfo innerBundleInfo;
    Want want;
    want.SetElementName("", BUNDLE_NAME_TEST, ABILITY_NAME_TEST, MODULE_NAME_TEST);
    bool ret = bundleConnectAbility->IsObtainAbilityInfo(want, flags, USERID, abilityInfo, nullptr, innerBundleInfo);
    EXPECT_EQ(ret, false);

    IBundleEventCallbackTest iBundleEventCallback;
    sptr<IRemoteObject> callBack = iBundleEventCallback.AsObject();
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string abilityName = ABILITY_NAME_TEST;
    want.SetElementName(bundleName, abilityName);
    std::string moduleName = MODULE_NAME1;
    AbilityInfo abilityInfoExt = MockAbilityInfo(bundleName, moduleName, abilityName);
    std::string keyName = bundleName + "." + moduleName + "." + abilityName;
    innerBundleInfo.InsertAbilitiesInfo(keyName, abilityInfoExt);
    bool isModuleNeedUpdate = bundleConnectAbility->CheckIsModuleNeedUpdate(innerBundleInfo, want, USERID, callBack);
    EXPECT_EQ(isModuleNeedUpdate, false);
}

/**
 * @tc.number: BundleMgrHostImplAddDesktopShortcutInfo_0001
 * @tc.name: BundleMgrHostImplAddDesktopShortcutInfo
 * @tc.desc: test AddDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId)
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleMgrHostImplAddDesktopShortcutInfo_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();

    ErrCode ret = localBundleMgrHostImpl->AddDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_NE(ret, ERR_OK);

    ClearDataMgr();
    ret = bundleMgrHostImpl_->AddDesktopShortcutInfo(shortcutInfo, USERID);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BundleMgrHostImplAddDesktopShortcutInfo_0002
 * @tc.name: BundleMgrHostImplAddDesktopShortcutInfo
 * @tc.desc: test AddDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId)
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleMgrHostImplAddDesktopShortcutInfo_0002, Function | MediumTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();

    ErrCode ret = localBundleMgrHostImpl->AddDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_NE(ret, ERR_OK);

    ClearDataMgr();
    ret = localBundleMgrHostImpl->AddDesktopShortcutInfo(shortcutInfo, USERID);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BundleMgrHostImplDeleteDesktopShortcutInfo_0001
 * @tc.name: BundleMgrHostImplDeleteDesktopShortcutInfo
 * @tc.desc: test DeleteDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId)
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleMgrHostImplDeleteDesktopShortcutInfo_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();

    ErrCode ret = localBundleMgrHostImpl->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_NE(ret, ERR_OK);

    ClearDataMgr();
    ret = localBundleMgrHostImpl->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BundleMgrHostImplDeleteDesktopShortcutInfo_0002
 * @tc.name: BundleMgrHostImplDeleteDesktopShortcutInfo
 * @tc.desc: test DeleteDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId)
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleMgrHostImplDeleteDesktopShortcutInfo_0002, Function | MediumTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();

    ErrCode ret = localBundleMgrHostImpl->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_NE(ret, ERR_OK);

    ClearDataMgr();
    ret = localBundleMgrHostImpl->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BundleMgrHostImplGetAllDesktopShortcutInfo_0001
 * @tc.name: BundleMgrHostImplGetAllDesktopShortcutInfo
 * @tc.desc: test GetAllDesktopShortcutInfo(int32_t userId, std::vector<ShortcutInfo> &shortcutInfos)
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleMgrHostImplGetAllDesktopShortcutInfo_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> lcalBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(lcalBundleMgrHostImpl, nullptr);
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();
    std::vector<ShortcutInfo> vecShortcutInfo;
    vecShortcutInfo.push_back(shortcutInfo);

    ErrCode ret = lcalBundleMgrHostImpl->GetAllDesktopShortcutInfo(USERID, vecShortcutInfo);
    EXPECT_NE(ret, ERR_OK);

    ClearDataMgr();
    ret = lcalBundleMgrHostImpl->GetAllDesktopShortcutInfo(USERID, vecShortcutInfo);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BundleMgrHostImplGetAllDesktopShortcutInfo_0002
 * @tc.name: BundleMgrHostImplGetAllDesktopShortcutInfo
 * @tc.desc: test GetAllDesktopShortcutInfo(int32_t userId, std::vector<ShortcutInfo> &shortcutInfos)
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleMgrHostImplGetAllDesktopShortcutInfo_0002, Function | MediumTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> localBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(localBundleMgrHostImpl, nullptr);
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();
    std::vector<ShortcutInfo> vecShortcutInfo;
    vecShortcutInfo.push_back(shortcutInfo);

    ErrCode ret = localBundleMgrHostImpl->GetAllDesktopShortcutInfo(USERID, vecShortcutInfo);
    EXPECT_NE(ret, ERR_OK);

    ClearDataMgr();
    ret = localBundleMgrHostImpl->GetAllDesktopShortcutInfo(USERID, vecShortcutInfo);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BundleDataMgrAddDesktopShortcutInfo_0001
 * @tc.name: BundleDataMgrAddDesktopShortcutInfo
 * ShortcutInfo
 * @tc.desc: test AddDesktopShortcutInfo
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleDataMgrAddDesktopShortcutInfo_0001, Function | SmallTest | Level1)
{
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();
    std::shared_ptr<BundleDataMgr> localBundleDataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(localBundleDataMgr, nullptr);
    int32_t userID = -1;
    ErrCode ret = localBundleDataMgr->AddDesktopShortcutInfo(shortcutInfo, userID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    userID = -1;
    shortcutInfo.id = "userID";
    ret = localBundleDataMgr->AddDesktopShortcutInfo(shortcutInfo, userID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: BundleDataMgrAddDesktopShortcutInfo_0002
 * @tc.name: BundleDataMgrAddDesktopShortcutInfo
 * ShortcutInfo
 * @tc.desc: test AddDesktopShortcutInfo
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleDataMgrAddDesktopShortcutInfo_0002, Function | MediumTest | Level1)
{
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();
    std::shared_ptr<BundleDataMgr> localBundleDataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(localBundleDataMgr, nullptr);
    int32_t userID = -1;
    ErrCode ret = localBundleDataMgr->AddDesktopShortcutInfo(shortcutInfo, userID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    shortcutInfo.id = "userID";
    ret = localBundleDataMgr->AddDesktopShortcutInfo(shortcutInfo, userID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: BundleDataMgrDeleteDesktopShortcutInfo_0001
 * @tc.name: BundleDataMgrDeleteDesktopShortcutInfo
 * ShortcutInfo
 * @tc.desc: test DeleteDesktopShortcutInfo
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleDataMgrDeleteDesktopShortcutInfo_0001, Function | SmallTest | Level1)
{
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();
    std::shared_ptr<BundleDataMgr> localBundleDataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(localBundleDataMgr, nullptr);

    ErrCode ret = localBundleDataMgr->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: BundleDataMgrDeleteDesktopShortcutInfo_0002
 * @tc.name: BundleDataMgrDeleteDesktopShortcutInfo
 * ShortcutInfo
 * @tc.desc: test DeleteDesktopShortcutInfo
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleDataMgrDeleteDesktopShortcutInfo_0002, Function | MediumTest | Level1)
{
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();
    std::shared_ptr<BundleDataMgr> localBundleDataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(localBundleDataMgr, nullptr);

    ErrCode ret = localBundleDataMgr->DeleteDesktopShortcutInfo(shortcutInfo, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: Marshalling_0100
 * Function: test Marshalling of ProxyData
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleDataMgrTest3, Marshalling_0100, Function | SmallTest | Level0)
{
    ProxyData proxyData;
    Parcel parcel;
    std::string testString = "testString";
    proxyData.uri = testString;
    proxyData.requiredReadPermission = testString;
    proxyData.requiredWritePermission = testString;

    bool result = proxyData.Marshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: Marshalling_0200
 * Function: test Marshalling of RouterItem
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleDataMgrTest3, Marshalling_0200, Function | SmallTest | Level0)
{
    RouterItem routerItem;
    Parcel parcel;
    std::string testString = "testString";
    routerItem.name = testString;
    routerItem.pageSourceFile = testString;
    routerItem.buildFunction = testString;
    routerItem.data.emplace(testString, testString);
    routerItem.customData = testString;
    routerItem.ohmurl = testString;
    routerItem.bundleName = testString;
    routerItem.moduleName = testString;

    bool result = routerItem.Marshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: Marshalling_0300
 * Function: test Marshalling of RecoverableApplicationInfo
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleDataMgrTest3, Marshalling_0300, Function | SmallTest | Level0)
{
    RecoverableApplicationInfo recoverableApplicationInfo;
    Parcel parcel;
    recoverableApplicationInfo.bundleName = BUNDLE_NAME_TEST;
    recoverableApplicationInfo.moduleName = MODULE_NAME_TEST;
    recoverableApplicationInfo.codePaths.push_back(LIB_PATH);

    bool result = recoverableApplicationInfo.Marshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: Unmarshalling_0100
 * Function: test Unmarshalling of DisposedRule
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleDataMgrTest3, Unmarshalling_0100, Function | SmallTest | Level0)
{
    DisposedRule disposedRule;
    Parcel parcel;

    auto result = disposedRule.Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.number: Unmarshalling_0200
 * Function: test Unmarshalling of RecoverableApplicationInfo
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleDataMgrTest3, Unmarshalling_0200, Function | SmallTest | Level0)
{
    RecoverableApplicationInfo recoverableApplicationInfo;
    Parcel parcel;

    auto result = recoverableApplicationInfo.Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.number: ReadFromParcel_0100
 * Function: test ReadFromParcel of DisposedRule
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleDataMgrTest3, ReadFromParcel_0100, Function | SmallTest | Level0)
{
    DisposedRule disposedRule;
    Parcel parcel;
    Want want;
    want.SetElementName("", BUNDLE_NAME_TEST, ABILITY_NAME_TEST, MODULE_NAME_TEST);
    parcel.WriteParcelable(&want);
    parcel.WriteInt32(1);
    parcel.WriteInt32(1);
    parcel.WriteInt32(1);
    parcel.WriteInt32(1);
    std::string element = "testElement";
    parcel.WriteString16(Str8ToStr16(element));

    bool result = disposedRule.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: ReadFromParcel_0200
 * Function: test ReadFromParcel of DisposedRule
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundleDataMgrTest3, ReadFromParcel_0200, Function | SmallTest | Level0)
{
    RecoverableApplicationInfo recoverableApplicationInfo;
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(BUNDLE_NAME_TEST));
    parcel.WriteString16(Str8ToStr16(MODULE_NAME_TEST));
    parcel.WriteInt32(1);
    parcel.WriteInt32(1);
    parcel.WriteBool(true);
    parcel.WriteInt32(1);
    parcel.WriteString16(Str8ToStr16(LIB_PATH));

    bool result = recoverableApplicationInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: BmsExtensionClientAddResourceInfoByBundleName_0100
 * @tc.name: AddResourceInfoByBundleName
 * @tc.desc: test AddResourceInfoByBundleName of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientAddResourceInfoByBundleName_0100, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::string bundleName = "bundleName";
    int32_t userId = 100;
    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    ErrCode ret = bmsExtensionClient->AddResourceInfoByBundleName(bundleName, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsExtensionClientAddResourceInfoByBundleName_0200
 * @tc.name: AddResourceInfoByBundleName
 * @tc.desc: test AddResourceInfoByBundleName of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientAddResourceInfoByBundleName_0200, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::string bundleName = "bundleName";
    int32_t userId = 100;
    ErrCode ret = bmsExtensionClient->AddResourceInfoByBundleName(bundleName, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
}

/**
 * @tc.number: BmsExtensionClientAddResourceInfoByAbility_0100
 * @tc.name: AddResourceInfoByAbility
 * @tc.desc: test AddResourceInfoByAbility of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientAddResourceInfoByAbility_0100, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::string bundleName = "bundleName";
    std::string moduleName = "moduleName";
    std::string abilityName = "abilityName";
    int32_t userId = 100;
    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    ErrCode res = bmsExtensionClient->AddResourceInfoByAbility(bundleName, moduleName, abilityName, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsExtensionClientAddResourceInfoByAbility_0200
 * @tc.name: AddResourceInfoByAbility
 * @tc.desc: test AddResourceInfoByAbility of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientAddResourceInfoByAbility_0200, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::string bundleName = "bundleName";
    std::string moduleName = "moduleName";
    std::string abilityName = "abilityName";
    int32_t userId = 100;
    ErrCode res = bmsExtensionClient->AddResourceInfoByAbility(bundleName, moduleName, abilityName, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
}


/**
 * @tc.number: BmsExtensionClientDeleteResourceInfo_0100
 * @tc.name: DeleteResourceInfo
 * @tc.desc: test DeleteResourceInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientDeleteResourceInfo_0100, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::string key = "abilityName";
    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    ErrCode res = bmsExtensionClient->DeleteResourceInfo(key);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsExtensionClientDeleteResourceInfo_0200
 * @tc.name: DeleteResourceInfo
 * @tc.desc: test DeleteResourceInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientDeleteResourceInfo_0200, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::string key = "abilityName";
    ErrCode res = bmsExtensionClient->DeleteResourceInfo(key);
    if (CheckBmsExtensionProfile()) {
        EXPECT_EQ(res, ERR_OK);
    } else {
        EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
    }
}

/**
 * @tc.number: BmsExtensionClientOptimizeDisposedPredicates_0100
 * @tc.name: OptimizeDisposedPredicates
 * @tc.desc: test OptimizeDisposedPredicates of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientOptimizeDisposedPredicates_0100, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::string callingName = "callingName";
    std::string appId = "appId";
    int32_t userId = 100;
    int32_t appIndex = 0;
    NativeRdb::AbsRdbPredicates absRdbPredicates("TableName");
    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    ErrCode res = bmsExtensionClient->OptimizeDisposedPredicates(
        callingName, appId, userId, appIndex, absRdbPredicates);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsExtensionClientOptimizeDisposedPredicates_0200
 * @tc.name: OptimizeDisposedPredicates
 * @tc.desc: test OptimizeDisposedPredicates of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientOptimizeDisposedPredicates_0200, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::string callingName = "callingName";
    std::string appId = "appId";
    int32_t userId = 100;
    int32_t appIndex = 0;
    NativeRdb::AbsRdbPredicates absRdbPredicates("TableName");
    ErrCode res = bmsExtensionClient->OptimizeDisposedPredicates(
        callingName, appId, userId, appIndex, absRdbPredicates);
    if (CheckBmsExtensionProfile()) {
        EXPECT_EQ(res, ERR_OK);
    } else {
        EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
    }
}

/**
 * @tc.number: BmsExtensionClientGetBundleInfos_0100
 * @tc.name: test BundleDataMgr::GetBundleInfos
 * @tc.desc: test GetBundleInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientGetBundleInfos_0100, Function | MediumTest | Level1)
{
    int32_t flags = 0;
    int32_t userId = Constants::ALL_USERID;
    std::vector<BundleInfo> bundleInfos;
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    ErrCode ret = bmsExtensionClient->GetBundleInfos(flags, bundleInfos, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsExtensionClientGetBundleInfos_0200
 * @tc.name: test BundleDataMgr::GetBundleInfos
 * @tc.desc: test GetBundleInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientGetBundleInfos_0200, Function | MediumTest | Level1)
{
    int32_t flags = 0;
    int32_t userId = Constants::ALL_USERID;
    std::vector<BundleInfo> bundleInfos;
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    ErrCode ret = bmsExtensionClient->GetBundleInfos(flags, bundleInfos, userId);
    if (CheckBmsExtensionProfile()) {
        EXPECT_EQ(ret, ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY);
    } else {
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    }
}

/**
 * @tc.number: BmsExtensionClientGetBundleInfo_0100
 * @tc.name: test BundleDataMgr::GetBundleInfo
 * @tc.desc: test GetBundleInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientGetBundleInfo_0100, Function | MediumTest | Level1)
{
    std::string bundleName;
    int32_t flags = 0;
    int32_t userId = Constants::ALL_USERID;
    BundleInfo bundleInfo;
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    ErrCode ret = bmsExtensionClient->GetBundleInfo(bundleName, flags, bundleInfo, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsExtensionClientGetBundleInfo_0200
 * @tc.name: test BundleDataMgr::GetBundleInfo
 * @tc.desc: test GetBundleInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientGetBundleInfo_0200, Function | MediumTest | Level1)
{
    std::string bundleName;
    int32_t flags = 0;
    int32_t userId = Constants::ALL_USERID;
    BundleInfo bundleInfo;
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    bool flag = false;
    if (bundleMgrService_->dataMgr_ == nullptr) {
        ResetDataMgr();
        flag = true;
    }
    ErrCode ret = bmsExtensionClient->GetBundleInfo(bundleName, flags, bundleInfo, userId);
    if (flag) {
        ClearDataMgr();
    }
    if (CheckBmsExtensionProfile()) {
        EXPECT_EQ(ret, ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY);
    } else {
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    }
}

/**
 * @tc.number: BmsExtensionClientGetUidByBundleName_0100
 * @tc.name: test BmsExtensionClient::GetUidByBundleName
 * @tc.desc: test GetUidByBundleName of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientGetUidByBundleName_0100, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    int32_t userId = USERID;
    int32_t uid = TEST_UID;
    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    ErrCode ret = bmsExtensionClient->GetUidByBundleName(BUNDLE_NAME_TEST, userId, uid);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsExtensionClientQueryAbilityInfos_0100
 * @tc.name: QueryAbilityInfos
 * @tc.desc: test QueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientQueryAbilityInfos_0100, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    Want want;
    want.SetElementName("", "com.ohos.settings", "", "");
    int32_t flags = 0;
    int32_t userId = Constants::ALL_USERID;
    std::vector<AbilityInfo> abilityInfos;
    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    bool flag = false;
    if (bundleMgrService_->dataMgr_ == nullptr) {
        ResetDataMgr();
        flag = true;
    }
    ErrCode res = bmsExtensionClient->QueryAbilityInfos(want, flags, userId, abilityInfos);
    if (flag) {
        ClearDataMgr();
    }
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsExtensionClientQueryAbilityInfos_0200
 * @tc.name: QueryAbilityInfos
 * @tc.desc: test QueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientQueryAbilityInfos_0200, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    Want want;
    want.SetElementName("", "", "", "");
    int32_t flags = 0;
    int32_t userId = Constants::ALL_USERID;
    std::vector<AbilityInfo> abilityInfos;
    bool flag = false;
    if (bundleMgrService_->dataMgr_ == nullptr) {
        ResetDataMgr();
        flag = true;
    }
    ErrCode res = bmsExtensionClient->QueryAbilityInfos(want, flags, userId, abilityInfos);
    if (flag) {
        ClearDataMgr();
    }
    if (CheckBmsExtensionProfile()) {
        EXPECT_EQ(res, ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY);
    } else {
        EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    }
}

/**
 * @tc.number: BmsExtensionClientQueryAbilityInfos_0300
 * @tc.name: QueryAbilityInfos
 * @tc.desc: test QueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientQueryAbilityInfos_0300, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    Want want;
    want.SetElementName("notEmpty", "", "", "");
    int32_t flags = 0;
    int32_t userId = Constants::ALL_USERID;
    std::vector<AbilityInfo> abilityInfos;
    bool flag = false;
    if (bundleMgrService_->dataMgr_ == nullptr) {
        ResetDataMgr();
        flag = true;
    }
    ErrCode res = bmsExtensionClient->QueryAbilityInfos(want, flags, userId, abilityInfos);
    if (flag) {
        ClearDataMgr();
    }
    if (CheckBmsExtensionProfile()) {
        EXPECT_EQ(res, ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY);
    } else {
        EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    }
}

/**
 * @tc.number: BmsExtensionClientQueryAbilityInfos_0400
 * @tc.name: QueryAbilityInfos
 * @tc.desc: test QueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientQueryAbilityInfos_0400, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    Want want;
    want.SetElementName("notEmpty", "", "", "");
    int32_t flags = 0;
    int32_t userId = Constants::ALL_USERID;
    std::vector<AbilityInfo> abilityInfos;
    bool flag = false;
    if (bundleMgrService_->dataMgr_ == nullptr) {
        ResetDataMgr();
        flag = true;
    }
    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    ErrCode res = bmsExtensionClient->QueryAbilityInfos(want, flags, userId, abilityInfos);
    if (flag) {
        ClearDataMgr();
    }
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsExtensionClientBatchGetBundleInfo_0100
 * @tc.name: BatchGetBundleInfo
 * @tc.desc: test BatchGetBundleInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientBatchGetBundleInfo_0100, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::vector<std::string> bundleNames;
    int32_t flags = 0;
    std::vector<BundleInfo> bundleInfos;
    int32_t userId = -100;
    bool flag = false;
    if (bundleMgrService_->dataMgr_ == nullptr) {
        ResetDataMgr();
        flag = true;
    }
    ErrCode res = bmsExtensionClient->BatchGetBundleInfo(bundleNames, flags, bundleInfos, userId);
    if (flag) {
        ClearDataMgr();
    }
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: BmsExtensionClientBatchGetBundleInfo_0200
 * @tc.name: BatchGetBundleInfo
 * @tc.desc: test BatchGetBundleInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientBatchGetBundleInfo_0200, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::vector<std::string> bundleNames;
    int32_t flags = 0;
    std::vector<BundleInfo> bundleInfos;
    int32_t userId = Constants::ALL_USERID;
    bool flag = false;
    if (bundleMgrService_->dataMgr_ == nullptr) {
        ResetDataMgr();
        flag = true;
    }
    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    ErrCode res = bmsExtensionClient->BatchGetBundleInfo(bundleNames, flags, bundleInfos, userId);
    if (flag) {
        ClearDataMgr();
    }
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsExtensionClientBatchGetBundleInfo_0300
 * @tc.name: BatchGetBundleInfo
 * @tc.desc: test BatchGetBundleInfo of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientBatchGetBundleInfo_0300, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::vector<std::string> bundleNames;
    int32_t flags = 0;
    std::vector<BundleInfo> bundleInfos;
    int32_t userId = Constants::ALL_USERID;
    bool flag = false;
    if (bundleMgrService_->dataMgr_ == nullptr) {
        ResetDataMgr();
        flag = true;
    }
    ErrCode res = bmsExtensionClient->BatchGetBundleInfo(bundleNames, flags, bundleInfos, userId);
    if (flag) {
        ClearDataMgr();
    }
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: BmsExtensionClientBatchQueryAbilityInfos_0100
 * @tc.name: BatchQueryAbilityInfos
 * @tc.desc: test BatchQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientBatchQueryAbilityInfos_0100, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::vector<Want> wants;
    Want want;
    wants.push_back(want);
    int32_t flags = 1;
    int32_t userId = Constants::ALL_USERID;
    std::vector<AbilityInfo> abilityInfos;
    bool isNewVersion = true;
    bool flag = false;
    if (bundleMgrService_->dataMgr_ == nullptr) {
        ResetDataMgr();
        flag = true;
    }
    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    ErrCode res = bmsExtensionClient->BatchQueryAbilityInfos(wants, flags, userId, abilityInfos, isNewVersion);
    if (flag) {
        ClearDataMgr();
    }
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsExtensionClientBatchQueryAbilityInfos_0200
 * @tc.name: BatchQueryAbilityInfos
 * @tc.desc: test BatchQueryAbilityInfos of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientBatchQueryAbilityInfos_0200, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    std::vector<Want> wants;
    Want want;
    wants.push_back(want);
    int32_t flags = 1;
    int32_t userId = Constants::ALL_USERID;
    std::vector<AbilityInfo> abilityInfos;
    bool isNewVersion = true;
    bool flag = false;
    if (bundleMgrService_->dataMgr_ == nullptr) {
        ResetDataMgr();
        flag = true;
    }
    ErrCode res = bmsExtensionClient->BatchQueryAbilityInfos(wants, flags, userId, abilityInfos, isNewVersion);
    if (flag) {
        ClearDataMgr();
    }
    if (CheckBmsExtensionProfile()) {
        EXPECT_EQ(res, ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY);
    } else {
        EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    }
}

/**
 * @tc.number: BmsExtensionClientQueryLauncherAbility_0100
 * @tc.name: QueryLauncherAbility
 * @tc.desc: test QueryLauncherAbility of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest3, BmsExtensionClientQueryLauncherAbility_0100, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ASSERT_NE(bmsExtensionClient, nullptr);
    Want want;
    int32_t userId = Constants::ALL_USERID;
    std::vector<AbilityInfo> abilityInfos;
    bool flag = false;
    if (bundleMgrService_->dataMgr_ == nullptr) {
        ResetDataMgr();
        flag = true;
    }
    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    ErrCode res = bmsExtensionClient->QueryLauncherAbility(want, userId, abilityInfos);
    if (flag) {
        ClearDataMgr();
    }
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: BundleMgrHostHandleAddDesktopShortcutInfo_0001
 * @tc.name: BundleMgrHostHandleAddDesktopShortcutInfo_0001
 * ShortcutInfo
 * @tc.desc: test BundleMgrHostHandleAddDesktopShortcutInfo(MessageParcel &data, MessageParcel &reply)
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleMgrHostHandleAddDesktopShortcutInfo_0001, Function | SmallTest | Level1)
{
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();
    std::shared_ptr<BundleMgrHost> localBundleMgrHost = std::make_shared<BundleMgrHost>();
    ASSERT_NE(localBundleMgrHost, nullptr);

    MessageParcel data;
    MessageParcel reply;

    auto ret = localBundleMgrHost->HandleAddDesktopShortcutInfo(data, reply);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: BundleMgrHostHandleAddDesktopShortcutInfo_0002
 * @tc.name: BundleMgrHostHandleAddDesktopShortcutInfo_0002
 * ShortcutInfo
 * @tc.desc: test BundleMgrHostHandleAddDesktopShortcutInfo(MessageParcel &data, MessageParcel &reply)
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleMgrHostHandleAddDesktopShortcutInfo_0002, Function | MediumTest | Level1)
{
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();
    std::shared_ptr<BundleMgrHost> localBundleMgrHost = std::make_shared<BundleMgrHost>();
    ASSERT_NE(localBundleMgrHost, nullptr);

    MessageParcel data;
    MessageParcel reply;

    auto ret = localBundleMgrHost->HandleAddDesktopShortcutInfo(data, reply);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: BundleMgrHostHandleDeleteDesktopShortcutInfo_0001
 * @tc.name: BundleMgrHostHandleDeleteDesktopShortcutInfo_0001
 * ShortcutInfo
 * @tc.desc: test HandleDeleteDesktopShortcutInfo(MessageParcel &data, MessageParcel &reply)
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleMgrHostHandleDeleteDesktopShortcutInfo_0001, Function | SmallTest | Level1)
{
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();
    std::shared_ptr<BundleMgrHost> localBundleMgrHost = std::make_shared<BundleMgrHost>();
    ASSERT_NE(localBundleMgrHost, nullptr);

    MessageParcel data;
    MessageParcel reply;

    auto ret = localBundleMgrHost->HandleDeleteDesktopShortcutInfo(data, reply);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: BundleMgrHostHandleDeleteDesktopShortcutInfo_0002
 * @tc.name: BundleMgrHostHandleDeleteDesktopShortcutInfo_0002
 * ShortcutInfo
 * @tc.desc: test HandleDeleteDesktopShortcutInfo(MessageParcel &data, MessageParcel &reply)
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleMgrHostHandleDeleteDesktopShortcutInfo_0002, Function | MediumTest | Level1)
{
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();
    std::shared_ptr<BundleMgrHost> localBundleMgrHost = std::make_shared<BundleMgrHost>();
    ASSERT_NE(localBundleMgrHost, nullptr);

    MessageParcel data;
    MessageParcel reply;

    auto ret = localBundleMgrHost->HandleDeleteDesktopShortcutInfo(data, reply);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: BundleMgrHostHandleGetAllDesktopShortcutInfo_0001
 * @tc.name: BundleMgrHostHandleGetAllDesktopShortcutInfo_0001
 * ShortcutInfo
 * @tc.desc: test HandleGetAllDesktopShortcutInfo(MessageParcel &data, MessageParcel &reply)
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleMgrHostHandleGetAllDesktopShortcutInfo_0001, Function | SmallTest | Level1)
{
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();
    std::shared_ptr<BundleMgrHost> localBundleMgrHost = std::make_shared<BundleMgrHost>();
    ASSERT_NE(localBundleMgrHost, nullptr);

    MessageParcel data;
    MessageParcel reply;

    auto ret = localBundleMgrHost->HandleGetAllDesktopShortcutInfo(data, reply);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BundleMgrHostHandleGetAllDesktopShortcutInfo_0002
 * @tc.name: BundleMgrHostHandleGetAllDesktopShortcutInfo_0002
 * ShortcutInfo
 * @tc.desc: test HandleGetAllDesktopShortcutInfo(MessageParcel &data, MessageParcel &reply)
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleMgrHostHandleGetAllDesktopShortcutInfo_0002, Function | MediumTest | Level1)
{
    ShortcutInfo shortcutInfo = BmsBundleDataMgrTest3::InitShortcutInfo();
    std::shared_ptr<BundleMgrHost> localBundleMgrHost = std::make_shared<BundleMgrHost>();
    ASSERT_NE(localBundleMgrHost, nullptr);

    MessageParcel data;
    MessageParcel reply;

    auto ret = localBundleMgrHost->HandleGetAllDesktopShortcutInfo(data, reply);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: NotifySandboxAppStatus_0100
 * @tc.name: test NotifySandboxAppStatus
 * @tc.desc: 1.test NotifySandboxAppStatus
 */
HWTEST_F(BmsBundleDataMgrTest3, NotifySandboxAppStatus_0100, Function | MediumTest | Level1)
{
    InnerBundleInfo info;
    int32_t uid = 0;
    int32_t userId = 100;
    SandboxInstallType type = (SandboxInstallType)3;
    ASSERT_NE(commonEventMgr_, nullptr);
    ErrCode ret = commonEventMgr_->NotifySandboxAppStatus(info, uid, userId, type);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_UNKNOWN_INSTALL_TYPE);
}

/**
 * @tc.number: GetCommonEventData_0100
 * @tc.name: test GetCommonEventData
 * @tc.desc: 1.test GetCommonEventData
 */
HWTEST_F(BmsBundleDataMgrTest3, GetCommonEventData_0100, Function | MediumTest | Level1)
{
    std::string bundleName;
    bool isEnableDynamicIcon = false;
    ASSERT_NE(commonEventMgr_, nullptr);
    commonEventMgr_->NotifyDynamicIconEvent(bundleName, isEnableDynamicIcon, -2, 0);

    commonEventMgr_->commonEventMap_.clear();
    NotifyType type = (NotifyType)14;
    std::string ret = commonEventMgr_->GetCommonEventData(type);
    EXPECT_EQ(ret, EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
}

/**
 * @tc.number: GetBundleInfosForContinuation_0100
 * @tc.name: test GetBundleInfosForContinuation
 * @tc.desc: 1.system run normally
 *           2.check GetBundleInfosForContinuation success
 */
HWTEST_F(BmsBundleDataMgrTest3, GetBundleInfosForContinuation_0100, Function | SmallTest | Level1)
{
    ResetDataMgr();
    std::vector<BundleInfo> bundleInfos;
    BundleInfo bundleInfo;
    AbilityInfo abilityInfo;
    abilityInfo.continuable = false;
    bundleInfo.abilityInfos.push_back(abilityInfo);
    bundleInfos.push_back(bundleInfo);
    ClearDataMgr();

    ResetDataMgr();
    GetBundleDataMgr()->GetBundleInfosForContinuation(bundleInfos);
    EXPECT_TRUE(bundleInfos.empty());
}

/**
 * @tc.number: GetContinueBundleNames_0100
 * @tc.name: test GetContinueBundleNames
 * @tc.desc: 1.system run normally
 *           2.check GetContinueBundleNames success
 */
HWTEST_F(BmsBundleDataMgrTest3, GetContinueBundleNames_0100, Function | SmallTest | Level1)
{
    ResetDataMgr();
    std::vector<std::string> bundleNames;
    std::string continueBundleName;
    int32_t userId = 10;

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    auto ret = dataMgr->GetContinueBundleNames(continueBundleName, bundleNames, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: GetContinueBundleNames_0200
 * @tc.name: test GetContinueBundleNames
 * @tc.desc: 1.system run normally
 *           2.check GetContinueBundleNames success
 */
HWTEST_F(BmsBundleDataMgrTest3, GetContinueBundleNames_0200, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleNames;
    std::string continueBundleName;
    int32_t userId = -4;
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    auto ret = dataMgr->GetContinueBundleNames(continueBundleName, bundleNames, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: GetContinueBundleNames_0300
 * @tc.name: test GetContinueBundleNames
 * @tc.desc: 1.system run normally
 *           2.check GetContinueBundleNames success
 */
HWTEST_F(BmsBundleDataMgrTest3, GetContinueBundleNames_0300, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleNames;
    std::string continueBundleName{ "com.example.test" };
    int32_t userId = -4;
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    auto ret = dataMgr->GetContinueBundleNames(continueBundleName, bundleNames, userId);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetContinueBundleNames_0400
 * @tc.name: test GetContinueBundleNames
 * @tc.desc: 1.system run normally
 *           2.check GetContinueBundleNames success
 */
HWTEST_F(BmsBundleDataMgrTest3, GetContinueBundleNames_0400, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleNames;
    std::string continueBundleName;
    int32_t userId = 100;
    ASSERT_NE(bundleMgrHostImpl_, nullptr);
    auto ret = bundleMgrHostImpl_->GetContinueBundleNames(continueBundleName, bundleNames, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: GetContinueBundleNames_0500
 * @tc.name: test GetContinueBundleNames
 * @tc.desc: 1.system run normally
 *           2.check GetContinueBundleNames success
 */
HWTEST_F(BmsBundleDataMgrTest3, GetContinueBundleNames_0500, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleNames;
    std::string continueBundleName{ "com.example.test" };
    int32_t userId = -4;
    ASSERT_NE(bundleMgrHostImpl_, nullptr);
    auto ret = bundleMgrHostImpl_->GetContinueBundleNames(continueBundleName, bundleNames, userId);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetContinueBundleNames_0600
 * @tc.name: test GetContinueBundleNames
 * @tc.desc: 1.system run normally
 *           2.check GetContinueBundleNames success
 */
HWTEST_F(BmsBundleDataMgrTest3, GetContinueBundleNames_0600, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::vector<std::string> bundleNames;
    std::string continueBundleName;
    int32_t userId = 100;
    auto ret = bundleMgrProxy->GetContinueBundleNames(continueBundleName, bundleNames, userId);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: GetContinueBundleNames_0700
 * @tc.name: test GetContinueBundleNames
 * @tc.desc: 1.system run normally
 *           2.check GetContinueBundleNames success
 */
HWTEST_F(BmsBundleDataMgrTest3, GetContinueBundleNames_0700, Function | SmallTest | Level1)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);

    std::vector<std::string> bundleNames;
    std::string continueBundleName{ "com.example.test" };
    int32_t userId = -4;
    auto ret = bundleMgrProxy->GetContinueBundleNames(continueBundleName, bundleNames, userId);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: UpdateIsPreInstallApp_0001
 * @tc.name: UpdateIsPreInstallApp
 * @tc.desc: test UpdateIsPreInstallApp
 */
HWTEST_F(BmsBundleDataMgrTest3, UpdateIsPreInstallApp_0001, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto bundleDataMgr = GetBundleDataMgr();
    EXPECT_NE(bundleDataMgr, nullptr);
    if (bundleDataMgr != nullptr) {
        InnerBundleInfo innerBundleInfo;
        innerBundleInfo.SetIsPreInstallApp(true);
        std::string bundleName = "";
        bundleDataMgr->bundleInfos_[bundleName] = innerBundleInfo;
        bundleDataMgr->UpdateIsPreInstallApp(bundleName, false);
        EXPECT_TRUE(bundleDataMgr->bundleInfos_[bundleName].IsPreInstallApp());

        bundleName = "com.test.bundle";
        bundleDataMgr->bundleInfos_[bundleName] = innerBundleInfo;
        bundleDataMgr->UpdateIsPreInstallApp(bundleName, false);
        EXPECT_FALSE(bundleDataMgr->bundleInfos_[bundleName].IsPreInstallApp());

        bundleDataMgr->UpdateIsPreInstallApp(bundleName, false);
        EXPECT_FALSE(bundleDataMgr->bundleInfos_[bundleName].IsPreInstallApp());
        bundleDataMgr->bundleInfos_.clear();
    }
}

/**
 * @tc.number: BundleDataMgr_0100
 * @tc.name: BatchQueryAbilityInfos
 * @tc.desc: test BatchQueryAbilityInfos the BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleDataMgr_0100, Function | SmallTest | Level1)
{
    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);

    std::vector<Want> wants;
    Want want;
    std::vector<AbilityInfo> abilityInfos;
    bundleDataMgr->ImplicitQueryCloneAbilityInfos(want, 0, 100, abilityInfos);

    want.SetAction("test");
    bundleDataMgr->bundleInfos_.clear();
    bundleDataMgr->ImplicitQueryCloneAbilityInfos(want, 0, 100, abilityInfos);

    ErrCode ret = bundleDataMgr->BatchQueryAbilityInfos(wants, 0, -1, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: BundleDataMgr_0200
 * @tc.name: GetCloneAppIndexesNoLock
 * @tc.desc: test GetCloneAppIndexesNoLock the BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleDataMgr_0200, Function | SmallTest | Level1)
{
    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);

    std::string bundleName;
    std::vector<int32_t> ret = bundleDataMgr->GetCloneAppIndexesNoLock(bundleName, -2);
    EXPECT_EQ(ret.size(), 0);
}

/**
 * @tc.number: BundleDataMgr_0300
 * @tc.name: GetApplicationInfoWithResponseId
 * @tc.desc: test GetApplicationInfoWithResponseId the BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleDataMgr_0300, Function | SmallTest | Level1)
{
    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);

    std::string appName;
    ApplicationInfo appInfo;
    int32_t userId = -1;
    ErrCode ret = bundleDataMgr->GetApplicationInfoWithResponseId(appName, 0, userId, appInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: BundleDataMgr_0400
 * @tc.name: CheckInnerBundleInfoWithFlagsV9
 * @tc.desc: test CheckInnerBundleInfoWithFlagsV9 the BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest3, BundleDataMgr_0400, Function | SmallTest | Level1)
{
    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.bundleStatus_ = AppExecFwk::InnerBundleInfo::BundleStatus::DISABLED;
    ErrCode ret = bundleDataMgr->CheckInnerBundleInfoWithFlagsV9(innerBundleInfo, 0, 100, 1);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_DISABLED);
}

/**
 * @tc.number: IsBundleInstalled_0001
 * @tc.name: IsBundleInstalled
 * @tc.desc: test IsBundleInstalled
 */
HWTEST_F(BmsBundleDataMgrTest3, IsBundleInstalled_0001, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto bundleDataMgr = GetBundleDataMgr();
    EXPECT_NE(bundleDataMgr, nullptr);
    if (bundleDataMgr != nullptr) {
        bundleDataMgr->AddUserId(0);
        bool isInstalled = false;
        ErrCode ret = bundleDataMgr->IsBundleInstalled(BUNDLE_NAME_TEST, 200, 0, isInstalled);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
        EXPECT_FALSE(isInstalled);

        ret = bundleDataMgr->IsBundleInstalled(BUNDLE_NAME_TEST, 0, -10, isInstalled);
        EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX);
        EXPECT_FALSE(isInstalled);

        ret = bundleDataMgr->IsBundleInstalled(BUNDLE_NAME_TEST, 0, 10000, isInstalled);
        EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX);
        EXPECT_FALSE(isInstalled);

        ret = bundleDataMgr->IsBundleInstalled(BUNDLE_NAME_TEST, 0, 0, isInstalled);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_FALSE(isInstalled);

        ret = bundleDataMgr->IsBundleInstalled(BUNDLE_NAME_TEST, Constants::ANY_USERID, 0, isInstalled);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_FALSE(isInstalled);
    }
}

/**
 * @tc.number: IsBundleInstalled_0002
 * @tc.name: IsBundleInstalled
 * @tc.desc: test IsBundleInstalled
 */
HWTEST_F(BmsBundleDataMgrTest3, IsBundleInstalled_0002, Function | SmallTest | Level1)
{
    auto bundleDataMgr = GetBundleDataMgr();
    EXPECT_NE(bundleDataMgr, nullptr);
    if (bundleDataMgr != nullptr) {
        bundleDataMgr->AddUserId(100);
        InnerBundleInfo innerBundleInfo;
        innerBundleInfo.SetInstallMark(BUNDLE_NAME_TEST, MODULE_NAME_TEST, InstallExceptionStatus::INSTALL_START);
        innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;
        innerBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME_TEST;
        bundleDataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
        bool isInstalled = false;
        ErrCode ret = bundleDataMgr->IsBundleInstalled(BUNDLE_NAME_TEST, 100, 0, isInstalled);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_FALSE(isInstalled);
    }
}

/**
 * @tc.number: IsBundleInstalled_0003
 * @tc.name: IsBundleInstalled
 * @tc.desc: test IsBundleInstalled
 */
HWTEST_F(BmsBundleDataMgrTest3, IsBundleInstalled_0003, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto bundleDataMgr = GetBundleDataMgr();
    EXPECT_NE(bundleDataMgr, nullptr);
    if (bundleDataMgr != nullptr) {
        bundleDataMgr->AddUserId(100);
        InnerBundleInfo innerBundleInfo;
        innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::SHARED;
        innerBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME_TEST;
        bundleDataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
        bool isInstalled = false;
        ErrCode ret = bundleDataMgr->IsBundleInstalled(BUNDLE_NAME_TEST, 100, 0, isInstalled);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_TRUE(isInstalled);

        bundleDataMgr->bundleInfos_.clear();
        innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP_SERVICE_FWK;
        innerBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME_TEST;
        bundleDataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
        isInstalled = false;
        ret = bundleDataMgr->IsBundleInstalled(BUNDLE_NAME_TEST, 100, 0, isInstalled);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_TRUE(isInstalled);

        bundleDataMgr->bundleInfos_.clear();
        InnerBundleUserInfo innerBundleUserInfo;
        innerBundleInfo.innerBundleUserInfos_.emplace(BUNDLE_NAME_TEST + "_2000", innerBundleUserInfo);
        bundleDataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
        ret = bundleDataMgr->IsBundleInstalled(BUNDLE_NAME_TEST, 100, 0, isInstalled);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_FALSE(isInstalled);

        bundleDataMgr->bundleInfos_.clear();
        innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;
        innerBundleInfo.innerBundleUserInfos_.clear();
        bundleDataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
        ret = bundleDataMgr->IsBundleInstalled(BUNDLE_NAME_TEST, 100, 0, isInstalled);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_FALSE(isInstalled);

        bundleDataMgr->bundleInfos_.clear();
        innerBundleInfo.innerBundleUserInfos_.emplace(BUNDLE_NAME_TEST + "_100", innerBundleUserInfo);
        bundleDataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
        ret = bundleDataMgr->IsBundleInstalled(BUNDLE_NAME_TEST, 100, 0, isInstalled);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_TRUE(isInstalled);
    }
}

/**
 * @tc.number: IsBundleInstalled_0004
 * @tc.name: IsBundleInstalled
 * @tc.desc: test IsBundleInstalled
 */
HWTEST_F(BmsBundleDataMgrTest3, IsBundleInstalled_0004, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto bundleDataMgr = GetBundleDataMgr();
    EXPECT_NE(bundleDataMgr, nullptr);
    if (bundleDataMgr != nullptr) {
        bundleDataMgr->AddUserId(100);
        InnerBundleInfo innerBundleInfo;
        innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;

        InnerBundleUserInfo innerBundleUserInfo;
        innerBundleInfo.innerBundleUserInfos_.emplace(BUNDLE_NAME_TEST + "_100", innerBundleUserInfo);
        bundleDataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
        bool isInstalled = false;
        auto ret = bundleDataMgr->IsBundleInstalled(BUNDLE_NAME_TEST, 100, 1, isInstalled);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_FALSE(isInstalled);
    }
}

/**
 * @tc.number: IsBundleInstalled_0005
 * @tc.name: IsBundleInstalled
 * @tc.desc: test IsBundleInstalled
 */
HWTEST_F(BmsBundleDataMgrTest3, IsBundleInstalled_0005, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto bundleDataMgr = GetBundleDataMgr();
    EXPECT_NE(bundleDataMgr, nullptr);
    if (bundleDataMgr != nullptr) {
        bundleDataMgr->AddUserId(100);
        InnerBundleInfo innerBundleInfo;
        innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;
        innerBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME_TEST;
        InnerBundleUserInfo innerBundleUserInfo;
        InnerBundleCloneInfo innerBundleCloneInfo;
        innerBundleUserInfo.cloneInfos.emplace("1", innerBundleCloneInfo);
        innerBundleInfo.innerBundleUserInfos_.emplace(BUNDLE_NAME_TEST + "_100", innerBundleUserInfo);
        bundleDataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
        bool isInstalled = false;
        auto ret = bundleDataMgr->IsBundleInstalled(BUNDLE_NAME_TEST, 100, 1, isInstalled);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_TRUE(isInstalled);
    }
}

/**
 * @tc.number: GetAllPluginInfo_0001
 * @tc.name: GetAllPluginInfo
 * @tc.desc: test GetAllPluginInfo
 */
HWTEST_F(BmsBundleDataMgrTest3, GetAllPluginInfo_0001, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);

    std::vector<PluginBundleInfo> pluginBundleInfos;
    auto ret = bundleDataMgr->GetAllPluginInfo(BUNDLE_NAME_TEST, 200, pluginBundleInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: GetAllPluginInfo_0002
 * @tc.name: GetAllPluginInfo
 * @tc.desc: test GetAllPluginInfo
 */
HWTEST_F(BmsBundleDataMgrTest3, GetAllPluginInfo_0002, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);
    bundleDataMgr->AddUserId(100);
    std::vector<PluginBundleInfo> pluginBundleInfos;
    auto ret = bundleDataMgr->GetAllPluginInfo(BUNDLE_NAME_TEST, 100, pluginBundleInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    ret = bundleDataMgr->GetAllPluginInfo("", 100, pluginBundleInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetAllPluginInfo_0003
 * @tc.name: GetAllPluginInfo
 * @tc.desc: test GetAllPluginInfo
 */
HWTEST_F(BmsBundleDataMgrTest3, GetAllPluginInfo_0003, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);
    bundleDataMgr->AddUserId(100);
    bundleDataMgr->AddUserId(101);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;
    innerBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME_TEST;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleInfo.innerBundleUserInfos_.emplace(BUNDLE_NAME_TEST + "_100", innerBundleUserInfo);
    bundleDataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    std::vector<PluginBundleInfo> pluginBundleInfos;
    auto ret1 = bundleDataMgr->GetAllPluginInfo(BUNDLE_NAME_TEST, 100, pluginBundleInfos);
    EXPECT_EQ(ret1, ERR_OK);
    auto ret2 = bundleDataMgr->GetAllPluginInfo(BUNDLE_NAME_TEST, 101, pluginBundleInfos);
    EXPECT_EQ(ret2, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetAllBundleDirs_0001
 * @tc.name: GetAllBundleDirs
 * @tc.desc: test GetAllBundleDirs
 */

HWTEST_F(BmsBundleDataMgrTest3, GetAllBundleDirs_0001, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto bundleDataMgr = GetBundleDataMgr();
    EXPECT_NE(bundleDataMgr, nullptr);
    if (bundleDataMgr != nullptr) {
        bundleDataMgr->AddUserId(100);
        InnerBundleInfo innerBundleInfo;
        innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;
        innerBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME_TEST;
        InnerBundleUserInfo innerBundleUserInfo;
        innerBundleInfo.innerBundleUserInfos_.emplace(BUNDLE_NAME_TEST + "_100", innerBundleUserInfo);
        bundleDataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
        std::vector<BundleDir> bundleDirs;
        auto ret = bundleDataMgr->GetAllBundleDirs(100, bundleDirs);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_EQ(bundleDirs.size(), 1);
    }
}

/**
 * @tc.number: GetAllBundleDirs_0002
 * @tc.name: GetAllBundleDirs
 * @tc.desc: test GetAllBundleDirs
 */

HWTEST_F(BmsBundleDataMgrTest3, GetAllBundleDirs_0002, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto bundleDataMgr = GetBundleDataMgr();
    EXPECT_NE(bundleDataMgr, nullptr);
    if (bundleDataMgr != nullptr) {
        bundleDataMgr->AddUserId(100);
        InnerBundleInfo innerBundleInfo;
        innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::SHARED;
        innerBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME_TEST;

        InnerBundleUserInfo innerBundleUserInfo;
        innerBundleInfo.innerBundleUserInfos_.emplace(BUNDLE_NAME_TEST + "_100", innerBundleUserInfo);
        bundleDataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
        std::vector<BundleDir> bundleDirs;
        auto ret = bundleDataMgr->GetAllBundleDirs(100, bundleDirs);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_EQ(bundleDirs.size(), 0);
    }
}

/**
 * @tc.number: IBundleStatusCallback_0001
 * @tc.name: SetUserId
 * @tc.desc: test SetUserId
 */
HWTEST_F(BmsBundleDataMgrTest3, IBundleStatusCallback_0001, Function | SmallTest | Level1)
{
    IBundleStatusCallbackTest iBundleStatusCallbackTest;
    iBundleStatusCallbackTest.SetUserId(Constants::DEFAULT_USERID);
    EXPECT_EQ(iBundleStatusCallbackTest.GetUserId(), Constants::DEFAULT_USERID);
}

/**
 * @tc.number: PostProcessAnyUser_0001
 * @tc.name: SetUserId
 * @tc.desc: test SetUserId
 */
HWTEST_F(BmsBundleDataMgrTest3, PostProcessAnyUser_0001, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto bundleDataMgr = GetBundleDataMgr();
    EXPECT_NE(bundleDataMgr, nullptr);
    int32_t flags = static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)
        | static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_OF_ANY_USER);
    int32_t userId = 100;
    int32_t originUserId = 100;
    BundleInfo bundleInfo;
    InnerBundleInfo innerBundleInfo;

    InnerBundleUserInfo userInfo1;
    userInfo1.bundleUserInfo.userId = 100;
    InnerBundleUserInfo userInfo2;
    userInfo2.bundleUserInfo.userId = 101;

    innerBundleInfo.AddInnerBundleUserInfo(userInfo1);
    innerBundleInfo.AddInnerBundleUserInfo(userInfo2);

    bundleDataMgr->PostProcessAnyUserFlags(flags, userId, originUserId, bundleInfo, innerBundleInfo);
    uint32_t flagsRet = static_cast<uint32_t>(bundleInfo.applicationInfo.applicationFlags);
    bool r1 = (flagsRet & static_cast<uint32_t>(ApplicationInfoFlag::FLAG_INSTALLED))
         == static_cast<uint32_t>(ApplicationInfoFlag::FLAG_INSTALLED);
    bool r2 = (flagsRet & static_cast<uint32_t>(ApplicationInfoFlag::FLAG_OTHER_INSTALLED))
        == static_cast<uint32_t>(ApplicationInfoFlag::FLAG_OTHER_INSTALLED);
    EXPECT_EQ(r1, true);
    EXPECT_EQ(r2, true);
}

/**
 * @tc.number: PostProcessAnyUser_0002
 * @tc.name: SetUserId
 * @tc.desc: test SetUserId
 */
HWTEST_F(BmsBundleDataMgrTest3, PostProcessAnyUser_0002, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto bundleDataMgr = GetBundleDataMgr();
    EXPECT_NE(bundleDataMgr, nullptr);
    int32_t flags = static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)
        | static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_OF_ANY_USER);
    int32_t userId = 100;
    int32_t originUserId = 100;
    BundleInfo bundleInfo;
    InnerBundleInfo innerBundleInfo;

    InnerBundleUserInfo userInfo1;
    userInfo1.bundleUserInfo.userId = 100;

    innerBundleInfo.AddInnerBundleUserInfo(userInfo1);

    bundleDataMgr->PostProcessAnyUserFlags(flags, userId, originUserId, bundleInfo, innerBundleInfo);
    uint32_t flagsRet = static_cast<uint32_t>(bundleInfo.applicationInfo.applicationFlags);
    bool r1 = (flagsRet & static_cast<uint32_t>(ApplicationInfoFlag::FLAG_INSTALLED))
         == static_cast<uint32_t>(ApplicationInfoFlag::FLAG_INSTALLED);
    bool r2 = (flagsRet & static_cast<uint32_t>(ApplicationInfoFlag::FLAG_OTHER_INSTALLED))
        != static_cast<uint32_t>(ApplicationInfoFlag::FLAG_OTHER_INSTALLED);
    EXPECT_EQ(r1, true);
    EXPECT_EQ(r2, true);
}

/**
 * @tc.number: GetMediaDataFromAshMem_0100
 * @tc.name: test GetMediaDataFromAshMem
 * @tc.desc: test GetMediaDataFromAshMem
 */
HWTEST_F(BmsBundleDataMgrTest3, GetMediaDataFromAshMem_0100, Function | SmallTest | Level0)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    MessageParcel replystd;
    size_t len = 1;
    auto mediaDataPtr = std::make_unique<uint8_t[]>(len);
    ASSERT_NE(mediaDataPtr, nullptr);
    auto ret = bundleMgrProxy->GetMediaDataFromAshMem(replystd, mediaDataPtr, len);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: InnerGetBigString_0100
 * @tc.name: test InnerGetBigString
 * @tc.desc: test InnerGetBigString
 */
HWTEST_F(BmsBundleDataMgrTest3, InnerGetBigString_0100, Function | SmallTest | Level0)
{
    auto bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    MessageParcel reply;
    std::string result;
    auto ret = bundleMgrProxy->InnerGetBigString(reply, result);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: GetAdditionalBundleInfos_0100
 * @tc.name: test GetAdditionalBundleInfos
 * @tc.desc: test GetAdditionalBundleInfos
 */
HWTEST_F(BmsBundleDataMgrTest3, GetAdditionalBundleInfos_0100, Function | SmallTest | Level0)
{
    ASSERT_NE(bundleUserMgrHostImpl_, nullptr);
    auto dataMgr = bundleUserMgrHostImpl_->GetDataMgrFromService();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    ExtensionAbilityInfo info;
    info.type = ExtensionAbilityType::DRIVER;
    innerBundleInfo.baseExtensionInfos_.emplace(BUNDLE_TEST2, info);
    dataMgr->bundleInfos_[BUNDLE_TEST1] = innerBundleInfo;
    std::set<PreInstallBundleInfo> preInstallBundleInfos;
    bundleUserMgrHostImpl_->GetAdditionalBundleInfos(preInstallBundleInfos);
    EXPECT_FALSE(preInstallBundleInfos.empty());
}

/**
 * @tc.number: CreateNewUser_0100
 * @tc.name: test CreateNewUser
 * @tc.desc: test CreateNewUser
 */
HWTEST_F(BmsBundleDataMgrTest3, CreateNewUser_0100, Function | SmallTest | Level0)
{
    ASSERT_NE(bundleUserMgrHostImpl_, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    std::vector<std::string> disallowList;
    auto res = bundleUserMgrHostImpl_->CreateNewUser(TEST_UID, disallowList);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetAllUninstallBundleInfo_0100
 * @tc.name: GetAllUninstallBundleInfo
 * @tc.desc: test GetAllUninstallBundleInfo
 */
HWTEST_F(BmsBundleDataMgrTest3, GetAllUninstallBundleInfo_0100, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);
    bundleDataMgr->uninstallDataMgr_ = nullptr;
    std::map<std::string, UninstallBundleInfo> uninstallBundleInfos;
    auto ret = bundleDataMgr->GetAllUninstallBundleInfo(uninstallBundleInfos);
    EXPECT_FALSE(ret);
    ResetDataMgr();
}

/**
 * @tc.number: GetAllUninstallBundleInfo_0200
 * @tc.name: GetAllUninstallBundleInfo
 * @tc.desc: test GetAllUninstallBundleInfo
 */
HWTEST_F(BmsBundleDataMgrTest3, GetAllUninstallBundleInfo_0200, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);
    bundleDataMgr->DeleteUninstallBundleInfo(BUNDLE_NAME_TEST, USERID);
    std::map<std::string, UninstallBundleInfo> uninstallBundleInfos;
    auto ret = bundleDataMgr->GetAllUninstallBundleInfo(uninstallBundleInfos);
    if (!ret) {
        EXPECT_TRUE(uninstallBundleInfos.empty());
    }
}

/**
 * @tc.number: RestoreUidAndGidFromUninstallInfo_0100
 * @tc.name: RestoreUidAndGidFromUninstallInfo
 * @tc.desc: test RestoreUidAndGidFromUninstallInfo
 */
HWTEST_F(BmsBundleDataMgrTest3, RestoreUidAndGidFromUninstallInfo_0100, Function | SmallTest | Level1)
{
    ResetDataMgr();
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME_TEST;

    UninstallDataUserInfo uninstallDataUserInfo;
    uninstallDataUserInfo.uid = TEST_MAX_UID;
    UninstallBundleInfo uninstallBundleInfo;
    uninstallBundleInfo.userInfos.emplace(std::make_pair(std::to_string(USERID), uninstallDataUserInfo));

    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);
    auto ret = bundleDataMgr->UpdateUninstallBundleInfo(BUNDLE_NAME_TEST, uninstallBundleInfo);
    ASSERT_TRUE(ret);

    bundleDataMgr->RestoreUidAndGidFromUninstallInfo();
    auto bundleId = TEST_MAX_UID - USERID * Constants::BASE_USER_RANGE;
    ret = bundleDataMgr->bundleIdMap_.find(bundleId) != bundleDataMgr->bundleIdMap_.end();
    EXPECT_TRUE(ret);
    auto restoreBundleName = bundleDataMgr->bundleIdMap_.at(bundleId);
    EXPECT_EQ(restoreBundleName, BUNDLE_NAME_TEST);
    bundleDataMgr->DeleteUninstallBundleInfo(BUNDLE_NAME_TEST, USERID);
    bundleDataMgr->bundleIdMap_.erase(bundleId);
}

/**
 * @tc.number: GetSignatureInfo_0001
 * @tc.name: GetSignatureInfo_0001
 * ShortcutInfo
 * @tc.desc: test GetSignatureInfo_0001(MessageParcel &data, MessageParcel &reply)
 */
HWTEST_F(BmsBundleDataMgrTest3, GetSignatureInfo_0001, Function | MediumTest | Level1)
{
    std::shared_ptr<BundleDataMgr> localBundleDataMgr = std::make_shared<BundleDataMgr>();
    EXPECT_NE(localBundleDataMgr, nullptr);
    SignatureInfo signatureInfo;
    ErrCode ret = localBundleDataMgr->GetSignatureInfoByUid(100, signatureInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_UID);
}

/**
 * @tc.number: GetSignatureInfo_0002
 * @tc.name: GetSignatureInfo_0002
 * ShortcutInfo
 * @tc.desc: test GetSignatureInfo_0002(MessageParcel &data, MessageParcel &reply)
 */
HWTEST_F(BmsBundleDataMgrTest3, GetSignatureInfo_0002, Function | MediumTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    std::shared_ptr<BundleMgrProxy> localBundleMgrProxy = std::make_shared<BundleMgrProxy>(remoteObject);
    SignatureInfo signatureInfo;
    ErrCode ret = localBundleMgrProxy->GetSignatureInfoByUid(100, signatureInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetSignatureInfo_0003
 * @tc.name: GetSignatureInfo_0003
 * ShortcutInfo
 * @tc.desc: test GetSignatureInfo_0003(MessageParcel &data, MessageParcel &reply)
 */
HWTEST_F(BmsBundleDataMgrTest3, GetSignatureInfo_0003, Function | MediumTest | Level1)
{
    SignatureInfo signatureInfo;
    ErrCode ret = bundleMgrHostImpl_->GetSignatureInfoByUid(100, signatureInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_UID);
}

/**
 * @tc.number: AddPluginInfo_0001
 * @tc.name: AddPluginInfo_0001
 * @tc.desc: test AddPluginInfo_0001(const InnerBundleInfo &innerBundleInfo,
        const PluginBundleInfo &pluginBundleInfo, const int32_t userId)
 */
HWTEST_F(BmsBundleDataMgrTest3, AddPluginInfo_0001, Function | MediumTest | Level1)
{
    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);

    InnerBundleInfo innerBundleInfo;
    PluginBundleInfo pluginBundleInfo;
    pluginBundleInfo.pluginBundleName = BUNDLE_TEST1;
    ErrCode result = ERR_OK;

    result = bundleDataMgr->AddPluginInfo(innerBundleInfo.GetBundleName(), pluginBundleInfo, USERID);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    innerBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_TEST2;
    bundleDataMgr->bundleInfos_.emplace(BUNDLE_TEST2, innerBundleInfo);
    result = bundleDataMgr->AddPluginInfo(BUNDLE_TEST2, pluginBundleInfo, USERID);
    EXPECT_EQ(result, ERR_APPEXECFWK_ADD_PLUGIN_INFO_ERROR);

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    userInfo.bundleName = BUNDLE_TEST2;
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);
    auto res = bundleDataMgr->UpdateInnerBundleInfo(innerBundleInfo, true);
    EXPECT_EQ(res, true);
    result = bundleDataMgr->AddPluginInfo(BUNDLE_TEST2, pluginBundleInfo, USERID);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: RemovePluginInfo_0001
 * @tc.name: RemovePluginInfo_0001
 * @tc.desc: test RemovePluginInfo_0001(const InnerBundleInfo &innerBundleInfo,
        const std::string &pluginBundleName, const int32_t userId)
 */
HWTEST_F(BmsBundleDataMgrTest3, RemovePluginInfo_0001, Function | MediumTest | Level1)
{
    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);

    InnerBundleInfo innerBundleInfo;
    std::string pluginBundleName = BUNDLE_TEST1;
    PluginBundleInfo pluginBundleInfo;
    pluginBundleInfo.pluginBundleName = BUNDLE_TEST1;
    ErrCode result = ERR_OK;

    result = bundleDataMgr->RemovePluginInfo(innerBundleInfo.GetBundleName(), pluginBundleName, USERID);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    innerBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_TEST2;
    bundleDataMgr->bundleInfos_.emplace(BUNDLE_TEST2, innerBundleInfo);
    result = bundleDataMgr->RemovePluginInfo(BUNDLE_TEST2, pluginBundleName, ServiceConstants::NOT_EXIST_USERID);
    EXPECT_EQ(result, ERR_APPEXECFWK_REMOVE_PLUGIN_INFO_ERROR);

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    userInfo.bundleName = BUNDLE_TEST2;
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);
    auto res = bundleDataMgr->UpdateInnerBundleInfo(innerBundleInfo, true);
    EXPECT_EQ(res, true);
    result = bundleDataMgr->AddPluginInfo(BUNDLE_TEST2, pluginBundleInfo, USERID);
    EXPECT_EQ(result, ERR_OK);

    result = bundleDataMgr->RemovePluginInfo(BUNDLE_TEST2, pluginBundleName, USERID);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: GetPluginBundleInfo_0001
 * @tc.name: GetPluginBundleInfo_0001
 * @tc.desc: test GetPluginBundleInfo_0001(const std::string &hostBundleName, const std::string &pluginBundleName,
    PluginBundleInfo &pluginBundleInfo, const int32_t userId)
 */
HWTEST_F(BmsBundleDataMgrTest3, GetPluginBundleInfo_0001, Function | MediumTest | Level1)
{
    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);

    std::string pluginBundleName = BUNDLE_TEST1;
    std::string hostBundleName = BUNDLE_TEST2;
    PluginBundleInfo pluginBundleInfo;
    bool result = true;

    result = bundleDataMgr->GetPluginBundleInfo("", "", USERID, pluginBundleInfo);
    EXPECT_EQ(result, false);
    result = bundleDataMgr->GetPluginBundleInfo(hostBundleName, pluginBundleName,
        USERID, pluginBundleInfo);
    EXPECT_EQ(result, false);

    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    userInfo.bundleName = BUNDLE_TEST2;
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);
    innerBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_TEST2;
    bundleDataMgr->bundleInfos_.emplace(BUNDLE_TEST2, innerBundleInfo);

    pluginBundleInfo.pluginBundleName = BUNDLE_TEST1;
    auto res = bundleDataMgr->AddPluginInfo(hostBundleName, pluginBundleInfo, USERID);
    EXPECT_EQ(res, ERR_OK);

    result = bundleDataMgr->GetPluginBundleInfo(hostBundleName, pluginBundleName, USERID, pluginBundleInfo);
    EXPECT_EQ(result, true);

    result = bundleDataMgr->GetPluginBundleInfo(hostBundleName, pluginBundleName,
        ServiceConstants::NOT_EXIST_USERID, pluginBundleInfo);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: FetchPluginBundleInfo_0001
 * @tc.name: FetchPluginBundleInfo_0001
 * @tc.desc: test FetchPluginBundleInfo_0001(const std::string &hostBundleName, const std::string &pluginBundleName,
    PluginBundleInfo &pluginBundleInfo)
 */
HWTEST_F(BmsBundleDataMgrTest3, FetchPluginBundleInfo_0001, Function | MediumTest | Level1)
{
    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);

    std::string pluginBundleName = BUNDLE_TEST1;
    std::string hostBundleName = BUNDLE_TEST2;
    PluginBundleInfo pluginBundleInfo;
    bool result = true;

    result = bundleDataMgr->FetchPluginBundleInfo("", "", pluginBundleInfo);
    EXPECT_EQ(result, false);

    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    userInfo.bundleName = BUNDLE_TEST2;
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);
    innerBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_TEST2;
    bundleDataMgr->bundleInfos_.emplace(BUNDLE_TEST2, innerBundleInfo);

    pluginBundleInfo.pluginBundleName = BUNDLE_TEST1;
    auto res = bundleDataMgr->AddPluginInfo(hostBundleName, pluginBundleInfo, USERID);
    EXPECT_EQ(res, ERR_OK);

    result = bundleDataMgr->FetchPluginBundleInfo(hostBundleName, pluginBundleName, pluginBundleInfo);
    EXPECT_EQ(result, true);

    std::string pluginBundleName2 = BUNDLE_TEST3;
    result = bundleDataMgr->FetchPluginBundleInfo(hostBundleName, pluginBundleName2,
        pluginBundleInfo);
    EXPECT_EQ(result, false);
}
} // OHOS
