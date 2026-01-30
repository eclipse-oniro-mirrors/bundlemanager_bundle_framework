/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "ability_manager_client.h"
#include "ability_info.h"
#include "app_install_extended_info.h"
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
#include "installd/installd_operator.h"
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
#include "bundle_manager_helper.h"

namespace OHOS {
namespace AppExecFwk {
    void ClearGlobalQueryEventInfo();
    bool InsertQueryEventInfo(int32_t errCode, const QueryEventInfo& info);
    bool TransQueryEventInfo(const std::vector<QueryEventInfo> &infos, EventInfo &report);
    void SetCleanBundleDataDirResult(bool cleanResult);
}
}

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using OHOS::AAFwk::Want;

namespace OHOS {
namespace {
const int32_t TEST_ACCESS_TOKENID = 1;
const int32_t TEST_ACCESS_TOKENID_EX = 2;
const int32_t TEST_QUERY_EVENT_UID = 20013998;
const int32_t TEST_QUERY_EVENT_BUNDLE_ID = 13998;
const int32_t TEST_QUERY_EVENT_UID2 = 20013999;
const int32_t TEST_QUERY_EVENT_BUNDLE_ID2 = 13999;
const int32_t MAX_QUERY_EVENT_REPORT_ONCE = 101;
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
const std::string FORM_ABILITY_NAME = "GameLoaderExtensionAbility";
const std::string FORM_TARGET_BUNDLE_NAME = "Game";
const std::string FORM_SUB_BUNDLE_NAME = "subGame";
const std::string FORM_DISABLED_DESKTOP_BEHAVIORS = "PULL_DOWN_SEARCH|LONG_CLICK";
constexpr int32_t FORM_KEEP_STATE_DURATION = 10000;
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
const std::string TEST_URI_HTTPS = "https://www.test.com";
const std::string TEST_URI_HTTP = "http://www.test.com";
const std::string META_DATA_SHORTCUTS_NAME = "ohos.ability.shortcuts";
constexpr int32_t MOCK_BUNDLE_MGR_EXT_FLAG = 10;
const std::string BMS_EXTENSION_PATH = "/system/etc/app/bms-extensions.json";
const std::string BUNDLE_NAME_FOR_TEST_U1ENABLE = "com.example.u1Enable_test";
const int32_t TEST_U100 = 100;
const int32_t TEST_U200 = 200;
const int32_t TEST_U1 = 1;
const int32_t TEST_SIZE_ONE = 1;
const int32_t TEST_VALUE_ZERO = 0;
const int32_t DEFAULT_APP_INDEX = 0;
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
enum {
    BMS_BROKER_ERR_INSTALL_FAILED = 8585217,
    BMS_BROKER_ERR_UNINSTALL_FAILED = 8585218,
};
const int FORMINFO_DESCRIPTIONID = 123;
const int ABILITYINFOS_SIZE_1 = 1;
const int ABILITYINFOS_SIZE_2 = 2;
const int32_t USERID = 100;
const int32_t ERROR_USERID = -1;
const int32_t MULTI_USERID = 101;
const int32_t TEST_USERID = 1001;
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
    InnerAbilityInfo MockAbilityInfo(
        const std::string &bundleName, const std::string &module, const std::string &abilityName) const;
    InnerExtensionInfo MockExtensionInfo(
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
    bool CheckPreInstallBundleInfo(const std::vector<PreInstallBundleInfo> &preInfos, const std::string &bundleName);

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
    InnerAbilityInfo innerAbilityInfo = MockAbilityInfo(bundleName, moduleName, abilityName);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertAbilitiesInfo(keyName, innerAbilityInfo);
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
    InnerExtensionInfo innerExtensionInfo = MockExtensionInfo(bundleName, moduleName, extensionName);
    InnerExtensionInfo innerExtensionInfo02 = MockExtensionInfo(bundleName, moduleName, extensionName + "02");
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertExtensionInfo(keyName, innerExtensionInfo);
    innerBundleInfo.InsertExtensionInfo(keyName02, innerExtensionInfo02);
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
        InnerAbilityInfo innerAbilityInfo = MockAbilityInfo(bundleName, moduleName, abilityName);
        innerBundleInfo.InsertAbilitiesInfo(keyName, innerAbilityInfo);
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
    formInfo.funInteractionParams.abilityName = FORM_ABILITY_NAME;
    formInfo.funInteractionParams.targetBundleName = FORM_TARGET_BUNDLE_NAME;
    formInfo.funInteractionParams.subBundleName = FORM_SUB_BUNDLE_NAME;
    formInfo.funInteractionParams.keepStateDuration = FORM_KEEP_STATE_DURATION;
    formInfo.sceneAnimationParams.abilityName = FORM_ABILITY_NAME;
    formInfo.sceneAnimationParams.disabledDesktopBehaviors = FORM_DISABLED_DESKTOP_BEHAVIORS;
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

InnerAbilityInfo BmsBundleDataMgrTest::MockAbilityInfo(
    const std::string &bundleName, const std::string &moduleName, const std::string &abilityName) const
{
    InnerAbilityInfo abilityInfo;
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

InnerExtensionInfo BmsBundleDataMgrTest::MockExtensionInfo(
    const std::string &bundleName, const std::string &moduleName, const std::string &extensionName) const
{
    InnerExtensionInfo extensionInfo;
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
    InnerAbilityInfo innerAbilityInfo = MockAbilityInfo(bundleName, moduleName, abilityName);
    std::string keyName = bundleName + "." + moduleName + "." + abilityName;
    innerBundleInfo.InsertAbilitiesInfo(keyName, innerAbilityInfo);
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
    InnerAbilityInfo innerAbilityInfo = MockAbilityInfo(bundleName, moduleName, abilityName);
    std::string keyName = bundleName + "." + moduleName + "." + abilityName;
    innerBundleInfo.InsertAbilitiesInfo(keyName, innerAbilityInfo);
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

bool BmsBundleDataMgrTest::CheckPreInstallBundleInfo(const std::vector<PreInstallBundleInfo> &preInfos,
    const std::string &bundleName)
{
    for (auto info : preInfos) {
        if (info.GetBundleName() == bundleName) {
            return true;
        }
    }
    return false;
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
 * @tc.number: ImplicitQueryCurAbilityInfos_0200
 * @tc.name: test ImplicitQueryCurAbilityInfos
 * @tc.desc: 1.system run normally
 *           2.check ImplicitQueryCurAbilityInfos failed
 */
HWTEST_F(BmsBundleDataMgrTest, ImplicitQueryCurAbilityInfos_0200, Function | SmallTest | Level1)
{
    Want want;
    std::vector<AbilityInfo> abilityInfo;
    int32_t appIndex = -1;
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
 * @tc.number: DeleteSharedBundleInfo_0300
 * @tc.name: test DeleteSharedBundleInfo
 * @tc.desc: 1.system run normally
 *           2.check DeleteSharedBundleInfo failed
 */
HWTEST_F(BmsBundleDataMgrTest, DeleteSharedBundleInfo_0300, Function | SmallTest | Level1)
{
    bool res = GetBundleDataMgr()->DeleteSharedBundleInfo("");
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
 * @tc.number: GetAdaptBaseShareBundleInfo_0100
 * @tc.name: test GetAdaptBaseShareBundleInfo
 * @tc.desc: 1.system run normally
 *           2.check GetAdaptBaseShareBundleInfo failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetAdaptBaseShareBundleInfo_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    Dependency dependency;
    BaseSharedBundleInfo baseSharedBundleInfo;
    bool ret = GetBundleDataMgr()->GetAdaptBaseShareBundleInfo(innerBundleInfo, dependency, baseSharedBundleInfo);
    EXPECT_FALSE(ret);

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.bundleType = BundleType::SHARED;
    innerModuleInfo.versionCode = 200;
    innerBundleInfo.innerSharedModuleInfos_[MODULE_TEST].push_back(innerModuleInfo);
    ret = GetBundleDataMgr()->GetAdaptBaseShareBundleInfo(innerBundleInfo, dependency, baseSharedBundleInfo);
    EXPECT_FALSE(ret);

    dependency.moduleName = MODULE_TEST;
    innerModuleInfo.versionCode = 100;
    innerBundleInfo.innerSharedModuleInfos_[MODULE_TEST].push_back(innerModuleInfo);
    ret = GetBundleDataMgr()->GetAdaptBaseShareBundleInfo(innerBundleInfo, dependency, baseSharedBundleInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(baseSharedBundleInfo.versionCode, 200);
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
    #if defined(USE_EXTENSION_DATA) && defined(CONTAIN_BROKER_CLIENT_ENABLED)
    EXPECT_THAT(ret, testing::AnyOf(
        ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY,
        BMS_BROKER_ERR_UNINSTALL_FAILED,
        BMS_BROKER_ERR_INSTALL_FAILED));
    #else
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    #endif
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
    #if defined(USE_EXTENSION_DATA) && defined(CONTAIN_BROKER_CLIENT_ENABLED)
    EXPECT_THAT(res, testing::AnyOf(
        ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY,
        BMS_BROKER_ERR_UNINSTALL_FAILED,
        BMS_BROKER_ERR_INSTALL_FAILED));
    #else
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    #endif
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
    #if defined(USE_EXTENSION_DATA) && defined(CONTAIN_BROKER_CLIENT_ENABLED)
    EXPECT_THAT(res, testing::AnyOf(
        ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY,
        BMS_BROKER_ERR_UNINSTALL_FAILED,
        BMS_BROKER_ERR_INSTALL_FAILED));
    #else
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    #endif
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
    const InnerBundleInfo* innerPtr = &innerBundleInfo;
    bool res = GetBundleDataMgr()->GetInnerBundleInfoWithFlags(
        BUNDLE_NAME_TEST, GET_ABILITY_INFO_DEFAULT, innerPtr, USERID);
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
    const InnerBundleInfo* innerPtr = &innerBundleInfo;
    ErrCode res = GetBundleDataMgr()->GetInnerBundleInfoWithFlagsV9(
        BUNDLE_NAME_TEST, GET_ABILITY_INFO_DEFAULT, innerPtr, USERID);
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
    const InnerBundleInfo* innerPtr = &innerBundleInfo;
    ErrCode res = GetBundleDataMgr()->GetInnerBundleInfoWithBundleFlagsV9(
        BUNDLE_NAME_TEST, GET_ABILITY_INFO_DEFAULT, innerPtr, USERID);
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
    const InnerBundleInfo* innerPtr = &innerBundleInfo;
    ErrCode res = GetBundleDataMgr()->GetInnerBundleInfoWithBundleFlagsV9(
        BUNDLE_NAME_TEST, GET_ABILITY_INFO_DEFAULT, innerPtr, ServiceConstants::NOT_EXIST_USERID);
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
        BUNDLE_NAME_TEST, BUNDLE_NAME_TEST, isEnabled, TEST_U100, TEST_U200);
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
        BUNDLE_NAME_TEST, BUNDLE_NAME_TEST, isEnabled, TEST_U100, TEST_U200);
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
    ErrCode res = GetBundleDataMgr()->GenerateUidAndGid(innerBundleUserInfo);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_BUNDLENAME_IS_EMPTY);
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
 * @tc.number: GetShortcutInfoByAppIndex_0100
 * @tc.name: test GetShortcutInfoByAppIndex
 * @tc.desc: 1.system run normally
 *           2.check GetShortcutInfoByAppIndex failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetShortcutInfoByAppIndex_0100, Function | SmallTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    int32_t appIndex = 0;
    ErrCode res = GetBundleDataMgr()->GetShortcutInfoByAppIndex("", appIndex, shortcutInfos);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    EXPECT_TRUE(shortcutInfos.empty());
    GetBundleDataMgr()->multiUserIdsSet_.clear();
}

/**
 * @tc.number: GetShortcutInfoByAppIndex_0200
 * @tc.name: test GetShortcutInfoByAppIndex
 * @tc.desc: 1.system run normally
 *           2.check GetShortcutInfoByAppIndex failed
 */
HWTEST_F(BmsBundleDataMgrTest, GetShortcutInfoByAppIndex_0200, Function | SmallTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    int32_t appIndex = 100;
    ErrCode res = GetBundleDataMgr()->GetShortcutInfoByAppIndex("", appIndex, shortcutInfos);
    EXPECT_EQ(res, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
    EXPECT_TRUE(shortcutInfos.empty());
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
    bool findDefaultApp = true;
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
 * @tc.number: ProcessBundleChangedEventForOtherUsers_0100
 * @tc.name: test ProcessBundleChangedEventForOtherUsers
 * @tc.desc: 1.ProcessBundleChangedEventForOtherUsers
 */
HWTEST_F(BmsBundleDataMgrTest, ProcessBundleChangedEventForOtherUsers_0100, Function | MediumTest | Level1)
{
    EventFwk::CommonEventData commonData;
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    NotifyBundleEvents installResult;
    installResult.bundleName = "notExist";
    installResult.type = NotifyType::UNINSTALL_BUNDLE;
    bool ret = commonEventMgr->ProcessBundleChangedEventForOtherUsers(nullptr, installResult, USERID, commonData);
    EXPECT_FALSE(ret);

    installResult.type = NotifyType::UPDATE;
    ret = commonEventMgr->ProcessBundleChangedEventForOtherUsers(nullptr, installResult, USERID, commonData);
    EXPECT_FALSE(ret);

    auto dataMgr = GetBundleDataMgr();
    ret = commonEventMgr->ProcessBundleChangedEventForOtherUsers(dataMgr, installResult, USERID, commonData);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ProcessBundleChangedEventForOtherUsers_0200
 * @tc.name: test ProcessBundleChangedEventForOtherUsers
 * @tc.desc: 1.ProcessBundleChangedEventForOtherUsers
 */
HWTEST_F(BmsBundleDataMgrTest, ProcessBundleChangedEventForOtherUsers_0200, Function | MediumTest | Level1)
{
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.innerBundleUserInfos_["100"] = userInfo;
    userInfo.bundleUserInfo.userId = 101;
    innerBundleInfo.innerBundleUserInfos_["101"] = userInfo;

    auto dataMgr = GetBundleDataMgr();
    dataMgr->bundleInfos_["bundleName"] = innerBundleInfo;
    EventFwk::CommonEventData commonData;
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    NotifyBundleEvents installResult;
    installResult.bundleName = "bundleName";
    installResult.type = NotifyType::UPDATE;
    bool ret = commonEventMgr->ProcessBundleChangedEventForOtherUsers(dataMgr, installResult, USERID, commonData);
    EXPECT_TRUE(ret);
    auto iter = dataMgr->bundleInfos_.find("bundleName");
    if (iter != dataMgr->bundleInfos_.end()) {
        dataMgr->bundleInfos_.erase(iter);
    }
}

/**
 * @tc.number: ProcessBundleChangedEventForOtherUsers_0300
 * @tc.name: test ProcessBundleChangedEventForOtherUsers
 * @tc.desc: 1.ProcessBundleChangedEventForOtherUsers
 */
HWTEST_F(BmsBundleDataMgrTest, ProcessBundleChangedEventForOtherUsers_0300, Function | MediumTest | Level1)
{
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.innerBundleUserInfos_["_100"] = userInfo;
    userInfo.bundleUserInfo.userId = 200;
    innerBundleInfo.innerBundleUserInfos_["_200"] = userInfo;

    auto dataMgr = GetBundleDataMgr();
    dataMgr->AddUserId(200);
    dataMgr->bundleInfos_["bundleName"] = innerBundleInfo;
    EventFwk::CommonEventData commonData;
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    NotifyBundleEvents installResult;
    installResult.bundleName = "bundleName";
    installResult.type = NotifyType::INSTALL;
    installResult.isInstallByBundleName = false;
    installResult.isRecover = false;
    bool ret = commonEventMgr->ProcessBundleChangedEventForOtherUsers(dataMgr, installResult, USERID, commonData);
    EXPECT_TRUE(ret);
    installResult.isInstallByBundleName = true;
    installResult.isRecover = false;
    ret = commonEventMgr->ProcessBundleChangedEventForOtherUsers(dataMgr, installResult, USERID, commonData);
    EXPECT_FALSE(ret);
    installResult.isInstallByBundleName = false;
    installResult.isRecover = true;
    ret = commonEventMgr->ProcessBundleChangedEventForOtherUsers(dataMgr, installResult, USERID, commonData);
    EXPECT_FALSE(ret);
    installResult.isInstallByBundleName = true;
    installResult.isRecover = true;
    ret = commonEventMgr->ProcessBundleChangedEventForOtherUsers(dataMgr, installResult, USERID, commonData);
    EXPECT_FALSE(ret);
    installResult.isInstallByBundleName = false;
    installResult.isRecover = false;
    installResult.appIndex = 1;
    ret = commonEventMgr->ProcessBundleChangedEventForOtherUsers(dataMgr, installResult, USERID, commonData);
    EXPECT_FALSE(ret);
    auto iter = dataMgr->bundleInfos_.find("bundleName");
    if (iter != dataMgr->bundleInfos_.end()) {
        dataMgr->bundleInfos_.erase(iter);
    }
    dataMgr->RemoveUserId(200);
}

/**
 * @tc.number: PublishCommonEvent_0100
 * @tc.name: test PublishCommonEvent
 * @tc.desc: 1.PublishCommonEvent
 */
HWTEST_F(BmsBundleDataMgrTest, PublishCommonEvent_0100, Function | MediumTest | Level1)
{
    EventFwk::CommonEventData commonData;
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    bool ret = commonEventMgr->PublishCommonEvent("notExist",
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED, USERID, commonData);
    EXPECT_FALSE(ret);

    ret = commonEventMgr->PublishCommonEvent("notExist",
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_INSTALLATION_STARTED, USERID, commonData);
    EXPECT_FALSE(ret);
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

/**
 * @tc.number: GetRecoverablePreInstallBundleInfos_0100
 * @tc.name: test GetRecoverablePreInstallBundleInfos
 * @tc.desc: 1.test GetRecoverablePreInstallBundleInfos, add u1enable, add innerBundleUserInfo for u1
 * @tc.require: issueI7HXM5
 */
HWTEST_F(BmsBundleDataMgrTest, GetRecoverablePreInstallBundleInfos_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME_FOR_TEST_U1ENABLE;
    // add u1Enable
    std::vector<std::string> acls;
    acls.push_back(std::string(Constants::PERMISSION_U1_ENABLED));
    info.SetAllowedAcls(acls);
    // add innerBundleUserInfo for u1
    InnerBundleUserInfo innerBundleUserInfo1;
    innerBundleUserInfo1.bundleUserInfo.userId = TEST_U1;
    innerBundleUserInfo1.bundleName = BUNDLE_NAME_FOR_TEST_U1ENABLE;
    info.AddInnerBundleUserInfo(innerBundleUserInfo1);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_FOR_TEST_U1ENABLE, info);
    std::vector<PreInstallBundleInfo> res = dataMgr->GetRecoverablePreInstallBundleInfos(TEST_U100);
    EXPECT_FALSE(CheckPreInstallBundleInfo(res, BUNDLE_NAME_FOR_TEST_U1ENABLE));
}

/**
 * @tc.number: GetRecoverablePreInstallBundleInfos_0200
 * @tc.name: test GetRecoverablePreInstallBundleInfos
 * @tc.desc: 1.test GetRecoverablePreInstallBundleInfos, no u1enable, no innerBundleUserInfo for u1
 * @tc.require: issueI7HXM5
 */
HWTEST_F(BmsBundleDataMgrTest, GetRecoverablePreInstallBundleInfos_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME_FOR_TEST_U1ENABLE;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_FOR_TEST_U1ENABLE, info);
    std::vector<PreInstallBundleInfo> res = dataMgr->GetRecoverablePreInstallBundleInfos(TEST_U100);
    EXPECT_FALSE(CheckPreInstallBundleInfo(res, BUNDLE_NAME_FOR_TEST_U1ENABLE));
}

/**
 * @tc.number: GetRecoverablePreInstallBundleInfos_0300
 * @tc.name: test GetRecoverablePreInstallBundleInfos
 * @tc.desc: 1.test GetRecoverablePreInstallBundleInfos
 * @tc.require: issueI7HXM5
 */
HWTEST_F(BmsBundleDataMgrTest, GetRecoverablePreInstallBundleInfos_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME_FOR_TEST_U1ENABLE;
    // add u1Enable
    std::vector<std::string> acls;
    acls.push_back(std::string(Constants::PERMISSION_U1_ENABLED));
    info.SetAllowedAcls(acls);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_FOR_TEST_U1ENABLE, info);
    std::vector<PreInstallBundleInfo> res = dataMgr->GetRecoverablePreInstallBundleInfos(TEST_U100);
    EXPECT_FALSE(CheckPreInstallBundleInfo(res, BUNDLE_NAME_FOR_TEST_U1ENABLE));
}

/**
 * @tc.number: GetRecoverablePreInstallBundleInfos_0400
 * @tc.name: test GetRecoverablePreInstallBundleInfos
 * @tc.desc: 1.test GetRecoverablePreInstallBundleInfos
 * @tc.require: issueI7HXM5
 */
HWTEST_F(BmsBundleDataMgrTest, GetRecoverablePreInstallBundleInfos_0400, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME_FOR_TEST_U1ENABLE;
    // add innerBundleUserInfo for u1
    InnerBundleUserInfo innerBundleUserInfo1;
    innerBundleUserInfo1.bundleUserInfo.userId = TEST_U1;
    innerBundleUserInfo1.bundleName = BUNDLE_NAME_FOR_TEST_U1ENABLE;
    info.AddInnerBundleUserInfo(innerBundleUserInfo1);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_FOR_TEST_U1ENABLE, info);
    std::vector<PreInstallBundleInfo> res = dataMgr->GetRecoverablePreInstallBundleInfos(TEST_U100);
    EXPECT_FALSE(CheckPreInstallBundleInfo(res, BUNDLE_NAME_FOR_TEST_U1ENABLE));
}

/**
 * @tc.number: GetRecoverablePreInstallBundleInfos_0500
 * @tc.name: test GetRecoverablePreInstallBundleInfos
 * @tc.desc: 1.test GetRecoverablePreInstallBundleInfos
 * @tc.require: issueI7HXM5
 */
HWTEST_F(BmsBundleDataMgrTest, GetRecoverablePreInstallBundleInfos_0500, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    PreInstallBundleInfo preInfo;
    preInfo.SetRemovable(false);
    preInfo.SetBundleName(BUNDLE_DESCRIPTION);
    preInfo.SetBundleType(BundleType::APP);
    dataMgr->preInstallDataStorage_->SavePreInstallStorageBundleInfo(preInfo);
    std::vector<PreInstallBundleInfo> res = dataMgr->GetRecoverablePreInstallBundleInfos(TEST_U100);
    EXPECT_TRUE(CheckPreInstallBundleInfo(res, BUNDLE_DESCRIPTION));
    dataMgr->preInstallDataStorage_->DeletePreInstallStorageBundleInfo(preInfo);
}

/**
 * @tc.number: GetRecoverablePreInstallBundleInfos_0600
 * @tc.name: test GetRecoverablePreInstallBundleInfos
 * @tc.desc: 1.test GetRecoverablePreInstallBundleInfos
 * @tc.require: issueI7HXM5
 */
HWTEST_F(BmsBundleDataMgrTest, GetRecoverablePreInstallBundleInfos_0600, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    PreInstallBundleInfo preInfo;
    preInfo.SetRemovable(false);
    preInfo.SetBundleName(BUNDLE_DESCRIPTION);
    preInfo.SetBundleType(BundleType::ATOMIC_SERVICE);
    dataMgr->preInstallDataStorage_->SavePreInstallStorageBundleInfo(preInfo);
    std::vector<PreInstallBundleInfo> res = dataMgr->GetRecoverablePreInstallBundleInfos(TEST_U100);
    EXPECT_TRUE(CheckPreInstallBundleInfo(res, BUNDLE_DESCRIPTION));
    dataMgr->preInstallDataStorage_->DeletePreInstallStorageBundleInfo(preInfo);
}

/**
 * @tc.number: GetRecoverablePreInstallBundleInfos_0700
 * @tc.name: test GetRecoverablePreInstallBundleInfos
 * @tc.desc: 1.test GetRecoverablePreInstallBundleInfos
 * @tc.require: issueI7HXM5
 */
HWTEST_F(BmsBundleDataMgrTest, GetRecoverablePreInstallBundleInfos_0700, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    PreInstallBundleInfo preInfo;
    preInfo.SetRemovable(false);
    preInfo.SetBundleName(BUNDLE_DESCRIPTION);
    preInfo.SetBundleType(BundleType::SHARED);
    dataMgr->preInstallDataStorage_->SavePreInstallStorageBundleInfo(preInfo);
    std::vector<PreInstallBundleInfo> res = dataMgr->GetRecoverablePreInstallBundleInfos(TEST_U100);
    EXPECT_FALSE(CheckPreInstallBundleInfo(res, BUNDLE_DESCRIPTION));
    dataMgr->preInstallDataStorage_->DeletePreInstallStorageBundleInfo(preInfo);
}

/**
 * @tc.number: SetBit_0001
 * @tc.name: SetBit_0001
 * @tc.desc: test SetBit_0001
 */
HWTEST_F(BmsBundleDataMgrTest, SetBit_0001, Function | MediumTest | Level1)
{
    uint8_t num = 0;
    uint8_t pos = 1;
    BundleUtil::SetBit(pos, num);
    EXPECT_EQ(num, 2);

    auto ret1 = BundleUtil::GetBitValue(num, pos);
    EXPECT_EQ(ret1, true);

    BundleUtil::ResetBit(pos, num);
    EXPECT_EQ(num, 0);
}

/**
 * @tc.number: QueryLauncherAbility_0002
 * @tc.name: test BmsExtensionClient::QueryLauncherAbility
 * @tc.desc: 1. system run normally
 *           2. enter if (res != ERR_OK)
 */
HWTEST_F(BmsBundleDataMgrTest, QueryLauncherAbility_0002, TestSize.Level1)
{
    Want want;
    int32_t userId = 0;
    std::vector<AbilityInfo> abilityInfos;
    AbilityInfo ability1;
    ApplicationInfo appInfo;
    appInfo.labelId = 1001;
    appInfo.label = "Default App Label";
    appInfo.iconId = 1001;
    ability1.applicationInfo = appInfo;
    abilityInfos.push_back(ability1);

    BmsExtensionClient client;
    for (auto& ability : abilityInfos) {
        client.ModifyLauncherAbilityInfo(ability);
    }
    EXPECT_EQ(abilityInfos[0].labelId, 1001);
    EXPECT_EQ(abilityInfos[0].label, "Default App Label");
    EXPECT_EQ(abilityInfos[0].iconId, 1001);
}

/**
 * @tc.number: QueryLauncherAbility_0003
 * @tc.name: test BmsExtensionClient::QueryLauncherAbility
 * @tc.desc: 1. system run normally
 *           2. enter if (res != ERR_OK)
 */
HWTEST_F(BmsBundleDataMgrTest, QueryLauncherAbility_0003, TestSize.Level1)
{
    Want want;
    int32_t userId = 0;
    std::vector<AbilityInfo> abilityInfos;

    AbilityInfo ability2;
    ability2.labelId = 2001;
    ApplicationInfo appInfo;
    appInfo.labelId = 1001;
    appInfo.label = "Default App Label";
    appInfo.iconId = 1001;
    ability2.applicationInfo = appInfo;
    abilityInfos.push_back(ability2);

    BmsExtensionClient client;
    for (auto& ability : abilityInfos) {
        client.ModifyLauncherAbilityInfo(ability);
    }

    EXPECT_EQ(abilityInfos[0].labelId, 2001);
    EXPECT_EQ(abilityInfos[0].label, "Default App Label");
    EXPECT_EQ(abilityInfos[0].iconId, 1001);
}

/**
 * @tc.number: QueryLauncherAbility_0004
 * @tc.name: test BmsExtensionClient::QueryLauncherAbility
 * @tc.desc: 1. system run normally
 *           2. enter if (res != ERR_OK)
 */
HWTEST_F(BmsBundleDataMgrTest, QueryLauncherAbility_0004, TestSize.Level1)
{
    Want want;
    int32_t userId = 0;
    std::vector<AbilityInfo> abilityInfos;

    AbilityInfo ability3;
    ability3.labelId = 3001;
    ability3.label = "Custom Label";
    ability3.iconId = 3001;
    ApplicationInfo appInfo;
    appInfo.labelId = 1001;
    appInfo.label = "Default App Label";
    appInfo.iconId = 1001;
    ability3.applicationInfo = appInfo;
    abilityInfos.push_back(ability3);
    BmsExtensionClient client;
    for (auto& ability : abilityInfos) {
        client.ModifyLauncherAbilityInfo(ability);
    }
    EXPECT_EQ(abilityInfos[0].labelId, 3001);
    EXPECT_EQ(abilityInfos[0].label, "Custom Label");
    EXPECT_EQ(abilityInfos[0].iconId, 3001);
}

/**
 * @tc.number: BundleMgrHostImplSetShortcutVisibleForSelf_0001
 * @tc.name: BundleMgrHostImplSetShortcutVisibleForSelf
 * @tc.desc: test SetShortcutVisibleForSelf(const std::string &shortcutId, bool visible)
 */
HWTEST_F(BmsBundleDataMgrTest, BundleMgrHostImplSetShortcutVisibleForSelf_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> lcalBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(lcalBundleMgrHostImpl, nullptr);
    std::string shortcutId = "shortcutId";
    bool visible = true;

    auto ret = lcalBundleMgrHostImpl->SetShortcutVisibleForSelf(shortcutId, true);
    EXPECT_NE(ret, ERR_OK);

    ClearDataMgr();
    ret = lcalBundleMgrHostImpl->SetShortcutVisibleForSelf(shortcutId, true);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetDirByBundleNameAndAppIndex_0100
 * @tc.name: test GetDirByBundleNameAndAppIndex
 * @tc.desc: 1.system run normally
 *           2.check appIndex invalid
 */
HWTEST_F(BmsBundleDataMgrTest, GetDirByBundleNameAndAppIndex_0100, Function | MediumTest | Level1)
{
    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);

    std::string bundleName;
    std::string sandboxDataDir;
    ErrCode result = bundleDataMgr->GetDirByBundleNameAndAppIndex(bundleName, -1, sandboxDataDir);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_GET_DIR_INVALID_APP_INDEX);

    result = bundleDataMgr->GetDirByBundleNameAndAppIndex(bundleName, 6, sandboxDataDir);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_GET_DIR_INVALID_APP_INDEX);
}

/**
 * @tc.number: GetDirByBundleNameAndAppIndex_0200
 * @tc.name: test GetDirByBundleNameAndAppIndex
 * @tc.desc: 1.system run normally
 *           2.bundleName not installed
 */
HWTEST_F(BmsBundleDataMgrTest, GetDirByBundleNameAndAppIndex_0200, Function | MediumTest | Level1)
{
    auto bundleDataMgr = GetBundleDataMgr();
    ASSERT_NE(bundleDataMgr, nullptr);

    std::string bundleName;
    std::string sandboxDataDir;
    ErrCode result = bundleDataMgr->GetDirByBundleNameAndAppIndex(bundleName, 0, sandboxDataDir);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: GetAppIdAndAppIdentifierByBundleName_0100
 * @tc.name: test GetAppIdAndAppIdentifierByBundleName
 * @tc.desc: test GetAppIdAndAppIdentifierByBundleName
 */
HWTEST_F(BmsBundleDataMgrTest, GetAppIdAndAppIdentifierByBundleName_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetAppIdentifier("appIdentifier");
    innerBundleInfo.SetProvisionId("appId");
    std::string bundleName = "com.test.appid";
    GetBundleDataMgr()->bundleInfos_.emplace(bundleName, innerBundleInfo);

    std::string appId;
    std::string appIdentifier;
    ErrCode ret = GetBundleDataMgr()->GetAppIdAndAppIdentifierByBundleName(bundleName, appId, appIdentifier);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appId, "_appId");
    EXPECT_EQ(appIdentifier, "appIdentifier");

    ret = GetBundleDataMgr()->GetAppIdAndAppIdentifierByBundleName("com.test.not.exist", appId, appIdentifier);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    RemoveBundleinfo(bundleName);
}

/**
 * @tc.number: AppIdAndAppIdentifierTransform_0100
 * @tc.name: test AppIdAndAppIdentifierTransform
 * @tc.desc: test AppIdAndAppIdentifierTransform
 */
HWTEST_F(BmsBundleDataMgrTest, AppIdAndAppIdentifierTransform_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetAppIdentifier("appIdentifier");
    innerBundleInfo.SetProvisionId("appId");
    std::string bundleName = "com.test.appid";
    GetBundleDataMgr()->bundleInfos_.emplace(bundleName, innerBundleInfo);

    std::string ret = GetBundleDataMgr()->AppIdAndAppIdentifierTransform("appIdentifier");
    EXPECT_EQ(ret, "_appId");

    ret = GetBundleDataMgr()->AppIdAndAppIdentifierTransform("_appId");
    EXPECT_EQ(ret, "appIdentifier");

    ret = GetBundleDataMgr()->AppIdAndAppIdentifierTransform("");
    EXPECT_EQ(ret, "");

    ret = GetBundleDataMgr()->AppIdAndAppIdentifierTransform("notexistappId");
    EXPECT_EQ(ret, "");

    RemoveBundleinfo(bundleName);
}

/**
 * @tc.number: BundleMgrHostImplGetAllShortcutInfoForSelf_0001
 * @tc.name: BundleMgrHostImplGetAllShortcutInfoForSelf
 * @tc.desc: test GetAllShortcutInfoForSelf(std::vector<ShortcutInfo> &shortcutInfos)
 */
HWTEST_F(BmsBundleDataMgrTest, BundleMgrHostImplGetAllShortcutInfoForSelf_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> lcalBundleMgrHostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(lcalBundleMgrHostImpl, nullptr);
    std::vector<ShortcutInfo> shortcutInfos;

    auto ret = lcalBundleMgrHostImpl->GetAllShortcutInfoForSelf(shortcutInfos);
    EXPECT_NE(ret, ERR_OK);

    ClearDataMgr();
    ret = lcalBundleMgrHostImpl->GetAllShortcutInfoForSelf(shortcutInfos);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BatchGetBundleStats_0100
 * @tc.name: test BatchGetBundleStats
 * @tc.desc: 1.Test the BatchGetBundleStats by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, BatchGetBundleStats_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> hostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<std::string> bundleNames;
    std::vector<BundleStorageStats> bundleStats;
    ErrCode ret = hostImpl->BatchGetBundleStats(bundleNames, USERID, bundleStats);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: BatchGetBundleStats_0200
 * @tc.name: test BatchGetBundleStats
 * @tc.desc: 1.Test the BatchGetBundleStats by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, BatchGetBundleStats_0200, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> hostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<std::string> bundleNames = {"com.ohos.systemui", "com.ohos.launcher"};
    std::vector<BundleStorageStats> bundleStats;
    ErrCode ret = hostImpl->BatchGetBundleStats(bundleNames, USERID, bundleStats);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: BatchGetBundleStats_0300
 * @tc.name: test BatchGetBundleStats
 * @tc.desc: 1.Test the BatchGetBundleStats by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, BatchGetBundleStats_0300, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> hostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<std::string> bundleNames = {"com.ohos.systemui", "com.ohos.launcher"};
    std::vector<BundleStorageStats> bundleStats;
    ClearDataMgr();
    ErrCode ret = hostImpl->BatchGetBundleStats(bundleNames, USERID, bundleStats);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: BatchGetBundleStats_0400
 * @tc.name: test BatchGetBundleStats
 * @tc.desc: 1.Test the BatchGetBundleStats by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, BatchGetBundleStats_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    std::vector<std::string> bundleNames = {"com.example.bundlekit.test"};
    std::vector<BundleStorageStats> bundleStats;
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    ErrCode res = GetBundleDataMgr()->BatchGetBundleStats(bundleNames, USERID, bundleStats);
    EXPECT_EQ(res, ERR_OK);

    GetBundleDataMgr()->multiUserIdsSet_.erase(USERID);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: BatchGetBundleStats_0500
 * @tc.name: test BatchGetBundleStats
 * @tc.desc: 1.Test the BatchGetBundleStats by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, BatchGetBundleStats_0500, Function | SmallTest | Level1)
{
    std::vector<std::string> bundleNames = {"com.example.bundlekit.test"};
    std::vector<BundleStorageStats> bundleStats;
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    ErrCode res = GetBundleDataMgr()->BatchGetBundleStats(bundleNames, USERID, bundleStats);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GetBundleDataMgr()->multiUserIdsSet_.erase(USERID);
}

/**
 * @tc.number: BatchGetBundleStats_0600
 * @tc.name: test BatchGetBundleStats
 * @tc.desc: 1.Test the BatchGetBundleStats by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, BatchGetBundleStats_0600, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    InnerBundleInfo innerBundleInfo;
    std::vector<std::string> bundleNames = {"com.example.bundlekit.test"};
    std::vector<BundleStorageStats> bundleStats;
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode res = GetBundleDataMgr()->BatchGetBundleStats(bundleNames, USERID, bundleStats);
    EXPECT_EQ(res, ERR_OK);

    GetBundleDataMgr()->multiUserIdsSet_.erase(USERID);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: BatchGetBundleStats_0700
 * @tc.name: test BatchGetBundleStats
 * @tc.desc: 1.Test the BatchGetBundleStats by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, BatchGetBundleStats_0700, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    std::vector<std::string> bundleNames = { BUNDLE_NAME_TEST };
    std::vector<BundleStorageStats> bundleStats;
    dataMgr->multiUserIdsSet_.insert(USERID);
    dataMgr->multiUserIdsSet_.insert(ERROR_USERID);
    dataMgr->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    ErrCode res = dataMgr->BatchGetBundleStats(bundleNames, ERROR_USERID, bundleStats);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    dataMgr->multiUserIdsSet_.erase(USERID);
    dataMgr->multiUserIdsSet_.erase(ERROR_USERID);
    dataMgr->bundleInfos_.clear();
}

/**
 * @tc.number: GetBindingSAUidsByBundleName_0100
 * @tc.name: test GetBindingSAUidsByBundleName
 * @tc.desc: 1.Test the GetBindingSAUidsByBundleName by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, GetBindingSAUidsByBundleName_0100, Function | SmallTest | Level1)
{
    std::map<std::string, std::set<int32_t>> saUidMap;
    auto res = GetBundleDataMgr()->GetBindingSAUidsByBundleName(BUNDLE_NAME_TEST, saUidMap);
    EXPECT_TRUE(res.empty());

    std::set<int32_t> saUidList;
    saUidList.emplace(TEST_VALUE_ZERO);
    saUidMap[BUNDLE_NAME_TEST] = saUidList;
    res = GetBundleDataMgr()->GetBindingSAUidsByBundleName(BUNDLE_NAME_TEST, saUidMap);
    EXPECT_EQ(res.size(), TEST_SIZE_ONE);
}

/**
 * @tc.number: BundleMgrHostHandleBatchGetBundleStats_0100
 * @tc.name: BundleMgrHostHandleBatchGetBundleStats_0100
 * @tc.desc: test BundleMgrHostHandleBatchGetBundleStats(MessageParcel &data, MessageParcel &reply)
 */
HWTEST_F(BmsBundleDataMgrTest, BundleMgrHostHandleBatchGetBundleStats_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHost> localBundleMgrHost = std::make_shared<BundleMgrHost>();
    ASSERT_NE(localBundleMgrHost, nullptr);

    MessageParcel data;
    MessageParcel reply;

    auto ret = localBundleMgrHost->HandleBatchGetBundleStats(data, reply);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetCallingInfo_0100
 * @tc.name: test GetCallingInfo
 * @tc.desc: 1.Test the GetCallingInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, GetCallingInfo_0100, Function | SmallTest | Level1)
{
    ASSERT_NE(bundleMgrHostImpl_, nullptr);
    auto dataMgr = bundleMgrHostImpl_->GetDataMgrFromService();
    ASSERT_NE(dataMgr, nullptr);
    int32_t callingUid = 0;
    std::string callingBundleName;
    std::string callingAppId;
    bool ret = bundleMgrHostImpl_->GetCallingInfo(callingUid, callingBundleName, callingAppId);
    EXPECT_EQ(ret, false);
    callingUid = TEST_QUERY_EVENT_UID;
    ret = bundleMgrHostImpl_->GetCallingInfo(callingUid, callingBundleName, callingAppId);
    EXPECT_EQ(ret, false);

    std::string bundleName = "com.GetCallingInfo_0100.test";
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;
    bundleInfo.applicationInfo.name = bundleName;
    ApplicationInfo applicationInfo;
    applicationInfo.name = bundleName;
    applicationInfo.bundleName = bundleName;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    info.SetAppIdentifier("appIdentifier");
    info.SetProvisionId("appId");
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = TEST_QUERY_EVENT_UID;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.userId = 100;
    info.AddInnerBundleUserInfo(innerBundleUserInfo);

    dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(bundleName, info);

    int32_t testBundleId = TEST_QUERY_EVENT_BUNDLE_ID;
    dataMgr->bundleIdMap_.insert(std::pair<int32_t, std::string>(testBundleId, bundleName));
    ret = bundleMgrHostImpl_->GetCallingInfo(callingUid, callingBundleName, callingAppId);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(callingBundleName, bundleName);
}

/**
 * @tc.number: SendQueryBundleInfoEvent_0100
 * @tc.name: test SendQueryBundleInfoEvent
 * @tc.desc: 1.Test the SendQueryBundleInfoEvent by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, SendQueryBundleInfoEvent_0100, Function | SmallTest | Level1)
{
    ASSERT_NE(bundleMgrHostImpl_, nullptr);
    auto dataMgr = bundleMgrHostImpl_->GetDataMgrFromService();
    ASSERT_NE(dataMgr, nullptr);
    ClearGlobalQueryEventInfo();
    size_t maxEvent = 7;
    QueryEventInfo test;
    test.errCode = ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    test.funcId = 1;
    test.userId = 100;
    test.uid = 1;
    test.appIndex = 0;
    test.flag = BundleFlag::GET_BUNDLE_DEFAULT;
    test.bundleName = "test.SendQueryBundleInfoEvent_0100";
    test.callingUid = 1001;
    test.callingBundleName = "com.test.SendQueryBundleInfoEvent_0100";
    test.callingAppId = "123asdf";
    test.lastReportEventTime = 0;

    // test no need report errcode
    test.errCode = ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    bool ret = bundleMgrHostImpl_->SendQueryBundleInfoEvent(test, 0, true);
    EXPECT_EQ(ret, false);

    // test reportNow is true
    test.errCode = ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    ret = bundleMgrHostImpl_->SendQueryBundleInfoEvent(test, 0, true);
    EXPECT_EQ(ret, true);

    // test infoSize >= MAX_QUERY_EVENT_REPORT_ONCE
    ClearGlobalQueryEventInfo();
    for (int32_t i = 0; i <= MAX_QUERY_EVENT_REPORT_ONCE; i++) {
        test.bundleName = "test.SendQueryBundleInfoEvent_0100_" + std::to_string(i);
        InsertQueryEventInfo(ERR_BUNDLE_MANAGER_INTERNAL_ERROR, test);
    }
    test.bundleName = "test.SendQueryBundleInfoEvent_0100_new";
    ret = bundleMgrHostImpl_->SendQueryBundleInfoEvent(test, 0, false);
    EXPECT_EQ(ret, true);

    // test infoSize < MAX_QUERY_EVENT_REPORT_ONCE, but has wait for more than intervalTime
    ClearGlobalQueryEventInfo();
    ret = bundleMgrHostImpl_->SendQueryBundleInfoEvent(test, 0, false);
    EXPECT_EQ(ret, true);

    // test infoSize < MAX_QUERY_EVENT_REPORT_ONCE and need wait for more than intervalTime
    ClearGlobalQueryEventInfo();
    int64_t oneDay =  86400;
    test.bundleName = "test.SendQueryBundleInfoEvent_0100";
    ret = bundleMgrHostImpl_->SendQueryBundleInfoEvent(test, oneDay, false);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: TransQueryEventInfo_0100
 * @tc.name: test TransQueryEventInfo
 * @tc.desc: 1.Test the TransQueryEventInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, TransQueryEventInfo_0100, Function | SmallTest | Level1)
{
    ASSERT_NE(bundleMgrHostImpl_, nullptr);
    auto dataMgr = bundleMgrHostImpl_->GetDataMgrFromService();
    ASSERT_NE(dataMgr, nullptr);
    ClearGlobalQueryEventInfo();
    size_t maxEvent = 7;
    QueryEventInfo test;
    test.errCode = ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    test.funcId = 1;
    test.userId = 100;
    test.uid = 1;
    test.appIndex = 0;
    test.flag = BundleFlag::GET_BUNDLE_DEFAULT;
    test.bundleName = "test.TransQueryEventInfo_0100";
    test.callingUid = 1001;
    test.callingBundleName = "com.test.TransQueryEventInfo_0100";
    test.callingAppId = "123asdf";
    test.lastReportEventTime = 0;

    std::vector<QueryEventInfo> infos;
    // test no need report errcode
    EventInfo report;
    bool ret = TransQueryEventInfo(infos, report);
    EXPECT_EQ(ret, false);

    infos.push_back(test);
    ret = TransQueryEventInfo(infos, report);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: InsertQueryEventInfo_0100
 * @tc.name: test InsertQueryEventInfo
 * @tc.desc: 1.Test the InsertQueryEventInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, InsertQueryEventInfo_0100, Function | SmallTest | Level1)
{
    ASSERT_NE(bundleMgrHostImpl_, nullptr);
    auto dataMgr = bundleMgrHostImpl_->GetDataMgrFromService();
    ASSERT_NE(dataMgr, nullptr);
    ClearGlobalQueryEventInfo();
    size_t maxEvent = 7;
    QueryEventInfo test;
    test.errCode = ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    test.funcId = 1;
    test.userId = 100;
    test.uid = 1;
    test.appIndex = 0;
    test.flag = BundleFlag::GET_BUNDLE_DEFAULT;
    test.bundleName = "test.InsertQueryEventInfo_0100";
    test.callingUid = 1001;
    test.callingBundleName = "com.test.InsertQueryEventInfo_0100";
    test.callingAppId = "123asdf";
    test.lastReportEventTime = 0;

    // test insert new info
    bool ret = InsertQueryEventInfo(ERR_BUNDLE_MANAGER_INTERNAL_ERROR, test);
    EXPECT_EQ(ret, true);

    // test insert same info
    ret = InsertQueryEventInfo(ERR_BUNDLE_MANAGER_INTERNAL_ERROR, test);
    EXPECT_EQ(ret, false);

    // test insert different errcode
    ret = InsertQueryEventInfo(ERR_OK, test);
    EXPECT_EQ(ret, true);

    // test insert different funcid
    test.funcId = 2;
    ret = InsertQueryEventInfo(ERR_BUNDLE_MANAGER_INTERNAL_ERROR, test);
    EXPECT_EQ(ret, true);

    // test insert different uid
    test.uid = 2;
    ret = InsertQueryEventInfo(ERR_BUNDLE_MANAGER_INTERNAL_ERROR, test);
    EXPECT_EQ(ret, true);

    // test insert different userid
    test.userId = 0;
    ret = InsertQueryEventInfo(ERR_BUNDLE_MANAGER_INTERNAL_ERROR, test);
    EXPECT_EQ(ret, true);

    // test insert different appIndex
    test.appIndex = 1;
    ret = InsertQueryEventInfo(ERR_BUNDLE_MANAGER_INTERNAL_ERROR, test);
    EXPECT_EQ(ret, true);

    // test insert different flag
    test.flag = BundleFlag::GET_BUNDLE_WITH_ABILITIES;
    ret = InsertQueryEventInfo(ERR_BUNDLE_MANAGER_INTERNAL_ERROR, test);
    EXPECT_EQ(ret, true);

    // test insert different bundlename
    test.bundleName = "com.test.InsertQueryEventInfo_0100_2";
    ret = InsertQueryEventInfo(ERR_BUNDLE_MANAGER_INTERNAL_ERROR, test);
    EXPECT_EQ(ret, true);

    // test insert different callinguid
    test.callingUid = 200000;
    ret = InsertQueryEventInfo(ERR_BUNDLE_MANAGER_INTERNAL_ERROR, test);
    EXPECT_EQ(ret, true);

    // test insert different callingBundleName
    test.callingBundleName = "com.test.InsertQueryEventInfo_0100_3";
    ret = InsertQueryEventInfo(ERR_BUNDLE_MANAGER_INTERNAL_ERROR, test);
    EXPECT_EQ(ret, true);

    // test insert different callingAppId
    test.callingAppId = "asdf123";
    ret = InsertQueryEventInfo(ERR_BUNDLE_MANAGER_INTERNAL_ERROR, test);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: GetBundleNameForUid_0100
 * @tc.name: test GetBundleNameForUid
 * @tc.desc: 1.Test the GetBundleNameForUid by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleNameForUid_0100, Function | SmallTest | Level1)
{
    ASSERT_NE(bundleMgrHostImpl_, nullptr);
    auto dataMgr = bundleMgrHostImpl_->GetDataMgrFromService();
    ASSERT_NE(dataMgr, nullptr);
    std::string testResult;
    bool testRet = bundleMgrHostImpl_->GetBundleNameForUid(1, testResult);
    EXPECT_FALSE(testRet);

    std::string bundleName = "com.GetBundleNameForUid_0100.test";
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;
    bundleInfo.applicationInfo.name = bundleName;
    ApplicationInfo applicationInfo;
    applicationInfo.name = bundleName;
    applicationInfo.bundleName = bundleName;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = TEST_QUERY_EVENT_UID2;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.userId = 100;
    info.AddInnerBundleUserInfo(innerBundleUserInfo);

    dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    dataMgr->AddInnerBundleInfo(bundleName, info);

    int32_t testBundleId = TEST_QUERY_EVENT_BUNDLE_ID2;
    dataMgr->bundleIdMap_.insert(std::pair<int32_t, std::string>(testBundleId, bundleName));

    testRet = bundleMgrHostImpl_->GetBundleNameForUid(TEST_QUERY_EVENT_UID2, testResult);
    EXPECT_TRUE(testRet);
}

/**
 * @tc.number: BundleMgrProxyBatchGetBundleStats_0100_0100
 * @tc.name: BundleMgrProxyBatchGetBundleStats_0100_0100
 * @tc.desc: test BundleMgrProxyBatchGetBundleStats_0100(MessageParcel &data, MessageParcel &reply)
 */
HWTEST_F(BmsBundleDataMgrTest, BundleMgrProxyBatchGetBundleStats_0100, Function | MediumTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    std::shared_ptr<BundleMgrProxy> localBundleMgrProxy = std::make_shared<BundleMgrProxy>(remoteObject);
    std::vector<std::string> bundleNames = {"com.example.bundlekit.test"};
    std::vector<BundleStorageStats> bundleStats;
    ErrCode ret = localBundleMgrProxy->BatchGetBundleStats(bundleNames, USERID, bundleStats);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: GetTestRunner_0100
 * @tc.name: GetTestRunner_0100
 * @tc.desc: test GetTestRunner
 */
HWTEST_F(BmsBundleDataMgrTest, GetTestRunner_0100, Function | MediumTest | Level1)
{
    ModuleTestRunner testRunner;
    ErrCode ret = GetBundleDataMgr()->GetTestRunner(BUNDLE_NAME_TEST, MODULE_NAME_TEST, testRunner);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
* @tc.number: GetTestRunner_0200
* @tc.name: GetTestRunner_0200
* @tc.desc: test GetTestRunner
*/
HWTEST_F(BmsBundleDataMgrTest, GetTestRunner_0200, Function | MediumTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    ModuleTestRunner testRunner;
    ErrCode ret = GetBundleDataMgr()->GetTestRunner(BUNDLE_NAME_TEST, BUNDLE_NAME_TEST, testRunner);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: UninstallBundleInfo_0002
 * @tc.name: test GetUid
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleDataMgrTest, UninstallBundleInfo_0002, Function | SmallTest | Level1)
{
    std::vector<int32_t> uids;
    // test add one uninstallbudnleinfo, but no userInfos
    std::string bundleName = "com.test.UninstallBundleInfo_0002_1";
    UninstallBundleInfo uninstallBundleInfo;

    auto uid = uninstallBundleInfo.GetUid(USERID, 0);
    EXPECT_EQ(uid, Constants::INVALID_UID);

    // test add one uninstallbudnleinfo, query userid is in userinfos
    bundleName = "com.test.UninstallBundleInfo_0002_2";
    UninstallBundleInfo uninstallBundleInfo2;
    uninstallBundleInfo2.bundleType = BundleType::ATOMIC_SERVICE;

    UninstallDataUserInfo uninstallDataUserInfo2;
    uninstallDataUserInfo2.uid = 20020033;
    uninstallBundleInfo2.userInfos.emplace(std::make_pair(std::to_string(USERID), uninstallDataUserInfo2));

    UninstallDataUserInfo uninstallDataUserInfo2_1;
    uninstallDataUserInfo2_1.uid = 20020034;
    std::string cloneInfoKey = std::to_string(USERID) + '_' + std::to_string(1);
    uninstallBundleInfo2.userInfos.emplace(std::make_pair(cloneInfoKey, uninstallDataUserInfo2_1));

    UninstallDataUserInfo uninstallDataUserInfo2_2;
    uninstallDataUserInfo2_2.uid = 20020035;
    cloneInfoKey = std::to_string(USERID) + '_' + std::to_string(2);
    uninstallBundleInfo2.userInfos.emplace(std::make_pair(cloneInfoKey, uninstallDataUserInfo2_2));

    UninstallDataUserInfo uninstallDataUserInfo2_3;
    uninstallDataUserInfo2_3.uid = 20020036;
    cloneInfoKey = std::to_string(MULTI_USERID) + '_' + std::to_string(1);
    uninstallBundleInfo2.userInfos.emplace(std::make_pair(cloneInfoKey, uninstallDataUserInfo2_3));

    uid = uninstallBundleInfo2.GetUid(USERID, 0);
    EXPECT_EQ(uid, 20020033);

    uid = uninstallBundleInfo2.GetUid(Constants::INVALID_USERID, 0);
    EXPECT_EQ(uid, Constants::INVALID_UID);

    uid = uninstallBundleInfo2.GetUid(USERID, 1);
    EXPECT_EQ(uid, 20020034);

    uid = uninstallBundleInfo2.GetUid(Constants::INVALID_USERID, 1);
    EXPECT_EQ(uid, Constants::INVALID_UID);
}

/**
 * @tc.number: GetAllUnisntallBundleUids_0001
 * @tc.name: test GetAllUnisntallBundleUids
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllUnisntallBundleUids_0001, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::vector<int32_t> uids;
    std::map<std::string, UninstallBundleInfo> uninstallBundleInfos;

    // add four uninstallbudnleinfo
    std::string bundleName1 = "com.test.GetAllUnisntallBundleUids_0001_1";
    UninstallBundleInfo uninstallBundleInfo1;
    uninstallBundleInfos.emplace(std::make_pair(bundleName1, uninstallBundleInfo1));

    std::string bundleName2 = "com.test.GetAllUnisntallBundleUids_0001_2";
    UninstallDataUserInfo uninstallDataUserInfo2;
    UninstallBundleInfo uninstallBundleInfo2;
    uninstallBundleInfo2.bundleType = BundleType::APP;
    uninstallBundleInfo2.userInfos.emplace(std::make_pair(std::to_string(USERID), uninstallDataUserInfo2));
    uninstallBundleInfos.emplace(std::make_pair(bundleName2, uninstallBundleInfo2));

    // apptype is not ATOMIC_SERVICE and not APP
    std::string bundleName3 = "com.test.GetAllUnisntallBundleUids_0001_3";
    UninstallDataUserInfo uninstallDataUserInfo3;
    UninstallBundleInfo uninstallBundleInfo3;
    uninstallBundleInfo3.bundleType = BundleType::SHARED;
    uninstallBundleInfo3.userInfos.emplace(std::make_pair(std::to_string(USERID), uninstallDataUserInfo3));
    uninstallBundleInfos.emplace(std::make_pair(bundleName3, uninstallBundleInfo3));

    // test add one uninstallbudnleinfo, and apptype is ATOMIC_SERVICE
    std::string bundleName4 = "com.test.GetAllUnisntallBundleUids_0001_4";
    UninstallBundleInfo uninstallBundleInfo4;
    uninstallBundleInfo4.bundleType = BundleType::ATOMIC_SERVICE;

    UninstallDataUserInfo uninstallDataUserInfo4;
    uninstallDataUserInfo4.uid = 20020033;
    uninstallBundleInfo4.userInfos.emplace(std::make_pair(std::to_string(USERID), uninstallDataUserInfo4));

    UninstallDataUserInfo uninstallDataUserInfo4_1;
    uninstallDataUserInfo4_1.uid = 20020034;
    std::string cloneInfoKey = std::to_string(USERID) + '_' + std::to_string(1);
    uninstallBundleInfo4.userInfos.emplace(std::make_pair(cloneInfoKey, uninstallDataUserInfo4_1));

    UninstallDataUserInfo uninstallDataUserInfo4_2;
    uninstallDataUserInfo4_2.uid = 20020035;
    cloneInfoKey = std::to_string(USERID) + '_' + std::to_string(2);
    uninstallBundleInfo4.userInfos.emplace(std::make_pair(cloneInfoKey, uninstallDataUserInfo4_2));

    UninstallDataUserInfo uninstallDataUserInfo4_3;
    uninstallDataUserInfo4_3.uid = 20020036;
    cloneInfoKey = std::to_string(MULTI_USERID) + '_' + std::to_string(1);
    uninstallBundleInfo4.userInfos.emplace(std::make_pair(cloneInfoKey, uninstallDataUserInfo4_3));

    uninstallBundleInfos.emplace(std::make_pair(bundleName4, uninstallBundleInfo4));

    // test get with invalid userid
    int32_t userId = -3;
    bool res = dataMgr->GetAllUnisntallBundleUids(userId, uninstallBundleInfos, uids);
    EXPECT_TRUE(res);
    EXPECT_EQ(uids.empty(), true);
    
    // test get with valid userid 
    res = dataMgr->GetAllUnisntallBundleUids(USERID, uninstallBundleInfos, uids);
    EXPECT_TRUE(res);
    EXPECT_EQ(uids.empty(), false);
}

/**
 * @tc.number: GetBundleStats_0300
 * @tc.name: test GetBundleStats
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleStats_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    // test bundlename not in bundleinfos_ and not uninstalled withkeepdata before
    std::vector<int64_t> bundleStats;
    std::string bundleName = "com.test.GetBundleStats_0300";
    bool res = dataMgr->GetBundleStats(bundleName, USERID, bundleStats);
    EXPECT_EQ(res, false);

    // test bundlename not in bundleinfos_ and uninstalled withkeepdata before
    UninstallBundleInfo uninstallBundleInfo;
    uninstallBundleInfo.bundleType = BundleType::ATOMIC_SERVICE;
    UninstallDataUserInfo uninstallDataUserInfo;
    uninstallDataUserInfo.uid = 20020033;
    uninstallBundleInfo.userInfos.emplace(std::make_pair(std::to_string(USERID), uninstallDataUserInfo));

    UninstallDataUserInfo uninstallDataUserInfo1;
    uninstallDataUserInfo1.uid = 20020034;
    std::string cloneInfoKey = std::to_string(USERID) + '_' + std::to_string(1);
    uninstallBundleInfo.userInfos.emplace(std::make_pair(cloneInfoKey, uninstallDataUserInfo1));

    UninstallDataUserInfo uninstallDataUserInfo2;
    uninstallDataUserInfo2.uid = -1;
    cloneInfoKey = std::to_string(USERID) + '_' + std::to_string(2);
    uninstallBundleInfo.userInfos.emplace(std::make_pair(cloneInfoKey, uninstallDataUserInfo2));

    UninstallDataUserInfo uninstallDataUserInfo3;
    uninstallDataUserInfo3.uid = 20020036;
    cloneInfoKey = std::to_string(MULTI_USERID) + '_' + std::to_string(1);
    uninstallBundleInfo.userInfos.emplace(std::make_pair(cloneInfoKey, uninstallDataUserInfo3));

    auto ret = dataMgr->UpdateUninstallBundleInfo(bundleName, uninstallBundleInfo);
    ASSERT_TRUE(ret);
    // test getbundlestat for main app, which has userinfo in UninstallBundleInfo
    res = dataMgr->GetBundleStats(bundleName, USERID, bundleStats, 0);
    EXPECT_EQ(res, true);
    // test getbundlestat for main app, which has no userinfo in UninstallBundleInfo
    res = dataMgr->GetBundleStats(bundleName, Constants::INVALID_USERID, bundleStats, 0);
    EXPECT_EQ(res, true);
    // test getbundlestat for clone app, which has userinfo in UninstallBundleInfo
    res = dataMgr->GetBundleStats(bundleName, USERID, bundleStats, 1);
    EXPECT_EQ(res, true);
    res = dataMgr->GetBundleStats(bundleName, USERID, bundleStats, 2);
    EXPECT_EQ(res, true);

    // test add bundleinfo
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = TEST_QUERY_EVENT_UID2;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;

    InnerBundleCloneInfo innerBundleCloneInfo;
    innerBundleCloneInfo.userId = USERID;
    innerBundleCloneInfo.appIndex = 1;
    innerBundleCloneInfo.uid = TEST_UID;
    innerBundleCloneInfo.gids = {0};
    innerBundleCloneInfo.accessTokenId = TEST_ACCESS_TOKENID;
    innerBundleCloneInfo.accessTokenIdEx = TEST_ACCESS_TOKENID_EX;

    InnerBundleCloneInfo innerBundleCloneInfo2;
    innerBundleCloneInfo2.userId = USERID;
    innerBundleCloneInfo2.appIndex = 2;
    innerBundleCloneInfo2.uid = -1;
    innerBundleCloneInfo2.gids = {1};
    innerBundleCloneInfo2.accessTokenId = TEST_ACCESS_TOKENID;
    innerBundleCloneInfo2.accessTokenIdEx = TEST_ACCESS_TOKENID_EX;

    std::string appIndexKey = std::to_string(innerBundleCloneInfo.appIndex);
    innerBundleUserInfo.cloneInfos.insert(make_pair(appIndexKey, innerBundleCloneInfo));
    appIndexKey = std::to_string(innerBundleCloneInfo2.appIndex);
    innerBundleUserInfo.cloneInfos.insert(make_pair(appIndexKey, innerBundleCloneInfo2));
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);

    res = dataMgr->GetBundleStats(bundleName, USERID, bundleStats);
    EXPECT_EQ(res, true);

    res = dataMgr->GetBundleStats(bundleName, USERID, bundleStats, 1);
    EXPECT_EQ(res, true);

    res = dataMgr->GetBundleStats(bundleName, USERID, bundleStats, 2);
    EXPECT_EQ(res, true);

    dataMgr->bundleInfos_.erase(bundleName);
    dataMgr->RemoveUninstalledBundleinfos(USERID);
    dataMgr->RemoveUninstalledBundleinfos(MULTI_USERID);
}

/**
 * @tc.number: BatchGetBundleStats_1000
 * @tc.name: test BatchGetBundleStats
 * @tc.desc: 1.Test the BatchGetBundleStats by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, BatchGetBundleStats_1000, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::vector<BundleStorageStats> bundleStats;
    std::string bundleName = "com.example.BatchGetBundleStats_1000_1";
    std::string bundleName2 = "com.example.BatchGetBundleStats_1000_2";
    std::vector<std::string> bundleNames = {bundleName, bundleName2, BUNDLE_NAME_TEST};
    // test bundlename not in bundleinfos_ and uninstalled withkeepdata before
    dataMgr->multiUserIdsSet_.insert(USERID);
    UninstallDataUserInfo uninstallDataUserInfo;
    uninstallDataUserInfo.uid = 20020033;
    UninstallBundleInfo uninstallBundleInfo;
    uninstallBundleInfo.bundleType = BundleType::ATOMIC_SERVICE;
    uninstallBundleInfo.userInfos.emplace(std::make_pair(std::to_string(USERID), uninstallDataUserInfo));
    auto ret = dataMgr->UpdateUninstallBundleInfo(bundleName, uninstallBundleInfo);
    ASSERT_TRUE(ret);
    ErrCode res = dataMgr->BatchGetBundleStats(bundleNames, USERID, bundleStats);
    EXPECT_EQ(res, ERR_OK);
    dataMgr->DeleteUninstallBundleInfo(bundleName, USERID);
    dataMgr->multiUserIdsSet_.erase(USERID);
}

/**
 * @tc.number: GetPreBundleSize_0010
 * @tc.name: test GetPreBundleSize
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleDataMgrTest, GetPreBundleSize_0010, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::string bundleName = "com.test.GetPreBundleSize_0010";
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);

    std::vector<BundleStorageStats> bundleStats;
    BundleStorageStats stats;
    stats.bundleName = bundleName;
    stats.bundleStats = {0, 0, 0, 0, 0};
    // index 0 : bundle data size
    stats.bundleStats[0] = 1;
    // index 1 : local bundle data size
    stats.bundleStats[1] = 2;
    bundleStats.emplace_back(stats);

    dataMgr->GetPreBundleSize(bundleName, bundleStats);
    auto statsIter = std::find_if(bundleStats.begin(), bundleStats.end(),
        [&bundleName](const BundleStorageStats &stats) { return stats.bundleName == bundleName; });
    EXPECT_EQ(statsIter->bundleStats[0], 1);
    dataMgr->bundleInfos_.erase(bundleName);

    dataMgr->GetPreBundleSize(bundleName, bundleStats);
    statsIter = std::find_if(bundleStats.begin(), bundleStats.end(),
        [&bundleName](const BundleStorageStats &stats) { return stats.bundleName == bundleName; });
    EXPECT_EQ(statsIter->bundleStats[0], 1);
}

/**
 * @tc.number: UninstallBundleInfo_1000
 * @tc.name: test update and get mdulenames in UninstallBundleInfo
 * @tc.desc: 1.Test the UpdateUninstallBundleInfo by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, UninstallBundleInfo_1000, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::vector<BundleStorageStats> bundleStats;
    std::string bundleName = "com.example.UninstallBundleInfo_1000";
    // test bundlename not in bundleinfos_ and uninstalled withkeepdata before
    dataMgr->multiUserIdsSet_.insert(USERID);
    UninstallDataUserInfo uninstallDataUserInfo;
    UninstallBundleInfo uninstallBundleInfo;
    uninstallBundleInfo.userInfos.emplace(std::make_pair(std::to_string(USERID), uninstallDataUserInfo));
    uninstallBundleInfo.moduleNames.push_back("module1");
    auto ret = dataMgr->UpdateUninstallBundleInfo(bundleName, uninstallBundleInfo);
    ASSERT_TRUE(ret);
    UninstallBundleInfo uninstallBundleInfo2;
    dataMgr->GetUninstallBundleInfo(bundleName, uninstallBundleInfo2);
    EXPECT_EQ(uninstallBundleInfo2.moduleNames.empty(), false);
    dataMgr->DeleteUninstallBundleInfo(bundleName, USERID);
    dataMgr->multiUserIdsSet_.erase(USERID);
}

/**
 * @tc.number: UninstallBundleInfo_2000
 * @tc.name: test GetUninstallBundleInfoWithUserAndAppIndex
 * @tc.desc: 1.Test the GetUninstallBundleInfoWithUserAndAppIndex by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, UninstallBundleInfo_2000, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto bundleDataMgr = GetBundleDataMgr();
    EXPECT_NE(bundleDataMgr, nullptr);

    std::string bundleName = "com.example.UninstallBundleInfo_2000";
    bundleDataMgr->uninstallDataMgr_ = nullptr;
    auto ret = bundleDataMgr->GetUninstallBundleInfoWithUserAndAppIndex(bundleName, USERID, 1);
    EXPECT_FALSE(ret);

    bundleDataMgr->uninstallDataMgr_ = std::make_shared<UninstallDataMgrStorageRdb>();
    EXPECT_NE(bundleDataMgr->uninstallDataMgr_, nullptr);
}
 
/**
 * @tc.number: UninstallBundleInfo_3000
 * @tc.name: test GetUninstallBundleInfoWithUserAndAppIndex
 * @tc.desc: 1.Test the GetUninstallBundleInfoWithUserAndAppIndex by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, UninstallBundleInfo_3000, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::vector<BundleStorageStats> bundleStats;
    std::string bundleName = "com.example.UninstallBundleInfo_3000";
    dataMgr->RemoveUninstalledBundleinfos(USERID);

    // test bundleName is empty
    auto ret = dataMgr->GetUninstallBundleInfoWithUserAndAppIndex("", USERID, 1);
    EXPECT_FALSE(ret);

    // test bundleName not unisntalled with keepdata
    ret = dataMgr->GetUninstallBundleInfoWithUserAndAppIndex(bundleName, USERID, 1);
    EXPECT_FALSE(ret);

    // test bundlename uninstalled withkeepdata before
    dataMgr->multiUserIdsSet_.insert(USERID);
    UninstallDataUserInfo uninstallDataUserInfo;
    UninstallBundleInfo uninstallBundleInfo;
    uninstallBundleInfo.userInfos.emplace(std::make_pair(std::to_string(USERID), uninstallDataUserInfo));
    uninstallBundleInfo.moduleNames.push_back("module1");

    UninstallDataUserInfo uninstallDataUserInfo1;
    uninstallDataUserInfo1.uid = 20020034;
    std::string cloneInfoKey = std::to_string(USERID) + '_' + std::to_string(1);
    uninstallBundleInfo.userInfos.emplace(std::make_pair(cloneInfoKey, uninstallDataUserInfo1));

    UninstallDataUserInfo uninstallDataUserInfo2;
    uninstallDataUserInfo2.uid = -1;
    cloneInfoKey = std::to_string(USERID) + '_' + std::to_string(2);
    uninstallBundleInfo.userInfos.emplace(std::make_pair(cloneInfoKey, uninstallDataUserInfo2));

    ret = dataMgr->UpdateUninstallBundleInfo(bundleName, uninstallBundleInfo);
    ASSERT_TRUE(ret);

    // test uid is invlaid
    ret = dataMgr->GetUninstallBundleInfoWithUserAndAppIndex(bundleName, USERID, 2);
    EXPECT_FALSE(ret);

    ret = dataMgr->GetUninstallBundleInfoWithUserAndAppIndex(bundleName, USERID, 1);
    EXPECT_TRUE(ret);

    dataMgr->RemoveUninstalledBundleinfos(USERID);
    dataMgr->multiUserIdsSet_.erase(USERID);
}
 
/**
 * @tc.number: IsBundleExistedOrUninstalledWithKeepData_0100
 * @tc.name: test IsBundleExistedOrUninstalledWithKeepData
 * @tc.desc: 1.judge bundle exist in oh
 */
HWTEST_F(BmsBundleDataMgrTest, IsBundleExistedOrUninstalledWithKeepData_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "com.test.IsBundleExistedOrUninstalledWithKeepData_0100";

    // test bundle not in bundleinfos and not unisntalled with keepdata before
    bool ret = bundleMgrHostImpl_->IsBundleExistedOrUninstalledWithKeepData(bundleName, USERID, 1);
    EXPECT_EQ(ret, false);

    // test bundlename uninstalled with keepdata before
    dataMgr->multiUserIdsSet_.insert(USERID);
    UninstallDataUserInfo uninstallDataUserInfo;
    UninstallBundleInfo uninstallBundleInfo;
    uninstallBundleInfo.userInfos.emplace(std::make_pair(std::to_string(USERID), uninstallDataUserInfo));
    uninstallBundleInfo.moduleNames.push_back("module1");

    UninstallDataUserInfo uninstallDataUserInfo1;
    uninstallDataUserInfo1.uid = 20020034;
    std::string cloneInfoKey = std::to_string(USERID) + '_' + std::to_string(1);
    uninstallBundleInfo.userInfos.emplace(std::make_pair(cloneInfoKey, uninstallDataUserInfo1));
    ret = dataMgr->UpdateUninstallBundleInfo(bundleName, uninstallBundleInfo);
    ASSERT_TRUE(ret);

    ret = bundleMgrHostImpl_->IsBundleExistedOrUninstalledWithKeepData(bundleName, USERID, 3);
    EXPECT_EQ(ret, false);

    ret = bundleMgrHostImpl_->IsBundleExistedOrUninstalledWithKeepData(bundleName, USERID, 1);
    EXPECT_EQ(ret, true);

    // test bundle in bundleinfos

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;

    InnerBundleCloneInfo innerBundleCloneInfo;
    innerBundleCloneInfo.userId = USERID;
    innerBundleCloneInfo.appIndex = 1;
    innerBundleCloneInfo.uid = TEST_UID;

    InnerBundleCloneInfo innerBundleCloneInfo2;
    innerBundleCloneInfo2.userId = USERID;
    innerBundleCloneInfo2.appIndex = 2;
    innerBundleCloneInfo2.uid = -1;

    std::string appIndexKey = std::to_string(innerBundleCloneInfo.appIndex);
    innerBundleUserInfo.cloneInfos.insert(make_pair(appIndexKey, innerBundleCloneInfo));
    appIndexKey = std::to_string(innerBundleCloneInfo2.appIndex);
    innerBundleUserInfo.cloneInfos.insert(make_pair(appIndexKey, innerBundleCloneInfo2));
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);

    ret = bundleMgrHostImpl_->IsBundleExistedOrUninstalledWithKeepData(bundleName, USERID, 1);
    EXPECT_EQ(ret, true);

    dataMgr->RemoveUninstalledBundleinfos(USERID);
    dataMgr->RemoveUninstalledBundleinfos(MULTI_USERID);
    dataMgr->multiUserIdsSet_.erase(USERID);
}

/**
* @tc.number: GetTestRunner_0300
* @tc.name: GetTestRunner_0300
* @tc.desc: test GetTestRunner
*/
HWTEST_F(BmsBundleDataMgrTest, GetTestRunner_0300, Function | MediumTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    ModuleTestRunner testRunner;
    ErrCode ret = GetBundleDataMgr()->GetTestRunner(BUNDLE_NAME_TEST, MODULE_NAME_TEST, testRunner);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_UNEXPECTED);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: HandleGetPluginBundlePathForSelf_0100
 * @tc.name: HandleGetPluginBundlePathForSelf_0100
 * @tc.desc: test BundleMgrHostHandleGetPluginBundlePathForSelf(MessageParcel &data, MessageParcel &reply)
 */
HWTEST_F(BmsBundleDataMgrTest, HandleGetPluginBundlePathForSelf_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHost> localBundleMgrHost = std::make_shared<BundleMgrHost>();
    ASSERT_NE(localBundleMgrHost, nullptr);

    MessageParcel data;
    MessageParcel reply;

    auto ret = localBundleMgrHost->HandleGetPluginBundlePathForSelf(data, reply);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AddInstallingBundleName_0100
 * @tc.name: test AddInstallingBundleName
 * @tc.desc: 1.system run normally
 *           2.check AddInstallingBundleName failed
 */
HWTEST_F(BmsBundleDataMgrTest, AddInstallingBundleName_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        BundleInstallStatus status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U100, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_NOT_EXIST);
        InnerBundleInfo innerBundleInfo;
        dataMgr->bundleInfos_[BUNDLE_TEST1] = innerBundleInfo;
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U100, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_NOT_EXIST);

        InnerBundleUserInfo innerBundleUserInfo;
        innerBundleUserInfo.bundleUserInfo.userId = TEST_U200;
        innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
        dataMgr->bundleInfos_[BUNDLE_TEST1] = innerBundleInfo;
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U100, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_NOT_EXIST);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, -1, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_NOT_EXIST);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, Constants::ANY_USERID, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLED);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U200, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLED);
        dataMgr->bundleInfos_.erase(BUNDLE_TEST1);
    }
}

/**
 * @tc.number: AddInstallingBundleName_0200
 * @tc.name: test AddInstallingBundleName
 * @tc.desc: 1.system run normally
 *           2.check AddInstallingBundleName failed
 */
HWTEST_F(BmsBundleDataMgrTest, AddInstallingBundleName_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        InnerBundleInfo innerBundleInfo;
        InnerBundleUserInfo innerBundleUserInfo;
        innerBundleUserInfo.bundleUserInfo.userId = 0;
        innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
        dataMgr->bundleInfos_[BUNDLE_TEST1] = innerBundleInfo;
        BundleInstallStatus status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U100, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLED);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U1, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_NOT_EXIST);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, 0, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLED);

        innerBundleInfo.innerBundleUserInfos_.clear();
        innerBundleUserInfo.bundleUserInfo.userId = TEST_U1;
        innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
        dataMgr->bundleInfos_[BUNDLE_TEST1] = innerBundleInfo;
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U100, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLED);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, 0, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_NOT_EXIST);
        dataMgr->bundleInfos_.erase(BUNDLE_TEST1);
    }
}

/**
 * @tc.number: GetProfilePath_0001
 * @tc.name: test GetProfilePath
 * @tc.desc: 1.system run normally
 *           2.test GetProfilePath
 */
HWTEST_F(BmsBundleDataMgrTest, GetProfilePath_0001, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        InnerModuleInfo innerModuleInfo;
        std::string res;
        res = dataMgr->GetProfilePath(ProfileType::EASY_GO_PROFILE, innerModuleInfo);
        EXPECT_TRUE(res.empty());
        innerModuleInfo.isEntry = true;
        res = dataMgr->GetProfilePath(ProfileType::EASY_GO_PROFILE, innerModuleInfo);
        EXPECT_TRUE(res.empty());
        res = dataMgr->GetProfilePath(static_cast<ProfileType>(-1), innerModuleInfo);
        EXPECT_TRUE(res.empty());
    }
}

/**
 * @tc.number: GetProfilePath_0002
 * @tc.name: test GetProfilePath
 * @tc.desc: 1.system run normally
 *           2.test GetProfilePath
 */
HWTEST_F(BmsBundleDataMgrTest, GetProfilePath_0002, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        InnerModuleInfo innerModuleInfo;
        std::string res;
        innerModuleInfo.isEntry = true;
        innerModuleInfo.easyGo = "$profile:easy_go";
        res = dataMgr->GetProfilePath(ProfileType::EASY_GO_PROFILE, innerModuleInfo);
        EXPECT_EQ(res, "resources/base/profile/easy_go.json");
    }
}

/**
 * @tc.number: GetProfilePath_0003
 * @tc.name: test GetProfilePath
 * @tc.desc: 1.system run normally
 *           2.test GetProfilePath
 */
HWTEST_F(BmsBundleDataMgrTest, GetProfilePath_0003, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerModuleInfo innerModuleInfo;
    std::string res;
    innerModuleInfo.isEntry = true;
    innerModuleInfo.shareFiles = "$profile:share_files";
    res = dataMgr->GetProfilePath(ProfileType::SHARE_FILES_PROFILE, innerModuleInfo);
    EXPECT_EQ(res, "resources/base/profile/share_files.json");

    innerModuleInfo.shareFiles = "$profile:share_files2";
    res = dataMgr->GetProfilePath(ProfileType::SHARE_FILES_PROFILE, innerModuleInfo);
    EXPECT_EQ(res, "resources/base/profile/share_files2.json");

    res = dataMgr->GetProfilePath(ProfileType::ADDITION_PROFILE, innerModuleInfo);
    EXPECT_EQ(res, "");

    innerModuleInfo.shareFiles = "";
    res = dataMgr->GetProfilePath(ProfileType::SHARE_FILES_PROFILE, innerModuleInfo);
    EXPECT_EQ(res, "");

    innerModuleInfo.shareFiles = "not-profile-path";
    res = dataMgr->GetProfilePath(ProfileType::SHARE_FILES_PROFILE, innerModuleInfo);
    EXPECT_EQ(res, "");

    innerModuleInfo.isEntry = false;
    innerModuleInfo.shareFiles = "$profile:share_files";
    res = dataMgr->GetProfilePath(ProfileType::SHARE_FILES_PROFILE, innerModuleInfo);
    EXPECT_EQ(res, "");
}

/**
 * @tc.number: GetProfileDataList_0001
 * @tc.name: test GetProfilePath
 * @tc.desc: 1.system run normally
 *           2.test GetProfilePath
 */
HWTEST_F(BmsBundleDataMgrTest, GetProfileDataList_0001, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        std::vector<BundleProfileData> profileDataList;
        int32_t userId = 100;
        dataMgr->GetProfileDataList(ProfileType::EASY_GO_PROFILE, userId, profileDataList);
        EXPECT_TRUE(profileDataList.empty());
    }
}

/**
 * @tc.number: GetProfileDataList_0002
 * @tc.name: test GetProfilePath
 * @tc.desc: 1.system run normally
 *           2.test GetProfilePath
 */
HWTEST_F(BmsBundleDataMgrTest, GetProfileDataList_0002, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        InnerBundleInfo innerBundleInfo;
        ApplicationInfo applicationInfo;
        innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
        GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
        std::vector<BundleProfileData> profileDataList;
        int32_t userId = 100;
        dataMgr->GetProfileDataList(ProfileType::EASY_GO_PROFILE, userId, profileDataList);
        EXPECT_TRUE(profileDataList.empty());
    }
}

/**
 * @tc.number: GetProfileDataList_0003
 * @tc.name: test GetProfilePath
 * @tc.desc: 1.system run normally
 *           2.test GetProfilePath
 */
HWTEST_F(BmsBundleDataMgrTest, GetProfileDataList_0003, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        InnerBundleInfo innerBundleInfo;
        ApplicationInfo applicationInfo;
        applicationInfo.bundleType = BundleType::SHARED;
        innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
        GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
        std::vector<BundleProfileData> profileDataList;
        int32_t userId = 100;
        dataMgr->GetProfileDataList(ProfileType::EASY_GO_PROFILE, userId, profileDataList);
        EXPECT_TRUE(profileDataList.empty());
    }
}

/**
 * @tc.number: GetProfileDataList_0004
 * @tc.name: test GetProfilePath
 * @tc.desc: 1.system run normally
 *           2.test GetProfilePath
 */
HWTEST_F(BmsBundleDataMgrTest, GetProfileDataList_0004, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        dataMgr->multiUserIdsSet_.insert(USERID);
        InnerBundleInfo innerBundleInfo;
        InnerBundleUserInfo innerBundleUserInfo;
        innerBundleUserInfo.bundleName = BUNDLE_TEST1;
        innerBundleUserInfo.bundleUserInfo.userId = USERID;
        innerBundleUserInfo.bundleUserInfo.enabled = true;
        innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
        GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
        std::vector<BundleProfileData> profileDataList;
        dataMgr->GetProfileDataList(ProfileType::EASY_GO_PROFILE, USERID, profileDataList);
        EXPECT_TRUE(profileDataList.empty());
        dataMgr->multiUserIdsSet_.erase(USERID);
    }
}

/**
 * @tc.number: GetProfileDataList_0005
 * @tc.name: test GetProfilePath
 * @tc.desc: 1.system run normally
 *           2.test GetProfilePath
 */
HWTEST_F(BmsBundleDataMgrTest, GetProfileDataList_0005, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        dataMgr->multiUserIdsSet_.insert(USERID);
        InnerBundleInfo innerBundleInfo;
        InnerBundleUserInfo innerBundleUserInfo;
        innerBundleUserInfo.bundleName = BUNDLE_TEST1;
        innerBundleUserInfo.bundleUserInfo.userId = USERID;
        innerBundleUserInfo.bundleUserInfo.enabled = false;
        innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
        GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
        std::vector<BundleProfileData> profileDataList;
        dataMgr->GetProfileDataList(ProfileType::EASY_GO_PROFILE, USERID, profileDataList);
        EXPECT_TRUE(profileDataList.empty());
        dataMgr->multiUserIdsSet_.erase(USERID);
    }
}

/**
 * @tc.number: GetProfileDataList_0006
 * @tc.name: test GetProfileDataList
 * @tc.desc: 1.system run normally
 *           2.test GetProfileDataList
 */
HWTEST_F(BmsBundleDataMgrTest, GetProfileDataList_0006, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(USERID);
    dataMgr->bundleInfos_.erase(BUNDLE_TEST1);
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = BUNDLE_TEST1;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.SetApplicationBundleType(BundleType::APP);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = true;
    innerModuleInfo.shareFiles = "$profile:share_files";
    innerBundleInfo.innerModuleInfos_.emplace(MODULE_TEST, innerModuleInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    std::vector<BundleProfileData> profileDataList;
    dataMgr->GetProfileDataList(ProfileType::SHARE_FILES_PROFILE, USERID, profileDataList);
    EXPECT_EQ(profileDataList.size(), 1);
    dataMgr->multiUserIdsSet_.erase(USERID);
    dataMgr->bundleInfos_.erase(BUNDLE_TEST1);
}

/**
 * @tc.number: GetProfileDataList_0007
 * @tc.name: test GetProfileDataList
 * @tc.desc: 1.system run normally
 *           2.test GetProfileDataList
 */
HWTEST_F(BmsBundleDataMgrTest, GetProfileDataList_0007, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(USERID);
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = BUNDLE_TEST1;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    innerBundleUserInfo.bundleUserInfo.enabled = false;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.SetApplicationBundleType(BundleType::APP);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = true;
    innerModuleInfo.shareFiles = "$profile:share_files";
    innerBundleInfo.innerModuleInfos_.emplace(MODULE_TEST, innerModuleInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    std::vector<BundleProfileData> profileDataList;
    dataMgr->GetProfileDataList(ProfileType::SHARE_FILES_PROFILE, USERID, profileDataList);
    EXPECT_EQ(profileDataList.size(), 0);
    dataMgr->multiUserIdsSet_.erase(USERID);
    dataMgr->bundleInfos_.erase(BUNDLE_TEST1);
}

/**
 * @tc.number: GetProfileDataList_0008
 * @tc.name: test GetProfileDataList
 * @tc.desc: 1.system run normally
 *           2.test GetProfileDataList
 */
HWTEST_F(BmsBundleDataMgrTest, GetProfileDataList_0008, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(USERID);
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = BUNDLE_TEST1;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    innerBundleUserInfo.bundleUserInfo.enabled = false;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.SetApplicationBundleType(BundleType::SHARED);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = true;
    innerModuleInfo.shareFiles = "$profile:share_files";
    innerBundleInfo.innerModuleInfos_.emplace(MODULE_TEST, innerModuleInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    std::vector<BundleProfileData> profileDataList;
    dataMgr->GetProfileDataList(ProfileType::SHARE_FILES_PROFILE, USERID, profileDataList);
    EXPECT_EQ(profileDataList.size(), 0);
    dataMgr->multiUserIdsSet_.erase(USERID);
    dataMgr->bundleInfos_.erase(BUNDLE_TEST1);
}

/**
 * @tc.number: GetProfileDataList_0009
 * @tc.name: test GetProfileDataList
 * @tc.desc: 1.system run normally
 *           2.test GetProfileDataList
 */
HWTEST_F(BmsBundleDataMgrTest, GetProfileDataList_0009, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(USERID);
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = BUNDLE_TEST1;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    innerBundleUserInfo.bundleUserInfo.enabled = false;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.SetApplicationBundleType(BundleType::SHARED);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = false;
    innerModuleInfo.shareFiles = "$profile:share_files";
    innerBundleInfo.innerModuleInfos_.emplace(MODULE_TEST, innerModuleInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    std::vector<BundleProfileData> profileDataList;
    dataMgr->GetProfileDataList(ProfileType::SHARE_FILES_PROFILE, USERID, profileDataList);
    EXPECT_EQ(profileDataList.size(), 0);
    dataMgr->multiUserIdsSet_.erase(USERID);
    dataMgr->bundleInfos_.erase(BUNDLE_TEST1);
}

/**
 * @tc.number: GetAllJsonProfile_0001
 * @tc.name: test GetAllJsonProfile
 * @tc.desc: 1.system run normally
 *           2.test GetAllJsonProfile
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllJsonProfile_0001, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        std::vector<JsonProfileInfo> profileInfos;
        auto ret1 = dataMgr->GetAllJsonProfile(ProfileType::EASY_GO_PROFILE, -1, profileInfos);
        EXPECT_NE(ret1, ERR_OK);

        auto ret2 = dataMgr->GetAllJsonProfile(ProfileType::UNSPECIFIED_PROFILE, Constants::ALL_USERID, profileInfos);
        EXPECT_NE(ret2, ERR_OK);
    }
}

/**
 * @tc.number: GetAllJsonProfile_0002
 * @tc.name: test GetAllJsonProfile
 * @tc.desc: 1.system run normally
 *           2.test GetAllJsonProfile
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllJsonProfile_0002, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(USERID);
    std::vector<JsonProfileInfo> profileInfos;
    auto ret = dataMgr->GetAllJsonProfile(ProfileType::SHARE_FILES_PROFILE, -1, profileInfos);
    EXPECT_NE(ret, ERR_OK);
    ret = dataMgr->GetAllJsonProfile(ProfileType::UNSPECIFIED_PROFILE, 100, profileInfos);
    EXPECT_NE(ret, ERR_OK);
    ret = dataMgr->GetAllJsonProfile(ProfileType::SHARE_FILES_PROFILE, 100, profileInfos);
    EXPECT_EQ(ret, ERR_OK);
    dataMgr->multiUserIdsSet_.erase(USERID);
}

/**
 * @tc.number: GetInnerModuleInfoForEntry_0001
 * @tc.name: test GetInnerModuleInfoForEntry
 * @tc.desc: 1.system run normally
 *           2.test GetInnerModuleInfoForEntry
 */
HWTEST_F(BmsBundleDataMgrTest, GetInnerModuleInfoForEntry_0001, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    auto ret = info.GetInnerModuleInfoForEntry();
    EXPECT_EQ(ret, std::nullopt);
}

/**
 * @tc.number: GetInnerModuleInfoForEntry_0002
 * @tc.name: test GetInnerModuleInfoForEntry
 * @tc.desc: 1.system run normally
 *           2.test GetInnerModuleInfoForEntry
 */
HWTEST_F(BmsBundleDataMgrTest, GetInnerModuleInfoForEntry_0002, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    InnerModuleInfo moduleInfo;
    moduleInfo.isEntry = true;
    info.innerModuleInfos_.try_emplace("entry", moduleInfo);
    auto ret = info.GetInnerModuleInfoForEntry();
    EXPECT_TRUE(ret->isEntry);
}

/**
 * @tc.number: AddInstallingBundleName_0300
 * @tc.name: test AddInstallingBundleName
 * @tc.desc: 1.system run normally
 *           2.check AddInstallingBundleName failed
 */
HWTEST_F(BmsBundleDataMgrTest, AddInstallingBundleName_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        dataMgr->AddInstallingBundleName(BUNDLE_TEST1, TEST_U100);
        BundleInstallStatus status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U100, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLING);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U200, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_NOT_EXIST);
        dataMgr->DeleteInstallingBundleName(BUNDLE_TEST1, TEST_U100);

        dataMgr->AddInstallingBundleName(BUNDLE_TEST1, 0);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, 0, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLING);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U1, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLING);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U100, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLING);
        dataMgr->DeleteInstallingBundleName(BUNDLE_TEST1, 0);

        dataMgr->AddInstallingBundleName(BUNDLE_TEST1, TEST_U1);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, 0, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLING);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U1, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLING);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U100, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLING);
        dataMgr->DeleteInstallingBundleName(BUNDLE_TEST1, TEST_U1);
    }
}

/**
 * @tc.number: DeleteInstallingBundleName_0100
 * @tc.name: test DeleteInstallingBundleName
 * @tc.desc: 1.system run normally
 *           2.check DeleteInstallingBundleName failed
 */
HWTEST_F(BmsBundleDataMgrTest, DeleteInstallingBundleName_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        dataMgr->installingBundleNames_.erase(BUNDLE_TEST1);
        BundleInstallStatus status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U100, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_NOT_EXIST);

        dataMgr->AddInstallingBundleName(BUNDLE_TEST1, TEST_U100);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U100, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLING);

        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U200, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_NOT_EXIST);

        dataMgr->DeleteInstallingBundleName(BUNDLE_TEST1, TEST_U100);
        dataMgr->AddInstallingBundleName(BUNDLE_TEST1, TEST_U1);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U1, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLING);

        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U100, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLING);

        dataMgr->DeleteInstallingBundleName(BUNDLE_TEST1, TEST_U1);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U1, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_NOT_EXIST);

        dataMgr->AddInstallingBundleName(BUNDLE_TEST1, 0);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U100, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_INSTALLING);

        dataMgr->DeleteInstallingBundleName(BUNDLE_TEST1, 0);
        status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST1, TEST_U100, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_NOT_EXIST);
        dataMgr->installingBundleNames_.erase(BUNDLE_TEST1);
    }
}

/**
 * @tc.number: DeleteInstallingBundleName_0200
 * @tc.name: test DeleteInstallingBundleName
 * @tc.desc: 1.system run normally
 *           2.check DeleteInstallingBundleName
 */
HWTEST_F(BmsBundleDataMgrTest, DeleteInstallingBundleName_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        dataMgr->DeleteInstallingBundleName(BUNDLE_TEST2, TEST_U100);
        BundleInstallStatus status = BundleInstallStatus::UNKNOWN_STATUS;
        dataMgr->GetBundleInstallStatus(BUNDLE_TEST2, TEST_U100, status);
        EXPECT_EQ(status, BundleInstallStatus::BUNDLE_NOT_EXIST);
    }
}

/**
 * @tc.number: ProcessAllowedAcls_0100
 * @tc.name: test ProcessAllowedAcls
 * @tc.desc: 1.system run normally
 *           2.check ProcessAllowedAcls
 */
HWTEST_F(BmsBundleDataMgrTest, ProcessAllowedAcls_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        InnerBundleInfo oldInfo;
        oldInfo.baseBundleInfo_->versionCode = 1000;
        std::vector<std::string> acls;
        acls.push_back("aaa");
        acls.push_back("bbb");
        oldInfo.allowedAcls_ = acls;
        InnerBundleInfo newInfo;
        newInfo.baseBundleInfo_->versionCode = 2000;
        dataMgr->ProcessAllowedAcls(newInfo, oldInfo);
        EXPECT_TRUE(oldInfo.GetAllowedAcls().empty());
    }
}

/**
 * @tc.number: ProcessAllowedAcls_0200
 * @tc.name: test ProcessAllowedAcls
 * @tc.desc: 1.system run normally
 *           2.check ProcessAllowedAcls
 */
HWTEST_F(BmsBundleDataMgrTest, ProcessAllowedAcls_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        InnerBundleInfo oldInfo;
        oldInfo.baseBundleInfo_->versionCode = 1000;
        InnerBundleInfo newInfo;
        newInfo.baseBundleInfo_->versionCode = 1000;
        std::vector<std::string> acls;
        acls.push_back("aaa");
        acls.push_back("bbb");
        newInfo.allowedAcls_ = acls;
        dataMgr->ProcessAllowedAcls(newInfo, oldInfo);
        EXPECT_FALSE(oldInfo.GetAllowedAcls().empty());
    }
}

/**
 * @tc.number: IsUpdateInnerBundleInfoSatisified_0100
 * @tc.name: test IsUpdateInnerBundleInfoSatisified
 * @tc.desc: 1.system run normally
 *           2.check IsUpdateInnerBundleInfoSatisified
 */
HWTEST_F(BmsBundleDataMgrTest, IsUpdateInnerBundleInfoSatisified_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        InnerBundleInfo oldInfo;
        oldInfo.SetApplicationBundleType(BundleType::ATOMIC_SERVICE);
        InnerModuleInfo moduleInfo;
        moduleInfo.isEntry = true;
        oldInfo.innerModuleInfos_[BUNDLE_NAME_TEST] = moduleInfo;
        oldInfo.baseBundleInfo_->versionCode = 1000;
        InnerBundleInfo newInfo;
        newInfo.baseBundleInfo_->versionCode = 1000;
        bool ret = dataMgr->IsUpdateInnerBundleInfoSatisified(oldInfo, newInfo);
        EXPECT_FALSE(ret);
        newInfo.baseBundleInfo_->versionCode = 2000;
        ret = dataMgr->IsUpdateInnerBundleInfoSatisified(oldInfo, newInfo);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: IsUpdateInnerBundleInfoSatisified_0200
 * @tc.name: test IsUpdateInnerBundleInfoSatisified
 * @tc.desc: 1.system run normally
 *           2.check IsUpdateInnerBundleInfoSatisified
 */
HWTEST_F(BmsBundleDataMgrTest, IsUpdateInnerBundleInfoSatisified_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        InnerBundleInfo oldInfo;
        InnerBundleInfo newInfo;
        newInfo.SetApplicationBundleType(BundleType::APP_SERVICE_FWK);
        bool ret = dataMgr->IsUpdateInnerBundleInfoSatisified(oldInfo, newInfo);
        EXPECT_TRUE(ret);
        newInfo.SetApplicationBundleType(BundleType::APP);
        ret = dataMgr->IsUpdateInnerBundleInfoSatisified(oldInfo, newInfo);
        EXPECT_TRUE(ret);
        InnerModuleInfo moduleInfo;
        moduleInfo.isEntry = true;
        newInfo.innerModuleInfos_[BUNDLE_NAME_TEST] = moduleInfo;
        oldInfo.innerModuleInfos_[BUNDLE_NAME_TEST] = moduleInfo;
        ret = dataMgr->IsUpdateInnerBundleInfoSatisified(oldInfo, newInfo);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: BackupBundleData_0100
 * @tc.name: BackupBundleData
 * @tc.desc: test BackupBundleData of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, BackupBundleData_0100, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    EXPECT_NE(bmsExtensionClient, nullptr);

    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    std::string bundleName = BUNDLE_NAME_TEST;
    int32_t userId = 100;
    int32_t appIndex = 0;
    auto ret = bmsExtensionClient->BackupBundleData(bundleName, userId, appIndex);
    EXPECT_NE(ret, ERR_OK);

    bmsExtensionClient->bmsExtensionImpl_ = std::make_shared<BmsExtensionDataMgr>();
    ret = bmsExtensionClient->BackupBundleData(bundleName, userId, appIndex);
    #ifdef USE_EXTENSION_DATA
    EXPECT_EQ(ret, ERR_OK);
    #else
    EXPECT_NE(ret, ERR_OK);
    #endif
}

/**
 * @tc.number: RecoverBackupBundleData_0100
 * @tc.name: RecoverBackupBundleData
 * @tc.desc: test RecoverBackupBundleData of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, RecoverBackupBundleData_0100, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    EXPECT_NE(bmsExtensionClient, nullptr);

    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    std::string bundleName = BUNDLE_NAME_TEST;
    int32_t userId = 100;
    int32_t appIndex = 0;
    auto ret = bmsExtensionClient->RecoverBackupBundleData(bundleName, userId, appIndex);
    EXPECT_NE(ret, ERR_OK);

    bmsExtensionClient->bmsExtensionImpl_ = std::make_shared<BmsExtensionDataMgr>();
    ret = bmsExtensionClient->RecoverBackupBundleData(bundleName, userId, appIndex);
    #ifdef USE_EXTENSION_DATA
    EXPECT_EQ(ret, ERR_OK);
    #else
    EXPECT_NE(ret, ERR_OK);
    #endif
}

/**
 * @tc.number: RemoveBackupBundleData_0100
 * @tc.name: RemoveBackupBundleData
 * @tc.desc: test RemoveBackupBundleData of BmsExtensionClient
 */
HWTEST_F(BmsBundleDataMgrTest, RemoveBackupBundleData_0100, Function | MediumTest | Level1)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    EXPECT_NE(bmsExtensionClient, nullptr);

    bmsExtensionClient->bmsExtensionImpl_ = nullptr;
    std::string bundleName = BUNDLE_NAME_TEST;
    int32_t userId = 100;
    int32_t appIndex = 0;
    auto ret = bmsExtensionClient->RemoveBackupBundleData(bundleName, userId, appIndex);
    EXPECT_NE(ret, ERR_OK);

    bmsExtensionClient->bmsExtensionImpl_ = std::make_shared<BmsExtensionDataMgr>();
    ret = bmsExtensionClient->RemoveBackupBundleData(bundleName, userId, appIndex);
    #ifdef USE_EXTENSION_DATA
    EXPECT_EQ(ret, ERR_OK);
    #else
    EXPECT_NE(ret, ERR_OK);
    #endif
}

/**
 * @tc.number: CreateAppGroupDir_0100
 * @tc.name: CreateAppGroupDir
 * @tc.desc: test CreateAppGroupDir
 */
HWTEST_F(BmsBundleDataMgrTest, CreateAppGroupDir_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::unordered_map<std::string, std::vector<DataGroupInfo>> dataGroupInfoMap;
    int32_t userId = 100;
    bool needCreateEl5Dir = true;
    DataDirEl dirEl = DataDirEl::EL5;
    auto ret = dataMgr->CreateAppGroupDir(dataGroupInfoMap, userId, needCreateEl5Dir, dirEl);
    EXPECT_TRUE(ret);

    DataGroupInfo groupInfo;
    groupInfo.userId = 100;
    groupInfo.dataGroupId = "123";
    groupInfo.uuid = "321";
    ret = dataMgr->CreateAppGroupDir(dataGroupInfoMap, userId, needCreateEl5Dir, dirEl);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetBundleNameList_0100
 * @tc.name: test GetBundleNameList empty result
 * @tc.desc: 1.Empty result when no matching bundles
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleNameList_0100, Function | SmallTest | Level1)
{
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->bundleInfos_.clear();

    std::vector<std::string> bundleNameList;
    GetBundleDataMgr()->GetBundleNameList(USERID, bundleNameList);

    EXPECT_TRUE(bundleNameList.empty());
}

/**
 * @tc.number: GetBundleNameList_0200
 * @tc.name: test GetBundleNameList with invalid user permission
 * @tc.desc: 1.Bundle without user permission should be filtered out
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleNameList_0200, Function | SmallTest | Level1)
{
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->bundleInfos_.clear();

    InnerBundleInfo sharedBundleInfo;
    sharedBundleInfo.SetApplicationBundleType(BundleType::SHARED);
    InnerBundleUserInfo sharedUserInfo;
    sharedUserInfo.bundleUserInfo.userId = USERID;
    sharedBundleInfo.innerBundleUserInfos_.emplace(BUNDLE_TEST1, sharedUserInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, sharedBundleInfo);

    std::vector<std::string> bundleNameList;
    GetBundleDataMgr()->GetBundleNameList(USERID, bundleNameList);

    EXPECT_TRUE(bundleNameList.empty());
    
    GetBundleDataMgr()->bundleInfos_.clear();
}

/**
 * @tc.number: GetBundleNameList_0300
 * @tc.name: test GetBundleNameList filters APP bundle without user info
 * @tc.desc: 1.APP bundle without user information should be filtered out
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleNameList_0300, Function | SmallTest | Level1)
{
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->bundleInfos_.clear();

    InnerBundleInfo bundleInfo;
    bundleInfo.SetApplicationBundleType(BundleType::APP);

    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, bundleInfo);

    std::vector<std::string> bundleNameList;
    GetBundleDataMgr()->GetBundleNameList(USERID, bundleNameList);

    EXPECT_TRUE(bundleNameList.empty());
    
    GetBundleDataMgr()->bundleInfos_.clear();
}

/**
 * @tc.number: GetBundleNameList_0400
 * @tc.name: test GetBundleNameList with valid bundle
 * @tc.desc: 1.Valid APP bundle with user permission should be included
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleNameList_0400, Function | SmallTest | Level1)
{
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->bundleInfos_.clear();

    MockInstallBundle(BUNDLE_TEST1, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    BundleInfo bundleInfo;
    bool getRet = GetBundleDataMgr()->GetBundleInfo(BUNDLE_TEST1, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, USERID);
    EXPECT_TRUE(getRet);

    std::vector<std::string> bundleNameList;
    GetBundleDataMgr()->GetBundleNameList(USERID, bundleNameList);

    EXPECT_EQ(bundleNameList.size(), 1);
    EXPECT_EQ(bundleNameList[0], BUNDLE_TEST1);
    
    MockUninstallBundle(BUNDLE_TEST1);
}

/**
 * @tc.number: GetBundleNameList_0500
 * @tc.name: test GetBundleNameList mixed scenario
 * @tc.desc: 1.Test mixed scenario with SHARED, APP without user, and valid APP bundles
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleNameList_0500, Function | SmallTest | Level1)
{
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    GetBundleDataMgr()->bundleInfos_.clear();

    MockInstallBundle(BUNDLE_TEST1, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    InnerBundleInfo sharedBundle;
    sharedBundle.SetApplicationBundleType(BundleType::SHARED);
    InnerBundleUserInfo sharedUser;
    sharedUser.bundleUserInfo.userId = USERID;
    sharedBundle.innerBundleUserInfos_.emplace(BUNDLE_TEST2, sharedUser);

    ApplicationInfo sharedAppInfo;
    sharedAppInfo.bundleName = BUNDLE_TEST2;
    sharedBundle.SetBaseApplicationInfo(sharedAppInfo);
    
    BundleInfo sharedBundleInfo;
    sharedBundleInfo.name = BUNDLE_TEST2;
    sharedBundle.SetBaseBundleInfo(sharedBundleInfo);
    
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST2, sharedBundle);

    InnerBundleInfo noUserBundle;
    noUserBundle.SetApplicationBundleType(BundleType::APP);
    
    ApplicationInfo noUserAppInfo;
    noUserAppInfo.bundleName = BUNDLE_TEST3;
    noUserBundle.SetBaseApplicationInfo(noUserAppInfo);
    
    BundleInfo noUserBundleInfo;
    noUserBundleInfo.name = BUNDLE_TEST3;
    noUserBundle.SetBaseBundleInfo(noUserBundleInfo);
    
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST3, noUserBundle);

    std::vector<std::string> bundleNameList;
    GetBundleDataMgr()->GetBundleNameList(USERID, bundleNameList);

    EXPECT_EQ(bundleNameList.size(), 1);
    EXPECT_EQ(bundleNameList[0], BUNDLE_TEST1);

    MockUninstallBundle(BUNDLE_TEST1);
    GetBundleDataMgr()->bundleInfos_.clear();
}

/**
 * @tc.number: GetBundleNameList_0600
 * @tc.name: test GetBundleNameList with multiple valid bundles
 * @tc.desc: 1.Multiple valid APP bundles should all be included
 */
HWTEST_F(BmsBundleDataMgrTest, GetBundleNameList_0600, Function | SmallTest | Level1)
{
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);

    MockInstallBundle(BUNDLE_TEST1, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_TEST2, MODULE_NAME_TEST1, ABILITY_NAME_TEST1);

    std::vector<std::string> bundleNameList;
    GetBundleDataMgr()->GetBundleNameList(USERID, bundleNameList);

    EXPECT_EQ(bundleNameList.size(), 2);
    EXPECT_TRUE(std::find(bundleNameList.begin(), bundleNameList.end(), BUNDLE_TEST1) != bundleNameList.end());
    EXPECT_TRUE(std::find(bundleNameList.begin(), bundleNameList.end(), BUNDLE_TEST2) != bundleNameList.end());

    MockUninstallBundle(BUNDLE_TEST1);
    MockUninstallBundle(BUNDLE_TEST2);
}

/**
 * @tc.number: GetAllAppProvisionInfo_0100
 * @tc.name: test GetAllAppProvisionInfo
 * @tc.desc: 1.Test the GetAllAppProvisionInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllAppProvisionInfo_0100, Function | SmallTest | Level1)
{
    GetBundleDataMgr()->multiUserIdsSet_.clear();
    int32_t userId = 101;
    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = GetBundleDataMgr()->GetAllAppProvisionInfo(userId, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: GetAllAppProvisionInfo_0200
 * @tc.name: test GetAllAppProvisionInfo
 * @tc.desc: 1.Test the GetAllAppProvisionInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllAppProvisionInfo_0200, Function | SmallTest | Level1)
{
    GetBundleDataMgr()->bundleInfos_.clear();
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetApplicationBundleType(BundleType::SHARED);

    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    
    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = GetBundleDataMgr()->GetAllAppProvisionInfo(USERID, appProvisionInfos);
    EXPECT_TRUE(appProvisionInfos.empty());
    EXPECT_EQ(ret, ERR_OK);

    GetBundleDataMgr()->bundleInfos_.clear();
}

/**
 * @tc.number: GetAllAppProvisionInfo_0300
 * @tc.name: test GetAllAppProvisionInfo
 * @tc.desc: 1.Test the GetAllAppProvisionInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllAppProvisionInfo_0300, Function | SmallTest | Level1)
{
    GetBundleDataMgr()->multiUserIdsSet_.insert(USERID);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetApplicationBundleType(BundleType::APP);
    innerBundleInfo.innerBundleUserInfos_.clear();
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    int32_t userId = 100;
    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = GetBundleDataMgr()->GetAllAppProvisionInfo(userId, appProvisionInfos);
    EXPECT_TRUE(appProvisionInfos.empty());
    EXPECT_EQ(ret, ERR_OK);
    GetBundleDataMgr()->bundleInfos_.clear();
}

/**
 * @tc.number: GetAllAppProvisionInfo_0400
 * @tc.name: test GetAllAppProvisionInfo
 * @tc.desc: 1.Test the GetAllAppProvisionInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllAppProvisionInfo_0400, Function | SmallTest | Level1)
{
    GetBundleDataMgr()->multiUserIdsSet_.insert(Constants::ANY_USERID);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetApplicationBundleType(BundleType::APP);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = 100;
    innerBundleInfo.innerBundleUserInfos_.emplace(BUNDLE_TEST1, innerBundleUserInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    int32_t userId = Constants::ANY_USERID;
    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = GetBundleDataMgr()->GetAllAppProvisionInfo(userId, appProvisionInfos);
    EXPECT_TRUE(appProvisionInfos.empty());
    EXPECT_EQ(ret, ERR_OK);
    GetBundleDataMgr()->bundleInfos_.clear();
}

/**
 * @tc.number: GetAllAppProvisionInfo_0500
 * @tc.name: test GetAllAppProvisionInfo
 * @tc.desc: 1.Test the GetAllAppProvisionInfo by BundleMgrProxy success
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllAppProvisionInfo_0500, Function | SmallTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr) << "Failed to get SystemAbilityManager";
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    ASSERT_NE(remoteObject, nullptr) << "Failed to get Bundle Manager Service";
    std::shared_ptr<BundleMgrProxy> bundleMgrProxy = std::make_shared<BundleMgrProxy>(remoteObject);
    int32_t userId = USERID;
    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrProxy->GetAllAppProvisionInfo(userId, appProvisionInfos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetAllAppProvisionInfo_0600
 * @tc.name: test GetAllAppProvisionInfo
 * @tc.desc: 1.Test the GetAllAppProvisionInfo by BundleMgrProxy  failed due to invalid userid
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllAppProvisionInfo_0600, Function | SmallTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr) << "Failed to get SystemAbilityManager";
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    ASSERT_NE(remoteObject, nullptr) << "Failed to get Bundle Manager Service";
    std::shared_ptr<BundleMgrProxy> bundleMgrProxy = std::make_shared<BundleMgrProxy>(remoteObject);
    int32_t userId = ERROR_USERID;
    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrProxy->GetAllAppProvisionInfo(userId, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: InnerGetAllAppProvisionInfo_0100
 * @tc.name: test InnerGetAllAppProvisionInfo
 * @tc.desc: 1.Test the InnerGetAllAppProvisionInfo
 */
HWTEST_F(BmsBundleDataMgrTest, InnerGetAllAppProvisionInfo_0100, Function | SmallTest | Level1)
{
    BundleManagerHelper bundleManagerHelper;
    int32_t userId = USERID;
    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleManagerHelper.InnerGetAllAppProvisionInfo(userId, appProvisionInfos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InnerGetAllAppProvisionInfo_0200
 * @tc.name: test InnerGetAllAppProvisionInfo
 * @tc.desc: 1.Test the InnerGetAllAppProvisionInfo fail invalid userid
 */
HWTEST_F(BmsBundleDataMgrTest, InnerGetAllAppProvisionInfo_0200, Function | SmallTest | Level1)
{
    BundleManagerHelper bundleManagerHelper;
    int32_t userId = ERROR_USERID;
    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleManagerHelper.InnerGetAllAppProvisionInfo(userId, appProvisionInfos);
    EXPECT_EQ(ret, ERROR_INVALID_USER_ID);
}

/**
 * @tc.number: GetMultiAppModeTypeByBundleName_0100
 * @tc.name: test GetMultiAppModeTypeByBundleName
 * @tc.desc: 1.Test the GetMultiAppModeTypeByBundleName
 */
HWTEST_F(BmsBundleDataMgrTest, GetMultiAppModeTypeByBundleName_0100, Function | SmallTest | Level1)
{
    std::string testBundle5 = "com.test.bundle5";
    InnerBundleInfo innerBundleInfo5;
    innerBundleInfo5.SetApplicationBundleType(BundleType::APP);
    innerBundleInfo5.SetAppIdentifier("testAppIdentifier5");
    MultiAppModeData multiAppMode;
    multiAppMode.multiAppModeType = MultiAppModeType::MULTI_INSTANCE;
    multiAppMode.maxCount = 1;
    innerBundleInfo5.SetMultiAppMode(multiAppMode);
    InnerBundleUserInfo innerBundleUserInfo5;
    innerBundleUserInfo5.bundleUserInfo.userId = 100;
    innerBundleInfo5.innerBundleUserInfos_.emplace(testBundle5, innerBundleUserInfo5);
    GetBundleDataMgr()->bundleInfos_.emplace(testBundle5, innerBundleInfo5);

    MultiAppModeType installedBundleMultiAppModeType;
    bool ret = GetBundleDataMgr()->GetMultiAppModeTypeByBundleName(testBundle5, installedBundleMultiAppModeType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(installedBundleMultiAppModeType, MultiAppModeType::MULTI_INSTANCE);

    ret = GetBundleDataMgr()->GetMultiAppModeTypeByBundleName(
        "com.test.bundle.notexist", installedBundleMultiAppModeType);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: HandleDetermineCloneNumList_0100
 * @tc.name: test HandleDetermineCloneNumList
 * @tc.desc: 1.Test the HandleDetermineCloneNumList
 */
HWTEST_F(BmsBundleDataMgrTest, HandleDetermineCloneNumList_0100, Function | SmallTest | Level1)
{
    std::string testBundle3 = "com.test.bundle3";
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetApplicationBundleType(BundleType::APP);
    innerBundleInfo.SetAppIdentifier("testAppIdentifier4");
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = 100;
    innerBundleInfo.innerBundleUserInfos_.emplace(testBundle3, innerBundleUserInfo);
    GetBundleDataMgr()->bundleInfos_.emplace(testBundle3, innerBundleInfo);

    std::string testBundle5 = "com.test.bundle5";
    InnerBundleInfo innerBundleInfo5;
    innerBundleInfo5.SetApplicationBundleType(BundleType::APP);
    innerBundleInfo5.SetAppIdentifier("testAppIdentifier5");
    MultiAppModeData multiAppMode;
    multiAppMode.multiAppModeType = MultiAppModeType::MULTI_INSTANCE;
    multiAppMode.maxCount = 1;
    innerBundleInfo5.SetMultiAppMode(multiAppMode);
    InnerBundleUserInfo innerBundleUserInfo5;
    innerBundleUserInfo5.bundleUserInfo.userId = 100;
    innerBundleInfo5.innerBundleUserInfos_.emplace(testBundle5, innerBundleUserInfo5);
    GetBundleDataMgr()->bundleInfos_.emplace(testBundle5, innerBundleInfo5);

    std::vector<std::tuple<std::string, std::string, uint32_t>> determineCloneNumList = {
        {"", "testAppIdentifier1", 0},
        {"com.test.bundle2", "testAppIdentifier2", 0},
        {testBundle3, "testAppIdentifier3", 0},
        {testBundle3, "testAppIdentifier4", 1},
        {testBundle3, "testAppIdentifier4", 6},
        {testBundle3, "testAppIdentifier4", 2},
        {testBundle5, "testAppIdentifier5", 2}
    };
    ErrCode ret = GetBundleDataMgr()->HandleDetermineCloneNumList(determineCloneNumList);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetInnerBundleInfoNoLock_0100
 * @tc.name: GetInnerBundleInfoNoLock
 * @tc.desc: test GetInnerBundleInfoNoLock with nonexistent name
 */
HWTEST_F(BmsBundleDataMgrTest, GetInnerBundleInfoNoLock_0100, Function | SmallTest | Level1)
{
    std::string bundleName = "testBundleName";
    int32_t uid = USERID;
    int32_t appIndex = 0;
    const InnerBundleInfo* innerPtr = nullptr;
    ErrCode result = GetBundleDataMgr()->GetInnerBundleInfoNoLock(bundleName, uid, appIndex, innerPtr);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_UID);
}

/**
 * @tc.number: GetInnerBundleInfoNoLock_0200
 * @tc.name: GetInnerBundleInfoNoLock
 * @tc.desc: test GetInnerBundleInfoNoLock with error uid
 */
HWTEST_F(BmsBundleDataMgrTest, GetInnerBundleInfoNoLock_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    std::string bundleName = "testBundleName";
    int32_t uid = Constants::ALL_USERID;
    int32_t appIndex = 0;
    InnerBundleInfo innerBundleInfo;
    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);
    const InnerBundleInfo* innerPtr = &innerBundleInfo;
    ErrCode result = dataMgr->GetInnerBundleInfoNoLock(bundleName, uid, appIndex, innerPtr);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_UID);
}

/**
 * @tc.number: GetPluginExtensionInfo_0100
 * @tc.name: GetPluginExtensionInfo
 * @tc.desc: test bundle not exist
 */
HWTEST_F(BmsBundleDataMgrTest, GetPluginExtensionInfo_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    Want want;
    want.SetElementName("", BUNDLE_NAME_TEST, ABILITY_NAME_TEST, MODULE_NAME_TEST);
    ExtensionAbilityInfo extensionInfo;
    auto ret = dataMgr->GetPluginExtensionInfo("testBundle", want, USERID, extensionInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetPluginExtensionInfo_0200
 * @tc.name: GetPluginExtensionInfo
 * @tc.desc: test plugin not exist
 */
HWTEST_F(BmsBundleDataMgrTest, GetPluginExtensionInfo_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleType = BundleType::APP_PLUGIN;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    dataMgr->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);

    ExtensionAbilityInfo extensionInfo;
    Want want;
    want.SetElementName("", BUNDLE_NAME_TEST, ABILITY_NAME_TEST, MODULE_NAME_TEST);
    auto ret = dataMgr->GetPluginExtensionInfo(BUNDLE_TEST1, want, 111, extensionInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_NOT_FOUND);
    dataMgr->bundleInfos_.erase(BUNDLE_TEST1);
}

/**
 * @tc.number: GetPluginExtensionInfo_0300
 * @tc.name: GetPluginExtensionInfo
 * @tc.desc: test GetPluginExtensionInfo with wrong plugin name
 */
HWTEST_F(BmsBundleDataMgrTest, GetPluginExtensionInfo_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleType = BundleType::APP_PLUGIN;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    PluginBundleInfo pluginBundleInfo;
    pluginBundleInfo.pluginBundleName = "pluginBundleName";
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    innerBundleInfo.innerBundleUserInfos_["_100"] = userInfo;
    innerBundleInfo.AddPluginBundleInfo(pluginBundleInfo, USERID);
    EXPECT_EQ(innerBundleInfo.pluginBundleInfos_.size(), 1);
    dataMgr->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);

    ExtensionAbilityInfo extensionInfo;
    Want want;
    want.SetElementName("", BUNDLE_NAME_TEST, ABILITY_NAME_TEST, MODULE_NAME_TEST);
    auto ret = dataMgr->GetPluginExtensionInfo(BUNDLE_TEST1, want, USERID, extensionInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_NOT_FOUND);
    dataMgr->bundleInfos_.erase(BUNDLE_TEST1);
}

/**
 * @tc.number: GetPluginExtensionInfo_0400
 * @tc.name: GetPluginExtensionInfo
 * @tc.desc: test GetPluginExtensionInfo with wrong extension name
 */
HWTEST_F(BmsBundleDataMgrTest, GetPluginExtensionInfo_0400, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleType = BundleType::APP_PLUGIN;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    PluginBundleInfo pluginBundleInfo;
    ExtensionAbilityInfo extension;
    extension.name = "extension";
    extension.moduleName = MODULE_NAME_TEST;
    pluginBundleInfo.pluginBundleName = BUNDLE_TEST1;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    innerBundleInfo.innerBundleUserInfos_["_100"] = userInfo;
    innerBundleInfo.AddPluginBundleInfo(pluginBundleInfo, USERID);
    EXPECT_EQ(innerBundleInfo.pluginBundleInfos_.size(), 1);
    dataMgr->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);

    ExtensionAbilityInfo extensionInfo;
    Want want;
    want.SetElementName(BUNDLE_TEST1, BUNDLE_TEST1, ABILITY_NAME_TEST, MODULE_NAME_TEST);
    auto ret = dataMgr->GetPluginExtensionInfo(BUNDLE_TEST1, want, USERID, extensionInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_ABILITY_NOT_FOUND);
    dataMgr->bundleInfos_.erase(BUNDLE_TEST1);
}

/**
 * @tc.number: GetPluginExtensionInfo_0500
 * @tc.name: GetPluginExtensionInfo
 * @tc.desc: test GetPluginExtensionInfo with wrong module name
 */
HWTEST_F(BmsBundleDataMgrTest, GetPluginExtensionInfo_0500, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleType = BundleType::APP_PLUGIN;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    PluginBundleInfo pluginBundleInfo;
    ExtensionAbilityInfo extension;
    extension.name = ABILITY_NAME_TEST;
    extension.moduleName = "moduleName";
    pluginBundleInfo.pluginBundleName = BUNDLE_TEST1;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    innerBundleInfo.innerBundleUserInfos_["_100"] = userInfo;
    innerBundleInfo.AddPluginBundleInfo(pluginBundleInfo, USERID);
    EXPECT_EQ(innerBundleInfo.pluginBundleInfos_.size(), 1);
    dataMgr->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);

    ExtensionAbilityInfo extensionInfo;
    Want want;
    want.SetElementName(BUNDLE_TEST1, BUNDLE_TEST1, ABILITY_NAME_TEST, MODULE_NAME_TEST);
    auto ret = dataMgr->GetPluginExtensionInfo(BUNDLE_TEST1, want, USERID, extensionInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_ABILITY_NOT_FOUND);
    dataMgr->bundleInfos_.erase(BUNDLE_TEST1);
}

/**
 * @tc.number: GetPluginExtensionInfo_0600
 * @tc.name: GetPluginExtensionInfo
 * @tc.desc: test GetPluginExtensionInfo run normally
 */
HWTEST_F(BmsBundleDataMgrTest, GetPluginExtensionInfo_0600, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleType = BundleType::APP_PLUGIN;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    PluginBundleInfo pluginBundleInfo;
    ExtensionAbilityInfo extension;
    extension.name = ABILITY_NAME_TEST;
    extension.moduleName = MODULE_NAME_TEST;
    pluginBundleInfo.pluginBundleName = BUNDLE_TEST1;
    pluginBundleInfo.extensionInfos.emplace(ABILITY_NAME_TEST, extension);
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    innerBundleInfo.innerBundleUserInfos_["_100"] = userInfo;
    innerBundleInfo.AddPluginBundleInfo(pluginBundleInfo, USERID);
    EXPECT_EQ(innerBundleInfo.pluginBundleInfos_.size(), 1);
    dataMgr->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);

    ExtensionAbilityInfo extensionInfo;
    Want want;
    want.SetElementName(BUNDLE_TEST1, BUNDLE_TEST1, ABILITY_NAME_TEST, MODULE_NAME_TEST);
    auto ret = dataMgr->GetPluginExtensionInfo(BUNDLE_TEST1, want, USERID, extensionInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(extensionInfo.name, ABILITY_NAME_TEST);

    pluginBundleInfo.GetExtensionInfoByName(ABILITY_NAME_TEST, "", extensionInfo);
    EXPECT_EQ(extensionInfo.name, ABILITY_NAME_TEST);
    dataMgr->bundleInfos_.erase(BUNDLE_TEST1);
}

/**
 * @tc.number: GetPluginBundleInfoByName_0100
 * @tc.name: GetPluginBundleInfoByName
 * @tc.desc: test GetPluginBundleInfoByName with false name
 */
HWTEST_F(BmsBundleDataMgrTest, GetPluginBundleInfoByName_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    userInfo.installedPluginSet.insert(BUNDLE_TEST1);
    innerBundleInfo.innerBundleUserInfos_["_100"] = userInfo;
    PluginBundleInfo resultInfo;
    bool result = innerBundleInfo.GetPluginBundleInfoByName(USERID, BUNDLE_TEST1, resultInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: GetPluginBundleInfoByName_0200
 * @tc.name: GetPluginBundleInfoByName
 * @tc.desc: test GetPluginBundleInfoByName with empty name
 */
HWTEST_F(BmsBundleDataMgrTest, GetPluginBundleInfoByName_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USERID;
    userInfo.installedPluginSet.insert(BUNDLE_TEST1);
    innerBundleInfo.innerBundleUserInfos_["_100"] = userInfo;
    PluginBundleInfo resultInfo;
    bool result = innerBundleInfo.GetPluginBundleInfoByName(USERID, "", resultInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: GetPluginExtensionInfo_0700
 * @tc.name: GetPluginExtensionInfo
 * @tc.desc: test GetPluginExtensionInfo with invalid userId
 */
HWTEST_F(BmsBundleDataMgrTest, GetPluginExtensionInfo_0700, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    dataMgr->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);

    ExtensionAbilityInfo extensionInfo;
    Want want;
    want.SetElementName(BUNDLE_TEST2, BUNDLE_TEST2, ABILITY_NAME_TEST, MODULE_NAME_TEST);
    std::vector<int32_t> invalidUserIds = { -1, 0, INT32_MAX};
    ExtensionAbilityInfo extInfo;
    for (auto userId : invalidUserIds) {
        auto ret = dataMgr->GetPluginExtensionInfo(BUNDLE_TEST1, want, userId, extInfo);
        EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_NOT_FOUND);
    }
    dataMgr->bundleInfos_.erase(BUNDLE_TEST1);
}

/**
 * @tc.number: GetPluginExtensionInfo_0800
 * @tc.name: GetPluginExtensionInfo
 * @tc.desc: test GetPluginExtensionInfo with empty parameters
 */
HWTEST_F(BmsBundleDataMgrTest, GetPluginExtensionInfo_0800, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    dataMgr->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);

    ExtensionAbilityInfo extensionInfo;
    Want want;
    want.SetElementName("", "", "", "");
    auto ret = dataMgr->GetPluginExtensionInfo(BUNDLE_TEST1, want, USERID, extensionInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_NOT_FOUND);
    dataMgr->bundleInfos_.erase(BUNDLE_TEST1);
}

/**
 * @tc.number: HandleGetPluginExtensionInfo_0100
 * @tc.name: HandleGetPluginExtensionInfo
 * @tc.desc: test HandleGetPluginExtensionInfo(MessageParcel &data, MessageParcel &reply)
 */
HWTEST_F(BmsBundleDataMgrTest, HandleGetPluginExtensionInfo_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHost> localBundleMgrHost = std::make_shared<BundleMgrHost>();
    ASSERT_NE(localBundleMgrHost, nullptr);
    MessageParcel data;
    MessageParcel reply;
    auto ret = localBundleMgrHost->HandleGetPluginExtensionInfo(data, reply);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);

    Want want;
    want.SetElementName(BUNDLE_TEST2, BUNDLE_TEST2, ABILITY_NAME_TEST, MODULE_NAME_TEST);
    data.WriteString(BUNDLE_TEST2);
    data.WriteParcelable(&want);
    ret = localBundleMgrHost->HandleGetPluginExtensionInfo(data, reply);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetCreateDirParamByBundleOption_0010
 * @tc.name: test GetCreateDirParamByBundleOption
 * @tc.desc: 1.Test the GetCreateDirParamByBundleOption by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, GetCreateDirParamByBundleOption_0010, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    BundleOptionInfo optionInfo;
    optionInfo.bundleName = MODULE_NAME_TEST1;
    optionInfo.userId = TEST_U100;
    CreateDirParam createDirParam;
    ErrCode ret = dataMgr->GetCreateDirParamByBundleOption(optionInfo, createDirParam);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    InnerBundleInfo innerBundleInfo;
    dataMgr->bundleInfos_[MODULE_NAME_TEST1] = innerBundleInfo;
    ret = dataMgr->GetCreateDirParamByBundleOption(optionInfo, createDirParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_USER_NOT_EXIST);

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = MODULE_NAME_TEST1;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    innerBundleUserInfo.uid = TEST_UID;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    dataMgr->bundleInfos_[MODULE_NAME_TEST1] = innerBundleInfo;
    optionInfo.appIndex = 1;
    ret = dataMgr->GetCreateDirParamByBundleOption(optionInfo, createDirParam);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_APPINDEX_NOT_EXIST);
    optionInfo.appIndex = 0;
    ret = dataMgr->GetCreateDirParamByBundleOption(optionInfo, createDirParam);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(createDirParam.uid, TEST_UID);
}

/**
 * @tc.number: GetCreateDirParamByBundleOption_0020
 * @tc.name: test GetCreateDirParamByBundleOption
 * @tc.desc: 1.Test the GetCreateDirParamByBundleOption by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, GetCreateDirParamByBundleOption_0020, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    BundleOptionInfo optionInfo;
    optionInfo.bundleName = MODULE_NAME_TEST1;
    optionInfo.userId = TEST_U100;
    optionInfo.appIndex = 1;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = MODULE_NAME_TEST1;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    InnerBundleCloneInfo innerBundleCloneInfo;
    innerBundleCloneInfo.appIndex = 1;
    innerBundleCloneInfo.uid = TEST_UID;
    innerBundleUserInfo.cloneInfos["1"] = innerBundleCloneInfo;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    dataMgr->bundleInfos_[MODULE_NAME_TEST1] = innerBundleInfo;
    CreateDirParam createDirParam;
    ErrCode ret = dataMgr->GetCreateDirParamByBundleOption(optionInfo, createDirParam);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(createDirParam.uid, TEST_UID);
}

/**
 * @tc.number: CalculatePreInstalledBundleSize_0100
 * @tc.name: test CalculatePreInstalledBundleSize
 * @tc.desc: 1.Test the CalculatePreInstalledBundleSize by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, CalculatePreInstalledBundleSize_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    int32_t appIndex = 1;
    std::vector<int64_t> bundleStats;
    dataMgr->bundleInfos_.clear();
    dataMgr->CalculatePreInstalledBundleSize(BUNDLE_NAME_TEST, appIndex, bundleStats);
    EXPECT_TRUE(bundleStats.empty());

    InnerBundleInfo innerBundleInfo;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    dataMgr->CalculatePreInstalledBundleSize(BUNDLE_NAME_TEST, appIndex, bundleStats);
    EXPECT_TRUE(bundleStats.empty());

    appIndex = 0;
    dataMgr->bundleInfos_.clear();
    innerBundleInfo.SetIsPreInstallApp(false);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    dataMgr->CalculatePreInstalledBundleSize(BUNDLE_NAME_TEST, appIndex, bundleStats);
    EXPECT_TRUE(bundleStats.empty());

    dataMgr->bundleInfos_.clear();
    innerBundleInfo.SetIsPreInstallApp(true);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    dataMgr->CalculatePreInstalledBundleSize(BUNDLE_NAME_TEST, appIndex, bundleStats);
    EXPECT_TRUE(bundleStats.empty());

    dataMgr->bundleInfos_.clear();
}

/**
 * @tc.number: CalculatePreInstalledBundleSize_0200
 * @tc.name: test CalculatePreInstalledBundleSize
 * @tc.desc: 1.Test the CalculatePreInstalledBundleSize by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, CalculatePreInstalledBundleSize_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    int32_t appIndex = 0;
    std::vector<int64_t> bundleStats;
    bundleStats.emplace_back(TEST_VALUE_ZERO);
    dataMgr->bundleInfos_.clear();
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.hapPath = Constants::BUNDLE_CODE_DIR;
    std::string modulePackage = MODULE_TEST;
    innerBundleInfo.InsertInnerModuleInfo(modulePackage, innerModuleInfo);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    dataMgr->CalculatePreInstalledBundleSize(BUNDLE_NAME_TEST, appIndex, bundleStats);
    EXPECT_FALSE(bundleStats.empty());
    EXPECT_EQ(bundleStats[0], TEST_VALUE_ZERO);
    dataMgr->bundleInfos_.clear();
}

/**
 * @tc.number: CalculatePreInstalledBundleSize_0300
 * @tc.name: test CalculatePreInstalledBundleSize
 * @tc.desc: 1.Test the CalculatePreInstalledBundleSize by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, CalculatePreInstalledBundleSize_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    int32_t appIndex = 0;
    std::vector<int64_t> bundleStats;
    bundleStats.emplace_back(TEST_VALUE_ZERO);
    dataMgr->bundleInfos_.clear();
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsPreInstallApp(true);
    InnerModuleInfo innerModuleInfo;
    std::string modulePackage = MODULE_TEST;
    innerBundleInfo.InsertInnerModuleInfo(modulePackage, innerModuleInfo);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    dataMgr->CalculatePreInstalledBundleSize(BUNDLE_NAME_TEST, appIndex, bundleStats);
    EXPECT_FALSE(bundleStats.empty());
    EXPECT_EQ(bundleStats[0], TEST_VALUE_ZERO);
    dataMgr->bundleInfos_.clear();
}

/**
 * @tc.number: GetAllInstallBundleUids_0100
 * @tc.name: test GetAllInstallBundleUids
 * @tc.desc: 1.Test the GetAllInstallBundleUids by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllInstallBundleUids_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.SetApplicationBundleType(BundleType::SHARED);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    std::vector<int32_t> uids;
    std::vector<std::string> bundleNames;
    int32_t responseUserId = USERID;
    dataMgr->GetAllInstallBundleUids(USERID, Constants::ANY_USERID, responseUserId, uids, bundleNames);
    EXPECT_TRUE(bundleNames.empty());
    dataMgr->bundleInfos_.clear();
}

/**
 * @tc.number: GetAllInstallBundleUids_0200
 * @tc.name: test GetAllInstallBundleUids
 * @tc.desc: 1.Test the GetAllInstallBundleUids by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllInstallBundleUids_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.SetApplicationBundleType(BundleType::APP);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    std::vector<int32_t> uids;
    std::vector<std::string> bundleNames;
    int32_t responseUserId = USERID;
    dataMgr->GetAllInstallBundleUids(USERID, Constants::ANY_USERID, responseUserId, uids, bundleNames);
    EXPECT_FALSE(bundleNames.empty());
    dataMgr->bundleInfos_.clear();
}

/**
 * @tc.number: GetAllInstallBundleUids_0300
 * @tc.name: test GetAllInstallBundleUids
 * @tc.desc: 1.Test the GetAllInstallBundleUids by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllInstallBundleUids_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.SetApplicationBundleType(BundleType::ATOMIC_SERVICE);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    std::vector<int32_t> uids;
    std::vector<std::string> bundleNames;
    int32_t responseUserId = USERID;
    dataMgr->GetAllInstallBundleUids(USERID, Constants::ANY_USERID, responseUserId, uids, bundleNames);
    EXPECT_FALSE(bundleNames.empty());
    dataMgr->bundleInfos_.clear();
}

/**
 * @tc.number: GetAllInstallBundleUids_0400
 * @tc.name: test GetAllInstallBundleUids
 * @tc.desc: 1.Test the GetAllInstallBundleUids by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllInstallBundleUids_0400, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.SetApplicationBundleType(BundleType::APP);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    std::vector<int32_t> uids;
    std::vector<std::string> bundleNames;
    int32_t responseUserId = USERID;
    dataMgr->GetAllInstallBundleUids(USERID, Constants::ANY_USERID, responseUserId, uids, bundleNames);
    EXPECT_FALSE(bundleNames.empty());
    dataMgr->bundleInfos_.clear();
}

/**
 * @tc.number: GetAllInstallBundleUids_0500
 * @tc.name: test GetAllInstallBundleUids
 * @tc.desc: 1.Test the GetAllInstallBundleUids by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllInstallBundleUids_0500, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = ERROR_USERID;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.SetApplicationBundleType(BundleType::APP);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_TEST, innerBundleInfo);
    std::vector<int32_t> uids;
    std::vector<std::string> bundleNames;
    int32_t responseUserId = USERID;
    dataMgr->GetAllInstallBundleUids(USERID, Constants::ANY_USERID, responseUserId, uids, bundleNames);
    EXPECT_TRUE(bundleNames.empty());
    dataMgr->bundleInfos_.clear();
}

/**
 * @tc.number: CleanBundleCacheFilesAutomatic_0100
 * @tc.name: test CleanBundleCacheFilesAutomatic
 * @tc.desc: 1.Test the CleanBundleCacheFilesAutomatic by BundleMgrProxy
 */
HWTEST_F(BmsBundleDataMgrTest, CleanBundleCacheFilesAutomatic_0100, Function | SmallTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr) << "Failed to get SystemAbilityManager";
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    ASSERT_NE(remoteObject, nullptr) << "Failed to get Bundle Manager Service";
    std::shared_ptr<BundleMgrProxy> bundleMgrProxy = std::make_shared<BundleMgrProxy>(remoteObject);
    uint64_t cacheSize = 1;
    CleanType cleanType = CleanType::CACHE_SPACE;
    std::optional<uint64_t> cleanedSize;
    auto res = bundleMgrProxy->CleanBundleCacheFilesAutomatic(cacheSize, cleanType, cleanedSize);
    EXPECT_NE(res, ERR_BUNDLE_MANAGER_IPC_TRANSACTION);
}

/**
 * @tc.number: ProcessUninstallBundle_1000
 * @tc.name: test ProcessUninstallBundle
 * @tc.desc: 1.Test the ProcessUninstallBundle by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, ProcessUninstallBundle_1000, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::vector<BundleOptionInfo> bundleOptionInfos;
    bool result = dataMgr->ProcessUninstallBundle(bundleOptionInfos);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: ProcessUninstallBundle_2000
 * @tc.name: test ProcessUninstallBundle
 * @tc.desc: 1.Test the ProcessUninstallBundle by BundleDataMgr
 */
HWTEST_F(BmsBundleDataMgrTest, ProcessUninstallBundle_2000, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName = "com.example.ProcessUninstallBundle_2000";
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    UninstallDataUserInfo uninstallDataUserInfo;
    uninstallDataUserInfo.uid = 20020033;
    UninstallBundleInfo uninstallBundleInfo;
    uninstallBundleInfo.bundleType = BundleType::APP;
    uninstallBundleInfo.userInfos.emplace(std::make_pair(std::to_string(TEST_USERID), uninstallDataUserInfo));
    auto ret = dataMgr->UpdateUninstallBundleInfo(bundleName, uninstallBundleInfo);
    ASSERT_TRUE(ret);
    std::vector<BundleOptionInfo> bundleOptionInfos;
    bool result = dataMgr->ProcessUninstallBundle(bundleOptionInfos);
    EXPECT_TRUE(result);
    EXPECT_EQ(bundleOptionInfos.size(), 1);
    dataMgr->DeleteUninstallBundleInfo(bundleName, TEST_USERID);
    dataMgr->multiUserIdsSet_.erase(TEST_USERID);
}

/**
 * @tc.number: CleanBundleCacheByInodeCount_0100
 * @tc.name: test CleanBundleCacheByInodeCount
 * @tc.desc: 1.Test the CleanBundleCacheByInodeCount by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, CleanBundleCacheByInodeCount_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> hostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<std::string> moduleNames = {"entry"};
    uint64_t cleanCacheSize = 0;
    ClearDataMgr();
    bool ret = hostImpl->CleanBundleCacheByInodeCount(
        BUNDLE_NAME_TEST, USERID, DEFAULT_APP_INDEX, moduleNames, cleanCacheSize);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CleanBundleCacheByInodeCount_0200
 * @tc.name: test CleanBundleCacheByInodeCount
 * @tc.desc: 1.Test the CleanBundleCacheByInodeCount by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, CleanBundleCacheByInodeCount_0200, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> hostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<std::string> moduleNames = {"entry"};
    uint64_t cleanCacheSize = 0;
    bool ret = hostImpl->CleanBundleCacheByInodeCount(
        BUNDLE_NAME_TEST, USERID, DEFAULT_APP_INDEX, moduleNames, cleanCacheSize);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CleanBundleCacheTaskGetCleanSize_0100
 * @tc.name: test CleanBundleCacheTaskGetCleanSize
 * @tc.desc: 1.Test the CleanBundleCacheTaskGetCleanSize by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, CleanBundleCacheTaskGetCleanSize_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> hostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    uint64_t cleanCacheSize = 0;
    std::string callingName = "callingBundleName";
    ClearDataMgr();
    hostImpl->CleanBundleCacheTaskGetCleanSize(
        BUNDLE_NAME_TEST, USERID, CleanType::CACHE_SPACE, DEFAULT_APP_INDEX, TEST_UID, callingName, cleanCacheSize);
    EXPECT_EQ(cleanCacheSize, 0);
    ScopeGuard stateGuard([&] { ResetDataMgr(); });
}

/**
 * @tc.number: CleanBundleCacheTaskGetCleanSize_0200
 * @tc.name: test CleanBundleCacheTaskGetCleanSize
 * @tc.desc: 1.Test the CleanBundleCacheTaskGetCleanSize by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, CleanBundleCacheTaskGetCleanSize_0200, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> hostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    uint64_t cleanCacheSize = 0;
    std::string callingName = "callingBundleName";
    hostImpl->CleanBundleCacheTaskGetCleanSize(
        BUNDLE_NAME_TEST, USERID, CleanType::CACHE_SPACE, DEFAULT_APP_INDEX, TEST_UID, callingName, cleanCacheSize);
    EXPECT_EQ(cleanCacheSize, 0);
    
    SetCleanBundleDataDirResult(false);
    hostImpl->CleanBundleCacheTaskGetCleanSize(
        BUNDLE_NAME_TEST, USERID, CleanType::CACHE_SPACE, DEFAULT_APP_INDEX, TEST_UID, callingName, cleanCacheSize);
    EXPECT_EQ(cleanCacheSize, 0);
    SetCleanBundleDataDirResult(true);
}

/**
 * @tc.number: CleanBundleCacheTaskGetCleanSize_0300
 * @tc.name: test CleanBundleCacheTaskGetCleanSize
 * @tc.desc: 1.Test the CleanBundleCacheTaskGetCleanSize by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleDataMgrTest, CleanBundleCacheTaskGetCleanSize_0300, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrHostImpl> hostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    uint64_t cleanCacheSize = 0;
    std::string callingName = "callingBundleName";
    hostImpl->CleanBundleCacheTaskGetCleanSize(
        BUNDLE_NAME_TEST, USERID, CleanType::INODE_COUNT, DEFAULT_APP_INDEX, TEST_UID, callingName, cleanCacheSize);
    EXPECT_EQ(cleanCacheSize, 0);
}

/**
 * @tc.number: GetQuotaData_0100
 * @tc.name: test GetQuotaData
 * @tc.desc: 1.system run normally
 *           2.dbqlk has value
 */
HWTEST_F(BmsBundleDataMgrTest, GetQuotaData_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto uid = GetBundleDataMgr()->GetUidByBundleName(BUNDLE_NAME_TEST, USERID, DEFAULT_APP_INDEX);
    auto dbqlk = InstalldOperator::GetQuotaData(uid);
    EXPECT_TRUE(dbqlk.has_value());
    int64_t quotaValue = InstalldOperator::GetDiskUsageFromQuota(uid);
    EXPECT_EQ(quotaValue, 0);
    quotaValue = InstalldOperator::GetBundleInodeCount(uid);
    EXPECT_EQ(quotaValue, 0);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAllAppInstallExtendedInfo_0100
 * @tc.name: test GetAllAppInstallExtendedInfo
 * @tc.desc: 1. test GetAllAppInstallExtendedInfo with valid bundles
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllAppInstallExtendedInfo_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<AppInstallExtendedInfo> appInstallExtendedInfos;
    ErrCode ret = dataMgr->GetAllAppInstallExtendedInfo(appInstallExtendedInfos);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GT(appInstallExtendedInfos.size(), 0);

    bool found = false;
    for (const auto& info : appInstallExtendedInfos) {
        if (info.bundleName == BUNDLE_NAME_TEST) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAllAppInstallExtendedInfo_0200
 * @tc.name: test GetAllAppInstallExtendedInfo with disabled bundle
 * @tc.desc: 1. test that disabled bundles are filtered out
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllAppInstallExtendedInfo_0200, Function | SmallTest | Level1)
{
    std::string bundleName = "com.example.test.disabled";

    // Create and add disabled bundle directly
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo appInfo;
    appInfo.bundleName = bundleName;
    appInfo.name = bundleName;
    appInfo.enabled = true;
    innerBundleInfo.SetBaseApplicationInfo(appInfo);
    innerBundleInfo.SetApplicationBundleType(BundleType::APP);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.modulePackage = MODULE_NAME_TEST;
    innerModuleInfo.moduleName = MODULE_NAME_TEST;
    innerModuleInfo.hashValue = "testHashValue";
    innerModuleInfo.isEntry = true;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_NAME_TEST, innerModuleInfo);

    bool startRet = GetBundleDataMgr()->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    ASSERT_TRUE(startRet);

    bool addRet = GetBundleDataMgr()->AddInnerBundleInfo(bundleName, innerBundleInfo);
    ASSERT_TRUE(addRet);

    bool endRet = GetBundleDataMgr()->UpdateBundleInstallState(bundleName, InstallState::INSTALL_SUCCESS);
    ASSERT_TRUE(endRet);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<AppInstallExtendedInfo> appInstallExtendedInfos;
    ErrCode ret = dataMgr->GetAllAppInstallExtendedInfo(appInstallExtendedInfos);

    EXPECT_EQ(ret, ERR_OK);

    // Disabled bundle should not be in result
    bool found = false;
    for (const auto& info : appInstallExtendedInfos) {
        if (info.bundleName == bundleName) {
            found = true;
            break;
        }
    }
    EXPECT_FALSE(found);

    RemoveBundleinfo(bundleName);
}

/**
 * @tc.number: GetAllAppInstallExtendedInfo_0300
 * @tc.name: test GetAllAppInstallExtendedInfo with shared bundle
 * @tc.desc: 1. test that shared bundles are filtered out
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllAppInstallExtendedInfo_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::string bundleName = "com.example.test.shared";

    // Create shared bundle
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo appInfo;
    appInfo.bundleName = bundleName;
    appInfo.name = bundleName;
    appInfo.enabled = true;

    innerBundleInfo.SetBaseApplicationInfo(appInfo);
    innerBundleInfo.SetApplicationBundleType(BundleType::SHARED);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.modulePackage = MODULE_NAME_TEST;
    innerModuleInfo.moduleName = MODULE_NAME_TEST;
    innerModuleInfo.hashValue = "testHashValue";
    innerModuleInfo.isEntry = true;

    innerBundleInfo.InsertInnerModuleInfo(MODULE_NAME_TEST, innerModuleInfo);

    bool startRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
    ASSERT_TRUE(startRet);

    bool addRet = dataMgr->AddInnerBundleInfo(bundleName, innerBundleInfo);
    ASSERT_TRUE(addRet);

    bool endRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_SUCCESS);
    ASSERT_TRUE(endRet);

    std::vector<AppInstallExtendedInfo> appInstallExtendedInfos;
    ErrCode ret = dataMgr->GetAllAppInstallExtendedInfo(appInstallExtendedInfos);

    EXPECT_EQ(ret, ERR_OK);

    // Shared bundle should not be in result
    bool found = false;
    for (const auto& info : appInstallExtendedInfos) {
        if (info.bundleName == bundleName) {
            found = true;
            break;
        }
    }
    EXPECT_FALSE(found);

    RemoveBundleinfo(bundleName);
}

/**
 * @tc.number: GetAllAppInstallExtendedInfo_0400
 * @tc.name: test GetAllAppInstallExtendedInfo with multiple bundles
 * @tc.desc: 1. test GetAllAppInstallExtendedInfo with multiple valid bundles
 */
HWTEST_F(BmsBundleDataMgrTest, GetAllAppInstallExtendedInfo_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_TEST1, MODULE_NAME_TEST, ABILITY_NAME_TEST1);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<AppInstallExtendedInfo> appInstallExtendedInfos;
    ErrCode ret = dataMgr->GetAllAppInstallExtendedInfo(appInstallExtendedInfos);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GE(appInstallExtendedInfos.size(), 2);

    bool foundFirst = false;
    bool foundSecond = false;
    for (const auto& info : appInstallExtendedInfos) {
        if (info.bundleName == BUNDLE_NAME_TEST) {
            foundFirst = true;
        }
        if (info.bundleName == BUNDLE_TEST1) {
            foundSecond = true;
        }
    }
    EXPECT_TRUE(foundFirst);
    EXPECT_TRUE(foundSecond);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_TEST1);
}
} // OHOS
