/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <cstdint>
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
#include "bundle_cache_mgr.h"
#include "bundle_data_mgr.h"
#include "bundle_info.h"
#include "bundle_permission_mgr.h"
#include "bundle_mgr_client_impl.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "bundle_mgr_host.h"
#include "bundle_mgr_proxy.h"
#include "bundle_status_callback_proxy.h"
#include "bundle_stream_installer_host_impl.h"
#include "clean_cache_callback_proxy.h"
#include "clone_param.h"
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
#include "parameter.h"
#include "perf_profile.h"
#include "process_cache_callback_host.h"
#include "scope_guard.h"
#include "service_control.h"
#include "shortcut_info.h"
#include "system_ability_helper.h"
#include "want.h"
#include "display_power_mgr_client.h"
#include "display_power_info.h"
#include "battery_srv_client.h"
#include "bundle_manager_helper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using OHOS::AAFwk::Want;
using namespace OHOS::DisplayPowerMgr;
using namespace OHOS::PowerMgr;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME_TEST = "com.example.bundlekit.test";
const std::string BUNDLE_NAME_TEST_CLEAR = "com.example.bundlekit.test.clear";
const std::string MODULE_NAME_TEST = "com.example.bundlekit.test.entry";
const std::string MODULE_NAME_TEST_CLEAR = "com.example.bundlekit.test.entry.clear";
const std::string MODULE_NAME_TEST_1 = "com.example.bundlekit.test.entry_A";
const std::string MODULE_NAME_TEST_2 = "com.example.bundlekit.test.entry_B";
const std::string MODULE_NAME_TEST_3 = "com.example.bundlekit.test.entry_C";
const std::string ABILITY_NAME_TEST1 = ".Reading1";
const std::string ABILITY_NAME_TEST = ".Reading";
const int32_t BASE_TEST_UID = 65535;
const int32_t TEST_UID = 20065535;
const std::string BUNDLE_LABEL = "Hello, OHOS";
const std::string BUNDLE_DESCRIPTION = "example helloworld";
const std::string BUNDLE_VENDOR = "example";
const std::string BUNDLE_VERSION_NAME = "1.0.0.1";
const std::string BUNDLE_MAIN_ABILITY = "com.example.bundlekit.test.entry";
const int32_t BUNDLE_MAX_SDK_VERSION = 0;
const int32_t BUNDLE_MIN_SDK_VERSION = 0;
const std::string BUNDLE_JOINT_USERID = "3";
const uint32_t BUNDLE_VERSION_CODE = 1001;
const std::string BUNDLE_NAME_TEST1 = "com.example.bundlekit.test1";
const std::string BUNDLE_NAME_DEMO = "com.example.bundlekit.demo";
const std::string MODULE_NAME_DEMO = "com.example.bundlekit.demo.entry";
const std::string ABILITY_NAME_DEMO = ".Writing";
const int DEMO_UID = 30001;
const std::string PACKAGE_NAME = "com.example.bundlekit.test.entry";
const std::string PROCESS_TEST = "test.process";
const std::string DEVICE_ID = "PHONE-001";
const int APPLICATION_INFO_FLAGS = 1;
const int DEFAULT_USER_ID_TEST = 100;
const int NEW_USER_ID_TEST = 200;
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
const uint32_t FORM_ENTITY = 1;
const uint32_t BACKGROUND_MODES = 1;
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
const uint32_t ABILITY_SIZE_ZERO = 0;
const uint32_t ABILITY_SIZE_ONE = 1;
const uint32_t ABILITY_SIZE_THREE = 3;
const uint32_t EXTENSION_SIZE_TWO = 2;
const uint32_t SKILL_SIZE_ZERO = 0;
const uint32_t SKILL_SIZE_TWO = 2;
const uint32_t PERMISSION_SIZE_ZERO = 0;
const uint32_t PERMISSION_SIZE_TWO = 2;
const uint32_t META_DATA_SIZE_ONE = 1;
const uint32_t BUNDLE_NAMES_SIZE_ZERO = 0;
const uint32_t BUNDLE_NAMES_SIZE_ONE = 1;
const uint32_t MODULE_NAMES_SIZE_ONE = 1;
const uint32_t MODULE_NAMES_SIZE_TWO = 2;
const uint32_t MODULE_NAMES_SIZE_THREE = 3;
const std::string EMPTY_STRING = "";
const int INVALID_UID = -1;
const std::string ABILITY_URI = "dataability:///com.example.hiworld.himusic.UserADataAbility/person/10";
const std::string ABILITY_TEST_URI = "dataability:///com.example.hiworld.himusic.UserADataAbility";
const std::string URI = "dataability://com.example.hiworld.himusic.UserADataAbility";
const std::string ERROR_URI = "dataability://";
const std::string HAP_FILE_PATH = "/data/test/resource/bms/bundle_kit/test.hap";
const std::string HAP_FILE_PATH1 = "/data/test/resource/bms/bundle_kit/test1.hap";
const std::string ERROR_HAP_FILE_PATH = "/data/test/resource/bms/bundle_kit/error.hap";
const std::string RELATIVE_HAP_FILE_PATH = "/data/test/resource/bms/bundle_kit/hello/../test.hap";
const std::string META_DATA = "name";
const std::string ERROR_META_DATA = "String";
const std::string BUNDLE_DATA_DIR = "/data/app/el2/100/base/com.example.bundlekit.test";
const std::string FILES_DIR = "/data/app/el2/100/base/com.example.bundlekit.test/files";
const std::string TEST_FILE_DIR = "/data/app/el2/100/base/com.example.bundlekit.test/files";
const std::string DATA_BASE_DIR = "/data/app/el2/100/database/com.example.bundlekit.test";
const std::string CACHE_DIR = "/data/app/el2/100/base/com.example.bundlekit.test/cache";
const std::string TEST_CACHE_DIR = "/data/app/el2/100/base/com.example.bundlekit.test/cache/cache";
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
const int FORMINFO_DESCRIPTIONID = 123;
const std::string CONTROLMESSAGE = "controlMessage";
const int32_t DEFAULT_USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
const std::string URI_SCHEME = "http";
const std::string URI_HOST = "example.com";
const std::string URI_PORT = "80";
const std::string URI_PATH = "path";
const std::string URI_PATH_START_WITH = "pathStart";
const std::string URI_PATH_REGEX = "pathRegex";
const std::string URI_UTD = "utd";
const std::string URI_LINK_FEATURE = "login";
const std::string SKILL_PERMISSION = "permission1";
const int32_t MAX_FILE_SUPPORTED = 1;
}  // namespace

class BmsCleanAllBundleCacheTest : public testing::Test {
public:
    using Want = OHOS::AAFwk::Want;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    static sptr<BundleMgrProxy> GetBundleMgrProxy();
    void MockInstallBundle(
        const std::string &bundleName, const std::string &moduleName, const std::string &abilityName,
        bool userDataClearable = true, bool isSystemApp = false) const;
    void MockInstallBundle(
        const std::string &bundleName, const std::vector<std::string> &moduleNameList, const std::string &abilityName,
        bool userDataClearable = true, bool isSystemApp = false) const;
    void MockUninstallBundle(const std::string &bundleName) const;
    InnerAbilityInfo MockAbilityInfo(
        const std::string &bundleName, const std::string &module, const std::string &abilityName) const;
    InnerModuleInfo MockModuleInfo(const std::string &moduleName) const;
    FormInfo MockFormInfo(
        const std::string &bundleName, const std::string &module, const std::string &abilityName) const;
    ShortcutInfo MockShortcutInfo(const std::string &bundleName, const std::string &shortcutId) const;
    CommonEventInfo MockCommonEventInfo(const std::string &bundleName, const int uid) const;
    void CreateFileDir() const;
    void CleanFileDir() const;
    void CheckCacheExist() const;
    void AddBundleInfo(const std::string &bundleName, BundleInfo &bundleInfo) const;
    void AddApplicationInfo(const std::string &bundleName, ApplicationInfo &appInfo,
        bool userDataClearable = true, bool isSystemApp = false) const;
    void AddInnerBundleInfoByTest(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, InnerBundleInfo &innerBundleInfo) const;
    void SaveToDatabase(const std::string &bundleName, InnerBundleInfo &innerBundleInfo,
        bool userDataClearable, bool isSystemApp) const;
    Skill MockAbilitySkillInfo() const;
public:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    NotifyBundleEvents installRes_;
};

std::shared_ptr<BundleMgrService> BmsCleanAllBundleCacheTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsCleanAllBundleCacheTest::installdService_ =
    std::make_shared<InstalldService>();

void BmsCleanAllBundleCacheTest::SetUpTestCase()
{}

void BmsCleanAllBundleCacheTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsCleanAllBundleCacheTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(DEFAULT_USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    installRes_ = {
        .bundleName = HAP_FILE_PATH,
        .modulePackage = HAP_FILE_PATH,
        .abilityName = ABILITY_NAME_DEMO,
        .resultCode = ERR_OK,
        .type = NotifyType::INSTALL,
        .uid = Constants::INVALID_UID,
    };
}

void BmsCleanAllBundleCacheTest::TearDown()
{}

std::shared_ptr<BundleDataMgr> BmsCleanAllBundleCacheTest::GetBundleDataMgr() const
{
    bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
    EXPECT_NE(bundleMgrService_, nullptr);
    return bundleMgrService_->GetDataMgr();
}

sptr<BundleMgrProxy> BmsCleanAllBundleCacheTest::GetBundleMgrProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        APP_LOGE("fail to get system ability mgr");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        APP_LOGE("fail to get bundle manager proxy");
        return nullptr;
    }

    APP_LOGI("get bundle manager proxy success");
    return iface_cast<BundleMgrProxy>(remoteObject);
}

void BmsCleanAllBundleCacheTest::AddBundleInfo(const std::string &bundleName, BundleInfo &bundleInfo) const
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

void BmsCleanAllBundleCacheTest::AddApplicationInfo(const std::string &bundleName, ApplicationInfo &appInfo,
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

void BmsCleanAllBundleCacheTest::AddInnerBundleInfoByTest(const std::string &bundleName,
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
    CommonEventInfo eventInfo = MockCommonEventInfo(bundleName, innerBundleInfo.GetUid(DEFAULT_USERID));
    innerBundleInfo.InsertCommonEvents(commonEventKey, eventInfo);
}

void BmsCleanAllBundleCacheTest::MockInstallBundle(
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

InnerModuleInfo BmsCleanAllBundleCacheTest::MockModuleInfo(const std::string &moduleName) const
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

void BmsCleanAllBundleCacheTest::SaveToDatabase(const std::string &bundleName,
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
    AddBundleInfo(bundleName, bundleInfo);
    innerBundleInfo.SetBaseApplicationInfo(appInfo);
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo1);
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    Security::AccessToken::AccessTokenIDEx accessTokenId;
    accessTokenId.tokenIDEx = 1;
    innerBundleInfo.SetAccessTokenIdEx(accessTokenId, DEFAULT_USERID);
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

void BmsCleanAllBundleCacheTest::MockInstallBundle(
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

FormInfo BmsCleanAllBundleCacheTest::MockFormInfo(
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

ShortcutInfo BmsCleanAllBundleCacheTest::MockShortcutInfo(
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

CommonEventInfo BmsCleanAllBundleCacheTest::MockCommonEventInfo(
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

void BmsCleanAllBundleCacheTest::MockUninstallBundle(const std::string &bundleName) const
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool startRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START);
    bool finishRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS);

    EXPECT_TRUE(startRet);
    EXPECT_TRUE(finishRet);
}

Skill BmsCleanAllBundleCacheTest::MockAbilitySkillInfo() const
{
    Skill skillForAbility;
    SkillUri uri;
    uri.scheme = URI_SCHEME;
    uri.host = URI_HOST;
    uri.port = URI_PORT;
    uri.path = URI_PATH;
    uri.pathStartWith = URI_PATH_START_WITH;
    uri.pathRegex = URI_PATH_REGEX;
    uri.type = EMPTY_STRING;
    uri.utd = URI_UTD;
    uri.maxFileSupported = MAX_FILE_SUPPORTED;
    uri.linkFeature = URI_LINK_FEATURE;
    skillForAbility.actions.push_back(ACTION);
    skillForAbility.entities.push_back(ENTITY);
    skillForAbility.uris.push_back(uri);
    skillForAbility.permissions.push_back(SKILL_PERMISSION);
    skillForAbility.domainVerify = true;
    return skillForAbility;
}

InnerAbilityInfo BmsCleanAllBundleCacheTest::MockAbilityInfo(
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
    Skill skill = MockAbilitySkillInfo();
    abilityInfo.skills.push_back(skill);
    abilityInfo.skills.push_back(skill);
    return abilityInfo;
}

void BmsCleanAllBundleCacheTest::CreateFileDir() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }

    if (access(TEST_FILE_DIR.c_str(), F_OK) != 0) {
        bool result = OHOS::ForceCreateDirectory(TEST_FILE_DIR);
        EXPECT_TRUE(result) << "fail to create file dir";
    }

    if (access(TEST_CACHE_DIR.c_str(), F_OK) != 0) {
        bool result = OHOS::ForceCreateDirectory(TEST_CACHE_DIR);
        EXPECT_TRUE(result) << "fail to create cache dir";
    }
}

void BmsCleanAllBundleCacheTest::CleanFileDir() const
{
    installdService_->Stop();
    InstalldClient::GetInstance()->ResetInstalldProxy();

    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR);
}

void BmsCleanAllBundleCacheTest::CheckCacheExist() const
{
    int dataExist = access(TEST_CACHE_DIR.c_str(), F_OK);
    EXPECT_EQ(dataExist, 0);
}

/**
 * @tc.number: CleanCache_0100
 * @tc.name: test can clean the cache files by empty bundle name
 * @tc.desc: 1.system run normally
 *           2.clean the cache files failed
 */
HWTEST_F(BmsCleanAllBundleCacheTest, CleanCache_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    CreateFileDir();

    sptr<MockCleanCache> cleanCache = new (std::nothrow) MockCleanCache();
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    auto result = hostImpl->CleanBundleCacheFiles("", cleanCache);
    EXPECT_FALSE(result == ERR_OK);
    CheckCacheExist();

    CleanFileDir();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanCache_0300
 * @tc.name: test can clean the cache files
 * @tc.desc: 1.system run normally
 *           2. userDataClearable is true
 *           3.clean the cache files succeed
 */
HWTEST_F(BmsCleanAllBundleCacheTest, CleanCache_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, true);
    CreateFileDir();

    sptr<MockCleanCache> cleanCache = new (std::nothrow) MockCleanCache();
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    auto result = hostImpl->CleanBundleCacheFiles(BUNDLE_NAME_TEST, cleanCache);
    EXPECT_TRUE(result == ERR_OK);

    CleanFileDir();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanCache_0400
 * @tc.name: test can clean the cache files
 * @tc.desc: 1.system run normally
 *           2. userDataClearable is false
 *           3.clean the cache files failed
 */
HWTEST_F(BmsCleanAllBundleCacheTest, CleanCache_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, false);
    CreateFileDir();

    sptr<MockCleanCache> cleanCache = new (std::nothrow) MockCleanCache();
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    auto result = hostImpl->CleanBundleCacheFiles(BUNDLE_NAME_TEST, cleanCache);
    EXPECT_FALSE(result == ERR_OK);

    CleanFileDir();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanCacheForSelf_0100
 * @tc.name: test can clean the cache files
 * @tc.desc: 1.system run normally
 *           2.GetApplicationInfoWithResponseId failed
 *           3.clean the cache files faild
 */
HWTEST_F(BmsCleanAllBundleCacheTest, CleanCacheForSelf_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    CreateFileDir();

    sptr<MockCleanCache> cleanCache = new (std::nothrow) MockCleanCache();
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    auto result = hostImpl->CleanBundleCacheFilesForSelf(cleanCache);
    EXPECT_FALSE(result == ERR_OK);

    CleanFileDir();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanCacheForSelf_0200
 * @tc.name: test can clean the cache files
 * @tc.desc: 1.system run normally
 *           2.cleanCache is nullptr
 *           3.clean the cache files failed
 */
HWTEST_F(BmsCleanAllBundleCacheTest, CleanCacheForSelf_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, false);
    CreateFileDir();

    IPCSkeleton::SetCallingUid(TEST_UID);
    auto uid = IPCSkeleton::GetCallingUid();
    EXPECT_EQ(uid, TEST_UID);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    sptr<MockCleanCache> cleanCache = nullptr;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    dataMgr->bundleIdMap_.insert({BASE_TEST_UID, BUNDLE_NAME_TEST});
    auto result = hostImpl->CleanBundleCacheFilesForSelf(cleanCache);
    EXPECT_EQ(result, ERR_APPEXECFWK_NULL_PTR);

    IPCSkeleton::SetCallingUid(20000001);
    dataMgr->bundleIdMap_.erase(BASE_TEST_UID);
    CleanFileDir();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanCacheForSelf_0300
 * @tc.name: test can clean the cache files
 * @tc.desc: 1.system run normally
 *           2.GetBundleNameAndIndexForUid failed
 *           3.clean the cache files failed
 */
HWTEST_F(BmsCleanAllBundleCacheTest, CleanCacheForSelf_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, false);
    CreateFileDir();

    sptr<MockCleanCache> cleanCache = new (std::nothrow) MockCleanCache();
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    auto result = hostImpl->CleanBundleCacheFilesForSelf(cleanCache);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    CleanFileDir();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanCacheForSelf_0400
 * @tc.name: test can clean the cache files
 * @tc.desc: 1.system run normally
 *           2.clean the cache files failed
 */
HWTEST_F(BmsCleanAllBundleCacheTest, CleanCacheForSelf_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    CreateFileDir();

    sptr<MockCleanCache> cleanCache = new (std::nothrow) MockCleanCache();
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    auto result = bundleMgrProxy->CleanBundleCacheFilesForSelf(cleanCache);
    EXPECT_FALSE(result == ERR_OK);

    CleanFileDir();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanCacheForSelf_0500
 * @tc.name: test can clean the cache files
 * @tc.desc: 1.system run normally
 *           2.clean the cache files failed by nullptr cleaCache
 */
HWTEST_F(BmsCleanAllBundleCacheTest, CleanCacheForSelf_0500, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    CreateFileDir();

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    ErrCode result = bundleMgrProxy->CleanBundleCacheFilesForSelf(nullptr);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_PARAM_ERROR);

    CleanFileDir();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}
/**
 * @tc.number: CleanBundleCacheFilesAutomatic_0100
 * @tc.name: test CleanBundleCacheFilesAutomatic
 * @tc.desc: 1. system run normally
 *           2. cacheSize is 0
 *           3. return ERR_BUNDLE_MANAGER_INVALID_PARAMETER
 */
HWTEST_F(BmsCleanAllBundleCacheTest, CleanBundleCacheFilesAutomatic_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    uint64_t cacheSize = 0;
    auto result = hostImpl->CleanBundleCacheFilesAutomatic(cacheSize);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: CleanCache_0500
 * @tc.name: test can clean the cache files
 * @tc.desc: 1.system run normally
 *           2. userDataClearable is false
 *           3.clean the cache files failed
 */
HWTEST_F(BmsCleanAllBundleCacheTest, CleanCache_0500, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, false);
    CreateFileDir();

    sptr<MockCleanCache> cleanCache = new (std::nothrow) MockCleanCache();
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    auto result = bundleMgrProxy->CleanBundleCacheFiles(BUNDLE_NAME_TEST, cleanCache);
    EXPECT_FALSE(result == ERR_OK);

    CleanFileDir();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanCache_0600
 * @tc.name: test can clean the cache files
 * @tc.desc: 1.system run normally
 *           2.clean the cache files failed by empty name
 */
HWTEST_F(BmsCleanAllBundleCacheTest, CleanCache_0600, Function | SmallTest | Level1)
{
    sptr<MockCleanCache> cleanCache = new (std::nothrow) MockCleanCache();
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    ErrCode result = bundleMgrProxy->CleanBundleCacheFiles("", cleanCache);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.number: CleanCache_0700
 * @tc.name: test can clean the cache files
 * @tc.desc: 1.system run normally
 *           2. userDataClearable is false
 *           3.clean the cache files failed by nullptr cleaCache
 */
HWTEST_F(BmsCleanAllBundleCacheTest, CleanCache_0700, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, false);
    CreateFileDir();

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    ErrCode result = bundleMgrProxy->CleanBundleCacheFiles(BUNDLE_NAME_TEST, nullptr);
    EXPECT_NE(result, ERR_OK);

    CleanFileDir();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanBundleCacheFilesAutomatic_0200
 * @tc.name: test CleanBundleCacheFilesAutomatic
 * @tc.desc: 1. system run normally
 *           2. cacheSize is 0
 *           3. return ERR_BUNDLE_MANAGER_INVALID_PARAMETER
 */
HWTEST_F(BmsCleanAllBundleCacheTest, CleanBundleCacheFilesAutomatic_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    uint64_t cacheSize = 0;
    ErrCode result = bundleMgrProxy->CleanBundleCacheFilesAutomatic(cacheSize);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: InnerCleanBundleCacheForSelfCallback_0100
 * @tc.name: test InnerCleanBundleCacheForSelfCallback with null callback
 * @tc.desc: 1. system run normally
 *           2. cleanCacheCallback is nullptr
 *           3. return ERROR_BUNDLE_SERVICE_EXCEPTION
 */
HWTEST_F(BmsCleanAllBundleCacheTest, InnerCleanBundleCacheForSelfCallback_0100, Function | SmallTest | Level1)
{
    sptr<CleanCacheCallback> cleanCacheCallback = nullptr;
    ErrCode result = BundleManagerHelper::InnerCleanBundleCacheForSelfCallback(cleanCacheCallback);
    EXPECT_EQ(result, ERROR_BUNDLE_SERVICE_EXCEPTION);
}

/**
 * @tc.number: InnerCleanBundleCacheForSelfCallback_0200
 * @tc.name: test InnerCleanBundleCacheForSelfCallback with valid callback
 * @tc.desc: 1. system run normally
 *           2. cleanCacheCallback is valid
 *           3. test successful execution path
 */
HWTEST_F(BmsCleanAllBundleCacheTest, InnerCleanBundleCacheForSelfCallback_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    CreateFileDir();

    sptr<CleanCacheCallback> cleanCacheCallback = new (std::nothrow) CleanCacheCallback();
    EXPECT_NE(cleanCacheCallback, nullptr);
    
    ErrCode result = BundleManagerHelper::InnerCleanBundleCacheForSelfCallback(cleanCacheCallback);
    EXPECT_NE(result, ERROR_BUNDLE_SERVICE_EXCEPTION);

    CleanFileDir();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: InnerCleanBundleCacheForSelfCallback_0300
 * @tc.name: test InnerCleanBundleCacheForSelfCallback error handling
 * @tc.desc: 1. system run normally
 *           2. test error handling when bundle manager operations fail
 *           3. verify error code conversion
 */
HWTEST_F(BmsCleanAllBundleCacheTest, InnerCleanBundleCacheForSelfCallback_0300, Function | SmallTest | Level1)
{
    sptr<CleanCacheCallback> cleanCacheCallback = new (std::nothrow) CleanCacheCallback();
    EXPECT_NE(cleanCacheCallback, nullptr);
    
    ErrCode result = BundleManagerHelper::InnerCleanBundleCacheForSelfCallback(cleanCacheCallback);
    EXPECT_NE(result, ERR_OK);
    EXPECT_NE(result, ERROR_BUNDLE_SERVICE_EXCEPTION);
}

/**
 * @tc.number: HandleCleanBundleCacheFilesForSelf_0100
 * @tc.name: test with null remote object
 * @tc.desc: 1. Prepare MessageParcel data without writing remote object
 *           2. Call HandleCleanBundleCacheFilesForSelf
 *           3. Expect ERR_APPEXECFWK_PARCEL_ERROR
 */
HWTEST_F(BmsCleanAllBundleCacheTest, HandleCleanBundleCacheFilesForSelf_0100, Function | SmallTest | Level1)
{
    MessageParcel data;
    MessageParcel reply;

    BundleMgrHost host;
    ErrCode result = host.HandleCleanBundleCacheFilesForSelf(data, reply);

    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleCleanBundleCacheFilesForSelf_0200
 * @tc.name: test with invalid remote object type
 * @tc.desc: 1. Write a non-ICleanCacheCallback remote object to MessageParcel data
 *           2. Call HandleCleanBundleCacheFilesForSelf
 *           3. Expect iface_cast to fail and return ERR_APPEXECFWK_PARCEL_ERROR
 */
HWTEST_F(BmsCleanAllBundleCacheTest, HandleCleanBundleCacheFilesForSelf_0200, Function | SmallTest | Level1)
{
    MessageParcel data;
    MessageParcel reply;
    
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    sptr<IRemoteObject> mockObject = hostImpl->AsObject();
    ASSERT_NE(mockObject, nullptr);
    
    data.WriteRemoteObject(mockObject);

    BundleMgrHost host;
    ErrCode result = host.HandleCleanBundleCacheFilesForSelf(data, reply);

    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}
}