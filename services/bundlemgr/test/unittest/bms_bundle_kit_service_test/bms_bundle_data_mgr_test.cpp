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
#define protected public

#include <chrono>
#include <fstream>
#include <thread>
#include <gtest/gtest.h>

#include "ability_manager_client.h"
#include "ability_info.h"
#include "app_provision_info.h"
#include "app_provision_info_manager.h"
#include "bundle_data_mgr.h"
#include "bundle_info.h"
#include "bundle_permission_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "bundle_mgr_host.h"
#include "bundle_mgr_proxy.h"
#include "bundle_status_callback_proxy.h"
#include "bundle_stream_installer_host_impl.h"
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
#include "service_control.h"
#include "system_ability_helper.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using OHOS::AAFwk::Want;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME_TEST = "com.example.bundlekit.test";
const std::string MODULE_NAME_TEST = "com.example.bundlekit.test.entry";
const std::string ABILITY_NAME_TEST = ".Reading";
const std::string BUNDLE_TEST1 = "bundleName1";
const std::string BUNDLE_TEST2 = "bundleName2";
const int32_t BASE_TEST_UID = 65535;
const int32_t TEST_UID = 20065535;
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
const int INVALID_UID = -1;
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
const int FORMINFO_DESCRIPTIONID = 123;

const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
const int32_t ICON_ID = 16777258;
const int32_t LABEL_ID = 16777257;

const size_t ZERO = 0;
}  // namespace

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

public:
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
    std::shared_ptr<InstalldService> service_ = std::make_shared<InstalldService>();
    std::shared_ptr<LauncherService> launcherService_ = std::make_shared<LauncherService>();
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr_ = std::make_shared<BundleCommonEventMgr>();
    std::shared_ptr<BundleUserMgrHostImpl> bundleUserMgrHostImpl_ = std::make_shared<BundleUserMgrHostImpl>();
    NotifyBundleEvents installRes_;
    const std::shared_ptr<BundleDataMgr> dataMgrInfo_ =
        DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_;
};

void BmsBundleDataMgrTest::SetUpTestCase()
{}

void BmsBundleDataMgrTest::TearDownTestCase()
{}

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
    if (!service_->IsServiceReady()) {
        service_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
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
    EXPECT_NE(dataMgrInfo_, nullptr);
    bundleMgrService_->dataMgr_ = dataMgrInfo_;
    EXPECT_NE(bundleMgrService_->dataMgr_, nullptr);
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
    Skill skill {{ACTION}, {ENTITY}};
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
    Skill skill {{ACTION}, {ENTITY}};
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
    auto accessTokenId = BundlePermissionMgr::CreateAccessTokenIdEx(innerBundleInfo, bundleName, USERID);
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
        Skill skill {{ACTION}, {ENTITY}};
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
    bool res = GetBundleDataMgr()->QueryAbilityInfoByUri(
        Constants::DATA_ABILITY_URI_PREFIX + Constants::DATA_ABILITY_URI_SEPARATOR, Constants::ALL_USERID, abilityInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: QueryAbilityInfosByUri_0100
 * @tc.name: test QueryAbilityInfoByUri
 * @tc.desc: 1.system run normally
 *           2.check QueryAbilityInfoByUri failed
 */
HWTEST_F(BmsBundleDataMgrTest, QueryAbilityInfosByUri_0100, Function | SmallTest | Level1)
{
    std::vector<AbilityInfo> abilityInfo;
    InnerBundleInfo innerBundleInfo;
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    bool res = GetBundleDataMgr()->QueryAbilityInfosByUri(Constants::DATA_ABILITY_URI_PREFIX, abilityInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: QueryAbilityInfosByUri_0200
 * @tc.name: test QueryAbilityInfoByUri
 * @tc.desc: 1.system run normally
 *           2.check QueryAbilityInfoByUri failed
 */
HWTEST_F(BmsBundleDataMgrTest, QueryAbilityInfosByUri_0200, Function | SmallTest | Level1)
{
    std::vector<AbilityInfo> abilityInfo;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    GetBundleDataMgr()->bundleInfos_.emplace(BUNDLE_TEST1, innerBundleInfo);
    bool res = GetBundleDataMgr()->QueryAbilityInfosByUri(
        Constants::DATA_ABILITY_URI_PREFIX + Constants::DATA_ABILITY_URI_SEPARATOR, abilityInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: GetApplicationInfos_0100
 * @tc.name: test QueryAbilityInfoByUri
 * @tc.desc: 1.system run normally
 *           2.check QueryAbilityInfoByUri failed
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
 * @tc.name: test QueryAbilityInfoByUri
 * @tc.desc: 1.system run normally
 *           2.check QueryAbilityInfoByUri failed
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
}