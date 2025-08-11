/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "aging/aging_handler.h"
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
const std::string COMMON_EVENT_EVENT_ERROR_KEY = "usual.event.PACKAGE_ADDED_D";
const std::string COMMON_EVENT_EVENT_NOT_EXISTS_KEY = "usual.event.PACKAGE_REMOVED";
const int FORMINFO_DESCRIPTIONID = 123;
const std::string ACTION_001 = "action001";
const std::string ACTION_002 = "action002";
const std::string ENTITY_001 = "entity001";
const std::string ENTITY_002 = "entity002";
const std::string TYPE_001 = "type001";
const std::string TYPE_002 = "type002";
const std::string TYPE_IMG_REGEX = "img/*";
const std::string TYPE_IMG_JPEG = "img/jpeg";
const std::string TYPE_WILDCARD = "*/*";
const std::string SCHEME_SEPARATOR = "://";
const std::string PORT_SEPARATOR = ":";
const std::string PATH_SEPARATOR = "/";
const std::string PARAM_AND_VALUE = "?param=value";
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
const int32_t DEFAULT_USERID = 100;
const int32_t ALL_USERID = -3;
const int32_t WAIT_TIME = 5; // init mocked bms
const int32_t ICON_ID = 16777258;
const int32_t LABEL_ID = 16777257;
const int32_t TEST_APP_INDEX1 = 1;
const int32_t TEST_APP_INDEX2 = 2;
const int32_t TEST_APP_INDEX3 = 3;
const int32_t TOTAL_APP_NUMS = 4;
const int32_t TEST_ACCESS_TOKENID = 1;
const int32_t TEST_ACCESS_TOKENID_EX = 2;
const std::string BUNDLE_NAME = "bundleName";
const std::string LAUNCHER_BUNDLE_NAME = "launcherBundleName";
const std::string MODULE_NAME = "moduleName";
const std::string ABILITY_NAME = "abilityName";
const std::string SHORTCUT_ID_KEY = "shortcutId";
const std::string ICON_KEY = "icon";
const std::string ICON_ID_KEY = "iconId";
const std::string LABEL_KEY = "label";
const std::string LABEL_ID_KEY = "labelId";
const std::string SHORTCUT_WANTS_KEY = "wants";
const std::string SHORTCUTS_KEY = "shortcuts";
const std::string HAP_NAME = "test.hap";
const size_t ZERO = 0;
constexpr const char* ILLEGAL_PATH_FIELD = "../";
const std::string BUNDLE_NAME_UNINSTALL_STATE = "bundleNameUninstallState";
const std::string URI_ISOLATION_ONLY = "isolationOnly";
const std::string URI_PERMISSION = "ohos.permission.GET_BUNDLE_INFO";
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
const std::string ERROR_LINK_FEATURE = "ERROR_LINK";
const std::string FILE_URI = "test.jpg";
const std::string URI_MIME_IMAGE = "image/jpeg";
constexpr const char* TYPE_ONLY_MATCH_WILDCARD = "reserved/wildcard";
const std::string TYPE_VIDEO_AVI = "video/avi";
const std::string TYPE_VIDEO_MS_VIDEO = "video/x-msvideo";
const std::string UTD_GENERAL_AVI = "general.avi";
const std::string UTD_GENERAL_VIDEO = "general.video";
constexpr const char* APP_LINKING = "applinking";
const int32_t APP_INDEX = 1;
const std::string CALLER_NAME_UT = "ut";
const int32_t MAX_WAITING_TIME = 600;
constexpr uint16_t UUID_LENGTH_MAX = 512;
}  // namespace

class BmsBundleKitServiceTest : public testing::Test {
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
    void MockInstallExtensionWithUri(
        const std::string &bundleName, const std::string &moduleName, const std::string &extensionName) const;
    void MockInstallBundle(
        const std::string &bundleName, const std::vector<std::string> &moduleNameList, const std::string &abilityName,
        bool userDataClearable = true, bool isSystemApp = false) const;
    void MockUninstallBundle(const std::string &bundleName) const;
    AbilityInfo MockAbilityInfo(
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
    void CheckBundleInfo(const std::string &bundleName, const std::string &moduleName, const uint32_t abilitySize,
        const BundleInfo &bundleInfo) const;
    void CheckBundleArchiveInfo(const std::string &bundleName, const std::string &moduleName,
        const uint32_t abilitySize, const BundleInfo &bundleInfo) const;
    void CheckBundleList(const std::string &bundleName, const std::vector<std::string> &bundleList) const;
    void CheckApplicationInfo(
        const std::string &bundleName, const uint32_t permissionSize, const ApplicationInfo &appInfo) const;
    void CheckAbilityInfo(const std::string &bundleName, const std::string &abilityName, int32_t flags,
        const AbilityInfo &appInfo) const;
    void CheckAbilityInfos(const std::string &bundleName, const std::string &abilityName, int32_t flags,
        const std::vector<AbilityInfo> &appInfo) const;
    void CheckSkillInfos(const std::vector<Skill> &skill) const;
    void CheckCompatibleApplicationInfo(
        const std::string &bundleName, const uint32_t permissionSize, const CompatibleApplicationInfo &appInfo) const;
    void CheckCompatibleAbilityInfo(
        const std::string &bundleName, const std::string &abilityName, const CompatibleAbilityInfo &appInfo) const;
    void CheckInstalledBundleInfos(const uint32_t abilitySize, const std::vector<BundleInfo> &bundleInfos) const;
    void CheckInstalledApplicationInfos(const uint32_t permsSize, const std::vector<ApplicationInfo> &appInfos) const;
    void CheckModuleInfo(const HapModuleInfo &hapModuleInfo) const;
    void CreateFileDir() const;
    void CleanFileDir() const;
    void CheckFileExist() const;
    void CheckFileNonExist() const;
    void CheckCacheExist() const;
    void CheckCacheNonExist() const;
    void CheckFormInfoTest(const std::vector<FormInfo> &forms) const;
    void CheckFormInfoDemo(const std::vector<FormInfo> &forms) const;
    void CheckShortcutInfoTest(std::vector<ShortcutInfo> &shortcutInfos) const;
    void CheckCommonEventInfoTest(std::vector<CommonEventInfo> &commonEventInfos) const;
    void CheckShortcutInfoDemo(std::vector<ShortcutInfo> &shortcutInfos) const;
    void AddBundleInfo(const std::string &bundleName, BundleInfo &bundleInfo) const;
    void AddApplicationInfo(const std::string &bundleName, ApplicationInfo &appInfo,
        bool userDataClearable = true, bool isSystemApp = false) const;
    void AddInnerBundleInfoByTest(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, InnerBundleInfo &innerBundleInfo) const;
    void SaveToDatabase(const std::string &bundleName, InnerBundleInfo &innerBundleInfo,
        bool userDataClearable, bool isSystemApp) const;
    void ShortcutWantToJson(nlohmann::json &jsonObject, const ShortcutWant &shortcutWant);
    void ClearBundleInfo(const std::string &bundleName);
    void AddCloneInfo(const std::string &bundleName, int32_t userId, int32_t appIndex);
    void ClearCloneInfo(const std::string &bundleName, int32_t userId);
    bool ChangeAppDisabledStatus(const std::string &bundleName, int32_t userId, int32_t appIndex, bool isEnabled);
    void QueryCloneApplicationInfosWithDisable();
    void QueryCloneApplicationInfosV9WithDisable();
    void QueryCloneAbilityInfosV9WithDisable(const Want &want);
    Skill MockAbilitySkillInfo() const;
    Skill MockExtensionSkillInfo() const;
    int32_t MockGetCurrentActiveUserId();
    ErrCode MockGetAllBundleCacheStat(const sptr<IProcessCacheCallback> processCacheCallback);
    ErrCode MockCleanAllBundleCache(const sptr<IProcessCacheCallback> processCacheCallback);

public:
    static std::shared_ptr<InstalldService> installdService_;
    std::shared_ptr<BundleMgrHostImpl> bundleMgrHostImpl_ = std::make_unique<BundleMgrHostImpl>();
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    std::shared_ptr<LauncherService> launcherService_ = std::make_shared<LauncherService>();
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr_ = std::make_shared<BundleCommonEventMgr>();
    std::shared_ptr<BundleUserMgrHostImpl> bundleUserMgrHostImpl_ = std::make_shared<BundleUserMgrHostImpl>();
    NotifyBundleEvents installRes_;
};

class ProcessCacheCallbackImpl : public ProcessCacheCallbackHost {
public:
    ProcessCacheCallbackImpl() : cacheStat_(std::make_shared<std::promise<uint64_t>>()),
        cleanResult_(std::make_shared<std::promise<int32_t>>()) {}
    ~ProcessCacheCallbackImpl() override
    {}
    void OnGetAllBundleCacheFinished(uint64_t cacheStat) override;
    void OnCleanAllBundleCacheFinished(int32_t result) override;
    uint64_t GetCacheStat() override;
    int32_t GetDelRet();
private:
    std::shared_ptr<std::promise<uint64_t>> cacheStat_;
    std::shared_ptr<std::promise<int32_t>> cleanResult_;
    DISALLOW_COPY_AND_MOVE(ProcessCacheCallbackImpl);
};

void ProcessCacheCallbackImpl::OnGetAllBundleCacheFinished(uint64_t cacheStat)
{
    if (cacheStat_ != nullptr) {
        cacheStat_->set_value(cacheStat);
    }
}

void ProcessCacheCallbackImpl::OnCleanAllBundleCacheFinished(int32_t result)
{
    if (cleanResult_ != nullptr) {
        cleanResult_->set_value(result);
    }
}

uint64_t ProcessCacheCallbackImpl::GetCacheStat()
{
    if (cacheStat_ != nullptr) {
        auto future = cacheStat_->get_future();
        std::chrono::milliseconds span(MAX_WAITING_TIME);
        if (future.wait_for(span) == std::future_status::timeout) {
            return 0;
        }
        return future.get();
    }
    return 0;
};

int32_t ProcessCacheCallbackImpl::GetDelRet()
{
    if (cleanResult_ != nullptr) {
        auto future = cleanResult_->get_future();
        std::chrono::milliseconds span(MAX_WAITING_TIME);
        if (future.wait_for(span) == std::future_status::timeout) {
            return -1;
        }
        return future.get();
    }
    return -1;
};

class ICleanCacheCallbackTest : public ICleanCacheCallback {
public:
    void OnCleanCacheFinished(bool succeeded);
    sptr<IRemoteObject> AsObject();
};

void ICleanCacheCallbackTest::OnCleanCacheFinished(bool succeeded) {}

sptr<IRemoteObject> ICleanCacheCallbackTest::AsObject()
{
    return nullptr;
}

class IBundleInstallerTest : public IBundleInstaller {
    bool Install(const std::string& bundleFilePath, const InstallParam& installParam,
        const sptr<IStatusReceiver>& statusReceiver);
    bool Recover(
        const std::string& bundleName, const InstallParam& installParam, const sptr<IStatusReceiver>& statusReceiver);
    bool Install(const std::vector<std::string>& bundleFilePaths, const InstallParam& installParam,
        const sptr<IStatusReceiver>& statusReceiver);
    bool Uninstall(
        const std::string& bundleName, const InstallParam& installParam, const sptr<IStatusReceiver>& statusReceiver);
    bool Uninstall(const UninstallParam& uninstallParam, const sptr<IStatusReceiver>& statusReceiver);
    bool Uninstall(const std::string& bundleName, const std::string& modulePackage, const InstallParam& installParam,
        const sptr<IStatusReceiver>& statusReceiver);
    ErrCode InstallSandboxApp(const std::string& bundleName, int32_t dlpType, int32_t userId, int32_t& appIndex);
    ErrCode UninstallSandboxApp(const std::string& bundleName, int32_t appIndex, int32_t userId);
    sptr<IBundleStreamInstaller> CreateStreamInstaller(const InstallParam& installParam,
        const sptr<IStatusReceiver>& statusReceiver, const std::vector<std::string>& originHapPaths);
    bool DestoryBundleStreamInstaller(uint32_t streamInstallerId);
    ErrCode StreamInstall(const std::vector<std::string>& bundleFilePaths, const InstallParam& installParam,
        const sptr<IStatusReceiver>& statusReceiver);
    sptr<IRemoteObject> AsObject();
};

bool IBundleInstallerTest::Install(
    const std::string& bundleFilePath, const InstallParam& installParam, const sptr<IStatusReceiver>& statusReceiver)
{
    return true;
}

bool IBundleInstallerTest::Recover(
    const std::string& bundleName, const InstallParam& installParam, const sptr<IStatusReceiver>& statusReceiver)
{
    return true;
}

bool IBundleInstallerTest::Install(const std::vector<std::string>& bundleFilePaths, const InstallParam& installParam,
    const sptr<IStatusReceiver>& statusReceiver)
{
    return true;
}

bool IBundleInstallerTest::Uninstall(
    const std::string& bundleName, const InstallParam& installParam, const sptr<IStatusReceiver>& statusReceiver)
{
    return true;
}

bool IBundleInstallerTest::Uninstall(const UninstallParam& uninstallParam, const sptr<IStatusReceiver>& statusReceiver)
{
    return true;
}

bool IBundleInstallerTest::Uninstall(const std::string& bundleName, const std::string& modulePackage,
    const InstallParam& installParam, const sptr<IStatusReceiver>& statusReceiver)
{
    return true;
}

ErrCode IBundleInstallerTest::InstallSandboxApp(
    const std::string& bundleName, int32_t dlpType, int32_t userId, int32_t& appIndex)
{
    return ERR_OK;
}

ErrCode IBundleInstallerTest::UninstallSandboxApp(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    return ERR_OK;
}

sptr<IBundleStreamInstaller> IBundleInstallerTest::CreateStreamInstaller(const InstallParam& installParam,
    const sptr<IStatusReceiver>& statusReceiver, const std::vector<std::string>& originHapPaths)
{
    return nullptr;
}

bool IBundleInstallerTest::DestoryBundleStreamInstaller(uint32_t streamInstallerId)
{
    return true;
}

ErrCode IBundleInstallerTest::StreamInstall(const std::vector<std::string>& bundleFilePaths,
    const InstallParam& installParam, const sptr<IStatusReceiver>& statusReceiver)
{
    return ERR_OK;
}

sptr<IRemoteObject> IBundleInstallerTest::AsObject()
{
    return nullptr;
}

class IBundleStatusCallbackTest : public IBundleStatusCallback {
public:
    void OnBundleStateChanged(const uint8_t installType, const int32_t resultCode, const std::string& resultMsg,
        const std::string& bundleName);
    void OnBundleAdded(const std::string& bundleName, const int userId);
    void OnBundleUpdated(const std::string& bundleName, const int userId);
    void OnBundleRemoved(const std::string& bundleName, const int userId);
    sptr<IRemoteObject> AsObject();
};

void IBundleStatusCallbackTest::OnBundleStateChanged(
    const uint8_t installType, const int32_t resultCode, const std::string& resultMsg, const std::string& bundleName)
{}

void IBundleStatusCallbackTest::OnBundleAdded(const std::string& bundleName, const int userId)
{
    SetBundleName(MODULE_NAME_TEST_1);
}

void IBundleStatusCallbackTest::OnBundleUpdated(const std::string& bundleName, const int userId)
{
    SetBundleName(MODULE_NAME_TEST_2);
}

void IBundleStatusCallbackTest::OnBundleRemoved(const std::string& bundleName, const int userId)
{
    SetBundleName(MODULE_NAME_TEST_3);
}

sptr<IRemoteObject> IBundleStatusCallbackTest::AsObject()
{
    return nullptr;
}

std::shared_ptr<BundleMgrService> BmsBundleKitServiceTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleKitServiceTest::installdService_ =
    std::make_shared<InstalldService>();

void BmsBundleKitServiceTest::SetUpTestCase()
{}

void BmsBundleKitServiceTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleKitServiceTest::SetUp()
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

void BmsBundleKitServiceTest::TearDown()
{}

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
const std::shared_ptr<BundleDistributedManager> BmsBundleKitServiceTest::GetBundleDistributedManager() const
{
    return bundleMgrService_->GetBundleDistributedManager();
}
#endif

std::shared_ptr<BundleDataMgr> BmsBundleKitServiceTest::GetBundleDataMgr() const
{
    bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
    EXPECT_NE(bundleMgrService_, nullptr);
    return bundleMgrService_->GetDataMgr();
}

std::shared_ptr<LauncherService> BmsBundleKitServiceTest::GetLauncherService() const
{
    return launcherService_;
}

sptr<BundleMgrProxy> BmsBundleKitServiceTest::GetBundleMgrProxy()
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

void BmsBundleKitServiceTest::AddBundleInfo(const std::string &bundleName, BundleInfo &bundleInfo) const
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

void BmsBundleKitServiceTest::AddApplicationInfo(const std::string &bundleName, ApplicationInfo &appInfo,
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

void BmsBundleKitServiceTest::AddInnerBundleInfoByTest(const std::string &bundleName,
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

void BmsBundleKitServiceTest::MockInstallBundle(
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

void BmsBundleKitServiceTest::MockInstallExtension(const std::string &bundleName,
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

void BmsBundleKitServiceTest::MockInstallExtensionWithUri(const std::string &bundleName,
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
    Skill skill = MockExtensionSkillInfo();
    std::vector<Skill> skills;
    skills.emplace_back(skill);
    innerBundleInfo.InsertExtensionSkillInfo(keyName, skills);
    innerBundleInfo.InsertExtensionSkillInfo(keyName02, skills);
    SaveToDatabase(bundleName, innerBundleInfo, false, false);
}

InnerModuleInfo BmsBundleKitServiceTest::MockModuleInfo(const std::string &moduleName) const
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

void BmsBundleKitServiceTest::SaveToDatabase(const std::string &bundleName,
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

void BmsBundleKitServiceTest::MockInstallBundle(
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

FormInfo BmsBundleKitServiceTest::MockFormInfo(
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

ShortcutInfo BmsBundleKitServiceTest::MockShortcutInfo(
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

ShortcutIntent BmsBundleKitServiceTest::MockShortcutIntent() const
{
    ShortcutIntent shortcutIntent;
    shortcutIntent.targetBundle = SHORTCUT_INTENTS_TARGET_BUNDLE;
    shortcutIntent.targetModule = SHORTCUT_INTENTS_TARGET_MODULE;
    shortcutIntent.targetClass = SHORTCUT_INTENTS_TARGET_CLASS;
    return shortcutIntent;
}

ShortcutWant BmsBundleKitServiceTest::MockShortcutWant() const
{
    ShortcutWant shortcutWant;
    shortcutWant.bundleName = BUNDLE_NAME_DEMO;
    shortcutWant.moduleName = MODULE_NAME_DEMO;
    shortcutWant.abilityName = ABILITY_NAME_DEMO;
    return shortcutWant;
}

Shortcut BmsBundleKitServiceTest::MockShortcut() const
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

CommonEventInfo BmsBundleKitServiceTest::MockCommonEventInfo(
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

void BmsBundleKitServiceTest::MockUninstallBundle(const std::string &bundleName) const
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool startRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START);
    bool finishRet = dataMgr->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS);

    EXPECT_TRUE(startRet);
    EXPECT_TRUE(finishRet);
}

Skill BmsBundleKitServiceTest::MockAbilitySkillInfo() const
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

Skill BmsBundleKitServiceTest::MockExtensionSkillInfo() const
{
    Skill skillForExtension;
    SkillUri uri;
    uri.scheme = URI_SCHEME;
    uri.host = URI_HOST;
    uri.port = URI_PORT;
    uri.path = URI_PATH;
    uri.pathStartWith = URI_PATH_START_WITH;
    uri.pathRegex = URI_PATH_REGEX;
    uri.type = EMPTY_STRING;
    uri.utd = URI_UTD;
    skillForExtension.actions.push_back(ACTION);
    skillForExtension.entities.push_back(ENTITY);
    skillForExtension.uris.push_back(uri);
    skillForExtension.permissions.push_back(SKILL_PERMISSION);
    return skillForExtension;
}

AbilityInfo BmsBundleKitServiceTest::MockAbilityInfo(
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
    Skill skill = MockAbilitySkillInfo();
    abilityInfo.skills.push_back(skill);
    abilityInfo.skills.push_back(skill);
    return abilityInfo;
}

InnerExtensionInfo BmsBundleKitServiceTest::MockExtensionInfo(
    const std::string &bundleName, const std::string &moduleName, const std::string &extensionName) const
{
    InnerExtensionInfo extensionInfo;
    extensionInfo.name = extensionName;
    extensionInfo.bundleName = bundleName;
    extensionInfo.moduleName = moduleName;
    Skill skill = MockExtensionSkillInfo();
    extensionInfo.skills.push_back(skill);
    extensionInfo.skills.push_back(skill);
    return extensionInfo;
}

void BmsBundleKitServiceTest::MockInnerBundleInfo(const std::string &bundleName, const std::string &moduleName,
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

void BmsBundleKitServiceTest::CheckBundleInfo(const std::string &bundleName, const std::string &moduleName,
    const uint32_t abilitySize, const BundleInfo &bundleInfo) const
{
    EXPECT_EQ(bundleName, bundleInfo.name);
    EXPECT_EQ(BUNDLE_LABEL, bundleInfo.label);
    EXPECT_EQ(BUNDLE_DESCRIPTION, bundleInfo.description);
    EXPECT_EQ(BUNDLE_VENDOR, bundleInfo.vendor);
    EXPECT_EQ(BUNDLE_VERSION_CODE, bundleInfo.versionCode);
    EXPECT_EQ(BUNDLE_VERSION_NAME, bundleInfo.versionName);
    EXPECT_EQ(BUNDLE_MIN_SDK_VERSION, bundleInfo.minSdkVersion);
    EXPECT_EQ(BUNDLE_MAX_SDK_VERSION, bundleInfo.maxSdkVersion);
    EXPECT_EQ(BUNDLE_MAIN_ABILITY, bundleInfo.mainEntry);
    EXPECT_EQ(bundleName, bundleInfo.applicationInfo.name);
    EXPECT_EQ(bundleName, bundleInfo.applicationInfo.bundleName);
    EXPECT_EQ(abilitySize, static_cast<uint32_t>(bundleInfo.abilityInfos.size()));
    EXPECT_EQ(true, bundleInfo.isDifferentName);
    EXPECT_EQ(BUNDLE_JOINT_USERID, bundleInfo.jointUserId);
    EXPECT_TRUE(bundleInfo.isKeepAlive);
    EXPECT_TRUE(bundleInfo.singleton);
}

void BmsBundleKitServiceTest::CheckBundleArchiveInfo(const std::string &bundleName, const std::string &moduleName,
    const uint32_t abilitySize, const BundleInfo &bundleInfo) const
{
    EXPECT_EQ(bundleName, bundleInfo.name);
    EXPECT_EQ(BUNDLE_LABEL, bundleInfo.label);
    EXPECT_EQ(BUNDLE_DESCRIPTION, bundleInfo.description);
    EXPECT_EQ(BUNDLE_VENDOR, bundleInfo.vendor);
    EXPECT_EQ(BUNDLE_VERSION_CODE, bundleInfo.versionCode);
    EXPECT_EQ(BUNDLE_VERSION_NAME, bundleInfo.versionName);
    EXPECT_EQ(BUNDLE_MIN_SDK_VERSION, bundleInfo.minSdkVersion);
    EXPECT_EQ(BUNDLE_MAX_SDK_VERSION, bundleInfo.maxSdkVersion);
    EXPECT_EQ(BUNDLE_MAIN_ABILITY, bundleInfo.mainEntry);
    EXPECT_EQ(bundleName, bundleInfo.applicationInfo.name);
    EXPECT_EQ(bundleName, bundleInfo.applicationInfo.bundleName);
    EXPECT_EQ(abilitySize, static_cast<uint32_t>(bundleInfo.abilityInfos.size()));
}

void BmsBundleKitServiceTest::CheckBundleList(
    const std::string &bundleName, const std::vector<std::string> &bundleList) const
{
    EXPECT_TRUE(std::find(bundleList.begin(), bundleList.end(), bundleName) != bundleList.end());
}

void BmsBundleKitServiceTest::CheckApplicationInfo(
    const std::string &bundleName, const uint32_t permissionSize, const ApplicationInfo &appInfo) const
{
    EXPECT_EQ(bundleName, appInfo.name);
    EXPECT_EQ(bundleName, appInfo.bundleName);
    EXPECT_EQ(BUNDLE_LABEL, appInfo.label);
    EXPECT_EQ(BUNDLE_DESCRIPTION, appInfo.description);
    EXPECT_EQ(DEVICE_ID, appInfo.deviceId);
    EXPECT_EQ(PROCESS_TEST, appInfo.process);
    EXPECT_EQ(CODE_PATH, appInfo.codePath);
    EXPECT_EQ(permissionSize, static_cast<uint32_t>(appInfo.permissions.size()));
    EXPECT_EQ(APPLICATION_INFO_FLAGS, appInfo.flags);
}

void BmsBundleKitServiceTest::CheckAbilityInfo(
    const std::string &bundleName, const std::string &abilityName, int32_t flags, const AbilityInfo &abilityInfo) const
{
    EXPECT_EQ(abilityName, abilityInfo.name);
    EXPECT_EQ(bundleName, abilityInfo.bundleName);
    EXPECT_EQ(LABEL, abilityInfo.label);
    EXPECT_EQ(DESCRIPTION, abilityInfo.description);
    EXPECT_EQ(DEVICE_ID, abilityInfo.deviceId);
    EXPECT_EQ(THEME, abilityInfo.theme);
    EXPECT_EQ(ICON_PATH, abilityInfo.iconPath);
    EXPECT_EQ(CODE_PATH, abilityInfo.codePath);
    EXPECT_EQ(ORIENTATION, abilityInfo.orientation);
    EXPECT_EQ(LAUNCH_MODE, abilityInfo.launchMode);
    EXPECT_EQ(URI, abilityInfo.uri);
    EXPECT_EQ(false, abilityInfo.supportPipMode);
    EXPECT_EQ(TARGET_ABILITY, abilityInfo.targetAbility);
    EXPECT_EQ(CONFIG_CHANGES, abilityInfo.configChanges);
    EXPECT_EQ(BACKGROUND_MODES, abilityInfo.backgroundModes);
    EXPECT_EQ(FORM_ENTITY, abilityInfo.formEntity);
    EXPECT_EQ(DEFAULT_FORM_HEIGHT, abilityInfo.defaultFormHeight);
    EXPECT_EQ(DEFAULT_FORM_WIDTH, abilityInfo.defaultFormWidth);
    if ((flags & GET_ABILITY_INFO_WITH_METADATA) != GET_ABILITY_INFO_WITH_METADATA) {
        EXPECT_EQ(0, abilityInfo.metaData.customizeData.size());
    } else {
        for (auto &info : abilityInfo.metaData.customizeData) {
            EXPECT_EQ(info.name, META_DATA_NAME);
            EXPECT_EQ(info.value, META_DATA_VALUE);
            EXPECT_EQ(info.extra, META_DATA_EXTRA);
        }
    }
}

void BmsBundleKitServiceTest::CheckSkillInfos(const std::vector<Skill> &skills) const
{
    for (auto skill : skills) {
        EXPECT_EQ(skill.actions[0], ACTION);
        EXPECT_EQ(skill.entities[0], ENTITY);
        EXPECT_EQ(skill.uris[0].scheme, URI_SCHEME);
        EXPECT_EQ(skill.uris[0].host, URI_HOST);
        EXPECT_EQ(skill.uris[0].port, URI_PORT);
        EXPECT_EQ(skill.uris[0].path, URI_PATH);
        EXPECT_EQ(skill.uris[0].pathStartWith, URI_PATH_START_WITH);
        EXPECT_EQ(skill.uris[0].pathRegex, URI_PATH_REGEX);
        EXPECT_EQ(skill.uris[0].type, EMPTY_STRING);
        EXPECT_EQ(skill.uris[0].utd, URI_UTD);
        EXPECT_EQ(skill.uris[0].maxFileSupported, MAX_FILE_SUPPORTED);
        EXPECT_EQ(skill.uris[0].linkFeature, URI_LINK_FEATURE);
        EXPECT_EQ(skill.actions[0], ACTION);
        EXPECT_EQ(skill.entities[0], ENTITY);
        EXPECT_EQ(skill.domainVerify, true);
        EXPECT_EQ(skill.permissions[0], SKILL_PERMISSION);
    }
}

void BmsBundleKitServiceTest::CheckAbilityInfos(const std::string &bundleName, const std::string &abilityName,
    int32_t flags, const std::vector<AbilityInfo> &abilityInfos) const
{
    for (auto abilityInfo : abilityInfos) {
        EXPECT_EQ(abilityName, abilityInfo.name);
        EXPECT_EQ(bundleName, abilityInfo.bundleName);
        EXPECT_EQ(LABEL, abilityInfo.label);
        EXPECT_EQ(DESCRIPTION, abilityInfo.description);
        EXPECT_EQ(DEVICE_ID, abilityInfo.deviceId);
        EXPECT_EQ(THEME, abilityInfo.theme);
        EXPECT_EQ(ICON_PATH, abilityInfo.iconPath);
        EXPECT_EQ(CODE_PATH, abilityInfo.codePath);
        EXPECT_EQ(ORIENTATION, abilityInfo.orientation);
        EXPECT_EQ(LAUNCH_MODE, abilityInfo.launchMode);
        EXPECT_EQ(URI, abilityInfo.uri);
        EXPECT_EQ(false, abilityInfo.supportPipMode);
        EXPECT_EQ(TARGET_ABILITY, abilityInfo.targetAbility);
        EXPECT_EQ(CONFIG_CHANGES, abilityInfo.configChanges);
        EXPECT_EQ(BACKGROUND_MODES, abilityInfo.backgroundModes);
        EXPECT_EQ(FORM_ENTITY, abilityInfo.formEntity);
        EXPECT_EQ(DEFAULT_FORM_HEIGHT, abilityInfo.defaultFormHeight);
        EXPECT_EQ(DEFAULT_FORM_WIDTH, abilityInfo.defaultFormWidth);
        if ((flags & GET_ABILITY_INFO_WITH_METADATA) != GET_ABILITY_INFO_WITH_METADATA) {
            EXPECT_EQ(0, abilityInfo.metaData.customizeData.size());
        } else {
            for (auto &info : abilityInfo.metaData.customizeData) {
                EXPECT_EQ(info.name, META_DATA_NAME);
                EXPECT_EQ(info.value, META_DATA_VALUE);
                EXPECT_EQ(info.extra, META_DATA_EXTRA);
            }
        }
        if ((flags & GET_ABILITY_INFO_WITH_PERMISSION) != GET_ABILITY_INFO_WITH_PERMISSION) {
            EXPECT_EQ(0, abilityInfo.permissions.size());
        } else {
            EXPECT_EQ(PERMISSION_SIZE_TWO, abilityInfo.permissions.size());
        }
        if ((flags & static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_SKILL)) !=
            static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_SKILL)) {
            EXPECT_EQ(abilityInfo.skills.size(), 0);
        } else {
            EXPECT_EQ(abilityInfo.skills.size(), SKILL_SIZE_TWO);
            CheckSkillInfos(abilityInfo.skills);
        }
    }
}

void BmsBundleKitServiceTest::CheckCompatibleAbilityInfo(
    const std::string &bundleName, const std::string &abilityName, const CompatibleAbilityInfo &abilityInfo) const
{
    EXPECT_EQ(abilityName, abilityInfo.name);
    EXPECT_EQ(bundleName, abilityInfo.bundleName);
    EXPECT_EQ(LABEL, abilityInfo.label);
    EXPECT_EQ(DESCRIPTION, abilityInfo.description);
    EXPECT_EQ(DEVICE_ID, abilityInfo.deviceId);
    EXPECT_EQ(ICON_PATH, abilityInfo.iconPath);
    EXPECT_EQ(ORIENTATION, abilityInfo.orientation);
    EXPECT_EQ(LAUNCH_MODE, abilityInfo.launchMode);
    EXPECT_EQ(URI, abilityInfo.uri);
    EXPECT_EQ(false, abilityInfo.supportPipMode);
    EXPECT_EQ(TARGET_ABILITY, abilityInfo.targetAbility);
    EXPECT_EQ(FORM_ENTITY, abilityInfo.formEntity);
    EXPECT_EQ(DEFAULT_FORM_HEIGHT, abilityInfo.defaultFormHeight);
    EXPECT_EQ(DEFAULT_FORM_WIDTH, abilityInfo.defaultFormWidth);
}
void BmsBundleKitServiceTest::CheckCompatibleApplicationInfo(
    const std::string &bundleName, const uint32_t permissionSize, const CompatibleApplicationInfo &appInfo) const
{
    EXPECT_EQ(bundleName, appInfo.name);
    EXPECT_EQ(BUNDLE_LABEL, appInfo.label);
    EXPECT_EQ(BUNDLE_DESCRIPTION, appInfo.description);
    EXPECT_EQ(PROCESS_TEST, appInfo.process);
    EXPECT_EQ(permissionSize, static_cast<uint32_t>(appInfo.permissions.size()));
}

void BmsBundleKitServiceTest::CheckModuleInfo(const HapModuleInfo &hapModuleInfo) const
{
    EXPECT_EQ(MODULE_NAME_TEST, hapModuleInfo.name);
    EXPECT_EQ(MODULE_NAME_TEST, hapModuleInfo.moduleName);
    EXPECT_EQ(BUNDLE_DESCRIPTION, hapModuleInfo.description);
    EXPECT_EQ(ICON_PATH, hapModuleInfo.iconPath);
    EXPECT_EQ(LABEL, hapModuleInfo.label);
    EXPECT_EQ(COLOR_MODE, hapModuleInfo.colorMode);
}

void BmsBundleKitServiceTest::CheckInstalledBundleInfos(
    const uint32_t abilitySize, const std::vector<BundleInfo> &bundleInfos) const
{
    bool isContainsDemoBundle = false;
    bool isContainsTestBundle = false;
    bool checkDemoAppNameRet = false;
    bool checkTestAppNameRet = false;
    bool checkDemoAbilitySizeRet = false;
    bool checkTestAbilitySizeRet = false;
    for (auto item : bundleInfos) {
        if (item.name == BUNDLE_NAME_DEMO) {
            isContainsDemoBundle = true;
            checkDemoAppNameRet = item.applicationInfo.name == BUNDLE_NAME_DEMO;
            uint32_t num = static_cast<uint32_t>(item.abilityInfos.size());
            checkDemoAbilitySizeRet = num == abilitySize;
        }
        if (item.name == BUNDLE_NAME_TEST) {
            isContainsTestBundle = true;
            checkTestAppNameRet = item.applicationInfo.name == BUNDLE_NAME_TEST;
            uint32_t num = static_cast<uint32_t>(item.abilityInfos.size());
            checkTestAbilitySizeRet = num == abilitySize;
        }
    }
    EXPECT_TRUE(isContainsDemoBundle);
    EXPECT_TRUE(isContainsTestBundle);
    EXPECT_TRUE(checkDemoAppNameRet);
    EXPECT_TRUE(checkTestAppNameRet);
    EXPECT_TRUE(checkDemoAbilitySizeRet);
    EXPECT_TRUE(checkTestAbilitySizeRet);
}

void BmsBundleKitServiceTest::CheckInstalledApplicationInfos(
    const uint32_t permsSize, const std::vector<ApplicationInfo> &appInfos) const
{
    bool isContainsDemoBundle = false;
    bool isContainsTestBundle = false;
    bool checkDemoAppNameRet = false;
    bool checkTestAppNameRet = false;
    bool checkDemoAbilitySizeRet = false;
    bool checkTestAbilitySizeRet = false;
    for (auto item : appInfos) {
        if (item.name == BUNDLE_NAME_DEMO) {
            isContainsDemoBundle = true;
            checkDemoAppNameRet = item.bundleName == BUNDLE_NAME_DEMO;
            uint32_t num = static_cast<uint32_t>(item.permissions.size());
            checkDemoAbilitySizeRet = num == permsSize;
        }
        if (item.name == BUNDLE_NAME_TEST) {
            isContainsTestBundle = true;
            checkTestAppNameRet = item.bundleName == BUNDLE_NAME_TEST;
            uint32_t num = static_cast<uint32_t>(item.permissions.size());
            checkTestAbilitySizeRet = num == permsSize;
        }
    }
    EXPECT_TRUE(isContainsDemoBundle);
    EXPECT_TRUE(isContainsTestBundle);
    EXPECT_TRUE(checkDemoAppNameRet);
    EXPECT_TRUE(checkTestAppNameRet);
    EXPECT_TRUE(checkDemoAbilitySizeRet);
    EXPECT_TRUE(checkTestAbilitySizeRet);
}

void BmsBundleKitServiceTest::CreateFileDir() const
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

void BmsBundleKitServiceTest::CleanFileDir() const
{
    installdService_->Stop();
    InstalldClient::GetInstance()->ResetInstalldProxy();

    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR);
}

void BmsBundleKitServiceTest::CheckFileExist() const
{
    int dataExist = access(TEST_FILE_DIR.c_str(), F_OK);
    EXPECT_EQ(dataExist, 0);
}

void BmsBundleKitServiceTest::CheckFileNonExist() const
{
    int dataExist = access(TEST_FILE_DIR.c_str(), F_OK);
    EXPECT_NE(dataExist, 0);
}

void BmsBundleKitServiceTest::CheckCacheExist() const
{
    int dataExist = access(TEST_CACHE_DIR.c_str(), F_OK);
    EXPECT_EQ(dataExist, 0);
}

void BmsBundleKitServiceTest::CheckCacheNonExist() const
{
    int dataExist = access(TEST_CACHE_DIR.c_str(), F_OK);
    EXPECT_NE(dataExist, 0);
}

void BmsBundleKitServiceTest::CheckFormInfoTest(const std::vector<FormInfo> &formInfos) const
{
    for (auto &formInfo : formInfos) {
        EXPECT_EQ(formInfo.name, FORM_NAME);
        EXPECT_EQ(formInfo.bundleName, BUNDLE_NAME_TEST);
        EXPECT_EQ(formInfo.moduleName, MODULE_NAME_TEST);
        EXPECT_EQ(formInfo.abilityName, ABILITY_NAME_TEST);
        EXPECT_EQ(formInfo.description, FORM_DESCRIPTION);
        EXPECT_EQ(formInfo.formConfigAbility, FORM_PATH);
        EXPECT_EQ(formInfo.defaultFlag, false);
        EXPECT_EQ(formInfo.type, FormType::JS);
        EXPECT_EQ(formInfo.colorMode, FormsColorMode::LIGHT_MODE);
        EXPECT_EQ(formInfo.descriptionId, FORMINFO_DESCRIPTIONID);
        EXPECT_EQ(formInfo.deepLink, FORM_PATH);
        EXPECT_EQ(formInfo.package, PACKAGE_NAME);
        EXPECT_EQ(formInfo.formVisibleNotify, true);
        unsigned i = 2;
        EXPECT_EQ(formInfo.supportDimensions.size(), i);
        EXPECT_EQ(formInfo.defaultDimension, 1);
        EXPECT_EQ(formInfo.updateDuration, 0);
        EXPECT_EQ(formInfo.scheduledUpdateTime, FORM_SCHEDULED_UPDATE_TIME);
        EXPECT_EQ(formInfo.jsComponentName, FORM_JS_COMPONENT_NAME);
        EXPECT_EQ(formInfo.updateEnabled, true);
        for (auto &info : formInfo.customizeDatas) {
            EXPECT_EQ(info.name, FORM_CUSTOMIZE_DATAS_NAME);
            EXPECT_EQ(info.value, FORM_CUSTOMIZE_DATAS_VALUE);
        }
        EXPECT_EQ(formInfo.src, FORM_SRC);
        EXPECT_EQ(formInfo.window.designWidth, FORM_JS_WINDOW_DESIGNWIDTH);
        EXPECT_EQ(formInfo.window.autoDesignWidth, true);
        EXPECT_EQ(formInfo.funInteractionParams.abilityName, FORM_ABILITY_NAME);
        EXPECT_EQ(formInfo.funInteractionParams.targetBundleName, FORM_TARGET_BUNDLE_NAME);
        EXPECT_EQ(formInfo.funInteractionParams.subBundleName, FORM_SUB_BUNDLE_NAME);
        EXPECT_EQ(formInfo.funInteractionParams.keepStateDuration, FORM_KEEP_STATE_DURATION);
        EXPECT_EQ(formInfo.sceneAnimationParams.abilityName, FORM_ABILITY_NAME);
        EXPECT_EQ(formInfo.sceneAnimationParams.disabledDesktopBehaviors, FORM_DISABLED_DESKTOP_BEHAVIORS);
    }
}

void BmsBundleKitServiceTest::CheckFormInfoDemo(const std::vector<FormInfo> &formInfos) const
{
    for (const auto &formInfo : formInfos) {
        EXPECT_EQ(formInfo.name, FORM_NAME);
        EXPECT_EQ(formInfo.bundleName, BUNDLE_NAME_DEMO);
        EXPECT_EQ(formInfo.moduleName, MODULE_NAME_DEMO);
        EXPECT_EQ(formInfo.abilityName, ABILITY_NAME_TEST);
        EXPECT_EQ(formInfo.description, FORM_DESCRIPTION);
        EXPECT_EQ(formInfo.formConfigAbility, FORM_PATH);
        EXPECT_EQ(formInfo.defaultFlag, false);
        EXPECT_EQ(formInfo.type, FormType::JS);
        EXPECT_EQ(formInfo.colorMode, FormsColorMode::LIGHT_MODE);
        EXPECT_EQ(formInfo.descriptionId, FORMINFO_DESCRIPTIONID);
        EXPECT_EQ(formInfo.deepLink, FORM_PATH);
        EXPECT_EQ(formInfo.package, PACKAGE_NAME);
        EXPECT_EQ(formInfo.formVisibleNotify, true);
        unsigned i = 2;
        EXPECT_EQ(formInfo.supportDimensions.size(), i);
        EXPECT_EQ(formInfo.defaultDimension, 1);
        EXPECT_EQ(formInfo.updateDuration, 0);
        EXPECT_EQ(formInfo.scheduledUpdateTime, FORM_SCHEDULED_UPDATE_TIME);
        EXPECT_EQ(formInfo.jsComponentName, FORM_JS_COMPONENT_NAME);
        EXPECT_EQ(formInfo.updateEnabled, true);
        EXPECT_EQ(formInfo.src, FORM_SRC);
        EXPECT_EQ(formInfo.window.designWidth, FORM_JS_WINDOW_DESIGNWIDTH);
        for (auto &info : formInfo.customizeDatas) {
            EXPECT_EQ(info.name, FORM_CUSTOMIZE_DATAS_NAME);
            EXPECT_EQ(info.value, FORM_CUSTOMIZE_DATAS_VALUE);
        }
        EXPECT_EQ(formInfo.funInteractionParams.abilityName, FORM_ABILITY_NAME);
        EXPECT_EQ(formInfo.funInteractionParams.targetBundleName, FORM_TARGET_BUNDLE_NAME);
        EXPECT_EQ(formInfo.funInteractionParams.subBundleName, FORM_SUB_BUNDLE_NAME);
        EXPECT_EQ(formInfo.funInteractionParams.keepStateDuration, FORM_KEEP_STATE_DURATION);
        EXPECT_EQ(formInfo.sceneAnimationParams.abilityName, FORM_ABILITY_NAME);
        EXPECT_EQ(formInfo.sceneAnimationParams.disabledDesktopBehaviors, FORM_DISABLED_DESKTOP_BEHAVIORS);
    }
}

void BmsBundleKitServiceTest::CheckShortcutInfoTest(std::vector<ShortcutInfo> &shortcutInfos) const
{
    for (const auto &shortcutInfo : shortcutInfos) {
        EXPECT_EQ(shortcutInfo.id, SHORTCUT_TEST_ID);
        EXPECT_EQ(shortcutInfo.bundleName, BUNDLE_NAME_TEST);
        EXPECT_EQ(shortcutInfo.hostAbility, SHORTCUT_HOST_ABILITY);
        EXPECT_EQ(shortcutInfo.icon, SHORTCUT_ICON);
        EXPECT_EQ(shortcutInfo.label, SHORTCUT_LABEL);
        EXPECT_EQ(shortcutInfo.disableMessage, SHORTCUT_DISABLE_MESSAGE);
        EXPECT_EQ(shortcutInfo.isStatic, true);
        EXPECT_EQ(shortcutInfo.isHomeShortcut, true);
        EXPECT_EQ(shortcutInfo.isEnables, true);
        for (auto &shortcutIntent : shortcutInfo.intents) {
            EXPECT_EQ(shortcutIntent.targetBundle, SHORTCUT_INTENTS_TARGET_BUNDLE);
            EXPECT_EQ(shortcutIntent.targetModule, SHORTCUT_INTENTS_TARGET_MODULE);
            EXPECT_EQ(shortcutIntent.targetClass, SHORTCUT_INTENTS_TARGET_CLASS);
        }
    }
}

void BmsBundleKitServiceTest::CheckCommonEventInfoTest(std::vector<CommonEventInfo> &commonEventInfos) const
{
    for (const auto &commonEventInfo : commonEventInfos) {
        EXPECT_EQ(commonEventInfo.name, COMMON_EVENT_NAME);
        EXPECT_EQ(commonEventInfo.bundleName, BUNDLE_NAME_TEST);
        EXPECT_EQ(commonEventInfo.permission, COMMON_EVENT_PERMISSION);
        for (auto item : commonEventInfo.data) {
            EXPECT_EQ(item, COMMON_EVENT_DATA);
        }
        for (auto item : commonEventInfo.type) {
            EXPECT_EQ(item, COMMON_EVENT_TYPE);
        }
        for (auto item : commonEventInfo.events) {
            EXPECT_EQ(item, COMMON_EVENT_EVENT);
        }
    }
}

void BmsBundleKitServiceTest::CheckShortcutInfoDemo(std::vector<ShortcutInfo> &shortcutInfos) const
{
    for (const auto &shortcutInfo : shortcutInfos) {
        EXPECT_EQ(shortcutInfo.id, SHORTCUT_DEMO_ID);
        EXPECT_EQ(shortcutInfo.bundleName, BUNDLE_NAME_DEMO);
        EXPECT_EQ(shortcutInfo.hostAbility, SHORTCUT_HOST_ABILITY);
        EXPECT_EQ(shortcutInfo.icon, SHORTCUT_ICON);
        EXPECT_EQ(shortcutInfo.label, SHORTCUT_LABEL);
        EXPECT_EQ(shortcutInfo.disableMessage, SHORTCUT_DISABLE_MESSAGE);
        EXPECT_EQ(shortcutInfo.isStatic, true);
        EXPECT_EQ(shortcutInfo.isHomeShortcut, true);
        EXPECT_EQ(shortcutInfo.isEnables, true);
        for (auto &shortcutIntent : shortcutInfo.intents) {
            EXPECT_EQ(shortcutIntent.targetBundle, SHORTCUT_INTENTS_TARGET_BUNDLE);
            EXPECT_EQ(shortcutIntent.targetModule, SHORTCUT_INTENTS_TARGET_MODULE);
            EXPECT_EQ(shortcutIntent.targetClass, SHORTCUT_INTENTS_TARGET_CLASS);
        }
    }
}

void BmsBundleKitServiceTest::ShortcutWantToJson(nlohmann::json &jsonObject, const ShortcutWant &shortcutWant)
{
    jsonObject = nlohmann::json {
        {BUNDLE_NAME, shortcutWant.bundleName},
        {MODULE_NAME, shortcutWant.moduleName},
        {ABILITY_NAME, shortcutWant.abilityName},
    };
}

void BmsBundleKitServiceTest::ClearBundleInfo(const std::string &bundleName)
{
    auto iterator = GetBundleDataMgr()->bundleInfos_.find(bundleName);
    if (iterator != GetBundleDataMgr()->bundleInfos_.end()) {
        GetBundleDataMgr()->bundleInfos_.erase(iterator);
    }
}

void BmsBundleKitServiceTest::AddCloneInfo(const std::string &bundleName, int32_t userId, int32_t appIndex)
{
    auto bundleInfoMapIter = GetBundleDataMgr()->bundleInfos_.find(bundleName);
    EXPECT_NE(bundleInfoMapIter, GetBundleDataMgr()->bundleInfos_.end());
    InnerBundleInfo &bundleInfoTest = bundleInfoMapIter->second;

    InnerBundleCloneInfo innerBundleCloneInfo;
    innerBundleCloneInfo.userId = userId;
    innerBundleCloneInfo.appIndex = appIndex;
    innerBundleCloneInfo.uid = TEST_UID;
    innerBundleCloneInfo.gids = {0};
    innerBundleCloneInfo.accessTokenId = TEST_ACCESS_TOKENID;
    innerBundleCloneInfo.accessTokenIdEx = TEST_ACCESS_TOKENID_EX;

    std::string appIndexKey = std::to_string(innerBundleCloneInfo.appIndex);
    std::string key = bundleName + Constants::FILE_UNDERLINE + std::to_string(userId);
    bundleInfoTest.innerBundleUserInfos_[key].cloneInfos.insert(make_pair(appIndexKey, innerBundleCloneInfo));
}

void BmsBundleKitServiceTest::ClearCloneInfo(const std::string &bundleName, int32_t userId)
{
    auto bundleInfoMapIter = GetBundleDataMgr()->bundleInfos_.find(bundleName);
    EXPECT_NE(bundleInfoMapIter, GetBundleDataMgr()->bundleInfos_.end());
    InnerBundleInfo &bundleInfoTest = bundleInfoMapIter->second;
    InnerBundleUserInfo bundleUserInfoTest;
    bool getBundleUserInfoRes = bundleInfoTest.GetInnerBundleUserInfo(userId, bundleUserInfoTest);
    EXPECT_TRUE(getBundleUserInfoRes);

    std::map<std::string, InnerBundleCloneInfo> emptyCloneInfos;
    bundleUserInfoTest.cloneInfos = emptyCloneInfos;
    std::string key = bundleName + Constants::FILE_UNDERLINE + std::to_string(userId);
    bundleInfoTest.innerBundleUserInfos_[key] = bundleUserInfoTest;
}

bool BmsBundleKitServiceTest::ChangeAppDisabledStatus(const std::string &bundleName, int32_t userId, int32_t appIndex,
    bool isEnabled)
{
    auto bundleInfoMapIter = GetBundleDataMgr()->bundleInfos_.find(bundleName);
    EXPECT_NE(bundleInfoMapIter, GetBundleDataMgr()->bundleInfos_.end());
    InnerBundleInfo &bundleInfoTest = bundleInfoMapIter->second;

    std::string key = bundleName + Constants::FILE_UNDERLINE + std::to_string(userId);
    bool isExists = bundleInfoTest.innerBundleUserInfos_.find(key) != bundleInfoTest.innerBundleUserInfos_.cend();
    if (!isExists) {
        return false;
    }
    if (appIndex == 0) {
        bundleInfoTest.innerBundleUserInfos_[key].bundleUserInfo.enabled = isEnabled;
    } else {
        std::map<std::string, InnerBundleCloneInfo> cloneInfos = bundleInfoTest.innerBundleUserInfos_[key].cloneInfos;
        std::string cloneKey = std::to_string(appIndex);
        bool isCloneIsExists = cloneInfos.find(cloneKey) != cloneInfos.cend();
        if (!isCloneIsExists) {
            return false;
        }
        bundleInfoTest.innerBundleUserInfos_[key].cloneInfos[cloneKey].enabled = isEnabled;
    }
    return true;
}

void BmsBundleKitServiceTest::QueryCloneApplicationInfosWithDisable()
{
    std::vector<ApplicationInfo> appInfos;
    int index = 0;
    int32_t flags = static_cast<int32_t>(ApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE);
    bool ret = GetBundleDataMgr()->GetApplicationInfos(flags, DEFAULT_USER_ID_TEST, appInfos);
    EXPECT_TRUE(ret);
    for (ApplicationInfo appInfo : appInfos) {
        if (appInfo.name == BUNDLE_NAME_TEST) {
            EXPECT_EQ(appInfo.appIndex, index++);
        }
    }
}

void BmsBundleKitServiceTest::QueryCloneApplicationInfosV9WithDisable()
{
    std::vector<ApplicationInfo> appInfos;
    int index = 0;
    int32_t flags = static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE);
    ErrCode ret = GetBundleDataMgr()->GetApplicationInfosV9(flags, DEFAULT_USER_ID_TEST, appInfos);
    EXPECT_EQ(ret, ERR_OK);
    for (ApplicationInfo appInfo : appInfos) {
        if (appInfo.name == BUNDLE_NAME_TEST) {
            EXPECT_EQ(appInfo.appIndex, index++);
        }
    }
}

void BmsBundleKitServiceTest::QueryCloneAbilityInfosV9WithDisable(const Want &want)
{
    std::vector<AbilityInfo> abilityInfos;
    int index = 0;
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_DISABLE);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ErrCode ret = hostImpl->QueryAbilityInfosV9(want, flags, DEFAULT_USERID, abilityInfos);
    EXPECT_EQ(ret, 0);
    for (AbilityInfo info : abilityInfos) {
        if (info.bundleName == BUNDLE_NAME_TEST) {
            EXPECT_EQ(info.appIndex, index++);
        }
    }
}

int32_t BmsBundleKitServiceTest::MockGetCurrentActiveUserId()
{
    return Constants::DEFAULT_USERID;
}

ErrCode BmsBundleKitServiceTest::MockGetAllBundleCacheStat(const sptr<IProcessCacheCallback> processCacheCallback)
{
    APP_LOGI("start");
    auto dataMgr = bundleMgrService_->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    auto userId = MockGetCurrentActiveUserId();
    if (userId <= Constants::U1) {
        APP_LOGE("Invalid userid: %{public}d", userId);
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    return ERR_OK;
}

ErrCode BmsBundleKitServiceTest::MockCleanAllBundleCache(const sptr<IProcessCacheCallback> processCacheCallback)
{
    APP_LOGI("start");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    auto userId = MockGetCurrentActiveUserId();
    if (userId <= Constants::U1) {
        APP_LOGE("Invalid userid: %{public}d", userId);
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    return ERR_OK;
}

/**
 * @tc.number: GetAllBundleCacheStat_0001
 * @tc.name: test GetAllBundleCacheStat interface
 * @tc.desc: 1. call GetAllBundleCacheStat
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllBundleCacheStat_0001, Function | MediumTest | Level1)
{
    std::cout << "START GetAllBundleCacheStat_0001" << std::endl;
    sptr<ProcessCacheCallbackImpl> getCache = new (std::nothrow) ProcessCacheCallbackImpl();
    ErrCode ret;
    if (getCache == nullptr) {
        ret = MockGetAllBundleCacheStat(getCache);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    }
    ret = MockGetAllBundleCacheStat(getCache);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    std::cout << "END GetAllBundleCacheStat_0001" << std::endl;
}

/**
 * @tc.number: CleanAllBundleCache_0001
 * @tc.name: test CleanAllBundleCache interface
 * @tc.desc: 1. call CleanAllBundleCache
 */
HWTEST_F(BmsBundleKitServiceTest, CleanAllBundleCache_0001, Function | MediumTest | Level1)
{
    std::cout << "START CleanAllBundleCache_0001" << std::endl;
    sptr<ProcessCacheCallbackImpl> delCache = new (std::nothrow) ProcessCacheCallbackImpl();
    ErrCode ret;
    if (delCache == nullptr) {
        ret = MockCleanAllBundleCache(delCache);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    }
    ret = MockCleanAllBundleCache(delCache);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
    std::cout << "END CleanAllBundleCache_0001" << std::endl;
}

/**
 * @tc.number: CheckModuleRemovable_0100
 * @tc.name: test can check module removable is enable by no setting
 * @tc.desc: 1.system run normally
 *           2.check the module removable successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckModuleRemovable_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    bool isRemovable = false;
    auto testRet = GetBundleDataMgr()->IsModuleRemovable(BUNDLE_NAME_TEST, MODULE_NAME_TEST, isRemovable,
        DEFAULT_USER_ID_TEST);
    EXPECT_EQ(testRet, ERR_OK);
    EXPECT_FALSE(isRemovable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckModuleRemovable_0200
 * @tc.name: test can check module removable is enable by setting
 * @tc.desc: 1.system run normally
 *           2.check the module removable successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckModuleRemovable_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    bool testRet = GetBundleDataMgr()->SetModuleRemovable(BUNDLE_NAME_TEST, MODULE_NAME_TEST, true,
        DEFAULT_USER_ID_TEST);
    EXPECT_TRUE(testRet);
    bool isRemovable = false;
    auto testRet1 = GetBundleDataMgr()->IsModuleRemovable(BUNDLE_NAME_TEST, MODULE_NAME_TEST, isRemovable,
        DEFAULT_USER_ID_TEST);
    EXPECT_EQ(testRet1, ERR_OK);
    EXPECT_TRUE(isRemovable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckModuleRemovable_0300
 * @tc.name: test can check module removable is disable by setting
 * @tc.desc: 1.system run normally
 *           2.check the module removable successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckModuleRemovable_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    bool testRet = GetBundleDataMgr()->SetModuleRemovable(BUNDLE_NAME_TEST, MODULE_NAME_TEST, false,
        DEFAULT_USER_ID_TEST);
    EXPECT_TRUE(testRet);
    bool isRemovable = false;
    auto testRet1 = GetBundleDataMgr()->IsModuleRemovable(BUNDLE_NAME_TEST, MODULE_NAME_TEST, isRemovable,
        DEFAULT_USER_ID_TEST);
    EXPECT_EQ(testRet1, ERR_OK);
    EXPECT_FALSE(isRemovable);

    bool testRet2 = GetBundleDataMgr()->SetModuleRemovable(BUNDLE_NAME_TEST, MODULE_NAME_TEST, true,
        DEFAULT_USER_ID_TEST);
    EXPECT_TRUE(testRet2);
    isRemovable = false;
    auto testRet3 = GetBundleDataMgr()->IsModuleRemovable(BUNDLE_NAME_TEST, MODULE_NAME_TEST, isRemovable,
        DEFAULT_USER_ID_TEST);
    EXPECT_EQ(testRet3, ERR_OK);
    EXPECT_TRUE(isRemovable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckModuleRemovable_0400
 * @tc.name: test can check module removable is disable by no install
 * @tc.desc: 1.system run normally
 *           2.check the module removable failed
 */
HWTEST_F(BmsBundleKitServiceTest, CheckModuleRemovable_0400, Function | SmallTest | Level1)
{
    bool isRemovable = false;
    auto testRet = GetBundleDataMgr()->IsModuleRemovable(BUNDLE_NAME_TEST, MODULE_NAME_TEST, isRemovable,
        DEFAULT_USER_ID_TEST);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_FALSE(isRemovable);
}

/**
 * @tc.number: CheckModuleRemovable_0500
 * @tc.name: test can check module removable is able by empty bundle name
 * @tc.desc: 1.system run normally
 *           2.check the module removable successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckModuleRemovable_0500, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    bool testRet = GetBundleDataMgr()->SetModuleRemovable("", "", true, DEFAULT_USER_ID_TEST);
    EXPECT_FALSE(testRet);
    bool isRemovable = false;
    auto testRet1 = GetBundleDataMgr()->IsModuleRemovable(BUNDLE_NAME_TEST, MODULE_NAME_TEST, isRemovable,
        DEFAULT_USER_ID_TEST);
    EXPECT_EQ(testRet1, ERR_OK);
    EXPECT_FALSE(isRemovable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckModuleRemovable_0600
 * @tc.name: test can check module removable is disable by empty bundle name
 * @tc.desc: 1.system run normally
 *           2.check the module removable failed
 */
HWTEST_F(BmsBundleKitServiceTest, CheckModuleRemovable_0600, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    bool testRet = GetBundleDataMgr()->SetModuleRemovable(BUNDLE_NAME_TEST, MODULE_NAME_TEST, true,
        DEFAULT_USER_ID_TEST);
    EXPECT_TRUE(testRet);
    bool isRemovable = false;
    auto testRet1 = GetBundleDataMgr()->IsModuleRemovable("", "", isRemovable, DEFAULT_USER_ID_TEST);
    EXPECT_EQ(testRet1, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    EXPECT_FALSE(isRemovable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckModuleRemovable_0700
 * @tc.name: test can check module removable is able by empty bundle name
 * @tc.desc: 1.system run normally
 *           2.check the module removable successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckModuleRemovable_0700, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    bool testRet = GetBundleDataMgr()->SetModuleRemovable("", "", true, DEFAULT_USER_ID_TEST);
    EXPECT_FALSE(testRet);
    bool isRemovable = false;
    auto testRet1 = GetBundleDataMgr()->IsModuleRemovable(BUNDLE_NAME_TEST, MODULE_NAME_TEST, isRemovable,
        DEFAULT_USER_ID_TEST);
    EXPECT_EQ(testRet1, ERR_OK);
    EXPECT_FALSE(isRemovable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleInfo_0100
 * @tc.name: test can get the bundleName's bundle info
 * @tc.desc: 1.system run normal
 *           2.get bundle info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfo_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    BundleInfo testResult;
    bool testRet = GetBundleDataMgr()->GetBundleInfo(BUNDLE_NAME_TEST, BundleFlag::GET_BUNDLE_DEFAULT, testResult,
        DEFAULT_USERID);
    EXPECT_TRUE(testRet);
    CheckBundleInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_SIZE_ZERO, testResult);
    BundleInfo demoResult;
    bool demoRet = GetBundleDataMgr()->GetBundleInfo(BUNDLE_NAME_DEMO, BundleFlag::GET_BUNDLE_WITH_ABILITIES,
        demoResult, DEFAULT_USERID);
    EXPECT_TRUE(demoRet);
    CheckBundleInfo(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_SIZE_ONE, demoResult);
    EXPECT_EQ(PERMISSION_SIZE_ZERO, demoResult.reqPermissions.size());

    BundleInfo bundleInfo;
    bool ret = GetBundleDataMgr()->GetBundleInfo(BUNDLE_NAME_DEMO, GET_BUNDLE_WITH_ABILITIES |
        GET_BUNDLE_WITH_REQUESTED_PERMISSION, bundleInfo, DEFAULT_USERID);
    EXPECT_TRUE(ret);
    CheckBundleInfo(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_SIZE_ONE, bundleInfo);
    EXPECT_EQ(PERMISSION_SIZE_TWO, bundleInfo.reqPermissions.size());

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetBundleInfo_0200
 * @tc.name: test can not get the bundleName's bundle info which not exist in system
 * @tc.desc: 1.system run normal
 *           2.get bundle info failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfo_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    BundleInfo result;
    bool ret = GetBundleDataMgr()->GetBundleInfo(BUNDLE_NAME_DEMO, BundleFlag::GET_BUNDLE_DEFAULT, result,
        DEFAULT_USERID);
    EXPECT_FALSE(ret);
    EXPECT_EQ(EMPTY_STRING, result.label);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleInfo_0300
 * @tc.name: test can not get bundle info with empty bundle name
 * @tc.desc: 1.system run normal
 *           2.get bundle info failed with empty bundle name
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfo_0300, Function | SmallTest | Level0)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    BundleInfo result;
    bool ret = GetBundleDataMgr()->GetBundleInfo(EMPTY_STRING, BundleFlag::GET_BUNDLE_DEFAULT, result, DEFAULT_USERID);
    EXPECT_FALSE(ret);
    EXPECT_EQ(EMPTY_STRING, result.name);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleInfo_0400
 * @tc.name: test can not get the bundleName's bundle info with no bundle in system
 * @tc.desc: 1.system run normally and without any bundle
 *           2.get bundle info failed with no bundle in system
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfo_0400, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    bool ret = GetBundleDataMgr()->GetBundleInfo(BUNDLE_NAME_TEST, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo,
        DEFAULT_USERID);
    EXPECT_FALSE(ret);
    EXPECT_EQ(EMPTY_STRING, bundleInfo.name);
    EXPECT_EQ(EMPTY_STRING, bundleInfo.label);
}

/**
 * @tc.number: GetBundleInfo_0500
 * @tc.name: test can get the bundleName's bundle info
 * @tc.desc: 1.system run normal
 *           2.get bundle info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfo_0500, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo testResult;
    bool testRet = hostImpl->GetBundleInfo(BUNDLE_NAME_TEST, BundleFlag::GET_BUNDLE_DEFAULT, testResult,
        DEFAULT_USERID);
    EXPECT_TRUE(testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleInfo_0600
 * @tc.name: test can get the bundleName's bundle info
 * @tc.desc: 1.system run normal
 *           2.get bundle info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfo_0600, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo testResult;
    bool testRet = hostImpl->GetBundleInfo(BUNDLE_NAME_TEST, GET_BUNDLE_WITH_ABILITIES |
        GET_BUNDLE_WITH_REQUESTED_PERMISSION, testResult, DEFAULT_USERID);

    EXPECT_TRUE(testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleInfo_0700
 * @tc.name: test can get the bundleName's bundle info
 * @tc.desc: 1.system run normal
 *           2.get bundle info failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfo_0700, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo testResult;
    bool testRet = hostImpl->GetBundleInfo("", GET_BUNDLE_WITH_ABILITIES |
        GET_BUNDLE_WITH_REQUESTED_PERMISSION, testResult, DEFAULT_USERID);
    EXPECT_FALSE(testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleInfo_0800
 * @tc.name: test can get AppId info
 * @tc.desc: 1.system run normal
 *           2.get AppId info is empty
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfo_0800, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo testResult;
    std::string testRet = hostImpl->GetAppIdByBundleName(BUNDLE_NAME_TEST, DEFAULT_USERID);
    EXPECT_EQ(testRet, Constants::EMPTY_STRING);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleInfo_0900
 * @tc.name: test can get the AppType info
 * @tc.desc: 1.system run normal
 *           2.get AppType info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfo_0900, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo testResult;
    std::string testRet = hostImpl->GetAppType(BUNDLE_NAME_TEST);
    EXPECT_EQ(testRet, "third-party");

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleInfo_1000
 * @tc.name: test can get the bundleName's bundle info with skill flag
 * @tc.desc: 1.system run normal
 *           2.get bundle info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfo_1000, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo testResult;
    bool testRet = hostImpl->GetBundleInfo(BUNDLE_NAME_TEST, GET_BUNDLE_WITH_ABILITIES |
        GET_BUNDLE_WITH_SKILL, testResult, DEFAULT_USERID);
    EXPECT_TRUE(testRet);
    EXPECT_EQ(testResult.abilityInfos.size(), ABILITY_SIZE_ONE);
    EXPECT_EQ(testResult.abilityInfos[0].skills.size(), SKILL_SIZE_TWO);
    testResult.abilityInfos.clear();
    testRet = hostImpl->GetBundleInfo(BUNDLE_NAME_TEST, GET_BUNDLE_WITH_EXTENSION_INFO |
        GET_BUNDLE_WITH_SKILL, testResult, DEFAULT_USERID);
    EXPECT_TRUE(testRet);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleInfos_0100
 * @tc.name: test can get the installed bundles's bundle info with nomal flag
 * @tc.desc: 1.system run normally
 *           2.get all installed bundle info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfos_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::vector<BundleInfo> bundleInfos;
    bool ret = GetBundleDataMgr()->GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, DEFAULT_USERID);
    EXPECT_TRUE(ret);
    CheckInstalledBundleInfos(ABILITY_SIZE_ZERO, bundleInfos);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetBundleInfos_0200
 * @tc.name: test can get the installed bundles's bundle info with abilities
 * @tc.desc: 1.system run normally
 *           2.get all installed bundle info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfos_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::vector<BundleInfo> bundleInfos;
    bool ret = GetBundleDataMgr()->GetBundleInfos(BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfos, DEFAULT_USERID);
    EXPECT_TRUE(ret);
    CheckInstalledBundleInfos(ABILITY_SIZE_ONE, bundleInfos);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetApplicationInfo_0100
 * @tc.name: test can get the appName's application info
 * @tc.desc: 1.system run normally
 *           2.get application info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfo_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);

    ApplicationInfo testResult;
    bool testRet = GetBundleDataMgr()->GetApplicationInfo(
        BUNDLE_NAME_TEST, ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID_TEST, testResult);
    EXPECT_TRUE(testRet);
    CheckApplicationInfo(BUNDLE_NAME_TEST, PERMISSION_SIZE_ZERO, testResult);

    ApplicationInfo demoResult;
    bool demoRet = GetBundleDataMgr()->GetApplicationInfo(
        BUNDLE_NAME_DEMO, ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION, DEFAULT_USER_ID_TEST, demoResult);
    EXPECT_TRUE(demoRet);
    CheckApplicationInfo(BUNDLE_NAME_DEMO, PERMISSION_SIZE_TWO, demoResult);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetApplicationInfo_0200
 * @tc.name: test can not get the appName's application info which not exist in system
 * @tc.desc: 1.system run normally
 *           2.get application info failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfo_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    ApplicationInfo result;
    bool ret = GetBundleDataMgr()->GetApplicationInfo(
        BUNDLE_NAME_DEMO, ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID_TEST, result);
    EXPECT_FALSE(ret);
    EXPECT_EQ(EMPTY_STRING, result.name);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetApplicationInfo_0300
 * @tc.name: test can not get application info with empty appName
 * @tc.desc: 1.system run normally
 *           2.get application info failed with empty appName
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfo_0300, Function | SmallTest | Level0)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    ApplicationInfo result;
    bool ret = GetBundleDataMgr()->GetApplicationInfo(
        EMPTY_STRING, ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID_TEST, result);
    EXPECT_FALSE(ret);
    EXPECT_EQ(EMPTY_STRING, result.name);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetApplicationInfo_0400
 * @tc.name: test can not get the appName's application info with no bundle in system
 * @tc.desc: 1.system run normally
 *           2.get application info failed with no bundle in system
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfo_0400, Function | SmallTest | Level0)
{
    ApplicationInfo result;
    bool ret = GetBundleDataMgr()->GetApplicationInfo(
        BUNDLE_NAME_TEST, ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID_TEST, result);
    EXPECT_FALSE(ret);
    EXPECT_EQ(EMPTY_STRING, result.name);
    EXPECT_EQ(EMPTY_STRING, result.label);
}

/**
 * @tc.number: GetApplicationInfo_0600
 * @tc.name: test can parceable application info(permissions and metaData)
 * @tc.desc: 1.system run normally
 *           2.get application info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfo_0600, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    ApplicationInfo testResult;
    bool testRet = GetBundleDataMgr()->GetApplicationInfo(BUNDLE_NAME_TEST,
        GET_APPLICATION_INFO_WITH_PERMISSION | GET_APPLICATION_INFO_WITH_METADATA, DEFAULT_USER_ID_TEST, testResult);
    EXPECT_TRUE(testRet);
    EXPECT_EQ(PERMISSION_SIZE_TWO, testResult.permissions.size());
    EXPECT_EQ(META_DATA_SIZE_ONE, testResult.metaData.size());

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetApplicationInfo_0700
 * @tc.name: test can not get application info with empty appName
 * @tc.desc: 1.system run normally
 *           2.get application info failed with empty appName
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfo_0700, Function | SmallTest | Level0)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ApplicationInfo result;
    bool ret = hostImpl->GetApplicationInfo(
        EMPTY_STRING, ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID_TEST, result);
    EXPECT_FALSE(ret);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetApplicationInfos_0100
 * @tc.name: test can get the installed bundles's application info with basic info flag
 * @tc.desc: 1.system run normally
 *           2.get all installed application info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfos_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::vector<ApplicationInfo> appInfos;
    bool ret = GetBundleDataMgr()->GetApplicationInfos(
        ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID_TEST, appInfos);
    EXPECT_TRUE(ret);
    CheckInstalledApplicationInfos(PERMISSION_SIZE_ZERO, appInfos);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetApplicationInfos_0200
 * @tc.name: test can get the installed bundles's application info with permissions
 * @tc.desc: 1.system run normally
 *           2.get all installed application info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfos_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::vector<ApplicationInfo> appInfos;
    bool ret = GetBundleDataMgr()->GetApplicationInfos(
        ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION, DEFAULT_USER_ID_TEST, appInfos);
    EXPECT_TRUE(ret);
    CheckInstalledApplicationInfos(PERMISSION_SIZE_TWO, appInfos);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetApplicationInfos_0300
 * @tc.name: test can get the installed bundles's application info with permissions
 * @tc.desc: 1.system run normally
 *           2.get all installed application info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfos_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::vector<ApplicationInfo> appInfos;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool ret = hostImpl->GetApplicationInfos(
        ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION, DEFAULT_USER_ID_TEST, appInfos);
    EXPECT_TRUE(ret);
    CheckInstalledApplicationInfos(PERMISSION_SIZE_TWO, appInfos);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetApplicationInfos_0400
 * @tc.name: test can get the installed bundles's application info with permissions
 * @tc.desc: 1.system run normally
 *           2.get all installed application info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfos_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::vector<ApplicationInfo> appInfos;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool ret = hostImpl->GetApplicationInfos(
        GET_ABILITY_INFO_DEFAULT, DEFAULT_USER_ID_TEST, appInfos);
    EXPECT_TRUE(ret);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetApplicationInfos_0500
 * @tc.name: test can get the installed bundles's application info with basic info flag
 * @tc.desc: 1.system run normally
 *           2.get all installed application info successfully
 * @tc.require: issueI7FMPK
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfos_0500, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.bundleStatus_ = InnerBundleInfo::BundleStatus::DISABLED;
    dataMgr->bundleInfos_.insert(
        pair<std::string, InnerBundleInfo>(LAUNCHER_BUNDLE_NAME, innerBundleInfo));
    std::vector<ApplicationInfo> appInfos;
    bool ret = dataMgr->GetApplicationInfos(
        ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID_TEST, appInfos);
    EXPECT_EQ(ret, true);
    EXPECT_GT(appInfos.size(), 0);
    dataMgr->bundleInfos_.erase(LAUNCHER_BUNDLE_NAME);
}

/**
 * @tc.number: GetApplicationInfos_0600
 * @tc.name: test can get the installed bundles's application info with basic info flag
 * @tc.desc: 1.system run normally
 *           2.get all installed application info successfully
 * @tc.require: issueI7FMPK
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfos_0600, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.bundleStatus_ = InnerBundleInfo::BundleStatus::DISABLED;
    dataMgr->bundleInfos_.insert(
        pair<std::string, InnerBundleInfo>(LAUNCHER_BUNDLE_NAME, innerBundleInfo));
    std::vector<ApplicationInfo> appInfos;
    bool ret = dataMgr->GetApplicationInfosV9(0, DEFAULT_USER_ID_TEST, appInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GT(appInfos.size(), 0);
    dataMgr->bundleInfos_.erase(LAUNCHER_BUNDLE_NAME);
}

/**
 * @tc.number: GetApplicationInfos_0700
 * @tc.name: test can get the installed bundles and cloneApp's application info with basic info flag
 * @tc.desc: 1.system run normally
 *           2.add cloneInfo
 *           3.get all installed application info and the clones successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfos_0700, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX1);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX2);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX3);

    std::vector<ApplicationInfo> appInfos;
    bool ret = GetBundleDataMgr()->GetApplicationInfos(
        ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID_TEST, appInfos);
    EXPECT_TRUE(ret);
    int index = 0;
    for (ApplicationInfo appInfo : appInfos) {
        if (appInfo.bundleName == BUNDLE_NAME_TEST) {
            EXPECT_EQ(appInfo.appIndex, index++);
        }
    }

    ClearCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetApplicationInfos_0800
 * @tc.name: test can get the installed bundles and cloneApp's application info
 * @tc.desc: 1.system run normally
 *           2.add cloneInfo
 *           3.disable main app
 *           4.get all installed application info and the clones successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfos_0800, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX1);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX2);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX3);

    EXPECT_TRUE(ChangeAppDisabledStatus(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, 0, false));

    std::vector<ApplicationInfo> appInfos;
    bool ret = GetBundleDataMgr()->GetApplicationInfos(
        ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID_TEST, appInfos);
    EXPECT_TRUE(ret);
    int index = 1;
    for (ApplicationInfo appInfo : appInfos) {
        if (appInfo.bundleName == BUNDLE_NAME_TEST) {
            EXPECT_EQ(appInfo.appIndex, index++);
        }
    }
    QueryCloneApplicationInfosWithDisable();

    ClearCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetApplicationInfos_0900
 * @tc.name: test can get the installed bundles and cloneApp's application info
 * @tc.desc: 1.system run normally
 *           2.add cloneInfo
 *           3.disable clone app
 *           4.get all installed application info and the clones successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfos_0900, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX1);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX2);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX3);

    EXPECT_TRUE(ChangeAppDisabledStatus(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX2, false));

    std::vector<ApplicationInfo> appInfos;
    bool ret = GetBundleDataMgr()->GetApplicationInfos(
        ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID_TEST, appInfos);
    EXPECT_TRUE(ret);
    int index = 0;
    for (ApplicationInfo appInfo : appInfos) {
        if (appInfo.bundleName == BUNDLE_NAME_TEST) {
            EXPECT_EQ(appInfo.appIndex, index++);
        }
        if (index == 2) {
            index++;
        }
    }
    QueryCloneApplicationInfosWithDisable();

    ClearCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAbilityLabel_0100
 * @tc.name: test can get the ability's label by bundleName and abilityName
 * @tc.desc: 1.system run normally
 *           2.get ability label successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetAbilityLabel_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::string testRet;
    ErrCode ret = GetBundleDataMgr()->GetAbilityLabel(BUNDLE_NAME_TEST, EMPTY_STRING, ABILITY_NAME_TEST, testRet);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(LABEL, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAbilityLabel_0200
 * @tc.name: test can not get the ability's label if bundle doesn't install
 * @tc.desc: 1.system run normally
 *           2.get empty ability label
 */
HWTEST_F(BmsBundleKitServiceTest, GetAbilityLabel_0200, Function | SmallTest | Level1)
{
    std::string testRet;
    ErrCode ret = GetBundleDataMgr()->GetAbilityLabel(BUNDLE_NAME_TEST, EMPTY_STRING, ABILITY_NAME_TEST, testRet);
    EXPECT_NE(0, ret);
    EXPECT_EQ(EMPTY_STRING, testRet);
}

/**
 * @tc.number: GetAbilityLabel_0300
 * @tc.name: test can not get the ability's label if bundle doesn't exist
 * @tc.desc: 1.system run normally
 *           2.get empty ability label
 */
HWTEST_F(BmsBundleKitServiceTest, GetAbilityLabel_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::string testRet;
    ErrCode ret = GetBundleDataMgr()->GetAbilityLabel(BUNDLE_NAME_DEMO, EMPTY_STRING, ABILITY_NAME_TEST, testRet);
    EXPECT_NE(0, ret);
    EXPECT_EQ(EMPTY_STRING, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAbilityLabel_0400
 * @tc.name: test can not get the ability's label if ability doesn't exist
 * @tc.desc: 1.system run normally
 *           2.get empty ability label
 */
HWTEST_F(BmsBundleKitServiceTest, GetAbilityLabel_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::string testRet;
    ErrCode ret = GetBundleDataMgr()->GetAbilityLabel(BUNDLE_NAME_TEST, EMPTY_STRING, ABILITY_NAME_DEMO, testRet);
    EXPECT_NE(0, ret);
    EXPECT_EQ(EMPTY_STRING, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAbilityLabel_0500
 * @tc.name: test can not get the ability's label if module doesn't exist
 * @tc.desc: 1.system run normally
 *           2.get empty ability label
 */
HWTEST_F(BmsBundleKitServiceTest, GetAbilityLabel_0500, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::string testRet;
    ErrCode ret = GetBundleDataMgr()->GetAbilityLabel(BUNDLE_NAME_TEST, MODULE_NAME_TEST_1, ABILITY_NAME_TEST, testRet);
    EXPECT_NE(0, ret);
    EXPECT_EQ(EMPTY_STRING, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAbilityLabel_0600
 * @tc.name: test can not get the ability's label if module and ability exist
 * @tc.desc: 1.system run normally
 *           2.get empty ability label
 */
HWTEST_F(BmsBundleKitServiceTest, GetAbilityLabel_0600, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::string testRet;
    ErrCode ret = GetBundleDataMgr()->GetAbilityLabel(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, testRet);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(LABEL, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAbilityLabel_0700
 * @tc.name: test can not get the ability's label if module exist and ability doesn't exist
 * @tc.desc: 1.system run normally
 *           2.get empty ability label
 */
HWTEST_F(BmsBundleKitServiceTest, GetAbilityLabel_0700, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::string testRet;
    ErrCode ret = GetBundleDataMgr()->GetAbilityLabel(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_DEMO, testRet);
    EXPECT_NE(0, ret);
    EXPECT_EQ(EMPTY_STRING, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAbilityLabel_0800
 * @tc.name: test can not get the ability's label if module exist and ability doesn't exist
 * @tc.desc: 1.system run normally
 *           2.get empty ability label
 */
HWTEST_F(BmsBundleKitServiceTest, GetAbilityLabel_0800, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::string testRet;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ErrCode ret = hostImpl->GetAbilityLabel(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_DEMO, testRet);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_EQ(EMPTY_STRING, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfo_0100
 * @tc.name: test can get the ability info by want
 * @tc.desc: 1.system run normally
 *           2.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfo_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo result;

    int32_t flags = GET_ABILITY_INFO_DEFAULT;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfo(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfo(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);

    flags = GET_ABILITY_INFO_WITH_METADATA;
    testRet = GetBundleDataMgr()->QueryAbilityInfo(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfo(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfo_0200
 * @tc.name: test can not get the ability info by want in which element name is wrong
 * @tc.desc: 1.system run normally
 *           2.get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfo_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    Want want;
    want.SetElementName(BUNDLE_NAME_DEMO, ABILITY_NAME_TEST);
    AbilityInfo result;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfo(want, 0, 0, result);
    EXPECT_EQ(false, testRet);

    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_DEMO);
    testRet = GetBundleDataMgr()->QueryAbilityInfo(want, 0, 0, result);
    EXPECT_EQ(false, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfo_0300
 * @tc.name: test can not get the ability info by want which bundle doesn't exist
 * @tc.desc: 1.system run normally
 *           2.get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfo_0300, Function | SmallTest | Level1)
{
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo result;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfo(want, 0, 0, result);
    EXPECT_EQ(false, testRet);
}

/**
 * @tc.number: QueryAbilityInfo_0400
 * @tc.name: test can not get the ability info by want which bundle doesn't exist
 * @tc.desc: 1.system run normally
 *           2.get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfo_0400, Function | SmallTest | Level1)
{
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    want.SetModuleName(MODULE_NAME_TEST);
    AbilityInfo result;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfo(want, 0, 0, result);
    EXPECT_EQ(false, testRet);
}

/**
 * @tc.number: QueryAbilityInfo_0500
 * @tc.name: test can get the ability info by want with bundleName, moduleName, abilityName
 * @tc.desc: 1.system run normally
 *           2.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfo_0500, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    want.SetModuleName(MODULE_NAME_TEST);
    AbilityInfo result;

    int32_t flags = GET_ABILITY_INFO_DEFAULT;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfo(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfo(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);
    EXPECT_EQ(MODULE_NAME_TEST, result.moduleName);

    flags = GET_ABILITY_INFO_WITH_METADATA;
    testRet = GetBundleDataMgr()->QueryAbilityInfo(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfo(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);
    EXPECT_EQ(MODULE_NAME_TEST, result.moduleName);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfo_0600
 * @tc.name: test can get the ability info by want with bundleName, moduleName, abilityName
 * @tc.desc: 1.system run normally
 *           2.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfo_0600, Function | SmallTest | Level1)
{
    std::vector<std::string> moduleList {MODULE_NAME_TEST, MODULE_NAME_TEST_1};
    MockInstallBundle(BUNDLE_NAME_TEST, moduleList, ABILITY_NAME_TEST);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    want.SetModuleName(MODULE_NAME_TEST);
    AbilityInfo result;
    int32_t flags = GET_ABILITY_INFO_DEFAULT;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfo(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfo(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);
    EXPECT_EQ(MODULE_NAME_TEST, result.moduleName);

    want.SetModuleName(MODULE_NAME_TEST_1);
    testRet = GetBundleDataMgr()->QueryAbilityInfo(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfo(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);
    EXPECT_EQ(MODULE_NAME_TEST_1, result.moduleName);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfo_0700
 * @tc.name: test can get the ability info by want with implicit query
 * @tc.desc: 1.system run normally
 *           2.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfo_0700, Function | SmallTest | Level1)
{
    std::vector<std::string> moduleList {MODULE_NAME_TEST, MODULE_NAME_TEST_1, MODULE_NAME_TEST_2};
    MockInstallBundle(BUNDLE_NAME_TEST, moduleList, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", MODULE_NAME_TEST_1);
    AbilityInfo result;
    int32_t flags = GET_ABILITY_INFO_DEFAULT;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfo(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfo(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);
    EXPECT_EQ(MODULE_NAME_TEST_1, result.moduleName);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfo_0800
 * @tc.name: test can get the ability info by want
 * @tc.desc: 1.system run normally
 *           2.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfo_0800, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo result;

    int32_t flags = GET_ABILITY_INFO_DEFAULT;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool testRet = hostImpl->QueryAbilityInfo(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfo(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);

    flags = GET_ABILITY_INFO_WITH_APPLICATION;
    testRet = hostImpl->QueryAbilityInfo(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfo(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfos_0100
 * @tc.name: test can get the ability info of list by want
 * @tc.desc: 1.system run normally
 *           2.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfos_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> result;

    int32_t flags = GET_ABILITY_INFO_DEFAULT;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfos(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);
    result.clear();

    flags = GET_ABILITY_INFO_WITH_METADATA;
    testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfos(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);
    result.clear();

    flags = GET_ABILITY_INFO_WITH_PERMISSION | GET_ABILITY_INFO_WITH_METADATA;
    testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfos(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfos_0200
 * @tc.name: test can not get the ability info by want in which bundle name is wrong
 * @tc.desc: 1.system run normally
 *           2.get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfos_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    Want want;
    want.SetElementName(BUNDLE_NAME_DEMO, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> result;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfos(want, 0, 0, result);
    EXPECT_EQ(false, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfos_0300
 * @tc.name: test can not get the ability info by want which bundle doesn't exist
 * @tc.desc: 1.system run normally
 *           2.get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfos_0300, Function | SmallTest | Level1)
{
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> result;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfos(want, 0, 0, result);
    EXPECT_EQ(false, testRet);
}

/**
 * @tc.number: QueryAbilityInfos_0400
 * @tc.name: test can not get the ability info by want which bundle doesn't exist
 * @tc.desc: 1.system run normally
 *           2.get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfos_0400, Function | SmallTest | Level1)
{
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    want.SetModuleName(MODULE_NAME_TEST);
    std::vector<AbilityInfo> result;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfos(want, 0, 0, result);
    EXPECT_EQ(false, testRet);
}

/**
 * @tc.number: QueryAbilityInfos_0500
 * @tc.name: test can get the ability info of list by want with bundleName, moduleName and abilityName
 * @tc.desc: 1.system run normally
 *           2.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfos_0500, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    want.SetModuleName(MODULE_NAME_TEST);
    std::vector<AbilityInfo> result;

    int32_t flags = GET_ABILITY_INFO_DEFAULT;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfos(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);
    for (const auto &ret : result) {
        EXPECT_EQ(MODULE_NAME_TEST, ret.moduleName);
    }
    result.clear();

    flags = GET_ABILITY_INFO_WITH_METADATA;
    testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfos(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);
    for (const auto &ret : result) {
        EXPECT_EQ(MODULE_NAME_TEST, ret.moduleName);
    }
    result.clear();

    flags = GET_ABILITY_INFO_WITH_PERMISSION | GET_ABILITY_INFO_WITH_METADATA;
    testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfos(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);
    for (const auto &ret : result) {
        EXPECT_EQ(MODULE_NAME_TEST, ret.moduleName);
    }
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfos_0600
 * @tc.name: test can get the ability info of list by want with bundleName, moduleName and abilityName
 * @tc.desc: 1.system run normally
 *           2.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfos_0600, Function | SmallTest | Level1)
{
    std::vector<std::string> moduleList {MODULE_NAME_TEST, MODULE_NAME_TEST_1};
    MockInstallBundle(BUNDLE_NAME_TEST, moduleList, ABILITY_NAME_TEST);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    want.SetModuleName(MODULE_NAME_TEST);
    std::vector<AbilityInfo> result;

    int32_t flags = GET_ABILITY_INFO_DEFAULT;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfos(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);
    for (const auto &ret : result) {
        EXPECT_EQ(MODULE_NAME_TEST, ret.moduleName);
    }
    result.clear();

    want.SetModuleName(MODULE_NAME_TEST_1);
    testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    CheckAbilityInfos(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);
    for (const auto &ret : result) {
        EXPECT_EQ(MODULE_NAME_TEST_1, ret.moduleName);
    }
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfos_0700
 * @tc.name: test can get the ability info by want with implicit query
 * @tc.desc: 1.system run normally
 *           2.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfos_0700, Function | SmallTest | Level1)
{
    std::vector<std::string> moduleList {MODULE_NAME_TEST, MODULE_NAME_TEST_1, MODULE_NAME_TEST_2};
    MockInstallBundle(BUNDLE_NAME_TEST, moduleList, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<AbilityInfo> result;
    int32_t flags = GET_ABILITY_INFO_DEFAULT;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    EXPECT_EQ(result.size(), MODULE_NAMES_SIZE_THREE);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfos_0800
 * @tc.name: test can get the ability info by want with implicit query
 * @tc.desc: 1.system run normally
 *           2.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfos_0800, Function | SmallTest | Level1)
{
    std::vector<std::string> moduleList {MODULE_NAME_TEST, MODULE_NAME_TEST_1, MODULE_NAME_TEST_2};
    MockInstallBundle(BUNDLE_NAME_TEST, moduleList, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", MODULE_NAME_TEST_1);
    std::vector<AbilityInfo> result;
    int32_t flags = GET_ABILITY_INFO_DEFAULT;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, 0, result);
    EXPECT_EQ(true, testRet);
    EXPECT_EQ(result.size(), MODULE_NAMES_SIZE_ONE);
    if (!result.empty()) {
        EXPECT_EQ(MODULE_NAME_TEST_1, result[0].moduleName);
    }
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfos_0900
 * @tc.name: test can get the main and clone app's abilityInfos by want with explicit query
 * @tc.desc: 1.system run normally
 *           2.get main and cloneApp's abilityInfos
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfos_0900, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX1);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> result;
    int32_t flags = GET_ABILITY_INFO_DEFAULT;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, DEFAULT_USERID, result);
    EXPECT_EQ(true, testRet);
    EXPECT_EQ(result.size(), 2);
    if (result.size() == 2) {
        EXPECT_EQ(result[1].appIndex, TEST_APP_INDEX1);
    }
    ClearCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfos_1000
 * @tc.name: test can get the ability info with skill flag by explicit query
 * @tc.desc: 1.system run normally
 *           2.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfos_1000, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> result;

    uint32_t flags = GET_ABILITY_INFO_WITH_SKILL;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, 0, result);
    EXPECT_EQ(testRet, true);
    EXPECT_EQ(result.size(), MODULE_NAMES_SIZE_ONE);
    EXPECT_EQ(result[0].skills.size(), SKILL_SIZE_TWO);
    CheckSkillInfos(result[0].skills);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfos_1100
 * @tc.name: test can get the ability info with skill flag by implicit query
 * @tc.desc: 1.system run normally
 *           2.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfos_1100, Function | SmallTest | Level1)
{
    std::vector<std::string> moduleList {MODULE_NAME_TEST, MODULE_NAME_TEST_1, MODULE_NAME_TEST_2};
    MockInstallBundle(BUNDLE_NAME_TEST, moduleList, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", MODULE_NAME_TEST_1);
    std::vector<AbilityInfo> result;
    int32_t flags = GET_ABILITY_INFO_WITH_SKILL;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, 0, result);
    EXPECT_EQ(testRet, true);
    EXPECT_EQ(result.size(), MODULE_NAMES_SIZE_ONE);
    EXPECT_EQ(result[0].skills.size(), SKILL_SIZE_TWO);
    CheckSkillInfos(result[0].skills);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfos_1200
 * @tc.name: test can get the ability info by explicit query
 * @tc.desc: 1.system run normally
 *           2.install clone apps
 *           3.disable main app
 *           4.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfos_1200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX1);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX2);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX3);

    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> result;
    int32_t flags = GET_ABILITY_INFO_DEFAULT;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, DEFAULT_USER_ID_TEST, result);
    EXPECT_TRUE(testRet);
    EXPECT_EQ(result.size(), TOTAL_APP_NUMS);

    EXPECT_TRUE(ChangeAppDisabledStatus(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, 0, false));

    result.clear();
    testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, DEFAULT_USER_ID_TEST, result);
    EXPECT_TRUE(testRet);
    EXPECT_EQ(result.size(), 3);

    result.clear();
    flags = static_cast<int32_t>(ApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE);
    testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, DEFAULT_USER_ID_TEST, result);
    EXPECT_TRUE(testRet);
    EXPECT_EQ(result.size(), TOTAL_APP_NUMS);

    int index = 0;
    for (AbilityInfo info : result) {
        if (info.bundleName == BUNDLE_NAME_TEST) {
            EXPECT_EQ(info.appIndex, index++);
        }
    }

    ClearCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfos_1300
 * @tc.name: test can get the ability info by implicit query
 * @tc.desc: 1.system run normally
 *           2.install clone apps
 *           3.disable main app
 *           4.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfos_1300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX1);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX2);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX3);

    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    std::vector<AbilityInfo> result;
    int32_t flags = GET_ABILITY_INFO_DEFAULT;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, DEFAULT_USER_ID_TEST, result);
    EXPECT_TRUE(testRet);

    EXPECT_TRUE(ChangeAppDisabledStatus(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, 0, false));

    result.clear();
    testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, DEFAULT_USER_ID_TEST, result);
    EXPECT_TRUE(testRet);
    int count = 0;
    for (AbilityInfo info : result) {
        if (info.bundleName == BUNDLE_NAME_TEST) {
            count++;
        }
    }
    EXPECT_EQ(count, 3);

    result.clear();
    flags = static_cast<int32_t>(ApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE);
    testRet = GetBundleDataMgr()->QueryAbilityInfos(want, flags, DEFAULT_USER_ID_TEST, result);
    EXPECT_TRUE(testRet);
    count = 0;
    for (AbilityInfo info : result) {
        if (info.bundleName == BUNDLE_NAME_TEST) {
            count++;
        }
    }
    EXPECT_EQ(count, TOTAL_APP_NUMS);

    ClearCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetLaunchWantForBundle_0100
 * @tc.name: test can get the launch want of a bundle
 * @tc.desc: 1.system run normally
 *           2.get launch want successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetLaunchWantForBundle_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    ErrCode testRet = GetBundleDataMgr()->GetLaunchWantForBundle(BUNDLE_NAME_TEST, want);
    EXPECT_EQ(ERR_OK, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetLaunchWantForBundle_0200
 * @tc.name: test can not get the launch want of a bundle which is not exist
 * @tc.desc: 1.system run normally
 *           2.get launch want failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetLaunchWantForBundle_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    ErrCode testRet = GetBundleDataMgr()->GetLaunchWantForBundle(BUNDLE_NAME_DEMO, want);
    EXPECT_NE(ERR_OK, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetLaunchWantForBundle_0300
 * @tc.name: test can not get the launch want of a bundle which its mainability is not exist
 * @tc.desc: 1.system run normally
 *           2.get launch want failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetLaunchWantForBundle_0300, Function | SmallTest | Level1)
{
    std::string bundleName = BUNDLE_NAME_DEMO;
    std::string moduleName = MODULE_NAME_DEMO;
    std::string abilityName = ABILITY_NAME_DEMO;
    InnerModuleInfo moduleInfo = MockModuleInfo(moduleName);
    std::string keyName = bundleName + "." + moduleName + "." + abilityName;
    AbilityInfo abilityInfo = MockAbilityInfo(bundleName, moduleName, abilityName);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertAbilitiesInfo(keyName, abilityInfo);
    innerBundleInfo.InsertInnerModuleInfo(moduleName, moduleInfo);
    Skill skill;
    std::vector<Skill> skills;
    skills.emplace_back(skill);
    innerBundleInfo.InsertSkillInfo(keyName, skills);
    SaveToDatabase(bundleName, innerBundleInfo, true, false);

    Want want;
    ErrCode testRet = GetBundleDataMgr()->GetLaunchWantForBundle(BUNDLE_NAME_DEMO, want);
    EXPECT_NE(ERR_OK, testRet);

    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetLaunchWantForBundle_0400
 * @tc.name: test can not get the launch want of empty name
 * @tc.desc: 1.system run normally
 *           2.get launch want failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetLaunchWantForBundle_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    Want want;
    ErrCode testRet = GetBundleDataMgr()->GetLaunchWantForBundle(EMPTY_STRING, want);
    EXPECT_NE(ERR_OK, testRet);

    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetLaunchWantForBundle_0500
 * @tc.name: test can not get the launch want when no bundle installed
 * @tc.desc: 1.system run normally
 *           2.get launch want failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetLaunchWantForBundle_0500, Function | SmallTest | Level1)
{
    Want want;
    ErrCode testRet = GetBundleDataMgr()->GetLaunchWantForBundle(BUNDLE_NAME_TEST, want);
    EXPECT_NE(ERR_OK, testRet);
}

/**
 * @tc.number: GetLaunchWantForBundle_0600
 * @tc.name: test can not get the launch want of a bundle which is not exist
 * @tc.desc: 1.system run normally
 *           2.get launch want failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetLaunchWantForBundle_0600, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    ErrCode testRet = bundleMgrProxy->GetLaunchWantForBundle(BUNDLE_NAME_DEMO, want);
    EXPECT_NE(ERR_OK, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetLaunchWant_0100
 * @tc.name: test can not get the launch want
 * @tc.desc: 1.system run normally
 *           2.get launch want failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetLaunchWant_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    ErrCode testRet = bundleMgrProxy->GetLaunchWant(want);
    EXPECT_NE(ERR_OK, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetLaunchWant_0200
 * @tc.name: test GetLaunchWant of BundleMgrHostImpl
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleKitServiceTest, GetLaunchWant_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    AAFwk::Want want;
    ErrCode testRet = hostImpl->GetLaunchWant(want);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleList_0100
 * @tc.name: test can get all installed bundle names
 * @tc.desc: 1.system run normally
 *           2.get installed bundle names successfully with correct names
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleList_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);

    std::vector<std::string> testResult;
    bool testRet = GetBundleDataMgr()->GetBundleList(testResult);
    EXPECT_TRUE(testRet);
    CheckBundleList(BUNDLE_NAME_TEST, testResult);
    CheckBundleList(BUNDLE_NAME_DEMO, testResult);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetDebugBundleList_0100
 * @tc.name: test can get all installed debug bundle names
 * @tc.desc: 1.system run normally
 *           2.get installed bundle names successfully with correct names
 */
HWTEST_F(BmsBundleKitServiceTest, GetDebugBundleList_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);

    for (auto &infoItem : GetBundleDataMgr()->bundleInfos_) {
        InnerBundleInfo &innerBundleInfo = infoItem.second;
        ApplicationInfo appInfo = innerBundleInfo.GetBaseApplicationInfo();
        if (appInfo.appProvisionType == Constants::APP_PROVISION_TYPE_RELEASE) {
            appInfo.appProvisionType = Constants::APP_PROVISION_TYPE_DEBUG;
            innerBundleInfo.SetBaseApplicationInfo(appInfo);
        }
    }

    std::vector<std::string> testResult;
    bool testRet = GetBundleDataMgr()->GetDebugBundleList(testResult, DEFAULT_USERID);
    EXPECT_TRUE(testRet);
    CheckBundleList(BUNDLE_NAME_TEST, testResult);
    CheckBundleList(BUNDLE_NAME_DEMO, testResult);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetBundleNameForUid_0100
 * @tc.name: test can get the bundle names with bundle installed
 * @tc.desc: 1.system run normally
 *           2.get installed bundle names successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleNameForUid_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::string testResult;
    bool testRet = GetBundleDataMgr()->GetBundleNameForUid(TEST_UID, testResult);
    EXPECT_FALSE(testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleNameForUid_0200
 * @tc.name: test can not get not installed bundle name
 * @tc.desc: 1.system run normally
 *           2.get installed bundle name by uid failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleNameForUid_0200, Function | SmallTest | Level1)
{
    std::string testResult;
    bool testRet = GetBundleDataMgr()->GetBundleNameForUid(TEST_UID, testResult);
    EXPECT_FALSE(testRet);
}

/**
 * @tc.number: GetBundleNameForUid_0300
 * @tc.name: test can not get installed bundle name by incorrect uid
 * @tc.desc: 1.system run normally
 *           2.get installed bundle name by uid failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleNameForUid_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::string testResult;
    bool testRet = GetBundleDataMgr()->GetBundleNameForUid(DEMO_UID, testResult);
    EXPECT_FALSE(testRet);
    EXPECT_NE(BUNDLE_NAME_TEST, testResult);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleNameForUid_0400
 * @tc.name: test can not get installed bundle name by invalid uid
 * @tc.desc: 1.system run normally
 *           2.get installed bundle name by uid failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleNameForUid_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);

    std::string testResult;
    bool testRet = GetBundleDataMgr()->GetBundleNameForUid(INVALID_UID, testResult);
    EXPECT_FALSE(testRet);
    EXPECT_NE(BUNDLE_NAME_TEST, testResult);
    EXPECT_NE(BUNDLE_NAME_DEMO, testResult);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetBundleNameForUid_0100
 * @tc.name: test can get the bundle names with bundle installed
 * @tc.desc: 1.system run normally
 *           2.get installed bundle names successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleNameForUid_0500, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo bundleInfo;
    bool testRet = hostImpl->GetBundleInfoForSelf(BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo);
    EXPECT_TRUE(testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckIsSystemAppByUid_0100
 * @tc.name: test can check the installed bundle whether system app or not by uid
 * @tc.desc: 1.system run normally
 *           2.check the installed bundle successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckIsSystemAppByUid_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);

    bool testRet = GetBundleDataMgr()->CheckIsSystemAppByUid(TEST_UID);
    EXPECT_FALSE(testRet);

    testRet = GetBundleDataMgr()->CheckIsSystemAppByUid(DEMO_UID);
    EXPECT_FALSE(testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: CheckIsSystemAppByUid_0200
 * @tc.name: test can check the installed bundle whether system app or not by uid
 * @tc.desc: 1.system run normally
 *           2.check the installed bundle successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckIsSystemAppByUid_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    bool testRet = GetBundleDataMgr()->CheckIsSystemAppByUid(INVALID_UID);
    EXPECT_FALSE(testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckIsSystemAppByUid_0300
 * @tc.name: Test CheckIsSystemAppByUid
 * @tc.desc: 1.Test the CheckIsSystemAppByUid by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, CheckIsSystemAppByUid_0300, Function | MediumTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<int> gids;
    auto ret = hostImpl->CheckIsSystemAppByUid(TEST_UID);
    EXPECT_EQ(ret, false);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: DUMP_0100
 * @tc.name: Dump bundlelist, bundle info for bundleName
 * @tc.desc: 1.system run normally
 *           2.dump info with one mock installed bundles
 */
HWTEST_F(BmsBundleKitServiceTest, DUMP_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::string infoResult;
    bool infoRet = hostImpl->DumpInfos(
        DumpFlag::DUMP_BUNDLE_INFO, BUNDLE_NAME_TEST, DEFAULT_USERID, infoResult);
    EXPECT_TRUE(infoRet);
    EXPECT_NE(std::string::npos, infoResult.find(BUNDLE_NAME_TEST));
    EXPECT_NE(std::string::npos, infoResult.find(MODULE_NAME_TEST));
    EXPECT_NE(std::string::npos, infoResult.find(ABILITY_NAME_TEST));

    std::string bundleNames;
    bool listRet = hostImpl->DumpInfos(
        DumpFlag::DUMP_BUNDLE_LIST, EMPTY_STRING, DEFAULT_USERID, bundleNames);
    EXPECT_TRUE(listRet);
    EXPECT_NE(std::string::npos, bundleNames.find(BUNDLE_NAME_TEST));

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_TEST, ABILITY_NAME_DEMO);

    std::string names;
    bool namesRet = hostImpl->DumpInfos(
        DumpFlag::DUMP_BUNDLE_LIST, EMPTY_STRING, DEFAULT_USERID, names);
    EXPECT_TRUE(namesRet);
    EXPECT_NE(std::string::npos, names.find(BUNDLE_NAME_DEMO));

    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: DUMP_0200
 * @tc.name: Dump empty bundle info for empty bundle name
 * @tc.desc: 1.system run normally
 *           2.dump with empty bundle name
 */
HWTEST_F(BmsBundleKitServiceTest, DUMP_0200, Function | SmallTest | Level0)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string emptyResult;
    bool emptyRet = hostImpl->DumpInfos(
        DumpFlag::DUMP_BUNDLE_INFO, EMPTY_STRING, DEFAULT_USERID, emptyResult);
    EXPECT_FALSE(emptyRet);
    emptyRet = hostImpl->DumpInfos(
        DumpFlag::DUMP_BUNDLE_INFO, BUNDLE_NAME_TEST, DEFAULT_USERID, emptyResult);
    EXPECT_TRUE(emptyRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: DUMP_0300
 * @tc.name: Dump bundlelist, bundle info for bundleName
 * @tc.desc: 1.system run normally
 *           2.dump info with 2 installed bundles
 */
HWTEST_F(BmsBundleKitServiceTest, DUMP_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string bundleNames;
    bool listRet = hostImpl->DumpInfos(
        DumpFlag::DUMP_BUNDLE_LIST, EMPTY_STRING, DEFAULT_USERID, bundleNames);
    EXPECT_TRUE(listRet);
    EXPECT_NE(std::string::npos, bundleNames.find(BUNDLE_NAME_DEMO));
    EXPECT_NE(std::string::npos, bundleNames.find(BUNDLE_NAME_TEST));

    std::string bundleInfo;
    bool infoRet = hostImpl->DumpInfos(
        DumpFlag::DUMP_BUNDLE_INFO, BUNDLE_NAME_TEST, DEFAULT_USERID, bundleInfo);
    EXPECT_TRUE(infoRet);
    EXPECT_NE(std::string::npos, bundleInfo.find(BUNDLE_NAME_TEST));

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: DUMP_0400
 * @tc.name: Dump empty bundle info for empty bundle name
 * @tc.desc: 1.system run normally
 *           2.dump with empty bundle name
 */
HWTEST_F(BmsBundleKitServiceTest, DUMP_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    std::string emptyResult;
    bool emptyRet = bundleMgrProxy->DumpInfos(
        DumpFlag::DUMP_BUNDLE_INFO, EMPTY_STRING, DEFAULT_USERID, emptyResult);
    EXPECT_FALSE(emptyRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: DUMP_0500
 * @tc.name: Dump empty bundle info for empty bundle name
 * @tc.desc: 1.system run normally
 *           2.dump with empty bundle name
 */
HWTEST_F(BmsBundleKitServiceTest, DUMP_0500, Function | SmallTest | Level0)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string emptyResult;
    bool emptyRet = hostImpl->DumpInfos(
        DumpFlag::DUMP_SHORTCUT_INFO, EMPTY_STRING, DEFAULT_USERID, emptyResult);
    EXPECT_FALSE(emptyRet);
    emptyRet = hostImpl->DumpInfos(
        DumpFlag::DUMP_SHORTCUT_INFO, BUNDLE_NAME_TEST, DEFAULT_USERID, emptyResult);
    EXPECT_TRUE(emptyRet);
    emptyRet = hostImpl->DumpInfos(
        DumpFlag::DUMP_SHORTCUT_INFO, BUNDLE_NAME_TEST, ALL_USERID, emptyResult);
    EXPECT_TRUE(emptyRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: DUMP_0600
 * @tc.name: Dump bundlelist, bundle info for bundleName
 * @tc.desc: 1.system run normally
 *           2.dump with empty bundle name
 */
HWTEST_F(BmsBundleKitServiceTest, DUMP_0600, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string emptyResult;
    bool emptyRet = hostImpl->DumpInfos(
        DumpFlag::DUMP_BUNDLE_LIST, EMPTY_STRING, ALL_USERID, emptyResult);
    EXPECT_TRUE(emptyRet);
}

/**
 * @tc.number: GetSandboxBundleInfo_0100
 * @tc.name: GetSandboxBundleInfo
 * @tc.desc: 1.test GetSandboxBundleInfo
 */
HWTEST_F(BmsBundleKitServiceTest, GetSandboxBundleInfo_0100, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string bundleName = "";
    int32_t appIndex = 100;
    std::string bundleName1 = BUNDLE_NAME_TEST;
    int32_t appIndex1 = 1000;
    int32_t appIndex2 = -1;
    BundleInfo info;
    bool emptyRet = hostImpl->GetSandboxBundleInfo(bundleName, appIndex, DEFAULT_USERID, info);
    EXPECT_NE(emptyRet, ERR_OK);
    emptyRet = hostImpl->GetSandboxBundleInfo(bundleName1, appIndex1, DEFAULT_USERID, info);
    EXPECT_NE(emptyRet, ERR_OK);
    emptyRet = hostImpl->GetSandboxBundleInfo(bundleName1, appIndex2, DEFAULT_USERID, info);
    EXPECT_NE(emptyRet, ERR_OK);
}

/**
 * @tc.number: QueryAbilityInfoByUri_0100
 * @tc.name: test can get the ability info by uri
 * @tc.desc: 1.system run normally
 *           2.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfoByUri_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    AbilityInfo result;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfoByUri(
        ABILITY_URI, DEFAULT_USERID, result);
    EXPECT_EQ(true, testRet);
    EXPECT_EQ(ABILITY_NAME_TEST, result.name);
    EXPECT_NE(ABILITY_NAME_DEMO, result.name);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfoByUri_0200
 * @tc.name: test can get the ability infos by uri
 * @tc.desc: 1.system run normally
 *           2.get ability info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfoByUri_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    AbilityInfo result;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfoByUri(
        ABILITY_URI, DEFAULT_USERID, result);
    EXPECT_EQ(true, testRet);
    EXPECT_EQ(ABILITY_NAME_TEST, result.name);
    EXPECT_NE(ABILITY_NAME_DEMO, result.name);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: QueryAbilityInfoByUri_0300
 * @tc.name: test can not get the ability info by uri which bundle doesn't exist
 * @tc.desc: 1.system run normally
 *           2.get ability info failed
 */

HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfoByUri_0300, Function | SmallTest | Level1)
{
    AbilityInfo result;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfoByUri(
        ABILITY_URI, DEFAULT_USERID, result);
    EXPECT_EQ(false, testRet);
}

/**
 * @tc.number: QueryAbilityInfoByUri_0400
 * @tc.name: test can not get the ability info by empty uri
 * @tc.desc: 1.system run normally
 *           2.get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfoByUri_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    AbilityInfo result;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfoByUri(
        "",  DEFAULT_USERID, result);
    EXPECT_EQ(false, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfoByUri_0500
 * @tc.name: test can not get the ability info by error uri
 * @tc.desc: 1.system run normally
 *           2.get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfoByUri_0500, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    AbilityInfo result;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfoByUri(
        ERROR_URI,  DEFAULT_USERID, result);
    EXPECT_EQ(false, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfoByUri_0600
 * @tc.name: test can get the ability info by uri
 * @tc.desc: 1.system run normally
 *           2.get ability info failed by zero userid
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfoByUri_0600, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    AbilityInfo result;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    bool testRet = bundleMgrProxy->QueryAbilityInfoByUri(
        ABILITY_URI, 0, result);
    EXPECT_EQ(false, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfoByUri_0700
 * @tc.name: test can get the ability info by uri
 * @tc.desc: 1.system run normally
 *           2.get ability info failed by empty ability uri
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfoByUri_0700, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    AbilityInfo result;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    bool testRet = bundleMgrProxy->QueryAbilityInfoByUri(
        "", result);
    EXPECT_EQ(false, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfoByUri_0800
 * @tc.name: test can get the ability info by uri
 * @tc.desc: 1.system run normally
 *           2.get ability info failed by empty ability uri
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfoByUri_0800, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    AbilityInfo result;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool testRet = hostImpl->QueryAbilityInfoByUri(
        ABILITY_URI, DEFAULT_USERID, result);
    EXPECT_EQ(true, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfoByUri_0900
 * @tc.name: test can get the ability info by uri
 * @tc.desc: 1.system run normally
 *           2.get ability info failed by empty ability uri
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfoByUri_0900, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    AbilityInfo result;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool testRet = hostImpl->QueryAbilityInfoByUri(
        ABILITY_URI, DEFAULT_USERID, result);
    EXPECT_EQ(true, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfosByUri_0100
 * @tc.name: test QueryAbilityInfosByUri by BundleMgrHostImpl
 * @tc.desc: 1.system run normally
 *           2.ability not found
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosByUri_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string uri = "invalid";
    std::vector<AbilityInfo> abilityInfos;
    bool ret = hostImpl->QueryAbilityInfosByUri(uri, abilityInfos);
    EXPECT_FALSE(ret);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfosByUri_0100
 * @tc.name: test QueryAbilityInfosByUri by BundleMgrHostImpl
 * @tc.desc: 1.system run normally
 *           2.ability not found
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosByUri_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    std::string uri = "dataability://com.example.hiworld.himusic.UserADataAbility";
    std::vector<AbilityInfo> abilityInfos;
    InnerBundleInfo innerBundleInfo;
    GetBundleDataMgr()->bundleInfos_.insert(
        pair<std::string, InnerBundleInfo>("moduleName", innerBundleInfo));
    EXPECT_FALSE(GetBundleDataMgr()->bundleInfos_.empty());
    bool ret = dataMgr->QueryAbilityInfosByUri(uri, abilityInfos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: QueryExtensionAbilityInfoByUri_0100
 * @tc.name: test can get the extensio ability info by uri
 * @tc.desc: 1.system run normally
 *           2.uri not include :///, invalid
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfoByUri_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    AbilityInfo result;
    ExtensionAbilityInfo extensionAbilityInfo;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    bool testRet = bundleMgrProxy->QueryExtensionAbilityInfoByUri(
        URI, DEFAULT_USERID, extensionAbilityInfo);
    EXPECT_EQ(false, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryExtensionAbilityInfoByUri_0100
 * @tc.name: test can get the extensio ability info by uri
 * @tc.desc: 1.system run normally
 *           2.query info failed by empty uri
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfoByUri_0200, Function | SmallTest | Level1)
{
    AbilityInfo result;
    ExtensionAbilityInfo extensionAbilityInfo;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    bool testRet = bundleMgrProxy->QueryExtensionAbilityInfoByUri(
        "", DEFAULT_USERID, extensionAbilityInfo);
    EXPECT_EQ(false, testRet);
}

/**
 * @tc.number: QueryKeepAliveBundleInfos_0100
 * @tc.name: test can get the keep alive bundle infos
 * @tc.desc: 1.system run normally
 *           2.get all keep alive bundle infos successfully
 */
HWTEST_F(BmsBundleKitServiceTest, QueryKeepAliveBundleInfos_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::vector<BundleInfo> bundleInfos;
    bool ret = GetBundleDataMgr()->QueryKeepAliveBundleInfos(bundleInfos);
    EXPECT_EQ(true, ret);
    CheckInstalledBundleInfos(ABILITY_SIZE_ONE, bundleInfos);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: QueryKeepAliveBundleInfos_0200
 * @tc.name: test can not get the keep alive bundle info which bundle doesn't exist
 * @tc.desc: 1.system run normally
 *           2.get bundle info failed
 */
HWTEST_F(BmsBundleKitServiceTest, QueryKeepAliveBundleInfos_0200, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;
    bool ret = GetBundleDataMgr()->QueryKeepAliveBundleInfos(bundleInfos);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: GetBundleArchiveInfo_0200
 * @tc.name: test can not get the bundle archive info by empty hap file path
 * @tc.desc: 1.system run normally
 *           2.get the bundle archive info failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleArchiveInfo_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo testResult;
    bool listRet = hostImpl->GetBundleArchiveInfo("", BundleFlag::GET_BUNDLE_DEFAULT, testResult);
    EXPECT_FALSE(listRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryKeepAliveBundleInfos_0300
 * @tc.name: test can not get the keep alive bundle info which bundle doesn't exist
 * @tc.desc: 1.system run normally
 *           2.get bundle info failed
 */
HWTEST_F(BmsBundleKitServiceTest, QueryKeepAliveBundleInfos_0300, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    bool ret = bundleMgrProxy->QueryKeepAliveBundleInfos(bundleInfos);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: QueryKeepAliveBundleInfos_0400
 * @tc.name: test can not get the keep alive bundle info which bundle doesn't exist
 * @tc.desc: 1.system run normally
 *           2.get result failed
 */
HWTEST_F(BmsBundleKitServiceTest, QueryKeepAliveBundleInfos_0400, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool ret = hostImpl->QueryKeepAliveBundleInfos(bundleInfos);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: GetBundleArchiveInfo_0300
 * @tc.name: test can not get the bundle archive info by no exist hap file path
 * @tc.desc: 1.system run normally
 *           2.get the bundle archive info failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleArchiveInfo_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo testResult;
    bool listRet = hostImpl->GetBundleArchiveInfo(ERROR_HAP_FILE_PATH, BundleFlag::GET_BUNDLE_DEFAULT, testResult);
    EXPECT_FALSE(listRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleArchiveInfo_0400
 * @tc.name: hapPath with ../ expect return false
 * @tc.desc: 1.system run normally
 *           2.get the bundle archive info failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleArchiveInfo_0400, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo bundleInfo;
    bool ret = hostImpl->GetBundleArchiveInfo(RELATIVE_HAP_FILE_PATH, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetBundleArchiveInfo_0500
 * @tc.name: hapPath with /data/storage/el2/base expect return false
 * @tc.desc: 1.system run normally
 *           2.get the bundle archive info failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleArchiveInfo_0500, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo bundleInfo;
    bool ret = hostImpl->GetBundleArchiveInfo("data/test", BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetBundleArchiveInfo_0600
 * @tc.name: hapPath with /data/storage/el2/base expect return false
 * @tc.desc: 1.system run normally
 *           2.get the bundle archive info failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleArchiveInfo_0600, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo bundleInfo;
    bool ret = hostImpl->GetBundleArchiveInfo(
        ServiceConstants::SANDBOX_DATA_PATH, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetHapModuleInfo_0100
 * @tc.name: test can get the hap module info
 * @tc.desc: 1.system run normally
 *           2.get the hap module info successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetHapModuleInfo_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    AbilityInfo abilityInfo;
    abilityInfo.bundleName = BUNDLE_NAME_TEST;
    abilityInfo.package = PACKAGE_NAME;

    HapModuleInfo hapModuleInfo;
    bool ret = GetBundleDataMgr()->GetHapModuleInfo(abilityInfo, hapModuleInfo);
    EXPECT_EQ(true, ret);
    CheckModuleInfo(hapModuleInfo);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetHapModuleInfo_0200
 * @tc.name: test can not get the hap module info by no exist bundleName
 * @tc.desc: 1.system run normally
 *           2.get the hap module info failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetHapModuleInfo_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    AbilityInfo abilityInfo;
    abilityInfo.bundleName = BUNDLE_NAME_DEMO;
    abilityInfo.package = PACKAGE_NAME;

    HapModuleInfo hapModuleInfo;
    bool ret = GetBundleDataMgr()->GetHapModuleInfo(abilityInfo, hapModuleInfo);
    EXPECT_EQ(false, ret);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetHapModuleInfo_0300
 * @tc.name: test can not get the hap module info by no exist package
 * @tc.desc: 1.system run normally
 *           2.get the hap module info failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetHapModuleInfo_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    AbilityInfo abilityInfo;
    abilityInfo.bundleName = BUNDLE_NAME_TEST;
    abilityInfo.package = BUNDLE_NAME_DEMO;

    HapModuleInfo hapModuleInfo;
    bool ret = GetBundleDataMgr()->GetHapModuleInfo(abilityInfo, hapModuleInfo);
    EXPECT_EQ(false, ret);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetHapModuleInfo_0400
 * @tc.name: test get the hap module info by userId
 * @tc.desc: 1.system run normally
 *           2.get the hap module info failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetHapModuleInfo_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    AbilityInfo abilityInfo;
    abilityInfo.bundleName = BUNDLE_NAME_TEST;
    abilityInfo.package = PACKAGE_NAME;
    HapModuleInfo hapModuleInfo;
    bool ret = GetBundleDataMgr()->GetHapModuleInfo(abilityInfo, hapModuleInfo, DEFAULT_USER_ID_TEST);
    EXPECT_EQ(true, ret);

    ret = GetBundleDataMgr()->GetHapModuleInfo(abilityInfo, hapModuleInfo, NEW_USER_ID_TEST);
    EXPECT_EQ(false, ret);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetHapModuleInfo_0500
 * @tc.name: test can get the hap module info
 * @tc.desc: 1.system run normally
 *           2.get the hap module info failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetHapModuleInfo_0500, Function | SmallTest | Level1)
{
    AbilityInfo abilityInfo1;
    abilityInfo1.bundleName = "";
    abilityInfo1.package = PACKAGE_NAME;

    AbilityInfo abilityInfo2;
    abilityInfo2.bundleName = BUNDLE_NAME_TEST;
    abilityInfo2.package = "";

    AbilityInfo abilityInfo3;
    abilityInfo3.bundleName = "";
    abilityInfo3.package = "";

    HapModuleInfo hapModuleInfo;
    bool ret = GetBundleDataMgr()->GetHapModuleInfo(abilityInfo1, hapModuleInfo);
    EXPECT_FALSE(ret);

    ret = GetBundleDataMgr()->GetHapModuleInfo(abilityInfo2, hapModuleInfo);
    EXPECT_FALSE(ret);

    ret = GetBundleDataMgr()->GetHapModuleInfo(abilityInfo3, hapModuleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CheckApplicationEnabled_0100
 * @tc.name: test can check bundle status is enable by no setting
 * @tc.desc: 1.system run normally
 *           2.check the bundle status successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckApplicationEnabled_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    bool isEnable = false;
    int32_t ret = GetBundleDataMgr()->IsApplicationEnabled(BUNDLE_NAME_TEST, 0, isEnable);
    EXPECT_EQ(0, ret);
    EXPECT_TRUE(isEnable);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckApplicationEnabled_0200
 * @tc.name: test can check bundle status is enable by setting
 * @tc.desc: 1.system run normally
 *           2.check the bundle status successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckApplicationEnabled_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    int32_t testRet = GetBundleDataMgr()->SetApplicationEnabled(BUNDLE_NAME_TEST, 0, true, CALLER_NAME_UT,
        Constants::DEFAULT_USERID);
    EXPECT_EQ(0, testRet);
    bool isEnable = false;
    int32_t ret = GetBundleDataMgr()->IsApplicationEnabled(BUNDLE_NAME_TEST, 0, isEnable);
    EXPECT_EQ(0, ret);
    EXPECT_TRUE(isEnable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckApplicationEnabled_0300
 * @tc.name: test can check bundle status is disable by setting
 * @tc.desc: 1.system run normally
 *           2.check the bundle status successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckApplicationEnabled_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    int32_t testRet = GetBundleDataMgr()->SetApplicationEnabled(BUNDLE_NAME_TEST, 0, false, CALLER_NAME_UT,
        Constants::DEFAULT_USERID);
    EXPECT_EQ(0, testRet);
    bool isEnable = false;
    int32_t ret = GetBundleDataMgr()->IsApplicationEnabled(BUNDLE_NAME_TEST, 0, isEnable);
    EXPECT_EQ(0, ret);
    EXPECT_FALSE(isEnable);

    int32_t testRet2 = GetBundleDataMgr()->SetApplicationEnabled(BUNDLE_NAME_TEST, 0, true, CALLER_NAME_UT,
        Constants::DEFAULT_USERID);
    EXPECT_EQ(0, testRet2);
    ret = GetBundleDataMgr()->IsApplicationEnabled(BUNDLE_NAME_TEST, 0, isEnable);
    EXPECT_EQ(0, ret);
    EXPECT_TRUE(isEnable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckApplicationEnabled_0400
 * @tc.name: test can check bundle status is disable by no install
 * @tc.desc: 1.system run normally
 *           2.check the bundle status failed
 */
HWTEST_F(BmsBundleKitServiceTest, CheckApplicationEnabled_0400, Function | SmallTest | Level1)
{
    bool isEnable = false;
    int32_t ret = GetBundleDataMgr()->IsApplicationEnabled(BUNDLE_NAME_TEST, 0, isEnable);
    EXPECT_NE(0, ret);
}

/**
 * @tc.number: CheckApplicationEnabled_0500
 * @tc.name: test can check bundle status is able by empty bundle name
 * @tc.desc: 1.system run normally
 *           2.check the bundle status successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckApplicationEnabled_0500, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    int32_t testRet = GetBundleDataMgr()->SetApplicationEnabled("", 0, true, CALLER_NAME_UT,
        Constants::DEFAULT_USERID);
    EXPECT_NE(0, testRet);
    bool isEnable = false;
    int32_t ret = GetBundleDataMgr()->IsApplicationEnabled(BUNDLE_NAME_TEST, 0, isEnable);
    EXPECT_EQ(0, ret);
    EXPECT_TRUE(isEnable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckApplicationEnabled_0600
 * @tc.name: test can check bundle status is disable by empty bundle name
 * @tc.desc: 1.system run normally
 *           2.check the bundle status failed
 */
HWTEST_F(BmsBundleKitServiceTest, CheckApplicationEnabled_0600, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    int32_t testRet = GetBundleDataMgr()->SetApplicationEnabled(BUNDLE_NAME_TEST, 0, true, CALLER_NAME_UT,
        Constants::DEFAULT_USERID);
    EXPECT_EQ(0, testRet);
    bool isEnable = false;
    int32_t testRet1 = GetBundleDataMgr()->IsApplicationEnabled("", 0, isEnable);
    EXPECT_NE(0, testRet1);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckApplicationEnabled_0700
 * @tc.name: test can check bundle status is enable by setting
 * @tc.desc: 1.system run normally
 *           2.check the bundle status successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckApplicationEnabled_0700, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    int32_t testRet = bundleMgrProxy->SetApplicationEnabled("", true, Constants::DEFAULT_USERID);
    EXPECT_NE(0, testRet);
    bool isEnable = false;
    int32_t testRet1 = bundleMgrProxy->IsApplicationEnabled("", isEnable);
    EXPECT_NE(0, testRet1);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckApplicationEnabled_0800
 * @tc.name: test can check bundle status is able by empty bundle name
 * @tc.desc: 1.system run normally
 *           2.check the bundle status successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckApplicationEnabled_0800, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ErrCode testRet = hostImpl->SetApplicationEnabled("", true, Constants::UNSPECIFIED_USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    bool isEnable = false;
    ErrCode ret = hostImpl->IsApplicationEnabled(BUNDLE_NAME_TEST, isEnable);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isEnable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckApplicationEnabled_0900
 * @tc.name: test can check bundle status is able by empty bundle name
 * @tc.desc: 1.system run normally
 *           2.check the bundle status successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckApplicationEnabled_0900, Function | SmallTest | Level1)
{
    ErrCode testRet = GetBundleDataMgr()->SetApplicationEnabled("", 0, true, CALLER_NAME_UT,
        Constants::INVALID_USERID);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: CheckApplicationEnabled_1000
 * @tc.name: test hostImpl->SetApplicationEnabled
 * @tc.desc: 1.system run normally
 *           2.check the bundle status successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckApplicationEnabled_1000, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    ErrCode testRet = hostImpl->SetApplicationEnabled(BUNDLE_NAME_TEST, true, Constants::DEFAULT_USERID);
    EXPECT_EQ(testRet, ERR_OK);
    bool isEnable = false;
    ErrCode ret = hostImpl->IsApplicationEnabled(BUNDLE_NAME_TEST, isEnable);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isEnable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleInfosByMetaData_0100
 * @tc.name: test can get the bundle infos by metadata
 * @tc.desc: 1.system run normally
 *           2.get bundle infos successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfosByMetaData_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::vector<BundleInfo> bundleInfos;
    bool testRet = GetBundleDataMgr()->GetBundleInfosByMetaData(META_DATA, bundleInfos);
    EXPECT_EQ(true, testRet);
    CheckInstalledBundleInfos(ABILITY_SIZE_ONE, bundleInfos);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetBundleInfosByMetaData_0200
 * @tc.name: test can not get the bundle infos by empty metadata
 * @tc.desc: 1.system run normally
 *           2.get bundle infos failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfosByMetaData_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::vector<BundleInfo> bundleInfos;
    bool testRet = GetBundleDataMgr()->GetBundleInfosByMetaData("", bundleInfos);
    EXPECT_EQ(false, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetBundleInfosByMetaData_0300
 * @tc.name: test can not get the bundle infos by no exist metadata
 * @tc.desc: 1.system run normally
 *           2.get bundle infos failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfosByMetaData_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::vector<BundleInfo> bundleInfos;
    bool testRet = GetBundleDataMgr()->GetBundleInfosByMetaData(ERROR_META_DATA, bundleInfos);
    EXPECT_EQ(false, testRet);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetBundleInfosByMetaData_0400
 * @tc.name: test can get the bundle infos by metadata
 * @tc.desc: 1.system run normally
 *           2.get bundle infos successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfosByMetaData_0400, Function | MediumTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<BundleInfo> bundleInfos;
    auto ret = hostImpl->GetBundleInfosByMetaData(META_DATA, bundleInfos);
    EXPECT_EQ(ret, true);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: RegisterBundleStatus_0100
 * @tc.name: test can register the bundle status by bundle name
 * @tc.desc: 1.system run normally
 *           2.bundle status callback successfully
 */
HWTEST_F(BmsBundleKitServiceTest, RegisterBundleStatus_0100, Function | SmallTest | Level1)
{
    sptr<MockBundleStatus> bundleStatusCallback = new (std::nothrow) MockBundleStatus();
    bundleStatusCallback->SetBundleName(HAP_FILE_PATH);
    bool result = GetBundleDataMgr()->RegisterBundleStatusCallback(bundleStatusCallback);
    EXPECT_TRUE(result);
    EXPECT_NE(commonEventMgr_, nullptr);
    commonEventMgr_->NotifyBundleStatus(installRes_, GetBundleDataMgr());

    int32_t callbackResult = bundleStatusCallback->GetResultCode();
    EXPECT_EQ(callbackResult, ERR_OK);
}

/**
 * @tc.number: RegisterBundleStatus_0200
 * @tc.name: test can register the bundle status by bundle name
 * @tc.desc: 1.system run normally
 *           2.bundle status callback failed by empty bundle name
 */
HWTEST_F(BmsBundleKitServiceTest, RegisterBundleStatus_0200, Function | SmallTest | Level1)
{
    sptr<MockBundleStatus> bundleStatusCallback = new (std::nothrow) MockBundleStatus();
    bundleStatusCallback->SetBundleName(HAP_FILE_PATH);
    bool result = GetBundleDataMgr()->RegisterBundleStatusCallback(bundleStatusCallback);
    EXPECT_TRUE(result);
    installRes_.bundleName = "";
    EXPECT_NE(commonEventMgr_, nullptr);
    commonEventMgr_->NotifyBundleStatus(installRes_, GetBundleDataMgr());

    int32_t callbackResult = bundleStatusCallback->GetResultCode();
    EXPECT_EQ(callbackResult, ERR_TIMED_OUT);
}

/**
 * @tc.number: RegisterBundleStatus_0300
 * @tc.name: test can register the bundle status by bundle name
 * @tc.desc: 1.system run normally
 *           2.bundle status callback failed by no exist bundle name
 */
HWTEST_F(BmsBundleKitServiceTest, RegisterBundleStatus_0300, Function | SmallTest | Level1)
{
    sptr<MockBundleStatus> bundleStatusCallback = new (std::nothrow) MockBundleStatus();
    bundleStatusCallback->SetBundleName(HAP_FILE_PATH);
    bool result = GetBundleDataMgr()->RegisterBundleStatusCallback(bundleStatusCallback);
    EXPECT_TRUE(result);
    installRes_.bundleName = ERROR_HAP_FILE_PATH;
    EXPECT_NE(commonEventMgr_, nullptr);
    commonEventMgr_->NotifyBundleStatus(installRes_, GetBundleDataMgr());

    int32_t callbackResult = bundleStatusCallback->GetResultCode();
    EXPECT_EQ(callbackResult, ERR_TIMED_OUT);
}

/**
 * @tc.number: RegisterBundleStatus_0400
 * @tc.name: test can register the bundle status by empty bundle name
 * @tc.desc: 1.system run normally
 *           2.bundle status callback failed
 */
HWTEST_F(BmsBundleKitServiceTest, RegisterBundleStatus_0400, Function | SmallTest | Level1)
{
    sptr<MockBundleStatus> bundleStatusCallback = new (std::nothrow) MockBundleStatus();
    bundleStatusCallback->SetBundleName("");
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool result = hostImpl->RegisterBundleStatusCallback(bundleStatusCallback);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: RegisterBundleStatus_0500
 * @tc.name: test can register the bundle status by bundle name
 * @tc.desc: 1.system run normally
 *           2.bundle status callback failed by no exist bundle name
 */
HWTEST_F(BmsBundleKitServiceTest, RegisterBundleStatus_0500, Function | SmallTest | Level1)
{
    sptr<MockBundleStatus> bundleStatusCallback = new (std::nothrow) MockBundleStatus();
    bundleStatusCallback->SetBundleName(HAP_FILE_PATH);
    bundleStatusCallback->SetUserId(DEFAULT_USERID);
    bool result = GetBundleDataMgr()->RegisterBundleStatusCallback(bundleStatusCallback);
    EXPECT_TRUE(result);
    installRes_.bundleName = ERROR_HAP_FILE_PATH;
    EXPECT_NE(commonEventMgr_, nullptr);
    commonEventMgr_->NotifyBundleStatus(installRes_, GetBundleDataMgr());

    int32_t callbackResult = bundleStatusCallback->GetResultCode();
    EXPECT_EQ(callbackResult, ERR_TIMED_OUT);
}

/**
 * @tc.number: RegisterBundleStatus_0600
 * @tc.name: test can not register, the bundle status dataMgr is nullptr
 * @tc.desc: 1.system run normally
 *           2.bundle status callback failed
 */
HWTEST_F(BmsBundleKitServiceTest, RegisterBundleStatus_0600, Function | SmallTest | Level1)
{
    sptr<IBundleStatusCallback> bundleStatusCallback = nullptr;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool result = hostImpl->RegisterBundleStatusCallback(bundleStatusCallback);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: RegisterBundleEventCallback_0100
 * @tc.name: test can not register, the bundle status bundleEventCallback is nullptr
 * @tc.desc: 1.system run normally
 *           2.bundle status callback failed
 */
HWTEST_F(BmsBundleKitServiceTest, RegisterBundleEventCallback_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool result = hostImpl->RegisterBundleEventCallback(nullptr);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: UnregisterBundleEventCallback_0100
 * @tc.name: test can not unregister, the bundle status bundleEventCallback is nullptr
 * @tc.desc: 1.system run normally
 *           2.bundle status callback failed
 */
HWTEST_F(BmsBundleKitServiceTest, UnregisterBundleEventCallback_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool result = hostImpl->UnregisterBundleEventCallback(nullptr);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: ClearBundleStatus_0100
 * @tc.name: test can clear the bundle status by bundle name
 * @tc.desc: 1.system run normally
 *           2.bundle status callback failed by cleared bundle name
 */
HWTEST_F(BmsBundleKitServiceTest, ClearBundleStatus_0100, Function | SmallTest | Level1)
{
    sptr<MockBundleStatus> bundleStatusCallback1 = new (std::nothrow) MockBundleStatus();
    bundleStatusCallback1->SetBundleName(HAP_FILE_PATH1);
    bool result1 = GetBundleDataMgr()->RegisterBundleStatusCallback(bundleStatusCallback1);
    EXPECT_TRUE(result1);

    bool result2 = GetBundleDataMgr()->ClearBundleStatusCallback(bundleStatusCallback1);
    EXPECT_TRUE(result2);

    sptr<MockBundleStatus> bundleStatusCallback = new (std::nothrow) MockBundleStatus();
    bundleStatusCallback->SetBundleName(HAP_FILE_PATH);
    bool result = GetBundleDataMgr()->RegisterBundleStatusCallback(bundleStatusCallback);
    EXPECT_TRUE(result);
    installRes_.bundleName = HAP_FILE_PATH;
    EXPECT_NE(commonEventMgr_, nullptr);
    commonEventMgr_->NotifyBundleStatus(installRes_, GetBundleDataMgr());

    int32_t callbackResult = bundleStatusCallback->GetResultCode();
    EXPECT_EQ(callbackResult, ERR_OK);

    installRes_.bundleName = HAP_FILE_PATH1;
    commonEventMgr_->NotifyBundleStatus(installRes_, GetBundleDataMgr());

    int32_t callbackResult1 = bundleStatusCallback1->GetResultCode();
    EXPECT_EQ(callbackResult1, ERR_TIMED_OUT);
}

/**
 * @tc.number: UnregisterBundleStatus_0100
 * @tc.name: test can unregister the bundle status by bundle name
 * @tc.desc: 1.system run normally
 *           2.bundle status callback failed by unregister bundle name
 */
HWTEST_F(BmsBundleKitServiceTest, UnregisterBundleStatus_0100, Function | SmallTest | Level1)
{
    sptr<MockBundleStatus> bundleStatusCallback = new (std::nothrow) MockBundleStatus();
    bundleStatusCallback->SetBundleName(HAP_FILE_PATH);
    bool result = GetBundleDataMgr()->RegisterBundleStatusCallback(bundleStatusCallback);
    EXPECT_TRUE(result);

    sptr<MockBundleStatus> bundleStatusCallback1 = new (std::nothrow) MockBundleStatus();
    bundleStatusCallback1->SetBundleName(HAP_FILE_PATH1);
    bool result1 = GetBundleDataMgr()->RegisterBundleStatusCallback(bundleStatusCallback1);
    EXPECT_TRUE(result1);

    bool result2 = GetBundleDataMgr()->UnregisterBundleStatusCallback();
    EXPECT_TRUE(result2);
    installRes_.bundleName = HAP_FILE_PATH;
    EXPECT_NE(commonEventMgr_, nullptr);
    commonEventMgr_->NotifyBundleStatus(installRes_, GetBundleDataMgr());

    int32_t callbackResult = bundleStatusCallback->GetResultCode();
    EXPECT_EQ(callbackResult, ERR_TIMED_OUT);

    installRes_.bundleName = HAP_FILE_PATH1;
    commonEventMgr_->NotifyBundleStatus(installRes_, GetBundleDataMgr());

    int32_t callbackResult1 = bundleStatusCallback1->GetResultCode();
    EXPECT_EQ(callbackResult1, ERR_TIMED_OUT);
}

/**
 * @tc.number: GetBundlesForUid_0200
 * @tc.name: test can not get not installed bundle names
 * @tc.desc: 1.system run normally
 *           2.get installed bundle names by uid failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundlesForUid_0200, Function | SmallTest | Level1)
{
    std::vector<std::string> testResult;
    bool testRet = GetBundleDataMgr()->GetBundlesForUid(TEST_UID, testResult);
    EXPECT_FALSE(testRet);
    EXPECT_EQ(BUNDLE_NAMES_SIZE_ZERO, testResult.size());
}

/**
 * @tc.number: GetBundlesForUid_0300
 * @tc.name: test can not get installed bundle names by incorrect uid
 * @tc.desc: 1.system run normally
 *           2.get installed bundle names by uid failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundlesForUid_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::vector<std::string> testResult;
    bool testRet = GetBundleDataMgr()->GetBundlesForUid(DEMO_UID, testResult);
    EXPECT_FALSE(testRet);
    EXPECT_EQ(BUNDLE_NAMES_SIZE_ZERO, testResult.size());

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundlesForUid_0400
 * @tc.name: test can not get installed bundle names by invalid uid
 * @tc.desc: 1.system run normally
 *           2.get installed bundle names by uid failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundlesForUid_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);

    std::vector<std::string> testResult;
    bool testRet = GetBundleDataMgr()->GetBundlesForUid(INVALID_UID, testResult);
    EXPECT_FALSE(testRet);
    EXPECT_EQ(BUNDLE_NAMES_SIZE_ZERO, testResult.size());

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetBundlesForUid_0500
 * @tc.name: test can get the bundle names with bundle installed
 * @tc.desc: 1.system run normally
 *           2.get installed bundle names successfully
 */
    HWTEST_F(BmsBundleKitServiceTest, GetBundlesForUid_0500, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    std::vector<std::string> testResult;
    testResult.emplace_back(BUNDLE_NAME_DEMO);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool testRet = hostImpl->GetBundlesForUid(TEST_UID, testResult);
    EXPECT_FALSE(testRet);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetNameForUid_0200
 * @tc.name: test can not get not installed uid name
 * @tc.desc: 1.system run normally
 *           2.get installed uid name by uid failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetNameForUid_0200, Function | SmallTest | Level1)
{
    std::string testResult;
    ErrCode testRet = GetBundleDataMgr()->GetNameForUid(TEST_UID, testResult);
    EXPECT_NE(testRet, ERR_OK);
    EXPECT_NE(BUNDLE_NAME_TEST, testResult);
}

/**
 * @tc.number: GetNameForUid_0300
 * @tc.name: test can not get installed uid name by incorrect uid
 * @tc.desc: 1.system run normally
 *           2.get installed uid name by uid failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetNameForUid_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::string testResult;
    ErrCode testRet = GetBundleDataMgr()->GetNameForUid(DEMO_UID, testResult);
    EXPECT_NE(testRet, ERR_OK);
    EXPECT_NE(BUNDLE_NAME_TEST, testResult);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetNameForUid_0400
 * @tc.name: test can not get installed uid name by invalid uid
 * @tc.desc: 1.system run normally
 *           2.get installed uid name by uid failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetNameForUid_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);

    std::string testResult;
    ErrCode testRet = GetBundleDataMgr()->GetNameForUid(INVALID_UID, testResult);
    EXPECT_NE(testRet, ERR_OK);
    EXPECT_NE(BUNDLE_NAME_TEST, testResult);
    EXPECT_NE(BUNDLE_NAME_DEMO, testResult);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: CheckAbilityEnabled_0100
 * @tc.name: test can check ability status is enable by no setting
 * @tc.desc: 1.system run normally
 *           2.check the ability status successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckAbilityEnabled_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo = MockAbilityInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    bool isEnable = false;
    int32_t testRet = GetBundleDataMgr()->IsAbilityEnabled(abilityInfo, 0, isEnable);
    EXPECT_EQ(0, testRet);
    EXPECT_TRUE(isEnable);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckAbilityEnabled_0200
 * @tc.name: test can check ability status is enable by setting
 * @tc.desc: 1.system run normally
 *           2.check the ability status successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckAbilityEnabled_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo = MockAbilityInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    int32_t testRet = GetBundleDataMgr()->SetAbilityEnabled(abilityInfo, 0, true, Constants::DEFAULT_USERID);
    EXPECT_TRUE(testRet == 0);
    bool isEnable = false;
    int32_t testRet1 = GetBundleDataMgr()->IsAbilityEnabled(abilityInfo, 0, isEnable);
    EXPECT_EQ(0, testRet1);
    EXPECT_TRUE(isEnable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckAbilityEnabled_0300
 * @tc.name: test can check ability status is disable by setting and can be enabled again
 * @tc.desc: 1.system run normally
 *           2.check the ability status successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckAbilityEnabled_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo = MockAbilityInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    int32_t testRet = GetBundleDataMgr()->SetAbilityEnabled(abilityInfo, 0, false, Constants::DEFAULT_USERID);
    EXPECT_EQ(0, testRet);
    bool isEnable = false;
    int32_t testRet1 = GetBundleDataMgr()->IsAbilityEnabled(abilityInfo, 0, isEnable);
    EXPECT_EQ(0, testRet1);
    EXPECT_FALSE(isEnable);
    int32_t testRet2 = GetBundleDataMgr()->SetAbilityEnabled(abilityInfo, 0, true, Constants::DEFAULT_USERID);
    EXPECT_EQ(0, testRet2);
    int32_t testRet3 = GetBundleDataMgr()->IsAbilityEnabled(abilityInfo, 0, isEnable);
    EXPECT_EQ(0, testRet3);
    EXPECT_TRUE(isEnable);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckAbilityEnabled_0400
 * @tc.name: test can check ability status is disable by no install
 * @tc.desc: 1.system run normally
 *           2.check the ability status failed
 */
HWTEST_F(BmsBundleKitServiceTest, CheckAbilityEnabled_0400, Function | SmallTest | Level1)
{
    AbilityInfo abilityInfo = MockAbilityInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    bool isEnable = false;
    int32_t testRet = GetBundleDataMgr()->IsAbilityEnabled(abilityInfo, 0, isEnable);
    EXPECT_NE(0, testRet);
}

/**
 * @tc.number: CheckAbilityEnabled_0500
 * @tc.name: test can check ability status is able by empty AbilityInfo
 * @tc.desc: 1.system run normally
 *           2.check the ability status successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckAbilityEnabled_0500, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    AbilityInfo abilityInfoEmpty;
    int32_t testRet = GetBundleDataMgr()->SetAbilityEnabled(abilityInfoEmpty, 0, false, Constants::DEFAULT_USERID);
    EXPECT_NE(0, testRet);
    AbilityInfo abilityInfo = MockAbilityInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    bool isEnable = false;
    int32_t testRet1 = GetBundleDataMgr()->IsAbilityEnabled(abilityInfo, 0, isEnable);
    EXPECT_EQ(0, testRet1);
    EXPECT_TRUE(isEnable);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckAbilityEnabled_0600
 * @tc.name: test can check ability status is disable by empty AbilityInfo
 * @tc.desc: 1.system run normally
 *           2.check the ability status failed
 */
HWTEST_F(BmsBundleKitServiceTest, CheckAbilityEnabled_0600, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo = MockAbilityInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    int32_t testRet = GetBundleDataMgr()->SetAbilityEnabled(abilityInfo, 0, true, Constants::DEFAULT_USERID);
    EXPECT_EQ(0, testRet);
    AbilityInfo abilityInfoEmpty;
    bool isEnable = false;
    int32_t testRet1 = GetBundleDataMgr()->IsAbilityEnabled(abilityInfoEmpty, 0, isEnable);
    EXPECT_NE(0, testRet1);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckAbilityEnabled_0700
 * @tc.name: test can check ability status is enable by empty moduleName
 * @tc.desc: 1.system run normally
 *           2.check the ability status successful
 */
HWTEST_F(BmsBundleKitServiceTest, CheckAbilityEnabled_0700, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo;
    abilityInfo.name = ABILITY_NAME_TEST;
    abilityInfo.bundleName = BUNDLE_NAME_TEST;
    int32_t testRet = GetBundleDataMgr()->SetAbilityEnabled(abilityInfo, 0, true, Constants::DEFAULT_USERID);
    EXPECT_EQ(0, testRet);
    bool isEnable = false;
    int32_t testRet1 = GetBundleDataMgr()->IsAbilityEnabled(abilityInfo, 0, isEnable);
    EXPECT_EQ(0, testRet1);
    EXPECT_TRUE(isEnable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckAbilityEnabled_0800
 * @tc.name: test can check ability status is disable by moduleName
 * @tc.desc: 1.system run normally
 *           2.check the ability status successful
 */
HWTEST_F(BmsBundleKitServiceTest, CheckAbilityEnabled_0800, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo;
    abilityInfo.name = ABILITY_NAME_TEST;
    abilityInfo.bundleName = BUNDLE_NAME_TEST;
    abilityInfo.moduleName = MODULE_NAME_TEST;
    int32_t testRet = GetBundleDataMgr()->SetAbilityEnabled(abilityInfo, 0, true, Constants::DEFAULT_USERID);
    EXPECT_EQ(0, testRet);
    bool isEnable = false;
    int32_t testRet1 = GetBundleDataMgr()->IsAbilityEnabled(abilityInfo, 0, isEnable);
    EXPECT_EQ(0, testRet1);
    EXPECT_TRUE(isEnable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckAbilityEnabled_0900
 * @tc.name: test can check ability status is disable by moduleName
 * @tc.desc: 1.system run normally
 *           2.check the ability status failed
 */
HWTEST_F(BmsBundleKitServiceTest, CheckAbilityEnabled_0900, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo;
    abilityInfo.name = ABILITY_NAME_TEST;
    abilityInfo.bundleName = BUNDLE_NAME_TEST;
    abilityInfo.moduleName = MODULE_NAME_TEST_1;
    int32_t testRet = GetBundleDataMgr()->SetAbilityEnabled(abilityInfo, 0, true, Constants::DEFAULT_USERID);
    EXPECT_FALSE(testRet == 0);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckAbilityEnabled_1000
 * @tc.name: test can check ability status is enable by no setting
 * @tc.desc: 1.system run normally
 *           2.check the ability status successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckAbilityEnabled_1000, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo;
    abilityInfo.name = ABILITY_NAME_TEST;
    abilityInfo.bundleName = BUNDLE_NAME_TEST;
    bool isEnable = false;
    int32_t testRet = GetBundleDataMgr()->IsAbilityEnabled(abilityInfo, 0, isEnable);
    EXPECT_EQ(0, testRet);
    EXPECT_TRUE(isEnable);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckAbilityEnabled_1100
 * @tc.name: test can check ability status is enable by no setting
 * @tc.desc: 1.system run normally
 *           2.check the ability status successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CheckAbilityEnabled_1100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo;
    abilityInfo.name = ABILITY_NAME_TEST;
    abilityInfo.bundleName = BUNDLE_NAME_TEST;
    abilityInfo.moduleName = MODULE_NAME_TEST;
    bool isEnable = false;
    int32_t testRet = GetBundleDataMgr()->IsAbilityEnabled(abilityInfo, 0, isEnable);
    EXPECT_EQ(0, testRet);
    EXPECT_TRUE(isEnable);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckAbilityEnabled_1200
 * @tc.name: test can check ability status is enable by wrong moduleName
 * @tc.desc: 1.system run normally
 *           2.check the ability status failed
 */
HWTEST_F(BmsBundleKitServiceTest, CheckAbilityEnabled_1200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo;
    abilityInfo.name = ABILITY_NAME_TEST;
    abilityInfo.bundleName = BUNDLE_NAME_TEST;
    abilityInfo.moduleName = MODULE_NAME_TEST_1;
    bool isEnable = false;
    int32_t testRet = GetBundleDataMgr()->IsAbilityEnabled(abilityInfo, 0, isEnable);
    EXPECT_NE(0, testRet);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckAbilityEnabled_1300
 * @tc.name: test can check ability status is disable by empty AbilityInfo
 * @tc.desc: 1.system run normally
 *           2.check the ability status failed
 */
HWTEST_F(BmsBundleKitServiceTest, CheckAbilityEnabled_1300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo = MockAbilityInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    int32_t testRet = GetBundleDataMgr()->SetAbilityEnabled(abilityInfo, 0, true, Constants::DEFAULT_USERID);
    EXPECT_EQ(0, testRet);
    AbilityInfo abilityInfoEmpty;
    bool isEnable = false;
    int32_t testRet1 = GetBundleDataMgr()->IsAbilityEnabled(abilityInfoEmpty, 0, isEnable);
    EXPECT_NE(0, testRet1);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckAbilityEnabled_1400
 * @tc.name: test can check ability status is disable by empty AbilityInfo
 * @tc.desc: 1.system run normally
 *           2.check the ability status failed
 */
HWTEST_F(BmsBundleKitServiceTest, CheckAbilityEnabled_1400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo = MockAbilityInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t testRet = hostImpl->SetAbilityEnabled(abilityInfo, true, Constants::DEFAULT_USERID);
    EXPECT_EQ(0, testRet);
    AbilityInfo abilityInfoEmpty;
    bool isEnable = false;
    int32_t testRet1 = hostImpl->IsAbilityEnabled(abilityInfoEmpty, isEnable);
    EXPECT_NE(0, testRet1);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CheckAbilityEnabled_1500
 * @tc.name: test can check ability status is enable by empty moduleName
 * @tc.desc: 1.system run normally
 *           2.check the ability status successful
 */
HWTEST_F(BmsBundleKitServiceTest, CheckAbilityEnabled_1500, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo;
    abilityInfo.name = ABILITY_NAME_TEST;
    abilityInfo.bundleName = BUNDLE_NAME_TEST;
    int32_t testRet = GetBundleDataMgr()->SetAbilityEnabled(abilityInfo, 0, true, Constants::UNSPECIFIED_USERID);
    EXPECT_NE(0, testRet);
    bool isEnable = false;
    int32_t testRet1 = GetBundleDataMgr()->IsAbilityEnabled(abilityInfo, 0, isEnable);
    EXPECT_EQ(0, testRet1);
    EXPECT_TRUE(isEnable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetFormInfoByModule_0100
 * @tc.name: test can  get the formInfo
 * @tc.desc: 1.system run normally
 *           2.get formInfo by moduleName successful
 */
HWTEST_F(BmsBundleKitServiceTest, GetFormInfoByModule_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfos;
    auto result = GetBundleDataMgr()->GetFormsInfoByModule(BUNDLE_NAME_TEST, MODULE_NAME_TEST, formInfos);
    EXPECT_EQ(result, true);
    EXPECT_FALSE(formInfos.empty());
    CheckFormInfoTest(formInfos);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetFormInfoByModule_0200
 * @tc.name: test can get the formInfo
 * @tc.desc: 1.system run normally
 *           2.get forms info in different bundle
 */
HWTEST_F(BmsBundleKitServiceTest, GetFormInfoByModule_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfo1;
    auto result = GetBundleDataMgr()->GetFormsInfoByModule(BUNDLE_NAME_TEST, MODULE_NAME_TEST, formInfo1);
    EXPECT_EQ(result, true);
    EXPECT_FALSE(formInfo1.empty());
    CheckFormInfoTest(formInfo1);

    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfo2;
    auto result1 = GetBundleDataMgr()->GetFormsInfoByModule(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, formInfo2);
    EXPECT_EQ(result1, true);
    EXPECT_FALSE(formInfo2.empty());
    CheckFormInfoDemo(formInfo2);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetFormInfoByModule_0400
 * @tc.name: test can not get the formInfo
 * @tc.desc:1.system run normally
 *          2.get form info with error moduleName
 */
HWTEST_F(BmsBundleKitServiceTest, GetFormInfoByModule_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfos;
    GetBundleDataMgr()->GetFormsInfoByModule(BUNDLE_NAME_TEST, MODULE_NAME_DEMO, formInfos);
    EXPECT_TRUE(formInfos.empty());
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetFormInfoByModule_0400
 * @tc.name: test can not get the formInfo
 * @tc.desc: 1.system run normally
 *           2.get form info with empty moduleName
 */
HWTEST_F(BmsBundleKitServiceTest, GetFormInfoByModule_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_DEMO);
    std::vector<FormInfo> formInfos;
    GetBundleDataMgr()->GetFormsInfoByModule(BUNDLE_NAME_TEST, EMPTY_STRING, formInfos);
    EXPECT_TRUE(formInfos.empty());
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetFormInfoByModule_0500
 * @tc.name: test can not get the formInfo
 * @tc.desc: 1.system run normally
 *           2.get form info with non bundle
 */
HWTEST_F(BmsBundleKitServiceTest, GetFormInfoByModule_0500, Function | SmallTest | Level1)
{
    std::vector<FormInfo> formInfos;
    GetBundleDataMgr()->GetFormsInfoByModule("", EMPTY_STRING, formInfos);
    EXPECT_TRUE(formInfos.empty());
}

/**
 * @tc.number: GetFormInfoByModule_0600
 * @tc.name: test can not get the formInfo
 * @tc.desc:1.system run normally
 *          2.get form info with empty moduleName
 */
HWTEST_F(BmsBundleKitServiceTest, GetFormInfoByModule_0600, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfos;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    auto result = bundleMgrProxy->GetFormsInfoByModule(BUNDLE_NAME_TEST, "", formInfos);
    EXPECT_EQ(result, false);
    EXPECT_TRUE(formInfos.empty());
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetFormInfoByModule_0800
 * @tc.name: test can  get the formInfo
 * @tc.desc: 1.system run normally
 *           2.get formInfo by moduleName successful
 */
HWTEST_F(BmsBundleKitServiceTest, GetFormInfoByModule_0800, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfos;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    auto result = hostImpl->GetFormsInfoByModule(BUNDLE_NAME_TEST, MODULE_NAME_TEST, formInfos);
    EXPECT_EQ(result, true);
    result = hostImpl->GetFormsInfoByModule("com.ohos.error", MODULE_NAME_TEST, formInfos);
    EXPECT_EQ(result, false);
    EXPECT_FALSE(formInfos.empty());
    CheckFormInfoTest(formInfos);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetFormInfoByApp_0100
 * @tc.name: test can get the formInfo by bundlename
 * @tc.desc: 1.system run normally
 *           2.get form info by bundleName
 */
HWTEST_F(BmsBundleKitServiceTest, GetFormInfoByApp_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfos;
    auto result = GetBundleDataMgr()->GetFormsInfoByApp(BUNDLE_NAME_TEST, formInfos);
    EXPECT_EQ(result, true);
    EXPECT_FALSE(formInfos.empty());
    CheckFormInfoTest(formInfos);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetFormInfoByApp_0200
 * @tc.name: test can get the formInfo in different app by bundlename
 * @tc.desc: 1.system run normally
 *           2.get form info by different bundleName
 */
HWTEST_F(BmsBundleKitServiceTest, GetFormInfoByApp_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfo1;
    auto result = GetBundleDataMgr()->GetFormsInfoByApp(BUNDLE_NAME_TEST, formInfo1);
    EXPECT_EQ(result, true);
    EXPECT_FALSE(formInfo1.empty());
    CheckFormInfoTest(formInfo1);

    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfo2;
    auto result1 = GetBundleDataMgr()->GetFormsInfoByApp(BUNDLE_NAME_DEMO, formInfo2);
    EXPECT_EQ(result1, true);
    EXPECT_FALSE(formInfo2.empty());
    CheckFormInfoDemo(formInfo2);

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetFormInfoByApp_0300
 * @tc.name: test can't get the formInfo in app by error app name
 * @tc.desc: 1.system run normally
 *           2.get form info by error bundleName
 */
HWTEST_F(BmsBundleKitServiceTest, GetFormInfoByApp_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfo1;
    GetBundleDataMgr()->GetFormsInfoByApp(BUNDLE_NAME_DEMO, formInfo1);
    EXPECT_TRUE(formInfo1.empty());
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetFormInfoByApp_0400
 * @tc.name: test can't get the formInfo in app by empty app name
 * @tc.desc: 1.system run normally
 *           2.get form info by empty bundleName
 */
HWTEST_F(BmsBundleKitServiceTest, GetFormInfoByApp_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfo1;
    GetBundleDataMgr()->GetFormsInfoByApp(EMPTY_STRING, formInfo1);
    EXPECT_TRUE(formInfo1.empty());
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetFormInfoByApp_0500
 * @tc.name: test can't get the formInfo have no bundle
 * @tc.desc: 1.system run normally
 *           2.get form info with non bundle
 */
HWTEST_F(BmsBundleKitServiceTest, GetFormInfoByApp_0500, Function | SmallTest | Level1)
{
    std::vector<FormInfo> formInfo1;
    GetBundleDataMgr()->GetFormsInfoByApp("", formInfo1);
    EXPECT_TRUE(formInfo1.empty());
}

/**
 * @tc.number: GetFormInfoByApp_0600
 * @tc.name: test can get the formInfo by bundlename
 * @tc.desc: 1.system run normally
 *           2.get form info fail by empty bundleName
 */
HWTEST_F(BmsBundleKitServiceTest, GetFormInfoByApp_0600, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfos;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    auto result = bundleMgrProxy->GetFormsInfoByApp("", formInfos);
    EXPECT_EQ(result, false);
    EXPECT_TRUE(formInfos.empty());
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetFormInfoByApp_0700
 * @tc.name: test can't get the formInfo have no bundle
 * @tc.desc: 1.system run normally
 *           2.get form info with non bundle
 */
HWTEST_F(BmsBundleKitServiceTest, GetFormInfoByApp_0700, Function | SmallTest | Level1)
{
    std::vector<FormInfo> formInfo;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    auto ret = hostImpl->GetFormsInfoByApp("", formInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: GetDistributedBundleInfo_0100
 * @tc.name: GetDistributedBundleInfo
 * @tc.desc: 1.system run normally
 *           2.test GetDistributedBundleInfo
 */
HWTEST_F(BmsBundleKitServiceTest, GetDistributedBundleInfo_0100, Function | SmallTest | Level1)
{
    std::string networkId = "";
    const std::string bundleName = "";
    DistributedBundleInfo distributedBundleInfo;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    auto ret = hostImpl->GetDistributedBundleInfo(bundleName, bundleName, distributedBundleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: GetAllFormInfo_0100
 * @tc.name: test can get all the formInfo
 * @tc.desc: 1.system run normally
 *           2.get forms by all the bundle
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllFormInfo_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfos;
    auto result = GetBundleDataMgr()->GetAllFormsInfo(formInfos);
    EXPECT_EQ(result, true);
    EXPECT_FALSE(formInfos.empty());
    for (const auto &info : formInfos) {
        if (info.bundleName == BUNDLE_NAME_TEST) {
            std::vector<FormInfo> formInfo;
            formInfo.emplace_back(info);
            CheckFormInfoTest(formInfo);
            break;
        }
    }
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAllFormInfo_0200
 * @tc.name: test can get all the formInfo
 * @tc.desc: 1.system run normally
 *           2.get forms by all the bundle
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllFormInfo_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfos;
    auto result = GetBundleDataMgr()->GetAllFormsInfo(formInfos);
    EXPECT_FALSE(formInfos.empty());
    EXPECT_EQ(result, true);
    for (const auto &info : formInfos) {
        if (info.bundleName == MODULE_NAME_DEMO) {
            std::vector<FormInfo> formInfo1;
            formInfo1.emplace_back(info);
            CheckFormInfoDemo(formInfo1);
        } else if (info.bundleName == MODULE_NAME_TEST){
            std::vector<FormInfo> formInfo2;
            formInfo2.emplace_back(info);
            CheckFormInfoTest(formInfo2);
        }
    }
    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetAllFormInfo_0300
 * @tc.name: test can get all the formInfo
 * @tc.desc: 1.system run normally
 *           2.get forms by all the bundle
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllFormInfo_0301, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfos;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    auto result = bundleMgrProxy->GetAllFormsInfo(formInfos);
    EXPECT_EQ(result, true);
    EXPECT_TRUE(formInfos.empty());
    for (const auto &info : formInfos) {
        if (info.bundleName == BUNDLE_NAME_TEST) {
            std::vector<FormInfo> formInfo;
            formInfo.emplace_back(info);
            CheckFormInfoTest(formInfo);
            break;
        }
    }
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAllFormInfo_0400
 * @tc.name: test can get all the formInfo
 * @tc.desc: 1.system run normally
 *           2.get forms by all the bundle
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllFormInfo_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<FormInfo> formInfos;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    auto result = hostImpl->GetAllFormsInfo(formInfos);
    EXPECT_EQ(result, true);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetShortcutInfos_0100
 * @tc.name: test can get shortcutInfo by bundleName
 * @tc.desc: 1.can get shortcutInfo
 */
HWTEST_F(BmsBundleKitServiceTest, GetShortcutInfos_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<ShortcutInfo> shortcutInfos;
    auto result = GetBundleDataMgr()->GetShortcutInfos(
        BUNDLE_NAME_TEST,  DEFAULT_USERID, shortcutInfos);
    EXPECT_TRUE(result);
    CheckShortcutInfoTest(shortcutInfos);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetShortcutInfos_0200
 * @tc.name: test have two bundle can get shortcutInfo by bundleName
 * @tc.desc: 1.can get shortcutInfo
 */
HWTEST_F(BmsBundleKitServiceTest, GetShortcutInfos_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_TEST);
    std::vector<ShortcutInfo> shortcutInfo1;
    auto result1 = GetBundleDataMgr()->GetShortcutInfos(
        BUNDLE_NAME_TEST,  DEFAULT_USERID, shortcutInfo1);
    EXPECT_TRUE(result1);
    CheckShortcutInfoTest(shortcutInfo1);
    std::vector<ShortcutInfo> shortcutInfo2;
    auto result2 = GetBundleDataMgr()->GetShortcutInfos(
        BUNDLE_NAME_DEMO,  DEFAULT_USERID, shortcutInfo2);
    EXPECT_TRUE(result2);
    CheckShortcutInfoDemo(shortcutInfo2);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetShortcutInfos_0300
 * @tc.name: test can't get the shortcutInfo in app by error app name
 * @tc.desc: 1.have not get shortcutinfo by appName
 */
HWTEST_F(BmsBundleKitServiceTest, GetShortcutInfos_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<ShortcutInfo> shortcutInfos;
    GetBundleDataMgr()->GetShortcutInfos(
        BUNDLE_NAME_DEMO,  DEFAULT_USERID, shortcutInfos);
    EXPECT_TRUE(shortcutInfos.empty());
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetShortcutInfos_0400
 * @tc.name: test can't get the shortcutInfo in app by null app name
 * @tc.desc: 1.have not get shortcutinfo by null app name
 */
HWTEST_F(BmsBundleKitServiceTest, GetShortcutInfos_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<ShortcutInfo> shortcutInfos;
    GetBundleDataMgr()->GetShortcutInfos(
        EMPTY_STRING,  DEFAULT_USERID, shortcutInfos);
    EXPECT_TRUE(shortcutInfos.empty());
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetShortcutInfos_0500
 * @tc.name: test can't get the shortcutInfo have no bundle
 * @tc.desc: 1.have not get shortcutInfo by appName
 *           2.can't get shortcutInfo
 */
HWTEST_F(BmsBundleKitServiceTest, GetShortcutInfos_0500, Function | SmallTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    GetBundleDataMgr()->GetShortcutInfos(
        BUNDLE_NAME_TEST, DEFAULT_USERID, shortcutInfos);
    EXPECT_TRUE(shortcutInfos.empty());
}

/**
 * @tc.number: GetShortcutInfos_0600
 * @tc.name: test can get shortcutInfo by bundleName
 * @tc.desc: 1.can get shortcutInfo
 */
HWTEST_F(BmsBundleKitServiceTest, GetShortcutInfos_0600, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<ShortcutInfo> shortcutInfos;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    bundleMgrProxy->GetShortcutInfos(
        BUNDLE_NAME_TEST, shortcutInfos);
    EXPECT_TRUE(shortcutInfos.empty());
    CheckShortcutInfoTest(shortcutInfos);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetShortcutInfos_0700
 * @tc.name: test can get shortcutInfo by bundleName
 * @tc.desc: 1.can not get shortcutInfo by empty bundle name
 */
HWTEST_F(BmsBundleKitServiceTest, GetShortcutInfos_0700, Function | SmallTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    bundleMgrProxy->GetShortcutInfos(
        "", shortcutInfos);
    EXPECT_TRUE(shortcutInfos.empty());
}

/**
 * @tc.number: GetShortcutInfos_0800
 * @tc.name: test can get shortcutInfo by bundleName
 * @tc.desc: 1.can get shortcutInfo
 */
HWTEST_F(BmsBundleKitServiceTest, GetShortcutInfos_0800, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<ShortcutInfo> shortcutInfos;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    auto result = hostImpl->GetShortcutInfos("", shortcutInfos);
    EXPECT_FALSE(result);
    result = hostImpl->GetShortcutInfos(
        BUNDLE_NAME_TEST,  DEFAULT_USERID, shortcutInfos);
    EXPECT_TRUE(result);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: Ability_0100
 * @tc.name: test can get the compatibleAbilityInfo by one bundle
 * @tc.desc: 1.can get compatibleAbilityInfo
 */
HWTEST_F(BmsBundleKitServiceTest, Ability_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfo(want, 0, 0, abilityInfo);
    EXPECT_TRUE(testRet);
    CompatibleAbilityInfo compatibleAbilityInfo;
    abilityInfo.ConvertToCompatiableAbilityInfo(compatibleAbilityInfo);
    CheckCompatibleAbilityInfo(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, compatibleAbilityInfo);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: Ability_0200
 * @tc.name: test can get the compatibleAbilityInfo by two bundle
 * @tc.desc: 1.can get compatibleAbilityInfo
 */
HWTEST_F(BmsBundleKitServiceTest, Ability_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    Want want1;
    want1.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo1;
    bool testRet1 = GetBundleDataMgr()->QueryAbilityInfo(want1, 0, 0, abilityInfo1);
    EXPECT_TRUE(testRet1);
    CompatibleAbilityInfo compatibleAbilityInfo1;
    abilityInfo1.ConvertToCompatiableAbilityInfo(compatibleAbilityInfo1);
    CheckCompatibleAbilityInfo(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, compatibleAbilityInfo1);
    Want want2;
    want2.SetElementName(BUNDLE_NAME_DEMO, ABILITY_NAME_DEMO);
    AbilityInfo abilityInfo2;
    bool testRet2 = GetBundleDataMgr()->QueryAbilityInfo(want2, 0, 0, abilityInfo2);
    EXPECT_TRUE(testRet2);
    CompatibleAbilityInfo compatibleAbilityInfo2;
    abilityInfo2.ConvertToCompatiableAbilityInfo(compatibleAbilityInfo2);
    CheckCompatibleAbilityInfo(BUNDLE_NAME_DEMO, ABILITY_NAME_DEMO, compatibleAbilityInfo2);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: Application_0100
 * @tc.name: test can get the compatibleApplicationInfo by one bundle
 * @tc.desc: 1.can get compatibleApplicationInfo
 */
HWTEST_F(BmsBundleKitServiceTest, Application_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    ApplicationInfo testResult;
    bool testRet = GetBundleDataMgr()->GetApplicationInfo(
        BUNDLE_NAME_TEST, ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID_TEST, testResult);
    EXPECT_TRUE(testRet);
    CompatibleApplicationInfo appInfo;
    testResult.ConvertToCompatibleApplicationInfo(appInfo);
    CheckCompatibleApplicationInfo(BUNDLE_NAME_TEST, PERMISSION_SIZE_ZERO, appInfo);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: Application_0100
 * @tc.name: test can get the compatibleApplicationInfo by two bundle
 * @tc.desc: 1.can get compatibleApplicationInfo
 */
HWTEST_F(BmsBundleKitServiceTest, Application_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);

    ApplicationInfo testResult1;
    bool testRet1 = GetBundleDataMgr()->GetApplicationInfo(
        BUNDLE_NAME_TEST, ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID_TEST, testResult1);
    EXPECT_TRUE(testRet1);
    CompatibleApplicationInfo appInfo1;
    testResult1.ConvertToCompatibleApplicationInfo(appInfo1);
    CheckCompatibleApplicationInfo(BUNDLE_NAME_TEST, PERMISSION_SIZE_ZERO, appInfo1);

    ApplicationInfo testResult2;
    bool testRet2 = GetBundleDataMgr()->GetApplicationInfo(
        BUNDLE_NAME_DEMO, ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID_TEST, testResult2);
    EXPECT_TRUE(testRet2);
    CompatibleApplicationInfo appInfo2;
    testResult2.ConvertToCompatibleApplicationInfo(appInfo2);
    CheckCompatibleApplicationInfo(BUNDLE_NAME_DEMO, PERMISSION_SIZE_ZERO, appInfo2);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: QueryAllAbilityInfos
 * @tc.name: test can get the All AbilityInfo
 * @tc.desc: 1.can get All AbilityInfo
 */
HWTEST_F(BmsBundleKitServiceTest, AllAbility_001, Function | SmallTest | Level1)
{
    std::vector<AbilityInfo> abilityInfos;
    Want want1;
    want1.SetElementName(BUNDLE_NAME_DEMO, ABILITY_NAME_DEMO);
    bool testRet1 = GetBundleDataMgr()->QueryLauncherAbilityInfos(want1, DEFAULT_USER_ID_TEST, abilityInfos) == ERR_OK;
    EXPECT_FALSE(testRet1);
}

/**
 * @tc.number: GetAllCommonEventInfo_0100
 * @tc.name: test can get CommonEventInfo by event key
 * @tc.desc: 1.can get CommonEventInfo
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllCommonEventInfo_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<CommonEventInfo> commonEventInfos;
    auto result = GetBundleDataMgr()->GetAllCommonEventInfo(COMMON_EVENT_EVENT, commonEventInfos);
    EXPECT_TRUE(result);
    CheckCommonEventInfoTest(commonEventInfos);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAllCommonEventInfo_0200
 * @tc.name: test can't get the commonEventInfo have no bundle
 * @tc.desc: 1.have not get commonEventInfo by event key
 *           2.can't get commonEventInfo
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllCommonEventInfo_0200, Function | SmallTest | Level1)
{
    std::vector<CommonEventInfo> commonEventInfos;
    GetBundleDataMgr()->GetAllCommonEventInfo(COMMON_EVENT_EVENT, commonEventInfos);
    EXPECT_TRUE(commonEventInfos.empty());
}

/**
 * @tc.number: GetAllCommonEventInfo_0300
 * @tc.name: test can't get the commonEventInfo in app by empty event key
 * @tc.desc: 1.have not get commonEventInfo by appName
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllCommonEventInfo_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<CommonEventInfo> commonEventInfos;
    GetBundleDataMgr()->GetAllCommonEventInfo(EMPTY_STRING, commonEventInfos);
    EXPECT_TRUE(commonEventInfos.empty());
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAllCommonEventInfo_0400
 * @tc.name: test can't get the commonEventInfo in app by error event key
 * @tc.desc: 1.have not get commonEventInfo by appName
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllCommonEventInfo_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<CommonEventInfo> commonEventInfos;
    GetBundleDataMgr()->GetAllCommonEventInfo(COMMON_EVENT_EVENT_ERROR_KEY, commonEventInfos);
    EXPECT_TRUE(commonEventInfos.empty());
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAllCommonEventInfo_0500
 * @tc.name: test can't get the commonEventInfo in app by not exists event key
 * @tc.desc: 1.have not get commonEventInfo by appName
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllCommonEventInfo_0500, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<CommonEventInfo> commonEventInfos;
    GetBundleDataMgr()->GetAllCommonEventInfo(COMMON_EVENT_EVENT_NOT_EXISTS_KEY, commonEventInfos);
    EXPECT_TRUE(commonEventInfos.empty());
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAllCommonEventInfo_0600
 * @tc.name: test can get CommonEventInfo by event key
 * @tc.desc: 1.can get CommonEventInfo
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllCommonEventInfo_0600, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<CommonEventInfo> commonEventInfos;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    bundleMgrProxy->GetAllCommonEventInfo(COMMON_EVENT_EVENT_NOT_EXISTS_KEY, commonEventInfos);
    EXPECT_TRUE(commonEventInfos.empty());
    CheckCommonEventInfoTest(commonEventInfos);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAllCommonEventInfo_0700
 * @tc.name: test can get CommonEventInfo by event key
 * @tc.desc: 1.can not get CommonEventInfo by empty key
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllCommonEventInfo_0700, Function | SmallTest | Level1)
{
    std::vector<CommonEventInfo> commonEventInfos;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    bool res = bundleMgrProxy->GetAllCommonEventInfo("", commonEventInfos);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetAllCommonEventInfo_0800
 * @tc.name: test can't get the commonEventInfo have no bundle
 * @tc.desc: 1.have not get commonEventInfo by event key
 *           2.can't get commonEventInfo
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllCommonEventInfo_0800, Function | SmallTest | Level1)
{
    std::vector<CommonEventInfo> commonEventInfos;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    hostImpl->GetAllCommonEventInfo(COMMON_EVENT_EVENT, commonEventInfos);
    EXPECT_TRUE(commonEventInfos.empty());
}

/**
 * @tc.number: skill match rules
 * @tc.name: action match test: want empty; skill empty
 * @tc.desc: expect false
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Action_001, Function | SmallTest | Level1)
{
    struct Skill skill;
    Want want;
    bool ret = skill.Match(want);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: action match test: want not empty; skill empty
 * @tc.desc: expect false
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Action_002, Function | SmallTest | Level1)
{
    struct Skill skill;
    Want want;
    want.SetAction(ACTION_001);
    bool ret = skill.Match(want);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: action match test: want empty; skill not empty
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Action_003, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    Want want;
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: action match test: want not empty; skill not empty; skill contains want
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Action_004, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    Want want;
    want.SetAction(ACTION_001);
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: action match test: want not empty; skill not empty; skill not contains want
 * @tc.desc: expect false
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Action_005, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    Want want;
    want.SetAction(ACTION_002);
    bool ret = skill.Match(want);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: entities match test: want empty; skill empty;
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Entity_001, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    Want want;
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: entities match test: want not empty; skill empty;
 * @tc.desc: expect false
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Entity_002, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    Want want;
    want.AddEntity(ENTITY_001);
    bool ret = skill.Match(want);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: entities match test: want empty; skill not empty;
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Entity_003, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    skill.entities.emplace_back(ENTITY_001);
    Want want;
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: entities match test: want not empty; skill not empty; skill contains want
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Entity_004, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    skill.entities.emplace_back(ENTITY_001);
    Want want;
    want.AddEntity(ENTITY_001);
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: entities match test: want not empty; skill not empty; skill contains want
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Entity_005, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    skill.entities.emplace_back(ENTITY_001);
    skill.entities.emplace_back(ENTITY_002);
    Want want;
    want.AddEntity(ENTITY_001);
    want.AddEntity(ENTITY_002);
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: entities match test: want not empty; skill not empty; skill not contains want
 * @tc.desc: expect false
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Entity_006, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    skill.entities.emplace_back(ENTITY_001);
    Want want;
    want.AddEntity(ENTITY_002);
    bool ret = skill.Match(want);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri and type match test: want empty; skill empty
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UriAndType_001, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    Want want;
    want.SetUri("");
    want.SetType("");
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri and type match test: want uri empty, type not empty; skill uri empty, type not empty
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UriAndType_002, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    SkillUri skillUri;
    skillUri.type = TYPE_001;
    skill.uris.emplace_back(skillUri);
    Want want;
    want.SetType(TYPE_001);
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri and type match test: want uri empty, type not empty; skill uri empty, type not empty; type not equal
 * @tc.desc: expect false
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UriAndType_003, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    SkillUri skillUri;
    skillUri.type = TYPE_001;
    skill.uris.emplace_back(skillUri);
    Want want;
    want.SetType(TYPE_002);
    bool ret = skill.Match(want);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri and type match test: want uri not empty, type empty; skill uri not empty, type empty
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UriAndType_004, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    SkillUri skillUri;
    skillUri.scheme = SCHEME_001;
    skill.uris.emplace_back(skillUri);
    Want want;
    want.SetUri(SCHEME_001 + SCHEME_SEPARATOR);
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri and type match test: want uri not empty, type empty; skill uri not empty, type empty; uri not equal
 * @tc.desc: expect false
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UriAndType_005, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    SkillUri skillUri;
    skillUri.scheme = SCHEME_001;
    skill.uris.emplace_back(skillUri);
    Want want;
    want.SetUri(SCHEME_002 + SCHEME_SEPARATOR);
    bool ret = skill.Match(want);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri and type match test: want uri empty, type not empty; skill uri empty, type not empty; regex
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UriAndType_006, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    SkillUri skillUri;
    skillUri.type = TYPE_IMG_REGEX;
    skill.uris.emplace_back(skillUri);
    Want want;
    want.SetType(TYPE_IMG_JPEG);
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri and type match test: want uri not empty, type empty; skill uri not empty, type empty
 *           uri path match.
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UriAndType_007, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    SkillUri skillUri;
    skillUri.scheme = SCHEME_001;
    skillUri.host = HOST_001;
    skillUri.port = PORT_001;
    skillUri.path = PATH_001;
    skill.uris.emplace_back(skillUri);
    Want want;
    want.SetUri(URI_PATH_001);
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri and type match test: want uri not empty, type empty; skill uri not empty, type empty
 *           uri pathStartWith match.
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UriAndType_008, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    SkillUri skillUri;
    skillUri.scheme = SCHEME_001;
    skillUri.host = HOST_001;
    skillUri.port = PORT_001;
    skillUri.pathStartWith = PATH_001;
    skill.uris.emplace_back(skillUri);
    Want want;
    want.SetUri(URI_PATH_DUPLICATE_001);
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri and type match test: want uri not empty, type empty; skill uri not empty, type empty
 *           uri pathRegex match.
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UriAndType_009, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    SkillUri skillUri;
    skillUri.scheme = SCHEME_001;
    skillUri.host = HOST_001;
    skillUri.port = PORT_001;
    skillUri.pathRegex = PATH_REGEX_001;
    skill.uris.emplace_back(skillUri);
    Want want;
    want.SetUri(URI_PATH_001);
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri's scheme prefix match test
 * @tc.desc: config only has scheme, param has "scheme://" prefix then match, otherwise not match.
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UriPrefix_001, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    SkillUri skillUri;
    skillUri.scheme = SCHEME_001;
    skill.uris.emplace_back(skillUri);
    // success testCase
    std::string uri = SCHEME_001 + SCHEME_SEPARATOR;
    Want want;
    want.SetUri(uri);
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);

    uri.append(HOST_001);
    want.SetUri(uri);
    ret = skill.Match(want);
    EXPECT_EQ(true, ret);

    uri.append(PORT_SEPARATOR).append(PORT_001);
    want.SetUri(uri);
    ret = skill.Match(want);
    EXPECT_EQ(true, ret);

    uri.append(PATH_SEPARATOR).append(PATH_001);
    want.SetUri(uri);
    ret = skill.Match(want);
    EXPECT_EQ(true, ret);
    // fail testCase
    uri = SCHEME_002 + SCHEME_SEPARATOR;
    want.SetUri(uri);
    ret = skill.Match(want);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri's scheme prefix match test
 * @tc.desc: config only has scheme and host, param has "scheme://host" prefix then match, otherwise not match.
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UriPrefix_002, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    SkillUri skillUri;
    skillUri.scheme = SCHEME_001;
    skillUri.host = HOST_001;
    skill.uris.emplace_back(skillUri);
    // success testCase
    std::string uri = SCHEME_001 + SCHEME_SEPARATOR + HOST_001;
    Want want;
    want.SetUri(uri);
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);

    uri.append(PORT_SEPARATOR).append(PORT_001);
    want.SetUri(uri);
    ret = skill.Match(want);
    EXPECT_EQ(true, ret);

    uri.append(PATH_SEPARATOR).append(PATH_001);
    want.SetUri(uri);
    ret = skill.Match(want);
    EXPECT_EQ(true, ret);

    uri = SCHEME_001 + SCHEME_SEPARATOR + HOST_001 + PATH_SEPARATOR + PATH_001;
    want.SetUri(uri);
    ret = skill.Match(want);
    EXPECT_EQ(true, ret);
    // fail testCase
    uri = SCHEME_001 + SCHEME_SEPARATOR + HOST_002;
    want.SetUri(uri);
    ret = skill.Match(want);
    EXPECT_EQ(false, ret);

    uri = SCHEME_002 + SCHEME_SEPARATOR + HOST_001;
    want.SetUri(uri);
    ret = skill.Match(want);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri's scheme prefix match test
 * @tc.desc: config only has scheme and host and port,
 * param has "scheme://host:port" prefix then match, otherwise not match.
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UriPrefix_003, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    SkillUri skillUri;
    skillUri.scheme = SCHEME_001;
    skillUri.host = HOST_001;
    skillUri.port = PORT_001;
    skill.uris.emplace_back(skillUri);
    // success testCase
    std::string uri = SCHEME_001 + SCHEME_SEPARATOR + HOST_001 + PORT_SEPARATOR + PORT_001;
    Want want;
    want.SetUri(uri);
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);

    uri.append(PATH_SEPARATOR).append(PATH_001);
    want.SetUri(uri);
    ret = skill.Match(want);
    EXPECT_EQ(true, ret);
    // fail testCase
    uri = SCHEME_001 + SCHEME_SEPARATOR + HOST_001 + PORT_SEPARATOR + PORT_002;
    want.SetUri(uri);
    ret = skill.Match(want);
    EXPECT_EQ(false, ret);

    uri = SCHEME_001 + SCHEME_SEPARATOR + HOST_002 + PORT_SEPARATOR + PORT_001;
    want.SetUri(uri);
    ret = skill.Match(want);
    EXPECT_EQ(false, ret);

    uri = SCHEME_002 + SCHEME_SEPARATOR + HOST_001 + PORT_SEPARATOR + PORT_001;
    want.SetUri(uri);
    ret = skill.Match(want);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri's scheme prefix match test with linkFeature
 * @tc.desc: config only has scheme and host and port,
 *           param has "scheme://host:port" prefix then match, otherwise not match.
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UriPrefix_004, Function | SmallTest | Level1)
{
    struct Skill skill;
    size_t uriIndex = 0;
    SkillUri skillUri;
    skillUri.scheme = SCHEME_001;
    skillUri.linkFeature = URI_LINK_FEATURE;
    skill.uris.emplace_back(skillUri);
    std::string uri = SCHEME_001 + SCHEME_SEPARATOR;
    Want want;
    want.SetUri(uri);
    want.SetParam("linkFeature", URI_LINK_FEATURE);
    bool ret = skill.Match(want, uriIndex);
    EXPECT_EQ(true, ret);

    uri.append(HOST_001);
    want.SetUri(uri);
    ret = skill.Match(want, uriIndex);
    EXPECT_EQ(true, ret);

    uri.append(PORT_SEPARATOR).append(PORT_001);
    want.SetUri(uri);
    ret = skill.Match(want, uriIndex);
    EXPECT_EQ(true, ret);

    uri.append(PATH_SEPARATOR).append(PATH_001);
    want.SetUri(uri);
    ret = skill.Match(want, uriIndex);
    EXPECT_EQ(true, ret);
    // fail testCase
    uri = SCHEME_002 + SCHEME_SEPARATOR;
    want.SetUri(uri);
    ret = skill.Match(want, uriIndex);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri with param match test
 * @tc.desc: want's uri has param, ignore param then match.
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UriWithParam_001, Function | SmallTest | Level1)
{
    // param uri:  scheme001://host001?param=value
    // config uri: scheme001://host001
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    SkillUri skillUri;
    skillUri.scheme = SCHEME_001;
    skillUri.host = HOST_001;
    skill.uris.emplace_back(skillUri);
    std::string uri = SCHEME_001 + SCHEME_SEPARATOR + HOST_001 + PARAM_AND_VALUE;
    Want want;
    want.SetUri(uri);
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);
    // param uri:  scheme001://host001:port001?param=value
    // config uri: scheme001://host001:port001
    skill.uris[0].port = PORT_001;
    uri = SCHEME_001 + SCHEME_SEPARATOR + HOST_001 + PORT_SEPARATOR + PORT_001 + PARAM_AND_VALUE;
    want.SetUri(uri);
    ret = skill.Match(want);
    EXPECT_EQ(true, ret);
    // param uri:  scheme001://host001:port001/path001?param=value
    // config uri: scheme001://host001:port001/path001
    skill.uris[0].path = PATH_001;
    uri = SCHEME_001 + SCHEME_SEPARATOR + HOST_001 + PORT_SEPARATOR + PORT_001 +
        PATH_SEPARATOR + PATH_001 + PARAM_AND_VALUE;
    want.SetUri(uri);
    ret = skill.Match(want);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: special type test.
 * @tc.desc: when want set type = TYPE_ONLY_MATCH_WILDCARD, only match wildcard.
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_TYPE_WILDCARD_001, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(ACTION_001);
    SkillUri skillUri;
    skillUri.type = TYPE_WILDCARD;
    skill.uris.emplace_back(skillUri);
    // success testCase
    Want want;
    want.SetType(TYPE_ONLY_MATCH_WILDCARD);
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);
    // failed testCase
    skill.uris[0].type = TYPE_IMG_REGEX;
    ret = skill.Match(want);
    EXPECT_EQ(false, ret);

    skill.uris[0].type = TYPE_IMG_JPEG;
    ret = skill.Match(want);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: action match test
 * @tc.desc: "action.system.home" is equal to "ohos.want.action.home"
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_HOME_ACTION_001, Function | SmallTest | Level1)
{
    struct Skill skill;
    skill.actions.emplace_back(Constants::ACTION_HOME);
    Want want;
    want.SetAction(Constants::WANT_ACTION_HOME);
    bool ret = skill.Match(want);
    EXPECT_EQ(true, ret);

    skill.actions.clear();
    skill.actions.emplace_back(Constants::WANT_ACTION_HOME);
    want.SetAction(Constants::ACTION_HOME);
    ret = skill.Match(want);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: utd match test
 * @tc.desc: param : utd, skill : utd
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UTD_001, Function | SmallTest | Level1)
{
    struct Skill skill;
    // success testCase
    bool ret = skill.MatchType(UTD_GENERAL_AVI, UTD_GENERAL_AVI);
    EXPECT_TRUE(ret);
    ret = skill.MatchType(UTD_GENERAL_AVI, UTD_GENERAL_VIDEO);
    EXPECT_TRUE(ret);
    // failed testCase
    ret = skill.MatchType(UTD_GENERAL_VIDEO, UTD_GENERAL_AVI);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: utd match test
 * @tc.desc: param : mimeType, skill : utd
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UTD_002, Function | SmallTest | Level1)
{
    struct Skill skill;
    // success testCase
    bool ret = skill.MatchType(TYPE_VIDEO_AVI, UTD_GENERAL_AVI);
    EXPECT_TRUE(ret);
    ret = skill.MatchType(TYPE_VIDEO_MS_VIDEO, UTD_GENERAL_AVI);
    EXPECT_TRUE(ret);
    ret = skill.MatchType(TYPE_VIDEO_AVI, UTD_GENERAL_VIDEO);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: utd match test
 * @tc.desc: param : utd, skill : mimeType
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_UTD_003, Function | SmallTest | Level1)
{
    struct Skill skill;
    // success testCase
    bool ret = skill.MatchType(UTD_GENERAL_AVI, TYPE_VIDEO_AVI);
    EXPECT_TRUE(ret);
    ret = skill.MatchType(UTD_GENERAL_AVI, TYPE_VIDEO_MS_VIDEO);
    EXPECT_TRUE(ret);
    // failed testCase
    ret = skill.MatchType(UTD_GENERAL_VIDEO, TYPE_VIDEO_AVI);
    EXPECT_FALSE(ret);
    ret = skill.MatchType(UTD_GENERAL_VIDEO, TYPE_VIDEO_MS_VIDEO);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri and type match test: want uri empty, type not empty, linkFeature not empty; skill uri empty,
 *           type not empty, linkFeature not empty.
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Link_Feature_001, Function | SmallTest | Level1)
{
    struct Skill skill;
    size_t uriIndex = 0;
    SkillUri skillUri;
    skillUri.type = TYPE_001;
    skillUri.linkFeature = URI_LINK_FEATURE;
    skill.uris.emplace_back(skillUri);
    Want want;
    want.SetType(TYPE_001);
    want.SetParam("linkFeature", ERROR_LINK_FEATURE);
    bool ret = skill.Match(want, uriIndex);
    EXPECT_EQ(false, ret);
    want.SetParam("linkFeature", URI_LINK_FEATURE);
    ret = skill.Match(want, uriIndex);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri and type match test: want uri empty, type empty, linkFeature not empty;
 *           skill uri empty, type empty, linkFeature not empty.
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Link_Feature_002, Function | SmallTest | Level1)
{
    struct Skill skill;
    size_t uriIndex = 0;
    SkillUri skillUri;
    skillUri.linkFeature = URI_LINK_FEATURE;
    skill.uris.emplace_back(skillUri);
    Want want;
    want.SetParam("linkFeature", URI_LINK_FEATURE);
    bool ret = skill.Match(want, uriIndex);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri and type match test: want uri not empty, type empty, linkFeature not empty; skill uri not empty,
 *           type empty, linkFeature not empty, uri path match.
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Link_Feature_003, Function | SmallTest | Level1)
{
    struct Skill skill;
    size_t uriIndex = 0;
    SkillUri skillUri;
    skillUri.scheme = SCHEME_001;
    skillUri.host = HOST_001;
    skillUri.port = PORT_001;
    skillUri.path = PATH_001;
    skillUri.linkFeature = URI_LINK_FEATURE;
    skill.uris.emplace_back(skillUri);
    Want want;
    want.SetUri(URI_PATH_001);
    want.SetParam("linkFeature", ERROR_LINK_FEATURE);
    bool ret = skill.Match(want, uriIndex);
    EXPECT_EQ(false, ret);
    want.SetParam("linkFeature", URI_LINK_FEATURE);
    ret = skill.Match(want, uriIndex);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri and type match test: want uri not empty, type empty, linkFeature not empty; skill uri empty,
 *           type not empty, linkFeature not empty, file type match.
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Link_Feature_004, Function | SmallTest | Level1)
{
    struct Skill skill;
    size_t uriIndex = 0;
    SkillUri skillUri;
    skillUri.type = URI_MIME_IMAGE;
    skillUri.linkFeature = URI_LINK_FEATURE;
    skill.uris.emplace_back(skillUri);
    Want want;
    want.SetUri(FILE_URI);
    want.SetParam("linkFeature", URI_LINK_FEATURE);
    bool ret = skill.Match(want, uriIndex);
    ret = skill.Match(want, uriIndex);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri and type match test: want uri not empty, type empty, linkFeature not empty; skill uri not empty,
 *           type empty, linkFeature not empty, uri pathRegex match.
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Link_Feature_005, Function | SmallTest | Level1)
{
    struct Skill skill;
    SkillUri skillUri;
    size_t uriIndex = 0;
    skillUri.scheme = SCHEME_001;
    skillUri.host = HOST_001;
    skillUri.port = PORT_001;
    skillUri.pathRegex = PATH_REGEX_001;
    skillUri.linkFeature = URI_LINK_FEATURE;
    skill.uris.emplace_back(skillUri);
    Want want;
    want.SetUri(URI_PATH_001);
    want.SetParam("linkFeature", ERROR_LINK_FEATURE);
    bool ret = skill.Match(want, uriIndex);
    EXPECT_EQ(false, ret);
    want.SetParam("linkFeature", URI_LINK_FEATURE);
    ret = skill.Match(want, uriIndex);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: skill match rules
 * @tc.name: uri and type match test: want uri not empty, type not empty, linkFeature not empty; skill uri not empty,
 *           type not empty, linkFeature not empty, uri and type match.
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, SkillMatch_Link_Feature_006, Function | SmallTest | Level1)
{
    struct Skill skill;
    SkillUri skillUri;
    size_t uriIndex = 0;
    skillUri.scheme = SCHEME_001;
    skillUri.host = HOST_001;
    skillUri.port = PORT_001;
    skillUri.pathRegex = PATH_REGEX_001;
    skillUri.linkFeature = URI_LINK_FEATURE;
    skillUri.type = TYPE_001;
    skill.uris.emplace_back(skillUri);
    Want want;
    want.SetUri(URI_PATH_001);
    want.SetType(TYPE_001);
    want.SetParam("linkFeature", URI_LINK_FEATURE);
    bool ret = skill.Match(want, uriIndex);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: GetAlldependentModuleNames
 * @tc.name: no dependencies
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, GetAlldependentModuleNames_001, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    std::vector<Dependency> dependencies;
    MockInnerBundleInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, dependencies, innerBundleInfo);
    std::vector<std::string> dependentModuleName;
    auto res = innerBundleInfo.GetAllDependentModuleNames(MODULE_NAME_TEST, dependentModuleName);
    EXPECT_TRUE(res);
    EXPECT_TRUE(dependentModuleName.empty());
}

/**
 * @tc.number: GetAlldependentModuleNames
 * @tc.name: one dependent module
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, GetAlldependentModuleNames_002, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    std::vector<Dependency> dependencies;
    Dependency dependency;
    dependency.moduleName = MODULE_NAME_TEST_1;
    dependencies.push_back(dependency);
    MockInnerBundleInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, dependencies, innerBundleInfo);
    dependencies.clear();
    MockInnerBundleInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST_1, ABILITY_NAME_TEST, dependencies, innerBundleInfo);

    std::vector<std::string> dependentModuleName;
    auto res = innerBundleInfo.GetAllDependentModuleNames(MODULE_NAME_TEST, dependentModuleName);
    EXPECT_TRUE(res);
    EXPECT_EQ(dependentModuleName.size(), MODULE_NAMES_SIZE_ONE);
    if (!dependentModuleName.empty()) {
        EXPECT_EQ(dependentModuleName[0], MODULE_NAME_TEST_1);
    }
}

/**
 * @tc.number: GetAlldependentModuleNames
 * @tc.name: more than one dependent module
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, GetAlldependentModuleNames_003, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    std::vector<Dependency> dependencies;
    Dependency dependency_1;
    dependency_1.moduleName = MODULE_NAME_TEST_1;
    Dependency dependency_2;
    dependency_2.moduleName = MODULE_NAME_TEST_2;
    dependencies.push_back(dependency_1);
    dependencies.push_back(dependency_2);
    MockInnerBundleInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, dependencies, innerBundleInfo);
    dependencies.clear();
    MockInnerBundleInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST_1, ABILITY_NAME_TEST, dependencies, innerBundleInfo);
    MockInnerBundleInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST_2, ABILITY_NAME_TEST, dependencies, innerBundleInfo);

    std::vector<std::string> dependentModuleName;
    auto res = innerBundleInfo.GetAllDependentModuleNames(MODULE_NAME_TEST, dependentModuleName);
    EXPECT_TRUE(res);
    EXPECT_EQ(dependentModuleName.size(), MODULE_NAMES_SIZE_TWO);
    if (dependentModuleName.size() == MODULE_NAMES_SIZE_TWO) {
        EXPECT_EQ(dependentModuleName[0], MODULE_NAME_TEST_1);
        EXPECT_EQ(dependentModuleName[MODULE_NAMES_SIZE_ONE], MODULE_NAME_TEST_2);
    }
}

/**
 * @tc.number: GetAlldependentModuleNames
 * @tc.name: Multiple dependent modules
 * @tc.desc: expect true
 */
HWTEST_F(BmsBundleKitServiceTest, GetAlldependentModuleNames_004, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    std::vector<Dependency> dependencies;
    Dependency dependency_1;
    dependency_1.moduleName = MODULE_NAME_TEST_1;
    Dependency dependency_2;
    dependency_2.moduleName = MODULE_NAME_TEST_2;
    dependencies.push_back(dependency_1);
    dependencies.push_back(dependency_2);
    MockInnerBundleInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, dependencies, innerBundleInfo);
    dependencies.clear();
    MockInnerBundleInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST_1, ABILITY_NAME_TEST, dependencies, innerBundleInfo);
    dependencies.clear();
    Dependency dependency_3;
    dependency_3.moduleName = MODULE_NAME_TEST_3;
    dependencies.push_back(dependency_3);
    MockInnerBundleInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST_2, ABILITY_NAME_TEST, dependencies, innerBundleInfo);
    dependencies.clear();
    MockInnerBundleInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST_3, ABILITY_NAME_TEST, dependencies, innerBundleInfo);

    std::vector<std::string> dependentModuleName;
    auto res = innerBundleInfo.GetAllDependentModuleNames(MODULE_NAME_TEST, dependentModuleName);
    EXPECT_TRUE(res);
    EXPECT_EQ(dependentModuleName.size(), MODULE_NAMES_SIZE_THREE);
    if (dependentModuleName.size() == MODULE_NAMES_SIZE_THREE) {
        EXPECT_EQ(dependentModuleName[0], MODULE_NAME_TEST_1);
        EXPECT_EQ(dependentModuleName[MODULE_NAMES_SIZE_ONE], MODULE_NAME_TEST_2);
        EXPECT_EQ(dependentModuleName[MODULE_NAMES_SIZE_TWO], MODULE_NAME_TEST_3);
    }
}

/**
 * @tc.number: Marshalling_001
 * @tc.name: BundleInfo Marshalling
 * @tc.desc: 1.Test the marshalling of BundleInfo
 */
HWTEST_F(BmsBundleKitServiceTest, Marshalling_001, Function | SmallTest | Level1)
{
    BundleInfo info;
    info.name = "com.ohos.contactsdataability";
    info.versionName = "1.0";
    info.vendor = "ohos";
    info.releaseType = "Release";
    info.mainEntry = "com.ohos.contactsdataability";
    info.entryModuleName = "entry";
    info.appId = "com.ohos.contactsdataability_BNtg4JBClbl92Rgc3jm"\
        "/RfcAdrHXaM8F0QOiwVEhnV5ebE5jNIYnAx+weFRT3QTyUjRNdhmc2aAzWyi+5t5CoBM=";
    info.cpuAbi = "armeabi";
    info.description = "dataability_description";
    info.applicationInfo.name = "com.ohos.contactsdataability";
    info.applicationInfo.bundleName = "com.ohos.contactsdataability";
    info.applicationInfo.versionName = "1.0";
    info.applicationInfo.iconPath = "$media:icon";
    info.applicationInfo.description = "dataability_description";
    info.applicationInfo.codePath = "/data/app/el1/budle/public/com.ohos.contactsdataability";
    info.applicationInfo.dataBaseDir = "/data/app/el2/database/com.ohos.contactsdataability";
    info.applicationInfo.apiReleaseType = "Release";
    info.applicationInfo.deviceId = "Id001";
    info.applicationInfo.entityType = "unsppecified";
    info.applicationInfo.vendor = "ohos";
    info.applicationInfo.nativeLibraryPath = "libs/arm";
    Parcel parcel;
    bool ret = info.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: Marshalling_002
 * @tc.name: RequestPermission Marshalling
 * @tc.desc: 1.Test the marshalling of RequestPermission
 */
HWTEST_F(BmsBundleKitServiceTest, Marshalling_002, Function | SmallTest | Level1)
{
    RequestPermission requestPermission;
    requestPermission.name = "ohos.global.systemres";
    requestPermission.reason = "1";
    Parcel parcel;
    bool ret = requestPermission.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: Marshalling_003
 * @tc.name: RequestPermissionUsedScene Marshalling
 * @tc.desc: 1.Test the marshalling of RequestPermissionUsedScene
 */
HWTEST_F(BmsBundleKitServiceTest, Marshalling_003, Function | SmallTest | Level1)
{
    RequestPermissionUsedScene usedScene;
    usedScene.abilities = {"ohos.global.systemres.MainAbility"};
    usedScene.when = "1";
    Parcel parcel;
    bool ret = usedScene.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: Marshalling_004
 * @tc.name: Metadata Marshalling
 * @tc.desc: 1.Test the marshalling of Metadata
 */
HWTEST_F(BmsBundleKitServiceTest, Marshalling_004, Function | SmallTest | Level1)
{
    Metadata metadata;
    metadata.valueId = 0;
    metadata.name = "ohos.global.systemres";
    metadata.value = "1";
    metadata.resource = "/data/accounts/account_0/applications/ohos.global.systemres";
    Parcel parcel;
    bool ret = metadata.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: Marshalling_005
 * @tc.name: RequestPermissionUsedScene Marshalling
 * @tc.desc: 1.Test the marshalling of RequestPermissionUsedScene
 */
HWTEST_F(BmsBundleKitServiceTest, Marshalling_005, Function | SmallTest | Level1)
{
    CustomizeData customizeData;
    customizeData.name = "ohos.global.systemres";
    customizeData.value = "1";
    customizeData.extra = "/data/accounts/account_0/applications/ohos.global.systemres";
    Parcel parcel;
    bool ret = customizeData.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: Marshalling_006
 * @tc.name: AppRunningControlRule Marshalling
 * @tc.desc: 1.Test the marshalling of AppRunningControlRule
 */
HWTEST_F(BmsBundleKitServiceTest, Marshalling_006, Function | SmallTest | Level1)
{
    AppRunningControlRule param;
    param.appId = "appId";
    param.controlMessage = "Success";
    Parcel parcel;
    bool ret = param.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: Marshalling_007
 * @tc.name: HapModuleInfo Marshalling
 * @tc.desc: 1.Test the marshalling of HapModuleInfo
 */
HWTEST_F(BmsBundleKitServiceTest, Marshalling_007, Function | SmallTest | Level1)
{
    HapModuleInfo info;
    std::vector<std::string> reqCapabilities;
    std::vector<std::string> deviceTypes;
    std::vector<Dependency> dependencies;
    std::vector<AbilityInfo> abilityInfos;
    AbilityInfo abilityInfo;
    std::map<std::string, bool> isRemovable;
    isRemovable["hap1"] = true;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    ExtensionAbilityInfo extensionAbilityInfo;
    std::vector<Metadata> metadata;
    Metadata data;
    reqCapabilities.emplace_back("video_support");
    deviceTypes.emplace_back("default");
    Dependency dependency;
    dependency.moduleName = MODULE_NAME_TEST_1;
    dependencies.emplace_back(dependency);
    abilityInfos.emplace_back(abilityInfo);
    extensionInfos.emplace_back(extensionAbilityInfo);
    metadata.emplace_back(data);
    info.reqCapabilities = reqCapabilities;
    info.deviceTypes = reqCapabilities;
    info.abilityInfos = abilityInfos;
    info.isRemovable = isRemovable;
    info.extensionInfos = extensionInfos;
    info.metadata = metadata;
    Parcel parcel;
    bool ret = info.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: Marshalling_008
 * @tc.name: ApplicationInfo Marshalling
 * @tc.desc: 1.Test the marshalling of ApplicationInfo
 */
HWTEST_F(BmsBundleKitServiceTest, Marshalling_008, Function | SmallTest | Level1)
{
    ApplicationInfo info;
    std::vector<std::string> allowCommonEvent;
    std::vector<std::string> permissions;
    std::vector<std::string> moduleSourceDirs;
    std::vector<std::string> targetBundleList;
    std::vector<std::string> assetAccessGroups;
    std::vector<ModuleInfo> moduleInfos;
    ModuleInfo moduleInfo;
    Metadata data1("paramName", "paramValue", "paramResource");
    std::map<std::string, std::vector<Metadata>> metadata;
    std::vector<Metadata> vecMetaData;
    vecMetaData.emplace_back(data1);
    metadata["name"] = vecMetaData;
    std::map<std::string, std::vector<CustomizeData>> metaData;
    std::vector<CustomizeData> vecCustomizeData;
    CustomizeData customizeData;
    vecCustomizeData.emplace_back(customizeData);
    metaData["moduleName"] = vecCustomizeData;
    allowCommonEvent.emplace_back("allow1");
    permissions.emplace_back("permission1");
    moduleSourceDirs.emplace_back("dir1");
    targetBundleList.emplace_back("target");
    assetAccessGroups.emplace_back("group1");
    moduleInfos.emplace_back(moduleInfo);
    info.allowCommonEvent = allowCommonEvent;
    info.permissions = permissions;
    info.targetBundleList = targetBundleList;
    info.moduleSourceDirs = moduleSourceDirs;
    info.assetAccessGroups = assetAccessGroups;
    info.moduleInfos = moduleInfos;
    info.metadata = metadata;
    info.metaData = metaData;

    Parcel parcel;
    bool ret = info.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: Marshalling_009
 * @tc.name: HqfInfo Marshalling
 * @tc.desc: 1.Test the marshalling of HqfInfo
 */
HWTEST_F(BmsBundleKitServiceTest, Marshalling_009, Function | SmallTest | Level1)
{
    HqfInfo info;
    info.moduleName = "module";
    info.hapSha256 = "sha256";
    info.cpuAbi = "apu";
    info.nativeLibraryPath = "/data";

    Parcel parcel;
    bool ret = info.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: Marshalling_010
 * @tc.name: AppqfInfo Marshalling
 * @tc.desc: 1.Test the marshalling of AppqfInfo
 */
HWTEST_F(BmsBundleKitServiceTest, Marshalling_010, Function | SmallTest | Level1)
{
    AppqfInfo info;
    info.versionName = "1.0";
    info.cpuAbi = "apu";
    info.nativeLibraryPath = "/data";
    std::vector<HqfInfo> hqfInfos;
    HqfInfo hqfInfo;
    hqfInfos.emplace_back(hqfInfo);
    info.hqfInfos = hqfInfos;

    Parcel parcel;
    bool ret = info.Marshalling(parcel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: Unmarshalling_001
 * @tc.name: RequestPermissionUsedScene Unmarshalling
 * @tc.desc: 1.Test the marshalling of RequestPermissionUsedScene
 */
HWTEST_F(BmsBundleKitServiceTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    CompatibleAbilityInfo compatibleAbilityInfo;
    compatibleAbilityInfo.name = "com.ohos.contactsdataability.ability";;
    compatibleAbilityInfo.moduleName = "entry";
    compatibleAbilityInfo.bundleName = "com.ohos.contactsdataability";
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    AbilityInfo abilityInfo;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfo(want, 0, 0, abilityInfo);
    EXPECT_TRUE(testRet);
    abilityInfo.ConvertToCompatiableAbilityInfo(compatibleAbilityInfo);
    CheckCompatibleAbilityInfo(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, compatibleAbilityInfo);
    Parcel parcel;
    bool ret = compatibleAbilityInfo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: Unmarshalling_002
 * @tc.name: RequestPermissionUsedScene Unmarshalling
 * @tc.desc: 1.Test the marshalling of RequestPermissionUsedScene
 */
HWTEST_F(BmsBundleKitServiceTest, Unmarshalling_002, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    ApplicationInfo testResult;
    bool testRet = GetBundleDataMgr()->GetApplicationInfo(
        BUNDLE_NAME_TEST, ApplicationFlag::GET_BASIC_APPLICATION_INFO, DEFAULT_USER_ID_TEST, testResult);
    EXPECT_TRUE(testRet);
    CompatibleApplicationInfo appInfo;
    testResult.ConvertToCompatibleApplicationInfo(appInfo);
    Parcel parcel;
    bool ret = appInfo.Unmarshalling(parcel);
    EXPECT_FALSE(ret);
    CheckCompatibleApplicationInfo(BUNDLE_NAME_TEST, PERMISSION_SIZE_ZERO, appInfo);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: Unmarshalling_003
 * @tc.name: AppRunningControlRule Unmarshalling
 * @tc.desc: 1.Test the Unmarshalling of AppRunningControlRule
 */
HWTEST_F(BmsBundleKitServiceTest, Unmarshalling_003, Function | SmallTest | Level1)
{
    AppRunningControlRule param1;
    param1.appId = "appId";
    param1.controlMessage = "Success";
    Parcel parcel;
    AppRunningControlRule param2;
    auto ret1 = param1.Marshalling(parcel);
    EXPECT_EQ(ret1, true);
    auto ret2 = param2.Unmarshalling(parcel);
    EXPECT_NE(ret2, nullptr);
    EXPECT_EQ(param1.appId, ret2->appId);
    EXPECT_EQ(param1.controlMessage, ret2->controlMessage);
}

/**
 * @tc.number: Unmarshalling_004
 * @tc.name: Unmarshalling
 * @tc.desc: 1.Test the Unmarshalling of HnpPackage
 */
HWTEST_F(BmsBundleKitServiceTest, Unmarshalling_004, Function | SmallTest | Level1)
{
    HnpPackage param1;
    param1.package = "package";
    param1.type = "type";
    Parcel parcel;
    HnpPackage param2;
    auto ret1 = param1.Marshalling(parcel);
    EXPECT_EQ(ret1, true);
    auto ret2 = param2.Unmarshalling(parcel);
    EXPECT_NE(ret2, nullptr);
    EXPECT_EQ(param1.type, ret2->type);
    EXPECT_EQ(param1.package, ret2->package);
}

/**
 * @tc.number: ReadFromParcelOfAppqfInfo_001
 * @tc.name: ReadFromParcel
 * @tc.desc: 1.Test ReadFromParcel of AppqfInfo
 */
HWTEST_F(BmsBundleKitServiceTest, ReadFromParcelOfAppqfInfo_001, Function | SmallTest | Level1)
{
    AppqfInfo param1;
    AppqfInfo param2;
    param1.versionName = "1.0";
    param1.cpuAbi = "apu";
    param1.nativeLibraryPath = "/data";
    std::vector<HqfInfo> hqfInfos;
    HqfInfo info;
    hqfInfos.emplace_back(info);
    param1.hqfInfos = hqfInfos;
    Parcel parcel;
    auto ret1 = param1.Marshalling(parcel);
    EXPECT_TRUE(ret1);
    auto ret2 = param2.ReadFromParcel(parcel);
    EXPECT_TRUE(ret2);
}

/**
 * @tc.number: ReadFromParcelOfHapModuleInfo_001
 * @tc.name: ReadFromParcel
 * @tc.desc: 1.Test ReadFromParcel of HapModuleInfo
 */
HWTEST_F(BmsBundleKitServiceTest, ReadFromParcelOfHapModuleInfo_001, Function | SmallTest | Level1)
{
    HapModuleInfo info;
    std::vector<std::string> reqCapabilities;
    std::vector<Dependency> dependencies;
    std::map<std::string, bool> isRemovable;
    isRemovable["hap1"] = true;
    reqCapabilities.emplace_back("video_support");
    Dependency dependency;
    dependency.moduleName = MODULE_NAME_TEST_1;
    dependencies.emplace_back(dependency);
    info.reqCapabilities = reqCapabilities;
    info.dependencies = dependencies;
    info.isRemovable = isRemovable;

    Parcel parcel;
    auto ret1 = info.Marshalling(parcel);
    EXPECT_EQ(ret1, true);
    auto ret2 = info.ReadFromParcel(parcel);
    EXPECT_TRUE(ret2);
}

/**
 * @tc.number: ReadFromParcelOfApplicationInfo_001
 * @tc.name: ReadFromParcel
 * @tc.desc: 1.Test ReadFromParcel of ApplicationInfo
 */
HWTEST_F(BmsBundleKitServiceTest, ReadFromParcelOfApplicationInfo_001, Function | SmallTest | Level1)
{
    ApplicationInfo info;
    Metadata data1("paramName", "paramValue", "paramResource");
    std::map<std::string, std::vector<Metadata>> metadata;
    std::vector<Metadata> vecMetaData;
    vecMetaData.emplace_back(data1);
    metadata["name"] = vecMetaData;
    std::map<std::string, std::vector<CustomizeData>> metaData;
    std::vector<CustomizeData> vecCustomizeData;
    CustomizeData customizeData;
    vecCustomizeData.emplace_back(customizeData);
    metaData["moduleName"] = vecCustomizeData;
    std::vector<std::string> targetBundleList;
    targetBundleList.emplace_back("target");
    info.metadata = metadata;
    info.metaData = metaData;
    info.targetBundleList = targetBundleList;
    Parcel parcel;
    auto ret1 = info.Marshalling(parcel);
    EXPECT_EQ(ret1, true);
    auto ret2 = info.ReadFromParcel(parcel);
    EXPECT_TRUE(ret2);
}

/**
 * @tc.number: ReadMetaDataFromParcel_001
 * @tc.name: ReadMetaDataFromParcel
 * @tc.desc: 1.Test ReadFromParcel of ApplicationInfo
 */
HWTEST_F(BmsBundleKitServiceTest, ReadMetaDataFromParcel_001, Function | SmallTest | Level1)
{
    ApplicationInfo info;
    std::map<std::string, std::vector<CustomizeData>> metaData;
    std::vector<CustomizeData> vecCustomizeData;
    CustomizeData customizeData;
    vecCustomizeData.emplace_back(customizeData);
    metaData["moduleName"] = vecCustomizeData;
    info.metaData = metaData;
    Parcel parcel;
    auto ret1 = info.Marshalling(parcel);
    EXPECT_EQ(ret1, true);
    auto ret2 = info.ReadMetaDataFromParcel(parcel);
    EXPECT_TRUE(ret2);
}

/**
 * @tc.number: CompatibleAbilityInfo_001
 * @tc.name: ReadFromParcel
 * @tc.desc: 1.Test ReadFromParcel of compatibleAbilityInfo success
 */
HWTEST_F(BmsBundleKitServiceTest, CompatibleAbilityInfo_001, Function | SmallTest | Level1)
{
    CompatibleAbilityInfo compatibleAbilityInfo;
    compatibleAbilityInfo.name = "com.ohos.contactsdata.ability";;
    compatibleAbilityInfo.moduleName = "entry";
    compatibleAbilityInfo.bundleName = "com.ohos.contactsdataability";
    Parcel parcel;
    auto ret = compatibleAbilityInfo.ReadFromParcel(parcel);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CompatibleAbilityInfo_002
 * @tc.name: ConvertToAbilityInfo
 * @tc.desc: 1.Test ConvertToAbilityInfo of compatibleAbilityInfo success
 */
HWTEST_F(BmsBundleKitServiceTest, CompatibleAbilityInfo_002, Function | SmallTest | Level1)
{
    CompatibleAbilityInfo compatibleAbilityInfo;
    compatibleAbilityInfo.name = "com.ohos.contactsdata.ability";
    AbilityInfo info;
    compatibleAbilityInfo.ConvertToAbilityInfo(info);
    EXPECT_EQ(compatibleAbilityInfo.name, info.name);
}

/**
 * @tc.number: CompatibleApplicationInfo_001
 * @tc.name: ReadFromParcel
 * @tc.desc: 1.Test ReadFromParcel of CompatibleApplicationInfo success
 */
HWTEST_F(BmsBundleKitServiceTest, CompatibleApplicationInfo_001, Function | SmallTest | Level1)
{
    CompatibleApplicationInfo appInfo;
    appInfo.name = "com.ohos.contactsdata.ability";
    Parcel parcel;
    auto ret = appInfo.ReadFromParcel(parcel);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CompatibleApplicationInfo_002
 * @tc.name: ConvertToApplicationInfo
 * @tc.desc: 1.Test ConvertToApplicationInfo of CompatibleApplicationInfo success
 */
HWTEST_F(BmsBundleKitServiceTest, CompatibleApplicationInfo_002, Function | SmallTest | Level1)
{
    CompatibleApplicationInfo appInfo;
    appInfo.name = "com.ohos.contactsdata.ability";
    ApplicationInfo info;
    appInfo.ConvertToApplicationInfo(info);
    EXPECT_EQ(appInfo.name, info.name);
}

/**
 * @tc.number: SeriviceStatusCallback_001
 * @tc.name: OnBundleStateChanged
 * @tc.desc: 1.Test StatusCallbackProxy
 */
HWTEST_F(BmsBundleKitServiceTest, SeriviceStatusCallback_001, Function | SmallTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    APP_LOGI("get proxy success.");
    auto proxy = iface_cast<BundleStatusCallbackProxy>(remoteObject);
    int32_t resultCode = 0;
    uint8_t installType = static_cast<uint8_t>(InstallType::INSTALL_CALLBACK);
    std::string resultMsg = Constants::EMPTY_STRING;
    proxy->OnBundleStateChanged(installType, resultCode, resultMsg, BUNDLE_NAME_TEST);
    EXPECT_EQ(resultMsg, "");
}

/**
 * @tc.number: SeriviceStatusCallback_004
 * @tc.name: OnBundleRemoved
 * @tc.desc: 1.Test StatusCallbackProxy
 */
HWTEST_F(BmsBundleKitServiceTest, SeriviceStatusCallback_004, Function | SmallTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    APP_LOGI("get proxy success.");
    auto proxy = iface_cast<BundleStatusCallbackProxy>(remoteObject);
    std::string bundleName = BUNDLE_NAME_TEST;
    proxy->OnBundleAdded(bundleName, DEFAULT_USER_ID_TEST);
    proxy->OnBundleUpdated(bundleName, DEFAULT_USER_ID_TEST);
    EXPECT_EQ(bundleName, BUNDLE_NAME_TEST);
    proxy->OnBundleRemoved(bundleName, DEFAULT_USER_ID_TEST);
}

/**
 * @tc.number: SeriviceStatusCallback_005
 * @tc.name: OnCleanCacheFinished
 * @tc.desc: 1.Test CleanCacheCallbackProxy
 */
HWTEST_F(BmsBundleKitServiceTest, SeriviceStatusCallback_005, Function | SmallTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    APP_LOGI("get proxy success.");
    auto proxy = iface_cast<CleanCacheCallbackProxy>(remoteObject);
    bool testRet = true;
    proxy->OnCleanCacheFinished(testRet);
    EXPECT_TRUE(testRet);
}

/**
 * @tc.number: SeriviceStatusCallback_006
 * @tc.name: OnBundleStateChanged
 * @tc.desc: 1.Test StatusCallbackProxy
 *           2.bundle state changed fail by wrong installType
 */
HWTEST_F(BmsBundleKitServiceTest, SeriviceStatusCallback_006, Function | SmallTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    APP_LOGI("get proxy success.");
    auto proxy = iface_cast<BundleStatusCallbackProxy>(remoteObject);
    int32_t resultCode = 0;
    int32_t installType = 0;
    std::string resultMsg = Constants::EMPTY_STRING;
    proxy->OnBundleStateChanged(installType, resultCode, resultMsg, BUNDLE_NAME_TEST);
    EXPECT_EQ(resultMsg, Constants::EMPTY_STRING);
}

/**
 * @tc.number: SeriviceStatusCallback_007
 * @tc.name: OnBundleStateChanged
 * @tc.desc: 1.Test StatusCallbackProxy
 *           2.bundle state changed fail by wrong resultCode
 */
HWTEST_F(BmsBundleKitServiceTest, SeriviceStatusCallback_007, Function | SmallTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    APP_LOGI("get proxy success.");
    auto proxy = iface_cast<BundleStatusCallbackProxy>(remoteObject);
    uint8_t resultCode = static_cast<uint8_t>(InstallType::INSTALL_CALLBACK);
    uint8_t installType = static_cast<uint8_t>(InstallType::INSTALL_CALLBACK);
    std::string resultMsg = Constants::EMPTY_STRING;
    proxy->OnBundleStateChanged(installType, resultCode, resultMsg, BUNDLE_NAME_TEST);
    EXPECT_EQ(resultCode, 0);
    EXPECT_EQ(installType, 0);
    EXPECT_EQ(resultMsg, Constants::EMPTY_STRING);
}

/**
 * @tc.number: SeriviceStatusCallback_008
 * @tc.name: OnBundleStateChanged
 * @tc.desc: 1.Test StatusCallbackProxy
 *           2.bundle state changed fail by wrong resultMsg
 */
HWTEST_F(BmsBundleKitServiceTest, SeriviceStatusCallback_008, Function | SmallTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    APP_LOGI("get proxy success.");
    auto proxy = iface_cast<BundleStatusCallbackProxy>(remoteObject);
    int32_t resultCode = 0;
    uint8_t installType = static_cast<uint8_t>(InstallType::INSTALL_CALLBACK);
    std::string resultMsg = "";
    proxy->OnBundleStateChanged(installType, resultCode, resultMsg, BUNDLE_NAME_TEST);
    EXPECT_EQ(installType, 0);
    EXPECT_EQ(resultMsg, "");
}

/**
 * @tc.number: SeriviceStatusCallback_009
 * @tc.name: OnBundleStateChanged
 * @tc.desc: 1.Test StatusCallbackProxy
 *           2.bundle state changed fail by wrong bundle name
 */
HWTEST_F(BmsBundleKitServiceTest, SeriviceStatusCallback_009, Function | SmallTest | Level1)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    APP_LOGI("get proxy success.");
    auto proxy = iface_cast<BundleStatusCallbackProxy>(remoteObject);
    int32_t resultCode = 0;
    uint8_t installType = static_cast<uint8_t>(InstallType::INSTALL_CALLBACK);
    std::string resultMsg = Constants::EMPTY_STRING;
    proxy->OnBundleStateChanged(installType, resultCode, resultMsg, "");
    EXPECT_EQ(installType, 0);
    EXPECT_EQ(resultMsg, Constants::EMPTY_STRING);
}

/**
 * @tc.number: SetDebugMode_0100
 * @tc.name: test SetDebugMode
 * @tc.desc: SetDebugMode
 */
HWTEST_F(BmsBundleKitServiceTest, SetDebugMode_0100, Function | SmallTest | Level1)
{
    bool isDebug = false;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t result = hostImpl->SetDebugMode(isDebug);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: SetDebugMode_0200
 * @tc.name: test SetDebugMode
 * @tc.desc: SetDebugMode
 */
HWTEST_F(BmsBundleKitServiceTest, SetDebugMode_0200, Function | SmallTest | Level1)
{
    bool isDebug = true;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t result = hostImpl->SetDebugMode(isDebug);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: SetDebugMode_0300
 * @tc.name: test SetDebugMode
 * @tc.desc: SetDebugMode
 */
HWTEST_F(BmsBundleKitServiceTest, SetDebugMode_0300, Function | SmallTest | Level1)
{
    bool isDebug = true;
    setuid(ServiceConstants::SHELL_UID);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t result = hostImpl->SetDebugMode(isDebug);
    EXPECT_EQ(result, ERR_BUNDLEMANAGER_SET_DEBUG_MODE_UID_CHECK_FAILED);
}

/**
 * @tc.name: DynamicSystemProcess_0100
 * @tc.desc: Test start and stop d-bms process
 * @tc.type: FUNC
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, DynamicSystemProcess_0100, Function | SmallTest | Level1)
{
    int32_t systemAbilityId = 402;
    std::string strExtra = std::to_string(systemAbilityId);
    auto extraArgv = strExtra.c_str();
    int ret = ServiceControlWithExtra(SERVICES_NAME.c_str(), START, &extraArgv, 1);
    EXPECT_EQ(ret, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    ret = ServiceControlWithExtra(SERVICES_NAME.c_str(), STOP, &extraArgv, 1);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: QueryAbilityInfosV9_0100
 * @tc.name: test QueryAbilityInfosV9
 * @tc.desc: 1.get ability info failed
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosV9_0100, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryAbilityInfosV9_0100");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> abilityInfos;

    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_ONLY_SYSTEM_APP);
    ErrCode ret = GetBundleDataMgr()->QueryAbilityInfosV9(want, flags, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryAbilityInfosV9_0100 finish");
}

/**
 * @tc.number: QueryAbilityInfosV9_0200
 * @tc.name: test QueryAbilityInfosV9
 * @tc.desc: 1.when disable ability, get ability info failed
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosV9_0200, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryAbilityInfosV9_0200");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> abilityInfos;

    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    ErrCode ret = GetBundleDataMgr()->QueryAbilityInfosV9(want, flags, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(abilityInfos.size() == 1);
    ret = GetBundleDataMgr()->SetAbilityEnabled(abilityInfos[0], 0, false, 0);
    EXPECT_EQ(ret, ERR_OK);

    std::vector<AbilityInfo> abilityInfosWhenDisabled;
    ret = GetBundleDataMgr()->QueryAbilityInfosV9(want, flags, 0, abilityInfosWhenDisabled);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_DISABLED);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryAbilityInfosV9_0200 finish");
}

/**
 * @tc.number: QueryAbilityInfosV9_0300
 * @tc.name: test QueryAbilityInfosV9
 * @tc.desc: 1.implicit query cur bundle, get ability info failed
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosV9_0300, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryAbilityInfosV9_0300");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.not.extist");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<AbilityInfo> abilityInfos;

    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    ErrCode ret = GetBundleDataMgr()->QueryAbilityInfosV9(want, flags, 0, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryAbilityInfosV9_0300 finish");
}

/**
 * @tc.number: QueryAbilityInfosV9_0400
 * @tc.name: test QueryAbilityInfosV9
 * @tc.desc: 1.implicit query cur bundle, get ability info failed
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosV9_0400, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryAbilityInfosV9_0400");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.not.extist");
    std::vector<AbilityInfo> abilityInfos;

    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    ErrCode ret = GetBundleDataMgr()->QueryAbilityInfosV9(want, flags, 0, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryAbilityInfosV9_0400 finish");
}

/**
 * @tc.number: QueryAbilityInfosV9_0500
 * @tc.name: test can get the ability info by want with implicit query
 * @tc.desc: 1.implicit query cur bundle only system, get ability info failed
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosV9_0500, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryAbilityInfosV9_0500");
    std::vector<std::string> moduleList {MODULE_NAME_TEST, MODULE_NAME_TEST_1, MODULE_NAME_TEST_2};
    MockInstallBundle(BUNDLE_NAME_TEST, moduleList, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<AbilityInfo> abilityInfos;
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_ONLY_SYSTEM_APP);

    ErrCode ret = GetBundleDataMgr()->QueryAbilityInfosV9(want, flags, 0, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryAbilityInfosV9_0500 finish");
}

/**
 * @tc.number: QueryAbilityInfosV9_0600
 * @tc.name: test can get the ability info by want with implicit query
 * @tc.desc: 1.implicit query cur bundle when disable
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosV9_0600, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryAbilityInfosV9_0600");
    std::vector<std::string> moduleList {MODULE_NAME_TEST, MODULE_NAME_TEST_1, MODULE_NAME_TEST_2};
    MockInstallBundle(BUNDLE_NAME_TEST, moduleList, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<AbilityInfo> abilityInfos;
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);

    ErrCode ret = GetBundleDataMgr()->QueryAbilityInfosV9(want, flags, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    for (const auto &abilityInfo : abilityInfos) {
        ret = GetBundleDataMgr()->SetAbilityEnabled(abilityInfo, 0, false, 0);
        EXPECT_EQ(ret, ERR_OK);
    }
    abilityInfos.clear();
    ret = GetBundleDataMgr()->QueryAbilityInfosV9(want, flags, 0, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryAbilityInfosV9_0600 finish");
}

/**
 * @tc.number: QueryAbilityInfosV9_0700
 * @tc.name: test QueryAbilityInfosV9
 * @tc.desc: 1.implicit query cur bundle, get ability info failed
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosV9_0700, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryAbilityInfosV9_0700");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.not.extist");
    std::vector<AbilityInfo> abilityInfos;

    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ErrCode ret = hostImpl->QueryAbilityInfosV9(want, flags, 0, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryAbilityInfosV9_0700 finish");
}

/**
 * @tc.number: QueryAbilityInfosV9_0800
 * @tc.name: test QueryAbilityInfosV9
 * @tc.desc: 1.explicit query ability info. 2.get abilityInfos
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosV9_0800, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryAbilityInfosV9_0800");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    int appIndex = TEST_APP_INDEX1;
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, appIndex);
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> abilityInfos;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ErrCode ret = hostImpl->QueryAbilityInfosV9(want, flags, DEFAULT_USERID, abilityInfos);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(abilityInfos.size(), 2);
    if (abilityInfos.size() == 2) {
        EXPECT_EQ(abilityInfos[1].appIndex, TEST_APP_INDEX1);
    }
    ClearCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryAbilityInfosV9_0800 finish");
}

/**
 * @tc.number: QueryAbilityInfosV9_0900
 * @tc.name:  test can get the ability info with skill flag by explicit query
 * @tc.desc: 1.Test the QueryAbilityInfosV9 by BundleMgrHostImpl with skill flag
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosV9_0900, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<AbilityInfo> result;
    uint32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT) |
        static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_SKILL);
    ErrCode ret = hostImpl->QueryAbilityInfosV9(want, flags, 0, result);
    CheckAbilityInfos(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfosV9_1000
 * @tc.name:  test can get the ability info with skill by implicit query
 * @tc.desc: 1.Test the QueryAbilityInfosV9 by BundleMgrHostImpl with skill flag
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosV9_1000, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetUri("http://example.com:80/path");
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<AbilityInfo> result;
    uint32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT) |
        static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_SKILL);
    ErrCode ret = hostImpl->QueryAbilityInfosV9(want, flags, 0, result);
    CheckAbilityInfos(BUNDLE_NAME_TEST, ABILITY_NAME_TEST, flags, result);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAbilityInfosV9_1100
 * @tc.name: test QueryAbilityInfosV9
 * @tc.desc: 1.explicit query ability info. 2.add cloneInfo. 3.disable main app. 4.get abilityInfos
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosV9_1100, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryAbilityInfosV9_1100");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX1);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX2);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX3);

    EXPECT_TRUE(ChangeAppDisabledStatus(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, 0, false));

    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> abilityInfos;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    ErrCode ret = hostImpl->QueryAbilityInfosV9(want, flags, DEFAULT_USERID, abilityInfos);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(abilityInfos.size(), 3);
    int index = 1;
    for (AbilityInfo info : abilityInfos) {
        EXPECT_EQ(info.appIndex, index++);
    }
    QueryCloneAbilityInfosV9WithDisable(want);

    ClearCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryAbilityInfosV9_1100 finish");
}

/**
 * @tc.number: QueryAbilityInfosV9_1200
 * @tc.name: test QueryAbilityInfosV9
 * @tc.desc: 1.explicit query ability info. 2.add cloneInfo. 3.disable clone app. 4.get abilityInfos
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosV9_1200, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryAbilityInfosV9_1200");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX1);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX2);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX3);

    EXPECT_TRUE(ChangeAppDisabledStatus(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX2, false));

    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<AbilityInfo> abilityInfos;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    ErrCode ret = hostImpl->QueryAbilityInfosV9(want, flags, DEFAULT_USERID, abilityInfos);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(abilityInfos.size(), 3);
    int index = 0;
    for (AbilityInfo info : abilityInfos) {
        EXPECT_EQ(info.appIndex, index++);
        if (index == 2) {
            index++;
        }
    }
    QueryCloneAbilityInfosV9WithDisable(want);

    ClearCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryAbilityInfosV9_1200 finish");
}

/**
 * @tc.number: QueryAbilityInfosV9_1300
 * @tc.name: test QueryAbilityInfosV9
 * @tc.desc: 1.implicit query ability info. 2. add cloneInfo. 3.disable main app. 4.get abilityInfos
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosV9_1300, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryAbilityInfosV9_1300");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX1);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX2);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX3);

    EXPECT_TRUE(ChangeAppDisabledStatus(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, 0, false));

    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    std::vector<AbilityInfo> abilityInfos;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    ErrCode ret = hostImpl->QueryAbilityInfosV9(want, flags, DEFAULT_USERID, abilityInfos);
    EXPECT_EQ(ret, 0);
    int index = 1;
    for (AbilityInfo info : abilityInfos) {
        if (info.bundleName == BUNDLE_NAME_TEST) {
            EXPECT_EQ(info.appIndex, index++);
        }
    }
    QueryCloneAbilityInfosV9WithDisable(want);

    ClearCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryAbilityInfosV9_1300 finish");
}

/**
 * @tc.number: QueryAbilityInfosV9_1400
 * @tc.name: test QueryAbilityInfosV9
 * @tc.desc: 1.implicit query ability info. 2. add cloneInfo. 3.disable one clone app. 4.get abilityInfos
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosV9_1400, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryAbilityInfosV9_1400");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX1);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX2);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, TEST_APP_INDEX3);

    EXPECT_TRUE(ChangeAppDisabledStatus(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX2, false));

    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    std::vector<AbilityInfo> abilityInfos;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    ErrCode ret = hostImpl->QueryAbilityInfosV9(want, flags, DEFAULT_USERID, abilityInfos);
    EXPECT_EQ(ret, 0);
    int index = 0;
    for (AbilityInfo info : abilityInfos) {
        if (info.bundleName == BUNDLE_NAME_TEST) {
            EXPECT_EQ(info.appIndex, index++);
        }
        if (index == 2) {
            index++;
        }
    }
    QueryCloneAbilityInfosV9WithDisable(want);

    ClearCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USERID);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryAbilityInfosV9_1400 finish");
}

/**
 * @tc.number: BatchQueryAbilityInfos_0100
 * @tc.name: test BatchQueryAbilityInfos
 * @tc.desc: 1.get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, BatchQueryAbilityInfos_0100, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BatchQueryAbilityInfos_0100");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<Want> wants = { want };
    std::vector<AbilityInfo> abilityInfos;

    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_ONLY_SYSTEM_APP);
    ErrCode ret = GetBundleDataMgr()->BatchQueryAbilityInfos(wants, flags, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("BatchQueryAbilityInfos_0100 finish");
}

/**
 * @tc.number: BatchQueryAbilityInfos_0200
 * @tc.name: test BatchQueryAbilityInfos
 * @tc.desc: 1.when disable ability, get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, BatchQueryAbilityInfos_0200, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BatchQueryAbilityInfos_0200");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<Want> wants = { want };
    std::vector<AbilityInfo> abilityInfos;

    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    ErrCode ret = GetBundleDataMgr()->BatchQueryAbilityInfos(wants, flags, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(abilityInfos.size() == 1);
    ret = GetBundleDataMgr()->SetAbilityEnabled(abilityInfos[0], 0, false, 0);
    EXPECT_EQ(ret, ERR_OK);
    ret = GetBundleDataMgr()->BatchQueryAbilityInfos(wants, flags, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_DISABLED);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("BatchQueryAbilityInfos_0200 finish");
}

/**
 * @tc.number: BatchQueryAbilityInfos_0300
 * @tc.name: test BatchQueryAbilityInfos
 * @tc.desc: 1.implicit query cur bundle, get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, BatchQueryAbilityInfos_0300, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BatchQueryAbilityInfos_0300");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.not.extist");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<Want> wants = { want };
    std::vector<AbilityInfo> abilityInfos;

    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    ErrCode ret = GetBundleDataMgr()->BatchQueryAbilityInfos(wants, flags, 0, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("BatchQueryAbilityInfos_0300 finish");
}

/**
 * @tc.number: BatchQueryAbilityInfos_0400
 * @tc.name: test BatchQueryAbilityInfos
 * @tc.desc: 1.implicit query cur bundle, get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, BatchQueryAbilityInfos_0400, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BatchQueryAbilityInfos_0400");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.not.extist");
    std::vector<Want> wants = { want };
    std::vector<AbilityInfo> abilityInfos;

    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    ErrCode ret = GetBundleDataMgr()->BatchQueryAbilityInfos(wants, flags, 0, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("BatchQueryAbilityInfos_0400 finish");
}

/**
 * @tc.number: BatchQueryAbilityInfos_0500
 * @tc.name: test can get the ability info by want with implicit query
 * @tc.desc: 1.implicit query cur bundle only system, get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, BatchQueryAbilityInfos_0500, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BatchQueryAbilityInfos_0500");
    std::vector<std::string> moduleList {MODULE_NAME_TEST, MODULE_NAME_TEST_1, MODULE_NAME_TEST_2};
    MockInstallBundle(BUNDLE_NAME_TEST, moduleList, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<Want> wants = { want };
    std::vector<AbilityInfo> abilityInfos;
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_ONLY_SYSTEM_APP);

    ErrCode ret = GetBundleDataMgr()->BatchQueryAbilityInfos(wants, flags, 0, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("BatchQueryAbilityInfos_0500 finish");
}

/**
 * @tc.number: BatchQueryAbilityInfos_0600
 * @tc.name: test can get the ability info by want with implicit query
 * @tc.desc: 1.implicit query cur bundle when disable
 */
HWTEST_F(BmsBundleKitServiceTest, BatchQueryAbilityInfos_0600, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BatchQueryAbilityInfos_0600");
    std::vector<std::string> moduleList {MODULE_NAME_TEST, MODULE_NAME_TEST_1, MODULE_NAME_TEST_2};
    MockInstallBundle(BUNDLE_NAME_TEST, moduleList, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<Want> wants = { want };
    std::vector<AbilityInfo> abilityInfos;
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);

    ErrCode ret = GetBundleDataMgr()->BatchQueryAbilityInfos(wants, flags, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    for (const auto &abilityInfo : abilityInfos) {
        ret = GetBundleDataMgr()->SetAbilityEnabled(abilityInfo, 0, false, 0);
        EXPECT_EQ(ret, ERR_OK);
    }
    abilityInfos.clear();
    ret = GetBundleDataMgr()->BatchQueryAbilityInfos(wants, flags, 0, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("BatchQueryAbilityInfos_0600 finish");
}

/**
 * @tc.number: BatchQueryAbilityInfos_0700
 * @tc.name: test BatchQueryAbilityInfos
 * @tc.desc: 1.implicit query cur bundle, get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, BatchQueryAbilityInfos_0700, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BatchQueryAbilityInfos_0700");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.not.extist");
    std::vector<Want> wants = { want };
    std::vector<AbilityInfo> abilityInfos;

    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ErrCode ret = hostImpl->BatchQueryAbilityInfos(wants, flags, 0, abilityInfos);
    EXPECT_NE(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("BatchQueryAbilityInfos_0700 finish");
}

/**
 * @tc.number: BatchQueryAbilityInfos_0800
 * @tc.name: test can get the ability info and skill info by want with implicit query
 * @tc.desc: 1.implicit query cur bundle
 */
HWTEST_F(BmsBundleKitServiceTest, BatchQueryAbilityInfos_0800, Function | SmallTest | Level1)
{
    APP_LOGI("begin of BatchQueryAbilityInfos_0800");
    std::vector<std::string> moduleList {MODULE_NAME_TEST, MODULE_NAME_TEST_1, MODULE_NAME_TEST_2};
    MockInstallBundle(BUNDLE_NAME_TEST, moduleList, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<Want> wants = { want };
    std::vector<AbilityInfo> abilityInfos;
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT) |
        static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_SKILL) ;
    ErrCode ret = GetBundleDataMgr()->BatchQueryAbilityInfos(wants, flags, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(abilityInfos.size(), ABILITY_SIZE_THREE);
    EXPECT_EQ(abilityInfos[0].skills.size(), SKILL_SIZE_TWO);
    abilityInfos.clear();
    flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    ret = GetBundleDataMgr()->BatchQueryAbilityInfos(wants, flags, 0, abilityInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(abilityInfos.size(), ABILITY_SIZE_THREE);
    EXPECT_EQ(abilityInfos[0].skills.size(), SKILL_SIZE_ZERO);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("BatchQueryAbilityInfos_0800 finish");
}

/**
 * @tc.number: BatchGetBundleInfo_0100
 * @tc.name: Test BatchGetBundleInfo
 * @tc.desc: 1.Test the BatchGetBundleInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, BatchGetBundleInfo_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<std::string> bundleNames = { BUNDLE_NAME_DEMO };
    std::vector<BundleInfo> bundleInfos;
    auto flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION);
    ErrCode ret = hostImpl->BatchGetBundleInfo(bundleNames, flags, bundleInfos, DEFAULT_USERID);
    EXPECT_EQ(ret, ERR_OK);
    CheckBundleInfo(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_SIZE_ZERO, bundleInfos[0]);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: BatchGetBundleInfo_0200
 * @tc.name: Test BatchGetBundleInfo
 * @tc.desc: 1.Test the BatchGetBundleInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, BatchGetBundleInfo_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<std::string> bundleNames = { BUNDLE_NAME_DEMO, BUNDLE_NAME_TEST };
    std::vector<BundleInfo> result;
    auto flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION);
    ErrCode ret = hostImpl->BatchGetBundleInfo(bundleNames, flags, result, DEFAULT_USERID);
    EXPECT_EQ(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0100
 * @tc.name: test QueryExtensionAbilityInfosV9
 * @tc.desc: 1.explicit query extension info failed, bundle not exist, appIndex = 0
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosV9_0100, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryExtensionAbilityInfosV9_0100");
    Want want;
    want.SetElementName("invlaidBundleName", ABILITY_NAME_TEST);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t flags = static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_DEFAULT);
    ErrCode ret = GetBundleDataMgr()->QueryExtensionAbilityInfosV9(want, flags, 0, extensionInfos);
    EXPECT_NE(ret, ERR_OK);
    APP_LOGI("QueryExtensionAbilityInfosV9_0100 finish");
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0200
 * @tc.name: test QueryExtensionAbilityInfosV9
 * @tc.desc: 1.explicit query extension info failed, bundle not exist, appIndex = 1
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosV9_0200, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryExtensionAbilityInfosV9_0200");
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t flags = static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_DEFAULT);
    int32_t appIndex = 1;
    ErrCode ret = GetBundleDataMgr()->QueryExtensionAbilityInfosV9(want, flags, 0, extensionInfos, appIndex);
    EXPECT_NE(ret, ERR_OK);
    APP_LOGI("QueryExtensionAbilityInfosV9_0200 finish");
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0300
 * @tc.name: test QueryExtensionAbilityInfosV9
 * @tc.desc: 1.implicit query extension info failed, scope in cur bundle, appIndex = 0, action not exist
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosV9_0300, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryExtensionAbilityInfosV9_0300");
    Want want;
    want.SetAction("action.not.exist");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t flags = static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_DEFAULT);
    ErrCode ret = GetBundleDataMgr()->QueryExtensionAbilityInfosV9(want, flags, 0, extensionInfos);
    EXPECT_NE(ret, ERR_OK);
    APP_LOGI("QueryExtensionAbilityInfosV9_0300 finish");
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0400
 * @tc.name: test QueryExtensionAbilityInfosV9
 * @tc.desc: 1.implicit query extension info failed, scope in cur bundle, appIndex = 1
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosV9_0400, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryExtensionAbilityInfosV9_0400");
    Want want;
    want.SetAction("action.not.exist");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t flags = static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_DEFAULT);
    int32_t appIndex = 1;
    ErrCode ret = GetBundleDataMgr()->QueryExtensionAbilityInfosV9(want, flags, 0, extensionInfos, appIndex);
    EXPECT_NE(ret, ERR_OK);
    APP_LOGI("QueryExtensionAbilityInfosV9_0400 finish");
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0500
 * @tc.name: test QueryExtensionAbilityInfosV9
 * @tc.desc: 1.implicit query extension info failed, scope in all bundle, appIndex = 1
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosV9_0500, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryExtensionAbilityInfosV9_0500");
    Want want;
    want.SetAction("action.not.exist");
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t flags = static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_DEFAULT);
    int32_t appIndex = 1;
    ErrCode ret = GetBundleDataMgr()->QueryExtensionAbilityInfosV9(want, flags, 0, extensionInfos, appIndex);
    EXPECT_NE(ret, ERR_OK);
    APP_LOGI("QueryExtensionAbilityInfosV9_0500 finish");
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0600
 * @tc.name: test QueryExtensionAbilityInfosV9
 * @tc.desc: 1.explicit query extension info success, get more than one extension
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosV9_0600, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryExtensionAbilityInfosV9_0600");
    std::string moduleName = "m1";
    std::string extension = "test-extension";
    MockInstallExtension(BUNDLE_NAME_TEST, moduleName, extension);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<ExtensionAbilityInfo> extensionInfos;

    int32_t flags = static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_DEFAULT);
    ErrCode ret = GetBundleDataMgr()->QueryExtensionAbilityInfosV9(want, flags, 0, extensionInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(extensionInfos.size(), 2);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryExtensionAbilityInfosV9_0600 finish");
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0700
 * @tc.name: test QueryExtensionAbilityInfosV9 proxy
 * @tc.desc: 1.system run normally
 *           2.extension not found
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosV9_0700, Function | SmallTest | Level1)
{
    Want want;
    int32_t flags = 0;
    int32_t userId = 100;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<ExtensionAbilityInfo> extensions;
    ErrCode ret = hostImpl->QueryExtensionAbilityInfosV9(want, flags, userId, extensions);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0800
 * @tc.name: test QueryExtensionAbilityInfosV9
 * @tc.desc: 1.explicit query extension info failed, bundle not exist, appIndex = 1
 * @tc.require: issueI56WFH
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosV9_0800, Function | SmallTest | Level1)
{
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t userId = 100;
    int32_t flags =
        static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_DEFAULT);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ErrCode ret = hostImpl->QueryExtensionAbilityInfosV9(want, flags, userId, extensionInfos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_1000
 * @tc.name: test QueryExtensionAbilityInfosV9
 * @tc.desc: 1.explicit query extension info success, get more than one extension
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosV9_1000, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string moduleName = "m1";
    std::string extension = "test-extension";
    MockInstallExtension(BUNDLE_NAME_TEST, moduleName, extension);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<ExtensionAbilityInfo> extensionInfos;

    int32_t flags = static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_DEFAULT);
    ErrCode ret = hostImpl->QueryExtensionAbilityInfosV9(want, flags, 0, extensionInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(extensionInfos.size(), 2);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryExtensionAbilityInfosV9_0600 finish");
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_1100
 * @tc.name: test QueryExtensionAbilityInfosV9 with skill flag by explicit query
 * @tc.desc: 1.explicit query extension info success, get more than one extension
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosV9_1100, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryExtensionAbilityInfosV9_1100");
    std::string moduleName = "m1";
    std::string extension = "test-extension";
    MockInstallExtension(BUNDLE_NAME_TEST, moduleName, extension);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<ExtensionAbilityInfo> extensionInfos;

    ErrCode ret = GetBundleDataMgr()->QueryExtensionAbilityInfosV9(want,
        static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_SKILL), 0, extensionInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(extensionInfos.size(), EXTENSION_SIZE_TWO);
    for (int i = 0; i < extensionInfos.size(); i++) {
        EXPECT_EQ(extensionInfos[i].skills.size(), SKILL_SIZE_TWO);
    }
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryExtensionAbilityInfosV9_1100 finish");
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_1200
 * @tc.name: test QueryExtensionAbilityInfosV9
 * @tc.desc: 1.implicit query extension info success, get more than one extension
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosV9_1200, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryExtensionAbilityInfosV9_1200");
    std::string moduleName = "m1";
    std::string extension = "test-extension";
    MockInstallExtensionWithUri(BUNDLE_NAME_TEST, moduleName, extension);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetUri("http://example.com:80/path");
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t flags = static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_DEFAULT);
    ErrCode ret = GetBundleDataMgr()->QueryExtensionAbilityInfosV9(want, flags, 0, extensionInfos); //
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(extensionInfos.size(), EXTENSION_SIZE_TWO);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("QueryExtensionAbilityInfosV9_1200 finish");
}

/**
 * @tc.number: TestAbleBundle_001
 * @tc.name: TestAbleBundle
 * @tc.desc: 1.Test the TestAbleBundle
 */
HWTEST_F(BmsBundleKitServiceTest, TestAbleBundle_001, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    bool testRet = GetBundleDataMgr()->DisableBundle(BUNDLE_NAME_TEST);
    EXPECT_EQ(testRet, true);
    bool testRet1 = GetBundleDataMgr()->EnableBundle(BUNDLE_NAME_TEST);
    EXPECT_EQ(testRet1, true);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: TestAbleBundle_002
 * @tc.name: TestAbleBundle
 * @tc.desc: 1.Test the TestAbleBundle
 *           2.query failed
 */
HWTEST_F(BmsBundleKitServiceTest, TestAbleBundle_002, Function | SmallTest | Level1)
{
    bool testRet = GetBundleDataMgr()->DisableBundle("");
    EXPECT_EQ(testRet, false);
    bool testRet1 = GetBundleDataMgr()->EnableBundle("");
    EXPECT_EQ(testRet1, false);
}

/**
 * @tc.number: GetProvisionId_001
 * @tc.name: GetProvisionId
 * @tc.desc: 1.Test the GetProvisionId success
 */
HWTEST_F(BmsBundleKitServiceTest, GetProvisionId_001, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::string provisionId;

    bool testRet = GetBundleDataMgr()->GetProvisionId(BUNDLE_NAME_TEST, provisionId);
    EXPECT_EQ(testRet, true);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetProvisionId_002
 * @tc.name: GetProvisionId
 * @tc.desc: 1.Test the GetProvisionId failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetProvisionId_002, Function | SmallTest | Level1)
{
    std::string provisionId;

    bool testRet = GetBundleDataMgr()->GetProvisionId("", provisionId);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetAppFeature_001
 * @tc.name: GetAppFeature
 * @tc.desc: 1.Test the GetAppFeature success
 */
HWTEST_F(BmsBundleKitServiceTest, GetAppFeature_001, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::string appFeature;

    bool testRet = GetBundleDataMgr()->GetAppFeature(BUNDLE_NAME_TEST, appFeature);
    EXPECT_EQ(testRet, true);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAppFeature_002
 * @tc.name: GetAppFeature
 * @tc.desc: 1.Test the GetAppFeature failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAppFeature_002, Function | SmallTest | Level1)
{
    std::string appFeature;

    bool testRet = GetBundleDataMgr()->GetAppFeature("", appFeature);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: QueryAbilityInfoWithFlagsV9_0100
 * @tc.name: test QueryAbilityInfoWithFlagsV9
 * @tc.desc: 1.explicit query Ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfoWithFlagsV9_0100, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryAbilityInfoWithFlagsV9_0100");
    std::optional<AbilityInfo> option;
    AbilityInfo info;
    InnerBundleInfo innerBundleInfo;
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_ONLY_SYSTEM_APP);
    ErrCode ret = GetBundleDataMgr()->QueryAbilityInfoWithFlagsV9(option, flags, 100, innerBundleInfo, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    APP_LOGI("QueryAbilityInfoWithFlagsV9_0100 finish");
}

/**
 * @tc.number: QueryAbilityInfoWithFlagsV9_0200
 * @tc.name: test QueryAbilityInfoWithFlagsV9
 * @tc.desc: 1.explicit query Ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfoWithFlagsV9_0200, Function | SmallTest | Level1)
{
    APP_LOGI("begin of QueryAbilityInfoWithFlagsV9_0200");
    std::optional<AbilityInfo> option;
    AbilityInfo info;
    InnerBundleInfo innerBundleInfo;
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    ErrCode ret = GetBundleDataMgr()->QueryAbilityInfoWithFlagsV9(option, flags, 100, innerBundleInfo, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_DISABLED);
    APP_LOGI("QueryAbilityInfoWithFlagsV9_0200 finish");
}

/**
 * @tc.number: ImplicitQueryCurAbilityInfosV9_0100
 * @tc.name: test ImplicitQueryCurAbilityInfosV9
 * @tc.desc: 1.explicit query CurAbility info ok
 */
HWTEST_F(BmsBundleKitServiceTest, ImplicitQueryCurAbilityInfosV9_0100, Function | SmallTest | Level1)
{
    APP_LOGI("begin of ImplicitQueryCurAbilityInfosV9_0100");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<AbilityInfo> abilityInfos;
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_ONLY_SYSTEM_APP);
    int32_t appIndex = -1;
    ErrCode ret = GetBundleDataMgr()->ImplicitQueryCurAbilityInfosV9(want, flags, 0, abilityInfos, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("ImplicitQueryCurAbilityInfosV9_0100 finish");
}

/**
 * @tc.number: ImplicitQueryCurAbilityInfosV9_0200
 * @tc.name: test ImplicitQueryCurAbilityInfosV9
 * @tc.desc: 1.explicit query CurAbility info ok
 */
HWTEST_F(BmsBundleKitServiceTest, ImplicitQueryCurAbilityInfosV9_0200, Function | SmallTest | Level1)
{
    APP_LOGI("begin of ImplicitQueryCurAbilityInfosV9_0200");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<AbilityInfo> abilityInfos;
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_DISABLE);
    int32_t appIndex = -1;
    ErrCode ret = GetBundleDataMgr()->ImplicitQueryCurAbilityInfosV9(want, flags, 0, abilityInfos, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("ImplicitQueryCurAbilityInfosV9_0200 finish");
}

/**
 * @tc.number: ImplicitQueryCurAbilityInfosV9_0300
 * @tc.name: test ImplicitQueryCurAbilityInfosV9
 * @tc.desc: 1.explicit query CurAbility info ok
 */
HWTEST_F(BmsBundleKitServiceTest, ImplicitQueryCurAbilityInfosV9_0300, Function | SmallTest | Level1)
{
    APP_LOGI("begin of ImplicitQueryCurAbilityInfosV9_0300");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<AbilityInfo> abilityInfos;
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION);
    int32_t appIndex = -1;
    ErrCode ret = GetBundleDataMgr()->ImplicitQueryCurAbilityInfosV9(want, flags, 0, abilityInfos, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("ImplicitQueryCurAbilityInfosV9_0300 finish");
}

/**
 * @tc.number: ImplicitQueryCurAbilityInfosV9_0400
 * @tc.name: test ImplicitQueryCurAbilityInfosV9
 * @tc.desc: 1.explicit query CurAbility info ok
 */
HWTEST_F(BmsBundleKitServiceTest, ImplicitQueryCurAbilityInfosV9_0400, Function | SmallTest | Level1)
{
    APP_LOGI("begin of ImplicitQueryCurAbilityInfosV9_0400");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<AbilityInfo> abilityInfos;
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_METADATA);
    int32_t appIndex = -1;
    ErrCode ret = GetBundleDataMgr()->ImplicitQueryCurAbilityInfosV9(want, flags, 0, abilityInfos, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("ImplicitQueryCurAbilityInfosV9_0400 finish");
}

/**
 * @tc.number: ImplicitQueryCurAbilityInfosV9_0500
 * @tc.name: test ImplicitQueryCurAbilityInfosV9
 * @tc.desc: 1.explicit query CurAbility info ok
 */
HWTEST_F(BmsBundleKitServiceTest, ImplicitQueryCurAbilityInfosV9_0500, Function | SmallTest | Level1)
{
    APP_LOGI("begin of ImplicitQueryCurAbilityInfosV9_0500");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    want.SetAction("action.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<AbilityInfo> abilityInfos;
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_PERMISSION);
    int32_t appIndex = -1;
    ErrCode ret = GetBundleDataMgr()->ImplicitQueryCurAbilityInfosV9(want, flags, 0, abilityInfos, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("ImplicitQueryCurAbilityInfosV9_0500 finish");
}

/**
 * @tc.number: ExplicitQueryExtensionInfoV9_0100
 * @tc.name: test ExplicitQueryExtensionInfoV9
 * @tc.desc: 1.explicit query extension info failed
 */
HWTEST_F(BmsBundleKitServiceTest, ExplicitQueryExtensionInfoV9_0100, Function | SmallTest | Level1)
{
    APP_LOGI("begin of ExplicitQueryExtensionInfoV9_0100");
    std::string moduleName = "m1";
    std::string extension = "test-extension";
    MockInstallExtension(BUNDLE_NAME_TEST, moduleName, extension);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    ExtensionAbilityInfo extensionInfo;
    int32_t flags = static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION);
    int32_t appIndex = -1;
    ErrCode ret = GetBundleDataMgr()->ExplicitQueryExtensionInfoV9(want, flags, 0, extensionInfo, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("ExplicitQueryExtensionInfoV9_0100 finish");
}

/**
 * @tc.number: ImplicitQueryCurExtensionInfosV9_0100
 * @tc.name: test ImplicitQueryCurExtensionInfosV9
 * @tc.desc: 1.explicit query curextension info success
 */
HWTEST_F(BmsBundleKitServiceTest, ImplicitQueryCurExtensionInfosV9_0100, Function | SmallTest | Level1)
{
    APP_LOGI("begin of ImplicitQueryCurExtensionInfosV9_0100");
    std::string moduleName = "m1";
    std::string extension = "test-extension";
    MockInstallExtension(BUNDLE_NAME_TEST, moduleName, extension);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<ExtensionAbilityInfo> infos;
    int32_t flags = static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION);
    int32_t appIndex = -1;
    ErrCode ret = GetBundleDataMgr()->ImplicitQueryCurExtensionInfosV9(want, flags, 0, infos, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("ImplicitQueryCurExtensionInfosV9_0100 finish");
}

/**
 * @tc.number: ImplicitQueryCurExtensionInfosV9_0200
 * @tc.name: test ImplicitQueryCurExtensionInfosV9
 * @tc.desc: 1.explicit query curextension info success
 */
HWTEST_F(BmsBundleKitServiceTest, ImplicitQueryCurExtensionInfosV9_0200, Function | SmallTest | Level1)
{
    APP_LOGI("begin of ImplicitQueryCurExtensionInfosV9_0200");
    std::string moduleName = "m1";
    std::string extension = "test-extension";
    MockInstallExtension(BUNDLE_NAME_TEST, moduleName, extension);
    Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", "");
    std::vector<ExtensionAbilityInfo> infos;
    int32_t flags = static_cast<int32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_DEFAULT);
    int32_t appIndex = -1;
    ErrCode ret = GetBundleDataMgr()->ImplicitQueryCurExtensionInfosV9(want, flags, 0, infos, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("ImplicitQueryCurExtensionInfosV9_0200 finish");
}

/**
 * @tc.number: GetMediaData_0100
 * @tc.name: test GetMediaData
 * @tc.desc: 1.explicit get mediadata failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetMediaData_0100, Function | SmallTest | Level1)
{
    APP_LOGI("begin of GetMediaData_0100");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::unique_ptr<uint8_t[]> mediaDataPtr;
    size_t len = 0;
    ErrCode ret = GetBundleDataMgr()->GetMediaData(BUNDLE_NAME_TEST1, MODULE_NAME_TEST, ABILITY_NAME_TEST,
        mediaDataPtr, len, 0);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("GetMediaData_0100 finish");
}

/**
 * @tc.number: GetMediaData_0200
 * @tc.name: test GetMediaData
 * @tc.desc: 1.explicit get mediadata failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetMediaData_0200, Function | SmallTest | Level1)
{
    APP_LOGI("begin of GetMediaData_0200");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::unique_ptr<uint8_t[]> mediaDataPtr;
    size_t len = 0;
    ErrCode ret = GetBundleDataMgr()->GetMediaData(BUNDLE_NAME_TEST, "", ABILITY_NAME_TEST,
        mediaDataPtr, len, 0);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("GetMediaData_0200 finish");
}

/**
 * @tc.number: GetMediaData_0200
 * @tc.name: test GetMediaData
 * @tc.desc: 1.explicit get mediadata failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetMediaData_0300, Function | SmallTest | Level1)
{
    APP_LOGI("begin of GetMediaData_0300");
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::unique_ptr<uint8_t[]> mediaDataPtr;
    size_t len = 0;
    ErrCode ret = GetBundleDataMgr()->GetMediaData(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST1,
        mediaDataPtr, len, 0);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
    MockUninstallBundle(BUNDLE_NAME_TEST);
    APP_LOGI("GetMediaData_0300 finish");
}

/**
 * @tc.number: Hidump_001
 * @tc.name: Hidump
 * @tc.desc: 1.Returns whether the interface is called successfully
 */
HWTEST_F(BmsBundleKitServiceTest, Hidump_001, Function | SmallTest | Level1)
{
    std::vector<std::string> args;
    std::string result;
    bool testRet = bundleMgrService_->Hidump(args, result);
    EXPECT_EQ(testRet, true);
    args.emplace_back("1");
    testRet = bundleMgrService_->Hidump(args, result);
    EXPECT_EQ(testRet, true);
    args.emplace_back("2");
    testRet = bundleMgrService_->Hidump(args, result);
    EXPECT_EQ(testRet, true);
    args.emplace_back("3");
    testRet = bundleMgrService_->Hidump(args, result);
    EXPECT_EQ(testRet, true);
}

/**
 * @tc.number: GetApplicationInfoV9_0100
 * @tc.name: Test GetApplicationInfoV9
 * @tc.desc: 1.Test the GetApplicationInfoV9 by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfoV9_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ApplicationInfo result;
    auto flag = ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION;
    ErrCode ret = hostImpl->GetApplicationInfoV9(
        BUNDLE_NAME_DEMO, flag, DEFAULT_USER_ID_TEST, result);
    EXPECT_EQ(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetApplicationInfosV9_0100
 * @tc.name: Test GetApplicationInfosV9
 * @tc.desc: 1.Test the GetApplicationInfosV9 by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfosV9_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<ApplicationInfo> appInfos;
    auto flag = ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION;
    ErrCode ret = hostImpl->GetApplicationInfosV9(flag, DEFAULT_USER_ID_TEST, appInfos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetApplicationInfosV9_0200
 * @tc.name: Test the GetApplicationInfosV9 by BundleMgrHostImpl
 * @tc.desc: 1.system run normally
 *           2.add cloneInfo
 *           3.get all installed application info and the clones successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfosV9_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX1);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX2);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX3);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<ApplicationInfo> appInfos;
    int32_t flags = static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT);
    ErrCode ret = hostImpl->GetApplicationInfosV9(flags, DEFAULT_USER_ID_TEST, appInfos);
    EXPECT_EQ(ret, ERR_OK);
    int index = 0;
    for (ApplicationInfo appInfo : appInfos) {
        if (appInfo.bundleName == BUNDLE_NAME_TEST) {
            EXPECT_EQ(appInfo.appIndex, index++);
        }
    }

    ClearCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetApplicationInfosV9_0300
 * @tc.name: test can get the installed bundles and cloneApp's application info
 * @tc.desc: 1.system run normally
 *           2.add cloneInfo
 *           3.disable main app
 *           4.get all installed application info and the clones successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfosV9_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX1);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX2);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX3);

    EXPECT_TRUE(ChangeAppDisabledStatus(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, 0, false));

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<ApplicationInfo> appInfos;
    int32_t flags = static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT);
    ErrCode ret = hostImpl->GetApplicationInfosV9(flags, DEFAULT_USER_ID_TEST, appInfos);
    EXPECT_EQ(ret, ERR_OK);
    int index = 1;
    for (ApplicationInfo appInfo : appInfos) {
        if (appInfo.bundleName == BUNDLE_NAME_TEST) {
            EXPECT_EQ(appInfo.appIndex, index++);
        }
    }
    QueryCloneApplicationInfosV9WithDisable();

    ClearCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetApplicationInfosV9_0400
 * @tc.name: test can get the installed bundles and cloneApp's application info
 * @tc.desc: 1.system run normally
 *           2.add cloneInfo
 *           3.disable clone app
 *           4.get all installed application info and the clones successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfosV9_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX1);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX2);
    AddCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX3);

    EXPECT_TRUE(ChangeAppDisabledStatus(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST, TEST_APP_INDEX2, false));

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<ApplicationInfo> appInfos;
    int32_t flags = static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT);
    ErrCode ret = hostImpl->GetApplicationInfosV9(flags, DEFAULT_USER_ID_TEST, appInfos);
    EXPECT_EQ(ret, ERR_OK);
    int index = 0;
    for (ApplicationInfo appInfo : appInfos) {
        if (appInfo.bundleName == BUNDLE_NAME_TEST) {
            EXPECT_EQ(appInfo.appIndex, index++);
        }
        if (index == 2) {
            index++;
        }
    }
    QueryCloneApplicationInfosV9WithDisable();

    ClearCloneInfo(BUNDLE_NAME_TEST, DEFAULT_USER_ID_TEST);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBundleInfoV9_0100
 * @tc.name: Test GetBundleInfoV9
 * @tc.desc: 1.Test the GetBundleInfoV9 by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfoV9_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo result;
    ErrCode ret = hostImpl->GetBundleInfoV9(BUNDLE_NAME_DEMO, GET_BUNDLE_WITH_ABILITIES |
        GET_BUNDLE_WITH_REQUESTED_PERMISSION, result, DEFAULT_USERID);

    EXPECT_EQ(ret, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetBundleInfoV9_0200
 * @tc.name: Test GetBundleInfoV9 with skill flag
 * @tc.desc: 1.Test the GetBundleInfoV9 by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfoV9_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo result_ability;
    int32_t flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SKILL);
    ErrCode ret_ability = hostImpl->GetBundleInfoV9(BUNDLE_NAME_DEMO, flags, result_ability, DEFAULT_USERID);
    EXPECT_EQ(ret_ability, ERR_OK);
    flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SKILL);
    BundleInfo result_extension;
    ErrCode ret_extension = hostImpl->GetBundleInfoV9(BUNDLE_NAME_DEMO, flags, result_extension, DEFAULT_USERID);
    EXPECT_EQ(ret_extension, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}


/**
 * @tc.number: GetUidByBundleName
 * @tc.name: Test GetUidByBundleName
 * @tc.desc: 1.Test the GetUidByBundleName by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetUidByBundleName_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundleInfo result;
    ErrCode ret = hostImpl->GetBundleInfoV9(BUNDLE_NAME_DEMO, GET_BUNDLE_WITH_ABILITIES |
        GET_BUNDLE_WITH_REQUESTED_PERMISSION, result, DEFAULT_USERID);
    int32_t uid = hostImpl->GetUidByBundleName(BUNDLE_NAME_DEMO, DEFAULT_USERID);
    EXPECT_EQ(uid, result.uid);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetBundleInfosImpl_0100
 * @tc.name: Test GetBundleInfos
 * @tc.desc: 1.Test the GetBundleInfos by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfosImpl_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<BundleInfo> bundleInfos;
    bool ret = hostImpl->GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, DEFAULT_USERID);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetBundleInfosImpl_0200
 * @tc.name: Test GetBundleInfos
 * @tc.desc: 1.Test the GetBundleInfos by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfosImpl_0200, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo info;
    info.bundleUserInfo.userId = DEFAULT_USERID;
    innerBundleUserInfos["_100"] = info;
    innerBundleInfo.innerBundleUserInfos_ = innerBundleUserInfos;
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.emplace(
        BUNDLE_NAME_DEMO, innerBundleInfo);
    std::vector<BundleInfo> bundleInfos;
    bool ret = hostImpl->GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, DEFAULT_USERID);
    EXPECT_TRUE(ret);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetNameForUidImpl_0100
 * @tc.name: test GetNameForUid
 * @tc.desc: 1.Test the GetNameForUid by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetNameForUidImpl_0100, Function | SmallTest | Level1)
{
    std::string name;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    auto ret = hostImpl->GetNameForUid(DEMO_UID, name);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_UID);
    hostImpl->isBrokerServiceExisted_ = true;
    ret = hostImpl->GetNameForUid(DEMO_UID, name);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_UID);
}

/**
 * @tc.number: GetNameAndIndexForUidImpl_0100
 * @tc.name: test GetNameAndIndexForUid
 * @tc.desc: 1.Test the GetNameAndIndexForUid by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetNameAndIndexForUidImpl_0100, Function | SmallTest | Level1)
{
    int32_t appIndex = -1;
    std::string name;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    auto ret = hostImpl->GetNameAndIndexForUid(DEMO_UID, name, appIndex);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_UID);
}

/**
 * @tc.number: GetSimpleAppInfoForUid_0100
 * @tc.name: test GetSimpleAppInfoForUid
 * @tc.desc: 1.Test the GetSimpleAppInfoForUid by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetSimpleAppInfoForUidImpl_0100, Function | SmallTest | Level1)
{
    std::vector<std::int32_t> uids;
    std::vector<SimpleAppInfo> simpleAppInfo;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    auto ret = hostImpl->GetSimpleAppInfoForUid(uids, simpleAppInfo);
    EXPECT_EQ(ret, ERR_OK);

    uids.emplace_back(DEMO_UID);
    ret = hostImpl->GetSimpleAppInfoForUid(uids, simpleAppInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: QueryAbilityInfoImpl_0100
 * @tc.name: test QueryAbilityInfo
 * @tc.desc: 1.Test the QueryAbilityInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfoImpl_0100, Function | SmallTest | Level1)
{
    Want want;
    AbilityInfo abilityInfo;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    auto ret = hostImpl->QueryAbilityInfo(want, abilityInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetHapModuleInfoImpl_0100
 * @tc.name: test GetHapModuleInfo
 * @tc.desc: 1.Test the GetHapModuleInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetHapModuleInfoImpl_0100, Function | SmallTest | Level1)
{
    AbilityInfo abilityInfo;
    HapModuleInfo hapModuleInfo;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    auto ret = hostImpl->GetHapModuleInfo(abilityInfo, hapModuleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CompileProcessAOT_0100
 * @tc.name: test CompileProcessAOT
 * @tc.desc: 1.Test the CompileProcessAOT by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, CompileProcessAOT_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::string bundleName;
    std::string compileMode = "test";
    std::vector<std::string> compileResults;
    ErrCode ret = hostImpl->CompileProcessAOT(bundleName, compileMode, true, compileResults);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED);
}

/**
 * @tc.number: CompileReset_0100
 * @tc.name: test CompileReset
 * @tc.desc: 1.Test the CompileReset by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, CompileReset_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::string bundleName;
    ErrCode ret = hostImpl->CompileReset(bundleName, true);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CopyAp_0100
 * @tc.name: test CopyAp
 * @tc.desc: 1.Test the CopyAp by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, CopyAp_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::string bundleName;
    std::vector<std::string> compileResults;
    ErrCode ret = hostImpl->CopyAp(bundleName, true, compileResults);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: IsCloneApplicationEnabled_0100
 * @tc.name: test IsCloneApplicationEnabled
 * @tc.desc: 1.Test the IsCloneApplicationEnabled by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, IsCloneApplicationEnabled_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::string bundleName;
    int32_t appIndex = 0;
    bool isEnable;
    ErrCode ret = hostImpl->IsCloneApplicationEnabled(bundleName, appIndex, isEnable);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: IsCloneAbilityEnabled_0100
 * @tc.name: test IsCloneAbilityEnabled
 * @tc.desc: 1.Test the IsCloneAbilityEnabled by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, IsCloneAbilityEnabled_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    AbilityInfo abilityInfo;
    int32_t appIndex = 0;
    bool isEnable;
    ErrCode ret = hostImpl->IsCloneAbilityEnabled(abilityInfo, appIndex, isEnable);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: SetCloneAbilityEnabled_0100
 * @tc.name: test SetCloneAbilityEnabled
 * @tc.desc: 1.Test the SetCloneAbilityEnabled by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, SetCloneAbilityEnabled_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    AbilityInfo abilityInfo;
    int32_t appIndex = 0;
    bool isEnable = false;
    ErrCode ret = hostImpl->SetCloneAbilityEnabled(abilityInfo, appIndex, isEnable, Constants::UNSPECIFIED_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: SetCloneAbilityEnabled_0200
 * @tc.name: test SetCloneAbilityEnabled
 * @tc.desc: 1.Test the SetCloneAbilityEnabled by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, SetCloneAbilityEnabled_0200, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    AbilityInfo abilityInfo;
    abilityInfo.bundleName = BUNDLE_NAME_TEST;
    abilityInfo.name = BUNDLE_NAME_TEST;
    int32_t appIndex = 1;
    bool isEnable = true;
    ErrCode ret = hostImpl->SetCloneAbilityEnabled(abilityInfo, appIndex, isEnable, Constants::DEFAULT_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: VerifyCallingPermission_0100
 * @tc.name: test VerifyCallingPermission
 * @tc.desc: 1.Test the VerifyCallingPermission by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, VerifyCallingPermission_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::string permission;
    bool ret = hostImpl->VerifyCallingPermission(permission);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: FilterAbilityInfos_0100
 * @tc.name: test FilterAbilityInfos
 * @tc.desc: 1.Test the FilterAbilityInfos by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, FilterAbilityInfos_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<AbilityInfo> abilityInfos;
    AbilityInfo abilityInfo;
    abilityInfo.kind = APP_LINKING;
    abilityInfos.push_back(abilityInfo);
    hostImpl->FilterAbilityInfos(abilityInfos);
    EXPECT_FALSE(abilityInfos.empty());
}

/**
 * @tc.number: FilterAbilityInfos_0200
 * @tc.name: test FilterAbilityInfos
 * @tc.desc: 1.Test the FilterAbilityInfos by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, FilterAbilityInfos_0200, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<AbilityInfo> abilityInfos;
    AbilityInfo abilityInfo;
    abilityInfos.push_back(abilityInfo);
    hostImpl->FilterAbilityInfos(abilityInfos);
    EXPECT_FALSE(abilityInfos.empty());
}

/**
 * @tc.number: GetAbilityInfo_0100
 * @tc.name: test GetAbilityInfo
 * @tc.desc: 1.Test the GetAbilityInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetAbilityInfo_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::string bundleName;
    std::string abilityName;
    AbilityInfo abilityInfo;
    bool ret = hostImpl->GetAbilityInfo(bundleName, abilityName, abilityInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsU1Enable_0001
 * @tc.name: Test IsU1Enable
 * @tc.desc: 1.Test IsU1Enable of InnerBundleInfo, acls has PERMISSION_U1_ENABLED
 */
HWTEST_F(BmsBundleKitServiceTest, IsU1Enable_0001, Function | SmallTest | Level1)
{
    std::vector<std::string> acls;
    acls.push_back(std::string(Constants::PERMISSION_U1_ENABLED));
    InnerBundleInfo info;
    bool isU1Enable = info.IsU1Enable();
    EXPECT_FALSE(isU1Enable);
    info.SetAllowedAcls(acls);
    isU1Enable = info.IsU1Enable();
    EXPECT_TRUE(isU1Enable);
}

/**
 * @tc.number: NotifyBundleStatus_0100
 * @tc.name: test NotifyBundleStatus
 * @tc.desc: 1.NotifyBundleStatus
 */
HWTEST_F(BmsBundleKitServiceTest, NotifyBundleStatus_0100, Function | SmallTest | Level1)
{
    sptr<MockBundleStatus> bundleStatusCallback = new (std::nothrow) MockBundleStatus();
    bundleStatusCallback->SetBundleName(HAP_FILE_PATH);
    bool result = GetBundleDataMgr()->RegisterBundleStatusCallback(bundleStatusCallback);
    EXPECT_TRUE(result);
    EXPECT_NE(commonEventMgr_, nullptr);
    installRes_.uid = 1;
    commonEventMgr_->NotifyBundleStatus(installRes_, GetBundleDataMgr());
    int32_t callbackResult = bundleStatusCallback->GetResultCode();
    EXPECT_EQ(callbackResult, ERR_OK);
}

/**
 * @tc.number: NotifyBundleStatus_0200
 * @tc.name: test NotifyBundleStatus
 * @tc.desc: 1.NotifyBundleStatus
 */
HWTEST_F(BmsBundleKitServiceTest, NotifyBundleStatus_0200, Function | SmallTest | Level1)
{
    sptr<MockBundleStatus> bundleStatusCallback = new (std::nothrow) MockBundleStatus();
    bundleStatusCallback->SetBundleName(HAP_FILE_PATH);
    bool result = GetBundleDataMgr()->RegisterBundleStatusCallback(bundleStatusCallback);
    EXPECT_TRUE(result);
    EXPECT_NE(commonEventMgr_, nullptr);
    installRes_.uid = 1;
    installRes_.type = NotifyType::START_INSTALL;
    commonEventMgr_->NotifyBundleStatus(installRes_, GetBundleDataMgr());
    int32_t callbackResult = bundleStatusCallback->GetResultCode();
    EXPECT_EQ(callbackResult, ERR_TIMED_OUT);
}

/**
 * @tc.number: NotifyBundleStatus_0300
 * @tc.name: test NotifyBundleStatus
 * @tc.desc: 1.NotifyBundleStatus
 */
HWTEST_F(BmsBundleKitServiceTest, NotifyBundleStatus_0300, Function | SmallTest | Level1)
{
    sptr<MockBundleStatus> bundleStatusCallback = new (std::nothrow) MockBundleStatus();
    bundleStatusCallback->SetBundleName(HAP_FILE_PATH);
    bool result = GetBundleDataMgr()->RegisterBundleStatusCallback(bundleStatusCallback);
    EXPECT_TRUE(result);
    EXPECT_NE(commonEventMgr_, nullptr);
    installRes_.uid = 1;
    installRes_.type = NotifyType::INSTALL;
    installRes_.bundleName = BUNDLE_NAME;
    commonEventMgr_->NotifyBundleStatus(installRes_, GetBundleDataMgr());
    int32_t callbackResult = bundleStatusCallback->GetResultCode();
    EXPECT_EQ(callbackResult, ERR_TIMED_OUT);
}

/**
 * @tc.number: Mgr_Proxy_SetShortcutVisibleForSelf_0100
 * @tc.name: test BundleMgrProxy interface SetShortcutVisibleForSelf
 */
HWTEST_F(BmsBundleKitServiceTest, Mgr_Proxy_SetShortcutVisibleForSelf_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string shortcutId = "shortcutId";
    bool visible = true;
    auto ret = bundleMgrProxy->SetShortcutVisibleForSelf(shortcutId, visible);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: Mgr_Proxy_GetAllShortcutInfoForSelf_0100
 * @tc.name: test BundleMgrProxy interface GetAllShortcutInfoForSelf
 */
HWTEST_F(BmsBundleKitServiceTest, Mgr_Proxy_GetAllShortcutInfoForSelf_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::vector<ShortcutInfo> shortcutInfos;
    auto ret = bundleMgrProxy->GetAllShortcutInfoForSelf(shortcutInfos);
    EXPECT_NE(ret, ERR_OK);
}
}
