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
const int32_t WAIT_TIME = 1; // init mocked bms
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

InnerAbilityInfo BmsBundleKitServiceTest::MockAbilityInfo(
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
    InnerAbilityInfo innerAbilityInfo = MockAbilityInfo(bundleName, moduleName, abilityName);
    std::string keyName = bundleName + "." + moduleName + "." + abilityName;
    innerBundleInfo.InsertAbilitiesInfo(keyName, innerAbilityInfo);
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
 * @tc.number: GetBundleStats_0100
 * @tc.name: test GetBundleStats
 * @tc.desc: 1.Test the GetBundleStats by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleStats_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<int64_t> bundleStats;
    int32_t appIndex = 0;
    hostImpl->isBrokerServiceExisted_ = true;
    bool ret = hostImpl->GetBundleStats(BUNDLE_NAME_TEST, DEFAULT_USERID, bundleStats, appIndex);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetBundleStats_0200
 * @tc.name: test GetBundleStats
 * @tc.desc: 1.Test the GetBundleStats by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleStats_0200, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<int64_t> bundleStats;
    int32_t appIndex = 0;
    bool ret = hostImpl->GetBundleStats("", DEFAULT_USERID, bundleStats, appIndex);
    EXPECT_FALSE(ret);
    ret = hostImpl->GetBundleStats(BUNDLE_NAME_TEST, DEFAULT_USERID, bundleStats, appIndex);
    EXPECT_FALSE(ret);
    appIndex = -1;
    ret = hostImpl->GetBundleStats(BUNDLE_NAME_TEST, DEFAULT_USERID, bundleStats, appIndex);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SetBrokerServiceStatus_0100
 * @tc.name: test SetBrokerServiceStatus
 * @tc.desc: 1.Test the SetBrokerServiceStatus by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, SetBrokerServiceStatus_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    hostImpl->SetBrokerServiceStatus(true);
    EXPECT_TRUE(hostImpl->isBrokerServiceExisted_);
}

/**
 * @tc.number: QueryExtensionAbilityInfosWithTypeName_0100
 * @tc.name: test QueryExtensionAbilityInfosWithTypeName
 * @tc.desc: 1.Test the QueryExtensionAbilityInfosWithTypeName by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosWithTypeName_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    Want want;
    want.SetElementName(BUNDLE_NAME_TEST, ABILITY_NAME_TEST);
    want.SetModuleName(MODULE_NAME_TEST);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t flags = 1;
    ErrCode ret =
        hostImpl->QueryExtensionAbilityInfosWithTypeName(want, TYPE_001, flags, DEFAULT_USERID, extensionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: QueryExtensionAbilityInfosWithTypeName_0200
 * @tc.name: test QueryExtensionAbilityInfosWithTypeName
 * @tc.desc: 1.Test the QueryExtensionAbilityInfosWithTypeName by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosWithTypeName_0200, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    Want want;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t flags = 1;
    ErrCode ret = hostImpl->QueryExtensionAbilityInfosWithTypeName(want, "", flags, DEFAULT_USERID, extensionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: QueryExtensionAbilityInfosOnlyWithTypeName_0100
 * @tc.name: test QueryExtensionAbilityInfosOnlyWithTypeName
 * @tc.desc: 1.Test the QueryExtensionAbilityInfosOnlyWithTypeName by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosOnlyWithTypeName_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    std::string typeName = TYPE_001;
    int32_t flags = 1;
    ErrCode ret = hostImpl->QueryExtensionAbilityInfosOnlyWithTypeName(typeName, flags, DEFAULT_USERID, extensionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: QueryExtensionAbilityInfosOnlyWithTypeName_0200
 * @tc.name: test QueryExtensionAbilityInfosOnlyWithTypeName
 * @tc.desc: 1.Test the QueryExtensionAbilityInfosOnlyWithTypeName by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosOnlyWithTypeName_0200, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    std::string typeName = "";
    int32_t flags = 1;
    ErrCode ret = hostImpl->QueryExtensionAbilityInfosOnlyWithTypeName(typeName, flags, DEFAULT_USERID, extensionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: ResetAOTCompileStatus_0100
 * @tc.name: test ResetAOTCompileStatus
 * @tc.desc: 1.Test the ResetAOTCompileStatus by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, ResetAOTCompileStatus_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    int32_t triggerMode = 1;
    ErrCode ret = hostImpl->ResetAOTCompileStatus(BUNDLE_NAME_TEST, MODULE_NAME_TEST, triggerMode);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetJsonProfile_0100
 * @tc.name: test GetJsonProfile
 * @tc.desc: 1.Test the GetJsonProfile by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetJsonProfile_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::string profile;
    ErrCode ret = hostImpl->GetJsonProfile(
        ProfileType::UTD_SDT_PROFILE, BUNDLE_NAME_TEST, MODULE_NAME_TEST, profile, DEFAULT_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetUninstalledBundleInfo_0100
 * @tc.name: test GetUninstalledBundleInfo
 * @tc.desc: 1.Test the GetUninstalledBundleInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetUninstalledBundleInfo_0100, Function | SmallTest | Level1)
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
    BundleInfo bundleInfo;
    ErrCode ret = hostImpl->GetUninstalledBundleInfo(BUNDLE_NAME_DEMO, bundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FAILED_GET_BUNDLE_INFO);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetUninstalledBundleInfo_0200
 * @tc.name: test GetUninstalledBundleInfo
 * @tc.desc: 1.Test the GetUninstalledBundleInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetUninstalledBundleInfo_0200, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    BundleInfo bundleInfo;
    ErrCode ret = hostImpl->GetUninstalledBundleInfo(BUNDLE_NAME_DEMO, bundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FAILED_GET_BUNDLE_INFO);
}

/**
 * @tc.number: ClearCache_0100
 * @tc.name: test ClearCache
 * @tc.desc: 1.Test the ClearCache by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, ClearCache_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    sptr<ICleanCacheCallback> cleanCacheCallback = new (std::nothrow) ICleanCacheCallbackTest();
    int32_t uid = 0;
    std::string callingBundleName;
    ErrCode ret = hostImpl->ClearCache(BUNDLE_NAME_DEMO, cleanCacheCallback, DEFAULT_USERID, uid, callingBundleName);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: IsBundleExist_0100
 * @tc.name: test IsBundleExist
 * @tc.desc: 1.Test the IsBundleExist by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, IsBundleExist_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    bool ret = hostImpl->IsBundleExist(BUNDLE_NAME_DEMO);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CanOpenLink_0100
 * @tc.name: test CanOpenLink
 * @tc.desc: 1.Test the CanOpenLink by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, CanOpenLink_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    bool canOpen;
    ErrCode ret = hostImpl->CanOpenLink(BUNDLE_NAME_DEMO, canOpen);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SCHEME_NOT_IN_QUERYSCHEMES);
}

/**
 * @tc.number: GetAllPreinstalledApplicationInfos_0100
 * @tc.name: test GetAllPreinstalledApplicationInfos
 * @tc.desc: 1.Test the GetAllPreinstalledApplicationInfos by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllPreinstalledApplicationInfos_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<PreinstalledApplicationInfo> preinstalledApplicationInfos;
    ErrCode ret = hostImpl->GetAllPreinstalledApplicationInfos(preinstalledApplicationInfos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetAllBundleInfoByDeveloperId_0100
 * @tc.name: test GetAllBundleInfoByDeveloperId
 * @tc.desc: 1.Test the GetAllBundleInfoByDeveloperId by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllBundleInfoByDeveloperId_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::string developerId;
    std::vector<BundleInfo> bundleInfos;
    ErrCode ret = hostImpl->GetAllBundleInfoByDeveloperId(developerId, bundleInfos, DEFAULT_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_DEVELOPERID);
}

/**
 * @tc.number: GetDeveloperIds_0100
 * @tc.name: test GetDeveloperIds
 * @tc.desc: 1.Test the GetDeveloperIds by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetDeveloperIds_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::string appDistributionType;
    std::vector<std::string> developerIdList;
    ErrCode ret = hostImpl->GetDeveloperIds(appDistributionType, developerIdList, DEFAULT_USERID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: SwitchUninstallState_0100
 * @tc.name: test SwitchUninstallState
 * @tc.desc: 1.Test the SwitchUninstallState by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, SwitchUninstallState_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    ErrCode ret = hostImpl->SwitchUninstallState(BUNDLE_NAME_DEMO, true, false);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: SwitchUninstallStateByUserId_0100
 * @tc.name: test SwitchUninstallStateByUserId
 * @tc.desc: 1.Test the SwitchUninstallStateByUserId by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, SwitchUninstallStateByUserId_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    ErrCode ret = hostImpl->SwitchUninstallStateByUserId(BUNDLE_NAME_DEMO, true, 100);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: QueryAbilityInfoByContinueType_0100
 * @tc.name: test QueryAbilityInfoByContinueType
 * @tc.desc: 1.Test the QueryAbilityInfoByContinueType by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfoByContinueType_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    AbilityInfo abilityInfo;
    ErrCode ret = hostImpl->QueryAbilityInfoByContinueType(BUNDLE_NAME_DEMO, TYPE_001, abilityInfo, DEFAULT_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: QueryCloneAbilityInfo_0100
 * @tc.name: test QueryCloneAbilityInfo
 * @tc.desc: 1.Test the QueryCloneAbilityInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, QueryCloneAbilityInfo_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    ElementName element;
    int32_t flags = 1;
    int32_t appIndex = 0;
    AbilityInfo abilityInfo;
    ErrCode ret = hostImpl->QueryCloneAbilityInfo(element, flags, appIndex, abilityInfo, DEFAULT_USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_CLONE_QUERY_PARAM_ERROR);
}

/**
 * @tc.number: GetCloneBundleInfo_0100
 * @tc.name: test GetCloneBundleInfo
 * @tc.desc: 1.Test the GetCloneBundleInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetCloneBundleInfo_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    int32_t flags = 1;
    int32_t appIndex = 0;
    BundleInfo bundleInfo;
    ErrCode ret = hostImpl->GetCloneBundleInfo(BUNDLE_NAME_DEMO, flags, appIndex, bundleInfo, DEFAULT_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetCloneAppIndexes_0100
 * @tc.name: test GetCloneAppIndexes
 * @tc.desc: 1.Test the GetCloneAppIndexes by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetCloneAppIndexes_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::vector<int32_t> appIndexes;
    ErrCode ret = hostImpl->GetCloneAppIndexes(BUNDLE_NAME_DEMO, appIndexes, DEFAULT_USERID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: QueryCloneExtensionAbilityInfoWithAppIndex_0100
 * @tc.name: test QueryCloneExtensionAbilityInfoWithAppIndex
 * @tc.desc: 1.Test the QueryCloneExtensionAbilityInfoWithAppIndex by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, QueryCloneExtensionAbilityInfoWithAppIndex_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    ElementName element;
    int32_t flags = 1;
    int32_t appIndex = 0;
    ExtensionAbilityInfo extensionAbilityInfo;
    ErrCode ret = hostImpl->QueryCloneExtensionAbilityInfoWithAppIndex(
        element, flags, appIndex, extensionAbilityInfo, DEFAULT_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: GetBundlePackInfo_0100
 * @tc.name: Test GetBundlePackInfo
 * @tc.desc: 1.Test the GetBundlePackInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundlePackInfo_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    BundlePackInfo bundlePackInfo;
    auto ret = hostImpl->GetBundlePackInfo(
        BUNDLE_NAME_DEMO, GET_PACK_INFO_ALL, bundlePackInfo, DEFAULT_USERID);
    EXPECT_EQ(ret, ERR_OK);

    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetBundlePackInfo_0200
 * @tc.name: Test GetBundlePackInfo
 * @tc.desc: 1.Test the GetBundlePackInfo
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundlePackInfo_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    BundlePackInfo bundlePackInfo;
    auto ret = dataMgr->GetBundlePackInfo(
        BUNDLE_NAME_DEMO, GET_PACK_INFO_ALL, bundlePackInfo, Constants::UNSPECIFIED_USERID);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetBundleUserInfo_0100
 * @tc.name: Test GetBundleUserInfo
 * @tc.desc: 1.Test the GetBundleUserInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleUserInfo_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    InnerBundleUserInfo innerBundleUserInfo;
    auto ret = hostImpl->GetBundleUserInfo(
        BUNDLE_NAME_DEMO, DEFAULT_USERID, innerBundleUserInfo);
    EXPECT_EQ(ret, true);

    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    ret = hostImpl->GetBundleUserInfos(
        BUNDLE_NAME_DEMO, innerBundleUserInfos);
    EXPECT_EQ(ret, true);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetBundleArchiveInfoBySandBoxPath_0100
 * @tc.name: Test GetBundleArchiveInfoBySandBoxPath
 * @tc.desc: 1.Test the GetBundleUserInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleArchiveInfoBySandBoxPath_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::string hapFilePath = "";
    int32_t flags = 1;
    BundleInfo bundleInfo;
    bool fromV9 = false;
    auto ret = hostImpl->GetBundleArchiveInfoBySandBoxPath(
        hapFilePath, flags, bundleInfo, fromV9);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: GetBundleGids_0100
 * @tc.name: Test GetBundleGids
 * @tc.desc: 1.Test the GetBundleGids by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleGids_0100, Function | MediumTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_DEMO, MODULE_NAME_DEMO, ABILITY_NAME_DEMO);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<int> gids;
    auto ret = hostImpl->GetBundleGids(BUNDLE_NAME_DEMO, gids);
    EXPECT_EQ(ret, true);
    MockUninstallBundle(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: GetBundleGidsByUid_0100
 * @tc.name: Test GetBundleGidsByUid
 * @tc.desc: 1.Test the GetBundleGidsByUid by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleGidsByUid_0100, Function | MediumTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<int> gids;
    auto ret = hostImpl->GetBundleGidsByUid(BUNDLE_NAME_TEST, TEST_UID, gids);
    EXPECT_EQ(ret, true);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: QueryAllAbilityInfos_0100
 * @tc.name: Test QueryAllAbilityInfos
 * @tc.desc: 1.Test the QueryAllAbilityInfos by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAllAbilityInfos_0100, Function | MediumTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME_TEST);
    name.SetBundleName(BUNDLE_NAME_TEST);
    want.SetElement(name);
    std::vector<AbilityInfo> AbilityInfo;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    auto ret = hostImpl->QueryAllAbilityInfos(want, DEFAULT_USERID, AbilityInfo);
    EXPECT_EQ(ret, true);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: DumpShortcutInfo_0100
 * @tc.name: Test DumpShortcutInfo
 * @tc.desc: 1.Test the DumpShortcutInfo by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, DumpShortcutInfo_0100, Function | MediumTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t userId = Constants::ALL_USERID;
    std::string result;
    auto ret = hostImpl->DumpShortcutInfo("ohos.test.error", userId, result);
    EXPECT_EQ(ret, false);
    EXPECT_NE(result.empty(), false);
    ret = hostImpl->DumpShortcutInfo(BUNDLE_NAME_TEST, userId, result);
    EXPECT_EQ(ret, true);
    EXPECT_NE(result.empty(), true);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SetModuleRemovable_0100
 * @tc.name: Test SetModuleRemovable
 * @tc.desc: 1.Test the SetModuleRemovable by BundleMgrHostImpl
 * @tc.require: issueI7FMPK
 */
HWTEST_F(BmsBundleKitServiceTest, SetModuleRemovable_0100, Function | MediumTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool isRemovable;
    auto ret1 = hostImpl->SetModuleRemovable(
        BUNDLE_NAME_TEST, MODULE_NAME_TEST, true);
    EXPECT_EQ(ret1, true);

    ErrCode ret2 = hostImpl->IsModuleRemovable(
        BUNDLE_NAME_TEST, MODULE_NAME_TEST, isRemovable);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_TRUE(isRemovable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SetModuleRemovable_0200
 * @tc.name: Test SetModuleRemovable
 * @tc.desc: 1.Test the SetModuleRemovable by BundleMgrHostImpl
 * @tc.require: issueI7FMPK
 */
HWTEST_F(BmsBundleKitServiceTest, SetModuleRemovable_0200, Function | MediumTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool isRemovable;
    auto ret1 = hostImpl->SetModuleRemovable(
        BUNDLE_NAME_TEST, MODULE_NAME_TEST, false);
    EXPECT_EQ(ret1, true);

    ErrCode ret2 = hostImpl->IsModuleRemovable(
        BUNDLE_NAME_TEST, MODULE_NAME_TEST, isRemovable);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_FALSE(isRemovable);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetModuleUpgradeFlag_0100
 * @tc.name: test can get the module upgrade flag
 * @tc.desc: 1.system run normally
 *           2.set module upgrade flag successfully
 *           3.get module upgrade flag successfully
 */
HWTEST_F(BmsBundleKitServiceTest, GetModuleUpgradeFlag_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ErrCode result = hostImpl->SetModuleUpgradeFlag(BUNDLE_NAME_TEST, MODULE_NAME_TEST, 1);
    EXPECT_TRUE(result == ERR_OK);
    auto res = hostImpl->GetModuleUpgradeFlag(BUNDLE_NAME_TEST, MODULE_NAME_TEST);
    EXPECT_TRUE(res);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetShortcutInfoV9_0100
 * @tc.name: test query archive information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.query archive information without an ability information
 */
HWTEST_F(BmsBundleKitServiceTest, GetShortcutInfoV9_0100, Function | MediumTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<ShortcutInfo> shortcutInfos;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ErrCode testRet = hostImpl->GetShortcutInfoV9(BUNDLE_NAME_TEST, shortcutInfos);
    EXPECT_EQ(testRet, ERR_OK);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetShortcutInfoByAppIndex_0100
 * @tc.name: test query archive information
 * @tc.desc: 1.under '/data/test/bms_bundle',there is a hap
 *           2.query archive information without an ability information
 */
HWTEST_F(BmsBundleKitServiceTest, GetShortcutInfoByAppIndex_0100, Function | MediumTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::vector<ShortcutInfo> shortcutInfos;
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t appIndex = 0;
    ErrCode testRet = hostImpl->GetShortcutInfoByAppIndex(BUNDLE_NAME_TEST, appIndex, shortcutInfos);
    EXPECT_EQ(testRet, ERR_OK);
    EXPECT_FALSE(shortcutInfos.empty());
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetShortcutInfoByAppIndex_0200
 * @tc.name: test can get shortcutInfo by bundleName and appIndex
 * @tc.desc: 1.can not get shortcutInfo by empty bundle name
 */
HWTEST_F(BmsBundleKitServiceTest, GetShortcutInfoByAppIndex_0200, Function | SmallTest | Level1)
{
    std::vector<ShortcutInfo> shortcutInfos;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    int32_t appIndex = 0;
    auto ret = bundleMgrProxy->GetShortcutInfoByAppIndex("", appIndex, shortcutInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_TRUE(shortcutInfos.empty());
}

/**
 * @tc.number: BundleStreamInstallerHostImplInit_0100
 * @tc.name: test Init
 * @tc.desc: Init is false
 */
HWTEST_F(BmsBundleKitServiceTest, BundleStreamInstallerHostImplInit_0100, Function | SmallTest | Level0)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver;
    const std::vector<std::string> originHapPaths;
    bool res = impl.Init(installParam, statusReceiver, originHapPaths);
    EXPECT_TRUE(res);
    impl.UnInit();
}

/**
 * @tc.number: CreateStream_0200
 * @tc.name: test CreateStream
 * @tc.desc: CreateStream is false
 */
HWTEST_F(BmsBundleKitServiceTest, CreateStream_0200, Function | SmallTest | Level0)
{
    uint32_t installerId = 1;
    int32_t installedUid = 0;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    std::string hapName = "123";
    auto res = impl.CreateStream(hapName);
    EXPECT_EQ(res, -1);
}

/**
 * @tc.number: CreateStream_0300
 * @tc.name: test CreateStream
 * @tc.desc: CreateStream is false
 */
HWTEST_F(BmsBundleKitServiceTest, CreateStream_0300, Function | SmallTest | Level0)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    std::string hapName = HAP_NAME;
    auto res = impl.CreateStream(hapName);
    EXPECT_EQ(res, -1);
}

/**
 * @tc.number: CreateStream_0400
 * @tc.name: test CreateStream
 * @tc.desc: CreateStream is false
 */
HWTEST_F(BmsBundleKitServiceTest, CreateStream_0400, Function | SmallTest | Level0)
{
    uint32_t installerId = 1;
    int32_t installedUid = 0;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    std::string hapName = HAP_NAME + ILLEGAL_PATH_FIELD;
    auto res = impl.CreateStream(hapName);
    EXPECT_GE(res, -1);
}

/**
 * @tc.number: Install_0100
 * @tc.name: test Install
 * @tc.desc: Install is false
 */
HWTEST_F(BmsBundleKitServiceTest, Install_0100, Function | SmallTest | Level0)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    bool res = impl.Install();
    EXPECT_FALSE(res);
}

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
/**
 * @tc.number: GetBundleDistributedManager_0001
 * @tc.name: test GetBundleDistributedManager
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test CheckAbilityEnableInstall
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleDistributedManager_0001, Function | SmallTest | Level0)
{
    auto bundleMgr = GetBundleDistributedManager();
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", "bundlename", "abilityname", "moudlename");
    bool ret = bundleMgr->CheckAbilityEnableInstall(want, 0, 100, nullptr);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: GetBundleDistributedManager_0001
 * @tc.name: test GetBundleDistributedManager
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test OnQueryRpcIdFinished
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleDistributedManager_0002, Function | SmallTest | Level0)
{
    auto bundleMgr = GetBundleDistributedManager();
    std::string queryRpcIdResult;
    bundleMgr->OnQueryRpcIdFinished(queryRpcIdResult);
    queryRpcIdResult = "[]";
    bundleMgr->OnQueryRpcIdFinished(queryRpcIdResult);
    queryRpcIdResult = "[0]";
    bundleMgr->OnQueryRpcIdFinished(queryRpcIdResult);
    EXPECT_EQ(queryRpcIdResult, "[0]");
}

/**
 * @tc.number: GetBundleDistributedManager_0001
 * @tc.name: test GetBundleDistributedManager
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test ComparePcIdString
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleDistributedManager_0003, Function | SmallTest | Level0)
{
    auto bundleMgr = GetBundleDistributedManager();
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", "bundlename", "abilityname", "moudlename");
    RpcIdResult rpcIdResult;
    int32_t res = bundleMgr->ComparePcIdString(want, rpcIdResult);
    EXPECT_EQ(res, ErrorCode::GET_DEVICE_PROFILE_FAILED);
}

/**
 * @tc.number: GetBundleDistributedManager_0031
 * @tc.name: test GetBundleDistributedManager
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test ComparePcIdString
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleDistributedManager_0031, Function | SmallTest | Level0)
{
    auto bundleMgr = GetBundleDistributedManager();
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    char deviceId[UUID_LENGTH_MAX] = { 0 };
    auto ret = GetDevUdid(deviceId, UUID_LENGTH_MAX);
    want.SetElementName(std::string{ deviceId }, "bundlename", "abilityname", "moudlename");
    RpcIdResult rpcIdResult;
    rpcIdResult.abilityInfo.rpcId.emplace_back("RPC_ID");
    int32_t res = bundleMgr->ComparePcIdString(want, rpcIdResult);
    EXPECT_EQ(res, ErrorCode::GET_DEVICE_PROFILE_FAILED);
}

/**
 * @tc.number: GetBundleDistributedManager_0001
 * @tc.name: test GetBundleDistributedManager
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test QueryRpcIdByAbilityToServiceCenter
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleDistributedManager_0004, Function | SmallTest | Level0)
{
    auto bundleMgr = GetBundleDistributedManager();
    TargetAbilityInfo targetAbilityInfo;
    setuid(Constants::FOUNDATION_UID);
    ScopeGuard uidGuard([&] { setuid(Constants::ROOT_UID); });
    bool res = bundleMgr->QueryRpcIdByAbilityToServiceCenter(targetAbilityInfo);
#ifdef USE_ARM64
    EXPECT_TRUE(res);
#else
    EXPECT_TRUE(res);
#endif
}

/**
 * @tc.number: GetBundleDistributedManager_0001
 * @tc.name: test GetBundleDistributedManager
 * @tc.require: issueI5MZ8V
 * @tc.desc: 1. system running normally
 *           2. test OutTimeMonitor
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleDistributedManager_0005, Function | SmallTest | Level0)
{
    auto bundleMgr = GetBundleDistributedManager();
    std::string transactId;
    QueryRpcIdParams queryRpcIdParams;
    bundleMgr->SendCallback(0, queryRpcIdParams);
    bundleMgr->OutTimeMonitor(transactId);
    EXPECT_EQ(transactId, "");
}
#endif

/**
 * @tc.number: Hidump_0001
 * @tc.name: test Hidump_0001
 * @tc.desc: Hidump is true
 */
HWTEST_F(BmsBundleKitServiceTest, Hidump_0001, Function | SmallTest | Level0)
{
    std::string arg = "-h";
    std::vector<std::string> args;
    args.push_back(arg);
    std::string result = "";
    auto res = bundleMgrService_->Hidump(args, result);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: Hidump_0002
 * @tc.name: test Hidump
 * @tc.desc: Hidump is true
 */
HWTEST_F(BmsBundleKitServiceTest, Hidump_0002, Function | SmallTest | Level0)
{
    std::weak_ptr<BundleDataMgr> dataMgr;
    HidumpHelper dumpHelper(dataMgr);
    HidumpParam hidumpParam;
    hidumpParam.hidumpFlag = HidumpFlag::GET_ABILITY;
    std::string result = "";
    auto res1 = dumpHelper.ProcessDump(hidumpParam, result);
    EXPECT_EQ(res1, ERR_APPEXECFWK_HIDUMP_SERVICE_ERROR);

    std::string arg = "-ability";
    std::vector<std::string> args;
    args.push_back(arg);
    result.clear();
    auto res2 = bundleMgrService_->Hidump(args, result);
    EXPECT_TRUE(res2);
}

/**
 * @tc.number: Hidump_0003
 * @tc.name: test Hidump
 * @tc.desc: Hidump is true
 */
HWTEST_F(BmsBundleKitServiceTest, Hidump_0003, Function | SmallTest | Level0)
{
    std::weak_ptr<BundleDataMgr> dataMgr;
    HidumpHelper dumpHelper(dataMgr);
    HidumpParam hidumpParam;
    hidumpParam.hidumpFlag = HidumpFlag::GET_ABILITY_LIST;
    std::string result = "";
    auto res1 = dumpHelper.ProcessDump(hidumpParam, result);
    EXPECT_EQ(res1, ERR_APPEXECFWK_HIDUMP_SERVICE_ERROR);

    std::string arg = "-ability-list";
    std::vector<std::string> args;
    args.push_back(arg);
    result.clear();
    auto res2 = bundleMgrService_->Hidump(args, result);
    EXPECT_TRUE(res2);
}

/**
 * @tc.number: Hidump_0004
 * @tc.name: test Hidump
 * @tc.desc: Hidump is true
 */
HWTEST_F(BmsBundleKitServiceTest, Hidump_0004, Function | SmallTest | Level0)
{
    std::weak_ptr<BundleDataMgr> dataMgr;
    HidumpHelper dumpHelper(dataMgr);
    HidumpParam hidumpParam;
    hidumpParam.hidumpFlag = HidumpFlag::GET_BUNDLE;
    std::string result = "";
    auto res1 = dumpHelper.ProcessDump(hidumpParam, result);
    EXPECT_EQ(res1, ERR_APPEXECFWK_HIDUMP_SERVICE_ERROR);

    std::string arg = "-bundle";
    std::vector<std::string> args;
    args.push_back(arg);
    result.clear();
    auto res2 = bundleMgrService_->Hidump(args, result);
    EXPECT_TRUE(res2);
}

/**
 * @tc.number: Hidump_0005
 * @tc.name: test Hidump
 * @tc.desc: Hidump is true
 */
HWTEST_F(BmsBundleKitServiceTest, Hidump_0005, Function | SmallTest | Level0)
{
    std::weak_ptr<BundleDataMgr> dataMgr;
    HidumpHelper dumpHelper(dataMgr);
    HidumpParam hidumpParam;
    hidumpParam.hidumpFlag = HidumpFlag::GET_BUNDLE_LIST;
    std::string result = "";
    auto res1 = dumpHelper.ProcessDump(hidumpParam, result);
    EXPECT_EQ(res1, ERR_APPEXECFWK_HIDUMP_SERVICE_ERROR);

    std::string arg = "-bundle-list";
    std::vector<std::string> args;
    args.push_back(arg);
    result.clear();
    auto res2 = bundleMgrService_->Hidump(args, result);
    EXPECT_TRUE(res2);
}

/**
 * @tc.number: Hidump_0006
 * @tc.name: test Hidump
 * @tc.desc: Hidump is true
 */
HWTEST_F(BmsBundleKitServiceTest, Hidump_0006, Function | SmallTest | Level0)
{
    std::weak_ptr<BundleDataMgr> dataMgr;
    HidumpHelper dumpHelper(dataMgr);
    HidumpParam hidumpParam;
    hidumpParam.hidumpFlag = HidumpFlag::GET_DEVICEID;
    std::string result = "";
    std::string arg = "-device";
    std::vector<std::string> args;
    args.push_back(arg);
    auto res = bundleMgrService_->Hidump(args, result);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: Hidump_0007
 * @tc.name: test Hidump
 * @tc.desc: Hidump is true
 */
HWTEST_F(BmsBundleKitServiceTest, Hidump_0007, Function | SmallTest | Level0)
{
    std::weak_ptr<BundleDataMgr> dataMgr;
    HidumpHelper dumpHelper(dataMgr);
    HidumpParam hidumpParam;
    hidumpParam.hidumpFlag = HidumpFlag::GET_ABILITY_BY_NAME;
    std::string result = "";
    auto res2 = dumpHelper.ProcessDump(hidumpParam, result);
    EXPECT_EQ(res2, ERR_APPEXECFWK_HIDUMP_SERVICE_ERROR);

    std::string arg1 = "-ability";
    std::string arg2 = "-ability";
    std::vector<std::string> args;
    args.push_back(arg1);
    args.push_back(arg2);
    result.clear();
    auto res = bundleMgrService_->Hidump(args, result);
    EXPECT_FALSE(res);

    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::string arg3 = ABILITY_NAME_TEST;
    std::vector<std::string> args1;
    args1.push_back(arg1);
    args1.push_back(arg3);
    result.clear();
    auto res1 = bundleMgrService_->Hidump(args1, result);
    EXPECT_TRUE(res1);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: Hidump_0008
 * @tc.name: test Hidump
 * @tc.desc: Hidump is true
 */
HWTEST_F(BmsBundleKitServiceTest, Hidump_0008, Function | SmallTest | Level0)
{
    std::weak_ptr<BundleDataMgr> dataMgr;
    HidumpHelper dumpHelper(dataMgr);
    HidumpParam hidumpParam;
    hidumpParam.hidumpFlag = HidumpFlag::GET_BUNDLE_BY_NAME;
    std::string result = "";
    auto res2 = dumpHelper.ProcessDump(hidumpParam, result);
    EXPECT_EQ(res2, ERR_APPEXECFWK_HIDUMP_SERVICE_ERROR);

    std::string arg1 = "-bundle";
    std::string arg2 = "-bundle";
    std::vector<std::string> args;
    args.push_back(arg1);
    args.push_back(arg2);
    result.clear();
    auto res = bundleMgrService_->Hidump(args, result);
    EXPECT_FALSE(res);
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    std::string arg3 = BUNDLE_NAME_TEST;
    std::vector<std::string> args1;
    args1.push_back(arg1);
    args1.push_back(arg3);
    result.clear();
    auto res1 = bundleMgrService_->Hidump(args1, result);
    EXPECT_TRUE(res1);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: Hidump_0009
 * @tc.name: test Hidump
 * @tc.desc: Hidump is true
 */
HWTEST_F(BmsBundleKitServiceTest, Hidump_0009, Function | SmallTest | Level0)
{
    std::string arg1 = "-b";
    std::vector<std::string> args;
    args.push_back(arg1);
    std::string result = "";
    auto res = bundleMgrService_->Hidump(args, result);
    EXPECT_TRUE(res);
    std::string arg3 = ABILITY_NAME_TEST;
    std::vector<std::string> args1;
    args1.push_back(arg1);
    args1.push_back(arg3);
    result.clear();
    auto res1 = bundleMgrService_->Hidump(args1, result);
    EXPECT_TRUE(res1);
}

/**
 * @tc.number: LoadInstallInfosFromDb_0001
 * @tc.name: test LoadInstallInfosFromDb
 * @tc.desc: LoadInstallInfosFromDb is true
 */
HWTEST_F(BmsBundleKitServiceTest, LoadInstallInfosFromDb_0001, Function | SmallTest | Level0)
{
    BMSEventHandler handler;
    bool res = handler.LoadInstallInfosFromDb();
    EXPECT_TRUE(res);
}

/**
 * @tc.number: AnalyzeUserData_0001
 * @tc.name: test AnalyzeUserData
 * @tc.desc: AnalyzeUserData is false
 */
HWTEST_F(BmsBundleKitServiceTest, AnalyzeUserData_0001, Function | SmallTest | Level0)
{
    BMSEventHandler handler;
    int32_t userId = 0;
    std::string userDataDir = "";
    std::string userDataBundleName = "";
    std::map<std::string, std::vector<InnerBundleUserInfo>> userMaps;
    bool res = handler.AnalyzeUserData(userId, userDataDir, userDataBundleName, userMaps);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: AnalyzeUserData_0002
 * @tc.name: test AnalyzeUserData
 * @tc.desc: AnalyzeUserData is true
 */
HWTEST_F(BmsBundleKitServiceTest, AnalyzeUserData_0002, Function | SmallTest | Level0)
{
    BMSEventHandler handler;
    int32_t userId = 0;
    std::string userDataDir = "/data/app/el2/100/base/";
    std::string userDataBundleName = BUNDLE_NAME_TEST;
    std::map<std::string, std::vector<InnerBundleUserInfo>> userMaps;
    bool res = handler.AnalyzeUserData(userId, userDataDir, userDataBundleName, userMaps);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: RemoveSystemAbility
 * @tc.name: test RemoveSystemAbility
 * @tc.desc: RemoveSystemAbility is true
 */
HWTEST_F(BmsBundleKitServiceTest, RemoveSystemAbility_0001, Function | SmallTest | Level0)
{
    SystemAbilityHelper helper;
    int32_t systemAbilityId = 0;
    bool res = helper.RemoveSystemAbility(systemAbilityId);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: SystemAbilityHelper_0100
 * @tc.name: test GetSystemAbility
 * @tc.desc: test the GetSystemAbility of SystemAbilityHelper
 */
HWTEST_F(BmsBundleKitServiceTest, SystemAbilityHelper_0100, Function | SmallTest | Level0)
{
    SystemAbilityHelper helper;

    int32_t systemAbilityId = 100;
    sptr<IRemoteObject> res = helper.GetSystemAbility(systemAbilityId);
    EXPECT_EQ(res, nullptr);
}

/**
 * @tc.number: SystemAbilityHelper_0200
 * @tc.name: test GetSystemAbility
 * @tc.desc: test the GetSystemAbility of SystemAbilityHelper
 */
HWTEST_F(BmsBundleKitServiceTest, SystemAbilityHelper_0200, Function | SmallTest | Level0)
{
    SystemAbilityHelper helper;

    int32_t systemAbilityId = 100;
    sptr<IRemoteObject> systemAbility;
    bool ret = helper.AddSystemAbility(systemAbilityId, systemAbility);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: SystemAbilityHelper_0300
 * @tc.name: test UninstallApp
 * @tc.desc: test the UninstallApp of SystemAbilityHelper
 */
HWTEST_F(BmsBundleKitServiceTest, SystemAbilityHelper_0300, Function | SmallTest | Level0)
{
    SystemAbilityHelper helper;

    std::string bundleName;
    int32_t uid = 100;
    int32_t appIndex = 1;
    bool ret = helper.UninstallApp(bundleName, uid,  appIndex);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SystemAbilityHelper_0400
 * @tc.name: test UninstallApp
 * @tc.desc: test the UninstallApp of SystemAbilityHelper
 */
HWTEST_F(BmsBundleKitServiceTest, SystemAbilityHelper_0400, Function | SmallTest | Level0)
{
    SystemAbilityHelper helper;

    std::string bundleName = "com.ohos.settings";
    int32_t uid = 1;
    int32_t appIndex = 100;
    bool ret = helper.UpgradeApp(bundleName, uid, appIndex);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SystemAbilityHelper_0500
 * @tc.name: test UninstallApp
 * @tc.desc: test the UninstallApp of SystemAbilityHelper
 */
HWTEST_F(BmsBundleKitServiceTest, SystemAbilityHelper_0500, Function | SmallTest | Level0)
{
    SystemAbilityHelper helper;

    int32_t systemAbilityId = 100;
    bool ret = helper.UnloadSystemAbility(systemAbilityId);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: AppRunningControlRuleResult_001
 * @tc.name: Marshalling and Unmarshalling
 * @tc.desc: 1.Test Marshalling and Unmarshalling successed
 */
HWTEST_F(BmsBundleKitServiceTest, AppRunningControlRuleResult_001, Function | SmallTest | Level1)
{
    AppRunningControlRuleResult result;
    result.controlMessage = CONTROLMESSAGE;
    result.controlWant = std::make_shared<AAFwk::Want>();
    Parcel parcel;
    auto ret1 = result.Marshalling(parcel);
    EXPECT_EQ(ret1, true);
    auto ret2 = result.Unmarshalling(parcel);
    EXPECT_NE(ret2, nullptr);
}

/**
 * @tc.number: ShortcutInfoBranchCover_001
 * @tc.name: Marshalling branch cover
 * @tc.desc: 1.Test Marshalling
 */
HWTEST_F(BmsBundleKitServiceTest, ShortcutInfoBranchCover_001, Function | SmallTest | Level1)
{
    ShortcutInfo shortcutInfo = MockShortcutInfo(BUNDLE_NAME_DEMO, SHORTCUT_TEST_ID);
    Parcel parcel;
    auto ret1 = shortcutInfo.Marshalling(parcel);
    EXPECT_EQ(ret1, true);
}

/**
 * @tc.number: ShortcutInfoBranchCover_002
 * @tc.name: shortcutIntent to_json and from_json branch cover
 * @tc.desc: 1.Test shortcutIntent to_json and from_json
 */
HWTEST_F(BmsBundleKitServiceTest, ShortcutInfoBranchCover_002, Function | SmallTest | Level1)
{
    ShortcutIntent shortcutIntent = MockShortcutIntent();
    nlohmann::json jsonObj;
    to_json(jsonObj, shortcutIntent);
    ShortcutIntent result;
    from_json(jsonObj, result);
    EXPECT_EQ(result.targetBundle, SHORTCUT_INTENTS_TARGET_BUNDLE);
    EXPECT_EQ(result.targetModule, SHORTCUT_INTENTS_TARGET_MODULE);
    EXPECT_EQ(result.targetClass, SHORTCUT_INTENTS_TARGET_CLASS);
}

/**
 * @tc.number: ShortcutInfoBranchCover_003
 * @tc.name: shortcutInfo to_json and from_json branch cover
 * @tc.desc: 1.Test shortcutInfo to_json and from_json
 */
HWTEST_F(BmsBundleKitServiceTest, ShortcutInfoBranchCover_003, Function | SmallTest | Level1)
{
    ShortcutInfo shortcutInfo = MockShortcutInfo(BUNDLE_NAME_DEMO, SHORTCUT_TEST_ID);
    nlohmann::json jsonObj;
    to_json(jsonObj, shortcutInfo);
    ShortcutInfo result;
    from_json(jsonObj, result);
    EXPECT_EQ(result.id, SHORTCUT_TEST_ID);
    EXPECT_EQ(result.bundleName, BUNDLE_NAME_DEMO);
    EXPECT_EQ(result.hostAbility, SHORTCUT_HOST_ABILITY);
    EXPECT_EQ(result.icon, SHORTCUT_ICON);
    EXPECT_EQ(result.label, SHORTCUT_LABEL);
    EXPECT_EQ(result.disableMessage, SHORTCUT_DISABLE_MESSAGE);
    EXPECT_EQ(result.isStatic, true);
    EXPECT_EQ(result.isHomeShortcut, true);
    EXPECT_EQ(result.isEnables, true);
}

/**
 * @tc.number: ShortcutInfoBranchCover_004
 * @tc.name: shortcutInfo to_json and from_json branch cover
 * @tc.desc: 1.Test shortcutInfo to_json and from_json
 */
HWTEST_F(BmsBundleKitServiceTest, ShortcutInfoBranchCover_004, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["id"] = false;
    jsonObject["label"] = "1";
    jsonObject["icon"] = "1";
    ShortcutInfo shortcutInfo;
    from_json(jsonObject, shortcutInfo);
    EXPECT_NE(shortcutInfo.icon, "1");
}

/**
 * @tc.number: ShortcutInfoBranchCover_005
 * @tc.name: shortcutWant to_json and from_json branch cover
 * @tc.desc: 1.Test shortcutWant to_json and from_json
 */
HWTEST_F(BmsBundleKitServiceTest, ShortcutInfoBranchCover_005, Function | SmallTest | Level1)
{
    ShortcutWant shortcutWant = MockShortcutWant();
    nlohmann::json jsonObj;
    ShortcutWantToJson(jsonObj, shortcutWant);
    ShortcutWant result;
    from_json(jsonObj, result);
    EXPECT_EQ(result.bundleName, BUNDLE_NAME_DEMO);
    EXPECT_EQ(result.moduleName, MODULE_NAME_DEMO);
    EXPECT_EQ(result.abilityName, ABILITY_NAME_DEMO);
}

/**
 * @tc.number: ShortcutInfoBranchCover_006
 * @tc.name: shortcutWant to_json and from_json branch cover
 * @tc.desc: 1.Test shortcutWant to_json and from_json
 */
HWTEST_F(BmsBundleKitServiceTest, ShortcutInfoBranchCover_006, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["bundleName"] = false;
    jsonObject["moduleName"] = "1";
    jsonObject["abilityName"] = "1";
    ShortcutWant shortcutWant;
    from_json(jsonObject, shortcutWant);
    EXPECT_NE(shortcutWant.moduleName, "1");
}

/**
 * @tc.number: ShortcutInfoBranchCover_007
 * @tc.name: shortcut from_json branch cover
 * @tc.desc: 1.Test shortcut from_json
 */
HWTEST_F(BmsBundleKitServiceTest, ShortcutInfoBranchCover_007, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["shortcutId"] = "1";
    jsonObject["label"] = "1";
    jsonObject["icon"] = "1";
    Shortcut shortcut;
    from_json(jsonObject, shortcut);
    EXPECT_EQ(shortcut.icon, "1");
}

/**
 * @tc.number: ShortcutInfoBranchCover_008
 * @tc.name: shortcut from_json branch cover
 * @tc.desc: 1.Test shortcut from_json
 */
HWTEST_F(BmsBundleKitServiceTest, ShortcutInfoBranchCover_008, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["shortcutId"] = false;
    jsonObject["label"] = "1";
    jsonObject["icon"] = "1";
    Shortcut shortcut;
    from_json(jsonObject, shortcut);
    EXPECT_NE(shortcut.icon, "1");
}

/**
 * @tc.number: ShortcutInfoBranchCover_009
 * @tc.name: shortcutJson from_json branch cover
 * @tc.desc: 1.Test shortcutJson from_json
 */
HWTEST_F(BmsBundleKitServiceTest, ShortcutInfoBranchCover_009, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = R"({"shortcuts":[{"shortcutId":"1","label":"1","icon":"1"}]})"_json;
    ShortcutJson shortcutJson;
    from_json(jsonObject, shortcutJson);
    Shortcut shortcut = shortcutJson.shortcuts.front();
    EXPECT_EQ(shortcut.shortcutId, "1");
    EXPECT_EQ(shortcut.label, "1");
    EXPECT_EQ(shortcut.icon, "1");
}

/**
 * @tc.number: ShortcutInfoBranchCover_0010
 * @tc.name: shortcutJson from_json branch cover
 * @tc.desc: 1.Test shortcutJson from_json
 */
HWTEST_F(BmsBundleKitServiceTest, ShortcutInfoBranchCover_0010, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["shortcuts"] = "1";
    ShortcutJson shortcutJson;
    from_json(jsonObject, shortcutJson);
    EXPECT_EQ(shortcutJson.shortcuts.size(), 0);
}

/**
 * @tc.number: DBMSBranchCover_0001
 * @tc.name: dbms Marshalling branch cover
 * @tc.desc: 1.Test dbms Marshalling and ReadFromParcel branch cover
 */
HWTEST_F(BmsBundleKitServiceTest, DBMSBranchCover_0001, Function | SmallTest | Level1)
{
    DistributedModuleInfo distributedModuleInfo1;
    DistributedModuleInfo distributedModuleInfo2;
    distributedModuleInfo1.moduleName = "testModuleName";
    DistributedAbilityInfo distributedAbioityInfo;
    distributedModuleInfo1.abilities.emplace_back(distributedAbioityInfo);
    Parcel parcel;
    auto ret1 = distributedModuleInfo1.Marshalling(parcel);
    EXPECT_TRUE(ret1);
    auto ret2 = distributedModuleInfo2.ReadFromParcel(parcel);
    EXPECT_TRUE(ret2);
}

/**
 * @tc.number: DBMSBranchCover_0002
 * @tc.name: dbms Unmarshalling branch cover
 * @tc.desc: 1.Test dbms Unmarshalling branch cover
 */
HWTEST_F(BmsBundleKitServiceTest, DBMSBranchCover_0002, Function | SmallTest | Level1)
{
    DistributedModuleInfo distributedModuleInfo1;
    distributedModuleInfo1.moduleName = "testModuleName";
    DistributedAbilityInfo distributedAbioityInfo;
    distributedModuleInfo1.abilities.emplace_back(distributedAbioityInfo);
    Parcel parcel;
    auto ret1 = distributedModuleInfo1.Marshalling(parcel);
    EXPECT_TRUE(ret1);
    DistributedModuleInfo distributedModuleInfo2;
    auto ret2 = distributedModuleInfo2.Unmarshalling(parcel);
    EXPECT_NE(ret2, nullptr);
    EXPECT_EQ(distributedModuleInfo1.moduleName, ret2->moduleName);
}

/**
 * @tc.number: DBMSBranchCover_0003
 * @tc.name: dbms Unmarshalling branch cover
 * @tc.desc: 1.Test dbms Unmarshalling branch cover
 */
HWTEST_F(BmsBundleKitServiceTest, DBMSBranchCover_0003, Function | SmallTest | Level1)
{
    DistributedModuleInfo distributedModuleInfo;
    std::string path = "/data/test/distributedModuleinfo.txt";
    std::ofstream file(path);
    file.close();
    int fd = -1;
    std::string prefix = "[ability]";
    distributedModuleInfo.Dump(prefix, fd);
    long length = lseek(fd, ZERO, SEEK_END);
    EXPECT_EQ(length, -1);
}

/**
 * @tc.number: DBMSAbilityInfoBranchCover_0001
 * @tc.name: DBMSAbilityInfo ReadFromParcel and marshalling test
 * @tc.desc: 1.DBMSAbilityInfo ReadFromParcel and marshalling test
 */
HWTEST_F(BmsBundleKitServiceTest, DBMSAbilityInfoBranchCover_0001, Function | SmallTest | Level1)
{
    DistributedAbilityInfo distributedAbilityInfo1;
    DistributedAbilityInfo distributedAbilityInfo2;
    distributedAbilityInfo1.abilityName = "testAbilityName";
    Parcel parcel;
    auto ret1 = distributedAbilityInfo1.Marshalling(parcel);
    EXPECT_TRUE(ret1);
    auto ret2 = distributedAbilityInfo2.ReadFromParcel(parcel);
    EXPECT_TRUE(ret2);
}

/**
 * @tc.number: DBMSAbilityInfoBranchCover_0002
 * @tc.name: DBMSAbilityInfo Unmarshalling test
 * @tc.desc: 1.DBMSAbilityInfo Unmarshalling test
 */
HWTEST_F(BmsBundleKitServiceTest, DBMSAbilityInfoBranchCover_0002, Function | SmallTest | Level1)
{
    DistributedAbilityInfo distributedAbilityInfo1;
    DistributedAbilityInfo distributedAbilityInfo2;
    distributedAbilityInfo1.abilityName = "testAbilityName";
    Parcel parcel;
    auto ret1 = distributedAbilityInfo1.Marshalling(parcel);
    EXPECT_TRUE(ret1);
    auto ret2 = distributedAbilityInfo2.Unmarshalling(parcel);
    EXPECT_NE(ret2, nullptr);
    EXPECT_EQ(distributedAbilityInfo1.abilityName, ret2->abilityName);
}

/**
 * @tc.number: DBMSAbilityInfoBranchCover_0003
 * @tc.name: DBMSAbilityInfo dump test
 * @tc.desc: 1.DBMSAbilityInfo dump test
 */
HWTEST_F(BmsBundleKitServiceTest, DBMSAbilityInfoBranchCover_0003, Function | SmallTest | Level1)
{
    DistributedAbilityInfo distributedAbilityInfo;
    std::string path = "/data/test/distributedAbilityInfo.txt";
    std::ofstream file(path);
    file.close();
    int fd = -1;
    std::string prefix = "[ability]";
    distributedAbilityInfo.Dump(prefix, fd);
    long length = lseek(fd, ZERO, SEEK_END);
    EXPECT_EQ(length, -1);
}

/**
 * @tc.number: PermissionDefBranchCover_0001
 * @tc.name: PermissionDef Marshalling test
 * @tc.desc: 1.PermissionDef Marshalling test
 */
HWTEST_F(BmsBundleKitServiceTest, PermissionDefBranchCover_0001, Function | SmallTest | Level1)
{
    PermissionDef param1;
    param1.permissionName = "testPermissioinName";
    param1.bundleName = "testBundleName";
    param1.label = "testLabel";
    param1.description = "testDescription";
    Parcel parcel;
    auto ret1 = param1.Marshalling(parcel);
    EXPECT_TRUE(ret1);
    PermissionDef param2;
    auto ret2 = param2.Unmarshalling(parcel);
    EXPECT_NE(ret2, nullptr);
    EXPECT_EQ(param1.permissionName, ret2->permissionName);
    EXPECT_EQ(param1.bundleName, ret2->bundleName);
    EXPECT_EQ(param1.grantMode, ret2->grantMode);
    EXPECT_EQ(param1.availableLevel, ret2->availableLevel);
    EXPECT_EQ(param1.provisionEnable, ret2->provisionEnable);
    EXPECT_EQ(param1.distributedSceneEnable, ret2->distributedSceneEnable);
    EXPECT_EQ(param1.isKernelEffect, ret2->isKernelEffect);
    EXPECT_EQ(param1.hasValue, ret2->hasValue);
    EXPECT_EQ(param1.label, ret2->label);
    EXPECT_EQ(param1.labelId, ret2->labelId);
    EXPECT_EQ(param1.description, ret2->description);
    EXPECT_EQ(param1.descriptionId, ret2->descriptionId);
}

/**
 * @tc.number: CommonEventInfoBranchCover_0001
 * @tc.name: CommonEventInfo Marshalling test
 * @tc.desc: 1.CommonEventInfo Marshalling test
 */
HWTEST_F(BmsBundleKitServiceTest, CommonEventInfoBranchCover_0001, Function | SmallTest | Level1)
{
    CommonEventInfo commonEventInfo;
    commonEventInfo.name = COMMON_EVENT_NAME;
    commonEventInfo.bundleName = BUNDLE_NAME;
    commonEventInfo.uid = 100;
    commonEventInfo.permission = COMMON_EVENT_PERMISSION;
    Parcel parcel;
    auto ret1 = commonEventInfo.Marshalling(parcel);
    EXPECT_TRUE(ret1);
    CommonEventInfo commonEventInfo2;
    auto ret2 = commonEventInfo2.Unmarshalling(parcel);
    EXPECT_NE(ret2, nullptr);
    EXPECT_EQ(commonEventInfo.name, ret2->name);
    EXPECT_EQ(commonEventInfo.bundleName, ret2->bundleName);
    EXPECT_EQ(commonEventInfo.uid, ret2->uid);
    EXPECT_EQ(commonEventInfo.permission, ret2->permission);
}

/**
 * @tc.number: CommonEventInfoBranchCover_0002
 * @tc.name: CommonEventInfo from_json test
 * @tc.desc: 1.CommonEventInfo from_json test
 */
HWTEST_F(BmsBundleKitServiceTest, CommonEventInfoBranchCover_0002, Function | SmallTest | Level1)
{
    CommonEventInfo commonEventInfo;
    commonEventInfo.name = COMMON_EVENT_NAME;
    commonEventInfo.bundleName = BUNDLE_NAME;
    commonEventInfo.uid = 100;
    commonEventInfo.permission = COMMON_EVENT_PERMISSION;
    nlohmann::json jsonObj;
    to_json(jsonObj, commonEventInfo);
    CommonEventInfo result;
    from_json(jsonObj, result);
    EXPECT_EQ(result.name, COMMON_EVENT_NAME);
    EXPECT_EQ(result.bundleName, BUNDLE_NAME);
    EXPECT_EQ(result.uid, 100);
    EXPECT_EQ(result.permission, COMMON_EVENT_PERMISSION);
}

/**
 * @tc.number: PerfProfileBranchCover_0001
 * @tc.name: PerfProfile GetBmsLoadStartTime test
 * @tc.desc: 1.PerfProfile GetBmsLoadStartTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0001, Function | SmallTest | Level1)
{
    int64_t time = 100;
    PerfProfile perfProfile;
    perfProfile.SetBmsLoadStartTime(time);
    int64_t ret = perfProfile.GetBmsLoadStartTime();
    EXPECT_EQ(ret, time);
}

/**
 * @tc.number: PerfProfileBranchCover_0002
 * @tc.name: PerfProfile GetBmsLoadEndTime test
 * @tc.desc: 1.PerfProfile GetBmsLoadEndTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0002, Function | SmallTest | Level1)
{
    int64_t time = 100;
    PerfProfile perfProfile;
    perfProfile.SetBmsLoadEndTime(time);
    int64_t ret = perfProfile.GetBmsLoadEndTime();
    EXPECT_EQ(ret, time);
}

/**
 * @tc.number: PerfProfileBranchCover_0003
 * @tc.name: PerfProfile GetBundleScanStartTime test
 * @tc.desc: 1.PerfProfile GetBundleScanStartTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0003, Function | SmallTest | Level1)
{
    int64_t time = 100;
    PerfProfile perfProfile;
    perfProfile.SetBundleScanStartTime(time);
    int64_t ret = perfProfile.GetBundleScanStartTime();
    EXPECT_EQ(ret, time);
}

/**
 * @tc.number: PerfProfileBranchCover_0004
 * @tc.name: PerfProfile GetBundleScanEndTime test
 * @tc.desc: 1.PerfProfile GetBundleScanEndTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0004, Function | SmallTest | Level1)
{
    int64_t time = 100;
    PerfProfile perfProfile;
    perfProfile.SetBundleScanEndTime(time);
    int64_t ret = perfProfile.GetBundleScanEndTime();
    EXPECT_EQ(ret, time);
}

/**
 * @tc.number: PerfProfileBranchCover_0005
 * @tc.name: PerfProfile GetBundleDownloadStartTime test
 * @tc.desc: 1.PerfProfile GetBundleDownloadStartTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0005, Function | SmallTest | Level1)
{
    PerfProfile perfProfile;
    int64_t time = 100;
    perfProfile.SetBundleDownloadStartTime(time);
    int64_t ret = perfProfile.GetBundleDownloadStartTime();
    EXPECT_EQ(ret, time);
}

/**
 * @tc.number: PerfProfileBranchCover_0006
 * @tc.name: PerfProfile GetBundleDownloadStartTime test
 * @tc.desc: 1.PerfProfile GetBundleDownloadStartTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0006, Function | SmallTest | Level1)
{
    PerfProfile perfProfile;
    int64_t time = 100;
    perfProfile.SetBundleDownloadEndTime(time);
    int64_t ret = perfProfile.GetBundleDownloadEndTime();
    EXPECT_EQ(ret, time);
}

/**
 * @tc.number: PerfProfileBranchCover_0007
 * @tc.name: PerfProfile GetBundleInstallStartTime test
 * @tc.desc: 1.PerfProfile GetBundleInstallStartTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0007, Function | SmallTest | Level1)
{
    PerfProfile perfProfile;
    int64_t time = 100;
    perfProfile.SetBundleInstallStartTime(time);
    int64_t ret = perfProfile.GetBundleInstallStartTime();
    EXPECT_EQ(ret, time);
}

/**
 * @tc.number: PerfProfileBranchCover_0008
 * @tc.name: PerfProfile GetBundleTotalInstallTime test
 * @tc.desc: 1.PerfProfile GetBundleTotalInstallTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0008, Function | SmallTest | Level1)
{
    PerfProfile perfProfile;
    int64_t ret = perfProfile.GetBundleTotalInstallTime();
    EXPECT_EQ(ret, ZERO);
}

/**
 * @tc.number: PerfProfileBranchCover_0009
 * @tc.name: PerfProfile GetBundleUninstallStartTime test
 * @tc.desc: 1.PerfProfile GetBundleUninstallStartTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0009, Function | SmallTest | Level1)
{
    PerfProfile perfProfile;
    int64_t time = 100;
    perfProfile.SetBundleUninstallStartTime(time);
    int64_t ret = perfProfile.GetBundleUninstallStartTime();
    EXPECT_EQ(ret, time);
}

/**
 * @tc.number: PerfProfileBranchCover_0010
 * @tc.name: PerfProfile GetBundleUninstallEndTime test
 * @tc.desc: 1.PerfProfile GetBundleUninstallEndTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0010, Function | SmallTest | Level1)
{
    PerfProfile perfProfile;
    int64_t time = 100;
    perfProfile.SetBundleUninstallEndTime(time);
    int64_t ret = perfProfile.GetBundleUninstallEndTime();
    EXPECT_EQ(ret, time);
}

/**
 * @tc.number: PerfProfileBranchCover_0011
 * @tc.name: PerfProfile GetBundleParseStartTime test
 * @tc.desc: 1.PerfProfile GetBundleParseStartTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0011, Function | SmallTest | Level1)
{
    PerfProfile perfProfile;
    int64_t time = 100;
    perfProfile.SetBundleParseStartTime(time);
    int64_t ret = perfProfile.GetBundleParseStartTime();
    EXPECT_EQ(ret, time);
}

/**
 * @tc.number: PerfProfileBranchCover_0012
 * @tc.name: PerfProfile GetBundleParseEndTime test
 * @tc.desc: 1.PerfProfile GetBundleParseEndTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0012, Function | SmallTest | Level1)
{
    PerfProfile perfProfile;
    int64_t time = 100;
    perfProfile.SetBundleParseEndTime(time);
    int64_t ret = perfProfile.GetBundleParseEndTime();
    EXPECT_EQ(ret, time);
}

/**
 * @tc.number: PerfProfileBranchCover_0013
 * @tc.name: PerfProfile GetAmsLoadStartTime test
 * @tc.desc: 1.PerfProfile GetAmsLoadStartTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0013, Function | SmallTest | Level1)
{
    PerfProfile perfProfile;
    int64_t time = 100;
    perfProfile.SetAmsLoadStartTime(time);
    int64_t ret = perfProfile.GetAmsLoadStartTime();
    EXPECT_EQ(ret, time);
}

/**
 * @tc.number: PerfProfileBranchCover_0014
 * @tc.name: PerfProfile GetAbilityLoadStartTime test
 * @tc.desc: 1.PerfProfile GetAbilityLoadStartTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0014, Function | SmallTest | Level1)
{
    PerfProfile perfProfile;
    int64_t time = 100;
    perfProfile.SetAbilityLoadStartTime(time);
    int64_t ret = perfProfile.GetAbilityLoadStartTime();
    EXPECT_EQ(ret, time);
}

/**
 * @tc.number: PerfProfileBranchCover_0015
 * @tc.name: PerfProfile GetAppForkStartTime test
 * @tc.desc: 1.PerfProfile GetAppForkStartTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0015, Function | SmallTest | Level1)
{
    PerfProfile perfProfile;
    int64_t time = 100;
    perfProfile.SetAppForkStartTime(time);
    int64_t ret = perfProfile.GetAppForkStartTime();
    EXPECT_EQ(ret, time);
}

/**
 * @tc.number: PerfProfileBranchCover_0016
 * @tc.name: PerfProfile GetPerfProfileEnabled test
 * @tc.desc: 1.PerfProfile GetPerfProfileEnabled test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0016, Function | SmallTest | Level1)
{
    PerfProfile perfProfile;
    bool enabled = true;
    perfProfile.SetPerfProfileEnabled(enabled);
    int64_t ret = perfProfile.GetPerfProfileEnabled();
    EXPECT_EQ(ret, enabled);
}

/**
 * @tc.number: PerfProfileBranchCover_0017
 * @tc.name: PerfProfile GetAmsLoadEndTime test
 * @tc.desc: 1.PerfProfile GetAmsLoadEndTime test
 */
HWTEST_F(BmsBundleKitServiceTest, PerfProfileBranchCover_0017, Function | SmallTest | Level1)
{
    PerfProfile perfProfile;
    int64_t time = 100;
    perfProfile.SetAmsLoadEndTime(time);
    int64_t ret = perfProfile.GetAmsLoadEndTime();
    EXPECT_EQ(ret, time);
}

/**
 * @tc.number: CompatibleAbilityBranchCover_0001
 * @tc.name: CompatibleAbility ReadFromParcel permission valid test
 * @tc.desc: 1.CompatibleAbility ReadFromParcel permission valid test
 */
HWTEST_F(BmsBundleKitServiceTest, CompatibleAbilityBranchCover_0001, Function | SmallTest | Level1)
{
    CompatibleAbilityInfo compatibleAbility;
    AbilityType type = AbilityType::UNKNOWN;
    DisplayOrientation orientation = DisplayOrientation::UNSPECIFIED;
    LaunchMode launchMode = LaunchMode::SINGLETON;
    std::vector<std::string> permissions;
    std::string permission = "permission";
    permissions.push_back(permission);
    compatibleAbility.type = type;
    compatibleAbility.orientation = orientation;
    compatibleAbility.launchMode = launchMode;
    compatibleAbility.permissions = permissions;
    Parcel parcel;
    bool ret1 = compatibleAbility.Marshalling(parcel);
    EXPECT_TRUE(ret1);
    CompatibleAbilityInfo compatibleAbilityInfo2;
    bool ret2 = compatibleAbilityInfo2.ReadFromParcel(parcel);
    EXPECT_TRUE(ret2);
    EXPECT_EQ(compatibleAbilityInfo2.type, compatibleAbility.type);
    EXPECT_EQ(compatibleAbilityInfo2.orientation, compatibleAbility.orientation);
    EXPECT_EQ(compatibleAbilityInfo2.launchMode, compatibleAbility.launchMode);
    EXPECT_EQ(compatibleAbilityInfo2.permissions, compatibleAbility.permissions);
}

/**
 * @tc.number: CompatibleAbilityBranchCover_0002
 * @tc.name: CompatibleAbility ReadFromParcel params  test
 * @tc.desc: 1.CompatibleAbility ReadFromParcel params  test
 */
HWTEST_F(BmsBundleKitServiceTest, CompatibleAbilityBranchCover_0002, Function | SmallTest | Level1)
{
    CompatibleAbilityInfo compatibleAbility;
    compatibleAbility.supportPipMode = false;
    compatibleAbility.grantPermission = false;
    compatibleAbility.readPermission = "readPermission";
    compatibleAbility.writePermission = "writePermisson";
    compatibleAbility.uriPermissionMode = "uriPermissionMode";
    compatibleAbility.uriPermissionPath = "uriPermissionPath";
    compatibleAbility.directLaunch = true;
    compatibleAbility.bundleName = "bundleName";
    compatibleAbility.className = "className";
    compatibleAbility.originalClassName = "originalClassName";
    compatibleAbility.deviceId = "deviceId";
    Parcel parcel;
    bool ret1 = compatibleAbility.Marshalling(parcel);
    EXPECT_TRUE(ret1);
    CompatibleAbilityInfo compatibleAbilityInfo2;
    bool ret2 = compatibleAbilityInfo2.ReadFromParcel(parcel);
    EXPECT_TRUE(ret2);
    EXPECT_EQ(compatibleAbility.supportPipMode, compatibleAbilityInfo2.supportPipMode);
    EXPECT_EQ(compatibleAbility.grantPermission, compatibleAbilityInfo2.grantPermission);
    EXPECT_EQ(compatibleAbility.readPermission, compatibleAbilityInfo2.readPermission);
    EXPECT_EQ(compatibleAbility.writePermission, compatibleAbilityInfo2.writePermission);
    EXPECT_EQ(compatibleAbility.uriPermissionMode, compatibleAbilityInfo2.uriPermissionMode);
    EXPECT_EQ(compatibleAbility.uriPermissionPath, compatibleAbilityInfo2.uriPermissionPath);
    EXPECT_EQ(compatibleAbility.directLaunch, compatibleAbilityInfo2.directLaunch);
    EXPECT_EQ(compatibleAbility.bundleName, compatibleAbilityInfo2.bundleName);
    EXPECT_EQ(compatibleAbility.className, compatibleAbilityInfo2.className);
    EXPECT_EQ(compatibleAbility.originalClassName, compatibleAbilityInfo2.originalClassName);
    EXPECT_EQ(compatibleAbility.deviceId, compatibleAbilityInfo2.deviceId);
    EXPECT_EQ(compatibleAbility.formEntity, compatibleAbilityInfo2.formEntity);
    EXPECT_EQ(compatibleAbility.minFormHeight, compatibleAbilityInfo2.minFormHeight);
    EXPECT_EQ(compatibleAbility.defaultFormHeight, compatibleAbilityInfo2.defaultFormHeight);
    EXPECT_EQ(compatibleAbility.minFormWidth, compatibleAbilityInfo2.minFormWidth);
    EXPECT_EQ(compatibleAbility.defaultFormWidth, compatibleAbilityInfo2.defaultFormWidth);
    EXPECT_EQ(compatibleAbility.iconId, compatibleAbilityInfo2.iconId);
    EXPECT_EQ(compatibleAbility.labelId, compatibleAbilityInfo2.labelId);
    EXPECT_EQ(compatibleAbility.descriptionId, compatibleAbilityInfo2.descriptionId);
    EXPECT_EQ(compatibleAbility.enabled, compatibleAbilityInfo2.enabled);
}

/**
 * @tc.number: FormInfoBranchCover_0001
 * @tc.name: FormInfo FormInfo params  test
 * @tc.desc: 1.FormInfo FormInfo params  test
 */
HWTEST_F(BmsBundleKitServiceTest, FormInfoBranchCover_0001, Function | SmallTest | Level1)
{
    ExtensionAbilityInfo extensionAbilityInfo;
    extensionAbilityInfo.bundleName = "bundleName";
    extensionAbilityInfo.moduleName = "moduleName";
    extensionAbilityInfo.name = "name";

    ExtensionFormInfo extensionFormInfo;
    extensionFormInfo.description = "description";
    extensionFormInfo.formConfigAbility = "formConfigAbility";
    extensionFormInfo.scheduledUpdateTime = "scheduledUpdateTime";
    extensionFormInfo.src = "src";
    extensionFormInfo.window.designWidth = 240;
    extensionFormInfo.window.autoDesignWidth = 240;
    extensionFormInfo.updateDuration = 60;
    extensionFormInfo.defaultDimension = 4;
    extensionFormInfo.isDefault = false;
    extensionFormInfo.formVisibleNotify = true;
    extensionFormInfo.updateEnabled = true;
    extensionFormInfo.type = FormType::JS;
    extensionFormInfo.colorMode = FormsColorMode::AUTO_MODE;

    FormInfo form(extensionAbilityInfo, extensionFormInfo);
    EXPECT_EQ(form.package, extensionAbilityInfo.bundleName + extensionAbilityInfo.moduleName);
    EXPECT_EQ(form.bundleName, extensionAbilityInfo.bundleName);
    EXPECT_EQ(form.originalBundleName, extensionAbilityInfo.bundleName);
    EXPECT_EQ(form.relatedBundleName, extensionAbilityInfo.bundleName);
    EXPECT_EQ(form.moduleName, extensionAbilityInfo.moduleName);
    EXPECT_EQ(form.abilityName, extensionAbilityInfo.name);
    EXPECT_EQ(form.name, extensionFormInfo.name);
    EXPECT_EQ(form.description, extensionFormInfo.description);
    EXPECT_EQ(form.jsComponentName, "");
    EXPECT_EQ(form.deepLink, "");
    EXPECT_EQ(form.formConfigAbility, extensionFormInfo.formConfigAbility);
    EXPECT_EQ(form.scheduledUpdateTime, extensionFormInfo.scheduledUpdateTime);
    EXPECT_EQ(form.src, extensionFormInfo.src);
    EXPECT_EQ(form.window.designWidth, extensionFormInfo.window.designWidth);
    EXPECT_EQ(form.window.autoDesignWidth, extensionFormInfo.window.autoDesignWidth);
    EXPECT_EQ(form.updateDuration, extensionFormInfo.updateDuration);
    EXPECT_EQ(form.defaultDimension, extensionFormInfo.defaultDimension);
    EXPECT_EQ(form.defaultFlag, extensionFormInfo.isDefault);
    EXPECT_EQ(form.formVisibleNotify, extensionFormInfo.formVisibleNotify);
    EXPECT_EQ(form.updateEnabled, extensionFormInfo.updateEnabled);
    EXPECT_EQ(form.type, extensionFormInfo.type);
    EXPECT_EQ(form.colorMode, extensionFormInfo.colorMode);
}

/**
 * @tc.number: QueryExtensionAbilityInfosV9_0900
 * @tc.name: 1.explicit query extension info failed, extensionInfos is empty
 * @tc.desc: 1.system run normal
 */
HWTEST_F(BmsBundleKitServiceTest, QueryExtensionAbilityInfosV9_0900, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleMgrService> bundleMgrService = DelayedSingleton<BundleMgrService>::GetInstance();
    bundleMgrService->InitBundleMgrHost();
    auto hostImpl = bundleMgrService->host_;
    int32_t flags = 0;
    int32_t userId = DEFAULT_USERID;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    Want want;
    ExtensionAbilityType extensionType = ExtensionAbilityType::FORM;
    auto testRet = hostImpl->QueryExtensionAbilityInfosV9(want, flags, userId, extensionInfos);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);

    extensionInfos.clear();
    testRet = hostImpl->QueryExtensionAbilityInfosV9(want, extensionType, flags, userId, extensionInfos);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);

    extensionInfos.clear();
    testRet = hostImpl->QueryExtensionAbilityInfosV9(want, flags, userId, extensionInfos);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);

    extensionInfos.clear();
    bool res = hostImpl->QueryExtensionAbilityInfos(want, extensionType, flags, userId, extensionInfos);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: ImplicitQueryAbilityInfos_0100
 * @tc.name: test can get the ability infos
 * @tc.desc: 1.system run normally
 *           2.get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, ImplicitQueryAbilityInfos_0100, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    std::vector<AbilityInfo> abilityInfos;
    int32_t appIndex = 1;
    int32_t flags = 0;
    bool testRet = GetBundleDataMgr()->ImplicitQueryAbilityInfos(
        want, flags, DEFAULT_USERID, abilityInfos, appIndex);
    EXPECT_EQ(testRet, false);
    ErrCode testRet1 = GetBundleDataMgr()->ImplicitQueryAbilityInfosV9(
        want, flags, DEFAULT_USERID, abilityInfos, appIndex);
    EXPECT_EQ(testRet1, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: ImplicitQueryAbilityInfos_0200
 * @tc.name: test can get the ability infos
 * @tc.desc: 1.system run normally
 *           2.get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, ImplicitQueryAbilityInfos_0200, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", "bundleName", "", "moduleName");
    std::vector<AbilityInfo> abilityInfos;
    int32_t appIndex = -1;
    int32_t flags = 0;
    ErrCode testRet = GetBundleDataMgr()->ImplicitQueryAbilityInfosV9(
        want, flags, DEFAULT_USERID, abilityInfos, appIndex);
    EXPECT_EQ(testRet, ERR_OK);
}

/**
 * @tc.number: ImplicitQueryAbilityInfos_0300
 * @tc.name: test can get the ability infos
 * @tc.desc: 1.system run normally
 *           2.get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, ImplicitQueryAbilityInfos_0300, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    std::vector<AbilityInfo> abilityInfos;
    int32_t appIndex = 0;
    int32_t flags = 0;
    GetBundleDataMgr()->ImplicitQueryAllAbilityInfos(
        want, flags, Constants::INVALID_USERID, abilityInfos, appIndex);
    ErrCode testRet = GetBundleDataMgr()->ImplicitQueryCurAbilityInfosV9(
        want, flags, DEFAULT_USERID, abilityInfos, appIndex);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    appIndex = 1;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", MODULE_NAME_TEST);
    GetBundleDataMgr()->ImplicitQueryAllAbilityInfos(
        want, flags, DEFAULT_USERID, abilityInfos, appIndex);
    EXPECT_EQ(abilityInfos.size(), 0);
}

/**
 * @tc.number: ImplicitQueryAbilityInfos_0400
 * @tc.name: test can get the ability infos
 * @tc.desc: 1.system run normally
 *           2.get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, ImplicitQueryAbilityInfos_0400, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    std::vector<AbilityInfo> abilityInfos;
    int32_t appIndex = 1;
    int32_t flags = 0;
    want.SetAction("action.system.home");
    want.AddEntity("entity.system.home");
    want.SetElementName("", BUNDLE_NAME_TEST, "", MODULE_NAME_TEST);
    GetBundleDataMgr()->ImplicitQueryAllAbilityInfosV9(
        want, flags, DEFAULT_USERID, abilityInfos, appIndex);
    EXPECT_EQ(abilityInfos.size(), 0);
}

/**
 * @tc.number: ImplicitQueryExtensionInfos_0100
 * @tc.name: test can get the extension infos
 * @tc.desc: 1.system run normally
 *           2.get extension info failed
 */
HWTEST_F(BmsBundleKitServiceTest, ImplicitQueryExtensionInfos_0100, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    int32_t appIndex = 1;
    int32_t flags = 0;
    bool res = GetBundleDataMgr()->ImplicitQueryExtensionInfos(
        want, flags, DEFAULT_USERID, extensionInfos, appIndex);
    EXPECT_EQ(res, false);
    ErrCode res1 = GetBundleDataMgr()->ImplicitQueryExtensionInfosV9(
        want, flags, DEFAULT_USERID, extensionInfos, appIndex);
    EXPECT_EQ(res1, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: QueryAbilityInfoWithFlags_0100
 * @tc.name: test can get the ability infos
 * @tc.desc: 1.system run normally
 *           2.get ability info failed
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfoWithFlags_0100, Function | SmallTest | Level1)
{
    std::optional<AbilityInfo> option;
    InnerBundleInfo innerBundleInfo;
    AbilityInfo info;
    bool testRet = GetBundleDataMgr()->QueryAbilityInfoWithFlags(
        option, GET_ABILITY_INFO_SYSTEMAPP_ONLY, DEFAULT_USERID, innerBundleInfo, info);
    EXPECT_EQ(testRet, false);
    testRet = GetBundleDataMgr()->QueryAbilityInfoWithFlags(
        option, GET_ABILITY_INFO_WITH_PERMISSION, DEFAULT_USERID, innerBundleInfo, info);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: GetAllBundleInfos_0100
 * @tc.name: test can get the bundle infos
 * @tc.desc: 1.system run normally
 *           2.get bundle info failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllBundleInfos_0100, Function | SmallTest | Level1)
{
    std::vector<BundleInfo> bundleInfos;
    int32_t flags = 0;
    InnerBundleInfo innerBundleInfo;
    GetBundleDataMgr()->bundleInfos_.insert(
        pair<std::string, InnerBundleInfo>("moduleName", innerBundleInfo));
    EXPECT_FALSE(GetBundleDataMgr()->bundleInfos_.empty());
    bool removable = false;
    GetBundleDataMgr()->UpdateRemovable("bundleName", removable);
    GetBundleDataMgr()->UpdateRemovable(BUNDLE_NAME_TEST, removable);
    bool testRet = GetBundleDataMgr()->GetAllBundleInfos(flags, bundleInfos);
    EXPECT_EQ(testRet, true);
    ErrCode testRet1 = GetBundleDataMgr()->GetAllBundleInfosV9(flags, bundleInfos);
    EXPECT_EQ(testRet1, ERR_OK);
}

/**
 * @tc.number: SetHideDesktopIcon_0001
 * @tc.name: test can SetHideDesktopIcon
 * @tc.desc: 1.system run normally
 *           2.SetHideDesktopIcon
 */
HWTEST_F(BmsBundleKitServiceTest, SetHideDesktopIcon_0001, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->hideDesktopIcon = false;
    innerBundleInfo.baseApplicationInfo_->needAppDetail = true;
    innerBundleInfo.baseApplicationInfo_->appDetailAbilityLibraryPath = "path";
    innerBundleInfo.SetHideDesktopIcon(true);
    EXPECT_TRUE(innerBundleInfo.GetBaseApplicationInfo().hideDesktopIcon);
    EXPECT_FALSE(innerBundleInfo.GetBaseApplicationInfo().needAppDetail);
    EXPECT_TRUE(innerBundleInfo.GetBaseApplicationInfo().appDetailAbilityLibraryPath.empty());
}

/**
 * @tc.number: SetHideDesktopIcon_0002
 * @tc.name: test can SetHideDesktopIcon
 * @tc.desc: 1.system run normally
 *           2.SetHideDesktopIcon
 */
HWTEST_F(BmsBundleKitServiceTest, SetHideDesktopIcon_0002, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->hideDesktopIcon = false;
    innerBundleInfo.baseApplicationInfo_->needAppDetail = true;
    innerBundleInfo.baseApplicationInfo_->appDetailAbilityLibraryPath = "path";
    innerBundleInfo.SetHideDesktopIcon(false);
    EXPECT_FALSE(innerBundleInfo.GetBaseApplicationInfo().hideDesktopIcon);
    EXPECT_TRUE(innerBundleInfo.GetBaseApplicationInfo().needAppDetail);
    EXPECT_FALSE(innerBundleInfo.GetBaseApplicationInfo().appDetailAbilityLibraryPath.empty());
}

/**
 * @tc.number: UpdateAppDetailAbilityAttrs_0001
 * @tc.name: test can UpdateAppDetailAbilityAttrs
 * @tc.desc: 1.system run normally
 *           2.UpdateAppDetailAbilityAttrs
 */
HWTEST_F(BmsBundleKitServiceTest, UpdateAppDetailAbilityAttrs_0001, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->hideDesktopIcon = true;
    std::string keyName = ServiceConstants::APP_DETAIL_ABILITY;
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.name = ServiceConstants::APP_DETAIL_ABILITY;
    innerBundleInfo.InsertAbilitiesInfo(keyName, innerAbilityInfo);

    innerBundleInfo.UpdateAppDetailAbilityAttrs();
    EXPECT_TRUE(innerBundleInfo.GetBaseApplicationInfo().hideDesktopIcon);
    EXPECT_FALSE(innerBundleInfo.GetBaseApplicationInfo().needAppDetail);
}

/**
 * @tc.number: UpdateAppDetailAbilityAttrs_0002
 * @tc.name: test can UpdateAppDetailAbilityAttrs
 * @tc.desc: 1.system run normally
 *           2.UpdateAppDetailAbilityAttrs
 */
HWTEST_F(BmsBundleKitServiceTest, UpdateAppDetailAbilityAttrs_0002, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->hideDesktopIcon = false;
    innerBundleInfo.baseApplicationInfo_->needAppDetail = false;
    innerBundleInfo.UpdateAppDetailAbilityAttrs();
    EXPECT_FALSE(innerBundleInfo.GetBaseApplicationInfo().hideDesktopIcon);
    EXPECT_FALSE(innerBundleInfo.GetBaseApplicationInfo().needAppDetail);
}

/**
 * @tc.number: UpdateAppDetailAbilityAttrs_0003
 * @tc.name: test can UpdateAppDetailAbilityAttrs
 * @tc.desc: 1.system run normally
 *           2.UpdateAppDetailAbilityAttrs
 */
HWTEST_F(BmsBundleKitServiceTest, UpdateAppDetailAbilityAttrs_0003, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->needAppDetail = true;
    Skill skill;
    skill.actions = {ACTION};
    skill.entities = {ENTITY};
    std::vector<Skill> skills;
    skills.emplace_back(skill);
    innerBundleInfo.InsertSkillInfo(BUNDLE_NAME, skills);
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.type = AbilityType::PAGE;
    innerBundleInfo.InsertAbilitiesInfo(BUNDLE_NAME, innerAbilityInfo);
    innerBundleInfo.UpdateAppDetailAbilityAttrs();
    EXPECT_FALSE(innerBundleInfo.GetBaseApplicationInfo().hideDesktopIcon);
    EXPECT_FALSE(innerBundleInfo.GetBaseApplicationInfo().needAppDetail);
}

/**
 * @tc.number: UpdateAppDetailAbilityAttrs_0004
 * @tc.name: test can UpdateAppDetailAbilityAttrs
 * @tc.desc: 1.system run normally
 *           2.UpdateAppDetailAbilityAttrs
 */
HWTEST_F(BmsBundleKitServiceTest, UpdateAppDetailAbilityAttrs_0004, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->needAppDetail = true;
    innerBundleInfo.UpdateAppDetailAbilityAttrs();
    EXPECT_FALSE(innerBundleInfo.GetBaseApplicationInfo().hideDesktopIcon);
    EXPECT_TRUE(innerBundleInfo.GetBaseApplicationInfo().needAppDetail);
}

/**
 * @tc.number: UpdateAppDetailAbilityAttrs_0005
 * @tc.name: test can UpdateAppDetailAbilityAttrs
 * @tc.desc: 1.system run normally
 *           2.UpdateAppDetailAbilityAttrs
 */
HWTEST_F(BmsBundleKitServiceTest, UpdateAppDetailAbilityAttrs_0005, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->needAppDetail = true;
    Skill skill;
    skill.actions = {ACTION};
    skill.entities = {ENTITY};
    std::vector<Skill> skills;
    skills.emplace_back(skill);
    innerBundleInfo.InsertSkillInfo(BUNDLE_NAME, skills);
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.type = AbilityType::DATA;
    innerBundleInfo.InsertAbilitiesInfo(BUNDLE_NAME, innerAbilityInfo);
    innerBundleInfo.UpdateAppDetailAbilityAttrs();
    EXPECT_FALSE(innerBundleInfo.GetBaseApplicationInfo().hideDesktopIcon);
    EXPECT_TRUE(innerBundleInfo.GetBaseApplicationInfo().needAppDetail);
}

/**
 * @tc.number: UpdateAppDetailAbilityAttrs_0006
 * @tc.name: test can UpdateAppDetailAbilityAttrs
 * @tc.desc: 1.system run normally
 *           2.UpdateAppDetailAbilityAttrs
 */
HWTEST_F(BmsBundleKitServiceTest, UpdateAppDetailAbilityAttrs_0006, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->needAppDetail = true;
    Skill skill;
    skill.actions = {ACTION};
    skill.entities = {ENTITY};
    std::vector<Skill> skills;
    skills.emplace_back(skill);
    innerBundleInfo.InsertSkillInfo(BUNDLE_NAME, skills);
    InnerAbilityInfo innerAbilityInfo;
    innerBundleInfo.InsertAbilitiesInfo(MODULE_NAME, innerAbilityInfo);

    innerAbilityInfo.name = ServiceConstants::APP_DETAIL_ABILITY;
    innerAbilityInfo.type = AbilityType::PAGE;
    innerBundleInfo.InsertAbilitiesInfo(BUNDLE_NAME, innerAbilityInfo);

    innerBundleInfo.UpdateAppDetailAbilityAttrs();
    EXPECT_FALSE(innerBundleInfo.GetBaseApplicationInfo().hideDesktopIcon);
    EXPECT_FALSE(innerBundleInfo.GetBaseApplicationInfo().needAppDetail);
}

/**
 * @tc.number: UpdateAppDetailAbilityAttrs_0007
 * @tc.name: test can UpdateAppDetailAbilityAttrs
 * @tc.desc: 1.system run normally
 *           2.UpdateAppDetailAbilityAttrs
 */
HWTEST_F(BmsBundleKitServiceTest, UpdateAppDetailAbilityAttrs_0007, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->needAppDetail = false;
    InnerAbilityInfo innerAbilityInfo;
    innerBundleInfo.InsertAbilitiesInfo(MODULE_NAME, innerAbilityInfo);

    innerAbilityInfo.name = ServiceConstants::APP_DETAIL_ABILITY;
    innerAbilityInfo.type = AbilityType::PAGE;
    innerBundleInfo.InsertAbilitiesInfo(BUNDLE_NAME, innerAbilityInfo);

    innerBundleInfo.UpdateAppDetailAbilityAttrs();
    EXPECT_FALSE(innerBundleInfo.GetBaseApplicationInfo().hideDesktopIcon);
    EXPECT_FALSE(innerBundleInfo.GetBaseApplicationInfo().needAppDetail);
}

/**
 * @tc.number: UpdateAppDetailAbilityAttrs_0008
 * @tc.name: test can UpdateAppDetailAbilityAttrs
 * @tc.desc: 1.system run normally
 *           2.UpdateAppDetailAbilityAttrs
 */
HWTEST_F(BmsBundleKitServiceTest, UpdateAppDetailAbilityAttrs_0008, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->needAppDetail = true;
    InnerAbilityInfo innerAbilityInfo;
    innerBundleInfo.InsertAbilitiesInfo(ABILITY_NAME, innerAbilityInfo);

    innerAbilityInfo.name = ServiceConstants::APP_DETAIL_ABILITY;
    innerAbilityInfo.type = AbilityType::PAGE;
    innerBundleInfo.InsertAbilitiesInfo(BUNDLE_NAME, innerAbilityInfo);

    innerBundleInfo.UpdateAppDetailAbilityAttrs();
    EXPECT_FALSE(innerBundleInfo.GetBaseApplicationInfo().hideDesktopIcon);
    EXPECT_TRUE(innerBundleInfo.GetBaseApplicationInfo().needAppDetail);

    const auto abilityInfos = innerBundleInfo.GetInnerAbilityInfos();
    EXPECT_FALSE(abilityInfos.find(ABILITY_NAME) == abilityInfos.end());
    EXPECT_TRUE(abilityInfos.find(BUNDLE_NAME) == abilityInfos.end());
}

/**
 * @tc.number: IsHideDesktopIcon_0001
 * @tc.name: test can IsHideDesktopIcon
 * @tc.desc: 1.system run normally
 *           2.IsHideDesktopIcon
 */
HWTEST_F(BmsBundleKitServiceTest, IsHideDesktopIcon_0001, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->needAppDetail = true;
    bool ret = innerBundleInfo.IsHideDesktopIcon();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsHideDesktopIcon_0002
 * @tc.name: test can IsHideDesktopIcon
 * @tc.desc: 1.system run normally
 *           2.IsHideDesktopIcon
 */
HWTEST_F(BmsBundleKitServiceTest, IsHideDesktopIcon_0002, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->needAppDetail = false;
    bool ret = innerBundleInfo.IsHideDesktopIcon();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: AppProvisionInfo_0001
 * @tc.name: test AppProvisionInfo Marshalling
 * @tc.desc: 1.system run normally
 *           2. AppProvisionInfo Marshalling
 */
HWTEST_F(BmsBundleKitServiceTest, AppProvisionInfo_0001, Function | SmallTest | Level1)
{
    AppProvisionInfo appProvisionInfo;
    Parcel parcel;
    auto ret = appProvisionInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: AppProvisionInfo_0002
 * @tc.name: test AppProvisionInfo ReadFromParcel
 * @tc.desc: 1.system run normally
 *           2. AppProvisionInfo ReadFromParcel
 */
HWTEST_F(BmsBundleKitServiceTest, AppProvisionInfo_0002, Function | SmallTest | Level1)
{
    AppProvisionInfo appProvisionInfo;
    Parcel parcel;
    auto ret = appProvisionInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);

    ret = appProvisionInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: AppProvisionInfo_0003
 * @tc.name: test AppProvisionInfo ReadFromParcel
 * @tc.desc: 1.system run normally
 *           2. AppProvisionInfo ReadFromParcel
 */
HWTEST_F(BmsBundleKitServiceTest, AppProvisionInfo_0003, Function | SmallTest | Level1)
{
    AppProvisionInfo appProvisionInfo;
    Parcel parcel;
    auto ret = appProvisionInfo.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: AppProvisionInfo_0004
 * @tc.name: test AppProvisionInfo Unmarshalling
 * @tc.desc: 1.system run normally
 *           2. AppProvisionInfo Unmarshalling
 */
HWTEST_F(BmsBundleKitServiceTest, AppProvisionInfo_0004, Function | SmallTest | Level1)
{
    AppProvisionInfo appProvisionInfo;
    Parcel parcel;
    AppProvisionInfo *info = appProvisionInfo.Unmarshalling(parcel);
    EXPECT_EQ(info, nullptr);
}

/**
 * @tc.number: AppProvisionInfo_0005
 * @tc.name: test AppProvisionInfo Marshalling
 * @tc.desc: 1.system run normally
 *           2. AppProvisionInfo Marshalling
 */
HWTEST_F(BmsBundleKitServiceTest, AppProvisionInfo_0005, Function | SmallTest | Level1)
{
    AppProvisionInfo appProvisionInfo;
    appProvisionInfo.versionCode = 200;
    Parcel parcel;
    auto ret = appProvisionInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);

    AppProvisionInfo *info = AppProvisionInfo::Unmarshalling(parcel);
    EXPECT_NE(info, nullptr);
    if (info != nullptr) {
        EXPECT_EQ(appProvisionInfo.versionCode, info->versionCode);
        delete info;
    }
}

/**
 * @tc.number: GetAppProvisionInfo_0001
 * @tc.name: test can get the bundleName's appProvisionInfo
 * @tc.desc: 1.system run normal
 *           2.get appProvisionInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAppProvisionInfo_0001, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    AppProvisionInfo appProvisionInfo;
    auto testRet = hostImpl->GetAppProvisionInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, appProvisionInfo);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetAppProvisionInfo_0002
 * @tc.name: test can get the bundleName's appProvisionInfo
 * @tc.desc: 1.system run normal
 *           2.get appProvisionInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAppProvisionInfo_0002, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    AppProvisionInfo appProvisionInfo;
    auto testRet = hostImpl->GetAppProvisionInfo(BUNDLE_NAME_TEST, INVALID_UID, appProvisionInfo);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAppProvisionInfo_0003
 * @tc.name: test can get the bundleName's appProvisionInfo
 * @tc.desc: 1.system run normally
 *           2.get appProvisionInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAppProvisionInfo_0003, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    AppProvisionInfo appProvisionInfo;
    auto ret = bundleMgrProxy->GetAppProvisionInfo(EMPTY_STRING, DEFAULT_USERID, appProvisionInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: GetAppProvisionInfo_0004
 * @tc.name: test can get the bundleName's appProvisionInfo
 * @tc.desc: 1.system run normally
 *           2.get appProvisionInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAppProvisionInfo_0004, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    AppProvisionInfo appProvisionInfo;
    auto ret = bundleMgrProxy->GetAppProvisionInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, appProvisionInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetAppProvisionInfo_0005
 * @tc.name: test can get the bundleName's appProvisionInfo
 * @tc.desc: 1.system run normally
 *           2.get appProvisionInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAppProvisionInfo_0005, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    AppProvisionInfo appProvisionInfo;
    auto ret = bundleMgrProxy->GetAppProvisionInfo(BUNDLE_NAME_TEST, INVALID_UID, appProvisionInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAppProvisionInfo_0006
 * @tc.name: test can get the bundleName's appProvisionInfo
 * @tc.desc: 1.system run normally
 *           2.get appProvisionInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAppProvisionInfo_0006, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AppProvisionInfo appProvisionInfo;
    auto ret = dataMgr->GetAppProvisionInfo(BUNDLE_NAME_TEST, DEFAULT_USERID, appProvisionInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetAppProvisionInfo_0007
 * @tc.name: test can get the bundleName's appProvisionInfo
 * @tc.desc: 1.system run normally
 *           2.get appProvisionInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAppProvisionInfo_0007, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AppProvisionInfo appProvisionInfo;
    auto ret = dataMgr->GetAppProvisionInfo(BUNDLE_NAME_TEST, INVALID_UID, appProvisionInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: BaseSharedBundleInfoTest
 * @tc.name: Test struct BaseSharedBundleInfo
 * @tc.desc: 1.Test parcel of BaseSharedBundleInfo
 */
HWTEST_F(BmsBundleKitServiceTest, BaseSharedBundleInfoTest, Function | SmallTest | Level1)
{
    BaseSharedBundleInfo info;
    info.bundleName = BUNDLE_NAME;
    OHOS::Parcel parcel;
    bool res = info.Marshalling(parcel);
    EXPECT_EQ(res, true);
    BaseSharedBundleInfo *newInfo = BaseSharedBundleInfo::Unmarshalling(parcel);
    EXPECT_TRUE(newInfo != nullptr);
    delete newInfo;
    newInfo = nullptr;
}

/**
 * @tc.number: GetBaseSharedBundleInfos_0100
 * @tc.name: Test use different param with GetBaseSharedBundleInfos
 * @tc.desc: 1.Test GetBaseSharedBundleInfos
 */
HWTEST_F(BmsBundleKitServiceTest, GetBaseSharedBundleInfos_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    std::vector<BaseSharedBundleInfo> baseSharedBundleInfos;
    auto ret = bundleMgrProxy->GetBaseSharedBundleInfos(
            BUNDLE_NAME_TEST, baseSharedBundleInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    ret = bundleMgrProxy->GetBaseSharedBundleInfos("", baseSharedBundleInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetBaseSharedBundleInfos_0200
 * @tc.name: Test use different param with GetBaseSharedBundleInfos
 * @tc.desc: 1.Test GetBaseSharedBundleInfos
 */
HWTEST_F(BmsBundleKitServiceTest, GetBaseSharedBundleInfos_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    std::vector<BaseSharedBundleInfo> infos;
    bool ret = hostImpl->GetBaseSharedBundleInfos(BUNDLE_NAME_TEST, infos);
    EXPECT_EQ(ret, false);
    ret = hostImpl->GetBaseSharedBundleInfos("", infos);
    EXPECT_EQ(ret, true);
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: BaseSharedBundleInfo_0100
 * @tc.name: Test GetMaxVerBaseSharedBundleInfo
 * @tc.desc: 1.Test GetMaxVerBaseSharedBundleInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleKitServiceTest, BaseSharedBundleInfo_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    BaseSharedBundleInfo packageInfo;
    bool ret = info.GetMaxVerBaseSharedBundleInfo("", packageInfo);
    EXPECT_EQ(ret, false);
    std::vector<InnerModuleInfo> moduleInfos;
    info.innerSharedModuleInfos_["entry"] = moduleInfos;
    ret = info.GetMaxVerBaseSharedBundleInfo("entry", packageInfo);
    EXPECT_EQ(ret, false);
    InnerModuleInfo moduleInfo;
    moduleInfo.bundleType = BundleType::APP;
    moduleInfos.emplace_back(moduleInfo);
    info.innerSharedModuleInfos_["entry"] = moduleInfos;
    ret = info.GetMaxVerBaseSharedBundleInfo("entry", packageInfo);
    EXPECT_EQ(ret, false);

    moduleInfos.clear();
    moduleInfo.bundleType = BundleType::SHARED;
    moduleInfos.emplace_back(moduleInfo);
    info.innerSharedModuleInfos_["entry"] = moduleInfos;
    ret = info.GetMaxVerBaseSharedBundleInfo("entry", packageInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BaseSharedBundleInfo_0200
 * @tc.name: Test GetBaseSharedBundleInfo
 * @tc.desc: 1.Test GetBaseSharedBundleInfo of InnerBundleInfo
 */
HWTEST_F(BmsBundleKitServiceTest, BaseSharedBundleInfo_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    BaseSharedBundleInfo packageInfo;
    bool ret = info.GetBaseSharedBundleInfo("", BUNDLE_VERSION_CODE, packageInfo);
    EXPECT_EQ(ret, false);
    std::vector<InnerModuleInfo> moduleInfos;
    info.innerSharedModuleInfos_["entry"] = moduleInfos;
    ret = info.GetBaseSharedBundleInfo("entry", BUNDLE_VERSION_CODE, packageInfo);
    EXPECT_EQ(ret, false);

    InnerModuleInfo moduleInfo;
    moduleInfo.bundleType = BundleType::APP;
    moduleInfos.emplace_back(moduleInfo);
    info.innerSharedModuleInfos_["entry"] = moduleInfos;
    ret = info.GetBaseSharedBundleInfo("entry", BUNDLE_VERSION_CODE, packageInfo);
    EXPECT_EQ(ret, false);

    moduleInfos.clear();
    moduleInfo.bundleType = BundleType::SHARED;
    moduleInfos.emplace_back(moduleInfo);
    info.innerSharedModuleInfos_["entry"] = moduleInfos;
    ret = info.GetBaseSharedBundleInfo("entry", BUNDLE_VERSION_CODE, packageInfo);
    EXPECT_EQ(ret, false);

    moduleInfos.clear();
    moduleInfo.versionCode = BUNDLE_VERSION_CODE;
    moduleInfos.emplace_back(moduleInfo);
    info.innerSharedModuleInfos_["entry"] = moduleInfos;
    ret = info.GetBaseSharedBundleInfo("entry", BUNDLE_VERSION_CODE, packageInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BaseSharedBundleInfo_0300
 * @tc.name: Test SetSharedBundleModuleNativeLibraryPath
 * @tc.desc: 1.Test SetSharedBundleModuleNativeLibraryPath of InnerBundleInfo
 */
HWTEST_F(BmsBundleKitServiceTest, BaseSharedBundleInfo_0300, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.SetCurrentModulePackage("entry");
    std::string nativeLibraryPath = "";
    info.SetSharedModuleNativeLibraryPath(nativeLibraryPath);
    EXPECT_EQ(nativeLibraryPath.empty(), true);

    nativeLibraryPath = "libs/arm";
    std::vector<InnerModuleInfo> moduleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.versionCode = BUNDLE_VERSION_CODE;
    moduleInfos.emplace_back(moduleInfo);
    info.innerSharedModuleInfos_["entry"] = moduleInfos;
    info.InsertInnerModuleInfo("entry", moduleInfo);
    info.SetSharedModuleNativeLibraryPath(nativeLibraryPath);
    EXPECT_EQ(info.GetInnerSharedModuleInfos().empty(), false);
}

/**
 * @tc.number: SharedBundleInfoTest
 * @tc.name: SharedBundleInfo to_json and from_json branch cover
 * @tc.desc: 1.Test to_json and from_json
 */
HWTEST_F(BmsBundleKitServiceTest, SharedBundleInfoTest, Function | SmallTest | Level1)
{
    SharedBundleInfo sharedBundleInfo;
    sharedBundleInfo.name = COMMON_EVENT_NAME;
    nlohmann::json jsonObj;
    to_json(jsonObj, sharedBundleInfo);
    SharedBundleInfo result;
    from_json(jsonObj, result);
    EXPECT_EQ(result.name, COMMON_EVENT_NAME);
}

/**
 * @tc.number: SharedModuleInfoTest
 * @tc.name: SharedModuleInfo to_json and from_json branch cover
 * @tc.desc: 1.Test to_json and from_json
 */
HWTEST_F(BmsBundleKitServiceTest, SharedModuleInfoTest, Function | SmallTest | Level1)
{
    SharedModuleInfo sharedModuleInfo;
    sharedModuleInfo.name = COMMON_EVENT_NAME;
    nlohmann::json jsonObj;
    to_json(jsonObj, sharedModuleInfo);
    SharedModuleInfo result;
    from_json(jsonObj, result);
    EXPECT_EQ(result.name, COMMON_EVENT_NAME);
}

/**
 * @tc.number: GetSharedBundleInfo_0100
 * @tc.name: Test GetSharedBundleInfoBySelf
 * @tc.desc: Test GetSharedBundleInfoBySelf with BundleMgrProxy
 */
HWTEST_F(BmsBundleKitServiceTest, GetSharedBundleInfo_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    SharedBundleInfo sharedBundleInfo;
    auto ret = bundleMgrProxy->GetSharedBundleInfoBySelf("", sharedBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    ret = bundleMgrProxy->GetSharedBundleInfoBySelf(BUNDLE_NAME_TEST, sharedBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ret = dataMgr->GetSharedBundleInfoBySelf("", sharedBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    InnerBundleInfo info;
    dataMgr->bundleInfos_.try_emplace(BUNDLE_NAME_TEST, info);
    ret = dataMgr->GetSharedBundleInfoBySelf(BUNDLE_NAME_TEST, sharedBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ret = hostImpl->GetSharedBundleInfoBySelf(BUNDLE_NAME_TEST, sharedBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetSharedBundleInfo_0200
 * @tc.name: Test GetSharedBundleInfo
 * @tc.desc: Test GetSharedBundleInfo with InnerBundleInfo
 */
HWTEST_F(BmsBundleKitServiceTest, GetSharedBundleInfo_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    SharedBundleInfo sharedBundleInfo;
    bool ret = info.GetSharedBundleInfo(sharedBundleInfo);
    EXPECT_EQ(ret, true);

    std::vector<InnerModuleInfo> innerModuleInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.name = BUNDLE_NAME_TEST;
    innerModuleInfo.emplace_back(moduleInfo);
    info.innerSharedModuleInfos_.try_emplace(MODULE_NAME_TEST, innerModuleInfo);
    ret = info.GetSharedBundleInfo(sharedBundleInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: GetSharedBundleInfo_0300
 * @tc.name: Test GetSharedBundleInfo
 * @tc.desc: Test GetSharedBundleInfo with InnerBundleInfo
 */
HWTEST_F(BmsBundleKitServiceTest, GetSharedBundleInfo_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    std::vector<SharedBundleInfo> sharedBundles;
    auto ret = GetBundleDataMgr()->GetSharedBundleInfo("", "", sharedBundles);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);

    ret = GetBundleDataMgr()->GetSharedBundleInfo(BUNDLE_NAME_TEST, MODULE_NAME_TEST, sharedBundles);
    EXPECT_EQ(ret, ERR_OK);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetSharedDependencies_0100
 * @tc.name: Test GetSharedDependencies
 * @tc.desc: Test GetSharedDependencies with BundleMgrProxy
 */
HWTEST_F(BmsBundleKitServiceTest, GetSharedDependencies_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);

    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    std::vector<Dependency> dependencies;
    auto ret = bundleMgrProxy->GetSharedDependencies("", "", dependencies);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    ret = bundleMgrProxy->GetSharedDependencies(
            BUNDLE_NAME_TEST, MODULE_NAME_TEST, dependencies);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    ret = dataMgr->GetSharedDependencies("", "", dependencies);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    InnerBundleInfo info;
    dataMgr->bundleInfos_.try_emplace(BUNDLE_NAME_TEST, info);
    ret = dataMgr->GetSharedDependencies(
            BUNDLE_NAME_TEST, MODULE_NAME_TEST, dependencies);
    EXPECT_EQ(ret, ERR_OK);

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ret = hostImpl->GetSharedDependencies(
            BUNDLE_NAME_TEST, MODULE_NAME_TEST, dependencies);
    EXPECT_EQ(ret, ERR_OK);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetSharedDependencies_0200
 * @tc.name: Test GetSharedDependencies
 * @tc.desc: Test GetSharedDependencies with InnerBundleInfo
 */
HWTEST_F(BmsBundleKitServiceTest, GetSharedDependencies_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::vector<Dependency> dependencies;
    bool ret = info.GetSharedDependencies("", dependencies);
    EXPECT_EQ(ret, false);

    InnerModuleInfo moduleInfo;
    info.InsertInnerModuleInfo(MODULE_NAME_TEST, moduleInfo);
    ret = info.GetSharedDependencies(MODULE_NAME_TEST, dependencies);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: SetAllowedAcls_0001
 * @tc.name: Test SetAllowedAcls
 * @tc.desc: 1.Test SetAllowedAcls of InnerBundleInfo, acls empty
 */
HWTEST_F(BmsBundleKitServiceTest, SetAllowedAcls_0001, Function | SmallTest | Level1)
{
    std::vector<std::string> acls;
    InnerBundleInfo info;
    info.SetAllowedAcls(acls);
    EXPECT_TRUE(info.GetAllowedAcls().empty());
}

/**
 * @tc.number: SetAllowedAcls_0002
 * @tc.name: Test SetAllowedAcls
 * @tc.desc: 1.Test SetAllowedAcls of InnerBundleInfo, acls not empty
 */
HWTEST_F(BmsBundleKitServiceTest, SetAllowedAcls_0002, Function | SmallTest | Level1)
{
    std::vector<std::string> acls;
    acls.push_back("");
    InnerBundleInfo info;
    info.SetAllowedAcls(acls);
    EXPECT_TRUE(info.GetAllowedAcls().empty());
}

/**
 * @tc.number: SetAllowedAcls_0003
 * @tc.name: Test SetAllowedAcls
 * @tc.desc: 1.Test SetAllowedAcls of InnerBundleInfo, acls not empty
 */
HWTEST_F(BmsBundleKitServiceTest, SetAllowedAcls_0003, Function | SmallTest | Level1)
{
    std::vector<std::string> acls;
    acls.push_back("ohos.permission.GET_BUNDLE_INFO");
    InnerBundleInfo info;
    info.SetAllowedAcls(acls);
    EXPECT_FALSE(info.GetAllowedAcls().empty());
}

/**
 * @tc.number: GetSpecifiedDistributionType_0001
 * @tc.name: test can get the bundleName's SpecifiedDistributionType
 * @tc.desc: 1.system run normally
 *           2.get SpecifiedDistributionType failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetSpecifiedDistributionType_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    } else {
        std::string specifiedDistributionType;
        auto ret = bundleMgrProxy->GetSpecifiedDistributionType(BUNDLE_NAME_TEST, specifiedDistributionType);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }
}

/**
 * @tc.number: GetSpecifiedDistributionType_0002
 * @tc.name: test can get the bundleName's SpecifiedDistributionType
 * @tc.desc: 1.system run normally
 *           2.get SpecifiedDistributionType failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetSpecifiedDistributionType_0002, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    } else {
        std::string specifiedDistributionType;
        auto ret = bundleMgrProxy->GetSpecifiedDistributionType("", specifiedDistributionType);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    }
}

/**
 * @tc.number: GetSpecifiedDistributionType_0003
 * @tc.name: test can get the bundleName's SpecifiedDistributionType
 * @tc.desc: 1.system run normally
 *           2.get SpecifiedDistributionType failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetSpecifiedDistributionType_0003, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    } else {
        std::string specifiedDistributionType;
        auto ret = bundleMgrProxy->GetSpecifiedDistributionType(BUNDLE_NAME_TEST, specifiedDistributionType);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetSpecifiedDistributionType_0004
 * @tc.name: test can get the bundleName's SpecifiedDistributionType
 * @tc.desc: 1.system run normally
 *           2.get SpecifiedDistributionType falied
 */
HWTEST_F(BmsBundleKitServiceTest, GetSpecifiedDistributionType_0004, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is nullptr.");
        EXPECT_EQ(dataMgr, nullptr);
    } else {
        std::string specifiedDistributionType;
        auto ret = dataMgr->GetSpecifiedDistributionType(BUNDLE_NAME_TEST, specifiedDistributionType);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }
}

/**
 * @tc.number: GetSpecifiedDistributionType_0005
 * @tc.name: test can get the bundleName's SpecifiedDistributionType
 * @tc.desc: 1.system run normally
 *           2.get SpecifiedDistributionType falied
 */
HWTEST_F(BmsBundleKitServiceTest, GetSpecifiedDistributionType_0005, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AppProvisionInfo appProvisionInfo;
    bool ans = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(BUNDLE_NAME_TEST,
        appProvisionInfo);
    EXPECT_TRUE(ans);

    auto dataMgr = GetBundleDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is nullptr.");
        EXPECT_EQ(dataMgr, nullptr);
    } else {
        std::string specifiedDistributionType;
        auto ret = dataMgr->GetSpecifiedDistributionType(BUNDLE_NAME_TEST, specifiedDistributionType);
        EXPECT_EQ(ret, ERR_OK);
    }

    MockUninstallBundle(BUNDLE_NAME_TEST);
    ans = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(BUNDLE_NAME_TEST);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: GetAdditionalInfo_0001
 * @tc.name: test can get the bundleName's AdditionalInfo
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAdditionalInfo_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    } else {
        std::string additionalInfo;
        auto ret = bundleMgrProxy->GetAdditionalInfo(BUNDLE_NAME_TEST, additionalInfo);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }
}

/**
 * @tc.number: GetAdditionalInfo_0002
 * @tc.name: test can get the bundleName's AdditionalInfo
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAdditionalInfo_0002, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    } else {
        std::string additionalInfo;
        auto ret = bundleMgrProxy->GetAdditionalInfo("", additionalInfo);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    }
}

/**
 * @tc.number: GetAdditionalInfo_0003
 * @tc.name: test can get the bundleName's AdditionalInfo
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAdditionalInfo_0003, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    } else {
        std::string additionalInfo;
        auto ret = bundleMgrProxy->GetAdditionalInfo(BUNDLE_NAME_TEST, additionalInfo);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAdditionalInfo_0004
 * @tc.name: test can get the bundleName's AdditionalInfo
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo falied
 */
HWTEST_F(BmsBundleKitServiceTest, GetAdditionalInfo_0004, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is nullptr.");
        EXPECT_EQ(dataMgr, nullptr);
    } else {
        std::string additionalInfo;
        auto ret = dataMgr->GetAdditionalInfo(BUNDLE_NAME_TEST, additionalInfo);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }
}

/**
 * @tc.number: GetAdditionalInfo_0005
 * @tc.name: test can get the bundleName's AdditionalInfo
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo succeed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAdditionalInfo_0005, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AppProvisionInfo appProvisionInfo;
    bool ans = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(BUNDLE_NAME_TEST,
        appProvisionInfo);
    EXPECT_TRUE(ans);

    auto dataMgr = GetBundleDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is nullptr.");
        EXPECT_EQ(dataMgr, nullptr);
    } else {
        std::string additionalInfo;
        auto ret = dataMgr->GetAdditionalInfo(BUNDLE_NAME_TEST, additionalInfo);
        EXPECT_EQ(ret, ERR_OK);
    }

    MockUninstallBundle(BUNDLE_NAME_TEST);
    ans = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(BUNDLE_NAME_TEST);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: GetAdditionalInfoForAllUser_0001
 * @tc.name: test can get the bundleName's AdditionalInfo
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAdditionalInfoForAllUser_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    } else {
        std::string additionalInfo;
        auto saveuid = getuid();
        setuid(Constants::FOUNDATION_UID);
        auto ret = bundleMgrProxy->GetAdditionalInfoForAllUser(BUNDLE_NAME_TEST, additionalInfo);
        setuid(saveuid);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }
}

/**
 * @tc.number: GetAdditionalInfoForAllUser_0002
 * @tc.name: test can get the bundleName's AdditionalInfo
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAdditionalInfoForAllUser_0002, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    } else {
        std::string additionalInfo;
        auto saveuid = getuid();
        setuid(Constants::FOUNDATION_UID);
        auto ret = bundleMgrProxy->GetAdditionalInfoForAllUser("", additionalInfo);
        setuid(saveuid);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    }
}

/**
 * @tc.number: GetAdditionalInfoForAllUser_0003
 * @tc.name: test can get the bundleName's AdditionalInfo
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAdditionalInfoForAllUser_0003, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    } else {
        std::string additionalInfo;
        auto saveuid = getuid();
        setuid(Constants::FOUNDATION_UID);
        auto ret = bundleMgrProxy->GetAdditionalInfoForAllUser(BUNDLE_NAME_TEST, additionalInfo);
        setuid(saveuid);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetAdditionalInfoForAllUser_0004
 * @tc.name: test can get the bundleName's AdditionalInfo
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo falied
 */
HWTEST_F(BmsBundleKitServiceTest, GetAdditionalInfoForAllUser_0004, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is nullptr.");
        EXPECT_EQ(dataMgr, nullptr);
    } else {
        std::string additionalInfo;
        auto ret = dataMgr->GetAdditionalInfoForAllUser(BUNDLE_NAME_TEST, additionalInfo);
        EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    }
}

/**
 * @tc.number: GetAdditionalInfoForAllUser_0005
 * @tc.name: test can get the bundleName's AdditionalInfo
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo succeed
 */
HWTEST_F(BmsBundleKitServiceTest, GetAdditionalInfoForAllUser_0005, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    AppProvisionInfo appProvisionInfo;
    bool ans = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(BUNDLE_NAME_TEST,
        appProvisionInfo);
    EXPECT_TRUE(ans);

    auto dataMgr = GetBundleDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is nullptr.");
        EXPECT_EQ(dataMgr, nullptr);
    } else {
        std::string additionalInfo;
        auto ret = dataMgr->GetAdditionalInfoForAllUser(BUNDLE_NAME_TEST, additionalInfo);
        EXPECT_EQ(ret, ERR_OK);
    }

    MockUninstallBundle(BUNDLE_NAME_TEST);
    ans = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(BUNDLE_NAME_TEST);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: GetAllLauncherAbility_0001
 * @tc.name: test get all launcherAbility
 * @tc.desc: 1.system run normally
 *           2.get GetAllLauncherAbility falied
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllLauncherAbility_0001, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    Want want;
    std::vector<AbilityInfo> abilityInfos;
    dataMgr->GetAllLauncherAbility(want, abilityInfos, DEFAULT_USER_ID_TEST, DEFAULT_USER_ID_TEST);
    EXPECT_NE(abilityInfos.size(), 0);
}

/**
 * @tc.number: GetAllLauncherAbility_0002
 * @tc.name: test get all launcherAbility
 * @tc.desc: 1.system run normally
 *           2.get GetAllLauncherAbility falied
 */
HWTEST_F(BmsBundleKitServiceTest, GetAllLauncherAbility_0002, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.bundleName = BUNDLE_NAME;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.bundleStatus_ = InnerBundleInfo::BundleStatus::DISABLED;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetEntryInstallationFree(true);

    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo userInfo;
    innerBundleUserInfos[MODULE_NAME] = userInfo;
    innerBundleInfo.innerBundleUserInfos_ = innerBundleUserInfos;

    Want want;
    std::vector<AbilityInfo> abilityInfos;
    dataMgr->bundleInfos_.insert(pair<std::string, InnerBundleInfo>(BUNDLE_NAME, innerBundleInfo));
    dataMgr->GetAllLauncherAbility(want, abilityInfos, DEFAULT_USER_ID_TEST, DEFAULT_USER_ID_TEST);
    EXPECT_NE(abilityInfos.size(), 0);
}

/**
 * @tc.number: GetLauncherAbilityByBundleName_0001
 * @tc.name: test get launcherAbility
 * @tc.desc: 1.system run normally
 *           2.get GetLauncherAbilityByBundleName falied
 */
HWTEST_F(BmsBundleKitServiceTest, GetLauncherAbilityByBundleName_0001, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    Want want;
    std::vector<AbilityInfo> abilityInfos;
    ErrCode res = dataMgr->GetLauncherAbilityByBundleName(
        want, abilityInfos, DEFAULT_USER_ID_TEST, DEFAULT_USER_ID_TEST);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetLauncherAbilityByBundleName_0002
 * @tc.name: test get launcherAbility
 * @tc.desc: 1.system run normally
 *           2.get GetLauncherAbilityByBundleName return ERR_OK
 */
HWTEST_F(BmsBundleKitServiceTest, GetLauncherAbilityByBundleName_0002, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    Want want;
    want.SetElementName(LAUNCHER_BUNDLE_NAME, ABILITY_NAME_TEST);

    ApplicationInfo applicationInfo;
    applicationInfo.name = LAUNCHER_BUNDLE_NAME;
    applicationInfo.bundleName = LAUNCHER_BUNDLE_NAME;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    std::vector<AbilityInfo> abilityInfos;
    dataMgr->bundleInfos_.insert(pair<std::string, InnerBundleInfo>(LAUNCHER_BUNDLE_NAME, innerBundleInfo));
    ErrCode res = dataMgr->GetLauncherAbilityByBundleName(
        want, abilityInfos, DEFAULT_USER_ID_TEST, DEFAULT_USER_ID_TEST);
    EXPECT_EQ(res, ERR_OK);

    res = dataMgr->UpdateBundleInstallState(LAUNCHER_BUNDLE_NAME, InstallState::UNINSTALL_START);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetLauncherAbilityByBundleName_0003
 * @tc.name: test get launcherAbility
 * @tc.desc: 1.system run normally
 *           2.get GetLauncherAbilityByBundleName return ERR_OK
 */
HWTEST_F(BmsBundleKitServiceTest, GetLauncherAbilityByBundleName_0003, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    Want want;
    want.SetElementName(LAUNCHER_BUNDLE_NAME, ABILITY_NAME_TEST);

    ApplicationInfo applicationInfo;
    applicationInfo.name = LAUNCHER_BUNDLE_NAME;
    applicationInfo.bundleName = LAUNCHER_BUNDLE_NAME;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.bundleStatus_ = InnerBundleInfo::BundleStatus::ENABLED;
    innerBundleInfo.SetHideDesktopIcon(true);

    std::vector<AbilityInfo> abilityInfos;
    dataMgr->bundleInfos_.insert(pair<std::string, InnerBundleInfo>(LAUNCHER_BUNDLE_NAME, innerBundleInfo));
    ErrCode res = dataMgr->GetLauncherAbilityByBundleName(
        want, abilityInfos, DEFAULT_USER_ID_TEST, DEFAULT_USER_ID_TEST);
    EXPECT_EQ(res, ERR_OK);

    res = dataMgr->UpdateBundleInstallState(LAUNCHER_BUNDLE_NAME, InstallState::UNINSTALL_START);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetLauncherAbilityByBundleName_0004
 * @tc.name: test get launcherAbility
 * @tc.desc: 1.system run normally
 *           2.get GetLauncherAbilityByBundleName return ERR_OK
 */
HWTEST_F(BmsBundleKitServiceTest, GetLauncherAbilityByBundleName_0004, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    Want want;
    want.SetElementName(LAUNCHER_BUNDLE_NAME, ABILITY_NAME_TEST);

    ApplicationInfo applicationInfo;
    applicationInfo.name = LAUNCHER_BUNDLE_NAME;
    applicationInfo.bundleName = LAUNCHER_BUNDLE_NAME;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.bundleStatus_ = InnerBundleInfo::BundleStatus::ENABLED;
    innerBundleInfo.SetHideDesktopIcon(false);
    innerBundleInfo.SetEntryInstallationFree(true);

    std::vector<AbilityInfo> abilityInfos;
    dataMgr->bundleInfos_.insert(pair<std::string, InnerBundleInfo>(LAUNCHER_BUNDLE_NAME, innerBundleInfo));
    ErrCode res = dataMgr->GetLauncherAbilityByBundleName(
        want, abilityInfos, DEFAULT_USER_ID_TEST, DEFAULT_USER_ID_TEST);
    EXPECT_EQ(res, ERR_OK);

    res = dataMgr->UpdateBundleInstallState(LAUNCHER_BUNDLE_NAME, InstallState::UNINSTALL_START);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetLauncherAbilityByBundleName_0005
 * @tc.name: test get launcherAbility
 * @tc.desc: 1.system run normally
 *           2.get GetLauncherAbilityByBundleName return ERR_OK
 */
HWTEST_F(BmsBundleKitServiceTest, GetLauncherAbilityByBundleName_0005, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    Want want;
    want.SetElementName(LAUNCHER_BUNDLE_NAME, ABILITY_NAME_TEST);

    ApplicationInfo applicationInfo;
    applicationInfo.name = LAUNCHER_BUNDLE_NAME;
    applicationInfo.bundleName = LAUNCHER_BUNDLE_NAME;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.bundleStatus_ = InnerBundleInfo::BundleStatus::ENABLED;
    innerBundleInfo.SetHideDesktopIcon(false);
    innerBundleInfo.SetEntryInstallationFree(false);

    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo userInfo;
    innerBundleUserInfos[MODULE_NAME] = userInfo;
    innerBundleInfo.innerBundleUserInfos_ = innerBundleUserInfos;

    std::vector<AbilityInfo> abilityInfos;
    dataMgr->bundleInfos_.insert(pair<std::string, InnerBundleInfo>(LAUNCHER_BUNDLE_NAME, innerBundleInfo));
    ErrCode res = dataMgr->GetLauncherAbilityByBundleName(
        want, abilityInfos, DEFAULT_USER_ID_TEST, DEFAULT_USER_ID_TEST);
    EXPECT_EQ(res, ERR_OK);

    res = dataMgr->UpdateBundleInstallState(LAUNCHER_BUNDLE_NAME, InstallState::UNINSTALL_START);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: SetModuleHapPath_001
 * @tc.name: test set SetModuleHapPath
 * @tc.desc: 1.system run normally
 *           2.SetModuleHapPath
 */
HWTEST_F(BmsBundleKitServiceTest, SetModuleHapPath_001, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.currentPackage_ = MODULE_NAME_TEST;
    std::string hapPath = HAP_FILE_PATH;
    innerBundleInfo.SetModuleHapPath(hapPath);
    EXPECT_NE(innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST].hapPath, hapPath);

    InnerModuleInfo moduleInfo;
    moduleInfo.modulePackage = MODULE_NAME_TEST;
    innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST] = moduleInfo;
    innerBundleInfo.SetModuleHapPath(hapPath);
    EXPECT_EQ(innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST].hapPath, hapPath);

    std::string nativeLibraryPath = "libs/arm";
    innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST].compressNativeLibs = true;
    innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST].nativeLibraryPath = nativeLibraryPath;
    innerBundleInfo.SetModuleHapPath(hapPath);
    EXPECT_EQ(innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST].nativeLibraryPath, nativeLibraryPath);

    innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST].compressNativeLibs = false;
    innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST].nativeLibraryPath = "";
    innerBundleInfo.SetModuleHapPath(hapPath);
    EXPECT_EQ(innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST].hapPath, hapPath);

    innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST].compressNativeLibs = false;
    innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST].nativeLibraryPath = nativeLibraryPath;
    innerBundleInfo.SetModuleHapPath(hapPath);
    EXPECT_NE(innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST].nativeLibraryPath, nativeLibraryPath);
}

/**
 * @tc.number: IsCompressNativeLibs_001
 * @tc.name: test IsCompressNativeLibs
 * @tc.desc: 1.system run normally
 *           2.IsCompressNativeLibs
 */
HWTEST_F(BmsBundleKitServiceTest, IsCompressNativeLibs_001, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    bool ret = innerBundleInfo.IsCompressNativeLibs(MODULE_NAME_TEST);
    EXPECT_TRUE(ret);

    innerBundleInfo.currentPackage_ = MODULE_NAME_TEST;
    InnerModuleInfo moduleInfo;
    moduleInfo.modulePackage = MODULE_NAME_TEST;
    moduleInfo.moduleName = MODULE_NAME_TEST;
    moduleInfo.name = MODULE_NAME_TEST;
    innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST] = moduleInfo;

    ret = innerBundleInfo.IsCompressNativeLibs(MODULE_NAME_TEST);
    EXPECT_TRUE(ret);

    innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST].compressNativeLibs = false;
    ret = innerBundleInfo.IsCompressNativeLibs(MODULE_NAME_TEST);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SetNativeLibraryFileNames_001
 * @tc.name: test SetNativeLibraryFileNames
 * @tc.desc: 1.system run normally
 *           2.SetNativeLibraryFileNames
 */
HWTEST_F(BmsBundleKitServiceTest, SetNativeLibraryFileNames_001, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    const std::vector<std::string> fileNames{"com.so"};
    innerBundleInfo.SetNativeLibraryFileNames(MODULE_NAME_TEST, fileNames);
    EXPECT_TRUE(innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST].nativeLibraryFileNames.empty());

    InnerModuleInfo moduleInfo;
    moduleInfo.modulePackage = MODULE_NAME_TEST;
    moduleInfo.moduleName = MODULE_NAME_TEST;
    moduleInfo.name = MODULE_NAME_TEST;
    innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST] = moduleInfo;

    innerBundleInfo.SetNativeLibraryFileNames(MODULE_NAME_TEST, fileNames);
    EXPECT_FALSE(innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST].nativeLibraryFileNames.empty());
}

/**
 * @tc.number: UpdateSharedModuleInfo_001
 * @tc.name: test UpdateSharedModuleInfo
 * @tc.desc: 1.system run normally
 *           2.UpdateSharedModuleInfo
 */
HWTEST_F(BmsBundleKitServiceTest, UpdateSharedModuleInfo_001, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.currentPackage_ = "";
    innerBundleInfo.UpdateSharedModuleInfo();
    EXPECT_TRUE(innerBundleInfo.innerSharedModuleInfos_.empty());
    InnerModuleInfo moduleInfo;
    moduleInfo.versionCode = 1000;
    std::vector<InnerModuleInfo> moduleInfos;
    moduleInfos.push_back(moduleInfo);
    moduleInfo.versionCode = 2000;
    moduleInfos.push_back(moduleInfo);
    innerBundleInfo.innerSharedModuleInfos_[MODULE_NAME_TEST_1] = moduleInfos;

    innerBundleInfo.currentPackage_ = MODULE_NAME_TEST_1;
    innerBundleInfo.UpdateSharedModuleInfo();
    EXPECT_FALSE(innerBundleInfo.innerSharedModuleInfos_.empty());
    EXPECT_TRUE(innerBundleInfo.innerSharedModuleInfos_[MODULE_NAME_TEST_1][0].cpuAbi.empty());
    EXPECT_TRUE(innerBundleInfo.innerSharedModuleInfos_[MODULE_NAME_TEST_1][1].cpuAbi.empty());

    moduleInfo.cpuAbi = "libs/arm";
    innerBundleInfo.innerModuleInfos_[MODULE_NAME_TEST_1] = moduleInfo;
    innerBundleInfo.UpdateSharedModuleInfo();
    EXPECT_TRUE(innerBundleInfo.innerSharedModuleInfos_[MODULE_NAME_TEST_1][0].cpuAbi.empty());
    EXPECT_FALSE(innerBundleInfo.innerSharedModuleInfos_[MODULE_NAME_TEST_1][1].cpuAbi.empty());
}

/**
 * @tc.number: GetLauncherAbilityByBundleName_0006
 * @tc.name: test get launcherAbility
 * @tc.desc: 1.system run normally
 *           2.get GetLauncherAbilityByBundleName return ERR_BUNDLE_MANAGER_APPLICATION_DISABLED
 * @tc.require: issueI7FMPK
 */
HWTEST_F(BmsBundleKitServiceTest, GetLauncherAbilityByBundleName_0006, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    Want want;
    want.SetElementName(LAUNCHER_BUNDLE_NAME, ABILITY_NAME_TEST);
    ApplicationInfo applicationInfo;
    applicationInfo.name = LAUNCHER_BUNDLE_NAME;
    applicationInfo.bundleName = LAUNCHER_BUNDLE_NAME;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.bundleStatus_ = InnerBundleInfo::BundleStatus::DISABLED;
    ClearBundleInfo(LAUNCHER_BUNDLE_NAME);
    dataMgr->bundleInfos_.insert(pair<std::string, InnerBundleInfo>(LAUNCHER_BUNDLE_NAME, innerBundleInfo));
    std::vector<AbilityInfo> abilityInfos;
    ErrCode res = dataMgr->GetLauncherAbilityByBundleName(
        want, abilityInfos, DEFAULT_USER_ID_TEST, DEFAULT_USER_ID_TEST);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_DISABLED);
    dataMgr->bundleInfos_.erase(LAUNCHER_BUNDLE_NAME);
}

/**
 * @tc.number: GetLauncherAbilityByBundleName_0007
 * @tc.name: test get launcherAbility
 * @tc.desc: 1.system run normally
 *           2.get GetLauncherAbilityByBundleName hideDesktopIcon return ERR_OK
 * @tc.require: issueI7FMPK
 */
HWTEST_F(BmsBundleKitServiceTest, GetLauncherAbilityByBundleName_0007, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    Want want;
    want.SetElementName(LAUNCHER_BUNDLE_NAME, ABILITY_NAME_TEST);
    ApplicationInfo applicationInfo;
    applicationInfo.name = LAUNCHER_BUNDLE_NAME;
    applicationInfo.bundleName = LAUNCHER_BUNDLE_NAME;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.bundleStatus_ = InnerBundleInfo::BundleStatus::ENABLED;
    innerBundleInfo.SetHideDesktopIcon(false);
    ClearBundleInfo(LAUNCHER_BUNDLE_NAME);
    dataMgr->bundleInfos_.insert(pair<std::string, InnerBundleInfo>(LAUNCHER_BUNDLE_NAME, innerBundleInfo));
    std::vector<AbilityInfo> abilityInfos;
    ErrCode res = dataMgr->GetLauncherAbilityByBundleName(
        want, abilityInfos, DEFAULT_USER_ID_TEST, DEFAULT_USER_ID_TEST);
    EXPECT_EQ(res, ERR_OK);
    dataMgr->bundleInfos_.erase(LAUNCHER_BUNDLE_NAME);
}

/**
 * @tc.number: QueryInnerBundleInfo_0001
 * @tc.name: test QueryInnerBundleInfo
 * @tc.desc: 1.test QueryInnerBundleInfo failed
 * @tc.require: issueI7FMPK
 */
HWTEST_F(BmsBundleKitServiceTest, QueryInnerBundleInfo_0001, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    InnerBundleInfo queryInnerBundleInfo;
    dataMgr->bundleInfos_.insert(pair<std::string, InnerBundleInfo>(LAUNCHER_BUNDLE_NAME, innerBundleInfo));
    bool res = dataMgr->QueryInnerBundleInfo(LAUNCHER_BUNDLE_NAME, queryInnerBundleInfo);
    EXPECT_EQ(res, true);
    dataMgr->bundleInfos_.erase(LAUNCHER_BUNDLE_NAME);
}

/**
 * @tc.number: QueryInnerBundleInfo_0002
 * @tc.name: test QueryInnerBundleInfo
 * @tc.desc: 1.test QueryInnerBundleInfo failed
 * @tc.require: issueI7FMPK
 */
HWTEST_F(BmsBundleKitServiceTest, QueryInnerBundleInfo_0002, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    InnerBundleInfo queryInnerBundleInfo;
    ClearBundleInfo(LAUNCHER_BUNDLE_NAME);
    bool res = dataMgr->QueryInnerBundleInfo(LAUNCHER_BUNDLE_NAME, queryInnerBundleInfo);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: QueryAbilityInfoByUri_1000
 * @tc.name: test can not get the ability info by bundleStatus_ = BundleStatus::DISABLED
 * @tc.desc: 1.system run normally
 *           2.get ability info failed
 * @tc.require: issueI7FMPK
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfoByUri_1000, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    AbilityInfo result;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.bundleStatus_ = InnerBundleInfo::BundleStatus::DISABLED;
    dataMgr->bundleInfos_.insert(pair<std::string, InnerBundleInfo>(LAUNCHER_BUNDLE_NAME, innerBundleInfo));
    bool ret = dataMgr->QueryAbilityInfoByUri(
        ABILITY_TEST_URI, DEFAULT_USERID, result);
    EXPECT_EQ(ret, false);
    dataMgr->bundleInfos_.erase(LAUNCHER_BUNDLE_NAME);
}

/**
 * @tc.number: QueryAbilityInfosByUri_0300
 * @tc.name: test can not get the ability infos by bundleStatus_ = BundleStatus::DISABLED
 * @tc.desc: 1.system run normally
 *           2.get ability infos failed
 * @tc.require: issueI7FMPK
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosByUri_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::vector<AbilityInfo> abilityInfos;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.bundleStatus_ = InnerBundleInfo::BundleStatus::DISABLED;
    dataMgr->bundleInfos_.insert(
        pair<std::string, InnerBundleInfo>(LAUNCHER_BUNDLE_NAME, innerBundleInfo));
    bool ret = dataMgr->QueryAbilityInfosByUri(ABILITY_TEST_URI, abilityInfos);
    EXPECT_EQ(ret, false);
    dataMgr->bundleInfos_.erase(LAUNCHER_BUNDLE_NAME);
}

/**
 * @tc.number: QueryAbilityInfosByUri_0400
 * @tc.name: test can not get the ability infos
 * @tc.desc: 1.system run normally
 *           2.get ability infos failed
 * @tc.require: issueI7FMPK
 */
HWTEST_F(BmsBundleKitServiceTest, QueryAbilityInfosByUri_0400, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::vector<AbilityInfo> abilityInfos;
    bool ret = dataMgr->QueryAbilityInfosByUri(ABILITY_URI, abilityInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: SetModuleRemovable_0300
 * @tc.name: test can check module removable is able by not find bundleName in bundleInfos_
 * @tc.desc: 1.system run normally
 *           2.check the module removable failed
 * @tc.require: issueI7FMPK
 */
HWTEST_F(BmsBundleKitServiceTest, SetModuleRemovable_0300, Function | SmallTest | Level1)
{
    ClearBundleInfo(BUNDLE_NAME_TEST_CLEAR);
    bool testRet = GetBundleDataMgr()->SetModuleRemovable(BUNDLE_NAME_TEST_CLEAR, MODULE_NAME_TEST_CLEAR, true,
        DEFAULT_USER_ID_TEST);
    EXPECT_FALSE(testRet);
    bool isRemovable = false;
    auto testRet1 = GetBundleDataMgr()->IsModuleRemovable(BUNDLE_NAME_TEST_CLEAR, MODULE_NAME_TEST_CLEAR, isRemovable,
        DEFAULT_USER_ID_TEST);
    EXPECT_EQ(testRet1, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_FALSE(isRemovable);
}

/**
 * @tc.number: InnerProcessShortcut_0001
 * @tc.name: test InnerProcessShortcut
 * @tc.desc: 1.system run normally
 *           2.test InnerProcessShortcut.
 */
HWTEST_F(BmsBundleKitServiceTest, InnerProcessShortcut_0001, Function | SmallTest | Level1)
{
    Shortcut shortcut;
    shortcut.shortcutId = "shortcut_id";
    shortcut.icon = "$media:16777226";
    int32_t iconId = 16777226;
    shortcut.label = "$string:16777222";
    int32_t labelId = 16777222;
    ShortcutWant want;
    want.bundleName = "bundleName";
    want.abilityName = "ability";
    shortcut.wants.emplace_back(want);

    ShortcutInfo shortcutInfo;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InnerProcessShortcut(shortcut, shortcutInfo);

    EXPECT_EQ(shortcutInfo.id, shortcut.shortcutId);
    EXPECT_EQ(shortcutInfo.label, shortcut.label);
    EXPECT_EQ(shortcutInfo.labelId, labelId);
    EXPECT_EQ(shortcutInfo.icon, shortcut.icon);
    EXPECT_EQ(shortcutInfo.iconId, iconId);
}

/**
 * @tc.number: InnerProcessShortcut_0002
 * @tc.name: test InnerProcessShortcut
 * @tc.desc: 1.system run normally
 *           2.test InnerProcessShortcut.
 */
HWTEST_F(BmsBundleKitServiceTest, InnerProcessShortcut_0002, Function | SmallTest | Level1)
{
    Shortcut shortcut;
    shortcut.shortcutId = "shortcut_id";
    shortcut.icon = "$media:icon";
    shortcut.label = "$string:label";
    ShortcutWant want;
    want.bundleName = "bundleName";
    want.abilityName = "ability";
    shortcut.wants.emplace_back(want);

    ShortcutInfo shortcutInfo;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InnerProcessShortcut(shortcut, shortcutInfo);

    EXPECT_EQ(shortcutInfo.id, shortcut.shortcutId);
    EXPECT_EQ(shortcutInfo.label, shortcut.label);
    EXPECT_EQ(shortcutInfo.labelId, 0);
    EXPECT_EQ(shortcutInfo.icon, shortcut.icon);
    EXPECT_EQ(shortcutInfo.iconId, 0);
}

/**
 * @tc.number: InnerProcessShortcut_0003
 * @tc.name: test InnerProcessShortcut
 * @tc.desc: 1.system run normally
 *           2.test InnerProcessShortcut.
 */
HWTEST_F(BmsBundleKitServiceTest, InnerProcessShortcut_0003, Function | SmallTest | Level1)
{
    Shortcut shortcut;
    shortcut.shortcutId = "shortcut_id";
    shortcut.icon = "$media:icon";
    shortcut.iconId = 16777226;
    shortcut.label = "$string:name";
    shortcut.labelId = 16777222;
    ShortcutWant want;
    want.bundleName = "bundleName";
    want.abilityName = "ability";
    shortcut.wants.emplace_back(want);

    ShortcutInfo shortcutInfo;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InnerProcessShortcut(shortcut, shortcutInfo);

    EXPECT_EQ(shortcutInfo.id, shortcut.shortcutId);
    EXPECT_EQ(shortcutInfo.label, shortcut.label);
    EXPECT_EQ(shortcutInfo.labelId, shortcut.labelId);
    EXPECT_EQ(shortcutInfo.icon, shortcut.icon);
    EXPECT_EQ(shortcutInfo.iconId, shortcut.iconId);
}

/**
 * @tc.number: SetAdditionalInfo_0001
 * @tc.name: test set the bundleName's AdditionalInfo
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, SetAdditionalInfo_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(nullptr, bundleMgrProxy);
    std::string additionalInfo = "additionalInfo";
    auto ret = bundleMgrProxy->SetAdditionalInfo("", additionalInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: SetAdditionalInfo_0002
 * @tc.name: test set the bundleName's AdditionalInfo
 * @tc.desc: 1.system run normally
 *           2.set additionalInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, SetAdditionalInfo_0002, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(nullptr, bundleMgrProxy);
    std::string additionalInfo = "additionalInfo";
    auto ret = bundleMgrProxy->SetAdditionalInfo(BUNDLE_NAME_TEST, additionalInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_NOT_APP_GALLERY_CALL);
}

/**
 * @tc.number: GetAppServiceHspInfo_0001
 * @tc.name: test GetAppServiceHspInfo
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleKitServiceTest, GetAppServiceHspInfo_0001, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    BundleInfo info;
    auto ret = innerBundleInfo.GetAppServiceHspInfo(info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    ApplicationInfo applicationInfo;
    applicationInfo.bundleType = BundleType::APP_SERVICE_FWK;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    ret = innerBundleInfo.GetAppServiceHspInfo(info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.modulePackage = MODULE_NAME;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_NAME, innerModuleInfo);
    ret = innerBundleInfo.GetAppServiceHspInfo(info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);

    InnerModuleInfo innerModuleInfo_2;
    innerModuleInfo_2.distro.moduleType = Profile::MODULE_TYPE_SHARED;
    innerModuleInfo_2.modulePackage = MODULE_NAME_TEST;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_NAME_TEST, innerModuleInfo_2);
    ret = innerBundleInfo.GetAppServiceHspInfo(info);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: SwitchUninstallState_0001
 * @tc.name: SwitchUninstallState
 * @tc.desc: 1.system run normally
 *           2.switch uninstallState return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST
 */
HWTEST_F(BmsBundleKitServiceTest, SwitchUninstallState_0001, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool stateChange = false;
    ErrCode res = dataMgr->SwitchUninstallState(BUNDLE_NAME_UNINSTALL_STATE, false, false, stateChange);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: SwitchUninstallStateByUserId_0001
 * @tc.name: SwitchUninstallStateByUserId
 * @tc.desc: 1.system run normally
 *           2.switch uninstallState return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST
 */
HWTEST_F(BmsBundleKitServiceTest, SwitchUninstallStateByUserId_0001, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    bool stateChange = false;
    ErrCode res = dataMgr->SwitchUninstallStateByUserId(BUNDLE_NAME_UNINSTALL_STATE, false, 100, stateChange);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: SwitchUninstallState_0002
 * @tc.name: SwitchUninstallState
 * @tc.desc: 1.system run normally
 *           2.switch uninstallState return ERR_BUNDLE_MANAGER_BUNDLE_CAN_NOT_BE_UNINSTALLED
 */
HWTEST_F(BmsBundleKitServiceTest, SwitchUninstallState_0002, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.SetRemovable(false);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_UNINSTALL_STATE, info);
    bool stateChange = false;
    ErrCode res = dataMgr->SwitchUninstallState(BUNDLE_NAME_UNINSTALL_STATE, true, false, stateChange);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_CAN_NOT_BE_UNINSTALLED);
    dataMgr->bundleInfos_.erase(BUNDLE_NAME_UNINSTALL_STATE);
}

/**
 * @tc.number: SwitchUninstallState_0003
 * @tc.name: SwitchUninstallState
 * @tc.desc: 1.system run normally
 *           2.switch uninstallState successfully
 */
HWTEST_F(BmsBundleKitServiceTest, SwitchUninstallState_0003, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_UNINSTALL_STATE, info);
    EXPECT_TRUE(info.uninstallState_);
    bool stateChange = false;
    ErrCode res = dataMgr->SwitchUninstallState(BUNDLE_NAME_UNINSTALL_STATE, true, false, stateChange);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_TRUE(info.uninstallState_);
    dataMgr->bundleInfos_.erase(BUNDLE_NAME_UNINSTALL_STATE);
}

/**
 * @tc.number: GetApplicationInfoAdaptBundleClone_0001
 * @tc.name: test GetApplicationInfoAdaptBundleClone
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfoAdaptBundleClone_0001, Function | SmallTest | Level1)
{
    InnerBundleUserInfo userInfo;
    int32_t appIndex = 0;
    ApplicationInfo applicationInfo;
    InnerBundleInfo innerBundleInfo;
    bool ret = innerBundleInfo.GetApplicationInfoAdaptBundleClone(userInfo, appIndex, applicationInfo);
    EXPECT_TRUE(ret);
    appIndex = 1;
    ret = innerBundleInfo.GetApplicationInfoAdaptBundleClone(userInfo, appIndex, applicationInfo);
    EXPECT_FALSE(ret);
    InnerBundleCloneInfo cloneInfo;
    userInfo.cloneInfos["1"] = cloneInfo;
    ret = innerBundleInfo.GetApplicationInfoAdaptBundleClone(userInfo, appIndex, applicationInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetApplicationInfoAdaptBundleClone_0002
 * @tc.name: test GetApplicationInfoAdaptBundleClone
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfoAdaptBundleClone_0002, Function | SmallTest | Level1)
{
    InnerBundleUserInfo userInfo;
    userInfo.accessTokenId = 1;
    userInfo.accessTokenIdEx = 2;
    userInfo.bundleUserInfo.enabled = false;
    userInfo.uid = 200;

    int32_t appIndex = 0;
    ApplicationInfo applicationInfo;
    InnerBundleInfo innerBundleInfo;
    bool ret = innerBundleInfo.GetApplicationInfoAdaptBundleClone(userInfo, appIndex, applicationInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(applicationInfo.accessTokenId, userInfo.accessTokenId);
    EXPECT_EQ(applicationInfo.accessTokenIdEx, userInfo.accessTokenIdEx);
    EXPECT_EQ(applicationInfo.enabled, userInfo.bundleUserInfo.enabled);
    EXPECT_EQ(applicationInfo.uid, userInfo.uid);
}

/**
 * @tc.number: GetApplicationInfoAdaptBundleClone_0003
 * @tc.name: test GetApplicationInfoAdaptBundleClone
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleKitServiceTest, GetApplicationInfoAdaptBundleClone_0003, Function | SmallTest | Level1)
{
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.accessTokenId = 1;
    cloneInfo.accessTokenIdEx = 2;
    cloneInfo.enabled = false;
    cloneInfo.uid = 200;
    cloneInfo.appIndex = 1;
    InnerBundleUserInfo userInfo;
    userInfo.cloneInfos["1"] = cloneInfo;

    int32_t appIndex = 1;
    ApplicationInfo applicationInfo;
    InnerBundleInfo innerBundleInfo;
    bool ret = innerBundleInfo.GetApplicationInfoAdaptBundleClone(userInfo, appIndex, applicationInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(applicationInfo.accessTokenId, cloneInfo.accessTokenId);
    EXPECT_EQ(applicationInfo.accessTokenIdEx, cloneInfo.accessTokenIdEx);
    EXPECT_EQ(applicationInfo.enabled, cloneInfo.enabled);
    EXPECT_EQ(applicationInfo.uid, cloneInfo.uid);
    EXPECT_EQ(applicationInfo.appIndex, cloneInfo.appIndex);
}

/**
 * @tc.number: GetBundleInfoAdaptBundleClone_0001
 * @tc.name: test GetBundleInfoAdaptBundleClone
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfoAdaptBundleClone_0001, Function | SmallTest | Level1)
{
    InnerBundleUserInfo userInfo;
    int32_t appIndex = 0;
    BundleInfo bundleInfo;
    InnerBundleInfo innerBundleInfo;
    bool ret = innerBundleInfo.GetBundleInfoAdaptBundleClone(userInfo, appIndex, bundleInfo);
    EXPECT_TRUE(ret);
    appIndex = 1;
    ret = innerBundleInfo.GetBundleInfoAdaptBundleClone(userInfo, appIndex, bundleInfo);
    EXPECT_FALSE(ret);
    InnerBundleCloneInfo cloneInfo;
    userInfo.cloneInfos["1"] = cloneInfo;
    ret = innerBundleInfo.GetBundleInfoAdaptBundleClone(userInfo, appIndex, bundleInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetBundleInfoAdaptBundleClone_0002
 * @tc.name: test GetBundleInfoAdaptBundleClone
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfoAdaptBundleClone_0002, Function | SmallTest | Level1)
{
    InnerBundleUserInfo userInfo;
    userInfo.uid = 100;
    userInfo.installTime = 200;
    userInfo.updateTime = 300;
    userInfo.firstInstallTime = 400;

    int32_t appIndex = 0;
    BundleInfo bundleInfo;
    InnerBundleInfo innerBundleInfo;
    bool ret = innerBundleInfo.GetBundleInfoAdaptBundleClone(userInfo, appIndex, bundleInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(bundleInfo.uid, userInfo.uid);
    EXPECT_EQ(bundleInfo.installTime, userInfo.installTime);
    EXPECT_EQ(bundleInfo.updateTime, userInfo.updateTime);
    EXPECT_EQ(bundleInfo.firstInstallTime, userInfo.firstInstallTime);
}

/**
 * @tc.number: GetBundleInfoAdaptBundleClone_0003
 * @tc.name: test GetBundleInfoAdaptBundleClone
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleInfoAdaptBundleClone_0003, Function | SmallTest | Level1)
{
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.enabled = false;
    cloneInfo.uid = 200;
    cloneInfo.appIndex = 1;
    InnerBundleUserInfo userInfo;
    userInfo.cloneInfos["1"] = cloneInfo;

    int32_t appIndex = 1;
    BundleInfo bundleInfo;
    InnerBundleInfo innerBundleInfo;
    bool ret = innerBundleInfo.GetBundleInfoAdaptBundleClone(userInfo, appIndex, bundleInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(bundleInfo.uid, cloneInfo.uid);
    EXPECT_EQ(bundleInfo.installTime, cloneInfo.installTime);
    EXPECT_EQ(bundleInfo.appIndex, cloneInfo.appIndex);
}

/**
 * @tc.number: GetUid_0001
 * @tc.name: test GetUid
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleKitServiceTest, GetUid_0001, Function | SmallTest | Level1)
{
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.enabled = false;
    cloneInfo.uid = 200;
    cloneInfo.appIndex = 1;
    InnerBundleUserInfo userInfo;
    userInfo.cloneInfos["1"] = cloneInfo;
    userInfo.uid = 101;
    userInfo.bundleUserInfo.userId = 100;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);

    int32_t uid = innerBundleInfo.GetUid(101);
    EXPECT_EQ(uid, INVALID_UID);

    uid = innerBundleInfo.GetUid(userInfo.bundleUserInfo.userId);
    EXPECT_EQ(uid, userInfo.uid);

    int32_t appIndex = 1;
    uid = innerBundleInfo.GetUid(userInfo.bundleUserInfo.userId, appIndex);
    EXPECT_EQ(uid, cloneInfo.uid);

    appIndex = 2;
    uid = innerBundleInfo.GetUid(userInfo.bundleUserInfo.userId, appIndex);
    EXPECT_EQ(uid, INVALID_UID);
}

/**
 * @tc.number: GetBundleNameAndIndexByName_0001
 * @tc.name: GetBundleNameAndIndexByName
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleKitServiceTest, GetBundleNameAndIndexByName_0001, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    if (dataMgr != nullptr) {
        std::string keyName = "com.ohos.example";
        std::string bundleName;
        int32_t appIndex = -1;
        dataMgr->GetBundleNameAndIndexByName(keyName, bundleName, appIndex);
        EXPECT_EQ(keyName, bundleName);
        EXPECT_EQ(appIndex, 0);

        keyName = "clone_com.ohos_example";
        dataMgr->GetBundleNameAndIndexByName(keyName, bundleName, appIndex);
        EXPECT_EQ(keyName, bundleName);
        EXPECT_EQ(appIndex, 0);

        keyName = "cclone_com.ohos_example";
        dataMgr->GetBundleNameAndIndexByName(keyName, bundleName, appIndex);
        EXPECT_EQ(keyName, bundleName);
        EXPECT_EQ(appIndex, 0);

        keyName = "1clone_com.ohos_example";
        dataMgr->GetBundleNameAndIndexByName(keyName, bundleName, appIndex);
        EXPECT_EQ(bundleName, "com.ohos_example");
        EXPECT_EQ(appIndex, 1);
    }
}

/**
 * @tc.number: GetCloneAppIndexes_0001
 * @tc.name: GetCloneAppIndexes
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundleKitServiceTest, GetCloneAppIndexes_0001, Function | SmallTest | Level1)
{
    std::string bundleName = BUNDLE_NAME_TEST;
    std::string moduleName = MODULE_NAME_TEST;
    std::string abilityName = ABILITY_NAME_TEST;
    int32_t userId = DEFAULT_USERID;
    MockInstallBundle(bundleName, moduleName, abilityName);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::vector<int32_t> appCloneIndexes = dataMgr->GetCloneAppIndexes(bundleName, userId);
    EXPECT_TRUE(appCloneIndexes.empty());
    int32_t userIdInvalid = 101;
    appCloneIndexes = dataMgr->GetCloneAppIndexes(bundleName, userIdInvalid);
    EXPECT_TRUE(appCloneIndexes.empty());
    appCloneIndexes = dataMgr->GetCloneAppIndexes("", userId);
    EXPECT_TRUE(appCloneIndexes.empty());

    int appIndex1 = TEST_APP_INDEX1;
    AddCloneInfo(bundleName, userId, appIndex1);
    int appIndex2 = TEST_APP_INDEX2;
    AddCloneInfo(bundleName, userId, appIndex2);
    appCloneIndexes = dataMgr->GetCloneAppIndexes(bundleName, userId);
    EXPECT_EQ(appCloneIndexes.size(), 2);

    ClearCloneInfo(bundleName, userId);
    MockUninstallBundle(bundleName);
}

/**
 * @tc.number: Mgr_Proxy_CopyAp_0001
 * @tc.name: test BundleMgrProxy interface CopyAp
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, Mgr_Proxy_CopyAp_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::vector<std::string> results;
    auto ret = bundleMgrProxy->CopyAp(BUNDLE_NAME_TEST, false, results);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: Mgr_Proxy_GetVerifyManager_0001
 * @tc.name: test BundleMgrProxy interface GetVerifyManager
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, Mgr_Proxy_GetVerifyManager_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::vector<std::string> results;
    auto ret = bundleMgrProxy->GetVerifyManager();
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.number: Mgr_Proxy_SetExtNameOrMIMEToApp_0001
 * @tc.name: test BundleMgrProxy interface SetExtNameOrMIMEToApp
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, Mgr_Proxy_SetExtNameOrMIMEToApp_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName { "bundle" };
    std::string moduleName { "module" };
    std::string abilityName { "ability" };
    std::string extName { "extension" };
    std::string mimeType { "1" };
    auto ret = bundleMgrProxy->SetExtNameOrMIMEToApp(bundleName, moduleName, abilityName, extName, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: Mgr_Proxy_DelExtNameOrMIMEToApp_0001
 * @tc.name: test BundleMgrProxy interface DelExtNameOrMIMEToApp
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, Mgr_Proxy_DelExtNameOrMIMEToApp_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName { "bundle" };
    std::string moduleName { "module" };
    std::string abilityName { "ability" };
    std::string extName { "extension" };
    std::string mimeType { "1" };
    auto ret = bundleMgrProxy->DelExtNameOrMIMEToApp(bundleName, moduleName, abilityName, extName, mimeType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: Mgr_Proxy_GetUninstalledBundleInfo_0001
 * @tc.name: test BundleMgrProxy interface GetUninstalledBundleInfo
 * @tc.desc: 1.system run normally
 *           2.get AdditionalInfo failed
 */
HWTEST_F(BmsBundleKitServiceTest, Mgr_Proxy_GetUninstalledBundleInfo_0001, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::string bundleName { "bundle" };
    BundleInfo bundleInfo;
    auto ret = bundleMgrProxy->GetUninstalledBundleInfo(bundleName, bundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FAILED_GET_BUNDLE_INFO);
}

/**
 * @tc.number: Mgr_Proxy_AddDesktopShortcutInfo_0100
 * @tc.name: test BundleMgrProxy interface AddDesktopShortcutInfo
 * @tc.desc: 1.return ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleKitServiceTest, Mgr_Proxy_AddDesktopShortcutInfo_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    ShortcutInfo shortcutInfo = MockShortcutInfo(BUNDLE_NAME_DEMO, SHORTCUT_TEST_ID);
    auto ret = bundleMgrProxy->AddDesktopShortcutInfo(shortcutInfo, DEFAULT_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: Mgr_Proxy_DeleteDesktopShortcutInfo_0100
 * @tc.name: test BundleMgrProxy interface DeleteDesktopShortcutInfo
 * @tc.desc: 1.return ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleKitServiceTest, Mgr_Proxy_DeleteDesktopShortcutInfo_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    ShortcutInfo shortcutInfo = MockShortcutInfo(BUNDLE_NAME_DEMO, SHORTCUT_TEST_ID);
    auto ret = bundleMgrProxy->DeleteDesktopShortcutInfo(shortcutInfo, DEFAULT_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: Mgr_Proxy_GetAllDesktopShortcutInfo_0100
 * @tc.name: test BundleMgrProxy interface GetAllDesktopShortcutInfo
 * @tc.desc: 1.return ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleKitServiceTest, Mgr_Proxy_GetAllDesktopShortcutInfo_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    std::vector<ShortcutInfo> shortcutInfos;
    auto ret = bundleMgrProxy->GetAllDesktopShortcutInfo(DEFAULT_USERID, shortcutInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: OnBundleAdded_0100
 * @tc.name: test IBundleStatusCallback interface OnBundleAdded
 * @tc.desc: 1.GetBundleName is MODULE_NAME_TEST_1
 */
HWTEST_F(BmsBundleKitServiceTest, OnBundleAdded_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<IBundleStatusCallback> bundleStatusCallback = std::make_shared<IBundleStatusCallbackTest>();
    ASSERT_NE(bundleStatusCallback, nullptr);
    bundleStatusCallback->OnBundleAdded("", DEFAULT_USERID, APP_INDEX);
    auto bundleName = bundleStatusCallback->GetBundleName();
    EXPECT_EQ(bundleName, MODULE_NAME_TEST_1);
}

/**
 * @tc.number: OnBundleUpdated_0100
 * @tc.name: test IBundleStatusCallback interface OnBundleUpdated
 * @tc.desc: 1.GetBundleName is MODULE_NAME_TEST_2
 */
HWTEST_F(BmsBundleKitServiceTest, OnBundleUpdated_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<IBundleStatusCallback> bundleStatusCallback = std::make_shared<IBundleStatusCallbackTest>();
    ASSERT_NE(bundleStatusCallback, nullptr);
    bundleStatusCallback->OnBundleUpdated("", DEFAULT_USERID, APP_INDEX);
    auto bundleName = bundleStatusCallback->GetBundleName();
    EXPECT_EQ(bundleName, MODULE_NAME_TEST_2);
}

/**
 * @tc.number: OnBundleRemoved_0100
 * @tc.name: test IBundleStatusCallback interface OnBundleRemoved
 * @tc.desc: 1.GetBundleName is MODULE_NAME_TEST_3
 */
HWTEST_F(BmsBundleKitServiceTest, OnBundleRemoved_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<IBundleStatusCallback> bundleStatusCallback = std::make_shared<IBundleStatusCallbackTest>();
    ASSERT_NE(bundleStatusCallback, nullptr);
    bundleStatusCallback->OnBundleRemoved("", DEFAULT_USERID, APP_INDEX);
    auto bundleName = bundleStatusCallback->GetBundleName();
    EXPECT_EQ(bundleName, MODULE_NAME_TEST_3);
}

/**
 * @tc.number: UninstallAndRecover_0100
 * @tc.name: test IBundleInstaller interface UninstallAndRecover
 * @tc.desc: 1.return true
 */
HWTEST_F(BmsBundleKitServiceTest, UninstallAndRecover_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<IBundleInstaller> bundleInstaller = std::make_shared<IBundleInstallerTest>();
    ASSERT_NE(bundleInstaller, nullptr);
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver;
    EXPECT_TRUE(bundleInstaller->UninstallAndRecover("", installParam, statusReceiver));
}

/**
 * @tc.number: InstallCloneApp_0100
 * @tc.name: test IBundleInstaller interface InstallCloneApp
 * @tc.desc: 1.ret is ERR_OK
 */
HWTEST_F(BmsBundleKitServiceTest, InstallCloneApp_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<IBundleInstaller> bundleInstaller = std::make_shared<IBundleInstallerTest>();
    ASSERT_NE(bundleInstaller, nullptr);
    int32_t appIndex = APP_INDEX;
    auto ret = bundleInstaller->InstallCloneApp("", DEFAULT_USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: UninstallCloneApp_0100
 * @tc.name: test IBundleInstaller interface UninstallCloneApp
 * @tc.desc: 1.ret is ERR_OK
 */
HWTEST_F(BmsBundleKitServiceTest, UninstallCloneApp_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<IBundleInstaller> bundleInstaller = std::make_shared<IBundleInstallerTest>();
    ASSERT_NE(bundleInstaller, nullptr);
    DestroyAppCloneParam destroyAppCloneParam;
    auto ret = bundleInstaller->UninstallCloneApp("", DEFAULT_USERID, APP_INDEX, destroyAppCloneParam);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: IsBundleInstalled_0001
 * @tc.name: test IsBundleInstalled
 * @tc.desc: 1.system run normal
 */
HWTEST_F(BmsBundleKitServiceTest, IsBundleInstalled_0001, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool isInstalled = false;
    auto testRet = hostImpl->IsBundleInstalled(BUNDLE_NAME_TEST, DEFAULT_USERID, 0, isInstalled);
    EXPECT_EQ(testRet, ERR_OK);
    EXPECT_FALSE(isInstalled);
}

/**
 * @tc.number: UpdatePrivilegeCapability_0001
 * @tc.name: test UpdatePrivilegeCapability
 * @tc.desc: 1.system run normal
 */
HWTEST_F(BmsBundleKitServiceTest, UpdatePrivilegeCapability_0001, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->keepAlive = false;
    innerBundleInfo.baseApplicationInfo_->associatedWakeUp = false;
    innerBundleInfo.baseApplicationInfo_->allowAppRunWhenDeviceFirstLocked = false;
    innerBundleInfo.baseApplicationInfo_->allowEnableNotification = false;
    innerBundleInfo.baseApplicationInfo_->allowMultiProcess = false;
    innerBundleInfo.baseApplicationInfo_->hideDesktopIcon = false;
    innerBundleInfo.baseApplicationInfo_->userDataClearable = true;
    innerBundleInfo.baseApplicationInfo_->formVisibleNotify = false;

    ApplicationInfo applicationInfo;
    applicationInfo.keepAlive = true;
    applicationInfo.associatedWakeUp = true;
    applicationInfo.allowAppRunWhenDeviceFirstLocked = true;
    applicationInfo.allowEnableNotification = true;
    applicationInfo.allowMultiProcess = true;
    applicationInfo.hideDesktopIcon = true;
    applicationInfo.userDataClearable = false;
    applicationInfo.formVisibleNotify = true;

    innerBundleInfo.UpdatePrivilegeCapability(applicationInfo);
    EXPECT_TRUE(innerBundleInfo.baseApplicationInfo_->keepAlive);
    EXPECT_TRUE(innerBundleInfo.baseApplicationInfo_->associatedWakeUp);
    EXPECT_TRUE(innerBundleInfo.baseApplicationInfo_->allowAppRunWhenDeviceFirstLocked);
    EXPECT_TRUE(innerBundleInfo.baseApplicationInfo_->allowEnableNotification);
    EXPECT_TRUE(innerBundleInfo.baseApplicationInfo_->allowMultiProcess);
    EXPECT_TRUE(innerBundleInfo.baseApplicationInfo_->hideDesktopIcon);
    EXPECT_FALSE(innerBundleInfo.baseApplicationInfo_->userDataClearable);
    EXPECT_TRUE(innerBundleInfo.baseApplicationInfo_->formVisibleNotify);
}

/**
 * @tc.number: UpdatePrivilegeCapability_0002
 * @tc.name: test UpdatePrivilegeCapability
 * @tc.desc: 1.system run normal
 */
HWTEST_F(BmsBundleKitServiceTest, UpdatePrivilegeCapability_0002, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->keepAlive = true;
    innerBundleInfo.baseApplicationInfo_->associatedWakeUp = true;
    innerBundleInfo.baseApplicationInfo_->allowAppRunWhenDeviceFirstLocked = true;
    innerBundleInfo.baseApplicationInfo_->allowEnableNotification = true;
    innerBundleInfo.baseApplicationInfo_->allowMultiProcess = true;
    innerBundleInfo.baseApplicationInfo_->hideDesktopIcon = true;
    innerBundleInfo.baseApplicationInfo_->userDataClearable = false;
    innerBundleInfo.baseApplicationInfo_->formVisibleNotify = true;

    ApplicationInfo applicationInfo;
    applicationInfo.keepAlive = false;
    applicationInfo.associatedWakeUp = false;
    applicationInfo.allowAppRunWhenDeviceFirstLocked = false;
    applicationInfo.allowEnableNotification = false;
    applicationInfo.allowMultiProcess = false;
    applicationInfo.hideDesktopIcon = false;
    applicationInfo.userDataClearable = true;
    applicationInfo.formVisibleNotify = false;

    innerBundleInfo.UpdatePrivilegeCapability(applicationInfo);
    EXPECT_FALSE(innerBundleInfo.baseApplicationInfo_->keepAlive);
    EXPECT_FALSE(innerBundleInfo.baseApplicationInfo_->associatedWakeUp);
    EXPECT_FALSE(innerBundleInfo.baseApplicationInfo_->allowAppRunWhenDeviceFirstLocked);
    EXPECT_FALSE(innerBundleInfo.baseApplicationInfo_->allowEnableNotification);
    EXPECT_TRUE(innerBundleInfo.baseApplicationInfo_->allowMultiProcess);
    EXPECT_TRUE(innerBundleInfo.baseApplicationInfo_->hideDesktopIcon);
    EXPECT_FALSE(innerBundleInfo.baseApplicationInfo_->userDataClearable);
    EXPECT_TRUE(innerBundleInfo.baseApplicationInfo_->formVisibleNotify);
}

/**
 * @tc.number: CreateBundleDataDirWithEl_0100
 * @tc.name: test create bundle el4 dir
 * @tc.desc: 1.return create dir successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CreateBundleDataDirWithEl_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ErrCode ret = hostImpl->CreateBundleDataDirWithEl(DEFAULT_USER_ID_TEST, DataDirEl::EL4);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CreateBundleDataDirWithEl_0200
 * @tc.name: test create bundle el4 dir
 * @tc.desc: 1.return create dir successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CreateBundleDataDirWithEl_0200, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    ErrCode ret = bundleMgrProxy->CreateBundleDataDirWithEl(DEFAULT_USER_ID_TEST, DataDirEl::EL4);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CleanBundleDataFiles_0100
 * @tc.name: test can clean the bundle data files by bundle name
 * @tc.desc: 1.system run normally
 *           2.clean the bundle data files successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CleanBundleDataFiles_0100, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    CreateFileDir();

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool testRet = hostImpl->CleanBundleDataFiles(BUNDLE_NAME_TEST, DEFAULT_USERID);
    EXPECT_TRUE(testRet);

    CleanFileDir();
    CheckFileNonExist();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanBundleDataFiles_0200
 * @tc.name: test can clean the bundle data files by empty bundle name
 * @tc.desc: 1.system run normally
 *           2.clean the bundle data files failed
 */
HWTEST_F(BmsBundleKitServiceTest, CleanBundleDataFiles_0200, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    CreateFileDir();

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool testRet = hostImpl->CleanBundleDataFiles("", DEFAULT_USERID);
    EXPECT_FALSE(testRet);
    CheckFileExist();

    CleanFileDir();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanBundleDataFiles_0300
 * @tc.name: test can clean the bundle data files by no exist bundle name
 * @tc.desc: 1.system run normally
 *           2.clean the bundle data files failed
 */
HWTEST_F(BmsBundleKitServiceTest, CleanBundleDataFiles_0300, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    CreateFileDir();

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool testRet = hostImpl->CleanBundleDataFiles(BUNDLE_NAME_DEMO, DEFAULT_USERID);
    EXPECT_FALSE(testRet);
    CheckFileExist();

    CleanFileDir();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanBundleDataFiles_0400
 * @tc.name: test can clean the bundle data files by bundle name
 * @tc.desc: 1.system run normally
 *           2.userDataClearable is false
 *           3.clean the cache files failed
 */
HWTEST_F(BmsBundleKitServiceTest, CleanBundleDataFiles_0400, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, false);
    CreateFileDir();

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool testRet = hostImpl->CleanBundleDataFiles(BUNDLE_NAME_TEST, DEFAULT_USERID);
    EXPECT_FALSE(testRet);

    CleanFileDir();
    CheckFileNonExist();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanBundleDataFiles_0500
 * @tc.name: test can clean the bundle data files by bundle name
 * @tc.desc: 1.system run normally
 *           2.userDataClearable is true
 *           3.clean the cache files succeed
 */
HWTEST_F(BmsBundleKitServiceTest, CleanBundleDataFiles_0500, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, true);
    CreateFileDir();

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool testRet = hostImpl->CleanBundleDataFiles(BUNDLE_NAME_TEST, DEFAULT_USERID);
    EXPECT_TRUE(testRet);

    CleanFileDir();
    CheckFileNonExist();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanBundleDataFiles_0600
 * @tc.name: test can clean the bundle data files by bundle name
 * @tc.desc: 1.system run normally
 *           2.clean the bundle data files successfully
 */
HWTEST_F(BmsBundleKitServiceTest, CleanBundleDataFiles_0600, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    CreateFileDir();

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool testRet = hostImpl->CleanBundleDataFiles(BUNDLE_NAME_TEST, DEFAULT_USERID);
    EXPECT_TRUE(testRet);

    CleanFileDir();
    CheckFileNonExist();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanBundleDataFiles_0700
 * @tc.name: test can clean the bundle data files by bundle name
 * @tc.desc: 1.system run normally
 *           2.clean the bundle data files failed by empty bundle name
 */
HWTEST_F(BmsBundleKitServiceTest, CleanBundleDataFiles_0700, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    bool testRet = bundleMgrProxy->CleanBundleDataFiles("", DEFAULT_USERID);
    EXPECT_FALSE(testRet);
}

/**
 * @tc.number: CleanBundleDataFiles_0800
 * @tc.name: test can clean the bundle data files by bundle name
 * @tc.desc: 1.system run normally
 *           2.userDataClearable is false, userId is false
 *           3.clean the cache files failed
 */
HWTEST_F(BmsBundleKitServiceTest, CleanBundleDataFiles_0800, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, false, false);
    CreateFileDir();

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    bool testRet = hostImpl->CleanBundleDataFiles(BUNDLE_NAME_TEST, 10001);
    EXPECT_FALSE(testRet);

    CleanFileDir();
    CheckFileNonExist();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanBundleDataFiles_0900
 * @tc.name: test can clean the bundle data files by bundle name
 * @tc.desc: 1.system run normally
 *           2.isBrokerServiceExisted is false, userId is false
 *           3.clean the cache files failed
 */
HWTEST_F(BmsBundleKitServiceTest, CleanBundleDataFiles_0900, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST);
    CreateFileDir();

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    hostImpl->isBrokerServiceExisted_ = true;
    bool testRet = hostImpl->CleanBundleDataFiles(BUNDLE_NAME_DEMO, DEFAULT_USERID);
    EXPECT_FALSE(testRet);

    CleanFileDir();
    CheckFileNonExist();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: GetPluginAbilityInfo_0100
 * @tc.name: test GetPluginAbilityInfo
 * @tc.desc: 1. return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST
 */
HWTEST_F(BmsBundleKitServiceTest, GetPluginAbilityInfo_0100, Function | SmallTest | Level1)
{
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        EXPECT_EQ(bundleMgrProxy, nullptr);
    }
    std::string hostBundleName = "test1";
    std::string pluginBundleName = "test2";
    std::string pluginModuleName = "test3";
    std::string pluginAbilityName = "test4";
    int32_t userId = 10;
    AbilityInfo abilityInfo;
    auto ret = bundleMgrProxy->GetPluginAbilityInfo(hostBundleName, pluginBundleName,
        pluginModuleName, pluginAbilityName, userId, abilityInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: CleanCache_0800
 * @tc.name: test can clean the cache files with failed userId
 * @tc.desc: 1.system run normally
 *           2. userDataClearable is false, isSystemApp is false
 *           3. clean the cache files failed by failed userId
 */
HWTEST_F(BmsBundleKitServiceTest, CleanCache_0800, Function | SmallTest | Level1)
{
    MockInstallBundle(BUNDLE_NAME_TEST, MODULE_NAME_TEST, ABILITY_NAME_TEST, false, true);
    CreateFileDir();

    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    int32_t failedId = -100;
    sptr<MockCleanCache> cleanCache = new (std::nothrow) MockCleanCache();
    ErrCode result = hostImpl->CleanBundleCacheFiles(BUNDLE_NAME_TEST, cleanCache, failedId);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    CleanFileDir();
    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: CleanBundleCacheFilesAutomaticImpl_0100
 * @tc.name: test CleanBundleCacheFilesAutomatic
 * @tc.desc: 1.Test the CleanBundleCacheFilesAutomatic by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, CleanBundleCacheFilesAutomaticImpl_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    uint64_t cacheSize = 1;
    ErrCode ret = hostImpl->CleanBundleCacheFilesAutomatic(cacheSize);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ALL_BUNDLES_ARE_RUNNING);
}

/**
 * @tc.number: CleanBundleCacheFilesGetCleanSize_0100
 * @tc.name: test CleanBundleCacheFilesGetCleanSize
 * @tc.desc: 1.Test the CleanBundleCacheFilesGetCleanSize by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, CleanBundleCacheFilesGetCleanSize_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    uint64_t cacheSize = 1;
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
    ErrCode ret = hostImpl->CleanBundleCacheFilesGetCleanSize(BUNDLE_NAME_DEMO, DEFAULT_USERID, cacheSize);
    EXPECT_EQ(ret, ERR_OK);
    DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.erase(BUNDLE_NAME_DEMO);
}

/**
 * @tc.number: CleanBundleCacheFilesGetCleanSize_0200
 * @tc.name: test CleanBundleCacheFilesGetCleanSize
 * @tc.desc: 1.Test the CleanBundleCacheFilesGetCleanSize by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, CleanBundleCacheFilesGetCleanSize_0200, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    uint64_t cacheSize = 1;
    ErrCode ret = hostImpl->CleanBundleCacheFilesGetCleanSize(BUNDLE_NAME_TEST, ALL_USERID, cacheSize);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    ret = hostImpl->CleanBundleCacheFilesGetCleanSize("", DEFAULT_USERID, cacheSize);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    ret = hostImpl->CleanBundleCacheFilesGetCleanSize(BUNDLE_NAME_TEST, DEFAULT_USERID, cacheSize);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: CleanBundleCacheTaskGetCleanSize_0100
 * @tc.name: test CleanBundleCacheTaskGetCleanSize
 * @tc.desc: 1.Test the CleanBundleCacheTaskGetCleanSize by BundleMgrHostImpl
 */
HWTEST_F(BmsBundleKitServiceTest, CleanBundleCacheTaskGetCleanSize_0100, Function | SmallTest | Level1)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    uint64_t cacheSize = 1;
    uint64_t uid = 1;
    hostImpl->CleanBundleCacheTaskGetCleanSize(BUNDLE_NAME_TEST, DEFAULT_USERID, cacheSize, uid, BUNDLE_NAME_TEST);
    EXPECT_FALSE(DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr()->bundleInfos_.empty());
}

/**
 * @tc.number: PluginBundleInfoTest
 * @tc.name: PluginBundleInfoTest to_json and from_json branch cover
 * @tc.desc: 1.Test to_json and from_json
 */
HWTEST_F(BmsBundleKitServiceTest, PluginBundleInfoTest_0100, Function | SmallTest | Level1)
{
    PluginBundleInfo pluginBundleInfo;
    pluginBundleInfo.pluginBundleName = BUNDLE_NAME_TEST;
    pluginBundleInfo.versionCode = BUNDLE_VERSION_CODE;
    pluginBundleInfo.versionName = BUNDLE_VERSION_NAME;
    pluginBundleInfo.iconId = ICON_ID;
    pluginBundleInfo.labelId = LABEL_ID;
    nlohmann::json jsonObj;
    to_json(jsonObj, pluginBundleInfo);
    PluginBundleInfo result;
    from_json(jsonObj, result);
    EXPECT_EQ(result.pluginBundleName, BUNDLE_NAME_TEST);
    EXPECT_EQ(result.versionCode, BUNDLE_VERSION_CODE);
    EXPECT_EQ(result.versionName, BUNDLE_VERSION_NAME);
    EXPECT_EQ(result.iconId, ICON_ID);
    EXPECT_EQ(result.labelId, LABEL_ID);
}

/**
 * @tc.number: PluginBundleInfoTest
 * @tc.name: PluginBundleInfo Marshalling and Unmarshalling
 * @tc.desc: 1.Test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleKitServiceTest, PluginBundleInfoTest_0200, Function | SmallTest | Level1)
{
    PluginBundleInfo info1;
    info1.pluginBundleName = BUNDLE_NAME_TEST;
    info1.versionCode = BUNDLE_VERSION_CODE;
    info1.iconId = ICON_ID;
    info1.labelId = LABEL_ID;

    Parcel parcel;
    auto ret1 = info1.Marshalling(parcel);
    EXPECT_EQ(ret1, true);

    PluginBundleInfo info2;
    auto ret2 = info2.Unmarshalling(parcel);
    EXPECT_NE(ret2, nullptr);
    EXPECT_EQ(info1.pluginBundleName, ret2->pluginBundleName);
    EXPECT_EQ(info1.versionCode, ret2->versionCode);
    EXPECT_EQ(info1.iconId, ret2->iconId);
    EXPECT_EQ(info1.labelId, ret2->labelId);
}

/**
 * @tc.number: PluginModuleInfoTest
 * @tc.name: PluginModuleInfo to_json and from_json branch cover
 * @tc.desc: 1.Test to_json and from_json
 */
HWTEST_F(BmsBundleKitServiceTest, PluginModuleInfoTest_0100, Function | SmallTest | Level1)
{
    PluginModuleInfo pluginModuleInfo;
    pluginModuleInfo.moduleName = MODULE_NAME;
    pluginModuleInfo.hapPath = HAP_FILE_PATH;
    pluginModuleInfo.description = DESCRIPTION;
    nlohmann::json jsonObj;
    to_json(jsonObj, pluginModuleInfo);
    PluginModuleInfo result;
    from_json(jsonObj, result);
    EXPECT_EQ(result.moduleName, MODULE_NAME);
    EXPECT_EQ(result.hapPath, HAP_FILE_PATH);
    EXPECT_EQ(result.description, DESCRIPTION);
    EXPECT_EQ(result.moduleArkTSMode, Constants::ARKTS_MODE_DYNAMIC);
}

/**
 * @tc.number: PluginModuleInfoTest
 * @tc.name: PluginModuleInfo Marshalling and Unmarshalling
 * @tc.desc: 1.Test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleKitServiceTest, PluginModuleInfoTest_0200, Function | SmallTest | Level1)
{
    PluginModuleInfo info1;
    info1.moduleName = MODULE_NAME;
    info1.hapPath = HAP_FILE_PATH;
    info1.description = DESCRIPTION;
    Parcel parcel;
    auto ret1 = info1.Marshalling(parcel);
    EXPECT_EQ(ret1, true);

    PluginModuleInfo info2;
    auto ret2 = info2.Unmarshalling(parcel);
    EXPECT_NE(ret2, nullptr);
    EXPECT_EQ(info1.moduleName, ret2->moduleName);
    EXPECT_EQ(info1.hapPath, ret2->hapPath);
    EXPECT_EQ(info1.moduleArkTSMode, ret2->moduleArkTSMode);
}

/**
 * @tc.number: PluginModuleInfoTest
 * @tc.name: PluginModuleInfo to_json and from_json branch cover
 * @tc.desc: 1.Test to_json and from_json
 */
HWTEST_F(BmsBundleKitServiceTest, PluginModuleInfoTest_0300, Function | SmallTest | Level1)
{
    PluginModuleInfo pluginModuleInfo;
    pluginModuleInfo.moduleName = MODULE_NAME;
    pluginModuleInfo.hapPath = HAP_FILE_PATH;
    pluginModuleInfo.description = DESCRIPTION;
    pluginModuleInfo.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    nlohmann::json jsonObj;
    to_json(jsonObj, pluginModuleInfo);
    PluginModuleInfo result;
    from_json(jsonObj, result);
    EXPECT_EQ(result.moduleName, MODULE_NAME);
    EXPECT_EQ(result.hapPath, HAP_FILE_PATH);
    EXPECT_EQ(result.description, DESCRIPTION);
    EXPECT_EQ(result.moduleArkTSMode, Constants::ARKTS_MODE_STATIC);
}

/**
 * @tc.number: PluginModuleInfoTest
 * @tc.name: PluginModuleInfo Marshalling and Unmarshalling
 * @tc.desc: 1.Test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleKitServiceTest, PluginModuleInfoTest_0400, Function | SmallTest | Level1)
{
    PluginModuleInfo info1;
    info1.moduleName = MODULE_NAME;
    info1.hapPath = HAP_FILE_PATH;
    info1.description = DESCRIPTION;
    info1.moduleArkTSMode = Constants::ARKTS_MODE_STATIC;
    Parcel parcel;
    auto ret1 = info1.Marshalling(parcel);
    EXPECT_EQ(ret1, true);

    PluginModuleInfo info2;
    auto ret2 = info2.Unmarshalling(parcel);
    EXPECT_NE(ret2, nullptr);
    EXPECT_EQ(info1.moduleName, ret2->moduleName);
    EXPECT_EQ(info1.hapPath, ret2->hapPath);
    EXPECT_EQ(info1.moduleArkTSMode, ret2->moduleArkTSMode);
}

/**
 * @tc.number: GetAbilityInfoByName
 * @tc.name: PluginBundleInfo Marshalling and Unmarshalling
 * @tc.desc: 1.Test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleKitServiceTest, GetAbilityInfoByName_1000, Function | SmallTest | Level0)
{
    PluginBundleInfo pluginBundleInfo;
    AbilityInfo info;
    const std::string moduleName = "moduleName1";
    const std::string abilityName = "abilityName1";
    bool result = pluginBundleInfo.GetAbilityInfoByName(abilityName, moduleName, info);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: GetAbilityInfoByName_2000
 * @tc.name: GetAbilityInfoByName_2000
 * @tc.desc: 1.Test GetAbilityInfoByName
 */
HWTEST_F(BmsBundleKitServiceTest, GetAbilityInfoByName_2000, Function | SmallTest | Level0)
{
    PluginBundleInfo pluginBundleInfo;
    AbilityInfo info;
    info.name = "abilityName1";
    pluginBundleInfo.abilityInfos.emplace("abilityName1", info);
    const std::string moduleName = "";
    const std::string abilityName = "abilityName1";
    bool result = pluginBundleInfo.GetAbilityInfoByName(abilityName, moduleName, info);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: GetAbilityInfoByName_3000
 * @tc.name: GetAbilityInfoByName_3000
 * @tc.desc: 1.Test GetAbilityInfoByName
 */
HWTEST_F(BmsBundleKitServiceTest, GetAbilityInfoByName_3000, Function | SmallTest | Level0)
{
    PluginBundleInfo pluginBundleInfo;
    AbilityInfo info;
    info.name = "abilityName1";
    info.moduleName = "moduleName1";
    pluginBundleInfo.abilityInfos.emplace("abilityName1", info);
    const std::string moduleName = "moduleName1";
    const std::string abilityName = "abilityName1";
    bool result = pluginBundleInfo.GetAbilityInfoByName(abilityName, moduleName, info);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: GetHapModuleInfo
 * @tc.name: PluginBundleInfo Marshalling and Unmarshalling
 * @tc.desc: 1.Test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleKitServiceTest, GetHapModuleInfo_1000, Function | SmallTest | Level0)
{
    PluginBundleInfo pluginBundleInfo;
    HapModuleInfo hapInfo;
    const std::string moduleName = "moduleName";
    bool result = pluginBundleInfo.GetHapModuleInfo(moduleName, hapInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: GetHapModuleInfo_2000
 * @tc.name: GetHapModuleInfo_2000
 * @tc.desc: 1.Test GetHapModuleInfo_2000
 */
HWTEST_F(BmsBundleKitServiceTest, GetHapModuleInfo_2000, Function | SmallTest | Level0)
{
    PluginBundleInfo pluginBundleInfo;
    PluginModuleInfo pluginModuleInfo;
    pluginModuleInfo.moduleName = "moduleName";
    pluginBundleInfo.pluginModuleInfos.emplace_back(pluginModuleInfo);
    HapModuleInfo hapInfo;
    bool result = pluginBundleInfo.GetHapModuleInfo("moduleName", hapInfo);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: GetHapModuleInfo_3000
 * @tc.name: GetHapModuleInfo_3000
 * @tc.desc: 1.Test GetHapModuleInfo_3000
 */
HWTEST_F(BmsBundleKitServiceTest, GetHapModuleInfo_3000, Function | SmallTest | Level0)
{
    PluginBundleInfo pluginBundleInfo;
    PluginModuleInfo pluginModuleInfo;
    pluginModuleInfo.moduleName = "moduleName";
    pluginModuleInfo.compileMode = "esmodule";
    pluginBundleInfo.pluginModuleInfos.emplace_back(pluginModuleInfo);
    AbilityInfo info;
    info.name = "abilityName";
    info.moduleName = "moduleName";
    pluginBundleInfo.abilityInfos.emplace("abilityName.moduleName.", info);
    HapModuleInfo hapInfo;
    bool result = pluginBundleInfo.GetHapModuleInfo("moduleName", hapInfo);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: GetHapModuleInfo_4000
 * @tc.name: GetHapModuleInfo_4000
 * @tc.desc: 1.Test GetHapModuleInfo_4000
 */
HWTEST_F(BmsBundleKitServiceTest, GetHapModuleInfo_4000, Function | SmallTest | Level0)
{
    PluginBundleInfo pluginBundleInfo;
    PluginModuleInfo pluginModuleInfo;
    pluginModuleInfo.moduleName = "moduleName";
    pluginModuleInfo.compileMode = "jsbundle";
    pluginBundleInfo.pluginModuleInfos.emplace_back(pluginModuleInfo);
    AbilityInfo info;
    info.name = "abilityName";
    info.moduleName = "moduleName";
    pluginBundleInfo.abilityInfos.emplace("abilityName.moduleName.", info);
    HapModuleInfo hapInfo;
    bool result = pluginBundleInfo.GetHapModuleInfo("moduleName", hapInfo);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: Marshalling_1000
 * @tc.name: PluginBundleInfo Marshalling and Unmarshalling
 * @tc.desc: 1.Test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleKitServiceTest, Marshalling_1000, Function | SmallTest | Level0)
{
    PluginBundleInfo pluginBundleInfo;
    pluginBundleInfo.pluginModuleInfos.clear();
    pluginBundleInfo.abilityInfos.clear();

    Parcel parcel;
    bool result = pluginBundleInfo.Marshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: Marshalling_2000
 * @tc.name: PluginBundleInfo Marshalling and Unmarshalling
 * @tc.desc: 1.Test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleKitServiceTest, Marshalling_2000, Function | SmallTest | Level0)
{
    PluginBundleInfo pluginBundleInfo;
    Parcel parcel;
    bool result = pluginBundleInfo.Marshalling(parcel);

    EXPECT_TRUE(result);
    EXPECT_GT(parcel.GetDataSize(), 0);
    int32_t moduleCount;
    parcel.ReadInt32(moduleCount);
    EXPECT_EQ(moduleCount, 0);

    int32_t abilityCount;
    parcel.ReadInt32(abilityCount);
    EXPECT_EQ(abilityCount, 0);
    std::string abilityName1;
    AbilityInfo abilityInfo1;
    parcel.ReadString(abilityName1);
    EXPECT_EQ(abilityName1, "");

    std::string abilityName2;
    AbilityInfo abilityInfo2;
    parcel.ReadString(abilityName2);
    EXPECT_EQ(abilityName2, "");
}

/**
 * @tc.number: Marshalling_3000
 * @tc.name: PluginBundleInfo Marshalling and Unmarshalling
 * @tc.desc: 1.Test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleKitServiceTest, Marshalling_3000, Function | SmallTest | Level0)
{
    PluginBundleInfo pluginBundleInfo;
    Parcel parcel;
    bool result = pluginBundleInfo.Marshalling(parcel);
    EXPECT_TRUE(result);
    EXPECT_GT(parcel.GetDataSize(), 0);
    int32_t moduleCount;
    parcel.ReadInt32(moduleCount);
    EXPECT_EQ(moduleCount, 0);

    int32_t abilityCount;
    parcel.ReadInt32(abilityCount);
    EXPECT_EQ(abilityCount, 0);

    std::string abilityName1;
    AbilityInfo abilityInfo1;
    parcel.ReadString(abilityName1);
    EXPECT_EQ(abilityName1, "");

    std::string abilityName2;
    AbilityInfo abilityInfo2;
    parcel.ReadString(abilityName2);
    EXPECT_EQ(abilityName2, "");
}

/**
 * @tc.number: IsRenameInstall_1000
 * @tc.name: PluginBundleInfo Marshalling and Unmarshalling
 * @tc.desc: 1.Test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleKitServiceTest, IsRenameInstall_1000, Function | SmallTest | Level0)
{
    InstallPluginParam installPluginParam;
    installPluginParam.parameters[AppExecFwk::InstallParam::RENAME_INSTALL_KEY] =
        AppExecFwk::InstallParam::PARAMETERS_VALUE_TRUE;
    bool result = installPluginParam.IsRenameInstall();
    EXPECT_TRUE(result);
}

/**
 * @tc.number: IsRenameInstall_2000
 * @tc.name: PluginBundleInfo Marshalling and Unmarshalling
 * @tc.desc: 1.Test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleKitServiceTest, IsRenameInstall_2000, Function | SmallTest | Level0)
{
    InstallPluginParam installPluginParam;
    installPluginParam.parameters[AppExecFwk::InstallParam::RENAME_INSTALL_KEY] = "false";
    bool result = installPluginParam.IsRenameInstall();
    EXPECT_FALSE(result);
}

/**
 * @tc.number: IsRenameInstall_3000
 * @tc.name: PluginBundleInfo Marshalling and Unmarshalling
 * @tc.desc: 1.Test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleKitServiceTest, IsRenameInstall_3000, Function | SmallTest | Level0)
{
    InstallPluginParam installPluginParam;
    bool result = installPluginParam.IsRenameInstall();
    EXPECT_FALSE(result);
}

/**
 * @tc.number: IsRenameInstall_4000
 * @tc.name: PluginBundleInfo Marshalling and Unmarshalling
 * @tc.desc: 1.Test Marshalling and Unmarshalling
 */
HWTEST_F(BmsBundleKitServiceTest, IsRenameInstall_4000, Function | SmallTest | Level0)
{
    InstallPluginParam installPluginParam;
    installPluginParam.parameters.clear();

    Parcel parcel;
    bool result = installPluginParam.Marshalling(parcel);
    EXPECT_TRUE(result);
    EXPECT_GT(parcel.GetDataSize(), 0);

    int32_t userId = Constants::UNSPECIFIED_USERID;
    parcel.ReadInt32(userId);
    EXPECT_EQ(userId, -2);
    uint32_t size;
    parcel.ReadUint32(size);
    EXPECT_EQ(size, 0);
}
}
