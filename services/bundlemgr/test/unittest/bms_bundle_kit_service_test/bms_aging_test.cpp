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
const std::string MODULE_NAME_TEST = "com.example.bundlekit.test.entry";
const std::string MODULE_NAME_TEST_1 = "com.example.bundlekit.test.entry_A";
const std::string MODULE_NAME_TEST_2 = "com.example.bundlekit.test.entry_B";
const std::string MODULE_NAME_TEST_3 = "com.example.bundlekit.test.entry_C";
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
const std::string BUNDLE_NAME_DEMO = "com.example.bundlekit.demo";
const std::string MODULE_NAME_DEMO = "com.example.bundlekit.demo.entry";
const std::string ABILITY_NAME_DEMO = ".Writing";
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
const int32_t WAIT_TIME = 2; // init mocked bms
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

class BmsAgingTest : public testing::Test {
public:
    using Want = OHOS::AAFwk::Want;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
public:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsAgingTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsAgingTest::installdService_ =
    std::make_shared<InstalldService>();

void BmsAgingTest::SetUpTestCase()
{}

void BmsAgingTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsAgingTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(DEFAULT_USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsAgingTest::TearDown()
{}
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
/**
 * @tc.number: AginTest_0018
 * @tc.name: test RecentlyUnuseBundleAgingHandler of ProcessBundle
 * @tc.desc: ProcessBundle is false
 */
HWTEST_F(BmsAgingTest, AginTest_0018, Function | SmallTest | Level0)
{
    RecentlyUnuseBundleAgingHandler bundleAgingMgr;
    AgingRequest request;
    bool ret = bundleAgingMgr.ProcessBundle(request);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: AginTest_0019
 * @tc.name: test RecentlyUnuseBundleAgingHandler of ProcessBundle
 * @tc.desc: ProcessBundle is false
 */
HWTEST_F(BmsAgingTest, AginTest_0019, Function | SmallTest | Level0)
{
    RecentlyUnuseBundleAgingHandler bundleAgingMgr;

    AgingRequest request;
    std::vector<AgingBundleInfo> agingBundles = {
        AgingBundleInfo("com.example.app1", 1000, 5, 0),
        AgingBundleInfo("com.example.app2", 2000, 3, 0)
    };
    request.AddAgingBundle(agingBundles[0]);
    request.AddAgingBundle(agingBundles[1]);
    bool ret = bundleAgingMgr.ProcessBundle(request);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: AginTest_0024
 * @tc.name: test RecentlyUnuseBundleAgingHandler of Process
 * @tc.desc: CleanCache is hasCleanCache
 */
HWTEST_F(BmsAgingTest, AginTest_0024, Function | SmallTest | Level0)
{
    RecentlyUnuseBundleAgingHandler bundleAgingMgr;
    AgingBundleInfo agingBundle("com.example.app2", 2000, 3, 0);
    bool ret = bundleAgingMgr.CleanCache(agingBundle);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InitAgingRequest_0001
 * @tc.name: test BundleAgingMgr of Process
 * @tc.desc: InitAgingRequest is true(uncord)
 */
HWTEST_F(BmsAgingTest, InitAgingRequest_0001, Function | SmallTest | Level0)
{
    const int64_t allBundleDataBytes = 1;
    BundleAgingMgr bundleAgingMgr;
    bundleAgingMgr.request_.SetTotalDataBytes(allBundleDataBytes);
    bool ret = bundleAgingMgr.InitAgingRequest();
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CheckPrerequisite_0001
 * @tc.name: test BundleAgingMgr of Process
 * @tc.desc: CheckPrerequisite is true
 */
HWTEST_F(BmsAgingTest, CheckPrerequisite_0001, Function | SmallTest | Level0)
{
    BundleAgingMgr bundleAgingMgr;
    AppExecFwk::BundleAgingMgr::AgingTriggertype type = AppExecFwk::BundleAgingMgr::AgingTriggertype::FREE_INSTALL;
    bool ret = bundleAgingMgr.CheckPrerequisite(type);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: CheckPrerequisite_0002
 * @tc.name: test BundleAgingMgr of Process
 * @tc.desc: CheckPrerequisite is false
 */
HWTEST_F(BmsAgingTest, CheckPrerequisite_0002, Function | SmallTest | Level0)
{
    BundleAgingMgr bundleAgingMgr;
    AppExecFwk::BundleAgingMgr::AgingTriggertype type = AppExecFwk::BundleAgingMgr::AgingTriggertype::PREIOD;
    DisplayPowerMgr::DisplayPowerMgrClient::GetInstance().SetDisplayState(DisplayPowerMgr::DisplayState::DISPLAY_ON);
    DisplayPowerMgr::DisplayState state = DisplayPowerMgr::DisplayPowerMgrClient::GetInstance().GetDisplayState();
    bool ret = bundleAgingMgr.CheckPrerequisite(type);
    if (state == DisplayPowerMgr::DisplayState::DISPLAY_ON) {
        EXPECT_FALSE(ret);
    } else {
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: Process_0001
 * @tc.name: test AgingHandlerChain of Process
 * @tc.desc: Process is isPassed
 */
HWTEST_F(BmsAgingTest, Process_0001, Function | SmallTest | Level0)
{
    AgingHandlerChain agingHandlerChain;
    AgingRequest request;
    RecentlyUnuseBundleAgingHandler ruAgingHandler;
    auto handler = std::make_shared<RecentlyUnuseBundleAgingHandler>(ruAgingHandler);
    agingHandlerChain.AddHandler(handler);
    request.SetTotalDataBytes(1);
    request.totalDataBytesThreshold_ = 0;
    bool ret = agingHandlerChain.Process(request);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: Dump_0001
 * @tc.name: test aging_request of Process
 * @tc.desc: Dump is void
 */
HWTEST_F(BmsAgingTest, Dump_0001, Function | SmallTest | Level0)
{
    DeviceUsageStats::BundleActiveClient::GetInstance();
    AppExecFwk::AgingRequest agingRequest;
    AppExecFwk::AgingBundleInfo bundleInfo("com.example.app1", 1, 2, 0);
    agingRequest.AddAgingBundle(bundleInfo);
    agingRequest.Dump();
    EXPECT_EQ(agingRequest.agingBundles_[0].GetStartCount(), 2);
}

/**
 * @tc.number: InitAgingRequest_0002
 * @tc.name: test BundleAgingMgr of Process
 * @tc.desc: InitAgingRequest is false
 */
HWTEST_F(BmsAgingTest, InitAgingRequest_0002, Function | SmallTest | Level0)
{
    BundleAgingMgr bundleAgingMgr;
    bundleAgingMgr.request_.totalDataBytesThreshold_ = 0;
    bundleAgingMgr.request_.SetTotalDataBytes(1);
    bool ret = bundleAgingMgr.InitAgingRequest();
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InitAgingRequest_0003
 * @tc.name: test BundleAgingMgr of Process
 * @tc.desc: InitAgingRequest is true
 */
HWTEST_F(BmsAgingTest, InitAgingRequest_0003, Function | SmallTest | Level0)
{
    BundleAgingMgr bundleAgingMgr;
    InnerBundleInfo innerBundleInfoOne;
    InnerBundleInfo innerBundleInfoTwo;
    const int64_t allBundleDataBytes = bundleAgingMgr.request_.GetTotalDataBytesThreshold() + 1;
    bundleAgingMgr.request_.SetTotalDataBytes(allBundleDataBytes);
    auto dataMgr = OHOS::DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    int32_t bundleidone = 1001;
    int32_t bundleidtwo = 1001;
    dataMgr->AddUserId(1001);
    dataMgr->AddUserId(1002);
    dataMgr->GenerateBundleId("app1", bundleidone);
    dataMgr->GenerateBundleId("app2", bundleidtwo);
    dataMgr->AddInnerBundleInfo("app1", innerBundleInfoOne, false);
    dataMgr->AddInnerBundleInfo("app2", innerBundleInfoTwo, false);
    dataMgr->UpdateBundleInstallState("app1", InstallState::INSTALL_SUCCESS, false);
    dataMgr->UpdateBundleInstallState("app2", InstallState::INSTALL_SUCCESS, false);

    bool ret = bundleAgingMgr.InitAgingRequest();
    EXPECT_FALSE(ret);
    dataMgr->RemoveUserId(1001);
    dataMgr->RemoveUserId(1002);
}

/**
 * @tc.number: AgingClean_0001
 * @tc.name: test BundleAgingMgr of AgingClean
 * @tc.desc: AgingClean is true
 */
HWTEST_F(BmsAgingTest, AgingClean_0001, Function | SmallTest | Level0)
{
    RecentlyUnuseBundleAgingHandler ruBundleAgingHandler;
    const AgingBundleInfo agingBundleInfo;
    AgingRequest request;
    request.SetAgingCleanType(AgingCleanType::CLEAN_OTHERS);
    bool ret = ruBundleAgingHandler.AgingClean(agingBundleInfo, request);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: ProcessBundle_0001
 * @tc.name: test RecentlyUnuseBundleAgingHandler of ProcessBundle
 * @tc.desc: ProcessBundle is true
 */
HWTEST_F(BmsAgingTest, ProcessBundle_0001, Function | SmallTest | Level0)
{
    AgingHandlerChain agingHandlerChain;
    AgingRequest request;
    RecentlyUnuseBundleAgingHandler ruAgingHandler;
    AgingBundleInfo agingBundleInfoFirst("mock_NOT_RUNNING", 1000, 5, 0);
    request.AddAgingBundle(agingBundleInfoFirst);
    auto handler = std::make_shared<RecentlyUnuseBundleAgingHandler>(ruAgingHandler);
    agingHandlerChain.AddHandler(handler);
    bool ret = ruAgingHandler.ProcessBundle(request);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: ProcessBundle_0002
 * @tc.name: test RecentlyUnuseBundleAgingHandler of ProcessBundle
 * @tc.desc: ProcessBundle is false
 */
HWTEST_F(BmsAgingTest, ProcessBundle_0002, Function | SmallTest | Level0)
{
    AgingHandlerChain agingHandlerChain;
    AgingRequest request;
    RecentlyUnuseBundleAgingHandler ruAgingHandler;
    AgingBundleInfo agingBundleInfoFirst("mock_NOT_RUNNING", 1000, 5, 0);
    request.AddAgingBundle(agingBundleInfoFirst);
    request.SetAgingCleanType(AgingCleanType::CLEAN_OTHERS);
    request.totalDataBytesThreshold_ = 2;
    auto handler = std::make_shared<RecentlyUnuseBundleAgingHandler>(ruAgingHandler);
    agingHandlerChain.AddHandler(handler);
    bool ret = ruAgingHandler.ProcessBundle(request);
    EXPECT_FALSE(ret);
    request.totalDataBytesThreshold_ = 0;
}

/**
 * @tc.number: SortAgingBundles_0001
 * @tc.name: SortAgingBundles_0001
 * @tc.desc: test sorting aging bundleInfo
 */
HWTEST_F(BmsAgingTest, SortAgingBundles_0001, Function | SmallTest | Level0)
{
    AgingRequest request;
    AgingBundleInfo agingBundleInfoFirst("com.example.app1", 2000, 5, 1);
    AgingBundleInfo agingBundleInfoSecond("com.example.app2", 1000, 6, 0);
    AgingBundleInfo agingBundleInfoThree("com.example.app3", 1000, 5, 0);
    request.AddAgingBundle(agingBundleInfoFirst);
    request.AddAgingBundle(agingBundleInfoSecond);
    request.AddAgingBundle(agingBundleInfoThree);
    request.SortAgingBundles();
    auto TestAgingBundles = request.GetAgingBundles();
    EXPECT_EQ(TestAgingBundles[0].GetBundleName(), "com.example.app3");
    EXPECT_EQ(TestAgingBundles[1].GetBundleName(), "com.example.app2");
    EXPECT_EQ(TestAgingBundles[2].GetBundleName(), "com.example.app1");
}

/**
 * @tc.number: SortAgingBundles_0002
 * @tc.name: SortAgingBundles_0002
 * @tc.desc: test sorting aging bundleInfo
 */
HWTEST_F(BmsAgingTest, SortAgingBundles_0002, Function | SmallTest | Level0)
{
    AgingRequest request;
    AgingBundleInfo agingBundleInfoFirst("com.example.app1", 2000, 5, 1);
    AgingBundleInfo agingBundleInfoSecond("com.example.app2", 1000, 6, 0);
    AgingBundleInfo agingBundleInfoThree("com.example.app3", 2000, 7, 1);
    request.AddAgingBundle(agingBundleInfoFirst);
    request.AddAgingBundle(agingBundleInfoSecond);
    request.AddAgingBundle(agingBundleInfoThree);
    request.SortAgingBundles();
    auto TestAgingBundles = request.GetAgingBundles();
    EXPECT_EQ(TestAgingBundles[0].GetBundleName(), "com.example.app2");
    EXPECT_EQ(TestAgingBundles[1].GetBundleName(), "com.example.app1");
    EXPECT_EQ(TestAgingBundles[2].GetBundleName(), "com.example.app3");
}
#endif
}
