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

#define private public
#include <chrono>
#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <thread>

#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "inner_bundle_info.h"
#include "module_json_updater.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string BUNDLE_A = "com.example.bundleA";
const std::string BUNDLE_B = "com.example.bundleB";
const std::string MODULE_A = "moduleA";
const std::string MODULE_B = "moduleB";
const std::string ABILITY_A = "abilityA";
const std::string ABILITY_B = "abilityB";
const std::string EXTENSION_A = "extensionA";
const std::string EXTENSION_B = "extensionB";
const std::string INVALID_HAP_PATH = "/path/not/exist/xxx.hap";
constexpr const char* OTA_FLAG = "otaFlag";
const int32_t USER_ID = 100;
const int32_t WAIT_TIME_SECONDS = 5;
const int32_t TARGET_MINOR_API_VERSION = 20;
const int32_t TARGET_PATCH_API_VERSION = 21;
const StartMode START_MODE = StartMode::RECENT_TASK;
const std::vector<std::string> ASSET_ACCESS_GROUPS = {"group1", "group2"};
const AppPreloadPhase APP_PRELOAD_PHASE = AppPreloadPhase::ABILITY_STAGE_CREATED;
const bool CLOUD_STRUCTURED_DATA_SYNC_ENABLED = true;
const std::map<std::string, std::vector<std::string>> REQUIRED_DEVICE_FEATURES = {
    {BUNDLE_A, {"feature1", "feature2"}},
    {BUNDLE_B, {"feature3", "feature4"}}
};
const std::string SYSTEM_THEME = "systemTheme";
const std::string CROSS_APP_SHARED_CONFIG = "crossAppSharedConfig";
const std::string FORM_EXTENSION_MODULE = "formExtensionModule";
const std::string FORM_WIDGET_MODULE = "formWidgetModule";
const std::string MODULE_ARK_TS_MODE = "static";
const std::string ARK_TS_MODE = "static";
const bool RESIZEABLE = true;
const std::vector<Metadata> METADATA = {
    {"metaName1", "metaValue1", "metaResource1"},
    {"metaName2", "metaValue2", "metaResource2"}
};
const std::unordered_set<std::string> CONTINUE_BUNDLE_NAMES = {"com.example.bundleC"};
const std::string START_WINDOW = "startWindow";
const uint32_t START_WINDOW_ID = 21;
const ExtensionAbilityType TYPE_LIVE_FORM = ExtensionAbilityType::LIVE_FORM;
const std::vector<std::string> APP_IDENTIFIER_ALLOW_LIST = {"com.example.bundleA"};
const bool ISOLATION_PROCESS = true;
}  // namespace

class BmsModuleJsonUpdaterTest : public testing::Test {
public:
    BmsModuleJsonUpdaterTest();
    ~BmsModuleJsonUpdaterTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    static void StartBundleService();
    static bool UpdateOtaFlag(OTAFlag flag);
    void SetUp();
    void TearDown();
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsModuleJsonUpdaterTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsModuleJsonUpdaterTest::BmsModuleJsonUpdaterTest()
{}

BmsModuleJsonUpdaterTest::~BmsModuleJsonUpdaterTest()
{}

void BmsModuleJsonUpdaterTest::SetUpTestCase()
{
    StartBundleService();
}

void BmsModuleJsonUpdaterTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsModuleJsonUpdaterTest::SetUp()
{}

void BmsModuleJsonUpdaterTest::TearDown()
{}

void BmsModuleJsonUpdaterTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME_SECONDS));
    }
}

bool BmsModuleJsonUpdaterTest::UpdateOtaFlag(OTAFlag flag)
{
    auto bmsPara = bundleMgrService_->GetBmsParam();
    if (bmsPara == nullptr) {
        return false;
    }

    std::string val;
    if (!bmsPara->GetBmsParam(OTA_FLAG, val)) {
        return bmsPara->SaveBmsParam(OTA_FLAG, std::to_string(flag));
    }

    int32_t valInt = 0;
    if (!StrToInt(val, valInt)) {
        return bmsPara->SaveBmsParam(OTA_FLAG, std::to_string(flag));
    }

    return bmsPara->SaveBmsParam(
        OTA_FLAG, std::to_string(static_cast<uint32_t>(flag) | static_cast<uint32_t>(valInt)));
}

/**
 * @tc.number: UpdateModuleJsonAsync_0100
 * @tc.name: UpdateModuleJsonAsync
 * @tc.desc: 1.Test the UpdateModuleJsonAsync function, expect ignoredBundles empty.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, UpdateModuleJsonAsync_0100, Function | SmallTest | Level1)
{
    ModuleJsonUpdater::SetIgnoreBundleNames({BUNDLE_A, BUNDLE_B});
    BmsModuleJsonUpdaterTest::UpdateOtaFlag(OTAFlag::UPDATE_MODULE_JSON);
    ModuleJsonUpdater::UpdateModuleJsonAsync();
    std::set<std::string> ignoredBundles = ModuleJsonUpdater::GetIgnoreBundleNames();
    EXPECT_TRUE(ignoredBundles.empty());
}

/**
 * @tc.number: UpdateModuleJson_0100
 * @tc.name: UpdateModuleJson
 * @tc.desc: 1.Test the UpdateModuleJson function, expect ignoredBundles empty.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, UpdateModuleJson_0100, Function | SmallTest | Level1)
{
    ModuleJsonUpdater::SetIgnoreBundleNames({BUNDLE_A, BUNDLE_B});
    ModuleJsonUpdater::UpdateModuleJson();
    std::set<std::string> ignoredBundles = ModuleJsonUpdater::GetIgnoreBundleNames();
    EXPECT_TRUE(ignoredBundles.empty());
}

/**
 * @tc.number: UpdateModuleJson_0200
 * @tc.name: UpdateModuleJson
 * @tc.desc: 1.Test the UpdateModuleJson function, expect ignoredBundles empty.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, UpdateModuleJson_0200, Function | SmallTest | Level1)
{
    auto dataMgr = BmsModuleJsonUpdaterTest::bundleMgrService_->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::map<std::string, InnerBundleInfo> infos = dataMgr->GetAllInnerBundleInfos();
    std::set<std::string> ignoredBundles;
    for (const auto &item : infos) {
        ignoredBundles.insert(item.first);
    }
    ModuleJsonUpdater::SetIgnoreBundleNames(ignoredBundles);
    ModuleJsonUpdater::UpdateModuleJson();
    ignoredBundles = ModuleJsonUpdater::GetIgnoreBundleNames();
    EXPECT_TRUE(ignoredBundles.empty());
}

/**
 * @tc.number: ParseBundleModuleJson_0100
 * @tc.name: ParseBundleModuleJson
 * @tc.desc: 1.Test the ParseBundleModuleJson function with innerModuleInfos empty, expect return false.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, ParseBundleModuleJson_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::map<std::string, InnerBundleInfo> outMap;
    bool ret = ModuleJsonUpdater::ParseBundleModuleJson(info, outMap);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(outMap.empty());
}

/**
 * @tc.number: ParseBundleModuleJson_0200
 * @tc.name: ParseBundleModuleJson
 * @tc.desc: 1.Test the ParseBundleModuleJson function with hapPath empty, expect return false.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, ParseBundleModuleJson_0200, Function | SmallTest | Level1)
{
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfos.try_emplace(BUNDLE_A, innerModuleInfo);
    InnerBundleInfo info;
    info.AddInnerModuleInfo(innerModuleInfos);
    std::map<std::string, InnerBundleInfo> outMap;
    bool ret = ModuleJsonUpdater::ParseBundleModuleJson(info, outMap);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(outMap.empty());
}

/**
 * @tc.number: ParseBundleModuleJson_0300
 * @tc.name: ParseBundleModuleJson
 * @tc.desc: 1.Test the ParseBundleModuleJson function, expect return true.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, ParseBundleModuleJson_0300, Function | SmallTest | Level1)
{
    std::map<std::string, InnerBundleInfo> infos =
        BmsModuleJsonUpdaterTest::bundleMgrService_->GetDataMgr()->GetAllInnerBundleInfos();
    EXPECT_FALSE(infos.empty());
    std::map<std::string, InnerBundleInfo> outMap;
    bool ret = ModuleJsonUpdater::ParseBundleModuleJson(infos.begin()->second, outMap);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(outMap.empty());
}

/**
 * @tc.number: ParseHapModuleJson_0100
 * @tc.name: ParseHapModuleJson
 * @tc.desc: 1.Test the ParseHapModuleJson function with empty hapPath, expect return false.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, ParseHapModuleJson_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo jsonInfo;
    bool ret = ModuleJsonUpdater::ParseHapModuleJson("", jsonInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ParseHapModuleJson_0200
 * @tc.name: ParseHapModuleJson
 * @tc.desc: 1.Test the ParseHapModuleJson function with err hapPath, expect return false.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, ParseHapModuleJson_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo jsonInfo;
    bool ret = ModuleJsonUpdater::ParseHapModuleJson(INVALID_HAP_PATH, jsonInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: MergeInnerBundleInfo_0100
 * @tc.name: MergeInnerBundleInfo
 * @tc.desc: 1.Test the MergeInnerBundleInfo function with empty map, expect return false.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, MergeInnerBundleInfo_0100, Function | SmallTest | Level1)
{
    std::map<std::string, InnerBundleInfo> moduleJsonMap;
    InnerBundleInfo mergedInfo;
    bool ret = ModuleJsonUpdater::MergeInnerBundleInfo(moduleJsonMap, mergedInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: MergeInnerBundleInfo_0200
 * @tc.name: MergeInnerBundleInfo
 * @tc.desc: 1.Test the MergeInnerBundleInfo function with not empty map, expect return true.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, MergeInnerBundleInfo_0200, Function | SmallTest | Level1)
{
    std::map<std::string, InnerBundleInfo> moduleJsonMap;
    moduleJsonMap.try_emplace(BUNDLE_A, InnerBundleInfo());
    InnerBundleInfo mergedInfo;
    bool ret = ModuleJsonUpdater::MergeInnerBundleInfo(moduleJsonMap, mergedInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: UpdateExtensionType_0100
 * @tc.name: UpdateExtensionType
 * @tc.desc: 1.Test the UpdateExtensionType function, expect innerExtensionInfos empty.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, UpdateExtensionType_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo curInfo;
    InnerBundleInfo mergedInfo;
    ModuleJsonUpdater::UpdateExtensionType(curInfo, mergedInfo);
    EXPECT_TRUE(mergedInfo.FetchInnerExtensionInfos().empty());
}

/**
 * @tc.number: CanUsePrivilegeExtension_0100
 * @tc.name: CanUsePrivilegeExtension
 * @tc.desc: 1.Test the CanUsePrivilegeExtension function with invalid param, expect return false.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, CanUsePrivilegeExtension_0100, Function | SmallTest | Level1)
{
    bool ret = ModuleJsonUpdater::CanUsePrivilegeExtension("", "");
    EXPECT_FALSE(ret);
    ret = ModuleJsonUpdater::CanUsePrivilegeExtension("", BUNDLE_A);
    EXPECT_FALSE(ret);
    ret = ModuleJsonUpdater::CanUsePrivilegeExtension(INVALID_HAP_PATH, "");
    EXPECT_FALSE(ret);
    ret = ModuleJsonUpdater::CanUsePrivilegeExtension(INVALID_HAP_PATH, BUNDLE_A);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: SetIgnoreBundleNames_0100
 * @tc.name: SetIgnoreBundleNames
 * @tc.desc: 1.Test the SetIgnoreBundleNames function.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, SetIgnoreBundleNames_0100, Function | SmallTest | Level1)
{
    ModuleJsonUpdater::SetIgnoreBundleNames({BUNDLE_A, BUNDLE_B});
    std::set<std::string> ignoredBundles = ModuleJsonUpdater::GetIgnoreBundleNames();
    EXPECT_FALSE(ignoredBundles.empty());
}

/**
 * @tc.number: GetIgnoreBundleNames_0100
 * @tc.name: GetIgnoreBundleNames
 * @tc.desc: 1.Test the GetIgnoreBundleNames function.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, GetIgnoreBundleNames_0100, Function | SmallTest | Level1)
{
    ModuleJsonUpdater::SetIgnoreBundleNames({});
    std::set<std::string> ignoredBundles = ModuleJsonUpdater::GetIgnoreBundleNames();
    EXPECT_TRUE(ignoredBundles.empty());
}

/**
 * @tc.number: ClearIgnoreBundleNames_0100
 * @tc.name: ClearIgnoreBundleNames
 * @tc.desc: 1.Test the ClearIgnoreBundleNames function.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, ClearIgnoreBundleNames_0100, Function | SmallTest | Level1)
{
    ModuleJsonUpdater::SetIgnoreBundleNames({BUNDLE_A, BUNDLE_B});
    std::set<std::string> ignoredBundles = ModuleJsonUpdater::GetIgnoreBundleNames();
    EXPECT_FALSE(ignoredBundles.empty());
    ModuleJsonUpdater::ClearIgnoreBundleNames();
    ignoredBundles = ModuleJsonUpdater::GetIgnoreBundleNames();
    EXPECT_TRUE(ignoredBundles.empty());
}

/**
 * @tc.number: UpdatePartialInnerBundleInfo_0100
 * @tc.name: UpdatePartialInnerBundleInfo
 * @tc.desc: 1.Test the UpdatePartialInnerBundleInfo function.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, UpdatePartialInnerBundleInfo_0100, Function | SmallTest | Level1)
{
    auto dataMgr = BmsModuleJsonUpdaterTest::bundleMgrService_->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    bool ret = dataMgr->UpdatePartialInnerBundleInfo(info);
    EXPECT_FALSE(ret);
    info.baseApplicationInfo_->bundleName = BUNDLE_A;
    ret = dataMgr->UpdatePartialInnerBundleInfo(info);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: UpdatePartialInnerBundleInfo_0200
 * @tc.name: UpdatePartialInnerBundleInfo
 * @tc.desc: 1.Test the UpdatePartialInnerBundleInfo function with ApplicationInfo and BundleInfo.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, UpdatePartialInnerBundleInfo_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo jsonInfo;
    jsonInfo.baseApplicationInfo_->targetMinorApiVersion = TARGET_MINOR_API_VERSION;
    jsonInfo.baseApplicationInfo_->targetPatchApiVersion = TARGET_PATCH_API_VERSION;
    jsonInfo.baseApplicationInfo_->startMode = START_MODE;
    jsonInfo.baseApplicationInfo_->assetAccessGroups = ASSET_ACCESS_GROUPS;
    jsonInfo.baseApplicationInfo_->appPreloadPhase = APP_PRELOAD_PHASE;
    jsonInfo.baseApplicationInfo_->cloudStructuredDataSyncEnabled = CLOUD_STRUCTURED_DATA_SYNC_ENABLED;
    InnerBundleInfo infoA;
    infoA.UpdatePartialInnerBundleInfo(jsonInfo);
    EXPECT_EQ(infoA.baseApplicationInfo_->targetMinorApiVersion, TARGET_MINOR_API_VERSION);
    EXPECT_EQ(infoA.baseApplicationInfo_->targetPatchApiVersion, TARGET_PATCH_API_VERSION);
    EXPECT_EQ(infoA.baseApplicationInfo_->startMode, START_MODE);
    EXPECT_TRUE(infoA.baseApplicationInfo_->assetAccessGroups.empty());
    EXPECT_NE(infoA.baseApplicationInfo_->appPreloadPhase, APP_PRELOAD_PHASE);
    EXPECT_EQ(infoA.baseApplicationInfo_->cloudStructuredDataSyncEnabled, CLOUD_STRUCTURED_DATA_SYNC_ENABLED);

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = true;
    innerModuleInfos.try_emplace(MODULE_A, innerModuleInfo);
    jsonInfo.AddInnerModuleInfo(innerModuleInfos);
    InnerBundleInfo infoB;
    infoB.UpdatePartialInnerBundleInfo(jsonInfo);
    EXPECT_EQ(infoB.baseApplicationInfo_->targetMinorApiVersion, TARGET_MINOR_API_VERSION);
    EXPECT_EQ(infoB.baseApplicationInfo_->targetPatchApiVersion, TARGET_PATCH_API_VERSION);
    EXPECT_EQ(infoB.baseApplicationInfo_->startMode, START_MODE);
    EXPECT_EQ(infoB.baseApplicationInfo_->assetAccessGroups, ASSET_ACCESS_GROUPS);
    EXPECT_EQ(infoB.baseApplicationInfo_->appPreloadPhase, APP_PRELOAD_PHASE);
    EXPECT_EQ(infoB.baseApplicationInfo_->cloudStructuredDataSyncEnabled, CLOUD_STRUCTURED_DATA_SYNC_ENABLED);
}

/**
 * @tc.number: UpdatePartialInnerBundleInfo_0300
 * @tc.name: UpdatePartialInnerBundleInfo
 * @tc.desc: 1.Test the UpdatePartialInnerBundleInfo function with ApplicationInfo and BundleInfo.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, UpdatePartialInnerBundleInfo_0300, Function | SmallTest | Level1)
{
    InnerBundleInfo jsonInfoA;
    jsonInfoA.baseApplicationInfo_ = nullptr;
    InnerBundleInfo infoA;
    infoA.UpdatePartialInnerBundleInfo(jsonInfoA);
    EXPECT_NE(infoA.baseApplicationInfo_->targetMinorApiVersion, TARGET_MINOR_API_VERSION);
    EXPECT_NE(infoA.baseApplicationInfo_->targetPatchApiVersion, TARGET_PATCH_API_VERSION);
    EXPECT_NE(infoA.baseApplicationInfo_->startMode, START_MODE);
    EXPECT_TRUE(infoA.baseApplicationInfo_->assetAccessGroups.empty());
    EXPECT_NE(infoA.baseApplicationInfo_->appPreloadPhase, APP_PRELOAD_PHASE);
    EXPECT_NE(infoA.baseApplicationInfo_->cloudStructuredDataSyncEnabled, CLOUD_STRUCTURED_DATA_SYNC_ENABLED);

    InnerBundleInfo jsonInfoB;
    InnerBundleInfo infoB;
    infoB.baseApplicationInfo_ = nullptr;
    infoB.baseBundleInfo_ = nullptr;
    infoB.UpdatePartialInnerBundleInfo(jsonInfoB);
    EXPECT_EQ(infoB.baseApplicationInfo_, nullptr);
    EXPECT_EQ(infoB.baseBundleInfo_, nullptr);
}

/**
 * @tc.number: UpdatePartialInnerBundleInfo_0400
 * @tc.name: UpdatePartialInnerBundleInfo
 * @tc.desc: 1.Test the UpdatePartialInnerBundleInfo function with innerModuleInfo.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, UpdatePartialInnerBundleInfo_0400, Function | SmallTest | Level1)
{
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    innerModuleInfos.try_emplace(MODULE_A, InnerModuleInfo());
    innerModuleInfos.try_emplace(MODULE_B, InnerModuleInfo());
    InnerBundleInfo info;
    info.AddInnerModuleInfo(innerModuleInfos);

    innerModuleInfos.clear();
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.requiredDeviceFeatures = REQUIRED_DEVICE_FEATURES;
    innerModuleInfo.systemTheme = SYSTEM_THEME;
    innerModuleInfo.crossAppSharedConfig = CROSS_APP_SHARED_CONFIG;
    innerModuleInfo.formExtensionModule = FORM_EXTENSION_MODULE;
    innerModuleInfo.formWidgetModule = FORM_WIDGET_MODULE;
    innerModuleInfo.moduleArkTSMode = MODULE_ARK_TS_MODE;
    innerModuleInfo.arkTSMode = ARK_TS_MODE;
    innerModuleInfo.resizeable = RESIZEABLE;
    innerModuleInfo.metadata = METADATA;
    innerModuleInfos.try_emplace(MODULE_A, innerModuleInfo);
    InnerBundleInfo jsonInfo;
    jsonInfo.AddInnerModuleInfo(innerModuleInfos);

    info.UpdatePartialInnerBundleInfo(jsonInfo);
    std::map<std::string, InnerModuleInfo> updatedInnerModuleInfos = info.GetInnerModuleInfos();
    auto item = updatedInnerModuleInfos.find(MODULE_A);
    EXPECT_TRUE(item != updatedInnerModuleInfos.end());
    EXPECT_FALSE(item->second.requiredDeviceFeatures.empty());
    EXPECT_EQ(item->second.systemTheme, SYSTEM_THEME);
    EXPECT_EQ(item->second.crossAppSharedConfig, CROSS_APP_SHARED_CONFIG);
    EXPECT_EQ(item->second.formExtensionModule, FORM_EXTENSION_MODULE);
    EXPECT_EQ(item->second.formWidgetModule, FORM_WIDGET_MODULE);
    EXPECT_EQ(item->second.moduleArkTSMode, MODULE_ARK_TS_MODE);
    EXPECT_EQ(item->second.arkTSMode, ARK_TS_MODE);
    EXPECT_EQ(item->second.resizeable, RESIZEABLE);
    EXPECT_FALSE(item->second.metadata.empty());
}

/**
 * @tc.number: UpdatePartialInnerBundleInfo_0500
 * @tc.name: UpdatePartialInnerBundleInfo
 * @tc.desc: 1.Test the UpdatePartialInnerBundleInfo function with innerSharedModuleInfo.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, UpdatePartialInnerBundleInfo_0500, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    info.InsertInnerSharedModuleInfo(MODULE_A, InnerModuleInfo());
    info.InsertInnerSharedModuleInfo(MODULE_B, InnerModuleInfo());

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.requiredDeviceFeatures = REQUIRED_DEVICE_FEATURES;
    innerModuleInfo.systemTheme = SYSTEM_THEME;
    innerModuleInfo.crossAppSharedConfig = CROSS_APP_SHARED_CONFIG;
    innerModuleInfo.formExtensionModule = FORM_EXTENSION_MODULE;
    innerModuleInfo.formWidgetModule = FORM_WIDGET_MODULE;
    innerModuleInfo.moduleArkTSMode = MODULE_ARK_TS_MODE;
    innerModuleInfo.arkTSMode = ARK_TS_MODE;
    innerModuleInfo.resizeable = RESIZEABLE;
    innerModuleInfo.metadata = METADATA;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    innerModuleInfos.try_emplace(MODULE_A, innerModuleInfo);
    InnerBundleInfo jsonInfo;
    jsonInfo.AddInnerModuleInfo(innerModuleInfos);

    info.UpdatePartialInnerBundleInfo(jsonInfo);
    std::map<std::string, std::vector<InnerModuleInfo>> innerSharedModuleInfos =
        info.GetInnerSharedModuleInfos();
    auto item = innerSharedModuleInfos.find(MODULE_A);
    EXPECT_TRUE(item != innerSharedModuleInfos.end());
    EXPECT_FALSE(item->second.empty());
    EXPECT_FALSE(item->second[0].requiredDeviceFeatures.empty());
    EXPECT_EQ(item->second[0].systemTheme, SYSTEM_THEME);
    EXPECT_EQ(item->second[0].crossAppSharedConfig, CROSS_APP_SHARED_CONFIG);
    EXPECT_EQ(item->second[0].formExtensionModule, FORM_EXTENSION_MODULE);
    EXPECT_EQ(item->second[0].formWidgetModule, FORM_WIDGET_MODULE);
    EXPECT_EQ(item->second[0].moduleArkTSMode, MODULE_ARK_TS_MODE);
    EXPECT_EQ(item->second[0].arkTSMode, ARK_TS_MODE);
    EXPECT_EQ(item->second[0].resizeable, RESIZEABLE);
    EXPECT_FALSE(item->second[0].metadata.empty());
}

/**
 * @tc.number: UpdatePartialInnerBundleInfo_0600
 * @tc.name: UpdatePartialInnerBundleInfo
 * @tc.desc: 1.Test the UpdatePartialInnerBundleInfo function with AbilityInfo.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, UpdatePartialInnerBundleInfo_0600, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::map<std::string, InnerAbilityInfo> innerAbilityInfos;
    InnerAbilityInfo tmpInnerAbilityInfo;
    tmpInnerAbilityInfo.moduleName = MODULE_A;
    tmpInnerAbilityInfo.name = ABILITY_A;
    innerAbilityInfos.try_emplace(ABILITY_A, tmpInnerAbilityInfo);
    innerAbilityInfos.try_emplace(ABILITY_B, InnerAbilityInfo());
    info.AddModuleAbilityInfo(innerAbilityInfos);

    InnerBundleInfo jsonInfo;
    innerAbilityInfos.clear();
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.moduleName = MODULE_A;
    innerAbilityInfo.name = ABILITY_A;
    innerAbilityInfo.continueBundleNames = CONTINUE_BUNDLE_NAMES;
    innerAbilityInfo.startWindow = START_WINDOW;
    innerAbilityInfo.startWindowId = START_WINDOW_ID;
    innerAbilityInfo.arkTSMode = ARK_TS_MODE;
    innerAbilityInfo.metadata = METADATA;
    innerAbilityInfos.try_emplace(ABILITY_A, innerAbilityInfo);
    jsonInfo.AddModuleAbilityInfo(innerAbilityInfos);

    info.UpdatePartialInnerBundleInfo(jsonInfo);
    std::map<std::string, InnerAbilityInfo> updatedInnerAbilityInfos = info.GetInnerAbilityInfos();
    auto item = updatedInnerAbilityInfos.find(ABILITY_A);
    EXPECT_TRUE(item != updatedInnerAbilityInfos.end());
    EXPECT_EQ(item->second.continueBundleNames, CONTINUE_BUNDLE_NAMES);
    EXPECT_EQ(item->second.startWindow, START_WINDOW);
    EXPECT_EQ(item->second.startWindowId, START_WINDOW_ID);
    EXPECT_EQ(item->second.arkTSMode, ARK_TS_MODE);
    EXPECT_FALSE(item->second.metadata.empty());
}

/**
 * @tc.number: UpdatePartialInnerBundleInfo_0700
 * @tc.name: UpdatePartialInnerBundleInfo
 * @tc.desc: 1.Test the UpdatePartialInnerBundleInfo function with ExtensionInfo.
 */
HWTEST_F(BmsModuleJsonUpdaterTest, UpdatePartialInnerBundleInfo_0700, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    std::map<std::string, InnerExtensionInfo> innerExtensionInfos;
    InnerExtensionInfo tmpInnerExtensionInfo;
    tmpInnerExtensionInfo.moduleName = MODULE_A;
    tmpInnerExtensionInfo.name = ABILITY_A;
    innerExtensionInfos.try_emplace(EXTENSION_A, tmpInnerExtensionInfo);
    innerExtensionInfos.try_emplace(EXTENSION_B, InnerExtensionInfo());
    info.AddModuleExtensionInfos(innerExtensionInfos);

    InnerBundleInfo jsonInfo;
    innerExtensionInfos.clear();
    InnerExtensionInfo innerExtensionInfo;
    innerExtensionInfo.moduleName = MODULE_A;
    innerExtensionInfo.name = ABILITY_A;
    innerExtensionInfo.type = TYPE_LIVE_FORM;
    innerExtensionInfo.appIdentifierAllowList = APP_IDENTIFIER_ALLOW_LIST;
    innerExtensionInfo.isolationProcess = ISOLATION_PROCESS;
    innerExtensionInfo.arkTSMode = ARK_TS_MODE;
    innerExtensionInfo.metadata = METADATA;
    innerExtensionInfos.try_emplace(EXTENSION_A, innerExtensionInfo);
    jsonInfo.AddModuleExtensionInfos(innerExtensionInfos);

    info.UpdatePartialInnerBundleInfo(jsonInfo);
    std::map<std::string, InnerExtensionInfo> updatedInnerExtensionInfos = info.GetInnerExtensionInfos();
    auto item = updatedInnerExtensionInfos.find(EXTENSION_A);
    EXPECT_TRUE(item != updatedInnerExtensionInfos.end());
    EXPECT_EQ(item->second.type, TYPE_LIVE_FORM);
    EXPECT_EQ(item->second.appIdentifierAllowList, APP_IDENTIFIER_ALLOW_LIST);
    EXPECT_EQ(item->second.isolationProcess, ISOLATION_PROCESS);
    EXPECT_EQ(item->second.arkTSMode, ARK_TS_MODE);
    EXPECT_FALSE(item->second.metadata.empty());
}
}