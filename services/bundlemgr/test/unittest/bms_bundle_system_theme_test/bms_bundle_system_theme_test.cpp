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
#include "application_info.h"
#include "inner_bundle_info.h"
#include "json_serializer.h"
#include "module_profile.h"
#define private public

#include <atomic>
#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <sstream>
#include <string>
#include <thread>

#include "bundle_mgr_service.h"
#include "serial_queue.h"
#include "single_delayed_task_mgr.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const nlohmann::json MODULE_JSON = R"(
{
    "app": {
        "bundleName": "com.example.backuptest",
        "debug": true,
        "icon": "$media:app_icon",
        "iconId": 16777220,
        "label": "$string:app_name",
        "labelId": 16777216,
        "minAPIVersion": 9,
        "targetAPIVersion": 9,
        "vendor": "example",
        "versionCode": 1000000,
        "versionName": "1.0.0"
    },
    "module": {
        "deliveryWithInstall": true,
        "description": "$string:entry_desc",
        "descriptionId": 16777219,
        "systemTheme": "$profile:theme_config",
        "deviceTypes": [
            "default"
        ],
        "abilities": [
            {
                "description": "$string:MainAbility_desc",
                "descriptionId": 16777217,
                "icon": "$media:icon",
                "iconId": 16777221,
                "label": "$string:MainAbility_label",
                "labelId": 16777218,
                "name": "MainAbility",
                "launchType": "unknowlaunchType",
                "orientation": "unknoworientation",
                "srcEntrance": "./ets/MainAbility/MainAbility.ts",
                "visible": true
            }
        ],
        "name": "entry",
        "installationFree": false,
        "mainElement": "MainAbility",
        "pages": "$profile:main_pages",
        "srcEntrance": "./ets/Application/AbilityStage.ts",
        "type": "entry",
        "virtualMachine": "ark0.0.0.3"
    }
})"_json;
}  // namespace

class BmsBundleSystemThemeTest : public testing::Test {
public:
    BmsBundleSystemThemeTest();
    ~BmsBundleSystemThemeTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleSystemThemeTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

    BmsBundleSystemThemeTest::BmsBundleSystemThemeTest()
{}

BmsBundleSystemThemeTest::~BmsBundleSystemThemeTest()
{}

void BmsBundleSystemThemeTest::SetUpTestCase()
{}

void BmsBundleSystemThemeTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleSystemThemeTest::SetUp()
{}

void BmsBundleSystemThemeTest::TearDown()
{}

/**
 * @tc.number: HapModuleInfoMarshallingTest_0101
 * @tc.name: test HapModuleInfoMarshallingTest_0101
 * @tc.desc: HapModuleInfoMarshallingTest_0101
 */
HWTEST_F(BmsBundleSystemThemeTest, HapModuleInfoMarshallingTest_0101, Function | SmallTest | Level1)
{
    HapModuleInfo info;
    info.systemTheme = "$profile:theme_config";
    Parcel parcel{};
    auto ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);
    
    HapModuleInfo info2;
    ret = info2.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(info2.systemTheme, "$profile:theme_config");
}

/**
 * @tc.number: HapModuleInfoFromJsonTest_0101
 * @tc.name: test HapModuleInfoFromJsonTest_0101
 * @tc.desc: HapModuleInfoFromJsonTest_0101
 */
HWTEST_F(BmsBundleSystemThemeTest, HapModuleInfoFromJsonTest_0101, Function | SmallTest | Level1)
{
    nlohmann::json json = R"(
        {
            "systemTheme": "$profile:theme_config"
        }
    )"_json;
    HapModuleInfo info;
    from_json(json, info);
    EXPECT_EQ(info.systemTheme, "$profile:theme_config");
}

/**
 * @tc.number: ApplicationInfoToJsonTest_0101
 * @tc.name: test ApplicationInfoToJsonTest_0101
 * @tc.desc: ApplicationInfoToJsonTest_0101
 */
HWTEST_F(BmsBundleSystemThemeTest, HapModuleInfoToJsonTest_0101, Function | SmallTest | Level1)
{
    HapModuleInfo info;
    info.systemTheme = "$profile:theme_config";
    nlohmann::json json;
    to_json(json, info);

    HapModuleInfo info2;
    from_json(json, info2);
    EXPECT_EQ(info.systemTheme, info2.systemTheme);
}

/**
 * @tc.number: ModuleProfileToInnerModuleInfoTest_0101
 * @tc.name: test ModuleProfileToInnerModuleInfoTest_0101
 * @tc.desc: ModuleProfileToInnerModuleInfoTest_0101
 */
HWTEST_F(BmsBundleSystemThemeTest, ModuleProfileToInnerModuleInfoTest_0101, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK);

    auto innerModuleInfo = innerBundleInfo.GetInnerModuleInfoByModuleName("entry");
    EXPECT_NE(innerModuleInfo, std::nullopt);
    EXPECT_EQ(innerModuleInfo->systemTheme, "$profile:theme_config");
}

/**
 * @tc.number: FindHapModuleInfoTest_0101
 * @tc.name: test FindHapModuleInfoTest_0101
 * @tc.desc: FindHapModuleInfoTest_0101
 */
HWTEST_F(BmsBundleSystemThemeTest, FindHapModuleInfoTest_0101, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK);

    auto hapModule = innerBundleInfo.FindHapModuleInfo("entry");
    EXPECT_NE(hapModule, std::nullopt);
    EXPECT_EQ(hapModule->systemTheme, "$profile:theme_config");
}
} // OHOS