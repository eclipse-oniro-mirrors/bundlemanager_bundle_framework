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
        "abilitySrcEntryDelegator": "abilitySrcEntryDelegator",
        "abilityStageSrcEntryDelegator": "abilityStageSrcEntryDelegator",
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

class BmsBundleSrcEntryDelegatorTest : public testing::Test {
public:
    BmsBundleSrcEntryDelegatorTest();
    ~BmsBundleSrcEntryDelegatorTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleSrcEntryDelegatorTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleSrcEntryDelegatorTest::BmsBundleSrcEntryDelegatorTest()
{}

BmsBundleSrcEntryDelegatorTest::~BmsBundleSrcEntryDelegatorTest()
{}

void BmsBundleSrcEntryDelegatorTest::SetUpTestCase()
{}

void BmsBundleSrcEntryDelegatorTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleSrcEntryDelegatorTest::SetUp()
{}

void BmsBundleSrcEntryDelegatorTest::TearDown()
{}

/**
 * @tc.number: HapModuleInfoMarshallingTest_0100
 * @tc.name: test HapModuleInfoMarshallingTest_0100
 * @tc.desc: HapModuleInfoMarshallingTest_0100
 */
HWTEST_F(BmsBundleSrcEntryDelegatorTest, HapModuleInfoMarshallingTest_0100, Function | SmallTest | Level1)
{
    HapModuleInfo info;
    info.abilitySrcEntryDelegator = "abilitySrcEntryDelegator";
    info.abilityStageSrcEntryDelegator = "abilityStageSrcEntryDelegator";
    Parcel parcel{};
    auto ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);
    
    HapModuleInfo info2;
    ret = info2.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(info2.abilitySrcEntryDelegator, "abilitySrcEntryDelegator");
    EXPECT_EQ(info2.abilityStageSrcEntryDelegator, "abilityStageSrcEntryDelegator");
}

/**
 * @tc.number: HapModuleInfoFromJsonTest_0100
 * @tc.name: test HapModuleInfoFromJsonTest_0100
 * @tc.desc: HapModuleInfoFromJsonTest_0100
 */
HWTEST_F(BmsBundleSrcEntryDelegatorTest, HapModuleInfoFromJsonTest_0100, Function | SmallTest | Level1)
{
    nlohmann::json json = R"(
        {
            "abilitySrcEntryDelegator": "abilitySrcEntryDelegator",
            "abilityStageSrcEntryDelegator": "abilityStageSrcEntryDelegator"
        }
    )"_json;
    HapModuleInfo info;
    from_json(json, info);
    EXPECT_EQ(info.abilitySrcEntryDelegator, "abilitySrcEntryDelegator");
    EXPECT_EQ(info.abilityStageSrcEntryDelegator, "abilityStageSrcEntryDelegator");
}

/**
 * @tc.number: ApplicationInfoToJsonTest_0100
 * @tc.name: test ApplicationInfoToJsonTest_0100
 * @tc.desc: ApplicationInfoToJsonTest_0100
 */
HWTEST_F(BmsBundleSrcEntryDelegatorTest, HapModuleInfoToJsonTest_0100, Function | SmallTest | Level1)
{
    HapModuleInfo info;
    info.abilitySrcEntryDelegator = "abilitySrcEntryDelegator";
    info.abilityStageSrcEntryDelegator = "abilityStageSrcEntryDelegator";
    nlohmann::json json;
    to_json(json, info);

    HapModuleInfo info2;
    from_json(json, info2);
    EXPECT_EQ(info.abilitySrcEntryDelegator, info2.abilitySrcEntryDelegator);
    EXPECT_EQ(info.abilityStageSrcEntryDelegator, info2.abilityStageSrcEntryDelegator);
}

/**
 * @tc.number: ModuleProfileToInnerModuleInfoTest_0100
 * @tc.name: test ModuleProfileToInnerModuleInfoTest_0100
 * @tc.desc: ModuleProfileToInnerModuleInfoTest_0100
 */
HWTEST_F(BmsBundleSrcEntryDelegatorTest, ModuleProfileToInnerModuleInfoTest_0100, Function | SmallTest | Level1)
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
    EXPECT_EQ(innerModuleInfo->abilitySrcEntryDelegator, "abilitySrcEntryDelegator");
    EXPECT_EQ(innerModuleInfo->abilityStageSrcEntryDelegator, "abilityStageSrcEntryDelegator");
}

/**
 * @tc.number: FindHapModuleInfoTest_0100
 * @tc.name: test FindHapModuleInfoTest_0100
 * @tc.desc: FindHapModuleInfoTest_0100
 */
HWTEST_F(BmsBundleSrcEntryDelegatorTest, FindHapModuleInfoTest_0100, Function | SmallTest | Level1)
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
    EXPECT_EQ(hapModule->abilitySrcEntryDelegator, "abilitySrcEntryDelegator");
    EXPECT_EQ(hapModule->abilityStageSrcEntryDelegator, "abilityStageSrcEntryDelegator");
}
} // OHOS