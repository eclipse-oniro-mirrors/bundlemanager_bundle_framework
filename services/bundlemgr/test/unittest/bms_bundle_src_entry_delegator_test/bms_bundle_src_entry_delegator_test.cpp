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
        "targetMinorApiVersion": 1,
        "targetPatchApiVersion": 2,
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
        "hnpPackages": [
            {
                "package": "testPublic.hnp",
                "type": "public"
            },
            {
                "package": "testPrivate.hnp",
                "type": "private"
            }
        ],
        "name": "entry",
        "installationFree": false,
        "mainElement": "MainAbility",
        "pages": "$profile:main_pages",
        "srcEntrance": "./ets/Application/AbilityStage.ts",
        "crossAppSharedConfig": "$profile:shared_config",
        "type": "entry",
        "virtualMachine": "ark0.0.0.3"
    }
})"_json;

const nlohmann::json MODULE_JSON2 = R"(
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
        "requiredDeviceFeatures": {
            "phone": [
                "large_screen"
            ]
        },
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

const nlohmann::json MODULE_JSON_FEATURE = R"(
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
        "requiredDeviceFeatures": {
            "phone": [
                "large_screen"
            ]
        },
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
        "hnpPackages": [
            {
                "package": "testPublic.hnp",
                "type": "public"
            },
            {
                "package": "testPrivate.hnp",
                "type": "private"
            }
        ],
        "name": "featureModule",
        "installationFree": false,
        "mainElement": "MainAbility",
        "pages": "$profile:main_pages",
        "srcEntrance": "./ets/Application/AbilityStage.ts",
        "type": "feature",
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
    info.requiredDeviceFeatures = {{"phone", {"large_screen"}}};
    info.crossAppSharedConfig = "$profile:shared_config";
    Parcel parcel{};
    auto ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);
    
    HapModuleInfo info2;
    ret = info2.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(info2.abilitySrcEntryDelegator, "abilitySrcEntryDelegator");
    EXPECT_EQ(info2.abilityStageSrcEntryDelegator, "abilityStageSrcEntryDelegator");
    EXPECT_EQ(info2.crossAppSharedConfig, "$profile:shared_config");
    EXPECT_EQ(info2.requiredDeviceFeatures.size(), 1);
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
            "abilityStageSrcEntryDelegator": "abilityStageSrcEntryDelegator",
            "requiredDeviceFeatures": {
                "phone": [
                    "large_screen"
                ]
            }
        }
    )"_json;
    HapModuleInfo info;
    from_json(json, info);
    EXPECT_EQ(info.abilitySrcEntryDelegator, "abilitySrcEntryDelegator");
    EXPECT_EQ(info.abilityStageSrcEntryDelegator, "abilityStageSrcEntryDelegator");
    EXPECT_EQ(info.requiredDeviceFeatures.size(), 1);
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
    info.crossAppSharedConfig = "$profile:shared_config";
    info.requiredDeviceFeatures = {{"phone", {"large_screen"}}};
    nlohmann::json json;
    to_json(json, info);

    HapModuleInfo info2;
    from_json(json, info2);
    EXPECT_EQ(info.abilitySrcEntryDelegator, info2.abilitySrcEntryDelegator);
    EXPECT_EQ(info.abilityStageSrcEntryDelegator, info2.abilityStageSrcEntryDelegator);
    EXPECT_EQ(info.crossAppSharedConfig, info2.crossAppSharedConfig);
    EXPECT_EQ(info.requiredDeviceFeatures.size(), info2.requiredDeviceFeatures.size());
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
    EXPECT_EQ(innerModuleInfo->crossAppSharedConfig, "$profile:shared_config");
    EXPECT_EQ(innerModuleInfo->requiredDeviceFeatures.size(), 0);

    auto bundleInfo = innerBundleInfo.GetBaseBundleInfo();
    EXPECT_EQ(bundleInfo.targetMinorApiVersion, 1);
    EXPECT_EQ(bundleInfo.targetPatchApiVersion, 2);

    auto appInfo = innerBundleInfo.GetBaseApplicationInfo();
    EXPECT_EQ(appInfo.targetMinorApiVersion, 1);
    EXPECT_EQ(appInfo.targetPatchApiVersion, 2);
}

/**
 * @tc.number: ModuleProfileToInnerModuleInfoTest_0200
 * @tc.name: test ModuleProfileToInnerModuleInfoTest_0200
 * @tc.desc: ModuleProfileToInnerModuleInfoTest_0200
 */
HWTEST_F(BmsBundleSrcEntryDelegatorTest, ModuleProfileToInnerModuleInfoTest_0200, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON2;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK);

    auto innerModuleInfo = innerBundleInfo.GetInnerModuleInfoByModuleName("entry");
    EXPECT_NE(innerModuleInfo, std::nullopt);
    EXPECT_EQ(innerModuleInfo->abilitySrcEntryDelegator, "abilitySrcEntryDelegator");
    EXPECT_EQ(innerModuleInfo->abilityStageSrcEntryDelegator, "abilityStageSrcEntryDelegator");
    EXPECT_EQ(innerModuleInfo->requiredDeviceFeatures.size(), 1);
    EXPECT_TRUE(innerModuleInfo->crossAppSharedConfig.empty());

    auto bundleInfo = innerBundleInfo.GetBaseBundleInfo();
    EXPECT_EQ(bundleInfo.targetMinorApiVersion, 0);
    EXPECT_EQ(bundleInfo.targetPatchApiVersion, 0);

    auto appInfo = innerBundleInfo.GetBaseApplicationInfo();
    EXPECT_EQ(appInfo.targetMinorApiVersion, 0);
    EXPECT_EQ(appInfo.targetPatchApiVersion, 0);
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
    EXPECT_EQ(hapModule->requiredDeviceFeatures.size(), 0);
    EXPECT_EQ(hapModule->crossAppSharedConfig, "$profile:shared_config");
}

/**
 * @tc.number: FindHapModuleInfoTest_0200
 * @tc.name: test FindHapModuleInfoTest_0200
 * @tc.desc: FindHapModuleInfoTest_0200
 */
HWTEST_F(BmsBundleSrcEntryDelegatorTest, FindHapModuleInfoTest_0200, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON2;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK);

    auto hapModule = innerBundleInfo.FindHapModuleInfo("entry");
    EXPECT_NE(hapModule, std::nullopt);
    EXPECT_EQ(hapModule->abilitySrcEntryDelegator, "abilitySrcEntryDelegator");
    EXPECT_EQ(hapModule->abilityStageSrcEntryDelegator, "abilityStageSrcEntryDelegator");
    EXPECT_EQ(hapModule->requiredDeviceFeatures.size(), 1);
    EXPECT_TRUE(hapModule->crossAppSharedConfig.empty());
}

/**
 * @tc.number: ApplicationInfoMarshallingTest_0100
 * @tc.name: test ApplicationInfoMarshallingTest_0100
 * @tc.desc: ApplicationInfoMarshallingTest_0100
 */
HWTEST_F(BmsBundleSrcEntryDelegatorTest, ApplicationInfoMarshallingTest_0100, Function | SmallTest | Level1)
{
    ApplicationInfo info;
    info.targetMinorApiVersion = 1;
    info.targetPatchApiVersion = 2;
    Parcel parcel{};
    auto ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);

    ApplicationInfo info2;
    ret = info2.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(info2.targetMinorApiVersion, 1);
    EXPECT_EQ(info2.targetPatchApiVersion, 2);
}

/**
 * @tc.number: ApplicationInfoToJsonTest_0100
 * @tc.name: test ApplicationInfoToJsonTest_0100
 * @tc.desc: ApplicationInfoToJsonTest_0100
 */
HWTEST_F(BmsBundleSrcEntryDelegatorTest, ApplicationInfoToJsonTest_0100, Function | SmallTest | Level1)
{
    ApplicationInfo info;
    info.targetMinorApiVersion = 1;
    info.targetPatchApiVersion = 2;
    nlohmann::json json;
    to_json(json, info);

    ApplicationInfo info2;
    from_json(json, info2);
    EXPECT_EQ(info.targetMinorApiVersion, info2.targetMinorApiVersion);
    EXPECT_EQ(info.targetPatchApiVersion, info2.targetPatchApiVersion);
}

/**
 * @tc.number: BundleInfoMarshallingTest_0100
 * @tc.name: test BundleInfoMarshallingTest_0100
 * @tc.desc: BundleInfoMarshallingTest_0100
 */
HWTEST_F(BmsBundleSrcEntryDelegatorTest, BundleInfoMarshallingTest_0100, Function | SmallTest | Level1)
{
    BundleInfo info;
    info.targetMinorApiVersion = 1;
    info.targetPatchApiVersion = 2;
    Parcel parcel{};
    auto ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);

    BundleInfo info2;
    ret = info2.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(info2.targetMinorApiVersion, 1);
    EXPECT_EQ(info2.targetPatchApiVersion, 2);
}

/**
 * @tc.number: BundleInfoToJsonTest_0100
 * @tc.name: test BundleInfoToJsonTest_0100
 * @tc.desc: BundleInfoToJsonTest_0100
 */
HWTEST_F(BmsBundleSrcEntryDelegatorTest, BundleInfoToJsonTest_0100, Function | SmallTest | Level1)
{
    BundleInfo info;
    info.targetMinorApiVersion = 1;
    info.targetPatchApiVersion = 2;
    nlohmann::json json;
    to_json(json, info);

    BundleInfo info2;
    from_json(json, info2);
    EXPECT_EQ(info.targetMinorApiVersion, info2.targetMinorApiVersion);
    EXPECT_EQ(info.targetPatchApiVersion, info2.targetPatchApiVersion);
}

/**
 * @tc.number: IsBundleCrossAppSharedConfig_0100
 * @tc.name: test IsBundleCrossAppSharedConfig_0100
 * @tc.desc: IsBundleCrossAppSharedConfig_0100
 */
HWTEST_F(BmsBundleSrcEntryDelegatorTest, IsBundleCrossAppSharedConfig_0100, Function | SmallTest | Level1)
{
    InnerBundleInfo bundleInfo;
    EXPECT_FALSE(bundleInfo.IsBundleCrossAppSharedConfig());

    InnerModuleInfo module1;
    bundleInfo.InsertInnerModuleInfo("module1", module1);
    EXPECT_FALSE(bundleInfo.IsBundleCrossAppSharedConfig());

    InnerModuleInfo module2;
    module2.crossAppSharedConfig = "test2";
    bundleInfo.InsertInnerModuleInfo("module2", module2);
    EXPECT_TRUE(bundleInfo.IsBundleCrossAppSharedConfig());
}

/**
 * @tc.number: IsBundleCrossAppSharedConfig_0200
 * @tc.name: test IsBundleCrossAppSharedConfig_0200
 * @tc.desc: IsBundleCrossAppSharedConfig_0200
 */
HWTEST_F(BmsBundleSrcEntryDelegatorTest, IsBundleCrossAppSharedConfig_0200, Function | SmallTest | Level1)
{
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    EXPECT_FALSE(installer.IsBundleCrossAppSharedConfig(newInfos));

    InnerBundleInfo bundleInfo1;
    InnerModuleInfo module1;
    bundleInfo1.InsertInnerModuleInfo("module1", module1);
    newInfos["bundleInfo1"] = bundleInfo1;
    EXPECT_FALSE(installer.IsBundleCrossAppSharedConfig(newInfos));

    InnerBundleInfo bundleInfo2;
    InnerModuleInfo module2;
    bundleInfo2.InsertInnerModuleInfo("module2", module2);
    newInfos["bundleInfo2"] = bundleInfo2;
    EXPECT_FALSE(installer.IsBundleCrossAppSharedConfig(newInfos));

    InnerBundleInfo bundleInfo3;
    InnerModuleInfo module3;
    bundleInfo3.InsertInnerModuleInfo("module3", module3);
    InnerModuleInfo module4;
    module4.crossAppSharedConfig = "test";
    bundleInfo3.InsertInnerModuleInfo("module4", module4);
    newInfos["bundleInfo3"] = bundleInfo3;
    EXPECT_TRUE(installer.IsBundleCrossAppSharedConfig(newInfos));
}

/**
 * @tc.number: GetHnpPackageTest_0100
 * @tc.name: test GetHnpPackageTest_0100
 * @tc.desc: GetHnpPackageTest_0100
 */
HWTEST_F(BmsBundleSrcEntryDelegatorTest, GetHnpPackageTest_0100, Function | SmallTest | Level1)
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
    EXPECT_GT(innerModuleInfo->hnpPackages.size(), 0);
}

/**
 * @tc.number: GetHnpPackageTest_0200
 * @tc.name: test GetHnpPackageTest_0200
 * @tc.desc: GetHnpPackageTest_0200
 */
HWTEST_F(BmsBundleSrcEntryDelegatorTest, GetHnpPackageTest_0200, Function | SmallTest | Level1)
{
    ModuleProfile moduleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;

    nlohmann::json profileJson = MODULE_JSON_FEATURE;
    profileFileBuffer << profileJson.dump();

    BundleExtractor bundleExtractor("");
    ErrCode result = moduleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    EXPECT_EQ(result, ERR_OK);

    auto innerModuleInfo = innerBundleInfo.GetInnerModuleInfoByModuleName("featureModule");
    EXPECT_NE(innerModuleInfo, std::nullopt);
    EXPECT_EQ(innerModuleInfo->hnpPackages.size(), 0);
}
} // OHOS