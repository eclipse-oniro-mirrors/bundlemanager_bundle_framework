/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <fstream>
#include <gtest/gtest.h>

#include "ability_info.h"
#include "access_token.h"
#include "application_info.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_info.h"
#include "inner_bundle_clone_info.h"
#include "inner_bundle_user_info.h"
#include "inner_bundle_info.h"
#include "json_constants.h"
#include "json_serializer.h"
#include "nlohmann/json.hpp"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::JsonConstants;
namespace OHOS {
class BmsBundleCloneAppBundleLogicTest : public testing::Test {
public:
    BmsBundleCloneAppBundleLogicTest();
    ~BmsBundleCloneAppBundleLogicTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsBundleCloneAppBundleLogicTest::BmsBundleCloneAppBundleLogicTest()
{}

BmsBundleCloneAppBundleLogicTest::~BmsBundleCloneAppBundleLogicTest()
{}

void BmsBundleCloneAppBundleLogicTest::SetUpTestCase()
{}

void BmsBundleCloneAppBundleLogicTest::TearDownTestCase()
{}

void BmsBundleCloneAppBundleLogicTest::SetUp()
{}

void BmsBundleCloneAppBundleLogicTest::TearDown()
{}


const nlohmann::json INNER_BUNDLE_INFO_JSON_3_2 = R"(
{
    "allowedAcls":[],
    "appFeature":"hos_system_app",
    "appIndex":0,
    "appType":0,
    "baseAbilityInfos":{
        "com.example.myapplication.entry.MainAbility":{
            "applicationInfo":{
            },
            "applicationName":"com.example.myapplication",
            "backgroundModes":0,
            "bundleName":"com.example.myapplication",
            "codePath":"",
            "compileMode":0,
            "configChanges":[
            ],
            "continuable":false,
            "defaultFormHeight":0,
            "defaultFormWidth":0,
            "description":"$string:MainAbility_desc",
            "descriptionId":16777218,
            "deviceCapabilities":[
            ],
            "deviceTypes":[
                "default",
                "tablet"
            ],
            "enabled":true,
            "excludeFromMissions":false,
            "extensionAbilityType":255,
            "formEnabled":false,
            "formEntity":0,
            "hapPath":"/data/app/el1/bundle/public/com.example.myapplication/entry.hap",
            "iconId":16777222,
            "iconPath":"$media:icon",
            "isLauncherAbility":false,
            "isModuleJson":true,
            "isNativeAbility":false,
            "isStageBasedModel":true,
            "kind":"",
            "label":"$string:MainAbility_label",
            "labelId":16777219,
            "launchMode":0,
            "maxWindowHeight":0,
            "maxWindowRatio":0,
            "maxWindowWidth":0,
            "metaData":{
                "customizeData":[
                ]
            },
            "metadata":[
            ],
            "minFormHeight":0,
            "minFormWidth":0,
            "minWindowHeight":0,
            "minWindowRatio":0,
            "minWindowWidth":0,
            "moduleName":"entry",
            "name":"MainAbility",
            "orientation":0,
            "package":"entry",
            "permissions":[

            ],
            "priority":0,
            "process":"",
            "readPermission":"",
            "removeMissionAfterTerminate":false,
            "resourcePath":"/data/app/el1/bundle/public/com.example.myapplication/entry/resources.index",
            "srcEntrance":"./ets/MainAbility/MainAbility.ts",
            "srcLanguage":"js",
            "srcPath":"",
            "startWindowBackground":"$color:white",
            "startWindowBackgroundId":16777221,
            "startWindowIcon":"$media:icon",
            "startWindowIconId":16777222,
            "supportPipMode":false,
            "supportWindowMode":[
                0,
                1,
                2
            ],
            "targetAbility":"",
            "theme":"",
            "type":1,
            "uid":-1,
            "uri":"",
            "visible":true,
            "writePermission":"",
            "supportExtNames": [],
            "supportMimeTypes": []
        }
    },
    "baseApplicationInfo":{
        "accessTokenId":0,
        "accessible":false,
        "allowCommonEvent":[
        ],
        "apiCompatibleVersion":9,
        "apiReleaseType":"Beta3",
        "apiTargetVersion":9,
        "appDetailAbilityLibraryPath":"",
        "appDistributionType":"os_integration",
        "appPrivilegeLevel":"system_core",
        "appProvisionType":"release",
        "arkNativeFileAbi":"",
        "arkNativeFilePath":"",
        "associatedWakeUp":false,
        "bundleName":"com.example.myapplication",
        "cacheDir":"",
        "codePath":"/data/app/el1/bundle/public/com.example.myapplication",
        "cpuAbi":"arm64-v8a"
    },
    "baseBundleInfo":{
        "abilityInfos":[],
        "appId":"com.example.myapplication",
        "appIndex":0,
        "applicationInfo":{
            "accessTokenId":0,
            "accessible":false,
            "allowCommonEvent":[
            ],
            "apiCompatibleVersion":0,
            "apiReleaseType":"",
            "apiTargetVersion":0,
            "appDetailAbilityLibraryPath":"",
            "appDistributionType":"none",
            "appPrivilegeLevel":"normal",
            "appProvisionType":"release"
        },
        "compatibleVersion":9,
        "cpuAbi":"",
        "defPermissions":[],
        "description":"",
        "entryInstallationFree":false,
        "entryModuleName":"entry",
        "extensionAbilityInfo":[],
        "gid":-1
    },
    "baseDataDir":"",
    "baseExtensionInfos":{},
    "shortcutInfos":{
    },
    "skillInfos":{
    },
    "userId_":0,
    "uninstallState":true
})"_json;

/**
 * @tc.number: AddCloneBundle_0001
 * @tc.name: innerBundleInfo add clone bundle
 * @tc.desc: 1.system running normally
 */
HWTEST_F(BmsBundleCloneAppBundleLogicTest, AddCloneBundle_0001, Function | SmallTest | Level1)
{
    int32_t userId = 1001;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.FromJson(INNER_BUNDLE_INFO_JSON_3_2);

    InnerBundleUserInfo tmpUserInfo;
    auto res = innerBundleInfo.GetInnerBundleUserInfo(userId, tmpUserInfo);
    EXPECT_EQ(res, false);

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = userId;

    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    res = innerBundleInfo.GetInnerBundleUserInfo(userId, tmpUserInfo);
    EXPECT_EQ(res, true);

    InnerBundleCloneInfo cloneInfo = {
        .userId = userId,
        .appIndex = 1,
        .uid = 0,
        .gids = {0},
        .accessTokenId = 1,
        .accessTokenIdEx = 2,
    };
    ErrCode r1 = innerBundleInfo.AddCloneBundle(cloneInfo);
    EXPECT_EQ(r1, ERR_OK);

    ErrCode r2 = innerBundleInfo.AddCloneBundle(cloneInfo);
    EXPECT_EQ(r2, ERR_APPEXECFWK_CLONE_INSTALL_APP_INDEX_EXISTED);

    cloneInfo.appIndex = 0;
    ErrCode r3 = innerBundleInfo.AddCloneBundle(cloneInfo);
    EXPECT_EQ(r3, ERR_APPEXECFWK_CLONE_INSTALL_INVALID_APP_INDEX);
}

/**
 * @tc.number: RemoveCloneBundle_0001
 * @tc.name: innerBundleInfo remove clone bundle
 * @tc.desc: 1.system running normally
 */
HWTEST_F(BmsBundleCloneAppBundleLogicTest, RemoveCloneBundle_0001, Function | SmallTest | Level1)
{
    int32_t userId = 1001;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.FromJson(INNER_BUNDLE_INFO_JSON_3_2);

    InnerBundleUserInfo tmpUserInfo;
    auto res = innerBundleInfo.GetInnerBundleUserInfo(userId, tmpUserInfo);
    EXPECT_EQ(res, false);

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = userId;

    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    res = innerBundleInfo.GetInnerBundleUserInfo(userId, tmpUserInfo);
    EXPECT_EQ(res, true);

    int32_t appIndex = 1;
    InnerBundleCloneInfo cloneInfo = {
        .userId = userId,
        .appIndex = appIndex,
        .uid = 0,
        .gids = {0},
        .accessTokenId = 1,
        .accessTokenIdEx = 2,
    };
    ErrCode r1 = innerBundleInfo.AddCloneBundle(cloneInfo);
    EXPECT_EQ(r1, ERR_OK);

    ErrCode r2 = innerBundleInfo.RemoveCloneBundle(userId, appIndex);
    EXPECT_EQ(r2, ERR_OK);

    ErrCode r3 = innerBundleInfo.AddCloneBundle(cloneInfo);
    EXPECT_EQ(r3, ERR_OK);
}

/**
 * @tc.number: QueryCloneBundle_0001
 * @tc.name: innerBundleInfo remove clone bundle
 * @tc.desc: 1.system running normally
 */
HWTEST_F(BmsBundleCloneAppBundleLogicTest, QueryCloneBundle_0001, Function | SmallTest | Level1)
{
    int32_t userId = 1001;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.FromJson(INNER_BUNDLE_INFO_JSON_3_2);

    InnerBundleUserInfo tmpUserInfo;
    auto res = innerBundleInfo.GetInnerBundleUserInfo(userId, tmpUserInfo);
    EXPECT_EQ(res, false);

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = userId;

    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    res = innerBundleInfo.GetInnerBundleUserInfo(userId, tmpUserInfo);
    EXPECT_EQ(res, true);

    int32_t appIndex = 1;
    int32_t appIndex2 = 2;
    InnerBundleCloneInfo cloneInfo = {
        .userId = userId,
        .appIndex = appIndex,
        .uid = 0,
        .gids = {0},
        .accessTokenId = 1,
        .accessTokenIdEx = 2,
    };
    ErrCode r1 = innerBundleInfo.AddCloneBundle(cloneInfo);
    EXPECT_EQ(r1, ERR_OK);

    // exists
    BundleInfo bundleInfo;
    ErrCode r2 = innerBundleInfo.GetBundleInfoV9(0, bundleInfo, userId, appIndex);
    EXPECT_EQ(r2, ERR_OK);

    // not exists
    ErrCode r3 = innerBundleInfo.GetBundleInfoV9(0, bundleInfo, userId, appIndex2);
    EXPECT_EQ(r3, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}
} // OHOS
