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
class BmsBundleCloneAppDataStructTest : public testing::Test {
public:
    BmsBundleCloneAppDataStructTest();
    ~BmsBundleCloneAppDataStructTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsBundleCloneAppDataStructTest::BmsBundleCloneAppDataStructTest()
{}

BmsBundleCloneAppDataStructTest::~BmsBundleCloneAppDataStructTest()
{}

void BmsBundleCloneAppDataStructTest::SetUpTestCase()
{}

void BmsBundleCloneAppDataStructTest::TearDownTestCase()
{}

void BmsBundleCloneAppDataStructTest::SetUp()
{}

void BmsBundleCloneAppDataStructTest::TearDown()
{}

const nlohmann::json APPLICATION_JSON = R"(
{
    "multiAppMode": {
        "multiAppModeType": 1,
        "maxCount": 5
    }
})"_json;

/**
 * @tc.number: OTA_ApplicationInfoJsonSerializer_0001
 * @tc.name: parse json to applicationInfo object
 * @tc.desc: 1.system running normally
 *           2.successfully deserialize ApplicationInfo
 */
HWTEST_F(BmsBundleCloneAppDataStructTest, OTA_ApplicationInfoJsonSerializer_0001, Function | SmallTest | Level1)
{
    ApplicationInfo applicationInfo;
    from_json(APPLICATION_JSON, applicationInfo);
    EXPECT_EQ(applicationInfo.multiAppMode.multiAppModeType, MultiAppModeType::MULTI_INSTANCE);
    EXPECT_EQ(applicationInfo.multiAppMode.maxCount, 5);
}

/**
 * @tc.number: OTA_ApplicationInfoJsonSerializer_0002
 * @tc.name: parse json to applicationInfo object
 * @tc.desc: 1.system running normally
 *           2.successfully deserialize ApplicationInfo
 */
HWTEST_F(BmsBundleCloneAppDataStructTest, OTA_ApplicationInfoJsonSerializer_0002, Function | SmallTest | Level1)
{
    ApplicationInfo applicationInfo;
    from_json(APPLICATION_JSON, applicationInfo);
    EXPECT_EQ(applicationInfo.multiAppMode.multiAppModeType, MultiAppModeType::MULTI_INSTANCE);
    EXPECT_EQ(applicationInfo.multiAppMode.maxCount, 5);

    nlohmann::json applicationInfoJson;
    to_json(applicationInfoJson, applicationInfo);

    ApplicationInfo applicationInfo2;
    from_json(APPLICATION_JSON, applicationInfo2);
    EXPECT_EQ(applicationInfo.multiAppMode.multiAppModeType, applicationInfo2.multiAppMode.multiAppModeType);
    EXPECT_EQ(applicationInfo.multiAppMode.maxCount, applicationInfo2.multiAppMode.maxCount);
}

/**
 * @tc.number: OTA_BundleCloneInfoJsonSerializer_0001
 * @tc.name: parse json to bundleCloneInfo object
 * @tc.desc: 1.system running normally
 *           2.successfully deserialize ApplicationInfo
 */
HWTEST_F(BmsBundleCloneAppDataStructTest, OTA_BundleCloneInfoJsonSerializer_0001, Function | SmallTest | Level1)
{
    InnerBundleCloneInfo bundleCloneInfo;
    bundleCloneInfo.accessTokenId = 10;
    bundleCloneInfo.accessTokenIdEx = 12;
    bundleCloneInfo.appIndex = 1;
    bundleCloneInfo.disabledAbilities = {"a", "b"};
    bundleCloneInfo.enabled = true;
    bundleCloneInfo.installTime = 10;
    bundleCloneInfo.uid = 20;

    nlohmann::json bundleCloneInfoJson;
    to_json(bundleCloneInfoJson, bundleCloneInfo);

    InnerBundleCloneInfo bundleCloneInfo2;
    from_json(bundleCloneInfoJson, bundleCloneInfo2);

    EXPECT_EQ(bundleCloneInfo.accessTokenId, bundleCloneInfo2.accessTokenId);
    EXPECT_EQ(bundleCloneInfo.accessTokenIdEx, bundleCloneInfo2.accessTokenIdEx);
    EXPECT_EQ(bundleCloneInfo.appIndex, bundleCloneInfo2.appIndex);
    EXPECT_TRUE(
        std::equal(bundleCloneInfo.disabledAbilities.begin(), bundleCloneInfo.disabledAbilities.end(),
        bundleCloneInfo2.disabledAbilities.begin())
    );
    EXPECT_EQ(bundleCloneInfo.enabled, bundleCloneInfo2.enabled);
    EXPECT_EQ(bundleCloneInfo.installTime, bundleCloneInfo2.installTime);
    EXPECT_EQ(bundleCloneInfo.uid, bundleCloneInfo2.uid);
}

/**
 * @tc.number: OTA_BundleUserInfoJsonSerializer_0001
 * @tc.name: parse json to bundleUserInfo object
 * @tc.desc: 1.system running normally
 *           2.successfully deserialize ApplicationInfo
 */
HWTEST_F(BmsBundleCloneAppDataStructTest, OTA_BundleUserInfoJsonSerializer_0001, Function | SmallTest | Level1)
{
    const int32_t appIndex = 1;
    const std::string strAppIndex = "1";
    InnerBundleUserInfo userInfo;
    InnerBundleCloneInfo bundleCloneInfo;
    bundleCloneInfo.accessTokenId = 10;
    bundleCloneInfo.accessTokenIdEx = 12;
    bundleCloneInfo.appIndex = appIndex;
    bundleCloneInfo.disabledAbilities = {"a", "b"};
    bundleCloneInfo.enabled = true;
    bundleCloneInfo.installTime = 10;
    bundleCloneInfo.uid = 20;

    userInfo.cloneInfos[strAppIndex] = bundleCloneInfo;

    nlohmann::json userInfoJson;
    to_json(userInfoJson, userInfo);

    std::string res = userInfoJson.dump();

    InnerBundleUserInfo userInfo2;
    from_json(userInfoJson, userInfo2);

    EXPECT_EQ(userInfo2.cloneInfos.size(), 1);
    EXPECT_EQ(userInfo2.cloneInfos.find(strAppIndex) != userInfo2.cloneInfos.end(), true);

    auto bundleCloneInfo2 = userInfo2.cloneInfos[strAppIndex];
    EXPECT_EQ(bundleCloneInfo.accessTokenId, bundleCloneInfo2.accessTokenId);
    EXPECT_EQ(bundleCloneInfo.accessTokenIdEx, bundleCloneInfo2.accessTokenIdEx);
    EXPECT_EQ(bundleCloneInfo.appIndex, bundleCloneInfo2.appIndex);
    EXPECT_TRUE(
        std::equal(bundleCloneInfo.disabledAbilities.begin(), bundleCloneInfo.disabledAbilities.end(),
        bundleCloneInfo2.disabledAbilities.begin())
    );
    EXPECT_EQ(bundleCloneInfo.enabled, bundleCloneInfo2.enabled);
    EXPECT_EQ(bundleCloneInfo.installTime, bundleCloneInfo2.installTime);
    EXPECT_EQ(bundleCloneInfo.uid, bundleCloneInfo2.uid);
}
} // OHOS
