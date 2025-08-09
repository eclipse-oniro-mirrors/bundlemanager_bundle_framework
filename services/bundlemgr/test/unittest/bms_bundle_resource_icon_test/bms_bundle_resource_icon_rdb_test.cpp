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

#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
#include "bundle_resource_icon_rdb.h"
#endif

#include "scope_guard.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const int32_t USER_ID = 100;
const int32_t TEST_USER_ID = 20000;
const int32_t TEST_USER_ID_TWO = 20001;
const int32_t APP_INDEX = 1;
const std::string BUNDLE_NAME = "com.example.bmsaccesstoken1";
const std::string MODULE_NAME = "entry";
const std::string ABILITY_NAME = "com.example.bmsaccesstoken1.MainAbility";
}  // namespace

class BmsBundleResourceIconRdbTest : public testing::Test {
public:
    BmsBundleResourceIconRdbTest();
    ~BmsBundleResourceIconRdbTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsBundleResourceIconRdbTest::BmsBundleResourceIconRdbTest()
{}

BmsBundleResourceIconRdbTest::~BmsBundleResourceIconRdbTest()
{}

void BmsBundleResourceIconRdbTest::SetUpTestCase()
{}

void BmsBundleResourceIconRdbTest::TearDownTestCase()
{}

void BmsBundleResourceIconRdbTest::SetUp()
{}

void BmsBundleResourceIconRdbTest::TearDown()
{}

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
/**
 * @tc.number: AddResourceInfo_0001
 * Function: BundleResourceIconRdb
 * @tc.name: test BundleResourceIconRdb
 * @tc.desc: 1. system running normally
 *           2. test AddResourceIconInfo
 */
HWTEST_F(BmsBundleResourceIconRdbTest, AddResourceInfo_0001, Function | SmallTest | Level0)
{
    BundleResourceIconRdb resourceIconRdb;
    ResourceInfo resourceInfo;
    bool ans = resourceIconRdb.AddResourceIconInfo(USER_ID, IconResourceType::THEME_ICON, resourceInfo);
    EXPECT_FALSE(ans);

    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.icon_ = "icon";
    resourceInfo.foreground_.push_back(1);
    resourceInfo.background_.push_back(1);
    ans = resourceIconRdb.AddResourceIconInfo(USER_ID, IconResourceType::THEME_ICON, resourceInfo);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.DeleteResourceIconInfo(resourceInfo.bundleName_, USER_ID);
    EXPECT_TRUE(ans);

    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.icon_ = "icon";
    resourceInfo.foreground_.push_back(1);
    resourceInfo.background_.push_back(1);
    ans = resourceIconRdb.AddResourceIconInfo(USER_ID, IconResourceType::DYNAMIC_ICON, resourceInfo);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.DeleteResourceIconInfo(resourceInfo.bundleName_, USER_ID);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: AddResourceInfos_0001
 * Function: BundleResourceIconRdb
 * @tc.name: test BundleResourceIconRdb
 * @tc.desc: 1. system running normally
 *           2. test AddResourceIconInfos
 */
HWTEST_F(BmsBundleResourceIconRdbTest, AddResourceInfos_0001, Function | SmallTest | Level0)
{
    BundleResourceIconRdb resourceIconRdb;
    std::vector<ResourceInfo> resourceInfos;
    bool ans = resourceIconRdb.AddResourceIconInfos(USER_ID, IconResourceType::THEME_ICON, resourceInfos);
    EXPECT_FALSE(ans);

    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfos.push_back(resourceInfo);

    ans = resourceIconRdb.AddResourceIconInfos(USER_ID, IconResourceType::THEME_ICON, resourceInfos);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.DeleteResourceIconInfo(resourceInfo.bundleName_, USER_ID);
    EXPECT_TRUE(ans);

    ResourceInfo resourceInfo_2;
    resourceInfos.push_back(resourceInfo_2);
    ans = resourceIconRdb.AddResourceIconInfos(USER_ID, IconResourceType::THEME_ICON, resourceInfos);
    EXPECT_FALSE(ans);
    ans = resourceIconRdb.DeleteResourceIconInfo(resourceInfo.bundleName_, USER_ID);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: DeleteResourceIconInfo_0001
 * Function: BundleResourceIconRdb
 * @tc.name: test BundleResourceIconRdb
 * @tc.desc: 1. system running normally
 *           2. test DeleteResourceIconInfo
 */
HWTEST_F(BmsBundleResourceIconRdbTest, DeleteResourceIconInfo_0001, Function | SmallTest | Level0)
{
    BundleResourceIconRdb resourceIconRdb;
    bool ans = resourceIconRdb.DeleteResourceIconInfo("", USER_ID);
    EXPECT_FALSE(ans);

    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.appIndex_ = APP_INDEX;
    resourceInfo.icon_ = "icon";
    ans = resourceIconRdb.AddResourceIconInfo(USER_ID, IconResourceType::DYNAMIC_ICON, resourceInfo);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.DeleteResourceIconInfo(resourceInfo.bundleName_, USER_ID, APP_INDEX);
    EXPECT_TRUE(ans);

    ans = resourceIconRdb.AddResourceIconInfo(USER_ID, IconResourceType::DYNAMIC_ICON, resourceInfo);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.DeleteResourceIconInfo(resourceInfo.bundleName_, USER_ID,
        APP_INDEX, IconResourceType::DYNAMIC_ICON);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: DeleteResourceIconInfos_0001
 * Function: BundleResourceIconRdb
 * @tc.name: test BundleResourceIconRdb
 * @tc.desc: 1. system running normally
 *           2. test DeleteResourceIconInfos
 */
HWTEST_F(BmsBundleResourceIconRdbTest, DeleteResourceIconInfos_0001, Function | SmallTest | Level0)
{
    BundleResourceIconRdb resourceIconRdb;
    bool ans = resourceIconRdb.DeleteResourceIconInfos("", USER_ID);
    EXPECT_FALSE(ans);

    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.icon_ = "icon";
    ans = resourceIconRdb.AddResourceIconInfo(USER_ID, IconResourceType::THEME_ICON, resourceInfo);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.DeleteResourceIconInfos(resourceInfo.bundleName_, USER_ID);
    EXPECT_TRUE(ans);

    ResourceInfo resourceInfo1;
    resourceInfo1.bundleName_ = "bundleName";
    resourceInfo1.appIndex_ = APP_INDEX;
    resourceInfo1.icon_ = "icon";
    std::vector<ResourceInfo> resourceInfos;
    resourceInfos.push_back(resourceInfo);
    resourceInfos.push_back(resourceInfo1);
    ans = resourceIconRdb.AddResourceIconInfos(USER_ID, IconResourceType::THEME_ICON, resourceInfos);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.DeleteResourceIconInfos(resourceInfo.bundleName_, USER_ID, IconResourceType::THEME_ICON);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: DeleteResourceIconInfos_0002
 * Function: BundleResourceIconRdb
 * @tc.name: test BundleResourceIconRdb
 * @tc.desc: 1. system running normally
 *           2. test DeleteResourceIconInfos
 */
HWTEST_F(BmsBundleResourceIconRdbTest, DeleteResourceIconInfos_0002, Function | SmallTest | Level0)
{
    BundleResourceIconRdb resourceIconRdb;
    bool ans = resourceIconRdb.DeleteResourceIconInfos("");
    EXPECT_FALSE(ans);

    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.icon_ = "icon";
    ans = resourceIconRdb.AddResourceIconInfo(USER_ID, IconResourceType::THEME_ICON, resourceInfo);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.AddResourceIconInfo(TEST_USER_ID, IconResourceType::THEME_ICON, resourceInfo);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.DeleteResourceIconInfos(resourceInfo.bundleName_, IconResourceType::THEME_ICON);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: GetAllResourceIconName_0001
 * Function: BundleResourceIconRdb
 * @tc.name: test BundleResourceIconRdb
 * @tc.desc: 1. system running normally
 *           2. test GetAllResourceIconName
 */
HWTEST_F(BmsBundleResourceIconRdbTest, GetAllResourceIconName_0001, Function | SmallTest | Level0)
{
    BundleResourceIconRdb resourceIconRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.icon_ = "icon";
    resourceInfo.foreground_.push_back(1);
    resourceInfo.background_.push_back(1);
    bool ans = resourceIconRdb.AddResourceIconInfo(USER_ID, IconResourceType::THEME_ICON, resourceInfo);
    EXPECT_TRUE(ans);

    std::set<std::string> bundleNames;
    ans = resourceIconRdb.GetAllResourceIconName(USER_ID, bundleNames, IconResourceType::THEME_ICON);
    EXPECT_TRUE(ans);
    auto iter = std::find(bundleNames.begin(), bundleNames.end(), "bundleName");
    EXPECT_TRUE(iter != bundleNames.end());

    ans = resourceIconRdb.DeleteResourceIconInfo(resourceInfo.bundleName_, USER_ID);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: ParseNameToResourceName_0001
 * Function: BundleResourceIconRdb
 * @tc.name: test BundleResourceIconRdb
 * @tc.desc: 1. system running normally
 *           2. test ParseNameToResourceName
 */
HWTEST_F(BmsBundleResourceIconRdbTest, ParseNameToResourceName_0001, Function | SmallTest | Level0)
{
    BundleResourceIconRdb resourceIconRdb;
    std::string key = "1_bundleName";
    std::string bundleName;
    resourceIconRdb.ParseNameToResourceName(key, bundleName);
    EXPECT_EQ(bundleName, "bundleName");

    key = "1_bundleName/moduleName/abilityName";
    resourceIconRdb.ParseNameToResourceName(key, bundleName);
    EXPECT_EQ(bundleName, "bundleName/moduleName/abilityName");

    key = "aaa_bundleName/moduleName/abilityName";
    resourceIconRdb.ParseNameToResourceName(key, bundleName);
    EXPECT_EQ(bundleName, "aaa_bundleName/moduleName/abilityName");
}

/**
 * @tc.number: BmsBundleResourceIconRdbTest_0001
 * Function: BundleResourceIconRdb
 * @tc.name: test BundleResourceIconRdb
 * @tc.desc: 1. system running normally
 *           2. test GetAllResourceIconInfo
 */
HWTEST_F(BmsBundleResourceIconRdbTest, GetAllResourceIconInfo_0001, Function | SmallTest | Level0)
{
    BundleResourceIconRdb resourceIconRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.icon_ = "icon";
    resourceInfo.foreground_.push_back(1);
    resourceInfo.background_.push_back(1);
    bool ans = resourceIconRdb.AddResourceIconInfo(TEST_USER_ID, IconResourceType::THEME_ICON, resourceInfo);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.AddResourceIconInfo(TEST_USER_ID, IconResourceType::DYNAMIC_ICON, resourceInfo);
    EXPECT_TRUE(ans);

    std::vector<LauncherAbilityResourceInfo> infos;
    ans = resourceIconRdb.GetAllResourceIconInfo(TEST_USER_ID,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), infos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(infos[0].icon.empty());
    EXPECT_TRUE(infos[0].foreground.empty());
    EXPECT_TRUE(infos[0].background.empty());

    ans = resourceIconRdb.GetAllResourceIconInfo(TEST_USER_ID,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON), infos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(infos[0].icon.empty());
    EXPECT_TRUE(infos[0].foreground.empty());
    EXPECT_TRUE(infos[0].background.empty());

    ans = resourceIconRdb.GetAllResourceIconInfo(TEST_USER_ID, 
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR), infos);
    EXPECT_TRUE(ans);
    EXPECT_TRUE(infos[0].icon.empty());

    ans = resourceIconRdb.GetAllResourceIconInfo(TEST_USER_ID,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR), infos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(infos[0].icon.empty());

    ans = resourceIconRdb.GetAllResourceIconInfo(TEST_USER_ID,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR), infos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(infos[0].icon.empty());

    ans = resourceIconRdb.DeleteResourceIconInfo(resourceInfo.bundleName_, TEST_USER_ID);
    EXPECT_TRUE(ans);
}

/**
 * @tc.number: ParseKey_0001
 * Function: BundleResourceIconRdb
 * @tc.name: test BundleResourceIconRdb
 * @tc.desc: 1. system running normally
 *           2. test ParseKey
 */
HWTEST_F(BmsBundleResourceIconRdbTest, ParseKey_0001, Function | SmallTest | Level0)
{
    BundleResourceIconRdb resourceIconRdb;
    std::string key = "1_bundleName/moduleName/abilityName";
    LauncherAbilityResourceInfo info;
    resourceIconRdb.ParseKey(key, info);
    EXPECT_EQ(info.bundleName, "bundleName");
    EXPECT_EQ(info.appIndex, 1);
    EXPECT_EQ(info.moduleName, "moduleName");
    EXPECT_EQ(info.abilityName, "abilityName");
}

/**
 * @tc.number: SetAndGetIsOnlineTheme_0001
 * Function: BundleResourceIconRdb
 * @tc.name: test BundleResourceIconRdb
 * @tc.desc: 1. system running normally
 *           2. test GetIsOnlineTheme and SetIsOnlineTheme
 */
HWTEST_F(BmsBundleResourceIconRdbTest, SetAndGetIsOnlineTheme_0001, Function | SmallTest | Level0)
{
    BundleResourceIconRdb resourceIconRdb;
    bool ans = resourceIconRdb.GetIsOnlineTheme(TEST_USER_ID_TWO);
    EXPECT_FALSE(ans);

    resourceIconRdb.SetIsOnlineTheme(TEST_USER_ID_TWO, true);
    ans = resourceIconRdb.GetIsOnlineTheme(TEST_USER_ID_TWO);
    EXPECT_TRUE(ans);

    resourceIconRdb.SetIsOnlineTheme(TEST_USER_ID_TWO, false);
    ans = resourceIconRdb.GetIsOnlineTheme(TEST_USER_ID_TWO);
    EXPECT_FALSE(ans);
}
#endif
} // OHOS
