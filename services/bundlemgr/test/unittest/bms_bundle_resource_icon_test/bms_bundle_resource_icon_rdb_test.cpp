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
#include "launcher_ability_resource_info.h"
#include "uninstall_bundle_resource_rdb.h"
#endif
#include "nlohmann/json.hpp"
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
const nlohmann::json LABEL_JSON_1 = R"(
{
    "LABEL": {
        "bundleName":"label"
    }
}
)"_json;

const nlohmann::json LABEL_JSON_2 = R"(
{
    "LABEL_1": {
        "bundleName":"label"
    }
}
)"_json;

const nlohmann::json LABEL_JSON_3 = R"(
{
    "LABEL": {
        "bundleName":1
    }
}
)"_json;

const nlohmann::json LABEL_JSON_4 = R"(
{
    "LABEL": {
        "bundleName":"label",
        "zh-Hans":"label2"
    }
}
)"_json;
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
 * @tc.number: DeleteResourceIconInfo_0002
 * Function: DeleteResourceIconInfo
 * @tc.name: test DeleteResourceIconInfo
 * @tc.desc: 1. system running normally
 *           2. test DeleteResourceIconInfo
 */
HWTEST_F(BmsBundleResourceIconRdbTest, DeleteResourceIconInfo_0002, Function | SmallTest | Level0)
{
    std::vector<ResourceInfo> resourceInfos;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.appIndex_ = APP_INDEX;
    resourceInfo.icon_ = "icon";
    resourceInfos.push_back(resourceInfo);
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.abilityName_ = "abilityName";
    resourceInfo.appIndex_ = APP_INDEX;
    resourceInfo.icon_ = "icon";
    resourceInfos.push_back(resourceInfo);
    resourceInfo.bundleName_ = "bundleName_bundleName";
    resourceInfo.appIndex_ = APP_INDEX;
    resourceInfo.icon_ = "icon";
    resourceInfos.push_back(resourceInfo);

    BundleResourceIconRdb resourceIconRdb;
    bool ans = resourceIconRdb.AddResourceIconInfos(USER_ID, IconResourceType::THEME_ICON, resourceInfos);
    EXPECT_TRUE(ans);

    ans = resourceIconRdb.DeleteResourceIconInfo("bundleName", USER_ID, APP_INDEX);
    EXPECT_TRUE(ans);
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    ans = resourceIconRdb.GetResourceIconInfos(resourceInfo.bundleName_, USER_ID, APP_INDEX,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON),
        launcherAbilityResourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(launcherAbilityResourceInfos.empty());

    ans = resourceIconRdb.DeleteResourceIconInfo(resourceInfo.bundleName_, USER_ID, APP_INDEX);
    EXPECT_TRUE(ans);

    ans = resourceIconRdb.GetResourceIconInfos(resourceInfo.bundleName_, USER_ID, APP_INDEX,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON),
        launcherAbilityResourceInfos);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: GetResourceIconInfos_0001
 * Function: BundleResourceIconRdb
 * @tc.name: test BundleResourceIconRdb
 * @tc.desc: 1. system running normally
 *           2. test GetResourceIconInfos
 */
HWTEST_F(BmsBundleResourceIconRdbTest, GetResourceIconInfos_0001, Function | SmallTest | Level0)
{
    BundleResourceIconRdb resourceIconRdb;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName_test";
    resourceInfo.appIndex_ = APP_INDEX;
    resourceInfo.icon_ = "";
    bool ans = resourceIconRdb.AddResourceIconInfo(USER_ID, IconResourceType::DYNAMIC_ICON, resourceInfo);
    EXPECT_TRUE(ans);

    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    ans = resourceIconRdb.GetResourceIconInfos(resourceInfo.bundleName_, USER_ID, APP_INDEX,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON),
        launcherAbilityResourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(launcherAbilityResourceInfos.empty());

    ans = resourceIconRdb.GetResourceIconInfos(resourceInfo.bundleName_, USER_ID, APP_INDEX,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR),
        launcherAbilityResourceInfos);
    EXPECT_FALSE(ans);
    EXPECT_TRUE(launcherAbilityResourceInfos.empty());

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
 * @tc.number: DeleteResourceIconInfos_0003
 * Function: DeleteResourceIconInfo
 * @tc.name: test DeleteResourceIconInfo
 * @tc.desc: 1. system running normally
 *           2. test DeleteResourceIconInfo
 */
HWTEST_F(BmsBundleResourceIconRdbTest, DeleteResourceIconInfos_0003, Function | SmallTest | Level0)
{
    std::vector<ResourceInfo> resourceInfos;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.appIndex_ = 0;
    resourceInfo.icon_ = "icon";
    resourceInfos.push_back(resourceInfo);
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.abilityName_ = "abilityName";
    resourceInfos.push_back(resourceInfo);
    resourceInfo.moduleName_ = "";
    resourceInfo.abilityName_ = "";
    resourceInfo.appIndex_ = APP_INDEX;
    resourceInfos.push_back(resourceInfo);
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.abilityName_ = "abilityName";
    resourceInfo.appIndex_ = APP_INDEX;
    resourceInfos.push_back(resourceInfo);

    BundleResourceIconRdb resourceIconRdb;
    bool ans = resourceIconRdb.AddResourceIconInfos(USER_ID, IconResourceType::THEME_ICON, resourceInfos);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.AddResourceIconInfos(TEST_USER_ID, IconResourceType::THEME_ICON, resourceInfos);
    EXPECT_TRUE(ans);
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    ans = resourceIconRdb.GetResourceIconInfos(resourceInfo.bundleName_, USER_ID, APP_INDEX,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON),
        launcherAbilityResourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(launcherAbilityResourceInfos.empty());

    ans = resourceIconRdb.DeleteResourceIconInfos(resourceInfo.bundleName_, USER_ID);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.GetResourceIconInfos(resourceInfo.bundleName_, USER_ID, APP_INDEX,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON),
        launcherAbilityResourceInfos);
    EXPECT_FALSE(ans);

    ans = resourceIconRdb.GetResourceIconInfos(resourceInfo.bundleName_, TEST_USER_ID, APP_INDEX,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON),
        launcherAbilityResourceInfos);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.DeleteResourceIconInfos(resourceInfo.bundleName_, TEST_USER_ID);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.GetResourceIconInfos(resourceInfo.bundleName_, TEST_USER_ID, APP_INDEX,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON),
        launcherAbilityResourceInfos);
    EXPECT_FALSE(ans);
}

/**
 * @tc.number: DeleteResourceIconInfos_0004
 * Function: DeleteResourceIconInfo
 * @tc.name: test DeleteResourceIconInfo
 * @tc.desc: 1. system running normally
 *           2. test DeleteResourceIconInfo
 */
HWTEST_F(BmsBundleResourceIconRdbTest, DeleteResourceIconInfos_0004, Function | SmallTest | Level0)
{
    std::vector<ResourceInfo> resourceInfos;
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = "bundleName";
    resourceInfo.appIndex_ = 0;
    resourceInfo.icon_ = "icon";
    resourceInfos.push_back(resourceInfo);
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.abilityName_ = "abilityName";
    resourceInfos.push_back(resourceInfo);
    resourceInfo.moduleName_ = "";
    resourceInfo.abilityName_ = "";
    resourceInfo.appIndex_ = APP_INDEX;
    resourceInfos.push_back(resourceInfo);
    resourceInfo.moduleName_ = "moduleName";
    resourceInfo.abilityName_ = "abilityName";
    resourceInfo.appIndex_ = APP_INDEX;
    resourceInfos.push_back(resourceInfo);

    BundleResourceIconRdb resourceIconRdb;
    bool ans = resourceIconRdb.AddResourceIconInfos(USER_ID, IconResourceType::THEME_ICON, resourceInfos);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.AddResourceIconInfos(TEST_USER_ID, IconResourceType::THEME_ICON, resourceInfos);
    EXPECT_TRUE(ans);
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    ans = resourceIconRdb.GetResourceIconInfos(resourceInfo.bundleName_, TEST_USER_ID, APP_INDEX,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON),
        launcherAbilityResourceInfos);
    EXPECT_TRUE(ans);
    EXPECT_FALSE(launcherAbilityResourceInfos.empty());

    ans = resourceIconRdb.DeleteResourceIconInfos(resourceInfo.bundleName_);
    EXPECT_TRUE(ans);
    ans = resourceIconRdb.GetResourceIconInfos(resourceInfo.bundleName_, TEST_USER_ID, APP_INDEX,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON),
        launcherAbilityResourceInfos);
    EXPECT_FALSE(ans);
    ans = resourceIconRdb.GetResourceIconInfos(resourceInfo.bundleName_, USER_ID, APP_INDEX,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON),
        launcherAbilityResourceInfos);
    EXPECT_FALSE(ans);
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
 * @tc.number: AddUninstallBundleResource_0001
 * Function: UninstallBundleResourceRdb
 * @tc.name: test UninstallBundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test AddUninstallBundleResource
 */
HWTEST_F(BmsBundleResourceIconRdbTest, AddUninstallBundleResource_0001, Function | SmallTest | Level0)
{
    UninstallBundleResourceRdb uninstallBundleResourceRdb;
    BundleResourceInfo resourceInfo;
    std::map<std::string, std::string> labelMap;
    bool ret = uninstallBundleResourceRdb.AddUninstallBundleResource("", 0, 0, labelMap, resourceInfo);
    EXPECT_FALSE(ret);
    ret = uninstallBundleResourceRdb.AddUninstallBundleResource(BUNDLE_NAME, USER_ID, 0, labelMap, resourceInfo);
    EXPECT_TRUE(ret);
    BundleResourceInfo bundleResourceInfo;
    ret = uninstallBundleResourceRdb.GetUninstallBundleResource(BUNDLE_NAME, USER_ID, 0, 1, bundleResourceInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: AddUninstallBundleResource_0002
 * Function: UninstallBundleResourceRdb
 * @tc.name: test UninstallBundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test AddUninstallBundleResource
 */
HWTEST_F(BmsBundleResourceIconRdbTest, AddUninstallBundleResource_0002, Function | SmallTest | Level0)
{
    UninstallBundleResourceRdb uninstallBundleResourceRdb;
    std::map<std::string, std::string> labelMap;
    BundleResourceInfo resourceInfo;
    resourceInfo.icon = "icon";
    resourceInfo.foreground.emplace_back(1);
    bool ret = uninstallBundleResourceRdb.AddUninstallBundleResource(BUNDLE_NAME, USER_ID, 0, labelMap, resourceInfo);
    EXPECT_TRUE(ret);
    BundleResourceInfo bundleResourceInfo;
    ret = uninstallBundleResourceRdb.GetUninstallBundleResource(BUNDLE_NAME, USER_ID, APP_INDEX, 1, bundleResourceInfo);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(bundleResourceInfo.icon.empty());
    ret = uninstallBundleResourceRdb.GetUninstallBundleResource(BUNDLE_NAME, USER_ID, 0, 1, bundleResourceInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(bundleResourceInfo.bundleName, BUNDLE_NAME);
    EXPECT_EQ(bundleResourceInfo.label, BUNDLE_NAME);
    EXPECT_FALSE(bundleResourceInfo.icon.empty());
    EXPECT_EQ(bundleResourceInfo.appIndex, 0);
    ret = uninstallBundleResourceRdb.DeleteUninstallBundleResource(BUNDLE_NAME, USER_ID, 0);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: AddUninstallBundleResource_0003
 * Function: UninstallBundleResourceRdb
 * @tc.name: test UninstallBundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test AddUninstallBundleResource
 */
HWTEST_F(BmsBundleResourceIconRdbTest, AddUninstallBundleResource_0003, Function | SmallTest | Level0)
{
    UninstallBundleResourceRdb uninstallBundleResourceRdb;
    std::map<std::string, std::string> labelMap;
    BundleResourceInfo resourceInfo;
    bool ret = uninstallBundleResourceRdb.AddUninstallBundleResource(BUNDLE_NAME, USER_ID, 0, labelMap, resourceInfo);
    EXPECT_TRUE(ret);
    BundleResourceInfo bundleResourceInfo;
    ret = uninstallBundleResourceRdb.GetUninstallBundleResource(BUNDLE_NAME, USER_ID, APP_INDEX, 1, bundleResourceInfo);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(bundleResourceInfo.icon.empty());
    resourceInfo.icon = "icon";
    ret = uninstallBundleResourceRdb.AddUninstallBundleResource(BUNDLE_NAME, USER_ID, 0, labelMap, resourceInfo);
    EXPECT_TRUE(ret);
    ret = uninstallBundleResourceRdb.GetUninstallBundleResource(BUNDLE_NAME, USER_ID, APP_INDEX, 1, bundleResourceInfo);
    EXPECT_FALSE(ret);
    resourceInfo.foreground.emplace_back(1);
    ret = uninstallBundleResourceRdb.AddUninstallBundleResource(BUNDLE_NAME, USER_ID, 0, labelMap, resourceInfo);
    EXPECT_TRUE(ret);
    ret = uninstallBundleResourceRdb.GetUninstallBundleResource(BUNDLE_NAME, USER_ID, 0, 1, bundleResourceInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(bundleResourceInfo.icon, resourceInfo.icon);
    ret = uninstallBundleResourceRdb.DeleteUninstallBundleResource(BUNDLE_NAME, USER_ID, 0);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: AddUninstallBundleResource_0004
 * Function: UninstallBundleResourceRdb
 * @tc.name: test UninstallBundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test AddUninstallBundleResource
 */
HWTEST_F(BmsBundleResourceIconRdbTest, AddUninstallBundleResource_0004, Function | SmallTest | Level0)
{
    UninstallBundleResourceRdb uninstallBundleResourceRdb;
    std::map<std::string, std::string> labelMap;
    std::vector<BundleResourceInfo> bundleResourceInfos;
    bool ret = uninstallBundleResourceRdb.GetAllUninstallBundleResource(0, 0, bundleResourceInfos);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(bundleResourceInfos.empty());

    BundleResourceInfo resourceInfo;
    resourceInfo.icon = "icon";
    resourceInfo.foreground.emplace_back(1);
    ret = uninstallBundleResourceRdb.AddUninstallBundleResource(BUNDLE_NAME, TEST_USER_ID,
        APP_INDEX, labelMap, resourceInfo);
    EXPECT_TRUE(ret);
    ret = uninstallBundleResourceRdb.GetAllUninstallBundleResource(TEST_USER_ID, 1, bundleResourceInfos);
    EXPECT_TRUE(ret);
    EXPECT_EQ(bundleResourceInfos.size(), 1);
    if (!bundleResourceInfos.empty()) {
        EXPECT_EQ(bundleResourceInfos[0].bundleName, BUNDLE_NAME);
        EXPECT_EQ(bundleResourceInfos[0].label, BUNDLE_NAME);
        EXPECT_EQ(bundleResourceInfos[0].icon, resourceInfo.icon);
    }

    ret = uninstallBundleResourceRdb.DeleteUninstallBundleResource(BUNDLE_NAME, TEST_USER_ID, APP_INDEX);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: DeleteUninstallBundleResource_0001
 * Function: UninstallBundleResourceRdb
 * @tc.name: test UninstallBundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test DeleteUninstallBundleResource
 */
HWTEST_F(BmsBundleResourceIconRdbTest, DeleteUninstallBundleResource_0001, Function | SmallTest | Level0)
{
    UninstallBundleResourceRdb uninstallBundleResourceRdb;
    bool ret = uninstallBundleResourceRdb.DeleteUninstallBundleResource("", USER_ID, 0);
    EXPECT_FALSE(ret);

    ret = uninstallBundleResourceRdb.DeleteUninstallBundleResource(BUNDLE_NAME, USER_ID, 0);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: ToString_0001
 * Function: UninstallBundleResourceRdb
 * @tc.name: test UninstallBundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test ToString
 */
HWTEST_F(BmsBundleResourceIconRdbTest, ToString_0001, Function | SmallTest | Level0)
{
    std::map<std::string, std::string> labelMap;
    labelMap[BUNDLE_NAME] = BUNDLE_NAME;
    UninstallBundleResourceRdb uninstallBundleResourceRdb;
    std::string labels = uninstallBundleResourceRdb.ToString(labelMap);
    EXPECT_FALSE(labels.empty());

    std::map<std::string, std::string> newLabelMap = uninstallBundleResourceRdb.FromString(labels);
    EXPECT_FALSE(newLabelMap.empty());

    auto iter = newLabelMap.find(BUNDLE_NAME);
    EXPECT_TRUE(iter != newLabelMap.end());
    if (iter != newLabelMap.end()) {
        EXPECT_EQ(iter->second, BUNDLE_NAME);
    }
}

/**
 * @tc.number: FromString_0001
 * Function: UninstallBundleResourceRdb
 * @tc.name: test UninstallBundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test FromString
 */
HWTEST_F(BmsBundleResourceIconRdbTest, FromString_0001, Function | SmallTest | Level0)
{
    UninstallBundleResourceRdb uninstallBundleResourceRdb;
    std::string labels = "";
    std::map<std::string, std::string> labelMap = uninstallBundleResourceRdb.FromString(labels);
    EXPECT_TRUE(labelMap.empty());

    labelMap = uninstallBundleResourceRdb.FromString(LABEL_JSON_1.dump());
    EXPECT_FALSE(labelMap.empty());
    EXPECT_TRUE(labelMap.find("bundleName") != labelMap.end());

    labelMap = uninstallBundleResourceRdb.FromString(LABEL_JSON_2.dump());
    EXPECT_TRUE(labelMap.empty());

    labelMap = uninstallBundleResourceRdb.FromString(LABEL_JSON_3.dump());
    EXPECT_TRUE(labelMap.empty());
}

/**
 * @tc.number: GetAvailableLabel_0001
 * Function: UninstallBundleResourceRdb
 * @tc.name: test UninstallBundleResourceRdb
 * @tc.desc: 1. system running normally
 *           2. test GetAvailableLabel
 */
HWTEST_F(BmsBundleResourceIconRdbTest, GetAvailableLabel_0001, Function | SmallTest | Level0)
{
    UninstallBundleResourceRdb uninstallBundleResourceRdb;
    std::string label = uninstallBundleResourceRdb.GetAvailableLabel(BUNDLE_NAME, "", LABEL_JSON_1.dump());
    EXPECT_EQ(label, BUNDLE_NAME);

    label = uninstallBundleResourceRdb.GetAvailableLabel(BUNDLE_NAME, "bundleName", LABEL_JSON_1.dump());
    EXPECT_EQ(label, "label");

    label = uninstallBundleResourceRdb.GetAvailableLabel(BUNDLE_NAME, "", LABEL_JSON_4.dump());
    EXPECT_EQ(label, "label2");
}
#endif
} // OHOS
