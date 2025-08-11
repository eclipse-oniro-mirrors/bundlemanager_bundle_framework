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

#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
#include "bundle_resource_theme_process.h"
#endif

#include "directory_ex.h"
#include "scope_guard.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const int32_t TEST_USER_ID = 20000;
constexpr const char* SYSTEM_THEME_PATH = "/data/service/el1/public/themes/";
constexpr const char* THEME_ICONS_A = "/a/app/icons/";
constexpr const char* THEME_ICONS_B = "/b/app/icons/";
constexpr const char* THEME_ICONS_A_FLAG = "/a/app/flag";
constexpr const char* THEME_ICONS_B_FLAG = "/b/app/flag";
constexpr const char* THEME_ICONS_CHAR = "/";
constexpr const char* TEST_BUNDLE_NAME = "com.example.bmsaccesstoken1";
constexpr const char* TEST_MODULE_NAME = "entry";
constexpr const char* TEST_ABILITY_NAME = "EntryAbility";
constexpr const char* COM_OHOS_CONTACTS_ENTRY_ABILITY = "com.ohos.contacts.EntryAbility";
constexpr const char* COM_OHOS_CONTACTS_ENTRY = "entry";
constexpr const char* COM_OHOS_CONTACTS = "com.ohos.contacts";
}  // namespace

class BmsBundleResourceThemeProcessTest : public testing::Test {
public:
    BmsBundleResourceThemeProcessTest();
    ~BmsBundleResourceThemeProcessTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsBundleResourceThemeProcessTest::BmsBundleResourceThemeProcessTest()
{}

BmsBundleResourceThemeProcessTest::~BmsBundleResourceThemeProcessTest()
{}

void BmsBundleResourceThemeProcessTest::SetUpTestCase()
{}

void BmsBundleResourceThemeProcessTest::TearDownTestCase()
{}

void BmsBundleResourceThemeProcessTest::SetUp()
{}

void BmsBundleResourceThemeProcessTest::TearDown()
{}

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
/**
 * @tc.number: IsBundleThemeExist_0001
 * Function: BmsBundleResourceThemeProcess
 * @tc.name: test BmsBundleResourceThemeProcess
 * @tc.desc: 1. system running normally
 *           2. test IsBundleThemeExist
 */
HWTEST_F(BmsBundleResourceThemeProcessTest, IsBundleThemeExist_0001, Function | SmallTest | Level0)
{
    bool ans = BundleResourceThemeProcess::IsBundleThemeExist("", TEST_USER_ID);
    EXPECT_FALSE(ans);

    ans = BundleResourceThemeProcess::IsBundleThemeExist(TEST_BUNDLE_NAME, TEST_USER_ID);
    EXPECT_FALSE(ans);

    OHOS::ForceCreateDirectory(SYSTEM_THEME_PATH + std::to_string(TEST_USER_ID) + THEME_ICONS_B + TEST_BUNDLE_NAME);
    ans = BundleResourceThemeProcess::IsBundleThemeExist(TEST_BUNDLE_NAME, TEST_USER_ID);
    EXPECT_TRUE(ans);

    OHOS::ForceCreateDirectory(SYSTEM_THEME_PATH + std::to_string(TEST_USER_ID) + THEME_ICONS_A + TEST_BUNDLE_NAME);
    ans = BundleResourceThemeProcess::IsBundleThemeExist(TEST_BUNDLE_NAME, TEST_USER_ID);
    EXPECT_TRUE(ans);

    OHOS::ForceRemoveDirectory(SYSTEM_THEME_PATH + std::to_string(TEST_USER_ID));
}

/**
 * @tc.number: IsAbilityThemeExist_0001
 * Function: BmsBundleResourceThemeProcess
 * @tc.name: test BmsBundleResourceThemeProcess
 * @tc.desc: 1. system running normally
 *           2. test IsAbilityThemeExist
 */
HWTEST_F(BmsBundleResourceThemeProcessTest, IsAbilityThemeExist_0001, Function | SmallTest | Level0)
{
    bool ans = BundleResourceThemeProcess::IsAbilityThemeExist("", "", "", TEST_USER_ID);
    EXPECT_FALSE(ans);

    ans = BundleResourceThemeProcess::IsAbilityThemeExist(TEST_BUNDLE_NAME, "", "", TEST_USER_ID);
    EXPECT_FALSE(ans);

    ans = BundleResourceThemeProcess::IsAbilityThemeExist("", TEST_BUNDLE_NAME, "", TEST_USER_ID);
    EXPECT_FALSE(ans);

    ans = BundleResourceThemeProcess::IsAbilityThemeExist("", "", TEST_ABILITY_NAME, TEST_USER_ID);
    EXPECT_FALSE(ans);

    ans = BundleResourceThemeProcess::IsAbilityThemeExist(TEST_BUNDLE_NAME, TEST_MODULE_NAME, "", TEST_USER_ID);
    EXPECT_FALSE(ans);

    ans = BundleResourceThemeProcess::IsAbilityThemeExist(TEST_BUNDLE_NAME, "", TEST_ABILITY_NAME, TEST_USER_ID);
    EXPECT_FALSE(ans);

    ans = BundleResourceThemeProcess::IsAbilityThemeExist("", TEST_BUNDLE_NAME, "", TEST_USER_ID);
    EXPECT_FALSE(ans);

    ans = BundleResourceThemeProcess::IsAbilityThemeExist(TEST_BUNDLE_NAME, TEST_MODULE_NAME, TEST_ABILITY_NAME,
        TEST_USER_ID);
    EXPECT_FALSE(ans);

    OHOS::ForceCreateDirectory(SYSTEM_THEME_PATH + std::to_string(TEST_USER_ID) + THEME_ICONS_B + TEST_BUNDLE_NAME +
        THEME_ICONS_CHAR + TEST_MODULE_NAME + THEME_ICONS_CHAR + TEST_ABILITY_NAME);
    ans = BundleResourceThemeProcess::IsAbilityThemeExist(TEST_BUNDLE_NAME, TEST_MODULE_NAME, TEST_ABILITY_NAME,
        TEST_USER_ID);
    EXPECT_TRUE(ans);

    OHOS::ForceCreateDirectory(SYSTEM_THEME_PATH + std::to_string(TEST_USER_ID) + THEME_ICONS_A + TEST_BUNDLE_NAME +
            THEME_ICONS_CHAR + TEST_MODULE_NAME + THEME_ICONS_CHAR + TEST_ABILITY_NAME);
    ans = BundleResourceThemeProcess::IsAbilityThemeExist(TEST_BUNDLE_NAME, TEST_MODULE_NAME, TEST_ABILITY_NAME,
        TEST_USER_ID);
    EXPECT_TRUE(ans);

    OHOS::ForceRemoveDirectory(SYSTEM_THEME_PATH + std::to_string(TEST_USER_ID));
}

/**
 * @tc.number: IsThemeExistInFlagA_0001
 * Function: BmsBundleResourceThemeProcess
 * @tc.name: test BmsBundleResourceThemeProcess
 * @tc.desc: 1. system running normally
 *           2. test IsThemeExistInFlagA
 */
HWTEST_F(BmsBundleResourceThemeProcessTest, IsThemeExistInFlagA_0001, Function | SmallTest | Level0)
{
    bool ans = BundleResourceThemeProcess::IsThemeExistInFlagA(TEST_BUNDLE_NAME, TEST_USER_ID);
    EXPECT_FALSE(ans);

    OHOS::ForceCreateDirectory(SYSTEM_THEME_PATH + std::to_string(TEST_USER_ID) + THEME_ICONS_A + TEST_BUNDLE_NAME);
    ans = BundleResourceThemeProcess::IsThemeExistInFlagA(TEST_BUNDLE_NAME, TEST_USER_ID);
    EXPECT_TRUE(ans);

    OHOS::ForceRemoveDirectory(SYSTEM_THEME_PATH + std::to_string(TEST_USER_ID));
}

/**
 * @tc.number: IsThemeExistInFlagB_0001
 * Function: BmsBundleResourceThemeProcess
 * @tc.name: test BmsBundleResourceThemeProcess
 * @tc.desc: 1. system running normally
 *           2. test IsThemeExistInFlagB
 */
HWTEST_F(BmsBundleResourceThemeProcessTest, IsThemeExistInFlagB_0001, Function | SmallTest | Level0)
{
    bool ans = BundleResourceThemeProcess::IsThemeExistInFlagB(TEST_BUNDLE_NAME, TEST_USER_ID);
    EXPECT_FALSE(ans);

    OHOS::ForceCreateDirectory(SYSTEM_THEME_PATH + std::to_string(TEST_USER_ID) + THEME_ICONS_B + TEST_BUNDLE_NAME);
    ans = BundleResourceThemeProcess::IsThemeExistInFlagB(TEST_BUNDLE_NAME, TEST_USER_ID);
    EXPECT_TRUE(ans);

    OHOS::ForceRemoveDirectory(SYSTEM_THEME_PATH + std::to_string(TEST_USER_ID));
}

/**
 * @tc.number: ProcessSpecialBundleResource_0001
 * Function: BmsBundleResourceThemeProcess
 * @tc.name: test BmsBundleResourceThemeProcess
 * @tc.desc: 1. system running normally
 *           2. test ProcessSpecialBundleResource
 */
HWTEST_F(BmsBundleResourceThemeProcessTest, ProcessSpecialBundleResource_0001, Function | SmallTest | Level0)
{
    std::vector<LauncherAbilityResourceInfo> resourceIconInfos;
    BundleResourceInfo bundleResourceInfo;
    BundleResourceThemeProcess::ProcessSpecialBundleResource(resourceIconInfos, bundleResourceInfo);

    LauncherAbilityResourceInfo info;
    info.bundleName = COM_OHOS_CONTACTS;
    info.moduleName = COM_OHOS_CONTACTS_ENTRY;
    info.abilityName = COM_OHOS_CONTACTS_ENTRY_ABILITY;
    info.icon = "icon";
    info.foreground.push_back(1);
    info.background.push_back(1);
    resourceIconInfos.push_back(info);
    bundleResourceInfo.bundleName = TEST_BUNDLE_NAME;
    bundleResourceInfo.icon = "icon1";
    BundleResourceThemeProcess::ProcessSpecialBundleResource(resourceIconInfos, bundleResourceInfo);
    EXPECT_EQ(bundleResourceInfo.icon, "icon1");

    BundleResourceInfo bundleResourceInfo1;
    bundleResourceInfo1.bundleName = COM_OHOS_CONTACTS;
    bundleResourceInfo1.icon = "icon1";
    BundleResourceThemeProcess::ProcessSpecialBundleResource(resourceIconInfos, bundleResourceInfo1);
    EXPECT_EQ(bundleResourceInfo1.icon, "icon");
}
#endif
}