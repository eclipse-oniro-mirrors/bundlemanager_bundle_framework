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

#define private public

#include <gtest/gtest.h>
#include <string>

#include "bundle_info.h"
#include "router_data_storage_rdb.h"
#include "router_item_compare.h"
#include "router_map_helper.h"
#include "sem_ver.h"
#include "uninstall_data_mgr_storage_rdb.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::Parcel;

namespace OHOS {
namespace {
    const size_t ROUTER_ITEM_TEST_SIZE = 12;
}  // namespace

class BmsBundleNavigationTest : public testing::Test {
public:
    BmsBundleNavigationTest();
    ~BmsBundleNavigationTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    RouterItem GenerateRouterItem0();
    RouterItem GenerateRouterItem1();
    RouterItem GenerateRouterItem2();
    RouterItem GenerateRouterItem3();
    RouterItem GenerateRouterItem4();
    RouterItem GenerateRouterItem5();
    RouterItem GenerateRouterItem6();
    RouterItem GenerateRouterItem7();
    RouterItem GenerateRouterItem8();
    RouterItem GenerateRouterItem9();
    RouterItem GenerateRouterItem10();
    RouterItem GenerateRouterItem11();

    void GenerateRouterArray(std::vector<RouterItem> &routerArray);
private:
    std::vector<RouterItem> routerArrayTest_;
};

BmsBundleNavigationTest::BmsBundleNavigationTest()
{
    GenerateRouterArray(routerArrayTest_);
}

BmsBundleNavigationTest::~BmsBundleNavigationTest()
{}

void BmsBundleNavigationTest::SetUpTestCase()
{}

void BmsBundleNavigationTest::TearDownTestCase()
{}

void BmsBundleNavigationTest::SetUp()
{}

void BmsBundleNavigationTest::TearDown()
{}

RouterItem BmsBundleNavigationTest::GenerateRouterItem0()
{
    RouterItem item;
    item.name = "DynamicPage1";
    item.pageSourceFile = "entry/src/index";
    item.buildFunction = "myBuildFunction1";
    item.ohmurl = "ohmurlTest&com.example.test&entry&entry/resources/base/profile&1.2.1";
    item.bundleName = "com.example.test";
    item.moduleName = "entry";
    return item;
}

RouterItem BmsBundleNavigationTest::GenerateRouterItem1()
{
    RouterItem item;
    item.name = "DynamicPage1";
    item.pageSourceFile = "feature/src/index";
    item.buildFunction = "myBuildFunction1";
    item.ohmurl = "ohmurlTest&com.example.test&feature&feature/resources/base/profile&1.2.1";
    item.bundleName = "com.example.test";
    item.moduleName = "feature";
    return item;
}

RouterItem BmsBundleNavigationTest::GenerateRouterItem2()
{
    RouterItem item;
    item.name = "DynamicPage1";
    item.pageSourceFile = "library/src/index";
    item.buildFunction = "myBuildFunction1";
    item.ohmurl = "ohmurlTest&com.example.test&library&library/resources/base/profile&1.2.1";
    item.bundleName = "com.example.test";
    item.moduleName = "library";
    return item;
}

RouterItem BmsBundleNavigationTest::GenerateRouterItem3()
{
    RouterItem item;
    item.name = "DynamicPage1";
    item.pageSourceFile = "entry/src/index";
    item.buildFunction = "myBuildFunction1";
    item.ohmurl = "ohmurlTest&com.example.test&entry&entry/resources/base/profile&1.2.2";
    item.bundleName = "com.example.test";
    item.moduleName = "entry";
    return item;
}

RouterItem BmsBundleNavigationTest::GenerateRouterItem4()
{
    RouterItem item;
    item.name = "DynamicPage1";
    item.pageSourceFile = "entry/src/index";
    item.buildFunction = "myBuildFunction1";
    item.ohmurl = "ohmurlTest&com.example.test&entry&entry/resources/base/profile&1.2.1";
    item.bundleName = "com.example.test";
    item.moduleName = "entry";
    return item;
}

RouterItem BmsBundleNavigationTest::GenerateRouterItem5()
{
    RouterItem item;
    item.name = "DynamicPage1";
    item.pageSourceFile = "entry/src/index";
    item.buildFunction = "myBuildFunction1";
    item.ohmurl = "ohmurlTest";
    item.bundleName = "com.example.test";
    item.moduleName = "entry";
    return item;
}

RouterItem BmsBundleNavigationTest::GenerateRouterItem6()
{
    RouterItem item;
    item.name = "DynamicPage1";
    item.pageSourceFile = "feature/src/index";
    item.buildFunction = "myBuildFunction1";
    item.ohmurl = "ohmurlTest";
    item.bundleName = "com.example.test";
    item.moduleName = "feature";
    return item;
}

RouterItem BmsBundleNavigationTest::GenerateRouterItem7()
{
    RouterItem item;
    item.name = "DynamicPage1";
    item.pageSourceFile = "entry/src/index";
    item.buildFunction = "myBuildFunction1";
    item.ohmurl = "ohmurlTestROUTER_ITEM_TEST_SIZE3";
    item.bundleName = "com.example.test";
    item.moduleName = "entry";
    return item;
}

RouterItem BmsBundleNavigationTest::GenerateRouterItem8()
{
    RouterItem item;
    item.name = "DynamicPage1";
    item.pageSourceFile = "library/src/index";
    item.buildFunction = "myBuildFunction1";
    item.ohmurl = "ohmurlTest";
    item.bundleName = "com.example.test";
    item.moduleName = "library";
    return item;
}

RouterItem BmsBundleNavigationTest::GenerateRouterItem9()
{
    RouterItem item;
    item.name = "DynamicPage2";
    item.pageSourceFile = "entry/src/index";
    item.buildFunction = "myBuildFunction1";
    item.ohmurl = "ohmurlTest&com.example.test&entry&entry/resources/base/profile&1.2.1ohmurlTest";
    item.bundleName = "com.example.test";
    item.moduleName = "entry";
    return item;
}

RouterItem BmsBundleNavigationTest::GenerateRouterItem10()
{
    RouterItem item;
    item.name = "DynamicPage3";
    item.pageSourceFile = "feature/src/index";
    item.buildFunction = "myBuildFunction1";
    item.ohmurl = "ohmurlTest";
    item.bundleName = "com.example.test";
    item.moduleName = "feature";
    return item;
}

RouterItem BmsBundleNavigationTest::GenerateRouterItem11()
{
    RouterItem item;
    item.name = "DynamicPage4";
    item.pageSourceFile = "entry/src/index";
    item.buildFunction = "myBuildFunction1";
    item.ohmurl = "ohmurlTest";
    item.bundleName = "com.example.test";
    item.moduleName = "entry";
    return item;
}

void BmsBundleNavigationTest::GenerateRouterArray(std::vector<RouterItem> &routerArray)
{
    routerArray.reserve(ROUTER_ITEM_TEST_SIZE);
    routerArray.emplace_back(GenerateRouterItem0());
    routerArray.emplace_back(GenerateRouterItem1());
    routerArray.emplace_back(GenerateRouterItem2());
    routerArray.emplace_back(GenerateRouterItem3());
    routerArray.emplace_back(GenerateRouterItem4());
    routerArray.emplace_back(GenerateRouterItem5());
    routerArray.emplace_back(GenerateRouterItem6());
    routerArray.emplace_back(GenerateRouterItem7());
    routerArray.emplace_back(GenerateRouterItem8());
    routerArray.emplace_back(GenerateRouterItem9());
    routerArray.emplace_back(GenerateRouterItem10());
    routerArray.emplace_back(GenerateRouterItem11());
}

/**
 * @tc.number: SemVerConstructor_0010
 * @tc.name: test construction function for SemVer class
 * @tc.desc: 1.SemVerConstructor
 */
HWTEST_F(BmsBundleNavigationTest, SemVerConstructor_0010, Function | SmallTest | Level0)
{
    std::string versionString = "1.2.0";
    SemVer semVer(versionString);
    EXPECT_EQ(semVer.major, "1");
    EXPECT_EQ(semVer.minor, "2");
    EXPECT_EQ(semVer.patch, "0");
    EXPECT_TRUE(semVer.prerelease.empty());
    EXPECT_TRUE(semVer.buildMeta.empty());
    EXPECT_EQ(semVer.raw, versionString);
}

/**
 * @tc.number: SemVerConstructor_0020
 * @tc.name: test construction function for SemVer class
 * @tc.desc: 1.SemVerConstructor
 */
HWTEST_F(BmsBundleNavigationTest, SemVerConstructor_0020, Function | SmallTest | Level0)
{
    std::string versionString = "abs.pat.nn";
    SemVer semVer(versionString);
    EXPECT_EQ(semVer.major, "abs");
    EXPECT_EQ(semVer.minor, "pat");
    EXPECT_EQ(semVer.patch, "nn");
    EXPECT_TRUE(semVer.prerelease.empty());
    EXPECT_TRUE(semVer.buildMeta.empty());
    EXPECT_EQ(semVer.raw, versionString);
}

/**
 * @tc.number: SemVerConstructor_0030
 * @tc.name: test construction function for SemVer class
 * @tc.desc: 1.SemVerConstructor
 */
HWTEST_F(BmsBundleNavigationTest, SemVerConstructor_0030, Function | SmallTest | Level0)
{
    std::string versionString = "1.2.1-";
    SemVer semVer(versionString);
    EXPECT_EQ(semVer.major, "1");
    EXPECT_EQ(semVer.minor, "2");
    EXPECT_EQ(semVer.patch, "1");
    EXPECT_TRUE(semVer.prerelease.empty());
    EXPECT_TRUE(semVer.buildMeta.empty());
    EXPECT_EQ(semVer.raw, versionString);
}

/**
 * @tc.number: SemVerConstructor_0040
 * @tc.name: test construction function for SemVer class
 * @tc.desc: 1.SemVerConstructor
 */
HWTEST_F(BmsBundleNavigationTest, SemVerConstructor_0040, Function | SmallTest | Level0)
{
    std::string versionString = "1.2.1-beta";
    SemVer semVer(versionString);
    EXPECT_EQ(semVer.major, "1");
    EXPECT_EQ(semVer.minor, "2");
    EXPECT_EQ(semVer.patch, "1");
    ASSERT_EQ(semVer.prerelease.size(), 1);
    EXPECT_EQ(semVer.prerelease[0], "beta");
    EXPECT_TRUE(semVer.buildMeta.empty());
    EXPECT_EQ(semVer.raw, versionString);
}

/**
 * @tc.number: SemVerConstructor_0050
 * @tc.name: test construction function for SemVer class
 * @tc.desc: 1.SemVerConstructor
 */
HWTEST_F(BmsBundleNavigationTest, SemVerConstructor_0050, Function | SmallTest | Level0)
{
    std::string versionString = "2.3.6-release.6.1";
    SemVer semVer(versionString);
    EXPECT_EQ(semVer.major, "2");
    EXPECT_EQ(semVer.minor, "3");
    EXPECT_EQ(semVer.patch, "6");
    ASSERT_EQ(semVer.prerelease.size(), 3);
    EXPECT_EQ(semVer.prerelease[0], "release");
    EXPECT_EQ(semVer.prerelease[1], "6");
    EXPECT_EQ(semVer.prerelease[2], "1");
    EXPECT_TRUE(semVer.buildMeta.empty());
    EXPECT_EQ(semVer.raw, versionString);
}

/**
 * @tc.number: SemVerConstructor_0060
 * @tc.name: test construction function for SemVer class
 * @tc.desc: 1.SemVerConstructor
 */
HWTEST_F(BmsBundleNavigationTest, SemVerConstructor_0060, Function | SmallTest | Level0)
{
    std::string versionString = "2.3.7-3.5";
    SemVer semVer(versionString);
    EXPECT_EQ(semVer.major, "2");
    EXPECT_EQ(semVer.minor, "3");
    EXPECT_EQ(semVer.patch, "7");
    ASSERT_EQ(semVer.prerelease.size(), 2);
    EXPECT_EQ(semVer.prerelease[0], "3");
    EXPECT_EQ(semVer.prerelease[1], "5");
    EXPECT_TRUE(semVer.buildMeta.empty());
    EXPECT_EQ(semVer.raw, versionString);
}

/**
 * @tc.number: SemVerConstructor_0070
 * @tc.name: test construction function for SemVer class
 * @tc.desc: 1.SemVerConstructor
 */
HWTEST_F(BmsBundleNavigationTest, SemVerConstructor_0070, Function | SmallTest | Level0)
{
    std::string versionString = "2.3.6-2.release";
    SemVer semVer(versionString);
    EXPECT_EQ(semVer.major, "2");
    EXPECT_EQ(semVer.minor, "3");
    EXPECT_EQ(semVer.patch, "6");
    ASSERT_EQ(semVer.prerelease.size(), 2);
    EXPECT_EQ(semVer.prerelease[0], "2");
    EXPECT_EQ(semVer.prerelease[1], "release");
    EXPECT_TRUE(semVer.buildMeta.empty());
    EXPECT_EQ(semVer.raw, versionString);
}

/**
 * @tc.number: SemVerConstructor_0080
 * @tc.name: test construction function for SemVer class
 * @tc.desc: 1.SemVerConstructor
 */
HWTEST_F(BmsBundleNavigationTest, SemVerConstructor_0080, Function | SmallTest | Level0)
{
    std::string versionString = "1.2.1+2356";
    SemVer semVer(versionString);
    EXPECT_EQ(semVer.major, "1");
    EXPECT_EQ(semVer.minor, "2");
    EXPECT_EQ(semVer.patch, "1");
    EXPECT_TRUE(semVer.prerelease.empty());
    ASSERT_EQ(semVer.buildMeta.size(), 1);
    EXPECT_EQ(semVer.buildMeta[0], "2356");
    EXPECT_EQ(semVer.raw, versionString);
}

/**
 * @tc.number: SemVerConstructor_0090
 * @tc.name: test construction function for SemVer class
 * @tc.desc: 1.SemVerConstructor
 */
HWTEST_F(BmsBundleNavigationTest, SemVerConstructor_0090, Function | SmallTest | Level0)
{
    std::string versionString = "1.2.3+2024.3.16";
    SemVer semVer(versionString);
    EXPECT_EQ(semVer.major, "1");
    EXPECT_EQ(semVer.minor, "2");
    EXPECT_EQ(semVer.patch, "3");
    EXPECT_TRUE(semVer.prerelease.empty());
    ASSERT_EQ(semVer.buildMeta.size(), 3);
    EXPECT_EQ(semVer.buildMeta[0], "2024");
    EXPECT_EQ(semVer.buildMeta[1], "3");
    EXPECT_EQ(semVer.buildMeta[2], "16");
    EXPECT_EQ(semVer.raw, versionString);
}

/**
 * @tc.number: SemVerConstructor_0100
 * @tc.name: test construction function for SemVer class
 * @tc.desc: 1.SemVerConstructor
 */
HWTEST_F(BmsBundleNavigationTest, SemVerConstructor_0100, Function | SmallTest | Level0)
{
    std::string versionString = "2.1.0-beta.2+3.6";
    SemVer semVer(versionString);
    EXPECT_EQ(semVer.major, "2");
    EXPECT_EQ(semVer.minor, "1");
    EXPECT_EQ(semVer.patch, "0");
    ASSERT_EQ(semVer.prerelease.size(), 2);
    EXPECT_EQ(semVer.prerelease[0], "beta");
    EXPECT_EQ(semVer.prerelease[1], "2");
    ASSERT_EQ(semVer.buildMeta.size(), 2);
    EXPECT_EQ(semVer.buildMeta[0], "3");
    EXPECT_EQ(semVer.buildMeta[1], "6");
    EXPECT_EQ(semVer.raw, versionString);
}

/**
 * @tc.number: SemVerConstructor_0110
 * @tc.name: test construction function for SemVer class
 * @tc.desc: 1.SemVerConstructor
 */
HWTEST_F(BmsBundleNavigationTest, SemVerConstructor_0110, Function | SmallTest | Level0)
{
    std::string versionString = "";
    SemVer semVer(versionString);
    EXPECT_EQ(semVer.major, "");
    EXPECT_EQ(semVer.minor, "");
    EXPECT_EQ(semVer.patch, "");
    EXPECT_TRUE(semVer.prerelease.empty());
    EXPECT_TRUE(semVer.buildMeta.empty());
}

/**
 * @tc.number: SemVerCompare_0001
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0001, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.0";
    SemVer semVer1(versionString1);

    std::string versionString2 = "2.2.2";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), -1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), -1);
}

/**
 * @tc.number: SemVerCompare_0002
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0002, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.0";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.1.1";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 1);
}

/**
 * @tc.number: SemVerCompare_0003
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0003, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.1";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.0";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 1);
}

/**
 * @tc.number: SemVerCompare_0004
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0004, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.0-release.1";
    SemVer semVer1(versionString1);

    std::string versionString2 = "2.2.2-beta1";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), -1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 1);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), -1);
}

/**
 * @tc.number: SemVerCompare_0005
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0005, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.0-release.1";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.1.1-release.1";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 1);
}

/**
 * @tc.number: SemVerCompare_0006
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0006, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.1-beta1";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.0-release";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), -1);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 1);
}

/**
 * @tc.number: SemVerCompare_0007
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0007, Function | SmallTest | Level0)
{
    std::string versionString1 = "01.2.0";
    SemVer semVer1(versionString1);

    std::string versionString2 = "2.2.2";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), -1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), -1);
}

/**
 * @tc.number: SemVerCompare_0008
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0008, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.02.0";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.1.1";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 1);
}

/**
 * @tc.number: SemVerCompare_0009
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0009, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.01";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.0";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 1);
}

/**
 * @tc.number: SemVerCompare_0010
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0010, Function | SmallTest | Level0)
{
    std::string versionString1 = "a01.2.3";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.3";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 1);
}

/**
 * @tc.number: SemVerCompare_0011
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0011, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.abc.3";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.1.3";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 1);
}

/**
 * @tc.number: SemVerCompare_0012
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0012, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.0";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.b03";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), -1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), -1);
}

/**
 * @tc.number: SemVerCompare_0013
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0013, Function | SmallTest | Level0)
{
    std::string versionString1 = "abc.2.3";
    SemVer semVer1(versionString1);

    std::string versionString2 = "bcd.2.3";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), -1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), -1);
}

/**
 * @tc.number: SemVerCompare_0014
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0014, Function | SmallTest | Level0)
{
    std::string versionString1 = "abs.0bc.2";
    SemVer semVer1(versionString1);

    std::string versionString2 = "abs.abc.3";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), -1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), -1);
}

/**
 * @tc.number: SemVerCompare_0015
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0015, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.patch1";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.patch";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 1);
}

/**
 * @tc.number: SemVerCompare_0016
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0016, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.1";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.1";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 0);
}

/**
 * @tc.number: SemVerCompare_0017
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0017, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.1";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.1-release";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 1);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 1);
}

/**
 * @tc.number: SemVerCompare_0018
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0018, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.1-release.1";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.1-release";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 1);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 1);
}

/**
 * @tc.number: SemVerCompare_0019
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0019, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.1-release.1";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.1-release.2";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), -1);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), -1);
}

/**
 * @tc.number: SemVerCompare_0020
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0020, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.1-release.1";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.1-beta.2";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 1);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 1);
}

/**
 * @tc.number: SemVerCompare_0021
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0021, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.1-release.1";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.1-release.1";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 0);
}

/**
 * @tc.number: SemVerCompare_0022
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0022, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.1-release.0001";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.1-release.1";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 0);
}

/**
 * @tc.number: SemVerCompare_0023
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0023, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.1+12";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.1+34567";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 0);
}

/**
 * @tc.number: SemVerCompare_0024
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0024, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.1-release.1+23";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.1-release.1";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 0);
}

/**
 * @tc.number: SemVerCompare_0025
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0025, Function | SmallTest | Level0)
{
    std::string versionString1 = "1.2.3-release.2";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.3-release.2";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 0);
}

/**
 * @tc.number: SemVerCompare_0026
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0026, Function | SmallTest | Level0)
{
    std::string versionString1 = "";
    SemVer semVer1(versionString1);

    std::string versionString2 = "1.2.3-release.2";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 1);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 1);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 1);
}

/**
 * @tc.number: SemVerCompare_0027
 * @tc.name: test compare function for SemVer
 * @tc.desc: 1.SemVerCompare
 */
HWTEST_F(BmsBundleNavigationTest, SemVerCompare_0027, Function | SmallTest | Level0)
{
    std::string versionString1 = "";
    SemVer semVer1(versionString1);

    std::string versionString2 = "";
    SemVer semVer2(versionString2);

    EXPECT_EQ(RouterMapHelper::CompareMain(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::ComparePre(semVer1, semVer2), 0);
    EXPECT_EQ(RouterMapHelper::Compare(semVer1, semVer2), 0);
}

/**
 * @tc.number: RouterMapMerge_0001
 * @tc.name: test merge function for router map
 * @tc.desc: 1.RouterMapMerge
 */
HWTEST_F(BmsBundleNavigationTest, RouterMapMerge_0001, Function | SmallTest | Level0)
{
    ASSERT_EQ(routerArrayTest_.size(), ROUTER_ITEM_TEST_SIZE);
    BundleInfo info;
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "entry";
    hapModuleInfo.routerArray.emplace_back(routerArrayTest_[0]);
    hapModuleInfo.routerArray.emplace_back(routerArrayTest_[9]);
    info.hapModuleInfos.emplace_back(hapModuleInfo);
    RouterMapHelper::MergeRouter(info);
    EXPECT_EQ(info.routerArray.size(), 2);
}

/**
 * @tc.number: RouterMapMerge_0002
 * @tc.name: test merge function for router map
 * @tc.desc: 1.RouterMapMerge
 */
HWTEST_F(BmsBundleNavigationTest, RouterMapMerge_0002, Function | SmallTest | Level0)
{
    ASSERT_EQ(routerArrayTest_.size(), ROUTER_ITEM_TEST_SIZE);
    BundleInfo info;
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "entry";
    hapModuleInfo.routerArray.emplace_back(routerArrayTest_[0]);
    hapModuleInfo.routerArray.emplace_back(routerArrayTest_[4]);
    info.hapModuleInfos.emplace_back(hapModuleInfo);
    RouterMapHelper::MergeRouter(info);
    EXPECT_EQ(info.routerArray.size(), 1);
}

/**
 * @tc.number: RouterMapMerge_0003
 * @tc.name: test merge function for router map
 * @tc.desc: 1.RouterMapMerge
 */
HWTEST_F(BmsBundleNavigationTest, RouterMapMerge_0003, Function | SmallTest | Level0)
{
    ASSERT_EQ(routerArrayTest_.size(), ROUTER_ITEM_TEST_SIZE);
    BundleInfo info;
    HapModuleInfo hapModuleInfoEntry;
    hapModuleInfoEntry.moduleName = "entry";
    hapModuleInfoEntry.moduleType = ModuleType::ENTRY;
    hapModuleInfoEntry.routerArray.emplace_back(routerArrayTest_[0]);
    info.hapModuleInfos.emplace_back(hapModuleInfoEntry);

    HapModuleInfo hapModuleInfoFeature;
    hapModuleInfoFeature.moduleName = "feature";
    hapModuleInfoFeature.moduleType = ModuleType::FEATURE;
    hapModuleInfoFeature.routerArray.emplace_back(routerArrayTest_[1]);
    info.hapModuleInfos.emplace_back(hapModuleInfoFeature);
    RouterMapHelper::MergeRouter(info);
    ASSERT_EQ(info.routerArray.size(), 1);
    EXPECT_EQ(info.routerArray[0].moduleName, "entry");
}

/**
 * @tc.number: RouterMapMerge_0004
 * @tc.name: test merge function for router map
 * @tc.desc: 1.RouterMapMerge
 */
HWTEST_F(BmsBundleNavigationTest, RouterMapMerge_0004, Function | SmallTest | Level0)
{
    ASSERT_EQ(routerArrayTest_.size(), ROUTER_ITEM_TEST_SIZE);
    BundleInfo info;
    HapModuleInfo hapModuleInfoEntry;
    hapModuleInfoEntry.moduleName = "entry";
    hapModuleInfoEntry.moduleType = ModuleType::ENTRY;
    hapModuleInfoEntry.routerArray.emplace_back(routerArrayTest_[0]);
    info.hapModuleInfos.emplace_back(hapModuleInfoEntry);

    HapModuleInfo hapModuleInfoLibrary;
    hapModuleInfoLibrary.moduleName = "library";
    hapModuleInfoLibrary.moduleType = ModuleType::SHARED;
    hapModuleInfoLibrary.routerArray.emplace_back(routerArrayTest_[2]);
    info.hapModuleInfos.emplace_back(hapModuleInfoLibrary);
    RouterMapHelper::MergeRouter(info);
    ASSERT_EQ(info.routerArray.size(), 1);
    EXPECT_EQ(info.routerArray[0].moduleName, "entry");
}

/**
 * @tc.number: RouterMapMerge_0005
 * @tc.name: test merge function for router map
 * @tc.desc: 1.RouterMapMerge
 */
HWTEST_F(BmsBundleNavigationTest, RouterMapMerge_0005, Function | SmallTest | Level0)
{
    ASSERT_EQ(routerArrayTest_.size(), ROUTER_ITEM_TEST_SIZE);
    BundleInfo info;
    HapModuleInfo hapModuleInfoFeature;
    hapModuleInfoFeature.moduleName = "feature";
    hapModuleInfoFeature.moduleType = ModuleType::FEATURE;
    hapModuleInfoFeature.routerArray.emplace_back(routerArrayTest_[1]);
    info.hapModuleInfos.emplace_back(hapModuleInfoFeature);

    HapModuleInfo hapModuleInfoLibrary;
    hapModuleInfoLibrary.moduleName = "library";
    hapModuleInfoLibrary.moduleType = ModuleType::SHARED;
    hapModuleInfoLibrary.routerArray.emplace_back(routerArrayTest_[2]);
    info.hapModuleInfos.emplace_back(hapModuleInfoLibrary);
    RouterMapHelper::MergeRouter(info);
    ASSERT_EQ(info.routerArray.size(), 1);
    EXPECT_EQ(info.routerArray[0].moduleName, "feature");
}

/**
 * @tc.number: RouterMapMerge_0006
 * @tc.name: test merge function for router map
 * @tc.desc: 1.RouterMapMerge
 */
HWTEST_F(BmsBundleNavigationTest, RouterMapMerge_0006, Function | SmallTest | Level0)
{
    ASSERT_EQ(routerArrayTest_.size(), ROUTER_ITEM_TEST_SIZE);
    BundleInfo info;
    HapModuleInfo hapModuleInfoEntry;
    hapModuleInfoEntry.moduleName = "entry";
    hapModuleInfoEntry.moduleType = ModuleType::ENTRY;
    hapModuleInfoEntry.routerArray.emplace_back(routerArrayTest_[0]);
    hapModuleInfoEntry.routerArray.emplace_back(routerArrayTest_[3]);
    info.hapModuleInfos.emplace_back(hapModuleInfoEntry);

    RouterMapHelper::MergeRouter(info);
    ASSERT_EQ(info.routerArray.size(), 1);
    EXPECT_EQ(info.routerArray[0].moduleName, "entry");
    EXPECT_EQ(info.routerArray[0].ohmurl,
        "ohmurlTest&com.example.test&entry&entry/resources/base/profile&1.2.2");
}

/**
 * @tc.number: RouterMapMerge_0007
 * @tc.name: test merge function for router map
 * @tc.desc: 1.RouterMapMerge
 */
HWTEST_F(BmsBundleNavigationTest, RouterMapMerge_0007, Function | SmallTest | Level0)
{
    ASSERT_EQ(routerArrayTest_.size(), ROUTER_ITEM_TEST_SIZE);
    BundleInfo info;
    HapModuleInfo hapModuleInfoEntry;
    hapModuleInfoEntry.moduleName = "entry";
    hapModuleInfoEntry.moduleType = ModuleType::ENTRY;
    hapModuleInfoEntry.routerArray.emplace_back(routerArrayTest_[5]);
    info.hapModuleInfos.emplace_back(hapModuleInfoEntry);

    HapModuleInfo hapModuleInfoFeature;
    hapModuleInfoFeature.moduleName = "feature";
    hapModuleInfoFeature.moduleType = ModuleType::FEATURE;
    hapModuleInfoFeature.routerArray.emplace_back(routerArrayTest_[6]);
    info.hapModuleInfos.emplace_back(hapModuleInfoFeature);

    RouterMapHelper::MergeRouter(info);
    ASSERT_EQ(info.routerArray.size(), 1);
    EXPECT_EQ(info.routerArray[0].moduleName, "entry");
    EXPECT_EQ(info.routerArray[0].ohmurl, "ohmurlTest");
}

/**
 * @tc.number: RouterMapMerge_0008
 * @tc.name: test merge function for router map
 * @tc.desc: 1.RouterMapMerge
 */
HWTEST_F(BmsBundleNavigationTest, RouterMapMerge_0008, Function | SmallTest | Level0)
{
    ASSERT_EQ(routerArrayTest_.size(), ROUTER_ITEM_TEST_SIZE);
    BundleInfo info;
    HapModuleInfo hapModuleInfoEntry;
    hapModuleInfoEntry.moduleName = "entry";
    hapModuleInfoEntry.moduleType = ModuleType::ENTRY;
    hapModuleInfoEntry.routerArray.emplace_back(routerArrayTest_[5]);
    info.hapModuleInfos.emplace_back(hapModuleInfoEntry);

    HapModuleInfo hapModuleInfoLibrary;
    hapModuleInfoLibrary.moduleName = "library";
    hapModuleInfoLibrary.moduleType = ModuleType::SHARED;
    hapModuleInfoLibrary.routerArray.emplace_back(routerArrayTest_[8]);
    info.hapModuleInfos.emplace_back(hapModuleInfoLibrary);

    RouterMapHelper::MergeRouter(info);
    ASSERT_EQ(info.routerArray.size(), 1);
    EXPECT_EQ(info.routerArray[0].moduleName, "entry");
    EXPECT_EQ(info.routerArray[0].ohmurl, "ohmurlTest");
}

/**
 * @tc.number: RouterMapMerge_0009
 * @tc.name: test merge function for router map
 * @tc.desc: 1.RouterMapMerge
 */
HWTEST_F(BmsBundleNavigationTest, RouterMapMerge_0009, Function | SmallTest | Level0)
{
    ASSERT_EQ(routerArrayTest_.size(), ROUTER_ITEM_TEST_SIZE);
    BundleInfo info;
    HapModuleInfo hapModuleInfoFeature;
    hapModuleInfoFeature.moduleName = "feature";
    hapModuleInfoFeature.moduleType = ModuleType::FEATURE;
    hapModuleInfoFeature.routerArray.emplace_back(routerArrayTest_[6]);
    info.hapModuleInfos.emplace_back(hapModuleInfoFeature);

    HapModuleInfo hapModuleInfoLibrary;
    hapModuleInfoLibrary.moduleName = "library";
    hapModuleInfoLibrary.moduleType = ModuleType::SHARED;
    hapModuleInfoLibrary.routerArray.emplace_back(routerArrayTest_[8]);
    info.hapModuleInfos.emplace_back(hapModuleInfoLibrary);

    RouterMapHelper::MergeRouter(info);
    ASSERT_EQ(info.routerArray.size(), 1);
    EXPECT_EQ(info.routerArray[0].moduleName, "feature");
    EXPECT_EQ(info.routerArray[0].ohmurl, "ohmurlTest");
}

/**
 * @tc.number: RouterMapMerge_0010
 * @tc.name: test merge function for router map
 * @tc.desc: 1.RouterMapMerge
 */
HWTEST_F(BmsBundleNavigationTest, RouterMapMerge_0010, Function | SmallTest | Level0)
{
    ASSERT_EQ(routerArrayTest_.size(), ROUTER_ITEM_TEST_SIZE);
    BundleInfo info;
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "entry";
    hapModuleInfo.routerArray.emplace_back(routerArrayTest_[0]);
    hapModuleInfo.routerArray.emplace_back(routerArrayTest_[9]);
    info.hapModuleInfos.emplace_back(hapModuleInfo);
    RouterMapHelper::MergeRouter(info);
    EXPECT_EQ(info.routerArray.size(), 2);
}

/**
 * @tc.number: RouterMapMerge_0011
 * @tc.name: test merge function for router map
 * @tc.desc: 1.RouterMapMerge
 */
HWTEST_F(BmsBundleNavigationTest, RouterMapMerge_0011, Function | SmallTest | Level0)
{
    ASSERT_EQ(routerArrayTest_.size(), ROUTER_ITEM_TEST_SIZE);
    BundleInfo info;
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "entry";
    hapModuleInfo.routerArray.emplace_back(routerArrayTest_[0]);
    hapModuleInfo.routerArray.emplace_back(routerArrayTest_[9]);
    hapModuleInfo.routerArray.emplace_back(routerArrayTest_[11]);
    info.hapModuleInfos.emplace_back(hapModuleInfo);

    HapModuleInfo hapModuleInfoFeature;
    hapModuleInfoFeature.moduleName = "feature";
    hapModuleInfoFeature.moduleType = ModuleType::FEATURE;
    hapModuleInfoFeature.routerArray.emplace_back(routerArrayTest_[10]);
    info.hapModuleInfos.emplace_back(hapModuleInfoFeature);

    RouterMapHelper::MergeRouter(info);
    EXPECT_EQ(info.routerArray.size(), 4);
}

/**
 * @tc.number: RouterMapMerge_0012
 * @tc.name: test merge function for router map
 * @tc.desc: 1.RouterMapMerge
 */
HWTEST_F(BmsBundleNavigationTest, RouterMapMerge_0012, Function | SmallTest | Level0)
{
    ASSERT_EQ(routerArrayTest_.size(), ROUTER_ITEM_TEST_SIZE);
    BundleInfo info;
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = "entry";
    hapModuleInfo.routerArray.emplace_back(routerArrayTest_[0]);
    hapModuleInfo.routerArray.emplace_back(routerArrayTest_[3]);
    hapModuleInfo.routerArray.emplace_back(routerArrayTest_[4]);
    hapModuleInfo.routerArray.emplace_back(routerArrayTest_[5]);
    hapModuleInfo.routerArray.emplace_back(routerArrayTest_[9]);
    hapModuleInfo.routerArray.emplace_back(routerArrayTest_[11]);
    info.hapModuleInfos.emplace_back(hapModuleInfo);

    HapModuleInfo hapModuleInfoFeature;
    hapModuleInfoFeature.moduleName = "feature";
    hapModuleInfoFeature.moduleType = ModuleType::FEATURE;
    hapModuleInfoFeature.routerArray.emplace_back(routerArrayTest_[1]);
    hapModuleInfoFeature.routerArray.emplace_back(routerArrayTest_[6]);
    hapModuleInfoFeature.routerArray.emplace_back(routerArrayTest_[10]);
    info.hapModuleInfos.emplace_back(hapModuleInfoFeature);

    HapModuleInfo hapModuleInfoLibrary;
    hapModuleInfoLibrary.moduleName = "library";
    hapModuleInfoLibrary.moduleType = ModuleType::SHARED;
    hapModuleInfoLibrary.routerArray.emplace_back(routerArrayTest_[2]);
    hapModuleInfoLibrary.routerArray.emplace_back(routerArrayTest_[8]);
    info.hapModuleInfos.emplace_back(hapModuleInfoLibrary);

    RouterMapHelper::MergeRouter(info);
    EXPECT_EQ(info.routerArray.size(), 4);
}

/**
 * @tc.number: RouterMapMerge_0013
 * @tc.name: test merge function for router map
 * @tc.desc: 1.RouterMapMerge
 */
HWTEST_F(BmsBundleNavigationTest, RouterMapMerge_0013, Function | SmallTest | Level0)
{
    ASSERT_EQ(routerArrayTest_.size(), ROUTER_ITEM_TEST_SIZE);

    std::string a = "-1";
    std::string b = "-1";
    int32_t ret = RouterMapHelper::CompareIdentifiers(a, b);
    EXPECT_EQ(ret, 1);

    a = "2";
    b = "1";
    ret = RouterMapHelper::CompareIdentifiers(a, b);
    EXPECT_EQ(ret, 1);

    a = "2";
    b = "1";
    ret = RouterMapHelper::CompareIdentifiers(a, b);
    EXPECT_EQ(ret, 1);

    a = "1";
    b = "0";
    ret = RouterMapHelper::CompareIdentifiers(a, b);
    EXPECT_EQ(ret, 1);

    a = "0";
    b = "1";
    ret = RouterMapHelper::CompareIdentifiers(a, b);
    EXPECT_EQ(ret, -1);

    a = "1";
    b = "2";
    ret = RouterMapHelper::CompareIdentifiers(a, b);
    EXPECT_EQ(ret, -1);

    a = "2";
    b = "1";
    ret = RouterMapHelper::CompareIdentifiers(a, b);
    EXPECT_EQ(ret, 1);

    a = "2";
    b = "2";
    ret = RouterMapHelper::CompareIdentifiers(a, b);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: IsRegexMatch_0001
 * @tc.name: test IsRegexMatch function for router map
 * @tc.desc: 1.IsRegexMatch
 */
HWTEST_F(BmsBundleNavigationTest, IsRegexMatch_0001, Function | SmallTest | Level0)
{
    const char *pattern = "";
    std::string str = "";
    bool result = RouterMapHelper::IsRegexMatch(str, pattern);
    EXPECT_TRUE(result);

    pattern = "[";
    str = "test";
    result = RouterMapHelper::IsRegexMatch(str, pattern);
    EXPECT_FALSE(result);

    pattern = "a.*b";
    str = "abc";
    result = RouterMapHelper::IsRegexMatch(str, pattern);
    EXPECT_TRUE(result);

    pattern = "a.*b";
    str = "acd";
    result = RouterMapHelper::IsRegexMatch(str, pattern);
    EXPECT_FALSE(result);

    pattern = ".";
    str = "a";
    result = RouterMapHelper::IsRegexMatch(str, pattern);
    EXPECT_TRUE(result);

    pattern = "^a";
    str = "a\nb";
    result = RouterMapHelper::IsRegexMatch(str, pattern);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: RouterDataStorageRdb_0001
 * @tc.name: test merge function for router map
 * @tc.desc: 1.UpdateRouterInfo
 */
HWTEST_F(BmsBundleNavigationTest, RouterDataStorageRdb_0001, Function | SmallTest | Level0)
{
    auto routerDataStorageRdb = std::make_shared<RouterDataStorageRdb>();
    ASSERT_NE(routerDataStorageRdb, nullptr);

    routerDataStorageRdb->rdbDataManager_ = nullptr;
    std::string bundleName;
    std::map<std::string, std::string> routerInfoMap;
    auto ret = routerDataStorageRdb->UpdateRouterInfo(bundleName, routerInfoMap);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RouterDataStorageRdb_0002
 * @tc.name: test merge function for router map
 * @tc.desc: 1.UpdateRouterInfo
 */
HWTEST_F(BmsBundleNavigationTest, RouterDataStorageRdb_0002, Function | SmallTest | Level0)
{
    auto routerDataStorageRdb = std::make_shared<RouterDataStorageRdb>();
    ASSERT_NE(routerDataStorageRdb, nullptr);

    std::string bundleName = "";
    std::map<std::string, std::string> routerInfoMap;
    auto ret = routerDataStorageRdb->UpdateRouterInfo(bundleName, routerInfoMap);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RouterDataStorageRdb_0003
 * @tc.name: test merge function for router map
 * @tc.desc: 1.UpdateRouterInfo
 */
HWTEST_F(BmsBundleNavigationTest, RouterDataStorageRdb_0003, Function | SmallTest | Level0)
{
    auto routerDataStorageRdb = std::make_shared<RouterDataStorageRdb>();
    ASSERT_NE(routerDataStorageRdb, nullptr);

    std::string bundleName = "xxxx";
    std::map<std::string, std::string> routerInfoMap;
    routerInfoMap["testKey"] = "testValue";
    auto ret = routerDataStorageRdb->UpdateRouterInfo(bundleName, routerInfoMap);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RouterDataStorageRdb_0004
 * @tc.name: test merge function for router map
 * @tc.desc: 1.RouterMapMerge
 */
HWTEST_F(BmsBundleNavigationTest, RouterDataStorageRdb_0004, Function | SmallTest | Level0)
{
    auto routerDataStorageRdb = std::make_shared<RouterDataStorageRdb>();
    ASSERT_NE(routerDataStorageRdb, nullptr);

    routerDataStorageRdb->rdbDataManager_ = nullptr;
    std::string bundleName;
    std::string moduleName;
    std::vector<RouterItem> routerInfos;
    auto ret = routerDataStorageRdb->GetRouterInfo(bundleName, moduleName, routerInfos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RouterDataStorageRdb_0005
 * @tc.name: test merge function for router map
 * @tc.desc: 1.RouterMapMerge
 */
HWTEST_F(BmsBundleNavigationTest, RouterDataStorageRdb_0005, Function | SmallTest | Level0)
{
    auto routerDataStorageRdb = std::make_shared<RouterDataStorageRdb>();
    ASSERT_NE(routerDataStorageRdb, nullptr);

    std::string bundleName;
    std::string moduleName;
    std::vector<RouterItem> routerInfos;
    auto ret = routerDataStorageRdb->GetRouterInfo(bundleName, moduleName, routerInfos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RouterDataStorageRdb_0006
 * @tc.name: test merge function for router map
 * @tc.desc: 1.GetAllBundleNames
 */
HWTEST_F(BmsBundleNavigationTest, RouterDataStorageRdb_0006, Function | SmallTest | Level0)
{
    auto routerDataStorageRdb = std::make_shared<RouterDataStorageRdb>();
    ASSERT_NE(routerDataStorageRdb, nullptr);

    routerDataStorageRdb->rdbDataManager_ = nullptr;
    std::set<std::string> bundleNames;
    routerDataStorageRdb->GetAllBundleNames(bundleNames);
    EXPECT_TRUE(bundleNames.empty());
}

/**
 * @tc.number: RouterDataStorageRdb_0007
 * @tc.name: test merge function for router map
 * @tc.desc: 1.GetAllBundleNames
 */
HWTEST_F(BmsBundleNavigationTest, RouterDataStorageRdb_0007, Function | SmallTest | Level0)
{
    auto routerDataStorageRdb = std::make_shared<RouterDataStorageRdb>();
    ASSERT_NE(routerDataStorageRdb, nullptr);

    std::set<std::string> bundleNames;
    routerDataStorageRdb->GetAllBundleNames(bundleNames);
    EXPECT_TRUE(bundleNames.empty());
}

/**
 * @tc.number: RouterDataStorageRdb_0008
 * @tc.name: test merge function for router map
 * @tc.desc: 1.DeleteRouterInfo
 */
HWTEST_F(BmsBundleNavigationTest, RouterDataStorageRdb_0008, Function | SmallTest | Level0)
{
    auto routerDataStorageRdb = std::make_shared<RouterDataStorageRdb>();
    ASSERT_NE(routerDataStorageRdb, nullptr);

    routerDataStorageRdb->rdbDataManager_ = nullptr;
    std::string bundleName;
    auto ret = routerDataStorageRdb->DeleteRouterInfo(bundleName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RouterDataStorageRdb_0009
 * @tc.name: test merge function for router map
 * @tc.desc: 1.DeleteRouterInfo
 */
HWTEST_F(BmsBundleNavigationTest, RouterDataStorageRdb_0009, Function | SmallTest | Level0)
{
    auto routerDataStorageRdb = std::make_shared<RouterDataStorageRdb>();
    ASSERT_NE(routerDataStorageRdb, nullptr);

    routerDataStorageRdb->rdbDataManager_ = nullptr;
    std::string bundleName;
    std::string moduleName;
    auto ret = routerDataStorageRdb->DeleteRouterInfo(bundleName, moduleName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: UninstallDataMgrStorageRdb_0001
 * @tc.name: test function for UninstallDataMgrStorageRdb
 * @tc.desc: 1.UpdateUninstallBundleInfo
 */
HWTEST_F(BmsBundleNavigationTest, UninstallDataMgrStorageRdb_0001, Function | SmallTest | Level0)
{
    auto uninstallDataMgrStorageRdb = std::make_shared<UninstallDataMgrStorageRdb>();
    ASSERT_NE(uninstallDataMgrStorageRdb, nullptr);

    uninstallDataMgrStorageRdb->rdbDataManager_ = nullptr;
    std::string bundleName;
    UninstallBundleInfo uninstallbundleInfo;
    auto ret = uninstallDataMgrStorageRdb->UpdateUninstallBundleInfo(bundleName, uninstallbundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: UninstallDataMgrStorageRdb_0002
 * @tc.name: test function for UninstallDataMgrStorageRdb
 * @tc.desc: 1.UpdateUninstallBundleInfo
 */
HWTEST_F(BmsBundleNavigationTest, UninstallDataMgrStorageRdb_0002, Function | SmallTest | Level0)
{
    auto uninstallDataMgrStorageRdb = std::make_shared<UninstallDataMgrStorageRdb>();
    ASSERT_NE(uninstallDataMgrStorageRdb, nullptr);

    std::string bundleName;
    UninstallBundleInfo uninstallbundleInfo;
    auto ret = uninstallDataMgrStorageRdb->UpdateUninstallBundleInfo(bundleName, uninstallbundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: UninstallDataMgrStorageRdb_0003
 * @tc.name: test function for UninstallDataMgrStorageRdb
 * @tc.desc: 1.GetUninstallBundleInfo
 */
HWTEST_F(BmsBundleNavigationTest, UninstallDataMgrStorageRdb_0003, Function | SmallTest | Level0)
{
    auto uninstallDataMgrStorageRdb = std::make_shared<UninstallDataMgrStorageRdb>();
    ASSERT_NE(uninstallDataMgrStorageRdb, nullptr);
    uninstallDataMgrStorageRdb->rdbDataManager_ = nullptr;

    std::string bundleName;
    UninstallBundleInfo uninstallbundleInfo;
    auto ret = uninstallDataMgrStorageRdb->GetUninstallBundleInfo(bundleName, uninstallbundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: UninstallDataMgrStorageRdb_0004
 * @tc.name: test function for UninstallDataMgrStorageRdb
 * @tc.desc: 1.GetUninstallBundleInfo
 */
HWTEST_F(BmsBundleNavigationTest, UninstallDataMgrStorageRdb_0004, Function | SmallTest | Level0)
{
    auto uninstallDataMgrStorageRdb = std::make_shared<UninstallDataMgrStorageRdb>();
    ASSERT_NE(uninstallDataMgrStorageRdb, nullptr);

    std::string bundleName;
    UninstallBundleInfo uninstallbundleInfo;
    auto ret = uninstallDataMgrStorageRdb->GetUninstallBundleInfo(bundleName, uninstallbundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: UninstallDataMgrStorageRdb_0005
 * @tc.name: test function for UninstallDataMgrStorageRdb
 * @tc.desc: 1.GetAllUninstallBundleInfo
 */
HWTEST_F(BmsBundleNavigationTest, UninstallDataMgrStorageRdb_0005, Function | SmallTest | Level0)
{
    auto uninstallDataMgrStorageRdb = std::make_shared<UninstallDataMgrStorageRdb>();
    ASSERT_NE(uninstallDataMgrStorageRdb, nullptr);
    uninstallDataMgrStorageRdb->rdbDataManager_ = nullptr;

    std::map<std::string, UninstallBundleInfo> uninstallBundleInfos;
    auto ret = uninstallDataMgrStorageRdb->GetAllUninstallBundleInfo(uninstallBundleInfos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: UninstallDataMgrStorageRdb_0006
 * @tc.name: test function for UninstallDataMgrStorageRdb
 * @tc.desc: 1.GetAllUninstallBundleInfo
 */
HWTEST_F(BmsBundleNavigationTest, UninstallDataMgrStorageRdb_0006, Function | SmallTest | Level0)
{
    auto uninstallDataMgrStorageRdb = std::make_shared<UninstallDataMgrStorageRdb>();
    ASSERT_NE(uninstallDataMgrStorageRdb, nullptr);
    uninstallDataMgrStorageRdb->rdbDataManager_ = nullptr;

    std::map<std::string, std::string> datas;
    std::map<std::string, UninstallBundleInfo> uninstallBundleInfos;
    uninstallDataMgrStorageRdb->TransformStrToInfo(datas, uninstallBundleInfos);
    EXPECT_TRUE(datas.empty());
    EXPECT_TRUE(uninstallBundleInfos.empty());
}

/**
 * @tc.number: UninstallDataMgrStorageRdb_0007
 * @tc.name: test function for UninstallDataMgrStorageRdb
 * @tc.desc: 1.DeleteUninstallBundleInfo
 */
HWTEST_F(BmsBundleNavigationTest, UninstallDataMgrStorageRdb_0007, Function | SmallTest | Level0)
{
    auto uninstallDataMgrStorageRdb = std::make_shared<UninstallDataMgrStorageRdb>();
    ASSERT_NE(uninstallDataMgrStorageRdb, nullptr);
    uninstallDataMgrStorageRdb->rdbDataManager_ = nullptr;

    std::string bundleName;
    auto ret = uninstallDataMgrStorageRdb->DeleteUninstallBundleInfo(bundleName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: UninstallDataMgrStorageRdb_0008
 * @tc.name: test function for UninstallDataMgrStorageRdb
 * @tc.desc: 1.DeleteUninstallBundleInfo
 */
HWTEST_F(BmsBundleNavigationTest, UninstallDataMgrStorageRdb_0008, Function | SmallTest | Level0)
{
    auto uninstallDataMgrStorageRdb = std::make_shared<UninstallDataMgrStorageRdb>();
    ASSERT_NE(uninstallDataMgrStorageRdb, nullptr);

    std::string bundleName;
    auto ret = uninstallDataMgrStorageRdb->DeleteUninstallBundleInfo(bundleName);
    EXPECT_FALSE(ret);
}
} // OHOS