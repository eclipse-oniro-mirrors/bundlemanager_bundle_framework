/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF. ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "installd/installd_operator.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string VALID_BUNDLE_NAME_1 = "com.example.test";
}  // namespace

class BmsBundleInstallParametersTest : public testing::Test {
public:
    BmsBundleInstallParametersTest();
    ~BmsBundleInstallParametersTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsBundleInstallParametersTest::BmsBundleInstallParametersTest()
{}

BmsBundleInstallParametersTest::~BmsBundleInstallParametersTest()
{}

void BmsBundleInstallParametersTest::SetUpTestCase()
{}

void BmsBundleInstallParametersTest::TearDownTestCase()
{}

void BmsBundleInstallParametersTest::SetUp()
{}

void BmsBundleInstallParametersTest::TearDown()
{}


/**
 * @tc.number: CheckBundleNameIsValid_0100
 * @tc.name: test CheckBundleNameIsValid with valid bundle name
 * @tc.desc: 1. test valid bundle name with dots and underscores
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckBundleNameIsValid_0100, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidBundleName(VALID_BUNDLE_NAME_1);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckBundleNameIsValid_0200
 * @tc.name: test CheckBundleNameIsValid with empty bundle name
 * @tc.desc: 1. test empty bundle name should return false
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckBundleNameIsValid_0200, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidBundleName("");
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckBundleNameIsValid_0300
 * @tc.name: test CheckBundleNameIsValid with too short bundle name
 * @tc.desc: 1. test bundle name less than 7 characters should return false
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckBundleNameIsValid_0300, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidBundleName("a.b.c");
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckBundleNameIsValid_0400
 * @tc.name: test CheckBundleNameIsValid with too long bundle name
 * @tc.desc: 1. test bundle name more than 128 characters should return false
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckBundleNameIsValid_0400, Function | SmallTest | Level0)
{
    std::string longBundleName(129, 'a');
    bool result = InstalldOperator::IsValidBundleName(longBundleName);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckBundleNameIsValid_0500
 * @tc.name: test CheckBundleNameIsValid with invalid first character
 * @tc.desc: 1. test bundle name starting with number should return false
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckBundleNameIsValid_0500, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidBundleName("1com.example.test");
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckBundleNameIsValid_0600
 * @tc.name: test CheckBundleNameIsValid with invalid characters
 * @tc.desc: 1. test bundle name with invalid characters should return false
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckBundleNameIsValid_0600, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidBundleName("com/example/test");
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckBundleNameIsValid_0700
 * @tc.name: test CheckBundleNameIsValid with clone bundle name
 * @tc.desc: 1. test valid clone bundle name format
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckBundleNameIsValid_0700, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidBundleName("+clone-1+com.example.test");
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckBundleNameIsValid_0800
 * @tc.name: test CheckBundleNameIsValid with invalid clone bundle name
 * @tc.desc: 1. test invalid clone bundle name without plus sign
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckBundleNameIsValid_0800, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidBundleName("+clone-1com.example.test");
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckBundleNameIsValid_0900
 * @tc.name: test CheckBundleNameIsValid with sandbox bundle name
 * @tc.desc: 1. test valid sandbox bundle name format
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckBundleNameIsValid_0900, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidBundleName("1_com.example.test");
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckBundleNameIsValid_1000
 * @tc.name: test CheckBundleNameIsValid with bundle name containing dots and underscores
 * @tc.desc: 1. test valid bundle name with dots and underscores
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckBundleNameIsValid_1000, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidBundleName("com.example_test.app");
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckUserIdIsValid_0100
 * @tc.name: test CheckUserIdIsValid with valid user id
 * @tc.desc: 1. test valid user id should return true
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckUserIdIsValid_0100, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidUserId(100);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckUserIdIsValid_0200
 * @tc.name: test CheckUserIdIsValid with zero user id
 * @tc.desc: 1. test zero user id should return true
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckUserIdIsValid_0200, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidUserId(0);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckUserIdIsValid_0300
 * @tc.name: test CheckUserIdIsValid with negative user id
 * @tc.desc: 1. test negative user id should return false
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckUserIdIsValid_0300, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidUserId(-1);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckUidIsValid_0100
 * @tc.name: test CheckUidIsValid with valid uid
 * @tc.desc: 1. test valid uid should return true
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckUidIsValid_0100, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidUid(10000);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckUidIsValid_0200
 * @tc.name: test CheckUidIsValid with zero uid
 * @tc.desc: 1. test zero uid should return true
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckUidIsValid_0200, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidUid(0);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckUidIsValid_0300
 * @tc.name: test CheckUidIsValid with negative uid
 * @tc.desc: 1. test negative uid should return false
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckUidIsValid_0300, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidUid(-1);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckAppIndexIsValid_0100
 * @tc.name: test CheckAppIndexIsValid with valid app index
 * @tc.desc: 1. test valid app index should return true
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckAppIndexIsValid_0100, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidAppIndex(100);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckAppIndexIsValid_0200
 * @tc.name: test CheckAppIndexIsValid with zero app index
 * @tc.desc: 1. test zero app index should return true
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckAppIndexIsValid_0200, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidAppIndex(0);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckAppIndexIsValid_0300
 * @tc.name: test CheckAppIndexIsValid with maximum valid app index
 * @tc.desc: 1. test maximum valid app index should return true
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckAppIndexIsValid_0300, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidAppIndex(1000);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckAppIndexIsValid_0400
 * @tc.name: test CheckAppIndexIsValid with negative app index
 * @tc.desc: 1. test negative app index should return false
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckAppIndexIsValid_0400, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidAppIndex(-1);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckAppIndexIsValid_0500
 * @tc.name: test CheckAppIndexIsValid with app index greater than maximum
 * @tc.desc: 1. test app index greater than maximum should return false
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckAppIndexIsValid_0500, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidAppIndex(1001);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckAplIsValid_0100
 * @tc.name: test CheckAplIsValid with normal apl
 * @tc.desc: 1. test normal apl should return true
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckAplIsValid_0100, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidApl("normal");
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckAplIsValid_0200
 * @tc.name: test CheckAplIsValid with system_basic apl
 * @tc.desc: 1. test system_basic apl should return true
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckAplIsValid_0200, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidApl("system_basic");
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckAplIsValid_0300
 * @tc.name: test CheckAplIsValid with system_core apl
 * @tc.desc: 1. test system_core apl should return true
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckAplIsValid_0300, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidApl("system_core");
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckAplIsValid_0400
 * @tc.name: test CheckAplIsValid with invalid apl
 * @tc.desc: 1. test invalid apl should return false
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckAplIsValid_0400, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidApl("invalid_apl");
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckAplIsValid_0500
 * @tc.name: test CheckAplIsValid with empty apl
 * @tc.desc: 1. test empty apl should return false
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckAplIsValid_0500, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidApl("");
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckPathByBundleDirSceneIsValid_0100
 * @tc.name: test CheckPathByBundleDirSceneIsValid with SET_DIR_APL scene
 * @tc.desc: 1. test valid path for SET_DIR_APL scene
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckPathByBundleDirSceneIsValid_0100, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidPathByBundleDirScene(
        BundleDirScene::SET_DIR_APL, "/data/app/el1/bundle/public");
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckPathByBundleDirSceneIsValid_0200
 * @tc.name: test CheckPathByBundleDirSceneIsValid with EXTRACT_HNP_FILES scene
 * @tc.desc: 1. test valid path for EXTRACT_HNP_FILES scene
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckPathByBundleDirSceneIsValid_0200, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidPathByBundleDirScene(
        BundleDirScene::EXTRACT_HNP_FILES, "/data/app/el1/bundle/public/test");
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckPathByBundleDirSceneIsValid_0300
 * @tc.name: test CheckPathByBundleDirSceneIsValid with SET_FILE_CON_FORCE scene
 * @tc.desc: 1. test valid path for SET_FILE_CON_FORCE scene
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckPathByBundleDirSceneIsValid_0300, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidPathByBundleDirScene(
        BundleDirScene::SET_FILE_CON_FORCE, "/data/app/el1/bundle/public");
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckPathByBundleDirSceneIsValid_0400
 * @tc.name: test CheckPathByBundleDirSceneIsValid with EXTRACT_DRIVER_SO_FILES scene
 * @tc.desc: 1. test valid path for EXTRACT_DRIVER_SO_FILES scene
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckPathByBundleDirSceneIsValid_0400, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidPathByBundleDirScene(
        BundleDirScene::EXTRACT_DRIVER_SO_FILES, "/data/app/el1/bundle/public/test");
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckPathByBundleDirSceneIsValid_0500
 * @tc.name: test CheckPathByBundleDirSceneIsValid with invalid path
 * @tc.desc: 1. test invalid path with .. should return false
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckPathByBundleDirSceneIsValid_0500, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidPathByBundleDirScene(
        BundleDirScene::SET_DIR_APL, "/data/app/el1/../bundle");
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckPathByBundleDirSceneIsValid_0600
 * @tc.name: test CheckPathByBundleDirSceneIsValid with mismatched scene and path
 * @tc.desc: 1. test path not matching scene prefix should return false
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckPathByBundleDirSceneIsValid_0600, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidPathByBundleDirScene(
        BundleDirScene::SET_DIR_APL, "/tmp/test");
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckUuidIsValid_0100
 * @tc.name: test CheckUuidIsValid with valid uuid
 * @tc.desc: 1. test valid uuid should return true
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckUuidIsValid_0100, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidUuid("550e8400-e29b-41d4-a716-446655440000");
    EXPECT_TRUE(result);
}

/**
 * @tc.number: CheckUuidIsValid_0200
 * @tc.name: test CheckUuidIsValid with empty uuid
 * @tc.desc: 1. test empty uuid should return false
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckUuidIsValid_0200, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidUuid("");
    EXPECT_FALSE(result);
}

/**
 * @tc.number: CheckUuidIsValid_0300
 * @tc.name: test CheckUuidIsValid with invalid uuid
 * @tc.desc: 1. test invalid uuid with .. should return false
 */
HWTEST_F(BmsBundleInstallParametersTest, CheckUuidIsValid_0300, Function | SmallTest | Level0)
{
    bool result = InstalldOperator::IsValidUuid("../test");
    EXPECT_FALSE(result);
}
}  // namespace OHOS