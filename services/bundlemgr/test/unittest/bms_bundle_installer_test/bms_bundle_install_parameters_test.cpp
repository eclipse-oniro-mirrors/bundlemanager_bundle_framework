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

#include "bundle_storage_stats.h"
#include "installd/installd_host_impl.h"
#include "installd/installd_operator.h"
#include "ipc/encryption_param.h"
#include "ipc/install_hnp_param.h"

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

/**
 * @tc.number: InstalldHostImpl_AddUserDirDeleteDfx_0100
 * @tc.name: test AddUserDirDeleteDfx with valid userId
 * @tc.desc: 1. test valid userId parameter
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_AddUserDirDeleteDfx_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.AddUserDirDeleteDfx(100);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_AddUserDirDeleteDfx_0200
 * @tc.name: test AddUserDirDeleteDfx with invalid userId
 * @tc.desc: 1. test negative userId should return param error
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_AddUserDirDeleteDfx_0200, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.AddUserDirDeleteDfx(-1);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CleanBundleDataDirByName_0100
 * @tc.name: test CleanBundleDataDirByName with valid parameters
 * @tc.desc: 1. test valid bundleName, userId, and appIndex
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CleanBundleDataDirByName_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.CleanBundleDataDirByName("com.example.test", 100, 0, false);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_CleanBundleDataDirByName_0200
 * @tc.name: test CleanBundleDataDirByName with invalid bundleName
 * @tc.desc: 1. test invalid bundleName should return param error
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CleanBundleDataDirByName_0200, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.CleanBundleDataDirByName("", 100, 0, false);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CleanBundleDataDirByName_0300
 * @tc.name: test CleanBundleDataDirByName with invalid userId
 * @tc.desc: 1. test negative userId should return param error
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CleanBundleDataDirByName_0300, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.CleanBundleDataDirByName("com.example.test", -1, 0, false);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CleanBundleDataDirByName_0400
 * @tc.name: test CleanBundleDataDirByName with invalid appIndex
 * @tc.desc: 1. test invalid appIndex should return param error
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CleanBundleDataDirByName_0400, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.CleanBundleDataDirByName("com.example.test", 100, -1, false);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_DeleteDataGroupDirs_0100
 * @tc.name: test DeleteDataGroupDirs with valid parameters
 * @tc.desc: 1. test valid userId and uuidList
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_DeleteDataGroupDirs_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> uuidList = {"550e8400-e29b-41d4-a716-446655440000"};
    ErrCode result = impl.DeleteDataGroupDirs(uuidList, 100);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_DeleteDataGroupDirs_0200
 * @tc.name: test DeleteDataGroupDirs with empty uuidList
 * @tc.desc: 1. test empty uuidList should return param error
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_DeleteDataGroupDirs_0200, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> uuidList;
    ErrCode result = impl.DeleteDataGroupDirs(uuidList, 100);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_DeleteDataGroupDirs_0300
 * @tc.name: test DeleteDataGroupDirs with invalid userId
 * @tc.desc: 1. test negative userId should return param error
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_DeleteDataGroupDirs_0300, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> uuidList = {"550e8400-e29b-41d4-a716-446655440000"};
    ErrCode result = impl.DeleteDataGroupDirs(uuidList, -1);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_DeleteDataGroupDirs_0400
 * @tc.name: test DeleteDataGroupDirs with invalid uuid
 * @tc.desc: 1. test invalid uuid should return param error
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_DeleteDataGroupDirs_0400, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> uuidList = {"../invalid"};
    ErrCode result = impl.DeleteDataGroupDirs(uuidList, 100);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CreateDataGroupDirs_0100
 * @tc.name: test CreateDataGroupDirs with invalid userId
 * @tc.desc: 1. test negative userId should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateDataGroupDirs_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<CreateDirParam> params;
    CreateDirParam param;
    param.userId = -1;
    param.uid = 10000;
    param.gid = 10000;
    param.uuid = "550e8400-e29b-41d4-a716-44665544010";
    params.push_back(param);
    ErrCode result = impl.CreateDataGroupDirs(params);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CreateDataGroupDirs_0200
 * @tc.name: test CreateDataGroupDirs with invalid uid
 * @tc.desc: 1. test negative uid should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateDataGroupDirs_0200, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<CreateDirParam> params;
    CreateDirParam param;
    param.userId = 100;
    param.uid = -1;
    param.gid = 10000;
    param.uuid = "550e8400-e29b-41d4-a716-44665544011";
    params.push_back(param);
    ErrCode result = impl.CreateDataGroupDirs(params);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CreateDataGroupDirs_0300
 * @tc.name: test CreateDataGroupDirs with invalid gid
 * @tc.desc: 1. test negative gid should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateDataGroupDirs_0300, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<CreateDirParam> params;
    CreateDirParam param;
    param.userId = 100;
    param.uid = 10000;
    param.gid = -1;
    param.uuid = "550e8400-e29b-41d4-a716-44665544012";
    params.push_back(param);
    ErrCode result = impl.CreateDataGroupDirs(params);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CreateDataGroupDirs_0400
 * @tc.name: test CreateDataGroupDirs with invalid uuid
 * @tc.desc: 1. test invalid uuid should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateDataGroupDirs_0400, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<CreateDirParam> params;
    CreateDirParam param;
    param.userId = 100;
    param.uid = 10000;
    param.gid = 10000;
    param.uuid = "../invalid";
    params.push_back(param);
    ErrCode result = impl.CreateDataGroupDirs(params);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CreateDataGroupDirs_0500
 * @tc.name: test CreateDataGroupDirs with empty uuid
 * @tc.desc: 1. test empty uuid should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateDataGroupDirs_0500, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<CreateDirParam> params;
    CreateDirParam param;
    param.userId = 100;
    param.uid = 10000;
    param.gid = 10000;
    param.uuid = "";
    params.push_back(param);
    ErrCode result = impl.CreateDataGroupDirs(params);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CreateDataGroupDirs_0600
 * @tc.name: test CreateDataGroupDirs with EL5 dataDirEl
 * @tc.desc: 1. test EL5 branch (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateDataGroupDirs_0600, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<CreateDirParam> params;
    CreateDirParam param;
    param.userId = 100;
    param.uid = 10000;
    param.gid = 10000;
    param.uuid = "550e8400-e29b-41d4-a716-44665544013";
    param.dataDirEl = DataDirEl::EL5;
    params.push_back(param);
    ErrCode result = impl.CreateDataGroupDirs(params);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_CreateExtensionDataDir_0100
 * @tc.name: test CreateExtensionDataDir with invalid bundleName
 * @tc.desc: 1. test empty bundleName should return param error
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateExtensionDataDir_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    CreateDirParam param;
    param.bundleName = "";
    param.userId = 100;
    param.uid = 10000;
    param.gid = 10000;
    param.apl = "normal";
    param.extensionDirs = {"ext1"};
    ErrCode result = impl.CreateExtensionDataDir(param);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CreateExtensionDataDir_0200
 * @tc.name: test CreateExtensionDataDir with invalid userId
 * @tc.desc: 1. test negative userId should return param error
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateExtensionDataDir_0200, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    CreateDirParam param;
    param.bundleName = "com.example.test";
    param.userId = -1;
    param.uid = 10000;
    param.gid = 10000;
    param.apl = "normal";
    param.extensionDirs = {"ext1"};
    ErrCode result = impl.CreateExtensionDataDir(param);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CreateExtensionDataDir_0300
 * @tc.name: test CreateExtensionDataDir with invalid uid
 * @tc.desc: 1. test negative uid should return param error
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateExtensionDataDir_0300, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    CreateDirParam param;
    param.bundleName = "com.example.test";
    param.userId = 100;
    param.uid = -1;
    param.gid = 10000;
    param.apl = "normal";
    param.extensionDirs = {"ext1"};
    ErrCode result = impl.CreateExtensionDataDir(param);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CreateExtensionDataDir_0400
 * @tc.name: test CreateExtensionDataDir with invalid gid
 * @tc.desc: 1. test negative gid should return param error
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateExtensionDataDir_0400, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    CreateDirParam param;
    param.bundleName = "com.example.test";
    param.userId = 100;
    param.uid = 10000;
    param.gid = -1;
    param.apl = "normal";
    param.extensionDirs = {"ext1"};
    ErrCode result = impl.CreateExtensionDataDir(param);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CreateExtensionDataDir_0500
 * @tc.name: test CreateExtensionDataDir with empty extensionDirs
 * @tc.desc: 1. test empty extensionDirs should return param error
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateExtensionDataDir_0500, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    CreateDirParam param;
    param.bundleName = "com.example.test";
    param.userId = 100;
    param.uid = 10000;
    param.gid = 10000;
    param.apl = "normal";
    param.extensionDirs = {};
    ErrCode result = impl.CreateExtensionDataDir(param);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CreateExtensionDataDir_0600
 * @tc.name: test CreateExtensionDataDir with invalid apl
 * @tc.desc: 1. test invalid apl should return param error
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateExtensionDataDir_0600, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    CreateDirParam param;
    param.bundleName = "com.example.test";
    param.userId = 100;
    param.uid = 10000;
    param.gid = 10000;
    param.apl = "invalid_apl";
    param.extensionDirs = {"ext1"};
    ErrCode result = impl.CreateExtensionDataDir(param);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CreateExtensionDataDir_0700
 * @tc.name: test CreateExtensionDataDir with too many extensionDirs
 * @tc.desc: 1. test extensionDirs size exceeding MAX_BATCH_QUERY_BUNDLE_SIZE should return param error
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateExtensionDataDir_0700, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    CreateDirParam param;
    param.bundleName = "com.example.test";
    param.userId = 100;
    param.uid = 10000;
    param.gid = 10000;
    param.apl = "normal";
    for (int i = 0; i < 1025; i++) {
        param.extensionDirs.push_back("ext" + std::to_string(i));
    }
    ErrCode result = impl.CreateExtensionDataDir(param);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CreateExtensionDataDir_0800
 * @tc.name: test CreateExtensionDataDir with invalid extensionDir name
 * @tc.desc: 1. test extensionDir with invalid characters should return param error
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateExtensionDataDir_0800, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    CreateDirParam param;
    param.bundleName = "com.example.test";
    param.userId = 100;
    param.uid = 10000;
    param.gid = 10000;
    param.apl = "normal";
    param.extensionDirs = {"../invalid"};
    ErrCode result = impl.CreateExtensionDataDir(param);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_CreateExtensionDataDir_0900
 * @tc.name: test CreateExtensionDataDir with CREATE_DIR_UNLOCKED flag
 * @tc.desc: 1. test CREATE_DIR_UNLOCKED branch (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateExtensionDataDir_0900, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    CreateDirParam param;
    param.bundleName = "com.example.test";
    param.userId = 100;
    param.uid = 10000;
    param.gid = 10000;
    param.apl = "normal";
    param.extensionDirs = {"ext1"};
    param.createDirFlag = CreateDirFlag::CREATE_DIR_UNLOCKED;
    ErrCode result = impl.CreateExtensionDataDir(param);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_CreateExtensionDataDir_1000
 * @tc.name: test CreateExtensionDataDir with valid parameters
 * @tc.desc: 1. test valid parameters should return ERR_OK
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_CreateExtensionDataDir_1000, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    CreateDirParam param;
    param.bundleName = "com.example.test";
    param.userId = 100;
    param.uid = 10000;
    param.gid = 10000;
    param.apl = "system_core";
    param.extensionDirs = {"ext1", "ext2"};
    ErrCode result = impl.CreateExtensionDataDir(param);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_ExtractHnpFiles_0100
 * @tc.name: test ExtractHnpFiles with empty hnpPackageMap
 * @tc.desc: 1. test empty hnpPackageMap should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ExtractHnpFiles_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::map<std::string, std::string> hnpPackageMap;
    ExtractParam extractParam;
    extractParam.srcPath = "/data/app/el1/bundle/public/test";
    extractParam.targetPath = "/data/app/el1/bundle/public/target";
    ErrCode result = impl.ExtractHnpFiles(hnpPackageMap, extractParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_ExtractHnpFiles_0200
 * @tc.name: test ExtractHnpFiles with invalid srcPath
 * @tc.desc: 1. test invalid srcPath should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ExtractHnpFiles_0200, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::map<std::string, std::string> hnpPackageMap = {{"key1", "value1"}};
    ExtractParam extractParam;
    extractParam.srcPath = "/tmp/../invalid";
    extractParam.targetPath = "/data/app/el1/bundle/public/target";
    ErrCode result = impl.ExtractHnpFiles(hnpPackageMap, extractParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_ExtractHnpFiles_0300
 * @tc.name: test ExtractHnpFiles with invalid targetPath
 * @tc.desc: 1. test invalid targetPath should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ExtractHnpFiles_0300, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::map<std::string, std::string> hnpPackageMap = {{"key1", "value1"}};
    ExtractParam extractParam;
    extractParam.srcPath = "/data/app/el1/bundle/public/test";
    extractParam.targetPath = "/tmp/invalid";
    ErrCode result = impl.ExtractHnpFiles(hnpPackageMap, extractParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleInstallNative_0100
 * @tc.name: test ProcessBundleInstallNative with invalid packageName
 * @tc.desc: 1. test invalid packageName packageName (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleInstallNative_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    InstallHnpParam installHnpParam;
    installHnpParam.packageName = "invalid";
    ErrCode result = impl.ProcessBundleInstallNative(installHnpParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleInstallNative_0200
 * @tc.name: test ProcessBundleInstallNative with empty packageName
 * @tc.desc: 1. test empty packageName should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleInstallNative_0200, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    InstallHnpParam installHnpParam;
    installHnpParam.packageName = "";
    ErrCode result = impl.ProcessBundleInstallNative(installHnpParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleInstallNative_0300
 * @tc.name: test ProcessBundleInstallNative with packageName starting with number
 * @tc.desc: 1. test packageName starting with number should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleInstallNative_0300, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    InstallHnpParam installHnpParam;
    installHnpParam.packageName = "1com.example.test";
    ErrCode result = impl.ProcessBundleInstallNative(installHnpParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleInstallNative_0400
 * @tc.name: test ProcessBundleInstallNative with packageName containing invalid characters
 * @tc.desc: 1. test packageName with invalid characters should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleInstallNative_0400, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    InstallHnpParam installHnpParam;
    installHnpParam.packageName = "com/example/test";
    ErrCode result = impl.ProcessBundleInstallNative(installHnpParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleInstallNative_0500
 * @tc.name: test ProcessBundleInstallNative with packageName too short
 * @tc.desc: 1. test packageName less than 7 characters should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleInstallNative_0500, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    InstallHnpParam installHnpParam;
    installHnpParam.packageName = "a.b.c";
    ErrCode result = impl.ProcessBundleInstallNative(installHnpParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleInstallNative_0600
 * @tc.name: test ProcessBundleInstallNative with packageName too long
 * @tc.desc: 1. test packageName more than 128 characters should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleInstallNative_0600, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    InstallHnpParam installHnpParam;
    installHnpParam.packageName = std::string(129, 'a');
    ErrCode result = impl.ProcessBundleInstallNative(installHnpParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleInstallNative_0700
 * @tc.name: test ProcessBundleInstallNative with valid clone packageName
 * @tc.desc: 1. test valid clone packageName format (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleInstallNative_0700, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    InstallHnpParam installHnpParam;
    installHnpParam.packageName = "+clone-1+com.example.test";
    installHnpParam.userId = "100";
    installHnpParam.hnpRootPath = "/data/app/el1/bundle/public/com.example.test/entry_tmp/hnp_tmp_extract_dir/";
    installHnpParam.hapPath = "/system/app/module01/module01.hap";
    installHnpParam.cpuAbi = "arm64";
    ErrCode result = impl.ProcessBundleInstallNative(installHnpParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_NATIVE_INSTALL_FAILED);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleInstallNative_0800
 * @tc.name: test ProcessBundleInstallNative with valid sandbox packageName
 * @tc.desc: 1. test valid sandbox packageName format (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleInstallNative_0800, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    InstallHnpParam installHnpParam;
    installHnpParam.packageName = "1_com.example.test";
    installHnpParam.userId = "100";
    installHnpParam.hnpRootPath = "/data/app/el1/bundle/public/com.example.test/entry_tmp/hnp_tmp_extract_dir/";
    installHnpParam.hapPath = "/system/app/module01/module01.hap";
    installHnpParam.cpuAbi = "arm64";
    ErrCode result = impl.ProcessBundleInstallNative(installHnpParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_NATIVE_INSTALL_FAILED);
}

/**
 * @tc.number: InstalldHostImpl_RemoveBundleDataDir_0100
 * @tc.name: test RemoveBundleDataDir with isAtomicService true
 * @tc.desc: 1. test isAtomicService branch calls InnerRemoveAtomicServiceBundleDataDir (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_RemoveBundleDataDir_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.RemoveBundleDataDir("com.example.test", 100, true, false);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_RemoveBundleDataDir_0200
 * @tc.name: test RemoveBundleDataDir with isAtomicService true and async true
 * @tc.desc: 1. test isAtomicService branch with async parameter (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_RemoveBundleDataDir_0200, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.RemoveBundleDataDir("com.example.test", 100, true, true);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_RemoveBundleDataDir_0300
 * @tc.name: test RemoveBundleDataDir with invalid bundleName
 * @tc.desc: 1. test invalid bundleName should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_RemoveBundleDataDir_0300, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.RemoveBundleDataDir("wrong", 100, false, false);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_RemoveBundleDataDir_0400
 * @tc.name: test RemoveBundleDataDir with empty bundleName
 * @tc.desc: 1. test empty bundleName should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_RemoveBundleDataDir_0400, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.RemoveBundleDataDir("", 100, false, false);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_RemoveBundleDataDir_0500
 * @tc.name: test RemoveBundleDataDir with invalid userId
 * @tc.desc: 1. test negative userId should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_RemoveBundleDataDir_0500, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.RemoveBundleDataDir("com.example.test", -1, false, false);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_RemoveBundleDataDir_0600
 * @tc.name: test RemoveBundleDataDir with async true
 * @tc.desc: 1. test async parameter affects InnerRemoveBundleDataDir call (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_RemoveBundleDataDir_0600, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.RemoveBundleDataDir("com.example.test", 100, false, true);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_RemoveBundleDataDir_0700
 * @tc.name: test RemoveBundleDataDir with normal parameters
 * @tc.desc: 1. test normal path calls InnerRemoveBundleDataDir (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_RemoveBundleDataDir_0700, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.RemoveBundleDataDir("com.example.test", 100, false, false);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleUnInstallNative_0100
 * @tc.name: test ProcessBundleUnInstallNative with invalid packageName
 * @tc.desc: 1. test invalid packageName should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleUnInstallNative_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.ProcessBundleUnInstallNative("100", "invalid");
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleUnInstallNative_0200
 * @tc.name: test ProcessBundleUnInstallNative with empty packageName
 * @tc.desc: 1. test empty packageName should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleUnInstallNative_0200, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.ProcessBundleUnInstallNative("100", "");
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleUnInstallNative_0300
 * @tc.name: test ProcessBundleUnInstallNative with packageName starting with number
 * @tc.desc: 1. test packageName starting with number should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleUnInstallNative_0300, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.ProcessBundleUnInstallNative("100", "1com.example.test");
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleUnInstallNative_0400
 * @tc.name: test ProcessBundleUnInstallNative with packageName containing invalid characters
 * @tc.desc: 1. test packageName with invalid characters should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleUnInstallNative_0400, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.ProcessBundleUnInstallNative("100", "com/example/test");
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleUnInstallNative_0500
 * @tc.name: test ProcessBundleUnInstallNative with packageName too short
 * @tc.desc: 1. test packageName less than 7 characters should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleUnInstallNative_0500, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.ProcessBundleUnInstallNative("100", "a.b.c");
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleUnInstallNative_0600
 * @tc.name: test ProcessBundleUnInstallNative with packageName too long
 * @tc.desc: 1. test packageName more than 128 characters should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleUnInstallNative_0600, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.ProcessBundleUnInstallNative("100", std::string(129, 'a'));
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleUnInstallNative_0700
 * @tc.name: test ProcessBundleUnInstallNative with valid clone packageName
 * @tc.desc: 1. test valid clone packageName format (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleUnInstallNative_0700, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.ProcessBundleUnInstallNative("100", "+clone-1+com.example.test");
    EXPECT_EQ(result, ERR_APPEXECFWK_NATIVE_UNINSTALL_FAILED);
}

/**
 * @tc.number: InstalldHostImpl_ProcessBundleUnInstallNative_0800
 * @tc.name: test ProcessBundleUnInstallNative with valid sandbox packageName
 * @tc.desc: 1. test valid sandbox packageName format (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_ProcessBundleUnInstallNative_0800, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    ErrCode result = impl.ProcessBundleUnInstallNative("100", "1_com.example.test");
    EXPECT_EQ(result, ERR_APPEXECFWK_NATIVE_UNINSTALL_FAILED);
}

/**
 * @tc.number: InstalldHostImpl_BatchGetBundleStats_0100
 * @tc.name: test BatchGetBundleStats with empty bundleNames
 * @tc.desc: 1. test empty bundleNames should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_BatchGetBundleStats_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> bundleNames;
    std::unordered_map<std::string, std::unordered_set<int32_t>> uidMap;
    std::vector<BundleStorageStats> bundleStats;
    ErrCode result = impl.BatchGetBundleStats(bundleNames, uidMap, bundleStats);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_BatchGetBundleStats_0200
 * @tc.name: test BatchGetBundleStats with bundleNames size exceeding MAX_BATCH_QUERY_BUNDLE_SIZE
 * @tc.desc: 1. test bundleNames size > 1024 should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_BatchGetBundleStats_0200, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> bundleNames;
    std::unordered_map<std::string, std::unordered_set<int32_t>> uidMap;
    std::vector<BundleStorageStats> bundleStats;
    for (int i = 0; i < 1025; i++) {
        std::string name = "com.example.test" + std::to_string(i);
        bundleNames.push_back(name);
        uidMap[name] = {10000 + i};
    }
    ErrCode result = impl.BatchGetBundleStats(bundleNames, uidMap, bundleStats);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_BatchGetBundleStats_0300
 * @tc.name: test BatchGetBundleStats with bundleNames size not equal to uidMap size
 * @tc.desc: 1. test bundleNames.size() != uidMap.size() should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_BatchGetBundleStats_0300, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> bundleNames = {"com.example.test1", "com.example.test2"};
    std::unordered_map<std::string, std::unordered_set<int32_t>> uidMap;
    uidMap["com.example.test1"] = {10000};
    std::vector<BundleStorageStats> bundleStats;
    ErrCode result = impl.BatchGetBundleStats(bundleNames, uidMap, bundleStats);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_BatchGetBundleStats_0400
 * @tc.name: test BatchGetBundleStats with invalid bundleName
 * @tc.desc: 1. test invalid bundleName should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_BatchGetBundleStats_0400, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> bundleNames = {"invalid"};
    std::unordered_map<std::string, std::unordered_set<int32_t>> uidMap;
    uidMap["invalid"] = {10000};
    std::vector<BundleStorageStats> bundleStats;
    ErrCode result = impl.BatchGetBundleStats(bundleNames, uidMap, bundleStats);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_BatchGetBundleStats_0500
 * @tc.name: test BatchGetBundleStats with empty bundleName
 * @tc.desc: 1. test empty bundleName should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_BatchGetBundleStats_0500, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> bundleNames = {""};
    std::unordered_map<std::string, std::unordered_set<int32_t>> uidMap;
    uidMap[""] = {10000};
    std::vector<BundleStorageStats> bundleStats;
    ErrCode result = impl.BatchGetBundleStats(bundleNames, uidMap, bundleStats);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_BatchGetBundleStats_0600
 * @tc.name: test BatchGetBundleStats with bundleName starting with number
 * @tc.desc: 1. test bundleName starting with number should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_BatchGetBundleStats_0600, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> bundleNames = {"1com.example.test"};
    std::unordered_map<std::string, std::unordered_set<int32_t>> uidMap;
    uidMap["1com.example.test"] = {10000};
    std::vector<BundleStorageStats> bundleStats;
    ErrCode result = impl.BatchGetBundleStats(bundleNames, uidMap, bundleStats);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_BatchGetBundleStats_0700
 * @tc.name: test BatchGetBundleStats with bundleName containing invalid characters
 * @tc.desc: 1. test bundleName with invalid characters should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_BatchGetBundleStats_0700, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> bundleNames = {"com/example/test"};
    std::unordered_map<std::string, std::unordered_set<int32_t>> uidMap;
    uidMap["com/example/test"] = {10000};
    std::vector<BundleStorageStats> bundleStats;
    ErrCode result = impl.BatchGetBundleStats(bundleNames, uidMap, bundleStats);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_BatchGetBundleStats_0800
 * @tc.name: test BatchGetBundleStats with bundleName too short
 * @tc.desc: 1. test bundleName less than 7 characters should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_BatchGetBundleStats_0800, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> bundleNames = {"a.b.c"};
    std::unordered_map<std::string, std::unordered_set<int32_t>> uidMap;
    uidMap["a.b.c"] = {10000};
    std::vector<BundleStorageStats> bundleStats;
    ErrCode result = impl.BatchGetBundleStats(bundleNames, uidMap, bundleStats);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_BatchGetBundleStats_0900
 * @tc.name: test BatchGetBundleStats with bundleName too long
 * @tc.desc: 1. test bundleName more than 128 characters should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_BatchGetBundleStats_0900, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::string longBundleName(129, 'a');
    std::vector<std::string> bundleNames = {longBundleName};
    std::unordered_map<std::string, std::unordered_set<int32_t>> uidMap;
    uidMap[longBundleName] = {10000};
    std::vector<BundleStorageStats> bundleStats;
    ErrCode result = impl.BatchGetBundleStats(bundleNames, uidMap, bundleStats);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_Batch
GetBundleStats_1000
 * @tc.name: test BatchGetBundleStats with valid clone bundleName
 * @tc.desc: 1. test valid clone bundleName format (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_BatchGetBundleStats_1000, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> bundleNames = {"+clone-1+com.example.test"};
    std::unordered_map<std::string, std::unordered_set<int32_t>> uidMap;
    uidMap["+clone-1+com.example.test"] = {10000};
    std::vector<BundleStorageStats> bundleStats;
    ErrCode result = impl.BatchGetBundleStats(bundleNames, uidMap, bundleStats);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_BatchGetBundleStats_1100
 * @tc.name: test BatchGetBundleStats with valid sandbox bundleName
 * @tc.desc: 1. test valid sandbox bundleName format (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_BatchGetBundleStats_1100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> bundleNames = {"1_com.example.test"};
    std::unordered_map<std::string, std::unordered_set<int32_t>> uidMap;
    uidMap["1_com.example.test"] = {10000};
    std::vector<BundleStorageStats> bundleStats;
    ErrCode result = impl.BatchGetBundleStats(bundleNames, uidMap, bundleStats);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_BatchGetBundleStats_1200
 * @tc.name: test BatchGetBundleStats with multiple valid bundleNames
 * @tc.desc: 1. test multiple valid bundleNames should return ERR_OK (new branch)
)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_BatchGetBundleStats_1200, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> bundleNames = {"com.example.test1", "com.example.test2", "com.example.test3"};
    std::unordered_map<std::string, std::unordered_set<int32_t>> uidMap;
    uidMap["com.example.test1"] = {10000};
    uidMap["com.example.test2"] = {10001};
    uidMap["com.example.test3"] = {10002};
    std::vector<BundleStorageStats> bundleStats;
    ErrCode result = impl.BatchGetBundleStats(bundleNames, uidMap, bundleStats);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_BatchGetBundleStats_1300
 * @tc.name: test BatchGetBundleStats with bundleName containing dots and underscores
 * @tc.desc: 1. test valid bundleName with dots and underscores (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_BatchGetBundleStats_1300, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> bundleNames = {"com.example_test.app"};
    std::unordered_map<std::string, std::unordered_set<int32_t>> uidMap;
    uidMap["com.example_test.app"] = {10000};
    std::vector<BundleStorageStats> bundleStats;
    ErrCode result = impl.BatchGetBundleStats(bundleNames, uidMap, bundleStats);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_BatchGetBundleStats_1400
 * @tc.name: test BatchGetBundleStats with multiple UIDs for same bundle
 * @tc.desc: 1. test bundle with multiple UIDs in uidMap (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_BatchGetBundleStats_1400, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> bundleNames = {"com.example.test"};
    std::unordered_map<std::string, std::unordered_set<int32_t>> uidMap;
    uidMap["com.example.test"] = {10000, 10001, 10002};
    std::vector<BundleStorageStats> bundleStats;
    ErrCode result = impl.BatchGetBundleStats(bundleNames, uidMap, bundleStats);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_BatchGetBundleStats_1500
 * @tc.name: test BatchGetBundleStats with MAX_BATCH_QUERY_BUNDLE_SIZE bundleNames
 * @tc.desc: 1. test exactly 1024 bundleNames should return ERR_OK (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_BatchGetBundleStats_1500, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> bundleNames;
    std::unordered_map<std::string, std::unordered_set<int32_t>> uidMap;
    for (int i = 0; i < 1024; i++) {
        std::string name = "com.example.test" + std::to_string(i);
        bundleNames.push_back(name);
        uidMap[name] = {10000 + i};
    }
    std::vector<BundleStorageStats> bundleStats;
    ErrCode result = impl.BatchGetBundleStats(bundleNames, uidMap, bundleStats);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_0100
 * @tc.name: test SetFileConForce with empty paths
 * @tc.desc: 1. test empty paths should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_0100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths;
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.example.test";
    createDirParam.apl = "normal";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_0200
 * @tc.name: test SetFileConForce with invalid bundleName
 * @tc.desc: 1. test invalid bundleName should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_0200, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "invalid";
    createDirParam.apl = "normal";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_0300
 * @tc.name: test SetFileConForce with empty bundleName
 * @tc.desc: 1. test empty bundleName should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_0300, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "";
    createDirParam.apl = "normal";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_0400
 * @tc.name: test SetFileConForce with bundleName starting with number
 * @tc.desc: 1. test bundleName starting with number should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_0400, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "1com.example.test";
    createDirParam.apl = "normal";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_0500
 * @tc.name: test SetFileConForce with bundleName containing invalid characters
 * @tc.desc: 1. test bundleName with invalid characters should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_0500, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com/example/test";
    createDirParam.apl = "normal";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_0600
 * @tc.name: test SetFileConForce with bundleName too short
 * @tc.desc: 1. test bundleName less than 7 characters should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_0600, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "a.b.c";
    createDirParam.apl = "normal";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_0700
 * @tc.name: test SetFileConForce with bundleName too long
 * @tc.desc: 1. test bundleName more than 128 characters should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_0700, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = std::string(129, 'a');
    createDirParam.apl = "normal";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_0800
 * @tc.name: test SetFileConForce with invalid apl
 * @tc.desc: 1. test invalid apl should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_0800, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.example.test";
    createDirParam.apl = "invalid_apl";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_0900
 * @tc.name: test SetFileConForce with empty apl
 * @tc.desc: 1. test empty apl should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_0900, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.example.test";
    createDirParam.apl = "";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_1000
 * @tc.name: test SetFileConForce with invalid uid
 * @tc.desc: 1. test negative uid should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_1000, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.example.test";
    createDirParam.apl = "normal";
    createDirParam.uid = -1;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_1100
 * @tc.name: test SetFileConForce with invalid path
 * @tc.desc: 1. test invalid path should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_1100, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/tmp/invalid"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.example.test";
    createDirParam.apl = "normal";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_1200
 * @tc.name: test SetFileConForce with path containing ..
 * @tc.desc: 1. test path with .. should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_1200, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/../bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.example.test";
    createDirParam.apl = "normal";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_1300
 * @tc.name: test SetFileConForce with multiple paths, one invalid
 * @tc.desc: 1. test multiple paths with one invalid should return param error (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_1300, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {
        "/data/app/el1/bundle/public/test1",
        "/tmp/invalid",
        "/data/app/el1/bundle/public/test2"
    };
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.example.test";
    createDirParam.apl = "normal";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_1400
 * @tc.name: test SetFileConForce with valid clone bundleName
 * @tc.desc: 1. test valid clone bundleName format (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_1400, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "+clone-1+com.example.test";
    createDirParam.apl = "normal";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_1500
 * @tc.name: test SetFileConForce with valid sandbox bundleName
 * @tc.desc: 1. test valid sandbox bundleName format (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_1500, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "1_com.example.test";
    createDirParam.apl = "normal";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_1600
 * @tc.name: test SetFileConForce with system_core apl
 * @tc.desc: 1. test system_core apl (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_1600, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.example.test";
    createDirParam.apl = "system_core";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_1700
 * @tc.name: test SetFileConForce with system_basic apl
 * @tc.desc: 1. test system_basic apl (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_1700, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.example.test";
    createDirParam.apl = "system_basic";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_1800
 * @tc.name: test SetFileConForce with multiple valid paths
 * @tc.desc: 1. test multiple valid paths (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_1800, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {
        "/data/app/el1/bundle/public/test1",
        "/data/app/el1/bundle/public/test2",
        "/data/app/el1/bundle/public/test3"
    };
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.example.test";
    createDirParam.apl = "normal";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_1900
 * @tc.name: test SetFileConForce with bundleName containing dots and underscores
 * @tc.desc: 1. test valid bundleName with dots and underscores (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_1900, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.example_test.app";
    createDirParam.apl = "normal";
    createDirParam.uid = 10000;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: InstalldHostImpl_SetFileConForce_2000
 * @tc.name: test SetFileConForce with valid parameters
 * @tc.desc: 1. test all valid parameters (new branch)
 */
HWTEST_F(BmsBundleInstallParametersTest, InstalldHostImpl_SetFileConForce_2000, Function | SmallTest | Level0)
{
    InstalldHostImpl impl;
    std::vector<std::string> paths = {"/data/app/el1/bundle/public/test"};
    CreateDirParam createDirParam;
    createDirParam.bundleName = "com.example.test";
    createDirParam.apl = "normal";
    createDirParam.uid = 10000;
    createDirParam.isPreInstallApp = true;
    createDirParam.debug = false;
    createDirParam.isDlpSandbox = false;
    createDirParam.dlpType = 0;
    createDirParam.isExtensionDir = false;
    ErrCode result = impl.SetFileConForce(paths, createDirParam);
    EXPECT_EQ(result, ERR_OK);
}
} // namespace OHOS
