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

#include "skills_description_manager.h"
#include "skills_description_rdb.h"
#include "skills_package_info.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const int32_t USER_ID = 100;
const int32_t TEST_USER_ID = 20000;
const std::string BUNDLE_NAME = "com.example.bundlename";
const std::string MODULE_NAME = "entry";
const std::string MODULE_NAME_TWO = "feature";
const std::string SKILL_NAME = "mainSkill";
const std::string SKILL_NAME_TWO = "featureSkill";
const std::string DESCRIPTION = "This is a test skill description";
const std::string DESCRIPTION_TWO = "This is another test skill description";
}  // namespace

class BmsSkillsDescriptionRdbTest : public testing::Test {
public:
    BmsSkillsDescriptionRdbTest();
    ~BmsSkillsDescriptionRdbTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsSkillsDescriptionRdbTest::BmsSkillsDescriptionRdbTest()
{}

BmsSkillsDescriptionRdbTest::~BmsSkillsDescriptionRdbTest()
{}

void BmsSkillsDescriptionRdbTest::SetUpTestCase()
{}

void BmsSkillsDescriptionRdbTest::TearDownTestCase()
{}

void BmsSkillsDescriptionRdbTest::SetUp()
{}

void BmsSkillsDescriptionRdbTest::TearDown()
{}

/**
 * @tc.number: AddSkillDescriptions_0001
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb AddSkillDescriptions with empty list
 * @tc.desc: 1. system running normally
 *           2. test AddSkillDescriptions with empty list
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, AddSkillDescriptions_0001, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;
    std::vector<SkillsPackageInfo> skillInfoList;
    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: AddSkillDescriptions_0002
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb AddSkillDescriptions with valid data
 * @tc.desc: 1. system running normally
 *           2. test AddSkillDescriptions with valid data
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, AddSkillDescriptions_0002, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;
    std::vector<SkillsPackageInfo> skillInfoList;

    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillsName = SKILL_NAME;
    skillInfo.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Clean up
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AddSkillDescriptions_0003
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb AddSkillDescriptions with multiple skills
 * @tc.desc: 1. system running normally
 *           2. test AddSkillDescriptions with multiple skills
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, AddSkillDescriptions_0003, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;
    std::vector<SkillsPackageInfo> skillInfoList;

    SkillsPackageInfo skillInfo1;
    skillInfo1.bundleName = BUNDLE_NAME;
    skillInfo1.moduleName = MODULE_NAME;
    skillInfo1.skillsName = SKILL_NAME;
    skillInfo1.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo1);

    SkillsPackageInfo skillInfo2;
    skillInfo2.bundleName = BUNDLE_NAME;
    skillInfo2.moduleName = MODULE_NAME_TWO;
    skillInfo2.skillsName = SKILL_NAME_TWO;
    skillInfo2.description = DESCRIPTION_TWO;
    skillInfoList.push_back(skillInfo2);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Clean up
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AddSkillDescriptions_0004
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb AddSkillDescriptions with invalid data
 * @tc.desc: 1. system running normally
 *           2. test AddSkillDescriptions with empty bundle name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, AddSkillDescriptions_0004, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;
    std::vector<SkillsPackageInfo> skillInfoList;

    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = "";
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillsName = SKILL_NAME;
    skillInfo.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AddSkillDescriptions_0005
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb AddSkillDescriptions with invalid data
 * @tc.desc: 1. system running normally
 *           2. test AddSkillDescriptions with empty module name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, AddSkillDescriptions_0005, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;
    std::vector<SkillsPackageInfo> skillInfoList;

    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = "";
    skillInfo.skillsName = SKILL_NAME;
    skillInfo.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AddSkillDescriptions_0006
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb AddSkillDescriptions with invalid data
 * @tc.desc: 1. system running normally
 *           2. test AddSkillDescriptions with empty skill name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, AddSkillDescriptions_0006, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;
    std::vector<SkillsPackageInfo> skillInfoList;

    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillsName = "";
    skillInfo.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AddSkillDescriptions_0007
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb AddSkillDescriptions with mixed valid and invalid data
 * @tc.desc: 1. system running normally
 *           2. test AddSkillDescriptions with mixed data
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, AddSkillDescriptions_0007, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;
    std::vector<SkillsPackageInfo> skillInfoList;

    // Invalid entry (empty bundle name)
    SkillsPackageInfo skillInfo1;
    skillInfo1.bundleName = "";
    skillInfo1.moduleName = MODULE_NAME;
    skillInfo1.skillsName = SKILL_NAME;
    skillInfo1.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo1);

    // Valid entry
    SkillsPackageInfo skillInfo2;
    skillInfo2.bundleName = BUNDLE_NAME;
    skillInfo2.moduleName = MODULE_NAME;
    skillInfo2.skillsName = SKILL_NAME;
    skillInfo2.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo2);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Clean up
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: DeleteSkillDescriptions_0001
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb DeleteSkillDescriptions by bundle name
 * @tc.desc: 1. system running normally
 *           2. test DeleteSkillDescriptions with empty bundle name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, DeleteSkillDescriptions_0001, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;
    ErrCode ret = skillsDescriptionRdb.DeleteSkillDescriptions("");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: DeleteSkillDescriptions_0002
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb DeleteSkillDescriptions by bundle name
 * @tc.desc: 1. system running normally
 *           2. test DeleteSkillDescriptions with valid bundle name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, DeleteSkillDescriptions_0002, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    // First add some data
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillsName = SKILL_NAME;
    skillInfo.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Then delete
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: DeleteSkillDescriptions_0003
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb DeleteSkillDescriptions by bundle and module name
 * @tc.desc: 1. system running normally
 *           2. test DeleteSkillDescriptions with empty bundle name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, DeleteSkillDescriptions_0003, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;
    ErrCode ret = skillsDescriptionRdb.DeleteSkillDescriptions("", MODULE_NAME);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: DeleteSkillDescriptions_0004
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb DeleteSkillDescriptions by bundle and module name
 * @tc.desc: 1. system running normally
 *           2. test DeleteSkillDescriptions with empty module name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, DeleteSkillDescriptions_0004, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;
    ErrCode ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME, "");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: DeleteSkillDescriptions_0005
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb DeleteSkillDescriptions by bundle and module name
 * @tc.desc: 1. system running normally
 *           2. test DeleteSkillDescriptions with valid names
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, DeleteSkillDescriptions_0005, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    // First add some data
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillsName = SKILL_NAME;
    skillInfo.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Then delete
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME, MODULE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: DeleteSkillDescriptions_0006
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb DeleteSkillDescriptions by full path
 * @tc.desc: 1. system running normally
 *           2. test DeleteSkillDescriptions with empty bundle name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, DeleteSkillDescriptions_0006, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;
    ErrCode ret = skillsDescriptionRdb.DeleteSkillDescriptions("", MODULE_NAME, SKILL_NAME);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: DeleteSkillDescriptions_0007
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb DeleteSkillDescriptions by full path
 * @tc.desc: 1. system running normally
 *           2. test DeleteSkillDescriptions with empty module name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, DeleteSkillDescriptions_0007, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;
    ErrCode ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME, "", SKILL_NAME);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: DeleteSkillDescriptions_0008
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb DeleteSkillDescriptions by full path
 * @tc.desc: 1. system running normally
 *           2. test DeleteSkillDescriptions with empty skill name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, DeleteSkillDescriptions_0008, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;
    ErrCode ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME, MODULE_NAME, "");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: DeleteSkillDescriptions_0009
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb DeleteSkillDescriptions by full path
 * @tc.desc: 1. system running normally
 *           2. test DeleteSkillDescriptions with valid names
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, DeleteSkillDescriptions_0009, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    // First add some data
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillsName = SKILL_NAME;
    skillInfo.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Then delete
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME, MODULE_NAME, SKILL_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: DeleteSkillDescriptions_0010
 * Function: SkillsDescriptionRdb
 * @tc.name: test SkillsDescriptionRdb DeleteSkillDescriptions with multiple skills
 * @tc.desc: 1. system running normally
 *           2. test deleting multiple skills by bundle name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, DeleteSkillDescriptions_0010, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    // First add multiple skills
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo skillInfo1;
    skillInfo1.bundleName = BUNDLE_NAME;
    skillInfo1.moduleName = MODULE_NAME;
    skillInfo1.skillsName = SKILL_NAME;
    skillInfo1.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo1);

    SkillsPackageInfo skillInfo2;
    skillInfo2.bundleName = BUNDLE_NAME;
    skillInfo2.moduleName = MODULE_NAME_TWO;
    skillInfo2.skillsName = SKILL_NAME_TWO;
    skillInfo2.description = DESCRIPTION_TWO;
    skillInfoList.push_back(skillInfo2);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Delete all by bundle name
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: SkillsDescriptionManager_AddSkillDescriptions_0001
 * Function: SkillsDescriptionManager
 * @tc.name: test SkillsDescriptionManager AddSkillDescriptions
 * @tc.desc: 1. system running normally
 *           2. test AddSkillDescriptions with valid data
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, SkillsDescriptionManager_AddSkillDescriptions_0001, Function | SmallTest | Level0)
{
    auto skillsDescriptionManager = DelayedSingleton<SkillsDescriptionManager>::GetInstance();
    ASSERT_NE(skillsDescriptionManager, nullptr);

    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillsName = SKILL_NAME;
    skillInfo.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionManager->AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Clean up
    ret = skillsDescriptionManager->DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: SkillsDescriptionManager_AddSkillDescriptions_0002
 * Function: SkillsDescriptionManager
 * @tc.name: test SkillsDescriptionManager AddSkillDescriptions with empty list
 * @tc.desc: 1. system running normally
 *           2. test AddSkillDescriptions with empty list
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, SkillsDescriptionManager_AddSkillDescriptions_0002,
    Function | SmallTest | Level0)
{
    auto skillsDescriptionManager = DelayedSingleton<SkillsDescriptionManager>::GetInstance();
    ASSERT_NE(skillsDescriptionManager, nullptr);

    std::vector<SkillsPackageInfo> skillInfoList;
    ErrCode ret = skillsDescriptionManager->AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: SkillsDescriptionManager_DeleteSkillDescriptions_0001
 * Function: SkillsDescriptionManager
 * @tc.name: test SkillsDescriptionManager DeleteSkillDescriptions by bundle name
 * @tc.desc: 1. system running normally
 *           2. test DeleteSkillDescriptions with empty bundle name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, SkillsDescriptionManager_DeleteSkillDescriptions_0001,
    Function | SmallTest | Level0)
{
    auto skillsDescriptionManager = DelayedSingleton<SkillsDescriptionManager>::GetInstance();
    ASSERT_NE(skillsDescriptionManager, nullptr);

    ErrCode ret = skillsDescriptionManager->DeleteSkillDescriptions("");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: SkillsDescriptionManager_DeleteSkillDescriptions_0002
 * Function: SkillsDescriptionManager
 * @tc.name: test SkillsDescriptionManager DeleteSkillDescriptions by bundle and module name
 * @tc.desc: 1. system running normally
 *           2. test DeleteSkillDescriptions with empty module name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, SkillsDescriptionManager_DeleteSkillDescriptions_0002,
    Function | SmallTest | Level0)
{
    auto skillsDescriptionManager = DelayedSingleton<SkillsDescriptionManager>::GetInstance();
    ASSERT_NE(skillsDescriptionManager, nullptr);

    ErrCode ret = skillsDescriptionManager->DeleteSkillDescriptions(BUNDLE_NAME, "");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: SkillsDescriptionManager_DeleteSkillDescriptions_0003
 * Function: SkillsDescriptionManager
 * @tc.name: test SkillsDescriptionManager DeleteSkillDescriptions by full path
 * @tc.desc: 1. system running normally
 *           2. test DeleteSkillDescriptions with empty skill name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, SkillsDescriptionManager_DeleteSkillDescriptions_0003,
    Function | SmallTest | Level0)
{
    auto skillsDescriptionManager = DelayedSingleton<SkillsDescriptionManager>::GetInstance();
    ASSERT_NE(skillsDescriptionManager, nullptr);

    ErrCode ret = skillsDescriptionManager->DeleteSkillDescriptions(BUNDLE_NAME, MODULE_NAME, "");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: SkillsDescriptionManager_Integration_0001
 * Function: SkillsDescriptionManager
 * @tc.name: test SkillsDescriptionManager integration
 * @tc.desc: 1. system running normally
 *           2. test full workflow: add and delete
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, SkillsDescriptionManager_Integration_0001, Function | SmallTest | Level0)
{
    auto skillsDescriptionManager = DelayedSingleton<SkillsDescriptionManager>::GetInstance();
    ASSERT_NE(skillsDescriptionManager, nullptr);

    // Add skills
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo skillInfo1;
    skillInfo1.bundleName = BUNDLE_NAME;
    skillInfo1.moduleName = MODULE_NAME;
    skillInfo1.skillsName = SKILL_NAME;
    skillInfo1.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo1);

    SkillsPackageInfo skillInfo2;
    skillInfo2.bundleName = BUNDLE_NAME;
    skillInfo2.moduleName = MODULE_NAME_TWO;
    skillInfo2.skillsName = SKILL_NAME_TWO;
    skillInfo2.description = DESCRIPTION_TWO;
    skillInfoList.push_back(skillInfo2);

    ErrCode ret = skillsDescriptionManager->AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Delete by module name
    ret = skillsDescriptionManager->DeleteSkillDescriptions(BUNDLE_NAME, MODULE_NAME);
    EXPECT_EQ(ret, ERR_OK);

    // Delete remaining by full path
    ret = skillsDescriptionManager->DeleteSkillDescriptions(BUNDLE_NAME, MODULE_NAME_TWO, SKILL_NAME_TWO);
    EXPECT_EQ(ret, ERR_OK);
}

} // OHOS
