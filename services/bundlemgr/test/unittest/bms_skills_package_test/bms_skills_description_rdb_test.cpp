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

/**
 * @tc.number: GetSkillDescription_0001
 * Function: SkillsDescriptionRdb
 * @tc.name: test GetSkillDescription with existing skill
 * @tc.desc: 1. system running normally
 *           2. test GetSkillDescription returns correct description for existing skill
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, GetSkillDescription_0001, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    // First add a skill description
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillsName = SKILL_NAME;
    skillInfo.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Then query it
    std::string description;
    ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME, SKILL_NAME, description);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(description, DESCRIPTION);

    // Clean up
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetSkillDescription_0002
 * Function: SkillsDescriptionRdb
 * @tc.name: test GetSkillDescription with non-existent skill
 * @tc.desc: 1. system running normally
 *           2. test GetSkillDescription returns ERR_OK for non-existent skill
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, GetSkillDescription_0002, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    std::string description = "original_value";
    ErrCode ret = skillsDescriptionRdb.GetSkillDescription("non.existent.bundle", "invalidModule", "invalidSkill", description);
    EXPECT_EQ(ret, ERR_OK);
    // Description should remain unchanged when skill is not found
    EXPECT_EQ(description, "original_value");
}

/**
 * @tc.number: GetSkillDescription_0003
 * Function: SkillsDescriptionRdb
 * @tc.name: test GetSkillDescription with empty bundle name
 * @tc.desc: 1. system running normally
 *           2. test GetSkillDescription handles empty bundle name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, GetSkillDescription_0003, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    std::string description;
    ErrCode ret = skillsDescriptionRdb.GetSkillDescription("", MODULE_NAME, SKILL_NAME, description);
    EXPECT_EQ(ret, ERR_OK);
    // Should not find anything with empty bundle name
    EXPECT_TRUE(description.empty());
}

/**
 * @tc.number: GetSkillDescription_0004
 * Function: SkillsDescriptionRdb
 * @tc.name: test GetSkillDescription with empty module name
 * @tc.desc: 1. system running normally
 *           2. test GetSkillDescription handles empty module name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, GetSkillDescription_0004, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    std::string description;
    ErrCode ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, "", SKILL_NAME, description);
    EXPECT_EQ(ret, ERR_OK);
    // Should not find anything with empty module name
    EXPECT_TRUE(description.empty());
}

/**
 * @tc.number: GetSkillDescription_0005
 * Function: SkillsDescriptionRdb
 * @tc.name: test GetSkillDescription with empty skill name
 * @tc.desc: 1. system running normally
 *           2. test GetSkillDescription handles empty skill name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, GetSkillDescription_0005, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    std::string description;
    ErrCode ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME, "", description);
    EXPECT_EQ(ret, ERR_OK);
    // Should not find anything with empty skill name
    EXPECT_TRUE(description.empty());
}

/**
 * @tc.number: GetSkillDescription_0006
 * Function: SkillsDescriptionRdb
 * @tc.name: test GetSkillDescription after delete
 * @tc.desc: 1. system running normally
 *           2. test GetSkillDescription returns ERR_OK after skill is deleted
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, GetSkillDescription_0006, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    // Add a skill description
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillsName = SKILL_NAME;
    skillInfo.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Verify it exists
    std::string description;
    ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME, SKILL_NAME, description);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(description, DESCRIPTION);

    // Delete it
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME, MODULE_NAME, SKILL_NAME);
    EXPECT_EQ(ret, ERR_OK);

    // Query again - should not find it
    std::string descriptionAfterDelete;
    ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME, SKILL_NAME, descriptionAfterDelete);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(descriptionAfterDelete.empty());
}

/**
 * @tc.number: GetSkillDescription_0007
 * Function: SkillsDescriptionRdb
 * @tc.name: test GetSkillDescription after update
 * @tc.desc: 1. system running normally
 *           2. test GetSkillDescription returns updated description
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, GetSkillDescription_0007, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    // Add initial skill description
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillsName = SKILL_NAME;
    skillInfo.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Query initial description
    std::string description;
    ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME, SKILL_NAME, description);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(description, DESCRIPTION);

    // Update with new description
    std::vector<SkillsPackageInfo> updatedList;
    SkillsPackageInfo updatedInfo;
    updatedInfo.bundleName = BUNDLE_NAME;
    updatedInfo.moduleName = MODULE_NAME;
    updatedInfo.skillsName = SKILL_NAME;
    updatedInfo.description = DESCRIPTION_TWO;
    updatedList.push_back(updatedInfo);

    ret = skillsDescriptionRdb.AddSkillDescriptions(updatedList);
    EXPECT_EQ(ret, ERR_OK);

    // Query updated description
    std::string updatedDescription;
    ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME, SKILL_NAME, updatedDescription);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(updatedDescription, DESCRIPTION_TWO);

    // Clean up
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetSkillDescription_0008
 * Function: SkillsDescriptionRdb
 * @tc.name: test GetSkillDescription with multiple skills
 * @tc.desc: 1. system running normally
 *           2. test GetSkillDescription returns correct description for each skill
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, GetSkillDescription_0008, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    // Add multiple skills
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

    // Query first skill
    std::string description1;
    ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME, SKILL_NAME, description1);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(description1, DESCRIPTION);

    // Query second skill
    std::string description2;
    ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME_TWO, SKILL_NAME_TWO, description2);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(description2, DESCRIPTION_TWO);

    // Clean up
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetSkillDescription_0009
 * Function: SkillsDescriptionRdb
 * @tc.name: test GetSkillDescription with special characters
 * @tc.desc: 1. system running normally
 *           2. test GetSkillDescription handles special characters in skill name
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, GetSkillDescription_0009, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    // Add skill with special characters
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillsName = "skill-with_special.chars";
    skillInfo.description = "Description with special characters: !@#$%^&*()";
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Query the skill
    std::string description;
    ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME, "skill-with_special.chars", description);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(description, "Description with special characters: !@#$%^&*()");

    // Clean up
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetSkillDescription_0010
 * Function: SkillsDescriptionRdb
 * @tc.name: test GetSkillDescription with empty description
 * @tc.desc: 1. system running normally
 *           2. test GetSkillDescription handles empty description
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, GetSkillDescription_0010, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    // Add skill with empty description
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillsName = SKILL_NAME;
    skillInfo.description = "";
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Query the skill
    std::string description;
    ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME, SKILL_NAME, description);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(description.empty());

    // Clean up
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetSkillDescription_0011
 * Function: SkillsDescriptionRdb
 * @tc.name: test GetSkillDescription with long description
 * @tc.desc: 1. system running normally
 *           2. test GetSkillDescription handles long description text
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, GetSkillDescription_0011, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    // Create a long description (1000 characters)
    std::string longDescription(1000, 'A');

    // Add skill with long description
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillsName = SKILL_NAME;
    skillInfo.description = longDescription;
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Query the skill
    std::string description;
    ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME, SKILL_NAME, description);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(description, longDescription);

    // Clean up
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetSkillDescription_0012
 * Function: SkillsDescriptionRdb
 * @tc.name: test GetSkillDescription multiple times
 * @tc.desc: 1. system running normally
 *           2. test GetSkillDescription returns consistent results on repeated queries
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, GetSkillDescription_0012, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    // Add a skill description
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillsName = SKILL_NAME;
    skillInfo.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Query multiple times
    for (int i = 0; i < 5; i++) {
        std::string description;
        ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME, SKILL_NAME, description);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_EQ(description, DESCRIPTION);
    }

    // Clean up
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetSkillDescription_0013
 * Function: SkillsDescriptionRdb
 * @tc.name: test GetSkillDescription with different bundles
 * @tc.desc: 1. system running normally
 *           2. test GetSkillDescription correctly distinguishes between different bundles
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, GetSkillDescription_0013, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    // Add skills for different bundles
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo skillInfo1;
    skillInfo1.bundleName = BUNDLE_NAME;
    skillInfo1.moduleName = MODULE_NAME;
    skillInfo1.skillsName = SKILL_NAME;
    skillInfo1.description = DESCRIPTION;
    skillInfoList.push_back(skillInfo1);

    SkillsPackageInfo skillInfo2;
    skillInfo2.bundleName = "com.example.another.bundle";
    skillInfo2.moduleName = MODULE_NAME;
    skillInfo2.skillsName = SKILL_NAME;
    skillInfo2.description = DESCRIPTION_TWO;
    skillInfoList.push_back(skillInfo2);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Query first bundle
    std::string description1;
    ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME, SKILL_NAME, description1);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(description1, DESCRIPTION);

    // Query second bundle
    std::string description2;
    ret = skillsDescriptionRdb.GetSkillDescription("com.example.another.bundle", MODULE_NAME, SKILL_NAME, description2);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(description2, DESCRIPTION_TWO);

    // Clean up
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
    ret = skillsDescriptionRdb.DeleteSkillDescriptions("com.example.another.bundle");
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetSkillDescription_0014
 * Function: SkillsDescriptionRdb
 * @tc.name: test GetSkillDescription with unicode characters
 * @tc.desc: 1. system running normally
 *           2. test GetSkillDescription handles unicode characters in description
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, GetSkillDescription_0014, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    // Add skill with unicode description
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillsName = SKILL_NAME;
    skillInfo.description = "测试描述中文🎉🚀";
    skillInfoList.push_back(skillInfo);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Query the skill
    std::string description;
    ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME, SKILL_NAME, description);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(description, "测试描述中文🎉🚀");

    // Clean up
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetSkillDescription_0015
 * Function: SkillsDescriptionRdb
 * @tc.name: test GetSkillDescription parameter consistency
 * @tc.desc: 1. system running normally
 *           2. test GetSkillDescription with same skill in different modules
 */
HWTEST_F(BmsSkillsDescriptionRdbTest, GetSkillDescription_0015, Function | SmallTest | Level0)
{
    SkillsDescriptionRdb skillsDescriptionRdb;

    // Add same skill name in different modules
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
    skillInfo2.skillsName = SKILL_NAME;
    skillInfo2.description = DESCRIPTION_TWO;
    skillInfoList.push_back(skillInfo2);

    ErrCode ret = skillsDescriptionRdb.AddSkillDescriptions(skillInfoList);
    EXPECT_EQ(ret, ERR_OK);

    // Query skill in first module
    std::string description1;
    ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME, SKILL_NAME, description1);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(description1, DESCRIPTION);

    // Query skill in second module
    std::string description2;
    ret = skillsDescriptionRdb.GetSkillDescription(BUNDLE_NAME, MODULE_NAME_TWO, SKILL_NAME, description2);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(description2, DESCRIPTION_TWO);

    // Clean up
    ret = skillsDescriptionRdb.DeleteSkillDescriptions(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

} // OHOS
