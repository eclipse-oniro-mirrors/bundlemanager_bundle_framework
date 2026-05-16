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

#include <gtest/gtest.h>
#include "skills_description_manager.h"
#include "skills_installer/skills_package_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

class BmsSkillsDescriptionManagerTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

// === AddSkillDescriptions ===

TEST_F(BmsSkillsDescriptionManagerTest, AddSkillDescriptions_EmptyList)
{
    auto manager = SkillsDescriptionManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::vector<SkillsPackageInfo> emptyList;
    ErrCode ret = manager->AddSkillDescriptions(emptyList);
    EXPECT_NE(ret, ERR_OK);
}

TEST_F(BmsSkillsDescriptionManagerTest, AddSkillDescriptions_ValidList)
{
    auto manager = SkillsDescriptionManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::vector<SkillsPackageInfo> list;
    SkillsPackageInfo info;
    info.bundleName = "com.test.manager";
    info.moduleName = "entry";
    info.skillsName = "skill1";
    info.description = "test description";
    list.push_back(info);
    ErrCode ret = manager->AddSkillDescriptions(list);
    EXPECT_EQ(ret, ERR_OK);
    // Clean up
    manager->DeleteSkillDescriptions("com.test.manager");
}

// === DeleteSkillDescriptions(bundleName) ===

TEST_F(BmsSkillsDescriptionManagerTest, DeleteSkillDescriptions_ByBundleName_Empty)
{
    auto manager = SkillsDescriptionManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    ErrCode ret = manager->DeleteSkillDescriptions("");
    EXPECT_NE(ret, ERR_OK);
}

TEST_F(BmsSkillsDescriptionManagerTest, DeleteSkillDescriptions_ByBundleName_Success)
{
    auto manager = SkillsDescriptionManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    // First add
    std::vector<SkillsPackageInfo> list;
    SkillsPackageInfo info;
    info.bundleName = "com.test.delete.bundle";
    info.moduleName = "entry";
    info.skillsName = "skill1";
    info.description = "desc";
    list.push_back(info);
    manager->AddSkillDescriptions(list);
    // Then delete
    ErrCode ret = manager->DeleteSkillDescriptions("com.test.delete.bundle");
    EXPECT_EQ(ret, ERR_OK);
}

// === DeleteSkillDescriptions(bundleName, moduleName) ===

TEST_F(BmsSkillsDescriptionManagerTest, DeleteSkillDescriptions_ByModule_EmptyParams)
{
    auto manager = SkillsDescriptionManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    ErrCode ret = manager->DeleteSkillDescriptions("", "module");
    EXPECT_NE(ret, ERR_OK);
    ret = manager->DeleteSkillDescriptions("bundle", "");
    EXPECT_NE(ret, ERR_OK);
}

TEST_F(BmsSkillsDescriptionManagerTest, DeleteSkillDescriptions_ByModule_Success)
{
    auto manager = SkillsDescriptionManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::vector<SkillsPackageInfo> list;
    SkillsPackageInfo info;
    info.bundleName = "com.test.delete.module";
    info.moduleName = "entry";
    info.skillsName = "skill1";
    info.description = "desc";
    list.push_back(info);
    manager->AddSkillDescriptions(list);
    ErrCode ret = manager->DeleteSkillDescriptions("com.test.delete.module", "entry");
    EXPECT_EQ(ret, ERR_OK);
}

// === DeleteSkillDescriptions(bundleName, moduleName, skillName) ===

TEST_F(BmsSkillsDescriptionManagerTest, DeleteSkillDescriptions_BySkill_EmptyParams)
{
    auto manager = SkillsDescriptionManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    ErrCode ret = manager->DeleteSkillDescriptions("", "module", "skill");
    EXPECT_NE(ret, ERR_OK);
    ret = manager->DeleteSkillDescriptions("bundle", "", "skill");
    EXPECT_NE(ret, ERR_OK);
    ret = manager->DeleteSkillDescriptions("bundle", "module", "");
    EXPECT_NE(ret, ERR_OK);
}

TEST_F(BmsSkillsDescriptionManagerTest, DeleteSkillDescriptions_BySkill_Success)
{
    auto manager = SkillsDescriptionManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::vector<SkillsPackageInfo> list;
    SkillsPackageInfo info;
    info.bundleName = "com.test.delete.skill";
    info.moduleName = "entry";
    info.skillsName = "skill1";
    info.description = "desc";
    list.push_back(info);
    manager->AddSkillDescriptions(list);
    ErrCode ret = manager->DeleteSkillDescriptions("com.test.delete.skill", "entry", "skill1");
    EXPECT_EQ(ret, ERR_OK);
}

// === GetSkillDescription ===

TEST_F(BmsSkillsDescriptionManagerTest, GetSkillDescription_Success)
{
    auto manager = SkillsDescriptionManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    // First add
    std::vector<SkillsPackageInfo> list;
    SkillsPackageInfo info;
    info.bundleName = "com.test.get";
    info.moduleName = "entry";
    info.skillsName = "skill1";
    info.description = "test description for get";
    list.push_back(info);
    manager->AddSkillDescriptions(list);
    // Then get
    std::string description;
    ErrCode ret = manager->GetSkillDescription("com.test.get", "entry", "skill1", description);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(description, "test description for get");
    // Clean up
    manager->DeleteSkillDescriptions("com.test.get");
}

TEST_F(BmsSkillsDescriptionManagerTest, GetSkillDescription_NotFound)
{
    auto manager = SkillsDescriptionManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::string description;
    ErrCode ret = manager->GetSkillDescription("com.test.notexist", "module", "skill", description);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(description.empty());
}
