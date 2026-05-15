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
#include "bundle_skill/skill_info.h"
#include "parcel.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int32_t TEST_VERSION_CODE = 100;
constexpr size_t TEST_LARGE_SRC_ENTRIES_SIZE = 100;
constexpr size_t TEST_LARGE_PERMISSIONS_SIZE = 50;
constexpr size_t TEST_LARGE_REQUEST_PERMISSIONS_SIZE = 25;
}

class BmsSkillInfoTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

SkillInfo CreateTestSkillInfo()
{
    SkillInfo info;
    info.bundleName = "com.test.bundle";
    info.moduleName = "entry";
    info.skillName = "MainSkill";
    info.skillType = SkillType::INDEPENDENT_SKILL;
    info.hapPath = "/data/app/test.hap";
    info.skillPath = "/data/app/skills/test";
    info.versionCode = TEST_VERSION_CODE;
    info.abilityName = "MainAbility";
    info.description = "test skill";
    info.srcEntries = {"entry1", "entry2"};
    info.permissions = {"perm1", "perm2"};
    info.requestPermissions = {"reqPerm1"};
    return info;
}

TEST_F(BmsSkillInfoTest, MarshallingAndUnmarshalling_Success)
{
    SkillInfo original = CreateTestSkillInfo();
    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    SkillInfo *restored = SkillInfo::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->bundleName, original.bundleName);
    EXPECT_EQ(restored->moduleName, original.moduleName);
    EXPECT_EQ(restored->skillName, original.skillName);
    EXPECT_EQ(restored->skillType, original.skillType);
    EXPECT_EQ(restored->hapPath, original.hapPath);
    EXPECT_EQ(restored->skillPath, original.skillPath);
    EXPECT_EQ(restored->versionCode, original.versionCode);
    EXPECT_EQ(restored->abilityName, original.abilityName);
    EXPECT_EQ(restored->description, original.description);
    EXPECT_EQ(restored->srcEntries, original.srcEntries);
    EXPECT_EQ(restored->permissions, original.permissions);
    EXPECT_EQ(restored->requestPermissions, original.requestPermissions);
    delete restored;
}

TEST_F(BmsSkillInfoTest, Unmarshalling_EmptyParcel_ReturnsNull)
{
    Parcel parcel;
    SkillInfo *result = SkillInfo::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

TEST_F(BmsSkillInfoTest, Marshalling_EmptyVectors)
{
    SkillInfo info;
    info.bundleName = "com.test";
    info.moduleName = "mod";
    info.skillName = "skill";
    Parcel parcel;
    ASSERT_TRUE(info.Marshalling(parcel));

    SkillInfo *restored = SkillInfo::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_TRUE(restored->srcEntries.empty());
    EXPECT_TRUE(restored->permissions.empty());
    EXPECT_TRUE(restored->requestPermissions.empty());
    delete restored;
}

TEST_F(BmsSkillInfoTest, Marshalling_LargeVectors)
{
    SkillInfo info;
    info.bundleName = "com.test";
    info.moduleName = "mod";
    info.skillName = "skill";
    info.srcEntries = std::vector<std::string>(TEST_LARGE_SRC_ENTRIES_SIZE, "entry");
    info.permissions = std::vector<std::string>(TEST_LARGE_PERMISSIONS_SIZE, "perm");
    info.requestPermissions = std::vector<std::string>(TEST_LARGE_REQUEST_PERMISSIONS_SIZE, "reqPerm");
    Parcel parcel;
    ASSERT_TRUE(info.Marshalling(parcel));
    SkillInfo *restored = SkillInfo::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->srcEntries.size(), TEST_LARGE_SRC_ENTRIES_SIZE);
    EXPECT_EQ(restored->permissions.size(), TEST_LARGE_PERMISSIONS_SIZE);
    EXPECT_EQ(restored->requestPermissions.size(), TEST_LARGE_REQUEST_PERMISSIONS_SIZE);
    delete restored;
}

TEST_F(BmsSkillInfoTest, SkillType_APP_SKILL)
{
    SkillInfo info;
    info.skillType = SkillType::APP_SKILL;
    Parcel parcel;
    ASSERT_TRUE(info.Marshalling(parcel));
    SkillInfo *restored = SkillInfo::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->skillType, SkillType::APP_SKILL);
    delete restored;
}

TEST_F(BmsSkillInfoTest, SkillType_INDEPENDENT_SKILL)
{
    SkillInfo info;
    info.skillType = SkillType::INDEPENDENT_SKILL;
    Parcel parcel;
    ASSERT_TRUE(info.Marshalling(parcel));
    SkillInfo *restored = SkillInfo::Unmarshalling(parcel);
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->skillType, SkillType::INDEPENDENT_SKILL);
    delete restored;
}
