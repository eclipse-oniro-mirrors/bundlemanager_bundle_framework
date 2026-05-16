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

#define private public
#include <gtest/gtest.h>
#include "skills_installer_util.h"
#include "inner_bundle_info.h"
#include "skills_installer/skills_package_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

class BmsSkillsInstallerUtilTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

// === ExtractSkillsPackage ===

TEST_F(BmsSkillsInstallerUtilTest, ExtractSkillsPackage_EmptyBundleName)
{
    std::vector<SkillsPackageInfo> skillInfoList;
    ErrCode ret = SkillsInstallerUtil::ExtractSkillsPackage(
        "", "module", "module", "/path/to.hsp", {"skill1"}, skillInfoList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

TEST_F(BmsSkillsInstallerUtilTest, ExtractSkillsPackage_EmptyModuleName)
{
    std::vector<SkillsPackageInfo> skillInfoList;
    ErrCode ret = SkillsInstallerUtil::ExtractSkillsPackage(
        "com.test", "", "module", "/path/to.hsp", {"skill1"}, skillInfoList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

TEST_F(BmsSkillsInstallerUtilTest, ExtractSkillsPackage_EmptyHspPath)
{
    std::vector<SkillsPackageInfo> skillInfoList;
    ErrCode ret = SkillsInstallerUtil::ExtractSkillsPackage(
        "com.test", "module", "module", "", {"skill1"}, skillInfoList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

TEST_F(BmsSkillsInstallerUtilTest, ExtractSkillsPackage_EmptyExtractModuleName)
{
    // When extractModuleName is empty, it should fall back to moduleName
    std::vector<SkillsPackageInfo> skillInfoList;
    // This will fail because the hspPath doesn't exist, but the param check should pass
    ErrCode ret = SkillsInstallerUtil::ExtractSkillsPackage(
        "com.test", "module", "", "/nonexistent.hsp", {"skill1"}, skillInfoList);
    // Should not be param error (empty extractModuleName is handled)
    EXPECT_NE(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

// === RemoveInvalidSkillProfiles ===

TEST_F(BmsSkillsInstallerUtilTest, RemoveInvalidSkillProfiles_EmptyList)
{
    InnerBundleInfo info;
    std::vector<SkillsPackageInfo> emptyList;
    ErrCode ret = SkillsInstallerUtil::RemoveInvalidSkillProfiles(emptyList, info);
    EXPECT_EQ(ret, ERR_OK);
}

TEST_F(BmsSkillsInstallerUtilTest, RemoveInvalidSkillProfiles_ModuleNotInMap_ClearsProfiles)
{
    InnerBundleInfo info;
    // Add a module with skillProfiles
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "module1";
    SkillProfile profile;
    profile.name = "oldSkill";
    moduleInfo.skillProfiles.push_back(profile);
    info.innerModuleInfos_["module1"] = moduleInfo;

    // validSkillsMap has no entry for "module1" -> skillProfiles should be cleared
    std::vector<SkillsPackageInfo> validSkills;
    SkillsPackageInfo pkgInfo;
    pkgInfo.moduleName = "otherModule";
    pkgInfo.skillsName = "skill";
    validSkills.push_back(pkgInfo);

    ErrCode ret = SkillsInstallerUtil::RemoveInvalidSkillProfiles(validSkills, info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(info.innerModuleInfos_["module1"].skillProfiles.empty());
}

TEST_F(BmsSkillsInstallerUtilTest, RemoveInvalidSkillProfiles_ModuleWithEmptyProfiles_NoChange)
{
    InnerBundleInfo info;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "module1";
    // skillProfiles is empty
    info.innerModuleInfos_["module1"] = moduleInfo;

    std::vector<SkillsPackageInfo> validSkills;
    SkillsPackageInfo pkgInfo;
    pkgInfo.moduleName = "module1";
    pkgInfo.skillsName = "skill1";
    validSkills.push_back(pkgInfo);

    ErrCode ret = SkillsInstallerUtil::RemoveInvalidSkillProfiles(validSkills, info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(info.innerModuleInfos_["module1"].skillProfiles.empty());
}

TEST_F(BmsSkillsInstallerUtilTest, RemoveInvalidSkillProfiles_InvalidProfileRemoved)
{
    InnerBundleInfo info;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "module1";
    SkillProfile validProfile;
    validProfile.name = "validSkill";
    SkillProfile invalidProfile;
    invalidProfile.name = "invalidSkill";
    moduleInfo.skillProfiles.push_back(validProfile);
    moduleInfo.skillProfiles.push_back(invalidProfile);
    info.innerModuleInfos_["module1"] = moduleInfo;

    std::vector<SkillsPackageInfo> validSkills;
    SkillsPackageInfo pkgInfo;
    pkgInfo.moduleName = "module1";
    pkgInfo.skillsName = "validSkill";
    validSkills.push_back(pkgInfo);

    ErrCode ret = SkillsInstallerUtil::RemoveInvalidSkillProfiles(validSkills, info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(info.innerModuleInfos_["module1"].skillProfiles.size(), 1u);
    EXPECT_EQ(info.innerModuleInfos_["module1"].skillProfiles[0].name, "validSkill");
}

TEST_F(BmsSkillsInstallerUtilTest, RemoveInvalidSkillProfiles_AllValid_NoRemoval)
{
    InnerBundleInfo info;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "module1";
    SkillProfile profile1;
    profile1.name = "skill1";
    SkillProfile profile2;
    profile2.name = "skill2";
    moduleInfo.skillProfiles.push_back(profile1);
    moduleInfo.skillProfiles.push_back(profile2);
    info.innerModuleInfos_["module1"] = moduleInfo;

    std::vector<SkillsPackageInfo> validSkills;
    SkillsPackageInfo pkg1;
    pkg1.moduleName = "module1";
    pkg1.skillsName = "skill1";
    SkillsPackageInfo pkg2;
    pkg2.moduleName = "module1";
    pkg2.skillsName = "skill2";
    validSkills.push_back(pkg1);
    validSkills.push_back(pkg2);

    ErrCode ret = SkillsInstallerUtil::RemoveInvalidSkillProfiles(validSkills, info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(info.innerModuleInfos_["module1"].skillProfiles.size(), 2u);
}
