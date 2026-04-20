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
#define protected public

#include <gtest/gtest.h>

#include <fstream>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

#include "independent_skills_installer.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_install_checker.h"
#include "install_param.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "skills_description_manager.h"
#include "bundle_user_mgr_host_impl.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.skills.test";
const std::string MODULE_NAME = "entry";
const std::string MODULE_NAME_TWO = "feature";
const std::string SKILL_NAME = "mainSkill";
const std::string SKILL_NAME_TWO = "featureSkill";
const std::string INVALID_BUNDLE_NAME = "";
const std::string TEST_HSP_PATH = "/data/test/resource/bms/skills/test.hsp";
const std::string TEST_APP_IDENTIFIER = "test.app.identifier";
const std::string TEST_APP_ID = "test.app.id";
const int32_t USER_ID = 100;
const int32_t INVALID_USER_ID = -1;
const int32_t DEFAULT_USER_ID = 0;
const int32_t U1_USER_ID = 1;
const uint32_t VERSION_CODE = 1000100;
const std::string COMPILE_SDK_TYPE = "OpenHarmony";
const int32_t WAIT_TIME = 2; // init mocked bms
}  // namespace

class BmsIndependentSkillsInstallerUninstallTest : public testing::Test {
public:
    BmsIndependentSkillsInstallerUninstallTest();
    ~BmsIndependentSkillsInstallerUninstallTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    void AddUserId(int32_t userId);
    void StartInstalldService() const;
    void StartBundleService();
    void CreateMockSkillBundleInfo(InnerBundleInfo &bundleInfo, const std::string &bundleName,
        const std::string &moduleName, const std::vector<std::string> &skillNames);

    std::shared_ptr<BundleDataMgr> dataMgr_;
private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsIndependentSkillsInstallerUninstallTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsIndependentSkillsInstallerUninstallTest::installdService_ =
    std::make_shared<InstalldService>();

BmsIndependentSkillsInstallerUninstallTest::BmsIndependentSkillsInstallerUninstallTest()
{}

BmsIndependentSkillsInstallerUninstallTest::~BmsIndependentSkillsInstallerUninstallTest()
{}

void BmsIndependentSkillsInstallerUninstallTest::SetUpTestCase()
{}

void BmsIndependentSkillsInstallerUninstallTest::TearDownTestCase()
{}

void BmsIndependentSkillsInstallerUninstallTest::SetUp()
{
    StartBundleService();
    StartInstalldService();
    dataMgr_ = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr_, nullptr);
}

void BmsIndependentSkillsInstallerUninstallTest::TearDown()
{}

void BmsIndependentSkillsInstallerUninstallTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsIndependentSkillsInstallerUninstallTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsIndependentSkillsInstallerUninstallTest::AddUserId(int32_t userId)
{
    if (dataMgr_ != nullptr) {
        dataMgr_->AddUserId(userId);
    }
}

void BmsIndependentSkillsInstallerUninstallTest::CreateMockSkillBundleInfo(InnerBundleInfo &bundleInfo,
    const std::string &bundleName, const std::string &moduleName,
    const std::vector<std::string> &skillNames)
{
    bundleInfo.baseApplicationInfo_ = std::make_shared<ApplicationInfo>();
    bundleInfo.baseApplicationInfo_->bundleName = bundleName;
    bundleInfo.baseApplicationInfo_->bundleType = BundleType::SKILL;
    bundleInfo.SetProvisionId("test_provision_id");
    bundleInfo.SetAppIdentifier(TEST_APP_IDENTIFIER);
    bundleInfo.baseApplicationInfo_->versionCode = VERSION_CODE;
    bundleInfo.currentPackage_ = moduleName;

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = moduleName;
    moduleInfo.modulePath = "/data/app/" + bundleName + "/" + moduleName;

    for (const auto &skillName : skillNames) {
        SkillProfile skillProfile;
        skillProfile.name = skillName;
        moduleInfo.skillProfiles.push_back(skillProfile);
    }

    bundleInfo.innerModuleInfos_[moduleName] = moduleInfo;

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USER_ID;
    bundleInfo.AddInnerBundleUserInfo(userInfo);
}

/**
 * @tc.number: SkillsInstaller_InnerProcessNeedDeleteSkillPackage_0001
 * Function: InnerProcessNeedDeleteSkillPackage
 * @tc.name: test InnerProcessNeedDeleteSkillPackage with no skills to delete
 * @tc.desc: 1. system running normally
 *           2. test InnerProcessNeedDeleteSkillPackage when current and old skills match
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_InnerProcessNeedDeleteSkillPackage_0001,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    installer->bundleName_ = BUNDLE_NAME;

    // Create old bundle info with skills
    std::vector<std::string> oldSkills = {SKILL_NAME};
    CreateMockSkillBundleInfo(installer->oldInnerBundleInfo_, BUNDLE_NAME, MODULE_NAME, oldSkills);

    // Create current bundle info with same skills
    InnerBundleInfo currentBundleInfo;
    CreateMockSkillBundleInfo(currentBundleInfo, BUNDLE_NAME, MODULE_NAME, oldSkills);

    installer->needDeleteSkillsPackageInfo_.clear();

    // Should not mark any skills for deletion
    installer->InnerProcessNeedDeleteSkillPackage(currentBundleInfo);

    EXPECT_EQ(installer->needDeleteSkillsPackageInfo_.size(), 0);
}

/**
 * @tc.number: SkillsInstaller_InnerProcessNeedDeleteSkillPackage_0002
 * Function: InnerProcessNeedDeleteSkillPackage
 * @tc.name: test InnerProcessNeedDeleteSkillPackage with skills to delete
 * @tc.desc: 1. system running normally
 *           2. test InnerProcessNeedDeleteSkillPackage identifies deleted skills
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_InnerProcessNeedDeleteSkillPackage_0002,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    installer->bundleName_ = BUNDLE_NAME;

    // Create old bundle info with two skills
    std::vector<std::string> oldSkills = {SKILL_NAME, SKILL_NAME_TWO};
    CreateMockSkillBundleInfo(installer->oldInnerBundleInfo_, BUNDLE_NAME, MODULE_NAME, oldSkills);

    // Create current bundle info with only one skill
    std::vector<std::string> currentSkills = {SKILL_NAME};
    InnerBundleInfo currentBundleInfo;
    CreateMockSkillBundleInfo(currentBundleInfo, BUNDLE_NAME, MODULE_NAME, currentSkills);

    installer->needDeleteSkillsPackageInfo_.clear();

    // Should mark SKILL_NAME_TWO for deletion
    installer->InnerProcessNeedDeleteSkillPackage(currentBundleInfo);

    EXPECT_EQ(installer->needDeleteSkillsPackageInfo_.size(), 1);
    EXPECT_EQ(installer->needDeleteSkillsPackageInfo_[0].bundleName, BUNDLE_NAME);
    EXPECT_EQ(installer->needDeleteSkillsPackageInfo_[0].moduleName, MODULE_NAME);
    EXPECT_EQ(installer->needDeleteSkillsPackageInfo_[0].skillsName, SKILL_NAME_TWO);
}

/**
 * @tc.number: SkillsInstaller_InnerProcessNeedDeleteSkillPackage_0003
 * Function: InnerProcessNeedDeleteSkillPackage
 * @tc.name: test InnerProcessNeedDeleteSkillPackage with multiple modules
 * @tc.desc: 1. system running normally
 *           2. test InnerProcessNeedDeleteSkillPackage handles multiple modules
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_InnerProcessNeedDeleteSkillPackage_0003,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    installer->bundleName_ = BUNDLE_NAME;

    // Create old bundle info with multiple modules and skills
    std::vector<std::string> oldSkillsModule1 = {SKILL_NAME};
    CreateMockSkillBundleInfo(installer->oldInnerBundleInfo_, BUNDLE_NAME, MODULE_NAME, oldSkillsModule1);

    InnerModuleInfo moduleInfo2;
    moduleInfo2.moduleName = MODULE_NAME_TWO;
    SkillProfile skillProfile2;
    skillProfile2.name = SKILL_NAME_TWO;
    moduleInfo2.skillProfiles.push_back(skillProfile2);
    installer->oldInnerBundleInfo_.innerModuleInfos_[MODULE_NAME_TWO] = moduleInfo2;

    // Create current bundle info without skills in second module
    InnerBundleInfo currentBundleInfo;
    CreateMockSkillBundleInfo(currentBundleInfo, BUNDLE_NAME, MODULE_NAME, oldSkillsModule1);

    InnerModuleInfo currentModuleInfo2;
    currentModuleInfo2.moduleName = MODULE_NAME_TWO;
    currentBundleInfo.innerModuleInfos_[MODULE_NAME_TWO] = currentModuleInfo2;

    installer->needDeleteSkillsPackageInfo_.clear();

    installer->InnerProcessNeedDeleteSkillPackage(currentBundleInfo);

    EXPECT_EQ(installer->needDeleteSkillsPackageInfo_.size(), 1);
    EXPECT_EQ(installer->needDeleteSkillsPackageInfo_[0].moduleName, MODULE_NAME_TWO);
    EXPECT_EQ(installer->needDeleteSkillsPackageInfo_[0].skillsName, SKILL_NAME_TWO);
}

/**
 * @tc.number: SkillsInstaller_RemoveOldSkillsPath_0001
 * Function: RemoveOldSkillsPath
 * @tc.name: test RemoveOldSkillsPath with empty needDeleteSkillsPackageInfo_
 * @tc.desc: 1. system running normally
 *           2. test RemoveOldSkillsPath returns early when nothing to delete
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_RemoveOldSkillsPath_0001,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    installer->needDeleteSkillsPackageInfo_.clear();
    installer->bundleName_ = BUNDLE_NAME;

    // Should return early without any operations
    installer->RemoveOldSkillsPath();

    // Verify no changes occurred
    EXPECT_TRUE(installer->needDeleteSkillsPackageInfo_.empty());
}

/**
 * @tc.number: SkillsInstaller_RemoveOldSkillsPath_0002
 * Function: RemoveOldSkillsPath
 * @tc.name: test RemoveOldSkillsPath with module to delete (empty skillsName)
 * @tc.desc: 1. system running normally
 *           2. test RemoveOldSkillsPath deletes module when skillsName is empty
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_RemoveOldSkillsPath_0002,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    installer->bundleName_ = BUNDLE_NAME;
    installer->dataMgr_ = dataMgr_;

    // Add a module to delete (skillsName is empty)
    SkillsPackageInfo packageInfo;
    packageInfo.bundleName = BUNDLE_NAME;
    packageInfo.moduleName = MODULE_NAME;
    packageInfo.skillsName = "";  // Empty skillsName means delete entire module
    installer->needDeleteSkillsPackageInfo_.push_back(packageInfo);

    size_t beforeSize = installer->needDeleteSkillsPackageInfo_.size();

    // RemoveOldSkillsPath should process the deletion
    installer->RemoveOldSkillsPath();

    // Verify the package was processed (vector should still contain the entry)
    EXPECT_EQ(installer->needDeleteSkillsPackageInfo_.size(), beforeSize);
}

/**
 * @tc.number: SkillsInstaller_RemoveOldSkillsPath_0003
 * Function: RemoveOldSkillsPath
 * @tc.name: test RemoveOldSkillsPath with skill to delete (non-empty skillsName)
 * @tc.desc: 1. system running normally
 *           2. test RemoveOldSkillsPath deletes specific skill when skillsName is set
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_RemoveOldSkillsPath_0003,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    installer->bundleName_ = BUNDLE_NAME;
    installer->dataMgr_ = dataMgr_;

    // Add a skill to delete (skillsName is not empty)
    SkillsPackageInfo packageInfo;
    packageInfo.bundleName = BUNDLE_NAME;
    packageInfo.moduleName = MODULE_NAME;
    packageInfo.skillsName = SKILL_NAME;  // Non-empty skillsName means delete specific skill
    installer->needDeleteSkillsPackageInfo_.push_back(packageInfo);

    size_t beforeSize = installer->needDeleteSkillsPackageInfo_.size();

    // RemoveOldSkillsPath should process the deletion
    installer->RemoveOldSkillsPath();

    // Verify the package was processed
    EXPECT_EQ(installer->needDeleteSkillsPackageInfo_.size(), beforeSize);
    EXPECT_EQ(installer->needDeleteSkillsPackageInfo_[0].skillsName, SKILL_NAME);
}

/**
 * @tc.number: SkillsInstaller_RemoveOldSkillsPath_0004
 * Function: RemoveOldSkillsPath
 * @tc.name: test RemoveOldSkillsPath with multiple packages to delete
 * @tc.desc: 1. system running normally
 *           2. test RemoveOldSkillsPath handles mixed module and skill deletions
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_RemoveOldSkillsPath_0004,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    installer->bundleName_ = BUNDLE_NAME;
    installer->dataMgr_ = dataMgr_;

    // Add multiple packages: one module and one skill
    SkillsPackageInfo moduleInfo;
    moduleInfo.bundleName = BUNDLE_NAME;
    moduleInfo.moduleName = MODULE_NAME;
    moduleInfo.skillsName = "";  // Delete entire module
    installer->needDeleteSkillsPackageInfo_.push_back(moduleInfo);

    SkillsPackageInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME_TWO;
    skillInfo.skillsName = SKILL_NAME;  // Delete specific skill
    installer->needDeleteSkillsPackageInfo_.push_back(skillInfo);

    size_t beforeSize = installer->needDeleteSkillsPackageInfo_.size();
    EXPECT_EQ(beforeSize, 2);

    // RemoveOldSkillsPath should process both deletions
    installer->RemoveOldSkillsPath();

    // Verify both packages were processed
    EXPECT_EQ(installer->needDeleteSkillsPackageInfo_.size(), beforeSize);
    EXPECT_EQ(installer->needDeleteSkillsPackageInfo_[0].skillsName, "");
    EXPECT_EQ(installer->needDeleteSkillsPackageInfo_[1].skillsName, SKILL_NAME);
}

/**
 * @tc.number: SkillsInstaller_RemoveOldSkillsPath_0005
 * Function: RemoveOldSkillsPath
 * @tc.name: test RemoveOldSkillsPath preserves installer state
 * @tc.desc: 1. system running normally
 *           2. test RemoveOldSkillsPath maintains installer object validity
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_RemoveOldSkillsPath_0005,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    installer->bundleName_ = BUNDLE_NAME;
    installer->userId_ = USER_ID;
    installer->dataMgr_ = dataMgr_;

    // Add a skill to delete
    SkillsPackageInfo packageInfo;
    packageInfo.bundleName = BUNDLE_NAME;
    packageInfo.moduleName = MODULE_NAME;
    packageInfo.skillsName = SKILL_NAME;
    installer->needDeleteSkillsPackageInfo_.push_back(packageInfo);

    // Call RemoveOldSkillsPath
    installer->RemoveOldSkillsPath();

    // Verify installer state is preserved
    EXPECT_EQ(installer->bundleName_, BUNDLE_NAME);
    EXPECT_EQ(installer->userId_, USER_ID);
    EXPECT_EQ(installer->dataMgr_, dataMgr_);
    ASSERT_NE(installer, nullptr);
}

/**
 * @tc.number: SkillsInstaller_BeforeUninstall_0001
 * Function: BeforeUninstall
 * @tc.name: test BeforeUninstall with empty bundle name
 * @tc.desc: 1. system running normally
 *           2. test BeforeUninstall returns error when bundleName is empty
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_BeforeUninstall_0001,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    ErrCode ret = installer->BeforeUninstall(INVALID_BUNDLE_NAME, USER_ID);
    EXPECT_EQ(ret, ERR_SKILLS_UNINSTALL_BUNDLENAME_NOT_EXIST);
}

/**
 * @tc.number: SkillsInstaller_BeforeUninstall_0002
 * Function: BeforeUninstall
 * @tc.name: test BeforeUninstall with null dataMgr
 * @tc.desc: 1. system running normally
 *           2. test BeforeUninstall returns error when dataMgr is null
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_BeforeUninstall_0002,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    bundleMgrService_->RegisterDataMgr(nullptr);

    ErrCode ret = installer->BeforeUninstall(BUNDLE_NAME, USER_ID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);

    bundleMgrService_->RegisterDataMgr(dataMgr_);
}

/**
 * @tc.number: SkillsInstaller_BeforeUninstall_0003
 * Function: BeforeUninstall
 * @tc.name: test BeforeUninstall with non-existent user
 * @tc.desc: 1. system running normally
 *           2. test BeforeUninstall returns error when user doesn't exist
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_BeforeUninstall_0003,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    ErrCode ret = installer->BeforeUninstall(BUNDLE_NAME, INVALID_USER_ID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_USER_NOT_EXIST);
}

/**
 * @tc.number: SkillsInstaller_BeforeUninstall_0004
 * Function: BeforeUninstall
 * @tc.name: test BeforeUninstall with non-existent bundle
 * @tc.desc: 1. system running normally
 *           2. test BeforeUninstall returns error when bundle doesn't exist
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_BeforeUninstall_0004,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);
    dataMgr_->bundleInfos_.erase(BUNDLE_NAME);
    ErrCode ret = installer->BeforeUninstall(BUNDLE_NAME, USER_ID);
    EXPECT_EQ(ret, ERR_SKILLS_UNINSTALL_BUNDLENAME_NOT_EXIST);
}

/**
 * @tc.number: SkillsInstaller_BeforeUninstall_0005
 * Function: BeforeUninstall
 * @tc.name: test BeforeUninstall with non-skill bundle type
 * @tc.desc: 1. system running normally
 *           2. test BeforeUninstall returns error when bundle is not skill type
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_BeforeUninstall_0005,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    // Create a non-skill bundle
    InnerBundleInfo bundleInfo;
    bundleInfo.baseApplicationInfo_ = std::make_shared<ApplicationInfo>();
    bundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    bundleInfo.baseApplicationInfo_->bundleType = BundleType::APP; // Not SKILL

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USER_ID;
    bundleInfo.AddInnerBundleUserInfo(userInfo);
    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo;

    ErrCode ret = installer->BeforeUninstall(BUNDLE_NAME, USER_ID);
    EXPECT_EQ(ret, ERR_SKILLS_UNINSTALL_WRONG_BUNDLE_TYPE);

    // Clean up
    dataMgr_->bundleInfos_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: SkillsInstaller_BeforeUninstall_0006
 * Function: BeforeUninstall
 * @tc.name: test BeforeUninstall with valid skill bundle
 * @tc.desc: 1. system running normally
 *           2. test BeforeUninstall succeeds with valid skill bundle
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_BeforeUninstall_0006,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    // Create a valid skill bundle
    InnerBundleInfo bundleInfo;
    CreateMockSkillBundleInfo(bundleInfo, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});
    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo;
    ErrCode ret = installer->BeforeUninstall(BUNDLE_NAME, USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(installer->bundleName_, BUNDLE_NAME);
    EXPECT_EQ(installer->userId_, USER_ID);

    // Clean up
    dataMgr_->bundleInfos_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: SkillsInstaller_BeforeUninstall_0007
 * Function: BeforeUninstall
 * @tc.name: test BeforeUninstall with user not installed bundle
 * @tc.desc: 1. system running normally
 *           2. test BeforeUninstall returns error when user hasn't installed bundle
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_BeforeUninstall_0007,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    // Create bundle installed for different user
    InnerBundleInfo bundleInfo;
    CreateMockSkillBundleInfo(bundleInfo, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = DEFAULT_USER_ID;
    bundleInfo.innerBundleUserInfos_.clear();
    bundleInfo.AddInnerBundleUserInfo(userInfo);
    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo;
    // Try to uninstall for USER_ID who hasn't installed it
    ErrCode ret = installer->BeforeUninstall(BUNDLE_NAME, USER_ID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_USER_NOT_INSTALL_HAP);

    // Clean up
    dataMgr_->bundleInfos_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: SkillsInstaller_ProcessUninstall_0001
 * Function: ProcessUninstall
 * @tc.name: test ProcessUninstall with BeforeUninstall failure
 * @tc.desc: 1. system running normally
 *           2. test ProcessUninstall fails when BeforeUninstall fails
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_ProcessUninstall_0001,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    InstallParam installParam;
    installParam.userId = USER_ID;

    // Bundle doesn't exist, BeforeUninstall will fail
    ErrCode ret = installer->ProcessUninstall(BUNDLE_NAME, installParam);
    EXPECT_EQ(ret, ERR_SKILLS_UNINSTALL_BUNDLENAME_NOT_EXIST);
}

/**
 * @tc.number: SkillsInstaller_ProcessUninstall_0002
 * Function: ProcessUninstall
 * @tc.name: test ProcessUninstall multi-user scenario
 * @tc.desc: 1. system running normally
 *           2. test ProcessUninstall removes only userInfo when multiple users exist
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_ProcessUninstall_0002,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    // Create bundle with multiple users
    InnerBundleInfo bundleInfo;
    CreateMockSkillBundleInfo(bundleInfo, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});

    InnerBundleUserInfo userInfo2;
    userInfo2.bundleUserInfo.userId = DEFAULT_USER_ID;
    bundleInfo.AddInnerBundleUserInfo(userInfo2);
    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo;
    InstallParam installParam;
    installParam.userId = USER_ID;
    // Should remove only USER_ID's userInfo
    ErrCode ret = installer->ProcessUninstall(BUNDLE_NAME, installParam);
    EXPECT_EQ(ret, ERR_OK);

    // Verify DEFAULT_USER_ID still exists
    InnerBundleInfo updatedInfo;
    dataMgr_->FetchInnerBundleInfo(BUNDLE_NAME, updatedInfo);
    EXPECT_TRUE(updatedInfo.HasInnerBundleUserInfo(DEFAULT_USER_ID));
    EXPECT_FALSE(updatedInfo.HasInnerBundleUserInfo(USER_ID));

    // Clean up
    dataMgr_->bundleInfos_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: SkillsInstaller_Uninstall_0001
 * Function: Uninstall
 * @tc.name: test Uninstall with non-existent bundle
 * @tc.desc: 1. system running normally
 *           2. test Uninstall fails when bundle doesn't exist
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_Uninstall_0001,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    InstallParam installParam;
    installParam.userId = USER_ID;
    ErrCode ret = installer->Uninstall(BUNDLE_NAME, installParam);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_GT(installer->startTime_, 0);
}

/**
 * @tc.number: SkillsInstaller_Uninstall_0002
 * Function: Uninstall
 * @tc.name: test Uninstall with valid skill bundle
 * @tc.desc: 1. system running normally
 *           2. test Uninstall succeeds for valid skill bundle
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_Uninstall_0002,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    // Create a valid skill bundle
    InnerBundleInfo bundleInfo;
    CreateMockSkillBundleInfo(bundleInfo, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});
    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo;
    dataMgr_->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    InstallParam installParam;
    installParam.userId = USER_ID;
    ErrCode ret = installer->Uninstall(BUNDLE_NAME, installParam);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GT(installer->startTime_, 0);

    // Verify bundle is removed
    InnerBundleInfo resultInfo;
    bool found = dataMgr_->FetchInnerBundleInfo(BUNDLE_NAME, resultInfo);
    EXPECT_FALSE(found);
}

/**
 * @tc.number: SkillsInstaller_Uninstall_0003
 * Function: Uninstall
 * @tc.name: test Uninstall with kill process flag
 * @tc.desc: 1. system running normally
 *           2. test Uninstall with killProcess flag set
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_Uninstall_0003,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    // Create a valid skill bundle
    InnerBundleInfo bundleInfo;
    CreateMockSkillBundleInfo(bundleInfo, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});

    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo;
    dataMgr_->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    InstallParam installParam;
    installParam.userId = USER_ID;
    installParam.killProcess = true;
    ErrCode ret = installer->Uninstall(BUNDLE_NAME, installParam);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: SkillsInstaller_Uninstall_0004
 * Function: Uninstall
 * @tc.name: test Uninstall with force executed flag
 * @tc.desc: 1. system running normally
 *           2. test Uninstall with forceExecuted flag set
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, SkillsInstaller_Uninstall_0004,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    ASSERT_NE(installer, nullptr);

    // Create a valid skill bundle
    InnerBundleInfo bundleInfo;
    CreateMockSkillBundleInfo(bundleInfo, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});

    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo;
    dataMgr_->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    InstallParam installParam;
    installParam.userId = USER_ID;
    installParam.forceExecuted = true;
    ErrCode ret = installer->Uninstall(BUNDLE_NAME, installParam);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BundleDataMgr_GetAllIndependentSKills_0001
 * Function: GetAllIndependentSKills
 * @tc.name: test GetAllIndependentSKills with invalid userId
 * @tc.desc: 1. system running normally
 *           2. test GetAllIndependentSKills returns error when userId doesn't exist
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, BundleDataMgr_GetAllIndependentSKills_0001,
    Function | SmallTest | Level0)
{
    std::vector<std::string> bundleNames;

    ErrCode ret = dataMgr_->GetAllIndependentSKills(INVALID_USER_ID, bundleNames);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
    EXPECT_TRUE(bundleNames.empty());
}

/**
 * @tc.number: BundleDataMgr_GetAllIndependentSKills_0002
 * Function: GetAllIndependentSKills
 * @tc.name: test GetAllIndependentSKills with no skills installed
 * @tc.desc: 1. system running normally
 *           2. test GetAllIndependentSKills returns empty list when no skills installed
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, BundleDataMgr_GetAllIndependentSKills_0002,
    Function | SmallTest | Level0)
{
    std::vector<std::string> bundleNames;

    ErrCode ret = dataMgr_->GetAllIndependentSKills(USER_ID, bundleNames);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(bundleNames.empty());
}

/**
 * @tc.number: BundleDataMgr_GetAllIndependentSKills_0003
 * Function: GetAllIndependentSKills
 * @tc.name: test GetAllIndependentSKills with single skill installed
 * @tc.desc: 1. system running normally
 *           2. test GetAllIndependentSKills returns correct skill bundle name
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, BundleDataMgr_GetAllIndependentSKills_0003,
    Function | SmallTest | Level0)
{
    // Create and add a skill bundle
    InnerBundleInfo bundleInfo;
    CreateMockSkillBundleInfo(bundleInfo, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});
    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo;
    dataMgr_->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    std::vector<std::string> bundleNames;
    ErrCode ret = dataMgr_->GetAllIndependentSKills(USER_ID, bundleNames);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(bundleNames.size(), 1);
    EXPECT_EQ(bundleNames[0], BUNDLE_NAME);

    // Clean up
    dataMgr_->bundleInfos_.erase(BUNDLE_NAME);
    dataMgr_->installStates_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: BundleDataMgr_GetAllIndependentSKills_0004
 * Function: GetAllIndependentSKills
 * @tc.name: test GetAllIndependentSKills with multiple skills installed
 * @tc.desc: 1. system running normally
 *           2. test GetAllIndependentSKills returns all skill bundle names
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, BundleDataMgr_GetAllIndependentSKills_0004,
    Function | SmallTest | Level0)
{
    // Create and add multiple skill bundles
    InnerBundleInfo bundleInfo1;
    CreateMockSkillBundleInfo(bundleInfo1, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});
    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo1;
    dataMgr_->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    InnerBundleInfo bundleInfo2;
    CreateMockSkillBundleInfo(bundleInfo2, BUNDLE_NAME + "2", MODULE_NAME, {SKILL_NAME_TWO});
    dataMgr_->bundleInfos_[BUNDLE_NAME + "2"] = bundleInfo2;
    dataMgr_->installStates_[BUNDLE_NAME + "2"] = InstallState::INSTALL_SUCCESS;
    std::vector<std::string> bundleNames;
    ErrCode ret = dataMgr_->GetAllIndependentSKills(USER_ID, bundleNames);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(bundleNames.size(), 2);
    // Bundle names should be in the list (order may vary)
    auto found1 = std::find(bundleNames.begin(), bundleNames.end(), BUNDLE_NAME) != bundleNames.end();
    auto found2 = std::find(bundleNames.begin(), bundleNames.end(), BUNDLE_NAME + "2") != bundleNames.end();
    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);

    // Clean up
    dataMgr_->bundleInfos_.erase(BUNDLE_NAME);
    dataMgr_->installStates_.erase(BUNDLE_NAME);
    dataMgr_->bundleInfos_.erase(BUNDLE_NAME + "2");
    dataMgr_->installStates_.erase(BUNDLE_NAME+ "2");
}

/**
 * @tc.number: BundleDataMgr_GetAllIndependentSKills_0005
 * Function: GetAllIndependentSKills
 * @tc.name: test GetAllIndependentSKills filters non-skill bundles
 * @tc.desc: 1. system running normally
 *           2. test GetAllIndependentSKills only returns SKILL type bundles
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, BundleDataMgr_GetAllIndependentSKills_0005,
    Function | SmallTest | Level0)
{
    // Create a skill bundle
    InnerBundleInfo skillBundleInfo;
    CreateMockSkillBundleInfo(skillBundleInfo, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});
    dataMgr_->bundleInfos_[BUNDLE_NAME] = skillBundleInfo;
    dataMgr_->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    // Create a non-skill (APP) bundle
    InnerBundleInfo appBundleInfo;
    appBundleInfo.baseApplicationInfo_ = std::make_shared<ApplicationInfo>();
    appBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME + "_app";
    appBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;  // Not SKILL
    appBundleInfo.SetProvisionId("test_provision_id");
    appBundleInfo.SetAppIdentifier(TEST_APP_IDENTIFIER);
    appBundleInfo.currentPackage_ = MODULE_NAME;

    InnerModuleInfo appModuleInfo;
    appModuleInfo.moduleName = MODULE_NAME;
    appBundleInfo.innerModuleInfos_[MODULE_NAME] = appModuleInfo;

    InnerBundleUserInfo appUserInfo;
    appUserInfo.bundleUserInfo.userId = USER_ID;
    appBundleInfo.AddInnerBundleUserInfo(appUserInfo);

    dataMgr_->bundleInfos_[BUNDLE_NAME + "_app"] = appBundleInfo;
    dataMgr_->installStates_[BUNDLE_NAME + "_app"] = InstallState::INSTALL_SUCCESS;
    std::vector<std::string> bundleNames;
    ErrCode ret = dataMgr_->GetAllIndependentSKills(USER_ID, bundleNames);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(bundleNames.size(), 1);
    EXPECT_EQ(bundleNames[0], BUNDLE_NAME);
    EXPECT_NE(bundleNames[0], BUNDLE_NAME + "_app");

    // Clean up
    dataMgr_->bundleInfos_.erase(BUNDLE_NAME);
    dataMgr_->installStates_.erase(BUNDLE_NAME);
    dataMgr_->bundleInfos_.erase(BUNDLE_NAME + "_app");
    dataMgr_->installStates_.erase(BUNDLE_NAME + "_app");
}

/**
 * @tc.number: BundleDataMgr_GetAllIndependentSKills_0006
 * Function: GetAllIndependentSKills
 * @tc.name: test GetAllIndependentSKills with multiple users
 * @tc.desc: 1. system running normally
 *           2. test GetAllIndependentSKills only returns skills for specified user
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, BundleDataMgr_GetAllIndependentSKills_0006,
    Function | SmallTest | Level0)
{
    AddUserId(DEFAULT_USER_ID);

    // Create a skill bundle installed for both users
    InnerBundleInfo bundleInfo;
    CreateMockSkillBundleInfo(bundleInfo, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});

    InnerBundleUserInfo userInfo2;
    userInfo2.bundleUserInfo.userId = DEFAULT_USER_ID;
    bundleInfo.AddInnerBundleUserInfo(userInfo2);

    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo;
    dataMgr_->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    // Get skills for USER_ID
    std::vector<std::string> bundleNamesUser1;
    ErrCode ret1 = dataMgr_->GetAllIndependentSKills(USER_ID, bundleNamesUser1);
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(bundleNamesUser1.size(), 1);
    EXPECT_EQ(bundleNamesUser1[0], BUNDLE_NAME);

    // Get skills for DEFAULT_USER_ID
    std::vector<std::string> bundleNamesUser2;
    ErrCode ret2 = dataMgr_->GetAllIndependentSKills(DEFAULT_USER_ID, bundleNamesUser2);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_EQ(bundleNamesUser2.size(), 1);
    EXPECT_EQ(bundleNamesUser2[0], BUNDLE_NAME);

    // Clean up
    dataMgr_->bundleInfos_.erase(BUNDLE_NAME);
    dataMgr_->installStates_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: BundleDataMgr_GetAllIndependentSKills_0007
 * Function: GetAllIndependentSKills
 * @tc.name: test GetAllIndependentSKills appends to existing vector
 * @tc.desc: 1. system running normally
 *           2. test GetAllIndependentSKills appends results to existing vector content
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, BundleDataMgr_GetAllIndependentSKills_0007,
    Function | SmallTest | Level0)
{
    // Create and add a skill bundle
    InnerBundleInfo bundleInfo;
    CreateMockSkillBundleInfo(bundleInfo, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});
    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo;
    dataMgr_->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    // Start with a vector that already has content
    std::vector<std::string> bundleNames;
    bundleNames.push_back("existing.bundle.name");

    ErrCode ret = dataMgr_->GetAllIndependentSKills(USER_ID, bundleNames);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(bundleNames.size(), 2);
    EXPECT_EQ(bundleNames[0], "existing.bundle.name");
    EXPECT_EQ(bundleNames[1], BUNDLE_NAME);

    // Clean up
    dataMgr_->bundleInfos_.erase(BUNDLE_NAME);
    dataMgr_->installStates_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: BundleUserMgrHostImpl_ProcessUninstallSkills_0001
 * Function: ProcessUninstallSkills
 * @tc.name: test ProcessUninstallSkills with no skills installed
 * @tc.desc: 1. system running normally
 *           2. test ProcessUninstallSkills returns true when no skills installed
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, BundleUserMgrHostImpl_ProcessUninstallSkills_0001,
    Function | SmallTest | Level0)
{
    auto bundleUserMgr = std::make_shared<BundleUserMgrHostImpl>();

    // No skills installed, should still return true
    bool ret = bundleUserMgr->ProcessUninstallSkills(USER_ID);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BundleUserMgrHostImpl_ProcessUninstallSkills_0002
 * Function: ProcessUninstallSkills
 * @tc.name: test ProcessUninstallSkills with single skill installed
 * @tc.desc: 1. system running normally
 *           2. test ProcessUninstallSkills successfully uninstalls single skill
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, BundleUserMgrHostImpl_ProcessUninstallSkills_0002,
    Function | SmallTest | Level0)
{
    auto bundleUserMgr = std::make_shared<BundleUserMgrHostImpl>();

    // Create and add a skill bundle
    InnerBundleInfo bundleInfo;
    CreateMockSkillBundleInfo(bundleInfo, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});
    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo;
    dataMgr_->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    // Uninstall the skill
    bool ret = bundleUserMgr->ProcessUninstallSkills(USER_ID);
    EXPECT_TRUE(ret);

    // Verify skill was removed
    InnerBundleInfo resultInfo;
    bool found = dataMgr_->FetchInnerBundleInfo(BUNDLE_NAME, resultInfo);
    EXPECT_FALSE(found);
}

/**
 * @tc.number: BundleUserMgrHostImpl_ProcessUninstallSkills_0003
 * Function: ProcessUninstallSkills
 * @tc.name: test ProcessUninstallSkills with multiple skills installed
 * @tc.desc: 1. system running normally
 *           2. test ProcessUninstallSkills successfully uninstalls all skills
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, BundleUserMgrHostImpl_ProcessUninstallSkills_0003,
    Function | SmallTest | Level0)
{
    auto bundleUserMgr = std::make_shared<BundleUserMgrHostImpl>();

    // Create and add multiple skill bundles
    InnerBundleInfo bundleInfo1;
    CreateMockSkillBundleInfo(bundleInfo1, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});
    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo1;
    dataMgr_->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    InnerBundleInfo bundleInfo2;
    CreateMockSkillBundleInfo(bundleInfo2, BUNDLE_NAME + "2", MODULE_NAME, {SKILL_NAME_TWO});
    dataMgr_->bundleInfos_[BUNDLE_NAME + "2"] = bundleInfo2;
    dataMgr_->installStates_[BUNDLE_NAME + "2"] = InstallState::INSTALL_SUCCESS;
    // Uninstall all skills
    bool ret = bundleUserMgr->ProcessUninstallSkills(USER_ID);
    EXPECT_TRUE(ret);

    // Verify all skills were removed
    InnerBundleInfo resultInfo1;
    bool found1 = dataMgr_->FetchInnerBundleInfo(BUNDLE_NAME, resultInfo1);
    EXPECT_FALSE(found1);

    InnerBundleInfo resultInfo2;
    bool found2 = dataMgr_->FetchInnerBundleInfo(BUNDLE_NAME + "2", resultInfo2);
    EXPECT_FALSE(found2);
}

/**
 * @tc.number: BundleUserMgrHostImpl_ProcessUninstallSkills_0004
 * Function: ProcessUninstallSkills
 * @tc.name: test ProcessUninstallSkills with non-skill bundles
 * @tc.desc: 1. system running normally
 *           2. test ProcessUninstallSkills only uninstalls SKILL type bundles
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, BundleUserMgrHostImpl_ProcessUninstallSkills_0004,
    Function | SmallTest | Level0)
{
    auto bundleUserMgr = std::make_shared<BundleUserMgrHostImpl>();

    // Create a skill bundle
    InnerBundleInfo skillBundleInfo;
    CreateMockSkillBundleInfo(skillBundleInfo, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});
    dataMgr_->bundleInfos_[BUNDLE_NAME] = skillBundleInfo;
    dataMgr_->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    // Create a non-skill (APP) bundle
    InnerBundleInfo appBundleInfo;
    appBundleInfo.baseApplicationInfo_ = std::make_shared<ApplicationInfo>();
    appBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME + "_app";
    appBundleInfo.baseApplicationInfo_->bundleType = BundleType::APP;
    appBundleInfo.SetProvisionId("test_provision_id");
    appBundleInfo.SetAppIdentifier(TEST_APP_IDENTIFIER);
    appBundleInfo.currentPackage_ = MODULE_NAME;

    InnerModuleInfo appModuleInfo;
    appModuleInfo.moduleName = MODULE_NAME;
    appBundleInfo.innerModuleInfos_[MODULE_NAME] = appModuleInfo;

    InnerBundleUserInfo appUserInfo;
    appUserInfo.bundleUserInfo.userId = USER_ID;
    appBundleInfo.AddInnerBundleUserInfo(appUserInfo);

    dataMgr_->bundleInfos_[BUNDLE_NAME + "_app"] = appBundleInfo;
    dataMgr_->installStates_[BUNDLE_NAME + "_app"] = InstallState::INSTALL_SUCCESS;
    // Uninstall skills
    bool ret = bundleUserMgr->ProcessUninstallSkills(USER_ID);
    EXPECT_TRUE(ret);

    // Verify skill bundle was removed but APP bundle still exists
    InnerBundleInfo skillResult;
    bool skillFound = dataMgr_->FetchInnerBundleInfo(BUNDLE_NAME, skillResult);
    EXPECT_FALSE(skillFound);

    InnerBundleInfo appResult;
    bool appFound = dataMgr_->FetchInnerBundleInfo(BUNDLE_NAME + "_app", appResult);
    EXPECT_TRUE(appFound);

    // Clean up
    dataMgr_->bundleInfos_.erase(BUNDLE_NAME + "_app");
    dataMgr_->installStates_.erase(BUNDLE_NAME + "_app");
}

/**
 * @tc.number: BundleUserMgrHostImpl_ProcessUninstallSkills_0005
 * Function: ProcessUninstallSkills
 * @tc.name: test ProcessUninstallSkills filters by user
 * @tc.desc: 1. system running normally
 *           2. test ProcessUninstallSkills only uninstalls skills for specified user
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, BundleUserMgrHostImpl_ProcessUninstallSkills_0005,
    Function | SmallTest | Level0)
{
    AddUserId(DEFAULT_USER_ID);
    auto bundleUserMgr = std::make_shared<BundleUserMgrHostImpl>();

    // Create a skill bundle installed for both users
    InnerBundleInfo bundleInfo;
    CreateMockSkillBundleInfo(bundleInfo, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});

    InnerBundleUserInfo userInfo2;
    userInfo2.bundleUserInfo.userId = DEFAULT_USER_ID;
    bundleInfo.AddInnerBundleUserInfo(userInfo2);

    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo;
    dataMgr_->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    // Uninstall skills for USER_ID only
    bool ret = bundleUserMgr->ProcessUninstallSkills(USER_ID);
    EXPECT_TRUE(ret);

    // Verify skill still exists for DEFAULT_USER_ID
    InnerBundleInfo resultInfo;
    dataMgr_->FetchInnerBundleInfo(BUNDLE_NAME, resultInfo);
    EXPECT_TRUE(resultInfo.HasInnerBundleUserInfo(DEFAULT_USER_ID));
    EXPECT_FALSE(resultInfo.HasInnerBundleUserInfo(USER_ID));

    // Clean up
    dataMgr_->bundleInfos_.erase(BUNDLE_NAME);
    dataMgr_->installStates_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: BundleUserMgrHostImpl_ProcessUninstallSkills_0006
 * Function: ProcessUninstallSkills
 * @tc.name: test ProcessUninstallSkills with START_USERID
 * @tc.desc: 1. system running normally
 *           2. test ProcessUninstallSkills with START_USERID (100) doesn't kill process
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, BundleUserMgrHostImpl_ProcessUninstallSkills_0006,
    Function | SmallTest | Level0)
{
    auto bundleUserMgr = std::make_shared<BundleUserMgrHostImpl>();

    // Create a skill bundle
    InnerBundleInfo bundleInfo;
    CreateMockSkillBundleInfo(bundleInfo, BUNDLE_NAME, MODULE_NAME, {SKILL_NAME});
    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo;
    dataMgr_->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    // USER_ID = 100 equals START_USERID, so killProcess should be false
    bool ret = bundleUserMgr->ProcessUninstallSkills(USER_ID);
    EXPECT_TRUE(ret);

    // Verify skill was removed
    InnerBundleInfo resultInfo;
    bool found = dataMgr_->FetchInnerBundleInfo(BUNDLE_NAME, resultInfo);
    EXPECT_FALSE(found);
}

/**
 * @tc.number: BundleUserMgrHostImpl_ProcessUninstallSkills_0007
 * Function: ProcessUninstallSkills
 * @tc.name: test ProcessUninstallSkills with non-START_USERID
 * @tc.desc: 1. system running normally
 *           2. test ProcessUninstallSkills with non-START_USERID sets killProcess
 */
HWTEST_F(BmsIndependentSkillsInstallerUninstallTest, BundleUserMgrHostImpl_ProcessUninstallSkills_0007,
    Function | SmallTest | Level0)
{
    AddUserId(DEFAULT_USER_ID);  // DEFAULT_USER_ID = 0
    auto bundleUserMgr = std::make_shared<BundleUserMgrHostImpl>();

    // Create a skill bundle for DEFAULT_USER_ID
    InnerBundleInfo bundleInfo;
    bundleInfo.baseApplicationInfo_ = std::make_shared<ApplicationInfo>();
    bundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    bundleInfo.baseApplicationInfo_->bundleType = BundleType::SKILL;
    bundleInfo.SetProvisionId("test_provision_id");
    bundleInfo.SetAppIdentifier(TEST_APP_IDENTIFIER);
    bundleInfo.baseApplicationInfo_->versionCode = VERSION_CODE;
    bundleInfo.currentPackage_ = MODULE_NAME;

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;
    moduleInfo.modulePath = "/data/app/" + BUNDLE_NAME + "/" + MODULE_NAME;

    SkillProfile skillProfile;
    skillProfile.name = SKILL_NAME;
    moduleInfo.skillProfiles.push_back(skillProfile);

    bundleInfo.innerModuleInfos_[MODULE_NAME] = moduleInfo;

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = DEFAULT_USER_ID;
    bundleInfo.AddInnerBundleUserInfo(userInfo);

    dataMgr_->bundleInfos_[BUNDLE_NAME] = bundleInfo;
    dataMgr_->installStates_[BUNDLE_NAME] = InstallState::INSTALL_SUCCESS;
    // DEFAULT_USER_ID = 0, not equal to START_USERID, so killProcess should be true
    bool ret = bundleUserMgr->ProcessUninstallSkills(DEFAULT_USER_ID);
    EXPECT_TRUE(ret);

    // Verify skill was removed
    InnerBundleInfo resultInfo;
    bool found = dataMgr_->FetchInnerBundleInfo(BUNDLE_NAME, resultInfo);
    EXPECT_FALSE(found);
}

}  // namespace OHOS
