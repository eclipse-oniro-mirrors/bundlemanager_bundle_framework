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
#include <thread>

#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_skill/skill_info.h"
#include "inner_bundle_info.h"
#include "bundle_info.h"
#include "installd_client.h"
#include "installd_service.h"
#include "appexecfwk_errors.h"
#include "bundle_constants.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME_TEST = "com.example.skill.test";
const std::string BUNDLE_NAME_TEST2 = "com.example.skill.test2";
const std::string MODULE_NAME_ENTRY = "entry";
const std::string SKILL_NAME_TEST = "testSkill";
const std::string SKILL_NAME_TEST2 = "testSkill2";
const std::string ABILITY_NAME_TEST = "TestAbility";
const std::string HAP_PATH = "/data/app/com.example.skill.test/entry.hap";
const int32_t USERID = 100;
constexpr int32_t BASE_TEST_UID = 20000000;
} // namespace

class BmsSkillBundleDataMgrTest : public testing::Test {
public:
    BmsSkillBundleDataMgrTest();
    ~BmsSkillBundleDataMgrTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;

    void MockInstallBundleWithSkill(const std::string &bundleName, const std::string &moduleName,
        const std::string &skillName, const std::string &abilityName) const;
    void MockInstallBundleWithSkills(const std::string &bundleName, const std::string &moduleName,
        const std::vector<SkillProfile> &skillProfiles) const;
    void MockUninstallBundle(const std::string &bundleName) const;

    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    static std::shared_ptr<InstalldService> installdService_;
};

std::shared_ptr<BundleMgrService> BmsSkillBundleDataMgrTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsSkillBundleDataMgrTest::installdService_ =
    std::make_shared<InstalldService>();

BmsSkillBundleDataMgrTest::BmsSkillBundleDataMgrTest()
{}

BmsSkillBundleDataMgrTest::~BmsSkillBundleDataMgrTest()
{}

void BmsSkillBundleDataMgrTest::SetUpTestCase()
{}

void BmsSkillBundleDataMgrTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsSkillBundleDataMgrTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void BmsSkillBundleDataMgrTest::TearDown()
{}

std::shared_ptr<BundleDataMgr> BmsSkillBundleDataMgrTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

void BmsSkillBundleDataMgrTest::MockInstallBundleWithSkill(const std::string &bundleName,
    const std::string &moduleName, const std::string &skillName, const std::string &abilityName) const
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = moduleName;
    moduleInfo.hapPath = HAP_PATH;
    moduleInfo.name = moduleName;

    SkillProfile profile;
    profile.name = skillName;
    profile.abilityName = abilityName;
    profile.version = "1.0.0";
    profile.srcEntries = {"src/main.js"};
    profile.permissions = {"ohos.permission.READ"};
    profile.visibility = Profile::SKILL_PROFILE_VISIBILITY_PUBLIC;
    moduleInfo.skillProfiles.emplace_back(profile);

    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.bundleName = bundleName;
    innerAbilityInfo.moduleName = moduleName;
    innerAbilityInfo.name = abilityName;

    std::string keyName = bundleName + "." + moduleName + "." + abilityName;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertAbilitiesInfo(keyName, innerAbilityInfo);
    innerBundleInfo.InsertInnerModuleInfo(moduleName, moduleInfo);

    ApplicationInfo appInfo;
    appInfo.bundleName = bundleName;
    appInfo.name = bundleName;
    appInfo.uid = BASE_TEST_UID;
    innerBundleInfo.SetBaseApplicationInfo(appInfo);

    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;
    bundleInfo.versionCode = 1;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    innerBundleUserInfo.uid = BASE_TEST_UID;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);

    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);
}

void BmsSkillBundleDataMgrTest::MockInstallBundleWithSkills(const std::string &bundleName,
    const std::string &moduleName, const std::vector<SkillProfile> &skillProfiles) const
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = moduleName;
    moduleInfo.hapPath = HAP_PATH;
    moduleInfo.name = moduleName;
    moduleInfo.skillProfiles = skillProfiles;

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.InsertInnerModuleInfo(moduleName, moduleInfo);

    ApplicationInfo appInfo;
    appInfo.bundleName = bundleName;
    appInfo.name = bundleName;
    appInfo.uid = BASE_TEST_UID;
    innerBundleInfo.SetBaseApplicationInfo(appInfo);

    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;
    bundleInfo.versionCode = 1;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    innerBundleUserInfo.uid = BASE_TEST_UID;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);

    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);
}

void BmsSkillBundleDataMgrTest::MockUninstallBundle(const std::string &bundleName) const
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    auto iterator = dataMgr->bundleInfos_.find(bundleName);
    if (iterator != dataMgr->bundleInfos_.end()) {
        dataMgr->bundleInfos_.erase(iterator);
    }
    dataMgr->installStates_.erase(bundleName);
}

/**
 * @tc.number: SkillBundleDataMgr_0001
 * @tc.name: GetSkillInfo with non-existent bundle
 * @tc.desc: Test GetSkillInfo returns ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST for non-existent bundle
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0001, TestSize.Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    SkillInfo skillInfo;
    auto ret = dataMgr->GetSkillInfo("com.non.existent", MODULE_NAME_ENTRY,
        SKILL_NAME_TEST, 0, USERID, skillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: SkillBundleDataMgr_0002
 * @tc.name: GetSkillInfo with non-existent module
 * @tc.desc: Test GetSkillInfo returns ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST for non-existent module
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0002, TestSize.Level1)
{
    MockInstallBundleWithSkill(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, SKILL_NAME_TEST, ABILITY_NAME_TEST);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    SkillInfo skillInfo;
    auto ret = dataMgr->GetSkillInfo(BUNDLE_NAME_TEST, "nonexistent_module", SKILL_NAME_TEST,
        0, USERID, skillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SkillBundleDataMgr_0003
 * @tc.name: GetSkillInfo with non-existent skill
 * @tc.desc: Test GetSkillInfo returns ERR_BUNDLE_MANAGER_SKILL_INFO_NOT_EXIST for non-existent skill
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0003, TestSize.Level1)
{
    MockInstallBundleWithSkill(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, SKILL_NAME_TEST, ABILITY_NAME_TEST);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    SkillInfo skillInfo;
    auto ret = dataMgr->GetSkillInfo(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, "nonexistent_skill",
        0, USERID, skillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SKILL_INFO_NOT_EXIST);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SkillBundleDataMgr_0004
 * @tc.name: GetSkillInfo successfully returns skill info
 * @tc.desc: Test GetSkillInfo returns correct skill info for installed bundle
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0004, TestSize.Level1)
{
    MockInstallBundleWithSkill(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, SKILL_NAME_TEST, ABILITY_NAME_TEST);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    SkillInfo skillInfo;
    auto ret = dataMgr->GetSkillInfo(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, SKILL_NAME_TEST,
        0, USERID, skillInfo);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(skillInfo.bundleName, BUNDLE_NAME_TEST);
    EXPECT_EQ(skillInfo.moduleName, MODULE_NAME_ENTRY);
    EXPECT_EQ(skillInfo.skillName, SKILL_NAME_TEST);
    EXPECT_EQ(skillInfo.skillType, SkillType::APP_SKILL);
    EXPECT_EQ(skillInfo.abilityName, ABILITY_NAME_TEST);
    EXPECT_EQ(skillInfo.versionCode, static_cast<uint32_t>(1));
    EXPECT_EQ(skillInfo.version, "1.0.0");
    EXPECT_EQ(skillInfo.visibility, Profile::SKILL_PROFILE_VISIBILITY_PUBLIC);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SkillBundleDataMgr_0005
 * @tc.name: GetSkillInfo with GET_SKILL_INFO_WITH_SRC_ENTRIES flag
 * @tc.desc: Test GetSkillInfo returns srcEntries when flag is set
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0005, TestSize.Level1)
{
    MockInstallBundleWithSkill(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, SKILL_NAME_TEST, ABILITY_NAME_TEST);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    uint32_t flags = static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_SRC_ENTRIES);
    SkillInfo skillInfo;
    auto ret = dataMgr->GetSkillInfo(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, SKILL_NAME_TEST,
        flags, USERID, skillInfo);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(skillInfo.srcEntries.size(), static_cast<size_t>(1));
    EXPECT_EQ(skillInfo.srcEntries[0], "src/main.js");

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SkillBundleDataMgr_0006
 * @tc.name: GetSkillInfo with GET_SKILL_INFO_WITH_PERMISSIONS flag
 * @tc.desc: Test GetSkillInfo returns permissions when flag is set
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0006, TestSize.Level1)
{
    MockInstallBundleWithSkill(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, SKILL_NAME_TEST, ABILITY_NAME_TEST);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    uint32_t flags = static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_PERMISSIONS);
    SkillInfo skillInfo;
    auto ret = dataMgr->GetSkillInfo(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, SKILL_NAME_TEST,
        flags, USERID, skillInfo);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(skillInfo.permissions.size(), static_cast<size_t>(1));
    EXPECT_EQ(skillInfo.permissions[0], "ohos.permission.READ");

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SkillBundleDataMgr_0007
 * @tc.name: GetSkillInfo without flags returns no srcEntries or permissions
 * @tc.desc: Test GetSkillInfo with default flags does not populate optional fields
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0007, TestSize.Level1)
{
    MockInstallBundleWithSkill(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, SKILL_NAME_TEST, ABILITY_NAME_TEST);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    SkillInfo skillInfo;
    auto ret = dataMgr->GetSkillInfo(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, SKILL_NAME_TEST,
        0, USERID, skillInfo);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_TRUE(skillInfo.srcEntries.empty());
    EXPECT_TRUE(skillInfo.permissions.empty());
    EXPECT_TRUE(skillInfo.requestPermissions.empty());

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SkillBundleDataMgr_0008
 * @tc.name: GetSkillInfo with invalid userId
 * @tc.desc: Test GetSkillInfo returns ERR_BUNDLE_MANAGER_INVALID_USER_ID for invalid userId
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0008, TestSize.Level1)
{
    MockInstallBundleWithSkill(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, SKILL_NAME_TEST, ABILITY_NAME_TEST);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    SkillInfo skillInfo;
    auto ret = dataMgr->GetSkillInfo(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, SKILL_NAME_TEST,
        0, 999, skillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SkillBundleDataMgr_0009
 * @tc.name: GetSkillInfos with non-existent bundle
 * @tc.desc: Test GetSkillInfos returns ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST for non-existent bundle
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0009, TestSize.Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<SkillInfo> skillInfos;
    auto ret = dataMgr->GetSkillInfos("com.non.existent", 0, USERID, skillInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: SkillBundleDataMgr_0010
 * @tc.name: GetSkillInfos returns all skills for a bundle
 * @tc.desc: Test GetSkillInfos returns all skill profiles for an installed bundle
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0010, TestSize.Level1)
{
    std::vector<SkillProfile> profiles;
    SkillProfile profile1;
    profile1.name = SKILL_NAME_TEST;
    profile1.abilityName = ABILITY_NAME_TEST;
    profile1.version = "1.0.0";
    profile1.srcEntries = {"src1.js"};
    profiles.emplace_back(profile1);

    SkillProfile profile2;
    profile2.name = SKILL_NAME_TEST2;
    profile2.abilityName = "SecondAbility";
    profile2.version = "2.0.0";
    profile2.permissions = {"ohos.permission.WRITE"};
    profiles.emplace_back(profile2);

    MockInstallBundleWithSkills(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, profiles);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<SkillInfo> skillInfos;
    auto ret = dataMgr->GetSkillInfos(BUNDLE_NAME_TEST, 0, USERID, skillInfos);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(skillInfos.size(), static_cast<size_t>(2));
    EXPECT_EQ(skillInfos[0].skillName, SKILL_NAME_TEST);
    EXPECT_EQ(skillInfos[0].version, "1.0.0");
    EXPECT_EQ(skillInfos[1].skillName, SKILL_NAME_TEST2);
    EXPECT_EQ(skillInfos[1].version, "2.0.0");

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SkillBundleDataMgr_0011
 * @tc.name: GetSkillInfos with empty skill profiles returns empty list
 * @tc.desc: Test GetSkillInfos returns empty list when bundle has no skill profiles
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0011, TestSize.Level1)
{
    MockInstallBundleWithSkills(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, {});

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<SkillInfo> skillInfos;
    auto ret = dataMgr->GetSkillInfos(BUNDLE_NAME_TEST, 0, USERID, skillInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(skillInfos.empty());

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SkillBundleDataMgr_0012
 * @tc.name: GetSkillInfos with invalid userId
 * @tc.desc: Test GetSkillInfos returns ERR_BUNDLE_MANAGER_INVALID_USER_ID for invalid userId
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0012, TestSize.Level1)
{
    MockInstallBundleWithSkill(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, SKILL_NAME_TEST, ABILITY_NAME_TEST);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<SkillInfo> skillInfos;
    auto ret = dataMgr->GetSkillInfos(BUNDLE_NAME_TEST, 0, 999, skillInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SkillBundleDataMgr_0013
 * @tc.name: GetSkillInfos with flags
 * @tc.desc: Test GetSkillInfos returns skill info with srcEntries when flag is set
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0013, TestSize.Level1)
{
    std::vector<SkillProfile> profiles;
    SkillProfile profile;
    profile.name = SKILL_NAME_TEST;
    profile.abilityName = ABILITY_NAME_TEST;
    profile.srcEntries = {"src/a.js", "src/b.js"};
    profile.permissions = {"ohos.permission.CAMERA"};
    profiles.emplace_back(profile);

    MockInstallBundleWithSkills(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, profiles);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    uint32_t flags = static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_SRC_ENTRIES) |
        static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_PERMISSIONS);
    std::vector<SkillInfo> skillInfos;
    auto ret = dataMgr->GetSkillInfos(BUNDLE_NAME_TEST, flags, USERID, skillInfos);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_EQ(skillInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(skillInfos[0].srcEntries.size(), static_cast<size_t>(2));
    EXPECT_EQ(skillInfos[0].permissions.size(), static_cast<size_t>(1));

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SkillBundleDataMgr_0014
 * @tc.name: GetAllSkillInfos with no bundles installed
 * @tc.desc: Test GetAllSkillInfos returns empty list when no bundles are installed
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0014, TestSize.Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<SkillInfo> skillInfos;
    auto ret = dataMgr->GetAllSkillInfos(0, USERID, skillInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(skillInfos.empty());
}

/**
 * @tc.number: SkillBundleDataMgr_0015
 * @tc.name: GetAllSkillInfos returns all skills from all bundles
 * @tc.desc: Test GetAllSkillInfos returns skills from multiple installed bundles
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0015, TestSize.Level1)
{
    std::vector<SkillProfile> profiles1;
    SkillProfile profile1;
    profile1.name = SKILL_NAME_TEST;
    profile1.abilityName = ABILITY_NAME_TEST;
    profiles1.emplace_back(profile1);
    MockInstallBundleWithSkills(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, profiles1);

    std::vector<SkillProfile> profiles2;
    SkillProfile profile2;
    profile2.name = SKILL_NAME_TEST2;
    profile2.abilityName = "OtherAbility";
    profiles2.emplace_back(profile2);
    MockInstallBundleWithSkills(BUNDLE_NAME_TEST2, MODULE_NAME_ENTRY, profiles2);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<SkillInfo> skillInfos;
    auto ret = dataMgr->GetAllSkillInfos(0, USERID, skillInfos);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_GE(skillInfos.size(), static_cast<size_t>(2));

    MockUninstallBundle(BUNDLE_NAME_TEST);
    MockUninstallBundle(BUNDLE_NAME_TEST2);
}

/**
 * @tc.number: SkillBundleDataMgr_0016
 * @tc.name: GetAllSkillInfos with invalid userId
 * @tc.desc: Test GetAllSkillInfos returns ERR_BUNDLE_MANAGER_INVALID_USER_ID for invalid userId
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0016, TestSize.Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<SkillInfo> skillInfos;
    auto ret = dataMgr->GetAllSkillInfos(0, 999, skillInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: SkillBundleDataMgr_0017
 * @tc.name: GetAllSkillInfos with flags
 * @tc.desc: Test GetAllSkillInfos respects skill info flags
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0017, TestSize.Level1)
{
    std::vector<SkillProfile> profiles;
    SkillProfile profile;
    profile.name = SKILL_NAME_TEST;
    profile.abilityName = ABILITY_NAME_TEST;
    profile.srcEntries = {"src/test.js"};
    profile.permissions = {"ohos.permission.INTERNET"};
    profiles.emplace_back(profile);
    MockInstallBundleWithSkills(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, profiles);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    uint32_t flags = static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_SRC_ENTRIES);
    std::vector<SkillInfo> skillInfos;
    auto ret = dataMgr->GetAllSkillInfos(flags, USERID, skillInfos);
    ASSERT_EQ(ret, ERR_OK);
    bool found = false;
    for (const auto &info : skillInfos) {
        if (info.skillName == SKILL_NAME_TEST && info.bundleName == BUNDLE_NAME_TEST) {
            EXPECT_FALSE(info.srcEntries.empty());
            found = true;
        }
    }
    EXPECT_TRUE(found);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SkillBundleDataMgr_0018
 * @tc.name: GetAllSkillInfos skips bundles not installed for the given user
 * @tc.desc: Test GetAllSkillInfos only returns skills for bundles installed for the specified user
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0018, TestSize.Level1)
{
    std::vector<SkillProfile> profiles;
    SkillProfile profile;
    profile.name = SKILL_NAME_TEST;
    profile.abilityName = ABILITY_NAME_TEST;
    profiles.emplace_back(profile);
    MockInstallBundleWithSkills(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, profiles);

    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    // Add another user who should not see the bundle installed for USERID
    dataMgr->AddUserId(101);

    std::vector<SkillInfo> skillInfos;
    auto ret = dataMgr->GetAllSkillInfos(0, 101, skillInfos);
    ASSERT_EQ(ret, ERR_OK);
    for (const auto &info : skillInfos) {
        EXPECT_NE(info.bundleName, BUNDLE_NAME_TEST);
    }

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SkillBundleDataMgr_0019
 * @tc.name: GetSkillInfoForSelf with invalid calling uid
 * @tc.desc: Test GetSkillInfoForSelf returns error for non-application uid
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0019, TestSize.Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    SkillInfo skillInfo;
    auto ret = dataMgr->GetSkillInfoForSelf(MODULE_NAME_ENTRY, SKILL_NAME_TEST, USERID, 0, skillInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: SkillBundleDataMgr_0020
 * @tc.name: GetSkillInfosForSelf with invalid calling uid
 * @tc.desc: Test GetSkillInfosForSelf returns error for non-application uid
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0020, TestSize.Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    std::vector<SkillInfo> skillInfos;
    auto ret = dataMgr->GetSkillInfosForSelf(0, USERID, skillInfos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: SkillBundleDataMgr_0021
 * @tc.name: IsSkillVisibleForQuery with all access level
 * @tc.desc: Test all visibility values are visible when query access level is ALL
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0021, TestSize.Level1)
{
    SkillProfile publicProfile;
    publicProfile.visibility = Profile::SKILL_PROFILE_VISIBILITY_PUBLIC;
    SkillProfile systemProfile;
    systemProfile.visibility = Profile::SKILL_PROFILE_VISIBILITY_SYSTEM;
    SkillProfile privateProfile;
    privateProfile.visibility = "private";
    SkillProfile unknownProfile;
    unknownProfile.visibility = "unknown";

    auto accessLevel = BundleDataMgr::SkillQueryAccessLevel::ALL;
    EXPECT_TRUE(BundleDataMgr::IsSkillVisibleForQuery(publicProfile, accessLevel));
    EXPECT_TRUE(BundleDataMgr::IsSkillVisibleForQuery(systemProfile, accessLevel));
    EXPECT_TRUE(BundleDataMgr::IsSkillVisibleForQuery(privateProfile, accessLevel));
    EXPECT_TRUE(BundleDataMgr::IsSkillVisibleForQuery(unknownProfile, accessLevel));
}

/**
 * @tc.number: SkillBundleDataMgr_0022
 * @tc.name: IsSkillVisibleForQuery with system and public access level
 * @tc.desc: Test only system and public skill profiles are visible for privileged callers
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0022, TestSize.Level1)
{
    SkillProfile publicProfile;
    publicProfile.visibility = Profile::SKILL_PROFILE_VISIBILITY_PUBLIC;
    SkillProfile systemProfile;
    systemProfile.visibility = Profile::SKILL_PROFILE_VISIBILITY_SYSTEM;
    SkillProfile privateProfile;
    privateProfile.visibility = "private";
    SkillProfile unknownProfile;
    unknownProfile.visibility = "unknown";

    auto accessLevel = BundleDataMgr::SkillQueryAccessLevel::SYSTEM_AND_PUBLIC;
    EXPECT_TRUE(BundleDataMgr::IsSkillVisibleForQuery(publicProfile, accessLevel));
    EXPECT_TRUE(BundleDataMgr::IsSkillVisibleForQuery(systemProfile, accessLevel));
    EXPECT_FALSE(BundleDataMgr::IsSkillVisibleForQuery(privateProfile, accessLevel));
    EXPECT_FALSE(BundleDataMgr::IsSkillVisibleForQuery(unknownProfile, accessLevel));
}

/**
 * @tc.number: SkillBundleDataMgr_0023
 * @tc.name: IsSkillVisibleForQuery with public only access level
 * @tc.desc: Test only public skill profiles are visible for non-privileged callers
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0023, TestSize.Level1)
{
    SkillProfile publicProfile;
    publicProfile.visibility = Profile::SKILL_PROFILE_VISIBILITY_PUBLIC;
    SkillProfile systemProfile;
    systemProfile.visibility = Profile::SKILL_PROFILE_VISIBILITY_SYSTEM;
    SkillProfile privateProfile;
    privateProfile.visibility = "private";
    SkillProfile unknownProfile;
    unknownProfile.visibility = "unknown";

    auto accessLevel = BundleDataMgr::SkillQueryAccessLevel::PUBLIC_ONLY;
    EXPECT_TRUE(BundleDataMgr::IsSkillVisibleForQuery(publicProfile, accessLevel));
    EXPECT_FALSE(BundleDataMgr::IsSkillVisibleForQuery(systemProfile, accessLevel));
    EXPECT_FALSE(BundleDataMgr::IsSkillVisibleForQuery(privateProfile, accessLevel));
    EXPECT_FALSE(BundleDataMgr::IsSkillVisibleForQuery(unknownProfile, accessLevel));
}

/**
 * @tc.number: SkillBundleDataMgr_0024
 * @tc.name: GetSkillQueryAccessLevel with self query
 * @tc.desc: Test self query can access all skill profile visibility values
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0024, TestSize.Level1)
{
    auto accessLevel = BundleDataMgr::GetSkillQueryAccessLevel(BUNDLE_NAME_TEST, BUNDLE_NAME_TEST, false);

    EXPECT_EQ(accessLevel, BundleDataMgr::SkillQueryAccessLevel::ALL);
}

/**
 * @tc.number: SkillBundleDataMgr_0025
 * @tc.name: GetSkillQueryAccessLevel with privileged caller
 * @tc.desc: Test privileged callers can access system and public skill profile visibility values
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0025, TestSize.Level1)
{
    auto accessLevel = BundleDataMgr::GetSkillQueryAccessLevel(BUNDLE_NAME_TEST, BUNDLE_NAME_TEST2, true);

    EXPECT_EQ(accessLevel, BundleDataMgr::SkillQueryAccessLevel::SYSTEM_AND_PUBLIC);
}

/**
 * @tc.number: SkillBundleDataMgr_0026
 * @tc.name: GetSkillQueryAccessLevel with non-privileged caller
 * @tc.desc: Test non-privileged callers can access public skill profile visibility values only
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0026, TestSize.Level1)
{
    auto accessLevel = BundleDataMgr::GetSkillQueryAccessLevel(BUNDLE_NAME_TEST, BUNDLE_NAME_TEST2, false);

    EXPECT_EQ(accessLevel, BundleDataMgr::SkillQueryAccessLevel::PUBLIC_ONLY);
}

/**
 * @tc.number: SkillBundleDataMgr_0027
 * @tc.name: FindSkillInfoFromAllBundles with self bundle
 * @tc.desc: Test self bundle can access private skill profiles in all-bundle query path
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0027, TestSize.Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    MockUninstallBundle(BUNDLE_NAME_TEST);

    SkillProfile privateProfile;
    privateProfile.name = "selfPrivateSkill";
    privateProfile.abilityName = ABILITY_NAME_TEST;
    privateProfile.visibility = "private";
    MockInstallBundleWithSkills(BUNDLE_NAME_TEST, MODULE_NAME_ENTRY, {privateProfile});

    SkillInfo skillInfo;
    auto ret = dataMgr->FindSkillInfoFromAllBundles(privateProfile.name, 0, USERID,
        BUNDLE_NAME_TEST, false, skillInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(skillInfo.bundleName, BUNDLE_NAME_TEST);
    EXPECT_EQ(skillInfo.skillName, privateProfile.name);

    MockUninstallBundle(BUNDLE_NAME_TEST);
}

/**
 * @tc.number: SkillBundleDataMgr_0028
 * @tc.name: FindSkillInfoFromAllBundles with non-privileged caller
 * @tc.desc: Test non-privileged caller cannot access private skill profiles from other bundles
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0028, TestSize.Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    MockUninstallBundle(BUNDLE_NAME_TEST2);

    SkillProfile privateProfile;
    privateProfile.name = "otherPrivateSkill";
    privateProfile.abilityName = ABILITY_NAME_TEST;
    privateProfile.visibility = "private";
    MockInstallBundleWithSkills(BUNDLE_NAME_TEST2, MODULE_NAME_ENTRY, {privateProfile});

    SkillInfo skillInfo;
    auto ret = dataMgr->FindSkillInfoFromAllBundles(privateProfile.name, 0, USERID,
        BUNDLE_NAME_TEST, false, skillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SKILL_INFO_NOT_EXIST);
    EXPECT_TRUE(skillInfo.skillName.empty());

    MockUninstallBundle(BUNDLE_NAME_TEST2);
}

/**
 * @tc.number: SkillBundleDataMgr_0029
 * @tc.name: FindSkillInfoFromAllBundles with privileged caller
 * @tc.desc: Test privileged caller can access system skill profiles from other bundles
 */
HWTEST_F(BmsSkillBundleDataMgrTest, SkillBundleDataMgr_0029, TestSize.Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    MockUninstallBundle(BUNDLE_NAME_TEST2);

    SkillProfile systemProfile;
    systemProfile.name = "otherSystemSkill";
    systemProfile.abilityName = ABILITY_NAME_TEST;
    systemProfile.visibility = Profile::SKILL_PROFILE_VISIBILITY_SYSTEM;
    MockInstallBundleWithSkills(BUNDLE_NAME_TEST2, MODULE_NAME_ENTRY, {systemProfile});

    SkillInfo nonPrivilegedSkillInfo;
    auto ret = dataMgr->FindSkillInfoFromAllBundles(systemProfile.name, 0, USERID,
        BUNDLE_NAME_TEST, false, nonPrivilegedSkillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SKILL_INFO_NOT_EXIST);
    EXPECT_TRUE(nonPrivilegedSkillInfo.skillName.empty());

    SkillInfo privilegedSkillInfo;
    ret = dataMgr->FindSkillInfoFromAllBundles(systemProfile.name, 0, USERID,
        BUNDLE_NAME_TEST, true, privilegedSkillInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(privilegedSkillInfo.bundleName, BUNDLE_NAME_TEST2);
    EXPECT_EQ(privilegedSkillInfo.skillName, systemProfile.name);

    MockUninstallBundle(BUNDLE_NAME_TEST2);
}
} // namespace OHOS
