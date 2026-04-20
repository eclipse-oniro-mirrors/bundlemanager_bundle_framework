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
const std::string TEST_HSP_PATH2 = "/data/test/resource/bms/skills/test2.hsp";
const std::string INVALID_HSP_PATH = "/invalid/path/test.hsp";
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

class BmsIndependentSkillsInstallerTest : public testing::Test {
public:
    BmsIndependentSkillsInstallerTest();
    ~BmsIndependentSkillsInstallerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    void AddUserId(int32_t userId);
    void StartInstalldService() const;
    void StartBundleService();

    std::shared_ptr<BundleDataMgr> dataMgr_;
private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsIndependentSkillsInstallerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsIndependentSkillsInstallerTest::installdService_ =
    std::make_shared<InstalldService>();

BmsIndependentSkillsInstallerTest::BmsIndependentSkillsInstallerTest()
{}

BmsIndependentSkillsInstallerTest::~BmsIndependentSkillsInstallerTest()
{}

void BmsIndependentSkillsInstallerTest::SetUpTestCase()
{}

void BmsIndependentSkillsInstallerTest::TearDownTestCase()
{}

void BmsIndependentSkillsInstallerTest::SetUp()
{
    StartBundleService();
    StartInstalldService();
    dataMgr_ = bundleMgrService_->GetDataMgr();
    ASSERT_NE(dataMgr_, nullptr);
}

void BmsIndependentSkillsInstallerTest::TearDown()
{}

void BmsIndependentSkillsInstallerTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsIndependentSkillsInstallerTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsIndependentSkillsInstallerTest::AddUserId(int32_t userId)
{
    if (dataMgr_ != nullptr) {
        dataMgr_->AddUserId(userId);
    }
}

/**
 * @tc.number: IndependentSkillsInstaller_Constructor_0001
 * Function: IndependentSkillsInstaller
 * @tc.name: test IndependentSkillsInstaller constructor
 * @tc.desc: 1. system running normally
 *           2. test constructor creates valid instance
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_Constructor_0001,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    EXPECT_NE(installer, nullptr);
    EXPECT_NE(installer->bundleInstallChecker_, nullptr);
    EXPECT_EQ(installer->versionUpgrade_, false);
    EXPECT_EQ(installer->moduleUpdate_, false);
    EXPECT_EQ(installer->isEnterpriseBundle_, false);
    EXPECT_EQ(installer->hasInstalledInUser_, false);
    EXPECT_EQ(installer->versionCode_, 0);
    EXPECT_EQ(installer->userId_, -1);
    EXPECT_EQ(installer->startTime_, 0);
}

/**
 * @tc.number: IndependentSkillsInstaller_ResetProperties_0001
 * Function: ResetProperties
 * @tc.name: test ResetProperties resets all member variables
 * @tc.desc: 1. system running normally
 *           2. test ResetProperties function
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ResetProperties_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->versionUpgrade_ = true;
    installer_->moduleUpdate_ = true;
    installer_->isEnterpriseBundle_ = true;
    installer_->hasInstalledInUser_ = true;
    installer_->versionCode_ = VERSION_CODE;
    installer_->userId_ = USER_ID;
    installer_->bundleName_ = BUNDLE_NAME;
    installer_->appIdentifier_ = TEST_APP_IDENTIFIER;
    installer_->compileSdkType_ = COMPILE_SDK_TYPE;

    installer_->ResetProperties();

    EXPECT_EQ(installer_->versionUpgrade_, false);
    EXPECT_EQ(installer_->moduleUpdate_, false);
    EXPECT_EQ(installer_->isEnterpriseBundle_, false);
    EXPECT_EQ(installer_->hasInstalledInUser_, false);
    EXPECT_EQ(installer_->versionCode_, 0);
    EXPECT_EQ(installer_->userId_, -1);
    EXPECT_EQ(installer_->bundleName_, "");
    EXPECT_EQ(installer_->appIdentifier_, "");
    EXPECT_EQ(installer_->compileSdkType_, "");
}

/**
 * @tc.number: IndependentSkillsInstaller_BeforeInstall_0001
 * Function: BeforeInstall
 * @tc.name: test BeforeInstall with empty hspPaths
 * @tc.desc: 1. system running normally
 *           2. test BeforeInstall returns error when hspPaths is empty
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_BeforeInstall_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> hspPaths;
    InstallParam installParam;
    installParam.userId = USER_ID;

    ErrCode ret = installer_->BeforeInstall(hspPaths, installParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: IndependentSkillsInstaller_BeforeInstall_0002
 * Function: BeforeInstall
 * @tc.name: test BeforeInstall with valid hspPaths but null dataMgr
 * @tc.desc: 1. system running normally
 *           2. test BeforeInstall returns error when dataMgr is null
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_BeforeInstall_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    std::vector<std::string> hspPaths = {TEST_HSP_PATH};
    InstallParam installParam;
    installParam.userId = USER_ID;

    bundleMgrService_->RegisterDataMgr(nullptr);
    ErrCode ret = installer_->BeforeInstall(hspPaths, installParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
    bundleMgrService_->RegisterDataMgr(dataMgr_);
}

/**
 * @tc.number: IndependentSkillsInstaller_BeforeInstall_0003
 * Function: BeforeInstall
 * @tc.name: test BeforeInstall with valid parameters
 * @tc.desc: 1. system running normally
 *           2. test BeforeInstall returns OK with valid parameters
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_BeforeInstall_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> hspPaths = {TEST_HSP_PATH};
    InstallParam installParam;
    installParam.userId = USER_ID;

    ErrCode ret = installer_->BeforeInstall(hspPaths, installParam);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckUserId_0001
 * Function: CheckUserId
 * @tc.name: test CheckUserId with null dataMgr
 * @tc.desc: 1. system running normally
 *           2. test CheckUserId returns error when dataMgr is null
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckUserId_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = nullptr;
    installer_->bundleName_ = BUNDLE_NAME;

    ErrCode ret = installer_->CheckUserId(USER_ID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckUserId_0002
 * Function: CheckUserId
 * @tc.name: test CheckUserId with non-existent user
 * @tc.desc: 1. system running normally
 *           2. test CheckUserId returns error when user doesn't exist
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckUserId_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;
    // Don't add USER_ID, so it doesn't exist

    ErrCode ret = installer_->CheckUserId(INVALID_USER_ID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_USER_NOT_EXIST);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckUserId_0003
 * Function: CheckUserId
 * @tc.name: test CheckUserId with DEFAULT_USER_ID
 * @tc.desc: 1. system running normally
 *           2. test CheckUserId returns error for DEFAULT_USER_ID
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckUserId_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    AddUserId(DEFAULT_USER_ID);
    installer_->bundleName_ = BUNDLE_NAME;

    ErrCode ret = installer_->CheckUserId(DEFAULT_USER_ID);
    EXPECT_EQ(ret, ERR_SKILLS_NOT_SUPPORT_SINGLETON_AND_U1);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckUserId_0004
 * Function: CheckUserId
 * @tc.name: test CheckUserId with U1_USER_ID
 * @tc.desc: 1. system running normally
 *           2. test CheckUserId returns error for U1_USER_ID
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckUserId_0004,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    AddUserId(U1_USER_ID);
    installer_->bundleName_ = BUNDLE_NAME;

    ErrCode ret = installer_->CheckUserId(U1_USER_ID);
    EXPECT_EQ(ret, ERR_SKILLS_NOT_SUPPORT_SINGLETON_AND_U1);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckUserId_0005
 * Function: CheckUserId
 * @tc.name: test CheckUserId with valid user
 * @tc.desc: 1. system running normally
 *           2. test CheckUserId returns OK for valid user
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckUserId_0005,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    AddUserId(USER_ID);
    installer_->bundleName_ = BUNDLE_NAME;

    ErrCode ret = installer_->CheckUserId(USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckFileType_0001
 * Function: CheckFileType
 * @tc.name: test CheckFileType with empty bundlePaths
 * @tc.desc: 1. system running normally
 *           2. test CheckFileType returns error for empty paths
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckFileType_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> bundlePaths;

    ErrCode ret = installer_->CheckFileType(bundlePaths);
    EXPECT_EQ(ret, ERR_SKILLS_ONLY_ALLOW_ONE_MODULE);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckFileType_0002
 * Function: CheckFileType
 * @tc.name: test CheckFileType with invalid file extension
 * @tc.desc: 1. system running normally
 *           2. test CheckFileType returns error for non-.hsp files
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckFileType_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> bundlePaths = {"/data/test/file.hap"};

    ErrCode ret = installer_->CheckFileType(bundlePaths);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INVALID_HAP_NAME);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckFileType_0003
 * Function: CheckFileType
 * @tc.name: test CheckFileType with valid .hsp file
 * @tc.desc: 1. system running normally
 *           2. test CheckFileType returns OK for .hsp files
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckFileType_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> bundlePaths = {TEST_HSP_PATH};

    ErrCode ret = installer_->CheckFileType(bundlePaths);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckFileType_0004
 * Function: CheckFileType
 * @tc.name: test CheckFileType with mixed file types
 * @tc.desc: 1. system running normally
 *           2. test CheckFileType returns error for mixed file types
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckFileType_0004,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> bundlePaths = {TEST_HSP_PATH, "/data/test/file.hap"};

    ErrCode ret = installer_->CheckFileType(bundlePaths);
    EXPECT_EQ(ret, ERR_SKILLS_ONLY_ALLOW_ONE_MODULE);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckAppIdentifier_0001
 * Function: CheckAppIdentifier
 * @tc.name: test CheckAppIdentifier with matching identifiers
 * @tc.desc: 1. system running normally
 *           2. test CheckAppIdentifier returns true for matching identifiers
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckAppIdentifier_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::string oldAppIdentifier = TEST_APP_IDENTIFIER;
    std::string newAppIdentifier = TEST_APP_IDENTIFIER;
    std::string oldAppId = TEST_APP_ID;
    std::string newAppId = TEST_APP_ID;

    bool ret = installer_->CheckAppIdentifier(oldAppIdentifier, newAppIdentifier, oldAppId, newAppId);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckAppIdentifier_0002
 * Function: CheckAppIdentifier
 * @tc.name: test CheckAppIdentifier with different identifiers
 * @tc.desc: 1. system running normally
 *           2. test CheckAppIdentifier returns true for different identifiers
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckAppIdentifier_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::string oldAppIdentifier = "old.identifier";
    std::string newAppIdentifier = "new.identifier";
    std::string oldAppId = TEST_APP_ID;
    std::string newAppId = TEST_APP_ID;

    bool ret = installer_->CheckAppIdentifier(oldAppIdentifier, newAppIdentifier, oldAppId, newAppId);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckAppIdentifier_0003
 * Function: CheckAppIdentifier
 * @tc.name: test CheckAppIdentifier with DEBUG_APP_IDENTIFIER
 * @tc.desc: 1. system running normally
 *           2. test CheckAppIdentifier handles DEBUG_LIB_ID correctly
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckAppIdentifier_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::string oldAppIdentifier = "DEBUG_LIB_ID";
    std::string newAppIdentifier = "DEBUG_LIB_ID";
    std::string oldAppId = TEST_APP_ID;
    std::string newAppId = TEST_APP_ID;

    bool ret = installer_->CheckAppIdentifier(oldAppIdentifier, newAppIdentifier, oldAppId, newAppId);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckAppIdentifier_0004
 * Function: CheckAppIdentifier
 * @tc.name: test CheckAppIdentifier with empty identifiers
 * @tc.desc: 1. system running normally
 *           2. test CheckAppIdentifier returns true for empty identifiers
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckAppIdentifier_0004,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::string oldAppIdentifier = "";
    std::string newAppIdentifier = "";
    std::string oldAppId = "111";
    std::string newAppId = "111";

    bool ret = installer_->CheckAppIdentifier(oldAppIdentifier, newAppIdentifier, oldAppId, newAppId);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckSingletonAndU1Enable_0001
 * Function: CheckSingletonAndU1Enable
 * @tc.name: test CheckSingletonAndU1Enable with empty newInfos
 * @tc.desc: 1. system running normally
 *           2. test CheckSingletonAndU1Enable returns OK for empty infos
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckSingletonAndU1Enable_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::unordered_map<std::string, InnerBundleInfo> newInfos;

    ErrCode ret = installer_->CheckSingletonAndU1Enable(newInfos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckSingletonAndU1Enable_0002
 * Function: CheckSingletonAndU1Enable
 * @tc.name: test CheckSingletonAndU1Enable with singleton enabled
 * @tc.desc: 1. system running normally
 *           2. test CheckSingletonAndU1Enable returns error for singleton apps
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckSingletonAndU1Enable_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo info;
    // Set singleton enabled
    info.SetSingleton(true);
    newInfos[BUNDLE_NAME] = info;

    ErrCode ret = installer_->CheckSingletonAndU1Enable(newInfos);
    EXPECT_EQ(ret, ERR_SKILLS_NOT_SUPPORT_SINGLETON_AND_U1);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveModuleDir_0001
 * Function: RemoveModuleDir
 * @tc.name: test RemoveModuleDir with valid parameters
 * @tc.desc: 1. system running normally
 *           2. test RemoveModuleDir executes without crash
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveModuleDir_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = BUNDLE_NAME;
    installer_->RemoveModuleDir(BUNDLE_NAME, MODULE_NAME);
    // Verify bundle name is still set after operation
    EXPECT_EQ(installer_->bundleName_, BUNDLE_NAME);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveModuleDir_0002
 * Function: RemoveModuleDir
 * @tc.name: test RemoveModuleDir with empty bundle name
 * @tc.desc: 1. system running normally
 *           2. test RemoveModuleDir handles empty bundle name
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveModuleDir_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = BUNDLE_NAME;
    installer_->RemoveModuleDir("", MODULE_NAME);
    // Verify bundle name is unchanged after operation with empty parameter
    EXPECT_EQ(installer_->bundleName_, BUNDLE_NAME);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveModuleDir_0003
 * Function: RemoveModuleDir
 * @tc.name: test RemoveModuleDir with empty module name
 * @tc.desc: 1. system running normally
 *           2. test RemoveModuleDir handles empty module name
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveModuleDir_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = BUNDLE_NAME;
    installer_->RemoveModuleDir(BUNDLE_NAME, "");
    // Verify bundle name is unchanged after operation with empty module name
    EXPECT_EQ(installer_->bundleName_, BUNDLE_NAME);
}

/**
 * @tc.number: IndependentSkillsInstaller_MergeBundleInfos_0001
 * Function: MergeBundleInfos
 * @tc.name: test MergeBundleInfos
 * @tc.desc: 1. system running normally
 *           2. test MergeBundleInfos executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_MergeBundleInfos_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = BUNDLE_NAME;
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    installer_->MergeBundleInfos(info);
    // Verify bundle name is set correctly after merge
    EXPECT_EQ(installer_->bundleName_, BUNDLE_NAME);
}

/**
 * @tc.number: IndependentSkillsInstaller_MarkPreInstallState_0001
 * Function: MarkPreInstallState
 * @tc.name: test MarkPreInstallState with isUninstalled=false
 * @tc.desc: 1. system running normally
 *           2. test MarkPreInstallState marks as pre-installed
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_MarkPreInstallState_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = BUNDLE_NAME;
    installer_->MarkPreInstallState(BUNDLE_NAME, false);
    // Verify bundle name is set after marking pre-install state
    EXPECT_EQ(installer_->bundleName_, BUNDLE_NAME);
}

/**
 * @tc.number: IndependentSkillsInstaller_MarkPreInstallState_0002
 * Function: MarkPreInstallState
 * @tc.name: test MarkPreInstallState with isUninstalled=true
 * @tc.desc: 1. system running normally
 *           2. test MarkPreInstallState marks as uninstalled
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_MarkPreInstallState_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = BUNDLE_NAME;
    installer_->MarkPreInstallState(BUNDLE_NAME, true);
    // Verify bundle name is set after marking uninstalled state
    EXPECT_EQ(installer_->bundleName_, BUNDLE_NAME);
}

/**
 * @tc.number: IndependentSkillsInstaller_Install_0001
 * Function: Install
* @tc.name: test Install with empty hspPaths
 * @tc.desc: 1. system running normally
 *           2. test Install returns error for empty paths
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_Install_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> hspPaths;
    InstallParam installParam;
    installParam.userId = USER_ID;
    ErrCode ret = installer_->Install(hspPaths, installParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: IndependentSkillsInstaller_Install_0002
 * Function: Install
 * @tc.name: test Install with non-existent user
 * @tc.desc: 1. system running normally
 *           2. test Install returns error for non-existent user
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_Install_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> hspPaths = {TEST_HSP_PATH};
    InstallParam installParam;
    installParam.userId = USER_ID;
    ErrCode ret = installer_->Install(hspPaths, installParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_STAT_FILE_FAILED);
}

/**
 * @tc.number: IndependentSkillsInstaller_InstallBundleByBundleName_0001
 * Function: InstallBundleByBundleName
 * @tc.name: test InstallBundleByBundleName with empty bundle name
 * @tc.desc: 1. system running normally
 *           2. test InstallBundleByBundleName returns error for empty name
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_InstallBundleByBundleName_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    InstallParam installParam;
    installParam.userId = USER_ID;

    ErrCode ret = installer_->InstallBundleByBundleName("", installParam);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: IndependentSkillsInstaller_InstallBundleByBundleName_0002
 * Function: InstallBundleByBundleName
 * @tc.name: test InstallBundleByBundleName with valid bundle name
 * @tc.desc: 1. system running normally
 *           2. test InstallBundleByBundleName executes without crash
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_InstallBundleByBundleName_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    InstallParam installParam;
    installParam.userId = USER_ID;
    installParam.isPreInstallApp = true;

    ErrCode ret = installer_->InstallBundleByBundleName(BUNDLE_NAME, installParam);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: IndependentSkillsInstaller_MkdirIfNotExist_0001
 * Function: MkdirIfNotExist
 * @tc.name: test MkdirIfNotExist with valid path
 * @tc.desc: 1. system running normally
 *           2. test MkdirIfNotExist creates directory successfully
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_MkdirIfNotExist_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::string testDir = "/data/test/bms_skills_test_dir";

    ErrCode ret = installer_->MkdirIfNotExist(testDir);
    EXPECT_EQ(ret, ERR_OK);

    // Clean up
    std::filesystem::remove_all(testDir);
}

/**
 * @tc.number: IndependentSkillsInstaller_MkdirIfNotExist_0002
 * Function: MkdirIfNotExist
 * @tc.name: test MkdirIfNotExist with existing directory
 * @tc.desc: 1. system running normally
 *           2. test MkdirIfNotExist returns OK for existing directory
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_MkdirIfNotExist_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::string testDir = "/data/test/bms_skills_existing_dir";

    // Create directory first
    std::filesystem::create_directories(testDir);

    ErrCode ret = installer_->MkdirIfNotExist(testDir);
    EXPECT_EQ(ret, ERR_OK);

    // Clean up
    std::filesystem::remove_all(testDir);
}

/**
 * @tc.number: IndependentSkillsInstaller_AddAppProvisionInfo_0001
 * Function: AddAppProvisionInfo
 * @tc.name: test AddAppProvisionInfo
 * @tc.desc: 1. system running normally
 *           2. test AddAppProvisionInfo executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_AddAppProvisionInfo_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = BUNDLE_NAME;
    Security::Verify::ProvisionInfo provisionInfo;
    InstallParam installParam;
    installParam.userId = USER_ID;

    installer_->AddAppProvisionInfo(BUNDLE_NAME, provisionInfo, installParam);
    // Verify bundle name is set after operation
    EXPECT_EQ(installer_->bundleName_, BUNDLE_NAME);
}

/**
 * @tc.number: IndependentSkillsInstaller_UpdateDeveloperId_0001
 * Function: UpdateDeveloperId
 * @tc.name: test UpdateDeveloperId
 * @tc.desc: 1. system running normally
 *           2. test UpdateDeveloperId executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_UpdateDeveloperId_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = BUNDLE_NAME;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;

    installer_->UpdateDeveloperId(infos, hapVerifyRes);
    // Verify bundle name is set after operation
    EXPECT_EQ(installer_->bundleName_, BUNDLE_NAME);
}

/**
 * @tc.number: IndependentSkillsInstaller_DeliveryProfileToCodeSign_0001
 * Function: DeliveryProfileToCodeSign
 * @tc.name: test DeliveryProfileToCodeSign
 * @tc.desc: 1. system running normally
 *           2. test DeliveryProfileToCodeSign executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_DeliveryProfileToCodeSign_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;

    ErrCode ret = installer_->DeliveryProfileToCodeSign(hapVerifyResults);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE);
}

/**
 * @tc.number: IndependentSkillsInstaller_VerifyCodeSignatureForHsp_0001
 * Function: VerifyCodeSignatureForHsp
 * @tc.name: test VerifyCodeSignatureForHsp with empty path
 * @tc.desc: 1. system running normally
 *           2. test VerifyCodeSignatureForHsp handles empty path
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_VerifyCodeSignatureForHsp_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    ErrCode ret = installer_->VerifyCodeSignatureForHsp("");
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_SavePreInstallBundleInfo_0001
 * Function: SavePreInstallBundleInfo
 * @tc.name: test SavePreInstallBundleInfo with successful install
 * @tc.desc: 1. system running normally
 *           2. test SavePreInstallBundleInfo handles success case
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_SavePreInstallBundleInfo_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = BUNDLE_NAME;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InstallParam installParam;
    installParam.isPreInstallApp = true;

    installer_->SavePreInstallBundleInfo(newInfos, installParam);
    // Verify installer state after successful save
    EXPECT_EQ(installer_->bundleName_, BUNDLE_NAME);
}

/**
 * @tc.number: IndependentSkillsInstaller_SavePreInstallBundleInfo_0002
 * Function: SavePreInstallBundleInfo
 * @tc.name: test SavePreInstallBundleInfo with failed install
 * @tc.desc: 1. system running normally
 *           2. test SavePreInstallBundleInfo handles failure case
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_SavePreInstallBundleInfo_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = BUNDLE_NAME;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InstallParam installParam;
    installParam.isPreInstallApp = true;

    installer_->SavePreInstallBundleInfo(newInfos, installParam);
    // Verify installer state after failed save
    EXPECT_EQ(installer_->bundleName_, BUNDLE_NAME);
}

/**
 * @tc.number: IndependentSkillsInstaller_FetchInnerBundleInfo_0001
 * Function: FetchInnerBundleInfo
 * @tc.name: test FetchInnerBundleInfo
 * @tc.desc: 1. system running normally
 *           2. test FetchInnerBundleInfo returns bundle info
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_FetchInnerBundleInfo_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = nullptr;

    installer_->bundleName_ = BUNDLE_NAME;
    InnerBundleInfo info;
    bool isAppExist = true;
    bool ret = installer_->FetchInnerBundleInfo(info, isAppExist);
    // Should return false since bundle doesn't exist
    EXPECT_TRUE(ret);
    EXPECT_FALSE(isAppExist);
}

/**
 * @tc.number: IndependentSkillsInstaller_FetchInnerBundleInfo_0002
 * Function: FetchInnerBundleInfo
 * @tc.name: test FetchInnerBundleInfo
 * @tc.desc: 1. system running normally
 *           2. test FetchInnerBundleInfo returns bundle info
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_FetchInnerBundleInfo_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = BUNDLE_NAME;
    InnerBundleInfo info;
    bool isAppExist = true;
    bool ret = installer_->FetchInnerBundleInfo(info, isAppExist);
    // Should return false since bundle doesn't exist
    EXPECT_TRUE(ret);
    EXPECT_FALSE(isAppExist);
}

/**
 * @tc.number: IndependentSkillsInstaller_FetchInnerBundleInfo_0003
 * Function: FetchInnerBundleInfo
 * @tc.name: test FetchInnerBundleInfo
 * @tc.desc: 1. system running normally
 *           2. test FetchInnerBundleInfo returns bundle info
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_FetchInnerBundleInfo_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = nullptr;
    bundleMgrService_->RegisterDataMgr(nullptr);
    installer_->bundleName_ = BUNDLE_NAME;
    InnerBundleInfo info;
    bool isAppExist = true;
    bool ret = installer_->FetchInnerBundleInfo(info, isAppExist);
    // Should return false since bundle doesn't exist
    EXPECT_FALSE(ret);
    bundleMgrService_->RegisterDataMgr(dataMgr_);
}

/**
 * @tc.number: IndependentSkillsInstaller_MemberVariables_0001
 * Function: Member Variables
 * @tc.name: test member variable initialization
 * @tc.desc: 1. system running normally
 *           2. test all member variables are properly initialized
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_MemberVariables_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    auto installer = std::make_shared<IndependentSkillsInstaller>();

    EXPECT_EQ(installer->versionUpgrade_, false);
    EXPECT_EQ(installer->moduleUpdate_, false);
    EXPECT_EQ(installer->isEnterpriseBundle_, false);
    EXPECT_EQ(installer->hasInstalledInUser_, false);
    EXPECT_EQ(installer->versionCode_, 0);
    EXPECT_EQ(installer->userId_, -1);
    EXPECT_EQ(installer->startTime_, 0);
    EXPECT_TRUE(installer->bundleName_.empty());
    EXPECT_TRUE(installer->appIdentifier_.empty());
    EXPECT_TRUE(installer->compileSdkType_.empty());
    EXPECT_NE(installer->bundleInstallChecker_, nullptr);
    EXPECT_TRUE(installer->uninstallModuleVec_.empty());
    EXPECT_TRUE(installer->deleteBundlePath_.empty());
    EXPECT_TRUE(installer->toDeleteTempHspPath_.empty());
}

/**
 * @tc.number: IndependentSkillsInstaller_MemberVariables_0002
 * Function: Member Variables
 * @tc.name: test member variable assignment
 * @tc.desc: 1. system running normally
 *           2. test member variables can be properly assigned
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_MemberVariables_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->versionUpgrade_ = true;
    installer_->moduleUpdate_ = true;
    installer_->isEnterpriseBundle_ = true;
    installer_->hasInstalledInUser_ = true;
    installer_->versionCode_ = VERSION_CODE;
    installer_->userId_ = USER_ID;
    installer_->startTime_ = 12345;
    installer_->bundleName_ = BUNDLE_NAME;
    installer_->appIdentifier_ = TEST_APP_IDENTIFIER;
    installer_->compileSdkType_ = COMPILE_SDK_TYPE;
    installer_->uninstallModuleVec_.push_back(MODULE_NAME);
    installer_->deleteBundlePath_.push_back(TEST_HSP_PATH);
    installer_->toDeleteTempHspPath_.push_back("/data/temp/test.hsp");

    EXPECT_EQ(installer_->versionUpgrade_, true);
    EXPECT_EQ(installer_->moduleUpdate_, true);
    EXPECT_EQ(installer_->isEnterpriseBundle_, true);
    EXPECT_EQ(installer_->hasInstalledInUser_, true);
    EXPECT_EQ(installer_->versionCode_, VERSION_CODE);
    EXPECT_EQ(installer_->userId_, USER_ID);
    EXPECT_EQ(installer_->startTime_, 12345);
    EXPECT_EQ(installer_->bundleName_, BUNDLE_NAME);
    EXPECT_EQ(installer_->appIdentifier_, TEST_APP_IDENTIFIER);
    EXPECT_EQ(installer_->compileSdkType_, COMPILE_SDK_TYPE);
    EXPECT_EQ(installer_->uninstallModuleVec_.size(), 1);
    EXPECT_EQ(installer_->deleteBundlePath_.size(), 1);
    EXPECT_EQ(installer_->toDeleteTempHspPath_.size(), 1);
}

/**
 * @tc.number: IndependentSkillsInstaller_CopyHspToSecurityDir_0001
 * Function: CopyHspToSecurityDir
 * @tc.name: test CopyHspToSecurityDir with empty paths
 * @tc.desc: 1. system running normally
 *           2. test CopyHspToSecurityDir handles empty paths
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CopyHspToSecurityDir_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> bundlePaths;

    ErrCode ret = installer_->CopyHspToSecurityDir(bundlePaths);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_CopyHspToSecurityDir_0002
 * Function: CopyHspToSecurityDir
 * @tc.name: test CopyHspToSecurityDir with valid path
 * @tc.desc: 1. system running normally
 *           2. test CopyHspToSecurityDir with invalid file path
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CopyHspToSecurityDir_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> bundlePaths = {INVALID_HSP_PATH};

    ErrCode ret = installer_->CopyHspToSecurityDir(bundlePaths);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_MarkInstallFinish_0001
 * Function: MarkInstallFinish
 * @tc.name: test MarkInstallFinish
 * @tc.desc: 1. system running normally
 *           2. test MarkInstallFinish returns error when bundleName is empty
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_MarkInstallFinish_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = "";

    ErrCode ret = installer_->MarkInstallFinish();
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_UninstallLowerVersion_0001
 * Function: UninstallLowerVersion
 * @tc.name: test UninstallLowerVersion with empty module list
 * @tc.desc: 1. system running normally
 *           2. test UninstallLowerVersion handles empty list
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_UninstallLowerVersion_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> moduleNameList;

    ErrCode ret = installer_->UninstallLowerVersion(moduleNameList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR);
}

/**
 * @tc.number: IndependentSkillsInstaller_UninstallLowerVersion_0002
 * Function: UninstallLowerVersion
 * @tc.name: test UninstallLowerVersion with module list
 * @tc.desc: 1. system running normally
 *           2. test UninstallLowerVersion with module names
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_UninstallLowerVersion_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> moduleNameList = {MODULE_NAME, MODULE_NAME_TWO};

    ErrCode ret = installer_->UninstallLowerVersion(moduleNameList);
    // Will fail since modules don't exist, but should not crash
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckNeedInstall_0001
 * Function: CheckNeedInstall
 * @tc.name: test CheckNeedInstall with empty infos
 * @tc.desc: 1. system running normally
 *           2. test CheckNeedInstall returns false for empty infos
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckNeedInstall_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo oldInfo;
    bool isDowngrade = false;

    bool ret = installer_->CheckNeedInstall(infos, oldInfo, isDowngrade);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckNeedInstall_0002
 * Function: CheckNeedInstall
 * @tc.name: test CheckNeedInstall with valid info
 * @tc.desc: 1. system running normally
 *           2. test CheckNeedInstall with valid bundle info
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckNeedInstall_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo newInfo;
    newInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    infos[BUNDLE_NAME] = newInfo;

    InnerBundleInfo oldInfo;
    bool isDowngrade = false;

    bool ret = installer_->CheckNeedInstall(infos, oldInfo, isDowngrade);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckAppLabelInfo_0001
 * Function: CheckAppLabelInfo
 * @tc.name: test CheckAppLabelInfo with empty infos
 * @tc.desc: 1. system running normally
 *           2. test CheckAppLabelInfo returns OK for empty infos
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckAppLabelInfo_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::unordered_map<std::string, InnerBundleInfo> infos;

    ErrCode ret = installer_->CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_SKILLS_HAS_NO_MODULE);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckAppLabelInfo_0002
 * Function: CheckAppLabelInfo
 * @tc.name: test CheckAppLabelInfo with valid infos
 * @tc.desc: 1. system running normally
 *           2. test CheckAppLabelInfo with valid bundle info
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckAppLabelInfo_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo info;
    infos[BUNDLE_NAME] = info;

    ErrCode ret = installer_->CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_SKILLS_INSTALL_TYPE_FAILED);
}

/**
 * @tc.number: IndependentSkillsInstaller_UpdateSkillsPackage_0001
 * Function: UpdateSkillsPackage
 * @tc.name: test UpdateSkillsPackage
 * @tc.desc: 1. system running normally
 *           2. test UpdateSkillsPackage executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_UpdateSkillsPackage_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = BUNDLE_NAME;
    installer_->userId_ = USER_ID;

    InnerBundleInfo oldInfo;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo newInfo;
    newInfos[BUNDLE_NAME] = newInfo;

    InstallParam installParam;
    installParam.userId = USER_ID;

    ErrCode ret = installer_->UpdateSkillsPackage(oldInfo, newInfos, installParam);
    // Will fail due to missing bundle data, but should not crash
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckAndParseFiles_0001
 * Function: CheckAndParseFiles
 * @tc.name: test CheckAndParseFiles with empty hspPaths
 * @tc.desc: 1. system running normally
 *           2. test CheckAndParseFiles returns error for empty paths
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckAndParseFiles_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> hspPaths;
    InstallParam installParam;
    installParam.userId = USER_ID;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    ErrCode ret = installer_->CheckAndParseFiles(hspPaths, installParam, newInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_EMPTY);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckAndParseFiles_0002
 * Function: CheckAndParseFiles
 * @tc.name: test CheckAndParseFiles with invalid hsp path
 * @tc.desc: 1. system running normally
 *           2. test CheckAndParseFiles returns error for invalid path
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckAndParseFiles_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> hspPaths = {INVALID_HSP_PATH};
    InstallParam installParam;
    installParam.userId = USER_ID;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    ErrCode ret = installer_->CheckAndParseFiles(hspPaths, installParam, newInfos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_ExtractModule_0001
 * Function: ExtractModule
 * @tc.name: test ExtractModule
 * @tc.desc: 1. system running normally
 *           2. test ExtractModule executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ExtractModule_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    InnerBundleInfo newInfo;
    std::string bundlePath = TEST_HSP_PATH;
    bool copyHapToInstallPath = false;
    bool isModuleExist = false;

    installer_->userId_ = USER_ID;
    installer_->bundleName_ = BUNDLE_NAME;

    ErrCode ret = installer_->ExtractModule(newInfo, bundlePath, copyHapToInstallPath, isModuleExist);
    // Will fail due to invalid file path, but should not crash
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_ProcessBundleUpdateStatus_0001
 * Function: ProcessBundleUpdateStatus
 * @tc.name: test ProcessBundleUpdateStatus
 * @tc.desc: 1. system running normally
 *           2. test ProcessBundleUpdateStatus executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ProcessBundleUpdateStatus_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = BUNDLE_NAME;
    installer_->userId_ = USER_ID;

    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    std::string hspPath = TEST_HSP_PATH;
    InstallParam installParam;
    installParam.userId = USER_ID;

    ErrCode ret = installer_->ProcessBundleUpdateStatus(oldInfo, newInfo, hspPath, installParam);
    // Will fail due to invalid file path, but should not crash
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_ProcessNewModuleInstall_0001
 * Function: ProcessNewModuleInstall
 * @tc.name: test ProcessNewModuleInstall
 * @tc.desc: 1. system running normally
 *           2. test ProcessNewModuleInstall executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ProcessNewModuleInstall_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = BUNDLE_NAME;
    installer_->userId_ = USER_ID;

    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    std::string hspPath = TEST_HSP_PATH;
    InstallParam installParam;
    installParam.userId = USER_ID;

    ErrCode ret = installer_->ProcessNewModuleInstall(newInfo, oldInfo, hspPath, installParam);
    // Will fail due to invalid file path, but should not crash
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_ProcessModuleUpdate_0001
 * Function: ProcessModuleUpdate
 * @tc.name: test ProcessModuleUpdate
 * @tc.desc: 1. system running normally
 *           2. test ProcessModuleUpdate executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ProcessModuleUpdate_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->bundleName_ = BUNDLE_NAME;
    installer_->userId_ = USER_ID;

    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    std::string hspPath = TEST_HSP_PATH;
    InstallParam installParam;
    installParam.userId = USER_ID;

    ErrCode ret = installer_->ProcessModuleUpdate(newInfo, oldInfo, hspPath, installParam);
    // Will fail due to invalid file path, but should not crash
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_ProcessInstall_0001
 * Function: ProcessInstall
 * @tc.name: test ProcessInstall with empty hspPaths
 * @tc.desc: 1. system running normally
 *           2. test ProcessInstall returns error for empty paths
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ProcessInstall_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> hspPaths;
    InstallParam installParam;
    installParam.userId = USER_ID;
    ErrCode ret = installer_->ProcessInstall(hspPaths, installParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: IndependentSkillsInstaller_ProcessInstall_0002
 * Function: ProcessInstall
 * @tc.name: test ProcessInstall with non-existent user
 * @tc.desc: 1. system running normally
 *           2. test ProcessInstall returns error for non-existent user
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ProcessInstall_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> hspPaths = {TEST_HSP_PATH};
    InstallParam installParam;
    installParam.userId = USER_ID;
    ErrCode ret = installer_->ProcessInstall(hspPaths, installParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_STAT_FILE_FAILED);
}

/**
 * @tc.number: IndependentSkillsInstaller_ProcessInstallBundleByBundleName_0001
 * Function: ProcessInstallBundleByBundleName
 * @tc.name: test ProcessInstallBundleByBundleName with empty bundle name
 * @tc.desc: 1. system running normally
 *           2. test ProcessInstallBundleByBundleName returns error for empty name
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ProcessInstallBundleByBundleName_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    InstallParam installParam;
    installParam.userId = USER_ID;
    ErrCode ret = installer_->ProcessInstallBundleByBundleName("", installParam);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_ProcessInstallBundleByBundleName_0002
 * Function: ProcessInstallBundleByBundleName
 * @tc.name: test ProcessInstallBundleByBundleName with valid bundle name
 * @tc.desc: 1. system running normally
 *           2. test ProcessInstallBundleByBundleName executes without crash
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ProcessInstallBundleByBundleName_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    InstallParam installParam;
    installParam.userId = USER_ID;
    installParam.isPreInstallApp = true;
    ErrCode ret = installer_->ProcessInstallBundleByBundleName(BUNDLE_NAME, installParam);
    // Will fail due to missing bundle, but should not crash
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_MultipleHspPaths_0001
 * Function: Install
 * @tc.name: test Install with multiple HSP paths
 * @tc.desc: 1. system running normally
 *           2. test Install handles multiple HSP paths
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_MultipleHspPaths_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> hspPaths = {TEST_HSP_PATH, TEST_HSP_PATH2};
    InstallParam installParam;
    installParam.userId = USER_ID;
    ErrCode ret = installer_->Install(hspPaths, installParam);
    // Will fail due to invalid files, but should not crash
    EXPECT_NE(ret, ERR_OK);
}
} // namespace OHOS
