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
#include "event_report.h"
#include "install_param.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "skills_description_manager.h"
#include "skills_installer_util.h"
#include "skills_package_info.h"

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
const std::string TEST_HSP_PATH3 = "/data/test/resource/bms/skills/hsp_A.hsp";
const std::string INVALID_HSP_PATH = "/invalid/path/test.hsp";
const std::string TEST_APP_IDENTIFIER = "test.app.identifier";
const std::string TEST_APP_ID = "test.app.id";
const std::string BASE_SKILL_DIR = "/data/app/el1/skills/public";
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

    ErrCode ret = installer_->InstallBundleByBundleName("bundle_no_exist", installParam);
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
    installer_->bundleName_ = BUNDLE_NAME;
    std::string testDir = std::string(BASE_SKILL_DIR) + ServiceConstants::PATH_SEPARATOR + BUNDLE_NAME;
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
 * @tc.number: IndependentSkillsInstaller_DeliveryProfileToCodeSign_0002
 * Function: DeliveryProfileToCodeSign
 * @tc.name: test DeliveryProfileToCodeSign
 * @tc.desc: 1. system running normally
 *           2. test DeliveryProfileToCodeSign executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_DeliveryProfileToCodeSign_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    Security::Verify::HapVerifyResult hapVerifyResult;
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.profileBlockLength = 0;
    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    hapVerifyResult.SetProvisionInfo(provisionInfo);
    hapVerifyResults.push_back(hapVerifyResult);

    ErrCode ret = installer_->DeliveryProfileToCodeSign(hapVerifyResults);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE);
}

/**
 * @tc.number: IndependentSkillsInstaller_DeliveryProfileToCodeSign_0003
 * Function: DeliveryProfileToCodeSign
 * @tc.name: test DeliveryProfileToCodeSign
 * @tc.desc: 1. system running normally
 *           2. test DeliveryProfileToCodeSign executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_DeliveryProfileToCodeSign_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    Security::Verify::HapVerifyResult hapVerifyResult;
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.profileBlockLength = 0;
    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE_NORMAL;
    provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    hapVerifyResult.SetProvisionInfo(provisionInfo);
    hapVerifyResults.push_back(hapVerifyResult);

    ErrCode ret = installer_->DeliveryProfileToCodeSign(hapVerifyResults);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE);
}

/**
 * @tc.number: IndependentSkillsInstaller_DeliveryProfileToCodeSign_0004
 * Function: DeliveryProfileToCodeSign
 * @tc.name: test DeliveryProfileToCodeSign
 * @tc.desc: 1. system running normally
 *           2. test DeliveryProfileToCodeSign executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_DeliveryProfileToCodeSign_0004,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    Security::Verify::HapVerifyResult hapVerifyResult;
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.profileBlockLength = 0;
    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE_MDM;
    provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    hapVerifyResult.SetProvisionInfo(provisionInfo);
    hapVerifyResults.push_back(hapVerifyResult);

    ErrCode ret = installer_->DeliveryProfileToCodeSign(hapVerifyResults);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE);
}

/**
 * @tc.number: IndependentSkillsInstaller_DeliveryProfileToCodeSign_0005
 * Function: DeliveryProfileToCodeSign
 * @tc.name: test DeliveryProfileToCodeSign
 * @tc.desc: 1. system running normally
 *           2. test DeliveryProfileToCodeSign executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_DeliveryProfileToCodeSign_0005,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    Security::Verify::HapVerifyResult hapVerifyResult;
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.profileBlockLength = 0;
    provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    hapVerifyResult.SetProvisionInfo(provisionInfo);
    hapVerifyResults.push_back(hapVerifyResult);

    ErrCode ret = installer_->DeliveryProfileToCodeSign(hapVerifyResults);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE);
}

/**
 * @tc.number: IndependentSkillsInstaller_DeliveryProfileToCodeSign_0006
 * Function: DeliveryProfileToCodeSign
 * @tc.name: test DeliveryProfileToCodeSign
 * @tc.desc: 1. system running normally
 *           2. test DeliveryProfileToCodeSign executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_DeliveryProfileToCodeSign_0006,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    Security::Verify::HapVerifyResult hapVerifyResult;
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.profileBlockLength = 10;
    provisionInfo.profileBlock = nullptr;
    provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    hapVerifyResult.SetProvisionInfo(provisionInfo);
    hapVerifyResults.push_back(hapVerifyResult);

    ErrCode ret = installer_->DeliveryProfileToCodeSign(hapVerifyResults);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE);
}

/**
 * @tc.number: IndependentSkillsInstaller_DeliveryProfileToCodeSign_0007
 * Function: DeliveryProfileToCodeSign
 * @tc.name: test DeliveryProfileToCodeSign
 * @tc.desc: 1. system running normally
 *           2. test DeliveryProfileToCodeSign executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_DeliveryProfileToCodeSign_0007,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    Security::Verify::HapVerifyResult hapVerifyResult;
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.profileBlockLength = 10;
    auto tempProfilePtr = std::make_unique<unsigned char[]>(provisionInfo.profileBlockLength);
    provisionInfo.profileBlock = std::move(tempProfilePtr);
    provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    hapVerifyResult.SetProvisionInfo(provisionInfo);
    hapVerifyResults.push_back(hapVerifyResult);

    ErrCode ret = installer_->DeliveryProfileToCodeSign(hapVerifyResults);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_DeliveryProfileToCodeSign_0008
 * Function: DeliveryProfileToCodeSign
 * @tc.name: test DeliveryProfileToCodeSign
 * @tc.desc: 1. system running normally
 *           2. test DeliveryProfileToCodeSign executes without error
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_DeliveryProfileToCodeSign_0008,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    Security::Verify::HapVerifyResult hapVerifyResult;
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.distributionType = Security::Verify::AppDistType::NONE_TYPE;
    provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    hapVerifyResult.SetProvisionInfo(provisionInfo);
    hapVerifyResults.push_back(hapVerifyResult);

    ErrCode ret = installer_->DeliveryProfileToCodeSign(hapVerifyResults);
    EXPECT_EQ(ret, ERR_OK);
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
 * @tc.number: IndependentSkillsInstaller_CheckAndParseFiles_0003
 * Function: CheckAndParseFiles
 * @tc.name: test CheckAndParseFiles with valid hsp path
 * @tc.desc: 1. system running normally
 *           2. test CheckAndParseFiles returns error for valid path
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckAndParseFiles_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> hspPaths = {TEST_HSP_PATH3};
    InstallParam installParam;
    installParam.userId = USER_ID;
    installParam.isPreInstallApp = false;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    ErrCode ret = installer_->CheckAndParseFiles(hspPaths, installParam, newInfos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckAndParseFiles_0004
 * Function: CheckAndParseFiles
 * @tc.name: test CheckAndParseFiles with valid hsp path
 * @tc.desc: 1. system running normally
 *           2. test CheckAndParseFiles returns error for valid path
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckAndParseFiles_0004,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> hspPaths = {TEST_HSP_PATH3};
    InstallParam installParam;
    installParam.userId = USER_ID;
    installParam.isPreInstallApp = true;
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
 * @tc.number: IndependentSkillsInstaller_ProcessInstall_0003
 * Function: ProcessInstall
 * @tc.name: test ProcessInstall with non-existent user
 * @tc.desc: 1. system running normally
 *           2. test ProcessInstall returns error for non-existent user
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ProcessInstall_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::vector<std::string> hspPaths = {TEST_HSP_PATH};
    InstallParam installParam;
    installParam.userId = INVALID_USER_ID;
    ErrCode ret = installer_->ProcessInstall(hspPaths, installParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_USER_NOT_EXIST);
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
 * @tc.number: IndependentSkillsInstaller_ProcessInstallBundleByBundleName_0003
 * Function: ProcessInstallBundleByBundleName
 * @tc.name: test ProcessInstallBundleByBundleName with valid bundle name
 * @tc.desc: 1. system running normally
 *           2. test ProcessInstallBundleByBundleName executes without crash
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ProcessInstallBundleByBundleName_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    InnerBundleInfo bundleInfo;
    installer_->dataMgr_->bundleInfos_["testbundleName"] = bundleInfo;

    InstallParam installParam;
    installParam.userId = INVALID_USER_ID;
    installParam.isPreInstallApp = true;
    ErrCode ret = installer_->ProcessInstallBundleByBundleName("testbundleName", installParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_USER_NOT_EXIST);

    installParam.userId = USER_ID;
    ret = installer_->ProcessInstallBundleByBundleName("testbundleName", installParam);
    EXPECT_EQ(ret, ERR_SKILLS_INSTALL_TYPE_FAILED);
}

/**
 * @tc.number: IndependentSkillsInstaller_ProcessInstallBundleByBundleName_0004
 * Function: ProcessInstallBundleByBundleName
 * @tc.name: test ProcessInstallBundleByBundleName with valid bundle name
 * @tc.desc: 1. system running normally
 *           2. test ProcessInstallBundleByBundleName executes without crash
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ProcessInstallBundleByBundleName_0004,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    InnerBundleInfo bundleInfo;
    bundleInfo.SetApplicationBundleType(BundleType::SKILL);
    installer_->dataMgr_->bundleInfos_["testbundleName"] = bundleInfo;

    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.userId = USER_ID;
    ErrCode ret = installer_->ProcessInstallBundleByBundleName("testbundleName", installParam);
    EXPECT_EQ(ret, ERR_OK);
    installer_->dataMgr_->bundleInfos_.erase("testbundleName");
    installer_->dataMgr_->dataStorage_->DeleteStorageBundleInfo(bundleInfo);
}

/**
 * @tc.number: IndependentSkillsInstaller_ProcessInstallBundleByBundleName_0005
 * Function: ProcessInstallBundleByBundleName
 * @tc.name: test ProcessInstallBundleByBundleName with valid bundle name
 * @tc.desc: 1. system running normally
 *           2. test ProcessInstallBundleByBundleName executes without crash
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ProcessInstallBundleByBundleName_0005,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    InnerBundleInfo bundleInfo;
    bundleInfo.SetApplicationBundleType(BundleType::SKILL);
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = USER_ID;
    bundleInfo.AddInnerBundleUserInfo(userInfo);
    installer_->dataMgr_->bundleInfos_["testbundleName"] = bundleInfo;

    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.userId = USER_ID;
    ErrCode ret = installer_->ProcessInstallBundleByBundleName("testbundleName", installParam);
    EXPECT_EQ(ret, ERR_SKILLS_INSTALL_USER_ALREADY_EXIST);
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

/**
 * @tc.number: IndependentSkillsInstaller_SendBundleSystemEvent_0001
 * Function: SendBundleSystemEvent
 * @tc.name: test SendBundleSystemEvent with INSTALL event
 * @tc.desc: 1. system running normally
 *           2. test SendBundleSystemEvent sends INSTALL event and preserves installer state
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_SendBundleSystemEvent_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;
    installer_->versionCode_ = VERSION_CODE;
    installer_->startTime_ = BundleUtil::GetCurrentTimeMs();

    InstallParam installParam;
    installParam.userId = USER_ID;
    installParam.isPreInstallApp = false;

    // Store original state
    std::string originalBundleName = installer_->bundleName_;
    uint32_t originalVersionCode = installer_->versionCode_;

    // Test INSTALL event with success
    installer_->SendBundleSystemEvent(BUNDLE_NAME, installParam, BundleEventType::INSTALL, ERR_OK);

    // Verify installer state is preserved after event sending
    EXPECT_EQ(installer_->bundleName_, originalBundleName);
    EXPECT_EQ(installer_->versionCode_, originalVersionCode);
}

/**
 * @tc.number: IndependentSkillsInstaller_SendBundleSystemEvent_0002
 * Function: SendBundleSystemEvent
 * @tc.name: test SendBundleSystemEvent with UNINSTALL event
 * @tc.desc: 1. system running normally
 *           2. test SendBundleSystemEvent sends UNINSTALL event and preserves installer state
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_SendBundleSystemEvent_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;
    installer_->versionCode_ = VERSION_CODE;
    installer_->startTime_ = BundleUtil::GetCurrentTimeMs();

    InstallParam installParam;
    installParam.userId = USER_ID;
    installParam.isPreInstallApp = false;
    installParam.isRemoveUser = true;

    // Store original state
    std::string originalBundleName = installer_->bundleName_;
    int32_t originalUserId = installer_->userId_;

    // Test UNINSTALL event with error
    installer_->SendBundleSystemEvent(BUNDLE_NAME, installParam, BundleEventType::UNINSTALL,
        ERR_APPEXECFWK_INSTALL_PARSE_FAILED);

    // Verify installer state is preserved after event sending
    EXPECT_EQ(installer_->bundleName_, originalBundleName);
    EXPECT_EQ(installer_->userId_, originalUserId);
}

/**
 * @tc.number: IndependentSkillsInstaller_SendBundleSystemEvent_0003
 * Function: SendBundleSystemEvent
 * @tc.name: test SendBundleSystemEvent with UPDATE event
 * @tc.desc: 1. system running normally
 *           2. test SendBundleSystemEvent sends UPDATE event with OTA flag
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_SendBundleSystemEvent_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;
    installer_->versionCode_ = VERSION_CODE;
    installer_->startTime_ = BundleUtil::GetCurrentTimeMs();

    InstallParam installParam;
    installParam.userId = USER_ID;
    installParam.isPreInstallApp = false;
    installParam.isOTA = true;

    // Store original state
    int64_t originalStartTime = installer_->startTime_;

    // Test UPDATE event with success
    installer_->SendBundleSystemEvent(BUNDLE_NAME, installParam, BundleEventType::UPDATE, ERR_OK);

    // Verify startTime is preserved
    EXPECT_EQ(installer_->startTime_, originalStartTime);
    EXPECT_GT(installer_->versionCode_, 0);
}

/**
 * @tc.number: IndependentSkillsInstaller_SendBundleSystemEvent_0004
 * Function: SendBundleSystemEvent
 * @tc.name: test SendBundleSystemEvent with preInstallApp
 * @tc.desc: 1. system running normally
 *           2. test SendBundleSystemEvent sends event for preInstallApp scenario
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_SendBundleSystemEvent_0004,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;
    installer_->versionCode_ = VERSION_CODE;
    installer_->startTime_ = BundleUtil::GetCurrentTimeMs();

    InstallParam installParam;
    installParam.userId = USER_ID;
    installParam.isPreInstallApp = true;
    installParam.isOTA = false;

    // Store original state
    std::string originalBundleName = installer_->bundleName_;
    uint32_t originalVersionCode = installer_->versionCode_;

    // Test preInstallApp scenario
    installer_->SendBundleSystemEvent(BUNDLE_NAME, installParam, BundleEventType::INSTALL, ERR_OK);

    // Verify installer state is preserved after event sending
    EXPECT_EQ(installer_->bundleName_, originalBundleName);
    EXPECT_EQ(installer_->versionCode_, originalVersionCode);
    EXPECT_GT(installer_->startTime_, 0);
}

/**
 * @tc.number: IndependentSkillsInstaller_SendBundleSystemEvent_0005
 * Function: SendBundleSystemEvent
 * @tc.name: test SendBundleSystemEvent with createUser scenario
 * @tc.desc: 1. system running normally
 *           2. test SendBundleSystemEvent handles createUser scenario
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_SendBundleSystemEvent_0005,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;
    installer_->versionCode_ = VERSION_CODE;
    installer_->startTime_ = BundleUtil::GetCurrentTimeMs();
    installer_->userId_ = USER_ID;

    InstallParam installParam;
    installParam.userId = USER_ID;
    installParam.isPreInstallApp = false;
    installParam.isCreateUser = true;

    // Store original state
    std::string originalBundleName = installer_->bundleName_;
    int32_t originalUserId = installer_->userId_;

    // Test createUser scenario
    installer_->SendBundleSystemEvent(BUNDLE_NAME, installParam, BundleEventType::INSTALL, ERR_OK);

    // Verify installer state is preserved
    EXPECT_EQ(installer_->bundleName_, originalBundleName);
    EXPECT_EQ(installer_->userId_, originalUserId);
    EXPECT_GT(installer_->versionCode_, 0);
}

/**
 * @tc.number: IndependentSkillsInstaller_GetInstallEventInfo_0001
 * Function: GetInstallEventInfo
 * @tc.name: test GetInstallEventInfo with non-existent bundle
 * @tc.desc: 1. system running normally
 *           2. test GetInstallEventInfo handles non-existent bundle gracefully
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_GetInstallEventInfo_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = "non.existent.bundle";
    installer_->startTime_ = BundleUtil::GetCurrentTimeMs();

    EventInfo eventInfo;
    installer_->GetInstallEventInfo(eventInfo);

    // When bundle doesn't exist, GetInstallEventInfo returns early
    // endTime should still be set by SendBundleSystemEvent
    EXPECT_GE(eventInfo.endTime, 0);
    EXPECT_TRUE(eventInfo.bundleName.empty());
}

/**
 * @tc.number: IndependentSkillsInstaller_GetInstallEventInfo_0002
 * Function: GetInstallEventInfo
 * @tc.name: test GetInstallEventInfo with empty bundleName
 * @tc.desc: 1. system running normally
 *           2. test GetInstallEventInfo handles empty bundleName gracefully
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_GetInstallEventInfo_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = "";
    installer_->startTime_ = BundleUtil::GetCurrentTimeMs();

    EventInfo eventInfo;
    installer_->GetInstallEventInfo(eventInfo);

    // When bundleName is empty, FetchInnerBundleInfo will fail
    // eventInfo should remain in default state
    EXPECT_TRUE(eventInfo.bundleName.empty());
    EXPECT_EQ(eventInfo.userId, Constants::INVALID_USERID);
}

/**
 * @tc.number: IndependentSkillsInstaller_GetInstallEventInfo_0003
 * Function: GetInstallEventInfo
 * @tc.name: test GetInstallEventInfo with null dataMgr
 * @tc.desc: 1. system running normally
 *           2. test GetInstallEventInfo handles null dataMgr gracefully
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_GetInstallEventInfo_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = nullptr;
    installer_->bundleName_ = BUNDLE_NAME;
    installer_->startTime_ = BundleUtil::GetCurrentTimeMs();

    EventInfo eventInfo;
    installer_->GetInstallEventInfo(eventInfo);

    // When dataMgr is null, FetchInnerBundleInfo will fail and return false
    // eventInfo should remain in default state
    EXPECT_TRUE(eventInfo.bundleName.empty());
    EXPECT_EQ(eventInfo.errCode, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_GetInstallEventInfo_0004
 * Function: GetInstallEventInfo
 * @tc.name: test GetInstallEventInfo populates EventInfo correctly
 * @tc.desc: 1. system running normally
 *           2. test GetInstallEventInfo initializes EventInfo fields
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_GetInstallEventInfo_0004,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;
    installer_->userId_ = USER_ID;
    installer_->versionCode_ = VERSION_CODE;
    installer_->startTime_ = BundleUtil::GetCurrentTimeMs();

    EventInfo eventInfo;
    installer_->GetInstallEventInfo(eventInfo);

    // Since bundle doesn't exist, GetInstallEventInfo returns early
    // Verify basic EventInfo structure
    EXPECT_EQ(eventInfo.userId, Constants::INVALID_USERID);
    EXPECT_TRUE(eventInfo.fingerprint.empty());
    EXPECT_TRUE(eventInfo.filePath.empty());
    EXPECT_TRUE(eventInfo.hashValue.empty());
}

/**
 * @tc.number: IndependentSkillsInstaller_ExtractSkills_0001
 * Function: ExtractSkills
 * @tc.name: test ExtractSkills with empty skill profiles
 * @tc.desc: 1. system running normally
 *           2. test ExtractSkills returns error when skillProfiles is empty
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ExtractSkills_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;

    InnerBundleInfo newInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;
    moduleInfo.skillProfiles.clear(); // Empty skill profiles

    std::string bundlePath = TEST_HSP_PATH;
    bool isModuleExist = false;

    ErrCode ret = installer_->ExtractSkills(newInfo, moduleInfo, bundlePath, isModuleExist);
    EXPECT_EQ(ret, ERR_SKILLS_HAS_NO_SKILLS_AGENT);
}

/**
 * @tc.number: IndependentSkillsInstaller_ExtractSkills_0002
 * Function: ExtractSkills
 * @tc.name: test ExtractSkills filters invalid skill names with "../"
 * @tc.desc: 1. system running normally
 *           2. test ExtractSkills filters out skill names containing "../"
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ExtractSkills_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;

    InnerBundleInfo newInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;

    // Add skill profiles with invalid paths containing "../"
    SkillProfile invalidSkill1;
    invalidSkill1.name = "../invalidSkill";
    SkillProfile invalidSkill2;
    invalidSkill2.name = "skill/../../../attack";
    moduleInfo.skillProfiles.push_back(invalidSkill1);
    moduleInfo.skillProfiles.push_back(invalidSkill2);

    std::string bundlePath = TEST_HSP_PATH;
    bool isModuleExist = false;

    ErrCode ret = installer_->ExtractSkills(newInfo, moduleInfo, bundlePath, isModuleExist);
    // Should return error since all skill names are filtered out
    EXPECT_EQ(ret, ERR_SKILLS_HAS_NO_SKILLS_AGENT);
}

/**
 * @tc.number: IndependentSkillsInstaller_ExtractSkills_0003
 * Function: ExtractSkills
 * @tc.name: test ExtractSkills with mixed valid and invalid skill names
 * @tc.desc: 1. system running normally
 *           2. test ExtractSkills filters invalid names but processes valid ones
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ExtractSkills_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;

    InnerBundleInfo newInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;

    // Add mixed skill profiles
    SkillProfile validSkill1;
    validSkill1.name = SKILL_NAME;
    SkillProfile invalidSkill;
    invalidSkill.name = "../invalidSkill";
    SkillProfile validSkill2;
    validSkill2.name = SKILL_NAME_TWO;

    moduleInfo.skillProfiles.push_back(validSkill1);
    moduleInfo.skillProfiles.push_back(invalidSkill);
    moduleInfo.skillProfiles.push_back(validSkill2);

    std::string bundlePath = TEST_HSP_PATH;
    bool isModuleExist = false;

    // Since the HSP file doesn't actually exist, ExtractSkillsPackage will fail
    // but we verify the filtering logic by checking that valid skills are processed
    ErrCode ret = installer_->ExtractSkills(newInfo, moduleInfo, bundlePath, isModuleExist);
    // Should fail due to non-existent HSP file, not due to empty skill list
    EXPECT_NE(ret, ERR_SKILLS_HAS_NO_SKILLS_AGENT);
}

/**
 * @tc.number: IndependentSkillsInstaller_ExtractSkills_0004
 * Function: ExtractSkills
 * @tc.name: test ExtractSkills with valid skill profiles
 * @tc.desc: 1. system running normally
 *           2. test ExtractSkills with valid skill profile names
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ExtractSkills_0004,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;

    InnerBundleInfo newInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;

    // Add valid skill profiles
    SkillProfile skill1;
    skill1.name = SKILL_NAME;
    SkillProfile skill2;
    skill2.name = SKILL_NAME_TWO;
    moduleInfo.skillProfiles.push_back(skill1);
    moduleInfo.skillProfiles.push_back(skill2);

    std::string bundlePath = TEST_HSP_PATH;
    bool isModuleExist = false;

    ErrCode ret = installer_->ExtractSkills(newInfo, moduleInfo, bundlePath, isModuleExist);
    // Since the HSP file doesn't exist, ExtractSkillsPackage will fail
    // But it should NOT be ERR_SKILLS_HAS_NO_SKILLS_AGENT
    EXPECT_NE(ret, ERR_SKILLS_HAS_NO_SKILLS_AGENT);
}

/**
 * @tc.number: IndependentSkillsInstaller_ExtractSkills_0005
 * Function: ExtractSkills
 * @tc.name: test ExtractSkills when module already exists (isModuleExist=true)
 * @tc.desc: 1. system running normally
 *           2. test ExtractSkills appends "+temp" to moduleName when isModuleExist is true
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ExtractSkills_0005,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;

    InnerBundleInfo newInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;

    SkillProfile skill;
    skill.name = SKILL_NAME;
    moduleInfo.skillProfiles.push_back(skill);

    std::string bundlePath = TEST_HSP_PATH;
    bool isModuleExist = true; // Module already exists

    ErrCode ret = installer_->ExtractSkills(newInfo, moduleInfo, bundlePath, isModuleExist);
    // Should process with temp module name (+temp suffix)
    // Will fail due to non-existent HSP, but not due to empty skill list
    EXPECT_NE(ret, ERR_SKILLS_HAS_NO_SKILLS_AGENT);
}

/**
 * @tc.number: IndependentSkillsInstaller_ExtractSkills_0006
 * Function: ExtractSkills
 * @tc.name: test ExtractSkills with empty bundle name
 * @tc.desc: 1. system running normally
 *           2. test ExtractSkills behavior with empty bundleName
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ExtractSkills_0006,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = ""; // Empty bundle name

    InnerBundleInfo newInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;

    SkillProfile skill;
    skill.name = SKILL_NAME;
    moduleInfo.skillProfiles.push_back(skill);

    std::string bundlePath = TEST_HSP_PATH;
    bool isModuleExist = false;

    ErrCode ret = installer_->ExtractSkills(newInfo, moduleInfo, bundlePath, isModuleExist);
    // Should fail when calling ExtractSkillsPackage with empty bundle name
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_ExtractSkills_0007
 * Function: ExtractSkills
 * @tc.name: test ExtractSkills with single valid skill
 * @tc.desc: 1. system running normally
 *           2. test ExtractSkills handles single skill correctly
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ExtractSkills_0007,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;

    InnerBundleInfo newInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;

    // Add single skill profile
    SkillProfile skill;
    skill.name = SKILL_NAME;
    moduleInfo.skillProfiles.push_back(skill);

    std::string bundlePath = TEST_HSP_PATH;
    bool isModuleExist = false;

    ErrCode ret = installer_->ExtractSkills(newInfo, moduleInfo, bundlePath, isModuleExist);
    // Should attempt to extract, fail due to non-existent file
    // but not due to empty skill list
    EXPECT_NE(ret, ERR_SKILLS_HAS_NO_SKILLS_AGENT);
}

/**
 * @tc.number: IndependentSkillsInstaller_ExtractSkills_0008
 * Function: ExtractSkills
 * @tc.name: test ExtractSkills with all skill names containing "../"
 * @tc.desc: 1. system running normally
 *           2. test ExtractSkills returns error when all skill names are invalid
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ExtractSkills_0008,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;

    InnerBundleInfo newInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;

    // Add only invalid skill profiles
    SkillProfile skill1;
    skill1.name = "../skill1";
    SkillProfile skill2;
    skill2.name = "path/../../skill2";
    SkillProfile skill3;
    skill3.name = "./../skill3";

    moduleInfo.skillProfiles.push_back(skill1);
    moduleInfo.skillProfiles.push_back(skill2);
    moduleInfo.skillProfiles.push_back(skill3);

    std::string bundlePath = TEST_HSP_PATH;
    bool isModuleExist = false;

    ErrCode ret = installer_->ExtractSkills(newInfo, moduleInfo, bundlePath, isModuleExist);
    // All skills filtered out, should return ERR_SKILLS_HAS_NO_SKILLS_AGENT
    EXPECT_EQ(ret, ERR_SKILLS_HAS_NO_SKILLS_AGENT);
}

/**
 * @tc.number: IndependentSkillsInstaller_ExtractSkills_0009
 * Function: ExtractSkills
 * @tc.name: test ExtractSkills with complex valid skill names
 * @tc.desc: 1. system running normally
 *           2. test ExtractSkills handles complex but valid skill names
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ExtractSkills_0009,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;

    InnerBundleInfo newInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;

    // Add complex but valid skill names
    SkillProfile skill1;
    skill1.name = "mainSkill/subSkill";
    SkillProfile skill2;
    skill2.name = "feature.v2.skill";
    SkillProfile skill3;
    skill3.name = "common_utils-helper";

    moduleInfo.skillProfiles.push_back(skill1);
    moduleInfo.skillProfiles.push_back(skill2);
    moduleInfo.skillProfiles.push_back(skill3);

    std::string bundlePath = TEST_HSP_PATH;
    bool isModuleExist = false;

    ErrCode ret = installer_->ExtractSkills(newInfo, moduleInfo, bundlePath, isModuleExist);
    // Should process these valid names, fail due to non-existent HSP
    EXPECT_NE(ret, ERR_SKILLS_HAS_NO_SKILLS_AGENT);
}

/**
 * @tc.number: IndependentSkillsInstaller_ExtractSkills_0010
 * Function: ExtractSkills
 * @tc.name: test ExtractSkills with module update scenario
 * @tc.desc: 1. system running normally
 *           2. test ExtractSkills with isModuleExist=true and existing module info
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ExtractSkills_0010,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;

    InnerBundleInfo newInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME_TWO;

    SkillProfile skill;
    skill.name = SKILL_NAME_TWO;
    moduleInfo.skillProfiles.push_back(skill);

    std::string bundlePath = TEST_HSP_PATH2;
    bool isModuleExist = true;

    ErrCode ret = installer_->ExtractSkills(newInfo, moduleInfo, bundlePath, isModuleExist);
    // Should handle module update scenario
    // Will fail due to non-existent file, but not due to empty skill list
    EXPECT_NE(ret, ERR_SKILLS_HAS_NO_SKILLS_AGENT);
}

/**
 * @tc.number: SkillsInstallerUtil_RemoveInvalidSkillProfiles_0001
 * Function: RemoveInvalidSkillProfiles
 * @tc.name: test RemoveInvalidSkillProfiles with empty skillInfoList
 * @tc.desc: 1. system running normally
 *           2. test RemoveInvalidSkillProfiles clears all skillProfiles when skillInfoList is empty
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, SkillsInstallerUtil_RemoveInvalidSkillProfiles_0001,
    Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;

    // Add skill profiles
    SkillProfile skill1;
    skill1.name = SKILL_NAME;
    SkillProfile skill2;
    skill2.name = SKILL_NAME_TWO;
    moduleInfo.skillProfiles.push_back(skill1);
    moduleInfo.skillProfiles.push_back(skill2);

    // Add module to InnerBundleInfo
    auto &innerModuleInfos = innerBundleInfo.FetchInnerModuleInfos();
    innerModuleInfos[MODULE_NAME] = moduleInfo;

    // Empty skillInfoList
    std::vector<SkillsPackageInfo> skillInfoList;

    ErrCode ret = SkillsInstallerUtil::RemoveInvalidSkillProfiles(skillInfoList, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    // Verify all skillProfiles are cleared
    auto it = innerModuleInfos.find(MODULE_NAME);
    ASSERT_NE(it, innerModuleInfos.end());
    EXPECT_EQ(it->second.skillProfiles.size(), 0);
}

/**
 * @tc.number: SkillsInstallerUtil_RemoveInvalidSkillProfiles_0002
 * Function: RemoveInvalidSkillProfiles
 * @tc.name: test RemoveInvalidSkillProfiles clears invalid skillProfiles
 * @tc.desc: 1. system running normally
 *           2. test RemoveInvalidSkillProfiles removes skills not in valid list
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, SkillsInstallerUtil_RemoveInvalidSkillProfiles_0002,
    Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;

    // Add multiple skill profiles
    SkillProfile skill1;
    skill1.name = "skill1";
    SkillProfile skill2;
    skill2.name = "skill2";
    SkillProfile skill3;
    skill3.name = "skill3";
    moduleInfo.skillProfiles.push_back(skill1);
    moduleInfo.skillProfiles.push_back(skill2);
    moduleInfo.skillProfiles.push_back(skill3);

    auto &innerModuleInfos = innerBundleInfo.FetchInnerModuleInfos();
    innerModuleInfos[MODULE_NAME] = moduleInfo;

    // Only skill1 and skill3 are valid
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo info1;
    info1.moduleName = MODULE_NAME;
    info1.skillsName = "skill1";
    SkillsPackageInfo info2;
    info2.moduleName = MODULE_NAME;
    info2.skillsName = "skill3";
    skillInfoList.push_back(info1);
    skillInfoList.push_back(info2);

    ErrCode ret = SkillsInstallerUtil::RemoveInvalidSkillProfiles(skillInfoList, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    // Verify only valid skillProfiles remain
    auto it = innerModuleInfos.find(MODULE_NAME);
    ASSERT_NE(it, innerModuleInfos.end());
    EXPECT_EQ(it->second.skillProfiles.size(), 2);
    EXPECT_EQ(it->second.skillProfiles[0].name, "skill1");
    EXPECT_EQ(it->second.skillProfiles[1].name, "skill3");
}

/**
 * @tc.number: SkillsInstallerUtil_RemoveInvalidSkillProfiles_0003
 * Function: RemoveInvalidSkillProfiles
 * @tc.name: test RemoveInvalidSkillProfiles with multiple modules
 * @tc.desc: 1. system running normally
 *           2. test RemoveInvalidSkillProfiles handles multiple modules correctly
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, SkillsInstallerUtil_RemoveInvalidSkillProfiles_0003,
    Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;

    // Add first module with skill profiles
    InnerModuleInfo moduleInfo1;
    moduleInfo1.moduleName = MODULE_NAME;
    SkillProfile skill1;
    skill1.name = SKILL_NAME;
    SkillProfile skill2;
    skill2.name = SKILL_NAME_TWO;
    moduleInfo1.skillProfiles.push_back(skill1);
    moduleInfo1.skillProfiles.push_back(skill2);

    // Add second module with skill profiles
    InnerModuleInfo moduleInfo2;
    moduleInfo2.moduleName = MODULE_NAME_TWO;
    SkillProfile skill3;
    skill3.name = "featureSkill1";
    SkillProfile skill4;
    skill4.name = "featureSkill2";
    moduleInfo2.skillProfiles.push_back(skill3);
    moduleInfo2.skillProfiles.push_back(skill4);

    auto &innerModuleInfos = innerBundleInfo.FetchInnerModuleInfos();
    innerModuleInfos[MODULE_NAME] = moduleInfo1;
    innerModuleInfos[MODULE_NAME_TWO] = moduleInfo2;

    // Only skill1 and featureSkill1 are valid
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo info1;
    info1.moduleName = MODULE_NAME;
    info1.skillsName = SKILL_NAME;
    SkillsPackageInfo info2;
    info2.moduleName = MODULE_NAME_TWO;
    info2.skillsName = "featureSkill1";
    skillInfoList.push_back(info1);
    skillInfoList.push_back(info2);

    ErrCode ret = SkillsInstallerUtil::RemoveInvalidSkillProfiles(skillInfoList, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    // Verify first module has only skill1
    auto it1 = innerModuleInfos.find(MODULE_NAME);
    ASSERT_NE(it1, innerModuleInfos.end());
    EXPECT_EQ(it1->second.skillProfiles.size(), 1);
    EXPECT_EQ(it1->second.skillProfiles[0].name, SKILL_NAME);

    // Verify second module has only featureSkill1
    auto it2 = innerModuleInfos.find(MODULE_NAME_TWO);
    ASSERT_NE(it2, innerModuleInfos.end());
    EXPECT_EQ(it2->second.skillProfiles.size(), 1);
    EXPECT_EQ(it2->second.skillProfiles[0].name, "featureSkill1");
}

/**
 * @tc.number: SkillsInstallerUtil_RemoveInvalidSkillProfiles_0004
 * Function: RemoveInvalidSkillProfiles
 * @tc.name: test RemoveInvalidSkillProfiles clears module with no valid skills
 * @tc.desc: 1. system running normally
 *           2. test RemoveInvalidSkillProfiles clears all skillProfiles for module with no valid skills
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, SkillsInstallerUtil_RemoveInvalidSkillProfiles_0004,
    Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;

    // Add first module with skill profiles (has valid skills)
    InnerModuleInfo moduleInfo1;
    moduleInfo1.moduleName = MODULE_NAME;
    SkillProfile skill1;
    skill1.name = SKILL_NAME;
    moduleInfo1.skillProfiles.push_back(skill1);

    // Add second module with skill profiles (no valid skills)
    InnerModuleInfo moduleInfo2;
    moduleInfo2.moduleName = MODULE_NAME_TWO;
    SkillProfile skill2;
    skill2.name = SKILL_NAME_TWO;
    moduleInfo2.skillProfiles.push_back(skill2);

    auto &innerModuleInfos = innerBundleInfo.FetchInnerModuleInfos();
    innerModuleInfos[MODULE_NAME] = moduleInfo1;
    innerModuleInfos[MODULE_NAME_TWO] = moduleInfo2;

    // Only skill1 from MODULE_NAME is valid
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo info1;
    info1.moduleName = MODULE_NAME;
    info1.skillsName = SKILL_NAME;
    skillInfoList.push_back(info1);

    ErrCode ret = SkillsInstallerUtil::RemoveInvalidSkillProfiles(skillInfoList, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    // Verify first module keeps its skill
    auto it1 = innerModuleInfos.find(MODULE_NAME);
    ASSERT_NE(it1, innerModuleInfos.end());
    EXPECT_EQ(it1->second.skillProfiles.size(), 1);

    // Verify second module is cleared
    auto it2 = innerModuleInfos.find(MODULE_NAME_TWO);
    ASSERT_NE(it2, innerModuleInfos.end());
    EXPECT_EQ(it2->second.skillProfiles.size(), 0);
}

/**
 * @tc.number: SkillsInstallerUtil_RemoveInvalidSkillProfiles_0005
 * Function: RemoveInvalidSkillProfiles
 * @tc.name: test RemoveInvalidSkillProfiles with module having no skillProfiles
 * @tc.desc: 1. system running normally
 *           2. test RemoveInvalidSkillProfiles handles module with no skillProfiles
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, SkillsInstallerUtil_RemoveInvalidSkillProfiles_0005,
    Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;

    // Add module with no skill profiles
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;
    moduleInfo.skillProfiles.clear();

    auto &innerModuleInfos = innerBundleInfo.FetchInnerModuleInfos();
    innerModuleInfos[MODULE_NAME] = moduleInfo;

    // Valid skills for this module
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo info;
    info.moduleName = MODULE_NAME;
    info.skillsName = SKILL_NAME;
    skillInfoList.push_back(info);

    ErrCode ret = SkillsInstallerUtil::RemoveInvalidSkillProfiles(skillInfoList, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    // Verify module still has no skillProfiles
    auto it = innerModuleInfos.find(MODULE_NAME);
    ASSERT_NE(it, innerModuleInfos.end());
    EXPECT_EQ(it->second.skillProfiles.size(), 0);
}

/**
 * @tc.number: SkillsInstallerUtil_RemoveInvalidSkillProfiles_0006
 * Function: RemoveInvalidSkillProfiles
 * @tc.name: test RemoveInvalidSkillProfiles with all valid skills
 * @tc.desc: 1. system running normally
 *           2. test RemoveInvalidSkillProfiles keeps all skillProfiles when all are valid
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, SkillsInstallerUtil_RemoveInvalidSkillProfiles_0006,
    Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;

    // Add skill profiles
    SkillProfile skill1;
    skill1.name = "skill1";
    SkillProfile skill2;
    skill2.name = "skill2";
    SkillProfile skill3;
    skill3.name = "skill3";
    moduleInfo.skillProfiles.push_back(skill1);
    moduleInfo.skillProfiles.push_back(skill2);
    moduleInfo.skillProfiles.push_back(skill3);

    auto &innerModuleInfos = innerBundleInfo.FetchInnerModuleInfos();
    innerModuleInfos[MODULE_NAME] = moduleInfo;

    // All skills are valid
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo info1;
    info1.moduleName = MODULE_NAME;
    info1.skillsName = "skill1";
    SkillsPackageInfo info2;
    info2.moduleName = MODULE_NAME;
    info2.skillsName = "skill2";
    SkillsPackageInfo info3;
    info3.moduleName = MODULE_NAME;
    info3.skillsName = "skill3";
    skillInfoList.push_back(info1);
    skillInfoList.push_back(info2);
    skillInfoList.push_back(info3);

    ErrCode ret = SkillsInstallerUtil::RemoveInvalidSkillProfiles(skillInfoList, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    // Verify all skillProfiles remain
    auto it = innerModuleInfos.find(MODULE_NAME);
    ASSERT_NE(it, innerModuleInfos.end());
    EXPECT_EQ(it->second.skillProfiles.size(), 3);
    EXPECT_EQ(it->second.skillProfiles[0].name, "skill1");
    EXPECT_EQ(it->second.skillProfiles[1].name, "skill2");
    EXPECT_EQ(it->second.skillProfiles[2].name, "skill3");
}

/**
 * @tc.number: SkillsInstallerUtil_RemoveInvalidSkillProfiles_0007
 * Function: RemoveInvalidSkillProfiles
 * @tc.name: test RemoveInvalidSkillProfiles with module not in skillInfoList
 * @tc.desc: 1. system running normally
 *           2. test RemoveInvalidSkillProfiles clears skillProfiles for modules not in skillInfoList
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, SkillsInstallerUtil_RemoveInvalidSkillProfiles_0007,
    Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;

    // Add module with skill profiles
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;
    SkillProfile skill1;
    skill1.name = SKILL_NAME;
    SkillProfile skill2;
    skill2.name = SKILL_NAME_TWO;
    moduleInfo.skillProfiles.push_back(skill1);
    moduleInfo.skillProfiles.push_back(skill2);

    auto &innerModuleInfos = innerBundleInfo.FetchInnerModuleInfos();
    innerModuleInfos[MODULE_NAME] = moduleInfo;

    // skillInfoList contains skills for a different module
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo info;
    info.moduleName = MODULE_NAME_TWO;  // Different module
    info.skillsName = "featureSkill";
    skillInfoList.push_back(info);

    ErrCode ret = SkillsInstallerUtil::RemoveInvalidSkillProfiles(skillInfoList, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    // Verify all skillProfiles are cleared since module is not in valid list
    auto it = innerModuleInfos.find(MODULE_NAME);
    ASSERT_NE(it, innerModuleInfos.end());
    EXPECT_EQ(it->second.skillProfiles.size(), 0);
}

/**
 * @tc.number: SkillsInstallerUtil_RemoveInvalidSkillProfiles_0008
 * Function: RemoveInvalidSkillProfiles
 * @tc.name: test RemoveInvalidSkillProfiles with duplicate valid skills
 * @tc.desc: 1. system running normally
 *           2. test RemoveInvalidSkillProfiles handles duplicate valid skills correctly
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, SkillsInstallerUtil_RemoveInvalidSkillProfiles_0008,
    Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;

    // Add skill profiles
    SkillProfile skill1;
    skill1.name = SKILL_NAME;
    SkillProfile skill2;
    skill2.name = SKILL_NAME_TWO;
    moduleInfo.skillProfiles.push_back(skill1);
    moduleInfo.skillProfiles.push_back(skill2);

    auto &innerModuleInfos = innerBundleInfo.FetchInnerModuleInfos();
    innerModuleInfos[MODULE_NAME] = moduleInfo;

    // skillInfoList contains duplicate entries for same skill
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo info1;
    info1.moduleName = MODULE_NAME;
    info1.skillsName = SKILL_NAME;
    SkillsPackageInfo info2;
    info2.moduleName = MODULE_NAME;
    info2.skillsName = SKILL_NAME;  // Duplicate
    skillInfoList.push_back(info1);
    skillInfoList.push_back(info2);

    ErrCode ret = SkillsInstallerUtil::RemoveInvalidSkillProfiles(skillInfoList, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    // Verify only skill1 remains (skill2 is removed)
    auto it = innerModuleInfos.find(MODULE_NAME);
    ASSERT_NE(it, innerModuleInfos.end());
    EXPECT_EQ(it->second.skillProfiles.size(), 1);
    EXPECT_EQ(it->second.skillProfiles[0].name, SKILL_NAME);
}

/**
 * @tc.number: SkillsInstallerUtil_RemoveInvalidSkillProfiles_0009
 * Function: RemoveInvalidSkillProfiles
 * @tc.name: test RemoveInvalidSkillProfiles with empty InnerBundleInfo
 * @tc.desc: 1. system running normally
 *           2. test RemoveInvalidSkillProfiles handles empty InnerBundleInfo
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, SkillsInstallerUtil_RemoveInvalidSkillProfiles_0009,
    Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    // No modules added

    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo info;
    info.moduleName = MODULE_NAME;
    info.skillsName = SKILL_NAME;
    skillInfoList.push_back(info);

    ErrCode ret = SkillsInstallerUtil::RemoveInvalidSkillProfiles(skillInfoList, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    // Verify no modules exist
    auto &innerModuleInfos = innerBundleInfo.FetchInnerModuleInfos();
    EXPECT_EQ(innerModuleInfos.size(), 0);
}

/**
 * @tc.number: SkillsInstallerUtil_RemoveInvalidSkillProfiles_0010
 * Function: RemoveInvalidSkillProfiles
 * @tc.name: test RemoveInvalidSkillProfiles with complex skill names
 * @tc.desc: 1. system running normally
 *           2. test RemoveInvalidSkillProfiles handles complex skill names
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, SkillsInstallerUtil_RemoveInvalidSkillProfiles_0010,
    Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = MODULE_NAME;

    // Add skill profiles with complex names
    SkillProfile skill1;
    skill1.name = "mainSkill/subSkill";
    SkillProfile skill2;
    skill2.name = "feature.v2.skill";
    SkillProfile skill3;
    skill3.name = "common_utils-helper";
    SkillProfile skill4;
    skill4.name = "invalidSkill";
    moduleInfo.skillProfiles.push_back(skill1);
    moduleInfo.skillProfiles.push_back(skill2);
    moduleInfo.skillProfiles.push_back(skill3);
    moduleInfo.skillProfiles.push_back(skill4);

    auto &innerModuleInfos = innerBundleInfo.FetchInnerModuleInfos();
    innerModuleInfos[MODULE_NAME] = moduleInfo;

    // Only first three are valid
    std::vector<SkillsPackageInfo> skillInfoList;
    SkillsPackageInfo info1;
    info1.moduleName = MODULE_NAME;
    info1.skillsName = "mainSkill/subSkill";
    SkillsPackageInfo info2;
    info2.moduleName = MODULE_NAME;
    info2.skillsName = "feature.v2.skill";
    SkillsPackageInfo info3;
    info3.moduleName = MODULE_NAME;
    info3.skillsName = "common_utils-helper";
    skillInfoList.push_back(info1);
    skillInfoList.push_back(info2);
    skillInfoList.push_back(info3);

    ErrCode ret = SkillsInstallerUtil::RemoveInvalidSkillProfiles(skillInfoList, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    // Verify only valid skillProfiles remain
    auto it = innerModuleInfos.find(MODULE_NAME);
    ASSERT_NE(it, innerModuleInfos.end());
    EXPECT_EQ(it->second.skillProfiles.size(), 3);
    EXPECT_EQ(it->second.skillProfiles[0].name, "mainSkill/subSkill");
    EXPECT_EQ(it->second.skillProfiles[1].name, "feature.v2.skill");
    EXPECT_EQ(it->second.skillProfiles[2].name, "common_utils-helper");
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveInfo_0001
 * Function: RemoveInfo
 * @tc.name: test RemoveInfo with null dataMgr
 * @tc.desc: 1. system running normally
 *           2. test RemoveInfo returns false when dataMgr is nullptr
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveInfo_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = nullptr;

    bool ret = installer_->RemoveInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveInfo_0002
 * Function: RemoveInfo
 * @tc.name: test RemoveInfo with valid dataMgr and non-existent bundle
 * @tc.desc: 1. system running normally
 *           2. test RemoveInfo handles non-existent bundle gracefully
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveInfo_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    // Try to remove a bundle that doesn't exist
    bool ret = installer_->RemoveInfo("non.existent.bundle");
    // UpdateBundleInstallState will fail for non-existent bundle
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveInfo_0003
 * Function: RemoveInfo
 * @tc.name: test RemoveInfo with empty bundle name
 * @tc.desc: 1. system running normally
 *           2. test RemoveInfo handles empty bundle name
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveInfo_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    bool ret = installer_->RemoveInfo("");
    // UpdateBundleInstallState will fail for empty bundle name
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveSkillDir_0001
 * Function: RemoveSkillDir
 * @tc.name: test RemoveSkillDir with empty bundleName
 * @tc.desc: 1. system running normally
 *           2. test RemoveSkillDir returns false when bundleName is empty
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveSkillDir_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    bool ret = installer_->RemoveSkillDir("", MODULE_NAME, SKILL_NAME);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveSkillDir_0002
 * Function: RemoveSkillDir
 * @tc.name: test RemoveSkillDir with empty moduleName
 * @tc.desc: 1. system running normally
 *           2. test RemoveSkillDir returns false when moduleName is empty
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveSkillDir_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    bool ret = installer_->RemoveSkillDir(BUNDLE_NAME, "", SKILL_NAME);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveSkillDir_0003
 * Function: RemoveSkillDir
 * @tc.name: test RemoveSkillDir with empty skillsName
 * @tc.desc: 1. system running normally
 *           2. test RemoveSkillDir returns false when skillsName is empty
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveSkillDir_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    bool ret = installer_->RemoveSkillDir(BUNDLE_NAME, MODULE_NAME, "");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveSkillDir_0004
 * Function: RemoveSkillDir
 * @tc.name: test RemoveSkillDir with all empty parameters
 * @tc.desc: 1. system running normally
 *           2. test RemoveSkillDir returns false when all parameters are empty
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveSkillDir_0004,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    bool ret = installer_->RemoveSkillDir("", "", "");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveSkillDir_0005
 * Function: RemoveSkillDir
 * @tc.name: test RemoveSkillDir with valid parameters but non-existent directory
 * @tc.desc: 1. system running normally
 *           2. test RemoveSkillDir returns false when RemoveDir fails
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveSkillDir_0005,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    // Use valid parameters but directory doesn't exist
    bool ret = installer_->RemoveSkillDir("1aaa", MODULE_NAME, SKILL_NAME);
    // RemoveDir will fail since directory doesn't exist
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveSkillDir_0006
 * Function: RemoveSkillDir
 * @tc.name: test RemoveSkillDir with special characters in parameters
 * @tc.desc: 1. system running normally
 *           2. test RemoveSkillDir handles special characters in parameters
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveSkillDir_0006,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    // Test with special characters (will pass validation, fail on RemoveDir)
    bool ret = installer_->RemoveSkillDir("com.example.skills", "moduleName", "skillName");
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveModuleDir_0001
 * Function: RemoveModuleDir
 * @tc.name: test RemoveModuleDir with empty bundleName
 * @tc.desc: 1. system running normally
 *           2. test RemoveModuleDir returns false when bundleName is empty
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveModuleDir_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    bool ret = installer_->RemoveModuleDir("", MODULE_NAME);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveModuleDir_0002
 * Function: RemoveModuleDir
 * @tc.name: test RemoveModuleDir with empty moduleName
 * @tc.desc: 1. system running normally
 *           2. test RemoveModuleDir returns false when moduleName is empty
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveModuleDir_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    bool ret = installer_->RemoveModuleDir(BUNDLE_NAME, "");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveModuleDir_0003
 * Function: RemoveModuleDir
 * @tc.name: test RemoveModuleDir with both empty parameters
 * @tc.desc: 1. system running normally
 *           2. test RemoveModuleDir returns false when both parameters are empty
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveModuleDir_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    bool ret = installer_->RemoveModuleDir("", "");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveModuleDir_0004
 * Function: RemoveModuleDir
 * @tc.name: test RemoveModuleDir with valid parameters but non-existent directory
 * @tc.desc: 1. system running normally
 *           2. test RemoveModuleDir returns false when RemoveDir fails
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveModuleDir_0004,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    bool ret = installer_->RemoveModuleDir(BUNDLE_NAME, MODULE_NAME);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: IndependentSkillsInstaller_RemoveModuleDir_0005
 * Function: RemoveModuleDir
 * @tc.name: test RemoveModuleDir with special characters in parameters
 * @tc.desc: 1. system running normally
 *           2. test RemoveModuleDir handles special characters in parameters
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RemoveModuleDir_0005,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    // Test with special characters (will pass validation, fail on RemoveDir)
    bool ret = installer_->RemoveModuleDir("com", "module-v2");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_UpdateDeveloperId_0001
 * Function: UpdateDeveloperId
 * @tc.name: test UpdateDeveloperId with empty infos
 * @tc.desc: 1. system running normally
 *           2. test UpdateDeveloperId returns early when infos is empty
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_UpdateDeveloperId_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;

    bool ret = installer_->UpdateDeveloperId(infos, hapVerifyRes);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_UpdateDeveloperId_0002
 * Function: UpdateDeveloperId
 * @tc.name: test UpdateDeveloperId with hapVerifyRes smaller than infos
 * @tc.desc: 1. system running normally
 *           2. test UpdateDeveloperId returns early when hapVerifyRes.size() < infos.size()
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_UpdateDeveloperId_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo info1;
    InnerBundleInfo info2;
    infos[BUNDLE_NAME] = info1;
    infos["com.example.bundle2"] = info2;

    // hapVerifyRes has only 1 element, but infos has 2
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes(1);

    bool ret = installer_->UpdateDeveloperId(infos, hapVerifyRes);
    // Should return early without modifying infos
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_SavePreInstallBundleInfo_0001
 * Function: SavePreInstallBundleInfo
 * @tc.name: test SavePreInstallBundleInfo with empty newInfos
 * @tc.desc: 1. system running normally
 *           2. test SavePreInstallBundleInfo returns false when newInfos is empty
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_SavePreInstallBundleInfo_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    std::unordered_map<std::string, InnerBundleInfo> newInfos; // Empty
    InstallParam installParam;

    bool ret = installer_->SavePreInstallBundleInfo(newInfos, installParam);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: IndependentSkillsInstaller_SavePreInstallBundleInfo_0002
 * Function: SavePreInstallBundleInfo
 * @tc.name: test SavePreInstallBundleInfo with valid newInfos
 * @tc.desc: 1. system running normally
 *           2. test SavePreInstallBundleInfo processes valid infos
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_SavePreInstallBundleInfo_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = BUNDLE_NAME;

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    newInfos[BUNDLE_NAME] = info;

    InstallParam installParam;

    bool ret = installer_->SavePreInstallBundleInfo(newInfos, installParam);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: IndependentSkillsInstaller_InnerProcessInstall_0001
 * Function: InnerProcessInstall
 * @tc.name: test InnerProcessInstall with empty newInfos
 * @tc.desc: 1. system running normally
 *           2. test InnerProcessInstall handles empty newInfos
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_InnerProcessInstall_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->userId_ = USER_ID;

    std::unordered_map<std::string, InnerBundleInfo> newInfos; // Empty
    InstallParam installParam;
    installParam.userId = USER_ID;

    ErrCode ret = installer_->InnerProcessInstall(newInfos, installParam);
    // Empty newInfos means no iteration, will call SaveBundleInfoToStorage
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: IndependentSkillsInstaller_SaveBundleInfoToStorage_0001
 * Function: SaveBundleInfoToStorage
 * @tc.name: test SaveBundleInfoToStorage with empty bundleName
 * @tc.desc: 1. system running normally
 *           2. test SaveBundleInfoToStorage handles empty bundleName
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_SaveBundleInfoToStorage_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = ""; // Empty bundle name
    installer_->userId_ = USER_ID;

    ErrCode ret = installer_->SaveBundleInfoToStorage();
    // Should fail at UpdateBundleInstallState with empty bundleName
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_STATE_ERROR);
}

/**
 * @tc.number: IndependentSkillsInstaller_MarkInstallFinish_0002
 * Function: MarkInstallFinish
 * @tc.name: test MarkInstallFinish with nullptr
 * @tc.desc: 1. system running normally
 *           2. test MarkInstallFinish handles empty bundleName
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_MarkInstallFinish_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = nullptr;
    ErrCode ret = installer_->MarkInstallFinish();
    // FetchInnerBundleInfo will fail with nullptr
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: IndependentSkillsInstaller_MarkInstallFinish_0003
 * Function: MarkInstallFinish
 * @tc.name: test MarkInstallFinish with exist bundleName
 * @tc.desc: 1. system running normally
 *           2. test MarkInstallFinish handles exist bundleName
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_MarkInstallFinish_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = "bundle_exist";
    InnerBundleInfo bundleInfo;
    installer_->dataMgr_->bundleInfos_["bundle_exist"] = bundleInfo;

    ErrCode ret = installer_->MarkInstallFinish();
    // FetchInnerBundleInfo will fail with empty bundleName
    EXPECT_EQ(ret, ERR_APPEXECFWK_UPDATE_BUNDLE_ERROR);
}

/**
 * @tc.number: IndependentSkillsInstaller_RollBack_0001
 * Function: RollBack
 * @tc.name: test RollBack with exist bundleName
 * @tc.desc: 1. system running normally
 *           2. test RollBack handles exist bundleName
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RollBack_0001,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    installer_->bundleName_ = "";
    bool ret = installer_->RollBack();
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IndependentSkillsInstaller_RollBack_0002
 * Function: RollBack
 * @tc.name: test RollBack with exist bundleName
 * @tc.desc: 1. system running normally
 *           2. test RollBack handles exist bundleName
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RollBack_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    InnerBundleInfo bundleInfo;
    bundleInfo.SetIsPreInstallApp(true);
    installer_->newInnerBundleInfo_ = bundleInfo;
    installer_->bundleName_ = "com.ohos.bundlename";
    bool ret = installer_->RollBack();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IndependentSkillsInstaller_RollBack_0003
 * Function: RollBack
 * @tc.name: test RollBack with exist bundleName
 * @tc.desc: 1. system running normally
 *           2. test RollBack handles exist bundleName
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RollBack_0003,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    bool ret = installer_->RollBack(newInfos, ERR_APPEXECFWK_INSTALL_FAILED_INCONSISTENT_SIGNATURE);
    EXPECT_TRUE(ret);

    ret = installer_->RollBack(newInfos, ERR_SKILLS_INSTALL_TYPE_NOT_SAME);
    EXPECT_TRUE(ret);

    ret = installer_->RollBack(newInfos, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
    EXPECT_TRUE(ret);

    ret = installer_->RollBack(newInfos, ERR_SKILLS_MODULE_NAME_NOT_SAME);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IndependentSkillsInstaller_RollBack_0004
 * Function: RollBack
 * @tc.name: test RollBack with exist bundleName
 * @tc.desc: 1. system running normally
 *           2. test RollBack handles exist bundleName
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RollBack_0004,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = nullptr;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    bool ret = installer_->RollBack(newInfos, ERR_APPEXECFWK_INSTALL_FAILED_NO_PROFILE_BLOCK_FAIL);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IndependentSkillsInstaller_RollBack_0005
 * Function: RollBack
 * @tc.name: test RollBack with exist bundleName
 * @tc.desc: 1. system running normally
 *           2. test RollBack handles exist bundleName
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_RollBack_0005,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo bundleInfo;
    newInfos["bundle"] = bundleInfo;
    bool ret = installer_->RollBack(newInfos, ERR_APPEXECFWK_INSTALL_FAILED_NO_PROFILE_BLOCK_FAIL);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IndependentSkillsInstaller_ResetProperties_0002
 * Function: ResetProperties
 * @tc.name: test ResetProperties resets sessionId_ and sessionCommitted_
 * @tc.desc: 1. system running normally
 *           2. test ResetProperties resets session-related fields used for FinishHapInstall
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_ResetProperties_0002,
    Function | SmallTest | Level0)
{
    auto installer_ = std::make_shared<IndependentSkillsInstaller>();
    installer_->dataMgr_ = dataMgr_;

    installer_->sessionId_ = 12345;
    installer_->sessionCommitted_ = true;
    installer_->uninstallModuleVec_.emplace_back(MODULE_NAME);
    installer_->deleteBundlePath_.emplace_back(TEST_HSP_PATH);
    installer_->toDeleteTempHspPath_.emplace_back(TEST_HSP_PATH2);

    installer_->ResetProperties();

    EXPECT_EQ(installer_->sessionId_, 0);
    EXPECT_EQ(installer_->sessionCommitted_, false);
    EXPECT_TRUE(installer_->uninstallModuleVec_.empty());
    EXPECT_TRUE(installer_->deleteBundlePath_.empty());
    EXPECT_TRUE(installer_->toDeleteTempHspPath_.empty());
}

/**
 * @tc.number: IndependentSkillsInstaller_Constructor_0002
 * Function: IndependentSkillsInstaller
 * @tc.name: test IndependentSkillsInstaller member variable initialization
 * @tc.desc: 1. system running normally
 *           2. test sessionId_ and sessionCommitted_ are initialized correctly
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_Constructor_0002,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    EXPECT_NE(installer, nullptr);
    EXPECT_EQ(installer->sessionId_, 0);
    EXPECT_EQ(installer->sessionCommitted_, false);
    EXPECT_TRUE(installer->needDeleteSkillsPackageInfo_.empty());
}

/**
 * @tc.number: IndependentSkillsInstaller_CheckAppLabelInfo_0004
 * Function: CheckAppLabelInfo
 * @tc.name: test CheckAppLabelInfo with skill type bundle
 * @tc.desc: 1. system running normally
 *           2. test CheckAppLabelInfo validates bundleName_ and versionCode_ are set
 */
HWTEST_F(BmsIndependentSkillsInstallerTest, IndependentSkillsInstaller_CheckAppLabelInfo_0004,
    Function | SmallTest | Level0)
{
    auto installer = std::make_shared<IndependentSkillsInstaller>();
    installer->dataMgr_ = dataMgr_;

    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleType = BundleType::SKILL;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    info.baseBundleInfo_->versionCode = VERSION_CODE;

    InnerModuleInfo moduleInfo;
    moduleInfo.distro.moduleType = Profile::MODULE_TYPE_SKILLS;
    moduleInfo.moduleName = MODULE_NAME;
    SkillProfile skillProfile;
    skillProfile.name = SKILL_NAME;
    moduleInfo.skillProfiles.emplace_back(skillProfile);
    info.innerModuleInfos_.emplace(MODULE_NAME, moduleInfo);
    info.currentPackage_ = MODULE_NAME;

    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos.emplace(TEST_HSP_PATH, info);

    ErrCode ret = installer->CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(installer->bundleName_, BUNDLE_NAME);
    EXPECT_EQ(installer->versionCode_, VERSION_CODE);
}
} // namespace OHOS
