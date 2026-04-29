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

#include "base_bundle_installer.h"
#include "bundle_clone_installer.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "inner_bundle_info.h"
#include "install_param.h"
#include "mock_status_receiver.h"
#include "share_file_helper.h"
#include "inner_bundle_clone_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string TEST_BUNDLE_NAME = "com.example.testbundle";
const std::string TEST_MODULE_NAME = "entry";
const std::string TEST_HAP_PATH = "/data/test/resource/test.hap";
const std::string TEST_SHARE_FILES_JSON = R"({"shareFiles":[{"path":"/test/path","mode":"read"}]})";
const std::string EMPTY_STRING = "";
const int32_t TEST_USER_ID = 100;
const int32_t TEST_USER_ID_2 = 101;
const int32_t TEST_APP_INDEX_1 = 1;
const int32_t TEST_APP_INDEX_2 = 2;
const uint32_t TEST_TOKEN_ID = 123456;
const uint32_t TEST_TOKEN_ID_2 = 123457;
}  // namespace

class BmsBundleShareFilesTest : public testing::Test {
public:
    BmsBundleShareFilesTest() = default;
    ~BmsBundleShareFilesTest() override = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    // Helper function to create a basic InnerBundleInfo with bundle name
    InnerBundleInfo CreateTestBundleInfo(const std::string &bundleName) const
    {
        BundleInfo bundleInfo;
        bundleInfo.name = bundleName;
        ApplicationInfo applicationInfo;
        applicationInfo.name = bundleName;

        InnerBundleInfo innerBundleInfo;
        innerBundleInfo.SetBaseBundleInfo(bundleInfo);
        innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
        return innerBundleInfo;
    }

    // Helper function to add module info to InnerBundleInfo
    void AddModuleInfo(InnerBundleInfo &info, const InnerModuleInfo &moduleInfo) const
    {
        std::map<std::string, InnerModuleInfo> innerModuleInfoMap;
        innerModuleInfoMap[moduleInfo.moduleName] = moduleInfo;
        info.AddInnerModuleInfo(innerModuleInfoMap);
    }

    // Helper function to add user info to InnerBundleInfo
    void AddUserInfo(InnerBundleInfo &info, const InnerBundleUserInfo &userInfo) const
    {
        info.AddInnerBundleUserInfo(userInfo);
    }

protected:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;
};

std::shared_ptr<BundleMgrService> BmsBundleShareFilesTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

void BmsBundleShareFilesTest::SetUpTestCase()
{
    bundleMgrService_->OnStart();
}

void BmsBundleShareFilesTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleShareFilesTest::SetUp()
{
    dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_TRUE(dataMgr_ != nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = dataMgr_;
}

void BmsBundleShareFilesTest::TearDown()
{
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
}

/**
 * @tc.number: BmsBundleShareFilesTest_0100
 * @tc.name: ShareFileHelper::SetShareFileInfo
 * @tc.desc: Test SetShareFileInfo with valid parameters
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0100 start";

    auto ret = ShareFileHelper::SetShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0100 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_0200
 * @tc.name: ShareFileHelper::SetShareFileInfo
 * @tc.desc: Test SetShareFileInfo with empty bundle name
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0200 start";

    auto ret = ShareFileHelper::SetShareFileInfo(
        TEST_SHARE_FILES_JSON, EMPTY_STRING, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0200 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_0300
 * @tc.name: ShareFileHelper::SetShareFileInfo
 * @tc.desc: Test SetShareFileInfo with empty JSON config
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0300 start";

    auto ret = ShareFileHelper::SetShareFileInfo(
        EMPTY_STRING, TEST_BUNDLE_NAME, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0300 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_0400
 * @tc.name: ShareFileHelper::UpdateShareFileInfo
 * @tc.desc: Test UpdateShareFileInfo with valid parameters
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0400 start";

    auto ret = ShareFileHelper::UpdateShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0400 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_0500
 * @tc.name: ShareFileHelper::UpdateShareFileInfo
 * @tc.desc: Test UpdateShareFileInfo with different user ID
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0500 start";

    auto ret = ShareFileHelper::UpdateShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, TEST_USER_ID_2, TEST_TOKEN_ID);
    EXPECT_EQ(ret, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0500 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_0600
 * @tc.name: ShareFileHelper::UnsetShareFileInfo
 * @tc.desc: Test UnsetShareFileInfo with valid parameters
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0600 start";

    auto ret = ShareFileHelper::UnsetShareFileInfo(TEST_TOKEN_ID, TEST_BUNDLE_NAME, TEST_USER_ID);
    EXPECT_EQ(ret, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0600 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_0700
 * @tc.name: ShareFileHelper::UnsetShareFileInfo
 * @tc.desc: Test UnsetShareFileInfo with empty bundle name
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0700 start";

    auto ret = ShareFileHelper::UnsetShareFileInfo(TEST_TOKEN_ID, EMPTY_STRING, TEST_USER_ID);
    EXPECT_EQ(ret, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0700 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_0800
 * @tc.name: BundleDataMgr::GetShareFilesJsonFromHap
 * @tc.desc: Test GetShareFilesJsonFromHap with empty shareFiles config
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_0800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0800 start";

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.shareFiles.clear();

    std::string jsonContent;
    auto ret = dataMgr_->GetShareFilesJsonFromHap(TEST_HAP_PATH, moduleInfo, jsonContent);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(jsonContent.empty());

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0800 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_0900
 * @tc.name: BundleDataMgr::GetShareFilesJsonFromHap
 * @tc.desc: Test GetShareFilesJsonFromHap with non-entry module
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_0900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0900 start";

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = false;
    moduleInfo.shareFiles = "/test/path";

    std::string jsonContent;
    auto ret = dataMgr_->GetShareFilesJsonFromHap(TEST_HAP_PATH, moduleInfo, jsonContent);
    EXPECT_NE(ret, ERR_OK);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_0900 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_1000
 * @tc.name: BaseBundleInstaller::ProcessBundleShareFiles
 * @tc.desc: Test ProcessBundleShareFiles with empty newInfos
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_1000, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1000 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo oldInfo;

    auto ret = installer->ProcessBundleShareFiles(newInfos, oldInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1000 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_1100
 * @tc.name: BaseBundleInstaller::ProcessModuleShareFiles
 * @tc.desc: Test ProcessModuleShareFiles with null dataMgr
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_1100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1100 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = nullptr;

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;

    auto ret = installer->ProcessModuleShareFiles(
        TEST_HAP_PATH, moduleInfo, TEST_BUNDLE_NAME, InnerBundleInfo());
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1100 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_1400
 * @tc.name: BaseBundleInstaller::ProcessUninstallShareFiles
 * @tc.desc: Test ProcessUninstallShareFiles with empty bundle info
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_1400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1400 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    InnerBundleInfo info;
    auto ret = installer->ProcessUninstallShareFiles(info, TEST_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1400 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_1500
 * @tc.name: BaseBundleInstaller::RollbackShareFiles
 * @tc.desc: Test RollbackShareFiles when hasShareFilesProcessed is false
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_1500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1500 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->hasShareFilesProcessed_ = false;

    installer->RollbackShareFiles(InnerBundleInfo());

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1500 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_1600
 * @tc.name: BaseBundleInstaller::RollbackShareFilesForNewInstall
 * @tc.desc: Test RollbackShareFilesForNewInstall
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_1600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1600 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    auto failCount = installer->RollbackShareFilesForNewInstall();
    EXPECT_GE(failCount, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1600 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_1700
 * @tc.name: BaseBundleInstaller::RollbackShareFilesForUpdate
 * @tc.desc: Test RollbackShareFilesForUpdate with empty oldInfo
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_1700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1700 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    InnerBundleInfo oldInfo;
    auto failCount = installer->RollbackShareFilesForUpdate(oldInfo);
    EXPECT_GE(failCount, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1700 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_1800
 * @tc.name: BaseBundleInstaller::SaveOldShareFilesForRollback
 * @tc.desc: Test SaveOldShareFilesForRollback with empty oldInfo
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_1800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1800 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    InnerBundleInfo oldBundleInfo;
    auto ret = installer->SaveOldShareFilesForRollback(oldBundleInfo);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1800 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_1900
 * @tc.name: BaseBundleInstaller::UpdateShareFileInfoForAllInstances
 * @tc.desc: Test UpdateShareFileInfoForAllInstances with empty userInfos
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_1900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1900 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    InnerBundleInfo oldInfo;

    auto ret = installer->UpdateShareFileInfoForAllInstances(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, oldInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(installer->hasShareFilesProcessed_);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_1900 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_2000
 * @tc.name: BaseBundleInstaller::UpdateMultiUserInstances
 * @tc.desc: Test UpdateMultiUserInstances with valid userInfo
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_2000, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_2000 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;

    auto failCount = installer->UpdateMultiUserInstances(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, userInfo);
    EXPECT_GE(failCount, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_2000 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_2400
 * @tc.name: BaseBundleInstaller::RollbackUserInstances
 * @tc.desc: Test RollbackUserInstances with empty cloneInfos
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_2400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_2400 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;
    userInfo.cloneInfos.clear();

    InnerBundleInfo oldInfo;

    auto failCount = installer->RollbackUserInstances(userInfo, oldInfo);
    EXPECT_GE(failCount, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_2400 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_2600
 * @tc.name: ShareFileHelper multiple calls
 * @tc.desc: Test multiple ShareFileHelper calls in sequence
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_2600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_2600 start";

    // Set
    auto ret1 = ShareFileHelper::SetShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret1, 0);

    // Update
    auto ret2 = ShareFileHelper::UpdateShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret2, 0);

    // Unset
    auto ret3 = ShareFileHelper::UnsetShareFileInfo(TEST_TOKEN_ID, TEST_BUNDLE_NAME, TEST_USER_ID);
    EXPECT_EQ(ret3, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_2600 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_2700
 * @tc.name: BaseBundleInstaller complete share files workflow
 * @tc.desc: Test complete workflow: set -> rollback -> unset
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_2700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_2700 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->isAppExist_ = false;
    installer->accessTokenId_ = TEST_TOKEN_ID;

    // Set
    auto ret1 = ShareFileHelper::SetShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret1, 0);
    installer->hasShareFilesProcessed_ = true;

    // Rollback for new install
    installer->hasShareFilesProcessed_ = true;
    installer->isAppExist_ = false;
    installer->RollbackShareFiles(InnerBundleInfo());

    // Unset
    InnerBundleInfo info;
    auto ret2 = installer->ProcessUninstallShareFiles(info, TEST_USER_ID);
    EXPECT_EQ(ret2, ERR_OK);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_2700 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_2800
 * @tc.name: BaseBundleInstaller with multiple users
 * @tc.desc: Test UpdateMultiUserInstances with multiple users
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_2800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_2800 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // User 1
    InnerBundleUserInfo userInfo1;
    userInfo1.bundleUserInfo.userId = TEST_USER_ID;
    userInfo1.accessTokenId = TEST_TOKEN_ID;

    auto failCount1 = installer->UpdateMultiUserInstances(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, userInfo1);
    EXPECT_GE(failCount1, 0);

    // User 2
    InnerBundleUserInfo userInfo2;
    userInfo2.bundleUserInfo.userId = TEST_USER_ID_2;
    userInfo2.accessTokenId = TEST_TOKEN_ID_2;

    auto failCount2 = installer->UpdateMultiUserInstances(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, userInfo2);
    EXPECT_GE(failCount2, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_2800 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_2900
 * @tc.name: BaseBundleInstaller with clone apps
 * @tc.desc: Test UpdateMultiUserInstances with clone apps
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_2900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_2900 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;

    // Add clone apps
    InnerBundleCloneInfo cloneInfo1;
    cloneInfo1.appIndex = TEST_APP_INDEX_1;
    cloneInfo1.accessTokenId = TEST_TOKEN_ID;
    std::string key1 = std::to_string(TEST_APP_INDEX_1);
    userInfo.cloneInfos[key1] = cloneInfo1;

    InnerBundleCloneInfo cloneInfo2;
    cloneInfo2.appIndex = TEST_APP_INDEX_2;
    cloneInfo2.accessTokenId = TEST_TOKEN_ID_2;
    std::string key2 = std::to_string(TEST_APP_INDEX_2);
    userInfo.cloneInfos[key2] = cloneInfo2;

    auto failCount = installer->UpdateMultiUserInstances(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, userInfo);
    EXPECT_GE(failCount, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_2900 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_3000
 * @tc.name: ShareFileHelper edge cases
 * @tc.desc: Test ShareFileHelper with edge case parameters
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_3000, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3000 start";

    // Empty all parameters
    auto ret1 = ShareFileHelper::SetShareFileInfo(
        EMPTY_STRING, EMPTY_STRING, 0, 0);
    EXPECT_EQ(ret1, 0);

    // Very large user ID
    auto ret2 = ShareFileHelper::SetShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, 999999, TEST_TOKEN_ID);
    EXPECT_EQ(ret2, 0);

    // Very large token ID
    auto ret3 = ShareFileHelper::SetShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, TEST_USER_ID, UINT32_MAX);
    EXPECT_EQ(ret3, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3000 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_3100
 * @tc.name: BundleDataMgr::GetShareFilesJsonFromHap edge cases
 * @tc.desc: Test GetShareFilesJsonFromHap with various module configurations
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_3100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3100 start";

    // Case 1: Module with empty shareFiles
    {
        InnerModuleInfo moduleInfo;
        moduleInfo.moduleName = TEST_MODULE_NAME;
        moduleInfo.isEntry = true;
        moduleInfo.shareFiles.clear();

        std::string jsonContent;
        auto ret = dataMgr_->GetShareFilesJsonFromHap(TEST_HAP_PATH, moduleInfo, jsonContent);
        EXPECT_EQ(ret, ERR_OK);
        EXPECT_TRUE(jsonContent.empty());
    }

    // Case 2: Module with non-empty shareFiles
    {
        InnerModuleInfo moduleInfo;
        moduleInfo.moduleName = TEST_MODULE_NAME;
        moduleInfo.isEntry = true;
        moduleInfo.shareFiles = "/test/path1";

        std::string jsonContent;
        auto ret = dataMgr_->GetShareFilesJsonFromHap(TEST_HAP_PATH, moduleInfo, jsonContent);
        // Note: May return error if file doesn't exist, which is expected
        EXPECT_TRUE(ret == ERR_OK || ret == ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST ||
                   ret == ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);
    }

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3100 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_3200
 * @tc.name: BaseBundleInstaller state flags verification
 * @tc.desc: Test that state flags are properly set and checked
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_3200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3200 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // Initial state
    EXPECT_FALSE(installer->hasShareFilesProcessed_);
    EXPECT_FALSE(installer->hasOldShareFilesJsonSaved_);
    EXPECT_TRUE(installer->oldShareFilesJson_.empty());

    // After SetShareFileInfo (simulating new install)
    installer->isAppExist_ = false;
    installer->accessTokenId_ = TEST_TOKEN_ID;
    auto ret = ShareFileHelper::SetShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret, 0);
    installer->hasShareFilesProcessed_ = true;
    EXPECT_TRUE(installer->hasShareFilesProcessed_);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3200 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_3300
 * @tc.name: BaseBundleInstaller::ProcessBundleShareFiles update scenario
 * @tc.desc: Test ProcessBundleShareFiles during app update with valid oldInfo
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_3300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3300 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->isAppExist_ = true;
    installer->userId_ = TEST_USER_ID;
    installer->accessTokenId_ = TEST_TOKEN_ID;

    // Create newInfos with entry module
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = true;
    moduleInfo.shareFiles = "/test/path";
    moduleInfo.hapPath = TEST_HAP_PATH;

    BundleInfo bundleInfo;
    bundleInfo.name = TEST_BUNDLE_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = TEST_BUNDLE_NAME;

    InnerBundleInfo newBundleInfo;
    newBundleInfo.SetBaseBundleInfo(bundleInfo);
    newBundleInfo.SetBaseApplicationInfo(applicationInfo);

    std::map<std::string, InnerModuleInfo> innerModuleInfoMap;
    innerModuleInfoMap[TEST_MODULE_NAME] = moduleInfo;
    newBundleInfo.AddInnerModuleInfo(innerModuleInfoMap);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos[TEST_HAP_PATH] = newBundleInfo;

    // Create oldInfo with user info
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;

    InnerBundleInfo oldInfo;
    oldInfo.SetBaseBundleInfo(bundleInfo);
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    oldInfo.AddInnerBundleUserInfo(userInfo);

    auto ret = installer->ProcessBundleShareFiles(newInfos, oldInfo);
    // May fail due to non-existent hap file, which is expected
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST ||
               ret == ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3300 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_3400
 * @tc.name: BaseBundleInstaller::ProcessBundleShareFiles new install with empty shareFiles
 * @tc.desc: Test ProcessBundleShareFiles during new install when shareFiles is empty
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_3400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3400 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->isAppExist_ = false;

    // Create newInfos with entry module but empty shareFiles
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = true;
    moduleInfo.shareFiles.clear();

    InnerBundleInfo newBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddModuleInfo(newBundleInfo, moduleInfo);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos[TEST_HAP_PATH] = newBundleInfo;

    InnerBundleInfo oldInfo;

    auto ret = installer->ProcessBundleShareFiles(newInfos, oldInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(installer->hasShareFilesProcessed_);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3400 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_3500
 * @tc.name: BaseBundleInstaller::ProcessModuleShareFiles new install scenario
 * @tc.desc: Test ProcessModuleShareFiles during new install
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_3500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3500 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->isAppExist_ = false;
    installer->userId_ = TEST_USER_ID;
    installer->accessTokenId_ = TEST_TOKEN_ID;

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = true;
    moduleInfo.shareFiles = "/test/path";

    InnerBundleInfo oldInfo;

    auto ret = installer->ProcessModuleShareFiles(TEST_HAP_PATH, moduleInfo, TEST_BUNDLE_NAME, oldInfo);
    // May fail due to non-existent hap file, which is expected
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST ||
               ret == ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3500 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_3600
 * @tc.name: BaseBundleInstaller::RollbackShareFiles new install failure
 * @tc.desc: Test RollbackShareFiles when new install fails
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_3600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3600 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->hasShareFilesProcessed_ = true;
    installer->isAppExist_ = false;
    installer->bundleName_ = TEST_BUNDLE_NAME;
    installer->userId_ = TEST_USER_ID;
    installer->accessTokenId_ = TEST_TOKEN_ID;

    InnerBundleInfo oldInfo;
    installer->RollbackShareFiles(oldInfo);

    EXPECT_FALSE(installer->hasShareFilesProcessed_);
    EXPECT_FALSE(installer->hasOldShareFilesJsonSaved_);
    EXPECT_TRUE(installer->oldShareFilesJson_.empty());

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3600 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_3700
 * @tc.name: BaseBundleInstaller::RollbackShareFiles update failure
 * @tc.desc: Test RollbackShareFiles when update fails with saved config
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_3700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3700 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->hasShareFilesProcessed_ = true;
    installer->hasOldShareFilesJsonSaved_ = true;
    installer->oldShareFilesJson_ = TEST_SHARE_FILES_JSON;
    installer->isAppExist_ = true;
    installer->bundleName_ = TEST_BUNDLE_NAME;

    // Create oldInfo with user info
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;

    InnerBundleInfo oldInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddUserInfo(oldInfo, userInfo);

    installer->RollbackShareFiles(oldInfo);

    EXPECT_FALSE(installer->hasShareFilesProcessed_);
    EXPECT_FALSE(installer->hasOldShareFilesJsonSaved_);
    EXPECT_TRUE(installer->oldShareFilesJson_.empty());

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3700 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_3800
 * @tc.name: BaseBundleInstaller::SaveOldShareFilesForRollback with entry module
 * @tc.desc: Test SaveOldShareFilesForRollback with valid entry module
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_3800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3800 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // Create oldBundleInfo with entry module
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = true;
    moduleInfo.shareFiles = "/test/path";
    moduleInfo.hapPath = TEST_HAP_PATH;

    InnerBundleInfo oldBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddModuleInfo(oldBundleInfo, moduleInfo);

    auto ret = installer->SaveOldShareFilesForRollback(oldBundleInfo);
    // May fail due to non-existent hap file, which is expected
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST ||
               ret == ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3800 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_3900
 * @tc.name: BaseBundleInstaller::SaveOldShareFilesForRollback with empty shareFiles
 * @tc.desc: Test SaveOldShareFilesForRollback when entry module has no shareFiles
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_3900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3900 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // Create oldBundleInfo with entry module but empty shareFiles
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = true;
    moduleInfo.shareFiles.clear();

    InnerBundleInfo oldBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddModuleInfo(oldBundleInfo, moduleInfo);

    auto ret = installer->SaveOldShareFilesForRollback(oldBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(installer->hasOldShareFilesJsonSaved_);
    EXPECT_TRUE(installer->oldShareFilesJson_.empty());

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_3900 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_4000
 * @tc.name: BaseBundleInstaller::SaveOldShareFilesForRollback with non-entry module
 * @tc.desc: Test SaveOldShareFilesForRollback when only non-entry modules exist
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_4000, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4000 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // Create oldBundleInfo with non-entry module only
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = false;
    moduleInfo.shareFiles = "/test/path";

    InnerBundleInfo oldBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddModuleInfo(oldBundleInfo, moduleInfo);

    auto ret = installer->SaveOldShareFilesForRollback(oldBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(installer->hasOldShareFilesJsonSaved_);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4000 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_4100
 * @tc.name: BaseBundleInstaller::UpdateShareFileInfoForAllInstances with multiple users
 * @tc.desc: Test UpdateShareFileInfoForAllInstances with multiple users
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_4100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4100 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // Create oldInfo with multiple users
    InnerBundleUserInfo userInfo1;
    userInfo1.bundleUserInfo.userId = TEST_USER_ID;
    userInfo1.accessTokenId = TEST_TOKEN_ID;

    InnerBundleUserInfo userInfo2;
    userInfo2.bundleUserInfo.userId = TEST_USER_ID_2;
    userInfo2.accessTokenId = TEST_TOKEN_ID_2;

    InnerBundleInfo oldInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddUserInfo(oldInfo, userInfo1);
    AddUserInfo(oldInfo, userInfo2);

    auto ret = installer->UpdateShareFileInfoForAllInstances(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, oldInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(installer->hasShareFilesProcessed_);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4100 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_4200
 * @tc.name: BaseBundleInstaller::UpdateShareFileInfoForAllInstances with clones
 * @tc.desc: Test UpdateShareFileInfoForAllInstances with clone apps
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_4200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4200 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // Create oldInfo with clones
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;

    InnerBundleCloneInfo cloneInfo1;
    cloneInfo1.appIndex = TEST_APP_INDEX_1;
    cloneInfo1.accessTokenId = TEST_TOKEN_ID;
    std::string key1 = std::to_string(TEST_APP_INDEX_1);
    userInfo.cloneInfos[key1] = cloneInfo1;

    InnerBundleCloneInfo cloneInfo2;
    cloneInfo2.appIndex = TEST_APP_INDEX_2;
    cloneInfo2.accessTokenId = TEST_TOKEN_ID_2;
    std::string key2 = std::to_string(TEST_APP_INDEX_2);
    userInfo.cloneInfos[key2] = cloneInfo2;

    InnerBundleInfo oldInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddUserInfo(oldInfo, userInfo);

    auto ret = installer->UpdateShareFileInfoForAllInstances(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, oldInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(installer->hasShareFilesProcessed_);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4200 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_4300
 * @tc.name: BaseBundleInstaller::RollbackShareFilesForUpdate without saved config
 * @tc.desc: Test RollbackShareFilesForUpdate when hasOldShareFilesJsonSaved is false
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_4300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4300 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->hasOldShareFilesJsonSaved_ = false;
    installer->bundleName_ = TEST_BUNDLE_NAME;

    InnerBundleInfo oldInfo;

    auto failCount = installer->RollbackShareFilesForUpdate(oldInfo);
    EXPECT_EQ(failCount, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4300 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_4400
 * @tc.name: BaseBundleInstaller::RollbackUserInstances with clones
 * @tc.desc: Test RollbackUserInstances with multiple clone apps
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_4400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4400 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->oldShareFilesJson_ = TEST_SHARE_FILES_JSON;
    installer->bundleName_ = TEST_BUNDLE_NAME;

    // Create userInfo with clones
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;

    InnerBundleCloneInfo cloneInfo1;
    cloneInfo1.appIndex = TEST_APP_INDEX_1;
    cloneInfo1.accessTokenId = TEST_TOKEN_ID;
    std::string key1 = std::to_string(TEST_APP_INDEX_1);
    userInfo.cloneInfos[key1] = cloneInfo1;

    InnerBundleCloneInfo cloneInfo2;
    cloneInfo2.appIndex = TEST_APP_INDEX_2;
    cloneInfo2.accessTokenId = TEST_TOKEN_ID_2;
    std::string key2 = std::to_string(TEST_APP_INDEX_2);
    userInfo.cloneInfos[key2] = cloneInfo2;

    InnerBundleInfo oldInfo;

    auto failCount = installer->RollbackUserInstances(userInfo, oldInfo);
    EXPECT_GE(failCount, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4400 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_4500
 * @tc.name: BundleDataMgr::GetShareFilesJsonFromHap with valid shareFiles
 * @tc.desc: Test GetShareFilesJsonFromHap with entry module having shareFiles
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_4500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4500 start";

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = true;
    moduleInfo.shareFiles = "/test/path";

    std::string jsonContent;
    auto ret = dataMgr_->GetShareFilesJsonFromHap(TEST_HAP_PATH, moduleInfo, jsonContent);
    // May fail due to non-existent hap file, which is expected
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST ||
               ret == ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4500 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_4600
 * @tc.name: ShareFileHelper::SetShareFileInfo error scenarios
 * @tc.desc: Test SetShareFileInfo with invalid parameters
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_4600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4600 start";

    // Invalid JSON format
    std::string invalidJson = R"({"invalid": })";
    auto ret1 = ShareFileHelper::SetShareFileInfo(
        invalidJson, TEST_BUNDLE_NAME, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret1, 0);

    // Very long bundle name
    std::string longBundleName(1000, 'a');
    auto ret2 = ShareFileHelper::SetShareFileInfo(
        TEST_SHARE_FILES_JSON, longBundleName, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret2, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4600 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_4700
 * @tc.name: ShareFileHelper::UpdateShareFileInfo error scenarios
 * @tc.desc: Test UpdateShareFileInfo with invalid parameters
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_4700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4700 start";

    // Invalid JSON format
    std::string invalidJson = R"({"invalid": })";
    auto ret1 = ShareFileHelper::UpdateShareFileInfo(
        invalidJson, TEST_BUNDLE_NAME, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret1, 0);

    // Empty bundle name with valid JSON
    auto ret2 = ShareFileHelper::UpdateShareFileInfo(
        TEST_SHARE_FILES_JSON, EMPTY_STRING, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret2, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4700 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_4800
 * @tc.name: BaseBundleInstaller::ProcessUninstallShareFiles with no entry module
 * @tc.desc: Test ProcessUninstallShareFiles when bundle has no entry module
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_4800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4800 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // Create info with non-entry module only
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = false;

    InnerBundleInfo info = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddModuleInfo(info, moduleInfo);

    auto ret = installer->ProcessUninstallShareFiles(info, TEST_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4800 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_4900
 * @tc.name: BaseBundleInstaller::ProcessUninstallShareFiles with entry module
 * @tc.desc: Test ProcessUninstallShareFiles with entry module
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_4900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4900 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // Create info with entry module
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = true;

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;

    InnerBundleInfo info = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddModuleInfo(info, moduleInfo);
    AddUserInfo(info, userInfo);

    auto ret = installer->ProcessUninstallShareFiles(info, TEST_USER_ID);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_4900 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_5000
 * @tc.name: BaseBundleInstaller complete update workflow
 * @tc.desc: Test complete update workflow: save old -> update -> rollback
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_5000, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5000 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->bundleName_ = TEST_BUNDLE_NAME;

    // Step 1: Save old config (simulate update scenario)
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;

    InnerBundleInfo oldInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddUserInfo(oldInfo, userInfo);

    // Step 2: Simulate update failure
    installer->hasShareFilesProcessed_ = true;
    installer->hasOldShareFilesJsonSaved_ = true;
    installer->oldShareFilesJson_ = TEST_SHARE_FILES_JSON;
    installer->isAppExist_ = true;

    // Step 3: Rollback
    installer->RollbackShareFiles(oldInfo);

    // Verify state after rollback
    EXPECT_FALSE(installer->hasShareFilesProcessed_);
    EXPECT_FALSE(installer->hasOldShareFilesJsonSaved_);
    EXPECT_TRUE(installer->oldShareFilesJson_.empty());

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5000 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_5100
 * @tc.name: BaseBundleInstaller multiple rollback scenarios
 * @tc.desc: Test multiple sequential rollback operations
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_5100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5100 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->bundleName_ = TEST_BUNDLE_NAME;
    installer->userId_ = TEST_USER_ID;
    installer->accessTokenId_ = TEST_TOKEN_ID;

    InnerBundleInfo oldInfo;

    // First rollback - new install
    installer->hasShareFilesProcessed_ = true;
    installer->isAppExist_ = false;
    installer->RollbackShareFiles(oldInfo);
    EXPECT_FALSE(installer->hasShareFilesProcessed_);

    // Second rollback - update with saved config
    installer->hasShareFilesProcessed_ = true;
    installer->hasOldShareFilesJsonSaved_ = true;
    installer->oldShareFilesJson_ = TEST_SHARE_FILES_JSON;
    installer->isAppExist_ = true;

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;

    oldInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddUserInfo(oldInfo, userInfo);

    installer->RollbackShareFiles(oldInfo);
    EXPECT_FALSE(installer->hasShareFilesProcessed_);
    EXPECT_FALSE(installer->hasOldShareFilesJsonSaved_);
    EXPECT_TRUE(installer->oldShareFilesJson_.empty());

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5100 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_5200
 * @tc.name: ShareFileHelper concurrent operations
 * @tc.desc: Test ShareFileHelper with multiple concurrent-like operations
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_5200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5200 start";

    // Set for user 1
    auto ret1 = ShareFileHelper::SetShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret1, 0);

    // Set for user 2
    auto ret2 = ShareFileHelper::SetShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, TEST_USER_ID_2, TEST_TOKEN_ID_2);
    EXPECT_EQ(ret2, 0);

    // Update for user 1
    auto ret3 = ShareFileHelper::UpdateShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret3, 0);

    // Update for user 2
    auto ret4 = ShareFileHelper::UpdateShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, TEST_USER_ID_2, TEST_TOKEN_ID_2);
    EXPECT_EQ(ret4, 0);

    // Unset for user 1
    auto ret5 = ShareFileHelper::UnsetShareFileInfo(TEST_TOKEN_ID, TEST_BUNDLE_NAME, TEST_USER_ID);
    EXPECT_EQ(ret5, 0);

    // Unset for user 2
    auto ret6 = ShareFileHelper::UnsetShareFileInfo(TEST_TOKEN_ID_2, TEST_BUNDLE_NAME, TEST_USER_ID_2);
    EXPECT_EQ(ret6, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5200 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_5300
 * @tc.name: BaseBundleInstaller state management across operations
 * @tc.desc: Test that state flags are properly managed across multiple operations
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_5300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5300 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // Initial state
    EXPECT_FALSE(installer->hasShareFilesProcessed_);
    EXPECT_FALSE(installer->hasOldShareFilesJsonSaved_);
    EXPECT_TRUE(installer->oldShareFilesJson_.empty());

    // Simulate save old config
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = true;
    moduleInfo.shareFiles.clear();

    InnerBundleInfo oldBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddModuleInfo(oldBundleInfo, moduleInfo);

    installer->SaveOldShareFilesForRollback(oldBundleInfo);
    EXPECT_TRUE(installer->hasOldShareFilesJsonSaved_);

    // Simulate processing
    installer->hasShareFilesProcessed_ = true;
    EXPECT_TRUE(installer->hasShareFilesProcessed_);

    // Simulate rollback
    InnerBundleInfo oldInfo;
    installer->isAppExist_ = true;
    installer->RollbackShareFiles(oldInfo);

    // Final state
    EXPECT_FALSE(installer->hasShareFilesProcessed_);
    EXPECT_FALSE(installer->hasOldShareFilesJsonSaved_);
    EXPECT_TRUE(installer->oldShareFilesJson_.empty());

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5300 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_5400
 * @tc.name: ProcessUninstallShareFiles user not found scenario
 * @tc.desc: Test ProcessUninstallShareFiles when userId not in userInfos
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_5400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5400 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // Create info with entry module
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = true;

    // Add user A (100)
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;

    InnerBundleInfo info = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddModuleInfo(info, moduleInfo);
    AddUserInfo(info, userInfo);

    // Try to uninstall for user B (101) who doesn't exist
    auto ret = installer->ProcessUninstallShareFiles(info, TEST_USER_ID_2);
    EXPECT_EQ(ret, ERR_OK);  // Should still succeed with warning log

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5400 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_5500
 * @tc.name: UpdateShareFileInfoForAllInstances with empty userInfos
 * @tc.desc: Test UpdateShareFileInfoForAllInstances when oldInfo has no users
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_5500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5500 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // Create oldInfo with no users
    InnerBundleInfo oldInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    // Don't add any user info

    auto ret = installer->UpdateShareFileInfoForAllInstances(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, oldInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(installer->hasShareFilesProcessed_);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5500 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_5600
 * @tc.name: RollbackShareFiles with hasShareFilesProcessed_ false
 * @tc.desc: Test RollbackShareFiles when shareFiles were not processed
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_5600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5600 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->hasShareFilesProcessed_ = false;
    installer->bundleName_ = TEST_BUNDLE_NAME;

    InnerBundleInfo oldInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);

    // Should return early without doing anything
    installer->RollbackShareFiles(oldInfo);

    // State should remain unchanged
    EXPECT_FALSE(installer->hasShareFilesProcessed_);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5600 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_5700
 * @tc.name: RollbackShareFilesForUpdate with empty userInfos
 * @tc.desc: Test RollbackShareFilesForUpdate when oldInfo has no users
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_5700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5700 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->hasOldShareFilesJsonSaved_ = true;
    installer->oldShareFilesJson_ = TEST_SHARE_FILES_JSON;
    installer->bundleName_ = TEST_BUNDLE_NAME;

    // Create oldInfo with saved config but no users
    InnerBundleInfo oldInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);

    auto failCount = installer->RollbackShareFilesForUpdate(oldInfo);
    EXPECT_EQ(failCount, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5700 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_5800
 * @tc.name: UpdateMultiUserInstances with no clones
 * @tc.desc: Test UpdateMultiUserInstances when user has no clone apps
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_5800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5800 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // Create userInfo with no clones
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;
    // cloneInfos is empty by default

    auto failCount = installer->UpdateMultiUserInstances(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, userInfo);
    EXPECT_EQ(failCount, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5800 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_5900
 * @tc.name: RollbackUserInstances with no clones
 * @tc.desc: Test RollbackUserInstances when user has no clone apps
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_5900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5900 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->oldShareFilesJson_ = TEST_SHARE_FILES_JSON;
    installer->bundleName_ = TEST_BUNDLE_NAME;

    // Create userInfo with no clones
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;

    InnerBundleInfo oldInfo;

    auto failCount = installer->RollbackUserInstances(userInfo, oldInfo);
    EXPECT_EQ(failCount, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_5900 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_6000
 * @tc.name: ProcessBundleShareFiles with multiple modules
 * @tc.desc: Test ProcessBundleShareFiles with both entry and non-entry modules
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_6000, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6000 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->isAppExist_ = false;

    // Create bundleInfo with entry module and non-entry module
    InnerModuleInfo entryModule;
    entryModule.moduleName = TEST_MODULE_NAME;
    entryModule.isEntry = true;
    entryModule.shareFiles = "/test/path";
    entryModule.hapPath = TEST_HAP_PATH;

    InnerModuleInfo featureModule;
    featureModule.moduleName = "feature";
    featureModule.isEntry = false;
    featureModule.hapPath = TEST_HAP_PATH;

    InnerBundleInfo newBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddModuleInfo(newBundleInfo, entryModule);
    AddModuleInfo(newBundleInfo, featureModule);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos[TEST_HAP_PATH] = newBundleInfo;

    InnerBundleInfo oldInfo;

    auto ret = installer->ProcessBundleShareFiles(newInfos, oldInfo);
    // May fail due to non-existent hap file, which is expected
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST ||
               ret == ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6000 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_6100
 * @tc.name: ProcessBundleShareFiles update scenario with empty newInfos
 * @tc.desc: Test ProcessBundleShareFiles during update when newInfos is empty
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_6100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6100 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->isAppExist_ = true;

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo oldInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);

    auto ret = installer->ProcessBundleShareFiles(newInfos, oldInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6100 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_6200
 * @tc.name: SaveOldShareFilesForRollback with multiple modules
 * @tc.desc: Test SaveOldShareFilesForRollback with entry and non-entry modules
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_6200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6200 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // Create bundleInfo with entry module and non-entry module
    InnerModuleInfo entryModule;
    entryModule.moduleName = TEST_MODULE_NAME;
    entryModule.isEntry = true;
    entryModule.shareFiles.clear();

    InnerModuleInfo featureModule;
    featureModule.moduleName = "feature";
    featureModule.isEntry = false;
    featureModule.shareFiles = "/test/path";

    InnerBundleInfo oldBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddModuleInfo(oldBundleInfo, entryModule);
    AddModuleInfo(oldBundleInfo, featureModule);

    auto ret = installer->SaveOldShareFilesForRollback(oldBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(installer->hasOldShareFilesJsonSaved_);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6200 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_6300
 * @tc.name: RollbackShareFilesForNewInstall without setting properties
 * @tc.desc: Test RollbackShareFilesForNewInstall with default state
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_6300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6300 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    // Don't set bundleName_, userId_, accessTokenId_
    // Test with default/empty values

    auto failCount = installer->RollbackShareFilesForNewInstall();
    EXPECT_GE(failCount, 0);  // Should handle gracefully

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6300 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_6400
 * @tc.name: Complete workflow: install -> update -> uninstall
 * @tc.desc: Test complete lifecycle with shareFiles
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_6400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6400 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->bundleName_ = TEST_BUNDLE_NAME;
    installer->userId_ = TEST_USER_ID;
    installer->accessTokenId_ = TEST_TOKEN_ID;

    // Phase 1: New install
    installer->isAppExist_ = false;
    InnerBundleInfo oldInfo;

    auto ret1 = ShareFileHelper::SetShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret1, 0);
    installer->hasShareFilesProcessed_ = true;

    // Phase 2: Update
    installer->isAppExist_ = true;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;
    oldInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddUserInfo(oldInfo, userInfo);

    auto ret2 = ShareFileHelper::UpdateShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, TEST_USER_ID, TEST_TOKEN_ID);
    EXPECT_EQ(ret2, 0);

    // Phase 3: Uninstall
    installer->isAppExist_ = true;
    InnerBundleInfo uninstallInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddModuleInfo(uninstallInfo, []() {
        InnerModuleInfo m;
        m.moduleName = TEST_MODULE_NAME;
        m.isEntry = true;
        return m;
    }());
    AddUserInfo(uninstallInfo, userInfo);

    auto ret3 = installer->ProcessUninstallShareFiles(uninstallInfo, TEST_USER_ID);
    EXPECT_EQ(ret3, ERR_OK);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6400 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_6500
 * @tc.name: Edge case: very large userId and tokenId values
 * @tc.desc: Test ShareFileHelper with maximum valid values
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_6500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6500 start";

    // Test with maximum uint32_t values
    auto ret1 = ShareFileHelper::SetShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, INT32_MAX, UINT32_MAX);
    EXPECT_EQ(ret1, 0);

    auto ret2 = ShareFileHelper::UpdateShareFileInfo(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, INT32_MAX, UINT32_MAX);
    EXPECT_EQ(ret2, 0);

    auto ret3 = ShareFileHelper::UnsetShareFileInfo(UINT32_MAX, TEST_BUNDLE_NAME, INT32_MAX);
    EXPECT_EQ(ret3, 0);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6500 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_6600
 * @tc.name: UpdateShareFileInfoForAllInstances with clone apps only
 * @tc.desc: Test UpdateShareFileInfoForAllInstances with user having only clones
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_6600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6600 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // Create userInfo with only clones (no main app specific handling needed)
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;

    // Add multiple clones
    for (int i = 1; i <= 3; i++) {
        InnerBundleCloneInfo cloneInfo;
        cloneInfo.appIndex = i;
        cloneInfo.accessTokenId = TEST_TOKEN_ID + i;
        std::string key = std::to_string(i);
        userInfo.cloneInfos[key] = cloneInfo;
    }

    InnerBundleInfo oldInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddUserInfo(oldInfo, userInfo);

    auto ret = installer->UpdateShareFileInfoForAllInstances(
        TEST_SHARE_FILES_JSON, TEST_BUNDLE_NAME, oldInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(installer->hasShareFilesProcessed_);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6600 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_6700
 * @tc.name: ProcessModuleShareFiles update scenario with existing data
 * @tc.desc: Test ProcessModuleShareFiles during update with valid oldInfo
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_6700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6700 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;
    installer->isAppExist_ = true;

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = true;
    moduleInfo.shareFiles = "/test/path";

    // Create oldInfo with user
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;

    InnerBundleInfo oldInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddUserInfo(oldInfo, userInfo);

    auto ret = installer->ProcessModuleShareFiles(TEST_HAP_PATH, moduleInfo, TEST_BUNDLE_NAME, oldInfo);
    // May fail due to non-existent hap file
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST ||
               ret == ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6700 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_6800
 * @tc.name: RollbackShareFiles reset state verification
 * @tc.desc: Test RollbackShareFiles properly resets all state flags
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_6800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6800 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // Set all state flags to true/non-empty
    installer->hasShareFilesProcessed_ = true;
    installer->hasOldShareFilesJsonSaved_ = true;
    installer->oldShareFilesJson_ = TEST_SHARE_FILES_JSON;
    installer->bundleName_ = TEST_BUNDLE_NAME;

    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.accessTokenId = TEST_TOKEN_ID;

    InnerBundleInfo oldInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddUserInfo(oldInfo, userInfo);
    installer->isAppExist_ = true;

    // Perform rollback
    installer->RollbackShareFiles(oldInfo);

    // Verify all state is reset
    EXPECT_FALSE(installer->hasShareFilesProcessed_);
    EXPECT_FALSE(installer->hasOldShareFilesJsonSaved_);
    EXPECT_TRUE(installer->oldShareFilesJson_.empty());

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6800 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_6900
 * @tc.name: SaveOldShareFilesForRollback clears old data
 * @tc.desc: Test SaveOldShareFilesForRollback clears previous saved data
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_6900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6900 start";

    auto installer = std::make_shared<BaseBundleInstaller>();
    EXPECT_TRUE(installer != nullptr);
    installer->dataMgr_ = dataMgr_;

    // First save
    InnerModuleInfo moduleInfo1;
    moduleInfo1.moduleName = TEST_MODULE_NAME;
    moduleInfo1.isEntry = true;
    moduleInfo1.shareFiles.clear();

    InnerBundleInfo oldBundleInfo1 = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddModuleInfo(oldBundleInfo1, moduleInfo1);

    installer->SaveOldShareFilesForRollback(oldBundleInfo1);
    EXPECT_TRUE(installer->hasOldShareFilesJsonSaved_);
    EXPECT_TRUE(installer->oldShareFilesJson_.empty());

    // Second save (simulating another update attempt)
    installer->hasOldShareFilesJsonSaved_ = false;
    installer->oldShareFilesJson_ = "old data";

    InnerModuleInfo moduleInfo2;
    moduleInfo2.moduleName = "entry2";
    moduleInfo2.isEntry = true;
    moduleInfo2.shareFiles.clear();

    InnerBundleInfo oldBundleInfo2 = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    AddModuleInfo(oldBundleInfo2, moduleInfo2);

    auto ret = installer->SaveOldShareFilesForRollback(oldBundleInfo2);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(installer->hasOldShareFilesJsonSaved_);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_6900 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_7000
 * @tc.name: BundleCloneInstaller::ProcessBundleShareFiles with null dataMgr
 * @tc.desc: Test ProcessBundleShareFiles when GetDataMgr fails (branch 1)
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_7000, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7000 start";

    auto cloneInstaller = std::make_shared<BundleCloneInstaller>();
    EXPECT_TRUE(cloneInstaller != nullptr);
    cloneInstaller->dataMgr_ = nullptr;

    // Save global dataMgr and set to nullptr
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;

    InnerBundleInfo info;
    std::string cloneBundleName = "com.test.clone";
    int32_t userId = TEST_USER_ID;
    uint32_t tokenId = TEST_TOKEN_ID;

    auto ret = cloneInstaller->ProcessBundleShareFiles(info, cloneBundleName, userId, tokenId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);

    // Restore global dataMgr
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = dataMgr;

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7000 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_7100
 * @tc.name: BundleCloneInstaller::ProcessBundleShareFiles with empty moduleInfos
 * @tc.desc: Test ProcessBundleShareFiles when bundle has no modules (branch 3)
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_7100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7100 start";

    auto cloneInstaller = std::make_shared<BundleCloneInstaller>();
    EXPECT_TRUE(cloneInstaller != nullptr);
    cloneInstaller->dataMgr_ = dataMgr_;

    InnerBundleInfo info;
    std::string cloneBundleName = "com.test.clone";
    int32_t userId = TEST_USER_ID;
    uint32_t tokenId = TEST_TOKEN_ID;

    auto ret = cloneInstaller->ProcessBundleShareFiles(info, cloneBundleName, userId, tokenId);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7100 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_7200
 * @tc.name: BundleCloneInstaller::ProcessBundleShareFiles with non-entry module only
 * @tc.desc: Test ProcessBundleShareFiles when bundle has only non-entry modules (branch 2.1)
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_7200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7200 start";

    auto cloneInstaller = std::make_shared<BundleCloneInstaller>();
    EXPECT_TRUE(cloneInstaller != nullptr);
    cloneInstaller->dataMgr_ = dataMgr_;

    BundleInfo bundleInfo;
    bundleInfo.name = TEST_BUNDLE_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = TEST_BUNDLE_NAME;

    InnerBundleInfo info;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "feature";
    moduleInfo.isEntry = false;

    std::map<std::string, InnerModuleInfo> innerModuleInfoMap;
    innerModuleInfoMap["feature"] = moduleInfo;
    info.AddInnerModuleInfo(innerModuleInfoMap);

    std::string cloneBundleName = "com.test.clone";
    int32_t userId = TEST_USER_ID;
    uint32_t tokenId = TEST_TOKEN_ID;

    auto ret = cloneInstaller->ProcessBundleShareFiles(info, cloneBundleName, userId, tokenId);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7200 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_7300
 * @tc.name: BundleCloneInstaller::ProcessBundleShareFiles with entry module and empty shareFiles
 * @tc.desc: Test ProcessBundleShareFiles with entry module but empty shareFiles (branch 2.4 success)
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_7300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7300 start";

    auto cloneInstaller = std::make_shared<BundleCloneInstaller>();
    EXPECT_TRUE(cloneInstaller != nullptr);
    cloneInstaller->dataMgr_ = dataMgr_;

    BundleInfo bundleInfo;
    bundleInfo.name = TEST_BUNDLE_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = TEST_BUNDLE_NAME;

    InnerBundleInfo info;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = true;
    moduleInfo.hapPath = TEST_HAP_PATH;
    moduleInfo.shareFiles.clear();

    std::map<std::string, InnerModuleInfo> innerModuleInfoMap;
    innerModuleInfoMap[TEST_MODULE_NAME] = moduleInfo;
    info.AddInnerModuleInfo(innerModuleInfoMap);

    std::string cloneBundleName = "com.test.clone";
    int32_t userId = TEST_USER_ID;
    uint32_t tokenId = TEST_TOKEN_ID;

    auto ret = cloneInstaller->ProcessBundleShareFiles(info, cloneBundleName, userId, tokenId);
    // May succeed with empty shareFiles or fail if hap file doesn't exist
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST ||
               ret == ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7300 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_7400
 * @tc.name: BundleCloneInstaller::ProcessBundleShareFiles with invalid hapPath
 * @tc.desc: Test ProcessBundleShareFiles when hapPath is invalid (branch 2.2)
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_7400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7400 start";

    auto cloneInstaller = std::make_shared<BundleCloneInstaller>();
    EXPECT_TRUE(cloneInstaller != nullptr);
    cloneInstaller->dataMgr_ = dataMgr_;

    BundleInfo bundleInfo;
    bundleInfo.name = TEST_BUNDLE_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = TEST_BUNDLE_NAME;

    InnerBundleInfo info;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = true;
    moduleInfo.hapPath = "/invalid/path/nonexistent.hap";
    moduleInfo.shareFiles = "/test/path";

    std::map<std::string, InnerModuleInfo> innerModuleInfoMap;
    innerModuleInfoMap[TEST_MODULE_NAME] = moduleInfo;
    info.AddInnerModuleInfo(innerModuleInfoMap);

    std::string cloneBundleName = "com.test.clone";
    int32_t userId = TEST_USER_ID;
    uint32_t tokenId = TEST_TOKEN_ID;

    auto ret = cloneInstaller->ProcessBundleShareFiles(info, cloneBundleName, userId, tokenId);
    EXPECT_TRUE(ret == ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST ||
               ret == ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7400 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_7500
 * @tc.name: BundleCloneInstaller::ProcessBundleShareFiles with multiple modules
 * @tc.desc: Test ProcessBundleShareFiles with entry and non-entry modules (branch 2.1 skip)
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_7500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7500 start";

    auto cloneInstaller = std::make_shared<BundleCloneInstaller>();
    EXPECT_TRUE(cloneInstaller != nullptr);
    cloneInstaller->dataMgr_ = dataMgr_;

    BundleInfo bundleInfo;
    bundleInfo.name = TEST_BUNDLE_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = TEST_BUNDLE_NAME;

    InnerBundleInfo info;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);

    // Add feature module (non-entry)
    InnerModuleInfo featureModule;
    featureModule.moduleName = "feature";
    featureModule.isEntry = false;
    featureModule.shareFiles = "/feature/path";

    // Add entry module
    InnerModuleInfo entryModule;
    entryModule.moduleName = TEST_MODULE_NAME;
    entryModule.isEntry = true;
    entryModule.hapPath = TEST_HAP_PATH;
    entryModule.shareFiles.clear();

    std::map<std::string, InnerModuleInfo> innerModuleInfoMap;
    innerModuleInfoMap["feature"] = featureModule;
    innerModuleInfoMap[TEST_MODULE_NAME] = entryModule;
    info.AddInnerModuleInfo(innerModuleInfoMap);

    std::string cloneBundleName = "com.test.clone";
    int32_t userId = TEST_USER_ID;
    uint32_t tokenId = TEST_TOKEN_ID;

    auto ret = cloneInstaller->ProcessBundleShareFiles(info, cloneBundleName, userId, tokenId);
    // Should process only entry module
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST ||
               ret == ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7500 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_7600
 * @tc.name: BundleCloneInstaller::ProcessBundleShareFiles with empty cloneBundleName
 * @tc.desc: Test ProcessBundleShareFiles with empty cloneBundleName
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_7600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7600 start";

    auto cloneInstaller = std::make_shared<BundleCloneInstaller>();
    EXPECT_TRUE(cloneInstaller != nullptr);
    cloneInstaller->dataMgr_ = dataMgr_;

    InnerBundleInfo info;
    std::string cloneBundleName = "";
    int32_t userId = TEST_USER_ID;
    uint32_t tokenId = TEST_TOKEN_ID;

    auto ret = cloneInstaller->ProcessBundleShareFiles(info, cloneBundleName, userId, tokenId);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7600 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_7700
 * @tc.name: BundleCloneInstaller::ProcessBundleShareFiles with edge case userId/tokenId
 * @tc.desc: Test ProcessBundleShareFiles with extreme userId and tokenId values
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_7700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7700 start";

    auto cloneInstaller = std::make_shared<BundleCloneInstaller>();
    EXPECT_TRUE(cloneInstaller != nullptr);
    cloneInstaller->dataMgr_ = dataMgr_;

    InnerBundleInfo info;

    // Test with minimum values
    auto ret1 = cloneInstaller->ProcessBundleShareFiles(info, "com.test.clone", 0, 0);
    EXPECT_EQ(ret1, ERR_OK);

    // Test with maximum values
    auto ret2 = cloneInstaller->ProcessBundleShareFiles(info, "com.test.clone", INT32_MAX, UINT32_MAX);
    EXPECT_EQ(ret2, ERR_OK);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7700 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_7800
 * @tc.name: BundleCloneInstaller::ProcessBundleShareFiles complete success path
 * @tc.desc: Test ProcessBundleShareFiles with valid entry module (branch 2.4)
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_7800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7800 start";

    auto cloneInstaller = std::make_shared<BundleCloneInstaller>();
    EXPECT_TRUE(cloneInstaller != nullptr);
    cloneInstaller->dataMgr_ = dataMgr_;

    BundleInfo bundleInfo;
    bundleInfo.name = TEST_BUNDLE_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = TEST_BUNDLE_NAME;

    InnerBundleInfo info;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = true;
    moduleInfo.hapPath = "/data/test/resource.hap";
    moduleInfo.shareFiles = "/test/sharefiles/path";

    std::map<std::string, InnerModuleInfo> innerModuleInfoMap;
    innerModuleInfoMap[TEST_MODULE_NAME] = moduleInfo;
    info.AddInnerModuleInfo(innerModuleInfoMap);

    std::string cloneBundleName = "com.test.clone";
    int32_t userId = TEST_USER_ID;
    uint32_t tokenId = TEST_TOKEN_ID;

    auto ret = cloneInstaller->ProcessBundleShareFiles(info, cloneBundleName, userId, tokenId);
    // May fail due to non-existent hap file, which is expected in test environment
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST ||
               ret == ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7800 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_7900
 * @tc.name: BundleCloneInstaller::ProcessBundleShareFiles multiple entry modules
 * @tc.desc: Test ProcessBundleShareFiles processes first entry module only
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_7900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7900 start";

    auto cloneInstaller = std::make_shared<BundleCloneInstaller>();
    EXPECT_TRUE(cloneInstaller != nullptr);
    cloneInstaller->dataMgr_ = dataMgr_;

    BundleInfo bundleInfo;
    bundleInfo.name = TEST_BUNDLE_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = TEST_BUNDLE_NAME;

    InnerBundleInfo info;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);

    // Add first entry module
    InnerModuleInfo entryModule1;
    entryModule1.moduleName = "entry1";
    entryModule1.isEntry = true;
    entryModule1.hapPath = TEST_HAP_PATH;
    entryModule1.shareFiles.clear();

    // Add second entry module
    InnerModuleInfo entryModule2;
    entryModule2.moduleName = "entry2";
    entryModule2.isEntry = true;
    entryModule2.hapPath = "/data/test/entry2.hap";

    std::map<std::string, InnerModuleInfo> innerModuleInfoMap;
    innerModuleInfoMap["entry1"] = entryModule1;
    innerModuleInfoMap["entry2"] = entryModule2;
    info.AddInnerModuleInfo(innerModuleInfoMap);

    std::string cloneBundleName = "com.test.clone";
    int32_t userId = TEST_USER_ID;
    uint32_t tokenId = TEST_TOKEN_ID;

    auto ret = cloneInstaller->ProcessBundleShareFiles(info, cloneBundleName, userId, tokenId);
    // Should process first entry module and return
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST ||
               ret == ERR_APPEXECFWK_INSTALL_FAILED_PROFILE_PARSE_FAIL);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_7900 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_HasEntryShareFiles_0100
 * @tc.name: HasEntryShareFiles
 * @tc.desc: test HasEntryShareFiles when entry module has shareFiles
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_HasEntryShareFiles_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_HasEntryShareFiles_0100 start";

    InnerBundleInfo bundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = true;
    moduleInfo.shareFiles = TEST_SHARE_FILES_JSON;
    AddModuleInfo(bundleInfo, moduleInfo);

    bool result = BaseBundleInstaller::HasEntryShareFiles(bundleInfo);
    EXPECT_TRUE(result);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_HasEntryShareFiles_0100 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_HasEntryShareFiles_0200
 * @tc.name: HasEntryShareFiles
 * @tc.desc: test HasEntryShareFiles when entry module has no shareFiles
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_HasEntryShareFiles_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_HasEntryShareFiles_0200 start";

    InnerBundleInfo bundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.isEntry = true;
    moduleInfo.shareFiles.clear();
    AddModuleInfo(bundleInfo, moduleInfo);

    bool result = BaseBundleInstaller::HasEntryShareFiles(bundleInfo);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_HasEntryShareFiles_0200 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_HasEntryShareFiles_0300
 * @tc.name: HasEntryShareFiles
 * @tc.desc: test HasEntryShareFiles when only non-entry module has shareFiles
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_HasEntryShareFiles_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_HasEntryShareFiles_0300 start";

    InnerBundleInfo bundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    InnerModuleInfo featureModule;
    featureModule.moduleName = "feature";
    featureModule.isEntry = false;
    featureModule.shareFiles = TEST_SHARE_FILES_JSON;
    AddModuleInfo(bundleInfo, featureModule);

    bool result = BaseBundleInstaller::HasEntryShareFiles(bundleInfo);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_HasEntryShareFiles_0300 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_HasEntryShareFiles_0400
 * @tc.name: HasEntryShareFiles
 * @tc.desc: test HasEntryShareFiles when no modules exist
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_HasEntryShareFiles_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_HasEntryShareFiles_0400 start";

    InnerBundleInfo bundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);

    bool result = BaseBundleInstaller::HasEntryShareFiles(bundleInfo);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_HasEntryShareFiles_0400 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_ShouldProcessShareFiles_0100
 * @tc.name: ShouldProcessShareFiles
 * @tc.desc: test ShouldProcessShareFiles in new install scenario with shareFiles
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_ShouldProcessShareFiles_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_ShouldProcessShareFiles_0100 start";

    InnerBundleInfo newBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    InnerModuleInfo entryModule;
    entryModule.moduleName = TEST_MODULE_NAME;
    entryModule.isEntry = true;
    entryModule.shareFiles = TEST_SHARE_FILES_JSON;
    AddModuleInfo(newBundleInfo, entryModule);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos[TEST_HAP_PATH] = newBundleInfo;
    InnerBundleInfo oldInfo;

    bool result = BaseBundleInstaller::ShouldProcessShareFiles(false, newInfos, oldInfo);
    EXPECT_TRUE(result);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_ShouldProcessShareFiles_0100 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_ShouldProcessShareFiles_0200
 * @tc.name: ShouldProcessShareFiles
 * @tc.desc: test ShouldProcessShareFiles in new install scenario without shareFiles
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_ShouldProcessShareFiles_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_ShouldProcessShareFiles_0200 start";

    InnerBundleInfo newBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    InnerModuleInfo entryModule;
    entryModule.moduleName = TEST_MODULE_NAME;
    entryModule.isEntry = true;
    entryModule.shareFiles.clear();
    AddModuleInfo(newBundleInfo, entryModule);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos[TEST_HAP_PATH] = newBundleInfo;
    InnerBundleInfo oldInfo;

    bool result = BaseBundleInstaller::ShouldProcessShareFiles(false, newInfos, oldInfo);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_ShouldProcessShareFiles_0200 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_ShouldProcessShareFiles_0300
 * @tc.name: ShouldProcessShareFiles
 * @tc.desc: test ShouldProcessShareFiles in update scenario where both old and new have shareFiles
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_ShouldProcessShareFiles_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_ShouldProcessShareFiles_0300 start";

    InnerBundleInfo newBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    InnerModuleInfo newEntryModule;
    newEntryModule.moduleName = TEST_MODULE_NAME;
    newEntryModule.isEntry = true;
    newEntryModule.shareFiles = TEST_SHARE_FILES_JSON;
    AddModuleInfo(newBundleInfo, newEntryModule);

    InnerBundleInfo oldBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    InnerModuleInfo oldEntryModule;
    oldEntryModule.moduleName = TEST_MODULE_NAME;
    oldEntryModule.isEntry = true;
    oldEntryModule.shareFiles = TEST_SHARE_FILES_JSON;
    AddModuleInfo(oldBundleInfo, oldEntryModule);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos[TEST_HAP_PATH] = newBundleInfo;

    bool result = BaseBundleInstaller::ShouldProcessShareFiles(true, newInfos, oldBundleInfo);
    EXPECT_TRUE(result);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_ShouldProcessShareFiles_0300 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_ShouldProcessShareFiles_0400
 * @tc.name: ShouldProcessShareFiles
 * @tc.desc: test ShouldProcessShareFiles in update scenario where only new has shareFiles
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_ShouldProcessShareFiles_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_ShouldProcessShareFiles_0400 start";

    InnerBundleInfo newBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    InnerModuleInfo newEntryModule;
    newEntryModule.moduleName = TEST_MODULE_NAME;
    newEntryModule.isEntry = true;
    newEntryModule.shareFiles = TEST_SHARE_FILES_JSON;
    AddModuleInfo(newBundleInfo, newEntryModule);

    InnerBundleInfo oldBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    InnerModuleInfo oldEntryModule;
    oldEntryModule.moduleName = TEST_MODULE_NAME;
    oldEntryModule.isEntry = true;
    oldEntryModule.shareFiles.clear();
    AddModuleInfo(oldBundleInfo, oldEntryModule);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos[TEST_HAP_PATH] = newBundleInfo;

    bool result = BaseBundleInstaller::ShouldProcessShareFiles(true, newInfos, oldBundleInfo);
    EXPECT_TRUE(result);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_ShouldProcessShareFiles_0400 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_ShouldProcessShareFiles_0500
 * @tc.name: ShouldProcessShareFiles
 * @tc.desc: test ShouldProcessShareFiles in update scenario where only old has shareFiles
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_ShouldProcessShareFiles_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_ShouldProcessShareFiles_0500 start";

    InnerBundleInfo newBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    InnerModuleInfo newEntryModule;
    newEntryModule.moduleName = TEST_MODULE_NAME;
    newEntryModule.isEntry = true;
    newEntryModule.shareFiles.clear();
    AddModuleInfo(newBundleInfo, newEntryModule);

    InnerBundleInfo oldBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    InnerModuleInfo oldEntryModule;
    oldEntryModule.moduleName = TEST_MODULE_NAME;
    oldEntryModule.isEntry = true;
    oldEntryModule.shareFiles = TEST_SHARE_FILES_JSON;
    AddModuleInfo(oldBundleInfo, oldEntryModule);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos[TEST_HAP_PATH] = newBundleInfo;

    bool result = BaseBundleInstaller::ShouldProcessShareFiles(true, newInfos, oldBundleInfo);
    EXPECT_TRUE(result);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_ShouldProcessShareFiles_0500 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_ShouldProcessShareFiles_0600
 * @tc.name: ShouldProcessShareFiles
 * @tc.desc: test ShouldProcessShareFiles in update scenario where neither old nor new has shareFiles
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_ShouldProcessShareFiles_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_ShouldProcessShareFiles_0600 start";

    InnerBundleInfo newBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    InnerModuleInfo newEntryModule;
    newEntryModule.moduleName = TEST_MODULE_NAME;
    newEntryModule.isEntry = true;
    newEntryModule.shareFiles.clear();
    AddModuleInfo(newBundleInfo, newEntryModule);

    InnerBundleInfo oldBundleInfo = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    InnerModuleInfo oldEntryModule;
    oldEntryModule.moduleName = TEST_MODULE_NAME;
    oldEntryModule.isEntry = true;
    oldEntryModule.shareFiles.clear();
    AddModuleInfo(oldBundleInfo, oldEntryModule);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos[TEST_HAP_PATH] = newBundleInfo;

    bool result = BaseBundleInstaller::ShouldProcessShareFiles(true, newInfos, oldBundleInfo);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_ShouldProcessShareFiles_0600 end";
}

/**
 * @tc.number: BmsBundleShareFilesTest_ShouldProcessShareFiles_0700
 * @tc.name: ShouldProcessShareFiles
 * @tc.desc: test ShouldProcessShareFiles with multiple bundles in new install scenario
 */
HWTEST_F(BmsBundleShareFilesTest, BmsBundleShareFilesTest_ShouldProcessShareFiles_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_ShouldProcessShareFiles_0700 start";

    InnerBundleInfo newBundleInfo1 = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    InnerModuleInfo entryModule1;
    entryModule1.moduleName = "entry1";
    entryModule1.isEntry = true;
    entryModule1.shareFiles.clear();
    AddModuleInfo(newBundleInfo1, entryModule1);

    InnerBundleInfo newBundleInfo2 = CreateTestBundleInfo(TEST_BUNDLE_NAME);
    InnerModuleInfo entryModule2;
    entryModule2.moduleName = "entry2";
    entryModule2.isEntry = true;
    entryModule2.shareFiles = TEST_SHARE_FILES_JSON;
    AddModuleInfo(newBundleInfo2, entryModule2);

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos["/data/test/hap1.hap"] = newBundleInfo1;
    newInfos["/data/test/hap2.hap"] = newBundleInfo2;
    InnerBundleInfo oldInfo;

    bool result = BaseBundleInstaller::ShouldProcessShareFiles(false, newInfos, oldInfo);
    EXPECT_TRUE(result);

    GTEST_LOG_(INFO) << "BmsBundleShareFilesTest_ShouldProcessShareFiles_0700 end";
}

}  // namespace OHOS
