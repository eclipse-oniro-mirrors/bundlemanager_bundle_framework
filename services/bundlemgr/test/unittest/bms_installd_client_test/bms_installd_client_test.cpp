/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "installd_client.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string BUNDLE_DIR = "bundleDir";
const std::string SRC_MODULE_PATH = "srcModulePath";
const std::string TARGET_PATH = "targetPath";
const std::string TARGET_SO_PATH = "targetSoPath";
const std::string CPU_ABI = "cpuAbi";
const std::string SRC_PATH = "srcPath";
const std::string OLD_PATH = "oldPath";
const std::string NEW_PATH = "newPath";
const std::string BUNDLE_NAME = "bundleName";
const std::string APL = "apl";
const std::string MODULE_NAME = "ModuleName";
const std::string DIR = "dir";
const std::string FILE = "file";
const std::string FILE_PATH = "filePath";
const std::string OLD_SO_PATH = "oldSoPath";
const std::string DIFF_FILE_PATH = "diffFilePath";
const std::string NEW_SO_PATH = "newSoPath";
const std::string SOURCE_DIR = "sourceDir";
const std::string DESTINATION_DIR = "destinationDir";
const int32_t USERID = 100;
const int32_t UID = 1000;
const int32_t GID = 1000;
const std::string EMPTY_STRING = "";
}  // namespace

class BmsInstalldClientTest : public testing::Test {
public:
    BmsInstalldClientTest();
    ~BmsInstalldClientTest();
    std::shared_ptr<InstalldClient> installClient_ = nullptr;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsInstalldClientTest::BmsInstalldClientTest()
{}

BmsInstalldClientTest::~BmsInstalldClientTest()
{}

void BmsInstalldClientTest::SetUpTestCase()
{}

void BmsInstalldClientTest::TearDownTestCase()
{}

void BmsInstalldClientTest::SetUp()
{
    installClient_ = std::make_shared<InstalldClient>();
}

void BmsInstalldClientTest::TearDown()
{}

/**
 * @tc.number: BmsInstalldClientTest_CreateBundleDir_0100
 * @tc.name: CreateBundleDir
 * @tc.desc: Test whether CreateBundleDir is called normally.(bundleDir is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_CreateBundleDir_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CreateBundleDir_0100 start";
    std::string bundleDir = EMPTY_STRING;
    ErrCode result = installClient_->CreateBundleDir(bundleDir);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CreateBundleDir_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_CreateBundleDir_0200
 * @tc.name: CreateBundleDir
 * @tc.desc: Test whether CreateBundleDir is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_CreateBundleDir_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CreateBundleDir_0200 start";
    std::string bundleDir = BUNDLE_DIR;
    ErrCode result = installClient_->CreateBundleDir(bundleDir);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::CreateBundleDir, bundleDir));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CreateBundleDir_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ExtractModuleFiles_0100
 * @tc.name: ExtractModuleFiles
 * @tc.desc: Test whether ExtractModuleFiles is called normally.(srcModulePath is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ExtractModuleFiles_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractModuleFiles_0100 start";
    std::string srcModulePath = EMPTY_STRING;
    std::string targetPath = TARGET_PATH;
    std::string targetSoPath = TARGET_SO_PATH;
    std::string cpuAbi = CPU_ABI;
    ErrCode result = installClient_->ExtractModuleFiles(srcModulePath, targetPath, targetSoPath, cpuAbi);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractModuleFiles_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ExtractModuleFiles_0200
 * @tc.name: ExtractModuleFiles
 * @tc.desc: Test whether init is called normally.(targetPath is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ExtractModuleFiles_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractModuleFiles_0200 start";
    std::string srcModulePath = SRC_MODULE_PATH;
    std::string targetPath = EMPTY_STRING;
    std::string targetSoPath = TARGET_SO_PATH;
    std::string cpuAbi = CPU_ABI;
    ErrCode result = installClient_->ExtractModuleFiles(srcModulePath, targetPath, targetSoPath, cpuAbi);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractModuleFiles_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ExtractModuleFiles_0300
 * @tc.name: ExtractModuleFiles
 * @tc.desc: Test whether ExtractModuleFiles is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ExtractModuleFiles_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractModuleFiles_0300 start";
    std::string srcModulePath = SRC_MODULE_PATH;
    std::string targetPath = TARGET_PATH;
    std::string targetSoPath = TARGET_SO_PATH;
    std::string cpuAbi = CPU_ABI;
    ErrCode result = installClient_->ExtractModuleFiles(srcModulePath, targetPath, targetSoPath, cpuAbi);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::ExtractModuleFiles,
    srcModulePath, targetPath, targetSoPath, cpuAbi));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractModuleFiles_0300 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ExtractFiles_0100
 * @tc.name: ExtractFiles
 * @tc.desc: Test whether ExtractFiles is called normally.(extractParam.srcPath is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ExtractFiles_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractFiles_0100 start";
    ExtractParam extractParam;
    extractParam.srcPath = EMPTY_STRING;
    extractParam.targetPath = TARGET_PATH;
    ErrCode result = installClient_->ExtractFiles(extractParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractFiles_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ExtractFiles_0200
 * @tc.name: ExtractFiles
 * @tc.desc: Test whether ExtractFiles is called normally.(extractParam.targetPath is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ExtractFiles_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractFiles_0200 start";
    ExtractParam extractParam;
    extractParam.srcPath = SRC_PATH;
    extractParam.targetPath = EMPTY_STRING;
    ErrCode result = installClient_->ExtractFiles(extractParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractFiles_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ExtractFiles_0300
 * @tc.name: ExtractFiles
 * @tc.desc: Test whether ExtractFiles is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ExtractFiles_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractFiles_0300 start";
    ExtractParam extractParam;
    extractParam.srcPath = SRC_PATH;
    extractParam.targetPath = TARGET_PATH;
    ErrCode result = installClient_->ExtractFiles(extractParam);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::ExtractFiles, extractParam));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractFiles_0300 end";
}

/**
 * @tc.number: BmsInstalldClientTest_RenameModuleDir_0100
 * @tc.name: RenameModuleDir
 * @tc.desc: Test whether RenameModuleDir is called normally.(oldPath is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_RenameModuleDir_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RenameModuleDir_0100 start";
    std::string oldPath = EMPTY_STRING;
    std::string newPath = NEW_PATH;
    ErrCode result = installClient_->RenameModuleDir(oldPath, newPath);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RenameModuleDir_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_RenameModuleDir_0200
 * @tc.name: RenameModuleDir
 * @tc.desc: Test whether RenameModuleDir is called normally.(newPath is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_RenameModuleDir_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RenameModuleDir_0200 start";
    std::string oldPath = OLD_PATH;
    std::string newPath = EMPTY_STRING;
    ErrCode result = installClient_->RenameModuleDir(oldPath, newPath);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RenameModuleDir_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_RenameModuleDir_0300
 * @tc.name: RenameModuleDir
 * @tc.desc: Test whether RenameModuleDir is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_RenameModuleDir_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RenameModuleDir_0300 start";
    std::string oldPath = OLD_PATH;
    std::string newPath = NEW_PATH;
    ErrCode result = installClient_->RenameModuleDir(oldPath, newPath);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::RenameModuleDir, oldPath, newPath));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RenameModuleDir_0300 end";
}

/**
 * @tc.number: BmsInstalldClientTest_CreateBundleDataDir_0100
 * @tc.name: CreateBundleDataDir
 * @tc.desc: Test whether CreateBundleDataDir is called normally.(bundleName is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_CreateBundleDataDir_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CreateBundleDataDir_0100 start";
    CreateDirParam createDirParam;
    createDirParam.bundleName = EMPTY_STRING;
    createDirParam.userId = USERID;
    createDirParam.uid = UID;
    createDirParam.gid = GID;
    createDirParam.apl = APL;
    createDirParam.isPreInstallApp = false;
    ErrCode result = installClient_->CreateBundleDataDir(createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CreateBundleDataDir_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_CreateBundleDataDir_0200
 * @tc.name: CreateBundleDataDir
 * @tc.desc: Test whether CreateBundleDataDir is called normally.(userid < 0)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_CreateBundleDataDir_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CreateBundleDataDir_0200 start";
    CreateDirParam createDirParam;
    createDirParam.bundleName = BUNDLE_NAME;
    createDirParam.userId = -1;
    createDirParam.uid = UID;
    createDirParam.gid = GID;
    createDirParam.apl = APL;
    createDirParam.isPreInstallApp = false;
    ErrCode result = installClient_->CreateBundleDataDir(createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CreateBundleDataDir_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_CreateBundleDataDir_0300
 * @tc.name: CreateBundleDataDir
 * @tc.desc: Test whether CreateBundleDataDir is called normally.(uid < 0)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_CreateBundleDataDir_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CreateBundleDataDir_0300 start";
    CreateDirParam createDirParam;
    createDirParam.bundleName = BUNDLE_NAME;
    createDirParam.userId = USERID;
    createDirParam.uid = -1;
    createDirParam.gid = GID;
    createDirParam.apl = APL;
    createDirParam.isPreInstallApp = false;
    ErrCode result = installClient_->CreateBundleDataDir(createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CreateBundleDataDir_0300 end";
}

/**
 * @tc.number: BmsInstalldClientTest_CreateBundleDataDir_0400
 * @tc.name: CreateBundleDataDir
 * @tc.desc: Test whether CreateBundleDataDir is called normally.(gid < 0)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_CreateBundleDataDir_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CreateBundleDataDir_0400 start";
    CreateDirParam createDirParam;
    createDirParam.bundleName = BUNDLE_NAME;
    createDirParam.userId = USERID;
    createDirParam.uid = UID;
    createDirParam.gid = -1;
    createDirParam.apl = APL;
    createDirParam.isPreInstallApp = false;
    ErrCode result = installClient_->CreateBundleDataDir(createDirParam);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CreateBundleDataDir_0400 end";
}

/**
 * @tc.number: BmsInstalldClientTest_CreateBundleDataDir_0500
 * @tc.name: CreateBundleDataDir
 * @tc.desc: Test whether CreateBundleDataDir is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_CreateBundleDataDir_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CreateBundleDataDir_0500 start";
    CreateDirParam createDirParam;
    createDirParam.bundleName = BUNDLE_NAME;
    createDirParam.userId = USERID;
    createDirParam.uid = UID;
    createDirParam.gid = GID;
    createDirParam.apl = APL;
    createDirParam.isPreInstallApp = false;
    ErrCode result = installClient_->CreateBundleDataDir(createDirParam);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::CreateBundleDataDir, createDirParam));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CreateBundleDataDir_0500 end";
}

/**
 * @tc.number: BmsInstalldClientTest_RemoveBundleDataDir_0100
 * @tc.name: RemoveBundleDataDir
 * @tc.desc: Test whether RemoveBundleDataDir is called normally.(bundleName is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_RemoveBundleDataDir_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveBundleDataDir_0100 start";
    std::string bundleName = EMPTY_STRING;
    int userid = USERID;
    ErrCode result = installClient_->RemoveBundleDataDir(bundleName, userid);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveBundleDataDir_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_RemoveBundleDataDir_0200
 * @tc.name: RemoveBundleDataDir
 * @tc.desc: Test whether RemoveBundleDataDir is called normally.(userid < 0)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_RemoveBundleDataDir_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveBundleDataDir_0200 start";
    std::string bundleName = BUNDLE_NAME;
    int userid = -1;
    ErrCode result = installClient_->RemoveBundleDataDir(bundleName, userid);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveBundleDataDir_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_RemoveBundleDataDir_0300
 * @tc.name: RemoveBundleDataDir
 * @tc.desc: Test whether RemoveBundleDataDir is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_RemoveBundleDataDir_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveBundleDataDir_0300 start";
    std::string bundleName = BUNDLE_NAME;
    int userid = USERID;
    ErrCode result = installClient_->RemoveBundleDataDir(bundleName, userid);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::RemoveBundleDataDir, bundleName, userid));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveBundleDataDir_0300 end";
}

/**
 * @tc.number: BmsInstalldClientTest_RemoveModuleDataDir_0100
 * @tc.name: RemoveModuleDataDir
 * @tc.desc: Test whether RemoveModuleDataDir is called normally.(ModuleName is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_RemoveModuleDataDir_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveModuleDataDir_0100 start";
    std::string ModuleName = EMPTY_STRING;
    int userid = USERID;
    ErrCode result = installClient_->RemoveModuleDataDir(ModuleName, userid);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveModuleDataDir_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_RemoveModuleDataDir_0200
 * @tc.name: RemoveModuleDataDir
 * @tc.desc: Test whether RemoveModuleDataDir is called normally.(userid < 0)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_RemoveModuleDataDir_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveModuleDataDir_0200 start";
    std::string ModuleName = MODULE_NAME;
    int userid = -1;
    ErrCode result = installClient_->RemoveModuleDataDir(ModuleName, userid);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveModuleDataDir_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_RemoveModuleDataDir_0300
 * @tc.name: RemoveModuleDataDir
 * @tc.desc: Test whether RemoveModuleDataDir is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_RemoveModuleDataDir_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveModuleDataDir_0300 start";
    std::string ModuleName = MODULE_NAME;
    int userid = USERID;
    ErrCode result = installClient_->RemoveModuleDataDir(ModuleName, userid);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::RemoveModuleDataDir, ModuleName, userid));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveModuleDataDir_0300 end";
}

/**
 * @tc.number: BmsInstalldClientTest_RemoveDir_0100
 * @tc.name: RemoveDir
 * @tc.desc: Test whether RemoveDir is called normally.(dir is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_RemoveDir_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveDir_0100 start";
    std::string dir = EMPTY_STRING;
    ErrCode result = installClient_->RemoveDir(dir);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveDir_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_RemoveDir_0200
 * @tc.name: RemoveDir
 * @tc.desc: Test whether RemoveDir is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_RemoveDir_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveDir_0200 start";
    std::string dir = DIR;
    ErrCode result = installClient_->RemoveDir(dir);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::RemoveDir, dir));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_RemoveDir_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_CleanBundleDataDir_0100
 * @tc.name: CleanBundleDataDir
 * @tc.desc: Test whether CleanBundleDataDir is called normally.(bundleDir is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_CleanBundleDataDir_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CleanBundleDataDir_0100 start";
    std::string bundleDir = EMPTY_STRING;
    ErrCode result = installClient_->CleanBundleDataDir(bundleDir);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CleanBundleDataDir_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_CleanBundleDataDir_0200
 * @tc.name: CleanBundleDataDir
 * @tc.desc: Test whether CleanBundleDataDir is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_CleanBundleDataDir_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CleanBundleDataDir_0200 start";
    std::string bundleDir = BUNDLE_DIR;
    ErrCode result = installClient_->CleanBundleDataDir(bundleDir);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::CleanBundleDataDir, bundleDir));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CleanBundleDataDir_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_GetBundleStats_0100
 * @tc.name: GetBundleStats
 * @tc.desc: Test whether GetBundleStats is called normally.(bundleName is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_GetBundleStats_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_GetBundleStats_0100 start";
    std::string bundleName = EMPTY_STRING;
    int userId = USERID;
    std::vector<int64_t> bundleStats;
    ErrCode result = installClient_->GetBundleStats(bundleName, userId, bundleStats, 0);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_GetBundleStats_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_GetBundleStats_0200
 * @tc.name: GetBundleStats
 * @tc.desc: Test whether GetBundleStats is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_GetBundleStats_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_GetBundleStats_0200 start";
    std::string bundleName = BUNDLE_NAME;
    int userId = USERID;
    std::vector<int64_t> bundleStats;
    ErrCode result = installClient_->GetBundleStats(bundleName, userId, bundleStats, 0);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::GetBundleStats, bundleName, userId, bundleStats, 0));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_GetBundleStats_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_SetDirApl_0100
 * @tc.name: SetDirApl
 * @tc.desc: Test whether SetDirApl is called normally.(dir is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_SetDirApl_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_SetDirApl_0100 start";
    std::string dir = EMPTY_STRING;
    std::string bundleName = BUNDLE_NAME;
    std::string apl = APL;
    ErrCode result = installClient_->SetDirApl(dir, bundleName, apl, false, false);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_SetDirApl_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_SetDirApl_0200
 * @tc.name: SetDirApl
 * @tc.desc: Test whether SetDirApl is called normally.(bundleName is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_SetDirApl_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_SetDirApl_0200 start";
    std::string dir = DIR;
    std::string bundleName = EMPTY_STRING;
    std::string apl = APL;
    ErrCode result = installClient_->SetDirApl(dir, bundleName, apl, true, false);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_SetDirApl_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_SetDirApl_0300
 * @tc.name: SetDirApl
 * @tc.desc: Test whether SetDirApl is called normally.(apl is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_SetDirApl_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_SetDirApl_0300 start";
    std::string dir = DIR;
    std::string bundleName = BUNDLE_NAME;
    std::string apl = EMPTY_STRING;
    ErrCode result = installClient_->SetDirApl(dir, bundleName, apl, false, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_SetDirApl_0300 end";
}

/**
 * @tc.number: BmsInstalldClientTest_SetDirApl_0400
 * @tc.name: SetDirApl
 * @tc.desc: Test whether SetDirApl is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_SetDirApl_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_SetDirApl_0400 start";
    std::string dir = DIR;
    std::string bundleName = BUNDLE_NAME;
    std::string apl = APL;
    ErrCode result = installClient_->SetDirApl(dir, bundleName, apl, true, false);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::SetDirApl, dir, bundleName, apl, true, false));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_SetDirApl_0400 end";
}

/**
 * @tc.number: BmsInstalldClientTest_GetBundleCachePath_0100
 * @tc.name: GetBundleCachePath
 * @tc.desc: Test whether GetBundleCachePath is called normally.(dir is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_GetBundleCachePath_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_GetBundleCachePath_0100 start";
    std::string dir = EMPTY_STRING;
    std::vector<std::string> cachePath;
    ErrCode result = installClient_->GetBundleCachePath(dir, cachePath);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_GetBundleCachePath_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_GetBundleCachePath_0200
 * @tc.name: GetBundleCachePath
 * @tc.desc: Test whether GetBundleCachePath is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_GetBundleCachePath_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_GetBundleCachePath_0200 start";
    std::string dir = DIR;
    std::vector<std::string> cachePath;
    ErrCode result = installClient_->GetBundleCachePath(dir, cachePath);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::GetBundleCachePath, dir, cachePath));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_GetBundleCachePath_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ResetInstalldProxy_0100
 * @tc.name: ResetInstalldProxy
 * @tc.desc: Test whether ResetInstalldProxy is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ResetInstalldProxy_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ResetInstalldProxy_0100 start";
    installClient_->ResetInstalldProxy();
    EXPECT_EQ(installClient_->installdProxy_, nullptr);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ResetInstalldProxy_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ScanDir_0100
 * @tc.name: ScanDir
 * @tc.desc: Test whether ScanDir is called normally.(dir is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ScanDir_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ScanDir_0100 start";
    std::string dir = EMPTY_STRING;
    std::vector<std::string> paths;
    ErrCode result = installClient_->ScanDir(dir, ScanMode::SUB_FILE_ALL, ResultMode::ABSOLUTE_PATH, paths);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ScanDir_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ScanDir_0200
 * @tc.name: ScanDir
 * @tc.desc: Test whether ScanDir is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ScanDir_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ScanDir_0200 start";
    std::string dir = DIR;
    std::vector<std::string> paths;
    ErrCode result = installClient_->ScanDir(dir, ScanMode::SUB_FILE_ALL, ResultMode::ABSOLUTE_PATH, paths);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::ScanDir,
    dir, ScanMode::SUB_FILE_ALL, ResultMode::ABSOLUTE_PATH, paths));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ScanDir_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_MoveFile_0100
 * @tc.name: MoveFile
 * @tc.desc: Test whether MoveFile is called normally.(oldPath is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_MoveFile_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_MoveFile_0100 start";
    std::string oldPath = EMPTY_STRING;
    std::string newPath = NEW_PATH;
    ErrCode result = installClient_->MoveFile(oldPath, newPath);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_MoveFile_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_MoveFile_0200
 * @tc.name: MoveFile
 * @tc.desc: Test whether MoveFile is called normally.(newPath is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_MoveFile_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_MoveFile_0200 start";
    std::string oldPath = OLD_PATH;
    std::string newPath = EMPTY_STRING;
    ErrCode result = installClient_->MoveFile(oldPath, newPath);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_MoveFile_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_MoveFile_0300
 * @tc.name: MoveFile
 * @tc.desc: Test whether MoveFile is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_MoveFile_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_MoveFile_0300 start";
    std::string oldPath = OLD_PATH;
    std::string newPath = NEW_PATH;
    ErrCode result = installClient_->MoveFile(oldPath, newPath);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::MoveFile, oldPath, newPath));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_MoveFile_0300 end";
}

/**
 * @tc.number: BmsInstalldClientTest_CopyFile_0100
 * @tc.name: CopyFile
 * @tc.desc: Test whether CopyFile is called normally.(oldPath is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_CopyFile_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CopyFile_0100 start";
    std::string oldPath = EMPTY_STRING;
    std::string newPath = NEW_PATH;
    ErrCode result = installClient_->CopyFile(oldPath, newPath);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CopyFile_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_CopyFile_0200
 * @tc.name: CopyFile
 * @tc.desc: Test whether CopyFile is called normally.(newPath is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_CopyFile_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CopyFile_0200 start";
    std::string oldPath = OLD_PATH;
    std::string newPath = EMPTY_STRING;
    ErrCode result = installClient_->CopyFile(oldPath, newPath);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CopyFile_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_CopyFile_0300
 * @tc.name: CopyFile
 * @tc.desc: Test whether CopyFile is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_CopyFile_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CopyFile_0300 start";
    std::string oldPath = OLD_PATH;
    std::string newPath = NEW_PATH;
    ErrCode result = installClient_->CopyFile(oldPath, newPath);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::CopyFile, oldPath, newPath, ""));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CopyFile_0300 end";
}

/**
 * @tc.number: BmsInstalldClientTest_Mkdir_0100
 * @tc.name: Mkdir
 * @tc.desc: Test whether Mkdir is called normally.(dir is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_Mkdir_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_Mkdir_0100 start";
    std::string dir = EMPTY_STRING;
    int32_t mode = 1;
    int32_t uid = UID;
    int32_t gid = GID;
    ErrCode result = installClient_->Mkdir(dir, mode, uid, gid);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_Mkdir_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_Mkdir_0200
 * @tc.name: Mkdir
 * @tc.desc: Test whether Mkdir is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_Mkdir_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_Mkdir_0200 start";
    std::string dir = DIR;
    int32_t mode = 1;
    int32_t uid = UID;
    int32_t gid = GID;
    ErrCode result = installClient_->Mkdir(dir, mode, uid, gid);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::Mkdir, dir, mode, uid, gid));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_Mkdir_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_GetFileStat_0100
 * @tc.name: GetFileStat
 * @tc.desc: Test whether GetFileStat is called normally.(file is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_GetFileStat_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_GetFileStat_0100 start";
    std::string file = EMPTY_STRING;
    FileStat fileStat;
    ErrCode result = installClient_->GetFileStat(file, fileStat);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_GetFileStat_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_GetFileStat_0200
 * @tc.name: GetFileStat
 * @tc.desc: Test whether GetFileStat is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_GetFileStat_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_GetFileStat_0200 start";
    std::string file = FILE;
    FileStat fileStat;
    ErrCode result = installClient_->GetFileStat(file, fileStat);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::GetFileStat, file, fileStat));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_GetFileStat_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ExtractDiffFiles_0100
 * @tc.name: ExtractDiffFiles
 * @tc.desc: Test whether ExtractDiffFiles is called normally.(filePath is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ExtractDiffFiles_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractDiffFiles_0100 start";
    std::string filePath = EMPTY_STRING;
    std::string targetPath = TARGET_PATH;
    std::string cpuAbi = CPU_ABI;
    ErrCode result = installClient_->ExtractDiffFiles(filePath, targetPath, cpuAbi);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractDiffFiles_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ExtractDiffFiles_0200
 * @tc.name: ExtractDiffFiles
 * @tc.desc: Test whether ExtractDiffFiles is called normally.(targetPath is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ExtractDiffFiles_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractDiffFiles_0200 start";
    std::string filePath = FILE_PATH;
    std::string targetPath = EMPTY_STRING;
    std::string cpuAbi = CPU_ABI;
    ErrCode result = installClient_->ExtractDiffFiles(filePath, targetPath, cpuAbi);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractDiffFiles_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ExtractDiffFiles_0300
 * @tc.name: ExtractDiffFiles
 * @tc.desc: Test whether ExtractDiffFiles is called normally.(cpuAbi is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ExtractDiffFiles_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractDiffFiles_0300 start";
    std::string filePath = FILE_PATH;
    std::string targetPath = TARGET_PATH;
    std::string cpuAbi = EMPTY_STRING;
    ErrCode result = installClient_->ExtractDiffFiles(filePath, targetPath, cpuAbi);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractDiffFiles_0300 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ExtractDiffFiles_0400
 * @tc.name: ExtractDiffFiles
 * @tc.desc: Test whether ExtractDiffFiles is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ExtractDiffFiles_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractDiffFiles_0400 start";
    std::string filePath = FILE_PATH;
    std::string targetPath = TARGET_PATH;
    std::string cpuAbi = CPU_ABI;
    ErrCode result = installClient_->ExtractDiffFiles(filePath, targetPath, cpuAbi);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::ExtractDiffFiles, filePath, targetPath, cpuAbi));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ExtractDiffFiles_0400 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ApplyDiffPatch_0100
 * @tc.name: ApplyDiffPatch
 * @tc.desc: Test whether ApplyDiffPatch is called normally.(oldSoPath is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ApplyDiffPatch_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ApplyDiffPatch_0100 start";
    std::string oldSoPath = EMPTY_STRING;
    std::string diffFilePath = DIFF_FILE_PATH;
    std::string newSoPath = NEW_SO_PATH;
    ErrCode result = installClient_->ApplyDiffPatch(oldSoPath, diffFilePath, newSoPath, 0);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ApplyDiffPatch_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ApplyDiffPatch_0200
 * @tc.name: ApplyDiffPatch
 * @tc.desc: Test whether ApplyDiffPatch is called normally.(diffFilePath is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ApplyDiffPatch_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ApplyDiffPatch_0200 start";
    std::string oldSoPath = OLD_SO_PATH;
    std::string diffFilePath = EMPTY_STRING;
    std::string newSoPath = NEW_SO_PATH;
    ErrCode result = installClient_->ApplyDiffPatch(oldSoPath, diffFilePath, newSoPath, 0);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ApplyDiffPatch_0200 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ApplyDiffPatch_0300
 * @tc.name: ApplyDiffPatch
 * @tc.desc: Test whether ApplyDiffPatch is called normally.(newSoPath is empty)
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ApplyDiffPatch_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ApplyDiffPatch_0300 start";
    std::string oldSoPath = OLD_SO_PATH;
    std::string diffFilePath = DIFF_FILE_PATH;
    std::string newSoPath = EMPTY_STRING;
    ErrCode result = installClient_->ApplyDiffPatch(oldSoPath, diffFilePath, newSoPath, 0);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ApplyDiffPatch_0300 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ApplyDiffPatch_0400
 * @tc.name: ApplyDiffPatch
 * @tc.desc: Test whether ApplyDiffPatch is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ApplyDiffPatch_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ApplyDiffPatch_0400 start";
    std::string oldSoPath = OLD_SO_PATH;
    std::string diffFilePath = DIFF_FILE_PATH;
    std::string newSoPath = NEW_SO_PATH;
    ErrCode result = installClient_->ApplyDiffPatch(oldSoPath, diffFilePath, newSoPath);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::ApplyDiffPatch, oldSoPath, diffFilePath, newSoPath, 0));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ApplyDiffPatch_0400 end";
}

/**
 * @tc.number: BmsInstalldClientTest_IsExistDir_0100
 * @tc.name: IsExistDir
 * @tc.desc: Test whether IsExistDir is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_IsExistDir_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_IsExistDir_0100 start";
    std::string dir = DIR;
    bool isExist = true;
    ErrCode result = installClient_->IsExistDir(dir, isExist);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::IsExistDir, dir, isExist));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_IsExistDir_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_IsDirEmpty_0100
 * @tc.name: IsDirEmpty
 * @tc.desc: Test whether IsDirEmpty is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_IsDirEmpty_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_IsDirEmpty_0100 start";
    std::string dir = DIR;
    bool isDirEmpty = true;
    ErrCode result = installClient_->IsDirEmpty(dir, isDirEmpty);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::IsDirEmpty, dir, isDirEmpty));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_IsDirEmpty_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_ObtainQuickFixFileDir_0100
 * @tc.name: ObtainQuickFixFileDir
 * @tc.desc: Test whether ObtainQuickFixFileDir is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_ObtainQuickFixFileDir_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ObtainQuickFixFileDir_0100 start";
    std::string dir = DIR;
    std::vector<std::string> dirVec ;
    ErrCode result = installClient_->ObtainQuickFixFileDir(dir, dirVec);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::ObtainQuickFixFileDir, dir, dirVec));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_ObtainQuickFixFileDir_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_CopyFiles_0100
 * @tc.name: CopyFiles
 * @tc.desc: Test whether CopyFiles is called normally.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_CopyFiles_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CopyFiles_0100 start";
    std::string sourceDir = SOURCE_DIR;
    std::string destinationDir = DESTINATION_DIR;
    ErrCode result = installClient_->CopyFiles(sourceDir, destinationDir);
    EXPECT_EQ(result, installClient_->CallService(&IInstalld::CopyFiles, sourceDir, destinationDir));
    GTEST_LOG_(INFO) << "BmsInstalldClientTest_CopyFiles_0100 end";
}

/**
 * @tc.number: BmsInstalldClientTest_SetEncryptionPolicy_0100
 * @tc.name: SetEncryptionPolicy
 * @tc.desc: call SetEncryptionPolicy.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_SetEncryptionPolicy_0100, TestSize.Level1)
{
    std::string keyId = "";
    ErrCode result = installClient_->SetEncryptionPolicy(0, "", 100, keyId);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: BmsInstalldClientTest_DeleteEncryptionKeyId_0100
 * @tc.name: DeleteEncryptionKeyId
 * @tc.desc: call DeleteEncryptionKeyId.
 */
HWTEST_F(BmsInstalldClientTest, BmsInstalldClientTest_DeleteEncryptionKeyId_0100, TestSize.Level1)
{
    ErrCode result = installClient_->DeleteEncryptionKeyId("");
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}
} // namespace AppExecFwk
} // namespace OHOS
