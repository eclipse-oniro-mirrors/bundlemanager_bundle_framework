/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <sstream>
#include <string>

#include "bundle_mgr_service.h"
#include "installd_host.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
}  // namespace

class BmsInstalldHostTest : public testing::Test {
public:
    BmsInstalldHostTest();
    ~BmsInstalldHostTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsInstalldHostTest::BmsInstalldHostTest()
{}

BmsInstalldHostTest::~BmsInstalldHostTest()
{}

void BmsInstalldHostTest::SetUpTestCase()
{}

void BmsInstalldHostTest::TearDownTestCase()
{
}

void BmsInstalldHostTest::SetUp()
{}

void BmsInstalldHostTest::TearDown()
{}

/**
 * @tc.number: HandleCreateBundleDir
 * @tc.name: test HandleCreateBundleDir
 * @tc.desc: 1.HandleCreateBundleDir test
 */
HWTEST_F(BmsInstalldHostTest, HandleCreateBundleDir_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleCreateBundleDir(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleExtractModuleFiles_0100
 * @tc.name: test HandleExtractModuleFiles
 * @tc.desc: 1.HandleExtractModuleFiles test
 */
HWTEST_F(BmsInstalldHostTest, HandleExtractModuleFiles_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleExtractModuleFiles(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleExtractFiles_0100
 * @tc.name: test HandleExtractFiles
 * @tc.desc: 1.HandleExtractFiles test
 */
HWTEST_F(BmsInstalldHostTest, HandleExtractFiles_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleExtractFiles(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleExecuteAOT_0100
 * @tc.name: test HandleExecuteAOT
 * @tc.desc: 1.HandleExecuteAOT test
 */
HWTEST_F(BmsInstalldHostTest, HandleExecuteAOT_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleExecuteAOT(data, reply);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: HandleRenameModuleDir_0100
 * @tc.name: test HandleRenameModuleDir
 * @tc.desc: 1.HandleRenameModuleDir test
 */
HWTEST_F(BmsInstalldHostTest, HandleRenameModuleDir_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleRenameModuleDir(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleCreateBundleDataDir_0100
 * @tc.name: test HandleCreateBundleDataDir
 * @tc.desc: 1.HandleCreateBundleDataDir test
 */
HWTEST_F(BmsInstalldHostTest, HandleCreateBundleDataDir_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleCreateBundleDataDir(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleCreateBundleDataDirWithVector_0100
 * @tc.name: test HandleCreateBundleDataDirWithVector
 * @tc.desc: 1.HandleCreateBundleDataDirWithVector test
 */
HWTEST_F(BmsInstalldHostTest, HandleCreateBundleDataDirWithVector_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleCreateBundleDataDirWithVector(data, reply);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: HandleRemoveBundleDataDir_0100
 * @tc.name: test HandleRemoveBundleDataDir
 * @tc.desc: 1.HandleRemoveBundleDataDir test
 */
HWTEST_F(BmsInstalldHostTest, HandleRemoveBundleDataDir_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleRemoveBundleDataDir(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleRemoveModuleDataDir_0100
 * @tc.name: test HandleRemoveModuleDataDir
 * @tc.desc: 1.HandleRemoveModuleDataDir test
 */
HWTEST_F(BmsInstalldHostTest, HandleRemoveModuleDataDir_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleRemoveModuleDataDir(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleRemoveDir_0100
 * @tc.name: test HandleRemoveDir
 * @tc.desc: 1.HandleRemoveDir test
 */
HWTEST_F(BmsInstalldHostTest, HandleRemoveDir_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleRemoveDir(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleCleanBundleDataDir_0100
 * @tc.name: test HandleCleanBundleDataDir
 * @tc.desc: 1.HandleCleanBundleDataDir test
 */
HWTEST_F(BmsInstalldHostTest, HandleCleanBundleDataDir_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleCleanBundleDataDir(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleCleanBundleDataDirByName_0100
 * @tc.name: test HandleCleanBundleDataDirByName
 * @tc.desc: 1.HandleCleanBundleDataDirByName test
 */
HWTEST_F(BmsInstalldHostTest, HandleCleanBundleDataDirByName_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleCleanBundleDataDirByName(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleGetBundleStats_0100
 * @tc.name: test HandleGetBundleStats
 * @tc.desc: 1.HandleGetBundleStats test
 */
HWTEST_F(BmsInstalldHostTest, HandleGetBundleStats_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleGetBundleStats(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleGetAllBundleStats_0100
 * @tc.name: test HandleGetAllBundleStats
 * @tc.desc: 1.HandleGetAllBundleStats test
 */
HWTEST_F(BmsInstalldHostTest, HandleGetAllBundleStats_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleGetAllBundleStats(data, reply);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: HandleSetDirApl_0100
 * @tc.name: test HandleSetDirApl
 * @tc.desc: 1.HandleSetDirApl test
 */
HWTEST_F(BmsInstalldHostTest, HandleSetDirApl_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleSetDirApl(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleGetBundleCachePath_0100
 * @tc.name: test HandleGetBundleCachePath
 * @tc.desc: 1.HandleGetBundleCachePath test
 */
HWTEST_F(BmsInstalldHostTest, HandleGetBundleCachePath_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleGetBundleCachePath(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleScanDir_0100
 * @tc.name: test HandleScanDir
 * @tc.desc: 1.HandleScanDir test
 */
HWTEST_F(BmsInstalldHostTest, HandleScanDir_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleScanDir(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleMoveFile_0100
 * @tc.name: test HandleMoveFile
 * @tc.desc: 1.HandleMoveFile test
 */
HWTEST_F(BmsInstalldHostTest, HandleMoveFile_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleMoveFile(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleCopyFile_0100
 * @tc.name: test HandleCopyFile
 * @tc.desc: 1.HandleCopyFile test
 */
HWTEST_F(BmsInstalldHostTest, HandleCopyFile_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleCopyFile(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleMkdir_0100
 * @tc.name: test HandleMkdir
 * @tc.desc: 1.HandleMkdir test
 */
HWTEST_F(BmsInstalldHostTest, HandleMkdir_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleMkdir(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleGetFileStat_0100
 * @tc.name: test HandleGetFileStat
 * @tc.desc: 1.HandleGetFileStat test
 */
HWTEST_F(BmsInstalldHostTest, HandleGetFileStat_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleGetFileStat(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleExtractDiffFiles_0100
 * @tc.name: test HandleExtractDiffFiles
 * @tc.desc: 1.HandleExtractDiffFiles test
 */
HWTEST_F(BmsInstalldHostTest, HandleExtractDiffFiles_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleExtractDiffFiles(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleApplyDiffPatch_0100
 * @tc.name: test HandleApplyDiffPatch
 * @tc.desc: 1.HandleApplyDiffPatch test
 */
HWTEST_F(BmsInstalldHostTest, HandleApplyDiffPatch_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleApplyDiffPatch(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleIsExistDir_0100
 * @tc.name: test HandleIsExistDir
 * @tc.desc: 1.HandleIsExistDir test
 */
HWTEST_F(BmsInstalldHostTest, HandleIsExistDir_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleIsExistDir(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleIsExistFile_0100
 * @tc.name: test HandleIsExistFile
 * @tc.desc: 1.HandleIsExistFile test
 */
HWTEST_F(BmsInstalldHostTest, HandleIsExistFile_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleIsExistFile(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleIsExistApFile_0100
 * @tc.name: test HandleIsExistApFile
 * @tc.desc: 1.HandleIsExistApFile test
 */
HWTEST_F(BmsInstalldHostTest, HandleIsExistApFile_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleIsExistApFile(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleIsDirEmpty_0100
 * @tc.name: test HandleIsDirEmpty
 * @tc.desc: 1.HandleIsDirEmpty test
 */
HWTEST_F(BmsInstalldHostTest, HandleIsDirEmpty_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleIsDirEmpty(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandObtainQuickFixFileDir_0100
 * @tc.name: test HandObtainQuickFixFileDir
 * @tc.desc: 1.HandObtainQuickFixFileDir test
 */
HWTEST_F(BmsInstalldHostTest, HandObtainQuickFixFileDir_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandObtainQuickFixFileDir(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandCopyFiles_0100
 * @tc.name: test HandCopyFiles
 * @tc.desc: 1.HandCopyFiles test
 */
HWTEST_F(BmsInstalldHostTest, HandCopyFiles_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandCopyFiles(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandGetNativeLibraryFileNames_0100
 * @tc.name: test HandGetNativeLibraryFileNames
 * @tc.desc: 1.HandGetNativeLibraryFileNames test
 */
HWTEST_F(BmsInstalldHostTest, HandGetNativeLibraryFileNames_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandGetNativeLibraryFileNames(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandVerifyCodeSignature_0100
 * @tc.name: test HandVerifyCodeSignature
 * @tc.desc: 1.HandVerifyCodeSignature test
 */
HWTEST_F(BmsInstalldHostTest, HandVerifyCodeSignature_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandVerifyCodeSignature(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleCheckEncryption_0100
 * @tc.name: test HandleCheckEncryption
 * @tc.desc: 1.HandleCheckEncryption test
 */
HWTEST_F(BmsInstalldHostTest, HandleCheckEncryption_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandleCheckEncryption(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandMoveFiles_0100
 * @tc.name: test HandMoveFiles
 * @tc.desc: 1.HandMoveFiles test
 */
HWTEST_F(BmsInstalldHostTest, HandMoveFiles_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandMoveFiles(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandExtractDriverSoFiles_0100
 * @tc.name: test HandExtractDriverSoFiles
 * @tc.desc: 1.HandExtractDriverSoFiles test
 */
HWTEST_F(BmsInstalldHostTest, HandExtractDriverSoFiles_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandExtractDriverSoFiles(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandExtractEncryptedSoFiles_0100
 * @tc.name: test HandExtractEncryptedSoFiles
 * @tc.desc: 1.HandExtractEncryptedSoFiles test
 */
HWTEST_F(BmsInstalldHostTest, HandExtractEncryptedSoFiles_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandExtractEncryptedSoFiles(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandVerifyCodeSignatureForHap_0100
 * @tc.name: test HandVerifyCodeSignatureForHap
 * @tc.desc: 1.HandVerifyCodeSignatureForHap test
 */
HWTEST_F(BmsInstalldHostTest, HandVerifyCodeSignatureForHap_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandVerifyCodeSignatureForHap(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandDeliverySignProfile_0100
 * @tc.name: test HandDeliverySignProfile
 * @tc.desc: 1.HandDeliverySignProfile test
 */
HWTEST_F(BmsInstalldHostTest, HandDeliverySignProfile_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandDeliverySignProfile(data, reply);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: HandRemoveSignProfile_0100
 * @tc.name: test HandRemoveSignProfile
 * @tc.desc: 1.HandRemoveSignProfile test
 */
HWTEST_F(BmsInstalldHostTest, HandRemoveSignProfile_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = installdHost.HandRemoveSignProfile(data, reply);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HandleMigrateData_0100
 * @tc.name: test HandleMigrateData
 * @tc.desc: 1.HandleMigrateData test
 */
HWTEST_F(BmsInstalldHostTest, HandleMigrateData_0100, Function | SmallTest | Level1)
{
    InstalldHost installdHost;
    MessageParcel data;
    MessageParcel reply;
    bool res = installdHost.HandleMigrateData(data, reply);
    EXPECT_TRUE(res);
}
} // OHOS