/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <gtest/gtest.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "bundle_util.h"
#include "bundle_extractor.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "installd/installd_operator.h"
#include "parameters.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
}; // namespace
class BmsInstalldOperatorTest : public testing::Test {
public:
    BmsInstalldOperatorTest();
    ~BmsInstalldOperatorTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsInstalldOperatorTest::BmsInstalldOperatorTest()
{}

BmsInstalldOperatorTest::~BmsInstalldOperatorTest()
{}

void BmsInstalldOperatorTest::SetUpTestCase()
{
}

void BmsInstalldOperatorTest::TearDownTestCase()
{}

void BmsInstalldOperatorTest::SetUp()
{}

void BmsInstalldOperatorTest::TearDown()
{}

/**
 * @tc.number: InstalldOperatorTest_0100
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling GetSameLevelTmpPath of InstalldOperator
*/
HWTEST_F(BmsInstalldOperatorTest, InstalldOperatorTest_0100, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::GetSameLevelTmpPath(path);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);

    path = "data/";
    EXPECT_NO_THROW(InstalldOperator::GetSameLevelTmpPath(path));
}

/**
 * @tc.number: InstalldOperatorTest_0200
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling RenameFile of InstalldOperator
*/
HWTEST_F(BmsInstalldOperatorTest, InstalldOperatorTest_0200, Function | SmallTest | Level0)
{
    std::string oldPath = "data/test";
    std::string newPath = "wrongPath/";
    auto ret = InstalldOperator::RenameFile(oldPath, newPath);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_0300
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling GenerateKeyId of InstalldOperator
*/
HWTEST_F(BmsInstalldOperatorTest, InstalldOperatorTest_0300, Function | SmallTest | Level0)
{
    EncryptionParam encryptionParam;
    encryptionParam.encryptionDirType = EncryptionDirType::GROUP;
    std::string keyId;
    EXPECT_NO_THROW(InstalldOperator::GenerateKeyId(encryptionParam, keyId));
}

/**
 * @tc.number: InstalldOperatorTest_0001
 * @tc.name: test function of SetKeyIdPolicy
 * @tc.desc: 1. calling SetKeyIdPolicy of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, InstalldOperatorTest_0001, Function | SmallTest | Level0)
{
    EncryptionParam encryptionParam;
    encryptionParam.encryptionDirType = EncryptionDirType::APP;
    std::string keyId = "testKeyId";
    EXPECT_NO_THROW(InstalldOperator::SetKeyIdPolicy(encryptionParam, keyId));

    encryptionParam.encryptionDirType = EncryptionDirType::GROUP;
    EXPECT_NO_THROW(InstalldOperator::SetKeyIdPolicy(encryptionParam, keyId));
}

/**
 * @tc.number: InstalldOperatorTest_0002
 * @tc.name: test function of DeleteKeyId
 * @tc.desc: 1. calling DeleteKeyId of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, InstalldOperatorTest_0002, Function | SmallTest | Level0)
{
    EncryptionParam encryptionParam;
    encryptionParam.encryptionDirType = EncryptionDirType::APP;
    EXPECT_NO_THROW(InstalldOperator::DeleteKeyId(encryptionParam));

    encryptionParam.encryptionDirType = EncryptionDirType::GROUP;
    EXPECT_NO_THROW(InstalldOperator::DeleteKeyId(encryptionParam));
}

/**
 * @tc.number: InstalldOperatorTest_0003
 * @tc.name: test function of MigrateData
 * @tc.desc: 1. calling MigrateData of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, InstalldOperatorTest_0003, Function | SmallTest | Level0)
{
    std::vector<std::string> sourcePaths;
    std::string destinationPath;
    EXPECT_NO_THROW(InstalldOperator::MigrateData(sourcePaths, destinationPath));
    sourcePaths.push_back("/data/test/sourcePath/test.txt");
    sourcePaths.push_back("/data/test/sourcePath/test2.txt");
    EXPECT_NO_THROW(InstalldOperator::MigrateData(sourcePaths, destinationPath));

    sourcePaths.push_back("/data/log");
    destinationPath = "data/log/hilog";
    EXPECT_NO_THROW(InstalldOperator::MigrateData(sourcePaths, destinationPath));
}

/**
 * @tc.number: InstalldOperatorTest_0004
 * @tc.name: test function of InnerMigrateData
 * @tc.desc: 1. calling InnerMigrateData of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, InstalldOperatorTest_0004, Function | SmallTest | Level0)
{
    std::string sourcePaths;
    std::string destinationPath;
    AppExecFwk::InstalldOperator::OwnershipInfo info;
    EXPECT_NE(InstalldOperator::InnerMigrateData(sourcePaths, destinationPath, info), ERR_OK);

    sourcePaths = "/data/log";
    EXPECT_NO_THROW(InstalldOperator::InnerMigrateData(sourcePaths, destinationPath, info));
}

/**
 * @tc.number: InstalldOperatorTest_0005
 * @tc.name: test function of MigrateDataCopyFile
 * @tc.desc: 1. calling MigrateDataCopyFile of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, InstalldOperatorTest_0005, Function | SmallTest | Level0)
{
    std::string sourcePaths;
    std::string destinationPath;
    AppExecFwk::InstalldOperator::OwnershipInfo info;
    EXPECT_NO_THROW(InstalldOperator::MigrateDataCopyFile(sourcePaths, destinationPath, info));

    sourcePaths = "/data/log";
    EXPECT_NO_THROW(InstalldOperator::MigrateDataCopyFile(sourcePaths, destinationPath, info));

    std::vector<std::string> realSourcePaths;
    EXPECT_NO_THROW(InstalldOperator::MigrateDataCheckPrmissions(realSourcePaths, destinationPath, info));

    realSourcePaths.push_back("/data/log");
    EXPECT_NO_THROW(InstalldOperator::MigrateDataCheckPrmissions(realSourcePaths, destinationPath, info));
}

/**
 * @tc.number: InstalldOperatorTest_0006
 * @tc.name: test function of ClearDir
 * @tc.desc: 1. calling ClearDir of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, InstalldOperatorTest_0006, Function | SmallTest | Level0)
{
    std::string dir = "/data/test/InstalldOperatorTest_0006";
    auto ret = InstalldOperator::MkOwnerDir(dir, 0, 0, 0);
    EXPECT_TRUE(ret);
    EXPECT_NO_THROW(InstalldOperator::ClearDir(dir));
}

/**
 * @tc.number: InstalldOperatorTest_0007
 * @tc.name: test function of RestoreconPath
 * @tc.desc: 1. calling RestoreconPath of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, InstalldOperatorTest_0007, Function | SmallTest | Level0)
{
    const std::string arkWebName = OHOS::system::GetParameter("persist.arkwebcore.package_name", "");
    const std::string arkWebLibPath = "/data/app/el1/bundle/public/" + arkWebName + "/libs/arm64/";
    if (std::filesystem::exists(arkWebLibPath)) {
        auto ret = InstalldOperator::RestoreconPath(arkWebLibPath);
        EXPECT_TRUE(ret);
    } else {
        auto ret = InstalldOperator::RestoreconPath(arkWebLibPath);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: InstalldOperatorTest_0008
 * @tc.name: test function of CheckDeviceMode
 * @tc.desc: 1. calling CheckDeviceMode with different cmdline values
 */
HWTEST_F(BmsInstalldOperatorTest, InstalldOperatorTest_0008, Function | SmallTest | Level0)
{
    char normalMode[] = "console=test";
    EXPECT_FALSE(InstalldOperator::CheckDeviceMode(normalMode));

    char userMode[] = "oemmode=user";
    EXPECT_FALSE(InstalldOperator::CheckDeviceMode(userMode));

    char attackedMode[] = "oemmode=rd oemmode=user";
    EXPECT_FALSE(InstalldOperator::CheckDeviceMode(attackedMode));

    char rdMode[] = "boot=normal oemmode=rd";
    EXPECT_TRUE(InstalldOperator::CheckDeviceMode(rdMode));
}

/**
 * @tc.number: InstalldOperatorTest_0009
 * @tc.name: test function of CheckEfuseStatus
 * @tc.desc: 1. calling CheckEfuseStatus with different cmdline values
 */
HWTEST_F(BmsInstalldOperatorTest, InstalldOperatorTest_0009, Function | SmallTest | Level0)
{
    char defaultStatus[] = "console=test";
    EXPECT_FALSE(InstalldOperator::CheckEfuseStatus(defaultStatus));

    char efusedStatus[] = "efuse_status=0";
    EXPECT_FALSE(InstalldOperator::CheckEfuseStatus(efusedStatus));

    char attackedStatus[] = "efuse_status=1 efuse_status=0";
    EXPECT_FALSE(InstalldOperator::CheckEfuseStatus(attackedStatus));

    char notEfusedStatus[] = "mode=debug efuse_status=1";
    EXPECT_TRUE(InstalldOperator::CheckEfuseStatus(notEfusedStatus));
}

/**
 * @tc.number: InstalldOperatorTest_0010
 * @tc.name: test function of ParsePluginId
 * @tc.desc: 1. calling ParsePluginId with invalid parameters
 */
HWTEST_F(BmsInstalldOperatorTest, InstalldOperatorTest_0010, Function | SmallTest | Level0)
{
    std::vector<std::string> pluginIds;
    EXPECT_FALSE(InstalldOperator::ParsePluginId("", pluginIds));

    const std::string noPermission = R"({"other.permission":"{\"pluginDistributionIDs\":\"plugin1\"}"})";
    EXPECT_FALSE(InstalldOperator::ParsePluginId(noPermission, pluginIds));

    const std::string noPluginId = R"({"ohos.permission.kernel.SUPPORT_PLUGIN":"{\"otherKey\":\"plugin1\"}"})";
    EXPECT_FALSE(InstalldOperator::ParsePluginId(noPluginId, pluginIds));
}

/**
 * @tc.number: InstalldOperatorTest_0011
 * @tc.name: test function of ParsePluginId
 * @tc.desc: 1. calling ParsePluginId with different separators
 */
HWTEST_F(BmsInstalldOperatorTest, InstalldOperatorTest_0011, Function | SmallTest | Level0)
{
    std::vector<std::string> pluginIds;
    const std::string pluginIdsWithComma =
        R"({"ohos.permission.kernel.SUPPORT_PLUGIN":"{\"pluginDistributionIDs\":\"plugin1, plugin2\"}"})";
    EXPECT_TRUE(InstalldOperator::ParsePluginId(pluginIdsWithComma, pluginIds));
    ASSERT_EQ(pluginIds.size(), 2);
    EXPECT_EQ(pluginIds[0], "plugin1");
    EXPECT_EQ(pluginIds[1], "plugin2");

    pluginIds.clear();
    const std::string pluginIdsWithPipe =
        R"({"ohos.permission.kernel.SUPPORT_PLUGIN":"{\"pluginDistributionIDs\":\"plugin3|plugin4\"}"})";
    EXPECT_TRUE(InstalldOperator::ParsePluginId(pluginIdsWithPipe, pluginIds));
    ASSERT_EQ(pluginIds.size(), 2);
    EXPECT_EQ(pluginIds[0], "plugin3");
    EXPECT_EQ(pluginIds[1], "plugin4");
}

/**
 * @tc.number: SetBinFileLabel_001
 * @tc.name: test SetBinFileLabel with empty path
 * @tc.desc: 1. binFilePath is empty
 *           2. verify return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR
 */
HWTEST_F(BmsInstalldOperatorTest, SetBinFileLabel_001, Function | SmallTest | Level0)
{
    std::string emptyPath = "";
    auto result = InstalldOperator::SetBinFileLabel(emptyPath);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: SetBinFileLabel_002
 * @tc.name: test SetBinFileLabel with non-existent file
 * @tc.desc: 1. binFilePath not exists
 *           2. verify return ERR_APPEXECFWK_INSTALL_FAILED_ACCESS_BIN_FILE
 */
HWTEST_F(BmsInstalldOperatorTest, SetBinFileLabel_002, Function | SmallTest | Level0)
{
    std::string nonExistPath = "/data/test/non_exist_bin_file_12345.bin";
    auto result = InstalldOperator::SetBinFileLabel(nonExistPath);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALL_FAILED_ACCESS_BIN_FILE);
}
} // OHOS