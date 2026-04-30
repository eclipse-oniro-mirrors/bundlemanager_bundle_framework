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
const std::string TEST_STRING = "testString";
const std::string TEST_OTHER_BUNDLE_NAME = "com.example.testOther";
const std::string TEST_BUNDLE_NAME = "com.example.testOperator";
const std::string TEST_BUNDLE_PATCH = "/data/app/el1/bundle/public/com.example.testOperator/";
const std::string HQF_PATCH_PATH = "/patch";
const std::string VERIFY_FILE_PATH = "/abcs/";
const std::string BASE_SKILL_DIR = "/data/app/el1/skills/public";
const std::string APP_EL1_PATH = "/data/app/el1";
const std::string APP_EL2_PATH = "/data/app/el2";
const std::string ARK_PROFILE_PATH = "/aot_compiler/ark_profile/";
const std::string SERVICE_EL2_PATH = "/data/service/el2/";
const std::string SYSTEM_OPTIMIZE_DIR = "/system_optimize/";
const std::string BUNDLE_BACKUP_KEEP_DIR = "/.backup";
const std::string HMDFS_CLOUD_DATA_PATH = "/hmdfs/cloud/data/";
const std::string PGO_DIR_PATH = "/data/local/pgo/";
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

/**
 * @tc.number: IsValidPathByCreateBundleDirScene_0100
 * @tc.name: test IsValidPathByCreateBundleDirScene
 * @tc.desc: test IsValidPathByCreateBundleDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByCreateBundleDirScene_0100, Function | SmallTest | Level0)
{
    std::string path = ServiceConstants::RELATIVE_PATH;
    auto ret =
        InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::BUNDLE_CODE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::BUNDLE_CODE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = TEST_BUNDLE_PATCH;
    ret = InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::BUNDLE_CODE_DIR, TEST_STRING, path);
    EXPECT_FALSE(ret);

    ret = InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::BUNDLE_CODE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::MODULE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::SO_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByCreateBundleDirScene_0200
 * @tc.name: test IsValidPathByCreateBundleDirScene
 * @tc.desc: test IsValidPathByCreateBundleDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByCreateBundleDirScene_0200, Function | SmallTest | Level0)
{
    std::string path = TEST_BUNDLE_PATCH + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByCreateBundleDirScene(
        BundleDirScene::EXTEND_RESOURCE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = TEST_BUNDLE_PATCH + ServiceConstants::EXT_RESOURCE_FILE_PATH;
    ret = InstalldOperator::IsValidPathByCreateBundleDirScene(
        BundleDirScene::EXTEND_RESOURCE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    path = TEST_BUNDLE_PATCH + TEST_STRING;
    ret =
        InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::EXTEND_PROFILE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = TEST_BUNDLE_PATCH + ServiceConstants::EXT_PROFILE;
    ret =
        InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::EXTEND_PROFILE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    path = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::PLUGIN_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = TEST_BUNDLE_PATCH + ServiceConstants::PLUGIN_FILE_PATH;
    ret = InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::PLUGIN_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByCreateBundleDirScene_0300
 * @tc.name: test IsValidPathByCreateBundleDirScene
 * @tc.desc: test IsValidPathByCreateBundleDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByCreateBundleDirScene_0300, Function | SmallTest | Level0)
{
    std::string path = TEST_BUNDLE_PATCH + TEST_STRING;
    auto ret =
        InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::QUICKFIX_PATCH_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = TEST_BUNDLE_PATCH + ServiceConstants::PATCH_PATH + TEST_STRING;
    ret =
        InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::QUICKFIX_PATCH_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    path = TEST_BUNDLE_PATCH + ServiceConstants::HOT_RELOAD_PATH + TEST_STRING;
    ret =
        InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::QUICKFIX_PATCH_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    path = TEST_BUNDLE_PATCH + HQF_PATCH_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret =
        InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::QUICKFIX_PATCH_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByCreateBundleDirScene_0400
 * @tc.name: test IsValidPathByCreateBundleDirScene
 * @tc.desc: test IsValidPathByCreateBundleDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByCreateBundleDirScene_0400, Function | SmallTest | Level0)
{
    std::string path = TEST_BUNDLE_PATCH + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::VERIFY_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = TEST_BUNDLE_PATCH + VERIFY_FILE_PATH;
    ret = InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::VERIFY_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    path = BASE_SKILL_DIR + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::BASE_SKILL_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = BASE_SKILL_DIR + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::BASE_SKILL_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidPathByCreateBundleDirScene(BundleDirScene::SET_DIR_APL, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByMkDirSceneNeedBundleName_0100
 * @tc.name: test IsValidPathByMkDirSceneNeedBundleName
 * @tc.desc: test IsValidPathByMkDirSceneNeedBundleName of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMkDirSceneNeedBundleName_0100, Function | SmallTest | Level0)
{
    std::string path =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    auto ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::EL1_ARK_PROFILE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::EL1_ARK_PROFILE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = std::string(APP_EL1_PATH) + ARK_PROFILE_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::EL1_ARK_PROFILE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = std::string(APP_EL1_PATH) + ARK_PROFILE_PATH + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::EL1_ARK_PROFILE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    path = std::string(ServiceConstants::BUNDLE_ASAN_LOG_DIR) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(BundleDirScene::ASAN_LOG_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByMkDirSceneNeedBundleName_0200
 * @tc.name: test IsValidPathByMkDirSceneNeedBundleName
 * @tc.desc: test IsValidPathByMkDirSceneNeedBundleName of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMkDirSceneNeedBundleName_0200, Function | SmallTest | Level0)
{
    std::string path = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    auto ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::EL1_ARK_STARTUP_CACHE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = std::string(APP_EL1_PATH) + SYSTEM_OPTIMIZE_DIR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::EL1_ARK_STARTUP_CACHE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = std::string(APP_EL1_PATH) + SYSTEM_OPTIMIZE_DIR + ServiceConstants::ARK_STARTUP_CACHE_DIR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::EL1_ARK_STARTUP_CACHE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    path = std::string(ServiceConstants::SHADER_CACHE_PATH) + TEST_STRING;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::SHADER_CACHE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = std::string(ServiceConstants::SHADER_CACHE_PATH) + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::SHADER_CACHE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByMkDirSceneNeedBundleName_0300
 * @tc.name: test IsValidPathByMkDirSceneNeedBundleName
 * @tc.desc: test IsValidPathByMkDirSceneNeedBundleName of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMkDirSceneNeedBundleName_0300, Function | SmallTest | Level0)
{
    std::string path =
        std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    auto ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::SCREEN_LOCK_FILE_BASE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) + ServiceConstants::BASE + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::SCREEN_LOCK_FILE_BASE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    path = std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) + ServiceConstants::DATABASE + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::SCREEN_LOCK_FILE_DATA_BASE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    path = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::EL1_SHADER_CACHE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = std::string(APP_EL1_PATH) + ServiceConstants::SHADER_CACHE_SUBDIR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::EL1_SHADER_CACHE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByMkDirSceneNeedBundleName_0400
 * @tc.name: test IsValidPathByMkDirSceneNeedBundleName
 * @tc.desc: test IsValidPathByMkDirSceneNeedBundleName of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMkDirSceneNeedBundleName_0400, Function | SmallTest | Level0)
{
    std::string path = std::string(APP_EL1_PATH) + SYSTEM_OPTIMIZE_DIR + TEST_BUNDLE_NAME;
    auto ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::EL1_SYSTEM_OPTIMIZE_SHADER_CACHE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);

    path = std::string(APP_EL1_PATH) + SYSTEM_OPTIMIZE_DIR + ServiceConstants::SHADER_CACHE_SUBDIR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::EL1_SYSTEM_OPTIMIZE_SHADER_CACHE_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    path = std::string(APP_EL1_PATH) + ServiceConstants::BASE + TEST_BUNDLE_NAME + BUNDLE_BACKUP_KEEP_DIR;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(BundleDirScene::BACK_UP_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    path = std::string(APP_EL2_PATH) + ServiceConstants::LOG + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::APP_EL2_LOG_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    path = std::string(SERVICE_EL2_PATH) + HMDFS_CLOUD_DATA_PATH + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::SERVICE_HMDFS_CLOUD_DATA_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    path = std::string(APP_EL2_PATH) + ServiceConstants::SHAREFILES + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(
        BundleDirScene::EL2_SHARE_FILES_DIR, TEST_BUNDLE_NAME, path);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidPathByMkDirSceneNeedBundleName(BundleDirScene::SET_DIR_APL, TEST_BUNDLE_NAME, path);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByMkDirSceneNoBundleName_0100
 * @tc.name: test IsValidPathByMkDirSceneNoBundleName
 * @tc.desc: test IsValidPathByMkDirSceneNoBundleName of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMkDirSceneNoBundleName_0100, Function | SmallTest | Level0)
{
    std::string path = TEST_BUNDLE_PATCH + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::CLOUD_SHADER_DIR, path);
    EXPECT_FALSE(ret);

    path = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::CLOUD_SHADER_COMMON_DIR, path);
    EXPECT_FALSE(ret);

    path = std::string(ServiceConstants::CLOUD_SHADER_PATH) + TEST_STRING;
    ret = InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::CLOUD_SHADER_DIR, path);
    EXPECT_TRUE(ret);

    path = std::string(ServiceConstants::CLOUD_SHADER_COMMON_PATH) + TEST_STRING;
    ret = InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::CLOUD_SHADER_COMMON_DIR, path);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByMkDirSceneNoBundleName_0200
 * @tc.name: test IsValidPathByMkDirSceneNoBundleName
 * @tc.desc: test IsValidPathByMkDirSceneNoBundleName of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMkDirSceneNoBundleName_0200, Function | SmallTest | Level0)
{
    std::string path = TEST_BUNDLE_PATCH + ServiceConstants::GALLERY_DOWNLOAD_PATH;
    auto ret =
        InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::SERVICE_BMS_GALLERY_DOWNLOAD_DIR, path);
    EXPECT_FALSE(ret);

    path = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::GALLERY_DOWNLOAD_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::SERVICE_BMS_GALLERY_DOWNLOAD_DIR, path);
    EXPECT_TRUE(ret);

    path = TEST_BUNDLE_PATCH + ServiceConstants::ENTERPRISE_CERT_PATH;
    ret = InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::SERVICE_BMS_ENTERPRISE_CERT_DIR, path);
    EXPECT_FALSE(ret);

    path = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::ENTERPRISE_CERT_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::SERVICE_BMS_ENTERPRISE_CERT_DIR, path);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByMkDirSceneNoBundleName_0300
 * @tc.name: test IsValidPathByMkDirSceneNoBundleName
 * @tc.desc: test IsValidPathByMkDirSceneNoBundleName of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMkDirSceneNoBundleName_0300, Function | SmallTest | Level0)
{
    std::string path = TEST_BUNDLE_PATCH + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::EL1_SYSTEM_OPTIMIZE_DIR, path);
    EXPECT_FALSE(ret);

    path = std::string(APP_EL1_PATH) + SYSTEM_OPTIMIZE_DIR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::EL1_SYSTEM_OPTIMIZE_DIR, path);
    EXPECT_TRUE(ret);

    path = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::SERVICE_BMS_DIR, path);
    EXPECT_TRUE(ret);

    path = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
           ServiceConstants::SECURITY_STREAM_INSTALL_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByMkDirSceneNoBundleName(
        BundleDirScene::SERVICE_BMS_SECURITY_STREAM_INSTALL_DIR, path);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByMkDirSceneNoBundleName_0400
 * @tc.name: test IsValidPathByMkDirSceneNoBundleName
 * @tc.desc: test IsValidPathByMkDirSceneNoBundleName of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMkDirSceneNoBundleName_0400, Function | SmallTest | Level0)
{
    std::string path =
        std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    auto ret =
        InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::SCREEN_LOCK_FILE_DATA_GROUP_DIR, path);
    EXPECT_FALSE(ret);

    path = std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) + ServiceConstants::DATA_GROUP_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::SCREEN_LOCK_FILE_DATA_GROUP_DIR, path);
    EXPECT_TRUE(ret);

    path = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::PGO_DIR, path);
    EXPECT_FALSE(ret);

    path = PGO_DIR_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::PGO_DIR, path);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidPathByMkDirSceneNoBundleName(BundleDirScene::SET_DIR_APL, path);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByMkDirScene_0100
 * @tc.name: test IsValidPathByMkDirScene
 * @tc.desc: test IsValidPathByMkDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMkDirScene_0100, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string path = ServiceConstants::RELATIVE_PATH;
    auto ret = InstalldOperator::IsValidPathByMkDirScene(BundleDirScene::EL1_ARK_PROFILE_DIR, bundleName, path);
    EXPECT_FALSE(ret);

    ret = InstalldOperator::IsValidPathByMkDirScene(BundleDirScene::SERVICE_BMS_DIR, bundleName, path);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByMkDirScene_0200
 * @tc.name: test IsValidPathByMkDirScene
 * @tc.desc: test IsValidPathByMkDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMkDirScene_0200, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string path = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + bundleName;
    auto ret = InstalldOperator::IsValidPathByMkDirScene(BundleDirScene::EL1_ARK_PROFILE_DIR, bundleName, path);
    EXPECT_FALSE(ret);

    path = std::string(APP_EL1_PATH) + ARK_PROFILE_PATH + bundleName;
    ret = InstalldOperator::IsValidPathByMkDirScene(BundleDirScene::EL1_ARK_PROFILE_DIR, bundleName, path);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidPathByMkDirScene(BundleDirScene::SET_DIR_APL, bundleName, path);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByMkDirScene_0300
 * @tc.name: test IsValidPathByMkDirScene
 * @tc.desc: test IsValidPathByMkDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMkDirScene_0300, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string path = TEST_BUNDLE_PATCH + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByMkDirScene(BundleDirScene::SERVICE_BMS_DIR, bundleName, path);
    EXPECT_FALSE(ret);

    path = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByMkDirScene(BundleDirScene::SERVICE_BMS_DIR, bundleName, path);
    EXPECT_TRUE(ret);

    path = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
           ServiceConstants::SECURITY_STREAM_INSTALL_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByMkDirScene(
        BundleDirScene::SERVICE_BMS_SECURITY_STREAM_INSTALL_DIR, bundleName, path);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRenameModuleDir_0100
 * @tc.name: test IsValidPathByRenameModuleDir
 * @tc.desc: test IsValidPathByRenameModuleDir of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRenameModuleDir_0100, Function | SmallTest | Level0)
{
    std::string oldPath = ServiceConstants::RELATIVE_PATH;
    std::string newPath = TEST_BUNDLE_PATCH;
    auto ret = InstalldOperator::IsValidPathByRenameModuleDir(
        oldPath, newPath, TEST_BUNDLE_NAME, BundleDirScene::BUNDLE_CODE_DIR);
    EXPECT_FALSE(ret);

    oldPath = TEST_BUNDLE_PATCH;
    newPath = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByRenameModuleDir(
        oldPath, newPath, TEST_BUNDLE_NAME, BundleDirScene::BUNDLE_CODE_DIR);
    EXPECT_FALSE(ret);

    oldPath = ServiceConstants::RELATIVE_PATH;
    newPath = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByRenameModuleDir(
        oldPath, newPath, TEST_BUNDLE_NAME, BundleDirScene::BUNDLE_CODE_DIR);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByRenameModuleDir_0200
 * @tc.name: test IsValidPathByRenameModuleDir
 * @tc.desc: test IsValidPathByRenameModuleDir of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRenameModuleDir_0200, Function | SmallTest | Level0)
{
    std::string oldPath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    std::string newPath = TEST_BUNDLE_PATCH;
    auto ret = InstalldOperator::IsValidPathByRenameModuleDir(
        oldPath, newPath, TEST_BUNDLE_NAME, BundleDirScene::BUNDLE_CODE_DIR);
    EXPECT_FALSE(ret);

    oldPath = TEST_BUNDLE_PATCH;
    newPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRenameModuleDir(
        oldPath, newPath, TEST_BUNDLE_NAME, BundleDirScene::BUNDLE_CODE_DIR);
    EXPECT_FALSE(ret);

    oldPath = TEST_BUNDLE_PATCH + TEST_STRING;
    newPath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRenameModuleDir(
        oldPath, newPath, TEST_OTHER_BUNDLE_NAME, BundleDirScene::BUNDLE_CODE_DIR);
    EXPECT_FALSE(ret);

    oldPath = TEST_BUNDLE_PATCH;
    newPath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRenameModuleDir(
        oldPath, newPath, TEST_BUNDLE_NAME, BundleDirScene::BUNDLE_CODE_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRenameModuleDir_0300
 * @tc.name: test IsValidPathByRenameModuleDir
 * @tc.desc: test IsValidPathByRenameModuleDir of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRenameModuleDir_0300, Function | SmallTest | Level0)
{
    std::string oldPath = BASE_SKILL_DIR + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    std::string newPath = BASE_SKILL_DIR + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    auto ret = InstalldOperator::IsValidPathByRenameModuleDir(
        oldPath, newPath, TEST_BUNDLE_NAME, BundleDirScene::BASE_SKILL_DIR);
    EXPECT_FALSE(ret);

    oldPath = BASE_SKILL_DIR + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    newPath = BASE_SKILL_DIR + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRenameModuleDir(
        oldPath, newPath, TEST_BUNDLE_NAME, BundleDirScene::BASE_SKILL_DIR);
    EXPECT_TRUE(ret);

    ret =
        InstalldOperator::IsValidPathByRenameModuleDir(oldPath, newPath, TEST_BUNDLE_NAME, BundleDirScene::SET_DIR_APL);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidSourcePathByMoveFileScene_0100
 * @tc.name: test IsValidSourcePathByMoveFileScene
 * @tc.desc: test IsValidSourcePathByMoveFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidSourcePathByMoveFileScene_0100, Function | SmallTest | Level0)
{
    std::string sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                             TEST_BUNDLE_NAME + ServiceConstants::INSTALL_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidSourcePathByMoveFileScene(
        sourcePath, BundleDirScene::MOVE_HAP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    sourcePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByMoveFileScene(
        sourcePath, BundleDirScene::MOVE_HAP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);

    sourcePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByMoveFileScene(
        sourcePath, BundleDirScene::MOVE_HAP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);

    sourcePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByMoveFileScene(
        sourcePath, BundleDirScene::MOVE_HAP_TO_TEMP_DIR, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidSourcePathByMoveFileScene(
        sourcePath, BundleDirScene::MOVE_HAP_TO_TEMP_DIR, TEST_OTHER_BUNDLE_NAME);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidSourcePathByMoveFileScene_0200
 * @tc.name: test IsValidSourcePathByMoveFileScene
 * @tc.desc: test IsValidSourcePathByMoveFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidSourcePathByMoveFileScene_0200, Function | SmallTest | Level0)
{
    std::string sourcePath = TEST_BUNDLE_PATCH + TEST_STRING;
    auto ret = InstalldOperator::IsValidSourcePathByMoveFileScene(
        sourcePath, BundleDirScene::MOVE_DRIVER_FILE, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    sourcePath = std::string(ServiceConstants::SYSTEM_SERVICE_DIR) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByMoveFileScene(
        sourcePath, BundleDirScene::MOVE_DRIVER_FILE, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    sourcePath = std::string(ServiceConstants::SYSTEM_SERVICE_DIR) + ServiceConstants::PATH_SEPARATOR +
                 TEST_BUNDLE_NAME + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByMoveFileScene(
        sourcePath, BundleDirScene::MOVE_DRIVER_FILE, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidSourcePathByMoveFileScene_0300
 * @tc.name: test IsValidSourcePathByMoveFileScene
 * @tc.desc: test IsValidSourcePathByMoveFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidSourcePathByMoveFileScene_0300, Function | SmallTest | Level0)
{
    std::string sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                             ServiceConstants::EXT_RESOURCE_FILE_PATH + ServiceConstants::PATH_SEPARATOR +
                             TEST_BUNDLE_NAME + ServiceConstants::HSP_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidSourcePathByMoveFileScene(
        sourcePath, BundleDirScene::MOVE_EXTEND_RESOURCE_FILE, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    sourcePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByMoveFileScene(
        sourcePath, BundleDirScene::MOVE_EXTEND_RESOURCE_FILE, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    sourcePath = TEST_BUNDLE_PATCH + ServiceConstants::EXT_RESOURCE_FILE_PATH + ServiceConstants::PATH_SEPARATOR +
                 TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByMoveFileScene(
        sourcePath, BundleDirScene::MOVE_EXTEND_RESOURCE_FILE, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByMoveFileScene(
        sourcePath, BundleDirScene::MOVE_EXTEND_RESOURCE_FILE_TO_TEMP_DIR, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByMoveFileScene(
        sourcePath, BundleDirScene::MOVE_EXTEND_RESOURCE_FILE_TO_TEMP_DIR, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidSourcePathByMoveFileScene_0400
 * @tc.name: test IsValidSourcePathByMoveFileScene
 * @tc.desc: test IsValidSourcePathByMoveFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidSourcePathByMoveFileScene_0400, Function | SmallTest | Level0)
{
    std::string sourcePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidSourcePathByMoveFileScene(
        sourcePath, BundleDirScene::MOVE_HSP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    sourcePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByMoveFileScene(
        sourcePath, BundleDirScene::MOVE_HSP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);

    sourcePath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret =
        InstalldOperator::IsValidSourcePathByMoveFileScene(sourcePath, BundleDirScene::MOVE_ABC_FILE, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    sourcePath = TEST_BUNDLE_PATCH + VERIFY_FILE_PATH + TEST_STRING;
    ret =
        InstalldOperator::IsValidSourcePathByMoveFileScene(sourcePath, BundleDirScene::MOVE_ABC_FILE, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidSourcePathByMoveFileScene(sourcePath, BundleDirScene::SET_DIR_APL, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidTargetPathByMoveFileScene_0100
 * @tc.name: test IsValidTargetPathByMoveFileScene
 * @tc.desc: test IsValidTargetPathByMoveFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidTargetPathByMoveFileScene_0100, Function | SmallTest | Level0)
{
    std::string targetPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                             TEST_BUNDLE_NAME + ServiceConstants::INSTALL_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidTargetPathByMoveFileScene(
        targetPath, BundleDirScene::MOVE_HAP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByMoveFileScene(
        targetPath, BundleDirScene::MOVE_HAP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByMoveFileScene(
        targetPath, BundleDirScene::MOVE_HAP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidTargetPathByMoveFileScene(
        targetPath, BundleDirScene::MOVE_HAP_TO_INSTALL_DIR, TEST_OTHER_BUNDLE_NAME);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidTargetPathByMoveFileScene_0200
 * @tc.name: test IsValidTargetPathByMoveFileScene
 * @tc.desc: test IsValidTargetPathByMoveFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidTargetPathByMoveFileScene_0200, Function | SmallTest | Level0)
{
    std::string targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidTargetPathByMoveFileScene(
        targetPath, BundleDirScene::MOVE_HAP_TO_TEMP_DIR, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    targetPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::INSTALL_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByMoveFileScene(
        targetPath, BundleDirScene::MOVE_HAP_TO_TEMP_DIR, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    targetPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME +
                 ServiceConstants::INSTALL_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByMoveFileScene(
        targetPath, BundleDirScene::MOVE_HAP_TO_TEMP_DIR, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);

    targetPath = std::string(ServiceConstants::SYSTEM_SERVICE_DIR) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidTargetPathByMoveFileScene(
        targetPath, BundleDirScene::MOVE_DRIVER_FILE, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    targetPath = std::string(ServiceConstants::SYSTEM_SERVICE_DIR) + ServiceConstants::PATH_SEPARATOR +
                 TEST_BUNDLE_NAME + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidTargetPathByMoveFileScene(
        targetPath, BundleDirScene::MOVE_DRIVER_FILE, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidTargetPathByMoveFileScene_0300
 * @tc.name: test IsValidTargetPathByMoveFileScene
 * @tc.desc: test IsValidTargetPathByMoveFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidTargetPathByMoveFileScene_0300, Function | SmallTest | Level0)
{
    std::string targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidTargetPathByMoveFileScene(
        targetPath, BundleDirScene::MOVE_EXTEND_RESOURCE_FILE, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + ServiceConstants::EXT_RESOURCE_FILE_PATH + ServiceConstants::PATH_SEPARATOR +
                 TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByMoveFileScene(
        targetPath, BundleDirScene::MOVE_EXTEND_RESOURCE_FILE, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByMoveFileScene(
        targetPath, BundleDirScene::MOVE_EXTEND_RESOURCE_FILE_TO_TEMP_DIR, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + ServiceConstants::EXT_RESOURCE_FILE_PATH + ServiceConstants::PATH_SEPARATOR +
                 TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByMoveFileScene(
        targetPath, BundleDirScene::MOVE_EXTEND_RESOURCE_FILE_TO_TEMP_DIR, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidTargetPathByMoveFileScene_0400
 * @tc.name: test IsValidTargetPathByMoveFileScene
 * @tc.desc: test IsValidTargetPathByMoveFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidTargetPathByMoveFileScene_0400, Function | SmallTest | Level0)
{
    std::string targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidTargetPathByMoveFileScene(
        targetPath, BundleDirScene::MOVE_HSP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByMoveFileScene(
        targetPath, BundleDirScene::MOVE_HSP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret =
        InstalldOperator::IsValidTargetPathByMoveFileScene(targetPath, BundleDirScene::MOVE_ABC_FILE, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + VERIFY_FILE_PATH + TEST_STRING;
    ret =
        InstalldOperator::IsValidTargetPathByMoveFileScene(targetPath, BundleDirScene::MOVE_ABC_FILE, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidTargetPathByMoveFileScene(targetPath, BundleDirScene::SET_DIR_APL, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByMoveFileScene_0100
 * @tc.name: test IsValidPathByMoveFileScene
 * @tc.desc: test IsValidPathByMoveFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMoveFileScene_0100, Function | SmallTest | Level0)
{
    std::string oldPath = ServiceConstants::RELATIVE_PATH;
    std::string newPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidPathByMoveFileScene(
        oldPath, newPath, BundleDirScene::MOVE_HAP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    oldPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    newPath = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByMoveFileScene(
        oldPath, newPath, BundleDirScene::MOVE_HAP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    oldPath = ServiceConstants::RELATIVE_PATH;
    newPath = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByMoveFileScene(
        oldPath, newPath, BundleDirScene::MOVE_HAP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByMoveFileScene_0200
 * @tc.name: test IsValidPathByMoveFileScene
 * @tc.desc: test IsValidPathByMoveFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMoveFileScene_0200, Function | SmallTest | Level0)
{
    std::string oldPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                          TEST_BUNDLE_NAME + ServiceConstants::INSTALL_FILE_SUFFIX;                // source false
    std::string newPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX; // target true
    auto ret = InstalldOperator::IsValidPathByMoveFileScene(
        oldPath, newPath, BundleDirScene::MOVE_HAP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);

    oldPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX; // source true
    newPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME +
              ServiceConstants::INSTALL_FILE_SUFFIX; // target false
    ret = InstalldOperator::IsValidPathByMoveFileScene(
        oldPath, newPath, BundleDirScene::MOVE_HAP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByMoveFileScene_0300
 * @tc.name: test IsValidPathByMoveFileScene
 * @tc.desc: test IsValidPathByMoveFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMoveFileScene_0300, Function | SmallTest | Level0)
{
    std::string oldPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    std::string newPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidPathByMoveFileScene(
        oldPath, newPath, BundleDirScene::MOVE_HAP_TO_INSTALL_DIR, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);

    oldPath = TEST_BUNDLE_PATCH + VERIFY_FILE_PATH + TEST_STRING;
    newPath = TEST_BUNDLE_PATCH + VERIFY_FILE_PATH + TEST_STRING;
    ret =
        InstalldOperator::IsValidPathByMoveFileScene(oldPath, newPath, BundleDirScene::MOVE_ABC_FILE, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidPathByMoveFileScene(oldPath, newPath, BundleDirScene::SET_DIR_APL, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);
}
} // OHOS