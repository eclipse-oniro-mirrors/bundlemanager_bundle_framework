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
#include "bundle_service_constants.h"
#include "directory_ex.h"
#include "file_ex.h"
#define private public
#include "installd/installd_operator.h"
#undef private
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
const std::string APP_EL3_PATH = "/data/app/el3";
const std::string APP_EL4_PATH = "/data/app/el4";
const std::string ARK_PROFILE_PATH = "/aot_compiler/ark_profile/";
const std::string SERVICE_EL2_PATH = "/data/service/el2/";
const std::string SYSTEM_OPTIMIZE_DIR = "/system_optimize/";
const std::string BUNDLE_BACKUP_KEEP_DIR = "/.backup";
const std::string HMDFS_CLOUD_DATA_PATH = "/hmdfs/cloud/data/";
const std::string PGO_DIR_PATH = "/data/local/pgo/";
const std::string LIBS_TMP_DIR = "libs+tmp";
const std::string DEPRECATED_ARK_CACHE_PATH = "/data/local/ark-cache";
const std::string DEPRECATED_ARK_PROFILE_PATH = "/data/local/ark-profile";
const std::string PGO_FILE_PATH = "pgo_files";
const std::string VERIFY_FILE_SUFFIX = ".abc";
const std::string FRAMEWORK_ARK_CACHE_PATH = "framework_ark_cache/";
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

/**
 * @tc.number: IsValidPathByCopyFileScene_0100
 * @tc.name: test IsValidPathByCopyFileScene
 * @tc.desc: test IsValidPathByCopyFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByCopyFileScene_0100, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsValidPathByCopyFileScene(
        ServiceConstants::RELATIVE_PATH, ServiceConstants::RELATIVE_PATH, BundleDirScene::COPY_PGO_FILE);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByCopyFileScene(
        ServiceConstants::RELATIVE_PATH, TEST_BUNDLE_PATCH, BundleDirScene::COPY_PGO_FILE);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByCopyFileScene(
        TEST_BUNDLE_PATCH, ServiceConstants::RELATIVE_PATH, BundleDirScene::COPY_PGO_FILE);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByCopyFileScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_PATCH, BundleDirScene::COPY_PGO_FILE);
    EXPECT_FALSE(ret);

    std::string oldPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                          PGO_FILE_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                          ServiceConstants::PGO_FILE_SUFFIX;
    ret = InstalldOperator::IsValidPathByCopyFileScene(oldPath, TEST_BUNDLE_PATCH, BundleDirScene::COPY_PGO_FILE);
    EXPECT_FALSE(ret);

    std::string newPath =
        std::string(APP_EL1_PATH) + ARK_PROFILE_PATH + TEST_STRING + ServiceConstants::PGO_FILE_SUFFIX;
    ret = InstalldOperator::IsValidPathByCopyFileScene(oldPath, newPath, BundleDirScene::COPY_PGO_FILE);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirScene_0100
 * @tc.name: test IsValidPathByRemoveDirScene
 * @tc.desc: test IsValidPathByRemoveDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirScene_0100, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsValidPathByRemoveDirScene(
        ServiceConstants::RELATIVE_PATH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_CODE_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_CODE_DIR);
    EXPECT_TRUE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_MODULE_DIR);
    EXPECT_TRUE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_AOT_ARK_CACHE_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_HNP_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BMS_BUNDLE_LIB_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BMS_BUNDLE_TEMP_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SCREEN_LOCK_DATA_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_AOT_ARK_PROFILE_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_LIB_DIR);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirScene_0200
 * @tc.name: test IsValidPathByRemoveDirScene
 * @tc.desc: test IsValidPathByRemoveDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirScene_0200, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_ARK_START_UP_CACHE_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_LOCAL_SHADER_CACHE_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SHARE_FILE_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_CLOUD_SHADER_CACHE_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_PLUGIN_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_ARK_AP_FILE);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_EXTEND_RESOURCE_FILE);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_QUICK_FIX_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SKILL_MODULE_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SKILL_BUNDLE_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_VERIFY_FILE);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirScene_0300
 * @tc.name: test IsValidPathByRemoveDirScene
 * @tc.desc: test IsValidPathByRemoveDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirScene_0300, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_PRELOAD_APP_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_ASAN_LOG_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_GALLERY_DOWNLOAD_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_ENTERPRISE_CERT_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SYSTEM_OPTIMIZE_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_LOCAL_ARK_CACHE_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_LOCAL_ARK_PROFILE_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SYSTEM_SERVICE_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_QUICK_FIX_FILE);
    EXPECT_TRUE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SECURITY_QUICK_FIX_DIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPathByRemoveDirScene(
        TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SANDBOX_DATA_DIR);
    EXPECT_FALSE(ret);
    ret =
        InstalldOperator::IsValidPathByRemoveDirScene(TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME, BundleDirScene::SET_DIR_APL);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsContainsPathPart_0100
 * @tc.name: test IsContainsPathPart
 * @tc.desc: test IsContainsPathPart of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsContainsPathPart_0100, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsContainsPathPart(ServiceConstants::RELATIVE_PATH, TEST_STRING);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsContainsPathPart(ServiceConstants::RELATIVE_PATH, ServiceConstants::RELATIVE_PATH);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsContainsPathPart(TEST_BUNDLE_PATCH, ServiceConstants::RELATIVE_PATH);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsContainsPathPart(TEST_BUNDLE_PATCH, TEST_STRING);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsContainsPathPart(TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsContainsBundleName_0100
 * @tc.name: test IsContainsBundleName
 * @tc.desc: test IsContainsBundleName of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsContainsBundleName_0100, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsContainsBundleName(ServiceConstants::RELATIVE_PATH, TEST_BUNDLE_NAME);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsContainsBundleName(TEST_BUNDLE_PATCH, TEST_STRING);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsContainsBundleName(TEST_BUNDLE_PATCH, TEST_BUNDLE_NAME);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidSourcePathByCopyVerifyFile_0100
 * @tc.name: test IsValidSourcePathByCopyVerifyFile
 * @tc.desc: test IsValidSourcePathByCopyVerifyFile of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidSourcePathByCopyVerifyFile_0100, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsValidSourcePathByCopyVerifyFile(ServiceConstants::RELATIVE_PATH);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidSourcePathByCopyVerifyFile(TEST_STRING);
    EXPECT_FALSE(ret);
    std::string sourcePath = TEST_STRING + VERIFY_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyVerifyFile(sourcePath);
    EXPECT_FALSE(ret);
    sourcePath = TEST_BUNDLE_PATCH + TEST_STRING + VERIFY_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyVerifyFile(sourcePath);
    EXPECT_TRUE(ret);
    sourcePath = std::string(APP_EL1_PATH) + ServiceConstants::BASE + TEST_STRING + VERIFY_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyVerifyFile(sourcePath);
    EXPECT_TRUE(ret);
    sourcePath = std::string(APP_EL1_PATH) + ServiceConstants::DATABASE + TEST_STRING + VERIFY_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyVerifyFile(sourcePath);
    EXPECT_TRUE(ret);
    sourcePath = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING + VERIFY_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyVerifyFile(sourcePath);
    EXPECT_FALSE(ret);
    sourcePath = std::string(APP_EL2_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING + VERIFY_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyVerifyFile(sourcePath);
    EXPECT_FALSE(ret);
    sourcePath = std::string(APP_EL2_PATH) + ServiceConstants::BASE + TEST_STRING + VERIFY_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyVerifyFile(sourcePath);
    EXPECT_TRUE(ret);
    sourcePath = std::string(APP_EL2_PATH) + ServiceConstants::DATABASE + TEST_STRING + VERIFY_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyVerifyFile(sourcePath);
    EXPECT_TRUE(ret);
    sourcePath = std::string(APP_EL3_PATH) + ServiceConstants::DATABASE + TEST_STRING + VERIFY_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyVerifyFile(sourcePath);
    EXPECT_TRUE(ret);
    sourcePath = std::string(APP_EL4_PATH) + ServiceConstants::DATABASE + TEST_STRING + VERIFY_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyVerifyFile(sourcePath);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidSourcePathByCopyFileScene_0100
 * @tc.name: test IsValidSourcePathByCopyFileScene
 * @tc.desc: test IsValidSourcePathByCopyFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidSourcePathByCopyFileScene_0100, Function | SmallTest | Level0)
{
    std::string sourcePath = std::string(ServiceConstants::RELATIVE_PATH);
    auto ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_PGO_FILE);
    EXPECT_FALSE(ret);

    sourcePath = TEST_BUNDLE_PATCH + PGO_FILE_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::PGO_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_PGO_FILE);
    EXPECT_FALSE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::PGO_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_PGO_FILE);
    EXPECT_FALSE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + PGO_FILE_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_PGO_FILE);
    EXPECT_FALSE(ret);

    sourcePath =
        std::string(ServiceConstants::HAP_COPY_PATH) + PGO_FILE_PATH + TEST_STRING + ServiceConstants::PGO_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_PGO_FILE);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidSourcePathByCopyFileScene_0200
 * @tc.name: test IsValidSourcePathByCopyFileScene
 * @tc.desc: test IsValidSourcePathByCopyFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidSourcePathByCopyFileScene_0200, Function | SmallTest | Level0)
{
    std::string sourcePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_HAP_TO_INSTALL_PATH);
    EXPECT_FALSE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_HAP_TO_INSTALL_PATH);
    EXPECT_FALSE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::INSTALL_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_HAP_TO_INSTALL_PATH);
    EXPECT_TRUE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_HAP_TO_INSTALL_PATH);
    EXPECT_TRUE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                 ServiceConstants::EXT_RESOURCE_FILE_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_EXTEND_RESOURCE_FILE);
    EXPECT_FALSE(ret);

    sourcePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_EXTEND_RESOURCE_FILE);
    EXPECT_FALSE(ret);

    sourcePath =
        TEST_BUNDLE_PATCH + ServiceConstants::EXT_RESOURCE_FILE_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_EXTEND_RESOURCE_FILE);
    EXPECT_FALSE(ret);

    sourcePath = TEST_BUNDLE_PATCH + ServiceConstants::EXT_RESOURCE_FILE_PATH + ServiceConstants::PATH_SEPARATOR +
                 TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_EXTEND_RESOURCE_FILE);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidSourcePathByCopyFileScene_0300
 * @tc.name: test IsValidSourcePathByCopyFileScene
 * @tc.desc: test IsValidSourcePathByCopyFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidSourcePathByCopyFileScene_0300, Function | SmallTest | Level0)
{
    std::string sourcePath = TEST_BUNDLE_PATCH + ServiceConstants::EXT_PROFILE;
    auto ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_EXTEND_PROFILE_FILE);
    EXPECT_FALSE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_EXTEND_PROFILE_FILE);
    EXPECT_FALSE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                 ServiceConstants::EXT_PROFILE + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_EXTEND_PROFILE_FILE);
    EXPECT_TRUE(ret);

    sourcePath = std::string(APP_EL2_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_HAP_TO_TEMP_PATH);
    EXPECT_FALSE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_HAP_TO_TEMP_PATH);
    EXPECT_FALSE(ret);

    sourcePath = std::string(APP_EL2_PATH) + ServiceConstants::BASE + TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_HAP_TO_TEMP_PATH);
    EXPECT_TRUE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::GALLERY_DOWNLOAD_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_HAP_TO_TEMP_PATH);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidSourcePathByCopyFileScene_0400
 * @tc.name: test IsValidSourcePathByCopyFileScene
 * @tc.desc: test IsValidSourcePathByCopyFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidSourcePathByCopyFileScene_0400, Function | SmallTest | Level0)
{
    std::string sourcePath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ARK_PROFILE_PATH + TEST_STRING + ServiceConstants::AP_SUFFIX;
    auto ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_AP_FILE);
    EXPECT_FALSE(ret);

    sourcePath =
        std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING + ServiceConstants::AP_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_AP_FILE);
    EXPECT_FALSE(ret);

    sourcePath = std::string(APP_EL1_PATH) + ARK_PROFILE_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_AP_FILE);
    EXPECT_FALSE(ret);

    sourcePath = std::string(APP_EL1_PATH) + ARK_PROFILE_PATH + TEST_STRING + ServiceConstants::AP_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_AP_FILE);
    EXPECT_TRUE(ret);

    sourcePath = TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_SERVICE_HSP);
    EXPECT_FALSE(ret);

    sourcePath = TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_SERVICE_HSP);
    EXPECT_TRUE(ret);

    sourcePath = TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_SKILL_HSP);
    EXPECT_FALSE(ret);

    sourcePath = TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_SKILL_HSP);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidSourcePathByCopyFileScene_0500
 * @tc.name: test IsValidSourcePathByCopyFileScene
 * @tc.desc: test IsValidSourcePathByCopyFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidSourcePathByCopyFileScene_0500, Function | SmallTest | Level0)
{
    std::string sourcePath = TEST_BUNDLE_PATCH + ServiceConstants::SECURITY_STREAM_INSTALL_PATH +
                             ServiceConstants::PATH_SEPARATOR + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_PLUGIN_HSP);
    EXPECT_FALSE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_PLUGIN_HSP);
    EXPECT_FALSE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                 ServiceConstants::SECURITY_STREAM_INSTALL_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_PLUGIN_HSP);
    EXPECT_FALSE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                 ServiceConstants::SECURITY_STREAM_INSTALL_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_PLUGIN_HSP);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_SHARED_HSP);
    EXPECT_TRUE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                 ServiceConstants::SECURITY_QUICK_FIX_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_HQF_FILE);
    EXPECT_FALSE(ret);

    sourcePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                 ServiceConstants::SECURITY_QUICK_FIX_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::QUICK_FIX_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_HQF_FILE);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidSourcePathByCopyFileScene_0600
 * @tc.name: test IsValidSourcePathByCopyFileScene
 * @tc.desc: test IsValidSourcePathByCopyFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidSourcePathByCopyFileScene_0600, Function | SmallTest | Level0)
{
    std::string sourcePath = TEST_STRING;
    auto ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_ABC_FILE);
    EXPECT_FALSE(ret);

    sourcePath = TEST_STRING + VERIFY_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_ABC_FILE);
    EXPECT_FALSE(ret);

    sourcePath = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING + VERIFY_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_ABC_FILE);
    EXPECT_FALSE(ret);

    sourcePath = TEST_BUNDLE_PATCH + VERIFY_FILE_PATH + TEST_STRING + VERIFY_FILE_SUFFIX;
    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::COPY_ABC_FILE);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidSourcePathByCopyFileScene(sourcePath, BundleDirScene::SET_DIR_APL);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidTargetPathByCopyFileScene_0100
 * @tc.name: test IsValidTargetPathByCopyFileScene
 * @tc.desc: test IsValidTargetPathByCopyFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidTargetPathByCopyFileScene_0100, Function | SmallTest | Level0)
{
    std::string targetPath = std::string(ServiceConstants::RELATIVE_PATH);
    auto ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_PGO_FILE);
    EXPECT_FALSE(ret);

    targetPath = std::string(ServiceConstants::HAP_COPY_PATH) + ARK_PROFILE_PATH + TEST_STRING +
                             ServiceConstants::PGO_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_PGO_FILE);
    EXPECT_FALSE(ret);

    targetPath =
        std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING + ServiceConstants::PGO_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_PGO_FILE);
    EXPECT_FALSE(ret);

    targetPath = std::string(APP_EL1_PATH) + ARK_PROFILE_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_PGO_FILE);
    EXPECT_FALSE(ret);

    targetPath = std::string(APP_EL1_PATH) + ARK_PROFILE_PATH + TEST_STRING + ServiceConstants::PGO_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_PGO_FILE);
    EXPECT_TRUE(ret);

    targetPath = ServiceConstants::HAP_COPY_PATH;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_HAP_TO_TEMP_PATH);
    EXPECT_TRUE(ret);

    targetPath = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_HAP_TO_TEMP_PATH);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidTargetPathByCopyFileScene_0200
 * @tc.name: test IsValidTargetPathByCopyFileScene
 * @tc.desc: test IsValidTargetPathByCopyFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidTargetPathByCopyFileScene_0200, Function | SmallTest | Level0)
{
    std::string targetPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                             TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_HAP_TO_INSTALL_PATH);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_HAP_TO_INSTALL_PATH);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_HAP_TO_INSTALL_PATH);
    EXPECT_TRUE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_HAP_TO_INSTALL_PATH);
    EXPECT_TRUE(ret);

    targetPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::EXT_RESOURCE_FILE_PATH +
                 ServiceConstants::PATH_SEPARATOR + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_EXTEND_RESOURCE_FILE);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_EXTEND_RESOURCE_FILE);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + ServiceConstants::EXT_RESOURCE_FILE_PATH + ServiceConstants::PATH_SEPARATOR +
                 TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_EXTEND_RESOURCE_FILE);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidTargetPathByCopyFileScene_0300
 * @tc.name: test IsValidTargetPathByCopyFileScene
 * @tc.desc: test IsValidTargetPathByCopyFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidTargetPathByCopyFileScene_0300, Function | SmallTest | Level0)
{
    std::string targetPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::EXT_PROFILE +
                             ServiceConstants::PATH_SEPARATOR + ServiceConstants::MANIFEST_JSON;
    auto ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_EXTEND_PROFILE_FILE);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::PATH_SEPARATOR + ServiceConstants::MANIFEST_JSON;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_EXTEND_PROFILE_FILE);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + ServiceConstants::EXT_PROFILE + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_EXTEND_PROFILE_FILE);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + ServiceConstants::EXT_PROFILE + ServiceConstants::PATH_SEPARATOR +
                 ServiceConstants::MANIFEST_JSON;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_EXTEND_PROFILE_FILE);
    EXPECT_TRUE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::AP_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_AP_FILE);
    EXPECT_FALSE(ret);

    targetPath = PGO_DIR_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_AP_FILE);
    EXPECT_FALSE(ret);

    targetPath = PGO_DIR_PATH + TEST_STRING + ServiceConstants::AP_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_AP_FILE);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidTargetPathByCopyFileScene_0400
 * @tc.name: test IsValidTargetPathByCopyFileScene
 * @tc.desc: test IsValidTargetPathByCopyFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidTargetPathByCopyFileScene_0400, Function | SmallTest | Level0)
{
    std::string targetPath = TEST_BUNDLE_PATCH + TEST_STRING;
    auto ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_SERVICE_HSP);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_SERVICE_HSP);
    EXPECT_TRUE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_SHARED_HSP);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_SHARED_HSP);
    EXPECT_TRUE(ret);

    targetPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PLUGIN_FILE_PATH +
                 ServiceConstants::PATH_SEPARATOR + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_PLUGIN_HSP);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_PLUGIN_HSP);
    EXPECT_FALSE(ret);

    targetPath =
        TEST_BUNDLE_PATCH + ServiceConstants::PLUGIN_FILE_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_PLUGIN_HSP);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + ServiceConstants::PLUGIN_FILE_PATH + ServiceConstants::PATH_SEPARATOR +
                 TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_PLUGIN_HSP);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidTargetPathByCopyFileScene_0500
 * @tc.name: test IsValidTargetPathByCopyFileScene
 * @tc.desc: test IsValidTargetPathByCopyFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidTargetPathByCopyFileScene_0500, Function | SmallTest | Level0)
{
    std::string targetPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATCH_PATH + TEST_STRING +
                             ServiceConstants::QUICK_FIX_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_HQF_FILE);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::QUICK_FIX_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_HQF_FILE);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + ServiceConstants::PATCH_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_HQF_FILE);
    EXPECT_FALSE(ret);

    targetPath =
        TEST_BUNDLE_PATCH + ServiceConstants::PATCH_PATH + TEST_STRING + ServiceConstants::QUICK_FIX_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_HQF_FILE);
    EXPECT_TRUE(ret);

    targetPath =
        TEST_BUNDLE_PATCH + ServiceConstants::HOT_RELOAD_PATH + TEST_STRING + ServiceConstants::QUICK_FIX_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_HQF_FILE);
    EXPECT_TRUE(ret);

    targetPath = TEST_BUNDLE_PATCH + "patch" + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::QUICK_FIX_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_HQF_FILE);
    EXPECT_TRUE(ret);

    targetPath = BASE_SKILL_DIR + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_SKILL_HSP);
    EXPECT_FALSE(ret);

    targetPath = BASE_SKILL_DIR + ServiceConstants::PATH_SEPARATOR + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_SKILL_HSP);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidTargetPathByCopyFileScene_0600
 * @tc.name: test IsValidTargetPathByCopyFileScene
 * @tc.desc: test IsValidTargetPathByCopyFileScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidTargetPathByCopyFileScene_0600, Function | SmallTest | Level0)
{
    std::string targetPath =
        std::string(ServiceConstants::HAP_COPY_PATH) + VERIFY_FILE_PATH + TEST_STRING + VERIFY_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_ABC_FILE);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING + VERIFY_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_ABC_FILE);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + VERIFY_FILE_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_ABC_FILE);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + VERIFY_FILE_PATH + TEST_STRING + VERIFY_FILE_SUFFIX;
    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::COPY_ABC_FILE);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidTargetPathByCopyFileScene(targetPath, BundleDirScene::SET_DIR_APL);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNeedBundleNamePartOne_0100
 * @tc.name: test IsValidPathByRemoveDirSceneNeedBundleNamePartOne
 * @tc.desc: test IsValidPathByRemoveDirSceneNeedBundleNamePartOne of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNeedBundleNamePartOne_0100, Function | SmallTest | Level0)
{
    std::string dir = ServiceConstants::RELATIVE_PATH;
    auto ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_CODE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_CODE_DIR);
    EXPECT_FALSE(ret);

    dir = TEST_BUNDLE_PATCH;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_CODE_DIR);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_MODULE_DIR);
    EXPECT_TRUE(ret);

    dir = TEST_BUNDLE_PATCH + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_STRING, BundleDirScene::REMOVE_BUNDLE_CODE_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNeedBundleNamePartOne_0200
 * @tc.name: test IsValidPathByRemoveDirSceneNeedBundleNamePartOne
 * @tc.desc: test IsValidPathByRemoveDirSceneNeedBundleNamePartOne of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNeedBundleNamePartOne_0200, Function | SmallTest | Level0)
{
    std::string dir = std::string(ServiceConstants::HAP_ARK_CACHE_PATH) + TEST_BUNDLE_NAME;
    auto ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_AOT_ARK_CACHE_DIR);
    EXPECT_TRUE(ret);

    dir = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_HNP_DIR);
    EXPECT_FALSE(ret);

    dir = TEST_BUNDLE_PATCH + ServiceConstants::HNPS_FILE_PATH;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_HNP_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNeedBundleNamePartOne_0300
 * @tc.name: test IsValidPathByRemoveDirSceneNeedBundleNamePartOne
 * @tc.desc: test IsValidPathByRemoveDirSceneNeedBundleNamePartOne of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNeedBundleNamePartOne_0300, Function | SmallTest | Level0)
{
    std::string dir = TEST_BUNDLE_PATCH + ServiceConstants::LIBS;
    auto ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BMS_BUNDLE_LIB_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME +
          ServiceConstants::PATH_SEPARATOR + ServiceConstants::LIBS;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BMS_BUNDLE_LIB_DIR);
    EXPECT_TRUE(ret);

    dir = TEST_BUNDLE_PATCH;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BMS_BUNDLE_TEMP_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME +
          ServiceConstants::TMP_SUFFIX;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BMS_BUNDLE_TEMP_DIR);
    EXPECT_TRUE(ret);

    dir = std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
          ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SCREEN_LOCK_DATA_DIR);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNeedBundleNamePartOne_0400
 * @tc.name: test IsValidPathByRemoveDirSceneNeedBundleNamePartOne
 * @tc.desc: test IsValidPathByRemoveDirSceneNeedBundleNamePartOne of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNeedBundleNamePartOne_0400, Function | SmallTest | Level0)
{
    std::string dir =
        std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) + ServiceConstants::BASE + TEST_BUNDLE_NAME;
    auto ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SCREEN_LOCK_DATA_DIR);
    EXPECT_TRUE(ret);

    dir = std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) + ServiceConstants::DATABASE + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SCREEN_LOCK_DATA_DIR);
    EXPECT_TRUE(ret);

    dir = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_AOT_ARK_PROFILE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + ARK_PROFILE_PATH + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_AOT_ARK_PROFILE_DIR);
    EXPECT_TRUE(ret);

    dir = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_LIB_DIR);
    EXPECT_FALSE(ret);

    dir = TEST_BUNDLE_PATCH + ServiceConstants::LIBS;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_LIB_DIR);
    EXPECT_TRUE(ret);

    dir = TEST_BUNDLE_PATCH + LIBS_TMP_DIR;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartOne(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_LIB_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNeedBundleNamePartTwo_0100
 * @tc.name: test IsValidPathByRemoveDirSceneNeedBundleNamePartTwo
 * @tc.desc: test IsValidPathByRemoveDirSceneNeedBundleNamePartTwo of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNeedBundleNamePartTwo_0100, Function | SmallTest | Level0)
{
    std::string dir = ServiceConstants::RELATIVE_PATH;
    auto ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_ARK_START_UP_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_ARK_START_UP_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_ARK_START_UP_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + SYSTEM_OPTIMIZE_DIR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_ARK_START_UP_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + SYSTEM_OPTIMIZE_DIR + ServiceConstants::ARK_STARTUP_CACHE_DIR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_ARK_START_UP_CACHE_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNeedBundleNamePartTwo_0200
 * @tc.name: test IsValidPathByRemoveDirSceneNeedBundleNamePartTwo
 * @tc.desc: test IsValidPathByRemoveDirSceneNeedBundleNamePartTwo of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNeedBundleNamePartTwo_0200, Function | SmallTest | Level0)
{
    std::string dir = std::string(ServiceConstants::SHADER_CACHE_PATH) + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_LOCAL_SHADER_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_LOCAL_SHADER_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::SHADER_CACHE_PATH) + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_LOCAL_SHADER_CACHE_DIR);
    EXPECT_TRUE(ret);

    dir = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SHARE_FILE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL2_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SHARE_FILE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL2_PATH) + ServiceConstants::SHAREFILES + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SHARE_FILE_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNeedBundleNamePartTwo_0300
 * @tc.name: test IsValidPathByRemoveDirSceneNeedBundleNamePartTwo
 * @tc.desc: test IsValidPathByRemoveDirSceneNeedBundleNamePartTwo of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNeedBundleNamePartTwo_0300, Function | SmallTest | Level0)
{
    std::string dir = std::string(ServiceConstants::SHADER_CACHE_PATH) + TEST_BUNDLE_NAME;
    auto ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_CLOUD_SHADER_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::NEW_CLOUD_SHADER_PATH) + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_CLOUD_SHADER_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::NEW_CLOUD_SHADER_PATH) + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_CLOUD_SHADER_CACHE_DIR);
    EXPECT_TRUE(ret);

    dir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PLUGIN_FILE_PATH +
          ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_PLUGIN_DIR);
    EXPECT_FALSE(ret);

    dir = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_PLUGIN_DIR);
    EXPECT_FALSE(ret);

    dir = TEST_BUNDLE_PATCH + ServiceConstants::PLUGIN_FILE_PATH;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_BUNDLE_PLUGIN_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNeedBundleNamePartTwo_0400
 * @tc.name: test IsValidPathByRemoveDirSceneNeedBundleNamePartTwo
 * @tc.desc: test IsValidPathByRemoveDirSceneNeedBundleNamePartTwo of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNeedBundleNamePartTwo_0400, Function | SmallTest | Level0)
{
    std::string dir = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    auto ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_ARK_AP_FILE);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + ARK_PROFILE_PATH + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_ARK_AP_FILE);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + ARK_PROFILE_PATH + TEST_BUNDLE_NAME + ServiceConstants::PGO_FILE_SUFFIX;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_ARK_AP_FILE);
    EXPECT_TRUE(ret);

    dir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::EXT_RESOURCE_FILE_PATH +
          ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_EXTEND_RESOURCE_FILE);
    EXPECT_FALSE(ret);

    dir = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_EXTEND_RESOURCE_FILE);
    EXPECT_FALSE(ret);

    dir = TEST_BUNDLE_PATCH + ServiceConstants::EXT_RESOURCE_FILE_PATH;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_EXTEND_RESOURCE_FILE);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNeedBundleNamePartTwo_0500
 * @tc.name: test IsValidPathByRemoveDirSceneNeedBundleNamePartTwo
 * @tc.desc: test IsValidPathByRemoveDirSceneNeedBundleNamePartTwo of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNeedBundleNamePartTwo_0500, Function | SmallTest | Level0)
{
    std::string dir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATCH_PATH + TEST_BUNDLE_NAME;
    auto ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_QUICK_FIX_DIR);
    EXPECT_FALSE(ret);

    dir = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_QUICK_FIX_DIR);
    EXPECT_FALSE(ret);

    dir = TEST_BUNDLE_PATCH + ServiceConstants::PATCH_PATH + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_QUICK_FIX_DIR);
    EXPECT_TRUE(ret);

    dir = TEST_BUNDLE_PATCH + ServiceConstants::HOT_RELOAD_PATH + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_QUICK_FIX_DIR);
    EXPECT_TRUE(ret);

    dir = TEST_BUNDLE_PATCH + HQF_PATCH_PATH + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_QUICK_FIX_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNeedBundleNamePartTwo_0600
 * @tc.name: test IsValidPathByRemoveDirSceneNeedBundleNamePartTwo
 * @tc.desc: test IsValidPathByRemoveDirSceneNeedBundleNamePartTwo of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNeedBundleNamePartTwo_0600, Function | SmallTest | Level0)
{
    std::string dir = TEST_BUNDLE_PATCH + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SKILL_MODULE_DIR);
    EXPECT_FALSE(ret);

    dir = BASE_SKILL_DIR + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SKILL_MODULE_DIR);
    EXPECT_FALSE(ret);

    dir = BASE_SKILL_DIR + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SKILL_MODULE_DIR);
    EXPECT_TRUE(ret);

    dir = BASE_SKILL_DIR + ServiceConstants::PATH_SEPARATOR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_SKILL_BUNDLE_DIR);
    EXPECT_TRUE(ret);

    dir = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_VERIFY_FILE);
    EXPECT_FALSE(ret);

    dir = TEST_BUNDLE_PATCH + VERIFY_FILE_PATH;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_VERIFY_FILE);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNeedBundleNamePartTwo_0700
 * @tc.name: test IsValidPathByRemoveDirSceneNeedBundleNamePartTwo
 * @tc.desc: test IsValidPathByRemoveDirSceneNeedBundleNamePartTwo for REMOVE_NPAPI_PLUGIN_DIR
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNeedBundleNamePartTwo_0700, Function | SmallTest | Level0)
{
    std::string dir = TEST_BUNDLE_PATCH + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_NPAPI_PLUGIN_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::NPAPI_PLUGIN_TARGET_BASE_PATH) + "100" +
          ServiceConstants::NPAPI_PLUGIN_TARGET_DIR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_NPAPI_PLUGIN_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::NPAPI_PLUGIN_TARGET_BASE_PATH) + "100" +
          ServiceConstants::NPAPI_PLUGIN_TARGET_DIR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_NPAPI_PLUGIN_DIR);
    EXPECT_TRUE(ret);

    dir = std::string(ServiceConstants::NPAPI_PLUGIN_TARGET_BASE_PATH) + "200" +
          ServiceConstants::NPAPI_PLUGIN_TARGET_DIR + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_NPAPI_PLUGIN_DIR);
    EXPECT_TRUE(ret);

    dir = std::string("/storage/media/") + "100" + "/local/files/Docs/Download/.mozilla/plugins/" + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_NPAPI_PLUGIN_DIR);
    EXPECT_TRUE(ret);

    dir = std::string("/invalid/path/") + TEST_BUNDLE_NAME;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNeedBundleNamePartTwo(
        dir, TEST_BUNDLE_NAME, BundleDirScene::REMOVE_NPAPI_PLUGIN_DIR);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNoBundleName_0100
 * @tc.name: test IsValidPathByRemoveDirSceneNoBundleName
 * @tc.desc: test IsValidPathByRemoveDirSceneNoBundleName of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNoBundleName_0100, Function | SmallTest | Level0)
{
    std::string dir = ServiceConstants::RELATIVE_PATH;
    auto ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_PRELOAD_APP_DIR);
    EXPECT_FALSE(ret);

    dir = TEST_BUNDLE_PATCH;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_PRELOAD_APP_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::DATA_PRELOAD_APP) + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_PRELOAD_APP_DIR);
    EXPECT_TRUE(ret);

    dir = TEST_BUNDLE_PATCH;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_ASAN_LOG_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::BUNDLE_ASAN_LOG_DIR) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_ASAN_LOG_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNoBundleName_0200
 * @tc.name: test IsValidPathByRemoveDirSceneNoBundleName
 * @tc.desc: test IsValidPathByRemoveDirSceneNoBundleName of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNoBundleName_0200, Function | SmallTest | Level0)
{
    std::string dir = TEST_BUNDLE_PATCH + ServiceConstants::GALLERY_DOWNLOAD_PATH;
    auto ret =
        InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_GALLERY_DOWNLOAD_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_GALLERY_DOWNLOAD_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::GALLERY_DOWNLOAD_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_GALLERY_DOWNLOAD_DIR);
    EXPECT_TRUE(ret);

    dir = TEST_BUNDLE_PATCH + ServiceConstants::ENTERPRISE_CERT_PATH;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_ENTERPRISE_CERT_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_ENTERPRISE_CERT_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::ENTERPRISE_CERT_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_ENTERPRISE_CERT_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNoBundleName_0300
 * @tc.name: test IsValidPathByRemoveDirSceneNoBundleName
 * @tc.desc: test IsValidPathByRemoveDirSceneNoBundleName of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNoBundleName_0300, Function | SmallTest | Level0)
{
    std::string dir = SYSTEM_OPTIMIZE_DIR + TEST_STRING;
    auto ret =
        InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_SYSTEM_OPTIMIZE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_SYSTEM_OPTIMIZE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + SYSTEM_OPTIMIZE_DIR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_SYSTEM_OPTIMIZE_DIR);
    EXPECT_TRUE(ret);

    dir = TEST_BUNDLE_PATCH;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_LOCAL_ARK_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = DEPRECATED_ARK_CACHE_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_LOCAL_ARK_CACHE_DIR);
    EXPECT_TRUE(ret);

    dir = DEPRECATED_ARK_PROFILE_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_LOCAL_ARK_PROFILE_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNoBundleName_0400
 * @tc.name: test IsValidPathByRemoveDirSceneNoBundleName
 * @tc.desc: test IsValidPathByRemoveDirSceneNoBundleName of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNoBundleName_0400, Function | SmallTest | Level0)
{
    std::string dir = TEST_BUNDLE_PATCH;
    auto ret =
        InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_SYSTEM_SERVICE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::SYSTEM_SERVICE_DIR) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_SYSTEM_SERVICE_DIR);
    EXPECT_TRUE(ret);

    dir = TEST_BUNDLE_PATCH;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_QUICK_FIX_FILE);
    EXPECT_TRUE(ret);

    dir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::SECURITY_QUICK_FIX_PATH;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_SECURITY_QUICK_FIX_DIR);
    EXPECT_TRUE(ret);

    dir = TEST_BUNDLE_PATCH + ServiceConstants::SECURITY_QUICK_FIX_PATH;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_SECURITY_QUICK_FIX_DIR);
    EXPECT_FALSE(ret);

    dir = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::SET_DIR_APL);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByRemoveDirSceneNoBundleName_0500
 * @tc.name: test IsValidPathByRemoveDirSceneNoBundleName
 * @tc.desc: test IsValidPathByRemoveDirSceneNoBundleName of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRemoveDirSceneNoBundleName_0500, Function | SmallTest | Level0)
{
    std::string dir = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_SANDBOX_DATA_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + ServiceConstants::BASE + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_SANDBOX_DATA_DIR);
    EXPECT_TRUE(ret);

    dir = std::string(APP_EL2_PATH) + ServiceConstants::DATABASE + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_SANDBOX_DATA_DIR);
    EXPECT_TRUE(ret);

    dir = std::string(APP_EL3_PATH) + ServiceConstants::BASE + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_SANDBOX_DATA_DIR);
    EXPECT_TRUE(ret);

    dir = std::string(APP_EL4_PATH) + ServiceConstants::DATABASE + TEST_STRING;
    ret = InstalldOperator::IsValidPathByRemoveDirSceneNoBundleName(dir, BundleDirScene::REMOVE_SANDBOX_DATA_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByMoveHapToCodeDir_0100
 * @tc.name: test IsValidPathByMoveHapToCodeDir
 * @tc.desc: test IsValidPathByMoveHapToCodeDir of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMoveHapToCodeDir_0100, Function | SmallTest | Level0)
{
    std::string originPath = ServiceConstants::RELATIVE_PATH;
    std::string targetPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidPathByMoveHapToCodeDir(originPath, targetPath);
    EXPECT_FALSE(ret);

    originPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::INSTALL_FILE_SUFFIX;
    targetPath = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByMoveHapToCodeDir(originPath, targetPath);
    EXPECT_FALSE(ret);

    originPath = ServiceConstants::RELATIVE_PATH;
    targetPath = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByMoveHapToCodeDir(originPath, targetPath);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByMoveHapToCodeDir_0200
 * @tc.name: test IsValidPathByMoveHapToCodeDir
 * @tc.desc: test IsValidPathByMoveHapToCodeDir of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMoveHapToCodeDir_0200, Function | SmallTest | Level0)
{
    std::string originPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    std::string targetPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                             TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidPathByMoveHapToCodeDir(originPath, targetPath);
    EXPECT_FALSE(ret);

    originPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    targetPath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::INSTALL_FILE_SUFFIX;
    ret = InstalldOperator::IsValidPathByMoveHapToCodeDir(originPath, targetPath);
    EXPECT_FALSE(ret);

    originPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::INSTALL_FILE_SUFFIX;
    targetPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::INSTALL_FILE_SUFFIX;
    ret = InstalldOperator::IsValidPathByMoveHapToCodeDir(originPath, targetPath);
    EXPECT_FALSE(ret);

    originPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::INSTALL_FILE_SUFFIX;
    targetPath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::INSTALL_FILE_SUFFIX;
    ret = InstalldOperator::IsValidPathByMoveHapToCodeDir(originPath, targetPath);
    EXPECT_TRUE(ret);

    originPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::HSP_FILE_SUFFIX;
    targetPath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidPathByMoveHapToCodeDir(originPath, targetPath);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByMoveHapToCodeDir_0300
 * @tc.name: test IsValidPathByMoveHapToCodeDir
 * @tc.desc: test IsValidPathByMoveHapToCodeDir of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMoveHapToCodeDir_0300, Function | SmallTest | Level0)
{
    std::string originPath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    std::string targetPath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                             ServiceConstants::INSTALL_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidPathByMoveHapToCodeDir(originPath, targetPath);
    EXPECT_FALSE(ret);

    originPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                 ServiceConstants::INSTALL_FILE_SUFFIX;
    targetPath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByMoveHapToCodeDir(originPath, targetPath);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByExtractDiffFiles_0100
 * @tc.name: test IsValidPathByExtractDiffFiles
 * @tc.desc: test IsValidPathByExtractDiffFiles of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByExtractDiffFiles_0100, Function | SmallTest | Level0)
{
    std::string filePath = ServiceConstants::RELATIVE_PATH;
    std::string targetPath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByExtractDiffFiles(filePath, targetPath);
    EXPECT_FALSE(ret);

    filePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
               ServiceConstants::QUICK_FIX_FILE_SUFFIX;
    targetPath = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByExtractDiffFiles(filePath, targetPath);
    EXPECT_FALSE(ret);

    filePath = ServiceConstants::RELATIVE_PATH;
    targetPath = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByExtractDiffFiles(filePath, targetPath);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByExtractDiffFiles_0200
 * @tc.name: test IsValidPathByExtractDiffFiles
 * @tc.desc: test IsValidPathByExtractDiffFiles of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByExtractDiffFiles_0200, Function | SmallTest | Level0)
{
    std::string filePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::QUICK_FIX_FILE_SUFFIX;
    std::string targetPath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByExtractDiffFiles(filePath, targetPath);
    EXPECT_TRUE(ret);

    filePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
               ServiceConstants::QUICK_FIX_FILE_SUFFIX;
    ret = InstalldOperator::IsValidPathByExtractDiffFiles(filePath, targetPath);
    EXPECT_FALSE(ret);

    filePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
               ServiceConstants::SECURITY_QUICK_FIX_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByExtractDiffFiles(filePath, targetPath);
    EXPECT_FALSE(ret);

    filePath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByExtractDiffFiles(filePath, targetPath);
    EXPECT_FALSE(ret);

    filePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
               ServiceConstants::SECURITY_QUICK_FIX_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
               ServiceConstants::QUICK_FIX_FILE_SUFFIX;
    ret = InstalldOperator::IsValidPathByExtractDiffFiles(filePath, targetPath);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByExtractDiffFiles_0300
 * @tc.name: test IsValidPathByExtractDiffFiles
 * @tc.desc: test IsValidPathByExtractDiffFiles of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByExtractDiffFiles_0300, Function | SmallTest | Level0)
{
    std::string filePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                           ServiceConstants::SECURITY_QUICK_FIX_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
                           ServiceConstants::QUICK_FIX_FILE_SUFFIX;
    std::string targetPath = TEST_BUNDLE_PATCH + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByExtractDiffFiles(filePath, targetPath);
    EXPECT_FALSE(ret);

    targetPath = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByExtractDiffFiles(filePath, targetPath);
    EXPECT_FALSE(ret);

    targetPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByExtractDiffFiles(filePath, targetPath);
    EXPECT_TRUE(ret);

    filePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::QUICK_FIX_FILE_SUFFIX;
    ret = InstalldOperator::IsValidPathByExtractDiffFiles(filePath, targetPath);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByApplyDiffPatch_0100
 * @tc.name: test IsValidPathByApplyDiffPatch
 * @tc.desc: test IsValidPathByApplyDiffPatch of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByApplyDiffPatch_0100, Function | SmallTest | Level0)
{
    std::string oldSoPath = ServiceConstants::RELATIVE_PATH;
    std::string diffFilePath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    std::string newSoPath = TEST_BUNDLE_PATCH + ServiceConstants::PATCH_PATH + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByApplyDiffPatch(oldSoPath, diffFilePath, newSoPath);
    EXPECT_FALSE(ret);

    oldSoPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    diffFilePath = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByApplyDiffPatch(oldSoPath, diffFilePath, newSoPath);
    EXPECT_FALSE(ret);

    diffFilePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    newSoPath = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByApplyDiffPatch(oldSoPath, diffFilePath, newSoPath);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByApplyDiffPatch_0200
 * @tc.name: test IsValidPathByApplyDiffPatch
 * @tc.desc: test IsValidPathByApplyDiffPatch of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByApplyDiffPatch_0200, Function | SmallTest | Level0)
{
    std::string oldSoPath = TEST_BUNDLE_PATCH + TEST_STRING;
    std::string diffFilePath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    std::string newSoPath = TEST_BUNDLE_PATCH + ServiceConstants::PATCH_PATH + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByApplyDiffPatch(oldSoPath, diffFilePath, newSoPath);
    EXPECT_FALSE(ret);

    oldSoPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    diffFilePath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByApplyDiffPatch(oldSoPath, diffFilePath, newSoPath);
    EXPECT_FALSE(ret);

    diffFilePath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByApplyDiffPatch(oldSoPath, diffFilePath, newSoPath);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByApplyDiffPatch_0300
 * @tc.name: test IsValidPathByApplyDiffPatch
 * @tc.desc: test IsValidPathByApplyDiffPatch of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByApplyDiffPatch_0300, Function | SmallTest | Level0)
{
    std::string oldSoPath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    std::string diffFilePath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    std::string newSoPath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByApplyDiffPatch(oldSoPath, diffFilePath, newSoPath);
    EXPECT_FALSE(ret);

    newSoPath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByApplyDiffPatch(oldSoPath, diffFilePath, newSoPath);
    EXPECT_FALSE(ret);

    newSoPath = TEST_BUNDLE_PATCH + ServiceConstants::PATCH_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByApplyDiffPatch(oldSoPath, diffFilePath, newSoPath);
    EXPECT_TRUE(ret);

    newSoPath = TEST_BUNDLE_PATCH + ServiceConstants::HOT_RELOAD_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByApplyDiffPatch(oldSoPath, diffFilePath, newSoPath);
    EXPECT_TRUE(ret);

    newSoPath = TEST_BUNDLE_PATCH + HQF_PATCH_PATH + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByApplyDiffPatch(oldSoPath, diffFilePath, newSoPath);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByExtractEncryptedSoFiles_0100
 * @tc.name: test IsValidPathByExtractEncryptedSoFiles
 * @tc.desc: test IsValidPathByExtractEncryptedSoFiles of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByExtractEncryptedSoFiles_0100, Function | SmallTest | Level0)
{
    std::string hapPath = ServiceConstants::RELATIVE_PATH;
    std::string realSoFilesPath = "";
    std::string tmpSoPath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByExtractEncryptedSoFiles(hapPath, realSoFilesPath, tmpSoPath);
    EXPECT_FALSE(ret);

    hapPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    tmpSoPath = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByExtractEncryptedSoFiles(hapPath, realSoFilesPath, tmpSoPath);
    EXPECT_FALSE(ret);

    hapPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    realSoFilesPath = ServiceConstants::RELATIVE_PATH;
    tmpSoPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByExtractEncryptedSoFiles(hapPath, realSoFilesPath, tmpSoPath);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByExtractEncryptedSoFiles_0200
 * @tc.name: test IsValidPathByExtractEncryptedSoFiles
 * @tc.desc: test IsValidPathByExtractEncryptedSoFiles of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByExtractEncryptedSoFiles_0200, Function | SmallTest | Level0)
{
    std::string hapPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                          TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    std::string realSoFilesPath = "";
    std::string tmpSoPath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByExtractEncryptedSoFiles(hapPath, realSoFilesPath, tmpSoPath);
    EXPECT_FALSE(ret);

    hapPath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByExtractEncryptedSoFiles(hapPath, realSoFilesPath, tmpSoPath);
    EXPECT_FALSE(ret);

    hapPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    tmpSoPath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByExtractEncryptedSoFiles(hapPath, realSoFilesPath, tmpSoPath);
    EXPECT_FALSE(ret);

    tmpSoPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByExtractEncryptedSoFiles(hapPath, realSoFilesPath, tmpSoPath);
    EXPECT_TRUE(ret);

    hapPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidPathByExtractEncryptedSoFiles(hapPath, realSoFilesPath, tmpSoPath);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByExtractEncryptedSoFiles_0300
 * @tc.name: test IsValidPathByExtractEncryptedSoFiles
 * @tc.desc: test IsValidPathByExtractEncryptedSoFiles of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByExtractEncryptedSoFiles_0300, Function | SmallTest | Level0)
{
    std::string hapPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    std::string realSoFilesPath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    std::string tmpSoPath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByExtractEncryptedSoFiles(hapPath, realSoFilesPath, tmpSoPath);
    EXPECT_FALSE(ret);

    realSoFilesPath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByExtractEncryptedSoFiles(hapPath, realSoFilesPath, tmpSoPath);
    EXPECT_TRUE(ret);

    hapPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidPathByExtractEncryptedSoFiles(hapPath, realSoFilesPath, tmpSoPath);
    EXPECT_TRUE(ret);

    realSoFilesPath.clear();
    tmpSoPath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByExtractEncryptedSoFiles(hapPath, realSoFilesPath, tmpSoPath);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByExtractModuleFiles_0100
 * @tc.name: test IsValidPathByExtractModuleFiles
 * @tc.desc: test IsValidPathByExtractModuleFiles of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByExtractModuleFiles_0100, Function | SmallTest | Level0)
{
    std::string srcModulePath = ServiceConstants::RELATIVE_PATH;
    std::string targetPath = TEST_BUNDLE_PATCH + TEST_STRING;
    std::string targetSoPath = "";
    auto ret = InstalldOperator::IsValidPathByExtractModuleFiles(srcModulePath, targetPath, targetSoPath);
    EXPECT_FALSE(ret);

    srcModulePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    targetPath = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByExtractModuleFiles(srcModulePath, targetPath, targetSoPath);
    EXPECT_FALSE(ret);

    srcModulePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    targetPath = TEST_BUNDLE_PATCH + TEST_STRING;
    targetSoPath = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByExtractModuleFiles(srcModulePath, targetPath, targetSoPath);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByExtractModuleFiles_0200
 * @tc.name: test IsValidPathByExtractModuleFiles
 * @tc.desc: test IsValidPathByExtractModuleFiles of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByExtractModuleFiles_0200, Function | SmallTest | Level0)
{
    std::string srcModulePath = TEST_BUNDLE_PATCH + TEST_STRING;
    std::string targetPath = TEST_BUNDLE_PATCH + TEST_STRING;
    std::string targetSoPath = "";
    auto ret = InstalldOperator::IsValidPathByExtractModuleFiles(srcModulePath, targetPath, targetSoPath);
    EXPECT_FALSE(ret);

    srcModulePath = TEST_BUNDLE_PATCH + TEST_STRING + ".txt";
    ret = InstalldOperator::IsValidPathByExtractModuleFiles(srcModulePath, targetPath, targetSoPath);
    EXPECT_FALSE(ret);

    srcModulePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    targetPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByExtractModuleFiles(srcModulePath, targetPath, targetSoPath);
    EXPECT_FALSE(ret);

    targetPath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByExtractModuleFiles(srcModulePath, targetPath, targetSoPath);
    EXPECT_TRUE(ret);

    srcModulePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidPathByExtractModuleFiles(srcModulePath, targetPath, targetSoPath);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByExtractModuleFiles_0300
 * @tc.name: test IsValidPathByExtractModuleFiles
 * @tc.desc: test IsValidPathByExtractModuleFiles of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByExtractModuleFiles_0300, Function | SmallTest | Level0)
{
    std::string srcModulePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    std::string targetPath = TEST_BUNDLE_PATCH + TEST_STRING;
    std::string targetSoPath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByExtractModuleFiles(srcModulePath, targetPath, targetSoPath);
    EXPECT_FALSE(ret);

    targetSoPath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByExtractModuleFiles(srcModulePath, targetPath, targetSoPath);
    EXPECT_TRUE(ret);

    srcModulePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidPathByExtractModuleFiles(srcModulePath, targetPath, targetSoPath);
    EXPECT_TRUE(ret);

    targetSoPath.clear();
    ret = InstalldOperator::IsValidPathByExtractModuleFiles(srcModulePath, targetPath, targetSoPath);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidCertPath_0100
 * @tc.name: test IsValidCertPath
 * @tc.desc: test IsValidCertPath of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidCertPath_0100, Function | SmallTest | Level0)
{
    std::string certPath = ServiceConstants::RELATIVE_PATH;
    auto ret = InstalldOperator::IsValidCertPath(certPath);
    EXPECT_FALSE(ret);

    certPath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::CER_SUFFIX;
    ret = InstalldOperator::IsValidCertPath(certPath);
    EXPECT_FALSE(ret);

    certPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING +
               ServiceConstants::CER_SUFFIX;
    ret = InstalldOperator::IsValidCertPath(certPath);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidCertPath_0200
 * @tc.name: test IsValidCertPath
 * @tc.desc: test IsValidCertPath of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidCertPath_0200, Function | SmallTest | Level0)
{
    std::string certPath =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::ENTERPRISE_CERT_PATH + TEST_STRING;
    auto ret = InstalldOperator::IsValidCertPath(certPath);
    EXPECT_FALSE(ret);

    certPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::ENTERPRISE_CERT_PATH + TEST_STRING +
               ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidCertPath(certPath);
    EXPECT_FALSE(ret);

    certPath = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::ENTERPRISE_CERT_PATH + TEST_STRING +
               ServiceConstants::CER_SUFFIX;
    ret = InstalldOperator::IsValidCertPath(certPath);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByCopyDirScene_0100
 * @tc.name: test IsValidPathByCopyDirScene
 * @tc.desc: test IsValidPathByCopyDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByCopyDirScene_0100, Function | SmallTest | Level0)
{
    std::string sourceDir = ServiceConstants::RELATIVE_PATH;
    std::string destinationDir = TEST_BUNDLE_PATCH + ServiceConstants::PLUGIN_FILE_PATH;
    auto ret = InstalldOperator::IsValidPathByCopyDirScene(
        sourceDir, destinationDir, TEST_BUNDLE_NAME, BundleDirScene::COPY_PLUGIN_DIR);
    EXPECT_FALSE(ret);

    sourceDir = TEST_BUNDLE_PATCH + ServiceConstants::PLUGIN_FILE_PATH;
    destinationDir = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByCopyDirScene(
        sourceDir, destinationDir, TEST_BUNDLE_NAME, BundleDirScene::COPY_PLUGIN_DIR);
    EXPECT_FALSE(ret);

    sourceDir = ServiceConstants::RELATIVE_PATH;
    destinationDir = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByCopyDirScene(
        sourceDir, destinationDir, TEST_BUNDLE_NAME, BundleDirScene::COPY_PLUGIN_DIR);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByCopyDirScene_0200
 * @tc.name: test IsValidPathByCopyDirScene
 * @tc.desc: test IsValidPathByCopyDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByCopyDirScene_0200, Function | SmallTest | Level0)
{
    std::string sourceDir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                            TEST_BUNDLE_NAME + ServiceConstants::PLUGIN_FILE_PATH;
    std::string destinationDir = TEST_BUNDLE_PATCH + ServiceConstants::PLUGIN_FILE_PATH;
    auto ret = InstalldOperator::IsValidPathByCopyDirScene(
        sourceDir, destinationDir, TEST_BUNDLE_NAME, BundleDirScene::COPY_PLUGIN_DIR);
    EXPECT_FALSE(ret);

    sourceDir = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByCopyDirScene(
        sourceDir, destinationDir, TEST_BUNDLE_NAME, BundleDirScene::COPY_PLUGIN_DIR);
    EXPECT_FALSE(ret);

    sourceDir = TEST_BUNDLE_PATCH + ServiceConstants::PLUGIN_FILE_PATH;
    ret = InstalldOperator::IsValidPathByCopyDirScene(
        sourceDir, destinationDir, TEST_STRING, BundleDirScene::COPY_PLUGIN_DIR);
    EXPECT_FALSE(ret);

    ret = InstalldOperator::IsValidPathByCopyDirScene(
        sourceDir, destinationDir, TEST_BUNDLE_NAME, BundleDirScene::COPY_PLUGIN_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByCopyDirScene_0300
 * @tc.name: test IsValidPathByCopyDirScene
 * @tc.desc: test IsValidPathByCopyDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByCopyDirScene_0300, Function | SmallTest | Level0)
{
    std::string sourceDir = TEST_BUNDLE_PATCH + ServiceConstants::PLUGIN_FILE_PATH;
    std::string destinationDir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
                                 TEST_BUNDLE_NAME + ServiceConstants::PLUGIN_FILE_PATH;
    auto ret = InstalldOperator::IsValidPathByCopyDirScene(
        sourceDir, destinationDir, TEST_BUNDLE_NAME, BundleDirScene::COPY_PLUGIN_DIR);
    EXPECT_FALSE(ret);

    destinationDir = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByCopyDirScene(
        sourceDir, destinationDir, TEST_BUNDLE_NAME, BundleDirScene::COPY_PLUGIN_DIR);
    EXPECT_FALSE(ret);

    destinationDir = TEST_BUNDLE_PATCH + ServiceConstants::PLUGIN_FILE_PATH;
    ret = InstalldOperator::IsValidPathByCopyDirScene(
        sourceDir, destinationDir, TEST_BUNDLE_NAME, BundleDirScene::SET_DIR_APL);
    EXPECT_FALSE(ret);

    ret = InstalldOperator::IsValidPathByCopyDirScene(
        sourceDir, destinationDir, TEST_BUNDLE_NAME, BundleDirScene::COPY_PLUGIN_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByClearDirScene_0100
 * @tc.name: test IsValidPathByClearDirScene
 * @tc.desc: test IsValidPathByClearDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByClearDirScene_0100, Function | SmallTest | Level0)
{
    std::string dir = ServiceConstants::RELATIVE_PATH;
    auto ret = InstalldOperator::IsValidPathByClearDirScene(dir, BundleDirScene::CLEAR_ARK_PROFILE_DIR);
    EXPECT_FALSE(ret);

    dir = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByClearDirScene(dir, BundleDirScene::CLEAR_ARK_PROFILE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByClearDirScene(dir, BundleDirScene::CLEAR_ARK_PROFILE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + ARK_PROFILE_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByClearDirScene(dir, BundleDirScene::CLEAR_ARK_PROFILE_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByClearDirScene_0200
 * @tc.name: test IsValidPathByClearDirScene
 * @tc.desc: test IsValidPathByClearDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByClearDirScene_0200, Function | SmallTest | Level0)
{
    std::string dir = TEST_BUNDLE_PATCH + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByClearDirScene(dir, BundleDirScene::CLEAR_ARK_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::FOR_ALL_APP_DIR) + TEST_STRING;
    ret = InstalldOperator::IsValidPathByClearDirScene(dir, BundleDirScene::CLEAR_ARK_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::FOR_ALL_APP_DIR) + FRAMEWORK_ARK_CACHE_PATH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByClearDirScene(dir, BundleDirScene::CLEAR_ARK_CACHE_DIR);
    EXPECT_TRUE(ret);

    dir = std::string(ServiceConstants::HAP_ARK_CACHE_PATH) + TEST_STRING;
    ret = InstalldOperator::IsValidPathByClearDirScene(dir, BundleDirScene::CLEAR_ARK_CACHE_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByClearDirScene_0300
 * @tc.name: test IsValidPathByClearDirScene
 * @tc.desc: test IsValidPathByClearDirScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByClearDirScene_0300, Function | SmallTest | Level0)
{
    std::string dir = std::string(APP_EL1_PATH) + ARK_PROFILE_PATH + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByClearDirScene(dir, BundleDirScene::CLEAR_ARK_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(ServiceConstants::HAP_ARK_CACHE_PATH) + TEST_STRING;
    ret = InstalldOperator::IsValidPathByClearDirScene(dir, BundleDirScene::CLEAR_ARK_PROFILE_DIR);
    EXPECT_FALSE(ret);

    dir = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByClearDirScene(dir, BundleDirScene::SET_DIR_APL);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByGetNativeLibraryFileNames_0100
 * @tc.name: test IsValidPathByGetNativeLibraryFileNames
 * @tc.desc: test IsValidPathByGetNativeLibraryFileNames of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByGetNativeLibraryFileNames_0100, Function | SmallTest | Level0)
{
    std::string filePath = ServiceConstants::RELATIVE_PATH;
    auto ret = InstalldOperator::IsValidPathByGetNativeLibraryFileNames(filePath);
    EXPECT_FALSE(ret);

    filePath = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByGetNativeLibraryFileNames(filePath);
    EXPECT_FALSE(ret);

    filePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::CER_SUFFIX;
    ret = InstalldOperator::IsValidPathByGetNativeLibraryFileNames(filePath);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByGetNativeLibraryFileNames_0200
 * @tc.name: test IsValidPathByGetNativeLibraryFileNames
 * @tc.desc: test IsValidPathByGetNativeLibraryFileNames of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByGetNativeLibraryFileNames_0200, Function | SmallTest | Level0)
{
    std::string filePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::INSTALL_FILE_SUFFIX;
    auto ret = InstalldOperator::IsValidPathByGetNativeLibraryFileNames(filePath);
    EXPECT_TRUE(ret);

    filePath = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::HSP_FILE_SUFFIX;
    ret = InstalldOperator::IsValidPathByGetNativeLibraryFileNames(filePath);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByRestoreconPathScene_0100
 * @tc.name: test IsValidPathByRestoreconPathScene
 * @tc.desc: test IsValidPathByRestoreconPathScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRestoreconPathScene_0100, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_STRING;
    std::string path = ServiceConstants::RELATIVE_PATH;
    auto ret = InstalldOperator::IsValidPathByRestoreconPathScene(
        bundleName, path, BundleDirScene::RESTORECON_ARK_WEB_LIB_PATH);
    EXPECT_FALSE(ret);

    path = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + bundleName +
           ServiceConstants::PATH_SEPARATOR + ServiceConstants::LIBS;
    ret = InstalldOperator::IsValidPathByRestoreconPathScene(
        bundleName, path, BundleDirScene::RESTORECON_ARK_WEB_LIB_PATH);
    EXPECT_FALSE(ret);

    bundleName = TEST_STRING;
    path = TEST_BUNDLE_PATCH + ServiceConstants::LIBS;
    ret = InstalldOperator::IsValidPathByRestoreconPathScene(
        bundleName, path, BundleDirScene::RESTORECON_ARK_WEB_LIB_PATH);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByRestoreconPathScene_0200
 * @tc.name: test IsValidPathByRestoreconPathScene
 * @tc.desc: test IsValidPathByRestoreconPathScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByRestoreconPathScene_0200, Function | SmallTest | Level0)
{
    std::string path = TEST_BUNDLE_PATCH + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByRestoreconPathScene(
        TEST_BUNDLE_NAME, path, BundleDirScene::RESTORECON_ARK_WEB_LIB_PATH);
    EXPECT_FALSE(ret);

    path = TEST_BUNDLE_PATCH + ServiceConstants::LIBS;
    ret = InstalldOperator::IsValidPathByRestoreconPathScene(
        TEST_BUNDLE_NAME, path, BundleDirScene::RESTORECON_ARK_WEB_LIB_PATH);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidPathByRestoreconPathScene(TEST_BUNDLE_NAME, path, BundleDirScene::SET_DIR_APL);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByCopyFilesScene_0100
 * @tc.name: test IsValidPathByCopyFilesScene
 * @tc.desc: test IsValidPathByCopyFilesScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByCopyFilesScene_0100, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string sourceDir = ServiceConstants::RELATIVE_PATH;
    std::string destinationDir = std::string(ServiceConstants::HAP_COPY_PATH) +
                                 ServiceConstants::SECURITY_QUICK_FIX_PATH + ServiceConstants::PATH_SEPARATOR +
                                 bundleName;
    auto ret = InstalldOperator::IsValidPathByCopyFilesScene(
        sourceDir, destinationDir, bundleName, BundleDirScene::COPY_QUICK_FIX_FILES);
    EXPECT_FALSE(ret);

    sourceDir = TEST_BUNDLE_PATCH;
    destinationDir = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByCopyFilesScene(
        sourceDir, destinationDir, bundleName, BundleDirScene::COPY_QUICK_FIX_FILES);
    EXPECT_FALSE(ret);

    sourceDir = ServiceConstants::RELATIVE_PATH;
    destinationDir = ServiceConstants::RELATIVE_PATH;
    ret = InstalldOperator::IsValidPathByCopyFilesScene(
        sourceDir, destinationDir, bundleName, BundleDirScene::COPY_QUICK_FIX_FILES);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByCopyFilesScene_0200
 * @tc.name: test IsValidPathByCopyFilesScene
 * @tc.desc: test IsValidPathByCopyFilesScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByCopyFilesScene_0200, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string sourceDir =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + bundleName;
    std::string destinationDir = std::string(ServiceConstants::HAP_COPY_PATH) +
                                 ServiceConstants::SECURITY_QUICK_FIX_PATH + ServiceConstants::PATH_SEPARATOR +
                                 bundleName;
    auto ret = InstalldOperator::IsValidPathByCopyFilesScene(
        sourceDir, destinationDir, bundleName, BundleDirScene::COPY_QUICK_FIX_FILES);
    EXPECT_FALSE(ret);

    sourceDir = TEST_STRING;
    ret = InstalldOperator::IsValidPathByCopyFilesScene(
        sourceDir, destinationDir, bundleName, BundleDirScene::COPY_QUICK_FIX_FILES);
    EXPECT_FALSE(ret);

    sourceDir = TEST_BUNDLE_PATCH;
    ret = InstalldOperator::IsValidPathByCopyFilesScene(
        sourceDir, destinationDir, TEST_STRING, BundleDirScene::COPY_QUICK_FIX_FILES);
    EXPECT_FALSE(ret);

    ret = InstalldOperator::IsValidPathByCopyFilesScene(
        sourceDir, destinationDir, bundleName, BundleDirScene::COPY_QUICK_FIX_FILES);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByCopyFilesScene_0300
 * @tc.name: test IsValidPathByCopyFilesScene
 * @tc.desc: test IsValidPathByCopyFilesScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByCopyFilesScene_0300, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string sourceDir = TEST_BUNDLE_PATCH;
    std::string destinationDir = TEST_BUNDLE_PATCH + bundleName;
    auto ret = InstalldOperator::IsValidPathByCopyFilesScene(
        sourceDir, destinationDir, bundleName, BundleDirScene::COPY_QUICK_FIX_FILES);
    EXPECT_FALSE(ret);

    destinationDir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + bundleName;
    ret = InstalldOperator::IsValidPathByCopyFilesScene(
        sourceDir, destinationDir, bundleName, BundleDirScene::COPY_QUICK_FIX_FILES);
    EXPECT_FALSE(ret);

    destinationDir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::SECURITY_QUICK_FIX_PATH +
                     ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByCopyFilesScene(
        sourceDir, destinationDir, bundleName, BundleDirScene::COPY_QUICK_FIX_FILES);
    EXPECT_FALSE(ret);

    destinationDir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::SECURITY_QUICK_FIX_PATH +
                     ServiceConstants::PATH_SEPARATOR + bundleName;
    ret = InstalldOperator::IsValidPathByCopyFilesScene(
        sourceDir, destinationDir, bundleName, BundleDirScene::SET_DIR_APL);
    EXPECT_FALSE(ret);

    ret = InstalldOperator::IsValidPathByCopyFilesScene(
        sourceDir, destinationDir, bundleName, BundleDirScene::COPY_QUICK_FIX_FILES);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByMoveFilesScene_0100
 * @tc.name: test IsValidPathByMoveFilesScene
 * @tc.desc: test IsValidPathByMoveFilesScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMoveFilesScene_0100, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string srcDir = ServiceConstants::RELATIVE_PATH;
    std::string desDir = TEST_BUNDLE_PATCH;
    auto ret =
        InstalldOperator::IsValidPathByMoveFilesScene(srcDir, desDir, bundleName, BundleDirScene::MOVE_SO_TO_REAL_PATH);
    EXPECT_FALSE(ret);

    srcDir = TEST_BUNDLE_PATCH;
    desDir = ServiceConstants::RELATIVE_PATH;
    ret =
        InstalldOperator::IsValidPathByMoveFilesScene(srcDir, desDir, bundleName, BundleDirScene::MOVE_SO_TO_REAL_PATH);
    EXPECT_FALSE(ret);

    srcDir = ServiceConstants::RELATIVE_PATH;
    desDir = ServiceConstants::RELATIVE_PATH;
    ret =
        InstalldOperator::IsValidPathByMoveFilesScene(srcDir, desDir, bundleName, BundleDirScene::MOVE_SO_TO_REAL_PATH);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByMoveFilesScene_0200
 * @tc.name: test IsValidPathByMoveFilesScene
 * @tc.desc: test IsValidPathByMoveFilesScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMoveFilesScene_0200, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string srcDir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + bundleName;
    std::string desDir = TEST_BUNDLE_PATCH;
    auto ret =
        InstalldOperator::IsValidPathByMoveFilesScene(srcDir, desDir, bundleName, BundleDirScene::MOVE_SO_TO_REAL_PATH);
    EXPECT_FALSE(ret);

    srcDir = TEST_STRING;
    ret =
        InstalldOperator::IsValidPathByMoveFilesScene(srcDir, desDir, bundleName, BundleDirScene::MOVE_SO_TO_REAL_PATH);
    EXPECT_FALSE(ret);

    srcDir = TEST_BUNDLE_PATCH;
    ret = InstalldOperator::IsValidPathByMoveFilesScene(
        srcDir, desDir, TEST_STRING, BundleDirScene::MOVE_SO_TO_REAL_PATH);
    EXPECT_FALSE(ret);

    ret =
        InstalldOperator::IsValidPathByMoveFilesScene(srcDir, desDir, bundleName, BundleDirScene::MOVE_SO_TO_REAL_PATH);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByMoveFilesScene_0300
 * @tc.name: test IsValidPathByMoveFilesScene
 * @tc.desc: test IsValidPathByMoveFilesScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMoveFilesScene_0300, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string srcDir = TEST_BUNDLE_PATCH;
    std::string desDir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + bundleName;
    auto ret =
        InstalldOperator::IsValidPathByMoveFilesScene(srcDir, desDir, bundleName, BundleDirScene::MOVE_SO_TO_REAL_PATH);
    EXPECT_FALSE(ret);

    desDir = TEST_STRING;
    ret =
        InstalldOperator::IsValidPathByMoveFilesScene(srcDir, desDir, bundleName, BundleDirScene::MOVE_SO_TO_REAL_PATH);
    EXPECT_FALSE(ret);

    desDir = TEST_BUNDLE_PATCH;
    ret = InstalldOperator::IsValidPathByMoveFilesScene(srcDir, desDir, bundleName, BundleDirScene::SET_DIR_APL);
    EXPECT_FALSE(ret);

    ret =
        InstalldOperator::IsValidPathByMoveFilesScene(srcDir, desDir, bundleName, BundleDirScene::MOVE_SO_TO_REAL_PATH);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByGetDiskUsageFromPathScene_0100
 * @tc.name: test IsValidPathByGetDiskUsageFromPathScene
 * @tc.desc: test IsValidPathByGetDiskUsageFromPathScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByGetDiskUsageFromPathScene_0100, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string path = ServiceConstants::RELATIVE_PATH;
    auto ret = InstalldOperator::IsValidPathByGetDiskUsageFromPathScene(
        path, bundleName, BundleDirScene::GET_BUNDLE_CACHE_DISK_USAGE);
    EXPECT_FALSE(ret);

    path = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByGetDiskUsageFromPathScene(
        path, bundleName, BundleDirScene::GET_BUNDLE_CACHE_DISK_USAGE);
    EXPECT_FALSE(ret);

    path = std::string(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR) + TEST_STRING;
    ret = InstalldOperator::IsValidPathByGetDiskUsageFromPathScene(
        path, bundleName, BundleDirScene::GET_BUNDLE_CACHE_DISK_USAGE);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByGetDiskUsageFromPathScene_0200
 * @tc.name: test IsValidPathByGetDiskUsageFromPathScene
 * @tc.desc: test IsValidPathByGetDiskUsageFromPathScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByGetDiskUsageFromPathScene_0200, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string path = std::string(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR) + bundleName +
                       ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByGetDiskUsageFromPathScene(
        path, bundleName, BundleDirScene::GET_BUNDLE_CACHE_DISK_USAGE);
    EXPECT_FALSE(ret);

    path = std::string(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR) + TEST_STRING + ServiceConstants::PATH_SEPARATOR +
           Constants::CACHE_DIR;
    ret = InstalldOperator::IsValidPathByGetDiskUsageFromPathScene(
        path, bundleName, BundleDirScene::GET_BUNDLE_CACHE_DISK_USAGE);
    EXPECT_FALSE(ret);

    path = std::string(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR) + bundleName + ServiceConstants::PATH_SEPARATOR +
           Constants::CACHE_DIR;
    ret = InstalldOperator::IsValidPathByGetDiskUsageFromPathScene(
        path, bundleName, BundleDirScene::GET_BUNDLE_CACHE_DISK_USAGE);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByGetDiskUsageFromPathScene_0300
 * @tc.name: test IsValidPathByGetDiskUsageFromPathScene
 * @tc.desc: test IsValidPathByGetDiskUsageFromPathScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByGetDiskUsageFromPathScene_0300, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string path = std::string(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR) + bundleName +
                       ServiceConstants::PATH_SEPARATOR + Constants::CACHE_DIR;
    auto ret = InstalldOperator::IsValidPathByGetDiskUsageFromPathScene(
        path, bundleName, BundleDirScene::GET_BUNDLE_CACHE_DISK_USAGE);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidPathByGetDiskUsageFromPathScene(
        path, TEST_STRING, BundleDirScene::GET_BUNDLE_CACHE_DISK_USAGE);
    EXPECT_FALSE(ret);

    ret = InstalldOperator::IsValidPathByGetDiskUsageFromPathScene(path, bundleName, BundleDirScene::SET_DIR_APL);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByGetFileStatScene_0100
 * @tc.name: test IsValidPathByGetFileStatScene
 * @tc.desc: test IsValidPathByGetFileStatScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByGetFileStatScene_0100, Function | SmallTest | Level0)
{
    std::string file = ServiceConstants::RELATIVE_PATH;
    auto ret = InstalldOperator::IsValidPathByGetFileStatScene(file, BundleDirScene::GET_BMS_FILE_STAT);
    EXPECT_FALSE(ret);

    ret = InstalldOperator::IsValidPathByGetFileStatScene(file, BundleDirScene::GET_USER_DATA_FILE_STAT);
    EXPECT_FALSE(ret);

    ret = InstalldOperator::IsValidPathByGetFileStatScene(file, BundleDirScene::GET_DATA_BASE_FILE_STAT);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByGetFileStatScene_0200
 * @tc.name: test IsValidPathByGetFileStatScene
 * @tc.desc: test IsValidPathByGetFileStatScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByGetFileStatScene_0200, Function | SmallTest | Level0)
{
    std::string file = TEST_BUNDLE_PATCH + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByGetFileStatScene(file, BundleDirScene::GET_BMS_FILE_STAT);
    EXPECT_FALSE(ret);

    file = std::string(ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByGetFileStatScene(file, BundleDirScene::GET_BMS_FILE_STAT);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidPathByGetFileStatScene(file, BundleDirScene::SET_DIR_APL);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByGetFileStatScene_0300
 * @tc.name: test IsValidPathByGetFileStatScene
 * @tc.desc: test IsValidPathByGetFileStatScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByGetFileStatScene_0300, Function | SmallTest | Level0)
{
    std::string file = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByGetFileStatScene(file, BundleDirScene::GET_USER_DATA_FILE_STAT);
    EXPECT_FALSE(ret);

    file = std::string(APP_EL1_PATH) + ServiceConstants::BASE + TEST_STRING;
    ret = InstalldOperator::IsValidPathByGetFileStatScene(file, BundleDirScene::GET_USER_DATA_FILE_STAT);
    EXPECT_TRUE(ret);

    file = std::string(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR) + TEST_STRING;
    ret = InstalldOperator::IsValidPathByGetFileStatScene(file, BundleDirScene::GET_DATA_BASE_FILE_STAT);
    EXPECT_FALSE(ret);

    file = std::string(ServiceConstants::BUNDLE_APP_DATA_BASE_DIR) + ServiceConstants::DATABASE + TEST_STRING;
    ret = InstalldOperator::IsValidPathByGetFileStatScene(file, BundleDirScene::GET_DATA_BASE_FILE_STAT);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByHashFiles_0100
 * @tc.name: test IsValidPathByHashFiles
 * @tc.desc: test IsValidPathByHashFiles of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByHashFiles_0100, Function | SmallTest | Level0)
{
    std::string file = ServiceConstants::RELATIVE_PATH;
    auto ret = InstalldOperator::IsValidPathByHashFiles(file);
    EXPECT_FALSE(ret);

    file = TEST_BUNDLE_PATCH + TEST_STRING;
    ret = InstalldOperator::IsValidPathByHashFiles(file);
    EXPECT_FALSE(ret);

    file = TEST_BUNDLE_PATCH + TEST_STRING + ServiceConstants::CER_SUFFIX;
    ret = InstalldOperator::IsValidPathByHashFiles(file);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByMigrateData_0100
 * @tc.name: test IsValidPathByMigrateData
 * @tc.desc: test IsValidPathByMigrateData of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMigrateData_0100, Function | SmallTest | Level0)
{
    std::vector<std::string> sourcePaths;
    std::string destinationPath = TEST_STRING;
    bool isInvalidsourcePath = false;

    sourcePaths.push_back(ServiceConstants::RELATIVE_PATH);
    auto ret = InstalldOperator::IsValidPathByMigrateData(sourcePaths, destinationPath, isInvalidsourcePath);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(isInvalidsourcePath);

    sourcePaths.clear();
    sourcePaths.push_back(TEST_STRING);
    sourcePaths.push_back(ServiceConstants::RELATIVE_PATH);
    isInvalidsourcePath = false;
    ret = InstalldOperator::IsValidPathByMigrateData(sourcePaths, destinationPath, isInvalidsourcePath);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(isInvalidsourcePath);
}

/**
 * @tc.number: IsValidPathByMigrateData_0200
 * @tc.name: test IsValidPathByMigrateData
 * @tc.desc: test IsValidPathByMigrateData of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMigrateData_0200, Function | SmallTest | Level0)
{
    std::vector<std::string> sourcePaths;
    std::string destinationPath = TEST_STRING;
    bool isInvalidsourcePath = false;

    sourcePaths.push_back(ServiceConstants::SANDBOX_DATA_PATH);
    auto ret = InstalldOperator::IsValidPathByMigrateData(sourcePaths, destinationPath, isInvalidsourcePath);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(isInvalidsourcePath);

    sourcePaths.clear();
    sourcePaths.push_back(TEST_STRING);
    destinationPath = ServiceConstants::RELATIVE_PATH;
    isInvalidsourcePath = true;
    ret = InstalldOperator::IsValidPathByMigrateData(sourcePaths, destinationPath, isInvalidsourcePath);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(isInvalidsourcePath);

    destinationPath = ServiceConstants::SANDBOX_DATA_PATH;
    isInvalidsourcePath = true;
    ret = InstalldOperator::IsValidPathByMigrateData(sourcePaths, destinationPath, isInvalidsourcePath);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(isInvalidsourcePath);
}

/**
 * @tc.number: IsValidPathByMigrateData_0300
 * @tc.name: test IsValidPathByMigrateData
 * @tc.desc: test IsValidPathByMigrateData of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByMigrateData_0300, Function | SmallTest | Level0)
{
    std::vector<std::string> sourcePaths;
    std::string destinationPath = TEST_STRING;
    bool isInvalidsourcePath = true;

    auto ret = InstalldOperator::IsValidPathByMigrateData(sourcePaths, destinationPath, isInvalidsourcePath);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(isInvalidsourcePath);

    sourcePaths.push_back(TEST_STRING);
    sourcePaths.push_back(TEST_STRING);
    ret = InstalldOperator::IsValidPathByMigrateData(sourcePaths, destinationPath, isInvalidsourcePath);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(isInvalidsourcePath);
}

/**
 * @tc.number: IsValidPathByCleanBundleDirsScene_0100
 * @tc.name: test IsValidPathByCleanBundleDirsScene
 * @tc.desc: test IsValidPathByCleanBundleDirsScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByCleanBundleDirsScene_0100, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string dir = ServiceConstants::RELATIVE_PATH;
    auto ret =
        InstalldOperator::IsValidPathByCleanBundleDirsScene(dir, bundleName, BundleDirScene::CLEAN_SHADER_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByCleanBundleDirsScene(dir, bundleName, BundleDirScene::CLEAN_SHADER_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + bundleName;
    ret = InstalldOperator::IsValidPathByCleanBundleDirsScene(dir, TEST_STRING, BundleDirScene::CLEAN_SHADER_CACHE_DIR);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByCleanBundleDirsScene_0200
 * @tc.name: test IsValidPathByCleanBundleDirsScene
 * @tc.desc: test IsValidPathByCleanBundleDirsScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByCleanBundleDirsScene_0200, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string dir = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + bundleName +
                      ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    auto ret =
        InstalldOperator::IsValidPathByCleanBundleDirsScene(dir, bundleName, BundleDirScene::CLEAN_SHADER_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + ServiceConstants::SHADER_CACHE_SUBDIR + bundleName;
    ret = InstalldOperator::IsValidPathByCleanBundleDirsScene(dir, bundleName, BundleDirScene::CLEAN_SHADER_CACHE_DIR);
    EXPECT_TRUE(ret);

    dir = std::string(ServiceConstants::SHADER_CACHE_PATH) + bundleName;
    ret = InstalldOperator::IsValidPathByCleanBundleDirsScene(dir, bundleName, BundleDirScene::CLEAN_SHADER_CACHE_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByCleanBundleDirsScene_0300
 * @tc.name: test IsValidPathByCleanBundleDirsScene
 * @tc.desc: test IsValidPathByCleanBundleDirsScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByCleanBundleDirsScene_0300, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string dir = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + bundleName;
    auto ret = InstalldOperator::IsValidPathByCleanBundleDirsScene(
        dir, bundleName, BundleDirScene::CLEAN_ARK_STARTUP_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + SYSTEM_OPTIMIZE_DIR + bundleName;
    ret = InstalldOperator::IsValidPathByCleanBundleDirsScene(
        dir, bundleName, BundleDirScene::CLEAN_ARK_STARTUP_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + SYSTEM_OPTIMIZE_DIR + ServiceConstants::ARK_STARTUP_CACHE_DIR + bundleName;
    ret = InstalldOperator::IsValidPathByCleanBundleDirsScene(
        dir, bundleName, BundleDirScene::CLEAN_ARK_STARTUP_CACHE_DIR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: IsValidPathByCleanBundleDirsScene_0400
 * @tc.name: test IsValidPathByCleanBundleDirsScene
 * @tc.desc: test IsValidPathByCleanBundleDirsScene of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByCleanBundleDirsScene_0400, Function | SmallTest | Level0)
{
    std::string bundleName = TEST_BUNDLE_NAME;
    std::string dir = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + bundleName;
    auto ret =
        InstalldOperator::IsValidPathByCleanBundleDirsScene(dir, bundleName, BundleDirScene::CLEAN_EL1_CACHE_DIR);
    EXPECT_FALSE(ret);

    dir = std::string(APP_EL1_PATH) + SYSTEM_OPTIMIZE_DIR + bundleName;
    ret = InstalldOperator::IsValidPathByCleanBundleDirsScene(dir, bundleName, BundleDirScene::CLEAN_EL1_CACHE_DIR);
    EXPECT_TRUE(ret);

    dir = std::string(APP_EL1_PATH) + ServiceConstants::SHADER_CACHE_SUBDIR + bundleName;
    ret = InstalldOperator::IsValidPathByCleanBundleDirsScene(dir, bundleName, BundleDirScene::CLEAN_EL1_CACHE_DIR);
    EXPECT_TRUE(ret);

    ret = InstalldOperator::IsValidPathByCleanBundleDirsScene(dir, bundleName, BundleDirScene::SET_DIR_APL);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByDeleteUninstallTmpDirs_0100
 * @tc.name: test IsValidPathByDeleteUninstallTmpDirs
 * @tc.desc: test IsValidPathByDeleteUninstallTmpDirs of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByDeleteUninstallTmpDirs_0100, Function | SmallTest | Level0)
{
    std::string dir = ServiceConstants::RELATIVE_PATH;
    auto ret = InstalldOperator::IsValidPathByDeleteUninstallTmpDirs(dir);
    EXPECT_FALSE(ret);

    dir = "/data/local" + std::string(ServiceConstants::PATH_SEPARATOR) + TEST_STRING;
    ret = InstalldOperator::IsValidPathByDeleteUninstallTmpDirs(dir);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByDeleteUninstallTmpDirs_0200
 * @tc.name: test IsValidPathByDeleteUninstallTmpDirs
 * @tc.desc: test IsValidPathByDeleteUninstallTmpDirs of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByDeleteUninstallTmpDirs_0200, Function | SmallTest | Level0)
{
    std::string dir = TEST_BUNDLE_PATCH;
    auto ret = InstalldOperator::IsValidPathByDeleteUninstallTmpDirs(dir);
    EXPECT_TRUE(ret);

    dir = std::string(ServiceConstants::NEW_CLOUD_SHADER_PATH) + TEST_STRING;
    ret = InstalldOperator::IsValidPathByDeleteUninstallTmpDirs(dir);
    EXPECT_TRUE(ret);

    dir = std::string(APP_EL1_PATH) + ServiceConstants::BASE + TEST_STRING;
    ret = InstalldOperator::IsValidPathByDeleteUninstallTmpDirs(dir);
    EXPECT_TRUE(ret);

    dir = std::string(APP_EL1_PATH) + ServiceConstants::DATABASE + TEST_STRING;
    ret = InstalldOperator::IsValidPathByDeleteUninstallTmpDirs(dir);
    EXPECT_TRUE(ret);

    dir = std::string(APP_EL1_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByDeleteUninstallTmpDirs(dir);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsValidPathByDeleteUninstallTmpDirs_0300
 * @tc.name: test IsValidPathByDeleteUninstallTmpDirs
 * @tc.desc: test IsValidPathByDeleteUninstallTmpDirs of InstalldOperator
 */
HWTEST_F(BmsInstalldOperatorTest, IsValidPathByDeleteUninstallTmpDirs_0300, Function | SmallTest | Level0)
{
    std::string dir = std::string(APP_EL2_PATH) + ServiceConstants::BASE + TEST_STRING;
    auto ret = InstalldOperator::IsValidPathByDeleteUninstallTmpDirs(dir);
    EXPECT_TRUE(ret);

    dir = std::string(APP_EL2_PATH) + ServiceConstants::DATABASE + TEST_STRING;
    ret = InstalldOperator::IsValidPathByDeleteUninstallTmpDirs(dir);
    EXPECT_TRUE(ret);

    dir = std::string(APP_EL3_PATH) + ServiceConstants::DATABASE + TEST_STRING;
    ret = InstalldOperator::IsValidPathByDeleteUninstallTmpDirs(dir);
    EXPECT_TRUE(ret);

    dir = std::string(APP_EL4_PATH) + ServiceConstants::BASE + TEST_STRING;
    ret = InstalldOperator::IsValidPathByDeleteUninstallTmpDirs(dir);
    EXPECT_TRUE(ret);

    dir = std::string(APP_EL2_PATH) + ServiceConstants::PATH_SEPARATOR + TEST_STRING;
    ret = InstalldOperator::IsValidPathByDeleteUninstallTmpDirs(dir);
    EXPECT_FALSE(ret);
}
} // OHOS
