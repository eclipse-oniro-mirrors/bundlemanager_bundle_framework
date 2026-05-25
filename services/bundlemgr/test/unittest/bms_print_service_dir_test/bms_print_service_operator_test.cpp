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

#include "directory_ex.h"
#include "file_ex.h"
#define private public
#include "installd/installd_operator.h"
#undef private

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string TEST_BUNDLE_NAME = "com.example.driver.print";
const std::string TEST_BUNDLE_NAME_CLONE = "com.example.driver.print.clone";
const int32_t TEST_USER_ID = 100;
const int32_t TEST_APP_INDEX = 0;
const int32_t TEST_CLONE_APP_INDEX = 1;
const uid_t TEST_APP_UID = 20010000;
const uid_t TEST_APP_UID_CLONE = 20010001;
constexpr uid_t PRINT_SERVICE_UID = 3823;
constexpr mode_t PRINT_SERVICE_DIR_MODE = 02750;
constexpr const char* PRINT_SERVICE_BASE_DIR = "/data/service/el1/100/print_service/data";
constexpr const char* TEST_TEMP_DIR = "/data/test/print_service_test";
}  // namespace

class BmsPrintServiceOperatorTest : public testing::Test {
public:
    BmsPrintServiceOperatorTest() = default;
    ~BmsPrintServiceOperatorTest() override = default;
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    static bool CheckDirExist(const std::string &dirPath);
    static bool CheckDirPermission(const std::string &dirPath, uid_t uid, gid_t gid, mode_t mode);
    static void CreatePrintServiceBaseDir();
    static void RemovePrintServiceBaseDir();
    static void CleanPrintServiceDir(const std::string &bundleName, int32_t appIndex);
};

void BmsPrintServiceOperatorTest::SetUpTestCase()
{
    // Create test directories
    mkdir(TEST_TEMP_DIR, 0755);
    CreatePrintServiceBaseDir();
}

void BmsPrintServiceOperatorTest::TearDownTestCase()
{
    // Clean up test directories
    RemovePrintServiceBaseDir();
    rmdir(TEST_TEMP_DIR);
}

void BmsPrintServiceOperatorTest::SetUp()
{
    // Clean up before each test
    CleanPrintServiceDir(TEST_BUNDLE_NAME, TEST_APP_INDEX);
    CleanPrintServiceDir(TEST_BUNDLE_NAME_CLONE, TEST_CLONE_APP_INDEX);
}

void BmsPrintServiceOperatorTest::TearDown()
{
    // Clean up after each test
    CleanPrintServiceDir(TEST_BUNDLE_NAME, TEST_APP_INDEX);
    CleanPrintServiceDir(TEST_BUNDLE_NAME_CLONE, TEST_CLONE_APP_INDEX);
}

bool BmsPrintServiceOperatorTest::CheckDirExist(const std::string &dirPath)
{
    struct stat statBuf = {0};
    if (stat(dirPath.c_str(), &statBuf) != 0) {
        return false;
    }
    return S_ISDIR(statBuf.st_mode);
}

bool BmsPrintServiceOperatorTest::CheckDirPermission(const std::string &dirPath, uid_t uid, gid_t gid, mode_t mode)
{
    struct stat statBuf = {0};
    if (stat(dirPath.c_str(), &statBuf) != 0) {
        return false;
    }

    bool uidMatch = (statBuf.st_uid == uid);
    bool gidMatch = (statBuf.st_gid == gid);
    bool modeMatch = ((statBuf.st_mode & 07777) == mode);

    return uidMatch && gidMatch && modeMatch;
}

void BmsPrintServiceOperatorTest::CreatePrintServiceBaseDir()
{
    // Create base directory: /data/service/el1/100/print_service/data
    std::string cmd = "mkdir -p " + std::string(PRINT_SERVICE_BASE_DIR);
    system(cmd.c_str());

    // Set proper ownership and permissions
    chown(PRINT_SERVICE_BASE_DIR, PRINT_SERVICE_UID, PRINT_SERVICE_UID);
    chmod(PRINT_SERVICE_BASE_DIR, 0755);
}

void BmsPrintServiceOperatorTest::RemovePrintServiceBaseDir()
{
    std::string cmd = "rm -rf " + std::string(PRINT_SERVICE_BASE_DIR);
    system(cmd.c_str());
}

void BmsPrintServiceOperatorTest::CleanPrintServiceDir(const std::string &bundleName, int32_t appIndex)
{
    std::string bundleDirName = bundleName;
    if (appIndex > 0) {
        bundleDirName = "+clone-" + std::to_string(appIndex) + "+" + bundleName;
    }
    std::string dirPath = std::string(PRINT_SERVICE_BASE_DIR) + "/" + bundleDirName;

    // Remove directory if exists
    if (CheckDirExist(dirPath)) {
        std::string cmd = "rm -rf " + dirPath;
        system(cmd.c_str());
    }
}

/**
 * @tc.number: BmsPrintServiceOperatorTest_0001
 * @tc.name: test_create_print_service_dir_success
 * @tc.desc: Test creating print service directory successfully with correct permissions.
 * @tc.require: Issuexxx
 */
HWTEST_F(BmsPrintServiceOperatorTest, BmsPrintServiceOperatorTest_0001, Function | SmallTest | Level0)
{
    ErrCode ret = InstalldOperator::CreatePrintServiceDir(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX, TEST_APP_UID);
    EXPECT_EQ(ret, ERR_OK);

    // Verify directory exists
    std::string dirPath = std::string(PRINT_SERVICE_BASE_DIR) + "/" + TEST_BUNDLE_NAME;
    EXPECT_TRUE(CheckDirExist(dirPath));

    // Verify directory permissions
    EXPECT_TRUE(CheckDirPermission(dirPath, TEST_APP_UID, PRINT_SERVICE_UID, PRINT_SERVICE_DIR_MODE));
}

/**
 * @tc.number: BmsPrintServiceOperatorTest_0002
 * @tc.name: test_create_print_service_dir_parent_not_exists
 * @tc.desc: Test creating print service directory when parent directory does not exist.
 * @tc.require: Issuexxx
 */
HWTEST_F(BmsPrintServiceOperatorTest, BmsPrintServiceOperatorTest_0002, Function | SmallTest | Level0)
{
    // Remove base directory to simulate parent not exists
    RemovePrintServiceBaseDir();

    ErrCode ret = InstalldOperator::CreatePrintServiceDir(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX, TEST_APP_UID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PRINT_SERVICE_PARENT_DIR_NOT_EXISTS);

    // Restore base directory for other tests
    CreatePrintServiceBaseDir();
}

/**
 * @tc.number: BmsPrintServiceOperatorTest_0003
 * @tc.name: test_create_print_service_dir_already_exists
 * @tc.desc: Test creating print service directory when it already exists with correct permissions.
 * @tc.require: Issuexxx
 */
HWTEST_F(BmsPrintServiceOperatorTest, BmsPrintServiceOperatorTest_0003, Function | SmallTest | Level0)
{
    // Create directory first
    ErrCode ret = InstalldOperator::CreatePrintServiceDir(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX, TEST_APP_UID);
    EXPECT_EQ(ret, ERR_OK);

    // Call CreatePrintServiceDir again (directory already exists)
    ret = InstalldOperator::CreatePrintServiceDir(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX, TEST_APP_UID);
    EXPECT_EQ(ret, ERR_OK);

    // Verify directory still has correct permissions
    std::string dirPath = std::string(PRINT_SERVICE_BASE_DIR) + "/" + TEST_BUNDLE_NAME;
    EXPECT_TRUE(CheckDirPermission(dirPath, TEST_APP_UID, PRINT_SERVICE_UID, PRINT_SERVICE_DIR_MODE));
}

/**
 * @tc.number: BmsPrintServiceOperatorTest_0004
 * @tc.name: test_create_print_service_dir_clone_app
 * @tc.desc: Test creating print service directory for clone application with correct directory name format.
 * @tc.require: Issuexxx
 */
HWTEST_F(BmsPrintServiceOperatorTest, BmsPrintServiceOperatorTest_0004, Function | SmallTest | Level0)
{
    ErrCode ret = InstalldOperator::CreatePrintServiceDir(
        TEST_BUNDLE_NAME_CLONE, TEST_USER_ID, TEST_CLONE_APP_INDEX, TEST_APP_UID_CLONE);
    EXPECT_EQ(ret, ERR_OK);

    // Verify directory exists with correct clone format: +clone-1+{bundleName}
    std::string bundleDirName = "+clone-" + std::to_string(TEST_CLONE_APP_INDEX) + "+" + TEST_BUNDLE_NAME_CLONE;
    std::string dirPath = std::string(PRINT_SERVICE_BASE_DIR) + "/" + bundleDirName;
    EXPECT_TRUE(CheckDirExist(dirPath));

    // Verify directory permissions
    EXPECT_TRUE(CheckDirPermission(dirPath, TEST_APP_UID_CLONE, PRINT_SERVICE_UID, PRINT_SERVICE_DIR_MODE));
}

/**
 * @tc.number: BmsPrintServiceOperatorTest_0005
 * @tc.name: test_create_print_service_dir_invalid_parameters
 * @tc.desc: Test creating print service directory with invalid parameters.
 * @tc.require: Issuexxx
 */
HWTEST_F(BmsPrintServiceOperatorTest, BmsPrintServiceOperatorTest_0005, Function | SmallTest | Level0)
{
    // Test with empty bundle name
    ErrCode ret = InstalldOperator::CreatePrintServiceDir("", TEST_USER_ID, TEST_APP_INDEX, TEST_APP_UID);
    EXPECT_NE(ret, ERR_OK);

    // Test with negative user ID
    ret = InstalldOperator::CreatePrintServiceDir(TEST_BUNDLE_NAME, -1, TEST_APP_INDEX, TEST_APP_UID);
    EXPECT_NE(ret, ERR_OK);

    // Test with negative app UID
    ret = InstalldOperator::CreatePrintServiceDir(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX, -1);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BmsPrintServiceOperatorTest_0006
 * @tc.name: test_remove_print_service_dir_success
 * @tc.desc: Test removing print service directory successfully.
 * @tc.require: Issuexxx
 */
HWTEST_F(BmsPrintServiceOperatorTest, BmsPrintServiceOperatorTest_0006, Function | SmallTest | Level0)
{
    // Create directory first
    ErrCode ret = InstalldOperator::CreatePrintServiceDir(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX, TEST_APP_UID);
    EXPECT_EQ(ret, ERR_OK);

    // Verify directory exists
    std::string dirPath = std::string(PRINT_SERVICE_BASE_DIR) + "/" + TEST_BUNDLE_NAME;
    EXPECT_TRUE(CheckDirExist(dirPath));

    // Remove directory
    ret = InstalldOperator::RemovePrintServiceDir(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX);
    EXPECT_EQ(ret, ERR_OK);

    // Verify directory does not exist
    EXPECT_FALSE(CheckDirExist(dirPath));
}

/**
 * @tc.number: BmsPrintServiceOperatorTest_0007
 * @tc.name: test_remove_print_service_dir_not_exists
 * @tc.desc: Test removing print service directory when it does not exist (should not fail).
 * @tc.require: Issuexxx
 */
HWTEST_F(BmsPrintServiceOperatorTest, BmsPrintServiceOperatorTest_0007, Function | SmallTest | Level0)
{
    // Ensure directory does not exist
    CleanPrintServiceDir(TEST_BUNDLE_NAME, TEST_APP_INDEX);

    // Remove non-existent directory (should return ERR_OK, not fail)
    ErrCode ret = InstalldOperator::RemovePrintServiceDir(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsPrintServiceOperatorTest_0008
 * @tc.name: test_remove_print_service_dir_clone_app
 * @tc.desc: Test removing print service directory for clone application.
 * @tc.require: Issuexxx
 */
HWTEST_F(BmsPrintServiceOperatorTest, BmsPrintServiceOperatorTest_0008, Function | SmallTest | Level0)
{
    int32_t appIndex = 2;
    uid_t appUid = TEST_APP_UID + 2;

    // Create clone directory first
    ErrCode ret = InstalldOperator::CreatePrintServiceDir(TEST_BUNDLE_NAME_CLONE, TEST_USER_ID, appIndex, appUid);
    EXPECT_EQ(ret, ERR_OK);

    // Verify directory exists
    std::string bundleDirName = "+clone-" + std::to_string(appIndex) + "+" + TEST_BUNDLE_NAME_CLONE;
    std::string dirPath = std::string(PRINT_SERVICE_BASE_DIR) + "/" + bundleDirName;
    EXPECT_TRUE(CheckDirExist(dirPath));

    // Remove clone directory
    ret = InstalldOperator::RemovePrintServiceDir(TEST_BUNDLE_NAME_CLONE, TEST_USER_ID, appIndex);
    EXPECT_EQ(ret, ERR_OK);

    // Verify directory does not exist
    EXPECT_FALSE(CheckDirExist(dirPath));
}

/**
 * @tc.number: BmsPrintServiceOperatorTest_0009
 * @tc.name: test_remove_print_service_dir_invalid_parameters
 * @tc.desc: Test removing print service directory with invalid parameters.
 * @tc.require: Issuexxx
 */
HWTEST_F(BmsPrintServiceOperatorTest, BmsPrintServiceOperatorTest_0009, Function | SmallTest | Level0)
{
    // Test with empty bundle name
    ErrCode ret = InstalldOperator::RemovePrintServiceDir("", TEST_USER_ID, TEST_APP_INDEX);
    EXPECT_NE(ret, ERR_OK);

    // Test with negative user ID
    ret = InstalldOperator::RemovePrintServiceDir(TEST_BUNDLE_NAME, -1, TEST_APP_INDEX);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BmsPrintServiceOperatorTest_0010
 * @tc.name: test_create_print_service_dir_permission_repair
 * @tc.desc: Test creating print service directory when it exists with wrong permissions (should repair).
 * @tc.require: Issuexxx
 */
HWTEST_F(BmsPrintServiceOperatorTest, BmsPrintServiceOperatorTest_0010, Function | SmallTest | Level0)
{
    std::string dirPath = std::string(PRINT_SERVICE_BASE_DIR) + "/" + TEST_BUNDLE_NAME;

    // Create directory with wrong permissions manually
    mkdir(dirPath.c_str(), 0755);  // Wrong mode
    chown(dirPath.c_str(), 1000, 1000);  // Wrong uid/gid

    // Verify wrong permissions
    EXPECT_FALSE(CheckDirPermission(dirPath, TEST_APP_UID, PRINT_SERVICE_UID, PRINT_SERVICE_DIR_MODE));

    // Call CreatePrintServiceDir to repair permissions
    ErrCode ret = InstalldOperator::CreatePrintServiceDir(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX, TEST_APP_UID);
    EXPECT_EQ(ret, ERR_OK);

    // Verify permissions are repaired
    EXPECT_TRUE(CheckDirPermission(dirPath, TEST_APP_UID, PRINT_SERVICE_UID, PRINT_SERVICE_DIR_MODE));
}

}  // namespace OHOS
