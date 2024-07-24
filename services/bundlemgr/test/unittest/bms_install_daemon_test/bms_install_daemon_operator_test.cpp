/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <gtest/gtest.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "bundle_util.h"
#include "bundle_extractor.h"
#include "file_ex.h"
#include "installd/installd_operator.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
const std::string TEST_STRING = "test.string";
const std::string TEST_LIB_STRING = "libs/arm64/test.so";
const std::string TEST_ERROR_LIB_STRING = "libs/arm64/test.txt";
const std::string TEST_DIFF_LIB_STRING = "libs/arm64/test.diff";
const std::string TEST_CPU_ABI = "arm64";
const std::string TEST_CPU_ARM = "arm";
const std::string TEST_PATH = "/test/test/";
const std::string TEST_PATH_ONE = "/data/test/";
const std::string TEST_LIB_SO = "libs/arm64/test.so";
const std::string TEST_LIB_SO_X = "libs/arm64/test.so.9";
const std::string TEST_LIB_SO_XX = "libs/arm64/test.so.11";
const std::string TEST_LIB_SO_CUSTOM = "libs/arm64/test.so.a";
const std::string TEST_LIB_AN = "an/arm64/test.an";
const std::string TEST_LIB_AP = "ap/test.ap";
const std::string TEST_RES_FILE = "resources/resfile/test.txt";
const std::string TEST_FILE_PATH = "/system/etc";
const std::string TEST_ERROR_PATH = "/system/abc";
const std::string TEST_ZIP_PATH = "/system/etc/graphic/bootpic.zip";
const std::string TEST_DIR_PATH = "/data/app/el1/bundle/public/com.example.test";
const std::string TEST_QUICK_FIX_FILE_PATH_FIRST = "/data/app/el1/bundle/public/com.example.test/patch_1000001";
const std::string TEST_QUICK_FIX_FILE_PATH_SECOND = "/data/app/el1/bundle/public/com.example.test/patch_1000002";
const std::string HAP_FILE_PATH = "/data/app/el1/bundle/public/com.example.test/patch_1000001/entry.hqf";
const std::string HAP_FILE_PATH_BACKUP = "/data/app/el1/bundle/public/com.example.test/patch_1000002/entry.hqf";
const std::string HAP_PATH = "/data/app/el1/bundle/public/com.example.test";
const std::string OVER_MAX_PATH_SIZE(300, 'x');
}; // namespace
class BmsInstallDaemonOperatorTest : public testing::Test {
public:
    BmsInstallDaemonOperatorTest();
    ~BmsInstallDaemonOperatorTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void CreateQuickFileDir(const std::string &dir) const;
    void DeleteQuickFileDir(const std::string &dir) const;
};

BmsInstallDaemonOperatorTest::BmsInstallDaemonOperatorTest()
{}

BmsInstallDaemonOperatorTest::~BmsInstallDaemonOperatorTest()
{}

void BmsInstallDaemonOperatorTest::SetUpTestCase()
{
}

void BmsInstallDaemonOperatorTest::TearDownTestCase()
{}

void BmsInstallDaemonOperatorTest::SetUp()
{}

void BmsInstallDaemonOperatorTest::TearDown()
{}

void BmsInstallDaemonOperatorTest::CreateQuickFileDir(const std::string &dir) const
{
    bool ret = BundleUtil::CreateDir(dir);
    EXPECT_TRUE(ret);
}

void BmsInstallDaemonOperatorTest::DeleteQuickFileDir(const std::string &dir) const
{
    bool ret = BundleUtil::DeleteDir(dir);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_0100
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsExistFile of InstalldOperator
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_0100, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::IsExistFile(path);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_0200
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsExistFile of InstalldOperator
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_0200, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsExistFile(TEST_PATH);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_0300
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsExistDir of InstalldOperator
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_0300, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::IsExistDir(path);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_0400
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsExistDir of InstalldOperator
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_0400, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsExistDir("");
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_0500
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsDirEmpty of InstalldOperator
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_0500, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::IsDirEmpty(path);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_0600
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling MkRecursiveDir of InstalldOperator
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_0600, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::MkRecursiveDir(path, false);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_0700
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling DeleteDir of InstalldOperator
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_0700, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::DeleteDir(path);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_0800
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractFiles of InstalldOperator
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_0800, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::ExtractFiles(path, TEST_STRING, TEST_STRING);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_0900
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsNativeSo of InstalldOperator
 *           2. targetSoPath is empty and return false
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_0900, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsNativeSo(TEST_STRING, TEST_STRING);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_01000
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsNativeSo of InstalldOperator
 *           2. entryName does not contain prefix and return false
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_01000, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsNativeSo(TEST_STRING, TEST_CPU_ABI);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_1100
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsNativeSo of InstalldOperator
 *           2. entryName does not contain .so suffix and return true
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_1100, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsNativeSo(TEST_ERROR_LIB_STRING, TEST_CPU_ABI);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_1200
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsNativeSo of InstalldOperator
 *           2. return true
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_1200, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsNativeSo(TEST_LIB_STRING, TEST_CPU_ABI);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_1300
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsDiffFiles of InstalldOperator
 *           2. targetSoPath is empty and return false
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_1300, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::IsDiffFiles(TEST_STRING, path, TEST_STRING);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_1400
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsDiffFiles of InstalldOperator
 *           2. entryName does not contain prefix and return false
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_1400, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::IsDiffFiles(TEST_STRING, TEST_STRING, TEST_CPU_ABI);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_1500
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsDiffFiles of InstalldOperator
 *           2. entryName does not contain .so suffix and return false
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_1500, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::IsDiffFiles(TEST_ERROR_LIB_STRING, TEST_STRING, TEST_CPU_ABI);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_1600
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsDiffFiles of InstalldOperator
 *           2. return true
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_1600, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::IsDiffFiles(TEST_DIFF_LIB_STRING, TEST_STRING, TEST_CPU_ABI);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_1700
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ObtainQuickFixFileDir of InstalldOperator
 *           2. return false
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_1700, Function | SmallTest | Level0)
{
    std::vector<std::string> vec;
    std::string dir;
    auto ret = InstalldOperator::ObtainQuickFixFileDir(dir, vec);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_1800
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ObtainQuickFixFileDir of InstalldOperator
 *           2. return false
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_1800, Function | SmallTest | Level0)
{
    std::vector<std::string> vec;
    auto ret = InstalldOperator::ObtainQuickFixFileDir("", vec);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_1900
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ObtainQuickFixFileDir of InstalldOperator
 *           2. return true
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_1900, Function | SmallTest | Level0)
{
    std::vector<std::string> vec;
    CreateQuickFileDir(TEST_QUICK_FIX_FILE_PATH_FIRST);
    bool res = SaveStringToFile(HAP_FILE_PATH, HAP_FILE_PATH);
    EXPECT_TRUE(res);

    auto ret = InstalldOperator::ObtainQuickFixFileDir(TEST_QUICK_FIX_FILE_PATH_FIRST, vec);
    EXPECT_TRUE(ret);
    auto size = static_cast<int32_t>(vec.size());
    EXPECT_EQ(size, 1);
    EXPECT_EQ(vec[0], TEST_QUICK_FIX_FILE_PATH_FIRST);
    DeleteQuickFileDir(TEST_QUICK_FIX_FILE_PATH_FIRST);
}

/**
 * @tc.number: InstalldOperatorTest_2000
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling CopyFiles of InstalldOperator
 *           2. return false
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_2000, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::CopyFiles(path, TEST_STRING);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::CopyFiles(path, "/.../");
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_2100
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling CopyFiles of InstalldOperator
 *           2. return false
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_2100, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::CopyFiles(TEST_STRING, path);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_2200
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling CopyFiles of InstalldOperator
 *           2. return false
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_2200, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::CopyFiles(path, path);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_2300
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling CopyFiles of InstalldOperator
 *           2. return true
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_2300, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::CopyFiles(path, path);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_2400
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling CopyFiles of InstalldOperator
 *           2. return true
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_2400, Function | SmallTest | Level0)
{
    CreateQuickFileDir(TEST_QUICK_FIX_FILE_PATH_FIRST);
    CreateQuickFileDir(TEST_QUICK_FIX_FILE_PATH_SECOND);
    bool res = SaveStringToFile(HAP_FILE_PATH, HAP_FILE_PATH);
    EXPECT_TRUE(res);
    auto ret = InstalldOperator::CopyFiles(TEST_QUICK_FIX_FILE_PATH_FIRST, TEST_QUICK_FIX_FILE_PATH_SECOND);
    EXPECT_TRUE(ret);
    int bundleCodeExist = access(HAP_FILE_PATH_BACKUP.c_str(), F_OK);
    EXPECT_EQ(bundleCodeExist, 0);
}

/**
 * @tc.number: InstalldOperatorTest_2500
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling MkRecursiveDir of InstalldOperator
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_2500, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::MkRecursiveDir(path, true);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_2600
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsNativeFile of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_2600, Function | SmallTest | Level0)
{
    ExtractParam extractParam;
    auto ret = InstalldOperator::IsNativeFile(TEST_LIB_SO, extractParam);
    EXPECT_FALSE(ret);

    extractParam.srcPath = TEST_PATH;
    extractParam.targetPath = TEST_PATH;
    extractParam.cpuAbi = TEST_CPU_ABI;
    extractParam.extractFileType = ExtractFileType::SO;
    ret = InstalldOperator::IsNativeFile(TEST_LIB_SO, extractParam);
    EXPECT_TRUE(ret);
    ret = InstalldOperator::IsNativeFile(TEST_LIB_SO_X, extractParam);
    EXPECT_TRUE(ret);
    ret = InstalldOperator::IsNativeFile(TEST_LIB_SO_XX, extractParam);
    EXPECT_TRUE(ret);
    ret = InstalldOperator::IsNativeFile(TEST_LIB_SO_CUSTOM, extractParam);
    EXPECT_TRUE(ret);

    extractParam.extractFileType = ExtractFileType::PATCH;
    ret = InstalldOperator::IsNativeFile(TEST_LIB_SO, extractParam);
    EXPECT_FALSE(ret);

    extractParam.extractFileType = ExtractFileType::AN;
    ret = InstalldOperator::IsNativeFile(TEST_LIB_SO, extractParam);
    EXPECT_FALSE(ret);

    extractParam.extractFileType = ExtractFileType::AN;
    ret = InstalldOperator::IsNativeFile(TEST_LIB_AN, extractParam);
    EXPECT_TRUE(ret);

    extractParam.extractFileType = ExtractFileType::AN;
    ret = InstalldOperator::IsNativeFile(TEST_LIB_AP, extractParam);
    EXPECT_FALSE(ret);

    extractParam.extractFileType = ExtractFileType::AP;
    ret = InstalldOperator::IsNativeFile(TEST_LIB_AP, extractParam);
    EXPECT_TRUE(ret);

    extractParam.extractFileType = ExtractFileType::RES_FILE;
    ret = InstalldOperator::IsNativeFile(TEST_RES_FILE, extractParam);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_2700
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractFiles of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_2700, Function | SmallTest | Level0)
{
    ExtractParam extractParam;
    auto ret = InstalldOperator::ExtractFiles(extractParam);
    EXPECT_FALSE(ret);

    extractParam.srcPath = HAP_FILE_PATH;
    extractParam.targetPath = TEST_PATH;
    extractParam.cpuAbi = TEST_CPU_ABI;
    extractParam.extractFileType = ExtractFileType::SO;
    ret = InstalldOperator::ExtractFiles(extractParam);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_2800
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling MkOwnerDir of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_2800, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::MkOwnerDir(TEST_STRING, 0, 0, 0);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_2900
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling MkOwnerDir of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_2900, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::MkOwnerDir("", 0, 0, 0);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_3000
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ChangeDirOwnerRecursively of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_3000, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::ChangeDirOwnerRecursively("", 0, 0);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::ChangeDirOwnerRecursively("data/test", 0, -1);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_3100
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling RenameDir of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_3100, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::RenameDir("", "");
    EXPECT_FALSE(ret);
}
/**
 * @tc.number: InstalldOperatorTest_3200
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling RenameDir of InstalldOperator
 *           2. oldDir is over size
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_3200, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::RenameDir(OVER_MAX_PATH_SIZE, "");
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_3300
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling RenameFile of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_3300, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::RenameFile("", "");
    EXPECT_FALSE(ret);
    ret = InstalldOperator::RenameFile("", "/test/123");
    EXPECT_FALSE(ret);
    ret = InstalldOperator::RenameFile("/test/123", "");
    EXPECT_FALSE(ret);
    ret = InstalldOperator::RenameFile("/test/123", "/test/123");
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_3400
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling RenameFile of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_3400, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::RenameFile(TEST_PATH, TEST_PATH);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_3500
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling GetDiskUsageFromPath of InstalldOperator
 *           2. path is over size
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_3500, Function | SmallTest | Level0)
{
    std::vector<std::string> path;
    path.push_back(OVER_MAX_PATH_SIZE);
    auto ret = InstalldOperator::GetDiskUsageFromPath(path);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_3600
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling GetDiskUsageFromPath of InstalldOperator
 *           2. path is over empty
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_3600, Function | SmallTest | Level0)
{
    std::vector<std::string> path;
    path.push_back("");
    auto ret = InstalldOperator::GetDiskUsageFromPath(path);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldHostImplTest_3700
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling CopyFile of InstalldOperator
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_3700, Function | SmallTest | Level0)
{
    bool ret = InstalldOperator::CopyFile("", "");
    EXPECT_EQ(ret, false);
    ret = InstalldOperator::CopyFile("invaild", "");
    EXPECT_EQ(ret, false);
    ret = InstalldOperator::CopyFile("data/test", "invaild");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InstalldHostImplTest_3800
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ApplyDiffPatch of InstalldOperator
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_3800, Function | SmallTest | Level0)
{
    bool ret = InstalldOperator::ApplyDiffPatch(
        TEST_QUICK_FIX_FILE_PATH_FIRST, TEST_QUICK_FIX_FILE_PATH_SECOND, TEST_PATH, 0);
    EXPECT_EQ(ret, false);
    std::string tempPath = "/data/test/installOperator";
    CreateQuickFileDir(tempPath);
    ret = InstalldOperator::ApplyDiffPatch(
        tempPath, tempPath, tempPath, 0);
    EXPECT_EQ(ret, true);
    DeleteQuickFileDir(tempPath);
}

/**
 * @tc.number: InstalldHostImplTest_3900
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ApplyDiffPatch of InstalldOperator
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_3900, Function | SmallTest | Level0)
{
    bool ret = InstalldOperator::ApplyDiffPatch("", "", TEST_PATH, 0);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: InstalldHostImplTest_4000
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ApplyDiffPatch of InstalldOperator
 * @tc.require: issueI5T6P3
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_4000, Function | SmallTest | Level0)
{
    bool ret = InstalldOperator::ApplyDiffPatch(
        TEST_QUICK_FIX_FILE_PATH_FIRST, TEST_QUICK_FIX_FILE_PATH_SECOND, TEST_PATH, 0);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InstalldOperatorTest_4100
 * @tc.name: test function of ExtractDiffFiles
 * @tc.desc: 1. calling ExtractDiffFiles
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_4100, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::ExtractDiffFiles(
        TEST_QUICK_FIX_FILE_PATH_FIRST, TEST_PATH, TEST_CPU_ABI);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::ExtractDiffFiles("", TEST_PATH, TEST_CPU_ABI);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_4200
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractFiles of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_4200, Function | SmallTest | Level0)
{
    ExtractParam extractParam;
    extractParam.srcPath = "/system/etc/graphic/bootpic.zip";
    auto ret = InstalldOperator::ExtractFiles(extractParam);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_4300
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling RenameDir of InstalldOperator
 *           2. oldDir is over size
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_4300, Function | SmallTest | Level0)
{
    std::string oldPath = "/test/123";
    auto ret = InstalldOperator::RenameDir(oldPath, "");
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_4400
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ChangeDirOwnerRecursively of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_4400, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::ChangeDirOwnerRecursively(TEST_PATH_ONE, 0, 0);
    EXPECT_TRUE(ret);
    ret = InstalldOperator::ChangeDirOwnerRecursively("/system/etc/init/bootpic.zip", 0, 0);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_4500
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsValidPath of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_4500, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsValidPath("", "");
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPath("/test/", "");
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPath("/test", "");
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPath("..test", "");
    EXPECT_FALSE(ret);
    ret = InstalldOperator::IsValidPath("//", "..");
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_4600
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsValidCodePath of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_4600, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsValidCodePath("");
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_4700
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling DeleteFiles of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_4700, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::DeleteFiles("");
    EXPECT_FALSE(ret);
    ret = InstalldOperator::DeleteFiles("/test/123");
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_4800
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling MkOwnerDir of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_4800, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::MkOwnerDir("", false, 0, 0);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_4900
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling TraverseCacheDirectory of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_4900, Function | SmallTest | Level0)
{
    std::vector<std::string> cacheDirs;
    InstalldOperator::TraverseCacheDirectory("", cacheDirs);
    EXPECT_EQ(cacheDirs.size(), 0);
    InstalldOperator::TraverseCacheDirectory(OVER_MAX_PATH_SIZE, cacheDirs);
    EXPECT_EQ(cacheDirs.size(), 0);
}

/**
 * @tc.number: InstalldOperatorTest_5000
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ScanDir of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_5000, Function | SmallTest | Level0)
{
    std::vector<std::string> paths;
    bool res = InstalldOperator::ScanDir(
        "", ScanMode::SUB_FILE_FILE, ResultMode::RELATIVE_PATH, paths);
    EXPECT_EQ(res, false);
    res = InstalldOperator::ScanDir(
        OVER_MAX_PATH_SIZE, ScanMode::SUB_FILE_FILE, ResultMode::RELATIVE_PATH, paths);
    EXPECT_EQ(res, false);
    res = InstalldOperator::ScanDir(
        "//", ScanMode::SUB_FILE_FILE, ResultMode::RELATIVE_PATH, paths);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: InstalldOperatorTest_5100
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling OpenHandle of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_5100, Function | SmallTest | Level0)
{
    void **handle = nullptr;
    bool res = InstalldOperator::OpenHandle(handle);
    EXPECT_EQ(res, false);
    InstalldOperator::CloseHandle(handle);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: InstalldOperatorTest_5200
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ProcessApplyDiffPatchPath of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_5200, Function | SmallTest | Level0)
{
    std::vector<std::string> oldSoFileNames;
    std::vector<std::string> diffFileNames;
    bool res = InstalldOperator::ProcessApplyDiffPatchPath(
        "", "", "", oldSoFileNames, diffFileNames);
    EXPECT_EQ(res, false);
    res = InstalldOperator::ProcessApplyDiffPatchPath(
        "noExist", "noExist", "noExist", oldSoFileNames, diffFileNames);
    EXPECT_EQ(res, false);
    res = InstalldOperator::ProcessApplyDiffPatchPath(
        "data/test", "data/test", "data/test", oldSoFileNames, diffFileNames);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: InstalldOperatorTest_5300
 * @tc.name: test function of ExtractDiffFiles
 * @tc.desc: 1. calling ExtractDiffFiles
 * @tc.require: issueI6PNQX
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_5300, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::ExtractDiffFiles(TEST_ZIP_PATH, "", TEST_CPU_ABI);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_5400
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ProcessApplyDiffPatchPath of InstalldOperator
 * @tc.require: issueI6PNQX
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_5400, Function | SmallTest | Level0)
{
    DeleteQuickFileDir(TEST_DIR_PATH);
    CreateQuickFileDir(TEST_DIR_PATH);
    
    std::vector<std::string> oldSoFileNames;
    std::vector<std::string> diffFileNames;
    bool res = InstalldOperator::ProcessApplyDiffPatchPath(
        TEST_DIR_PATH, TEST_DIR_PATH, TEST_DIR_PATH, oldSoFileNames, diffFileNames);
    EXPECT_EQ(res, false);

    DeleteQuickFileDir(TEST_DIR_PATH);
}

/**
 * @tc.number: InstalldOperatorTest_5500
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ProcessApplyDiffPatchPath of InstalldOperator
 * @tc.require: issueI6PNQX
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_5500, Function | SmallTest | Level0)
{
    std::vector<std::string> oldSoFileNames;
    std::vector<std::string> diffFileNames;
    bool res = InstalldOperator::ProcessApplyDiffPatchPath(
        TEST_FILE_PATH, TEST_FILE_PATH, "", oldSoFileNames, diffFileNames);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: InstalldOperatorTest_5600
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ProcessApplyDiffPatchPath of InstalldOperator
 * @tc.require: issueI6PNQX
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_5600, Function | SmallTest | Level0)
{
    std::vector<std::string> oldSoFileNames;
    std::vector<std::string> diffFileNames;
    bool res = InstalldOperator::ProcessApplyDiffPatchPath(
        TEST_FILE_PATH, TEST_FILE_PATH, TEST_FILE_PATH, oldSoFileNames, diffFileNames);
    EXPECT_TRUE(res);
    res = InstalldOperator::ProcessApplyDiffPatchPath(
        TEST_FILE_PATH, TEST_FILE_PATH, "noExist", oldSoFileNames, diffFileNames);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: InstalldOperatorTest_5700
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ApplyDiffPatch of InstalldOperator
 * @tc.require: issueI6PNQX
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_5700, Function | SmallTest | Level0)
{
    bool ret = InstalldOperator::ApplyDiffPatch(TEST_FILE_PATH, TEST_FILE_PATH, TEST_FILE_PATH, 0);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::ApplyDiffPatch(TEST_FILE_PATH, TEST_FILE_PATH, "", 0);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::ApplyDiffPatch(TEST_FILE_PATH, TEST_FILE_PATH, TEST_FILE_PATH, 0);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_5800
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ObtainQuickFixFileDir of InstalldOperator
 *           2. return false
 * @tc.require: issueI6PNQX
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_5800, Function | SmallTest | Level0)
{
    std::vector<std::string> vec;
    std::string dir = TEST_ERROR_PATH;
    auto ret = InstalldOperator::ObtainQuickFixFileDir(dir, vec);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_5900
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling VerifyCodeSignature of InstalldOperator
 *           2. return false
 * @tc.require: issueI6PNQX
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_5900, Function | SmallTest | Level0)
{
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = TEST_STRING;
    codeSignatureParam.cpuAbi = TEST_STRING;
    codeSignatureParam.targetSoPath = TEST_STRING;
    codeSignatureParam.signatureFileDir = "";
    codeSignatureParam.isEnterpriseBundle = false;
    codeSignatureParam.appIdentifier = TEST_STRING;
    auto ret = InstalldOperator::VerifyCodeSignature(codeSignatureParam);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_6000
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractDiffFiles of InstalldOperator
 *           2. return false
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_6000, Function | SmallTest | Level0)
{
    BundleExtractor extractor("");
    InstalldOperator::ExtractTargetFile(extractor, "", "", "", ExtractFileType::SO);
    auto ret = InstalldOperator::ExtractDiffFiles(
        TEST_QUICK_FIX_FILE_PATH_FIRST, TEST_PATH, TEST_CPU_ABI);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_6100
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractDiffFiles of InstalldOperator
 *           2. return false
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_6100, Function | SmallTest | Level0)
{
    BundleExtractor extractor("");
    InstalldOperator::ExtractTargetFile(
        extractor, TEST_DIFF_LIB_STRING, "data/test", TEST_CPU_ABI, ExtractFileType::AP);
    InstalldOperator::ExtractTargetFile(extractor, "", "data/test", "", ExtractFileType::ALL);
    auto ret = InstalldOperator::ExtractDiffFiles(
        TEST_QUICK_FIX_FILE_PATH_FIRST, TEST_PATH, TEST_CPU_ABI);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_4300
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling RenameDir of InstalldOperator
 *           2. oldDir is over size
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_6200, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::RenameDir("/data/test", "/data/test/test");
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_6300
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling GetPathDir of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_6300, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::GetPathDir("");
    EXPECT_EQ(ret, std::string());
}

/**
 * @tc.number: InstalldOperatorTest_6400
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling GetPathDir of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_6400, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::GetPathDir("/data/");
    EXPECT_EQ(ret, "/data/");
}

/**
 * @tc.number: InstalldOperatorTest_6500
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling RenameFile of InstalldOperator
 * @tc.require: issueI6PNQX
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_6500, Function | SmallTest | Level0)
{
    CreateQuickFileDir("/data/OperatorTest");

    auto result = InstalldOperator::RenameFile("/data/OperatorTest", "/data/OperatorTest");
    EXPECT_FALSE(result);
    result = InstalldOperator::RenameFile("/data/OperatorTest", "/data/OperatorTest1");
    EXPECT_FALSE(result);

    DeleteQuickFileDir("/data/OperatorTest1");
}

/**
 * @tc.number: InstalldOperatorTest_6700
 * @tc.name: test function of GetNativeLibraryFileNames
 * @tc.desc: 1. calling GetNativeLibraryFileNames
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_6700, Function | SmallTest | Level0)
{
    std::vector<std::string> diffFileNames;
    bool res = InstalldOperator::GetNativeLibraryFileNames("", "", diffFileNames);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: InstalldOperatorTest_6800
 * @tc.name: test function of GetNativeLibraryFileNames
 * @tc.desc: 1. calling GetNativeLibraryFileNames
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_6800, Function | SmallTest | Level0)
{
    std::vector<std::string> diffFileNames;
    bool res = InstalldOperator::GetNativeLibraryFileNames(TEST_ZIP_PATH, TEST_CPU_ABI, diffFileNames);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: InstalldOperatorTest_6900
 * @tc.name: test function of VerifyCodeSignature
 * @tc.desc: 1. calling VerifyCodeSignature
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_6900, Function | SmallTest | Level0)
{
    CodeSignatureParam codeSignatureParam;
    bool res = InstalldOperator::VerifyCodeSignature(codeSignatureParam);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: InstalldOperatorTest_7000
 * @tc.name: test function of VerifyCodeSignature
 * @tc.desc: 1. calling VerifyCodeSignature
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_7000, Function | SmallTest | Level0)
{
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.signatureFileDir = "/";
    bool res = InstalldOperator::VerifyCodeSignature(codeSignatureParam);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: InstalldOperatorTest_7100
 * @tc.name: test function of CheckEncryption
 * @tc.desc: 1. calling CheckEncryption
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_7100, Function | SmallTest | Level0)
{
    CheckEncryptionParam checkEncryptionParam;
    checkEncryptionParam.modulePath = "";
    checkEncryptionParam.cpuAbi = TEST_STRING;
    checkEncryptionParam.targetSoPath = TEST_STRING;
    checkEncryptionParam.bundleId = -1;
    bool isEncrypted = false;
    bool res = InstalldOperator::CheckEncryption(checkEncryptionParam, isEncrypted);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: InstalldOperatorTest_7200
 * @tc.name: test function of ExtractDriverSoFiles
 * @tc.desc: 1. calling ExtractDriverSoFiles
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_7200, Function | SmallTest | Level0)
{
    std::string srcPath = "";
    std::unordered_multimap<std::string, std::string> dirMap;
    bool res = InstalldOperator::ExtractDriverSoFiles(srcPath, dirMap);
    EXPECT_EQ(res, false);

    srcPath = "invalid";
    res = InstalldOperator::ExtractDriverSoFiles(srcPath, dirMap);
    EXPECT_EQ(res, false);

    srcPath = "";
    dirMap.emplace(srcPath, srcPath);
    res = InstalldOperator::ExtractDriverSoFiles(srcPath, dirMap);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: InstalldOperatorTest_7300
 * @tc.name: test function of ExtractDriverSoFiles
 * @tc.desc: 1. calling ExtractDriverSoFiles
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_7300, Function | SmallTest | Level0)
{
    std::string srcPath = "invalid";
    std::unordered_multimap<std::string, std::string> dirMap;
    dirMap.emplace(srcPath, srcPath);
    bool res = InstalldOperator::ExtractDriverSoFiles(srcPath, dirMap);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: InstalldOperatorTest_7400
 * @tc.name: test function of ExtractDriverSoFiles
 * @tc.desc: 1. calling ExtractDriverSoFiles
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_7400, Function | SmallTest | Level0)
{
    std::string srcPath = "data/test";
    std::unordered_multimap<std::string, std::string> dirMap;
    dirMap.emplace(srcPath, srcPath);
    bool res = InstalldOperator::ExtractDriverSoFiles(srcPath, dirMap);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: InstalldOperatorTest_7500
 * @tc.name: test function of CopyDriverSoFiles
 * @tc.desc: 1. calling CopyDriverSoFiles
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_7500, Function | SmallTest | Level0)
{
    std::string destinedDir = "invalid";
    std::string originalDir = "invalid";
    BundleExtractor extractor("");
    bool res = InstalldOperator::CopyDriverSoFiles(extractor, originalDir, destinedDir);
    EXPECT_EQ(res, false);

    destinedDir = "invalid/";
    res = InstalldOperator::CopyDriverSoFiles(extractor, originalDir, destinedDir);
    EXPECT_EQ(res, false);

    destinedDir = "invalid/test";
    originalDir = "invalid/test";
    res = InstalldOperator::CopyDriverSoFiles(extractor, originalDir, destinedDir);
    EXPECT_EQ(res, false);

    destinedDir = "data/test";
    originalDir = "data/test";
    res = InstalldOperator::CopyDriverSoFiles(extractor, originalDir, destinedDir);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: InstalldOperatorTest_7600
 * @tc.name: test function of GenerateKeyIdAndSetPolicy
 * @tc.desc: 1. calling GenerateKeyIdAndSetPolicy
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_7600, Function | SmallTest | Level0)
{
    std::string keyId = "";
    bool res = InstalldOperator::GenerateKeyIdAndSetPolicy(0, "", 100, keyId);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: InstalldOperatorTest_7700
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractFiles of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_7700, Function | SmallTest | Level0)
{
    ExtractParam extractParam;
    std::string hnpPackageInfo;
    auto ret = InstalldOperator::ExtractFiles(hnpPackageInfo, extractParam);
    EXPECT_FALSE(ret);

    extractParam.srcPath = HAP_FILE_PATH;
    extractParam.targetPath = TEST_PATH;
    extractParam.cpuAbi = TEST_CPU_ABI;
    extractParam.extractFileType = ExtractFileType::HNPS_FILE;
    ret = InstalldOperator::ExtractFiles(hnpPackageInfo, extractParam);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_7800
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling DeleteKeyId of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_7800, Function | SmallTest | Level0)
{
    std::string keyId;
    bool ret = InstalldOperator::DeleteKeyId(keyId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InstalldOperatorTest_7900
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling GetAtomicServiceBundleDataDir of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_7900, Function | SmallTest | Level0)
{
    std::string bundleName;
    int32_t userId = 100;
    std::vector<std::string> allPathNames;
    bool ret = InstalldOperator::GetAtomicServiceBundleDataDir(bundleName, userId, allPathNames);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: InstalldOperatorTest_8000
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ProcessBundleInstallNative of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_8000, Function | SmallTest | Level0)
{
    std::string userId = "100";
    std::string hnpRootPath = "/hnp/root/path";
    std::string hapPath = "happath";
    std::string cpuAbi = "cpuabi";
    std::string packageName = "";
    bool ret = InstalldOperator::ProcessBundleInstallNative(userId, hnpRootPath, hapPath, cpuAbi, packageName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_8100
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ProcessBundleInstallNative of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_8100, Function | SmallTest | Level0)
{
    std::string userId = "100";
    std::string hnpRootPath = "/hnp/root/path";
    std::string hapPath = "";
    std::string cpuAbi = "cpuabi";
    std::string packageName = "com.acts.example";
    bool ret = InstalldOperator::ProcessBundleInstallNative(userId, hnpRootPath, hapPath, cpuAbi, packageName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_8200
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ProcessBundleInstallNative of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_8200, Function | SmallTest | Level0)
{
    std::string userId = "100";
    std::string hnpRootPath = "/hnp/root/path";
    std::string hapPath = "happath";
    std::string cpuAbi = "";
    std::string packageName = "com.acts.example";
    bool ret = InstalldOperator::ProcessBundleInstallNative(userId, hnpRootPath, hapPath, cpuAbi, packageName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_8300
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ProcessBundleUnInstallNative of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_8300, Function | SmallTest | Level0)
{
    std::string userId = "";
    std::string packageName = "";
    bool ret = InstalldOperator::ProcessBundleUnInstallNative(userId, packageName);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_8400
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ProcessBundleUnInstallNative of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_8400, Function | SmallTest | Level0)
{
    std::string userId = "100";
    std::string packageName = "com.acts.example";
    bool ret = InstalldOperator::ProcessBundleUnInstallNative(userId, packageName);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_8500
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling DeleteFilesExceptDirs of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_8500, Function | SmallTest | Level0)
{
    std::string dataPath = "/data/data.path";
    std::vector<std::string> dirsToKeep;
    bool ret = InstalldOperator::DeleteFilesExceptDirs(dataPath, dirsToKeep);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_8600
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling DeleteFilesExceptDirs of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_8600, Function | SmallTest | Level0)
{
    std::string dataPath = "";
    std::vector<std::string> dirsToKeep;
    bool ret = InstalldOperator::DeleteFilesExceptDirs(dataPath, dirsToKeep);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_8700
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling InitialiseQuotaMounts of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_8700, Function | SmallTest | Level0)
{
    bool ret = InstalldOperator::InitialiseQuotaMounts();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_8800
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling GetDiskUsageFromQuota of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_8800, Function | SmallTest | Level0)
{
    int32_t uid = 100;
    int64_t ret = InstalldOperator::GetDiskUsageFromQuota(uid);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: InstalldOperatorTest_8900
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling PrepareEntryMap of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_8900, Function | SmallTest | Level0)
{
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.targetSoPath = "target/file.path";
    std::vector<std::string> soEntryFiles;
    Security::CodeSign::EntryMap entryMap;
    bool ret = InstalldOperator::PrepareEntryMap(codeSignatureParam, soEntryFiles, entryMap);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_9000
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling PerformCodeSignatureCheck of InstalldOperator
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_9000, Function | SmallTest | Level0)
{
    CodeSignatureParam codeSignatureParam;
    Security::CodeSign::EntryMap entryMap;
    ErrCode ret = InstalldOperator::PerformCodeSignatureCheck(codeSignatureParam, entryMap);
    EXPECT_EQ(ret, ERR_OK);
}
} // OHOS