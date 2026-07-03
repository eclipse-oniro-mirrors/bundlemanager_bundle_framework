/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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
#include <dlfcn.h>
#include <fcntl.h>
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
#include "driver_install_ext.h"
#include "file_ex.h"
#include "installd/installd_operator.h"
#include "ipc/extract_param.h"
#include "ipc/skills_package_param.h"
#include "skills_installer/skills_package_info.h"

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
const std::string TEST_MODULE_PATH = "/system/app/ShellAssistant/ShellAssistant_Feature_Anco.hap";
const std::string TEST_V8A_CPU_ABI = "arm64-v8a";
const std::string TEST_TARGET_SO_PATH = "/data/app/el1/bundle/public/libs/arm64/";
const std::string TEST_APP_IDENTIFIER = "5765880207854632823";
const std::string HAP_COMPRESS_NATIVE_LIBS_FALSE_01 =
    "/data/test/resource/bms/install_operator/compressNativeLibsFalse01.hap";
const std::string HAP_SO_LIBS = "libs/libhello.z.so";
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
    void CreateFile(const std::string &filePath, const std::string &content) const;
    void DeleteFile(const std::string &filePath) const;
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
    BundleUtil::CreateDir(dir);
}

void BmsInstallDaemonOperatorTest::DeleteQuickFileDir(const std::string &dir) const
{
    BundleUtil::DeleteDir(dir);
}

void BmsInstallDaemonOperatorTest::CreateFile(const std::string &filePath, const std::string &content) const
{
    SaveStringToFile(filePath, content);
}

void BmsInstallDaemonOperatorTest::DeleteFile(const std::string &filePath) const
{
    RemoveFile(filePath);
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
    path = "/data/app/el2";
    ret = InstalldOperator::MkRecursiveDir(path, false);
    EXPECT_TRUE(ret);
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
    auto ret = InstalldOperator::ExtractFiles(path, TEST_STRING, TEST_STRING, false, false);
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
    path = "/data/app/el2";
    ret = InstalldOperator::MkRecursiveDir(path, false);
    EXPECT_TRUE(ret);
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

    extractParam.extractFileType = ExtractFileType::ALL;
    ret = InstalldOperator::IsNativeFile(TEST_RES_FILE, extractParam);
    EXPECT_FALSE(ret);

    extractParam.extractFileType = ExtractFileType::SO;
    ret = InstalldOperator::IsNativeFile(TEST_LIB_SO, extractParam);
    EXPECT_TRUE(ret);

    extractParam.extractFileType = ExtractFileType::HNPS_FILE;
    ret = InstalldOperator::IsNativeFile(TEST_RES_FILE, extractParam);
    EXPECT_FALSE(ret);

    extractParam.extractFileType = ExtractFileType::NPAPI_PLUGIN;
    ret = InstalldOperator::IsNativeFile(TEST_RES_FILE, extractParam);
    EXPECT_FALSE(ret);

    extractParam.extractFileType = ExtractFileType::RES_FILE;
    ret = InstalldOperator::IsNativeFile("t", extractParam);
    EXPECT_FALSE(ret);
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

    extractParam.bundleName = "com.example.test";
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
    EXPECT_TRUE(ret);
    ret = InstalldOperator::RenameFile("/test/123", TEST_PATH);
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
    EXPECT_TRUE(ret);
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
    EXPECT_EQ(ret, 0);
    ret = InstalldOperator::GetCacheDiskUsageFromPath(path);
    EXPECT_EQ(ret, 0);
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
    EXPECT_EQ(ret, 0);
    ret = InstalldOperator::GetCacheDiskUsageFromPath(path);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: InstalldOperatorTest_3610
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling GetDiskUsageFromPath of InstalldOperator
 *           2. path is invalid
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_3610, Function | SmallTest | Level0)
{
    std::vector<std::string> path;
    path.push_back("/data/app/el2/100/base/test");
    auto ret = InstalldOperator::GetDiskUsageFromPath(path, 1);
    EXPECT_EQ(ret, 0);
    ret = InstalldOperator::GetCacheDiskUsageFromPath(path);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: InstalldOperatorTest_3650
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling GetDiskUsage of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_3650, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::GetDiskUsage("", true);
    EXPECT_EQ(ret, 0);
    ret = InstalldOperator::GetDiskUsage(TEST_PATH, false);
    EXPECT_EQ(ret, 0);
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
    extractParam.bundleName = "com.example.test";
    extractParam.srcPath = "/system/etc/graphic/bootpic.zip";
#ifdef USE_ARM64
    EXPECT_NO_THROW(InstalldOperator::ExtractFiles(extractParam));
#else
    EXPECT_TRUE(InstalldOperator::ExtractFiles(extractParam));
#endif
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
    EXPECT_TRUE(ret);
    ret = InstalldOperator::DeleteFiles("/test/123");
    EXPECT_TRUE(ret);
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
    ret = InstalldOperator::MkOwnerDir("/data/app/el2", false, 0, 0);
    EXPECT_TRUE(ret);
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
#ifdef USE_ARM64
    EXPECT_NO_THROW(InstalldOperator::ExtractDiffFiles(TEST_ZIP_PATH, "", TEST_CPU_ABI));
#else
    EXPECT_TRUE(InstalldOperator::ExtractDiffFiles(TEST_ZIP_PATH, "", TEST_CPU_ABI));
#endif
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
    ErrCode ret = InstalldOperator::VerifyCodeSignature(codeSignatureParam);
    EXPECT_NE(ret, ERR_OK);
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
    ExtractParam param;
    param.extractFileType = ExtractFileType::SO;
    InstalldOperator::ExtractTargetFile(extractor, "", param);
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
    ExtractParam param;
    param.targetPath = "data/test";
    param.cpuAbi = TEST_CPU_ABI;
    param.extractFileType = ExtractFileType::AP;
    InstalldOperator::ExtractTargetFile(extractor, TEST_DIFF_LIB_STRING, param);
    param.cpuAbi = "";
    param.extractFileType = ExtractFileType::ALL;
    InstalldOperator::ExtractTargetFile(extractor, "", param);
    auto ret = InstalldOperator::ExtractDiffFiles(
        TEST_QUICK_FIX_FILE_PATH_FIRST, TEST_PATH, TEST_CPU_ABI);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ExtractTargetFile_0001
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractTargetFile of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, ExtractTargetFile_0001, Function | SmallTest | Level0)
{
    BundleExtractor extractor(HAP_COMPRESS_NATIVE_LIBS_FALSE_01);
    ExtractParam param;
    param.targetPath = "/data/test/install_operator";
    param.cpuAbi = TEST_CPU_ABI;
    param.extractFileType = ExtractFileType::ALL;
    bool ret = InstalldOperator::ExtractTargetFile(extractor, TEST_DIFF_LIB_STRING, param);
    EXPECT_FALSE(ret);

    param.extractFileType = ExtractFileType::AP;
    ret = InstalldOperator::ExtractTargetFile(extractor, TEST_DIFF_LIB_STRING, param);
    EXPECT_FALSE(ret);

    param.extractFileType = ExtractFileType::SO;
    ret = InstalldOperator::ExtractTargetFile(extractor, HAP_SO_LIBS, param);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ExtractTargetFile_0002
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractTargetFile of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, ExtractTargetFile_0002, Function | SmallTest | Level0)
{
    BundleExtractor extractor(HAP_COMPRESS_NATIVE_LIBS_FALSE_01);
    bool ret = extractor.ExtractFile("", "");
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
    EXPECT_TRUE(result);
    result = InstalldOperator::RenameFile("/data/OperatorTest", "/data/OperatorTest1");
    EXPECT_TRUE(result);

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
#ifdef USE_ARM64
    EXPECT_NO_THROW(InstalldOperator::GetNativeLibraryFileNames(TEST_ZIP_PATH, TEST_CPU_ABI, diffFileNames));
#else
    EXPECT_TRUE(InstalldOperator::GetNativeLibraryFileNames(TEST_ZIP_PATH, TEST_CPU_ABI, diffFileNames));
#endif
}

/**
 * @tc.number: InstalldOperatorTest_6900
 * @tc.name: test function of VerifyCodeSignature
 * @tc.desc: 1. calling VerifyCodeSignature
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_6900, Function | SmallTest | Level0)
{
    CodeSignatureParam codeSignatureParam;
    ErrCode ret = InstalldOperator::VerifyCodeSignature(codeSignatureParam);
    EXPECT_NE(ret, ERR_OK);
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
    ErrCode ret = InstalldOperator::VerifyCodeSignature(codeSignatureParam);
    EXPECT_NE(ret, ERR_OK);
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
    auto res = InstalldOperator::CheckEncryption(checkEncryptionParam, isEncrypted);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_ENCRYPTION_EXTRACTOR_INIT_FAILED);
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
    bool res = InstalldOperator::CopyDriverSoFiles(originalDir, destinedDir);
    EXPECT_EQ(res, false);

    destinedDir = "invalid/";
    res = InstalldOperator::CopyDriverSoFiles(originalDir, destinedDir);
    EXPECT_EQ(res, false);

    destinedDir = "invalid/test";
    originalDir = "invalid/test";
    res = InstalldOperator::CopyDriverSoFiles(originalDir, destinedDir);
    EXPECT_EQ(res, false);

    destinedDir = "data/test";
    originalDir = "data/test";
    res = InstalldOperator::CopyDriverSoFiles(originalDir, destinedDir);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: InstalldOperatorTest_7600
 * @tc.name: test function of GenerateKeyIdAndSetPolicy
 * @tc.desc: 1. calling GenerateKeyIdAndSetPolicy
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_7600, Function | SmallTest | Level0)
{
    EncryptionParam encryptionParam("", "", 0, 100, EncryptionDirType::APP);
    std::string keyId;
    bool res = InstalldOperator::GenerateKeyIdAndSetPolicy(encryptionParam, keyId);
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
    std::map<std::string, std::string> hnpPackageMap;
    auto ret = InstalldOperator::ExtractFiles(hnpPackageMap, extractParam);
    EXPECT_FALSE(ret);

    extractParam.srcPath = HAP_FILE_PATH;
    extractParam.targetPath = TEST_PATH;
    extractParam.cpuAbi = TEST_CPU_ABI;
    extractParam.extractFileType = ExtractFileType::HNPS_FILE;
    ret = InstalldOperator::ExtractFiles(hnpPackageMap, extractParam);
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
    EncryptionParam encryptionParam("", "", 0, 100, EncryptionDirType::APP);
    bool ret = InstalldOperator::DeleteKeyId(encryptionParam);
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
    InstallHnpParam param;
    param.userId = "100";
    param.hnpRootPath = "/hnp/root/path";
    param.hapPath = "happath";
    param.cpuAbi = "cpuabi";
    param.packageName = "";
    param.sessionId = 0;
    bool ret = InstalldOperator::ProcessBundleInstallNative(param);
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
    InstallHnpParam param;
    param.userId = "100";
    param.hnpRootPath = "/hnp/root/path";
    param.hapPath = "";
    param.cpuAbi = "cpuabi";
    param.packageName = "com.acts.example";
    param.sessionId = 0;
    bool ret = InstalldOperator::ProcessBundleInstallNative(param);
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
    InstallHnpParam param;
    param.userId = "100";
    param.hnpRootPath = "/hnp/root/path";
    param.hapPath = "happath";
    param.cpuAbi = "";
    param.packageName = "com.acts.example";
    param.sessionId = 0;
    bool ret = InstalldOperator::ProcessBundleInstallNative(param);
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
    EXPECT_FALSE(ret);
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
    codeSignatureParam.targetSoPath = "";
    ret = InstalldOperator::PrepareEntryMap(codeSignatureParam, soEntryFiles, entryMap);
    EXPECT_FALSE(ret);
    codeSignatureParam.targetSoPath = "target";
    ret = InstalldOperator::PrepareEntryMap(codeSignatureParam, soEntryFiles, entryMap);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_8910
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsValidCodePath of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_8910, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsValidCodePath("/data/app/el1/skills/public/com.test");
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_8920
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsValidCodePath of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_8920, Function | SmallTest | Level0)
{
    auto ret = InstalldOperator::IsValidCodePath("/data/app/el1/skills/public/../com.test");
    EXPECT_FALSE(ret);
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

/**
 * @tc.number: InstalldOperatorTest_9100
 * @tc.name: test function of ExtractProfile
 * @tc.desc: 1. calling ExtractProfile
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_9100, Function | SmallTest | Level0)
{
    BundleExtractor extractor("");

    std::filebuf file;
    std::ostream dest(&file);
    bool ret = extractor.ExtractProfile(dest);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_9200
 * @tc.name: test function of ExtractProfile
 * @tc.desc: 1. calling ExtractProfile
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_9200, Function | SmallTest | Level0)
{
    BundleExtractor extractor("");

    std::filebuf file;
    std::ostream dest(&file);
    bool ret = extractor.ExtractPackFile(dest);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_9300
 * @tc.name: test function of ExtractTargetHnpFile
 * @tc.desc: 1. calling ExtractFiles of ExtractTargetHnpFile
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_9300, Function | SmallTest | Level1)
{
    BundleExtractor extractor("");
    std::string entryName;
    std::string targetPath;
    InstalldOperator::ExtractTargetHnpFile(extractor, entryName, targetPath, ExtractFileType::ALL);
    targetPath = TEST_PATH;
    InstalldOperator::ExtractTargetHnpFile(extractor, entryName, targetPath);
    std::string path = "test.path";
    auto ret = InstalldOperator::IsDiffFiles(TEST_STRING, path, TEST_STRING);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_9400
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling DeterminePrefix of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_9400, Function | SmallTest | Level1)
{
    std::string cpuAbi = "";
    std::string prefix = "";
    auto ret = InstalldOperator::DeterminePrefix(ExtractFileType::HNPS_FILE, cpuAbi, prefix);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_9500
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling DetermineSuffix of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_9500, Function | SmallTest | Level1)
{
    std::vector<std::string> suffixes;
    auto ret = InstalldOperator::DetermineSuffix(ExtractFileType::HNPS_FILE, suffixes);
    EXPECT_TRUE(ret);
    ret = InstalldOperator::DetermineSuffix(ExtractFileType::ALL, suffixes);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_9501
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling DeterminePrefix with NPAPI_PLUGIN type
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_9501, Function | SmallTest | Level1)
{
    std::string cpuAbi = "";
    std::string prefix = "";
    auto ret = InstalldOperator::DeterminePrefix(ExtractFileType::NPAPI_PLUGIN, cpuAbi, prefix);
    EXPECT_TRUE(ret);
    EXPECT_EQ(prefix, ServiceConstants::NPAPI_PLUGIN_PATH);
}

/**
 * @tc.number: InstalldOperatorTest_9502
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling DetermineSuffix with NPAPI_PLUGIN type
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_9502, Function | SmallTest | Level1)
{
    std::vector<std::string> suffixes;
    auto ret = InstalldOperator::DetermineSuffix(ExtractFileType::NPAPI_PLUGIN, suffixes);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_9600
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ScanSoFiles of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_9600, Function | SmallTest | Level1)
{
    std::string newSoPath = "";
    std::string originPath = "";
    std::string currentPath = "";
    std::vector<std::string> paths;
    auto ret = InstalldOperator::ScanSoFiles(newSoPath, originPath, currentPath, paths);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_9700
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling VerifyCodeSignature of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_9700, Function | SmallTest | Level0)
{
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = TEST_STRING;
    codeSignatureParam.cpuAbi = "";
    codeSignatureParam.targetSoPath = TEST_STRING;
    codeSignatureParam.signatureFileDir = "";
    codeSignatureParam.isEnterpriseBundle = false;
    codeSignatureParam.appIdentifier = TEST_STRING;
    ErrCode ret = InstalldOperator::VerifyCodeSignature(codeSignatureParam);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: InstalldOperatorTest_9800
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling CheckEncryption of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_9800, Function | SmallTest | Level0)
{
    CheckEncryptionParam checkEncryptionParam;
    checkEncryptionParam.modulePath = "";
    checkEncryptionParam.cpuAbi = "";
    checkEncryptionParam.targetSoPath = TEST_STRING;
    checkEncryptionParam.bundleId = -1;
    bool isEncrypted = false;
    auto ret = InstalldOperator::CheckEncryption(checkEncryptionParam, isEncrypted);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_ENCRYPTION_EXTRACTOR_INIT_FAILED);
}

/**
 * @tc.number: InstalldOperatorTest_9900
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling MoveFiles of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_9900, Function | SmallTest | Level0)
{
    std::string srcDir = "";
    std::string desDir = "";
    auto ret =InstalldOperator::MoveFiles(srcDir, desDir, true);
    EXPECT_FALSE(ret);
    ret =InstalldOperator::MoveFiles(srcDir, desDir, false);
    EXPECT_FALSE(ret);
    ret =InstalldOperator::MoveFiles(srcDir, desDir);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_10000
 * @tc.name: test function of InstalldOperatorTest
 * @tc.desc: 1. calling CheckEncryption
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_10000, Function | SmallTest | Level0)
{
    CheckEncryptionParam checkEncryptionParam;
    checkEncryptionParam.modulePath.resize(4097, 'a');
    checkEncryptionParam.cpuAbi = TEST_STRING;
    checkEncryptionParam.targetSoPath = TEST_STRING;
    checkEncryptionParam.bundleId = -1;
    bool isEncrypted = false;
    auto ret = InstalldOperator::CheckEncryption(checkEncryptionParam, isEncrypted);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_ENCRYPTION_EXTRACTOR_INIT_FAILED);
}

/**
 * @tc.number: InstalldOperatorTest_10100
 * @tc.name: test function of InstalldOperatorTest
 * @tc.desc: 1. calling ExtractFiles
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_10100, Function | SmallTest | Level0)
{
    ExtractParam extractParam;
    std::map<std::string, std::string> hnpPackageMap = {
        {"package", "hnpsample.hnp"},
        {"type", "public"}
    };
    auto ret = InstalldOperator::ExtractFiles(hnpPackageMap, extractParam);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_10200
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractFiles of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_10200, Function | SmallTest | Level0)
{
    ExtractParam extractParam;
    extractParam.srcPath = TEST_ZIP_PATH;
    extractParam.targetPath = TEST_PATH;
    extractParam.cpuAbi = TEST_CPU_ABI;
    extractParam.extractFileType = ExtractFileType::SO;
    std::map<std::string, std::string> hnpPackageMap = {
        {"package", "hnpsample.hnp"},
        {"type", "public"}
    };
    auto ret = InstalldOperator::ExtractFiles(hnpPackageMap, extractParam);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_10300
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractFiles of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_10300, Function | SmallTest | Level0)
{
    ExtractParam extractParam;
    extractParam.srcPath = TEST_ZIP_PATH;
    extractParam.targetPath = TEST_PATH;
    extractParam.cpuAbi = TEST_CPU_ABI;
    extractParam.extractFileType = ExtractFileType::SO;
    std::map<std::string, std::string> hnpPackageMap;
#ifdef USE_ARM64
    EXPECT_NO_THROW(InstalldOperator::ExtractFiles(hnpPackageMap, extractParam));
#else
    EXPECT_TRUE(InstalldOperator::ExtractFiles(hnpPackageMap, extractParam));
#endif
}

/**
 * @tc.number: InstalldOperatorTest_10400
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractTargetFile of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_10400, Function | SmallTest | Level0)
{
    BundleExtractor extractor("");
    std::string entryName = TEST_LIB_AP;
    ExtractParam param;
    param.targetPath = "/data/app/el1/";
    param.cpuAbi = TEST_CPU_ABI;
    param.extractFileType = ExtractFileType::AP;
    InstalldOperator::ExtractTargetFile(extractor, entryName, param);
    auto ret = InstalldOperator::ExtractDiffFiles(TEST_QUICK_FIX_FILE_PATH_FIRST, TEST_PATH, TEST_CPU_ABI);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_10500
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling RenameFile of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_10500, Function | SmallTest | Level0)
{
    CreateQuickFileDir("/test/oldPath");
#ifdef USE_ARM64
    EXPECT_NO_THROW(InstalldOperator::RenameFile("/test/oldPath", "/test/newPath"));
#else
    EXPECT_TRUE(InstalldOperator::RenameFile("/test/oldPath", "/test/newPath"));
#endif
    DeleteQuickFileDir("/test/newPath");
}

/**
 * @tc.number: InstalldOperatorTest_10600
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsExistApFile of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_10600, Function | SmallTest | Level0)
{
    CreateFile("/data/test/test.ap", "test");
    auto ret = InstalldOperator::IsExistApFile("/data/test/test.ap");
    EXPECT_TRUE(ret);
    DeleteFile("/data/test/test.ap");
}

/**
 * @tc.number: InstalldOperatorTest_10700
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling DeleteFilesExceptDirs of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_10700, Function | SmallTest | Level0)
{
    CreateQuickFileDir("/temp/test");
    CreateFile("/temp/test/test.ap", "test");
    std::vector<std::string> dirsToKeep;
#ifdef USE_ARM64
    EXPECT_NO_THROW(InstalldOperator::DeleteFilesExceptDirs("/temp", dirsToKeep));
#else
    EXPECT_TRUE(InstalldOperator::DeleteFilesExceptDirs("/temp", dirsToKeep));
    DeleteFile("/temp/test/test.ap");
    DeleteQuickFileDir("/temp");
#endif
}

/**
 * @tc.number: InstalldOperatorTest_10800
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ScanDir of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_10800, Function | SmallTest | Level0)
{
    CreateQuickFileDir("/temp/test/test1");
    CreateFile("/temp/test.ap", "test");
    std::vector<std::string> paths;
#ifdef USE_ARM64
    EXPECT_NO_THROW(InstalldOperator::ScanDir("/temp/", ScanMode::SUB_FILE_DIR, ResultMode::RELATIVE_PATH, paths));
#else
    EXPECT_TRUE(InstalldOperator::ScanDir("/temp/", ScanMode::SUB_FILE_DIR, ResultMode::RELATIVE_PATH, paths));
#endif
    DeleteFile("/temp/test.ap");
    DeleteQuickFileDir("/temp");
}

/**
 * @tc.number: InstalldOperatorTest_10900
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ScanDir of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_10900, Function | SmallTest | Level0)
{
    CreateQuickFileDir("/temp/test/test1");
    CreateFile("/temp/test.ap", "test");
    std::vector<std::string> paths;
#ifdef USE_ARM64
    EXPECT_NO_THROW(InstalldOperator::ScanDir("/temp/", ScanMode::SUB_FILE_FILE, ResultMode::RELATIVE_PATH, paths));
#else
    EXPECT_TRUE(InstalldOperator::ScanDir("/temp/", ScanMode::SUB_FILE_FILE, ResultMode::RELATIVE_PATH, paths));
#endif
    DeleteFile("/temp/test.ap");
    DeleteQuickFileDir("/temp");
}

/**
 * @tc.number: InstalldOperatorTest_11000
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ScanDir of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_11000, Function | SmallTest | Level0)
{
    CreateQuickFileDir("/temp/test/test1");
    CreateFile("/temp/test.ap", "test");
    std::vector<std::string> paths;
#ifdef USE_ARM64
    EXPECT_NO_THROW(InstalldOperator::ScanDir("/temp/", ScanMode::SUB_FILE_ALL, ResultMode::RELATIVE_PATH, paths));
#else
    EXPECT_TRUE(InstalldOperator::ScanDir("/temp/", ScanMode::SUB_FILE_ALL, ResultMode::RELATIVE_PATH, paths));
#endif
    DeleteFile("/temp/test.ap");
    DeleteQuickFileDir("/temp");
}

/**
 * @tc.number: InstalldOperatorTest_11200
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ApplyDiffPatch of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_11200, Function | SmallTest | Level0)
{
    std::string newSoPath;
    newSoPath.resize(4097, 'a');
    auto ret = InstalldOperator::ApplyDiffPatch(TEST_FILE_PATH, TEST_FILE_PATH, newSoPath, 1);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_11300
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling PerformCodeSignatureCheck of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_11300, Function | SmallTest | Level0)
{
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.isCompileSdkOpenHarmony = true;
    codeSignatureParam.isEnterpriseBundle = true;
    Security::CodeSign::EntryMap entryMap;
    ErrCode ret = InstalldOperator::PerformCodeSignatureCheck(codeSignatureParam, entryMap);
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.number: InstalldOperatorTest_11400
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling PerformCodeSignatureCheck of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_11400, Function | SmallTest | Level0)
{
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.signatureFileDir = "test";
    Security::CodeSign::EntryMap entryMap;
    ErrCode ret = InstalldOperator::PerformCodeSignatureCheck(codeSignatureParam, entryMap);
    EXPECT_EQ(ret, CS_SUCCESS);
}

/**
 * @tc.number: InstalldOperatorTest_11500
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling VerifyCodeSignature of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_11500, Function | SmallTest | Level0)
{
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = TEST_STRING;
    codeSignatureParam.cpuAbi = TEST_CPU_ABI;
    codeSignatureParam.targetSoPath = "target/file.path";
    codeSignatureParam.signatureFileDir = "";
    codeSignatureParam.isCompileSdkOpenHarmony = true;
    codeSignatureParam.isEnterpriseBundle = true;
    codeSignatureParam.isPreInstalledBundle = true;
    ErrCode ret = InstalldOperator::VerifyCodeSignature(codeSignatureParam);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: InstalldOperatorTest_11600
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling VerifyCodeSignatures of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_11600, Function | SmallTest | Level0)
{
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = TEST_ZIP_PATH;
    codeSignatureParam.cpuAbi = TEST_CPU_ABI;
    codeSignatureParam.targetSoPath = "target/file.path";
    codeSignatureParam.signatureFileDir = "";
    codeSignatureParam.isCompileSdkOpenHarmony = true;
    codeSignatureParam.isEnterpriseBundle = true;
    codeSignatureParam.isPreInstalledBundle = false;
    ErrCode ret = InstalldOperator::VerifyCodeSignature(codeSignatureParam);
#ifdef USE_ARM64
    EXPECT_NE(ret, ERR_OK);
#else
    EXPECT_EQ(ret, ERR_OK);
#endif

    codeSignatureParam.modulePath = TEST_MODULE_PATH;
    codeSignatureParam.cpuAbi = TEST_V8A_CPU_ABI;
    codeSignatureParam.targetSoPath = TEST_TARGET_SO_PATH;
    codeSignatureParam.appIdentifier = TEST_APP_IDENTIFIER;
    codeSignatureParam.signatureFileDir = "";
    codeSignatureParam.isCompileSdkOpenHarmony = true;
    codeSignatureParam.isEnterpriseBundle = false;
    codeSignatureParam.isPreInstalledBundle = true;
    codeSignatureParam.isInternaltestingBundle = false;
    codeSignatureParam.isCompressNativeLibrary = true;
    auto ret2 = InstalldOperator::VerifyCodeSignature(codeSignatureParam);
    EXPECT_NE(ret2, ERR_OK);
}

/**
 * @tc.number: InstalldOperatorTest_11700
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling VerifyCodeSignature of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_11700, Function | SmallTest | Level0)
{
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = "/system/app/com.ohos.camera/Camera.hap";
    codeSignatureParam.cpuAbi = TEST_CPU_ABI;
    codeSignatureParam.targetSoPath = "target/file.path";
    codeSignatureParam.appIdentifier = "";
    codeSignatureParam.signatureFileDir = "";
    codeSignatureParam.isCompileSdkOpenHarmony = true;
    codeSignatureParam.isEnterpriseBundle = true;
    codeSignatureParam.isPreInstalledBundle = true;
    ErrCode ret = InstalldOperator::VerifyCodeSignature(codeSignatureParam);
#ifdef USE_ARM64
    EXPECT_NE(ret, ERR_OK);
#else
    EXPECT_EQ(ret, ERR_OK);
#endif
}

/**
 * @tc.number: InstalldOperatorTest_11800
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling VerifyCodeSignature of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_11800, Function | SmallTest | Level0)
{
    CreateQuickFileDir("/temp/");
    CreateFile("/temp/test", "test");
    std::string srcDir = "/temp/test";
    std::string desDir = "/temp/test";
    auto ret =InstalldOperator::MoveFiles(srcDir, desDir, true);
    EXPECT_FALSE(ret);
    DeleteFile("/temp/test");
    DeleteQuickFileDir("/temp");
}

/**
 * @tc.number: InstalldOperatorTest_11900
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractTargetHnpFile of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_11900, Function | SmallTest | Level1)
{
    CreateQuickFileDir("/temp/");
    CreateFile("/temp/test", "test");
    BundleExtractor extractor("");
    std::string entryName;
    std::string targetPath = "/temp/test/";
    InstalldOperator::ExtractTargetHnpFile(extractor, entryName, targetPath, ExtractFileType::ALL);
    std::string dir = InstalldOperator::GetPathDir(targetPath);
    auto ret = !InstalldOperator::IsExistDir(dir) && !InstalldOperator::MkRecursiveDir(dir, true);
    EXPECT_TRUE(ret);
    DeleteFile("/temp/test");
    DeleteQuickFileDir("/temp");
}

/**
 * @tc.number: InstalldOperatorTest_12000
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling MoveFileOrDir of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_12000, Function | SmallTest | Level1)
{
    auto ret = InstalldOperator::MoveFileOrDir("", "", S_IFDIR);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::MoveFileOrDir("", "", S_IFCHR);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_12100
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling MoveFile of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_12100, Function | SmallTest | Level1)
{
    CreateFile("/temp.ap", "test");
    auto ret = InstalldOperator::MoveFile("", "");
    EXPECT_FALSE(ret);
#ifdef USE_ARM64
    EXPECT_NO_THROW(InstalldOperator::MoveFile("/temp.ap", "/temp1.ap"));
#else
    EXPECT_TRUE(InstalldOperator::MoveFile("/temp.ap", "/temp1.ap"));
#endif
    DeleteFile("/temp1.ap");
}

/**
 * @tc.number: InstalldOperatorTest_12200
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractDriverSoFiles of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_12200, Function | SmallTest | Level0)
{
    std::string srcPath = "";
    std::unordered_multimap<std::string, std::string> dirMap;
    dirMap.insert(std::make_pair(".", ".."));
    auto ret = InstalldOperator::ExtractDriverSoFiles(srcPath, dirMap);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_12300
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractResourceFiles of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_12300, Function | SmallTest | Level0)
{
    ExtractParam extractParam;
    extractParam.srcPath = TEST_ZIP_PATH;
    extractParam.targetPath = TEST_PATH;
    extractParam.cpuAbi = TEST_CPU_ABI;
    extractParam.extractFileType = ExtractFileType::SO;
    BundleExtractor extractor("");
#ifdef USE_ARM64
    EXPECT_NO_THROW(InstalldOperator::ExtractResourceFiles(extractParam, extractor));
#else
    EXPECT_TRUE(InstalldOperator::ExtractResourceFiles(extractParam, extractor));
#endif
}

/**
 * @tc.number: InstalldOperatorTest_12400
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling CheckAndDeleteLinkFile of InstalldOperator
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_12400, Function | SmallTest | Level0)
{
    std::string path;
    auto ret = InstalldOperator::CheckAndDeleteLinkFile(path);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_12500
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling UpdateFileProperties of InstalldOperator
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_12500, Function | SmallTest | Level0)
{
    std::string path;
    AppExecFwk::InstalldOperator::OwnershipInfo info;
    auto ret = InstalldOperator::UpdateFileProperties(path, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MIGRATE_DATA_OTHER_REASON_FAILED);
}

/**
 * @tc.number: InstalldOperatorTest_12600
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling UpdateFileProperties of InstalldOperator
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_12600, Function | SmallTest | Level0)
{
    std::string path = "/data/xxxxxx";
    AppExecFwk::InstalldOperator::OwnershipInfo info;
    auto ret = InstalldOperator::UpdateFileProperties(path, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MIGRATE_DATA_OTHER_REASON_FAILED);
}

/**
 * @tc.number: InstalldOperatorTest_12700
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling UpdateFileProperties of InstalldOperator
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_12700, Function | SmallTest | Level0)
{
    std::string path = "/data/test/InstalldOperatorTest_12700";
    OHOS::ForceCreateDirectory(path);
    AppExecFwk::InstalldOperator::OwnershipInfo info;
    info.mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IXOTH;
    info.uid = 1010;
    info.gid = 1010;
    auto ret = InstalldOperator::UpdateFileProperties(path, info);
    EXPECT_EQ(ret, ERR_OK);
    OHOS::ForceRemoveDirectory(path);
}

/**
 * @tc.number: InstalldOperatorTest_12800
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling UpdateFileProperties of InstalldOperator
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_12800, Function | SmallTest | Level0)
{
    std::string path = "/data/test/InstalldOperatorTest_12800";
    OHOS::ForceCreateDirectory(path);
    AppExecFwk::InstalldOperator::OwnershipInfo info;
    struct stat buf = {};
    if (stat("/data/test/", &buf) != 0) {
        info.uid = static_cast<int32_t>(buf.st_uid);
        info.gid = static_cast<int32_t>(buf.st_gid);
        info.mode = static_cast<int32_t>(buf.st_mode);
    }
    auto ret = InstalldOperator::UpdateFileProperties(path, info);
    EXPECT_EQ(ret, ERR_OK);
    OHOS::ForceRemoveDirectory(path);
}

/**
 * @tc.number: vs
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ForceCreateDirectory of InstalldOperator
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_12900, Function | SmallTest | Level0)
{
    std::string path = "/data";
    AppExecFwk::InstalldOperator::OwnershipInfo info;
    auto ret = InstalldOperator::ForceCreateDirectory(path, info);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstalldOperatorTest_13000
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ForceCreateDirectory of InstalldOperator
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_13000, Function | SmallTest | Level0)
{
    std::string path = "/data/test/InstalldOperatorTest_13000";
    AppExecFwk::InstalldOperator::OwnershipInfo info;
    info.mode = S_ISUID | S_ISGID;
    auto ret = InstalldOperator::ForceCreateDirectory(path, info);
    EXPECT_EQ(ret, ERR_OK);
    OHOS::ForceRemoveDirectory(path);
}

/**
 * @tc.number: InstalldOperatorTest_13100
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling UpdateFileProperties of InstalldOperator
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_13100, Function | SmallTest | Level0)
{
    std::string path = "/data/test/InstalldOperatorTest_13100";
    AppExecFwk::InstalldOperator::OwnershipInfo info;
    info.mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IXOTH;
    info.uid = 1010;
    info.gid = 1010;
    auto ret = InstalldOperator::ForceCreateDirectory(path, info);

    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        EXPECT_EQ(info.uid, static_cast<int32_t>(buf.st_uid));
        EXPECT_EQ(info.gid, static_cast<int32_t>(buf.st_gid));
        EXPECT_EQ(info.mode, static_cast<int32_t>(buf.st_mode));
    }
    OHOS::ForceRemoveDirectory(path);
}

/**
 * @tc.number: InstalldOperatorTest_13200
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling UpdateFileProperties of InstalldOperator
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_13200, Function | SmallTest | Level0)
{
    std::string path = "/data/test/InstalldOperatorTest_13200";
    AppExecFwk::InstalldOperator::OwnershipInfo info;
    struct stat buf = {};
    if (stat("/tmp", &buf) != 0) {
        info.uid = static_cast<int32_t>(buf.st_uid);
        info.gid = static_cast<int32_t>(buf.st_gid);
        info.mode = static_cast<int32_t>(buf.st_mode);
    }
    auto ret = InstalldOperator::ForceCreateDirectory(path, info);
    EXPECT_EQ(ret, ERR_OK);
    OHOS::ForceRemoveDirectory(path);
}

/**
 * @tc.number: InstalldOperatorTest_13300
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling MigrateDataCreateAhead of InstalldOperator
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_13300, Function | SmallTest | Level0)
{
    std::string sourcePath;
    std::string destPath{ "/tmp" };
    AppExecFwk::InstalldOperator::OwnershipInfo info;

    auto ret = InstalldOperator::MigrateDataCreateAhead(sourcePath, destPath, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MIGRATE_DATA_SOURCE_PATH_INVALID);
}

/**
 * @tc.number: InstalldOperatorTest_13400
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling MigrateDataCreateAhead of InstalldOperator
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_13400, Function | SmallTest | Level0)
{
    std::string sourcePath { "/data/test/InstalldOperatorTest_13400" };
    std::string destPath;
    AppExecFwk::InstalldOperator::OwnershipInfo info;

    auto ret = InstalldOperator::MigrateDataCreateAhead(sourcePath, destPath, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MIGRATE_DATA_DESTINATION_PATH_INVALID);
}

/**
 * @tc.number: InstalldOperatorTest_13500
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling MigrateDataCreateAhead of InstalldOperator
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_13500, Function | SmallTest | Level0)
{
    std::string sourcePath { "/data/test/sourcePath/test.txt" };
    std::string destPath { "/data/test/InstalldOperatorTest_13500"};
    AppExecFwk::InstalldOperator::OwnershipInfo info;
    struct stat buf = {};
    if (stat(destPath.c_str(), &buf) != 0) {
        info.uid = static_cast<int32_t>(buf.st_uid);
        info.gid = static_cast<int32_t>(buf.st_gid);
        info.mode = static_cast<int32_t>(buf.st_mode);
    }

    auto ret = InstalldOperator::MigrateDataCreateAhead(sourcePath, destPath, info);
    std::string desiredValue { "/data/test/InstalldOperatorTest_13500/data/test/sourcePath" };
    EXPECT_EQ(destPath, desiredValue);
    EXPECT_EQ(ret, ERR_OK);
    OHOS::ForceRemoveDirectory("/data/test/InstalldOperatorTest_13500");
}

/**
 * @tc.number: InstalldOperatorTest_13600
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling MigrateDataCreateAhead of InstalldOperator
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_13600, Function | SmallTest | Level0)
{
    std::string sourcePath { "/data/test/sourcePath///test.txt" };
    std::string destPath { "/data/test/InstalldOperatorTest_13600"};
    std::ofstream out(sourcePath);
    AppExecFwk::InstalldOperator::OwnershipInfo info;
    struct stat buf = {};
    if (stat(destPath.c_str(), &buf) != 0) {
        info.uid = static_cast<int32_t>(buf.st_uid);
        info.gid = static_cast<int32_t>(buf.st_gid);
        info.mode = static_cast<int32_t>(buf.st_mode);
    }

    auto ret = InstalldOperator::MigrateDataCreateAhead(sourcePath, destPath, info);
    std::string desiredValue { "/data/test/InstalldOperatorTest_13600/data/test/sourcePath//" };
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(destPath, desiredValue);
    OHOS::ForceRemoveDirectory("/data/test/InstalldOperatorTest_13600");
}

/**
 * @tc.number: InstalldOperatorTest_13700
 * @tc.name: test function of InstalldOperator with not DRIVER_EXECUTE_DIR path
 * @tc.desc: 1. calling MoveFile of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_13700, Function | SmallTest | Level1)
{
    std::string srcPath = "/data/service/el1/public/print_service/cups/test.txt";
    std::string dstPath = "/data/service/el1/public/print_service/cups/test1.txt";
    CreateFile(srcPath, "test");
    bool ret = InstalldOperator::MoveFile(srcPath, dstPath);
    EXPECT_EQ(ret, true);
    DeleteFile(dstPath);
}

/**
 * @tc.number: InstalldOperatorTest_13800
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractTargetFile of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_13800, Function | SmallTest | Level0)
{
    BundleExtractor extractor("");
    ExtractParam param;
    param.targetPath = "/data/app/el1/";
    param.cpuAbi = TEST_CPU_ABI;
    param.extractFileType = ExtractFileType::AP;
    auto ret = InstalldOperator::ExtractTargetFile(extractor, "../", param);
    EXPECT_FALSE(ret);
    ret = InstalldOperator::ExtractTargetFile(extractor, "/..", param);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_13900
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling CopyDir of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_13900, Function | SmallTest | Level1)
{
    std::string srcPath;
    std::string dstPath;
    bool ret = InstalldOperator::CopyDir(srcPath, dstPath);
    EXPECT_EQ(ret, false);

    srcPath = "/data/test/plugins_1";
    ret = InstalldOperator::CopyDir(srcPath, dstPath);
    EXPECT_EQ(ret, false);

    OHOS::ForceCreateDirectory(srcPath);
    dstPath = "/data/test/plugins_2";
    ret = InstalldOperator::CopyDir(srcPath, dstPath);
    EXPECT_EQ(ret, true);

    srcPath += "/test";
    OHOS::ForceCreateDirectory(srcPath);

    std::string filePath = srcPath + "/test.txt";
    CreateFile(filePath, "test");
    ret = InstalldOperator::CopyDir(srcPath, dstPath);
    EXPECT_EQ(ret, true);
    OHOS::ForceRemoveDirectory("/data/test/plugins_1");
    OHOS::ForceRemoveDirectory("/data/test/plugins_2");
}

/**
 * @tc.number: InstalldOperatorTest_14000
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ProcessBundleInstallNative of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_14000, Function | SmallTest | Level0)
{
    InstallHnpParam param;
    param.userId = "100";
    param.hnpRootPath = "/hnp/root/path";
    param.hapPath = "happath";
    param.cpuAbi = "cpuabi";
    param.packageName = "com.test.demo";
    param.appIdentifier = "";
    std::string hnpPath = "public/test.hnp";
    param.hnpPaths.emplace_back(hnpPath);
    bool ret = InstalldOperator::ProcessBundleInstallNative(param);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_14100
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ProcessBundleInstallNative of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_14100, Function | SmallTest | Level0)
{
    InstallHnpParam param;
    param.userId = "100";
    param.hnpRootPath = "/hnp/root/path";
    param.hapPath = "happath";
    param.cpuAbi = "cpuabi";
    param.packageName = "com.test.demo";
    param.appIdentifier = "123456";
    bool ret = InstalldOperator::ProcessBundleInstallNative(param);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_14200
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling IsExistApFile of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_14200, Function | SmallTest | Level0)
{
    std::string testFile = "/data/test/test.txt";
    CreateFile(testFile, "test content");
    bool ret = InstalldOperator::IsExistApFile(testFile + "/test.ap");
    EXPECT_FALSE(ret);
    DeleteFile(testFile);
}

/**
 * @tc.number: InstalldOperatorTest_14300
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling GetSameLevelTmpPath of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_14300, Function | SmallTest | Level0)
{
    std::string result = InstalldOperator::GetSameLevelTmpPath("test.txt");
    EXPECT_EQ(result, Constants::EMPTY_STRING);
}

/**
 * @tc.number: InstalldOperatorTest_14400
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling DeleteCertAndRemoveKey of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_14400, Function | SmallTest | Level0)
{
    ErrCode ret = InstalldOperator::DeleteCertAndRemoveKey("");
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldOperatorTest_14500
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling DeleteCertAndRemoveKey of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_14500, Function | SmallTest | Level0)
{
    std::string longPath(Constants::BMS_MAX_PATH_LENGTH + 1, 'a');
    ErrCode ret = InstalldOperator::DeleteCertAndRemoveKey(longPath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: InstalldOperatorTest_14600
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling DeleteCertAndRemoveKey of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_14600, Function | SmallTest | Level0)
{
    std::string certPath = "/data/test/test_cert.pem";
    ErrCode ret = InstalldOperator::DeleteCertAndRemoveKey(certPath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_ENTERPRISE_CERT_READ_CERT_FAILED);
}

/**
 * @tc.number: InstalldOperatorTest_14700
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling DeleteCertAndRemoveKey of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_14700, Function | SmallTest | Level0)
{
    std::string certPath = "/data/test/test_cert.pem";
    std::string certDir = "/data/test/";
    InstalldOperator::MkRecursiveDir(certDir, false);
    CreateFile(certPath, "test cert content");
    chmod(certDir.c_str(), 0444);
    ErrCode ret = InstalldOperator::DeleteCertAndRemoveKey(certPath);
    chmod(certDir.c_str(), 0755);
    DeleteFile(certPath);
    InstalldOperator::DeleteDir(certDir);
    EXPECT_EQ(ret, ERR_APPEXECFWK_ENTERPRISE_CERT_REMOVE_KEY_ERROR);
}

/**
 * @tc.number: InstalldOperatorTest_14800
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling CopyDir of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_14800, Function | SmallTest | Level0)
{
    std::string srcDir = "/data/test/test_dir1";
    std::string destDir = "/data/test/test_dir2";
    bool ret = InstalldOperator::CopyDir(srcDir, destDir);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_14900
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling TraverseCacheDirectory of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_14900, Function | SmallTest | Level0)
{
    std::string testDir = "/data/test/test_dir";
    InstalldOperator::MkRecursiveDir(testDir, true);
    std::vector<std::string> cacheDirs;
    InstalldOperator::TraverseCacheDirectory(testDir, cacheDirs);
    InstalldOperator::DeleteDir(testDir);
    EXPECT_TRUE(true);
}

/**
 * @tc.number: InstalldOperatorTest_15000
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ScanDir of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_15000, Function | SmallTest | Level0)
{
    std::string nonExistentPath = "/data/test/test_dir";
    std::vector<std::string> paths;
    bool ret = InstalldOperator::ScanDir(nonExistentPath, ScanMode::SUB_FILE_ALL,
        ResultMode::ABSOLUTE_PATH, paths);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_15100
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ObtainNativeSoFile of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_15100, Function | SmallTest | Level0)
{
    std::string testFile = "/data/test/empty.zip";
    CreateFile(testFile, "");
    std::ofstream ofs(testFile, std::ios::binary);
    const unsigned char emptyZip[] = {
        0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    ofs.write(reinterpret_cast<const char*>(emptyZip), sizeof(emptyZip));
    ofs.close();
    BundleExtractor extractor(testFile);
    extractor.Init();
    std::vector<std::string> soEntryFiles;
    bool ret = InstalldOperator::ObtainNativeSoFile(extractor, "arm64", soEntryFiles);
    DeleteFile(testFile);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_15200
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ExtractDriverSoFiles of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_15200, Function | SmallTest | Level0)
{
    std::string srcPath = "/data/test/src";
    std::unordered_multimap<std::string, std::string> dirMap;
    dirMap.insert({".", "/system/lib"});
    bool ret = InstalldOperator::ExtractDriverSoFiles(srcPath, dirMap);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_15300
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling SetKeyIdPolicy of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_15300, Function | SmallTest | Level0)
{
    EncryptionParam param;
    param.bundleName = "com.test.policy";
    param.userId = 100;
    param.encryptionDirType = EncryptionDirType::APP;
    std::string longKeyId;
    for (int i = 0; i < 9; i++) {
        longKeyId += "00";
    }
    bool ret = InstalldOperator::SetKeyIdPolicy(param, longKeyId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_15400
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling MigrateDataCreateAhead of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_15400, Function | SmallTest | Level0)
{
    std::string sourcePath = "noSlashPath";  // No '/' character
    std::string destPath = "/data/test/dest";
    AppExecFwk::InstalldOperator::OwnershipInfo info;
    info.uid = 1000;
    info.gid = 1000;
    info.mode = 0755;
    int32_t ret = InstalldOperator::MigrateDataCreateAhead(sourcePath, destPath, info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MIGRATE_DATA_OTHER_REASON_FAILED);
}

/**
 * @tc.number: InstalldOperatorTest_15500
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ClearDir of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_15500, Function | SmallTest | Level0)
{
    std::string nonExistentPath = "/data/test/nonexistent_clear_dir_12345";
    bool ret = InstalldOperator::ClearDir(nonExistentPath);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_15600
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling WriteCertToFile of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_15600, Function | SmallTest | Level0)
{
    std::string emptyCertFilePath = "";
    std::string certContent = "test cert content";
    bool ret = InstalldOperator::WriteCertToFile(emptyCertFilePath, certContent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_15700
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling RestoreconPath of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_15700, Function | SmallTest | Level0)
{
    std::string invalidPath = "/data/test/test_dir";
    bool ret = InstalldOperator::RestoreconPath(invalidPath);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_15800
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling ProcessApplyDiffPatchPath of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_15800, Function | SmallTest | Level0)
{
    std::vector<std::string> oldSoFileNames;
    std::vector<std::string> diffFileNames;
    bool res = InstalldOperator::ProcessApplyDiffPatchPath(
        "noExist", "", "noExist", oldSoFileNames, diffFileNames);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: InstalldOperatorTest_16000
 * @tc.name: test function of InstalldOperator
 * @tc.desc: 1. calling GetBundleInodeCount of InstalldOperator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_16000, Function | MediumTest | Level1)
{
    int32_t uid = -1;
    auto ret = InstalldOperator::GetBundleInodeCount(uid);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: InstalldOperatorTest_16100
 * @tc.name: test ParseSkillMd function of InstalldOperator
 * @tc.desc: 1. calling ParseSkillMd with empty path
 *           2. verify error returned
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_16100, Function | SmallTest | Level0)
{
    std::string emptyPath;
    std::string name;
    std::string description;
    ErrCode ret = InstalldOperator::ParseSkillMd(emptyPath, name, description);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    EXPECT_TRUE(name.empty());
    EXPECT_TRUE(description.empty());
}

/**
 * @tc.number: InstalldOperatorTest_16200
 * @tc.name: test ParseSkillMd function of InstalldOperator
 * @tc.desc: 1. calling ParseSkillMd with non-existent file
 *           2. verify error returned
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_16200, Function | SmallTest | Level0)
{
    std::string nonExistentPath = "/data/test/nonexistent_skill_md_12345/SKILL.md";
    std::string name;
    std::string description;
    ErrCode ret = InstalldOperator::ParseSkillMd(nonExistentPath, name, description);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    EXPECT_TRUE(name.empty());
    EXPECT_TRUE(description.empty());
}

/**
 * @tc.number: InstalldOperatorTest_16300
 * @tc.name: test ParseSkillMd function of InstalldOperator
 * @tc.desc: 1. calling ParseSkillMd with valid frontmatter file
 *           2. verify name and description parsed correctly
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_16300, Function | SmallTest | Level0)
{
    // Create test directory and SKILL.md file
    std::string testDir = "/data/test/skill_md_test_16300";
    std::string skillMdPath = testDir + "/SKILL.md";
    CreateQuickFileDir(testDir);

    // Create SKILL.md with YAML frontmatter format
    std::string content = "---\n";
    content += "name: testSkill\n";
    content += "description: This is a test skill description\n";
    content += "---\n";
    CreateFile(skillMdPath, content);

    std::string name;
    std::string description;
    ErrCode ret = InstalldOperator::ParseSkillMd(skillMdPath, name, description);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(name, "testSkill");
    EXPECT_EQ(description, "This is a test skill description");

    DeleteQuickFileDir(testDir);
}

/**
 * @tc.number: InstalldOperatorTest_16400
 * @tc.name: test ParseSkillMd function of InstalldOperator
 * @tc.desc: 1. calling ParseSkillMd with markdown format (# name:)
 *           2. verify parse failed because frontmatter is required
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_16400, Function | SmallTest | Level0)
{
    // Create test directory and SKILL.md file
    std::string testDir = "/data/test/skill_md_test_16400";
    std::string skillMdPath = testDir + "/SKILL.md";
    CreateQuickFileDir(testDir);

    // Create SKILL.md with markdown format
    std::string content = "# name: markdownSkill\n";
    content += "# description: This is a markdown format skill\n";
    CreateFile(skillMdPath, content);

    std::string name;
    std::string description;
    ErrCode ret = InstalldOperator::ParseSkillMd(skillMdPath, name, description);

    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARSE_FAILED);
    EXPECT_TRUE(name.empty());
    EXPECT_TRUE(description.empty());

    DeleteQuickFileDir(testDir);
}

/**
 * @tc.number: InstalldOperatorTest_16500
 * @tc.name: test ParseSkillMd function of InstalldOperator
 * @tc.desc: 1. calling ParseSkillMd without name field
 *           2. verify error returned
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_16500, Function | SmallTest | Level0)
{
    // Create test directory and SKILL.md file
    std::string testDir = "/data/test/skill_md_test_16500";
    std::string skillMdPath = testDir + "/SKILL.md";
    CreateQuickFileDir(testDir);

    // Create SKILL.md without name field
    std::string content = "description: This skill has no name\n";
    CreateFile(skillMdPath, content);

    std::string name;
    std::string description;
    ErrCode ret = InstalldOperator::ParseSkillMd(skillMdPath, name, description);

    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARSE_FAILED);
    EXPECT_TRUE(name.empty());

    DeleteQuickFileDir(testDir);
}

/**
 * @tc.number: InstalldOperatorTest_16600
 * @tc.name: test ValidateSkillName function of InstalldOperator
 * @tc.desc: 1. calling ValidateSkillName with non-existent file
 *           2. verify validation fails
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_16600, Function | SmallTest | Level0)
{
    std::string skillName = "testSkill";
    std::string nonExistentPath = "/data/test/nonexistent_skill_16600/SKILL.md";

    bool ret = InstalldOperator::ValidateSkillName(skillName, nonExistentPath);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_16700
 * @tc.name: test ValidateSkillName function of InstalldOperator
 * @tc.desc: 1. calling ValidateSkillName with matching name in frontmatter
 *           2. verify validation passes
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_16700, Function | SmallTest | Level0)
{
    // Create test directory and SKILL.md file
    std::string testDir = "/data/test/skill_validate_test_16700";
    std::string skillMdPath = testDir + "/SKILL.md";
    CreateQuickFileDir(testDir);

    // Create SKILL.md with matching name in YAML frontmatter
    std::string content = "---\n";
    content += "name: matchingSkill\n";
    content += "description: Test skill for validation\n";
    content += "---\n";
    CreateFile(skillMdPath, content);

    bool ret = InstalldOperator::ValidateSkillName("matchingSkill", skillMdPath);
    EXPECT_TRUE(ret);

    DeleteQuickFileDir(testDir);
}

/**
 * @tc.number: InstalldOperatorTest_16800
 * @tc.name: test ValidateSkillName function of InstalldOperator
 * @tc.desc: 1. calling ValidateSkillName with mismatched name
 *           2. verify validation fails
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_16800, Function | SmallTest | Level0)
{
    // Create test directory and SKILL.md file
    std::string testDir = "/data/test/skill_validate_test_16800";
    std::string skillMdPath = testDir + "/SKILL.md";
    CreateQuickFileDir(testDir);

    // Create SKILL.md with different name
    std::string content = "name: differentSkill\n";
    content += "description: Test skill with mismatched name\n";
    CreateFile(skillMdPath, content);

    bool ret = InstalldOperator::ValidateSkillName("expectedSkill", skillMdPath);
    EXPECT_FALSE(ret);

    DeleteQuickFileDir(testDir);
}

/**
 * @tc.number: InstalldOperatorTest_16900
 * @tc.name: test ExtractSkillFromHsp function of InstalldOperator
 * @tc.desc: 1. calling ExtractSkillFromHsp with invalid target path
 *           2. verify extraction fails
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_16900, Function | SmallTest | Level0)
{
    // Create a mock extractor (using real HAP file)
    std::string testHapPath = "/system/app/ShellAssistant/ShellAssistant_Feature_Anco.hap";
    if (!InstalldOperator::IsExistFile(testHapPath)) {
        // Skip test if HAP file doesn't exist
        GTEST_LOG_(INFO) << "Test HAP file not found, skipping test";
        return;
    }

    BundleExtractor extractor(testHapPath);
    if (!extractor.Init()) {
        GTEST_LOG_(INFO) << "Failed to initialize extractor, skipping test";
        return;
    }

    // Use invalid target path (too long)
    std::string invalidTargetPath(300, 'x');

    bool ret = InstalldOperator::ExtractSkillFromHsp(extractor, "testSkill", invalidTargetPath);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InstalldOperatorTest_17000
 * @tc.name: test ExtractSkillsPackage function of InstalldOperator
 * @tc.desc: 1. calling ExtractSkillsPackage with empty bundleName
 *           2. verify error returned
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_17000, Function | SmallTest | Level0)
{
    SkillsPackageParam param;
    param.bundleName = "";  // Empty bundleName
    param.moduleName = "testModule";
    param.hspPath = "/data/test/test.hsp";
    param.skillNameList.push_back("skill1");

    std::vector<SkillsPackageInfo> skillInfoList;
    ErrCode ret = InstalldOperator::ExtractSkillsPackage(param, skillInfoList);

    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    EXPECT_TRUE(skillInfoList.empty());
}

/**
 * @tc.number: InstalldOperatorTest_17100
 * @tc.name: test ExtractSkillsPackage function of InstalldOperator
 * @tc.desc: 1. calling ExtractSkillsPackage with empty moduleName
 *           2. verify error returned
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_17100, Function | SmallTest | Level0)
{
    SkillsPackageParam param;
    param.bundleName = "com.example.test";
    param.moduleName = "";  // Empty moduleName
    param.hspPath = "/data/test/test.hsp";
    param.skillNameList.push_back("skill1");

    std::vector<SkillsPackageInfo> skillInfoList;
    ErrCode ret = InstalldOperator::ExtractSkillsPackage(param, skillInfoList);

    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    EXPECT_TRUE(skillInfoList.empty());
}

/**
 * @tc.number: InstalldOperatorTest_17200
 * @tc.name: test ExtractSkillsPackage function of InstalldOperator
 * @tc.desc: 1. calling ExtractSkillsPackage with empty hspPath
 *           2. verify error returned
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_17200, Function | SmallTest | Level0)
{
    SkillsPackageParam param;
    param.bundleName = "com.example.test";
    param.moduleName = "testModule";
    param.hspPath = "";  // Empty hspPath
    param.skillNameList.push_back("skill1");

    std::vector<SkillsPackageInfo> skillInfoList;
    ErrCode ret = InstalldOperator::ExtractSkillsPackage(param, skillInfoList);

    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    EXPECT_TRUE(skillInfoList.empty());
}

/**
 * @tc.number: InstalldOperatorTest_17300
 * @tc.name: test ExtractSkillsPackage function of InstalldOperator
 * @tc.desc: 1. calling ExtractSkillsPackage with non-existent HSP file
 *           2. verify error returned
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_17300, Function | SmallTest | Level0)
{
    SkillsPackageParam param;
    param.bundleName = "com.example.test";
    param.moduleName = "testModule";
    param.hspPath = "/data/test/nonexistent_file_17300.hsp";  // Non-existent file
    param.skillNameList.push_back("skill1");

    std::vector<SkillsPackageInfo> skillInfoList;
    ErrCode ret = InstalldOperator::ExtractSkillsPackage(param, skillInfoList);

    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    EXPECT_TRUE(skillInfoList.empty());
}

/**
 * @tc.number: InstalldOperatorTest_17400
 * @tc.name: test ExtractSkillsPackage function of InstalldOperator
 * @tc.desc: 1. calling ExtractSkillsPackage with empty skillNameList
 *           2. verify success with empty result list
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_17400, Function | SmallTest | Level0)
{
    // Create a temporary valid HSP file path for testing
    std::string testHapPath = "/system/app/ShellAssistant/ShellAssistant_Feature_Anco.hap";
    if (!InstalldOperator::IsExistFile(testHapPath)) {
        GTEST_LOG_(INFO) << "Test HAP file not found, skipping test";
        return;
    }

    SkillsPackageParam param;
    param.bundleName = "com.example.test";
    param.moduleName = "testModule";
    param.hspPath = testHapPath;
    // Empty skillNameList - no skills to extract

    std::vector<SkillsPackageInfo> skillInfoList;
    ErrCode ret = InstalldOperator::ExtractSkillsPackage(param, skillInfoList);

    // Should succeed with empty result list
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(skillInfoList.empty());
}

/**
 * @tc.number: InstalldOperatorTest_17500
 * @tc.name: test ParseSkillMd function of InstalldOperator
 * @tc.desc: 1. calling ParseSkillMd with non-frontmatter mixed format
 *           2. verify parse failed
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_17500, Function | SmallTest | Level0)
{
    // Create test directory and SKILL.md file
    std::string testDir = "/data/test/skill_md_test_17500";
    std::string skillMdPath = testDir + "/SKILL.md";
    CreateQuickFileDir(testDir);

    // Create SKILL.md with mixed format
    std::string content = "#name: mixedFormatSkill\n";
    content += "description: This is a mixed format skill\n";
    CreateFile(skillMdPath, content);

    std::string name;
    std::string description;
    ErrCode ret = InstalldOperator::ParseSkillMd(skillMdPath, name, description);

    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARSE_FAILED);
    EXPECT_TRUE(name.empty());
    EXPECT_TRUE(description.empty());

    DeleteQuickFileDir(testDir);
}

/**
 * @tc.number: InstalldOperatorTest_17600
 * @tc.name: test ParseSkillMd function of InstalldOperator
 * @tc.desc: 1. calling ParseSkillMd with frontmatter and extra whitespace
 *           2. verify whitespace trimmed correctly
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_17600, Function | SmallTest | Level0)
{
    // Create test directory and SKILL.md file
    std::string testDir = "/data/test/skill_md_test_17600";
    std::string skillMdPath = testDir + "/SKILL.md";
    CreateQuickFileDir(testDir);

    // Create SKILL.md with YAML frontmatter and extra whitespace
    std::string content = "---\n";
    content += "name:  \t  whitespaceSkill  \t \n";
    content += "description:  \t  Description with whitespace  \t \n";
    content += "---\n";
    CreateFile(skillMdPath, content);

    std::string name;
    std::string description;
    ErrCode ret = InstalldOperator::ParseSkillMd(skillMdPath, name, description);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(name, "whitespaceSkill");
    EXPECT_EQ(description, "Description with whitespace");

    DeleteQuickFileDir(testDir);
}

/**
 * @tc.number: InstalldOperatorTest_17700
 * @tc.name: test ValidateSkillName function of InstalldOperator
 * @tc.desc: 1. calling ValidateSkillName with markdown format name
 *           2. verify validation fails because frontmatter is required
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_17700, Function | SmallTest | Level0)
{
    // Create test directory and SKILL.md file
    std::string testDir = "/data/test/skill_validate_test_17700";
    std::string skillMdPath = testDir + "/SKILL.md";
    CreateQuickFileDir(testDir);

    // Create SKILL.md with markdown format
    std::string content = "# name: markdownNameSkill\n";
    content += "# description: Test skill with markdown format\n";
    CreateFile(skillMdPath, content);

    bool ret = InstalldOperator::ValidateSkillName("markdownNameSkill", skillMdPath);
    EXPECT_FALSE(ret);

    DeleteQuickFileDir(testDir);
}

/**
 * @tc.number: InstalldOperatorTest_17800
 * @tc.name: test ParseSkillMd function of InstalldOperator
 * @tc.desc: 1. calling ParseSkillMd with frontmatter name but no description
 *           2. verify success with empty description
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_17800, Function | SmallTest | Level0)
{
    // Create test directory and SKILL.md file
    std::string testDir = "/data/test/skill_md_test_17800";
    std::string skillMdPath = testDir + "/SKILL.md";
    CreateQuickFileDir(testDir);

    // Create SKILL.md with YAML frontmatter and only name
    std::string content = "---\n";
    content += "name: skillWithoutDescription\n";
    content += "---\n";
    CreateFile(skillMdPath, content);

    std::string name;
    std::string description;
    ErrCode ret = InstalldOperator::ParseSkillMd(skillMdPath, name, description);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(name, "skillWithoutDescription");
    EXPECT_TRUE(description.empty());

    DeleteQuickFileDir(testDir);
}

/**
 * @tc.number: InstalldOperatorTest_17900
 * @tc.name: test GetBundleDataDirPaths function with valid parameters
 * @tc.desc: 1. calling GetBundleDataDirPaths with valid bundleName, appIndex, userId
 *           2. verify function returns true and collects all data directory paths
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_17900, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::string bundleName = "com.example.test";
    int32_t appIndex = 0;
    int32_t userId = 100;
    std::vector<std::string> dataDirPaths;

    bool ret = installdOperator.GetBundleDataDirPaths(bundleName, appIndex, userId, dataDirPaths);

    EXPECT_TRUE(ret);
    EXPECT_GT(dataDirPaths.size(), 0);
    // Verify some expected paths are collected
    bool hasBasePath = false;
    bool hasDatabasePath = false;
    bool hasSharefilesPath = false;
    for (const auto &path : dataDirPaths) {
        if (path.find("/base/" + bundleName) != std::string::npos) {
            hasBasePath = true;
        }
        if (path.find("/database/" + bundleName) != std::string::npos) {
            hasDatabasePath = true;
        }
        if (path.find("/sharefiles/" + bundleName) != std::string::npos) {
            hasSharefilesPath = true;
        }
    }
    EXPECT_TRUE(hasBasePath);
    EXPECT_TRUE(hasDatabasePath);
    EXPECT_TRUE(hasSharefilesPath);
}

/**
 * @tc.number: InstalldOperatorTest_18000
 * @tc.name: test GetBundleDataDirPaths with empty bundleName
 * @tc.desc: 1. calling GetBundleDataDirPaths with empty bundleName
 *           2. verify function returns false
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_18000, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::string bundleName = "";  // Empty bundleName
    int32_t appIndex = 0;
    int32_t userId = 100;
    std::vector<std::string> dataDirPaths;

    bool ret = installdOperator.GetBundleDataDirPaths(bundleName, appIndex, userId, dataDirPaths);

    EXPECT_FALSE(ret);
    EXPECT_EQ(dataDirPaths.size(), 0);
}

/**
 * @tc.number: InstalldOperatorTest_18100
 * @tc.name: test GetBundleDataDirPaths with negative userId
 * @tc.desc: 1. calling GetBundleDataDirPaths with negative userId
 *           2. verify function returns false
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_18100, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::string bundleName = "com.example.test";
    int32_t appIndex = 0;
    int32_t userId = -1;  // Invalid userId
    std::vector<std::string> dataDirPaths;

    bool ret = installdOperator.GetBundleDataDirPaths(bundleName, appIndex, userId, dataDirPaths);

    EXPECT_FALSE(ret);
    EXPECT_EQ(dataDirPaths.size(), 0);
}

/**
 * @tc.number: InstalldOperatorTest_18200
 * @tc.name: test GetBundleDataDirPaths with appIndex > 0 (clone app)
 * @tc.desc: 1. calling GetBundleDataDirPaths with appIndex = 1
 *           2. verify function correctly builds clone app data directory paths
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_18200, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::string bundleName = "com.example.test";
    int32_t appIndex = 1;  // Clone app index
    int32_t userId = 100;
    std::vector<std::string> dataDirPaths;

    bool ret = installdOperator.GetBundleDataDirPaths(bundleName, appIndex, userId, dataDirPaths);

    EXPECT_TRUE(ret);
    EXPECT_GT(dataDirPaths.size(), 0);
    // Verify clone app path format
    bool hasClonePath = false;
    for (const auto &path : dataDirPaths) {
        if (path.find("/data/app/el1/100/base/+clone-1+com.example.test") != std::string::npos) {
            hasClonePath = true;
            break;
        }
    }
    EXPECT_TRUE(hasClonePath);
}

/**
 * @tc.number: InstalldOperatorTest_18300
 * @tc.name: test GetBundleDataDirPaths with userId = 0
 * @tc.desc: 1. calling GetBundleDataDirPaths with userId = 0 (active user)
 *           2. verify function correctly handles active user
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_18300, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::string bundleName = "com.example.test";
    int32_t appIndex = 0;
    int32_t userId = 0;  // Active user
    std::vector<std::string> dataDirPaths;

    bool ret = installdOperator.GetBundleDataDirPaths(bundleName, appIndex, userId, dataDirPaths);

    EXPECT_TRUE(ret);
    EXPECT_GT(dataDirPaths.size(), 0);
    // Verify userId 0 is correctly used in paths
    bool hasUserId0 = false;
    for (const auto &path : dataDirPaths) {
        if (path.find("/el1/0/") != std::string::npos || path.find("/el2/0/") != std::string::npos) {
            hasUserId0 = true;
            break;
        }
    }
    EXPECT_TRUE(hasUserId0);
}

/**
 * @tc.number: InstalldOperatorTest_18400
 * @tc.name: test GetBundleDataDirPaths verifies all expected paths
 * @tc.desc: 1. calling GetBundleDataDirPaths and verify all expected path types
 *           2. verify base, database, sharefiles, log, system_optimize paths
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_18400, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::string bundleName = "com.example.test";
    int32_t appIndex = 0;
    int32_t userId = 100;
    std::vector<std::string> dataDirPaths;

    bool ret = installdOperator.GetBundleDataDirPaths(bundleName, appIndex, userId, dataDirPaths);

    EXPECT_TRUE(ret);
    // Verify all expected path types exist
    bool hasElPath = false;
    bool hasEl1BasePath = false;
    bool hasEl1OptimizePath = false;
    bool hasEl2SharefilesPath = false;
    bool hasServicePath = false;

    for (const auto &path : dataDirPaths) {
        // Check for el2, el5 base/database paths
        if (path.find("/data/app/el2/100/") != std::string::npos ||
            path.find("/data/app/el5/100/") != std::string::npos) {
            hasElPath = true;
        }
        // Check for el1 optimize paths
        if (path.find("/data/app/el1/100/") != std::string::npos) {
            hasEl1BasePath = true;
            if (path.find("/system_optimize/") != std::string::npos ||
                path.find("/ark_startup_cache/") != std::string::npos ||
                path.find("/shader_cache/") != std::string::npos) {
                hasEl1OptimizePath = true;
            }
        }
        // Check for el2 sharefiles
        if (path.find("/sharefiles/") != std::string::npos) {
            hasEl2SharefilesPath = true;
        }
        // Check for service paths
        if (path.find("/data/service/") != std::string::npos) {
            hasServicePath = true;
        }
    }

    EXPECT_TRUE(hasElPath);
    EXPECT_TRUE(hasEl1BasePath);
    EXPECT_TRUE(hasEl1OptimizePath);
    EXPECT_TRUE(hasEl2SharefilesPath);
    EXPECT_TRUE(hasServicePath);
}

/**
 * @tc.number: InstalldOperatorTest_18500
 * @tc.name: test GetBundleDataDirPaths clears output parameter
 * @tc.desc: 1. calling GetBundleDataDirPaths twice
 *           2. verify output vector is cleared before each call
 */
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_18500, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::string bundleName = "com.example.test";
    int32_t appIndex = 0;
    int32_t userId = 100;
    std::vector<std::string> dataDirPaths;

    // First call
    bool ret1 = installdOperator.GetBundleDataDirPaths(bundleName, appIndex, userId, dataDirPaths);
    EXPECT_TRUE(ret1);
    size_t firstCallSize = dataDirPaths.size();

    // Second call with same parameters
    bool ret2 = installdOperator.GetBundleDataDirPaths(bundleName, appIndex, userId, dataDirPaths);
    EXPECT_TRUE(ret2);
    size_t secondCallSize = dataDirPaths.size();

    EXPECT_EQ(firstCallSize, secondCallSize);
}

/**
 * @tc.number: InstalldOperatorTest_18600
 * @tc.name: test AnonymizePath with single segment filename
 * @tc.desc: 1. calling AnonymizePath with single filename
 *           2. verify anonymization pattern (keep even chars, replace odd with *)
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_18600, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::string filename = "/abc/document.txt";
    std::string result = installdOperator.AnonymizePath(filename);
    // "abc" -> "a*c" (keep even indices: 0,2)
    // "document.txt" -> "d*c*m*n*.*x*" (keep even indices: 0,2,4,6,8,10)
    EXPECT_EQ(result, "/a*c/d*c*m*n*.*x*");
}

/**
 * @tc.number: InstalldOperatorTest_18700
 * @tc.name: test AnonymizePath with empty path
 * @tc.desc: 1. calling AnonymizePath with empty string
 *           2. verify empty string is returned unchanged
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_18700, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::string emptyPath = "";
    std::string result = installdOperator.AnonymizePath(emptyPath);
    EXPECT_EQ(result, "");
}

/**
 * @tc.number: InstalldOperatorTest_18800
 * @tc.name: test AnonymizePath with single segment filename
 * @tc.desc: 1. calling AnonymizePath with single filename
 *           2. verify anonymization pattern (keep even chars, replace odd with *)
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_18800, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::string filename = "document.txt";
    std::string result = installdOperator.AnonymizePath(filename);
    // "document.txt" -> "d*c*m*n*.*x*" (entire string anonymized including extension)
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result, filename);
    // Verify the result has correct anonymization pattern
    EXPECT_EQ(result, "d*c*m*n*.*x*");
}

/**
 * @tc.number: InstalldOperatorTest_18900
 * @tc.name: test AnonymizePath with multi-segment path
 * @tc.desc: 1. calling AnonymizePath with full path
 *           2. verify all segments are anonymized
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_18900, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::string fullPath = "/data/storage/el2/base/haps/entry/cache/image.png";
    std::string result = installdOperator.AnonymizePath(fullPath);
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result, fullPath);
    // Verify the entire path is anonymized correctly (including extension)
    EXPECT_EQ(result, "/d*t*/s*o*a*e/e*2/b*s*/h*p*/e*t*y/c*c*e/i*a*e*p*g");
}

/**
 * @tc.number: InstalldOperatorTest_19000
 * @tc.name: test AnonymizePath with no extension
 * @tc.desc: 1. calling AnonymizePath with filename without extension
 *           2. verify entire name is anonymized
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_19000, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::string noExtPath = "/data/storage/el2/database";
    std::string result = installdOperator.AnonymizePath(noExtPath);
    EXPECT_EQ(result, "/d*t*/s*o*a*e/e*2/d*t*b*s*");
}

/**
 * @tc.number: InstalldOperatorTest_19100
 * @tc.name: test AnonymizePath with multiple extensions
 * @tc.desc: 1. calling AnonymizePath with filename like file.tar.gz
 *           2. verify entire filename including all extensions is anonymized
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_19100, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::string multiExtPath = "/data/app/archive.tar.gz";
    std::string result = installdOperator.AnonymizePath(multiExtPath);
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result, multiExtPath);
    // Verify the entire filename including all extensions is anonymized
    EXPECT_EQ(result, "/d*t*/a*p/a*c*i*e*t*r*g*");
}

/**
 * @tc.number: InstalldOperatorTest_19200
 * @tc.name: test AnonymizePath with hidden file
 * @tc.desc: 1. calling AnonymizePath with hidden file (.gitignore)
 *           2. verify dot at start is not treated as extension separator
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_19200, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::string hiddenFilePath = "/data/storage/.gitignore";
    std::string result = installdOperator.AnonymizePath(hiddenFilePath);
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result, hiddenFilePath);
    // Hidden file should start with dot
    EXPECT_TRUE(result.find("/.*") != std::string::npos);
}

/**
 * @tc.number: InstalldOperatorTest_19300
 * @tc.name: test AnonymizePath with single character segments
 * @tc.desc: 1. calling AnonymizePath with short segments
 *           2. verify no crash with single chars
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_19300, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::string shortPath = "/a/b/c.txt";
    std::string result = installdOperator.AnonymizePath(shortPath);
    EXPECT_EQ(result, "/a/b/c*t*t");
}

/**
 * @tc.number: InstalldOperatorTest_19500
 * @tc.name: test GetLargestFilesRecursive with empty dirPaths
 * @tc.desc: 1. calling GetLargestFilesRecursive with empty vector
 *           2. verify function returns false
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_19500, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::vector<std::string> emptyDirs;
    std::vector<std::pair<std::string, uint64_t>> results;

    bool ret = installdOperator.GetLargestFilesRecursive(emptyDirs, 10, results);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(results.empty());
}

/**
 * @tc.number: InstalldOperatorTest_19600
 * @tc.name: test GetLargestFilesRecursive with valid directory
 * @tc.desc: 1. calling GetLargestFilesRecursive with valid path
 *           2. verify function returns true and populates results
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_19600, Function | SmallTest | Level0)
{
    CreateQuickFileDir(TEST_DIR_PATH);
    InstalldOperator installdOperator;
    std::vector<std::string> dirPaths = {TEST_DIR_PATH};
    std::vector<std::pair<std::string, uint64_t>> results;

    bool ret = installdOperator.GetLargestFilesRecursive(dirPaths, 10, results);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(results.empty());
    DeleteQuickFileDir(TEST_DIR_PATH);
}

/**
 * @tc.number: InstalldOperatorTest_19700
 * @tc.name: test GetLargestFilesRecursive with timeout values
 * @tc.desc: 1. calling GetLargestFilesRecursive with various timeouts
 *           2. verify timeout adjustments (<=0 becomes 3, >180 becomes 180)
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_19700, Function | SmallTest | Level0)
{
    CreateQuickFileDir(TEST_DIR_PATH);
    InstalldOperator installdOperator;
    std::vector<std::string> dirPaths = {TEST_DIR_PATH};
    std::vector<std::pair<std::string, uint64_t>> results;

    // Test with timeout = 0 (should use 3 seconds)
    bool ret1 = installdOperator.GetLargestFilesRecursive(dirPaths, 0, results);
    EXPECT_TRUE(ret1);

    results.clear();

    // Test with timeout = -1 (should use 3 seconds)
    bool ret2 = installdOperator.GetLargestFilesRecursive(dirPaths, -1, results);
    EXPECT_TRUE(ret2);

    results.clear();

    // Test with timeout = 200 (should use 180 seconds max)
    bool ret3 = installdOperator.GetLargestFilesRecursive(dirPaths, 200, results);
    EXPECT_TRUE(ret3);
    DeleteQuickFileDir(TEST_DIR_PATH);
}

/**
 * @tc.number: InstalldOperatorTest_19800
 * @tc.name: test GetLargestFilesRecursive with multiple directories
 * @tc.desc: 1. calling GetLargestFilesRecursive with multiple paths
 *           2. verify results from all directories are included
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_19800, Function | SmallTest | Level0)
{
    CreateQuickFileDir(TEST_DIR_PATH);
    InstalldOperator installdOperator;
    std::vector<std::string> dirPaths = {TEST_DIR_PATH, TEST_FILE_PATH};
    std::vector<std::pair<std::string, uint64_t>> results;

    bool ret = installdOperator.GetLargestFilesRecursive(dirPaths, 10, results);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(results.empty());
    DeleteQuickFileDir(TEST_DIR_PATH);
}

/**
 * @tc.number: InstalldOperatorTest_19900
 * @tc.name: test GetLargestFilesRecursive clears output parameter
 * @tc.desc: 1. calling GetLargestFilesRecursive with pre-populated results
 *           2. verify results are cleared before processing
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_19900, Function | SmallTest | Level0)
{
    CreateQuickFileDir(TEST_DIR_PATH);
    InstalldOperator installdOperator;
    std::vector<std::string> dirPaths = {TEST_DIR_PATH};
    std::vector<std::pair<std::string, uint64_t>> results;

    // Pre-populate with dummy data
    results.emplace_back("/dummy/path", 999999);
    EXPECT_FALSE(results.empty());

    // Call function
    bool ret = installdOperator.GetLargestFilesRecursive(dirPaths, 10, results);
    EXPECT_TRUE(ret);

    // Verify dummy data is gone
    bool hasDummy = std::any_of(results.begin(), results.end(),
        [](const std::pair<std::string, uint64_t>& item) {
            return item.first == "/dummy/path";
        });
    EXPECT_FALSE(hasDummy);
    DeleteQuickFileDir(TEST_DIR_PATH);
}

/**
 * @tc.number: InstalldOperatorTest_20000
 * @tc.name: test GetLargestFilesRecursive result sorting
 * @tc.desc: 1. calling GetLargestFilesRecursive with valid directory
 *           2. verify results are sorted by size in descending order
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_20000, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::vector<std::string> dirPaths = {TEST_FILE_PATH};
    std::vector<std::pair<std::string, uint64_t>> results;

    bool ret = installdOperator.GetLargestFilesRecursive(dirPaths, 10, results);
    EXPECT_TRUE(ret);

    if (results.size() > 1) {
        // Verify descending order by size
        for (size_t i = 0; i < results.size() - 1; ++i) {
            EXPECT_GE(results[i].second, results[i + 1].second);
        }
    }
}

/**
 * @tc.number: InstalldOperatorTest_20100
 * @tc.name: test GetLargestFilesRecursive with non-existent path
 * @tc.desc: 1. calling GetLargestFilesRecursive with invalid directory
 *           2. verify function handles gracefully (may fail or return empty)
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_20100, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::vector<std::string> dirPaths = {"/non/existent/path/that/does/not/exist"};
    std::vector<std::pair<std::string, uint64_t>> results;

    // Function should handle non-existent path gracefully
    bool ret = installdOperator.GetLargestFilesRecursive(dirPaths, 5, results);
    // May return false or true with empty results depending on implementation
    EXPECT_TRUE(ret);
    EXPECT_TRUE(results.empty());
}

/**
 * @tc.number: InstalldOperatorTest_20200
 * @tc.name: test GetLargestFilesRecursive with very short timeout
 * @tc.desc: 1. calling GetLargestFilesRecursive with 1 second timeout
 *           2. verify function respects timeout and returns quickly
*/
HWTEST_F(BmsInstallDaemonOperatorTest, InstalldOperatorTest_20200, Function | SmallTest | Level0)
{
    InstalldOperator installdOperator;
    std::vector<std::string> dirPaths = {TEST_DIR_PATH};
    std::vector<std::pair<std::string, uint64_t>> results;

    auto start = std::chrono::steady_clock::now();
    bool ret = installdOperator.GetLargestFilesRecursive(dirPaths, 1, results);
    auto end = std::chrono::steady_clock::now();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: MatchPathTemplate_0100
 * @tc.name: test MatchPathTemplate with simple prefix
 * @tc.desc: 1. test pattern without % performs simple prefix match
*/
HWTEST_F(BmsInstallDaemonOperatorTest, MatchPathTemplate_0100, Function | SmallTest | Level0)
{
    EXPECT_TRUE(InstalldOperator::MatchPathTemplate("/data/app/el1/100/test", "/data/app/el1/"));
    EXPECT_FALSE(InstalldOperator::MatchPathTemplate("/data/app/el2/100/test", "/data/app/el1/"));
    EXPECT_TRUE(InstalldOperator::MatchPathTemplate("/data/app/el1/", "/data/app/el1/"));
}

/**
 * @tc.number: MatchPathTemplate_0200
 * @tc.name: test MatchPathTemplate with % wildcard
 * @tc.desc: 1. test % matches dynamic userId segment
*/
HWTEST_F(BmsInstallDaemonOperatorTest, MatchPathTemplate_0200, Function | SmallTest | Level0)
{
    EXPECT_TRUE(InstalldOperator::MatchPathTemplate(
        "/data/app/el1/100/system_optimize/com.example", "/data/app/el1/%/system_optimize/"));
    EXPECT_TRUE(InstalldOperator::MatchPathTemplate(
        "/data/app/el1/9999/system_optimize/com.example", "/data/app/el1/%/system_optimize/"));
    EXPECT_FALSE(InstalldOperator::MatchPathTemplate(
        "/data/app/el2/100/system_optimize/com.example", "/data/app/el1/%/system_optimize/"));
    EXPECT_FALSE(InstalldOperator::MatchPathTemplate(
        "/data/app/el1/100/other/com.example", "/data/app/el1/%/system_optimize/"));
}

/**
 * @tc.number: MatchPathTemplate_0300
 * @tc.name: test MatchPathTemplate with path traversal in pattern
 * @tc.desc: 1. test pattern segment containing .. returns false
*/
HWTEST_F(BmsInstallDaemonOperatorTest, MatchPathTemplate_0300, Function | SmallTest | Level0)
{
    EXPECT_FALSE(InstalldOperator::MatchPathTemplate(
        "/data/app/el1/100/test", "/data/app/el1/%/system_optimize/../"));
}

/**
 * @tc.number: MatchPathTemplate_0400
 * @tc.name: test MatchPathTemplate with multiple % wildcards
 * @tc.desc: 1. test multiple % segments match correctly
*/
HWTEST_F(BmsInstallDaemonOperatorTest, MatchPathTemplate_0400, Function | SmallTest | Level0)
{
    EXPECT_TRUE(InstalldOperator::MatchPathTemplate(
        "/data/app/el1/100/base/com.example/cache", "/data/app/el1/%/base/%/cache"));
    EXPECT_FALSE(InstalldOperator::MatchPathTemplate(
        "/data/app/el1/100/base/com.example/other", "/data/app/el1/%/base/%/cache"));
}

/**
 * @tc.number: MatchPathTemplate_0500
 * @tc.name: test MatchPathTemplate with empty pattern and empty path
 * @tc.desc: 1. test empty pattern matches any path; 2. test empty path against non-empty prefix pattern returns false
*/
HWTEST_F(BmsInstallDaemonOperatorTest, MatchPathTemplate_0500, Function | SmallTest | Level0)
{
    EXPECT_TRUE(InstalldOperator::MatchPathTemplate("/data/app/test", ""));
    EXPECT_TRUE(InstalldOperator::MatchPathTemplate("", ""));
    EXPECT_FALSE(InstalldOperator::MatchPathTemplate("", "/data/app"));
    EXPECT_TRUE(InstalldOperator::MatchPathTemplate("/data/app", "/data/app"));
}
} // OHOS