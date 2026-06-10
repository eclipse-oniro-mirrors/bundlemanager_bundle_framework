/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <fstream>
#include <memory>
#include <set>
#include <thread>

#include "zip.h"
#include "zip_reader.h"
#include "zlib_callback_info.h"
namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
using namespace testing::ext;

namespace {
const std::string BASE_PATH = "/data/app/el2/100/base/";
const std::string APP_PATH = "com.example.zlib/com.example.zlib/com.example.zlib.MainAbility/files/";
const std::string TEST_ZIP_OK = "/data/test/resource/bms/test_zip/resourceManagerTest.hap";
const std::string TEST_ZIP_DMAGED = "/data/test/resource/bms/test_zip/ohos_test.xml";
const std::string KEEP_TOP_LEVEL_TEST_PATH = "/data/test/zip_keep_top_level/";
const std::string KEEP_TOP_LEVEL_SINGLE_PATH = KEEP_TOP_LEVEL_TEST_PATH + "single";
const std::string KEEP_TOP_LEVEL_FIRST_PATH = KEEP_TOP_LEVEL_TEST_PATH + "first";
const std::string KEEP_TOP_LEVEL_SECOND_PATH = KEEP_TOP_LEVEL_TEST_PATH + "second";
const std::string KEEP_TOP_LEVEL_SINGLE_ZIP = KEEP_TOP_LEVEL_TEST_PATH + "single.zip";
const std::string KEEP_TOP_LEVEL_SINGLE_FALSE_ZIP = KEEP_TOP_LEVEL_TEST_PATH + "single_false.zip";
const std::string KEEP_TOP_LEVEL_MULTI_ZIP = KEEP_TOP_LEVEL_TEST_PATH + "multi.zip";

bool CreateTestFile(const std::string &path)
{
    std::ofstream file(path);
    file << "zip test";
    return file.good();
}

bool PrepareKeepTopLevelTestFiles()
{
    return FilePath::CreateDirectory(FilePath(KEEP_TOP_LEVEL_SINGLE_PATH)) &&
        FilePath::CreateDirectory(FilePath(KEEP_TOP_LEVEL_FIRST_PATH)) &&
        FilePath::CreateDirectory(FilePath(KEEP_TOP_LEVEL_SECOND_PATH)) &&
        CreateTestFile(KEEP_TOP_LEVEL_SINGLE_PATH + "/single.txt") &&
        CreateTestFile(KEEP_TOP_LEVEL_FIRST_PATH + "/first.txt") &&
        CreateTestFile(KEEP_TOP_LEVEL_SECOND_PATH + "/second.txt");
}

std::set<std::string> GetZipEntryNames(const std::string &zipPath)
{
    std::set<std::string> entryNames;
    FilePath filePath(zipPath);
    ZipReader reader;
    if (!reader.Open(filePath)) {
        return entryNames;
    }
    while (reader.HasMore()) {
        if (!reader.OpenCurrentEntryInZip()) {
            return {};
        }
        FilePath entryPath = reader.CurrentEntryInfo()->GetFilePath();
        entryNames.insert(entryPath.Value());
        if (!reader.AdvanceToNextEntry()) {
            return {};
        }
    }
    return entryNames;
}
}  // namespac

bool Zip(const ZipParams &params, const OPTIONS &options);
bool Zips(const ZipParams &params, const OPTIONS &options);

class ZipTest : public testing::Test {
public:
    ZipTest()
    {}
    ~ZipTest()
    {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ZipTest::SetUpTestCase(void)
{}

void ZipTest::TearDownTestCase(void)
{}

void ZipTest::SetUp()
{}

void ZipTest::TearDown()
{
    unlink(KEEP_TOP_LEVEL_SINGLE_ZIP.c_str());
    unlink(KEEP_TOP_LEVEL_SINGLE_FALSE_ZIP.c_str());
    unlink(KEEP_TOP_LEVEL_MULTI_ZIP.c_str());
    unlink((KEEP_TOP_LEVEL_SINGLE_PATH + "/single.txt").c_str());
    unlink((KEEP_TOP_LEVEL_FIRST_PATH + "/first.txt").c_str());
    unlink((KEEP_TOP_LEVEL_SECOND_PATH + "/second.txt").c_str());
    rmdir(KEEP_TOP_LEVEL_SINGLE_PATH.c_str());
    rmdir(KEEP_TOP_LEVEL_FIRST_PATH.c_str());
    rmdir(KEEP_TOP_LEVEL_SECOND_PATH.c_str());
    rmdir(KEEP_TOP_LEVEL_TEST_PATH.c_str());
}

void ZipCallBack(int result)
{
    printf("--Zip--callback--result=%d--\n", result);
}
void UnzipCallBack(int result)
{
    printf("--UnZip--callback--result=%d--\n", result);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_zip_0100_8file
 * @tc.name: zip_0100_8file
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_zip_0100_8file, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "test";
    std::string dest = BASE_PATH + APP_PATH + "result/8file.zip";

    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    OPTIONS options;
    auto ret = Zip(src, dest, options, false, zlibCallbackInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_zip_0200_1file
 * @tc.name: zip_0200_1file
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_zip_0200_1file, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "test/01";
    std::string dest = BASE_PATH + APP_PATH + "result/1file.zip";

    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    OPTIONS options;
    auto ret = Zip(src, dest, options, false, zlibCallbackInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_zip_0100_zip1file
 * @tc.name: zip_0100_zip1file
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_zip_0100_zip1file, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "test/01/zip1.txt";
    std::string dest = BASE_PATH + APP_PATH + "result/zip1file.zip";

    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    OPTIONS options;
    auto ret = Zip(src, dest, options, false, zlibCallbackInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_keep_top_level_folder_0100
 * @tc.name: keep_top_level_folder_0100
 * @tc.desc: Verify Zip keeps the source directory name only when keepTopLevelFolder is true.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_keep_top_level_folder_0100, Function | MediumTest | Level1)
{
    ASSERT_TRUE(PrepareKeepTopLevelTestFiles());
    OPTIONS options;
    std::vector<FilePath> srcFiles = { FilePath(KEEP_TOP_LEVEL_SINGLE_PATH) };

    ZipParams withoutTopLevelParams(srcFiles, FilePath(KEEP_TOP_LEVEL_SINGLE_FALSE_ZIP));
    ASSERT_TRUE(Zip(withoutTopLevelParams, options));
    EXPECT_EQ(GetZipEntryNames(KEEP_TOP_LEVEL_SINGLE_FALSE_ZIP), std::set<std::string>({ "single.txt" }));

    options.keepTopLevelFolder = true;
    ZipParams withTopLevelParams(srcFiles, FilePath(KEEP_TOP_LEVEL_SINGLE_ZIP));
    ASSERT_TRUE(Zip(withTopLevelParams, options));
    EXPECT_EQ(GetZipEntryNames(KEEP_TOP_LEVEL_SINGLE_ZIP), std::set<std::string>({ "single/single.txt" }));
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_keep_top_level_folder_0200
 * @tc.name: keep_top_level_folder_0200
 * @tc.desc: Verify Zips keeps each source directory name when keepTopLevelFolder is true.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_keep_top_level_folder_0200, Function | MediumTest | Level1)
{
    ASSERT_TRUE(PrepareKeepTopLevelTestFiles());
    std::vector<FilePath> srcFiles = {
        FilePath(KEEP_TOP_LEVEL_FIRST_PATH),
        FilePath(KEEP_TOP_LEVEL_SECOND_PATH)
    };
    OPTIONS options;
    options.keepTopLevelFolder = true;
    ZipParams params(srcFiles, FilePath(KEEP_TOP_LEVEL_MULTI_ZIP));

    ASSERT_TRUE(Zips(params, options));
    EXPECT_EQ(GetZipEntryNames(KEEP_TOP_LEVEL_MULTI_ZIP),
        std::set<std::string>({ "first/first.txt", "second/second.txt" }));
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_unzip_0100_8file
 * @tc.name: unzip_0100_8file
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_unzip_0100_8file, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "result/8file.zip";
    std::string dest = BASE_PATH + APP_PATH + "unzip/01";

    OPTIONS options;
    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    auto ret = Unzip(src, dest, options, zlibCallbackInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_unzip_0100_8file_parallel
 * @tc.name: unzip_0100_8file_parallel
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_unzip_0100_8file_parallel, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "result/8file.zip";
    std::string dest = BASE_PATH + APP_PATH + "unzip/01";

    OPTIONS options;
    options.parallel = PARALLEL_STRATEGY_PARALLEL_DECOMPRESSION;
    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    auto ret = Unzip(src, dest, options, zlibCallbackInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_unzip_single_0200_1file
 * @tc.name: unzip_single_0200_1file
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_unzip_single_0200_1file, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "result/1file.zip";
    std::string dest = BASE_PATH + APP_PATH + "unzip/02";

    OPTIONS options;
    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    auto ret = Unzip(src, dest, options, zlibCallbackInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_unzip_single_0200_1file_parallel
 * @tc.name: unzip_single_0200_1file_parallel
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_unzip_single_0200_1file_parallel, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "result/1file.zip";
    std::string dest = BASE_PATH + APP_PATH + "unzip/02";

    OPTIONS options;
    options.parallel = PARALLEL_STRATEGY_PARALLEL_DECOMPRESSION;
    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    auto ret = Unzip(src, dest, options, zlibCallbackInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_zip_0100_zip1file
 * @tc.name: zip_0100_zip1file
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_unzip_0100_zip1file, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "result/zip1file.zip";
    std::string dest = BASE_PATH + APP_PATH + "unzip/zip1file";

    OPTIONS options;
    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    auto ret = Unzip(src, dest, options, zlibCallbackInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_zip_0100_zip1file_parallel
 * @tc.name: zip_0100_zip1file_parallel
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_unzip_0100_zip1file_parallel, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "result/zip1file.zip";
    std::string dest = BASE_PATH + APP_PATH + "unzip/zip1file";

    OPTIONS options;
    options.parallel = PARALLEL_STRATEGY_PARALLEL_DECOMPRESSION;
    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    auto ret = Unzip(src, dest, options, zlibCallbackInfo);
    EXPECT_FALSE(ret);
}


/**
 * @tc.number: APPEXECFWK_LIBZIP_Checkzip_0100
 * @tc.name: Checkzip_0100
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_Checkzip_0100, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "test";
    std::string dest = BASE_PATH + APP_PATH + "check";
    FilePath destFile(dest);

    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    OPTIONS options;
    auto ret = Zip(src, dest, options, false, zlibCallbackInfo);
    destFile.CheckDestDirTail();
    FilePath newDestFile(destFile.CheckDestDirTail());
    std::cout << newDestFile.Value() << std::endl;
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_Checkzip_0200
 * @tc.name: Checkzip_0200
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_Checkzip_0200, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "test";
    std::string dest = BASE_PATH + APP_PATH + "error/check.zip";

    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    OPTIONS options;
    auto ret = Zip(src, dest, options, false, zlibCallbackInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_Checkzip_0300
 * @tc.name: Checkzip_0300
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_Checkzip_0300, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "error";
    std::string src1 = BASE_PATH + APP_PATH + "#%#@$%";
    std::string src2 = BASE_PATH + APP_PATH + "error/error1";
    std::string dest = BASE_PATH + APP_PATH + "/check.zip";

    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    OPTIONS options;
    auto ret1 = Zip(src, dest, options, false, zlibCallbackInfo);
    auto ret2 = Zip(src1, dest, options, false, zlibCallbackInfo);
    auto ret3 = Zip(src2, dest, options, false, zlibCallbackInfo);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(ret3);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_Checkzip_0400
 * @tc.name: Checkzip_0400
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_Checkzip_0400, Function | MediumTest | Level1)
{
    std::string src1 = BASE_PATH + APP_PATH + "error.txt";
    std::string dest = BASE_PATH + APP_PATH + "check.zip";
    FilePath srcFile1(src1);

    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    OPTIONS options;
    auto ret = Zip(src1, dest, options, false, zlibCallbackInfo);
    EXPECT_TRUE(ret);
    std::cout << "srcFile1  DirName: " << srcFile1.DirName().Value() << std::endl;
    std::cout << "srcFile1  Value:   " << srcFile1.Value() << std::endl;
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_Checkzip_0500
 * @tc.name: Checkzip_0500
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_Checkzip_0500, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "error";
    std::string dest = BASE_PATH + APP_PATH + "error1";

    OPTIONS options;
    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    auto ret = Unzip(src, dest, options, zlibCallbackInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_Checkzip_0500_parallel
 * @tc.name: Checkzip_0500_parallel
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_Checkzip_0500_parallel, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "error";
    std::string dest = BASE_PATH + APP_PATH + "error1";

    OPTIONS options;
    options.parallel = PARALLEL_STRATEGY_PARALLEL_DECOMPRESSION;
    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    auto ret = Unzip(src, dest, options, zlibCallbackInfo);
    EXPECT_FALSE(ret);
}


/**
 * @tc.number: APPEXECFWK_LIBZIP_Checkzip_0600
 * @tc.name: Checkzip_0600
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_Checkzip_0600, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "test";
    std::string dest = "";

    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    OPTIONS options;
    auto ret = Zip(src, dest, options, false, zlibCallbackInfo);
    EXPECT_FALSE(ret);
    std::cout << dest << std::endl;
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_Checkzip_0700
 * @tc.name: Checkzip_0700
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_Checkzip_0700, Function | MediumTest | Level1)
{
    std::string src = "";
    std::string dest = BASE_PATH + APP_PATH;
    FilePath destFile(dest);

    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    OPTIONS options;
    auto ret = Zip(src, dest, options, false, zlibCallbackInfo);
    EXPECT_FALSE(ret);
    destFile.CheckDestDirTail();
    FilePath newDestFile(destFile.CheckDestDirTail());
    std::cout << newDestFile.Value() << std::endl;
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_Checkzip_0800
 * @tc.name: Checkzip_0800
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_Checkzip_0800, Function | MediumTest | Level1)
{
    std::string src = "";
    std::string dest = BASE_PATH + APP_PATH;

    OPTIONS options;
    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    auto ret = Unzip(src, dest, options, zlibCallbackInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_Checkzip_0800_parallel
 * @tc.name: Checkzip_0800_parallel
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_Checkzip_0800_parallel, Function | MediumTest | Level1)
{
    std::string src = "";
    std::string dest = BASE_PATH + APP_PATH;

    OPTIONS options;
    options.parallel = PARALLEL_STRATEGY_PARALLEL_DECOMPRESSION;
    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>();
    auto ret = Unzip(src, dest, options, zlibCallbackInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_GetOriginalSize_0100
 * @tc.name: GetOriginalSize_0100
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_GetOriginalSize_0100, Function | MediumTest | Level1)
{
    std::string src = "";
    int64_t originalSize = 0;

    auto ret = GetOriginalSize(src, originalSize);
    EXPECT_EQ(ret, ERR_ZLIB_SRC_FILE_DISABLED);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_GetOriginalSize_0200
 * @tc.name: GetOriginalSize_0200
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_GetOriginalSize_0200, Function | MediumTest | Level1)
{
    std::string src = BASE_PATH + APP_PATH + "result/8file.zip";
    int64_t originalSize = 0;

    auto ret = GetOriginalSize(src, originalSize);
    EXPECT_EQ(ret, ERR_ZLIB_SRC_FILE_DISABLED);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_GetOriginalSize_0300
 * @tc.name: GetOriginalSize_0300
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_GetOriginalSize_0300, Function | MediumTest | Level1)
{
    std::string src = TEST_ZIP_DMAGED;
    int64_t originalSize = 0;

    auto ret = GetOriginalSize(src, originalSize);
    EXPECT_EQ(ret, ERR_ZLIB_SRC_FILE_FORMAT_ERROR);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_GetOriginalSize_0400
 * @tc.name: GetOriginalSize_0400
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_GetOriginalSize_0400, Function | MediumTest | Level1)
{
    std::string src = TEST_ZIP_OK;
    int64_t originalSize = 0;

    auto ret = GetOriginalSize(src, originalSize);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GT(originalSize, 0);
}
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
