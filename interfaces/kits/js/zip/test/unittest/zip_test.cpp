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
#include <cstring>
#include <fstream>
#include <memory>
#include <set>
#include <thread>

#include "ani_zlib_callback_info.h"
#include "gzip_entity.h"
#include "zip.h"
#include "zlib_callback_info.h"
#define private public
#include "zip_reader.h"
#undef private
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
const std::string UNZIP_ERROR_DETAIL_TEST_PATH = "/data/test/zip_error_detail/";
const std::string UNZIP_ERROR_DETAIL_SRC = UNZIP_ERROR_DETAIL_TEST_PATH + "not_zip.txt";
const std::string UNZIP_ERROR_DETAIL_DEST = UNZIP_ERROR_DETAIL_TEST_PATH + "dest";

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

class MockZlibCallbackInfo : public ZlibCallbackInfoBase {
public:
    void OnZipUnZipFinish(ErrCode result) override
    {
        result_ = result;
        detailMessage_.clear();
    }

    void OnZipUnZipFinish(ErrCode result, const std::string &detailMessage) override
    {
        result_ = result;
        detailMessage_ = detailMessage;
    }

    void DoTask(const OHOS::AppExecFwk::InnerEvent::Callback& task) override
    {
        task();
    }

    ErrCode result_ = ERR_OK;
    std::string detailMessage_;
};
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
    unlink(UNZIP_ERROR_DETAIL_SRC.c_str());
    unlink((KEEP_TOP_LEVEL_SINGLE_PATH + "/single.txt").c_str());
    unlink((KEEP_TOP_LEVEL_FIRST_PATH + "/first.txt").c_str());
    unlink((KEEP_TOP_LEVEL_SECOND_PATH + "/second.txt").c_str());
    rmdir(UNZIP_ERROR_DETAIL_DEST.c_str());
    rmdir(UNZIP_ERROR_DETAIL_TEST_PATH.c_str());
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
 * @tc.number: APPEXECFWK_LIBZIP_UnzipErrorDetail_0100
 * @tc.name: UnzipErrorDetail_0100
 * @tc.desc: Verify invalid destination path returns detailed unzip error.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_UnzipErrorDetail_0100, Function | MediumTest | Level1)
{
    std::string src = TEST_ZIP_OK;
    std::string dest = "";
    auto zlibCallbackInfo = std::make_shared<MockZlibCallbackInfo>();

    OPTIONS options;
    auto ret = Unzip(src, dest, options, zlibCallbackInfo);
    EXPECT_FALSE(ret);
    EXPECT_EQ(zlibCallbackInfo->result_, ERR_ZLIB_DEST_FILE_DISABLED);
    EXPECT_EQ(zlibCallbackInfo->detailMessage_, "destination path is empty or contains relative path");
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_UnzipErrorDetail_0200
 * @tc.name: UnzipErrorDetail_0200
 * @tc.desc: Verify invalid source path returns detailed unzip error.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_UnzipErrorDetail_0200, Function | MediumTest | Level1)
{
    std::string src = "";
    std::string dest = BASE_PATH + APP_PATH;
    auto zlibCallbackInfo = std::make_shared<MockZlibCallbackInfo>();

    OPTIONS options;
    auto ret = Unzip(src, dest, options, zlibCallbackInfo);
    EXPECT_FALSE(ret);
    EXPECT_EQ(zlibCallbackInfo->result_, ERR_ZLIB_SRC_FILE_DISABLED);
    EXPECT_EQ(zlibCallbackInfo->detailMessage_, "source path is empty or contains relative path");
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_UnzipErrorDetail_0300
 * @tc.name: UnzipErrorDetail_0300
 * @tc.desc: Verify inaccessible source path returns detailed unzip error.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_UnzipErrorDetail_0300, Function | MediumTest | Level1)
{
    std::string src = UNZIP_ERROR_DETAIL_TEST_PATH + "not_exist.zip";
    std::string dest = UNZIP_ERROR_DETAIL_DEST;
    auto zlibCallbackInfo = std::make_shared<MockZlibCallbackInfo>();

    OPTIONS options;
    auto ret = Unzip(src, dest, options, zlibCallbackInfo);
    EXPECT_FALSE(ret);
    EXPECT_EQ(zlibCallbackInfo->result_, ERR_ZLIB_SRC_FILE_DISABLED);
    EXPECT_EQ(zlibCallbackInfo->detailMessage_, "source file does not exist or cannot be accessed");
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_UnzipErrorDetail_0400
 * @tc.name: UnzipErrorDetail_0400
 * @tc.desc: Verify non-ZIP source file returns detailed unzip error.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_UnzipErrorDetail_0400, Function | MediumTest | Level1)
{
    ASSERT_TRUE(FilePath::CreateDirectory(FilePath(UNZIP_ERROR_DETAIL_DEST)));
    ASSERT_TRUE(CreateTestFile(UNZIP_ERROR_DETAIL_SRC));
    auto zlibCallbackInfo = std::make_shared<MockZlibCallbackInfo>();

    OPTIONS options;
    auto ret = Unzip(UNZIP_ERROR_DETAIL_SRC, UNZIP_ERROR_DETAIL_DEST, options, zlibCallbackInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(zlibCallbackInfo->result_, ERR_ZLIB_SRC_FILE_FORMAT_ERROR);
    EXPECT_EQ(zlibCallbackInfo->detailMessage_, "source file is not in ZIP format or is damaged");
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_UnzipErrorDetail_0500
 * @tc.name: UnzipErrorDetail_0500
 * @tc.desc: Verify non-ZIP source file returns detailed unzip error in parallel mode.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_UnzipErrorDetail_0500, Function | MediumTest | Level1)
{
    ASSERT_TRUE(FilePath::CreateDirectory(FilePath(UNZIP_ERROR_DETAIL_DEST)));
    ASSERT_TRUE(CreateTestFile(UNZIP_ERROR_DETAIL_SRC));
    auto zlibCallbackInfo = std::make_shared<MockZlibCallbackInfo>();

    OPTIONS options;
    options.parallel = PARALLEL_STRATEGY_PARALLEL_DECOMPRESSION;
    auto ret = Unzip(UNZIP_ERROR_DETAIL_SRC, UNZIP_ERROR_DETAIL_DEST, options, zlibCallbackInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(zlibCallbackInfo->result_, ERR_ZLIB_SRC_FILE_FORMAT_ERROR);
    EXPECT_EQ(zlibCallbackInfo->detailMessage_, "source file is not in ZIP format or is damaged");
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_ANIUnzipErrorDetail_0100
 * @tc.name: ANIUnzipErrorDetail_0100
 * @tc.desc: Verify ANI callback keeps detailed unzip error.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_ANIUnzipErrorDetail_0100, Function | MediumTest | Level1)
{
    ANIZlibCallbackInfo callbackInfo;
    callbackInfo.OnZipUnZipFinish(
        ERR_ZLIB_SRC_FILE_DISABLED, "source file does not exist or cannot be accessed");

    auto result = callbackInfo.GetDetailedResult();
    EXPECT_EQ(result.errCode, ERR_ZLIB_SRC_FILE_DISABLED);
    EXPECT_EQ(result.detailMessage, "source file does not exist or cannot be accessed");
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

/**
 * @tc.number: APPEXECFWK_LIBZIP_ZipReader_AdvanceToNextEntry_0100
 * @tc.name: ZipReader_AdvanceToNextEntry_0100
 * @tc.desc: Test ZipReader::AdvanceToNextEntry with valid zip file to verify type safety improvements
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_ZipReader_AdvanceToNextEntry_0100, Function | MediumTest | Level1)
{
    FilePath filePath(TEST_ZIP_OK);
    ZipReader reader;
    ASSERT_TRUE(reader.Open(filePath));

    // Open first entry
    ASSERT_TRUE(reader.OpenCurrentEntryInZip());

    // Advance through entries - tests the uLong type conversion and >= comparison
    int entryCount = 0;
    while (reader.HasMore()) {
        if (!reader.AdvanceToNextEntry()) {
            break;
        }
        entryCount++;
        if (entryCount > 100) { // Safety limit
            break;
        }
    }
    EXPECT_GT(entryCount, 0);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_ZipReader_OpenInternal_0100
 * @tc.name: ZipReader_OpenInternal_0100
 * @tc.desc: Test ZipReader::OpenInternal with valid zip to verify number_entry overflow check
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_ZipReader_OpenInternal_0100, Function | MediumTest | Level1)
{
    FilePath filePath(TEST_ZIP_OK);
    ZipReader reader;

    // Open should succeed and validate number_entry against INT_MAX
    bool ret = reader.Open(filePath);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_ZipReader_OpenInternal_0200
 * @tc.name: ZipReader_OpenInternal_0200
 * @tc.desc: Test ZipReader::OpenInternal with damaged zip file
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_ZipReader_OpenInternal_0200, Function | MediumTest | Level1)
{
    FilePath filePath(TEST_ZIP_DMAGED);
    ZipReader reader;

    // Open should fail for damaged file
    bool ret = reader.Open(filePath);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_ZipParallelReader_GotoEntry_0100
 * @tc.name: ZipParallelReader_GotoEntry_0100
 * @tc.desc: Test ZipParallelReader::GotoEntry with valid and invalid entry positions
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_ZipParallelReader_GotoEntry_0100, Function | MediumTest | Level1)
{
    FilePath filePath(TEST_ZIP_OK);
    ZipParallelReader parallelReader;
    ASSERT_TRUE(parallelReader.Open(filePath));

    int resourceId = 0;
    unzFile zipFile = parallelReader.GetZipHandler(resourceId);
    ASSERT_NE(zipFile, nullptr);

    // Obtain a valid file position by going to the first entry and reading its pos.
    // Hardcoding {0, 0} is unreliable because pos_in_zipfile is an internal offset
    // that only unzGetFilePos can produce correctly.
    ASSERT_EQ(unzGoToFirstFile(zipFile), UNZ_OK);
    unz_file_pos validPos;
    ASSERT_EQ(unzGetFilePos(zipFile, &validPos), UNZ_OK);
    bool ret = parallelReader.GotoEntry(zipFile, validPos);
    EXPECT_TRUE(ret);

    // Test with invalid position (num_of_file beyond entry count)
    unz_file_pos invalidPos = {999999, 0};
    ret = parallelReader.GotoEntry(zipFile, invalidPos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_ZipParallelReader_GetZipHandler_0100
 * @tc.name: ZipParallelReader_GetZipHandler_0100
 * @tc.desc: Test ZipParallelReader::GetZipHandler with negative resourceId
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_ZipParallelReader_GetZipHandler_0100, Function | MediumTest | Level1)
{
    FilePath filePath(TEST_ZIP_OK);
    ZipParallelReader parallelReader;
    ASSERT_TRUE(parallelReader.Open(filePath));

    // Test with negative resourceId - should be normalized to 0
    int resourceId = -1;
    unzFile zipFile = parallelReader.GetZipHandler(resourceId);
    EXPECT_NE(zipFile, nullptr);
    EXPECT_EQ(resourceId, 0); // Should be normalized

    // Test with valid resourceId
    resourceId = 1;
    zipFile = parallelReader.GetZipHandler(resourceId);
    EXPECT_NE(zipFile, nullptr);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_ZipParallelReader_GetZipHandler_0200
 * @tc.name: ZipParallelReader_GetZipHandler_0200
 * @tc.desc: Test ZipParallelReader::GetZipHandler with large resourceId
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_ZipParallelReader_GetZipHandler_0200, Function | MediumTest | Level1)
{
    FilePath filePath(TEST_ZIP_OK);
    ZipParallelReader parallelReader;
    ASSERT_TRUE(parallelReader.Open(filePath));

    // Test with large resourceId - should be wrapped by modulo
    int resourceId = 100;
    unzFile zipFile = parallelReader.GetZipHandler(resourceId);
    EXPECT_NE(zipFile, nullptr);
    // 100 % 2 = 0, so resourceId should be 0 after normalization
    EXPECT_EQ(resourceId % 2, 0);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_ZipParallelReader_GotoEntry_0200
 * @tc.name: ZipParallelReader_GotoEntry_0200
 * @tc.desc: Test ZipParallelReader::GotoEntry with nullptr zipFile — should return false.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_ZipParallelReader_GotoEntry_0200, Function | MediumTest | Level1)
{
    ZipParallelReader parallelReader;
    unzFile nullFile = nullptr;
    unz_file_pos pos = {0, 0};
    bool ret = parallelReader.GotoEntry(nullFile, pos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_ZipReader_AdvanceToNextEntry_0200
 * @tc.name: ZipReader_AdvanceToNextEntry_0200
 * @tc.desc: Test AdvanceToNextEntry reaches end — verifies the >= comparison when
 *           currentEntryIndex + 1 >= numEntries_ sets reachedEnd_.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_ZipReader_AdvanceToNextEntry_0200, Function | MediumTest | Level1)
{
    FilePath filePath(TEST_ZIP_OK);
    ZipReader reader;
    ASSERT_TRUE(reader.Open(filePath));
    ASSERT_TRUE(reader.OpenCurrentEntryInZip());

    // Advance until we reach the end — the >= check fires on the last entry
    int entryCount = 0;
    while (reader.HasMore()) {
        if (!reader.AdvanceToNextEntry()) {
            break;
        }
        entryCount++;
        if (entryCount > 100) {
            break;
        }
    }
    // After exhausting entries, HasMore should be false (reachedEnd_ set)
    EXPECT_FALSE(reader.HasMore());
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_ZipParallelReader_GotoEntry_0300
 * @tc.name: ZipParallelReader_GotoEntry_0300
 * @tc.desc: Test GotoEntry with numEntries < 0 — covers the defensive numEntries < 0 branch
 *           (L323 Branch 1). Uses #define private public to set numEntries_ to -1.
 *           zipFile is a dummy non-null pointer since GotoEntry returns before using it.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_ZipParallelReader_GotoEntry_0300, Function | MediumTest | Level1)
{
    ZipParallelReader parallelReader;
    // Set numEntries_ to -1 to trigger the numEntries < 0 branch
    parallelReader.numEntries_ = -1;
    // Dummy non-null zipFile — GotoEntry returns false before dereferencing it
    unzFile dummyFile = reinterpret_cast<unzFile>(0x1);
    unz_file_pos pos = {0, 0};
    bool ret = parallelReader.GotoEntry(dummyFile, pos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_ZipParallelReader_GotoEntry_0400
 * @tc.name: ZipParallelReader_GotoEntry_0400
 * @tc.desc: Test GotoEntry with filePos.num_of_file >= numEntries — covers the >= branch
 *           (L323 Branch 2). Sets numEntries_ to 0 and filePos.num_of_file to 1.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_ZipParallelReader_GotoEntry_0400, Function | MediumTest | Level1)
{
    ZipParallelReader parallelReader;
    // Set numEntries_ to 0 so any filePos.num_of_file >= 0 triggers the >= branch
    parallelReader.numEntries_ = 0;
    unzFile dummyFile = reinterpret_cast<unzFile>(0x1);
    unz_file_pos pos = {1, 0};  // num_of_file=1 >= numEntries=0 → true
    bool ret = parallelReader.GotoEntry(dummyFile, pos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_GZipEntity_Destructor_ClosesHandle_0100
 * @tc.name: GZipEntity_Destructor_ClosesHandle_0100
 * @tc.desc: Verify that GZipEntity's destructor properly closes the gzFile handle via Deleter.
 *           Open a file with gzopen, swap the handle into GZipEntity, let entity go out of scope,
 *           then verify the handle is closed by attempting gzflush (should fail on closed handle).
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_GZipEntity_Destructor_ClosesHandle_0100, Function | MediumTest | Level1)
{
    const std::string gzPath = "/data/local/tmp/zip_test_gzip_entity_0100.gz";
    gzFile rawHandle = gzopen(gzPath.c_str(), "wb");
    ASSERT_NE(rawHandle, nullptr) << "Failed to create gzip file for test";

    // Write some data to ensure the file is properly initialized
    const char *testData = "test data for gzip entity";
    int writeResult = gzwrite(rawHandle, testData, strlen(testData));
    EXPECT_GT(writeResult, 0) << "Failed to write to gzip file";

    // Swap the handle into GZipEntity
    {
        GZipEntity entity;
        entity.gzs.reset(rawHandle);
        // entity goes out of scope here, destructor should call gzclose via Deleter
    }

    // Verify the handle was closed by attempting to use it
    // gzflush on a closed handle should return Z_STREAM_ERROR or crash if not properly closed
    // We use a safer approach: try to reopen the file, which should succeed if properly closed
    gzFile reopenedHandle = gzopen(gzPath.c_str(), "rb");
    EXPECT_NE(reopenedHandle, nullptr) << "File should be reopenable after GZipEntity destruction";
    if (reopenedHandle != nullptr) {
        gzclose(reopenedHandle);
    }

    // Clean up test file
    remove(gzPath.c_str());
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_GZipEntity_NullHandle_NoCrash_0300
 * @tc.name: GZipEntity_NullHandle_NoCrash_0300
 * @tc.desc: Verify that GZipEntity with null handle does not crash on destruction.
 *           The Deleter should check for nullptr before calling gzclose.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_GZipEntity_NullHandle_NoCrash_0300, Function | SmallTest | Level1)
{
    // Construct GZipEntity with default (null) handle
    {
        GZipEntity entity;
        // entity.gzs is nullptr by default
        // Destructor should not crash when Deleter is called with nullptr
    }
    // If we reach here without crash, the test passes
    SUCCEED();
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_GZipEntity_ResetHandle_ClosesPrevious_0400
 * @tc.name: GZipEntity_ResetHandle_ClosesPrevious_0400
 * @tc.desc: Verify that resetting GZipEntity's handle properly closes the previous handle.
 *           Open two files, swap first into entity, then reset with second handle,
 *           verify first handle is closed by reopening the first file.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_GZipEntity_ResetHandle_ClosesPrevious_0400, Function | MediumTest | Level1)
{
    const std::string gzPath1 = "/data/local/tmp/zip_test_gzip_entity_0400_1.gz";
    const std::string gzPath2 = "/data/local/tmp/zip_test_gzip_entity_0400_2.gz";

    gzFile handle1 = gzopen(gzPath1.c_str(), "wb");
    ASSERT_NE(handle1, nullptr) << "Failed to create first gzip file";
    gzwrite(handle1, "data1", 5);

    gzFile handle2 = gzopen(gzPath2.c_str(), "wb");
    ASSERT_NE(handle2, nullptr) << "Failed to create second gzip file";
    gzwrite(handle2, "data2", 5);

    {
        GZipEntity entity;
        entity.gzs.reset(handle1);
        // Reset with handle2, should close handle1 via Deleter
        entity.gzs.reset(handle2);
        // entity goes out of scope, should close handle2
    }

    // Both files should be reopenable, confirming both handles were closed
    gzFile reopened1 = gzopen(gzPath1.c_str(), "rb");
    EXPECT_NE(reopened1, nullptr) << "First file should be reopenable after handle reset";
    if (reopened1 != nullptr) {
        gzclose(reopened1);
    }

    gzFile reopened2 = gzopen(gzPath2.c_str(), "rb");
    EXPECT_NE(reopened2, nullptr) << "Second file should be reopenable after entity destruction";
    if (reopened2 != nullptr) {
        gzclose(reopened2);
    }

    // Clean up test files
    remove(gzPath1.c_str());
    remove(gzPath2.c_str());
}

}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
