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
#include <atomic>
#include <cstdint>
#include <fstream>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

#include "ani_zlib_callback_info.h"
#include "zip.h"
#include "zip_reader.h"
#include "zlib_callback_info.h"
#include "../napi/class_gzip/gzip_entity.h"
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
namespace {
const std::string GZ_STRESS_PATH = "/data/test/zip_gzip_stress/";
constexpr int32_t GZ_STRESS_ENTITY_NUM = 500;
constexpr int32_t GZ_STRESS_WORKER_NUM = 16;
constexpr int32_t GZ_STRESS_GC_THREAD_NUM = 4;
constexpr int32_t GZ_STRESS_CHUNK_SIZE = 32 * 1024;
constexpr int32_t GZ_STRESS_WRITE_ROUNDS = 64;
constexpr int32_t GZ_STRESS_GC_BATCH = 20;
constexpr int32_t GZ_STRESS_SMALL_ENTITY_NUM = 50;
}  // namespace

/**
 * @tc.number: APPEXECFWK_LIBZIP_GZipEntity_GcDtorStress_0001
 * @tc.name: GZipEntity_GcDtorStress_0001
 * @tc.desc: Regression test for GZipEntity batch destruction safety.
 *           Verifies that the close-without-release leftover state
 *           (gzclose succeeded but gzs still holds the freed pointer)
 *           is safe under batch destruction, simulating the taskpool
 *           GC finalizer scenario (ArkFinalizersPack::ProcessAll).
 *
 *           Prerequisite: Deleter<gzFile_s> must be a no-op (HEAD behavior).
 *           If Deleter calls gzclose, this test will crash by design.
 *           All counters must hold exactly, and a fresh gzopen/gzclose
 *           round proves zlib state health after batch destruction.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_GZipEntity_GcDtorStress_0001, Function | MediumTest | Level1)
{
    FilePath::CreateDirectory(FilePath(GZ_STRESS_PATH));
    // mass compression ops - pile up gzFile objects held by GZipEntity
    std::vector<std::unique_ptr<GZipEntity>> entities;
    std::atomic<int32_t> openOk(0);
    for (int32_t i = 0; i < GZ_STRESS_ENTITY_NUM; ++i) {
        auto entity = std::make_unique<GZipEntity>();
        std::string name = GZ_STRESS_PATH + "stress_gc_" + std::to_string(i) + ".gz";
        gzFile file = gzopen(name.c_str(), "wb");
        ASSERT_NE(file, nullptr) << "gzopen failed for " << name;
        std::unique_ptr<gzFile_s, Deleter<gzFile_s>> gzFile(file);
        entity->gzs.swap(gzFile);
        openOk++;
        entities.push_back(std::move(entity));
    }
    ASSERT_EQ(openOk.load(), GZ_STRESS_ENTITY_NUM);

    // close every gzFile but deliberately skip gzs.release(), leaving the exact
    // leftover state of the exporter close-failure path (gzclose succeeded, gzs still
    // holds the now-freed pointer)
    std::atomic<int32_t> closeOk(0);
    for (auto &entity : entities) {
        int32_t ret = gzclose(entity->gzs.get());
        if (ret == Z_OK) {
            closeOk++;
        }
    }
    EXPECT_EQ(closeOk.load(), GZ_STRESS_ENTITY_NUM);

    // batch destruct all GZipEntity, simulating the taskpool GC finalizer
    // (ArkFinalizersPack::ProcessAll -> unique_ptr reset) on the piled-up objects.
    // With no-op Deleter, this is safe; with gzclose-calling Deleter, this would crash.
    entities.clear();

    // zlib state must remain healthy after the batch destruction
    std::string fresh = GZ_STRESS_PATH + "stress_gc_fresh.gz";
    gzFile file = gzopen(fresh.c_str(), "wb");
    ASSERT_NE(file, nullptr);
    EXPECT_EQ(gzclose(file), Z_OK);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_GZipEntity_GcDtorStress_0002
 * @tc.name: GZipEntity_GcDtorStress_0002
 * @tc.desc: Regression test for concurrent GZipEntity destruction safety.
 *           Simulates async NAPI workers performing gzwrite/gzclose while
 *           GC finalizer threads concurrently destruct entities. Workers
 *           close the gzFile but skip gzs.release() (exporter close-failure
 *           leftover state) and hand entities to a finished queue; GC threads
 *           destruct finished entities (stale gzs) and pool entities (live gzFile).
 *
 *           Prerequisite: Deleter<gzFile_s> must be a no-op (HEAD behavior).
 *           All counters must hold exactly: every entity is either closed by
 *           a worker, destructed from the pool, or failed during gzwrite.
 *           All writes must complete, and zlib state must remain healthy.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_GZipEntity_GcDtorStress_0002, Function | MediumTest | Level1)
{
    FilePath::CreateDirectory(FilePath(GZ_STRESS_PATH));
    std::mutex poolMutex;
    std::vector<std::unique_ptr<GZipEntity>> pool;
    std::vector<char> chunk(GZ_STRESS_CHUNK_SIZE, 'b');
    for (int32_t i = 0; i < GZ_STRESS_ENTITY_NUM; ++i) {
        auto entity = std::make_unique<GZipEntity>();
        std::string name = GZ_STRESS_PATH + "stress_gc_pool_" + std::to_string(i) + ".gz";
        gzFile file = gzopen(name.c_str(), "wb");
        ASSERT_NE(file, nullptr) << "gzopen failed for " << name;
        std::unique_ptr<gzFile_s, Deleter<gzFile_s>> gzFile(file);
        entity->gzs.swap(gzFile);
        pool.push_back(std::move(entity));
    }

    // finished queue: entities already gzclose-d WITHOUT gzs.release() - each gzs is a
    // stale pointer, the exporter close-failure leftover state handed to GC finalizers
    std::mutex finishedMutex;
    std::vector<std::unique_ptr<GZipEntity>> finished;
    std::atomic<int32_t> closedByWorker(0);
    std::atomic<int32_t> writeOk(0);
    std::atomic<int32_t> writeFailed(0);
    std::atomic<int32_t> destructedFromPool(0);
    std::atomic<int32_t> destructedFromFinished(0);
    std::atomic<bool> workersDone(false);
    // GC threads: prefer destructing finished (stale) entities, otherwise destruct live
    // pool entities; exit only when workers are done and both sources are drained
    auto gcThread = [&poolMutex, &pool, &finishedMutex, &finished, &workersDone,
                     &destructedFromPool, &destructedFromFinished]() {
        while (true) {
            std::unique_ptr<GZipEntity> entity;
            bool fromFinished = false;
            {
                std::lock_guard<std::mutex> lock(finishedMutex);
                if (!finished.empty()) {
                    entity = std::move(finished.back());
                    finished.pop_back();
                    fromFinished = true;
                }
            }
            if (!entity) {
                std::lock_guard<std::mutex> lock(poolMutex);
                if (!pool.empty()) {
                    entity = std::move(pool.back());
                    pool.pop_back();
                }
            }
            if (!entity) {
                if (workersDone.load()) {
                    // re-check both sources under lock, then exit when fully drained
                    std::lock_guard<std::mutex> lock(finishedMutex);
                    if (!finished.empty()) {
                        continue;
                    }
                } else {
                    std::this_thread::yield();
                    continue;
                }
                std::lock_guard<std::mutex> lock(poolMutex);
                if (!pool.empty()) {
                    continue;
                }
                return;
            }
            if (fromFinished) {
                destructedFromFinished++;
                // finished-queue entity: destruct directly WITHOUT closing/releasing.
                // With no-op Deleter this is safe; with gzclose-calling Deleter it would crash.
            } else {
                destructedFromPool++;
                // pool entity holds a LIVE gzFile: close it properly and give the fd
                // back before destruction, so the case never leaks fds no matter how
                // the worker/GC race distributes entities (RLIMIT_NOFILE stability on
                // low-fd devices). After gzs.release() the pointer is null, so Deleter
                // firing during entity.reset() is safe in both phases
                gzclose(entity->gzs.get());
                entity->gzs.release();
            }
            entity.reset();
        }
    };
    // worker threads: async-NAPI-worker simulation - multi-round gzwrite then gzclose,
    // deliberately WITHOUT gzs.release(), then hand the entity to the finished queue
    auto workerThread = [&poolMutex, &pool, &chunk, &finishedMutex, &finished,
                         &closedByWorker, &writeOk, &writeFailed]() {
        while (true) {
            std::unique_ptr<GZipEntity> entity;
            {
                std::lock_guard<std::mutex> lock(poolMutex);
                if (pool.empty()) {
                    return;
                }
                entity = std::move(pool.back());
                pool.pop_back();
            }
            // multiple gzwrite rounds widen the race window with GC destructors
            bool allRoundsOk = true;
            for (int32_t round = 0; round < GZ_STRESS_WRITE_ROUNDS; ++round) {
                int32_t written = gzwrite(entity->gzs.get(), chunk.data(),
                    static_cast<uint32_t>(chunk.size()));
                if (written == static_cast<int32_t>(chunk.size())) {
                    writeOk++;
                } else {
                    allRoundsOk = false;
                }
            }
            if (!allRoundsOk) {
                gzclose(entity->gzs.get());
                entity->gzs.release();
                writeFailed++;
                return;
            }
            if (gzclose(entity->gzs.get()) == Z_OK) {
                closedByWorker++;
            }
            {
                std::lock_guard<std::mutex> lock(finishedMutex);
                finished.push_back(std::move(entity));
            }
        }
    };

    std::vector<std::thread> workerThreads;
    for (int32_t w = 0; w < GZ_STRESS_WORKER_NUM; ++w) {
        workerThreads.emplace_back(workerThread);
    }
    std::vector<std::thread> gcThreads;
    for (int32_t g = 0; g < GZ_STRESS_GC_THREAD_NUM; ++g) {
        gcThreads.emplace_back(gcThread);
    }
    for (auto &t : workerThreads) {
        t.join();
    }
    workersDone = true;
    for (auto &t : gcThreads) {
        t.join();
    }
    // pass path counters (deterministic with no-op Deleter):
    // every entity is either closed by a worker (then destructed from finished queue),
    // destructed directly from the pool, or failed during gzwrite (closed and released
    // by the worker before returning)
    EXPECT_EQ(closedByWorker.load() + destructedFromPool.load() + writeFailed.load(), GZ_STRESS_ENTITY_NUM);
    // GC threads drain the finished queue completely after workers finish
    EXPECT_EQ(destructedFromFinished.load(), closedByWorker.load());
    // every worker-closed entity must have completed all its gzwrite rounds
    EXPECT_EQ(writeOk.load(), closedByWorker.load() * GZ_STRESS_WRITE_ROUNDS);
    // gz files written by workers must be valid gzip streams
    std::string first = GZ_STRESS_PATH + "stress_gc_pool_0.gz";
    gzFile file = gzopen(first.c_str(), "rb");
    ASSERT_NE(file, nullptr);
    EXPECT_EQ(gzclose(file), Z_OK);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_GZipEntity_GcDtorStress_0003
 * @tc.name: GZipEntity_GcDtorStress_0003
 * @tc.desc: Regression test for concurrent GZipEntity destruction safety (read side).
 *           Simulates async NAPI workers performing gzread/gzclose while GC finalizer
 *           threads concurrently destruct entities. Workers read to EOF, close the gzFile
 *           without gzs.release() (exporter close-failure leftover state), and hand
 *           entities to a finished queue; GC threads destruct finished entities (stale
 *           read-side gzs) and pool entities (live read-side gzFile).
 *
 *           Prerequisite: Deleter<gzFile_s> must be a no-op (HEAD behavior).
 *           All counters must hold exactly, decompressed content must stay intact,
 *           and zlib state must remain healthy after the stress round.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_GZipEntity_GcDtorStress_0003, Function | MediumTest | Level1)
{
    FilePath::CreateDirectory(FilePath(GZ_STRESS_PATH));
    // prepare a source gzip stream containing known payload
    const std::string payload = "gzip gc destructor stress payload line";
    std::string gzPath = GZ_STRESS_PATH + "stress_gc_read.gz";
    {
        gzFile file = gzopen(gzPath.c_str(), "wb");
        ASSERT_NE(file, nullptr);
        for (int32_t i = 0; i < GZ_STRESS_WRITE_ROUNDS; ++i) {
            int32_t written = gzwrite(file, payload.data(), static_cast<uint32_t>(payload.size()));
            ASSERT_EQ(written, static_cast<int32_t>(payload.size()));
        }
        ASSERT_EQ(gzclose(file), Z_OK);
    }
    const std::string expected = [payload]() {
        std::string all;
        for (int32_t i = 0; i < GZ_STRESS_WRITE_ROUNDS; ++i) {
            all += payload;
        }
        return all;
    }();

    std::mutex poolMutex;
    std::vector<std::unique_ptr<GZipEntity>> pool;
    for (int32_t i = 0; i < GZ_STRESS_ENTITY_NUM; ++i) {
        auto entity = std::make_unique<GZipEntity>();
        gzFile file = gzopen(gzPath.c_str(), "rb");
        ASSERT_NE(file, nullptr) << "gzopen failed for round " << i;
        std::unique_ptr<gzFile_s, Deleter<gzFile_s>> gzFile(file);
        entity->gzs.swap(gzFile);
        pool.push_back(std::move(entity));
    }

    // finished queue: read-side entities already gzclose-d WITHOUT gzs.release()
    std::mutex finishedMutex;
    std::vector<std::unique_ptr<GZipEntity>> finished;
    std::atomic<int32_t> readDone(0);
    std::atomic<int32_t> contentOk(1);
    std::atomic<int32_t> destructedFromPool(0);
    std::atomic<int32_t> destructedFromFinished(0);
    std::atomic<bool> workersDone(false);
    // GC threads: prefer destructing finished (stale) entities, otherwise destruct live
    // pool entities; exit only when workers are done and both sources are drained
    auto gcThread = [&poolMutex, &pool, &finishedMutex, &finished, &workersDone,
                     &destructedFromPool, &destructedFromFinished]() {
        while (true) {
            std::unique_ptr<GZipEntity> entity;
            bool fromFinished = false;
            {
                std::lock_guard<std::mutex> lock(finishedMutex);
                if (!finished.empty()) {
                    entity = std::move(finished.back());
                    finished.pop_back();
                    fromFinished = true;
                }
            }
            if (!entity) {
                std::lock_guard<std::mutex> lock(poolMutex);
                if (!pool.empty()) {
                    entity = std::move(pool.back());
                    pool.pop_back();
                }
            }
            if (!entity) {
                if (workersDone.load()) {
                    // re-check both sources under lock, then exit when fully drained
                    std::lock_guard<std::mutex> lock(finishedMutex);
                    if (!finished.empty()) {
                        continue;
                    }
                } else {
                    std::this_thread::yield();
                    continue;
                }
                std::lock_guard<std::mutex> lock(poolMutex);
                if (!pool.empty()) {
                    continue;
                }
                return;
            }
            if (fromFinished) {
                destructedFromFinished++;
                // finished-queue entity: destruct directly WITHOUT closing/releasing.
                // With no-op Deleter this is safe; with gzclose-calling Deleter it would crash.
            } else {
                destructedFromPool++;
                // pool entity holds a LIVE read-side gzFile: close it properly and give
                // the fd back before destruction, so the case never leaks fds no matter
                // how the worker/GC race distributes entities (RLIMIT_NOFILE stability
                // on low-fd devices). After gzs.release() the pointer is null, so
                // Deleter firing during entity.reset() is safe in both phases
                gzclose(entity->gzs.get());
                entity->gzs.release();
            }
            entity.reset();
        }
    };
    // worker threads: decompress to EOF, verify content, close WITHOUT gzs.release()
    // (exporter close-failure leftover state), then hand the entity to the finished queue
    auto workerThread = [&poolMutex, &pool, &finishedMutex, &finished, &expected,
                         &readDone, &contentOk]() {
        while (true) {
            std::unique_ptr<GZipEntity> entity;
            {
                std::lock_guard<std::mutex> lock(poolMutex);
                if (pool.empty()) {
                    return;
                }
                entity = std::move(pool.back());
                pool.pop_back();
            }
            std::string content;
            char buf[GZ_STRESS_CHUNK_SIZE];
            int32_t len = 0;
            while ((len = gzread(entity->gzs.get(), buf, sizeof(buf))) > 0) {
                content.append(buf, static_cast<size_t>(len));
            }
            if (content != expected) {
                contentOk = 0;
            }
            gzclose(entity->gzs.get());
            {
                std::lock_guard<std::mutex> lock(finishedMutex);
                finished.push_back(std::move(entity));
            }
            readDone++;
        }
    };

    std::vector<std::thread> workerThreads;
    for (int32_t w = 0; w < GZ_STRESS_WORKER_NUM; ++w) {
        workerThreads.emplace_back(workerThread);
    }
    std::vector<std::thread> gcThreads;
    for (int32_t g = 0; g < GZ_STRESS_GC_THREAD_NUM; ++g) {
        gcThreads.emplace_back(gcThread);
    }
    for (auto &t : workerThreads) {
        t.join();
    }
    workersDone = true;
    for (auto &t : gcThreads) {
        t.join();
    }
    // pass path counters (deterministic with no-op Deleter):
    // every entity is either fully read by a worker (then destructed from finished
    // queue) or destructed directly from the pool; content must be intact every time
    EXPECT_EQ(readDone.load() + destructedFromPool.load(), GZ_STRESS_ENTITY_NUM);
    EXPECT_EQ(destructedFromFinished.load(), readDone.load());
    EXPECT_EQ(contentOk.load(), 1);
    // source stream must still be consumable after the stress round
    gzFile file = gzopen(gzPath.c_str(), "rb");
    ASSERT_NE(file, nullptr);
    EXPECT_EQ(gzclose(file), Z_OK);
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_GZipEntity_GcDtorStress_0004
 * @tc.name: GZipEntity_GcDtorStress_0004
 * @tc.desc: Regression test for Deleter<gzFile_s> behavior with live gzFile pointers.
 *           Verifies that batch destruction of GZipEntity objects with still-live gzFile
 *           pointers (never explicitly closed) is safe. Simulates JS-side GZipEntity
 *           objects that skip close() and are reclaimed by the taskpool GC finalizer.
 *
 *           Prerequisite: Deleter<gzFile_s> must be a no-op (HEAD behavior).
 *           Small scale (50 entities) to stay well below RLIMIT_NOFILE. The fresh
 *           gzopen/gzclose health check at the end proves the fd budget is not exhausted.
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_GZipEntity_GcDtorStress_0004, Function | MediumTest | Level1)
{
    FilePath::CreateDirectory(FilePath(GZ_STRESS_PATH));
    // pile up live gzFile objects held by GZipEntity, then never gzclose and never
    // release: simulates JS objects that skip close() and are reclaimed by the GC
    std::vector<std::unique_ptr<GZipEntity>> entities;
    std::atomic<int32_t> openOk(0);
    for (int32_t i = 0; i < GZ_STRESS_SMALL_ENTITY_NUM; ++i) {
        auto entity = std::make_unique<GZipEntity>();
        std::string name = GZ_STRESS_PATH + "stress_gc_deleter_" + std::to_string(i) + ".gz";
        gzFile file = gzopen(name.c_str(), "wb");
        ASSERT_NE(file, nullptr) << "gzopen failed for " << name;
        std::unique_ptr<gzFile_s, Deleter<gzFile_s>> gzFile(file);
        entity->gzs.swap(gzFile);
        openOk++;
        entities.push_back(std::move(entity));
    }
    ASSERT_EQ(openOk.load(), GZ_STRESS_SMALL_ENTITY_NUM);

    // batch destruct all GZipEntity with every gzs still pointing at a LIVE gzFile:
    // simulates the taskpool GC finalizer (ArkFinalizersPack::ProcessAll -> unique_ptr
    // reset) reclaiming objects whose close() was never called.
    // With no-op Deleter, fds are leaked (~50, bounded, expected, see tc.desc).
    entities.clear();

    // zlib state must remain healthy after the batch destruction - also proves the fd
    // budget is not exhausted (leaked ~50 fds stay well under limits)
    std::string fresh = GZ_STRESS_PATH + "stress_gc_deleter_fresh.gz";
    gzFile file = gzopen(fresh.c_str(), "wb");
    ASSERT_NE(file, nullptr);
    EXPECT_EQ(gzclose(file), Z_OK);
}
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
