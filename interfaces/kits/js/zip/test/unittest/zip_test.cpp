/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include <memory>
#include <thread>

#include "zip.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
using namespace testing::ext;

namespace {
const std::string BASE_PATH = "/data/app/el2/100/base/";
const std::string APP_PATH = "com.example.zlib/com.example.zlib/com.example.zlib.MainAbility/files/";
const std::string TEST_ZIP_OK = "/data/test/resource/bms/test_zip/resourceManagerTest.hap";
const std::string TEST_ZIP_DMAGED = "/data/test/resource/bms/test_zip/ohos_test.xml";
}  // namespac
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
{}

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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
}

/**
 * @tc.number: APPEXECFWK_LIBZIP_GetOriginalSize_0100
 * @tc.name: GetOriginalSize_0100
 * @tc.desc:
 */
HWTEST_F(ZipTest, APPEXECFWK_LIBZIP_GetOriginalSize_0100, Function | MediumTest | Level2)
{
    std::string src = "";
    int64_t originalSize = 0;

    auto ret = GetOriginalSize(src, originalSize);
    EXPECT_EQ(ret, ERR_ZLIB_SRC_FILE_DISABLED);
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
}
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
