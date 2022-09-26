/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <chrono>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bundle_info.h"
#include "rpcid_decode/syscap_tool.h"
#include "bundle_data_storage_database.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "install_param.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "system_bundle_installer.h"
#include "want.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using namespace OHOS::DistributedKv;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
}  // namespace

class BmsSyscapToolTest : public testing::Test {
public:
    BmsSyscapToolTest();
    ~BmsSyscapToolTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsSyscapToolTest::BmsSyscapToolTest()
{}

BmsSyscapToolTest::~BmsSyscapToolTest()
{}

void BmsSyscapToolTest::SetUpTestCase()
{}

void BmsSyscapToolTest::TearDownTestCase()
{}

void BmsSyscapToolTest::SetUp()
{}

void BmsSyscapToolTest::TearDown()
{}

/**
 * @tc.number: RPCIDFileDecodeToBuffer_0100
 * @tc.name: test the file decode to buffer
 * @tc.desc: RPCIDFileDecodeToBuffer
 */
HWTEST_F(BmsSyscapToolTest, RPCIDFileDecodeToBuffer_0100, Function | SmallTest | Level0)
{
    char *inputFile = nullptr;
    char *syscapSetBuf;
    uint32_t syscapSetLength = 0;
    int32_t ret = RPCIDFileDecodeToBuffer(inputFile, &syscapSetBuf, &syscapSetLength);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.number: RPCIDFileDecodeToBuffer_0200
 * @tc.name: test the file decode to buffer
 * @tc.desc: RPCIDFileDecodeToBuffer
 */
HWTEST_F(BmsSyscapToolTest, RPCIDFileDecodeToBuffer_0200, Function | SmallTest | Level0)
{
    string file = "";
    int len = file.length();
    char inputFile[len + 1];
    strcpy_s(inputFile, len + 1, file.c_str());
    char *syscapSetBuf = inputFile;
    uint32_t syscapSetLength = 0;
    int32_t ret = RPCIDFileDecodeToBuffer(inputFile, &syscapSetBuf, &syscapSetLength);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.number: RPCIDFileDecodeToBuffer_0300
 * @tc.name: test the file decode to buffer
 * @tc.desc: RPCIDFileDecodeToBuffer
 */
HWTEST_F(BmsSyscapToolTest, RPCIDFileDecodeToBuffer_0300, Function | SmallTest | Level0)
{
    string file = "BmsSyscapToolTest";
    int len = file.length();
    char inputFile[len + 1];
    strcpy_s(inputFile, len + 1, file.c_str());
    char *syscapSetBuf = inputFile;
    uint32_t syscapSetLength = 0;
    int32_t ret = RPCIDFileDecodeToBuffer(inputFile, &syscapSetBuf, &syscapSetLength);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.number: RPCIDFileDecodeToBuffer_0400
 * @tc.name: test the file decode to buffer
 * @tc.desc: RPCIDFileDecodeToBuffer
 */
HWTEST_F(BmsSyscapToolTest, RPCIDFileDecodeToBuffer_0400, Function | SmallTest | Level0)
{
    string file = "/data/test";
    int len = file.length();
    char inputFile[len + 1];
    strcpy_s(inputFile, len + 1, file.c_str());
    char *syscapSetBuf = inputFile;
    uint32_t syscapSetLength = 0;
    int32_t ret = RPCIDFileDecodeToBuffer(inputFile, &syscapSetBuf, &syscapSetLength);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.number: RPCIDStreamDecodeToBuffer_0100
 * @tc.name: test the stream decode to buffer
 * @tc.desc: RPCIDStreamDecodeToBuffer
 */
HWTEST_F(BmsSyscapToolTest, RPCIDStreamDecodeToBuffer_0100, Function | SmallTest | Level0)
{
    char *contextBuffer = nullptr;
    char *syscapSetBuf;
    uint32_t syscapSetLength = 0;
    uint32_t bufferLen = 0;
    int32_t ret = RPCIDStreamDecodeToBuffer(contextBuffer, bufferLen, &syscapSetBuf, &syscapSetLength);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.number: RPCIDStreamDecodeToBuffer_0200
 * @tc.name: test the stream decode to buffer
 * @tc.desc: RPCIDStreamDecodeToBuffer
 */
HWTEST_F(BmsSyscapToolTest, RPCIDStreamDecodeToBuffer_0200, Function | SmallTest | Level0)
{
    string file = "apiVersionType = 1";
    int len = file.length();
    char inputFile[len + 1];
    strcpy_s(inputFile, len + 1, file.c_str());
    char *syscapSetBuf = inputFile;
    uint32_t syscapSetLength = 0;
    uint32_t bufferLen = 0;
    int32_t ret = RPCIDStreamDecodeToBuffer(inputFile, bufferLen, &syscapSetBuf, &syscapSetLength);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.number: RPCIDStreamDecodeToBuffer_0300
 * @tc.name: test the stream decode to buffer
 * @tc.desc: RPCIDStreamDecodeToBuffer
 */
HWTEST_F(BmsSyscapToolTest, RPCIDStreamDecodeToBuffer_0300, Function | SmallTest | Level0)
{
    string file = "apiVersionType = 1";
    int len = file.length();
    char inputFile[len + 1];
    strcpy_s(inputFile, len + 1, file.c_str());
    char *syscapSetBuf;
    uint32_t syscapSetLength = 0;
    uint32_t bufferLen = len + 2;
    int32_t ret = RPCIDStreamDecodeToBuffer(inputFile, bufferLen, &syscapSetBuf, &syscapSetLength);
    EXPECT_EQ(ret, -1);
}
} // OHOS
