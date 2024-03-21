/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <sstream>
#include <string>

#include "bundle_mgr_service.h"
#include "verify_manager_host_impl.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
    const std::string FILE_PATH = "/data/service/el1/public/bms/bundle_manager_service/a.abc";
    const std::string INVALID_PATH = "/data/service/el1/public/bms/bundle_manager_service/../../a.abc";
    const std::string INVALID_SUFFIX = "/data/service/el1/public/bms/bundle_manager_service/a.so";
    const std::string INVALID_PREFIX = "/data/app/el1/bundle/public/a.abc";
    const std::string ABC_FILE = "a.abc";
    const std::string ERR_FILE_PATH = "data";
    const std::string BUNDLE_NAME = "com.ohos.launcher";
    const std::string EMPTY_STRING = "";
    const int32_t FD = 0;
}  // namespace

class BmsBundleVerifyManagerTest : public testing::Test {
public:
    BmsBundleVerifyManagerTest();
    ~BmsBundleVerifyManagerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleVerifyManagerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleVerifyManagerTest::BmsBundleVerifyManagerTest()
{}

BmsBundleVerifyManagerTest::~BmsBundleVerifyManagerTest()
{}

void BmsBundleVerifyManagerTest::SetUpTestCase()
{}

void BmsBundleVerifyManagerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleVerifyManagerTest::SetUp()
{}

void BmsBundleVerifyManagerTest::TearDown()
{}

/**
 * @tc.number: VerifyAbc
 * @tc.name: test VerifyAbc
 * @tc.desc: 1.VerifyAbc test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_0100, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    abcPaths.push_back(FILE_PATH);
    abcPaths.push_back(ERR_FILE_PATH);
    abcPaths.push_back(EMPTY_STRING);
    
    auto ret = impl.VerifyAbc(abcPaths);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetFileDir
 * @tc.name: test GetFileDir
 * @tc.desc: 1.GetFileDir test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_0200, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;

    std::string fileName = BUNDLE_NAME;
    auto ret = impl.GetFileDir(ERR_FILE_PATH, fileName);
    EXPECT_FALSE(ret);

    ret = impl.GetFileDir(FILE_PATH, fileName);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: MoveAbc
 * @tc.name: test MoveAbc
 * @tc.desc: 1.MoveAbc test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_0300, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;

    std::string fileName = BUNDLE_NAME;
    std::vector<std::string> abcPaths;
    abcPaths.push_back(FILE_PATH);
    
    impl.Rollback(abcPaths);

    auto ret = impl.MkdirIfNotExist(FILE_PATH);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_GET_PROXY_ERROR);

    std::vector<std::string> abcNames;
    abcNames.push_back(BUNDLE_NAME);
    ret = impl.MoveAbc(abcPaths, abcNames, FILE_PATH);
    EXPECT_FALSE(ret);

    ret = impl.MoveAbc(abcPaths, abcPaths, FILE_PATH);
    EXPECT_FALSE(ret);

    abcPaths.clear();
    abcPaths.push_back(ERR_FILE_PATH);
    ret = impl.MoveAbc(abcPaths, abcPaths, BUNDLE_NAME);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InnerVerify
 * @tc.name: test InnerVerify
 * @tc.desc: 1.InnerVerify test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_0400, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    std::vector<std::string> abcNames;
    abcPaths.push_back(EMPTY_STRING);
    impl.RemoveTempFiles(abcPaths);
    abcPaths.clear();

    abcPaths.push_back(FILE_PATH);
    abcNames.push_back(FILE_PATH);
    impl.RemoveTempFiles(abcPaths);

    std::string fileName = BUNDLE_NAME;
    auto ret = impl.GetFileName(FILE_PATH, fileName);
    EXPECT_TRUE(ret);
    ret = impl.GetFileName(ERR_FILE_PATH, fileName);
    EXPECT_FALSE(ret);

    auto ret1 = impl.InnerVerify(abcPaths, abcNames, true);
    EXPECT_EQ(ret1, ERR_BUNDLE_MANAGER_VERIFY_VERIFY_ABC_FAILED);
}

/**
 * @tc.number: CreateFd
 * @tc.name: test CreateFd
 * @tc.desc: 1.CreateFd test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_0500, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    int32_t fd = FD;
    std::string path;
    auto ret = impl.CreateFd(BUNDLE_NAME, fd, path);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR);

    ret = impl.CreateFd("test..abc", fd, path);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR);

    std::string maxFileName = std::string(256, 'a');
    maxFileName.append(".abc");
    ret = impl.CreateFd(maxFileName, fd, path);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR);

    ret = impl.CreateFd("test.abc", fd, path);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: DeleteAbc
 * @tc.name: test DeleteAbc
 * @tc.desc: 1.DeleteAbc test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_0600, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    auto ret = impl.DeleteAbc(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DELETE_ABC_PARAM_ERROR);

    ret = impl.DeleteAbc("test..abc");
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DELETE_ABC_PARAM_ERROR);

    ret = impl.DeleteAbc("test.txt");
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DELETE_ABC_PARAM_ERROR);

    ret = impl.DeleteAbc("test.abc");
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_DELETE_ABC_FAILED);
}

/**
 * @tc.number: InnerVerify
 * @tc.name: test InnerVerify
 * @tc.desc: 1.InnerVerify test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_0700, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    std::vector<std::string> abcNames;
    abcPaths.push_back(INVALID_PATH);
    abcNames.push_back(INVALID_PATH);
    auto ret1 = impl.Verify(abcPaths, abcNames, true);
    EXPECT_EQ(ret1, ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR);
}

/**
 * @tc.number: InnerVerify
 * @tc.name: test InnerVerify
 * @tc.desc: 1.InnerVerify test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_0800, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    std::vector<std::string> abcNames;
    abcPaths.push_back(INVALID_SUFFIX);
    abcNames.push_back(INVALID_SUFFIX);
    auto ret1 = impl.Verify(abcPaths, abcNames, true);
    EXPECT_EQ(ret1, ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR);
}

/**
 * @tc.number: InnerVerify
 * @tc.name: test InnerVerify
 * @tc.desc: 1.InnerVerify test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_0900, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    std::vector<std::string> abcNames;
    abcPaths.push_back(INVALID_PREFIX);
    abcNames.push_back(INVALID_PREFIX);
    auto ret1 = impl.Verify(abcPaths, abcNames, true);
    EXPECT_EQ(ret1, ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR);
}

/**
 * @tc.number: CheckFileParam
 * @tc.name: test CheckFileParam
 * @tc.desc: 1.CheckFileParam test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_1000, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    std::vector<std::string> abcNames;
    auto ret1 = impl.CheckFileParam(abcPaths, abcNames);
    EXPECT_FALSE(ret1);
    abcPaths.push_back(INVALID_PREFIX);
    ret1 = impl.CheckFileParam(abcPaths, abcNames);
    EXPECT_FALSE(ret1);

    abcPaths.clear();
    abcNames.push_back(INVALID_PREFIX);
    ret1 = impl.CheckFileParam(abcPaths, abcNames);
    EXPECT_FALSE(ret1);

    abcPaths.push_back(INVALID_PREFIX);
    ret1 = impl.CheckFileParam(abcPaths, abcNames);
    EXPECT_FALSE(ret1);
}

/**
 * @tc.number: CheckFileParam
 * @tc.name: test CheckFileParam
 * @tc.desc: 1.CheckFileParam test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_1100, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    std::vector<std::string> abcNames;
    abcPaths.push_back(INVALID_PATH);
    abcNames.push_back(INVALID_PATH);
    auto ret1 = impl.CheckFileParam(abcPaths, abcNames);
    EXPECT_FALSE(ret1);

    abcPaths.clear();
    abcPaths.push_back(ERR_FILE_PATH);
    ret1 = impl.CheckFileParam(abcPaths, abcNames);
    EXPECT_FALSE(ret1);

    abcPaths.clear();
    abcPaths.push_back(INVALID_PREFIX);
    ret1 = impl.CheckFileParam(abcPaths, abcNames);
    EXPECT_FALSE(ret1);
}

/**
 * @tc.number: CheckFileParam
 * @tc.name: test CheckFileParam
 * @tc.desc: 1.CheckFileParam test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_1200, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    std::vector<std::string> abcNames;
    abcPaths.push_back(FILE_PATH);
    abcNames.push_back(INVALID_PATH);
    auto ret1 = impl.CheckFileParam(abcPaths, abcNames);
    EXPECT_FALSE(ret1);

    abcNames.clear();
    abcNames.push_back(ERR_FILE_PATH);
    ret1 = impl.CheckFileParam(abcPaths, abcNames);
    EXPECT_FALSE(ret1);

    abcNames.clear();
    abcNames.push_back(FILE_PATH);
    ret1 = impl.CheckFileParam(abcPaths, abcNames);
    EXPECT_TRUE(ret1);
}
} // OHOS