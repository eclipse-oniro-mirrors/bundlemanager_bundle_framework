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
#include "verify_util.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
    const std::string FILE_PATH = "/data/app/el2/base/a.abc";
    const std::string INVALID_PATH = "/data/service/el1/public/bms/bundle_manager_service/../../a.abc";
    const std::string INVALID_SUFFIX = "/data/app/el2/base/a.so";
    const std::string ABC_FILE = "a.abc";
    const std::string ERR_FILE_PATH = "data";
    const std::string BUNDLE_NAME = "com.ohos.launcher";
    const std::string EMPTY_STRING = "";
    const int32_t FD = 0;
    const int32_t USERID = 100;

    const std::string DATA_STORAGE = "/data/storage//testdir1/testdir2/test.abc";
    const std::string DATA_STORAGE_EL1_BUNDLE_ONE = "/data/storage/el1/bundle/testdir1/testdir2/test.abc";
    const std::string DATA_STORAGE_EL1_BUNDLE_TWO = "data/storage/el1/bundle/testdir1/testdir2/test.abc";
    const std::string DATA_STORAGE_EL1 = "/data/storage/el1/base/testdir1/testdir2/test.abc";
    const std::string DATA_STORAGE_EL1_I = "/data/storage/el1/database/testdir1/testdir2/test.abc";
    const std::string DATA_STORAGE_EL2 = "/data/storage/el2/base/testdir1/testdir2/test.abc";
    const std::string DATA_STORAGE_EL2_I = "/data/storage/el2/database/testdir1/testdir2/test.abc";
    const std::string DATA_STORAGE_EL3 = "/data/storage/el3/base/testdir1/testdir2/test.abc";
    const std::string DATA_STORAGE_EL3_I = "/data/storage/el3/database/testdir1/testdir2/test.abc";
    const std::string DATA_STORAGE_EL4 = "/data/storage/el4/base/testdir1/testdir2/test.abc";
    const std::string DATA_STORAGE_EL4_I = "/data/storage/el4/database/testdir1/testdir2/test.abc";
    const std::string REAL_DATA_STORAGE_BUNDLE_EL1 =
        "/data/app/el1/bundle/public/com.ohos.launcher/testdir1/testdir2/test.abc";
    const std::string REAL_DATA_STORAGE_EL1 =
        "/data/app/el1/100/base/com.ohos.launcher/testdir1/testdir2/test.abc";
    const std::string REAL_DATA_STORAGE_EL1_I =
        "/data/app/el1/100/database/com.ohos.launcher/testdir1/testdir2/test.abc";
    const std::string REAL_DATA_STORAGE_EL2 =
        "/data/app/el2/100/base/com.ohos.launcher/testdir1/testdir2/test.abc";
    const std::string REAL_DATA_STORAGE_EL2_I =
        "/data/app/el2/100/database/com.ohos.launcher/testdir1/testdir2/test.abc";
    const std::string REAL_DATA_STORAGE_EL3 =
        "/data/app/el3/100/base/com.ohos.launcher/testdir1/testdir2/test.abc";
    const std::string REAL_DATA_STORAGE_EL3_I =
        "/data/app/el3/100/database/com.ohos.launcher/testdir1/testdir2/test.abc";
    const std::string REAL_DATA_STORAGE_EL4 =
        "/data/app/el4/100/base/com.ohos.launcher/testdir1/testdir2/test.abc";
    const std::string REAL_DATA_STORAGE_EL4_I =
        "/data/app/el4/100/database/com.ohos.launcher/testdir1/testdir2/test.abc";
}  // namespace

class BmsBundleVerifyManagerTest : public testing::Test {
public:
    BmsBundleVerifyManagerTest();
    ~BmsBundleVerifyManagerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void SetBundleDataMgr();

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

void BmsBundleVerifyManagerTest::SetBundleDataMgr()
{
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<AppExecFwk::BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
}

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
    SetBundleDataMgr();
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
    ret = impl.MoveAbc(BUNDLE_NAME, abcNames);
    EXPECT_FALSE(ret);

    ret = impl.MoveAbc(BUNDLE_NAME, abcPaths);
    EXPECT_FALSE(ret);

    abcPaths.clear();
    abcPaths.push_back(ERR_FILE_PATH);
    ret = impl.MoveAbc(BUNDLE_NAME, abcPaths);
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

    auto ret1 = impl.InnerVerify(BUNDLE_NAME, abcPaths);
    EXPECT_EQ(ret1, ERR_BUNDLE_MANAGER_VERIFY_VERIFY_ABC_FAILED);
}

/**
 * @tc.number: DeleteAbc
 * @tc.name: test DeleteAbc
 * @tc.desc: 1.DeleteAbc test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_0500, Function | SmallTest | Level1)
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
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_0600, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    abcPaths.push_back(INVALID_PATH);
    auto ret1 = impl.Verify(abcPaths);
    EXPECT_EQ(ret1, ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR);
}

/**
 * @tc.number: InnerVerify
 * @tc.name: test InnerVerify
 * @tc.desc: 1.InnerVerify test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_0700, Function | SmallTest | Level2)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    abcPaths.push_back(INVALID_SUFFIX);
    auto ret1 = impl.Verify(abcPaths);
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
    abcPaths.push_back(INVALID_SUFFIX);
    auto ret1 = impl.Verify(abcPaths);
    EXPECT_EQ(ret1, ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR);
}

/**
 * @tc.number: CheckFileParam
 * @tc.name: test CheckFileParam
 * @tc.desc: 1.CheckFileParam test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_0900, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::vector<std::string> abcPaths;
    auto ret1 = impl.CheckFileParam(abcPaths);
    EXPECT_FALSE(ret1);

    abcPaths.push_back(FILE_PATH);
    ret1 = impl.CheckFileParam(abcPaths);
    EXPECT_TRUE(ret1);

    abcPaths.push_back(INVALID_SUFFIX);
    ret1 = impl.CheckFileParam(abcPaths);
    EXPECT_FALSE(ret1);

    abcPaths.clear();
    abcPaths.push_back(INVALID_PATH);
    ret1 = impl.CheckFileParam(abcPaths);
    EXPECT_FALSE(ret1);
}

/**
 * @tc.number: GetRealPath
 * @tc.name: test GetRealPath
 * @tc.desc: 1.GetRealPath test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_1000, Function | SmallTest | Level2)
{
    VerifyManagerHostImpl impl;
    auto ret1 = impl.GetRealPath(BUNDLE_NAME, USERID, DATA_STORAGE_EL1_BUNDLE_ONE);
    EXPECT_EQ(ret1, REAL_DATA_STORAGE_BUNDLE_EL1);

    ret1 = impl.GetRealPath(BUNDLE_NAME, USERID, DATA_STORAGE_EL1_BUNDLE_TWO);
    EXPECT_EQ(ret1, REAL_DATA_STORAGE_BUNDLE_EL1);

    ret1 = impl.GetRealPath(BUNDLE_NAME, USERID, DATA_STORAGE_EL1);
    EXPECT_EQ(ret1, REAL_DATA_STORAGE_EL1);

    ret1 = impl.GetRealPath(BUNDLE_NAME, USERID, DATA_STORAGE_EL1_I);
    EXPECT_EQ(ret1, REAL_DATA_STORAGE_EL1_I);

    ret1 = impl.GetRealPath(BUNDLE_NAME, USERID, DATA_STORAGE_EL2);
    EXPECT_EQ(ret1, REAL_DATA_STORAGE_EL2);

    ret1 = impl.GetRealPath(BUNDLE_NAME, USERID, DATA_STORAGE_EL2_I);
    EXPECT_EQ(ret1, REAL_DATA_STORAGE_EL2_I);

    ret1 = impl.GetRealPath(BUNDLE_NAME, USERID, DATA_STORAGE_EL3);
    EXPECT_EQ(ret1, REAL_DATA_STORAGE_EL3);

    ret1 = impl.GetRealPath(BUNDLE_NAME, USERID, DATA_STORAGE_EL3_I);
    EXPECT_EQ(ret1, REAL_DATA_STORAGE_EL3_I);

    ret1 = impl.GetRealPath(BUNDLE_NAME, USERID, DATA_STORAGE_EL4);
    EXPECT_EQ(ret1, REAL_DATA_STORAGE_EL4);

    ret1 = impl.GetRealPath(BUNDLE_NAME, USERID, DATA_STORAGE_EL4_I);
    EXPECT_EQ(ret1, REAL_DATA_STORAGE_EL4_I);
}

/**
 * @tc.number: GetRealPath
 * @tc.name: test GetRealPath
 * @tc.desc: 1.GetRealPath test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_1100, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    auto ret1 = impl.GetRealPath(BUNDLE_NAME, USERID, DATA_STORAGE);
    EXPECT_TRUE(ret1.empty());
}

/**
 * @tc.number: GetRealPath
 * @tc.name: test GetRealPath
 * @tc.desc: 1.GetRealPath test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_1200, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    std::string bundleName;
    auto ret = impl.GetCallingBundleName(bundleName);
    EXPECT_FALSE(ret);

    int32_t userId = USERID;
    std::vector<std::string> abcPaths;
    abcPaths.push_back(DATA_STORAGE);
    auto ret1 = impl.CopyFilesToTempDir(BUNDLE_NAME, userId, abcPaths);
    EXPECT_FALSE(ret1);
}

/**
 * @tc.number: GetBundleMutex
 * @tc.name: test GetBundleMutex
 * @tc.desc: 1.GetBundleMutex test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_1300, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;

    std::string rootDir = "/data";
    std::vector<std::string> names;
    names.push_back("testname");
    
    impl.Rollback(rootDir, names);

    std::string bundleName = "com.test.bundleName";
    impl.RemoveTempFiles(bundleName);

    bool ret = impl.VerifyAbc(rootDir, names);

    EXPECT_FALSE(ret);
}

/**
 * @tc.number: VerifyAbc
 * @tc.name: test VerifyAbc
 * @tc.desc: 1.VerifyAbc test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_1400, Function | SmallTest | Level1)
{
    std::string abcPath = "/data/abc.path";
    bool ret = VerifyUtil::VerifyAbc(abcPath);

    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetBundleMutex
 * @tc.name: test GetBundleMutex
 * @tc.desc: 1.GetBundleMutex test
 */
HWTEST_F(BmsBundleVerifyManagerTest, VerifyManagerTest_1500, Function | SmallTest | Level1)
{
    VerifyManagerHostImpl impl;
    auto &mtx = impl.GetBundleMutex(BUNDLE_NAME);
    EXPECT_EQ(&mtx, &impl.bundleMutexMap_[BUNDLE_NAME]);
}
} // OHOS