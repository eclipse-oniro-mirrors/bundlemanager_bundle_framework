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

#include <gtest/gtest.h>

#define private public
#include "bundle_service_constants.h"
#include "bundle_constants.h"
#include "directory_ex.h"
#include "install_exception_mgr.h"
#include "installd_client.h"
#include "nlohmann/json.hpp"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string BUNDLE_NAME = "com.example.myapplication";
const std::string OLD_BUNDLE_DIR_NAME = "/data/app/el1/bundle/public/+old-com.example.myapplication";
const std::string NEW_BUNDLE_DIR_NAME = "/data/app/el1/bundle/public/+new-com.example.myapplication";
const std::string REAL_BUNDLE_DIR_NAME = "/data/app/el1/bundle/public/com.example.myapplication";
}  // namespace

class BmsInstallExceptionMgrTest : public testing::Test {
public:
    BmsInstallExceptionMgrTest() {}
    ~BmsInstallExceptionMgrTest() {}
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsInstallExceptionMgrTest::SetUpTestCase()
{}

void BmsInstallExceptionMgrTest::TearDownTestCase()
{}

void BmsInstallExceptionMgrTest::SetUp()
{}

void BmsInstallExceptionMgrTest::TearDown()
{}

/**
 * @tc.number: installExceptionMgrTest_0001
 * @tc.name: installExceptionMgrTest
 * @tc.desc: test installExceptionMgrTest
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0001, TestSize.Level1)
{
    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::RENAME_NEW_TO_RELA_PATH;
    std::string str = info.ToString();
    EXPECT_FALSE(str.empty());

    InstallExceptionInfo newInfo;
    bool ret = newInfo.FromString(str);
    EXPECT_TRUE(ret);
    EXPECT_EQ(info.status, newInfo.status);
}

/**
 * @tc.number: installExceptionMgrTest_0002
 * @tc.name: installExceptionMgrTest
 * @tc.desc: test installExceptionMgrTest
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0002, TestSize.Level1)
{
    std::string str = "{";
    InstallExceptionInfo info;
    bool ret = info.FromString(str);
    EXPECT_FALSE(ret);
    str = "{}";
    ret = info.FromString(str);
    EXPECT_TRUE(ret);
    str = "{\"\":}";
    nlohmann::json exceptionJson = R"(
        {
            "installRenameExceptionStatus" : "string"
        }
    )"_json;

    std::string jsonBuff(exceptionJson.dump());
    ret = info.FromString(jsonBuff);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: installExceptionMgrTest_0003
 * @tc.name: installExceptionMgrTest
 * @tc.desc: test installExceptionMgrTest
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0003, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    mgr->installExceptionMgr_ = nullptr;
    (void)mgr->HandleAllBundleExceptionInfo();
    InstallExceptionInfo info;
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
    ret = mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: installExceptionMgrTest_0004
 * @tc.name: installExceptionMgrTest
 * @tc.desc: test installExceptionMgrTest
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0004, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    mgr->installExceptionMgr_ = std::make_shared<InstallExceptionMgrRdb>();
    mgr->installExceptionMgr_->rdbDataManager_ = nullptr;

    InstallExceptionInfo info;
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
    ret = mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: installExceptionMgrTest_0005
 * @tc.name: installExceptionMgrTest
 * @tc.desc: test installExceptionMgrTest
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0005, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    mgr->installExceptionMgr_ = std::make_shared<InstallExceptionMgrRdb>();

    InstallExceptionInfo info;
    ErrCode ret = mgr->SaveBundleExceptionInfo("", info);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
    ret = mgr->DeleteBundleExceptionInfo("");
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: installExceptionMgrTest_0006
 * @tc.name: installExceptionMgrTest
 * @tc.desc: test installExceptionMgrTest
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0006, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);

    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::RENAME_RELA_TO_OLD_PATH;
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    ret = mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: installExceptionMgrTest_0007
 * @tc.name: installExceptionMgrTest
 * @tc.desc: test installExceptionMgrTest
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0007, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);

    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::RENAME_RELA_TO_OLD_PATH;
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    std::map<std::string, InstallExceptionInfo> installExceptionInfos;
    mgr->installExceptionMgr_->GetAllBundleExceptionInfo(installExceptionInfos);
    EXPECT_FALSE(installExceptionInfos.empty());
    EXPECT_EQ(info.status, installExceptionInfos[BUNDLE_NAME].status);
    ret = mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: installExceptionMgrTest_0008
 * @tc.name: installExceptionMgrTest
 * @tc.desc: test installExceptionMgrTest
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0008, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);

    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::UNKOWN_STATUS;
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);

    info.status = InstallRenameExceptionStatus::RENAME_RELA_TO_OLD_PATH;
    ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);

    bool ans = OHOS::ForceCreateDirectory(OLD_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    ans = OHOS::ForceCreateDirectory(NEW_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    mgr->HandleAllBundleExceptionInfo();
    (void)OHOS::ForceRemoveDirectory(REAL_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(NEW_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(OLD_BUNDLE_DIR_NAME);

    info.status = InstallRenameExceptionStatus::DELETE_OLD_PATH;
    ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    ans = OHOS::ForceCreateDirectory(OLD_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    mgr->HandleAllBundleExceptionInfo();
    (void)OHOS::ForceRemoveDirectory(OLD_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(NEW_BUNDLE_DIR_NAME);

    ret = mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}
} //AppExecFwk
} // OHOS
