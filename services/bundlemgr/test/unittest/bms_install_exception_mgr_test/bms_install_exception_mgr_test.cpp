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
#include "bundle_constants.h"
#include "bundle_mgr_service.h"
#include "bundle_service_constants.h"
#include "directory_ex.h"
#include "install_exception_mgr.h"
#include "installd/installd_service.h"
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
const std::string TEMP_BUNDLE_DIR_NAME = "/data/app/el1/bundle/public/+temp-com.example.myapplication";
const std::string OLD_BUNDLE_DIR_NAME_EMPTY = "/data/app/el1/bundle/public/+old-";
const int32_t USERID = 100;
const int32_t WAIT_TIME = 2; // init mocked bms
}  // namespace

class BmsInstallExceptionMgrTest : public testing::Test {
public:
    BmsInstallExceptionMgrTest() {}
    ~BmsInstallExceptionMgrTest() {}
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsInstallExceptionMgrTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsInstallExceptionMgrTest::installdService_ =
    std::make_shared<InstalldService>();

void BmsInstallExceptionMgrTest::SetUpTestCase()
{}

void BmsInstallExceptionMgrTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
}

void BmsInstallExceptionMgrTest::SetUp()
{
    installdService_->Start();
    if (!DelayedSingleton<BundleMgrService>::GetInstance()->IsServiceReady()) {
        DelayedSingleton<BundleMgrService>::GetInstance()->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsInstallExceptionMgrTest::TearDown()
{}

const std::shared_ptr<BundleDataMgr> BmsInstallExceptionMgrTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: installExceptionMgrTest_0001
 * @tc.name: installExceptionMgrTest
 * @tc.desc: test installExceptionMgrTest
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0001, TestSize.Level1)
{
    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::RENAME_NEW_TO_REAL_PATH;
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
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);

    info.status = InstallRenameExceptionStatus::RENAME_RELA_TO_OLD_PATH;
    ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);

    bool ans = OHOS::ForceCreateDirectory(OLD_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    ans = OHOS::ForceCreateDirectory(NEW_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    ans = OHOS::ForceCreateDirectory(TEMP_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    mgr->HandleAllBundleExceptionInfo();
    (void)OHOS::ForceRemoveDirectory(REAL_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(NEW_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(OLD_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(TEMP_BUNDLE_DIR_NAME);

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

/**
 * @tc.number: installExceptionMgrTest_0009
 * @tc.name: installExceptionMgrTest
 * @tc.desc: test installExceptionMgrTest
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0009, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    InstallExceptionInfo info;
    auto ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    bool ans = OHOS::ForceCreateDirectory(OLD_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    ans = OHOS::ForceCreateDirectory(OLD_BUNDLE_DIR_NAME_EMPTY);
    EXPECT_TRUE(ans);
    mgr->HandleAllBundleExceptionInfo();
    auto exist = access(OLD_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_EQ(exist, 0);
    exist = access(OLD_BUNDLE_DIR_NAME_EMPTY.c_str(), F_OK);
    EXPECT_EQ(exist, 0);
    ret = mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);

    (void)OHOS::ForceRemoveDirectory(OLD_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(OLD_BUNDLE_DIR_NAME_EMPTY);
}

/**
 * @tc.number: installExceptionMgrTest_0010
 * @tc.name: installExceptionMgrTest
 * @tc.desc: test installExceptionMgrTest
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0010, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    bool ans = OHOS::ForceCreateDirectory(OLD_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    mgr->HandleAllBundleExceptionInfo();
    auto exist = access(OLD_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_EQ(exist, 0);
    (void)OHOS::ForceRemoveDirectory(OLD_BUNDLE_DIR_NAME);
}

/**
 * @tc.number: installExceptionMgrTest_0011
 * @tc.name: installExceptionMgrTest
 * @tc.desc: test installExceptionMgrTest
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0011, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    InstallExceptionInfo info;
    auto ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    bool ans = OHOS::ForceCreateDirectory(OLD_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    mgr->HandleAllBundleExceptionInfo();
    auto exist = access(OLD_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_EQ(exist, 0);
    (void)OHOS::ForceRemoveDirectory(OLD_BUNDLE_DIR_NAME);
    ret = mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: installExceptionMgrTest_0012
 * @tc.name: test HandleBundleExceptionInfo with null installExceptionMgr_
 * @tc.desc: test HandleBundleExceptionInfo when installExceptionMgr_ is null
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0012, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    mgr->installExceptionMgr_ = nullptr;
    bool result = mgr->HandleBundleExceptionInfo(BUNDLE_NAME);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: installExceptionMgrTest_0013
 * @tc.name: test HandleBundleExceptionInfo with empty bundleName
 * @tc.desc: test HandleBundleExceptionInfo when bundleName is empty
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0013, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    mgr->installExceptionMgr_ = std::make_shared<InstallExceptionMgrRdb>();
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    bool result = mgr->HandleBundleExceptionInfo("");
    EXPECT_FALSE(result);
}

/**
 * @tc.number: installExceptionMgrTest_0014
 * @tc.name: test HandleBundleExceptionInfo when bundle not exist
 * @tc.desc: test HandleBundleExceptionInfo when GetBundleExceptionInfo returns false
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0014, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    bool result = mgr->HandleBundleExceptionInfo("com.example.nonexistent");
    EXPECT_FALSE(result);
}

/**
 * @tc.number: installExceptionMgrTest_0015
 * @tc.name: test HandleBundleExceptionInfo with valid bundle
 * @tc.desc: test HandleBundleExceptionInfo when bundle exists
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0015, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::CREATE_NEW_DIR;
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    bool result = mgr->HandleBundleExceptionInfo(BUNDLE_NAME);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: installExceptionMgrTest_0016
 * @tc.name: test InnerProcessCreateNewDir with RemoveDir failure
 * @tc.desc: test InnerProcessCreateNewDir when RemoveDir fails
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0016, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::CREATE_NEW_DIR;
    bool ans = OHOS::ForceCreateDirectory(NEW_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    mgr->HandleBundleExceptionInfo(BUNDLE_NAME);
    auto exist = access(NEW_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_NE(exist, 0);
}

/**
 * @tc.number: installExceptionMgrTest_0017
 * @tc.name: test InnerProcessRealToOldPath with RemoveDir failure
 * @tc.desc: test InnerProcessRealToOldPath when RemoveDir fails
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0017, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::RENAME_RELA_TO_OLD_PATH;
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    bool ans = OHOS::ForceCreateDirectory(OLD_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    mgr->HandleBundleExceptionInfo(BUNDLE_NAME);
    auto exist = access(OLD_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_NE(exist, 0);
    exist = access(REAL_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_EQ(exist, 0);
    (void)OHOS::ForceRemoveDirectory(REAL_BUNDLE_DIR_NAME);
}

/**
 * @tc.number: installExceptionMgrTest_0018
 * @tc.name: test InnerProcessRealToOldPath with RenameModuleDir failure
 * @tc.desc: test InnerProcessRealToOldPath when RenameModuleDir fails
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0018, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::RENAME_RELA_TO_OLD_PATH;
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    bool ans = OHOS::ForceCreateDirectory(NEW_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    mgr->HandleBundleExceptionInfo(BUNDLE_NAME);
    auto exist = access(REAL_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_NE(exist, 0);
    exist = access(NEW_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_NE(exist, 0);
    (void)OHOS::ForceRemoveDirectory(NEW_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(REAL_BUNDLE_DIR_NAME);
}

/**
 * @tc.number: installExceptionMgrTest_0019
 * @tc.name: test InnerProcessNewToRealPath with not same versionCode and RenameModuleDir success
 * @tc.desc: test InnerProcessNewToRealPath when versionCode matches and rename succeeds
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0019, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::RENAME_NEW_TO_REAL_PATH;
    info.versionCode = 1001;
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    bool ans = OHOS::ForceCreateDirectory(OLD_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    ans = OHOS::ForceCreateDirectory(NEW_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    mgr->HandleBundleExceptionInfo(BUNDLE_NAME);
    auto exist = access(OLD_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_NE(exist, 0);
    exist = access(REAL_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_NE(exist, 0);
    exist = access(NEW_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_EQ(exist, 0);
    (void)OHOS::ForceRemoveDirectory(OLD_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(NEW_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(REAL_BUNDLE_DIR_NAME);
}

/**
 * @tc.number: installExceptionMgrTest_0020
 * @tc.name: test InnerProcessNewToRealPath with same versionCode and RenameModuleDir failure
 * @tc.desc: test InnerProcessNewToRealPath when versionCode matches but rename fails
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0020, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::RENAME_NEW_TO_REAL_PATH;
    info.versionCode = 1001;
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseBundleInfo_->versionCode = 1001;
    innerBundleInfo.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    dataMgr->bundleInfos_[BUNDLE_NAME] = innerBundleInfo;
    bool ans = OHOS::ForceCreateDirectory(NEW_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    ans = OHOS::ForceCreateDirectory(OLD_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    mgr->HandleBundleExceptionInfo(BUNDLE_NAME);
    auto exist = access(NEW_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_NE(exist, 0);
    exist = access(OLD_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_NE(exist, 0);
    exist = access(REAL_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_EQ(exist, 0);
    (void)OHOS::ForceRemoveDirectory(NEW_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(OLD_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(REAL_BUNDLE_DIR_NAME);
    dataMgr->bundleInfos_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: installExceptionMgrTest_0023
 * @tc.name: test InnerProcessDeleteOldPath with RenameModuleDir failure
 * @tc.desc: test InnerProcessDeleteOldPath when RenameModuleDir fails
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0023, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::DELETE_OLD_PATH;
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    bool ans = OHOS::ForceCreateDirectory(TEMP_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    mgr->HandleBundleExceptionInfo(BUNDLE_NAME);
    auto exist = access(TEMP_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_NE(exist, 0);
    (void)OHOS::ForceRemoveDirectory(TEMP_BUNDLE_DIR_NAME);
}

/**
 * @tc.number: installExceptionMgrTest_0024
 * @tc.name: test InnerProcessDeleteOldPath with RemoveDir failure
 * @tc.desc: test InnerProcessDeleteOldPath when RemoveDir fails
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0024, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::DELETE_OLD_PATH;
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    bool ans = mgr->HandleBundleExceptionInfo(BUNDLE_NAME);
    EXPECT_TRUE(ans);
    InstallExceptionInfo newInfo;
    ans = mgr->installExceptionMgr_->GetBundleExceptionInfo(BUNDLE_NAME, newInfo);
    EXPECT_TRUE(ans);
    EXPECT_EQ(info.status, newInfo.status);
    mgr->installExceptionMgr_->DeleteBundleExceptionInfo(BUNDLE_NAME);
}

/**
 * @tc.number: installExceptionMgrTest_0025
 * @tc.name: test InnerProcessDeleteOldPath with RemoveDir failure
 * @tc.desc: test InnerProcessDeleteOldPath when RemoveDir fails
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrTest_0025, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::DELETE_OLD_PATH;
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    bool ans = OHOS::ForceCreateDirectory(OLD_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    mgr->HandleBundleExceptionInfo(BUNDLE_NAME);
    auto exist = access(OLD_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_NE(exist, 0);
    (void)OHOS::ForceRemoveDirectory(OLD_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(TEMP_BUNDLE_DIR_NAME);
    ret = mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: installExceptionMgrRdbTest_0001
 * @tc.name: test GetAllBundleExceptionInfo with null rdbDataManager_
 * @tc.desc: test GetAllBundleExceptionInfo when rdbDataManager_ is null
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrRdbTest_0001, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    mgr->installExceptionMgr_ = std::make_shared<InstallExceptionMgrRdb>();
    mgr->installExceptionMgr_->rdbDataManager_ = nullptr;
    std::map<std::string, InstallExceptionInfo> installExceptionInfos;
    mgr->installExceptionMgr_->GetAllBundleExceptionInfo(installExceptionInfos);
    EXPECT_TRUE(installExceptionInfos.empty());
}

/**
 * @tc.number: installExceptionMgrRdbTest_0002
 * @tc.name: test GetAllBundleExceptionInfo with empty data
 * @tc.desc: test GetAllBundleExceptionInfo when QueryAllData returns empty
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrRdbTest_0002, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    mgr->installExceptionMgr_ = std::make_shared<InstallExceptionMgrRdb>();
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    std::map<std::string, InstallExceptionInfo> installExceptionInfos;
    mgr->installExceptionMgr_->GetAllBundleExceptionInfo(installExceptionInfos);
    EXPECT_TRUE(installExceptionInfos.empty());
}

/**
 * @tc.number: installExceptionMgrRdbTest_0003
 * @tc.name: test GetAllBundleExceptionInfo with valid data
 * @tc.desc: test GetAllBundleExceptionInfo when QueryAllData returns valid data
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrRdbTest_0003, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::CREATE_NEW_DIR;
    info.versionCode = 1001;
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    std::map<std::string, InstallExceptionInfo> installExceptionInfos;
    mgr->installExceptionMgr_->GetAllBundleExceptionInfo(installExceptionInfos);
    EXPECT_FALSE(installExceptionInfos.empty());
    EXPECT_EQ(installExceptionInfos[BUNDLE_NAME].status, info.status);
    EXPECT_EQ(installExceptionInfos[BUNDLE_NAME].versionCode, info.versionCode);
    ret = mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: installExceptionMgrRdbTest_0004
 * @tc.name: test GetBundleExceptionInfo with empty bundleName
 * @tc.desc: test GetBundleExceptionInfo when bundleName is empty
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrRdbTest_0004, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    InstallExceptionInfo installExceptionInfo;
    bool result = mgr->installExceptionMgr_->GetBundleExceptionInfo("", installExceptionInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: installExceptionMgrRdbTest_0005
 * @tc.name: test GetBundleExceptionInfo when bundle not exist
 * @tc.desc: test GetBundleExceptionInfo when QueryData returns false
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrRdbTest_0005, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    InstallExceptionInfo installExceptionInfo;
    bool result = mgr->installExceptionMgr_->GetBundleExceptionInfo("com.example.example", installExceptionInfo);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: installExceptionMgrRdbTest_0006
 * @tc.name: test GetBundleExceptionInfo with valid bundle
 * @tc.desc: test GetBundleExceptionInfo when bundle exists
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrRdbTest_0006, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    InstallExceptionInfo info;
    info.status = InstallRenameExceptionStatus::RENAME_RELA_TO_OLD_PATH;
    info.versionCode = 2002;
    ErrCode ret = mgr->SaveBundleExceptionInfo(BUNDLE_NAME, info);
    EXPECT_EQ(ret, ERR_OK);
    InstallExceptionInfo installExceptionInfo;
    bool result = mgr->installExceptionMgr_->GetBundleExceptionInfo(BUNDLE_NAME, installExceptionInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(installExceptionInfo.status, info.status);
    EXPECT_EQ(installExceptionInfo.versionCode, info.versionCode);
    ret = mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: installExceptionMgrRdbTest_0007
 * @tc.name: test GetBundleExceptionInfo with invalid data
 * @tc.desc: test GetBundleExceptionInfo when FromString returns false
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrRdbTest_0007, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_->rdbDataManager_, nullptr);
    bool result = mgr->installExceptionMgr_->rdbDataManager_->InsertData(BUNDLE_NAME, "{invalid}");
    EXPECT_TRUE(result);
    InstallExceptionInfo installExceptionInfo;
    result = mgr->installExceptionMgr_->GetBundleExceptionInfo(BUNDLE_NAME, installExceptionInfo);
    EXPECT_FALSE(result);
    ErrCode ret = mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: installExceptionMgrRdbTest_0008
 * @tc.name: test GetBundleExceptionInfo with nullptr
 * @tc.desc: test GetBundleExceptionInfo when returns false
 */
HWTEST_F(BmsInstallExceptionMgrTest, installExceptionMgrRdbTest_0008, TestSize.Level1)
{
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    ASSERT_NE(mgr->installExceptionMgr_, nullptr);
    mgr->installExceptionMgr_->rdbDataManager_ = nullptr;
    InstallExceptionInfo installExceptionInfo;
    bool result = mgr->installExceptionMgr_->GetBundleExceptionInfo(BUNDLE_NAME, installExceptionInfo);
    EXPECT_FALSE(result);
    mgr->installExceptionMgr_ = std::make_shared<InstallExceptionMgrRdb>();
}

/**
 * @tc.number: baseBundleInstallerCodePathTest_0001
 * @tc.name: test InnerProcessCodePathCreateNewDir with isUpdate false
 * @tc.desc: test InnerProcessCodePathCreateNewDir returns ERR_OK when isUpdate is false
 */
HWTEST_F(BmsInstallExceptionMgrTest, baseBundleInstallerCodePathTest_0001, TestSize.Level1)
{
    BaseBundleInstaller installer;
    ErrCode result = installer.InnerProcessCodePathCreateNewDir(BUNDLE_NAME, false);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: baseBundleInstallerCodePathTest_0002
 * @tc.name: test InnerProcessCodePathCreateNewDir with isUpdate true
 * @tc.desc: test InnerProcessCodePathCreateNewDir when isUpdate is true
 */
HWTEST_F(BmsInstallExceptionMgrTest, baseBundleInstallerCodePathTest_0002, TestSize.Level1)
{
    BaseBundleInstaller installer;
    ErrCode result = installer.InnerProcessCodePathCreateNewDir(BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_OK);
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
}

/**
 * @tc.number: baseBundleInstallerCodePathTest_0003
 * @tc.name: test InnerProcessCodePathRealToOld with SaveBundleExceptionInfo failure
 * @tc.desc: test InnerProcessCodePathRealToOld when SaveBundleExceptionInfo fails
 */
HWTEST_F(BmsInstallExceptionMgrTest, baseBundleInstallerCodePathTest_0003, TestSize.Level1)
{
    BaseBundleInstaller installer;
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    mgr->installExceptionMgr_ = nullptr;
    ErrCode result = installer.InnerProcessCodePathRealToOld(BUNDLE_NAME, 1001);
    EXPECT_NE(result, ERR_OK);
    mgr->installExceptionMgr_ = std::make_shared<InstallExceptionMgrRdb>();
}

/**
 * @tc.number: baseBundleInstallerCodePathTest_0004
 * @tc.name: test InnerProcessCodePathRealToOld with non-existent real path
 * @tc.desc: test InnerProcessCodePathRealToOld when real path does not exist (ENOENT)
 */
HWTEST_F(BmsInstallExceptionMgrTest, baseBundleInstallerCodePathTest_0004, TestSize.Level1)
{
    BaseBundleInstaller installer;
    ErrCode result = installer.InnerProcessCodePathRealToOld(BUNDLE_NAME, 1001);
    EXPECT_EQ(result, ERR_OK);
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    result = mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: baseBundleInstallerCodePathTest_0005
 * @tc.name: test InnerProcessCodePathRealToOld with existing real path
 * @tc.desc: test InnerProcessCodePathRealToOld when real path exists but rename fails
 */
HWTEST_F(BmsInstallExceptionMgrTest, baseBundleInstallerCodePathTest_0005, TestSize.Level1)
{
    (void)OHOS::ForceRemoveDirectory(REAL_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(OLD_BUNDLE_DIR_NAME);
    BaseBundleInstaller installer;
    ErrCode result = installer.InnerProcessCodePathRealToOld(BUNDLE_NAME, 1001);
    EXPECT_EQ(result, ERR_OK);
    bool ans = OHOS::ForceCreateDirectory(REAL_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    result = installer.InnerProcessCodePathRealToOld(BUNDLE_NAME, 1001);
    EXPECT_EQ(result, ERR_OK);
    auto exist = access(REAL_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_NE(exist, 0);
    exist = access(OLD_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_EQ(exist, 0);
    (void)OHOS::ForceRemoveDirectory(REAL_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(OLD_BUNDLE_DIR_NAME);
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
}

/**
 * @tc.number: baseBundleInstallerCodePathTest_0006
 * @tc.name: test InnerProcessCodePathNewToReal with SaveBundleExceptionInfo failure
 * @tc.desc: test InnerProcessCodePathNewToReal when SaveBundleExceptionInfo fails
 */
HWTEST_F(BmsInstallExceptionMgrTest, baseBundleInstallerCodePathTest_0006, TestSize.Level1)
{
    BaseBundleInstaller installer;
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    mgr->installExceptionMgr_ = nullptr;
    ErrCode result = installer.InnerProcessCodePathNewToReal(BUNDLE_NAME, 1001);
    EXPECT_NE(result, ERR_OK);
    mgr->installExceptionMgr_ = std::make_shared<InstallExceptionMgrRdb>();
}

/**
 * @tc.number: baseBundleInstallerCodePathTest_0007
 * @tc.name: test InnerProcessCodePathNewToReal with non-existent new path
 * @tc.desc: test InnerProcessCodePathNewToReal when new path does not exist
 */
HWTEST_F(BmsInstallExceptionMgrTest, baseBundleInstallerCodePathTest_0007, TestSize.Level1)
{
    BaseBundleInstaller installer;
    ErrCode result = installer.InnerProcessCodePathNewToReal(BUNDLE_NAME, 1001);
    EXPECT_NE(result, ERR_OK);
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
}

/**
 * @tc.number: baseBundleInstallerCodePathTest_0008
 * @tc.name: test InnerProcessCodePathNewToReal with existing new path
 * @tc.desc: test InnerProcessCodePathNewToReal when new path exists
 */
HWTEST_F(BmsInstallExceptionMgrTest, baseBundleInstallerCodePathTest_0008, TestSize.Level1)
{
    BaseBundleInstaller installer;
    bool ans = OHOS::ForceCreateDirectory(NEW_BUNDLE_DIR_NAME);
    EXPECT_TRUE(ans);
    ErrCode result = installer.InnerProcessCodePathNewToReal(BUNDLE_NAME, 1001);
    EXPECT_EQ(result, ERR_OK);
    auto exist = access(NEW_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_NE(exist, 0);
    exist = access(REAL_BUNDLE_DIR_NAME.c_str(), F_OK);
    EXPECT_EQ(exist, 0);
    (void)OHOS::ForceRemoveDirectory(NEW_BUNDLE_DIR_NAME);
    (void)OHOS::ForceRemoveDirectory(REAL_BUNDLE_DIR_NAME);
    auto mgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    ASSERT_NE(mgr, nullptr);
    mgr->DeleteBundleExceptionInfo(BUNDLE_NAME);
}
} //AppExecFwk
} // OHOS
