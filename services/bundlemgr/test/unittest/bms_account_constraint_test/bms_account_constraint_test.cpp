/*
* Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#define protected public

#include <fstream>
#include <gtest/gtest.h>

#include "app_provision_info_manager.h"
#include "base_bundle_installer.h"
#include "bundle_cache_mgr.h"
#include "bundle_clone_installer.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_multiuser_installer.h"
#include "bundle_sandbox_installer.h"
#include "data_group_info.h"
#include "hmp_bundle_installer.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "parameters.h"
#include "plugin_installer.h"
#include "rdb_data_manager.h"
#include "scope_guard.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::Parcel;

namespace OHOS {
namespace {
const int32_t WAIT_TIME = 2;
constexpr int32_t USER_ID = 100;
constexpr int32_t DEFAULT_USERID = 0;
}  // namespace

class BmsAccountConstraintTest : public testing::Test {
public:
    BmsAccountConstraintTest();
    ~BmsAccountConstraintTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsAccountConstraintTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsAccountConstraintTest::BmsAccountConstraintTest()
{}

BmsAccountConstraintTest::~BmsAccountConstraintTest()
{}

void BmsAccountConstraintTest::SetUpTestCase()
{
    bundleMgrService_->OnStart();
    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
}

void BmsAccountConstraintTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsAccountConstraintTest::SetUp()
{
}

void BmsAccountConstraintTest::TearDown()
{
}

/**
 * @tc.number: CheckOsAccountConstraintEnabled_0001
 * @tc.name: test InnerProcessBundleInstall
 * @tc.desc: 1.Test InnerProcessBundleInstall the BaseBundleInstaller
*/
HWTEST_F(BmsAccountConstraintTest, CheckOsAccountConstraintEnabled_0001, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    installer.isAppExist_ = false;
    InnerBundleInfo newInfo;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.insert(std::make_pair("com.example.helloworld", newInfo));
    InnerBundleInfo oldInfo;
    InstallParam installParam;
    int32_t uid = 0;
    auto ret = installer.InnerProcessBundleInstall(newInfos, oldInfo, installParam, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_ACCOUNT_CONSTRAINT);
}

/**
 * @tc.number: CheckOsAccountConstraintEnabled_0002
 * @tc.name: test InnerProcessBundleInstall
 * @tc.desc: 1.Test InnerProcessBundleInstall the BaseBundleInstaller
*/
HWTEST_F(BmsAccountConstraintTest, CheckOsAccountConstraintEnabled_0002, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    installer.isAppExist_ = true;
    installer.userId_ = -3;
    InnerBundleInfo newInfo;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    newInfos.insert(std::make_pair("com.example.helloworld", newInfo));
    InnerBundleInfo oldInfo;
    InstallParam installParam;
    int32_t uid = 0;
    auto ret = installer.InnerProcessBundleInstall(newInfos, oldInfo, installParam, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_ACCOUNT_CONSTRAINT);
}

/**
 * @tc.number: LoadPreInstallWhiteList_0100
 * @tc.name: LoadPreInstallWhiteList
 * @tc.desc: test LoadPreInstallWhiteList
 */
HWTEST_F(BmsAccountConstraintTest, LoadPreInstallWhiteList_0100, Function | MediumTest | Level1)
{
    std::string testName = "com.test.test";
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::vector<int32_t> userIds;
    
    auto installAndRecoverPair1 =
        std::make_pair(std::vector<std::string>(), std::vector<std::string>{testName});
    handler->userInstallAndRecoverMap_[100] = installAndRecoverPair1;
    auto installAndRecoverPair2 = std::make_pair(std::vector<std::string>(), std::vector<std::string>());
    handler->userInstallAndRecoverMap_[101] = installAndRecoverPair2;
    auto ret = handler->IsRecoverListEmpty(testName, userIds);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(userIds.empty());

    userIds.clear();
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(DEFAULT_USERID);
    dataMgr->multiUserIdsSet_.insert(USER_ID);
    handler->LoadPreInstallWhiteList();
    ret = handler->IsRecoverListEmpty(testName, userIds);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(userIds.empty());
}


/**
 * @tc.number: LoadPreInstallWhiteList_0200
 * @tc.name: LoadPreInstallWhiteList
 * @tc.desc: test LoadPreInstallWhiteList
 */
HWTEST_F(BmsAccountConstraintTest, LoadPreInstallWhiteList_0200, Function | MediumTest | Level1)
{
    std::string testName = "com.test.test";
    std::vector<int32_t> userIds;
    auto installAndRecoverPair1 =
        std::make_pair(std::vector<std::string>(), std::vector<std::string>{testName});
    bundleMgrService_->handler_->userInstallAndRecoverMap_[100] = installAndRecoverPair1;
    auto installAndRecoverPair2 = std::make_pair(std::vector<std::string>(), std::vector<std::string>());
    bundleMgrService_->handler_->userInstallAndRecoverMap_[101] = installAndRecoverPair2;
    bundleMgrService_->dataMgr_ = nullptr;
    bundleMgrService_->handler_->LoadPreInstallWhiteList();
    auto ret = bundleMgrService_->handler_->IsRecoverListEmpty(testName, userIds);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(userIds.empty());
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    bundleMgrService_->GetDataMgr()->AddUserId(DEFAULT_USERID);
    bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
    ASSERT_NE(bundleMgrService_->dataMgr_, nullptr);
}

/**
 * @tc.number: HandlePreInstallBundleNamesException_0100
 * @tc.name: HandlePreInstallBundleNamesException
 * @tc.desc: test HandlePreInstallBundleNamesException
 */
HWTEST_F(BmsAccountConstraintTest, HandlePreInstallBundleNamesException_0100, Function | MediumTest | Level1)
{
    std::string testName = "com.test.test";
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    PreInstallBundleInfo info;
    handler->loadExistData_.emplace(testName, info);
    auto preInstallExceptionMgr = std::make_shared<PreInstallExceptionMgr>();
    ASSERT_NE(preInstallExceptionMgr, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->preInstallExceptionMgr_ = preInstallExceptionMgr;
    auto bmsParam = std::make_shared<BmsParam>();
    ASSERT_NE(bmsParam, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->bmsParam_ = bmsParam;
    preInstallExceptionMgr->exceptionBundleNames_.insert(testName);
    std::set<std::string> exceptionBundleNames;
    exceptionBundleNames.emplace(testName);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(USER_ID);
    handler->LoadPreInstallWhiteList();
    handler->HandlePreInstallBundleNamesException(preInstallExceptionMgr, exceptionBundleNames);
    EXPECT_TRUE(preInstallExceptionMgr->exceptionBundleNames_.find(testName) ==
        preInstallExceptionMgr->exceptionBundleNames_.end());
}

/**
 * @tc.number: InnerProcessBundleInstall_0001
 * @tc.name: CleanArkStartupCache
 * @tc.desc: test CleanArkStartupCache
 */
HWTEST_F(BmsAccountConstraintTest, InnerProcessBundleInstall_0001, Function | MediumTest | Level1)
{
    auto bundleName = "com.example.helloworld";
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetSingleton(false);
    newInfos.insert(std::pair<std::string, InnerBundleInfo>(bundleName, innerBundleInfo));
    InnerBundleInfo oldInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    oldInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    InstallParam installParam;
    installParam.needSavePreInstallInfo = false;
    installParam.isPatch = true;
    int32_t uid = 0;

    BaseBundleInstaller installer;
    installer.bundleName_ = bundleName;
    installer.isAppExist_ = true;
    installer.userId_ = -3;
    installer.InitDataMgr();
    installer.dataMgr_->bundleInfos_.emplace(bundleName, oldInfo);
    auto res = installer.InnerProcessBundleInstall(newInfos, oldInfo, installParam, uid);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALLD_CLEAN_DIR_FAILED);
}

/**
 * @tc.number: InnerProcessBundleInstall_0002
 * @tc.name: CleanArkStartupCache
 * @tc.desc: test CleanArkStartupCache
 */
HWTEST_F(BmsAccountConstraintTest, InnerProcessBundleInstall_0002, Function | MediumTest | Level1)
{
    auto bundleName = "com.example.helloworld";
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetSingleton(false);
    newInfos.insert(std::pair<std::string, InnerBundleInfo>(bundleName, innerBundleInfo));
    InnerBundleInfo oldInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    oldInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    InstallParam installParam;
    installParam.needSavePreInstallInfo = false;
    int32_t uid = 0;

    BaseBundleInstaller installer;
    installer.bundleName_ = bundleName;
    installer.isAppExist_ = true;
    installer.userId_ = -3;
    installer.InitDataMgr();
    installer.dataMgr_->bundleInfos_.emplace(bundleName, oldInfo);
    auto res = installer.InnerProcessBundleInstall(newInfos, oldInfo, installParam, uid);
    EXPECT_EQ(res, ERR_APPEXECFWK_GET_INSTALL_TEMP_BUNDLE_ERROR);
}

/**
 * @tc.number: CheckOsAccountConstraintEnabled_0003
 * @tc.name: test ProcessBundleInstall
 * @tc.desc: 1.Test ProcessBundleInstall the BundleMultiUserInstaller
*/
HWTEST_F(BmsAccountConstraintTest, CheckOsAccountConstraintEnabled_0003, Function | MediumTest | Level1)
{
    BundleMultiUserInstaller installer;
    installer.dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    InnerBundleInfo info;
    InnerBundleUserInfo userInfo;
    info.AddInnerBundleUserInfo(userInfo);
    installer.dataMgr_->bundleInfos_.emplace("com.example.helloworld", info);
    auto ret = installer.ProcessBundleInstall("com.example.helloworld", 100);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_ACCOUNT_CONSTRAINT);
}

/**
 * @tc.number: CheckOsAccountConstraintEnabled_0004
 * @tc.name: test ProcessRecover
 * @tc.desc: 1.Test ProcessRecover
*/
HWTEST_F(BmsAccountConstraintTest, CheckOsAccountConstraintEnabled_0004, Function | MediumTest | Level1)
{
    BaseBundleInstaller installer;
    std::string bundleName = "com.example.helloworld";
    InstallParam installParam;
    installParam.userId = 100;
    int32_t uid = 0;
    auto ret = installer.ProcessRecover(bundleName, installParam, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_ACCOUNT_CONSTRAINT);
}
} // OHOS
