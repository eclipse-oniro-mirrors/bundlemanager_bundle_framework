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
const int32_t WAIT_TIME = 5;
constexpr int32_t USER_ID = 100;
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
} // OHOS
