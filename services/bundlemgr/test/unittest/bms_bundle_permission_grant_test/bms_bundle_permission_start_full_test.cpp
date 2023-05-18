/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <sstream>
#include <string>

#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_verify_mgr.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "permission_define.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {
const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
}  // namespace

class BmsBundlePermissionStartFullTest : public testing::Test {
public:
    BmsBundlePermissionStartFullTest();
    ~BmsBundlePermissionStartFullTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StartInstalldService() const;
    void StartBundleService();
private:
    std::shared_ptr<InstalldService> installdService_ = std::make_shared<InstalldService>();
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
};

BmsBundlePermissionStartFullTest::BmsBundlePermissionStartFullTest()
{}

BmsBundlePermissionStartFullTest::~BmsBundlePermissionStartFullTest()
{}

void BmsBundlePermissionStartFullTest::SetUpTestCase()
{}

void BmsBundlePermissionStartFullTest::TearDownTestCase()
{}

void BmsBundlePermissionStartFullTest::SetUp()
{
    StartInstalldService();
    StartBundleService();
}

void BmsBundlePermissionStartFullTest::TearDown()
{}

ErrCode BmsBundlePermissionStartFullTest::InstallBundle(const std::string &bundlePath) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USERID;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundlePermissionStartFullTest::UnInstallBundle(const std::string &bundleName) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USERID;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

void BmsBundlePermissionStartFullTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundlePermissionStartFullTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

const std::shared_ptr<BundleDataMgr> BmsBundlePermissionStartFullTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: BmsBundlePermissionStartFullTest
 * Function: UpdateDefineAndRequestPermissions
 * @tc.name: test UpdateDefineAndRequestPermissions verify false
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionStartFullTest, BmsBundlePermissionStartFullTest_0100, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);

    Security::AccessToken::AccessTokenIDEx tokenIdEx;
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    std::vector<std::string> newRequestPermName;
    res = BundlePermissionMgr::UpdateDefineAndRequestPermissions(tokenIdEx, oldInfo, newInfo, newRequestPermName);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BmsBundlePermissionStartFullTest
 * Function: AddDefineAndRequestPermissions
 * @tc.name: test AddDefineAndRequestPermissions false
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionStartFullTest, BmsBundlePermissionStartFullTest_0200, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);

    Security::AccessToken::AccessTokenIDEx tokenIdEx;
    InnerBundleInfo innerBundleInfo;
    std::vector<std::string> newRequestPermName;
    res = BundlePermissionMgr::AddDefineAndRequestPermissions(tokenIdEx, innerBundleInfo, newRequestPermName);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BmsBundlePermissionStartFullTest_0300
 * Function: VerifySystemApp
 * @tc.name: test VerifySystemApp false
 * @tc.desc: 1. system running normally
 */
HWTEST_F(BmsBundlePermissionStartFullTest, BmsBundlePermissionStartFullTest_0300, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);

    int32_t beginSystemApiVersion = 100;
    res = BundlePermissionMgr::VerifySystemApp(beginSystemApiVersion);
    EXPECT_EQ(res, true);
}
} // OHOS