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
#include <vector>
#define private public
#include "system_ability_definition.h"
#include "system_ability.h"
#include "bundle_mgr_interface.h"
#include "bundle_installer_proxy.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_multiuser_installer.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
constexpr int32_t USERID = 100;
constexpr int32_t WAIT_TIME = 5; // init mocked bms

}; // namespace
class BmsBundleMultiuserInstallPermissionTest : public testing::Test {
public:
    BmsBundleMultiuserInstallPermissionTest();
    ~BmsBundleMultiuserInstallPermissionTest();
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp();
    void TearDown();
};


BmsBundleMultiuserInstallPermissionTest::BmsBundleMultiuserInstallPermissionTest()
{}

BmsBundleMultiuserInstallPermissionTest::~BmsBundleMultiuserInstallPermissionTest()
{}

void BmsBundleMultiuserInstallPermissionTest::SetUpTestCase()
{
}

void BmsBundleMultiuserInstallPermissionTest::TearDownTestCase()
{
}
void BmsBundleMultiuserInstallPermissionTest::SetUp()
{
}

void BmsBundleMultiuserInstallPermissionTest::TearDown()
{}

/**
 * @tc.number: ProcessBundleInstall_0100
 * @tc.name: ProcessBundleInstall by BundleMultiUserInstaller
 * @tc.desc: test ProcessBundleInstall
 */
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, ProcessBundleInstall_0100, Function | SmallTest | Level0)
{
    BundleMultiUserInstaller installer;
    installer.dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(installer.dataMgr_, nullptr);
    installer.dataMgr_->AddUserId(1);
    InnerBundleInfo info;
    installer.dataMgr_->bundleInfos_.try_emplace("test", info);
    auto res = installer.ProcessBundleInstall("test", 1);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
}

/**
 * @tc.number: RecoverHapToken_0100
 * @tc.name: RecoverHapToken by BundleMultiUserInstaller
 * @tc.desc: test RecoverHapToken
 */
HWTEST_F(BmsBundleMultiuserInstallPermissionTest, RecoverHapToken_0100, Function | SmallTest | Level0)
{
    BundleMultiUserInstaller installer;
    installer.dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(installer.dataMgr_, nullptr);
    UninstallBundleInfo unInstallBundleInfo;
    unInstallBundleInfo.appId = 1;
    std::map<std::string, UninstallDataUserInfo> userInfos;
    UninstallDataUserInfo uninstallDataUserInfo;
    unInstallBundleInfo.userInfos.try_emplace("100", uninstallDataUserInfo);
    installer.dataMgr_->UpdateUninstallBundleInfo("test", unInstallBundleInfo);
    Security::AccessToken::AccessTokenIDEx accessTokenIdEx;
    InnerBundleInfo innerBundleInfo;
    auto res = installer.RecoverHapToken("test", 100, accessTokenIdEx, innerBundleInfo);
    EXPECT_EQ(res, false);
    installer.dataMgr_->DeleteUninstallBundleInfo("test", 100);
}
} // OHOS