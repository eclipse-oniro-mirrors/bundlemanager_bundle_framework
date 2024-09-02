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
#include <gtest/gtest.h>
#include <vector>

#include "system_ability_definition.h"
#include "system_ability.h"
#include "bundle_mgr_interface.h"
#include "bundle_installer_proxy.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
const std::string HSPNAME = "hspName";
const char* DATA = "data";
size_t DATA_SIZE = 4;
const std::string OVER_MAX_NAME_SIZE(260, 'x');
constexpr int32_t TEST_INSTALLER_ID = 1024;
constexpr int32_t DEFAULT_INSTALLER_ID = 0;
constexpr int32_t TEST_INSTALLER_UID = 100;
constexpr int32_t INVAILD_ID = -1;

constexpr const char* ILLEGAL_PATH_FIELD = "../";
}; // namespace
class BmsBundleMultiuserInstallIPCTest : public testing::Test {
public:
    BmsBundleMultiuserInstallIPCTest();
    ~BmsBundleMultiuserInstallIPCTest();
    static void SetUpTestCase();
    static void TearDownTestCase();

    sptr<IBundleMgr> GetBundleMgrProxy();
    sptr<IBundleInstaller> GetInstallerProxy();
    void SetUp();
    void TearDown();

private:
    sptr<BundleInstallerHost> installerHost_ = nullptr;
    sptr<BundleInstallerProxy> installerProxy_ = nullptr;
};

BmsBundleMultiuserInstallIPCTest::BmsBundleMultiuserInstallIPCTest()
{}

BmsBundleMultiuserInstallIPCTest::~BmsBundleMultiuserInstallIPCTest()
{}

void BmsBundleMultiuserInstallIPCTest::SetUpTestCase()
{
}

void BmsBundleMultiuserInstallIPCTest::TearDownTestCase()
{
}
void BmsBundleMultiuserInstallIPCTest::SetUp()
{}

void BmsBundleMultiuserInstallIPCTest::TearDown()
{}

sptr<IBundleMgr> BmsBundleMultiuserInstallIPCTest::GetBundleMgrProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        APP_LOGE("fail to get system ability mgr.");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        APP_LOGE("fail to get bundle manager proxy.");
        return nullptr;
    }

    APP_LOGI("get bundle manager proxy success.");
    return iface_cast<IBundleMgr>(remoteObject);
}

sptr<IBundleInstaller> BmsBundleMultiuserInstallIPCTest::GetInstallerProxy()
{
    sptr<IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    if (!bundleMgrProxy) {
        APP_LOGE("bundle mgr proxy is nullptr.");
        return nullptr;
    }

    sptr<IBundleInstaller> installerProxy = bundleMgrProxy->GetBundleInstaller();
    if (!installerProxy) {
        APP_LOGE("fail to get bundle installer proxy");
        return nullptr;
    }

    APP_LOGI("get bundle installer proxy success.");
    return installerProxy;
}

HWTEST_F(BmsBundleMultiuserInstallIPCTest,
    InstallMultiuserInstallTest001_BundleNameEmpty, Function | SmallTest | Level0)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        return;
    }
    const std::string bundleName = "";
    const int32_t userId = 100;

    auto result = installerProxy->InstallExisted(bundleName, userId);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

HWTEST_F(BmsBundleMultiuserInstallIPCTest,
    InstallMultiuserInstallTest001_BundleNotFound, Function | SmallTest | Level0)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        return;
    }
    const std::string bundleName = "ohos.samples.etsclock.notfound";
    const int32_t userId = 100;

    auto result = installerProxy->InstallExisted(bundleName, userId);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

HWTEST_F(BmsBundleMultiuserInstallIPCTest,
    InstallMultiuserInstallTest001_UserIdNotFound, Function | SmallTest | Level0)
{
    sptr<IBundleInstaller> installerProxy = GetInstallerProxy();
    if (!installerProxy) {
        APP_LOGE("get bundle installer Failure.");
        return;
    }
    const std::string bundleName = "ohos.samples.etsclock";
    const int32_t userId = 200;

    auto result = installerProxy->InstallExisted(bundleName, userId);
    EXPECT_TRUE(result == ERR_BUNDLE_MANAGER_INVALID_USER_ID || result == ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}
} // OHOS