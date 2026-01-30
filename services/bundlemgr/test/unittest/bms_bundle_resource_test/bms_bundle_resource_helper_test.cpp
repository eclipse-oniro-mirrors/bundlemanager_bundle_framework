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

#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

#include "application_info.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "bundle_parser.h"
#include "bundle_permission_mgr.h"
#include "bundle_resource_drawable.h"

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
#include "bundle_resource_callback.h"
#include "bundle_resource_change_type.h"
#include "bundle_resource_configuration.h"
#include "bundle_resource_constants.h"
#include "bundle_resource_event_subscriber.h"
#include "bundle_resource_helper.h"
#include "bundle_resource_host_impl.h"
#include "bundle_resource_info.h"
#include "bundle_resource_manager.h"
#include "bundle_resource_observer.h"
#include "bundle_resource_param.h"
#include "bundle_resource_parser.h"
#include "bundle_resource_process.h"
#include "bundle_resource_rdb.h"
#include "bundle_resource_register.h"
#include "bundle_system_state.h"
#include "launcher_ability_resource_info.h"
#include "nlohmann/json.hpp"
#endif

#include "directory_ex.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "parameter.h"
#include "permission_define.h"
#include "remote_ability_info.h"
#include "scope_guard.h"
#include "system_ability_definition.h"
#include "system_ability_helper.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {
const int32_t USERID = 100;
const int32_t WAIT_TIME = 2; // init mocked bms
const std::string BUNDLE_NAME = "com.example.bmsaccesstoken1";
const std::string BUNDLE_NAME_NOT_EXIST = "com.example.not_exist";
const std::string HAP_FILE_PATH1 = "/data/test/resource/bms/accesstoken_bundle/bmsAccessTokentest1.hap";
}  // namespace

class BmsBundleResourceHelperTest : public testing::Test {
public:
    BmsBundleResourceHelperTest();
    ~BmsBundleResourceHelperTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StartInstalldService() const;
    void StartBundleService();
    sptr<BundleMgrProxy> GetBundleMgrProxy();

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleResourceHelperTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleResourceHelperTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleResourceHelperTest::BmsBundleResourceHelperTest()
{}

BmsBundleResourceHelperTest::~BmsBundleResourceHelperTest()
{}

void BmsBundleResourceHelperTest::SetUpTestCase()
{}

void BmsBundleResourceHelperTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleResourceHelperTest::SetUp()
{
    StartInstalldService();
    StartBundleService();
}

void BmsBundleResourceHelperTest::TearDown()
{}

ErrCode BmsBundleResourceHelperTest::InstallBundle(const std::string &bundlePath) const
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
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = USERID;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleResourceHelperTest::UnInstallBundle(const std::string &bundleName) const
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

void BmsBundleResourceHelperTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleResourceHelperTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

const std::shared_ptr<BundleDataMgr> BmsBundleResourceHelperTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

sptr<BundleMgrProxy> BmsBundleResourceHelperTest::GetBundleMgrProxy()
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
    return iface_cast<BundleMgrProxy>(remoteObject);
}

/**
 * @tc.number: AddResourceInfoByBundleName_0010
 * Function: AddResourceInfoByBundleName
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddResourceInfoByBundleName
 */
HWTEST_F(BmsBundleResourceHelperTest, AddResourceInfoByBundleName_0010, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    BundleResourceHelper::AddResourceInfoByBundleName(BUNDLE_NAME, USERID, ADD_RESOURCE_TYPE::INSTALL_BUNDLE);
    bool ret = BundleResourceHelper::DeleteBundleResourceInfo(BUNDLE_NAME, USERID, true);
    EXPECT_TRUE(ret);

    BundleResourceHelper::AddResourceInfoByBundleName(BUNDLE_NAME, USERID, ADD_RESOURCE_TYPE::UPDATE_BUNDLE);
    ret = BundleResourceHelper::DeleteBundleResourceInfo(BUNDLE_NAME, USERID, true);
    EXPECT_TRUE(ret);

    BundleResourceHelper::AddResourceInfoByBundleName(BUNDLE_NAME, USERID, ADD_RESOURCE_TYPE::CREATE_USER);
    ret = BundleResourceHelper::DeleteBundleResourceInfo(BUNDLE_NAME, USERID, true);
    EXPECT_TRUE(ret);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}

/**
 * @tc.number: AddCloneBundleResourceInfo_0010
 * Function: AddCloneBundleResourceInfo
 * @tc.name: test
 * @tc.desc: 1. system running normally
 *           2. test AddCloneBundleResourceInfo
 */
HWTEST_F(BmsBundleResourceHelperTest, AddCloneBundleResourceInfo_0010, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    bool ret = BundleResourceHelper::AddCloneBundleResourceInfo(BUNDLE_NAME_NOT_EXIST, USERID, 1, false);
    EXPECT_FALSE(ret);

    ret = BundleResourceHelper::AddCloneBundleResourceInfo(BUNDLE_NAME, USERID, 1, false);
    EXPECT_TRUE(ret);

    ret = BundleResourceHelper::DeleteCloneBundleResourceInfo(BUNDLE_NAME, USERID, 1, false);
    EXPECT_TRUE(ret);

    ErrCode unInstallResult = UnInstallBundle(BUNDLE_NAME);
    EXPECT_EQ(unInstallResult, ERR_OK);
}
}
