/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <filesystem>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
#include "app_control_manager_host_impl.h"
#include "app_control_constants.h"
#endif
#ifdef APP_DOMAIN_VERIFY_ENABLED
#include "app_domain_verify_mgr_client.h"
#endif
#include "app_service_fwk/app_service_fwk_installer.h"
#include "bundle_file_util.h"
#include "bundle_info.h"
#include "bundle_installer.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_multiuser_installer.h"
#include "bundle_resource_helper.h"
#include "bundle_resource_manager.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "hmp_bundle_installer.h"
#include "install_param.h"
#include "installd/installd_load_callback.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "install_exception_mgr.h"
#include "mock_status_receiver.h"
#include "parameter.h"
#include "parameters.h"
#include "plugin_installer.h"
#include "scope_guard.h"
#include "shared/shared_bundle_installer.h"
#include "system_bundle_installer.h"
#include "utd_handler.h"
#include "want.h"
#include "uninstall_bundle_info.h"
#include "installd/installd_permission_mgr.h"
#include "bundle_cache_mgr.h"
#include "process_cache_callback_host.h"
#include "ipc/skills_package_param.h"
#include "skills_installer/skills_package_info.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.l3jsdemo";
const std::string RESOURCE_ROOT_PATH = "/data/test/resource/bms/install_bundle/";
const std::string RIGHT_BUNDLE = "right.hap";
const int32_t USERID = 100;
const int32_t ADD_NEW_USERID = 200;
}  // namespace

class BmsBundleEnterpriseDeviceTest : public testing::Test {
public:
    BmsBundleEnterpriseDeviceTest();
    ~BmsBundleEnterpriseDeviceTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    bool InstallSystemBundle(const std::string &filePath) const;
    bool InstallSystemBundle(const std::string &filePath, bool isRemovable, bool needSavePreInstall = true) const;
    ErrCode MockForceUnInstallBundle(const std::string &bundleName,
        const InstallParam &installParam) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    ErrCode UnInstallBundle(const std::string &bundleName, const InstallParam &installParam) const;
    void ClearBundleInfo();
    ErrCode RecoverBundle(const std::string &bundleName, const InstallParam &installParam) const;
    void ResetDataMgr();
private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<InstalldService> BmsBundleEnterpriseDeviceTest::installdService_ =
    std::make_shared<InstalldService>();

std::shared_ptr<BundleMgrService> BmsBundleEnterpriseDeviceTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleEnterpriseDeviceTest::BmsBundleEnterpriseDeviceTest()
{}

BmsBundleEnterpriseDeviceTest::~BmsBundleEnterpriseDeviceTest()
{}

void BmsBundleEnterpriseDeviceTest::SetUpTestCase()
{
    bundleMgrService_->InitBundleInstaller();
    bundleMgrService_->InitBmsParam();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    bundleMgrService_->ready_ = true;
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleEnterpriseDeviceTest::TearDownTestCase()
{}

void BmsBundleEnterpriseDeviceTest::SetUp()
{}

void BmsBundleEnterpriseDeviceTest::TearDown()
{}

const std::shared_ptr<BundleDataMgr> BmsBundleEnterpriseDeviceTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

void BmsBundleEnterpriseDeviceTest::ResetDataMgr()
{
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(bundleMgrService_->dataMgr_, nullptr);
}

bool BmsBundleEnterpriseDeviceTest::InstallSystemBundle(const std::string &filePath) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    auto installer = std::make_unique<SystemBundleInstaller>();
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.isPreInstallApp = true;
    setuid(Constants::FOUNDATION_UID);
    installParam.SetKillProcess(false);
    setuid(Constants::ROOT_UID);
    installParam.needSendEvent = false;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    return installer->InstallSystemBundle(
        filePath, installParam, Constants::AppType::SYSTEM_APP) == ERR_OK;
}

bool BmsBundleEnterpriseDeviceTest::InstallSystemBundle(const std::string &filePath,
    bool isRemovable, bool needSavePreInstall) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    auto installer = std::make_unique<SystemBundleInstaller>();
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.isPreInstallApp = true;
    setuid(Constants::FOUNDATION_UID);
    installParam.SetKillProcess(false);
    setuid(Constants::ROOT_UID);
    installParam.needSendEvent = false;
    installParam.needSavePreInstallInfo = needSavePreInstall;
    installParam.copyHapToInstallPath = false;
    installParam.removable = isRemovable;
    return installer->InstallSystemBundle(
        filePath, installParam, Constants::AppType::SYSTEM_APP) == ERR_OK;
}

ErrCode BmsBundleEnterpriseDeviceTest::UnInstallBundle(const std::string &bundleName) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
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
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleEnterpriseDeviceTest::UnInstallBundle(
    const std::string &bundleName, const InstallParam &installParam) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
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
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleEnterpriseDeviceTest::MockForceUnInstallBundle(const std::string &bundleName,
    const InstallParam &installParam) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
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
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    return receiver->GetResultCode();
}

void BmsBundleEnterpriseDeviceTest::ClearBundleInfo()
{
    if (bundleMgrService_ == nullptr) {
        return;
    }
    auto dataMgt = bundleMgrService_->GetDataMgr();
    if (dataMgt == nullptr) {
        return;
    }
    auto dataStorage = dataMgt->GetDataStorage();
    if (dataStorage == nullptr) {
        return;
    }

    // clear innerBundleInfo from data manager
    dataMgt->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
    dataMgt->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_SUCCESS);

    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    // clear innerBundleInfo from data storage
    bool result = dataStorage->DeleteStorageBundleInfo(innerBundleInfo);
    EXPECT_TRUE(result) << "the bundle info in db clear fail: " << BUNDLE_NAME;
}

ErrCode BmsBundleEnterpriseDeviceTest::RecoverBundle(
    const std::string &bundleName, const InstallParam &installParam) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
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
    bool result = installer->Recover(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

/**
 * @tc.number: IsEnterpriseForAllUser_0100
 * @tc.name: test IsEnterpriseForAllUser
 * @tc.desc: 1.Test IsEnterpriseForAllUser
*/
HWTEST_F(BmsBundleEnterpriseDeviceTest, IsEnterpriseForAllUser_0100, Function | MediumTest | Level1)
{
    InstallParam installParam;
    BaseBundleInstaller installer;
    EXPECT_FALSE(installer.IsEnterpriseForAllUser(installParam, ""));

    installParam.parameters.emplace("ohos.bms.param.enterpriseForAllUser", "true");
    EXPECT_FALSE(installer.IsEnterpriseForAllUser(installParam, ""));

    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "true");
    EXPECT_FALSE(installer.IsEnterpriseForAllUser(installParam, ""));

    installer.dataMgr_ = GetBundleDataMgr();
    InnerBundleInfo info;
    installer.dataMgr_->bundleInfos_.emplace("bundleName", info);
    EXPECT_FALSE(installer.IsEnterpriseForAllUser(installParam, "bundleName"));

    info.SetAppDistributionType(Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM);
    installer.dataMgr_->bundleInfos_["bundleName"] = info;
    EXPECT_FALSE(installer.IsEnterpriseForAllUser(installParam, "bundleName"));

    info.SetInstalledForAllUser(true);
    installer.dataMgr_->bundleInfos_["bundleName"] = info;
    EXPECT_TRUE(installer.IsEnterpriseForAllUser(installParam, "bundleName"));
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "false");
}

/**
 * @tc.number: BaseBundleInstaller_1010
 * @tc.name: test IsAllowEnterPrise when both parameters are false
 * @tc.desc: 1.Set allowEnterpriseBundle to false
 *           2.Set isEnterpriseDevice to false
 *           3.Verify the return value of IsAllowEnterPrise under FF condition
 *           4.Cover branch path when (!A && !B)
 * @tc.type: Function
 */
HWTEST_F(BmsBundleEnterpriseDeviceTest, BaseBundleInstaller_1010, Function | SmallTest | Level0)
{
    bool oldA = OHOS::system::GetBoolParameter(
        ServiceConstants::ALLOW_ENTERPRISE_BUNDLE, false);
    bool oldB = OHOS::system::GetBoolParameter(
        ServiceConstants::IS_ENTERPRISE_DEVICE, false);

    OHOS::system::SetParameter(ServiceConstants::ALLOW_ENTERPRISE_BUNDLE, "false");
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "false");

    BaseBundleInstaller installer;

    bool result = installer.IsAllowEnterPrise();
    EXPECT_FALSE(result);

    OHOS::system::SetParameter(ServiceConstants::ALLOW_ENTERPRISE_BUNDLE,
        oldA ? "true" : "false");
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE,
        oldB ? "true" : "false");
}


/**
 * @tc.number: BaseBundleInstaller_1011
 * @tc.name: test IsAllowEnterPrise when allowEnterpriseBundle is true
 * @tc.desc: 1.Test IsAllowEnterPrise when allowEnterpriseBundle is true
 *           2.Test IsAllowEnterPrise when isEnterpriseDevice is false
 *           3.Cover branch !A is false and && short-circuit
 */
HWTEST_F(BmsBundleEnterpriseDeviceTest, BaseBundleInstaller_1011, Function | SmallTest | Level0)
{
    bool oldA = OHOS::system::GetBoolParameter(
        ServiceConstants::ALLOW_ENTERPRISE_BUNDLE, false);
    bool oldB = OHOS::system::GetBoolParameter(
        ServiceConstants::IS_ENTERPRISE_DEVICE, false);

    OHOS::system::SetParameter(ServiceConstants::ALLOW_ENTERPRISE_BUNDLE, "true");
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "false");

    BaseBundleInstaller installer;
    EXPECT_TRUE(installer.IsAllowEnterPrise());

    OHOS::system::SetParameter(ServiceConstants::ALLOW_ENTERPRISE_BUNDLE,
        oldA ? "true" : "false");
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE,
        oldB ? "true" : "false");
}

/**
 * @tc.number: BaseBundleInstaller_1012
 * @tc.name: test IsAllowEnterPrise when isEnterpriseDevice is true
 * @tc.desc: 1.Test IsAllowEnterPrise when allowEnterpriseBundle is false
 *           2.Test IsAllowEnterPrise when isEnterpriseDevice is true
 *           3.Cover branch !B is false
 */
HWTEST_F(BmsBundleEnterpriseDeviceTest, BaseBundleInstaller_1012, Function | SmallTest | Level0)
{
    bool oldA = OHOS::system::GetBoolParameter(
        ServiceConstants::ALLOW_ENTERPRISE_BUNDLE, false);
    bool oldB = OHOS::system::GetBoolParameter(
        ServiceConstants::IS_ENTERPRISE_DEVICE, false);

    OHOS::system::SetParameter(ServiceConstants::ALLOW_ENTERPRISE_BUNDLE, "false");
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "true");

    BaseBundleInstaller installer;
    EXPECT_TRUE(installer.IsAllowEnterPrise());

    OHOS::system::SetParameter(ServiceConstants::ALLOW_ENTERPRISE_BUNDLE,
        oldA ? "true" : "false");
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE,
        oldB ? "true" : "false");
}

/**
 * @tc.number: BaseBundleInstaller_1013
 * @tc.name: test IsAllowEnterPrise when both parameters are true
 * @tc.desc: 1.Test IsAllowEnterPrise when allowEnterpriseBundle is true
 *           2.Test IsAllowEnterPrise when isEnterpriseDevice is true
 *           3.Cover branch both parameters are true
 */
HWTEST_F(BmsBundleEnterpriseDeviceTest, BaseBundleInstaller_1013, Function | SmallTest | Level0)
{
    bool oldA = OHOS::system::GetBoolParameter(
        ServiceConstants::ALLOW_ENTERPRISE_BUNDLE, false);
    bool oldB = OHOS::system::GetBoolParameter(
        ServiceConstants::IS_ENTERPRISE_DEVICE, false);

    OHOS::system::SetParameter(ServiceConstants::ALLOW_ENTERPRISE_BUNDLE, "true");
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "true");

    BaseBundleInstaller installer;
    EXPECT_TRUE(installer.IsAllowEnterPrise());

    OHOS::system::SetParameter(ServiceConstants::ALLOW_ENTERPRISE_BUNDLE,
        oldA ? "true" : "false");
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE,
        oldB ? "true" : "false");
}

/**
 * @tc.number: UninstallPreInstallBundle_0200
 * @tc.name: test unisntall  preinstall bundle
 * @tc.desc: 1.uninstall the hap
 *           2.query bundle is revoverable or not
 */
HWTEST_F(BmsBundleEnterpriseDeviceTest, UninstallPreInstallBundle_0200, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    bool result = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(result) << "the bundle file install failed: " << bundleFile;

    // test GetForceUnisntalledUsers
    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(BUNDLE_NAME);
    dataMgr->GetPreInstallBundleInfo(BUNDLE_NAME, preInstallBundleInfo);
    std::vector<int> forceUnisntallUsers = preInstallBundleInfo.GetForceUnisntalledUsers();
    bool getForceUninstall = forceUnisntallUsers.empty();
    EXPECT_TRUE(getForceUninstall);

    // test ForceUnInstallBundle succeed
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "true");
    InstallParam installParam;
    installParam.userId = USERID;
    setuid(Constants::EDC_UID);
    installParam.parameters.emplace(Constants::VERIFY_UNINSTALL_FORCED_KEY,
        Constants::VERIFY_UNINSTALL_FORCED_VALUE);
    ErrCode uninstallRes = MockForceUnInstallBundle(BUNDLE_NAME, installParam);
    EXPECT_EQ(uninstallRes, ERR_OK);

    // test forceuninstalluser in preinstallbundleinfo
    preInstallBundleInfo.SetBundleName(BUNDLE_NAME);
    dataMgr->GetPreInstallBundleInfo(BUNDLE_NAME, preInstallBundleInfo);
    bool isForceUninstall = preInstallBundleInfo.HasForceUninstalledUser(USERID);
    EXPECT_TRUE(isForceUninstall);

    // test GetRecoverablePreInstallBundleInfos
    dataMgr->GetRecoverablePreInstallBundleInfos(USERID);

    // test recover failed and succeed
    ErrCode recoverRes = RecoverBundle(BUNDLE_NAME, installParam);
    EXPECT_NE(recoverRes, ERR_OK);
    preInstallBundleInfo.ClearForceUninstalledUsers();
    dataMgr->SavePreInstallBundleInfo(BUNDLE_NAME, preInstallBundleInfo);
    recoverRes = RecoverBundle(BUNDLE_NAME, installParam);
    EXPECT_EQ(recoverRes, ERR_OK);
    uninstallRes = MockForceUnInstallBundle(BUNDLE_NAME, installParam);
    EXPECT_EQ(uninstallRes, ERR_OK);

    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "false");
    ClearBundleInfo();
}


/**
 * @tc.number: UninstallPreInstallBundle_0400
 * @tc.name: test the wrong system bundle file can't be installed
 * @tc.desc: 1.the system bundle file don't exists
 *           2.the system bundle can't be installed and the result is fail
 */
HWTEST_F(BmsBundleEnterpriseDeviceTest, UninstallPreInstallBundle_0400, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "true");
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    bool result = InstallSystemBundle(bundleFile);
    EXPECT_TRUE(result) << "the bundle file install failed: " << bundleFile;

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = ADD_NEW_USERID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    dataMgr->AddInnerBundleUserInfo(BUNDLE_NAME, innerBundleUserInfo);

    // test multiuser force uninstall
    InstallParam installParam;
    installParam.userId = USERID;
    setuid(Constants::EDC_UID);
    installParam.parameters.emplace(Constants::VERIFY_UNINSTALL_FORCED_KEY,
        Constants::VERIFY_UNINSTALL_FORCED_VALUE);
    ErrCode res = MockForceUnInstallBundle(BUNDLE_NAME, installParam);
    EXPECT_EQ(res, ERR_OK);

    // test ClearForceUninstalledUsers and recover
    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(BUNDLE_NAME);
    preInstallBundleInfo.ClearForceUninstalledUsers();
    dataMgr->SavePreInstallBundleInfo(BUNDLE_NAME, preInstallBundleInfo);
    res = RecoverBundle(BUNDLE_NAME, installParam);
    EXPECT_EQ(res, ERR_OK);
    dataMgr->RemoveInnerBundleUserInfo(BUNDLE_NAME, ADD_NEW_USERID);
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "false");
    ClearBundleInfo();
}

/**
 * @tc.number: GetBundleNamesForNewUser_0300
 * @tc.name: test GetBundleNamesForNewUser
 */
HWTEST_F(BmsBundleEnterpriseDeviceTest, GetBundleNamesForNewUser_0300, Function | SmallTest | Level1)
{
    ResetDataMgr();
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.SetInstalledForAllUser(true);
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "true");
    dataMgr->bundleInfos_.try_emplace(BUNDLE_NAME, info);
    std::vector<std::string> ret = dataMgr->GetBundleNamesForNewUser();
    EXPECT_EQ(ret.size(), 1);
    dataMgr->bundleInfos_.clear();
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "false");
}
} // OHOS
