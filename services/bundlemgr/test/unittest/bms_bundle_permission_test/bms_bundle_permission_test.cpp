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
#include <cstdint>
#define private public
#define protected public

#include <gtest/gtest.h>

#include <chrono>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string PACKAGE_NAME = "com.test.debug.update";
const std::string BUNDLE_NAME = "com.test.debug.update";
const std::string BUNDLE_FILE_DIR = "/data/test/resource/bms/install_bundle/";
const std::string ENTRY_BUNDLE = "entry_hap.hap";
const std::string ENTRY2_BUNDLE = "entry2_hap.hap";
const std::string FEATURE_BUNDLE = "feature_hap.hap";
const std::string FEATURE2_BUNDLE = "feature2_hap.hap";
const std::string BUNDLE_DATA_DIR = "/data/app/el2/100/base/com.test.debug.update";
const std::string BUNDLE_CODE_DIR = "/data/app/el1/bundle/public/com.test.debug.update";
const std::string SEPARATOR = "/";
const std::chrono::seconds SLEEP_TIME {2};
const int32_t USERID = 100;
const uint32_t VERSION_1 = 1000001;
const uint32_t VERSION_2 = 1000002;
const int32_t MAX_TRY_TIMES = 1000;
const int32_t WAIT_TIME = 5; // init mocked bms
}  // namespace

class BmsBundlePermissionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UninstallBundle(const std::string &bundleName) const;
    ErrCode UpdateBundle(const std::string &bundlePath) const;
    ErrCode UpdateBundle(const std::string &bundlePath, const bool needCheckInfo) const;

    void StopInstalldService() const;
    void StartInstalldService() const;
    void StopBundleService() const;

    bool CheckApplicationInfo() const;
    std::vector<RequestPermission> getBundlePermissions() const;
    bool CheckBundlePermissions(bool notZero) const;

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundlePermissionTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundlePermissionTest::installdService_ =
    std::make_shared<InstalldService>();

void BmsBundlePermissionTest::SetUpTestCase()
{
}

void BmsBundlePermissionTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
}

void BmsBundlePermissionTest::SetUp()
{
    installdService_->Start();
    if (!DelayedSingleton<BundleMgrService>::GetInstance()->IsServiceReady()) {
        DelayedSingleton<BundleMgrService>::GetInstance()->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundlePermissionTest::TearDown()
{
    // clear files.
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_CODE_DIR);
}

const std::shared_ptr<BundleDataMgr> BmsBundlePermissionTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

ErrCode BmsBundlePermissionTest::InstallBundle(const std::string &bundlePath) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
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
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundlePermissionTest::UninstallBundle(const std::string &bundleName) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
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

ErrCode BmsBundlePermissionTest::UpdateBundle(const std::string &bundlePath) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
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
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundlePermissionTest::UpdateBundle(const std::string &bundlePath, const bool needCheckInfo) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
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
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);

    // check can not access the application info between updating.
    if (needCheckInfo) {
        bool isBlock = false;
        for (int32_t i = 0; i < MAX_TRY_TIMES; i++) {
            std::this_thread::sleep_for(10ms);
            bool isExist = CheckApplicationInfo();
            if (isExist) {
                isBlock = true;
                break;
            }
        }
        if (!isBlock) {
            EXPECT_FALSE(true) << "the bundle info is not disable during updating";
            return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
        }
    }

    return receiver->GetResultCode();
}

void BmsBundlePermissionTest::StopInstalldService() const
{
    installdService_->Stop();
    InstalldClient::GetInstance()->ResetInstalldProxy();
}

void BmsBundlePermissionTest::StartInstalldService() const
{
    installdService_->Start();
}

void BmsBundlePermissionTest::StopBundleService() const
{
    DelayedSingleton<BundleMgrService>::GetInstance()->OnStop();
}

bool BmsBundlePermissionTest::CheckApplicationInfo() const
{
    ApplicationInfo info;
    auto dataMgr = GetBundleDataMgr();
    if (dataMgr == nullptr) {
        return false;
    }
    bool result = dataMgr->GetApplicationInfo(PACKAGE_NAME, ApplicationFlag::GET_BASIC_APPLICATION_INFO, USERID, info);
    return result;
}

std::vector<RequestPermission> BmsBundlePermissionTest::getBundlePermissions() const
{
    std::vector<RequestPermission> emptyList = {};
    auto dataMgr = GetBundleDataMgr();
    if (dataMgr == nullptr) {
        return emptyList;
    }
    BundleInfo bundleInfo;
    uint32_t flag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION);
    bool result = dataMgr->GetBundleInfo(PACKAGE_NAME, flag, bundleInfo, 100);
    if (result) {
        return bundleInfo.reqPermissionDetails;
    }
    return emptyList;
}

bool BmsBundlePermissionTest::CheckBundlePermissions(bool notZero) const
{
    std::vector<RequestPermission> permissions = getBundlePermissions();
    if (permissions.empty()) {
        return false;
    }
    for (const auto &item : permissions) {
        if (notZero) {
            if (item.reasonId == 0) {
                return false;
            }
        } else {
            if (item.reasonId != 0) {
                return false;
            }
        }
    }
    return true;
}

/**
 * @tc.number: CheckBundlePermission_0100
 * @tc.name: test CheckBundlePermission
 * @tc.desc: test install 1 module
 */
HWTEST_F(BmsBundlePermissionTest, CheckBundlePermission_0100, Function | SmallTest | Level2)
{
    bool notZero = true;
    bool isZero = false;
    ErrCode installResult = InstallBundle(BUNDLE_FILE_DIR + ENTRY_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(notZero));

    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);

    installResult = InstallBundle(BUNDLE_FILE_DIR + ENTRY2_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(isZero));

    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);

    installResult = InstallBundle(BUNDLE_FILE_DIR + FEATURE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(notZero));

    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);

    installResult = InstallBundle(BUNDLE_FILE_DIR + FEATURE2_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(isZero));

    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);
}

/**
 * @tc.number: CheckBundlePermission_0200
 * @tc.name: test CheckBundlePermission
 * @tc.desc: test install multi module
 */
HWTEST_F(BmsBundlePermissionTest, CheckBundlePermission_0200, Function | SmallTest | Level2)
{
    bool notZero = true;
    bool isZero = false;
    ErrCode installResult = InstallBundle(BUNDLE_FILE_DIR + ENTRY_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(notZero));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + FEATURE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(notZero));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + FEATURE2_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(notZero));

    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);

    installResult = InstallBundle(BUNDLE_FILE_DIR + ENTRY2_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(isZero));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + FEATURE2_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(isZero));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + FEATURE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(notZero));

    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);

    installResult = InstallBundle(BUNDLE_FILE_DIR + FEATURE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(notZero));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + ENTRY2_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(notZero));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + FEATURE2_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(notZero));

    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);

    installResult = InstallBundle(BUNDLE_FILE_DIR + FEATURE2_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(isZero));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + ENTRY2_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(isZero));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + FEATURE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(notZero));

    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);

    installResult = InstallBundle(BUNDLE_FILE_DIR + FEATURE2_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(isZero));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + ENTRY_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(notZero));

    installResult = UpdateBundle(BUNDLE_FILE_DIR + FEATURE_BUNDLE);
    EXPECT_EQ(installResult, ERR_OK);
    EXPECT_TRUE(CheckBundlePermissions(notZero));

    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);
}
} // OHOS
