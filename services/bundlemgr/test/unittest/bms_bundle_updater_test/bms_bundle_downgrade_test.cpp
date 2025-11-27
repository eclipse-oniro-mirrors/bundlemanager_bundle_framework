/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <chrono>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "common_tool.h"
#include "directory_ex.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.l3jsdemo";
const std::string BUNDLE_FILE_DIR = "/data/test/resource/bms/downgrade_bundle/";
const std::string V1_BUNDLE_SYSTEM = "version1.hap";
const std::string V2_BUNDLE_SYSTEM = "version2.hap";
const std::string V1_BUNDLE_NORMAL = "versionNormalHapTest1.hap";
const std::string V2_BUNDLE_NORMAL = "versionNormalHapTest2.hap";
const std::string BUNDLE_DATA_DIR = "/data/app/el2/100/base/com.example.l3jsdemo";
const std::string BUNDLE_CODE_DIR = "/data/app/el1/bundle/public/com.example.l3jsdemo";
const int32_t USERID = 100;
const uint32_t VERSION_1 = 1;
const uint32_t VERSION_2 = 2;
const int32_t WAIT_TIME = 2; // init mocked bms
}  // namespace

class BmsBundleDowngradeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UninstallBundle(const std::string &bundleName) const;
    ErrCode UpdateBundle(const std::string &bundlePath, bool downgrade = false) const;

    void StopInstalldService() const;
    void StartInstalldService() const;
    void StopBundleService() const;

    void CheckFileExist() const;
    bool CheckApplicationInfo() const;
    bool CheckBundleInfo(const uint32_t versionCode, const bool needCheckVersion) const;

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleDowngradeTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleDowngradeTest::installdService_ =
    std::make_shared<InstalldService>();

void BmsBundleDowngradeTest::SetUpTestCase()
{
}

void BmsBundleDowngradeTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
}

void BmsBundleDowngradeTest::SetUp()
{
    installdService_->Start();
    if (!DelayedSingleton<BundleMgrService>::GetInstance()->IsServiceReady()) {
        DelayedSingleton<BundleMgrService>::GetInstance()->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleDowngradeTest::TearDown()
{
    // clear files.
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_CODE_DIR);
}

const std::shared_ptr<BundleDataMgr> BmsBundleDowngradeTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

ErrCode BmsBundleDowngradeTest::InstallBundle(const std::string &bundlePath) const
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

ErrCode BmsBundleDowngradeTest::UninstallBundle(const std::string &bundleName) const
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

ErrCode BmsBundleDowngradeTest::UpdateBundle(
    const std::string &bundlePath, bool downgrade) const
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
    if (downgrade) {
        installParam.parameters[ServiceConstants::BMS_PARA_INSTALL_ALLOW_DOWNGRADE] = ServiceConstants::BMS_TRUE;
    }
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

void BmsBundleDowngradeTest::StopInstalldService() const
{
    installdService_->Stop();
    InstalldClient::GetInstance()->ResetInstalldProxy();
}

void BmsBundleDowngradeTest::StartInstalldService() const
{
    installdService_->Start();
}

void BmsBundleDowngradeTest::StopBundleService() const
{
    DelayedSingleton<BundleMgrService>::GetInstance()->OnStop();
}

void BmsBundleDowngradeTest::CheckFileExist() const
{
    CommonTool tool;
    bool isCodeExist = tool.CheckFilePathISExist(BUNDLE_CODE_DIR);
    EXPECT_TRUE(isCodeExist);
    bool isDataExist = tool.CheckFilePathISExist(BUNDLE_DATA_DIR);
    EXPECT_TRUE(isDataExist);
}

bool BmsBundleDowngradeTest::CheckBundleInfo(const uint32_t versionCode, const bool needCheckVersion) const
{
    BundleInfo info;
    auto dataMgr = GetBundleDataMgr();
    if (dataMgr == nullptr) {
        return false;
    }
    bool isExist = dataMgr->GetBundleInfo(BUNDLE_NAME, BundleFlag::GET_BUNDLE_DEFAULT, info, USERID);
    if (!isExist) {
        return false;
    }
    if (needCheckVersion) {
        if (info.versionCode != versionCode) {
            return false;
        }
    }
    return true;
}

/**
 * @tc.number: BmsBundleDowngradeTest_0010
 * @tc.name: test the lower version bundle can't be updated
 * @tc.desc: 1. the bundle file is the lower version
 *           2. the bundle can't be updated and the result is fail
 */
HWTEST_F(BmsBundleDowngradeTest, BmsBundleDowngradeTest_0010, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(BUNDLE_FILE_DIR + V2_BUNDLE_SYSTEM);
    EXPECT_EQ(installResult, ERR_OK);

    ErrCode updateResult = UpdateBundle(BUNDLE_FILE_DIR + V1_BUNDLE_SYSTEM);
    EXPECT_EQ(updateResult, ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);

    EXPECT_TRUE(CheckBundleInfo(VERSION_2, true));
    CheckFileExist();
    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleDowngradeTest_0020
 * @tc.name: test the lower version bundle can't be updated
 * @tc.desc: 1. the bundle file is the lower version
 *           2. test allow install downgrade, system app not allow downgrade
 */
HWTEST_F(BmsBundleDowngradeTest, BmsBundleDowngradeTest_0020, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(BUNDLE_FILE_DIR + V2_BUNDLE_SYSTEM);
    EXPECT_EQ(installResult, ERR_OK);

    ErrCode updateResult = UpdateBundle(BUNDLE_FILE_DIR + V1_BUNDLE_SYSTEM, true);
    EXPECT_EQ(updateResult, ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);

    EXPECT_TRUE(CheckBundleInfo(VERSION_2, true));
    CheckFileExist();
    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleDowngradeTest_0030
 * @tc.name: test the lower version bundle can't be updated
 * @tc.desc: 1. the bundle file is the lower version
 *           2. the bundle can't be updated and the result is fail
 */
HWTEST_F(BmsBundleDowngradeTest, BmsBundleDowngradeTest_0030, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(BUNDLE_FILE_DIR + V2_BUNDLE_SYSTEM);
    EXPECT_EQ(installResult, ERR_OK);

    ErrCode updateResult = UpdateBundle(BUNDLE_FILE_DIR + V1_BUNDLE_NORMAL);
    EXPECT_EQ(updateResult, ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);

    EXPECT_TRUE(CheckBundleInfo(VERSION_2, true));
    CheckFileExist();
    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleDowngradeTest_0040
 * @tc.name: test the lower version bundle can't be updated
 * @tc.desc: 1. the bundle file is the lower version
 *           2. test allow install downgrade
 */
HWTEST_F(BmsBundleDowngradeTest, BmsBundleDowngradeTest_0040, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(BUNDLE_FILE_DIR + V2_BUNDLE_NORMAL);
    EXPECT_EQ(installResult, ERR_OK);

    ErrCode updateResult = UpdateBundle(BUNDLE_FILE_DIR + V1_BUNDLE_NORMAL, true);
    EXPECT_EQ(updateResult, ERR_OK);

    EXPECT_TRUE(CheckBundleInfo(VERSION_1, true));
    CheckFileExist();
    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);
}

/**
 * @tc.number: BmsBundleDowngradeTest_0050
 * @tc.name: test the lower version bundle can't be updated
 * @tc.desc: 1. the bundle file is the lower version
 *           2. test allow install downgrade
 */
HWTEST_F(BmsBundleDowngradeTest, BmsBundleDowngradeTest_0050, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(BUNDLE_FILE_DIR + V2_BUNDLE_NORMAL);
    EXPECT_EQ(installResult, ERR_OK);

    ErrCode updateResult = UpdateBundle(BUNDLE_FILE_DIR + V1_BUNDLE_SYSTEM, true);
    EXPECT_EQ(updateResult, ERR_OK);

    EXPECT_TRUE(CheckBundleInfo(VERSION_1, true));
    CheckFileExist();
    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);
}
} // OHOS
