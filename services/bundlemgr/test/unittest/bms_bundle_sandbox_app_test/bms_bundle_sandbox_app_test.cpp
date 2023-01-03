/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "bundle_data_storage_database.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_sandbox_installer.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "system_bundle_installer.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using namespace OHOS::DistributedKv;
using namespace OHOS;
using OHOS::DelayedSingleton;

namespace {
const std::string BUNDLE_NAME = "com.example.l3jsdemo";
const std::string BUNDLE_NAME_INVALID = "";
const std::string OTHER_BUNDLE_NAME = "com.example.ohosproject.hmservice";
const std::string UNINSTALLED_BUNDLE_NAME = "com.example.l3jsdemo1";
const std::string RESOURCE_ROOT_PATH = "/data/test/resource/bms/install_bundle/";
const std::string RIGHT_BUNDLE_FIRST = "first_right.hap";
const std::string SANDBOX_TEST = "sandboxTest.hap";
const std::string BUNDLE_DATA_DIR1 = "/data/app/el1/100/base/";
const std::string BUNDLE_DATA_DIR2 = "/data/app/el1/100/database/";
const std::string BUNDLE_DATA_DIR3 = "/data/app/el2/100/base/";
const std::string BUNDLE_DATA_DIR4 = "/data/app/el2/100/database/";
const std::string BUNDLE_CODE_DIR = "/data/app/el1/bundle/public/com.example.l3jsdemo";
int32_t INVALID_DLP_TYPE = 0;
int32_t DLP_TYPE_1 = 1;
int32_t DLP_TYPE_2 = 2;
int32_t DLP_TYPE_3 = 3;
int32_t INVALID_APP_INDEX = 0;
int32_t APP_INDEX_1 = 1;
int32_t APP_INDEX_2 = 2;
const int32_t USERID = 100;
const int32_t INVALID_USERID = 300;
const int32_t TEST_UID = 20010039;
const int32_t WAIT_TIME = 5; // init mocked bms
} // namespace

class BmsSandboxAppTest : public testing::Test {
public:
    BmsSandboxAppTest();
    ~BmsSandboxAppTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    ErrCode InstallSandboxApp(const std::string &bundleName, int32_t dplType, int32_t userId, int32_t &appIndex) const;
    ErrCode UninstallSandboxApp(const std::string &bundleName, int32_t appIndex, int32_t userId) const;
    ErrCode GetSandboxAppBundleInfo(const std::string &bundleName, const int32_t &appIndex, const int32_t &userId,
        BundleInfo &info);
    ErrCode GetSandboxHapModuleInfo(const AbilityInfo &abilityInfo, int32_t appIndex, int32_t userId,
        HapModuleInfo &hapModuleInfo);
    ErrCode GetInnerBundleInfoByUid(const int32_t &uid, InnerBundleInfo &innerBundleInfo);
    ErrCode InstallBundles(const std::vector<std::string> &filePaths, bool &&flag) const;
    ErrCode UninstallBundle(const std::string &bundleName) const;
    ErrCode GetSandboxAppInfo(
        const std::string &bundleName, const int32_t &appIndex, int32_t &userId, InnerBundleInfo &info);
    bool DeleteSandboxAppIndex(const std::string &bundleName, int32_t appIndex);
    int32_t GenerateSandboxAppIndex(const std::string &bundleName);
    const std::shared_ptr<BundleSandboxAppHelper> GetBundleSandboxAppHelper() const;
    void SaveSandboxAppInfo(const InnerBundleInfo &info, const int32_t &appIndex);
    void DeleteSandboxAppInfo(const std::string &bundleName, const int32_t &appIndex);
    void CheckPathAreExisted(const std::string &bundleName, int32_t appIndex);
    void CheckPathAreNonExisted(const std::string &bundleName, int32_t appIndex);
    void ClearDataMgr();
    void SetDataMgr();

private:
    bool GetDataMgr();
    bool GetSandboxDataMgr();

    std::shared_ptr<InstalldService> installdService_ = std::make_shared<InstalldService>();
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;
    std::shared_ptr<BundleSandboxDataMgr> sandboxDataMgr_ = nullptr;
    std::shared_ptr<BundleSandboxAppHelper> bundleSandboxAppHelper_ =
        DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    const std::shared_ptr<BundleDataMgr> dataMgrInfo_ =
        DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_;
};

BmsSandboxAppTest::BmsSandboxAppTest()
{}

BmsSandboxAppTest::~BmsSandboxAppTest()
{}

void BmsSandboxAppTest::SetUpTestCase()
{
}

void BmsSandboxAppTest::TearDownTestCase()
{
}

void BmsSandboxAppTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsSandboxAppTest::TearDown()
{
}

void BmsSandboxAppTest::ClearDataMgr()
{
    bundleMgrService_->dataMgr_ = nullptr;
}

void BmsSandboxAppTest::SetDataMgr()
{
    EXPECT_NE(dataMgrInfo_, nullptr);
    bundleMgrService_->dataMgr_ = dataMgrInfo_;
    EXPECT_NE(bundleMgrService_->dataMgr_, nullptr);
}

ErrCode BmsSandboxAppTest::InstallSandboxApp(const std::string &bundleName, int32_t dplType, int32_t userId,
    int32_t &appIndex) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    return installer->InstallSandboxApp(bundleName, dplType, userId, appIndex);
}

ErrCode BmsSandboxAppTest::UninstallSandboxApp(const std::string &bundleName, int32_t appIndex, int32_t userId) const
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    return installer->UninstallSandboxApp(bundleName, appIndex, userId);
}

ErrCode BmsSandboxAppTest::GetSandboxAppBundleInfo(const std::string &bundleName, const int32_t &appIndex,
    const int32_t &userId, BundleInfo &info)
{
    bool ret = GetSandboxDataMgr();
    EXPECT_TRUE(ret);

    return sandboxDataMgr_->GetSandboxAppBundleInfo(bundleName, appIndex, userId, info);
}

ErrCode BmsSandboxAppTest::GetSandboxHapModuleInfo(const AbilityInfo &abilityInfo, int32_t appIndex, int32_t userId,
    HapModuleInfo &hapModuleInfo)
{
    bool ret = GetSandboxDataMgr();
    EXPECT_TRUE(ret);

    return sandboxDataMgr_->GetSandboxHapModuleInfo(abilityInfo, appIndex, userId, hapModuleInfo);
}

ErrCode BmsSandboxAppTest::GetInnerBundleInfoByUid(const int32_t &uid, InnerBundleInfo &innerBundleInfo)
{
    bool ret = GetSandboxDataMgr();
    EXPECT_TRUE(ret);

    return sandboxDataMgr_->GetInnerBundleInfoByUid(uid, innerBundleInfo);
}

ErrCode BmsSandboxAppTest::GetSandboxAppInfo(
    const std::string &bundleName, const int32_t &appIndex, int32_t &userId, InnerBundleInfo &info)
{
    return bundleSandboxAppHelper_->GetSandboxAppInfo(bundleName, appIndex, userId, info);
}

bool BmsSandboxAppTest::DeleteSandboxAppIndex(const std::string &bundleName, int32_t appIndex)
{
    bool ret = GetSandboxDataMgr();
    EXPECT_TRUE(ret);

    return sandboxDataMgr_->DeleteSandboxAppIndex(bundleName, appIndex);
}

const std::shared_ptr<BundleSandboxAppHelper> BmsSandboxAppTest::GetBundleSandboxAppHelper() const
{
    return bundleSandboxAppHelper_;
}

bool BmsSandboxAppTest::GetSandboxDataMgr()
{
    if (!sandboxDataMgr_) {
        if (!GetDataMgr()) {
            APP_LOGE("Get dataMgr shared_ptr failed");
            return false;
        }

        sandboxDataMgr_ = dataMgr_->GetSandboxAppHelper()->GetSandboxDataMgr();
        if (!sandboxDataMgr_) {
            APP_LOGE("Get sandbox dataMgr shared_ptr nullptr");
            return false;
        }
    }
    return true;
}

bool BmsSandboxAppTest::GetDataMgr()
{
    if (bundleMgrService_ && !dataMgr_) {
        dataMgr_ = bundleMgrService_->GetDataMgr();
        if (!dataMgr_) {
            APP_LOGE("Get dataMgr shared_ptr nullptr");
            return false;
        }
    }
    return true;
}

ErrCode BmsSandboxAppTest::InstallBundles(const std::vector<std::string> &filePaths,
    bool &&flag) const
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
    installParam.installFlag = flag ? InstallFlag::NORMAL : InstallFlag::REPLACE_EXISTING;
    bool result = installer->Install(filePaths, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsSandboxAppTest::UninstallBundle(const std::string &bundleName) const
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
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

int32_t BmsSandboxAppTest::GenerateSandboxAppIndex(const std::string &bundleName)
{
    return bundleSandboxAppHelper_->GenerateSandboxAppIndex(bundleName);
}

void BmsSandboxAppTest::SaveSandboxAppInfo(const InnerBundleInfo &info, const int32_t &appIndex)
{
    return bundleSandboxAppHelper_->SaveSandboxAppInfo(info, appIndex);
}

void BmsSandboxAppTest::DeleteSandboxAppInfo(const std::string &bundleName, const int32_t &appIndex)
{
    return bundleSandboxAppHelper_->DeleteSandboxAppInfo(bundleName, appIndex);
}

void BmsSandboxAppTest::CheckPathAreExisted(const std::string &bundleName, int32_t appIndex)
{
    auto innerBundleName = bundleName + Constants::FILE_UNDERLINE + std::to_string(appIndex);
    auto dataPath = BUNDLE_DATA_DIR1 + innerBundleName;
    int32_t ret = access(dataPath.c_str(), F_OK);
    EXPECT_EQ(ret, 0);

    dataPath = BUNDLE_DATA_DIR2 + innerBundleName;
    ret = access(dataPath.c_str(), F_OK);
    EXPECT_EQ(ret, 0);

    dataPath = BUNDLE_DATA_DIR3 + innerBundleName + "/cache";
    ret = access(dataPath.c_str(), F_OK);
    EXPECT_EQ(ret, 0);

    dataPath = BUNDLE_DATA_DIR3 + innerBundleName + "/files";
    ret = access(dataPath.c_str(), F_OK);
    EXPECT_EQ(ret, 0);

    dataPath = BUNDLE_DATA_DIR3 + innerBundleName + "/haps";
    ret = access(dataPath.c_str(), F_OK);
    EXPECT_EQ(ret, 0);

    dataPath = BUNDLE_DATA_DIR3 + innerBundleName + "/preferences";
    ret = access(dataPath.c_str(), F_OK);
    EXPECT_EQ(ret, 0);

    dataPath = BUNDLE_DATA_DIR3 + innerBundleName + "/temp";
    ret = access(dataPath.c_str(), F_OK);
    EXPECT_EQ(ret, 0);

    dataPath = BUNDLE_DATA_DIR4 + innerBundleName;
    ret = access(dataPath.c_str(), F_OK);
    EXPECT_EQ(ret, 0);
}

void BmsSandboxAppTest::CheckPathAreNonExisted(const std::string &bundleName, int32_t appIndex)
{
    auto innerBundleName = bundleName + Constants::FILE_UNDERLINE + std::to_string(appIndex);
    auto dataPath = BUNDLE_DATA_DIR1 + innerBundleName;
    int32_t ret = access(dataPath.c_str(), F_OK);
    EXPECT_NE(ret, 0);

    dataPath = BUNDLE_DATA_DIR2 + innerBundleName;
    ret = access(dataPath.c_str(), F_OK);
    EXPECT_NE(ret, 0);

    dataPath = BUNDLE_DATA_DIR3 + innerBundleName + "/cache";
    ret = access(dataPath.c_str(), F_OK);
    EXPECT_NE(ret, 0);

    dataPath = BUNDLE_DATA_DIR3 + innerBundleName + "/el3";
    ret = access(dataPath.c_str(), F_OK);
    EXPECT_NE(ret, 0);

    dataPath = BUNDLE_DATA_DIR3 + innerBundleName + "/el4";
    ret = access(dataPath.c_str(), F_OK);
    EXPECT_NE(ret, 0);

    dataPath = BUNDLE_DATA_DIR3 + innerBundleName + "/haps";
    ret = access(dataPath.c_str(), F_OK);
    EXPECT_NE(ret, 0);

    dataPath = BUNDLE_DATA_DIR3 + innerBundleName + "/preferences";
    ret = access(dataPath.c_str(), F_OK);
    EXPECT_NE(ret, 0);

    dataPath = BUNDLE_DATA_DIR3 + innerBundleName + "/temp";
    ret = access(dataPath.c_str(), F_OK);
    EXPECT_NE(ret, 0);

    dataPath = BUNDLE_DATA_DIR4 + innerBundleName;
    ret = access(dataPath.c_str(), F_OK);
    EXPECT_NE(ret, 0);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_0100
 * @tc.name: test anormal input parameters
 * @tc.desc: 1.the input bundleName is empty
 *           2.the sandbox app install failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_0100, Function | SmallTest | Level0)
{
    int32_t appIndex = 0;
    auto ret = InstallSandboxApp("", DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_0200
 * @tc.name: test anormal input parameters
 * @tc.desc: 1.the input dlp type is anormal
 *           2.the sandbox app install failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_0200, Function | SmallTest | Level0)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, INVALID_DLP_TYPE, USERID, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_0300
 * @tc.name: test anormal input parameters
 * @tc.desc: 1.the input dlp type is anormal
 *           2.the sandbox app install failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_0300, Function | SmallTest | Level0)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_3, USERID, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_0400
 * @tc.name: test anormal input parameters
 * @tc.desc: 1.the input userId is anormal
 *           2.the sandbox app install failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_0400, Function | SmallTest | Level0)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, INVALID_USERID, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_USER_NOT_EXIST);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_0500
 * @tc.name: test anormal input parameters
 * @tc.desc: 1.the input bundleName and dlp type are anormal
 *           2.the sandbox app install failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_0500, Function | SmallTest | Level0)
{
    int32_t appIndex = 0;
    auto ret = InstallSandboxApp("", INVALID_DLP_TYPE, USERID, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_0600
 * @tc.name: test anormal input parameters
 * @tc.desc: 1.the input bundleName and useId are anormal
 *           2.the sandbox app install failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_0600, Function | SmallTest | Level0)
{
    int32_t appIndex = 0;
    auto ret = InstallSandboxApp("", DLP_TYPE_1, INVALID_USERID, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
    ret = InstallSandboxApp("", DLP_TYPE_1, Constants::DEFAULT_USERID - 1, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_0700
 * @tc.name: test anormal input parameters
 * @tc.desc: 1.the input dlp type and useId are anormal
 *           2.the sandbox app install failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_0700, Function | SmallTest | Level0)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, INVALID_DLP_TYPE, INVALID_USERID, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_0800
 * @tc.name: test anormal input parameters
 * @tc.desc: 1.the input bundleName, dlp type and useId are anormal
 *           2.the sandbox app install failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_0800, Function | SmallTest | Level0)
{
    int32_t appIndex = 0;
    auto ret = InstallSandboxApp("", INVALID_DLP_TYPE, INVALID_USERID, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_0900
 * @tc.name: test original bundle has not been installed
 * @tc.desc: 1. the original bundle has not been installed
 *           2.the sandbox app install failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_0900, Function | SmallTest | Level0)
{
    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(UNINSTALLED_BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_APP_NOT_EXISTED);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_1000
 * @tc.name: test original bundle has been installed at other userId
 * @tc.desc: 1. the original bundle has been installed at other userId
 *           2.the sandbox app install failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_1000, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, INVALID_USERID, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_USER_NOT_EXIST);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_1100
 * @tc.name: test original bundle has been installed at other userId
 * @tc.desc: 1. the original bundle has been installed at other userId
 *           2.the sandbox app install failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_1100, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_2, INVALID_USERID, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_USER_NOT_EXIST);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_1200
 * @tc.name: test original bundle has been installed at other userId
 * @tc.desc: 1. the original bundle has been installed at current userId
 *           2.the sandbox app install successfully
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_1200, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_1300
 * @tc.name: test original bundle has been installed at other userId
 * @tc.desc: 1. the original bundle has been installed at current userId
 *           2.the sandbox app install successfully
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_1300, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_2, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    UninstallBundle(BUNDLE_NAME);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_1);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_1400
 * @tc.name: test install sandbox app multiple times
 * @tc.desc: 1.install sandbox app multiple times
 *           2.the sandbox app install successfully
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_1400, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile1 = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile1);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    int32_t secondAppIndex = 0;
    ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, secondAppIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(secondAppIndex, APP_INDEX_2);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_2);

    UninstallBundle(BUNDLE_NAME);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_1);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_2);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_1500
 * @tc.name: test install sandbox app multiple times
 * @tc.desc: 1.install sandbox app multiple times
 *           2.the sandbox app install successfully
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_1500, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile1 = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile1);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    int32_t secondAppIndex = 0;
    ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_2, USERID, secondAppIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(secondAppIndex, APP_INDEX_2);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_2);

    UninstallBundle(BUNDLE_NAME);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_1);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_2);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_1600
 * @tc.name: test install sandbox app multiple times
 * @tc.desc: 1.install sandbox app multiple times
 *           2.the sandbox app install successfully
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_1600, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile1 = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile1);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_2, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    int32_t secondAppIndex = 0;
    ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, secondAppIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(secondAppIndex, APP_INDEX_2);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_2);

    UninstallBundle(BUNDLE_NAME);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_1);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_2);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_1700
 * @tc.name: test install sandbox app multiple times
 * @tc.desc: 1.install sandbox app multiple times
 *           2.the sandbox app install successfully
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_1700, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile1 = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile1);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_2, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    int32_t secondAppIndex = 0;
    ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_2, USERID, secondAppIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(secondAppIndex, APP_INDEX_2);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_2);

    UninstallBundle(BUNDLE_NAME);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_1);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_2);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_1800
 * @tc.name: test install sandbox app multiple times
 * @tc.desc: 1.install sandbox app multiple times
 *           2.the sandbox app install successfully
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_1800, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile1 = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile1);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    auto bundleFile2 = RESOURCE_ROOT_PATH + SANDBOX_TEST;
    filePaths.clear();
    filePaths.emplace_back(bundleFile2);
    installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    int32_t secondAppIndex = 0;
    ret = InstallSandboxApp(OTHER_BUNDLE_NAME, DLP_TYPE_1, USERID, secondAppIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(secondAppIndex, APP_INDEX_1);
    CheckPathAreExisted(OTHER_BUNDLE_NAME, APP_INDEX_1);

    UninstallBundle(BUNDLE_NAME);
    UninstallBundle(OTHER_BUNDLE_NAME);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_1);
    CheckPathAreNonExisted(OTHER_BUNDLE_NAME, APP_INDEX_1);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_1900
 * @tc.name: test install sandbox app multiple times
 * @tc.desc: 1.install sandbox app multiple times
 *           2.the sandbox app install successfully
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_1900, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile1 = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile1);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    auto bundleFile2 = RESOURCE_ROOT_PATH + SANDBOX_TEST;
    filePaths.clear();
    filePaths.emplace_back(bundleFile2);
    installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_2, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    int32_t secondAppIndex = 0;
    ret = InstallSandboxApp(OTHER_BUNDLE_NAME, DLP_TYPE_2, USERID, secondAppIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(secondAppIndex, APP_INDEX_1);
    CheckPathAreExisted(OTHER_BUNDLE_NAME, APP_INDEX_1);

    UninstallBundle(BUNDLE_NAME);
    UninstallBundle(OTHER_BUNDLE_NAME);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_1);
    CheckPathAreNonExisted(OTHER_BUNDLE_NAME, APP_INDEX_1);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_2000
 * @tc.name: test update original bundle after installing sandbox app
 * @tc.desc: 1.update original bundle after installing sandbox app
 *           2.the sandbox app will be installed successfully
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_2000, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile1 = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile1);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    int32_t secondAppIndex = 0;
    ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, secondAppIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(secondAppIndex, APP_INDEX_2);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_2);

    installRes = InstallBundles(filePaths, false);
    EXPECT_EQ(installRes, ERR_OK);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_1);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_2);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppInstallTest_2100
 * @tc.name: test uninstall original bundle after installing sandbox app
 * @tc.desc: 1.uninstall original bundle after installing sandbox app
 *           2.the sandbox app will be installed successfully
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppInstallTest_2100, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile1 = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile1);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    int32_t secondAppIndex = 0;
    ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, secondAppIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(secondAppIndex, APP_INDEX_2);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_2);

    installRes = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installRes, ERR_OK);

    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_1);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_2);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_0100
 * @tc.name: test anormal input parameters
 * @tc.desc: 1. input bundleName is anormal
 *           2.the sandbox app will be uninstalled failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_0100, Function | SmallTest | Level0)
{
    auto ret = UninstallSandboxApp("", APP_INDEX_1, USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_0200
 * @tc.name: test anormal input parameters
 * @tc.desc: 1. input app index is anormal
 *           2.the sandbox app will be uninstalled failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_0200, Function | SmallTest | Level0)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    auto res = UninstallSandboxApp(BUNDLE_NAME, INVALID_APP_INDEX, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_0300
 * @tc.name: test anormal input parameters
 * @tc.desc: 1. input userId is anormal
 *           2.the sandbox app will be uninstalled failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_0300, Function | SmallTest | Level0)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    auto res = UninstallSandboxApp(BUNDLE_NAME, APP_INDEX_1, INVALID_USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_USER_NOT_EXIST);
    res = UninstallSandboxApp(BUNDLE_NAME, APP_INDEX_1, Constants::DEFAULT_USERID - 1);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_0400
 * @tc.name: test anormal input parameters
 * @tc.desc: 1. input bundleName and app index are anormal
 *           2.the sandbox app will be uninstalled failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_0400, Function | SmallTest | Level1)
{
    auto res = UninstallSandboxApp("", INVALID_APP_INDEX, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_0500
 * @tc.name: test anormal input parameters
 * @tc.desc: 1. input bundleName and userId are anormal
 *           2.the sandbox app will be uninstalled failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_0500, Function | SmallTest | Level1)
{
    auto res = UninstallSandboxApp("", APP_INDEX_1, INVALID_USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_0600
 * @tc.name: test anormal input parameters
 * @tc.desc: 1. input app index and userId are anormal
 *           2.the sandbox app will be uninstalled failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_0600, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    auto res = UninstallSandboxApp(BUNDLE_NAME, INVALID_APP_INDEX, INVALID_USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_0700
 * @tc.name: test anormal input parameters
 * @tc.desc: 1. input bundleName, app index and userId are anormal
 *           2.the sandbox app will be uninstalled failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_0700, Function | SmallTest | Level1)
{
    auto res = UninstallSandboxApp("", INVALID_APP_INDEX, INVALID_USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_0800
 * @tc.name: test uninstall sandbox without installing the original bundle
 * @tc.desc: 1. uninstall sandbox without installing the original bundle
 *           2.the sandbox app will be uninstalled failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_0800, Function | SmallTest | Level1)
{
    auto res = UninstallSandboxApp(UNINSTALLED_BUNDLE_NAME, APP_INDEX_1, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_NO_SANDBOX_APP_INFO);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_0900
 * @tc.name: test uninstall sandbox with installing the original bundle
 * @tc.desc: 1. uninstall sandbox without installing the sandbox
 *           2.the sandbox app will be uninstalled failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_0900, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    auto res = UninstallSandboxApp(BUNDLE_NAME, APP_INDEX_1, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_NO_SANDBOX_APP_INFO);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_1000
 * @tc.name: test uninstall sandbox with installing the original bundle
 * @tc.desc: 1. uninstall sandbox with installing the sandbox at other userId
 *           2.the sandbox app will be uninstalled failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_1000, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    auto res = UninstallSandboxApp(BUNDLE_NAME, APP_INDEX_1, INVALID_USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_USER_NOT_EXIST);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_1100
 * @tc.name: test uninstall sandbox with installing the original bundle
 * @tc.desc: 1. uninstall sandbox with installing the sandbox at current userId
 *           2.the sandbox app will be uninstalled successfully
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_1100, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    auto res = UninstallSandboxApp(BUNDLE_NAME, APP_INDEX_1, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_NO_SANDBOX_APP_INFO);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    res = UninstallSandboxApp(BUNDLE_NAME, APP_INDEX_1, USERID);
    EXPECT_EQ(res, ERR_OK);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_1200
 * @tc.name: test uninstall sandbox multiple times
 * @tc.desc: 1. uninstall sandbox multiple times
 *           2. the sandbox app will be uninstalled failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_1200, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    bundleFile = RESOURCE_ROOT_PATH + SANDBOX_TEST;
    filePaths.clear();
    filePaths.emplace_back(bundleFile);
    installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    int32_t secondAppIndex = 0;
    ret = InstallSandboxApp(OTHER_BUNDLE_NAME, DLP_TYPE_1, USERID, secondAppIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(secondAppIndex, APP_INDEX_1);
    CheckPathAreExisted(OTHER_BUNDLE_NAME, APP_INDEX_1);

    auto res = UninstallSandboxApp(BUNDLE_NAME, APP_INDEX_1, USERID);
    EXPECT_EQ(res, ERR_OK);
    CheckPathAreExisted(OTHER_BUNDLE_NAME, APP_INDEX_1);

    UninstallBundle(BUNDLE_NAME);
    UninstallBundle(OTHER_BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_1300
 * @tc.name: test uninstall sandbox multiple times
 * @tc.desc: 1. uninstall sandbox multiple times
 *           2. the sandbox app will be uninstalled failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_1300, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    bundleFile = RESOURCE_ROOT_PATH + SANDBOX_TEST;
    filePaths.clear();
    filePaths.emplace_back(bundleFile);
    installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    int32_t secondAppIndex = 0;
    ret = InstallSandboxApp(OTHER_BUNDLE_NAME, DLP_TYPE_1, USERID, secondAppIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(secondAppIndex, APP_INDEX_1);
    CheckPathAreExisted(OTHER_BUNDLE_NAME, APP_INDEX_1);

    auto res = UninstallSandboxApp(OTHER_BUNDLE_NAME, APP_INDEX_1, USERID);
    EXPECT_EQ(res, ERR_OK);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    UninstallBundle(BUNDLE_NAME);
    UninstallBundle(OTHER_BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_1400
 * @tc.name: test uninstall sandbox multiple times
 * @tc.desc: 1. uninstall sandbox multiple times
 *           2. the sandbox app will be uninstalled failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_1400, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    bundleFile = RESOURCE_ROOT_PATH + SANDBOX_TEST;
    filePaths.clear();
    filePaths.emplace_back(bundleFile);
    installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    int32_t secondAppIndex = 0;
    ret = InstallSandboxApp(OTHER_BUNDLE_NAME, DLP_TYPE_1, USERID, secondAppIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(secondAppIndex, APP_INDEX_1);
    CheckPathAreExisted(OTHER_BUNDLE_NAME, APP_INDEX_1);

    auto res = UninstallSandboxApp(BUNDLE_NAME, APP_INDEX_1, USERID);
    EXPECT_EQ(res, ERR_OK);
    CheckPathAreExisted(OTHER_BUNDLE_NAME, APP_INDEX_1);

    res = UninstallSandboxApp(OTHER_BUNDLE_NAME, APP_INDEX_1, USERID);
    EXPECT_EQ(res, ERR_OK);

    UninstallBundle(BUNDLE_NAME);
    UninstallBundle(OTHER_BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_1500
 * @tc.name: test uninstall sandbox multiple times
 * @tc.desc: 1. uninstall sandbox multiple times
 *           2. the sandbox app will be uninstalled failed
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_1500, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    bundleFile = RESOURCE_ROOT_PATH + SANDBOX_TEST;
    filePaths.clear();
    filePaths.emplace_back(bundleFile);
    installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    int32_t secondAppIndex = 0;
    ret = InstallSandboxApp(OTHER_BUNDLE_NAME, DLP_TYPE_1, USERID, secondAppIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(secondAppIndex, APP_INDEX_1);
    CheckPathAreExisted(OTHER_BUNDLE_NAME, APP_INDEX_1);

    auto res = UninstallSandboxApp(OTHER_BUNDLE_NAME, APP_INDEX_1, USERID);
    EXPECT_EQ(res, ERR_OK);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    res = UninstallSandboxApp(BUNDLE_NAME, APP_INDEX_1, USERID);
    EXPECT_EQ(res, ERR_OK);

    UninstallBundle(BUNDLE_NAME);
    UninstallBundle(OTHER_BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_1600
 * @tc.name: InstallSandboxApp
 * @tc.desc: 1.Test the interface of InstallSandboxApp
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_1600, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    auto installer = std::make_shared<BundleSandboxInstaller>();
    int32_t appIndex = 0;
    auto ret = installer->InstallSandboxApp("", DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
    int32_t userId = Constants::DEFAULT_USERID - 1;
    ret = installer->InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, userId, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_1700
 * @tc.name: InstallSandboxApp
 * @tc.desc: 1.Test the interface of InstallSandboxApp
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_1700, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    auto installer = std::make_shared<BundleSandboxInstaller>();
    ClearDataMgr();

    InnerBundleInfo info;
    installer->SandboxAppRollBack(info, USERID);
    EXPECT_EQ(installer->GetSandboxDataMgr(), ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);
    SetDataMgr();

    installer->SandboxAppRollBack(info, Constants::INVALID_USERID);
    ApplicationInfo appInfo;
    appInfo.bundleName = BUNDLE_NAME;

    InnerBundleUserInfo innerUserInfo;
    innerUserInfo.bundleUserInfo.userId = USERID;
    innerUserInfo.uid = TEST_UID;

    info.SetBaseApplicationInfo(appInfo);
    info.AddInnerBundleUserInfo(innerUserInfo);
    installer->SandboxAppRollBack(info, USERID);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsSandboxAppUnInstallTest_1800
 * @tc.name: InstallSandboxApp
 * @tc.desc: 1.Test the interface of InstallSandboxApp
 */
HWTEST_F(BmsSandboxAppTest, BmsSandboxAppUnInstallTest_1800, Function | SmallTest | Level1)
{
    auto installer = std::make_shared<BundleSandboxInstaller>();
    ClearDataMgr();

    InnerBundleInfo info;
    ErrCode res = installer->UninstallAllSandboxApps("", USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    res = installer->UninstallAllSandboxApps("bundleName", USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);
    SetDataMgr();

    res = installer->UninstallAllSandboxApps("bundleName", USERID);
    EXPECT_EQ(res, ERR_OK);

    ApplicationInfo appInfo;
    appInfo.bundleName = BUNDLE_NAME;

    InnerBundleUserInfo innerUserInfo;
    innerUserInfo.bundleUserInfo.userId = USERID;
    innerUserInfo.uid = TEST_UID;

    info.SetBaseApplicationInfo(appInfo);
    info.AddInnerBundleUserInfo(innerUserInfo);
    res = installer->UninstallAllSandboxApps(BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: BmsGETSandboxAppMSG_0100
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandbox app bundleInfo information failed by empty bundlename
 */
HWTEST_F(BmsSandboxAppTest, BmsGETSandboxAppMSG_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    BundleInfo info;
    auto testRet = GetSandboxAppBundleInfo(BUNDLE_NAME_INVALID, APP_INDEX_1, USERID, info);
    EXPECT_EQ(testRet, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsGETSandboxAppMSG_0200
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandbox app bundleInfo information failed by invalid appIndex
 */
HWTEST_F(BmsSandboxAppTest, BmsGETSandboxAppMSG_0200, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    BundleInfo info;
    auto testRet = GetSandboxAppBundleInfo(BUNDLE_NAME, INVALID_APP_INDEX, USERID, info);
    EXPECT_EQ(testRet, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsGETSandboxAppMSG_0300
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandbox app bundleInfo information failed by invalid userId
 */
HWTEST_F(BmsSandboxAppTest, BmsGETSandboxAppMSG_0300, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    BundleInfo info;
    auto testRet = GetSandboxAppBundleInfo(BUNDLE_NAME, APP_INDEX_1, INVALID_USERID, info);
    EXPECT_EQ(testRet, ERR_APPEXECFWK_SANDBOX_INSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsGETSandboxAppMSG_0400
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandbox app bundleInfo information failed
 */
HWTEST_F(BmsSandboxAppTest, BmsGETSandboxAppMSG_0400, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    BundleInfo info;
    auto testRet = GetSandboxAppBundleInfo(BUNDLE_NAME_INVALID, APP_INDEX_1, INVALID_USERID, info);
    EXPECT_EQ(testRet, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsGETSandboxAppMSG_0500
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandboxApp bundleInfo information failed
 */
HWTEST_F(BmsSandboxAppTest, BmsGETSandboxAppMSG_0500, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    BundleInfo info;
    auto testRet = GetSandboxAppBundleInfo(BUNDLE_NAME, INVALID_APP_INDEX, INVALID_USERID, info);
    EXPECT_EQ(testRet, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsGETSandboxAppMSG_0600
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandbox app bundleInfo information failed
 */
HWTEST_F(BmsSandboxAppTest, BmsGETSandboxAppMSG_0600, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    BundleInfo info;
    auto testRet = GetSandboxAppBundleInfo(BUNDLE_NAME_INVALID, INVALID_APP_INDEX, INVALID_USERID, info);
    EXPECT_EQ(testRet, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsGETSandboxAppMSG_0700
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. the sandbox app install failed
 *           2. get sandbox app bundleInfo information failed by not installed hap
 */
HWTEST_F(BmsSandboxAppTest, BmsGETSandboxAppMSG_0700, Function | SmallTest | Level1)
{
    BundleInfo info;
    auto testRet = GetSandboxAppBundleInfo(BUNDLE_NAME, APP_INDEX_1, USERID, info);
    EXPECT_EQ(testRet, ERR_APPEXECFWK_SANDBOX_INSTALL_NO_SANDBOX_APP_INFO);
}

/**
 * @tc.number: BmsGETSandboxAppMSG_0800
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. get sandbox app bundleInfo information failed by not installed sandbox app
 */
HWTEST_F(BmsSandboxAppTest, BmsGETSandboxAppMSG_0800, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    BundleInfo info;
    auto testRet = GetSandboxAppBundleInfo(BUNDLE_NAME, APP_INDEX_1, USERID, info);
    EXPECT_EQ(testRet, ERR_APPEXECFWK_SANDBOX_INSTALL_NO_SANDBOX_APP_INFO);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsGETSandboxAppMSG_0900
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install failed
 *           3. get sandbox app bundleInfo information by not installed sandbox app under the specified user
 */
HWTEST_F(BmsSandboxAppTest, BmsGETSandboxAppMSG_0900, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_2, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    BundleInfo info;
    auto testRet = GetSandboxAppBundleInfo(BUNDLE_NAME, APP_INDEX_1, INVALID_USERID, info);
    EXPECT_EQ(testRet, ERR_APPEXECFWK_SANDBOX_INSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsGETSandboxAppMSG_1000
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandbox app bundleInfo information successfully
 */
HWTEST_F(BmsSandboxAppTest, BmsGETSandboxAppMSG_1000, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    BundleInfo info;
    auto testRet = GetSandboxAppBundleInfo(BUNDLE_NAME, APP_INDEX_1, USERID, info);
    EXPECT_EQ(testRet, ERR_OK);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsGETSandboxAppMSG_1100
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandbox app bundleInfo information successfully
 */
HWTEST_F(BmsSandboxAppTest, BmsGETSandboxAppMSG_1100, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    BundleInfo info;
    auto bundleSandboxAppHelper = GetBundleSandboxAppHelper();
    auto testRet = bundleSandboxAppHelper->GetSandboxAppBundleInfo(BUNDLE_NAME, APP_INDEX_1, USERID, info);
    EXPECT_EQ(testRet, ERR_OK);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsGETSandboxAppMSG_1200
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. get sandbox app bundleInfo information failed by not install sanbox app
 */
HWTEST_F(BmsSandboxAppTest, BmsGETSandboxAppMSG_1200, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    BundleInfo info;
    auto bundleSandboxAppHelper = GetBundleSandboxAppHelper();
    auto testRet = bundleSandboxAppHelper->GetSandboxAppBundleInfo(BUNDLE_NAME, APP_INDEX_1, USERID, info);
    EXPECT_EQ(testRet, ERR_APPEXECFWK_SANDBOX_INSTALL_NO_SANDBOX_APP_INFO);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: BmsGETSandboxAppMSG_1300
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. get sandbox app bundleInfo information failed by not install sanbox app
 */
HWTEST_F(BmsSandboxAppTest, BmsGETSandboxAppMSG_1300, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    BundleInfo info;
    auto bundleSandboxAppHelper = GetBundleSandboxAppHelper();
    auto ret = bundleSandboxAppHelper->GetSandboxAppBundleInfo(
        BUNDLE_NAME, APP_INDEX_1, Constants::ALL_USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: GetSandboxHapModuleInfo_0100
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandbox app bundleInfo information failed by empty bundlename
 */
HWTEST_F(BmsSandboxAppTest, GetSandboxHapModuleInfo_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = Constants::INITIAL_APP_INDEX;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    AbilityInfo abilityInfo;
    HapModuleInfo info;

    ErrCode testRet = GetSandboxHapModuleInfo(abilityInfo, appIndex, USERID, info);
    EXPECT_NE(testRet, ERR_OK);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: GetSandboxHapModuleInfo_0100
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandbox app bundleInfo information failed by empty bundlename
 */
HWTEST_F(BmsSandboxAppTest, GetSandboxHapModuleInfo_0200, Function | SmallTest | Level1)
{
    AbilityInfo abilityInfo;
    HapModuleInfo info;
    int32_t appIndex = Constants::INITIAL_APP_INDEX;
    ErrCode testRet = GetSandboxHapModuleInfo(abilityInfo, appIndex, USERID, info);
    EXPECT_NE(testRet, ERR_OK);
    appIndex = Constants::MAX_APP_INDEX + 1;
    testRet = GetSandboxHapModuleInfo(abilityInfo, appIndex, USERID, info);
    EXPECT_NE(testRet, ERR_OK);
}

/**
 * @tc.number: GetSandboxHapModuleInfo_0100
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandbox app bundleInfo information failed by empty bundlename
 */
HWTEST_F(BmsSandboxAppTest, GetSandboxHapModuleInfo_0300, Function | SmallTest | Level1)
{
    AbilityInfo abilityInfo;
    HapModuleInfo info;
    int32_t appIndex = Constants::INITIAL_APP_INDEX;

    ErrCode testRet = GetSandboxHapModuleInfo(abilityInfo, appIndex, Constants::INITIAL_APP_INDEX, info);
    EXPECT_NE(testRet, ERR_OK);
}

/**
 * @tc.number: GetSandboxHapModuleInfo_0400
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandbox app bundleInfo information failed by empty bundlename
 */
HWTEST_F(BmsSandboxAppTest, GetSandboxHapModuleInfo_0400, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = Constants::MAX_APP_INDEX - 1;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    AbilityInfo abilityInfo;
    abilityInfo.bundleName = BUNDLE_NAME;
    HapModuleInfo info;

    auto bundleSandboxAppHelper = GetBundleSandboxAppHelper();
    ErrCode testRet = bundleSandboxAppHelper->GetSandboxHapModuleInfo(abilityInfo, appIndex, USERID, info);
    EXPECT_EQ(testRet, ERR_APPEXECFWK_SANDBOX_QUERY_NO_MODULE_INFO);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: GetSandboxHapModuleInfo_0500
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandbox app bundleInfo information failed by empty bundlename
 */
HWTEST_F(BmsSandboxAppTest, GetSandboxHapModuleInfo_0500, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = Constants::INITIAL_APP_INDEX;
    AbilityInfo abilityInfo;
    abilityInfo.bundleName = BUNDLE_NAME;

    HapModuleInfo info;

    auto bundleSandboxAppHelper = GetBundleSandboxAppHelper();
    ErrCode testRet = bundleSandboxAppHelper->GetSandboxHapModuleInfo(abilityInfo, appIndex, USERID, info);
    EXPECT_EQ(testRet, ERR_APPEXECFWK_SANDBOX_QUERY_PARAM_ERROR);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: GetInnerBundleInfoByUid_0100
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandbox app bundleInfo information success by uid
 * @tc.require: issueI5Y75O
 */
HWTEST_F(BmsSandboxAppTest, GetInnerBundleInfoByUid_0100, Function | SmallTest | Level1)
{
    ApplicationInfo appInfo;
    appInfo.bundleName = BUNDLE_NAME;

    InnerBundleUserInfo innerUserInfo;
    innerUserInfo.bundleUserInfo.userId = USERID;
    innerUserInfo.uid = TEST_UID;

    InnerBundleInfo info;
    info.SetBaseApplicationInfo(appInfo);
    info.AddInnerBundleUserInfo(innerUserInfo);

    SaveSandboxAppInfo(info, APP_INDEX_1);

    InnerBundleInfo newInfo;
    ErrCode testRet = GetInnerBundleInfoByUid(TEST_UID, newInfo);
    EXPECT_EQ(testRet, ERR_OK);
    EXPECT_EQ(newInfo.GetBundleName(), BUNDLE_NAME);

    DeleteSandboxAppInfo(BUNDLE_NAME, APP_INDEX_1);
}

/**
 * @tc.number: GetInnerBundleInfoByUid_0200
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandbox app bundleInfo information failed by empty bundlename
 */
HWTEST_F(BmsSandboxAppTest, GetInnerBundleInfoByUid_0200, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    ErrCode testRet = GetInnerBundleInfoByUid(-1, info);
    EXPECT_NE(testRet, ERR_OK);
}

/**
 * @tc.number: GetInnerBundleInfoByUid_0300
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. install a hap successfully
 *           2. the sandbox app install successfully
 *           3. get sandbox app bundleInfo information failed by wrong uid
 */
HWTEST_F(BmsSandboxAppTest, GetInnerBundleInfoByUid_0300, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_1, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(appIndex, APP_INDEX_1);
    CheckPathAreExisted(BUNDLE_NAME, APP_INDEX_1);

    InnerBundleInfo info;
    ErrCode testRet = GetInnerBundleInfoByUid(-1, info);
    EXPECT_NE(testRet, ERR_OK);

    UninstallBundle(BUNDLE_NAME);
}

/**
 * @tc.number: GetInnerBundleInfoByUid_0400
 * @tc.name: get sandbox app bundleInfo information
 * @tc.desc: 1. system run normally
 * @tc.require: issueI5Y75O
 */
HWTEST_F(BmsSandboxAppTest, GetInnerBundleInfoByUid_0400, Function | SmallTest | Level1)
{
    InnerBundleInfo info;
    auto testRet = GetBundleSandboxAppHelper();

#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
    testRet->sandboxDataMgr_ = nullptr;
    testRet->SaveSandboxAppInfo(info, APP_INDEX_1);
    testRet->DeleteSandboxAppInfo(BUNDLE_NAME, APP_INDEX_1);

    BundleInfo bundleInfo;
    auto res = testRet->GetSandboxAppBundleInfo(BUNDLE_NAME, APP_INDEX_1, USERID, bundleInfo);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR);

    res = testRet->GenerateSandboxAppIndex(BUNDLE_NAME);
    EXPECT_EQ(res, Constants::INITIAL_APP_INDEX);

    res = testRet->DeleteSandboxAppIndex(BUNDLE_NAME, APP_INDEX_1);
    EXPECT_EQ(res, false);

    int32_t userId = 100;
    testRet->GetSandboxAppInfoMap();
    res = testRet->GetSandboxAppInfo(BUNDLE_NAME, APP_INDEX_1, userId, info);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR);

    AbilityInfo abilityInfo;
    HapModuleInfo hapModuleInfo;
    res = testRet->GetSandboxHapModuleInfo(abilityInfo, APP_INDEX_1, USERID, hapModuleInfo);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR);

    res = testRet->GetInnerBundleInfoByUid(0, info);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR);

    std::shared_ptr<IBundleDataStorage> dataStorage;
    testRet->RemoveSandboxApp(dataStorage, info);

    res = testRet->InstallSandboxApp(BUNDLE_NAME, 0, USERID, APP_INDEX_1);
    EXPECT_EQ(res, ERR_APPEXECFWK_SANDBOX_INSTALL_APP_NOT_EXISTED);

    res = testRet->UninstallSandboxApp(BUNDLE_NAME, APP_INDEX_1, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);

    res = testRet->UninstallAllSandboxApps(BUNDLE_NAME, USERID);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);

    EXPECT_EQ(testRet->sandboxDataMgr_, nullptr);

    testRet->sandboxDataMgr_ = std::make_shared<BundleSandboxDataMgr>();
    EXPECT_NE(testRet->sandboxDataMgr_, nullptr);
#endif
}

/**
 * @tc.number: GenerateSandboxAppIndex_0100
 * @tc.name: test original bundle has been installed at other userId
 * @tc.desc: 1. the original bundle has been installed at current userId
 *           2.the sandbox app install successfully
 */
HWTEST_F(BmsSandboxAppTest, GenerateSandboxAppIndex_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_2, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);

    int32_t ret1 = GenerateSandboxAppIndex(BUNDLE_NAME);
    EXPECT_NE(ret1, Constants::INITIAL_APP_INDEX);

    ret1 = GenerateSandboxAppIndex("");
    EXPECT_EQ(ret1, Constants::INITIAL_APP_INDEX);

    UninstallBundle(BUNDLE_NAME);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_1);
}

/**
 * @tc.number: GetSandboxAppInfo_0100
 * @tc.name: test original bundle has been installed at other userId
 * @tc.desc: 1. the original bundle has been installed at current userId
 *           2.the sandbox app install successfully
 */
HWTEST_F(BmsSandboxAppTest, GetSandboxAppInfo_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> filePaths;
    auto bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE_FIRST;
    filePaths.emplace_back(bundleFile);
    auto installRes = InstallBundles(filePaths, true);
    EXPECT_EQ(installRes, ERR_OK);

    int32_t appIndex = 0;
    int32_t RightUserId = 100;
    InnerBundleInfo info;
    auto ret = InstallSandboxApp(BUNDLE_NAME, DLP_TYPE_2, USERID, appIndex);
    EXPECT_EQ(ret, ERR_OK);

    SaveSandboxAppInfo(info, 0);

    ErrCode ret1 = GetSandboxAppInfo(
        BUNDLE_NAME, appIndex, RightUserId, info);
    EXPECT_EQ(ret1, ERR_OK);

    RightUserId = Constants::DEFAULT_USERID - 1;
    ret1 = GetSandboxAppInfo(
        BUNDLE_NAME, appIndex, RightUserId, info);
    EXPECT_EQ(ret1, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
    DeleteSandboxAppInfo("", 0);

    DeleteSandboxAppInfo(BUNDLE_NAME, 0);
    UninstallBundle(BUNDLE_NAME);
    CheckPathAreNonExisted(BUNDLE_NAME, APP_INDEX_1);
}

/**
 * @tc.number: DeleteSandboxAppIndex_001
 * @tc.name: ConvertResourcePath
 * @tc.desc: 1.Test the interface of ConvertResourcePath
 */
HWTEST_F(BmsSandboxAppTest, GetSandboxAppInfo_0200, Function | SmallTest | Level1)
{
    std::string bundleName = "";
    int32_t appIndex = 0;
    bool ret = DeleteSandboxAppIndex(bundleName, appIndex);
    EXPECT_EQ(ret, false);
}