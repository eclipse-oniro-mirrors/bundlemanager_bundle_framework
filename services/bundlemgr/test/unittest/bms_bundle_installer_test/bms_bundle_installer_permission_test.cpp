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

#define private public
#define protected public
#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
#include "app_control_manager_host_impl.h"
#include "app_control_constants.h"
#endif
#ifdef APP_DOMAIN_VERIFY_ENABLED
#include "app_domain_verify_mgr_client.h"
#endif
#include "app_service_fwk/app_service_fwk_installer.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "install_param.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "scope_guard.h"
#include "shared/shared_bundle_installer.h"
#include "system_bundle_installer.h"
#include "want.h"
#include "file_ex.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.l3jsdemo";
const std::string BUNDLE_DATA_DIR = "/data/app/el2/100/base/com.example.l3jsdemo";
const std::string BUNDLE_CODE_DIR = "/data/app/el1/bundle/public/com.example.l3jsdemo";
const int32_t USERID = 100;
const int32_t WAIT_TIME = 5; // init mocked bms
const std::string BUNDLE_LIBRARY_PATH_DIR = "/data/app/el1/bundle/public/com.example.l3jsdemo/libs/arm";
}  // namespace

class BmsBundleInstallerPermissionTest : public testing::Test {
public:
    BmsBundleInstallerPermissionTest();
    ~BmsBundleInstallerPermissionTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    bool InstallSystemBundle(const std::string &filePath) const;
    bool OTAInstallSystemBundle(const std::string &filePath) const;
    void CheckFileExist() const;
    void CheckFileNonExist() const;
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    const std::shared_ptr<BundleInstallerManager> GetBundleInstallerManager() const;
    void StopInstalldService() const;
    void StopBundleService();
    ErrCode InstallThirdPartyBundle(const std::string &filePath) const;
    ErrCode UpdateThirdPartyBundle(const std::string &filePath) const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    void CreateInstallerManager();
    void ClearBundleInfo();
    void ClearDataMgr();
    void ResetDataMgr();

private:
    std::shared_ptr<BundleInstallerManager> manager_ = nullptr;
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleInstallerPermissionTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleInstallerPermissionTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleInstallerPermissionTest::BmsBundleInstallerPermissionTest()
{}

BmsBundleInstallerPermissionTest::~BmsBundleInstallerPermissionTest()
{}

bool BmsBundleInstallerPermissionTest::InstallSystemBundle(const std::string &filePath) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    auto installer = std::make_unique<SystemBundleInstaller>();
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.needSendEvent = false;
    installParam.needSavePreInstallInfo = true;
    installParam.isPreInstallApp = true;
    installParam.noSkipsKill = false;
    installParam.copyHapToInstallPath = false;
    return installer->InstallSystemBundle(
        filePath, installParam, Constants::AppType::SYSTEM_APP) == ERR_OK;
}

bool BmsBundleInstallerPermissionTest::OTAInstallSystemBundle(const std::string &filePath) const
{
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    auto installer = std::make_unique<SystemBundleInstaller>();
    std::vector<std::string> filePaths;
    filePaths.push_back(filePath);
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.needSendEvent = false;
    installParam.needSavePreInstallInfo = true;
    installParam.isPreInstallApp = true;
    installParam.noSkipsKill = false;
    installParam.copyHapToInstallPath = false;
    return installer->OTAInstallSystemBundle(
        filePaths, installParam, Constants::AppType::SYSTEM_APP) == ERR_OK;
}

ErrCode BmsBundleInstallerPermissionTest::InstallThirdPartyBundle(const std::string &filePath) const
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
    bool result = installer->Install(filePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleInstallerPermissionTest::UpdateThirdPartyBundle(const std::string &filePath) const
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
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    bool result = installer->Install(filePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsBundleInstallerPermissionTest::UnInstallBundle(const std::string &bundleName) const
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

void BmsBundleInstallerPermissionTest::SetUpTestCase()
{
}

void BmsBundleInstallerPermissionTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleInstallerPermissionTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleInstallerPermissionTest::TearDown()
{
    OHOS::ForceRemoveDirectory(BUNDLE_DATA_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_CODE_DIR);
    OHOS::ForceRemoveDirectory(BUNDLE_LIBRARY_PATH_DIR);
}

void BmsBundleInstallerPermissionTest::CheckFileExist() const
{
    int bundleCodeExist = access(BUNDLE_CODE_DIR.c_str(), F_OK);
    EXPECT_EQ(bundleCodeExist, 0) << "the bundle code dir does not exists: " << BUNDLE_CODE_DIR;

    int bundleDataExist = access(BUNDLE_DATA_DIR.c_str(), F_OK);
    EXPECT_EQ(bundleDataExist, 0) << "the bundle data dir does not exists: " << BUNDLE_DATA_DIR;
}

void BmsBundleInstallerPermissionTest::CheckFileNonExist() const
{
    int bundleCodeExist = access(BUNDLE_CODE_DIR.c_str(), F_OK);
    EXPECT_NE(bundleCodeExist, 0) << "the bundle code dir exists: " << BUNDLE_CODE_DIR;

    int bundleDataExist = access(BUNDLE_DATA_DIR.c_str(), F_OK);
    EXPECT_NE(bundleDataExist, 0) << "the bundle data dir exists: " << BUNDLE_DATA_DIR;
}

const std::shared_ptr<BundleDataMgr> BmsBundleInstallerPermissionTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

const std::shared_ptr<BundleInstallerManager> BmsBundleInstallerPermissionTest::GetBundleInstallerManager() const
{
    return manager_;
}

void BmsBundleInstallerPermissionTest::ClearDataMgr()
{
    bundleMgrService_->dataMgr_ = nullptr;
}

void BmsBundleInstallerPermissionTest::ResetDataMgr()
{
    bundleMgrService_->dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(bundleMgrService_->dataMgr_, nullptr);
}

void BmsBundleInstallerPermissionTest::StopInstalldService() const
{
    if (installdService_->IsServiceReady()) {
        installdService_->Stop();
        InstalldClient::GetInstance()->ResetInstalldProxy();
    }
}

void BmsBundleInstallerPermissionTest::StopBundleService()
{
    if (bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStop();
        bundleMgrService_.reset();
    }
}

void BmsBundleInstallerPermissionTest::CreateInstallerManager()
{
    if (manager_ != nullptr) {
        return;
    }
    manager_ = std::make_shared<BundleInstallerManager>();
    EXPECT_NE(nullptr, manager_);
}

void BmsBundleInstallerPermissionTest::ClearBundleInfo()
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

/**
 * @tc.number: ExtractHnpFiles_0100
 * @tc.name: test ExtractHnpFiles
 * @tc.desc: 1.Test the ExtractHnpFiles of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, ExtractHnpFiles_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    std::string hnpPackageInfo;
    ExtractParam extractParam;
    auto ret = installdHostImpl.ExtractHnpFiles(hnpPackageInfo, extractParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: ProcessBundleInstallNative_0100
 * @tc.name: test ProcessBundleInstallNative_0100
 * @tc.desc: 1.Test the ProcessBundleInstallNative of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, ProcessBundleInstallNative_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    std::string userId = std::to_string(USERID);
    std::string cpuAbi = "arm64";
    std::string packageName = "com.example.test";
    std::string hnpRootPath = "/data/app/el1/bundle/public/com.example.test/entry_tmp/hnp_tmp_extract_dir/";
    std::string hapPath = "/system/app/module01/module01.hap";
    auto ret = installdHostImpl.ProcessBundleInstallNative(userId, hnpRootPath, hapPath, cpuAbi, packageName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: ProcessBundleUnInstallNative_0100
 * @tc.name: test ProcessBundleUnInstallNative
 * @tc.desc: 1.Test the ProcessBundleUnInstallNative of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, ProcessBundleUnInstallNative_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    std::string userId = std::to_string(USERID);
    std::string packageName = "com.example.test";
    auto ret = installdHostImpl.ProcessBundleUnInstallNative(userId, packageName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: PendSignAOT_0100
 * @tc.name: test PendSignAOT
 * @tc.desc: 1.Test the PendSignAOT of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, PendSignAOT_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    std::string anFileName;
    std::vector<uint8_t> signData;
    auto ret = installdHostImpl.PendSignAOT(anFileName, signData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
    ret = installdHostImpl.StopAOT();
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: CreateBundleDataDirWithVector_0100
 * @tc.name: test CreateBundleDataDirWithVector
 * @tc.desc: test CreateBundleDataDirWithVector of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, CreateBundleDataDirWithVector_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    std::vector<CreateDirParam> createDirParams;
    auto ret = installdHostImpl.CreateBundleDataDirWithVector(createDirParams);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);

    CreateDirParam createDirParam;
    createDirParams.push_back(createDirParam);
    ret = installdHostImpl.CreateBundleDataDirWithVector(createDirParams);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: GetBundleCachePath_0100
 * @tc.name: test GetBundleCachePath
 * @tc.desc: 1.Test the GetBundleCachePath of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, GetBundleCachePath_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    std::string dir;
    std::vector<std::string> cachePath;
    auto ret = installdHostImpl.GetBundleCachePath(dir, cachePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: CreateExtensionDataDir_0100
 * @tc.name: test CreateExtensionDataDir
 * @tc.desc: 1.Test the CreateExtensionDataDir of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, CreateExtensionDataDir_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    CreateDirParam createDirParam;
    auto ret = installdHostImpl.CreateExtensionDataDir(createDirParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: GetFileStat_0100
 * @tc.name: test GetFileStat
 * @tc.desc: test GetFileStat of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, GetFileStat_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    std::string file = "test.file";
    FileStat fileStat;
    ErrCode ret = installdHostImpl.GetFileStat(file, fileStat);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: VerifyCodeSignature_0100
 * @tc.name: test VerifyCodeSignature
 * @tc.desc: 1.Test the VerifyCodeSignature of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, VerifyCodeSignature_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = "";
    ErrCode ret = installdHostImpl.VerifyCodeSignature(codeSignatureParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: GetNativeLibraryFileNames_0100
 * @tc.name: test GetNativeLibraryFileNames
 * @tc.desc: 1.Test the GetNativeLibraryFileNames of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, GetNativeLibraryFileNames_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    std::vector<std::string> fileNames;
    std::string filePath = "/data/test/xxx.hap";
    std::string cpuAbi = "libs/arm";

    ErrCode ret = installdHostImpl.GetNativeLibraryFileNames(filePath, cpuAbi, fileNames);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: CheckEncryption_0100
 * @tc.name: test CheckEncryption
 * @tc.desc: 1.Test the CheckEncryption of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, CheckEncryption_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    CheckEncryptionParam checkEncryptionParam;
    checkEncryptionParam.modulePath = "";
    bool isEncrypted = false;
    ErrCode ret = installdHostImpl.CheckEncryption(checkEncryptionParam, isEncrypted);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: ExtractDriverSoFiles_0100
 * @tc.name: test ExtractDriverSoFiles
 * @tc.desc: 1.Test the ExtractDriverSoFiles of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, ExtractDriverSoFiles_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    std::unordered_multimap<std::string, std::string> dirMap;
    std::string srcPath = "test.src.psth";
    ErrCode ret = installdHostImpl.ExtractDriverSoFiles(srcPath, dirMap);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: ExtractDiffFiles_0100
 * @tc.name: test ExtractDiffFiles
 * @tc.desc: test ExtractDiffFiles of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, ExtractDiffFiles_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    std::string filePath;
    std::string targetPath = "test.target.path";
    std::string cpuAbi;
    ErrCode ret = installdHostImpl.ExtractDiffFiles(filePath, targetPath, cpuAbi);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    filePath = "test.permission.path";
    ret = installdHostImpl.ExtractDiffFiles(filePath, targetPath, cpuAbi);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: ApplyDiffPatch_0100
 * @tc.name: test ApplyDiffPatch
 * @tc.desc: test ApplyDiffPatch of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, ApplyDiffPatch_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    std::string oldSoPath = "test.old.so.path";
    std::string diffFilePath;
    std::string newSoPath = "new.so.path";
    int32_t uid = -1;
    ErrCode ret = installdHostImpl.ApplyDiffPatch(oldSoPath, diffFilePath, newSoPath, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    diffFilePath = "test.diff.file.path";
    ret = installdHostImpl.ApplyDiffPatch(oldSoPath, diffFilePath, newSoPath, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}
} // OHOS
