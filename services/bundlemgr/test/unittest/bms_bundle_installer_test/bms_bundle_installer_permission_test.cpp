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
#include "app_provision_info_manager.h"
#include "app_service_fwk/app_service_fwk_installer.h"
#include "bundle_clone_installer.h"
#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_multiuser_installer.h"
#include "bundle_sandbox_data_mgr.h"
#include "bundle_sandbox_installer.h"
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
    ErrCode UnInstallBundle(const std::string &bundleName, bool keepData = false) const;
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
    setuid(Constants::FOUNDATION_UID);
    installParam.SetKillProcess(false);
    setuid(Constants::ROOT_UID);
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
    setuid(Constants::FOUNDATION_UID);
    installParam.SetKillProcess(false);
    setuid(Constants::ROOT_UID);
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

ErrCode BmsBundleInstallerPermissionTest::UnInstallBundle(const std::string &bundleName, bool keepData) const
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
    installParam.isKeepData = keepData;
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

/**
 * @tc.number: GetDiskUsage_0100
 * @tc.name: test GetDiskUsage
 * @tc.desc: 1.Test the GetDiskUsage of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, GetDiskUsage_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    std::string dir;
    bool isRealPath = false;
    int64_t statSize = 0;
    ErrCode ret = installdHostImpl.GetDiskUsage(dir, statSize, isRealPath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: GetDiskUsageFromPath_0100
 * @tc.name: test GetDiskUsageFromPath
 * @tc.desc: 1.Test the GetDiskUsageFromPath of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, GetDiskUsageFromPath_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    std::vector<std::string> path;
    int64_t statSize = 0;
    ErrCode ret = installdHostImpl.GetDiskUsageFromPath(path, statSize);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: CleanBundleDataDirByName_0100
 * @tc.name: test CleanBundleDataDirByName
 * @tc.desc: 1.Test the CleanBundleDataDirByName of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, CleanBundleDataDirByName_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    int userId = 100;
    int appIndex = 1;
    ErrCode result = installdHostImpl.CleanBundleDataDirByName(BUNDLE_NAME, userId, appIndex);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: GetAllBundleStats_0100
 * @tc.name: test GetAllBundleStats
 * @tc.desc: 1.Test the GetAllBundleStats of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, GetAllBundleStats_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::vector<int64_t> bundleStats = { 0 };
    std::vector<int32_t> uids;
    auto ret = hostImpl.GetAllBundleStats(0, bundleStats, uids);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: RemoveExtensionDir_0100
 * @tc.name: test RemoveExtensionDir
 * @tc.desc: 1.Test the RemoveExtensionDir of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, RemoveExtensionDir_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    int userId = 100;
    std::vector<std::string> extensionBundleDirs;
    auto ret = hostImpl.RemoveExtensionDir(userId, extensionBundleDirs);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: IsExistExtensionDir_0100
 * @tc.name: test IsExistExtensionDir
 * @tc.desc: 1.Test the IsExistExtensionDir of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, IsExistExtensionDir_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    int32_t userId = 100;
    std::string extensionBundleDir;
    bool isExist = false;
    auto ret = hostImpl.IsExistExtensionDir(userId, extensionBundleDir, isExist);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: GetExtensionSandboxTypeList_0100
 * @tc.name: test GetExtensionSandboxTypeList
 * @tc.desc: 1.Test the GetExtensionSandboxTypeList of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, GetExtensionSandboxTypeList_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    std::vector<std::string> typeList;
    ErrCode ret = installdHostImpl.GetExtensionSandboxTypeList(typeList);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: DeleteEncryptionKeyId_0100
 * @tc.name: test DeleteEncryptionKeyId
 * @tc.desc: 1.Test the DeleteEncryptionKeyId of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, DeleteEncryptionKeyId_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl installdHostImpl;
    std::string bundleName = "com.example.testbundle";
    int32_t userId = USERID;
    EncryptionParam encryptionParam(bundleName, "", 0, userId, EncryptionDirType::APP);
    ErrCode ret = installdHostImpl.DeleteEncryptionKeyId(encryptionParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: CopyFiles_0100
 * @tc.name: test CopyFiles
 * @tc.desc: 1.Test the CopyFiles of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, CopyFiles_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::string sourceDir = "test.source.dir";
    std::string destinationDir = "test.destination.dir";
    ErrCode ret = hostImpl.CopyFiles(sourceDir, destinationDir);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: ObtainQuickFixFileDir_0100
 * @tc.name: test ObtainQuickFixFileDir
 * @tc.desc: 1.Test the ObtainQuickFixFileDir of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, ObtainQuickFixFileDir_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::string dir = "test.dir";
    std::vector<std::string> dirVec;
    ErrCode ret = hostImpl.ObtainQuickFixFileDir(dir, dirVec);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: MoveFiles_0100
 * @tc.name: test MoveFiles
 * @tc.desc: 1.Test the MoveFiles of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, MoveFiles_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::string srcDir = "test.src.dir";
    std::string desDir = "test.des.dir";
    ErrCode ret = hostImpl.MoveFiles(srcDir, desDir);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: SetEncryptionPolicy_0100
 * @tc.name: test SetEncryptionPolicy
 * @tc.desc: 1.Test the SetEncryptionPolicy of InstalldHostImpl without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, SetEncryptionPolicy_0100, Function | SmallTest | Level1)
{
    InstalldHostImpl hostImpl;
    std::string bundleName = "com.example.testbundle";
    int32_t userId = USERID;
    std::string keyId;
    int32_t uid = -1;
    EncryptionParam encryptionParam(bundleName, "", uid, userId, EncryptionDirType::APP);
    ErrCode ret = hostImpl.SetEncryptionPolicy(encryptionParam, keyId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PERMISSION_DENIED);
}

/**
 * @tc.number: InnerProcessBundleInstall_0100
 * @tc.name: InnerProcessBundleInstall
 * @tc.desc: test InnerProcessBundleInstall
 */
HWTEST_F(BmsBundleInstallerPermissionTest, InnerProcessBundleInstall_0100, TestSize.Level1)
{
    BaseBundleInstaller installer;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetSingleton(false);
    newInfos.insert(std::pair<std::string, InnerBundleInfo>("com.example.testbundle", innerBundleInfo));
    int32_t uid = 3057;
    InnerBundleInfo oldInfo;
    InstallParam installParam;
    installParam.needSavePreInstallInfo = false;
    installer.isAppExist_ = true;
    installer.userId_ = 1;
    auto res = installer.InnerProcessBundleInstall(newInfos, oldInfo, installParam, uid);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
}

/**
 * @tc.number: InnerProcessInstallByPreInstallInfo_0100
 * @tc.name: test InnerProcessInstallByPreInstallInfo
 * @tc.desc: 1.Test the InnerProcessInstallByPreInstallInfo of BaseBundleInstaller without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, InnerProcessInstallByPreInstallInfo_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();
    InnerBundleInfo innerBundleInfo;
    int32_t uid = 0;
    InstallParam installParam;
    installParam.userId = 100;
    installer.dataMgr_->AddUserId(100);
    installer.dataMgr_->bundleInfos_.try_emplace("com.example.testbundle", innerBundleInfo);
    installer.isAppExist_ = true;
    ErrCode ret = installer.InnerProcessInstallByPreInstallInfo(
        "com.example.testbundle", installParam, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
}

/**
 * @tc.number: ProcessBundleInstallStatus_0100
 * @tc.name: test ProcessBundleInstallStatus
 * @tc.desc: 1.Test the ProcessBundleInstallStatus of BaseBundleInstaller without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, ProcessBundleInstallStatus_0100, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.dataMgr_ = GetBundleDataMgr();
    InnerBundleInfo innerBundleInfo;
    int32_t uid = 0;
    InstallParam installParam;
    installer.isAppExist_ = true;
    installer.userId_ = 1;
    installer.bundleName_ = "com.example.testbundle";

    ErrCode ret = installer.ProcessBundleInstallStatus(innerBundleInfo, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
}

/**
 * @tc.number: UpdateHapToken_0100
 * @tc.name: test UpdateHapToken
 * @tc.desc: test UpdateHapToken of BaseBundleInstaller without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, UpdateHapToken_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo newInfo;
    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo info;
    info.accessTokenId = -1;
    info.bundleUserInfo.userId = 1;
    innerBundleUserInfos.try_emplace(BUNDLE_NAME, info);
    newInfo.innerBundleUserInfos_ = innerBundleUserInfos;
    BaseBundleInstaller installer;
    installer.InitDataMgr();

    ErrCode ret = installer.UpdateHapToken(false, newInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
}

/**
 * @tc.number: BaseBundleInstaller_0001
 * @tc.name: test InnerProcessInstallByPreInstallInfo
 * @tc.desc: test InnerProcessInstallByPreInstallInfo of BaseBundleInstaller without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, BaseBundleInstaller_0001, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.InitDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(101);

    std::string bundleName = Constants::SCENE_BOARD_BUNDLE_NAME;
    InstallParam installParam;
    installParam.userId = 101;
    int32_t uid = -1;
    ErrCode ret = installer.InnerProcessInstallByPreInstallInfo(bundleName, installParam, uid);
    if (ret != ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED) {
        bundleName = ServiceConstants::LAUNCHER_BUNDLE_NAME;
        ErrCode ret2 = installer.InnerProcessInstallByPreInstallInfo(bundleName, installParam, uid);
        EXPECT_EQ(ret2, ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
    }
    bundleMgrService_->GetDataMgr()->RemoveUserId(101);
}

/**
 * @tc.number: BaseBundleInstaller_0002
 * @tc.name: test UpdateHapToken
 * @tc.desc: test UpdateHapToken of BaseBundleInstaller without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, BaseBundleInstaller_0002, Function | SmallTest | Level0)
{
    BaseBundleInstaller installer;
    installer.InitDataMgr();
    installer.bundleName_ = "test";

    InnerBundleInfo info;
    int32_t uid = -1;
    ErrCode ret = installer.ProcessBundleInstallStatus(info, uid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
}

/**
 * @tc.number: BaseBundleInstaller_0003
 * @tc.name: test RecoverHapToken
 * @tc.desc: test RecoverHapToken of BaseBundleInstaller without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, BaseBundleInstaller_0003, Function | SmallTest | Level0)
{
    std::string bundleName = "test";
    auto dataMgr = bundleMgrService_->GetDataMgr();
    UninstallBundleInfo uninstallBundleInfo;
    UninstallDataUserInfo uninstallDataUserInfo;
    uninstallBundleInfo.userInfos["100"] = uninstallDataUserInfo;
    EXPECT_TRUE(dataMgr->UpdateUninstallBundleInfo(bundleName, uninstallBundleInfo));

    BaseBundleInstaller installer;
    installer.InitDataMgr();
    installer.bundleName_ = bundleName;

    InnerBundleInfo oldInnerBundleInfo;
    BundleInfo oldBundleInfo;
    oldBundleInfo.versionCode = 100;
    oldInnerBundleInfo.SetBaseBundleInfo(oldBundleInfo);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    oldInnerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);

    Security::AccessToken::AccessTokenIDEx accessTokenIdEx;

    auto ret = installer.RecoverHapToken(bundleName, 100, accessTokenIdEx, oldInnerBundleInfo);
    EXPECT_EQ(ret, false);
    EXPECT_TRUE(dataMgr->DeleteUninstallBundleInfo(bundleName, 100));
}

/**
 * @tc.number: BundleMultiUserInstaller_0001
 * @tc.name: test RecoverHapToken
 * @tc.desc: test RecoverHapToken of BaseBundleInstaller without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, BundleMultiUserInstaller_0001, Function | SmallTest | Level0)
{
    std::string bundleName = "test";
    auto dataMgr = bundleMgrService_->GetDataMgr();
    UninstallBundleInfo uninstallBundleInfo;
    UninstallDataUserInfo uninstallDataUserInfo;
    uninstallBundleInfo.userInfos["100"] = uninstallDataUserInfo;
    EXPECT_TRUE(dataMgr->UpdateUninstallBundleInfo(bundleName, uninstallBundleInfo));

    BundleMultiUserInstaller installer;
    EXPECT_EQ(installer.GetDataMgr(), ERR_OK);

    InnerBundleInfo oldInnerBundleInfo;
    BundleInfo oldBundleInfo;
    oldBundleInfo.versionCode = 100;
    oldInnerBundleInfo.SetBaseBundleInfo(oldBundleInfo);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    oldInnerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);

    Security::AccessToken::AccessTokenIDEx accessTokenIdEx;

    auto ret = installer.RecoverHapToken(bundleName, 100, accessTokenIdEx, oldInnerBundleInfo);
    EXPECT_EQ(ret, false);
    EXPECT_TRUE(dataMgr->DeleteUninstallBundleInfo(bundleName, 100));
}

/**
 * @tc.number: BundleMultiUserInstaller_0002
 * @tc.name: test RecoverHapToken
 * @tc.desc: test RecoverHapToken of BaseBundleInstaller without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, BundleMultiUserInstaller_0002, Function | SmallTest | Level0)
{
    std::string bundleName = "test";
    auto dataMgr = bundleMgrService_->GetDataMgr();
    UninstallBundleInfo uninstallBundleInfo;
    EXPECT_TRUE(dataMgr->uninstallDataMgr_->UpdateUninstallBundleInfo(bundleName, uninstallBundleInfo));

    BundleMultiUserInstaller installer;
    EXPECT_EQ(installer.GetDataMgr(), ERR_OK);

    InnerBundleInfo oldInnerBundleInfo;
    BundleInfo oldBundleInfo;
    oldBundleInfo.versionCode = 100;
    oldInnerBundleInfo.SetBaseBundleInfo(oldBundleInfo);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleUserInfo.userId = USERID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    oldInnerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);

    Security::AccessToken::AccessTokenIDEx accessTokenIdEx;

    auto ret = installer.RecoverHapToken(bundleName, 100, accessTokenIdEx, oldInnerBundleInfo);
    EXPECT_EQ(ret, false);
    EXPECT_TRUE(dataMgr->uninstallDataMgr_->DeleteUninstallBundleInfo(bundleName));
}

/**
 * @tc.number: BundleSandboxInstaller_0001
 * @tc.name: test InstallSandboxApp
 * @tc.desc: test InstallSandboxApp of BaseBundleInstaller without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, BundleSandboxInstaller_0001, Function | SmallTest | Level0)
{
    std::string bundleName = Constants::SCENE_BOARD_BUNDLE_NAME;
    auto dataMgr = bundleMgrService_->GetDataMgr();

    BundleSandboxInstaller installer;
    installer.dataMgr_ = bundleMgrService_->GetDataMgr();
    int32_t appIndex = 0;

    auto ret = installer.InstallSandboxApp(bundleName, 1, 100, appIndex);
    if (ret != ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED) {
        bundleName = ServiceConstants::LAUNCHER_BUNDLE_NAME;
        ErrCode ret2 = installer.InstallSandboxApp(bundleName, 1, 100, appIndex);
        EXPECT_EQ(ret2, ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
    }
}

/**
 * @tc.number: BundleSandboxInstaller_0002
 * @tc.name: test InstallSandboxApp
 * @tc.desc: test InstallSandboxApp of BaseBundleInstaller without permission
*/
HWTEST_F(BmsBundleInstallerPermissionTest, BundleSandboxInstaller_0002, Function | SmallTest | Level0)
{
    std::string bundleName = Constants::SCENE_BOARD_BUNDLE_NAME;
    auto dataMgr = bundleMgrService_->GetDataMgr();
    AppProvisionInfo appProvisionInfo;
    auto result = dataMgr->GetAppProvisionInfo(bundleName, 100, appProvisionInfo);
    if (result != ERR_OK) {
        bundleName = ServiceConstants::LAUNCHER_BUNDLE_NAME;
        auto result2 = dataMgr->GetAppProvisionInfo(bundleName, 100, appProvisionInfo);
        EXPECT_EQ(result2, ERR_OK);
    }
    auto deleteRes = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(bundleName);
    EXPECT_TRUE(deleteRes);

    BundleSandboxInstaller installer;
    installer.dataMgr_ = bundleMgrService_->GetDataMgr();
    int32_t appIndex = 0;

    auto ret = installer.InstallSandboxApp(bundleName, 1, 100, appIndex);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);

    auto addRes = DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(
        bundleName, appProvisionInfo);
    EXPECT_TRUE(addRes);
}
} // OHOS
