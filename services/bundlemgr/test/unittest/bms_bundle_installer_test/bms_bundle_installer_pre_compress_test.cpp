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

#include <gtest/gtest.h>

#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "iremote_proxy.h"
#define private public
#define protected public
#include "base_bundle_installer.h"
#include "bundle_mgr_service.h"
#include "bundle_service_constants.h"
#include "bundle_util.h"
#include "bundle_verify_mgr.h"
#include "directory_ex.h"
#include "install_param.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "on_demand_install_data_mgr.h"
#include "scope_guard.h"
#include "system_bundle_installer.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
const std::string RESOURCE_ROOT_PATH = "/data/test/resource/bms/install_bundle/";
const std::string RIGHT_BUNDLE = "right.hap";
const std::string RIGHT_HAP_PATH = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
const std::string RIGHT_BUNDLE_NAME = "com.example.l3jsdemo";
const std::string TEST_DIR = "/data/test/bms_bundle_installer_pre_compress_test";
const std::string STAGING_DIR =
    std::string(ServiceConstants::HAP_COPY_PATH) + "/bms_bundle_installer_pre_compress_test";
const std::string NOT_EXIST_ARCHIVE = "/preload/app/com.example.precompress.notexist/entry.hap.zst";
const std::string ENTRY_HAP_NAME = "entry.hap";
const std::string ENTRY_ARCHIVE_NAME = "entry.hap.zst";
const std::string AG_CONFIG_BUNDLE_NAME = "com.example.precompress.agconfig";
const std::string PRE_COMPRESS_BUNDLE_NAME = "com.example.precompress.installer";
const std::string EXTRACT_BUNDLE_NAME = "com.example.precompress.extract";
const std::string MODULE_NAME_TEST = "moduleName";
const std::string TEST_CPU_ABI = "arm64";
const std::string AG_CONFIG_CONTENT = "{\"agConfig\":\"test\"}";
const std::string DATA_PRELOAD_HAP_PATH = "/data/preload/app/com.example.precompress/entry.hap";
const int32_t USERID = 100;

class PreCompressInstallerInstalldProxy : public IRemoteProxy<IInstalld> {
public:
    PreCompressInstallerInstalldProxy() : IRemoteProxy<IInstalld>(nullptr) {}

    ErrCode RemoveDir(const std::string &dir, BundleDirScene scene, const std::string &bundleName,
        bool async) override
    {
        removeDirs.emplace_back(dir);
        removeDirScenes.emplace_back(scene);
        removeDirBundleNames.emplace_back(bundleName);
        return removeDirResult;
    }

    ErrCode MoveHapToCodeDir(const std::string &originPath, const std::string &targetPath) override
    {
        moveOriginPaths.emplace_back(originPath);
        moveTargetPaths.emplace_back(targetPath);
        return moveResult;
    }

    ErrCode VerifyCodeSignatureForHap(const CodeSignatureParam &codeSignatureParam) override
    {
        signatureModulePaths.emplace_back(codeSignatureParam.modulePath);
        signaturePreInstalledFlags.emplace_back(codeSignatureParam.isPreInstalledBundle);
        return ERR_OK;
    }

    std::vector<std::string> removeDirs;
    std::vector<BundleDirScene> removeDirScenes;
    std::vector<std::string> removeDirBundleNames;
    ErrCode removeDirResult = ERR_OK;
    std::vector<std::string> moveOriginPaths;
    std::vector<std::string> moveTargetPaths;
    ErrCode moveResult = ERR_OK;
    std::vector<std::string> signatureModulePaths;
    std::vector<bool> signaturePreInstalledFlags;
};

class InstalldProxyGuard final {
public:
    explicit InstalldProxyGuard(const sptr<IInstalld> &proxy)
        : originalProxy_(InstalldClient::GetInstance()->installdProxy_)
    {
        InstalldClient::GetInstance()->installdProxy_ = proxy;
    }

    ~InstalldProxyGuard()
    {
        InstalldClient::GetInstance()->installdProxy_ = originalProxy_;
    }

private:
    sptr<IInstalld> originalProxy_;
};

bool WriteText(const std::string &path, const std::string &text)
{
    if (!OHOS::ForceCreateDirectory(path.substr(0, path.rfind(ServiceConstants::FILE_SEPARATOR_CHAR)))) {
        return false;
    }
    std::ofstream file(path, std::ios::out | std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }
    file << text;
    return file.good();
}

std::string ReadText(const std::string &path)
{
    std::ifstream file(path);
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// a preload dir that is declared compressed but holds a plain package
std::string PrepareMixedPreloadDir()
{
    std::string mixedDir = TEST_DIR + "/mixed";
    return WriteText(mixedDir + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME, AG_CONFIG_CONTENT) ? mixedDir : "";
}

PreInstallBundleInfo MakePreInstallInfo(const std::string &bundleName, const std::string &bundlePath,
    bool isCompressed)
{
    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(bundleName);
    preInstallBundleInfo.AddBundlePath(bundlePath);
    preInstallBundleInfo.SetCompressed(isCompressed);
    preInstallBundleInfo.SetAppType(Constants::AppType::SYSTEM_APP);
    preInstallBundleInfo.SetRemovable(true);
    return preInstallBundleInfo;
}

InnerBundleInfo MakeModuleInfo(const std::string &bundleName, bool isPreInstallApp)
{
    InnerBundleInfo info;
    info.currentPackage_ = MODULE_NAME_TEST;
    InnerModuleInfo moduleInfo;
    moduleInfo.name = MODULE_NAME_TEST;
    moduleInfo.moduleName = MODULE_NAME_TEST;
    moduleInfo.modulePackage = MODULE_NAME_TEST;
    moduleInfo.isLibIsolated = false;
    moduleInfo.compressNativeLibs = true;
    info.innerModuleInfos_[MODULE_NAME_TEST] = moduleInfo;
    info.baseApplicationInfo_->cpuAbi = TEST_CPU_ABI;
    info.baseApplicationInfo_->nativeLibraryPath = "";
    info.baseApplicationInfo_->bundleName = bundleName;
    info.baseBundleInfo_->isPreInstallApp = isPreInstallApp;
    return info;
}
}  // namespace

class BmsBundleInstallerPreCompressTest : public testing::Test {
public:
    BmsBundleInstallerPreCompressTest();
    ~BmsBundleInstallerPreCompressTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    ErrCode UnInstallBundle(const std::string &bundleName) const;
    void RemoveBundle(const std::string &bundleName) const;

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleInstallerPreCompressTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleInstallerPreCompressTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundleInstallerPreCompressTest::BmsBundleInstallerPreCompressTest()
{}

BmsBundleInstallerPreCompressTest::~BmsBundleInstallerPreCompressTest()
{}

void BmsBundleInstallerPreCompressTest::SetUpTestCase()
{}

void BmsBundleInstallerPreCompressTest::TearDownTestCase()
{}

void BmsBundleInstallerPreCompressTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    bundleMgrService_->InitBundleInstaller();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    (void)OHOS::ForceRemoveDirectory(TEST_DIR);
    ASSERT_TRUE(OHOS::ForceCreateDirectory(TEST_DIR));
}

void BmsBundleInstallerPreCompressTest::TearDown()
{
    (void)OHOS::ForceRemoveDirectory(TEST_DIR);
    (void)OHOS::ForceRemoveDirectory(STAGING_DIR);
}

std::shared_ptr<BundleDataMgr> BmsBundleInstallerPreCompressTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

ErrCode BmsBundleInstallerPreCompressTest::UnInstallBundle(const std::string &bundleName) const
{
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (installer == nullptr) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (receiver == nullptr) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    InstallParam installParam;
    installParam.userId = USERID;
    installParam.installFlag = InstallFlag::NORMAL;
    if (!installer->Uninstall(bundleName, installParam, receiver)) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    return receiver->GetResultCode();
}

void BmsBundleInstallerPreCompressTest::RemoveBundle(const std::string &bundleName) const
{
    auto dataMgr = GetBundleDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    if (dataMgr->IsBundleExist(bundleName)) {
        (void)UnInstallBundle(bundleName);
    }
    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(bundleName);
    (void)dataMgr->DeletePreInstallBundleInfo(bundleName, preInstallBundleInfo);
}

/**
 * @tc.number: PrepareCompressedPreloadPaths_0100
 * @tc.name: test PrepareCompressedPreloadPaths
 * @tc.desc: 1. the paths of a plain install are kept as they are
 *           2. a compressed install whose preload dir holds a plain package fails and keeps no path
 */
HWTEST_F(BmsBundleInstallerPreCompressTest, PrepareCompressedPreloadPaths_0100, Function | SmallTest | Level0)
{
    std::string mixedDir = PrepareMixedPreloadDir();
    ASSERT_FALSE(mixedDir.empty());
    BaseBundleInstaller installer;
    InstallParam installParam;
    std::vector<std::string> parsedPaths = { mixedDir };
    EXPECT_EQ(installer.PrepareCompressedPreloadPaths(installParam, parsedPaths), ERR_OK);
    EXPECT_EQ(parsedPaths, std::vector<std::string> { mixedDir });

    installParam.compressedPreload = true;
    EXPECT_EQ(installer.PrepareCompressedPreloadPaths(installParam, parsedPaths),
        ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    EXPECT_TRUE(parsedPaths.empty());
    EXPECT_TRUE(installer.toDeleteTempHapPath_.empty());
    EXPECT_TRUE(installer.decompressedSourceMap_.empty());
}

/**
 * @tc.number: GetOriginalSourcePath_0100
 * @tc.name: test GetOriginalSourcePath and ResetInstallProperties
 * @tc.desc: 1. a decompressed path is mapped back to its archive, any other path is kept
 *           2. the mapping is cleared with the install properties
 */
HWTEST_F(BmsBundleInstallerPreCompressTest, GetOriginalSourcePath_0100, Function | SmallTest | Level0)
{
    std::string tempHapPath = STAGING_DIR + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME;
    std::string archivePath = NOT_EXIST_ARCHIVE;
    BaseBundleInstaller installer;
    EXPECT_EQ(installer.GetOriginalSourcePath(tempHapPath), tempHapPath);
    installer.decompressedSourceMap_[tempHapPath] = archivePath;
    EXPECT_EQ(installer.GetOriginalSourcePath(tempHapPath), archivePath);
    EXPECT_EQ(installer.GetOriginalSourcePath(RIGHT_HAP_PATH), RIGHT_HAP_PATH);

    installer.ResetInstallProperties();
    EXPECT_TRUE(installer.decompressedSourceMap_.empty());
    EXPECT_EQ(installer.GetOriginalSourcePath(tempHapPath), tempHapPath);
}

/**
 * @tc.number: ProcessAgConfigFile_0100
 * @tc.name: test ProcessAgConfigFile
 * @tc.desc: 1. nothing is done when neither the old nor the new package is a compressed preload
 *           2. nothing is done when the new package is a compressed preload but this install did not decompress it
 */
HWTEST_F(BmsBundleInstallerPreCompressTest, ProcessAgConfigFile_0100, Function | SmallTest | Level0)
{
    sptr<PreCompressInstallerInstalldProxy> proxy = new (std::nothrow) PreCompressInstallerInstalldProxy();
    ASSERT_NE(proxy, nullptr);
    InstalldProxyGuard proxyGuard(proxy);
    BaseBundleInstaller installer;
    installer.bundleName_ = AG_CONFIG_BUNDLE_NAME;
    InstallParam installParam;

    installer.ProcessAgConfigFile(installParam, false, false);
    installer.ProcessAgConfigFile(installParam, false, true);
    EXPECT_TRUE(proxy->removeDirs.empty());
    EXPECT_TRUE(proxy->moveOriginPaths.empty());
}

/**
 * @tc.number: ProcessAgConfigFile_0200
 * @tc.name: test ProcessAgConfigFile
 * @tc.desc: 1. the ag_config.json of the code dir is removed when a compressed preload becomes a plain package
 *           2. a failed removal does not stop the install
 */
HWTEST_F(BmsBundleInstallerPreCompressTest, ProcessAgConfigFile_0200, Function | SmallTest | Level0)
{
    sptr<PreCompressInstallerInstalldProxy> proxy = new (std::nothrow) PreCompressInstallerInstalldProxy();
    ASSERT_NE(proxy, nullptr);
    InstalldProxyGuard proxyGuard(proxy);
    BaseBundleInstaller installer;
    installer.bundleName_ = AG_CONFIG_BUNDLE_NAME;
    InstallParam installParam;
    std::string configPath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR +
        AG_CONFIG_BUNDLE_NAME + ServiceConstants::PATH_SEPARATOR + ServiceConstants::AG_CONFIG_FILE;

    installer.ProcessAgConfigFile(installParam, true, false);
    ASSERT_EQ(proxy->removeDirs.size(), 1U);
    EXPECT_EQ(proxy->removeDirs[0], configPath);
    EXPECT_EQ(proxy->removeDirScenes[0], BundleDirScene::REMOVE_MODULE_DIR);
    EXPECT_EQ(proxy->removeDirBundleNames[0], AG_CONFIG_BUNDLE_NAME);
    EXPECT_TRUE(proxy->moveOriginPaths.empty());

    proxy->removeDirResult = ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    installer.ProcessAgConfigFile(installParam, true, false);
    EXPECT_EQ(proxy->removeDirs.size(), 2U);
}

/**
 * @tc.number: ProcessAgConfigFile_0300
 * @tc.name: test ProcessAgConfigFile
 * @tc.desc: 1. the ag_config.json beside the archives is staged and moved into the code dir
 *           2. the ag_config.json of the code dir is removed when the archives come without it
 *           3. nothing is moved when the file can not be staged, a failed move does not stop the install
 */
HWTEST_F(BmsBundleInstallerPreCompressTest, ProcessAgConfigFile_0300, Function | SmallTest | Level0)
{
    sptr<PreCompressInstallerInstalldProxy> proxy = new (std::nothrow) PreCompressInstallerInstalldProxy();
    ASSERT_NE(proxy, nullptr);
    InstalldProxyGuard proxyGuard(proxy);
    std::string sourceDir = TEST_DIR + "/source/";
    std::string noConfigDir = TEST_DIR + "/no_config/";
    std::string tempDir = TEST_DIR + "/temp/";
    ASSERT_TRUE(WriteText(sourceDir + ENTRY_ARCHIVE_NAME, AG_CONFIG_CONTENT));
    ASSERT_TRUE(WriteText(sourceDir + ServiceConstants::AG_CONFIG_FILE, AG_CONFIG_CONTENT));
    ASSERT_TRUE(WriteText(noConfigDir + ENTRY_ARCHIVE_NAME, AG_CONFIG_CONTENT));
    ASSERT_TRUE(OHOS::ForceCreateDirectory(tempDir));
    BaseBundleInstaller installer;
    installer.bundleName_ = AG_CONFIG_BUNDLE_NAME;
    InstallParam installParam;
    installParam.compressedPreload = true;
    std::string configPath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR +
        AG_CONFIG_BUNDLE_NAME + ServiceConstants::PATH_SEPARATOR + ServiceConstants::AG_CONFIG_FILE;

    installer.decompressedSourceMap_ = { { tempDir + ENTRY_HAP_NAME, sourceDir + ENTRY_ARCHIVE_NAME } };
    installer.ProcessAgConfigFile(installParam, false, true);
    ASSERT_EQ(proxy->moveOriginPaths.size(), 1U);
    EXPECT_EQ(proxy->moveOriginPaths[0], tempDir + ServiceConstants::AG_CONFIG_FILE);
    EXPECT_EQ(proxy->moveTargetPaths[0], configPath);
    EXPECT_EQ(ReadText(tempDir + ServiceConstants::AG_CONFIG_FILE), AG_CONFIG_CONTENT);

    installer.decompressedSourceMap_ = { { tempDir + ENTRY_HAP_NAME, noConfigDir + ENTRY_ARCHIVE_NAME } };
    installer.ProcessAgConfigFile(installParam, true, true);
    ASSERT_EQ(proxy->removeDirs.size(), 1U);
    EXPECT_EQ(proxy->removeDirs[0], configPath);

    installer.decompressedSourceMap_ = { { TEST_DIR + "/missing/" + ENTRY_HAP_NAME, sourceDir + ENTRY_ARCHIVE_NAME } };
    installer.ProcessAgConfigFile(installParam, true, true);
    EXPECT_EQ(proxy->moveOriginPaths.size(), 1U);
    EXPECT_EQ(proxy->removeDirs.size(), 1U);

    proxy->moveResult = ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
    installer.decompressedSourceMap_ = { { tempDir + ENTRY_HAP_NAME, sourceDir + ENTRY_ARCHIVE_NAME } };
    installer.ProcessAgConfigFile(installParam, true, true);
    EXPECT_EQ(proxy->moveOriginPaths.size(), 2U);
}

/**
 * @tc.number: VerifyCodeSignatureForHap_PreCompress_0100
 * @tc.name: test VerifyCodeSignatureForHap
 * @tc.desc: 1. a preinstall app copied into the code dir is verified as an installed package
 *           2. a data preload app is verified as an installed package
 *           3. a preinstall app running in place is verified as a preinstalled package
 */
HWTEST_F(BmsBundleInstallerPreCompressTest, VerifyCodeSignatureForHap_PreCompress_0100, Function | SmallTest | Level0)
{
    sptr<PreCompressInstallerInstalldProxy> proxy = new (std::nothrow) PreCompressInstallerInstalldProxy();
    ASSERT_NE(proxy, nullptr);
    InstalldProxyGuard proxyGuard(proxy);
    std::string codeHapPath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR +
        PRE_COMPRESS_BUNDLE_NAME + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME;
    std::unordered_map<std::string, InnerBundleInfo> infos = {
        { RIGHT_HAP_PATH, MakeModuleInfo(PRE_COMPRESS_BUNDLE_NAME, true) }
    };
    BaseBundleInstaller installer;

    installer.copyHapToInstallPath_ = true;
    EXPECT_EQ(installer.VerifyCodeSignatureForHap(infos, RIGHT_HAP_PATH, codeHapPath), ERR_OK);
    installer.copyHapToInstallPath_ = false;
    EXPECT_EQ(installer.VerifyCodeSignatureForHap(infos, RIGHT_HAP_PATH, DATA_PRELOAD_HAP_PATH), ERR_OK);
    EXPECT_EQ(installer.VerifyCodeSignatureForHap(infos, RIGHT_HAP_PATH, codeHapPath), ERR_OK);
    infos[RIGHT_HAP_PATH] = MakeModuleInfo(PRE_COMPRESS_BUNDLE_NAME, false);
    EXPECT_EQ(installer.VerifyCodeSignatureForHap(infos, RIGHT_HAP_PATH, codeHapPath), ERR_OK);

    ASSERT_EQ(proxy->signaturePreInstalledFlags.size(), 4U);
    EXPECT_FALSE(proxy->signaturePreInstalledFlags[0]);
    EXPECT_FALSE(proxy->signaturePreInstalledFlags[1]);
    EXPECT_TRUE(proxy->signaturePreInstalledFlags[2]);
    EXPECT_FALSE(proxy->signaturePreInstalledFlags[3]);
    EXPECT_EQ(proxy->signatureModulePaths[0], codeHapPath);
}

/**
 * @tc.number: ExtractModule_PreCompress_0100
 * @tc.name: test ExtractModule
 * @tc.desc: 1. a preinstall app running in place keeps the hap path under the image
 *           2. a preinstall app copied into the code dir uses the hap path of the code dir
 */
HWTEST_F(BmsBundleInstallerPreCompressTest, ExtractModule_PreCompress_0100, Function | SmallTest | Level0)
{
    std::string modulePath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR +
        EXTRACT_BUNDLE_NAME;
    ScopeGuard dirGuard([modulePath] { (void)OHOS::ForceRemoveDirectory(modulePath); });
    std::string expectedCodeHapPath = std::string(ServiceConstants::PATH_SEPARATOR) + MODULE_NAME_TEST +
        ServiceConstants::INSTALL_FILE_SUFFIX;
    for (bool copyHapToInstallPath : { false, true }) {
        InnerBundleInfo info = MakeModuleInfo(EXTRACT_BUNDLE_NAME, true);
        BaseBundleInstaller installer;
        installer.userId_ = USERID;
        installer.bundleName_ = EXTRACT_BUNDLE_NAME;
        installer.modulePackage_ = MODULE_NAME_TEST;
        installer.modulePath_ = RIGHT_HAP_PATH;
        installer.copyHapToInstallPath_ = copyHapToInstallPath;
        ASSERT_EQ(installer.InnerProcessNativeLibs(info, modulePath), ERR_OK);
        info.SetIsNewVersion(true);
        ASSERT_EQ(installer.ExtractModule(info, modulePath), ERR_OK);
        std::string hapPath = info.innerModuleInfos_[MODULE_NAME_TEST].hapPath;
        if (copyHapToInstallPath) {
            EXPECT_NE(hapPath, RIGHT_HAP_PATH);
            EXPECT_TRUE(BundleUtil::EndWith(hapPath, expectedCodeHapPath));
        } else {
            EXPECT_EQ(hapPath, RIGHT_HAP_PATH);
        }
    }
}

/**
 * @tc.number: ParseHapFiles_PreCompress_0100
 * @tc.name: test ParseHapFiles
 * @tc.desc: 1. the parsed infos carry whether the packages come from compressed archives
 */
HWTEST_F(BmsBundleInstallerPreCompressTest, ParseHapFiles_PreCompress_0100, Function | SmallTest | Level0)
{
    std::vector<std::string> bundlePaths = { RIGHT_HAP_PATH };
    for (bool compressedPreload : { true, false }) {
        BaseBundleInstaller installer;
        std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
        ASSERT_EQ(installer.bundleInstallChecker_->CheckMultipleHapsSignInfo(bundlePaths, hapVerifyRes), ERR_OK);
        InstallParam installParam;
        installParam.userId = USERID;
        installParam.compressedPreload = compressedPreload;
        std::unordered_map<std::string, InnerBundleInfo> infos;
        EXPECT_EQ(installer.ParseHapFiles(bundlePaths, installParam, Constants::AppType::THIRD_PARTY_APP,
            hapVerifyRes, infos), ERR_OK);
        ASSERT_EQ(infos.size(), 1U);
        EXPECT_EQ(infos.begin()->second.IsCompressedPreload(), compressedPreload);
    }
}

/**
 * @tc.number: InnerProcessInstallByPreInstallInfo_PreCompress_0100
 * @tc.name: test InnerProcessInstallByPreInstallInfo
 * @tc.desc: 1. a compressed preinstall app is installed from its archives, so a plain package in its dir fails
 *           2. the same dir recorded as plain is installed from its packages
 */
HWTEST_F(BmsBundleInstallerPreCompressTest, InnerProcessInstallByPreInstallInfo_PreCompress_0100,
    Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::string mixedDir = PrepareMixedPreloadDir();
    ASSERT_FALSE(mixedDir.empty());
    ScopeGuard deleteGuard([this] { RemoveBundle(PRE_COMPRESS_BUNDLE_NAME); });
    InstallParam installParam;
    installParam.userId = USERID;

    ASSERT_TRUE(dataMgr->SavePreInstallBundleInfo(PRE_COMPRESS_BUNDLE_NAME,
        MakePreInstallInfo(PRE_COMPRESS_BUNDLE_NAME, mixedDir, true)));
    BaseBundleInstaller installer;
    int32_t uid = Constants::INVALID_UID;
    EXPECT_EQ(installer.InnerProcessInstallByPreInstallInfo(PRE_COMPRESS_BUNDLE_NAME, installParam, uid),
        ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    EXPECT_FALSE(dataMgr->IsBundleExist(PRE_COMPRESS_BUNDLE_NAME));

    ASSERT_TRUE(dataMgr->SavePreInstallBundleInfo(PRE_COMPRESS_BUNDLE_NAME,
        MakePreInstallInfo(PRE_COMPRESS_BUNDLE_NAME, mixedDir, false)));
    BaseBundleInstaller plainInstaller;
    ErrCode ret = plainInstaller.InnerProcessInstallByPreInstallInfo(PRE_COMPRESS_BUNDLE_NAME, installParam, uid);
    // the plain package of the dir is not a valid hap, it is rejected by the check of the package itself
    EXPECT_NE(ret, ERR_OK);
    EXPECT_NE(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: RecoverOnDemandInstallBundle_PreCompress_0100
 * @tc.name: test RecoverOnDemandInstallBundle
 * @tc.desc: 1. a compressed on demand app is recovered from its archives, so a plain package in its dir fails
 *           2. the on demand info is kept when the recovery fails
 */
HWTEST_F(BmsBundleInstallerPreCompressTest, RecoverOnDemandInstallBundle_PreCompress_0100,
    Function | SmallTest | Level0)
{
    std::string mixedDir = PrepareMixedPreloadDir();
    ASSERT_FALSE(mixedDir.empty());
    ScopeGuard deleteGuard([] {
        (void)OnDemandInstallDataMgr::GetInstance().DeleteOnDemandInstallBundleInfo(PRE_COMPRESS_BUNDLE_NAME);
    });
    ASSERT_TRUE(OnDemandInstallDataMgr::GetInstance().SaveOnDemandInstallBundleInfo(PRE_COMPRESS_BUNDLE_NAME,
        MakePreInstallInfo(PRE_COMPRESS_BUNDLE_NAME, mixedDir, true)));

    BaseBundleInstaller installer;
    InstallParam installParam;
    installParam.userId = USERID;
    int32_t uid = Constants::INVALID_UID;
    EXPECT_EQ(installer.RecoverOnDemandInstallBundle(PRE_COMPRESS_BUNDLE_NAME, installParam, uid),
        ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    PreInstallBundleInfo onDemandInfo;
    EXPECT_TRUE(OnDemandInstallDataMgr::GetInstance().GetOnDemandInstallBundleInfo(PRE_COMPRESS_BUNDLE_NAME,
        onDemandInfo));
    EXPECT_TRUE(onDemandInfo.IsCompressed());
}

/**
 * @tc.number: CheckShellCanInstallPreApp_PreCompress_0100
 * @tc.name: test CheckShellCanInstallPreApp
 * @tc.desc: 1. a shell install fails when the archive of the uninstalled preinstall app can not be decompressed
 */
HWTEST_F(BmsBundleInstallerPreCompressTest, CheckShellCanInstallPreApp_PreCompress_0100,
    Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    ScopeGuard deleteGuard([this] { RemoveBundle(PRE_COMPRESS_BUNDLE_NAME); });
    ASSERT_TRUE(dataMgr->SavePreInstallBundleInfo(PRE_COMPRESS_BUNDLE_NAME,
        MakePreInstallInfo(PRE_COMPRESS_BUNDLE_NAME, NOT_EXIST_ARCHIVE, true)));
    BaseBundleInstaller installer;
    installer.dataMgr_ = dataMgr;
    installer.sysEventInfo_.callingUid = ServiceConstants::SHELL_UID;
    InnerBundleInfo newInfo;
    newInfo.baseApplicationInfo_->bundleName = PRE_COMPRESS_BUNDLE_NAME;
    std::unordered_map<std::string, InnerBundleInfo> newInfos = { { RIGHT_HAP_PATH, newInfo } };

    EXPECT_EQ(installer.CheckShellCanInstallPreApp(newInfos), ERR_APPEXECFWK_INSTALL_DECOMPRESS_APP_FAILED);
}

/**
 * @tc.number: CheckPreBundle_PreCompress_0100
 * @tc.name: test CheckPreBundle
 * @tc.desc: 1. nothing is recovered when the archive of the uninstalled preinstall app can not be decompressed
 *           2. the uninstalled preinstall app of the same signature is recovered from its package before installing
 */
HWTEST_F(BmsBundleInstallerPreCompressTest, CheckPreBundle_PreCompress_0100, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    RemoveBundle(RIGHT_BUNDLE_NAME);
    ScopeGuard deleteGuard([this] { RemoveBundle(RIGHT_BUNDLE_NAME); });
    Security::Verify::HapVerifyResult hapVerifyResult;
    ASSERT_EQ(BundleVerifyMgr::HapVerify(RIGHT_HAP_PATH, hapVerifyResult, true), ERR_OK);
    Security::Verify::ProvisionInfo provisionInfo = hapVerifyResult.GetProvisionInfo();
    InnerBundleInfo newInfo;
    newInfo.baseApplicationInfo_->bundleName = RIGHT_BUNDLE_NAME;
    newInfo.baseApplicationInfo_->isSystemApp = true;
    newInfo.SetProvisionId(provisionInfo.appId);
    newInfo.SetAppIdentifier(provisionInfo.bundleInfo.appIdentifier);
    std::unordered_map<std::string, InnerBundleInfo> newInfos = { { RIGHT_HAP_PATH, newInfo } };
    InstallParam installParam;
    installParam.userId = USERID;

    ASSERT_TRUE(dataMgr->SavePreInstallBundleInfo(RIGHT_BUNDLE_NAME,
        MakePreInstallInfo(RIGHT_BUNDLE_NAME, NOT_EXIST_ARCHIVE, true)));
    BaseBundleInstaller installer;
    installer.dataMgr_ = dataMgr;
    installer.CheckPreBundle(newInfos, installParam, false);
    EXPECT_FALSE(installer.isPreBundleRecovered_);
    EXPECT_FALSE(dataMgr->IsBundleExist(RIGHT_BUNDLE_NAME));

    ASSERT_TRUE(dataMgr->SavePreInstallBundleInfo(RIGHT_BUNDLE_NAME,
        MakePreInstallInfo(RIGHT_BUNDLE_NAME, RIGHT_HAP_PATH, false)));
    BaseBundleInstaller recoverInstaller;
    recoverInstaller.dataMgr_ = dataMgr;
    recoverInstaller.CheckPreBundle(newInfos, installParam, false);
    EXPECT_TRUE(recoverInstaller.isPreBundleRecovered_);
    EXPECT_TRUE(dataMgr->IsBundleExist(RIGHT_BUNDLE_NAME));
}

/**
 * @tc.number: InstallCopiedPreloadBundle_0100
 * @tc.name: test installing a preinstall app copied into the code dir
 * @tc.desc: 1. the package decompressed into the security dir is moved into the code dir and verified there
 *           2. the app is still a preinstall app and its preinstall record keeps the package it came from
 */
HWTEST_F(BmsBundleInstallerPreCompressTest, InstallCopiedPreloadBundle_0100, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    RemoveBundle(RIGHT_BUNDLE_NAME);
    ScopeGuard deleteGuard([this] { RemoveBundle(RIGHT_BUNDLE_NAME); });
    // like a decompressed archive, the package to install lives in the security dir and is moved by the install
    std::string stagedHapPath = STAGING_DIR + ServiceConstants::PATH_SEPARATOR + RIGHT_BUNDLE;
    ASSERT_TRUE(OHOS::ForceCreateDirectory(STAGING_DIR));
    ASSERT_TRUE(BundleUtil::CopyFileFast(RIGHT_HAP_PATH, stagedHapPath));
    std::string realStagedHapPath;
    ASSERT_TRUE(OHOS::PathToRealPath(stagedHapPath, realStagedHapPath));

    InstallParam installParam;
    installParam.userId = USERID;
    installParam.isPreInstallApp = true;
    installParam.needSendEvent = false;
    installParam.needSavePreInstallInfo = true;
    installParam.removable = true;
    installParam.copyHapToInstallPath = true;
    SystemBundleInstaller installer;
    EXPECT_EQ(installer.InstallSystemBundle(stagedHapPath, installParam, Constants::AppType::SYSTEM_APP), ERR_OK);

    InnerBundleInfo info;
    ASSERT_TRUE(dataMgr->FetchInnerBundleInfo(RIGHT_BUNDLE_NAME, info));
    EXPECT_TRUE(info.IsPreInstallApp());
    EXPECT_FALSE(info.IsCompressedPreload());
    std::string codeDir = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR +
        RIGHT_BUNDLE_NAME + ServiceConstants::PATH_SEPARATOR;
    ASSERT_FALSE(info.GetInnerModuleInfos().empty());
    for (const auto &item : info.GetInnerModuleInfos()) {
        EXPECT_EQ(item.second.hapPath.compare(0, codeDir.size(), codeDir), 0) << item.second.hapPath;
        EXPECT_TRUE(BundleUtil::IsExistFileNoLog(item.second.hapPath));
    }
    EXPECT_FALSE(BundleUtil::IsExistFileNoLog(stagedHapPath));

    PreInstallBundleInfo preInstallBundleInfo;
    ASSERT_TRUE(dataMgr->GetPreInstallBundleInfo(RIGHT_BUNDLE_NAME, preInstallBundleInfo));
    EXPECT_FALSE(preInstallBundleInfo.IsCompressed());
    EXPECT_EQ(preInstallBundleInfo.GetBundlePaths(), std::vector<std::string> { realStagedHapPath });
}
}  // namespace OHOS
