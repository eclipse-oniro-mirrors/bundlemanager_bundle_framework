/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include <string>
#include <vector>

#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_status_receiver.h"
#include "parameter.h"
#include "parameters.h"
#include "plugin_installer.h"
#include "plugin/install_plugin_param.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.ohos.resourcedemo";
const std::string HAP_FILE_PATH1 = "/data/test/resource/bms/resource_manager/resourceManagerTest.hap";
const std::string HOST_BUNDLE_NAME = "com.example.host1";
const std::string HOST_BUNDLE_PATH1 = "/data/test/resource/bms/plugin_installer/hostBundleTest1.hap";
const std::string HOST_BUNDLE_PATH2 = "/data/test/resource/bms/plugin_installer/hostBundleTest2.hap";
const std::string PLUGIN_NAME = "com.example.pluginTest1";
const std::string PLUGIN_PATH1 = "/data/test/resource/bms/plugin_installer/plugin.hsp";
const std::string PLUGIN_PATH2 = "/data/test/resource/bms/plugin_installer/pluginWithWrongId.hsp";
const std::string PLUGIN_PATH3 = "/data/test/resource/bms/plugin_installer/pluginNotExist.hsp";
const std::string PLUGIN_PATH4 = "/data/test/resource/bms/plugin_installer/pluginWithWrongProf.hsp";
const std::string PLUGIN_ID1 = "11111111";
const std::string PLUGIN_ID2 = "22222222";
const std::string TEST_MODULE_NAME = "testModuleName";
const int32_t USER_ID = 100;
const int32_t NEW_USER_ID = 200;
const int32_t WAIT_TIME = 2; // init mocked bms
const std::string APP_SERVICES_CAPABILITIES1 = R"(
    {
        "ohos.permission.kernel.SUPPORT_PLUGIN":{
            "pluginDistributionIDs":"11111111|22222222"
        }
})";
const std::string APP_SERVICES_CAPABILITIES2 = R"({
    "ohos.permission.kernel.SUPPORT_PLUGIN_TEST":{
        "pluginDistributionIDs":"11111111|22222222"
    }
})";
const std::string APP_SERVICES_CAPABILITIES3 = R"({
    "ohos.permission.kernel.SUPPORT_PLUGIN":{
    }
})";
} // namespace

class BmsPluginInstallerTest :  public testing::Test {
public:
    BmsPluginInstallerTest();
    ~BmsPluginInstallerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    ErrCode InstallBundle(const std::string &bundlePath) const;
    ErrCode UninstallBundle(const std::string &bundleName) const;

    // void StopInstalldService() const;
    void StartInstalldService() const;
    void StartBundleService();
    // void StopBundleService() const;

    // bool CheckApplicationInfo() const;
    // std::vector<RequestPermission> getBundlePermissions() const;
    // bool CheckBundlePermissions(bool notZero) const;

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsPluginInstallerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsPluginInstallerTest::installdService_ =
    std::make_shared<InstalldService>();

BmsPluginInstallerTest::BmsPluginInstallerTest()
{}

BmsPluginInstallerTest::~BmsPluginInstallerTest()
{}

void BmsPluginInstallerTest::SetUpTestCase()
{
    bundleMgrService_->InitBundleInstaller();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
    bundleMgrService_->GetDataMgr()->LoadDataFromPersistentStorage();
}

void BmsPluginInstallerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsPluginInstallerTest::SetUp()
{
    StartInstalldService();
    InstallBundle(HOST_BUNDLE_PATH1);
    OHOS::system::SetParameter(ServiceConstants::IS_SUPPORT_PLUGIN, "true");
}

void BmsPluginInstallerTest::TearDown()
{
    OHOS::system::SetParameter(ServiceConstants::IS_SUPPORT_PLUGIN, "false");
    UninstallBundle(HOST_BUNDLE_NAME);
}

ErrCode BmsPluginInstallerTest::InstallBundle(const std::string &bundlePath) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_NULL_PTR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_NULL_PTR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_NULL_PTR;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.userId = USER_ID;
    installParam.withCopyHaps = true;
    bool result = installer->Install(bundlePath, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

ErrCode BmsPluginInstallerTest::UninstallBundle(const std::string &bundleName) const
{
    if (!bundleMgrService_) {
        return ERR_APPEXECFWK_NULL_PTR;
    }
    auto installer = bundleMgrService_->GetBundleInstaller();
    if (!installer) {
        EXPECT_FALSE(true) << "the installer is nullptr";
        return ERR_APPEXECFWK_NULL_PTR;
    }
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    if (!receiver) {
        EXPECT_FALSE(true) << "the receiver is nullptr";
        return ERR_APPEXECFWK_NULL_PTR;
    }
    InstallParam installParam;
    installParam.installFlag = InstallFlag::NORMAL;
    installParam.userId = USER_ID;
    bool result = installer->Uninstall(bundleName, installParam, receiver);
    EXPECT_TRUE(result);
    return receiver->GetResultCode();
}

const std::shared_ptr<BundleDataMgr> BmsPluginInstallerTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

void BmsPluginInstallerTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsPluginInstallerTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USER_ID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

/**
 * @tc.number: InstallPlugin_0001
 * @tc.name: test InstallPlugin
*/
HWTEST_F(BmsPluginInstallerTest, InstallPlugin_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    std::vector<std::string> pluginFilePaths = {PLUGIN_PATH1};
    ErrCode ret = installer.InstallPlugin(HOST_BUNDLE_NAME, pluginFilePaths, pluginParam);
    EXPECT_EQ(ret, ERR_OK);

    ret = installer.UninstallPlugin(HOST_BUNDLE_NAME, PLUGIN_NAME, pluginParam);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: InstallPlugin_0002
 * @tc.name: test InstallPlugin
*/
HWTEST_F(BmsPluginInstallerTest, InstallPlugin_0002, Function | SmallTest | Level0)
{
    ErrCode installRes = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installRes, ERR_OK);

    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    std::vector<std::string> pluginFilePaths = {PLUGIN_PATH1};
    ErrCode ret = installer.InstallPlugin(BUNDLE_NAME, pluginFilePaths, pluginParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_INSTALL_PARSE_PLUGINID_ERROR);

    installRes = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installRes, ERR_OK);
}

/**
 * @tc.number: InstallPlugin_0003
 * @tc.name: test InstallPlugin
*/
HWTEST_F(BmsPluginInstallerTest, InstallPlugin_0003, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    std::vector<std::string> pluginFilePaths = {PLUGIN_PATH2};
    ErrCode ret = installer.InstallPlugin(HOST_BUNDLE_NAME, pluginFilePaths, pluginParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_INSTALL_CHECK_PLUGINID_ERROR);
}

/**
 * @tc.number: InstallPlugin_0004
 * @tc.name: test InstallPlugin
*/
HWTEST_F(BmsPluginInstallerTest, InstallPlugin_0004, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    std::vector<std::string> pluginFilePaths = {PLUGIN_PATH1};
    ErrCode ret = installer.InstallPlugin("com.test.demo", pluginFilePaths, pluginParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_HOST_APPLICATION_NOT_FOUND);
}

/**
 * @tc.number: InstallPlugin_0005
 * @tc.name: test InstallPlugin
*/
HWTEST_F(BmsPluginInstallerTest, InstallPlugin_0005, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = NEW_USER_ID;
    std::vector<std::string> pluginFilePaths = {PLUGIN_PATH1};
    ErrCode ret = installer.InstallPlugin(HOST_BUNDLE_NAME, pluginFilePaths, pluginParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_USER_NOT_EXIST);
}

/**
 * @tc.number: UninstallPlugin_0001
 * @tc.name: test UninstallPlugin
*/
HWTEST_F(BmsPluginInstallerTest, UninstallPlugin_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = NEW_USER_ID;
    ErrCode ret = installer.UninstallPlugin(HOST_BUNDLE_NAME, PLUGIN_NAME, pluginParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_USER_NOT_EXIST);

    pluginParam.userId = -1;
    ret = installer.UninstallPlugin(HOST_BUNDLE_NAME, PLUGIN_NAME, pluginParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_USER_NOT_EXIST);
}

/**
 * @tc.number: UninstallPlugin_0002
 * @tc.name: test UninstallPlugin
*/
HWTEST_F(BmsPluginInstallerTest, UninstallPlugin_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    ErrCode ret = installer.UninstallPlugin("", PLUGIN_NAME, pluginParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_HOST_APPLICATION_NOT_FOUND);

    pluginParam.userId = NEW_USER_ID;
    ret = installer.UninstallPlugin(HOST_BUNDLE_NAME, PLUGIN_NAME, pluginParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_USER_NOT_EXIST);
}

/**
 * @tc.number: UninstallPlugin_0003
 * @tc.name: test UninstallPlugin
*/
HWTEST_F(BmsPluginInstallerTest, UninstallPlugin_0003, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;

    ErrCode ret = installer.UninstallPlugin(HOST_BUNDLE_NAME, "", pluginParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_NOT_FOUND);
}


/**
 * @tc.number: ParseFiles_0001
 * @tc.name: test ParseFiles
*/
HWTEST_F(BmsPluginInstallerTest, ParseFiles_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    std::vector<std::string> pluginFilePaths = {PLUGIN_PATH1};
    ErrCode ret = installer.ParseFiles(pluginFilePaths, pluginParam);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ParseFiles_0002
 * @tc.name: test ParseFiles
*/
HWTEST_F(BmsPluginInstallerTest, ParseFiles_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    std::vector<std::string> pluginFilePaths;
    ErrCode ret = installer.ParseFiles(pluginFilePaths, pluginParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_EMPTY);
}

/**
 * @tc.number: ParseFiles_0003
 * @tc.name: test ParseFiles
*/
HWTEST_F(BmsPluginInstallerTest, ParseFiles_0003, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    std::vector<std::string> pluginFilePaths = {PLUGIN_PATH4};
    ErrCode ret = installer.ParseFiles(pluginFilePaths, pluginParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_INSTALL_PARSE_PLUGINID_ERROR);
}

/**
 * @tc.number: MkdirIfNotExist_0001
 * @tc.name: test MkdirIfNotExist
*/
HWTEST_F(BmsPluginInstallerTest, MkdirIfNotExist_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    std::string newDir = "/data/test/newDir";
    ErrCode ret = installer.MkdirIfNotExist(BUNDLE_NAME, BundleDirScene::BUNDLE_CODE_DIR, newDir);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
    ret = installer.MkdirIfNotExist(BUNDLE_NAME, BundleDirScene::BUNDLE_CODE_DIR, newDir);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.number: ParseHapPaths_0001
 * @tc.name: test ParseHapPaths
*/
HWTEST_F(BmsPluginInstallerTest, ParseHapPaths_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    std::vector<std::string> inBundlePath = {PLUGIN_PATH1};
    std::vector<std::string> parsedPath;
    ErrCode ret = installer.ParseHapPaths(pluginParam, inBundlePath, parsedPath);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ParseHapPaths_0002
 * @tc.name: test ParseHapPaths
*/
HWTEST_F(BmsPluginInstallerTest, ParseHapPaths_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    std::string path = "/data/bms_app_install/test.hsp";
    std::vector<std::string> inBundlePath = {path};
    std::vector<std::string> parsedPath;
    ErrCode ret = installer.ParseHapPaths(pluginParam, inBundlePath, parsedPath);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ParseHapPaths_0003
 * @tc.name: test ParseHapPaths
*/
HWTEST_F(BmsPluginInstallerTest, ParseHapPaths_0003, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    std::vector<std::string> inBundlePath;
    std::vector<std::string> parsedPath;
    ErrCode ret = installer.ParseHapPaths(pluginParam, inBundlePath, parsedPath);
    EXPECT_EQ(ret, ERR_OK);

    std::string path = "/data/bms_app_install/../test.hsp";
    inBundlePath.emplace_back(path);
    ret = installer.ParseHapPaths(pluginParam, inBundlePath, parsedPath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: ParseHapPaths_0004
 * @tc.name: test ParseHapPaths with app clone sandbox path
*/
HWTEST_F(BmsPluginInstallerTest, ParseHapPaths_0004, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    installer.userId_ = USER_ID;
    InstallPluginParam pluginParam;
    std::string path = "/data/bms_app_clone/dataclone/test.hsp";
    std::vector<std::string> inBundlePath = {path};
    std::vector<std::string> parsedPath;
    ErrCode ret = installer.ParseHapPaths(pluginParam, inBundlePath, parsedPath);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(parsedPath.size(), 1);
    EXPECT_EQ(parsedPath[0], std::string(ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH) +
        ServiceConstants::GALLERY_DOWNLOAD_PATH + std::to_string(USER_ID) +
        ServiceConstants::GALLERY_CLONE_PATH + "dataclone/test.hsp");
}

/**
 * @tc.number: ParseHapPaths_0005
 * @tc.name: test ParseHapPaths with invalid app clone sandbox path
*/
HWTEST_F(BmsPluginInstallerTest, ParseHapPaths_0005, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    std::string path = "/data/bms_app_clone/dataclone/../test.hsp";
    std::vector<std::string> inBundlePath = {path};
    std::vector<std::string> parsedPath;
    ErrCode ret = installer.ParseHapPaths(pluginParam, inBundlePath, parsedPath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    EXPECT_TRUE(parsedPath.empty());
}

/**
 * @tc.number: CopyHspToSecurityDir_0001
 * @tc.name: test CopyHspToSecurityDir
*/
HWTEST_F(BmsPluginInstallerTest, CopyHspToSecurityDir_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    std::vector<std::string> inBundlePath = {PLUGIN_PATH1};

    ErrCode ret = installer.CopyHspToSecurityDir(inBundlePath, pluginParam);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ObtainHspFileAndSignatureFilePath_0001
 * @tc.name: test ObtainHspFileAndSignatureFilePath
*/
HWTEST_F(BmsPluginInstallerTest, ObtainHspFileAndSignatureFilePath_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    std::string sigFilePath;
    std::vector<std::string> inBundlePath;
    std::vector<std::string> bundlePaths;
    ErrCode ret = installer.ObtainHspFileAndSignatureFilePath(inBundlePath, bundlePaths, sigFilePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);

    inBundlePath.emplace_back(PLUGIN_PATH1);
    ret = installer.ObtainHspFileAndSignatureFilePath(inBundlePath, bundlePaths, sigFilePath);
    EXPECT_EQ(ret, ERR_OK);

    inBundlePath.emplace_back("/data/test/plugin.sig");
    ret = installer.ObtainHspFileAndSignatureFilePath(inBundlePath, bundlePaths, sigFilePath);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ProcessNativeLibrary_0001
 * @tc.name: test ProcessNativeLibrary
*/
HWTEST_F(BmsPluginInstallerTest, ProcessNativeLibrary_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InnerBundleInfo innerBundleInfo;
    std::string moduleDir = "/data/test/plugin_module";
    ErrCode ret = installer.MkdirIfNotExist(BUNDLE_NAME, BundleDirScene::BUNDLE_CODE_DIR, moduleDir);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    std::string pluginBundleDir = "/data/test";
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.compressNativeLibs = false;
    innerModuleInfo.nativeLibraryPath = "lib/arm64";
    innerBundleInfo.innerModuleInfos_.emplace(TEST_MODULE_NAME, innerModuleInfo);

    ret = installer.ProcessNativeLibrary(PLUGIN_PATH1, moduleDir,
        TEST_MODULE_NAME, pluginBundleDir, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ProcessNativeLibrary_0002
 * @tc.name: test ProcessNativeLibrary
*/
HWTEST_F(BmsPluginInstallerTest, ProcessNativeLibrary_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InnerBundleInfo innerBundleInfo;
    std::string moduleDir = "/data/test/plugin_module";
    ErrCode ret = installer.MkdirIfNotExist(BUNDLE_NAME, BundleDirScene::BUNDLE_CODE_DIR, moduleDir);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);

    std::string pluginBundleDir = "/data/test";
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.compressNativeLibs = true;
    innerModuleInfo.nativeLibraryPath = "lib/arm64";
    innerBundleInfo.innerModuleInfos_.emplace(TEST_MODULE_NAME, innerModuleInfo);

    ret = installer.ProcessNativeLibrary(PLUGIN_PATH1, moduleDir,
        TEST_MODULE_NAME, pluginBundleDir, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ProcessNativeLibrary_0003
 * @tc.name: test ProcessNativeLibrary
*/
HWTEST_F(BmsPluginInstallerTest, ProcessNativeLibrary_0003, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InnerBundleInfo innerBundleInfo;
    std::string moduleDir = "/data/test/plugin_module";
    std::string pluginBundleDir = "/data/test";

    ErrCode ret = installer.ProcessNativeLibrary(PLUGIN_PATH1, moduleDir,
        TEST_MODULE_NAME, pluginBundleDir, innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: VerifyCodeSignatureForNativeFiles_0001
 * @tc.name: test VerifyCodeSignatureForNativeFiles
*/
HWTEST_F(BmsPluginInstallerTest, VerifyCodeSignatureForNativeFiles_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    std::string cpuAbi = "arm64";

    ErrCode ret = installer.VerifyCodeSignatureForNativeFiles(PLUGIN_PATH1, cpuAbi,
        "", "", false);
    EXPECT_EQ(ret, ERR_OK);

    ret = installer.VerifyCodeSignatureForNativeFiles(PLUGIN_PATH1, cpuAbi,
        "", "", true);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: VerifyCodeSignatureForNativeFiles_0002
 * @tc.name: test VerifyCodeSignatureForNativeFiles
*/
HWTEST_F(BmsPluginInstallerTest, VerifyCodeSignatureForNativeFiles_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    std::string cpuAbi = "arm64";
    std::string soPath = "/data/test/lib/arm64";

    ErrCode ret = installer.VerifyCodeSignatureForNativeFiles(PLUGIN_PATH3, cpuAbi,
        soPath, "", true);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED);
}

/**
 * @tc.number: VerifyCodeSignatureForHsp_0001
 * @tc.name: test VerifyCodeSignatureForHsp
*/
HWTEST_F(BmsPluginInstallerTest, VerifyCodeSignatureForHsp_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    ErrCode ret = installer.VerifyCodeSignatureForHsp("", "", false, false);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED);
}

/**
 * @tc.number: DeliveryProfileToCodeSign_0001
 * @tc.name: test DeliveryProfileToCodeSign
*/
HWTEST_F(BmsPluginInstallerTest, DeliveryProfileToCodeSign_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    ErrCode ret = installer.DeliveryProfileToCodeSign(hapVerifyResults);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE);

    Security::Verify::HapVerifyResult hapVerifyResult;
    hapVerifyResults.emplace_back(hapVerifyResult);
    ret = installer.DeliveryProfileToCodeSign(hapVerifyResults);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE);

    auto verifyRes = BundleVerifyMgr::HapVerify(PLUGIN_PATH1, hapVerifyResult);
    hapVerifyResults.clear();
    hapVerifyResults.emplace_back(hapVerifyResult);
    ret = installer.DeliveryProfileToCodeSign(hapVerifyResults);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckPluginId_0001
 * @tc.name: test CheckPluginId
*/
HWTEST_F(BmsPluginInstallerTest, CheckPluginId_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    std::string hostBundleName;
    ErrCode ret = installer.CheckPluginId(hostBundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_INSTALL_CHECK_PLUGINID_ERROR);

    installer.pluginIds_.emplace_back("1111");
    ret = installer.CheckPluginId(hostBundleName);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: CheckPluginId_0002
 * @tc.name: test CheckPluginId
*/
HWTEST_F(BmsPluginInstallerTest, CheckPluginId_0002, Function | SmallTest | Level0)
{
    ErrCode installResult = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installResult, ERR_OK);

    PluginInstaller installer;
    ErrCode ret = installer.CheckPluginId(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_INSTALL_CHECK_PLUGINID_ERROR);

    installer.pluginIds_.emplace_back("1111");
    ret = installer.CheckPluginId(HOST_BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_INSTALL_CHECK_PLUGINID_ERROR);

    installer.pluginIds_.emplace_back("11111111");
    ret = installer.CheckPluginId(HOST_BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);

    installResult = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installResult, ERR_OK);
}

/**
 * @tc.number: ParsePluginId_0001
 * @tc.name: test ParsePluginId
*/
HWTEST_F(BmsPluginInstallerTest, ParsePluginId_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    std::string appServiceCapabilities;
    std::vector<std::string> pluginIds;
    bool ret = installer.ParsePluginId(appServiceCapabilities, pluginIds);
    EXPECT_EQ(ret, false);

    ret = installer.ParsePluginId(APP_SERVICES_CAPABILITIES1, pluginIds);
    EXPECT_EQ(ret, true);
    ASSERT_EQ(pluginIds.size(), 2);
    EXPECT_EQ(pluginIds[0], PLUGIN_ID1);
    EXPECT_EQ(pluginIds[1], PLUGIN_ID2);
}

/**
 * @tc.number: ParsePluginId_0002
 * @tc.name: test ParsePluginId
*/
HWTEST_F(BmsPluginInstallerTest, ParsePluginId_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    std::vector<std::string> pluginIds;
    bool ret = installer.ParsePluginId(APP_SERVICES_CAPABILITIES2, pluginIds);
    EXPECT_EQ(ret, false);

    ret = installer.ParsePluginId(APP_SERVICES_CAPABILITIES3, pluginIds);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: CheckSupportPluginPermission_0001
 * @tc.name: test CheckSupportPluginPermission
*/
HWTEST_F(BmsPluginInstallerTest, CheckSupportPluginPermission_0001, Function | SmallTest | Level0)
{
    ErrCode installRes = InstallBundle(HAP_FILE_PATH1);
    EXPECT_EQ(installRes, ERR_OK);

    PluginInstaller installer;
    auto ret = installer.CheckSupportPluginPermission(BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);

    ret = installer.CheckSupportPluginPermission(HOST_BUNDLE_NAME);
    EXPECT_EQ(ret, ERR_OK);

    installRes = UninstallBundle(BUNDLE_NAME);
    EXPECT_EQ(installRes, ERR_OK);
}

/**
 * @tc.number: CheckPluginAppLabelInfo_0001
 * @tc.name: test CheckPluginAppLabelInfo
*/
HWTEST_F(BmsPluginInstallerTest, CheckPluginAppLabelInfo_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    auto ret = installer.CheckPluginAppLabelInfo();
    EXPECT_EQ(ret, ERR_OK);

    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = "test";
    installer.parsedBundles_.emplace("test", info);
    ret = installer.CheckPluginAppLabelInfo();
    EXPECT_EQ(ret, ERR_OK);

    InnerBundleInfo info2;
    installer.parsedBundles_.emplace("test2", info2);
    ret = installer.CheckPluginAppLabelInfo();
    EXPECT_EQ(ret, ERR_APPEXECFWK_PLUGIN_CHECK_APP_LABEL_ERROR);
}

/**
 * @tc.number: ProcessPluginInstall_0001
 * @tc.name: test ProcessPluginInstall
*/
HWTEST_F(BmsPluginInstallerTest, ProcessPluginInstall_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = HOST_BUNDLE_NAME;
    ErrCode ret = installer.ProcessPluginInstall(info);
    EXPECT_EQ(ret, ERR_OK);

    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    std::vector<std::string> pluginFilePaths = {PLUGIN_PATH1};
    ret = installer.InstallPlugin(HOST_BUNDLE_NAME, pluginFilePaths, pluginParam);
    EXPECT_EQ(ret, ERR_OK);
    ret = installer.ProcessPluginInstall(info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED);
}

/**
 * @tc.number: CreatePluginDir_0001
 * @tc.name: test CreatePluginDir
*/
HWTEST_F(BmsPluginInstallerTest, CreatePluginDir_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    std::string pluginDir;
    ErrCode ret = installer.CreatePluginDir(HOST_BUNDLE_NAME, pluginDir);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppIdentifier_0001
 * @tc.name: test CheckAppIdentifier
*/
HWTEST_F(BmsPluginInstallerTest, CheckAppIdentifier_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InnerBundleInfo pluginInfo;
    installer.parsedBundles_.emplace("test", pluginInfo);
    bool ret = installer.CheckAppIdentifier();
    EXPECT_EQ(ret, true);

    installer.oldPluginInfo_.appId = "appId";
    ret = installer.CheckAppIdentifier();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: CheckVersionCodeForUpdate_0001
 * @tc.name: test CheckVersionCodeForUpdate
*/
HWTEST_F(BmsPluginInstallerTest, CheckVersionCodeForUpdate_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InnerBundleInfo pluginInfo;
    installer.parsedBundles_.emplace("test", pluginInfo);
    bool ret = installer.CheckVersionCodeForUpdate();
    EXPECT_EQ(ret, true);

    installer.oldPluginInfo_.versionCode = 2000000;
    ret = installer.CheckVersionCodeForUpdate();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: SavePluginInfoToStorage_0001
 * @tc.name: test SavePluginInfoToStorage
*/
HWTEST_F(BmsPluginInstallerTest, SavePluginInfoToStorage_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InnerBundleInfo pluginInfo;
    InnerBundleInfo bundleInfo;

    ErrCode ret = installer.SavePluginInfoToStorage(pluginInfo, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    installer.userId_ = USER_ID;
    bundleInfo.baseApplicationInfo_->bundleName = HOST_BUNDLE_NAME;
    ret = installer.SavePluginInfoToStorage(pluginInfo, bundleInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ProcessPluginUninstall_0001
 * @tc.name: test ProcessPluginUninstall
*/
HWTEST_F(BmsPluginInstallerTest, ProcessPluginUninstall_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InnerBundleInfo bundleInfo;

    ErrCode ret = installer.ProcessPluginUninstall(bundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_REMOVE_PLUGIN_INFO_ERROR);
}

/**
 * @tc.number: GetModuleNames_0001
 * @tc.name: test GetModuleNames with empty parsedBundles
*/
HWTEST_F(BmsPluginInstallerTest, GetModuleNames_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    // empty parsedBundles_ branch
    EXPECT_EQ(installer.GetModuleNames(), Constants::EMPTY_STRING);
}

/**
 * @tc.number: GetModuleNames_0002
 * @tc.name: test GetModuleNames with non-empty parsedBundles
*/
HWTEST_F(BmsPluginInstallerTest, GetModuleNames_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InnerBundleInfo info;
    info.SetCurrentModulePackage("test_module");
    installer.parsedBundles_.emplace("/path/to/plugin.hsp", info);
    std::string result = installer.GetModuleNames();
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.number: RemoveOldInstallDir_0001
 * @tc.name: test RemoveOldInstallDir with isPluginExist_ false and true
*/
HWTEST_F(BmsPluginInstallerTest, RemoveOldInstallDir_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    // isPluginExist_ = false branch → return early
    installer.isPluginExist_ = false;
    EXPECT_NO_THROW(installer.RemoveOldInstallDir(HOST_BUNDLE_NAME));

    // isPluginExist_ = true branch → call RemoveDir
    installer.isPluginExist_ = true;
    installer.oldPluginInfo_.codePath = "/data/test/old_plugin_dir";
    EXPECT_NO_THROW(installer.RemoveOldInstallDir(HOST_BUNDLE_NAME));
}

/**
 * @tc.number: UninstallRollBack_0001
 * @tc.name: test UninstallRollBack
*/
HWTEST_F(BmsPluginInstallerTest, UninstallRollBack_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    installer.bundleName_ = "test.plugin";
    installer.userId_ = USER_ID;
    installer.oldPluginInfo_.codePath = "/data/test/plugin";
    EXPECT_NO_THROW(installer.UninstallRollBack(HOST_BUNDLE_NAME));
}

/**
 * @tc.number: PluginRollBack_0001
 * @tc.name: test PluginRollBack with isPluginExist_ false
*/
HWTEST_F(BmsPluginInstallerTest, PluginRollBack_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    installer.bundleName_ = "test.plugin";
    installer.userId_ = USER_ID;
    // !isPluginExist_ branch → RemovePluginInfo
    installer.isPluginExist_ = false;
    EXPECT_NO_THROW(installer.PluginRollBack(HOST_BUNDLE_NAME));
}

/**
 * @tc.number: PluginRollBack_0002
 * @tc.name: test PluginRollBack with isPluginExist_ true
*/
HWTEST_F(BmsPluginInstallerTest, PluginRollBack_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    installer.bundleName_ = "test.plugin";
    installer.userId_ = USER_ID;
    // isPluginExist_ branch → UpdatePluginBundleInfo + RemovePluginFromUserInfo
    installer.isPluginExist_ = true;
    installer.oldPluginInfo_.codePath = "/data/test/plugin";
    EXPECT_NO_THROW(installer.PluginRollBack(HOST_BUNDLE_NAME));
}

/**
 * @tc.number: RemoveDir_0001
 * @tc.name: test RemoveDir
*/
HWTEST_F(BmsPluginInstallerTest, RemoveDir_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    std::string dir = "/data/test/nonexist_plugin_dir";
    EXPECT_NO_THROW(installer.RemoveDir(dir, HOST_BUNDLE_NAME));
}

/**
 * @tc.number: RemoveEmptyDirs_0001
 * @tc.name: test RemoveEmptyDirs
*/
HWTEST_F(BmsPluginInstallerTest, RemoveEmptyDirs_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    installer.bundleNameWithTime_ = "test.bundle.time";
    InnerBundleInfo info;
    installer.parsedBundles_.emplace("test_module", info);
    std::string pluginDir = "/data/test/plugins";
    EXPECT_NO_THROW(installer.RemoveEmptyDirs(pluginDir, HOST_BUNDLE_NAME));
}

/**
 * @tc.number: NotifyPluginEvents_0001
 * @tc.name: test NotifyPluginEvents with INSTALL type
*/
HWTEST_F(BmsPluginInstallerTest, NotifyPluginEvents_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    installer.bundleName_ = "test.plugin";
    EXPECT_NO_THROW(installer.NotifyPluginEvents(NotifyType::INSTALL, 1000));
}

/**
 * @tc.number: NotifyPluginEvents_0002
 * @tc.name: test NotifyPluginEvents with UPDATE type
*/
HWTEST_F(BmsPluginInstallerTest, NotifyPluginEvents_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    installer.bundleName_ = "test.plugin";
    EXPECT_NO_THROW(installer.NotifyPluginEvents(NotifyType::UPDATE, 1000));
}

/**
 * @tc.number: NotifyPluginEvents_0003
 * @tc.name: test NotifyPluginEvents with UNINSTALL type
*/
HWTEST_F(BmsPluginInstallerTest, NotifyPluginEvents_0003, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    installer.bundleName_ = "test.plugin";
    EXPECT_NO_THROW(installer.NotifyPluginEvents(NotifyType::UNINSTALL_BUNDLE, 1000));
}

/**
 * @tc.number: SendPluginCommonEvent_0001
 * @tc.name: test SendPluginCommonEvent with INSTALL type
*/
HWTEST_F(BmsPluginInstallerTest, SendPluginCommonEvent_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    EXPECT_NO_THROW(installer.SendPluginCommonEvent(HOST_BUNDLE_NAME, "test.plugin", NotifyType::INSTALL));
}

/**
 * @tc.number: SendPluginCommonEvent_0002
 * @tc.name: test SendPluginCommonEvent with UNINSTALL type
*/
HWTEST_F(BmsPluginInstallerTest, SendPluginCommonEvent_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    EXPECT_NO_THROW(installer.SendPluginCommonEvent(HOST_BUNDLE_NAME, "test.plugin", NotifyType::UNINSTALL_BUNDLE));
}

/**
 * @tc.number: UpdateRouterInfoForPlugin_0001
 * @tc.name: test UpdateRouterInfoForPlugin with isPluginExist_ false
*/
HWTEST_F(BmsPluginInstallerTest, UpdateRouterInfoForPlugin_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InnerBundleInfo pluginInfo;
    // !isPluginExist_ branch → InsertRouterInfo only
    installer.isPluginExist_ = false;
    EXPECT_NO_THROW(installer.UpdateRouterInfoForPlugin(HOST_BUNDLE_NAME, pluginInfo));
}

/**
 * @tc.number: UpdateRouterInfoForPlugin_0002
 * @tc.name: test UpdateRouterInfoForPlugin with isPluginExist_ true
*/
HWTEST_F(BmsPluginInstallerTest, UpdateRouterInfoForPlugin_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InnerBundleInfo pluginInfo;
    // isPluginExist_ branch → DeleteRouterInfo + InsertRouterInfo
    installer.isPluginExist_ = true;
    installer.oldPluginInfo_.codePath = "/data/test/plugin";
    EXPECT_NO_THROW(installer.UpdateRouterInfoForPlugin(HOST_BUNDLE_NAME, pluginInfo));
}

/**
 * @tc.number: DeleteRouterInfoForPlugin_0001
 * @tc.name: test DeleteRouterInfoForPlugin
*/
HWTEST_F(BmsPluginInstallerTest, DeleteRouterInfoForPlugin_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    installer.oldPluginInfo_.codePath = "/data/test/plugin";
    EXPECT_NO_THROW(installer.DeleteRouterInfoForPlugin(HOST_BUNDLE_NAME));
}

/**
 * @tc.number: MergePluginBundleInfo_0001
 * @tc.name: test MergePluginBundleInfo with single bundle
*/
HWTEST_F(BmsPluginInstallerTest, MergePluginBundleInfo_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    installer.bundleName_ = "test.plugin";
    installer.userId_ = USER_ID;
    InnerBundleInfo info1;
    info1.baseApplicationInfo_->bundleName = "test.plugin";
    installer.parsedBundles_.emplace("/path/to/plugin1.hsp", info1);
    InnerBundleInfo result;
    installer.MergePluginBundleInfo(result);
    EXPECT_EQ(result.GetBundleName(), "test.plugin");
}

/**
 * @tc.number: MergePluginBundleInfo_0002
 * @tc.name: test MergePluginBundleInfo with multiple bundles
*/
HWTEST_F(BmsPluginInstallerTest, MergePluginBundleInfo_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    installer.bundleName_ = "test.plugin";
    installer.userId_ = USER_ID;
    InnerBundleInfo info1;
    info1.baseApplicationInfo_->bundleName = "test.plugin";
    InnerBundleInfo info2;
    info2.baseApplicationInfo_->bundleName = "test.plugin";
    installer.parsedBundles_.emplace("/path/to/plugin1.hsp", info1);
    installer.parsedBundles_.emplace("/path/to/plugin2.hsp", info2);
    InnerBundleInfo result;
    installer.MergePluginBundleInfo(result);
    EXPECT_EQ(result.GetBundleName(), "test.plugin");
}

/**
 * @tc.number: ObtainHspFileAndSignatureFilePath_0002
 * @tc.name: test ObtainHspFileAndSignatureFilePath with multi-file including sig
*/
HWTEST_F(BmsPluginInstallerTest, ObtainHspFileAndSignatureFilePath_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    // Multi-file: hsp + sig → covers numberOfHsp/numberOfSignatureFile counting
    std::vector<std::string> inBundlePath = {PLUGIN_PATH1, "/data/test/plugin.sig"};
    std::vector<std::string> bundlePaths;
    std::string sigFilePath;
    ErrCode ret = installer.ObtainHspFileAndSignatureFilePath(inBundlePath, bundlePaths, sigFilePath);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(bundlePaths.size(), 1);
    EXPECT_EQ(sigFilePath, "/data/test/plugin.sig");
}

/**
 * @tc.number: ObtainHspFileAndSignatureFilePath_0003
 * @tc.name: test ObtainHspFileAndSignatureFilePath with single non-hsp file
*/
HWTEST_F(BmsPluginInstallerTest, ObtainHspFileAndSignatureFilePath_0003, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    // Single file not ending with .hsp → covers invalid file branch
    std::vector<std::string> inBundlePath = {"/data/test/plugin.txt"};
    std::vector<std::string> bundlePaths;
    std::string sigFilePath;
    ErrCode ret = installer.ObtainHspFileAndSignatureFilePath(inBundlePath, bundlePaths, sigFilePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: ObtainHspFileAndSignatureFilePath_0004
 * @tc.name: test ObtainHspFileAndSignatureFilePath with multi-file including invalid suffix
*/
HWTEST_F(BmsPluginInstallerTest, ObtainHspFileAndSignatureFilePath_0004, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    // Multi-file with invalid suffix → covers invalid file in shared bundle dir
    std::vector<std::string> inBundlePath = {PLUGIN_PATH1, "/data/test/plugin.txt"};
    std::vector<std::string> bundlePaths;
    std::string sigFilePath;
    ErrCode ret = installer.ObtainHspFileAndSignatureFilePath(inBundlePath, bundlePaths, sigFilePath);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: UninstallPlugin_0004
 * @tc.name: test UninstallPlugin with negative userId
*/
HWTEST_F(BmsPluginInstallerTest, UninstallPlugin_0004, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    // userId < DEFAULT_USERID branch
    pluginParam.userId = -1;
    ErrCode ret = installer.UninstallPlugin(HOST_BUNDLE_NAME, PLUGIN_NAME, pluginParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_USER_NOT_EXIST);
}

/**
 * @tc.number: InstallPlugin_0006
 * @tc.name: test InstallPlugin with host not installed for user
*/
HWTEST_F(BmsPluginInstallerTest, InstallPlugin_0006, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    // Add NEW_USER_ID so HasUserId passes, but host not installed for this user
    dataMgr->AddUserId(NEW_USER_ID);

    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = NEW_USER_ID;
    std::vector<std::string> pluginFilePaths = {PLUGIN_PATH1};
    // HasInnerBundleUserInfo returns false → ERR_APPEXECFWK_HOST_APPLICATION_NOT_FOUND
    ErrCode ret = installer.InstallPlugin(HOST_BUNDLE_NAME, pluginFilePaths, pluginParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_HOST_APPLICATION_NOT_FOUND);
}

/**
 * @tc.number: UninstallPlugin_0005
 * @tc.name: test UninstallPlugin with host not installed for user
*/
HWTEST_F(BmsPluginInstallerTest, UninstallPlugin_0005, Function | SmallTest | Level0)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(NEW_USER_ID);

    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = NEW_USER_ID;
    // HasInnerBundleUserInfo returns false
    ErrCode ret = installer.UninstallPlugin(HOST_BUNDLE_NAME, PLUGIN_NAME, pluginParam);
    EXPECT_EQ(ret, ERR_APPEXECFWK_HOST_APPLICATION_NOT_FOUND);
}

/**
 * @tc.number: RemovePluginDir_0001
 * @tc.name: test RemovePluginDir
*/
HWTEST_F(BmsPluginInstallerTest, RemovePluginDir_0001, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InnerBundleInfo hostInfo;
    hostInfo.baseApplicationInfo_->bundleName = HOST_BUNDLE_NAME;
    installer.bundleNameWithTime_ = "test.time";
    EXPECT_NO_THROW(installer.RemovePluginDir(hostInfo));
}

/**
 * @tc.number: CheckVersionCodeForUpdate_0002
 * @tc.name: test CheckVersionCodeForUpdate with higher or equal version
*/
HWTEST_F(BmsPluginInstallerTest, CheckVersionCodeForUpdate_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InnerBundleInfo pluginInfo;
    installer.parsedBundles_.emplace("test", pluginInfo);

    // old version = 0, new version >= 0 → true (default versionCode is 0)
    installer.oldPluginInfo_.versionCode = 0;
    bool ret = installer.CheckVersionCodeForUpdate();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: InstallPlugin_0008
 * @tc.name: test InstallPlugin with plugin not exist file path
*/
HWTEST_F(BmsPluginInstallerTest, InstallPlugin_0008, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    std::vector<std::string> pluginFilePaths = {PLUGIN_PATH3};
    ErrCode ret = installer.InstallPlugin(HOST_BUNDLE_NAME, pluginFilePaths, pluginParam);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: CopyHspToSecurityDir_0002
 * @tc.name: test CopyHspToSecurityDir with empty paths
*/
HWTEST_F(BmsPluginInstallerTest, CopyHspToSecurityDir_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InstallPluginParam pluginParam;
    pluginParam.userId = USER_ID;
    std::vector<std::string> bundlePaths;
    // Empty paths → loop doesn't execute, returns ERR_OK
    ErrCode ret = installer.CopyHspToSecurityDir(bundlePaths, pluginParam);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: ParseHapPaths_0006
 * @tc.name: test ParseHapPaths with APP_INSTALL_SANDBOX_PATH prefix
*/
HWTEST_F(BmsPluginInstallerTest, ParseHapPaths_0006, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    installer.userId_ = USER_ID;
    InstallPluginParam pluginParam;
    std::string path = "/data/bms_app_install/test.hsp";
    std::vector<std::string> inBundlePath = {path};
    std::vector<std::string> parsedPath;
    ErrCode ret = installer.ParseHapPaths(pluginParam, inBundlePath, parsedPath);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(parsedPath.size(), 1);
    EXPECT_EQ(parsedPath[0], std::string(ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH) +
        ServiceConstants::GALLERY_DOWNLOAD_PATH + std::to_string(USER_ID) +
        ServiceConstants::PATH_SEPARATOR + "test.hsp");
}

/**
 * @tc.number: ProcessPluginInstall_0002
 * @tc.name: test ProcessPluginInstall with empty parsedBundles
*/
HWTEST_F(BmsPluginInstallerTest, ProcessPluginInstall_0002, Function | SmallTest | Level0)
{
    PluginInstaller installer;
    InnerBundleInfo info;
    // parsedBundles_ is empty → returns ERR_OK immediately
    ErrCode ret = installer.ProcessPluginInstall(info);
    EXPECT_EQ(ret, ERR_OK);
}

} // OHOS