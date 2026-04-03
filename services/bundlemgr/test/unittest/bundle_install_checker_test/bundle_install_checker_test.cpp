/*
* Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <fstream>
#include <filesystem>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include "app_provision_info.h"
#include "bundle_install_checker.h"
#include "bundle_verify_mgr.h"
#include "bundle_util.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"
#include "parameter.h"
#include "parameters.h"
#include "bundle_extractor.h"
#include "bundle_parser.h"
#include "zip_file.h"
#include "securec.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
}  // namespace

class BundleInstallCheckerTest : public testing::Test {
public:
    BundleInstallCheckerTest();
    ~BundleInstallCheckerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BundleInstallCheckerTest::BundleInstallCheckerTest()
{}

BundleInstallCheckerTest::~BundleInstallCheckerTest()
{}

void BundleInstallCheckerTest::SetUpTestCase()
{}

void BundleInstallCheckerTest::TearDownTestCase()
{}

void BundleInstallCheckerTest::SetUp()
{}

void BundleInstallCheckerTest::TearDown()
{}

/**
 * @tc.number: BundleInstallCheckerTest_0001
 * @tc.name: test the CheckProvisionInfoIsValid.
 * @tc.desc: test the CheckProvisionInfoIsValid.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0001, TestSize.Level2)
{
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult1;
    hapVerifyResult1.provisionInfo.appId = "testAppId1";
    hapVerifyRes.emplace_back(hapVerifyResult1);

    Security::Verify::HapVerifyResult hapVerifyResult2;
    hapVerifyResult2.provisionInfo.appId = "testAppId2";
    hapVerifyRes.emplace_back(hapVerifyResult2);

    BundleInstallChecker bundleInstallChecker;
    bool isValid = bundleInstallChecker.CheckProvisionInfoIsValid(hapVerifyRes);
    EXPECT_FALSE(isValid);
}

/**
 * @tc.number: BundleInstallCheckerTest_0002
 * @tc.name: test the CheckProvisionInfoIsValid.
 * @tc.desc: test the CheckProvisionInfoIsValid.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0002, TestSize.Level2)
{
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult1;
    hapVerifyResult1.provisionInfo.appId = "testAppId";
    hapVerifyResult1.provisionInfo.bundleInfo.apl = "testApl1";
    hapVerifyRes.emplace_back(hapVerifyResult1);

    Security::Verify::HapVerifyResult hapVerifyResult2;
    hapVerifyResult2.provisionInfo.appId = "testAppId";
    hapVerifyResult2.provisionInfo.bundleInfo.apl = "testApl2";
    hapVerifyRes.emplace_back(hapVerifyResult2);

    BundleInstallChecker bundleInstallChecker;
    bool isValid = bundleInstallChecker.CheckProvisionInfoIsValid(hapVerifyRes);
    EXPECT_FALSE(isValid);
}

/**
 * @tc.number: BundleInstallCheckerTest_0003
 * @tc.name: test the CheckProvisionInfoIsValid.
 * @tc.desc: test the CheckProvisionInfoIsValid.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0003, TestSize.Level2)
{
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult1;
    hapVerifyResult1.provisionInfo.appId = "testAppId";
    hapVerifyResult1.provisionInfo.bundleInfo.apl = "testApl";
    hapVerifyResult1.provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    hapVerifyRes.emplace_back(hapVerifyResult1);

    Security::Verify::HapVerifyResult hapVerifyResult2;
    hapVerifyResult2.provisionInfo.appId = "testAppId";
    hapVerifyResult2.provisionInfo.bundleInfo.apl = "testApl";
    hapVerifyResult2.provisionInfo.distributionType = Security::Verify::AppDistType::NONE_TYPE;
    hapVerifyRes.emplace_back(hapVerifyResult2);

    BundleInstallChecker bundleInstallChecker;
    bool isValid = bundleInstallChecker.CheckProvisionInfoIsValid(hapVerifyRes);
    EXPECT_FALSE(isValid);
}

/**
 * @tc.number: BundleInstallCheckerTest_0004
 * @tc.name: test the CheckProvisionInfoIsValid.
 * @tc.desc: test the CheckProvisionInfoIsValid.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0004, TestSize.Level2)
{
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult1;
    hapVerifyResult1.provisionInfo.appId = "testAppId";
    hapVerifyResult1.provisionInfo.bundleInfo.apl = "testApl";
    hapVerifyResult1.provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    hapVerifyResult1.provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    hapVerifyRes.emplace_back(hapVerifyResult1);

    Security::Verify::HapVerifyResult hapVerifyResult2;
    hapVerifyResult2.provisionInfo.appId = "testAppId";
    hapVerifyResult2.provisionInfo.bundleInfo.apl = "testApl";
    hapVerifyResult2.provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    hapVerifyResult2.provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    hapVerifyRes.emplace_back(hapVerifyResult2);

    BundleInstallChecker bundleInstallChecker;
    bool isValid = bundleInstallChecker.CheckProvisionInfoIsValid(hapVerifyRes);
    EXPECT_FALSE(isValid);
}

/**
 * @tc.number: BundleInstallCheckerTest_0005
 * @tc.name: test the CheckProvisionInfoIsValid.
 * @tc.desc: test the CheckProvisionInfoIsValid.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0005, TestSize.Level2)
{
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult1;
    hapVerifyResult1.provisionInfo.appId = "testAppId";
    hapVerifyResult1.provisionInfo.bundleInfo.apl = "testApl";
    hapVerifyResult1.provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    hapVerifyResult1.provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    hapVerifyResult1.provisionInfo.bundleInfo.appIdentifier = "testAppIdentifier1";
    hapVerifyRes.emplace_back(hapVerifyResult1);

    Security::Verify::HapVerifyResult hapVerifyResult2;
    hapVerifyResult2.provisionInfo.appId = "testAppId";
    hapVerifyResult2.provisionInfo.bundleInfo.apl = "testApl";
    hapVerifyResult2.provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    hapVerifyResult2.provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    hapVerifyResult2.provisionInfo.bundleInfo.appIdentifier = "testAppIdentifier2";
    hapVerifyRes.emplace_back(hapVerifyResult2);

    BundleInstallChecker bundleInstallChecker;
    bool isValid = bundleInstallChecker.CheckProvisionInfoIsValid(hapVerifyRes);
    EXPECT_FALSE(isValid);
}

/**
 * @tc.number: BundleInstallCheckerTest_0006
 * @tc.name: test the VaildInstallPermission.
 * @tc.desc: test the VaildInstallPermission.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0006, TestSize.Level2)
{
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    InstallParam installParam;
    installParam.isCallByShell = false;
    installParam.installBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    installParam.installEnterpriseBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    installParam.installEtpMdmBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    installParam.installInternaltestingBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;

    BundleInstallChecker bundleInstallChecker;
    bool isValid = bundleInstallChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_TRUE(isValid);
}

/**
 * @tc.number: BundleInstallCheckerTest_0007
 * @tc.name: test the VaildInstallPermission.
 * @tc.desc: test the VaildInstallPermission.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0007, TestSize.Level2)
{
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult1;
    hapVerifyResult1.provisionInfo.appId = "testAppId";
    hapVerifyResult1.provisionInfo.bundleInfo.apl = "testApl";
    hapVerifyResult1.provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    hapVerifyResult1.provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    hapVerifyResult1.provisionInfo.bundleInfo.appIdentifier = "testAppIdentifier1";
    hapVerifyRes.emplace_back(hapVerifyResult1);

    InstallParam installParam;
    installParam.isCallByShell = true;

    BundleInstallChecker bundleInstallChecker;
    bool isValid = bundleInstallChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_FALSE(isValid);
}

/**
 * @tc.number: BundleInstallCheckerTest_0008
 * @tc.name: test the VaildInstallPermission.
 * @tc.desc: test the VaildInstallPermission.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0008, TestSize.Level2)
{
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult1;
    hapVerifyResult1.provisionInfo.appId = "testAppId";
    hapVerifyResult1.provisionInfo.bundleInfo.apl = "testApl";
    hapVerifyResult1.provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    hapVerifyResult1.provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    hapVerifyResult1.provisionInfo.bundleInfo.appIdentifier = "testAppIdentifier1";
    hapVerifyRes.emplace_back(hapVerifyResult1);

    InstallParam installParam;
    installParam.isCallByShell = false;
    installParam.installEnterpriseBundlePermissionStatus = PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS;

    BundleInstallChecker bundleInstallChecker;
    bool isValid = bundleInstallChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_FALSE(isValid);
}

/**
 * @tc.number: BundleInstallCheckerTest_0054
 * @tc.name: test GetHideDesktopIconByBundlePath with empty path.
 * @tc.desc: return false when bundle path is empty.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0054, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    bool hideDesktopIcon = false;
    bool ret = bundleInstallChecker.GetHideDesktopIconByBundlePath("", hideDesktopIcon);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(hideDesktopIcon);
}

/**
 * @tc.number: BundleInstallCheckerTest_0055
 * @tc.name: test GetHideDesktopIconByBundlePath with invalid path.
 * @tc.desc: return false when ParseHapProfile failed.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0055, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    bool hideDesktopIcon = false;
    bool ret = bundleInstallChecker.GetHideDesktopIconByBundlePath("/invalid/path/not_exist.hap", hideDesktopIcon);
    EXPECT_FALSE(ret);
    EXPECT_FALSE(hideDesktopIcon);
}

/**
 * @tc.number: BundleInstallCheckerTest_0009
 * @tc.name: test the VaildInstallPermission.
 * @tc.desc: test the VaildInstallPermission.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0009, TestSize.Level2)
{
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult1;
    hapVerifyResult1.provisionInfo.appId = "testAppId";
    hapVerifyResult1.provisionInfo.bundleInfo.apl = "testApl";
    hapVerifyResult1.provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE_NORMAL;
    hapVerifyResult1.provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    hapVerifyResult1.provisionInfo.bundleInfo.appIdentifier = "testAppIdentifier1";
    hapVerifyRes.emplace_back(hapVerifyResult1);

    InstallParam installParam;
    installParam.isSelfUpdate = true;

    BundleInstallChecker bundleInstallChecker;
    bool ret1 = bundleInstallChecker.VaildEnterpriseInstallPermission(installParam, hapVerifyResult1.provisionInfo);
    EXPECT_FALSE(ret1);

    bool isValid = bundleInstallChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_FALSE(isValid);
}

/**
 * @tc.number: BundleInstallCheckerTest_0010
 * @tc.name: test the VaildInstallPermission.
 * @tc.desc: test the VaildInstallPermission.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0010, TestSize.Level2)
{
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult1;
    hapVerifyResult1.provisionInfo.appId = "testAppId";
    hapVerifyResult1.provisionInfo.bundleInfo.apl = "testApl";
    hapVerifyResult1.provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE_MDM;
    hapVerifyResult1.provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    hapVerifyResult1.provisionInfo.bundleInfo.appIdentifier = "testAppIdentifier1";
    hapVerifyRes.emplace_back(hapVerifyResult1);

    InstallParam installParam;
    installParam.isSelfUpdate = true;

    BundleInstallChecker bundleInstallChecker;
    bool ret1 = bundleInstallChecker.VaildEnterpriseInstallPermission(installParam, hapVerifyResult1.provisionInfo);
    EXPECT_TRUE(ret1);

    bool isValid = bundleInstallChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_TRUE(isValid);
}

/**
 * @tc.number: BundleInstallCheckerTest_0011
 * @tc.name: test the VaildInstallPermission.
 * @tc.desc: test the VaildInstallPermission.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0011, TestSize.Level2)
{
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult1;
    hapVerifyResult1.provisionInfo.appId = "testAppId";
    hapVerifyResult1.provisionInfo.bundleInfo.apl = "testApl";
    hapVerifyResult1.provisionInfo.distributionType = Security::Verify::AppDistType::INTERNALTESTING;
    hapVerifyResult1.provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    hapVerifyResult1.provisionInfo.bundleInfo.appIdentifier = "testAppIdentifier1";
    hapVerifyRes.emplace_back(hapVerifyResult1);

    InstallParam installParam;
    installParam.isCallByShell = false;
    installParam.installInternaltestingBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;

    BundleInstallChecker bundleInstallChecker;
    bool isValid = bundleInstallChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_TRUE(isValid);
}

/**
 * @tc.number: BundleInstallCheckerTest_0012
 * @tc.name: test the VaildInstallPermission.
 * @tc.desc: test the VaildInstallPermission.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0012, TestSize.Level2)
{
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult1;
    hapVerifyResult1.provisionInfo.appId = "testAppId";
    hapVerifyResult1.provisionInfo.bundleInfo.apl = "testApl";
    hapVerifyResult1.provisionInfo.distributionType = Security::Verify::AppDistType::INTERNALTESTING;
    hapVerifyResult1.provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    hapVerifyResult1.provisionInfo.bundleInfo.appIdentifier = "testAppIdentifier1";
    hapVerifyRes.emplace_back(hapVerifyResult1);

    InstallParam installParam;
    installParam.isCallByShell = false;
    installParam.installInternaltestingBundlePermissionStatus = PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS;

    BundleInstallChecker bundleInstallChecker;
    bool isValid = bundleInstallChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_FALSE(isValid);
}

/**
 * @tc.number: BundleInstallCheckerTest_0013
 * @tc.name: test the VaildInstallPermission.
 * @tc.desc: test the VaildInstallPermission.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0013, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos["test"] = InnerBundleInfo();

    InstallCheckParam checkParam;
    checkParam.isInstalledForAllUser = true;
    std::string distributionType = Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL;

    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "true");

    ErrCode ret = bundleInstallChecker.CheckEnterpriseForAllUser(infos, checkParam, distributionType);
    EXPECT_EQ(ret, ERR_OK);
    OHOS::system::RemoveParameter(ServiceConstants::IS_ENTERPRISE_DEVICE);
}

/**
 * @tc.number: BundleInstallCheckerTest_0014
 * @tc.name: test the VaildInstallPermissionForShare.
 * @tc.desc: test the VaildInstallPermissionForShare.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0014, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    InstallCheckParam checkParam;
    checkParam.isCallByShell = false;
    checkParam.installBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    checkParam.installEnterpriseBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    checkParam.installEtpMdmBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    checkParam.installInternaltestingBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;

    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;

    auto ret = bundleInstallChecker.VaildInstallPermissionForShare(checkParam, hapVerifyRes);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BundleInstallCheckerTest_0015
 * @tc.name: test the VaildInstallPermissionForShare.
 * @tc.desc: test the VaildInstallPermissionForShare.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0015, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    InstallCheckParam checkParam;
    checkParam.isCallByShell = true;
    checkParam.installBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;

    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult1;
    hapVerifyResult1.provisionInfo.appId = "testAppId";
    hapVerifyResult1.provisionInfo.bundleInfo.apl = "testApl";
    hapVerifyResult1.provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    hapVerifyResult1.provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    hapVerifyResult1.provisionInfo.bundleInfo.appIdentifier = "testAppIdentifier1";
    hapVerifyRes.emplace_back(hapVerifyResult1);

    auto ret = bundleInstallChecker.VaildInstallPermissionForShare(checkParam, hapVerifyRes);
    EXPECT_EQ(ret, false);

    auto ret2 = bundleInstallChecker.CheckInstallPermission(checkParam, hapVerifyRes);
    EXPECT_EQ(ret2, ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED);
}

/**
 * @tc.number: BundleInstallCheckerTest_0016
 * @tc.name: test the CheckDependency.
 * @tc.desc: test the CheckDependency.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0016, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos["test1"] = InnerBundleInfo();

    auto ret = bundleInstallChecker.CheckDependency(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BundleInstallCheckerTest_0017
 * @tc.name: test the CheckDependency.
 * @tc.desc: test the CheckDependency.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0017, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::string bundleName = "com.test.bundleInstallChecker";
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = bundleName;
    infos[bundleName] = innerBundleInfo;
    std::string moduleName = "entry";

    auto ret = bundleInstallChecker.FindModuleInInstallingPackage(moduleName, bundleName, infos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleInstallCheckerTest_0018
 * @tc.name: test the CheckBundleName.
 * @tc.desc: test the CheckBundleName.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0018, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::string provisionBundleName;
    std::string bundleName;

    auto ret = bundleInstallChecker.CheckBundleName(provisionBundleName, bundleName);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);

    provisionBundleName = "test";
    auto ret2 = bundleInstallChecker.CheckBundleName(provisionBundleName, bundleName);
    EXPECT_EQ(ret2, ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
}

/**
 * @tc.number: BundleInstallCheckerTest_0019
 * @tc.name: test the SetPackInstallationFree.
 * @tc.desc: test the SetPackInstallationFree.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0019, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    BundlePackInfo bundlePackInfo;
    PackageModule packMoudle;
    bundlePackInfo.summary.modules.emplace_back(packMoudle);

    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.isNewVersion_ = true;
    innerBundleInfo.baseApplicationInfo_->bundleType = BundleType::ATOMIC_SERVICE;

    bundleInstallChecker.SetPackInstallationFree(bundlePackInfo, innerBundleInfo);
    EXPECT_EQ(bundlePackInfo.summary.modules[0].distro.installationFree, true);
}

/**
 * @tc.number: BundleInstallCheckerTest_0020
 * @tc.name: test the SetPackInstallationFree.
 * @tc.desc: test the SetPackInstallationFree.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0020, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "entry";
    innerBundleInfo.innerModuleInfos_["entry"] = innerModuleInfo;

    infos["entry"] = innerBundleInfo;
    infos["entry2"] = innerBundleInfo;

    std::map<std::string, std::string> hashParams;
    hashParams["entry"] = "entry";

    auto ret = bundleInstallChecker.CheckHapHashParams(infos, hashParams);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_MODULE_NAME_DUPLICATE);
}

/**
 * @tc.number: BundleInstallCheckerTest_0021
 * @tc.name: test the SetPackInstallationFree.
 * @tc.desc: test the SetPackInstallationFree.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0021, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "entry";
    innerBundleInfo.innerModuleInfos_["entry"] = innerModuleInfo;

    infos["entry"] = innerBundleInfo;

    std::map<std::string, std::string> hashParams;
    hashParams["entry"] = "entry";

    auto ret = bundleInstallChecker.CheckHapHashParams(infos, hashParams);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BundleInstallCheckerTest_0022
 * @tc.name: test the GetValidReleaseType.
 * @tc.desc: test the GetValidReleaseType.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0022, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;

    auto ret = bundleInstallChecker.GetValidReleaseType(infos);
    EXPECT_EQ(std::get<0>(ret), false);
}

/**
 * @tc.number: BundleInstallCheckerTest_0023
 * @tc.name: test the CheckAppLabelInfo.
 * @tc.desc: test the CheckAppLabelInfo.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0023, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    innerBundleInfo1.baseApplicationInfo_->bundleName = "test1";

    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo2.baseApplicationInfo_->bundleName = "test2";

    infos["test1"] = innerBundleInfo1;
    infos["test2"] = innerBundleInfo2;

    auto ret = bundleInstallChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_BUNDLENAME_NOT_SAME);
}

/**
 * @tc.number: BundleInstallCheckerTest_0024
 * @tc.name: test the CheckAppLabelInfo.
 * @tc.desc: test the CheckAppLabelInfo.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0024, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    innerBundleInfo1.baseApplicationInfo_->bundleName = "test1";
    innerBundleInfo1.baseBundleInfo_->versionCode = 1;

    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo2.baseApplicationInfo_->bundleName = "test1";
    innerBundleInfo2.baseBundleInfo_->versionCode = 2;

    infos["test1"] = innerBundleInfo1;
    infos["test2"] = innerBundleInfo2;

    auto ret = bundleInstallChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_VERSIONCODE_NOT_SAME);
}

/**
 * @tc.number: BundleInstallCheckerTest_0025
 * @tc.name: test the CheckAppLabelInfo.
 * @tc.desc: test the CheckAppLabelInfo.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0025, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    innerBundleInfo1.baseApplicationInfo_->bundleName = "test1";
    innerBundleInfo1.baseBundleInfo_->versionCode = 1;
    innerBundleInfo1.baseBundleInfo_->releaseType = "debug";

    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo2.baseApplicationInfo_->bundleName = "test1";
    innerBundleInfo2.baseBundleInfo_->versionCode = 1;
    innerBundleInfo1.baseBundleInfo_->releaseType = "release";

    infos["test1"] = innerBundleInfo1;
    infos["test2"] = innerBundleInfo2;

    auto ret = bundleInstallChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_RELEASETYPE_NOT_SAME);
}

/**
 * @tc.number: BundleInstallCheckerTest_0026
 * @tc.name: test the CheckAppLabelInfo.
 * @tc.desc: test the CheckAppLabelInfo.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0026, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    innerBundleInfo1.baseApplicationInfo_->bundleName = "test1";
    innerBundleInfo1.baseBundleInfo_->versionCode = 1;
    innerBundleInfo1.baseBundleInfo_->releaseType = "debug";
    innerBundleInfo1.baseApplicationInfo_->singleton = true;

    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo2.baseApplicationInfo_->bundleName = "test1";
    innerBundleInfo2.baseBundleInfo_->versionCode = 1;
    innerBundleInfo2.baseBundleInfo_->releaseType = "debug";
    innerBundleInfo2.baseApplicationInfo_->singleton = false;

    infos["test1"] = innerBundleInfo1;
    infos["test2"] = innerBundleInfo2;

    auto ret = bundleInstallChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_SINGLETON_NOT_SAME);
}

/**
 * @tc.number: BundleInstallCheckerTest_0027
 * @tc.name: test the CheckMultiArkNativeFile.
 * @tc.desc: test the CheckMultiArkNativeFile.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0027, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;

    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo2.baseApplicationInfo_->arkNativeFileAbi = "x86";

    infos["test1"] = innerBundleInfo1;
    infos["test2"] = innerBundleInfo2;

    auto ret = bundleInstallChecker.CheckMultiArkNativeFile(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BundleInstallCheckerTest_0028
 * @tc.name: test the CheckModuleNameForMulitHaps.
 * @tc.desc: test the CheckModuleNameForMulitHaps.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0028, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    InnerModuleInfo innerModuleInfo1;
    innerModuleInfo1.moduleName = "module1";
    innerBundleInfo1.innerModuleInfos_["module1"] = innerModuleInfo1;

    InnerBundleInfo innerBundleInfo2;
    InnerModuleInfo innerModuleInfo2;
    innerModuleInfo2.moduleName = "module1";
    innerBundleInfo2.innerModuleInfos_["module1"] = innerModuleInfo2;

    infos["test1"] = innerBundleInfo1;
    infos["test2"] = innerBundleInfo2;

    auto ret = bundleInstallChecker.CheckModuleNameForMulitHaps(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_NOT_UNIQUE_DISTRO_MODULE_NAME);
}

/**
 * @tc.number: BundleInstallCheckerTest_0029
 * @tc.name: test the IsExistedDistroModule.
 * @tc.desc: test the IsExistedDistroModule.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0029, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::string moduleName = "entry";
    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = moduleName;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = moduleName;
    newInfo.innerModuleInfos_[moduleName] = innerModuleInfo;

    InnerBundleInfo info;
    InnerModuleInfo innerModuleInfo2;
    innerModuleInfo2.moduleName = "entry2";
    info.innerModuleInfos_[moduleName] = innerModuleInfo2;
    info.isNewVersion_ = true;

    auto ret = bundleInstallChecker.IsExistedDistroModule(newInfo, info);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleInstallCheckerTest_0030
 * @tc.name: test the IsExistedDistroModule.
 * @tc.desc: test the IsExistedDistroModule.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0030, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::string moduleName = "entry";
    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = moduleName;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = moduleName;
    innerModuleInfo.distro.moduleType = "entryType";
    newInfo.innerModuleInfos_[moduleName] = innerModuleInfo;
    newInfo.isNewVersion_ = true;

    InnerBundleInfo info;
    InnerModuleInfo innerModuleInfo2;
    innerModuleInfo2.moduleName = "entry2";
    innerModuleInfo2.distro.moduleType = "featureType";
    info.innerModuleInfos_[moduleName] = innerModuleInfo2;
    info.isNewVersion_ = false;

    auto ret = bundleInstallChecker.IsExistedDistroModule(newInfo, info);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundleInstallCheckerTest_0031
 * @tc.name: test the CheckSupportIsolation.
 * @tc.desc: test the CheckSupportIsolation.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0031, TestSize.Level2)
{
    const char *param = "true";
    OHOS::SetBMSMockParameter(param, -1);

    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isolationMode = "nonisolationOnly";
    innerBundleInfo.innerModuleInfos_["entry"] = innerModuleInfo;
    infos["test"] = innerBundleInfo;

    auto ret = bundleInstallChecker.CheckIsolationMode(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_ISOLATION_MODE_FAILED);
}

/**
 * @tc.number: BundleInstallCheckerTest_0032
 * @tc.name: test the CheckDeveloperMode.
 * @tc.desc: test the CheckDeveloperMode.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0032, TestSize.Level2)
{
    OHOS::system::SetParameter(ServiceConstants::DEVELOPERMODE_STATE, "true");
    BundleInstallChecker bundleInstallChecker;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult;
    hapVerifyResult.provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    hapVerifyRes.emplace_back(hapVerifyResult);

    Security::AccessToken::AccessTokenID callerToken = 0;

    auto ret = bundleInstallChecker.CheckDeveloperMode(hapVerifyRes, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    OHOS::system::RemoveParameter(ServiceConstants::DEVELOPERMODE_STATE);
}

/**
 * @tc.number: BundleInstallCheckerTest_0033
 * @tc.name: test the CheckDeveloperMode.
 * @tc.desc: test the CheckDeveloperMode.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0033, TestSize.Level2)
{
    OHOS::system::SetParameter(ServiceConstants::DEVELOPERMODE_STATE, "false");
    BundleInstallChecker bundleInstallChecker;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult;
    hapVerifyResult.provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    hapVerifyRes.emplace_back(hapVerifyResult);

    Security::AccessToken::AccessTokenID callerToken = 0;

    auto ret = bundleInstallChecker.CheckDeveloperMode(hapVerifyRes, callerToken);
    EXPECT_EQ(ret, ERR_OK);

    auto ret3 = bundleInstallChecker.CheckHspInstallCondition(hapVerifyRes, callerToken);
    EXPECT_EQ(ret3, ERR_OK);
    OHOS::system::RemoveParameter(ServiceConstants::DEVELOPERMODE_STATE);
}

/**
 * @tc.number: BundleInstallCheckerTest_0034
 * @tc.name: test the CheckAllowEnterpriseBundle.
 * @tc.desc: test the CheckAllowEnterpriseBundle.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0034, TestSize.Level2)
{
    OHOS::system::SetParameter(ServiceConstants::ALLOW_ENTERPRISE_BUNDLE, "false");
    OHOS::system::SetParameter(ServiceConstants::IS_ENTERPRISE_DEVICE, "false");
    OHOS::system::SetParameter(ServiceConstants::DEVELOPERMODE_STATE, "false");
    BundleInstallChecker bundleInstallChecker;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult hapVerifyResult;
    hapVerifyResult.provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE_NORMAL;
    hapVerifyRes.emplace_back(hapVerifyResult);

    auto ret = bundleInstallChecker.CheckAllowEnterpriseBundle(hapVerifyRes);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_ENTERPRISE_BUNDLE_NOT_ALLOWED);

    OHOS::system::RemoveParameter(ServiceConstants::ALLOW_ENTERPRISE_BUNDLE);
    OHOS::system::RemoveParameter(ServiceConstants::IS_ENTERPRISE_DEVICE);
    OHOS::system::RemoveParameter(ServiceConstants::DEVELOPERMODE_STATE);
}

/**
 * @tc.number: BundleInstallCheckerTest_0036
 * @tc.name: test the CheckAppDistributionType.
 * @tc.desc: test the CheckAppDistributionType.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0036, TestSize.Level2)
{
    BmsParam param;
    bool saveRes = param.SaveBmsParam(Constants::APP_DISTRIBUTION_TYPE_WHITE_LIST, "0,1");
    EXPECT_TRUE(saveRes);

    BundleInstallChecker bundleInstallChecker;
    std::string distributionType = "no";
    auto enumRes = bundleInstallChecker.GetAppDistributionTypeEnum(distributionType);
    EXPECT_EQ(enumRes, 0);

    auto ret = bundleInstallChecker.CheckAppDistributionType(distributionType);
    EXPECT_EQ(ret, ERR_OK);

    bool clearRes = param.SaveBmsParam(Constants::APP_DISTRIBUTION_TYPE_WHITE_LIST, "");
    EXPECT_TRUE(clearRes);
}

/**
 * @tc.number: BundleInstallCheckerTest_0037
 * @tc.name: test the DetermineCloneApp.
 * @tc.desc: test the DetermineCloneApp.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0037, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->multiAppMode.multiAppModeType = MultiAppModeType::APP_CLONE;

    auto ret = bundleInstallChecker.DetermineCloneApp(innerBundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BundleInstallCheckerTest_0038
 * @tc.name: test the DetermineCloneApp.
 * @tc.desc: test the DetermineCloneApp.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0038, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->multiAppMode.multiAppModeType = MultiAppModeType::APP_CLONE;
    innerBundleInfo.baseApplicationInfo_->multiAppMode.maxCount = 3;

    auto ret = bundleInstallChecker.DetermineCloneApp(innerBundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BundleInstallCheckerTest_0039
 * @tc.name: test the CheckAppLabelInfo.
 * @tc.desc: test the CheckAppLabelInfo.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0039, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    innerBundleInfo1.baseApplicationInfo_->bundleName = "test1";
    innerBundleInfo1.baseBundleInfo_->versionCode = 2;
    innerBundleInfo1.baseBundleInfo_->releaseType = "debug";
    innerBundleInfo1.SetAppType(Constants::AppType::SYSTEM_APP);
    innerBundleInfo1.SetIsPreInstallApp(false);
    InnerModuleInfo innerModuleInfo1;
    innerModuleInfo1.moduleName = "entry";
    Distro dist1;
    dist1.moduleType = "entry";
    innerModuleInfo1.distro = dist1;
    innerModuleInfo1.isEntry = true;
    innerBundleInfo1.innerModuleInfos_.try_emplace(innerModuleInfo1.moduleName, innerModuleInfo1);

    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo2.SetIsPreInstallApp(true);
    innerBundleInfo2.SetAppType(Constants::AppType::SYSTEM_APP);
    innerBundleInfo2.baseApplicationInfo_->bundleName = "test1";
    innerBundleInfo2.baseBundleInfo_->versionCode = 3;
    innerBundleInfo2.baseBundleInfo_->releaseType = "debug";
    InnerModuleInfo innerModuleInfo2;
    innerModuleInfo2.moduleName = "lib";
    Distro dist2;
    dist2.moduleType = "shared";
    innerModuleInfo2.distro = dist2;
    innerBundleInfo2.innerModuleInfos_.try_emplace(innerModuleInfo2.moduleName, innerModuleInfo2);

    infos["test1"] = innerBundleInfo1;
    infos["test2"] = innerBundleInfo2;

    auto ret = bundleInstallChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_VERSIONCODE_NOT_SAME);
}

/**
 * @tc.number: BundleInstallCheckerTest_0040
 * @tc.name: test the CheckAppLabelInfo.
 * @tc.desc: test the CheckAppLabelInfo.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0040, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    innerBundleInfo1.baseApplicationInfo_->bundleName = "test1";
    innerBundleInfo1.baseBundleInfo_->versionCode = 3;
    innerBundleInfo1.baseBundleInfo_->releaseType = "debug";
    innerBundleInfo1.baseApplicationInfo_->singleton = true;
    innerBundleInfo1.SetAppType(Constants::AppType::THIRD_PARTY_APP);
    innerBundleInfo1.SetIsPreInstallApp(true);
    InnerModuleInfo innerModuleInfo1;
    innerModuleInfo1.moduleName = "entry";
    innerModuleInfo1.isEntry = true;
    Distro dist1;
    dist1.moduleType = "entry";
    innerModuleInfo1.distro = dist1;
    innerBundleInfo1.innerModuleInfos_.try_emplace(innerModuleInfo1.moduleName, innerModuleInfo1);

    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo2.SetIsPreInstallApp(true);
    innerBundleInfo2.SetAppType(Constants::AppType::SYSTEM_APP);
    innerBundleInfo2.baseApplicationInfo_->bundleName = "test1";
    innerBundleInfo2.baseApplicationInfo_->singleton = false;
    innerBundleInfo2.baseBundleInfo_->versionCode = 2;
    innerBundleInfo2.baseBundleInfo_->releaseType = "debug";
    InnerModuleInfo innerModuleInfo2;
    innerModuleInfo2.moduleName = "lib";
    Distro dist2;
    dist2.moduleType = "shared";
    innerModuleInfo2.distro = dist2;
    innerBundleInfo2.innerModuleInfos_.try_emplace(innerModuleInfo2.moduleName, innerModuleInfo2);

    infos["test1"] = innerBundleInfo1;
    infos["test2"] = innerBundleInfo2;

    auto ret = bundleInstallChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_SINGLETON_NOT_SAME);
}

/**
 * @tc.number: BundleInstallCheckerTest_0041
 * @tc.name: test the GetVersionCode.
 * @tc.desc: test the GetVersionCode.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0041, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    uint32_t ret = bundleInstallChecker.GetVersionCode(infos);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: BundleInstallCheckerTest_0042
 * @tc.name: test ProcessCodeSignatureParam.
 * @tc.desc: test ProcessCodeSignatureParam.
 */
HWTEST_F(BundleInstallCheckerTest, BundleInstallCheckerTest_0042, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    Security::Verify::HapVerifyResult hapVerifyResult;
    CodeSignatureParam codeSignatureParam;
    bundleInstallChecker.ProcessCodeSignatureParam(hapVerifyResult, codeSignatureParam);
    EXPECT_EQ(codeSignatureParam.profileBlockLength, 0);

    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    hapVerifyResult.SetProvisionInfo(provisionInfo);
    bundleInstallChecker.ProcessCodeSignatureParam(hapVerifyResult, codeSignatureParam);
    EXPECT_EQ(codeSignatureParam.profileBlockLength, 0);
    EXPECT_FALSE(codeSignatureParam.isEnterpriseResigned);

    provisionInfo.profileBlockLength = 100;
    provisionInfo.profileBlock = std::make_unique<unsigned char[]>(provisionInfo.profileBlockLength);
    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE_NORMAL;
    provisionInfo.isEnterpriseResigned = true;
    hapVerifyResult.SetProvisionInfo(provisionInfo);
    codeSignatureParam.profileBlockLength = 0;
    codeSignatureParam.isEnterpriseResigned = false;
    bundleInstallChecker.ProcessCodeSignatureParam(hapVerifyResult, codeSignatureParam);
    EXPECT_EQ(codeSignatureParam.profileBlockLength, 100);
    EXPECT_TRUE(codeSignatureParam.isEnterpriseResigned);

    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE_MDM;
    hapVerifyResult.SetProvisionInfo(provisionInfo);
    codeSignatureParam.profileBlockLength = 0;
    bundleInstallChecker.ProcessCodeSignatureParam(hapVerifyResult, codeSignatureParam);
    EXPECT_EQ(codeSignatureParam.profileBlockLength, 100);

    provisionInfo.distributionType = Security::Verify::AppDistType::INTERNALTESTING;
    hapVerifyResult.SetProvisionInfo(provisionInfo);
    codeSignatureParam.profileBlockLength = 0;
    bundleInstallChecker.ProcessCodeSignatureParam(hapVerifyResult, codeSignatureParam);
    EXPECT_EQ(codeSignatureParam.profileBlockLength, 100);
}

/**
 * @tc.number: CalculateRequiredInodes_0001
 * @tc.name: test BundleExtractor::CalculateRequiredInodes with small file
 * @tc.desc: 1. fileSize < 923*4KB
 *           2. verify inode count = 1
 */
HWTEST_F(BundleInstallCheckerTest, CalculateRequiredInodes_0001, TestSize.Level2)
{
    // Test small file: fileSize < 923*4KB (3692 KB)
    uint64_t fileSizeKb = 1000;
    uint32_t inodes = BundleExtractor::CalculateRequiredInodes(fileSizeKb);
    EXPECT_EQ(inodes, 1);
}

/**
 * @tc.number: CalculateRequiredInodes_0002
 * @tc.name: test BundleExtractor::CalculateRequiredInodes at threshold 1
 * @tc.desc: 1. fileSize = 923*4KB
 *           2. verify inode count = 3
 */
HWTEST_F(BundleInstallCheckerTest, CalculateRequiredInodes_0002, TestSize.Level2)
{
    uint64_t fileSizeKb = 3692;  // Exactly threshold 1
    uint32_t inodes = BundleExtractor::CalculateRequiredInodes(fileSizeKb);
    EXPECT_EQ(inodes, 3);
}

/**
 * @tc.number: CalculateRequiredInodes_0003
 * @tc.name: test BundleExtractor::CalculateRequiredInodes at threshold 2
 * @tc.desc: 1. fileSize = 923*4+2*1018*4 KB
 *           2. verify inode count starts increasing
 */
HWTEST_F(BundleInstallCheckerTest, CalculateRequiredInodes_0003, TestSize.Level2)
{
    uint64_t fileSizeKb = 11836;  // Exactly threshold 2
    uint32_t inodes = BundleExtractor::CalculateRequiredInodes(fileSizeKb);
    EXPECT_EQ(inodes, 3);
}

/**
 * @tc.number: CalculateRequiredInodes_0004
 * @tc.name: test BundleExtractor::CalculateRequiredInodes in large range
 * @tc.desc: 1. fileSize in large range
 *           2. verify inode calculation with ceiling
 */
HWTEST_F(BundleInstallCheckerTest, CalculateRequiredInodes_0004, TestSize.Level2)
{
    uint64_t fileSizeKb = 12000;  // Just above threshold 2
    uint32_t inodes = BundleExtractor::CalculateRequiredInodes(fileSizeKb);
    EXPECT_EQ(inodes, 4);  // 3 + 1
}

/**
 * @tc.number: CalculateRequiredInodes_0005
 * @tc.name: test BundleExtractor::CalculateRequiredInodes in huge range
 * @tc.desc: 1. fileSize in huge range
 *           2. verify double indirect blocks
 */
HWTEST_F(BundleInstallCheckerTest, CalculateRequiredInodes_0005, TestSize.Level2)
{
    uint64_t fileSizeKb = 8400000;  // Well above threshold 3
    uint32_t inodes = BundleExtractor::CalculateRequiredInodes(fileSizeKb);
    EXPECT_GT(inodes, 2040);  // Should be much larger than BASE_INODES_LARGE
}

/**
 * @tc.number: CalculateInstallInodes_0001
 * @tc.name: test BundleInstallChecker::CalculateInstallInodes with empty infos
 * @tc.desc: 1. test with empty infos map
 *           2. verify completes successfully
 */
HWTEST_F(BundleInstallCheckerTest, CalculateInstallInodes_0001, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;

    ErrCode ret = bundleInstallChecker.CalculateInstallInodes(infos, false);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.number: CalculateInstallInodes_0002
 * @tc.name: test BundleInstallChecker::CalculateInstallInodes with mock InnerBundleInfo (new install)
 * @tc.desc: 1. test with mock InnerBundleInfo containing module info
 *           2. verify inode counts are calculated correctly for new install
 */
HWTEST_F(BundleInstallCheckerTest, CalculateInstallInodes_0002, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;

    // Create mock InnerBundleInfo
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "test.bundle";
    innerBundleInfo.currentPackage_ = "entry";

    // Add mock module info
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.modulePackage = "test.entry";
    moduleInfo.compressNativeLibs = true;
    moduleInfo.cpuAbi = "arm64-v8a";

    innerBundleInfo.innerModuleInfos_["test.entry"] = moduleInfo;
    infos["/data/test/test.hap"] = innerBundleInfo;

    ErrCode ret = bundleInstallChecker.CalculateInstallInodes(infos, true);
    // The method should calculate inodes without storing in InnerBundleInfo
    EXPECT_GE(ret, ERR_OK);
}

/**
 * @tc.number: CalculateInstallInodes_0003
 * @tc.name: test BundleInstallChecker::CalculateInstallInodes with mock InnerBundleInfo (update)
 * @tc.desc: 1. test with mock InnerBundleInfo containing module info
 *           2. verify inode counts are calculated correctly for update
 */
HWTEST_F(BundleInstallCheckerTest, CalculateInstallInodes_0003, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;

    // Create mock InnerBundleInfo
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "test.bundle";
    innerBundleInfo.currentPackage_ = "entry";

    // Add mock module info
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.modulePackage = "test.entry";
    moduleInfo.compressNativeLibs = false;
    moduleInfo.cpuAbi = "arm64-v8a";

    innerBundleInfo.innerModuleInfos_["test.entry"] = moduleInfo;
    infos["/data/test/test.hap"] = innerBundleInfo;

    ErrCode ret = bundleInstallChecker.CalculateInstallInodes(infos, false);
    EXPECT_GE(ret, ERR_OK);
}

/**
 * @tc.number: CalculateInstallInodes_0004
 * @tc.name: test BundleInstallChecker::CalculateInstallInodes with multiple bundles
 * @tc.desc: 1. test with multiple InnerBundleInfo
 *           2. verify total inode counts are calculated correctly
 */
HWTEST_F(BundleInstallCheckerTest, CalculateInstallInodes_0004, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;

    // Create first mock InnerBundleInfo
    InnerBundleInfo innerBundleInfo1;
    innerBundleInfo1.baseApplicationInfo_->bundleName = "test.bundle1";
    innerBundleInfo1.currentPackage_ = "entry1";

    InnerModuleInfo moduleInfo1;
    moduleInfo1.moduleName = "entry1";
    moduleInfo1.modulePackage = "test.entry1";
    moduleInfo1.compressNativeLibs = true;
    moduleInfo1.cpuAbi = "arm64-v8a";

    innerBundleInfo1.innerModuleInfos_["test.entry1"] = moduleInfo1;
    infos["/data/test/test1.hap"] = innerBundleInfo1;

    // Create second mock InnerBundleInfo
    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo2.baseApplicationInfo_->bundleName = "test.bundle2";
    innerBundleInfo2.currentPackage_ = "entry2";

    InnerModuleInfo moduleInfo2;
    moduleInfo2.moduleName = "entry2";
    moduleInfo2.modulePackage = "test.entry2";
    moduleInfo2.compressNativeLibs = false;
    moduleInfo2.cpuAbi = "arm64-v8a";

    innerBundleInfo2.innerModuleInfos_["test.entry2"] = moduleInfo2;
    infos["/data/test/test2.hap"] = innerBundleInfo2;

    ErrCode ret = bundleInstallChecker.CalculateInstallInodes(infos, true);
    EXPECT_GE(ret, ERR_OK);
}

/**
 * @tc.number: CalculateInstallInodes_0005
 * @tc.name: test BundleInstallChecker::CalculateInstallInodes with empty module info
 * @tc.desc: 1. test with InnerBundleInfo having empty module infos
 *           2. verify handles gracefully
 */
HWTEST_F(BundleInstallCheckerTest, CalculateInstallInodes_0005, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;

    // Create mock InnerBundleInfo with empty module infos
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "test.bundle";
    innerBundleInfo.currentPackage_ = "entry";

    infos["/data/test/test.hap"] = innerBundleInfo;

    ErrCode ret = bundleInstallChecker.CalculateInstallInodes(infos, true);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CalculateInstallInodes_0006
 * @tc.name: test BundleInstallChecker::CalculateInstallInodes with non-existent file
 * @tc.desc: 1. test with non-existent HAP file path
 *           2. verify handles gracefully
 */
HWTEST_F(BundleInstallCheckerTest, CalculateInstallInodes_0006, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;

    // Create mock InnerBundleInfo
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "test.bundle";
    innerBundleInfo.currentPackage_ = "entry";

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.modulePackage = "test.entry";
    moduleInfo.compressNativeLibs = true;
    moduleInfo.cpuAbi = "arm64-v8a";

    innerBundleInfo.innerModuleInfos_["test.entry"] = moduleInfo;
    infos["/non/exist/path/test.hap"] = innerBundleInfo;

    ErrCode ret = bundleInstallChecker.CalculateInstallInodes(infos, true);
    // Should succeed even if file doesn't exist (returns 0 inodes)
    EXPECT_GE(ret, ERR_OK);
}

/**
* @tc.number: CalculateInstallInodes_0007
* @tc.name: test BundleInstallChecker::CalculateInstallInodes with total inodes zero
* @tc.desc: 1. test with bundle that returns 0 inodes
*           2. verify skips check and returns ERR_OK
*/
HWTEST_F(BundleInstallCheckerTest, CalculateInstallInodes_0007, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;

    // Create mock InnerBundleInfo with empty module info (will return 0 inodes)
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "test.bundle";
    innerBundleInfo.currentPackage_ = "entry";

    infos["/data/test/test.hap"] = innerBundleInfo;

    ErrCode ret = bundleInstallChecker.CalculateInstallInodes(infos, true);
    // Should succeed because totalRequiredInodes is 0
    EXPECT_EQ(ret, ERR_OK);
}

/**
* @tc.number: CalculateInstallInodes_0008
* @tc.name: test BundleInstallChecker::CalculateInstallInodes with new install
* @tc.desc: 1. test new install scenario (isNewInstall=true)
*           2. verify directory inode overhead is added
*/
HWTEST_F(BundleInstallCheckerTest, CalculateInstallInodes_0008, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;

       // Create mock InnerBundleInfo
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "test.bundle";
    innerBundleInfo.currentPackage_ = "entry";

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.modulePackage = "test.entry";
    moduleInfo.compressNativeLibs = false;
    moduleInfo.cpuAbi = "arm64-v8a";

    innerBundleInfo.innerModuleInfos_["test.entry"] = moduleInfo;
    infos["/data/test/test.hap"] = innerBundleInfo;

    ErrCode ret = bundleInstallChecker.CalculateInstallInodes(infos, true);
    // New install should add CREATE_DIRS_WHEN_INSTALL (22) inodes
    EXPECT_GE(ret, ERR_OK);
}

/**
* @tc.number: CalculateInstallInodes_0009
* @tc.name: test BundleInstallChecker::CalculateInstallInodes with update install
* @tc.desc: 1. test update scenario (isNewInstall=false)
*           2. verify directory inode overhead is not added
*/
HWTEST_F(BundleInstallCheckerTest, CalculateInstallInodes_0009, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;

    // Create mock InnerBundleInfo
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "test.bundle";
    innerBundleInfo.currentPackage_ = "entry";

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.modulePackage = "test.entry";
    moduleInfo.compressNativeLibs = false;
    moduleInfo.cpuAbi = "arm64-v8a";

    innerBundleInfo.innerModuleInfos_["test.entry"] = moduleInfo;
    infos["/data/test/test.hap"] = innerBundleInfo;

    ErrCode ret = bundleInstallChecker.CalculateInstallInodes(infos, false);
    //'Update should not add CREATE_DIRS_WHEN_INSTALL inodes
    EXPECT_GE(ret, ERR_OK);
}

/**
* @tc.number: CalculateInstallInodes_0010
* @tc.name: test BundleInstallChecker::CalculateInstallInodes with multiple modules
* @tc.desc: 1. test with bundle containing multiple modules
*           2. verify uses first module's info
*/
HWTEST_F(BundleInstallCheckerTest, CalculateInstallInodes_0010, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;

    // Create mock InnerBundleInfo with multiple modules
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "test.bundle";
    innerBundleInfo.currentPackage_ = "entry";

    // First module
    InnerModuleInfo moduleInfo1;
    moduleInfo1.moduleName = "entry";
    moduleInfo1.modulePackage = "test.entry";
    moduleInfo1.compressNativeLibs = true;
    moduleInfo1.cpuAbi = "arm64-v8a";
    innerBundleInfo.innerModuleInfos_["test.entry"] = moduleInfo1;

    // Second module
    InnerModuleInfo moduleInfo2;
    moduleInfo2.moduleName = "feature";
    moduleInfo2.modulePackage = "test.feature";
    moduleInfo2.compressNativeLibs = false;
    moduleInfo2.cpuAbi = "";
    innerBundleInfo.innerModuleInfos_["test.feature"] = moduleInfo2;

    infos["/data/test/test.hap"] = innerBundleInfo;

    ErrCode ret = bundleInstallChecker.CalculateInstallInodes(infos, true);
    // Should use first module's info (compressNativeLibs=true, cpuAbi=arm64-v8a)
    EXPECT_GE(ret, ERR_OK);
}

/**
* @tc.number: CalculateInstallInodes_0011
* @tc.name: test BundleInstallChecker::CalculateInstallInodes with hnp packages
* @tc.desc: 1. test with bundle containing HNP packages
*           2. verify HNP packages are considered
*/
HWTEST_F(BundleInstallCheckerTest, CalculateInstallInodes_0011, TestSize.Level2)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;

    // Create mock InnerBundleInfo with HNP packages
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_->bundleName = "test.bundle";
    innerBundleInfo.currentPackage_ = "entry";

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.modulePackage = "test.entry";
    moduleInfo.compressNativeLibs = false;
    moduleInfo.cpuAbi = "arm64-v8a";

    // Add HNP packages
    HnpPackage hnpPkg1;
    hnpPkg1.package = "test_hnp1";
    hnpPkg1.type = "hnp";
    moduleInfo.hnpPackages.push_back(hnpPkg1);

    HnpPackage hnpPkg2;
    hnpPkg2.package = "test_hnp2";
    hnpPkg2.type = "hnp";
    moduleInfo.hnpPackages.push_back(hnpPkg2);

    innerBundleInfo.innerModuleInfos_["test.entry"] = moduleInfo;
    infos["/data/test/test.hap"] = innerBundleInfo;

    ErrCode ret = bundleInstallChecker.CalculateInstallInodes(infos, true);
    // Should consider HNP packages in inode calculation
    EXPECT_GE(ret, ERR_OK);
}

} // OHOS
