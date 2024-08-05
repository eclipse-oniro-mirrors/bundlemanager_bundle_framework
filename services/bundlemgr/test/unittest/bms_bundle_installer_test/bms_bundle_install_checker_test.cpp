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

#include <cstdio>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include "app_provision_info.h"
#include "base_bundle_installer.h"
#include "bundle_install_checker.h"
#include "bundle_verify_mgr.h"
#include "bundle_util.h"
#include "bundle_mgr_service.h"
#include "directory_ex.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
const std::string HAP = "hap";
const std::string HAP_ONE = "hap1";
const std::string HAP_TWO = "hap2";
const std::string HAP_THREE = "hap3";
const std::string HAP_FOUR = "hap4";
const std::string HAP_FIVE = "hap5";
const std::string ARM = "arm";
const std::string ARM_SO_PATH = "/lib/arm/arm.so";
const std::string ARM_AN_PATH = "/an/arm/arm.so";
const std::string X86 = "x86";
const std::string X86_SO_PATH = "/lib/x86/x86.so";
const std::string X86_AN_PATH = "/an/x86/x86.so";
const std::string BUNDLE_NAME = "com.example.test";
const std::string TEST_PATH = "//com.example.test/";
const std::string MODULE_PACKAGE = "com.example.test";
const std::string MODULE_PATH = "test_tmp";
const std::string ENTRY = "entry";
const std::string PROXY_DATAS = "2";
const std::string NONISOLATION_ONLY_VALUE = "nonisolationOnly";
const std::string ISOLATION_ONLY_VALUE = "isolationOnly";
const int32_t PRIORITY_ONE = 1;
const int32_t PRIORITY_TWO = 2;
const int32_t TEST_UID = 20013999;
const int32_t TEST_BUNDLE_ID = 13999;
}  // namespace

class BmsBundleInstallCheckerTest : public testing::Test {
public:
    BmsBundleInstallCheckerTest();
    ~BmsBundleInstallCheckerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleInstallCheckerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleInstallCheckerTest::BmsBundleInstallCheckerTest()
{}

BmsBundleInstallCheckerTest::~BmsBundleInstallCheckerTest()
{}

void BmsBundleInstallCheckerTest::SetUpTestCase()
{
}

void BmsBundleInstallCheckerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleInstallCheckerTest::SetUp()
{}

void BmsBundleInstallCheckerTest::TearDown()
{}

/**
 * @tc.number: CheckMultiNativeFile_0100
 * @tc.name: test the start function of BundleInstallChecker
 * @tc.desc: 1. BundleInstallChecker
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckMultiNativeFile_0100, Function | SmallTest | Level0)
{
    BundleInstallChecker bundleInstallChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    infos.emplace(HAP, innerBundleInfo);

    InnerBundleInfo innerBundleInfo1;
    innerBundleInfo1.SetArkNativeFileAbi(ARM);
    innerBundleInfo1.SetArkNativeFilePath(ARM_AN_PATH);
    innerBundleInfo1.SetCpuAbi(ARM);
    innerBundleInfo1.SetNativeLibraryPath(ARM_SO_PATH);
    infos.emplace(HAP_ONE, innerBundleInfo1);

    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo2.SetArkNativeFileAbi(ARM);
    innerBundleInfo2.SetArkNativeFilePath(ARM_AN_PATH);
    innerBundleInfo2.SetCpuAbi(ARM);
    innerBundleInfo2.SetNativeLibraryPath(ARM_SO_PATH);
    infos.emplace(HAP_TWO, innerBundleInfo2);
    ErrCode ret = bundleInstallChecker.CheckMultiNativeFile(infos);
    EXPECT_EQ(ret, ERR_OK);

    InnerBundleInfo innerBundleInfo3;
    infos.emplace(HAP_THREE, innerBundleInfo3);
    ret = bundleInstallChecker.CheckMultiNativeFile(infos);
    EXPECT_EQ(ret, ERR_OK);

    InnerBundleInfo innerBundleInfo4;
    innerBundleInfo4.SetArkNativeFileAbi(X86);
    innerBundleInfo4.SetArkNativeFilePath(X86_AN_PATH);
    infos.emplace(HAP_FOUR, innerBundleInfo4);
    ret = bundleInstallChecker.CheckMultiNativeFile(infos);
    EXPECT_NE(ret, ERR_OK);

    InnerBundleInfo innerBundleInfo5;
    innerBundleInfo5.SetCpuAbi(X86);
    innerBundleInfo5.SetNativeLibraryPath(X86_SO_PATH);
    infos.emplace(HAP_FIVE, innerBundleInfo5);
    ret = bundleInstallChecker.CheckMultiNativeFile(infos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: CheckMultiNativeFile_0200
 * @tc.name: Test CheckMultiNativeFile
 * @tc.desc: 1.Test the CheckMultiNativeFile of InnerBundleInfo
 */
HWTEST_F(BmsBundleInstallCheckerTest, CheckMultiNativeFile_0200, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo1;
    innerBundleInfo1.SetCpuAbi(ARM);
    innerBundleInfo1.SetNativeLibraryPath(ARM_SO_PATH);
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos.emplace(HAP_ONE, innerBundleInfo1);
    BundleInstallChecker installChecker;
    ErrCode ret = installChecker.CheckMultiNativeFile(infos);
    EXPECT_EQ(ret, ERR_OK);
    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo2.SetCpuAbi(X86);
    innerBundleInfo2.SetNativeLibraryPath(X86_SO_PATH);
    infos.emplace(HAP_TWO, innerBundleInfo2);
    ret = installChecker.CheckMultiNativeFile(infos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: CheckMultiNativeFile_0300
 * @tc.name: Test CheckMultiNativeFile
 * @tc.desc: 1.Test the CheckMultiNativeFile of InnerBundleInfo
 */
HWTEST_F(BmsBundleInstallCheckerTest, CheckMultiNativeFile_0300, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo1;
    innerBundleInfo1.SetArkNativeFileAbi(ARM);
    innerBundleInfo1.SetArkNativeFilePath(ARM_AN_PATH);
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos.emplace(HAP_ONE, innerBundleInfo1);

    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo2.SetArkNativeFileAbi(X86);
    innerBundleInfo2.SetArkNativeFilePath(X86_AN_PATH);
    infos.emplace(HAP_TWO, innerBundleInfo2);
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckMultiNativeFile(infos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: CheckMultiArkNativeFile_0100
 * @tc.name: Test CheckMultiArkNativeFile
 * @tc.desc: 1.Test the CheckMultiArkNativeFile of InnerBundleInfo
 */
HWTEST_F(BmsBundleInstallCheckerTest, CheckMultiArkNativeFile_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo1;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos.emplace(HAP_ONE, innerBundleInfo1);
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckMultiArkNativeFile(infos);
    EXPECT_EQ(ret, ERR_OK);
    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo2.SetArkNativeFileAbi(ARM);
    infos.emplace(HAP_TWO, innerBundleInfo1);
    ret = installChecker.CheckMultiArkNativeFile(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckMultiArkNativeFile_0200
 * @tc.name: Test CheckMultiArkNativeFile
 * @tc.desc: 1.Test the CheckMultiArkNativeFile of InnerBundleInfo
 */
HWTEST_F(BmsBundleInstallCheckerTest, CheckMultiArkNativeFile_0200, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo1;
    innerBundleInfo1.SetArkNativeFileAbi(ARM);
    innerBundleInfo1.SetArkNativeFilePath(ARM_AN_PATH);
    innerBundleInfo1.SetCpuAbi(ARM);
    innerBundleInfo1.SetNativeLibraryPath(ARM_SO_PATH);
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos.emplace(HAP_ONE, innerBundleInfo1);

    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo2.SetArkNativeFileAbi(X86);
    innerBundleInfo2.SetArkNativeFilePath(X86_AN_PATH);
    infos.emplace(HAP_TWO, innerBundleInfo2);
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckMultiArkNativeFile(infos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: ExtractModule_0100
 * @tc.name: test the start function of ExtractModule
 * @tc.desc: 1. BaseBundleInstaller
 * @tc.require: issueI5VW01
*/
HWTEST_F(BmsBundleInstallCheckerTest, ExtractModule_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.currentPackage_ = MODULE_PACKAGE;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isLibIsolated = true;
    innerModuleInfo.cpuAbi = X86;
    innerModuleInfo.nativeLibraryPath = X86;
    innerModuleInfo.moduleName = MODULE_PACKAGE;
    innerModuleInfo.modulePackage = MODULE_PACKAGE;
    innerModuleInfo.name = MODULE_PACKAGE;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_PACKAGE, innerModuleInfo);
    BaseBundleInstaller baseBundleInstaller;
    baseBundleInstaller.modulePackage_ = MODULE_PACKAGE;
    ErrCode ret = baseBundleInstaller.ExtractModule(innerBundleInfo, MODULE_PATH);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: CheckSysCape_0100
 * @tc.name: test the start function of CheckSysCap
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckSysCape_0100, Function | SmallTest | Level0)
{
    std::string bundlePath = "/data/test/test.hap";
    std::vector<std::string> bundlePaths;
    bundlePaths.push_back(bundlePath);
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckSysCap(bundlePaths);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: CheckSystemSize_0100
 * @tc.name: test the start function of CheckSystemSize
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckSystemSize_0100, Function | SmallTest | Level0)
{
    std::string bundlePath = "/data/app/el1/bundle";
    Constants::AppType appType = Constants::AppType::SYSTEM_APP;
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckSystemSize(bundlePath, appType);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckSystemSize_0200
 * @tc.name: test the start function of CheckSystemSize
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckSystemSize_0200, Function | SmallTest | Level0)
{
    std::string bundlePath = "/data/app/el1/bundle";
    Constants::AppType appType = Constants::AppType::THIRD_SYSTEM_APP;
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckSystemSize(bundlePath, appType);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckSystemSize_0300
 * @tc.name: test the start function of CheckSystemSize
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckSystemSize_0300, Function | SmallTest | Level0)
{
    std::string bundlePath = "/data/app/el1/bundle";
    Constants::AppType appType = Constants::AppType::THIRD_PARTY_APP;
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckSystemSize(bundlePath, appType);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckSystemSize_0400
 * @tc.name: test the start function of CheckSystemSize
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckSystemSize_0400, Function | SmallTest | Level0)
{
    std::string bundlePath = "";
    Constants::AppType appType = Constants::AppType::THIRD_PARTY_APP;
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckSystemSize(bundlePath, appType);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT);
}

/**
 * @tc.number: CheckSystemSize_0500
 * @tc.name: test the start function of CheckSystemSize
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckSystemSize_0500, Function | SmallTest | Level0)
{
    std::string bundlePath = "/data/app/el1/bundle/public/patch_1000001";
    bool res = BundleUtil::CreateDir(bundlePath);
    EXPECT_TRUE(res);

    Constants::AppType appType = Constants::AppType::SYSTEM_APP;
    Constants::AppType appType1 = Constants::AppType::THIRD_SYSTEM_APP;
    Constants::AppType appType2 = Constants::AppType::THIRD_PARTY_APP;
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckSystemSize(bundlePath, appType);
    EXPECT_EQ(ret, ERR_OK);
    ret = installChecker.CheckSystemSize(bundlePath, appType1);
    EXPECT_EQ(ret, ERR_OK);
    ret = installChecker.CheckSystemSize(bundlePath, appType2);
    EXPECT_EQ(ret, ERR_OK);

    res = BundleUtil::DeleteDir(bundlePath);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: CheckSystemSize_0600
 * @tc.name: test the start function of CheckSystemSize
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckSystemSize_0600, Function | SmallTest | Level0)
{
    std::string bundlePath = "/data/app/el1/bundle/100";
    Constants::AppType appType = Constants::AppType::SYSTEM_APP;
    Constants::AppType appType1 = Constants::AppType::THIRD_SYSTEM_APP;
    Constants::AppType appType2 = Constants::AppType::THIRD_PARTY_APP;
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckSystemSize(bundlePath, appType);
    EXPECT_EQ(ret, ERR_OK);
    ret = installChecker.CheckSystemSize(bundlePath, appType1);
    EXPECT_EQ(ret, ERR_OK);
    ret = installChecker.CheckSystemSize(bundlePath, appType2);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckSystemSize_0700
 * @tc.name: test the start function of CheckSystemSize
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckSystemSize_0700, Function | SmallTest | Level0)
{
    std::string bundlePath = "/data/app/el1/bundle/0";
    Constants::AppType appType = Constants::AppType::SYSTEM_APP;
    Constants::AppType appType1 = Constants::AppType::THIRD_SYSTEM_APP;
    Constants::AppType appType2 = Constants::AppType::THIRD_PARTY_APP;
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckSystemSize(bundlePath, appType);
    EXPECT_EQ(ret, ERR_OK);
    ret = installChecker.CheckSystemSize(bundlePath, appType1);
    EXPECT_EQ(ret, ERR_OK);
    ret = installChecker.CheckSystemSize(bundlePath, appType2);
    EXPECT_EQ(ret, ERR_OK);
}
/**
 * @tc.number: CheckHapHashParams_0100
 * @tc.name: test the start function of CheckHapHashParams
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckHapHashParams_0100, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::map<std::string, std::string> hashParams;
    hashParams.insert(pair<string, string>("1", "2"));
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckHapHashParams(infos, hashParams);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_CHECK_HAP_HASH_PARAM);
}

/**
 * @tc.number: IsExistedDistroModule_0100
 * @tc.name: test the start function of IsExistedDistroModule
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, IsExistedDistroModule_0100, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo newInfo;
    InnerBundleInfo info;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = ".entry";
    newInfo.currentPackage_ = "";
    newInfo.InsertInnerModuleInfo("", innerModuleInfo);
    auto ret = installChecker.IsExistedDistroModule(newInfo, info);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsExistedDistroModule_0200
 * @tc.name: test the start function of IsExistedDistroModule
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, IsExistedDistroModule_0200, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo newInfo;
    InnerBundleInfo info;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "";
    newInfo.currentPackage_ = "1";
    newInfo.InsertInnerModuleInfo("1", innerModuleInfo);
    auto ret = installChecker.IsExistedDistroModule(newInfo, info);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsExistedDistroModule_0300
 * @tc.name: test the start function of IsExistedDistroModule
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, IsExistedDistroModule_0300, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo newInfo;
    InnerBundleInfo info;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "";
    newInfo.currentPackage_ = "1";
    newInfo.InsertInnerModuleInfo("", innerModuleInfo);
    auto ret = installChecker.IsExistedDistroModule(newInfo, info);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsExistedDistroModule_0400
 * @tc.name: test the start function of IsExistedDistroModule
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, IsExistedDistroModule_0400, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo newInfo;
    InnerBundleInfo info;
    InnerModuleInfo innerModuleInfo;
    info.InsertInnerModuleInfo(HAP, innerModuleInfo);
    innerModuleInfo.moduleName = ENTRY;
    newInfo.SetCurrentModulePackage(MODULE_PACKAGE);
    newInfo.SetIsNewVersion(false);
    newInfo.InsertInnerModuleInfo(HAP, innerModuleInfo);
    auto ret = installChecker.IsExistedDistroModule(newInfo, info);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsExistedDistroModule_0500
 * @tc.name: test the start function of IsExistedDistroModule
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, IsExistedDistroModule_0500, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo newInfo;
    InnerBundleInfo info;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = HAP;
    newInfo.SetCurrentModulePackage(HAP);
    newInfo.SetIsNewVersion(true);
    newInfo.InsertInnerModuleInfo(HAP, innerModuleInfo);
    info.SetIsNewVersion(false);
    info.InsertInnerModuleInfo(HAP, innerModuleInfo);
    auto ret = installChecker.IsExistedDistroModule(newInfo, info);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: CheckMainElement_0100
 * @tc.name: test the start function of CheckMainElement
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckMainElement_0100, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo info;
    info.innerModuleInfos_.clear();
    auto ret = installChecker.CheckMainElement(info);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckMainElement_0200
 * @tc.name: test the start function of CheckMainElement
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckMainElement_0200, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo info;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.distro.moduleType = Profile::MODULE_TYPE_SHARED;
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    info.AddInnerModuleInfo(innerModuleInfos);
    auto ret = installChecker.CheckMainElement(info);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckMainElement_0300
 * @tc.name: test the start function of CheckMainElement
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckMainElement_0300, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo info;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.distro.moduleType = Profile::MODULE_TYPE_ENTRY;
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    info.AddInnerModuleInfo(innerModuleInfos);
    auto ret = installChecker.CheckMainElement(info);
    EXPECT_EQ(ret, ERR_OK);
    BundleInfo bundleInfo;
    bundleInfo.entryInstallationFree = true;
    info.SetBaseBundleInfo(bundleInfo);
    ret = installChecker.CheckMainElement(info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR);
}

/**
 * @tc.number: GetPrivilegeCapabilityValue_0100
 * @tc.name: test the start function of GetPrivilegeCapabilityValue
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, GetPrivilegeCapabilityValue_0100, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo info;
    std::vector<std::string> existInJson;
    existInJson.push_back("1");
    existInJson.push_back("2");
    std::string key = "1";
    bool existInPreJson = true;
    bool existInProvision = false;
    auto ret = installChecker.GetPrivilegeCapabilityValue(existInJson, key, existInPreJson, existInProvision);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetPrivilegeCapabilityValue_0200
 * @tc.name: test the start function of GetPrivilegeCapabilityValue
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, GetPrivilegeCapabilityValue_0200, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo info;
    std::vector<std::string> existInJson;
    existInJson.push_back("1");
    existInJson.push_back("2");
    std::string key = "0";
    bool existInPreJson = true;
    bool existInProvision = false;
    auto ret = installChecker.GetPrivilegeCapabilityValue(existInJson, key, existInPreJson, existInProvision);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CheckDeviceType_0100
 * @tc.name: test the start function of CheckDeviceType
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckDeviceType_0100, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    InnerBundleInfo innerBundleInfo2;
    infos.insert(pair<string, InnerBundleInfo>("1", innerBundleInfo1));
    infos.insert(pair<string, InnerBundleInfo>("2", innerBundleInfo2));
    auto ret = installChecker.CheckDeviceType(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckDeviceType_0200
 * @tc.name: test the start function of CollectProvisionInfo
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckDeviceType_0200, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    Security::Verify::ProvisionInfo provisionInfo;
    AppPrivilegeCapability appPrivilegeCapability;
    InnerBundleInfo newInfo;
    provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    provisionInfo.distributionType = Security::Verify::AppDistType::NONE_TYPE;
    installChecker.CollectProvisionInfo(provisionInfo, appPrivilegeCapability, newInfo);
    EXPECT_EQ(newInfo.GetAppProvisionType(), Constants::APP_PROVISION_TYPE_DEBUG);
}

/**
 * @tc.number: CheckDeviceType_0300
 * @tc.name: test the start function of CheckSysCap
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckDeviceType_0300, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    BundlePackInfo bundlePackInfo;
    InnerBundleInfo innerBundleInfo;
    installChecker.SetEntryInstallationFree(bundlePackInfo, innerBundleInfo);
    std::vector<std::string> bundlePaths;
    ErrCode res = installChecker.CheckSysCap(bundlePaths);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: CheckDeviceType_0400
 * @tc.name: test the start function of IsContainModuleName
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckDeviceType_0400, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo newInfo;
    InnerBundleInfo info;
    bool res = installChecker.IsContainModuleName(newInfo, info);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: CheckDeviceType_0500
 * @tc.name: test the start function of CheckModuleNameForMulitHaps
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckDeviceType_0500, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo newInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "";
    newInfo.AddInnerModuleInfo(innerModuleInfos);
    infos.emplace("/data/app/el1/bundle", newInfo);
    ErrCode res = installChecker.CheckModuleNameForMulitHaps(infos);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR);
}

/**
 * @tc.number: CheckDeviceType_0600
 * @tc.name: test the start function of MatchSignature
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckDeviceType_0600, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::vector<std::string> appSignatures;
    bool res = installChecker.MatchSignature(appSignatures, "");
    EXPECT_EQ(res, false);
    appSignatures.push_back("/data/app/el1/bundle");
    res = installChecker.MatchSignature(appSignatures, "");
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: CheckAppLabel_0001
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabel_0001, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    BaseBundleInstaller baseBundleInstaller;
    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_OK);
    oldInfo.SetAppFeature("hos_normal_app");
    newInfo.SetAppFeature("hos_system_app");
    ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_APPTYPE_NOT_SAME);
}

/**
 * @tc.number: CheckAppLabel_0002
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabel_0002, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.baseBundleInfo_->releaseType = "release_type";
    newInfo.baseBundleInfo_->releaseType = "normal_type";
    BaseBundleInstaller baseBundleInstaller;
    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_RELEASETYPE_NOT_SAME);
}

/**
 * @tc.number: CheckAppLabel_0003
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabel_0003, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.SetAppDistributionType("hos_normal_type");
    newInfo.SetAppDistributionType("hos_system_type");
    BaseBundleInstaller baseBundleInstaller;
    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_APP_DISTRIBUTION_TYPE_NOT_SAME);
}

/**
 * @tc.number: CheckAppLabel_0004
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabel_0004, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.SetAppProvisionType("hos_normal_type");
    newInfo.SetAppProvisionType("hos_system_type");
    BaseBundleInstaller baseBundleInstaller;
    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_APP_PROVISION_TYPE_NOT_SAME);
}

/**
 * @tc.number: CheckAppLabel_0005
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabel_0005, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.SetIsNewVersion(false);
    newInfo.SetIsNewVersion(true);
    BaseBundleInstaller baseBundleInstaller;
    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_STATE_ERROR);
}

/**
 * @tc.number: CheckAppLabel_0006
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabel_0006, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.SetAsanEnabled(false);
    newInfo.SetAsanEnabled(true);
    BaseBundleInstaller baseBundleInstaller;
    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabel_0007
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabel_0007, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.SetApplicationBundleType(BundleType::APP);
    newInfo.SetApplicationBundleType(BundleType::ATOMIC_SERVICE);
    BaseBundleInstaller baseBundleInstaller;
    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_BUNDLE_TYPE_NOT_SAME);
}

/**
 * @tc.number: GetCallingEventInfo_0001
 * @tc.name: test the start function of GetCallingEventInfo
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, GetCallingEventInfo_0001, Function | SmallTest | Level0)
{
    EventInfo eventInfo;
    BaseBundleInstaller baseBundleInstaller;
    baseBundleInstaller.GetCallingEventInfo(eventInfo);
    EXPECT_EQ(eventInfo.callingBundleName, Constants::EMPTY_STRING);
}

/**
 * @tc.number: GetCallingEventInfo_0002
 * @tc.name: test the start function of GetCallingEventInfo
 * @tc.desc: 1. BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallCheckerTest, GetCallingEventInfo_0002, Function | SmallTest | Level0)
{
    BaseBundleInstaller baseBundleInstaller;
    baseBundleInstaller.dataMgr_ = std::make_shared<BundleDataMgr>();
    EventInfo eventInfo;
    baseBundleInstaller.GetCallingEventInfo(eventInfo);
    EXPECT_EQ(eventInfo.callingBundleName, Constants::EMPTY_STRING);
}

/**
 * @tc.number: GetCallingEventInfo_0003
 * @tc.name: test the start function of GetCallingEventInfo
 * @tc.desc: 1. BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallCheckerTest, GetCallingEventInfo_0003, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = BUNDLE_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.bundleName = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.uid = TEST_UID;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.userId = 100;
    info.AddInnerBundleUserInfo(innerBundleUserInfo);
    BaseBundleInstaller baseBundleInstaller;
    baseBundleInstaller.dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(baseBundleInstaller.dataMgr_, nullptr);
    bool ret1 = baseBundleInstaller.dataMgr_ ->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 =  baseBundleInstaller.dataMgr_ ->AddInnerBundleInfo(BUNDLE_NAME, info);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);

    EventInfo eventInfo;
    eventInfo.callingUid = TEST_UID;

    baseBundleInstaller.dataMgr_->bundleIdMap_.insert(std::pair<int32_t, std::string>(TEST_BUNDLE_ID, BUNDLE_NAME));
    baseBundleInstaller.GetCallingEventInfo(eventInfo);
    EXPECT_EQ(eventInfo.callingBundleName, BUNDLE_NAME);

    baseBundleInstaller.dataMgr_->bundleIdMap_.erase(TEST_BUNDLE_ID);
    baseBundleInstaller.dataMgr_->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: GetInstallEventInfo_0001
 * @tc.name: test the start function of GetInstallEventInfo
 * @tc.desc: 1. BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallCheckerTest, GetInstallEventInfo_0001, Function | SmallTest | Level0)
{
    BaseBundleInstaller baseBundleInstaller;
    EventInfo eventInfo;
    baseBundleInstaller.GetInstallEventInfo(eventInfo);
    EXPECT_EQ(eventInfo.fingerprint, Constants::EMPTY_STRING);
}

/**
 * @tc.number: GetInstallEventInfo_0002
 * @tc.name: test the start function of GetInstallEventInfo
 * @tc.desc: 1. BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallCheckerTest, GetInstallEventInfo_0002, Function | SmallTest | Level0)
{
    BaseBundleInstaller baseBundleInstaller;
    baseBundleInstaller.dataMgr_ = std::make_shared<BundleDataMgr>();;
    EventInfo eventInfo;
    baseBundleInstaller.GetInstallEventInfo(eventInfo);
    EXPECT_EQ(eventInfo.fingerprint, Constants::EMPTY_STRING);
}

/**
 * @tc.number: GetInstallEventInfo_0003
 * @tc.name: test the start function of GetInstallEventInfo
 * @tc.desc: 1. BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallCheckerTest, GetInstallEventInfo_0003, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = BUNDLE_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.appDistributionType = Constants::APP_DISTRIBUTION_TYPE_APP_GALLERY;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    BaseBundleInstaller baseBundleInstaller;
    baseBundleInstaller.dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(baseBundleInstaller.dataMgr_, nullptr);
    bool ret1 = baseBundleInstaller.dataMgr_->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 =  baseBundleInstaller.dataMgr_->AddInnerBundleInfo(BUNDLE_NAME, info);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);

    baseBundleInstaller.bundleName_ = BUNDLE_NAME;
    EventInfo eventInfo;
    baseBundleInstaller.GetInstallEventInfo(eventInfo);
    EXPECT_EQ(eventInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_APP_GALLERY);

    baseBundleInstaller.dataMgr_->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: GetInstallEventInfo_0004
 * @tc.name: test the start function of GetInstallEventInfo
 * @tc.desc: 1. BaseBundleInstaller
*/
HWTEST_F(BmsBundleInstallCheckerTest, GetInstallEventInfo_0004, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.applicationInfo.name = BUNDLE_NAME;
    ApplicationInfo applicationInfo;
    applicationInfo.name = BUNDLE_NAME;
    applicationInfo.bundleName = BUNDLE_NAME;
    applicationInfo.appDistributionType = Constants::APP_DISTRIBUTION_TYPE_APP_GALLERY;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetBaseApplicationInfo(applicationInfo);
    BaseBundleInstaller baseBundleInstaller;
    baseBundleInstaller.dataMgr_ = std::make_shared<BundleDataMgr>();
    EXPECT_NE(baseBundleInstaller.dataMgr_, nullptr);
    bool ret1 = baseBundleInstaller.dataMgr_->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START);
    bool ret2 =  baseBundleInstaller.dataMgr_->AddInnerBundleInfo(BUNDLE_NAME, info);
    EXPECT_TRUE(ret1);
    EXPECT_TRUE(ret2);

    baseBundleInstaller.bundleName_ = BUNDLE_NAME;
    EventInfo eventInfo;
    InnerModuleInfo moduleInfo;
    moduleInfo.hapPath = "xxxx.hap";
    moduleInfo.hashValue = "111";
    info.InsertInnerModuleInfo(BUNDLE_NAME, moduleInfo);
    baseBundleInstaller.GetInstallEventInfo(eventInfo);
    EXPECT_EQ(eventInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_APP_GALLERY);
    if (!eventInfo.filePath.empty()) {
        EXPECT_EQ(eventInfo.filePath[0], moduleInfo.hapPath);
        EXPECT_EQ(eventInfo.hashValue[0], moduleInfo.hashValue);
    }
    baseBundleInstaller.dataMgr_->UpdateBundleInstallState(BUNDLE_NAME, InstallState::UNINSTALL_START);
}

/**
 * @tc.number: ConvertToAppProvisionInfo_0001
 * @tc.name: test the start function of ConvertToAppProvisionInfo
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, ConvertToAppProvisionInfo_0001, Function | SmallTest | Level0)
{
    BundleInstallChecker bundleInstallChecker;
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    provisionInfo.distributionType = Security::Verify::AppDistType::NONE_TYPE;
    AppProvisionInfo appProvisionInfo = bundleInstallChecker.ConvertToAppProvisionInfo(provisionInfo);
    EXPECT_EQ(appProvisionInfo.type, Constants::APP_PROVISION_TYPE_DEBUG);
    EXPECT_EQ(appProvisionInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_NONE);
    EXPECT_EQ(appProvisionInfo.apl, "normal");
}

/**
 * @tc.number: ConvertToAppProvisionInfo_0002
 * @tc.name: test the start function of ConvertToAppProvisionInfo
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, ConvertToAppProvisionInfo_0002, Function | SmallTest | Level0)
{
    BundleInstallChecker bundleInstallChecker;
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    provisionInfo.distributionType = Security::Verify::AppDistType::APP_GALLERY;
    AppProvisionInfo appProvisionInfo = bundleInstallChecker.ConvertToAppProvisionInfo(provisionInfo);
    EXPECT_EQ(appProvisionInfo.type, Constants::APP_PROVISION_TYPE_RELEASE);
    EXPECT_EQ(appProvisionInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_APP_GALLERY);
    EXPECT_EQ(appProvisionInfo.apl, "normal");
}

/**
 * @tc.number: ConvertToAppProvisionInfo_0003
 * @tc.name: test the start function of ConvertToAppProvisionInfo
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, ConvertToAppProvisionInfo_0003, Function | SmallTest | Level0)
{
    BundleInstallChecker bundleInstallChecker;
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    provisionInfo.bundleInfo.apl = "system_basic";
    AppProvisionInfo appProvisionInfo = bundleInstallChecker.ConvertToAppProvisionInfo(provisionInfo);
    EXPECT_EQ(appProvisionInfo.type, Constants::APP_PROVISION_TYPE_RELEASE);
    EXPECT_EQ(appProvisionInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE);
    EXPECT_EQ(appProvisionInfo.apl, "system_basic");

    provisionInfo.distributionType = Security::Verify::AppDistType::OS_INTEGRATION;
    appProvisionInfo = bundleInstallChecker.ConvertToAppProvisionInfo(provisionInfo);
    EXPECT_EQ(appProvisionInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_OS_INTEGRATION);

    provisionInfo.distributionType = Security::Verify::AppDistType::CROWDTESTING;
    appProvisionInfo = bundleInstallChecker.ConvertToAppProvisionInfo(provisionInfo);
    EXPECT_EQ(appProvisionInfo.appDistributionType, Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING);
}

/**
 * @tc.number: GetPrivilegeCapability_0001
 * @tc.name: test the start function of GetPrivilegeCapability
 * @tc.desc: 1. GetPrivilegeCapability
 * @tc.require: issueI6PKSW
*/
HWTEST_F(BmsBundleInstallCheckerTest, GetPrivilegeCapability_0001, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InstallCheckParam installcheckParam;
    InnerBundleInfo newInfo;
    installChecker.GetPrivilegeCapability(installcheckParam, newInfo);
    EXPECT_EQ(newInfo.GetIsKeepAlive(), false);
}

/**
 * @tc.number: SetEntryInstallationFree_0001
 * @tc.name: test the start function of SetEntryInstallationFree
 * @tc.desc: 1. SetEntryInstallationFree_0001
 * @tc.require: issueI6PKSW
*/
HWTEST_F(BmsBundleInstallCheckerTest, SetEntryInstallationFree_0001, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    BundlePackInfo bundlePackInfo;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetIsNewVersion(false);
    PackageModule packageModule;
    packageModule.distro.moduleType = ENTRY;
    packageModule.distro.installationFree = true;
    bundlePackInfo.summary.modules.emplace_back(packageModule);
    bundlePackInfo.SetValid(true);
    installChecker.SetEntryInstallationFree(bundlePackInfo, innerBundleInfo);
    EXPECT_EQ(innerBundleInfo.GetApplicationBundleType(), BundleType::ATOMIC_SERVICE);
}

/**
 * @tc.number: CheckAppLabelInfo_0001
 * @tc.name: test the start function of CheckAppLabelInfo
 * @tc.desc: 1. CheckAppLabelInfo_0001
 * @tc.require: issueI6PKSW
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0001, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo1.SetAppType(Constants::AppType::SYSTEM_APP);
    innerBundleInfo2.SetAppType(Constants::AppType::THIRD_PARTY_APP);
    infos.emplace(HAP, innerBundleInfo1);
    infos.emplace(HAP_ONE, innerBundleInfo2);
    auto ret = installChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_APPTYPE_NOT_SAME);
}

/**
 * @tc.number: CheckAppLabelInfo_0002
 * @tc.name: test the start function of CheckAppLabelInfo
 * @tc.desc: 1. CheckAppLabelInfo_0002
 * @tc.require: issueI6PKSW
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0002, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo1.SetIsNewVersion(true);
    innerBundleInfo2.SetIsNewVersion(false);
    infos.emplace(HAP, innerBundleInfo1);
    infos.emplace(HAP_ONE, innerBundleInfo2);
    auto ret = installChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_STATE_ERROR);
}

/**
 * @tc.number: CheckAppLabelInfo_0003
 * @tc.name: test the start function of CheckAppLabelInfo
 * @tc.desc: 1. CheckAppLabelInfo_0003
 * @tc.require: issueI6PKSW
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0003, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo1.SetTargetBundleName(HAP);
    innerBundleInfo2.SetTargetBundleName(HAP_ONE);
    infos.emplace(HAP, innerBundleInfo1);
    infos.emplace(HAP_ONE, innerBundleInfo2);
    auto ret = installChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_TARGET_BUNDLE_NAME_NOT_SAME);
}

/**
 * @tc.number: CheckAppLabelInfo_0004
 * @tc.name: test the start function of CheckAppLabelInfo
 * @tc.desc: 1. CheckAppLabelInfo_0004
 * @tc.require: issueI6PKSW
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0004, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo1.SetTargetPriority(PRIORITY_ONE);
    innerBundleInfo2.SetTargetPriority(PRIORITY_TWO);
    infos.emplace(HAP, innerBundleInfo1);
    infos.emplace(HAP_ONE, innerBundleInfo2);
    auto ret = installChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_TARGET_PRIORITY_NOT_SAME);
}

/**
 * @tc.number: CheckAppLabelInfo_0005
 * @tc.name: test the start function of CheckAppLabelInfo
 * @tc.desc: 1. CheckAppLabelInfo_0005
 * @tc.require: issueI6PKSW
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0005, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo1.SetAsanEnabled(true);
    innerBundleInfo2.SetAsanEnabled(false);
    infos.emplace(HAP, innerBundleInfo1);
    infos.emplace(HAP_ONE, innerBundleInfo2);
    auto ret = installChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0006
 * @tc.name: test the start function of CheckAppLabelInfo
 * @tc.desc: 1. CheckAppLabelInfo_0006
 * @tc.require: issueI6PKSW
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0006, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo1.SetApplicationBundleType(BundleType::APP);
    innerBundleInfo2.SetApplicationBundleType(BundleType::ATOMIC_SERVICE);
    infos.emplace(HAP, innerBundleInfo1);
    infos.emplace(HAP_ONE, innerBundleInfo2);
    auto ret = installChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_BUNDLE_TYPE_NOT_SAME);
}

/**
 * @tc.number: CheckAppLabelInfo_0007
 * @tc.name: test the start function of CheckAppLabelInfo
 * @tc.desc: 1. CheckAppLabelInfo_0007
 * @tc.require: issueI6PKSW
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0007, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo1.SetEntryInstallationFree(true);
    innerBundleInfo2.SetEntryInstallationFree(false);
    infos.emplace(HAP, innerBundleInfo1);
    infos.emplace(HAP_ONE, innerBundleInfo2);
    auto ret = installChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_TYPE_ERROR);
}

/**
 * @tc.number: CheckAppLabel_0008
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabel_0008, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.debug = false;
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    applicationInfo.debug = true;
    newInfo.SetBaseApplicationInfo(applicationInfo);
    BaseBundleInstaller baseBundleInstaller;
    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabel_0009
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabel_0009, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.SetGwpAsanEnabled(false);
    newInfo.SetGwpAsanEnabled(true);
    BaseBundleInstaller baseBundleInstaller;
    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabel_0010
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabel_0010, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    oldInfo.SetTsanEnabled(false);
    newInfo.SetTsanEnabled(true);
    BaseBundleInstaller baseBundleInstaller;
    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0008
 * @tc.name: test the start function of CheckAppLabelInfo
 * @tc.desc: 1. CheckAppLabelInfo_0008
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0008, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    BundleInfo bundleInfo;
    bundleInfo.compatibleVersion = PRIORITY_ONE;
    innerBundleInfo1.SetBaseBundleInfo(bundleInfo);
    InnerBundleInfo innerBundleInfo2;
    infos.emplace(HAP, innerBundleInfo1);
    infos.emplace(HAP_ONE, innerBundleInfo2);
    auto ret = installChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0009
 * @tc.name: test the start function of CheckAppLabelInfo
 * @tc.desc: 1. CheckAppLabelInfo_0009
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0009, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    InnerBundleInfo innerBundleInfo2;
    ApplicationInfo applicationInfo;
    applicationInfo.debug = false;
    innerBundleInfo1.SetBaseApplicationInfo(applicationInfo);
    applicationInfo.debug = true;
    innerBundleInfo2.SetBaseApplicationInfo(applicationInfo);
    infos.emplace(HAP, innerBundleInfo1);
    infos.emplace(HAP_ONE, innerBundleInfo2);
    auto ret = installChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0010
 * @tc.name: test the start function of CheckAppLabelInfo
 * @tc.desc: 1. CheckAppLabelInfo_0010
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0010, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    BundleInfo bundleInfo;
    bundleInfo.targetVersion = PRIORITY_ONE;
    innerBundleInfo1.SetBaseBundleInfo(bundleInfo);
    InnerBundleInfo innerBundleInfo2;
    infos.emplace(HAP, innerBundleInfo1);
    infos.emplace(HAP_ONE, innerBundleInfo2);
    auto ret = installChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_RELEASETYPE_TARGET_NOT_SAME);
}

/**
 * @tc.number: CheckAppLabelInfo_0012
 * @tc.name: test the start function of CheckAppLabelInfo
 * @tc.desc: 1. CheckAppLabelInfo_0012
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0012, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo1.SetGwpAsanEnabled(true);
    innerBundleInfo2.SetGwpAsanEnabled(false);
    infos.emplace(HAP, innerBundleInfo1);
    infos.emplace(HAP_ONE, innerBundleInfo2);
    auto ret = installChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0013
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. Same version
 *           2. Both newInfo and oldInfo are not Entry
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0013, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    BaseBundleInstaller baseBundleInstaller;

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = false;
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    oldInfo.innerModuleInfos_ = innerModuleInfos;
    newInfo.innerModuleInfos_ = innerModuleInfos;

    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0013
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. Same version
 *           2. Both newInfo and oldInfo are Entry
 *           3. old is release, new is debug
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0014, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.debug = false;
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    applicationInfo.debug = true;
    newInfo.SetBaseApplicationInfo(applicationInfo);
    BaseBundleInstaller baseBundleInstaller;

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = true;
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    oldInfo.innerModuleInfos_ = innerModuleInfos;
    newInfo.innerModuleInfos_ = innerModuleInfos;

    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0013
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. Same version
 *           2. Both newInfo and oldInfo are Entry
 *           3. Both old and new is debug
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0015, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.debug = true;
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    applicationInfo.debug = true;
    newInfo.SetBaseApplicationInfo(applicationInfo);
    BaseBundleInstaller baseBundleInstaller;

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = true;
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    oldInfo.innerModuleInfos_ = innerModuleInfos;
    newInfo.innerModuleInfos_ = innerModuleInfos;

    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0016
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. Same version
 *           2. oldInfo is entry, newInfo is not entry
 *           3. oldInfo is release, newInfo is debug
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0016, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.debug = false;
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    applicationInfo.debug = true;
    newInfo.SetBaseApplicationInfo(applicationInfo);
    BaseBundleInstaller baseBundleInstaller;

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = true;
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    oldInfo.innerModuleInfos_ = innerModuleInfos;

    std::map<std::string, InnerModuleInfo> innerModuleInfos2;
    InnerModuleInfo innerModuleInfo2;
    innerModuleInfo2.isEntry = false;
    innerModuleInfos2.try_emplace(ENTRY, innerModuleInfo2);
    newInfo.innerModuleInfos_ = innerModuleInfos2;

    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0017
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. Same version
 *           2. oldInfo is not entry, newInfo is entry
 *           3. oldInfo is debug, newInfo is release
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0017, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.debug = true;
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    applicationInfo.debug = false;
    newInfo.SetBaseApplicationInfo(applicationInfo);
    BaseBundleInstaller baseBundleInstaller;

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = false;
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    oldInfo.innerModuleInfos_ = innerModuleInfos;

    std::map<std::string, InnerModuleInfo> innerModuleInfos2;
    InnerModuleInfo innerModuleInfo2;
    innerModuleInfo2.isEntry = true;
    innerModuleInfos2.try_emplace(ENTRY, innerModuleInfo2);
    newInfo.innerModuleInfos_ = innerModuleInfos2;

    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0018
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. Same version
 *           2. oldInfo is not entry, newInfo is entry
 *           3. oldInfo is debug, newInfo is debug
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0018, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.debug = true;
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    applicationInfo.debug = true;
    newInfo.SetBaseApplicationInfo(applicationInfo);
    BaseBundleInstaller baseBundleInstaller;

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = false;
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    oldInfo.innerModuleInfos_ = innerModuleInfos;

    std::map<std::string, InnerModuleInfo> innerModuleInfos2;
    InnerModuleInfo innerModuleInfo2;
    innerModuleInfo2.isEntry = true;
    innerModuleInfos2.try_emplace(ENTRY, innerModuleInfo2);
    newInfo.innerModuleInfos_ = innerModuleInfos2;

    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0019
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. Same version
 *           2. oldInfo is not entry, newInfo is not entry
 *           3. oldInfo is release, newInfo is debug
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0019, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.debug = false;
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    applicationInfo.debug = false;
    newInfo.SetBaseApplicationInfo(applicationInfo);
    BaseBundleInstaller baseBundleInstaller;

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = false;
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    oldInfo.innerModuleInfos_ = innerModuleInfos;

    std::map<std::string, InnerModuleInfo> innerModuleInfos2;
    InnerModuleInfo innerModuleInfo2;
    innerModuleInfo2.isEntry = true;
    innerModuleInfos2.try_emplace(ENTRY, innerModuleInfo2);
    newInfo.innerModuleInfos_ = innerModuleInfos2;

    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0020
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. Same version
 *           2. oldInfo is entry, newInfo is not entry
 *           3. oldInfo is debug, newInfo is debug
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0020, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.debug = true;
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    applicationInfo.debug = true;
    newInfo.SetBaseApplicationInfo(applicationInfo);
    BaseBundleInstaller baseBundleInstaller;

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = true;
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    oldInfo.innerModuleInfos_ = innerModuleInfos;

    std::map<std::string, InnerModuleInfo> innerModuleInfos2;
    InnerModuleInfo innerModuleInfo2;
    innerModuleInfo2.isEntry = false;
    innerModuleInfos2.try_emplace(ENTRY, innerModuleInfo2);
    newInfo.innerModuleInfos_ = innerModuleInfos2;

    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0020
 * @tc.name: test the start function of CheckAppLabel
 * @tc.desc: 1. Same version
 *           2. oldInfo is entry, newInfo is not entry
 *           3. oldInfo is release, newInfo is release
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0021, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.debug = false;
    oldInfo.SetBaseApplicationInfo(applicationInfo);
    applicationInfo.debug = false;
    newInfo.SetBaseApplicationInfo(applicationInfo);
    BaseBundleInstaller baseBundleInstaller;

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = true;
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    oldInfo.innerModuleInfos_ = innerModuleInfos;

    std::map<std::string, InnerModuleInfo> innerModuleInfos2;
    InnerModuleInfo innerModuleInfo2;
    innerModuleInfo2.isEntry = false;
    innerModuleInfos2.try_emplace(ENTRY, innerModuleInfo2);
    newInfo.innerModuleInfos_ = innerModuleInfos2;

    auto ret = baseBundleInstaller.CheckAppLabel(oldInfo, newInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0022
 * @tc.name: test the start function of CheckAppLabelInfo
 * @tc.desc: 1. Info HasEntry
 *           2. entry is release
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0022, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = false;
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    innerBundleInfo.innerModuleInfos_ = innerModuleInfos;

    ApplicationInfo applicationInfo;
    applicationInfo.debug = false;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    infos.emplace(HAP, innerBundleInfo);
    auto ret = installChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0023
 * @tc.name: test the start function of CheckAppLabelInfo
 * @tc.desc: 1. Info HasEntry
 *           2. entry is debug
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0023, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = false;
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    innerBundleInfo.innerModuleInfos_ = innerModuleInfos;

    ApplicationInfo applicationInfo;
    applicationInfo.debug = true;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    infos.emplace(HAP, innerBundleInfo);
    auto ret = installChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0023
 * @tc.name: test the start function of CheckAppLabelInfo
 * @tc.desc: 1. Info no entry
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0024, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;

    infos.emplace(HAP, innerBundleInfo);
    auto ret = installChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckAppLabelInfo_0025
 * @tc.name: test the start function of CheckAppLabelInfo
 * @tc.desc: 1. CheckAppLabelInfo_0025
 * @tc.require: issueI6PKSW
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckAppLabelInfo_0025, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo1;
    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo1.SetTsanEnabled(true);
    innerBundleInfo2.SetTsanEnabled(false);
    infos.emplace(HAP, innerBundleInfo1);
    infos.emplace(HAP_ONE, innerBundleInfo2);
    auto ret = installChecker.CheckAppLabelInfo(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckProxyDatas_0001
 * @tc.name: test the start function of CheckProxyDatas
 * @tc.desc: 1. test CheckProxyDatas
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckProxyDatas_0001, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = PROXY_DATAS;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = ENTRY;
    ProxyData data;
    data.uri = "//";
    innerModuleInfo.proxyDatas.push_back(data);
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    innerBundleInfo.innerModuleInfos_ = innerModuleInfos;
    auto ret = installChecker.CheckProxyDatas(innerBundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_CHECK_PROXY_DATA_URI_FAILED);
}

/**
 * @tc.number: CheckProxyDatas_0001
 * @tc.name: test the start function of CheckProxyDatas
 * @tc.desc: 1. test CheckProxyDatas
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckProxyDatas_0002, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo innerBundleInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = "";
    innerModuleInfos.try_emplace("", innerModuleInfo);
    innerBundleInfo.innerModuleInfos_ = innerModuleInfos;
    auto ret = installChecker.CheckProxyDatas(innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckProxyDatas_0001
 * @tc.name: test the start function of CheckProxyDatas
 * @tc.desc: 1. test CheckProxyDatas
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckProxyDatas_0003, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = PROXY_DATAS;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = ENTRY;
    ProxyData data;
    data.uri = "//2/";
    data.requiredReadPermission = "wrong_permission";
    innerModuleInfo.proxyDatas.push_back(data);
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    innerBundleInfo.innerModuleInfos_ = innerModuleInfos;
    auto ret = installChecker.CheckProxyDatas(innerBundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_CHECK_PROXY_DATA_PERMISSION_FAILED);
}

/**
 * @tc.number: CheckProxyDatas_0004
 * @tc.name: test the start function of CheckProxyDatas
 * @tc.desc: 1. test CheckProxyDatas
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckProxyDatas_0004, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo innerBundleInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    ProxyData data;
    data.uri = MODULE_PATH;
    innerModuleInfo.proxyDatas.emplace_back(data);
    innerModuleInfos.try_emplace(HAP, innerModuleInfo);
    innerBundleInfo.innerModuleInfos_ = innerModuleInfos;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    auto ret = installChecker.CheckProxyDatas(innerBundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_CHECK_PROXY_DATA_URI_FAILED);
}

/**
 * @tc.number: CheckProxyDatas_0005
 * @tc.name: test the start function of CheckProxyDatas
 * @tc.desc: 1. test CheckProxyDatas
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckProxyDatas_0005, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo innerBundleInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    ProxyData data;
    data.uri = TEST_PATH;
    data.requiredReadPermission = "wrong_permission";
    innerModuleInfo.proxyDatas.emplace_back(data);
    innerModuleInfos.try_emplace(HAP, innerModuleInfo);
    innerBundleInfo.innerModuleInfos_ = innerModuleInfos;
    ApplicationInfo applicationInfo;
    applicationInfo.isSystemApp = false;
    applicationInfo.bundleName = BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    auto ret = installChecker.CheckProxyDatas(innerBundleInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_CHECK_PROXY_DATA_PERMISSION_FAILED);
}

/**
 * @tc.number: CheckProxyDatas_0006
 * @tc.name: test the start function of CheckProxyDatas
 * @tc.desc: 1. test CheckProxyDatas
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckProxyDatas_0006, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InnerBundleInfo innerBundleInfo;
    auto ret = installChecker.CheckProxyDatas(innerBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckIsolationMode_0001
 * @tc.name: test the start function of CheckIsolationMode
 * @tc.desc: 1. test CheckIsolationMode
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckIsolationMode_0001, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    auto ret = installChecker.CheckIsolationMode(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckDuplicateProxyData_0001
 * @tc.name: test the start function of CheckDuplicateProxyData
 * @tc.desc: 1. test CheckDuplicateProxyData
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckDuplicateProxyData_0001, Function | SmallTest | Level0)
{
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = ENTRY;
    ProxyData data;
    data.uri = "//2/";
    innerModuleInfo.proxyDatas.push_back(data);
    innerModuleInfos.try_emplace(ENTRY, innerModuleInfo);
    newInfo.innerModuleInfos_ = innerModuleInfos;
    oldInfo.innerModuleInfos_ = innerModuleInfos;

    BaseBundleInstaller baseBundleInstaller;
    bool ret = baseBundleInstaller.CheckDuplicateProxyData(newInfo, oldInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: CheckDuplicateProxyData_0002
 * @tc.name: test the start function of CheckDuplicateProxyData
 * @tc.desc: 1. test CheckDuplicateProxyData
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckDuplicateProxyData_0002, Function | SmallTest | Level0)
{
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;

    BaseBundleInstaller baseBundleInstaller;
    bool ret = baseBundleInstaller.CheckDuplicateProxyData(newInfo, oldInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: CheckDuplicateProxyData_0002
 * @tc.name: test the start function of CheckDuplicateProxyData
 * @tc.desc: 1. test CheckDuplicateProxyData
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckDuplicateProxyData_0003, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> newInfos;

    BaseBundleInstaller baseBundleInstaller;
    bool ret = baseBundleInstaller.CheckDuplicateProxyData(newInfos);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: CheckSignatureFileDir_0001
 * @tc.name: test the start function of CheckSignatureFileDir
 * @tc.desc: 1. test CheckSignatureFileDir
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckSignatureFileDir_0001, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckSignatureFileDir("");
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID);
}

/**
 * @tc.number: CheckSignatureFileDir_0002
 * @tc.name: test the start function of CheckSignatureFileDir
 * @tc.desc: 1. test CheckSignatureFileDir
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckSignatureFileDir_0002, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckSignatureFileDir("data/test");
    EXPECT_EQ(ret, ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID);
}

/**
 * @tc.number: CheckSignatureFileDir_0003
 * @tc.name: test the start function of CheckSignatureFileDir
 * @tc.desc: 1. test CheckSignatureFileDir
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckSignatureFileDir_0003, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckSignatureFileDir("test.sig");
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckCheckProxyPermissionLevel_0001
 * @tc.name: test the start function of CheckProxyPermissionLevel
 * @tc.desc: 1. test CheckProxyPermissionLevel
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckProxyPermissionLevel_0001, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckProxyPermissionLevel("");
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: CheckCheckProxyPermissionLevel_0002
 * @tc.name: test the start function of CheckProxyPermissionLevel
 * @tc.desc: 1. test CheckProxyPermissionLevel
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckProxyPermissionLevel_0002, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckProxyPermissionLevel("ohos.permission.GET_BUNDLE_INFO");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: CheckCheckProxyPermissionLevel_0003
 * @tc.name: test the start function of CheckProxyPermissionLevel
 * @tc.desc: 1. test CheckProxyPermissionLevel
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckProxyPermissionLevel_0003, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckProxyPermissionLevel("wrong_permission_name");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: CheckMDMUpdateBundleForSelf_0001
 * @tc.name: test the start function of CheckMDMUpdateBundleForSelf
 * @tc.desc: 1. test CheckMDMUpdateBundleForSelf
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckMDMUpdateBundleForSelf_0001, Function | SmallTest | Level0)
{
    BaseBundleInstaller baseBundleInstaller;
    InstallParam param;
    param.isSelfUpdate = false;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    auto ret = baseBundleInstaller.CheckMDMUpdateBundleForSelf(param, innerBundleInfo, infos, true);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckMDMUpdateBundleForSelf_0002
 * @tc.name: test the start function of CheckMDMUpdateBundleForSelf
 * @tc.desc: 1. test CheckMDMUpdateBundleForSelf
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckMDMUpdateBundleForSelf_0002, Function | SmallTest | Level0)
{
    BaseBundleInstaller baseBundleInstaller;
    InstallParam param;
    param.isSelfUpdate = true;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    auto ret = baseBundleInstaller.CheckMDMUpdateBundleForSelf(param, innerBundleInfo, infos, false);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_SELF_UPDATE_BUNDLENAME_NOT_SAME);
}

/**
 * @tc.number: CheckMDMUpdateBundleForSelf_0003
 * @tc.name: test the start function of CheckMDMUpdateBundleForSelf
 * @tc.desc: 1. test CheckMDMUpdateBundleForSelf
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckMDMUpdateBundleForSelf_0003, Function | SmallTest | Level0)
{
    BaseBundleInstaller baseBundleInstaller;
    InstallParam param;
    param.isSelfUpdate = true;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;

    innerBundleInfo.SetAppDistributionType("");
    auto ret = baseBundleInstaller.CheckMDMUpdateBundleForSelf(param, innerBundleInfo, infos, true);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_SELF_UPDATE_NOT_MDM);
}

/**
 * @tc.number: CheckMDMUpdateBundleForSelf_0004
 * @tc.name: test the start function of CheckMDMUpdateBundleForSelf
 * @tc.desc: 1. test CheckMDMUpdateBundleForSelf
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckMDMUpdateBundleForSelf_0004, Function | SmallTest | Level0)
{
    BaseBundleInstaller baseBundleInstaller;
    InstallParam param;
    param.isSelfUpdate = true;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;

    innerBundleInfo.SetAppDistributionType(Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM);
    auto ret = baseBundleInstaller.CheckMDMUpdateBundleForSelf(param, innerBundleInfo, infos, true);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckMDMUpdateBundleForSelf_0005
 * @tc.name: test the start function of CheckMDMUpdateBundleForSelf
 * @tc.desc: 1. test CheckMDMUpdateBundleForSelf
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckMDMUpdateBundleForSelf_0005, Function | SmallTest | Level0)
{
    BaseBundleInstaller baseBundleInstaller;
    InstallParam param;
    param.isSelfUpdate = true;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetAppDistributionType(Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM);
    infos.emplace(BUNDLE_NAME, innerBundleInfo);
    auto ret = baseBundleInstaller.CheckMDMUpdateBundleForSelf(param, innerBundleInfo, infos, true);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: CheckMDMUpdateBundleForSelf_0006
 * @tc.name: test the start function of CheckMDMUpdateBundleForSelf
 * @tc.desc: 1. test CheckMDMUpdateBundleForSelf
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckMDMUpdateBundleForSelf_0006, Function | SmallTest | Level0)
{
    BaseBundleInstaller baseBundleInstaller;
    InstallParam param;
    param.isSelfUpdate = true;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    innerBundleInfo.SetAppDistributionType(Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM);
    InnerBundleInfo innerBundleInfo2;
    ApplicationInfo applicationInfo2;
    applicationInfo.bundleName = "wrong_name";
    innerBundleInfo2.SetBaseApplicationInfo(applicationInfo2);
    infos.emplace(BUNDLE_NAME, innerBundleInfo2);

    auto ret = baseBundleInstaller.CheckMDMUpdateBundleForSelf(param, innerBundleInfo, infos, true);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_SELF_UPDATE_BUNDLENAME_NOT_SAME);
}

/**
 * @tc.number: VaildEnterpriseInstallPermission_0001
 * @tc.name: test the start function of VaildEnterpriseInstallPermission
 * @tc.desc: 1. test VaildEnterpriseInstallPermission
*/
HWTEST_F(BmsBundleInstallCheckerTest, VaildEnterpriseInstallPermission_0001, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InstallParam param;
    Security::Verify::ProvisionInfo provisionInfo;
    param.isSelfUpdate = true;
    auto ret = installChecker.VaildEnterpriseInstallPermission(param, provisionInfo);
    EXPECT_EQ(ret, false);
    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE_MDM;
    ret = installChecker.VaildEnterpriseInstallPermission(param, provisionInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: VaildEnterpriseInstallPermission_0002
 * @tc.name: test the start function of VaildEnterpriseInstallPermission
 * @tc.desc: 1. test VaildEnterpriseInstallPermission
*/
HWTEST_F(BmsBundleInstallCheckerTest, VaildEnterpriseInstallPermission_0002, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InstallParam param;
    Security::Verify::ProvisionInfo provisionInfo;
    param.isCallByShell = true;
    provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    auto ret = installChecker.VaildEnterpriseInstallPermission(param, provisionInfo);
    EXPECT_EQ(ret, false);
    provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    ret = installChecker.VaildEnterpriseInstallPermission(param, provisionInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: VaildEnterpriseInstallPermission_0003
 * @tc.name: test the start function of VaildEnterpriseInstallPermission
 * @tc.desc: 1. test VaildEnterpriseInstallPermission
*/
HWTEST_F(BmsBundleInstallCheckerTest, VaildEnterpriseInstallPermission_0003, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InstallParam param;
    Security::Verify::ProvisionInfo provisionInfo;
    param.isCallByShell = false;
    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE_NORMAL;
    auto ret = installChecker.VaildEnterpriseInstallPermission(param, provisionInfo);
    EXPECT_EQ(ret, false);
    param.installEtpNormalBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    ret = installChecker.VaildEnterpriseInstallPermission(param, provisionInfo);
    EXPECT_EQ(ret, true);
    param.installEtpMdmBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    ret = installChecker.VaildEnterpriseInstallPermission(param, provisionInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: VaildEnterpriseInstallPermission_0004
 * @tc.name: test the start function of VaildEnterpriseInstallPermission
 * @tc.desc: 1. test VaildEnterpriseInstallPermission
*/
HWTEST_F(BmsBundleInstallCheckerTest, VaildEnterpriseInstallPermission_0004, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InstallParam param;
    Security::Verify::ProvisionInfo provisionInfo;
    param.isCallByShell = false;
    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE_MDM;
    auto ret = installChecker.VaildEnterpriseInstallPermission(param, provisionInfo);
    EXPECT_EQ(ret, false);
    param.installEtpMdmBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    ret = installChecker.VaildEnterpriseInstallPermission(param, provisionInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: MatchSignature_0101
 * @tc.name: test the start function of MatchSignature
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, MatchSignature_0101, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::vector<std::string> appSignatures;
    bool res = installChecker.MatchSignature(appSignatures, "");
    EXPECT_FALSE(res);
    appSignatures.push_back("exist");
    res = installChecker.MatchSignature(appSignatures, "");
    EXPECT_FALSE(res);
    res = installChecker.MatchSignature(appSignatures, "not_exist");
    EXPECT_FALSE(res);
    res = installChecker.MatchSignature(appSignatures, "exist");
    EXPECT_TRUE(res);
}

/**
 * @tc.number: MatchSignature_0102
 * @tc.name: test the start function of MatchOldSignatures
 * @tc.desc: 1. BundleInstallChecker
*/
HWTEST_F(BmsBundleInstallCheckerTest, MatchSignature_0102, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::vector<std::string> appSignatures;
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    bool res = installChecker.MatchOldSignatures("", appSignatures);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: VaildInstallPermissionForShare_0100
 * @tc.name: test VaildInstallPermissionForShare
 * @tc.desc: 1.test isCallByShell is false
 */
HWTEST_F(BmsBundleInstallCheckerTest, VaildInstallPermissionForShare_0100, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InstallCheckParam checkParam;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult result;
    hapVerifyRes.emplace_back(result);
    checkParam.isCallByShell = false;
    checkParam.installBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    checkParam.installEnterpriseBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    checkParam.installEtpMdmBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    bool res1 = installChecker.VaildInstallPermissionForShare(checkParam, hapVerifyRes);
    EXPECT_TRUE(res1);

    checkParam.installBundlePermissionStatus = PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    bool res2 = installChecker.VaildInstallPermissionForShare(checkParam, hapVerifyRes);
    EXPECT_FALSE(res2);

    checkParam.installEnterpriseBundlePermissionStatus = PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    bool res3 = installChecker.VaildInstallPermissionForShare(checkParam, hapVerifyRes);
    EXPECT_FALSE(res3);

    checkParam.installEtpMdmBundlePermissionStatus = PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    bool res4 = installChecker.VaildInstallPermissionForShare(checkParam, hapVerifyRes);
    EXPECT_FALSE(res4);

    checkParam.installBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    bool res5 = installChecker.VaildInstallPermissionForShare(checkParam, hapVerifyRes);
    EXPECT_TRUE(res5);

    checkParam.installEnterpriseBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    bool res6 = installChecker.VaildInstallPermissionForShare(checkParam, hapVerifyRes);
    EXPECT_TRUE(res6);
}

/**
 * @tc.number: VaildInstallPermissionForShare_0200
 * @tc.name: test VaildInstallPermissionForShare
 * @tc.desc: 1.test isCallByShell is true
 */
HWTEST_F(BmsBundleInstallCheckerTest, VaildInstallPermissionForShare_0200, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InstallCheckParam checkParam;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    Security::Verify::HapVerifyResult result;
    hapVerifyRes.emplace_back(result);
    checkParam.isCallByShell = true;
    checkParam.installBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    checkParam.installEnterpriseBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    checkParam.installEtpMdmBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    bool res1 = installChecker.VaildInstallPermissionForShare(checkParam, hapVerifyRes);
    EXPECT_TRUE(res1);

    checkParam.installBundlePermissionStatus = PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    bool res2 = installChecker.VaildInstallPermissionForShare(checkParam, hapVerifyRes);
    EXPECT_FALSE(res2);

    checkParam.installEnterpriseBundlePermissionStatus = PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    bool res3 = installChecker.VaildInstallPermissionForShare(checkParam, hapVerifyRes);
    EXPECT_FALSE(res3);

    checkParam.installEtpMdmBundlePermissionStatus = PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    bool res4 = installChecker.VaildInstallPermissionForShare(checkParam, hapVerifyRes);
    EXPECT_FALSE(res4);

    checkParam.installBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    bool res5 = installChecker.VaildInstallPermissionForShare(checkParam, hapVerifyRes);
    EXPECT_TRUE(res5);

    checkParam.installEnterpriseBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    bool res6 = installChecker.VaildInstallPermissionForShare(checkParam, hapVerifyRes);
    EXPECT_TRUE(res6);
}

/**
 * @tc.number: VaildEnterpriseInstallPermissionForShare_0100
 * @tc.name: test VaildEnterpriseInstallPermissionForShare
 * @tc.desc: 1.test VaildEnterpriseInstallPermissionForShare of BundleInstallChecker
 */
HWTEST_F(BmsBundleInstallCheckerTest, VaildEnterpriseInstallPermissionForShare_0100, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InstallCheckParam checkParam;
    Security::Verify::ProvisionInfo provisionInfo;
    checkParam.isCallByShell = true;
    provisionInfo.type = Security::Verify::ProvisionType::RELEASE;
    bool res1 = installChecker.VaildEnterpriseInstallPermissionForShare(checkParam, provisionInfo);
    EXPECT_FALSE(res1);

    checkParam.isCallByShell = false;
    provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    bool res2 = installChecker.VaildEnterpriseInstallPermissionForShare(checkParam, provisionInfo);
    EXPECT_TRUE(res2);

    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE_NORMAL;
    bool res3 = installChecker.VaildEnterpriseInstallPermissionForShare(checkParam, provisionInfo);
    EXPECT_FALSE(res3);

    checkParam.installEtpNormalBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    bool res4 = installChecker.VaildEnterpriseInstallPermissionForShare(checkParam, provisionInfo);
    EXPECT_TRUE(res4);

    checkParam.installEtpMdmBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    bool res5 = installChecker.VaildEnterpriseInstallPermissionForShare(checkParam, provisionInfo);
    EXPECT_TRUE(res5);

    checkParam.installEtpMdmBundlePermissionStatus = PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    bool res6 = installChecker.VaildEnterpriseInstallPermissionForShare(checkParam, provisionInfo);
    EXPECT_TRUE(res6);

    checkParam.installEtpNormalBundlePermissionStatus = PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    bool res7 = installChecker.VaildEnterpriseInstallPermissionForShare(checkParam, provisionInfo);
    EXPECT_FALSE(res7);

    checkParam.installEtpMdmBundlePermissionStatus = PermissionStatus::HAVE_PERMISSION_STATUS;
    bool res8 = installChecker.VaildEnterpriseInstallPermissionForShare(checkParam, provisionInfo);
    EXPECT_TRUE(res8);

    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE_MDM;
    bool res9 = installChecker.VaildEnterpriseInstallPermissionForShare(checkParam, provisionInfo);
    EXPECT_TRUE(res9);

    checkParam.installEtpMdmBundlePermissionStatus = PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    bool res10 = installChecker.VaildEnterpriseInstallPermissionForShare(checkParam, provisionInfo);
    EXPECT_FALSE(res10);

    checkParam.installEtpNormalBundlePermissionStatus = PermissionStatus::NON_HAVE_PERMISSION_STATUS;
    bool res11 = installChecker.VaildEnterpriseInstallPermissionForShare(checkParam, provisionInfo);
    EXPECT_FALSE(res11);
}

/**
 * @tc.number: ResetAOTCompileStatus_0100
 * @tc.name: test ResetAOTCompileStatus
 * @tc.desc: 1.test ResetAOTCompileStatus of InnerBundleInfo
 */
HWTEST_F(BmsBundleInstallCheckerTest, ResetAOTCompileStatus_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfonfo;
    auto res = innerBundleInfonfo.ResetAOTCompileStatus(ENTRY);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);

    InnerModuleInfo innerModuleInfo;
    innerBundleInfonfo.InsertInnerModuleInfo(ENTRY, innerModuleInfo);
    res = innerBundleInfonfo.ResetAOTCompileStatus(ENTRY);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: GetLastInstallationTimeTest
 * @tc.name: test GetLastInstallationTime
 * @tc.desc: 1.test GetLastInstallationTime of InnerBundleInfo
*/
HWTEST_F(BmsBundleInstallCheckerTest, GetLastInstallationTimeTest, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfonfo;
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleInfonfo.innerBundleUserInfos_.try_emplace(BUNDLE_NAME, innerBundleUserInfo);
    int64_t res = innerBundleInfonfo.GetLastInstallationTime();
    EXPECT_GE(res, 0);
}

/**
 * @tc.number: GetEntryModuleNameTest
 * @tc.name: test GetEntryModuleName
 * @tc.desc: 1.test GetEntryModuleName of InnerBundleInfo
*/
HWTEST_F(BmsBundleInstallCheckerTest, GetEntryModuleNameTest, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfonfo;
    std::string res = innerBundleInfonfo.GetEntryModuleName();
    EXPECT_EQ(res.empty(), true);

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.isEntry = true;
    innerModuleInfo.modulePackage = HAP_TWO;
    innerBundleInfonfo.InsertInnerModuleInfo(HAP_ONE, innerModuleInfo);
    res = innerBundleInfonfo.GetEntryModuleName();
    EXPECT_EQ(res.empty(), false);
}

/**
 * @tc.number: VaildInstallPermission_0100
 * @tc.name: test VaildInstallPermission
 * @tc.desc: 1.test install permission
 */
HWTEST_F(BmsBundleInstallCheckerTest, VaildInstallPermission_0100, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    InstallParam installParam;
    installParam.isSelfUpdate = false;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    bool ret = installChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_EQ(ret, true);

    Security::Verify::HapVerifyResult result;
    hapVerifyRes.emplace_back(result);
    ret = installChecker.VaildInstallPermission(installParam, hapVerifyRes);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: FindModuleInInstalledPackage_0100
 * @tc.name: test FindModuleInInstalledPackage
 * @tc.desc: 1.test find module in install package
 */
HWTEST_F(BmsBundleInstallCheckerTest, FindModuleInInstalledPackage_0100, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::string moduleName = ENTRY;
    std::string bundleName = BUNDLE_NAME;
    uint32_t versionCode = 0;
    bool ret = installChecker.FindModuleInInstalledPackage(moduleName, bundleName, versionCode);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: CheckHapHashParams_0200
 * @tc.name: test the function of CheckHapHashParams
 * @tc.desc: 1.test check hap hash params by CheckHapHashParams
*/
HWTEST_F(BmsBundleInstallCheckerTest, CheckHapHashParams_0200, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    infos.emplace(HAP, innerBundleInfo);
    std::map<std::string, std::string> hashParams;
    hashParams.insert(pair<string, string>(ENTRY, BUNDLE_NAME));
    BundleInstallChecker installChecker;
    auto ret = installChecker.CheckHapHashParams(infos, hashParams);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_MODULE_NAME_EMPTY);

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerModuleInfo innerModuleInfo;
    ProxyData data;
    data.uri = MODULE_PATH;
    innerModuleInfo.moduleName = MODULE_PACKAGE;
    innerModuleInfo.proxyDatas.emplace_back(data);
    innerModuleInfos.try_emplace(HAP, innerModuleInfo);
    innerBundleInfo.innerModuleInfos_ = innerModuleInfos;
    infos.clear();
    infos.emplace(HAP, innerBundleInfo);
    ret = installChecker.CheckHapHashParams(infos, hashParams);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_CHECK_HAP_HASH_PARAM);
}

/**
 * @tc.number: CheckEnterpriseBundle_0100
 * @tc.name: test CheckEnterpriseBundle
 * @tc.desc: 1.test check enterprise bundle
 */
HWTEST_F(BmsBundleInstallCheckerTest, CheckEnterpriseBundle_0100, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    Security::Verify::HapVerifyResult result;
    Security::Verify::ProvisionInfo provisionInfo;
    provisionInfo.type = Security::Verify::ProvisionType::DEBUG;
    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE_NORMAL;
    result.SetProvisionInfo(provisionInfo);
    bool ret = installChecker.CheckEnterpriseBundle(result);
    EXPECT_EQ(ret, true);

    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE_MDM;
    result.SetProvisionInfo(provisionInfo);
    ret = installChecker.CheckEnterpriseBundle(result);
    EXPECT_EQ(ret, true);

    provisionInfo.distributionType = Security::Verify::AppDistType::ENTERPRISE;
    result.SetProvisionInfo(provisionInfo);
    ret = installChecker.CheckEnterpriseBundle(result);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: ParseBundleInfo_0100
 * @tc.name: test ParseBundleInfo
 * @tc.desc: 1.test parse bundle info
 */
HWTEST_F(BmsBundleInstallCheckerTest, ParseBundleInfo_0100, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::string bundlePath = "";
    InnerBundleInfo info;
    BundlePackInfo packInfo;
    bool ret = installChecker.ParseBundleInfo(bundlePath, info, packInfo);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: FindModuleInInstallingPackage_0100
 * @tc.name: test FindModuleInInstallingPackage
 * @tc.desc: 1.test find module in installing package
 */
HWTEST_F(BmsBundleInstallCheckerTest, FindModuleInInstallingPackage_0100, Function | SmallTest | Level0)
{
    BundleInstallChecker installChecker;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::string moduleName = MODULE_PACKAGE;
    std::string bundleName = BUNDLE_NAME;
    bool ret = installChecker.FindModuleInInstallingPackage(moduleName, bundleName, infos);
    EXPECT_EQ(ret, false);

    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo;
    ProxyData data;
    data.uri = MODULE_PATH;
    innerModuleInfo.moduleName = MODULE_PACKAGE;
    innerModuleInfo.proxyDatas.emplace_back(data);
    innerModuleInfos.try_emplace(HAP, innerModuleInfo);
    innerBundleInfo.innerModuleInfos_ = innerModuleInfos;
    infos.emplace(HAP, innerBundleInfo);
    ret = installChecker.FindModuleInInstallingPackage(moduleName, bundleName, infos);
    EXPECT_EQ(ret, false);
}
} // OHOS
