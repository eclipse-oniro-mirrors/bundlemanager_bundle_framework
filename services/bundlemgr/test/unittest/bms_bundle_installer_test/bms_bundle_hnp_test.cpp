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

#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_multiuser_installer.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "hmp_bundle_installer.h"
#include "install_param.h"
#include "installd/installd_service.h"
#include "installd_client.h"
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

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace AppExecFwk {
void SetInodeCountValue(uint64_t count, uint32_t value);
}
namespace {
const int32_t USERID = 100;
}  // namespace

class BmsBundleHnpTest : public testing::Test {
public:
    BmsBundleHnpTest();
    ~BmsBundleHnpTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
private:
};

BmsBundleHnpTest::BmsBundleHnpTest()
{}

BmsBundleHnpTest::~BmsBundleHnpTest()
{}

void BmsBundleHnpTest::SetUpTestCase()
{}

void BmsBundleHnpTest::TearDownTestCase()
{}

void BmsBundleHnpTest::SetUp()
{}

void BmsBundleHnpTest::TearDown()
{}

HWTEST_F(BmsBundleHnpTest, GetInnerModuleInfoHnpInfo_0001, Function | SmallTest | Level3)
{
    InnerBundleInfo info;

    // empty info -> should return nullopt
    auto ret = info.GetInnerModuleInfoHnpInfo("");
    EXPECT_EQ(ret, std::nullopt);

    // prepare a module with hnpPackages
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "moduleA";
    HnpPackage pkg;
    pkg.package = "example.hnp";
    pkg.type = "public";
    moduleInfo.hnpPackages.push_back(pkg);
    moduleInfo.moduleHnpsPath = "/tmp/moduleA/hnps";
    info.innerModuleInfos_.try_emplace("moduleA", moduleInfo);

    // query by module name
    auto ret2 = info.GetInnerModuleInfoHnpInfo("moduleA");
    EXPECT_NE(ret2, std::nullopt);
    EXPECT_EQ((*ret2)[0].package, "example.hnp");
    EXPECT_EQ((*ret2)[0].type, "public");

    // query with empty moduleName should return the first non-empty hnpPackages
    auto ret3 = info.GetInnerModuleInfoHnpInfo("");
    EXPECT_NE(ret3, std::nullopt);

    // query non-existing module should return nullopt
    auto ret4 = info.GetInnerModuleInfoHnpInfo("nonExistModule");
    EXPECT_EQ(ret4, std::nullopt);
}

HWTEST_F(BmsBundleHnpTest, GetInnerModuleInfoHnpPath_0001, Function | SmallTest | Level3)
{
    InnerBundleInfo info;

    // empty info -> empty path
    std::string path = info.GetInnerModuleInfoHnpPath("");
    EXPECT_EQ(path, "");

    // module exists but hnpPackages empty -> still empty path
    InnerModuleInfo emptyModule;
    emptyModule.moduleName = "moduleB";
    info.innerModuleInfos_.try_emplace("moduleB", emptyModule);
    std::string path2 = info.GetInnerModuleInfoHnpPath("moduleB");
    EXPECT_EQ(path2, "");

    // module with hnpPackages should return moduleHnpsPath
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "moduleC";
    HnpPackage pkg;
    pkg.package = "example.hnp";
    pkg.type = "private";
    moduleInfo.hnpPackages.push_back(pkg);
    moduleInfo.moduleHnpsPath = "/opt/moduleC/hnps";
    info.innerModuleInfos_.try_emplace("moduleC", moduleInfo);

    std::string path3 = info.GetInnerModuleInfoHnpPath("moduleC");
    EXPECT_EQ(path3, "/opt/moduleC/hnps");
}

HWTEST_F(BmsBundleHnpTest, ProcessBundleInstallNative_0001, Function | SmallTest | Level3)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    info.innerModuleInfos_.try_emplace("entry", moduleInfo);

    info.SetCurrentModulePackage("feature");
    ErrCode ret = installer.ProcessBundleInstallNative(info, USERID, false);
    EXPECT_EQ(ret, ERR_OK);

    info.SetCurrentModulePackage("entry");
    ret = installer.ProcessBundleInstallNative(info, USERID, true);
    EXPECT_EQ(ret, ERR_OK);

    EXPECT_FALSE(installer.isHnpInstalled_);
}

HWTEST_F(BmsBundleHnpTest, ProcessBundleInstallNative_0002, Function | SmallTest | Level3)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    std::string bundleName = "com.example.hnp";
    HnpPackage pkg;
    pkg.package = "example.hnp";
    pkg.type = "public";
    moduleInfo.hnpPackages.push_back(pkg);
    moduleInfo.moduleHnpsPath = "/tmp/entry/hnps";
    info.innerModuleInfos_.try_emplace("entry", moduleInfo);
    info.SetCurrentModulePackage("entry");

    ErrCode ret = installer.ProcessBundleInstallNative(info, USERID, true);
    EXPECT_EQ(ret, ERR_OK);
    
    EXPECT_TRUE(installer.isHnpInstalled_);

    std::unordered_set<int32_t> userIds = { 100 };
    installer.RollbackHnpInstall(bundleName, userIds);
    ret = installer.ProcessBundleInstallNative(info, USERID, true);
    EXPECT_EQ(ret, ERR_OK);
}

HWTEST_F(BmsBundleHnpTest, ProcessBundleUnInstallNative_0001, Function | SmallTest | Level3)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;

    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    std::string bundleName = "com.example.hnp";
    HnpPackage pkg;
    pkg.package = "example.hnp";
    pkg.type = "public";
    moduleInfo.hnpPackages.push_back(pkg);
    moduleInfo.moduleHnpsPath = "/tmp/entry/hnps";
    info.innerModuleInfos_.try_emplace("entry", moduleInfo);
    info.SetCurrentModulePackage("entry");

    ErrCode ret = installer.ProcessBundleUnInstallNative(info, USERID, bundleName, moduleInfo.moduleName);
    EXPECT_EQ(ret, ERR_OK);

    std::unordered_set<int32_t> userIds = { 100 };
    ret = installer.ProcessBundleUnInstallNative(info, userIds, bundleName, moduleInfo.moduleName);
    EXPECT_EQ(ret, ERR_OK);
}

HWTEST_F(BmsBundleHnpTest, ExtractHnpFileDir_0001, Function | SmallTest | Level3)
{
    BaseBundleInstaller installer;

    std::map<std::string, std::string> hnpPackageMap;
    hnpPackageMap.emplace("example.hnp", "public");

    std::string unsupportedAbi = "unsupported_abi";
    ErrCode ret = installer.ExtractHnpFileDir(unsupportedAbi, hnpPackageMap, "/tmp/modulePath");
    EXPECT_EQ(ret, ERR_APPEXECFWK_NATIVE_HNP_EXTRACT_FAILED);

    std::string supportedAbi = "arm64-v8a";
    ret = installer.ExtractHnpFileDir(supportedAbi, hnpPackageMap, "/tmp/modulePath");
    EXPECT_EQ(ret, ERR_OK);
}

HWTEST_F(BmsBundleHnpTest, ExtractModule_0001, Function | SmallTest | Level3)
{
    BaseBundleInstaller installer;
    InnerBundleInfo info;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "moduleA";

    HnpPackage pkg;
    pkg.package = "example.hnp";
    pkg.type = "test";
    moduleInfo.hnpPackages.push_back(pkg);
    HnpPackage pkg2;
    pkg2.package = "example2.hnp";
    pkg2.type = "private";
    moduleInfo.hnpPackages.push_back(pkg2);
    HnpPackage pkg3;
    pkg3.package = "example3.hnp";
    pkg3.type = "public";
    moduleInfo.hnpPackages.push_back(pkg3);
    HnpPackage pkg4;
    pkg4.package = "com../../example4.hnp";
    pkg4.type = "public";
    moduleInfo.hnpPackages.push_back(pkg4);

    moduleInfo.moduleHnpsPath = "/tmp/moduleA/hnps";
    info.innerModuleInfos_.try_emplace("moduleA", moduleInfo);
    info.SetCurrentModulePackage("moduleA");
    std::string unsupportedAbi = "unsupported_abi";
    info.SetCpuAbi(unsupportedAbi);

    ErrCode ret = installer.ExtractModule(info, "/tmp/modulePath");
    EXPECT_EQ(ret, ERR_APPEXECFWK_NATIVE_HNP_EXTRACT_FAILED);

    std::string supportedAbi = "arm64-v8a";
    info.SetCpuAbi(supportedAbi);
    ret = installer.ExtractModule(info, "/tmp/modulePath");
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: GetBundleCacheSizeByAppIndex_0010
 * @tc.name: test GetBundleCacheSizeByAppIndex
 * @tc.desc: 1.Test the GetBundleCacheSizeByAppIndex of BundleCacheMgr
*/
HWTEST_F(BmsBundleHnpTest, GetBundleCacheSizeByAppIndex_0010, Function | SmallTest | Level0)
{
    std::string bundleName = "com.example.testapp";
    int32_t userId = 100;
    int32_t appIndex = 0;
    std::vector<std::string> moduleNames = {"entry", "feature"};
    uint64_t cacheStat = 0;
    BundleCacheMgr bundleCacheMgr;
    bundleCacheMgr.GetBundleCacheSizeByAppIndex(bundleName, userId, appIndex, moduleNames, cacheStat);
    EXPECT_GE(cacheStat, 0);
}

/**
 * @tc.number: GetBundleCacheSizeByAppIndex_0020
 * @tc.name: test GetBundleCacheSizeByAppIndex
 * @tc.desc: 1.Test the GetBundleCacheSizeByAppIndex of BundleCacheMgr
*/
HWTEST_F(BmsBundleHnpTest, GetBundleCacheSizeByAppIndex_0020, Function | SmallTest | Level0)
{
    std::string bundleName = "com.example.testapp";
    BundleCacheMgr bundleCacheMgr;
    int32_t invalidAppIndex = -1;
    std::vector<std::string> moduleNames;
    uint64_t cacheStat = 0;
    bundleCacheMgr.GetBundleCacheSizeByAppIndex(bundleName, USERID, invalidAppIndex, moduleNames, cacheStat);
    EXPECT_EQ(cacheStat, 0);
}

/**
 * @tc.number: GetBundleInodeCount_0010
 * @tc.name: test GetBundleInodeCount
 * @tc.desc: 1.Test the GetBundleInodeCount of BundleCacheMgr
*/
HWTEST_F(BmsBundleHnpTest, GetBundleInodeCount_0010, Function | SmallTest | Level0)
{
    int32_t uid = 20010001;
    uint64_t inodeCount = 0;
    SetInodeCountValue(100, 0);
    BundleCacheMgr bundleCacheMgr;
    ErrCode result = bundleCacheMgr.GetBundleInodeCount(uid, inodeCount);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(inodeCount, 100);
}

/**
 * @tc.number: GetBundleInodeCount_0020
 * @tc.name: test GetBundleInodeCount
 * @tc.desc: 1.Test the GetBundleInodeCount of BundleCacheMgr
*/
HWTEST_F(BmsBundleHnpTest, GetBundleInodeCount_0020, Function | SmallTest | Level0)
{
    int32_t uid = -1;
    uint64_t inodeCount = 100;
    BundleCacheMgr bundleCacheMgr;
    ErrCode result = bundleCacheMgr.GetBundleInodeCount(uid, inodeCount);
    EXPECT_EQ(result, ERR_BUNDLE_MANAGER_INVALID_UID);
    EXPECT_EQ(inodeCount, 0);
}

/**
 * @tc.number: GetBundleInodeCount_0030
 * @tc.name: test GetBundleInodeCount
 * @tc.desc: 1.Test the GetBundleInodeCount of BundleCacheMgr
*/
HWTEST_F(BmsBundleHnpTest, GetBundleInodeCount_0030, Function | MediumTest | Level0)
{
    int32_t uid = 0;
    uint64_t inodeCount = 0;
    SetInodeCountValue(50, 0);
    BundleCacheMgr bundleCacheMgr;
    ErrCode result = bundleCacheMgr.GetBundleInodeCount(uid, inodeCount);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(inodeCount, 50);
}

/**
 * @tc.number: GetBundleInodeCount_0040
 * @tc.name: test GetBundleInodeCount
 * @tc.desc: 1.Test the GetBundleInodeCount of BundleCacheMgr
*/
HWTEST_F(BmsBundleHnpTest, GetBundleInodeCount_0040, Function | SmallTest | Level0)
{
    int32_t uid = 20010001;
    uint64_t inodeCount = 0;
    SetInodeCountValue(150, 1);
    BundleCacheMgr bundleCacheMgr;
    ErrCode result = bundleCacheMgr.GetBundleInodeCount(uid, inodeCount);
    EXPECT_EQ(result, 1);
    EXPECT_GE(inodeCount, 0);
}
} // OHOS
