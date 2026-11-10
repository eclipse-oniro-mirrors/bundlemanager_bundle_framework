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

#include <gtest/gtest.h>

#define private public
#include "installd_client.h"
#include "bundle_data_storage_rdb.h"
#include "preinstall_data_storage_rdb.h"
#include "bundle_exception_handler.h"
#include "inner_bundle_info.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.ohos.launcher";
const std::string Package_NAME = "launcher_settings";
const std::string BUNDLE_DIR_NAME = "/data/app/el1/bundle/public/com.ohos.nweb/libs/arm/libnweb_adapter.so";
const std::string BUNDLE_OR_MOUDLE_DIR = "/data/app/el1/bundle/public/";
const std::string EMPTY_STRING = "";
const int32_t USERID = 100;
}  // namespace

class BmsBundleExceptionHandlerTest : public testing::Test {
public:
    BmsBundleExceptionHandlerTest()
    {}
    ~BmsBundleExceptionHandlerTest()
    {}
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<IBundleDataStorage> dataStorage = nullptr;
    std::shared_ptr<BundleExceptionHandler> bundleExceptionHandler_ = nullptr;
};

void BmsBundleExceptionHandlerTest::SetUpTestCase()
{}

void BmsBundleExceptionHandlerTest::TearDownTestCase()
{}

void BmsBundleExceptionHandlerTest::SetUp()
{
    bundleExceptionHandler_ = std::make_shared<BundleExceptionHandler>(dataStorage);
}

void BmsBundleExceptionHandlerTest::TearDown()
{}

/**
 * @tc.number: RemoveBundleAndDataDirTest_0100
 * @tc.name: RemoveBundleAndDataDir
 * @tc.desc: test RemoveBundleAndDataDir
 */
HWTEST_F(BmsBundleExceptionHandlerTest, RemoveBundleAndDataDirTest_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RemoveBundleAndDataDirTest_0100 start";
    int32_t userId = 100;
    bool result = bundleExceptionHandler_->RemoveBundleAndDataDir(BUNDLE_DIR_NAME, BUNDLE_OR_MOUDLE_DIR, userId);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "RemoveBundleAndDataDirTest_0100 end";
}

/**
 * @tc.number: RemoveBundleAndDataDirTest_0200
 * @tc.name: RemoveBundleAndDataDir
 * @tc.desc: test RemoveBundleAndDataDir (The return value of the mock RemoveDir function is not 0)
 */
HWTEST_F(BmsBundleExceptionHandlerTest, RemoveBundleAndDataDirTest_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RemoveBundleAndDataDirTest_0200 start";
    int32_t userId = 100;
    bool result = bundleExceptionHandler_->RemoveBundleAndDataDir(EMPTY_STRING, BUNDLE_OR_MOUDLE_DIR, userId);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "RemoveBundleAndDataDirTest_0200 end";
}

/**
 * @tc.number: RemoveBundleAndDataDirTest_0300
 * @tc.name: RemoveBundleAndDataDir
 * @tc.desc: test RemoveBundleAndDataDir (The return value of the mock RemoveBundleDataDir function is not 0)
 */
HWTEST_F(BmsBundleExceptionHandlerTest, RemoveBundleAndDataDirTest_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RemoveBundleAndDataDirTest_0300 start";
    int32_t userId = 0;
    bool result = bundleExceptionHandler_->RemoveBundleAndDataDir(EMPTY_STRING, BUNDLE_OR_MOUDLE_DIR, userId);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "RemoveBundleAndDataDirTest_0300 end";
}

/**
 * @tc.number: RemoveBundleAndDataDirTest_0400
 * @tc.name: RemoveBundleAndDataDir
 * @tc.desc: test RemoveBundleAndDataDir (Parameter bundledir is' ')
 */
HWTEST_F(BmsBundleExceptionHandlerTest, RemoveBundleAndDataDirTest_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RemoveBundleAndDataDirTest_0400 start";
    int32_t userId = 100;
    bool result = bundleExceptionHandler_->RemoveBundleAndDataDir(EMPTY_STRING, EMPTY_STRING, userId);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "RemoveBundleAndDataDirTest_0400 end";
}

/**
 * @tc.number: HandleInvalidBundleTest_0100
 * @tc.name: HandleInvalidBundle
 * @tc.desc: test HandleInvalidBundle (Set the mark status to InstallExceptionStatus::INSTALL_ START)
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleInvalidBundleTest_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0100 start";
    bool isBundleValid = true;
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    int32_t userId = 100;
    bool result = bundleExceptionHandler_->RemoveBundleAndDataDir(BUNDLE_DIR_NAME, BUNDLE_OR_MOUDLE_DIR, userId);
    EXPECT_EQ(result, true);
    info.SetInstallMark(BUNDLE_NAME, Package_NAME, InstallExceptionStatus::INSTALL_START);
    bundleExceptionHandler_->HandleInvalidBundle(info, isBundleValid);
    auto data = info.GetInstallMark();
    EXPECT_EQ(isBundleValid, false);
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0100 end";
}

/**
 * @tc.number: HandleInvalidBundleTest_0200
 * @tc.name: HandleInvalidBundle
 * @tc.desc: test HandleInvalidBundle (Set the bundle status to BundleStatus::ENABLED)
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleInvalidBundleTest_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0200 start";
    bool isBundleValid = true;
    InnerBundleInfo info;
    const InnerBundleInfo::BundleStatus data = InnerBundleInfo::BundleStatus::ENABLED;
    info.SetBundleStatus(data);
    bundleExceptionHandler_->HandleInvalidBundle(info, isBundleValid);
    EXPECT_EQ(info.GetBundleStatus(), InnerBundleInfo::BundleStatus::ENABLED);
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0200 end";
}

/**
 * @tc.number: HandleInvalidBundleTest_0300
 * @tc.name: HandleInvalidBundle
 * @tc.desc: test HandleInvalidBundle (Set the mark status to InstallExceptionStatus::INSTALL_FINISH)
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleInvalidBundleTest_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0300 start";
    bool isBundleValid = true;
    InnerBundleInfo info;
    info.SetInstallMark(BUNDLE_NAME, Package_NAME, InstallExceptionStatus::INSTALL_FINISH);
    bundleExceptionHandler_->HandleInvalidBundle(info, isBundleValid);
    auto data = info.GetInstallMark();
    EXPECT_EQ(data.status, InstallExceptionStatus::INSTALL_FINISH);
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0300 end";
}

/**
 * @tc.number: HandleInvalidBundleTest_0400
 * @tc.name: HandleInvalidBundle
 * @tc.desc: test HandleInvalidBundle (Set the mark status to InstallExceptionStatus::INSTALL_START)
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleInvalidBundleTest_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0400 start";
    bool isBundleValid = true;
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    info.SetInstallMark(BUNDLE_NAME, Package_NAME, InstallExceptionStatus::INSTALL_START);
    bundleExceptionHandler_->HandleInvalidBundle(info, isBundleValid);
    auto data = info.GetInstallMark();
    EXPECT_EQ(isBundleValid, false);
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0400 end";
}

/**
 * @tc.number: HandleInvalidBundleTest_0500
 * @tc.name: HandleInvalidBundle
 * @tc.desc: test HandleInvalidBundle (Set the mark status to InstallExceptionStatus::UPDATING_EXISTED_START)
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleInvalidBundleTest_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0500 start";
    bool isBundleValid = true;
    InnerBundleInfo info;
    int32_t userId = 100;
    bool result = bundleExceptionHandler_->RemoveBundleAndDataDir(BUNDLE_DIR_NAME, BUNDLE_OR_MOUDLE_DIR, userId);
    EXPECT_EQ(result, true);
    info.SetInstallMark(BUNDLE_NAME, Package_NAME, InstallExceptionStatus::UPDATING_EXISTED_START);
    bundleExceptionHandler_->HandleInvalidBundle(info, isBundleValid);
    auto data = info.GetInstallMark();
    EXPECT_EQ(data.status, InstallExceptionStatus::UPDATING_EXISTED_START);
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0500 end";
}

/**
 * @tc.number: HandleInvalidBundleTest_0600
 * @tc.name: HandleInvalidBundle
 * @tc.desc: test HandleInvalidBundle (Set the mark status to InstallExceptionStatus::UPDATING_NEW_START)
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleInvalidBundleTest_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0600 start";
    bool isBundleValid = true;
    InnerBundleInfo info;
    int32_t userId = 100;
    bool result = bundleExceptionHandler_->RemoveBundleAndDataDir(BUNDLE_DIR_NAME, BUNDLE_OR_MOUDLE_DIR, userId);
    EXPECT_EQ(result, true);
    info.SetInstallMark(BUNDLE_NAME, Package_NAME, InstallExceptionStatus::UPDATING_NEW_START);
    bundleExceptionHandler_->HandleInvalidBundle(info, isBundleValid);
    auto data = info.GetInstallMark();
    EXPECT_EQ(data.status, InstallExceptionStatus::UPDATING_NEW_START);
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0600 end";
}

/**
 * @tc.number: HandleInvalidBundleTest_0700
 * @tc.name: HandleInvalidBundle
 * @tc.desc: test HandleInvalidBundle (Set the mark status to InstallExceptionStatus::UNINSTALL_BUNDLE_START)
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleInvalidBundleTest_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0700 start";
    bool isBundleValid = true;
    InnerBundleInfo info;
    int32_t userId = 100;
    bool result = bundleExceptionHandler_->RemoveBundleAndDataDir(BUNDLE_DIR_NAME, BUNDLE_OR_MOUDLE_DIR, userId);
    EXPECT_EQ(result, true);
    info.SetInstallMark(BUNDLE_NAME, Package_NAME, InstallExceptionStatus::UNINSTALL_BUNDLE_START);
    bundleExceptionHandler_->HandleInvalidBundle(info, isBundleValid);
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0700 end";
}

/**
 * @tc.number: HandleInvalidBundleTest_0800
 * @tc.name: HandleInvalidBundle
 * @tc.desc: test HandleInvalidBundle (Set the mark status to InstallExceptionStatus::UNINSTALL_PACKAGE_START)
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleInvalidBundleTest_0800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0800 start";
    bool isBundleValid = true;
    InnerBundleInfo info;
    int32_t userId = 100;
    bool result = bundleExceptionHandler_->RemoveBundleAndDataDir(BUNDLE_DIR_NAME, BUNDLE_OR_MOUDLE_DIR, userId);
    EXPECT_EQ(result, true);
    info.SetInstallMark(BUNDLE_NAME, Package_NAME, InstallExceptionStatus::UNINSTALL_PACKAGE_START);
    bundleExceptionHandler_->HandleInvalidBundle(info, isBundleValid);
    auto data = info.GetInstallMark();
    EXPECT_EQ(data.status, InstallExceptionStatus::UNINSTALL_PACKAGE_START);
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0800 end";
}

/**
 * @tc.number: HandleInvalidBundleTest_0900
 * @tc.name: HandleInvalidBundle
 * @tc.desc: test HandleInvalidBundle (Set the mark status to InstallExceptionStatus::UPDATING_FINISH)
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleInvalidBundleTest_0900, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0900 start";
    bool isBundleValid = true;
    InnerBundleInfo info;
    int32_t userId = 100;
    bool result = bundleExceptionHandler_->RemoveBundleAndDataDir(BUNDLE_DIR_NAME, BUNDLE_OR_MOUDLE_DIR, userId);
    EXPECT_EQ(result, true);
    info.SetInstallMark(BUNDLE_NAME, Package_NAME, InstallExceptionStatus::UPDATING_FINISH);
    bundleExceptionHandler_->HandleInvalidBundle(info, isBundleValid);
    auto data = info.GetInstallMark();
    EXPECT_EQ(data.status, InstallExceptionStatus::UPDATING_FINISH);
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_0900 end";
}

/**
 * @tc.number: DeleteBundleInfoFromStorageTest_1100
 * @tc.name: DeleteBundleInfoFromStorage
 * @tc.desc: test DeleteBundleInfoFromStorage (Do not take if branch coverage)
 */
HWTEST_F(BmsBundleExceptionHandlerTest, DeleteBundleInfoFromStorageTest_1100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DeleteBundleInfoFromStorageTest_1100 start";
    bool isBundleValid = true;
    std::shared_ptr<IBundleDataStorage> dataStorageSptr = nullptr;
    BundleExceptionHandler BundleExceptionHandler(dataStorageSptr);
    InnerBundleInfo info;
    int32_t userId = 100;
    bool result = BundleExceptionHandler.RemoveBundleAndDataDir(BUNDLE_DIR_NAME, BUNDLE_OR_MOUDLE_DIR, userId);
    EXPECT_EQ(result, true);
    info.SetInstallMark(BUNDLE_NAME, Package_NAME, InstallExceptionStatus::UPDATING_FINISH);
    BundleExceptionHandler.HandleInvalidBundle(info, isBundleValid);
    auto data = info.GetInstallMark();
    EXPECT_EQ(data.status, InstallExceptionStatus::UPDATING_FINISH);
    BundleExceptionHandler.DeleteBundleInfoFromStorage(info);
    GTEST_LOG_(INFO) << "DeleteBundleInfoFromStorageTest_1100 end";
}


/**
 * @tc.number: HandleInvalidBundleTest_1000
 * @tc.name: HandleInvalidBundle
 * @tc.desc: test CheckSharedAndRmvInvalidModule (Set the bundle status to BundleStatus::ENABLED)
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleInvalidBundleTest_1000, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_1000 start";
    bool isBundleValid = true;
    InnerBundleInfo info;
    const InnerBundleInfo::BundleStatus data = InnerBundleInfo::BundleStatus::ENABLED;
    info.SetInstallMark(BUNDLE_NAME, Package_NAME, InstallExceptionStatus::INSTALL_FINISH);
    info.SetBundleStatus(data);
    info.SetApplicationBundleType(BundleType::SHARED);
    bundleExceptionHandler_->HandleInvalidBundle(info, isBundleValid);
    EXPECT_EQ(isBundleValid, false);
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_1000 end";
}

/**
 * @tc.number: HandleInvalidBundleTest_1100
 * @tc.name: HandleInvalidBundle
 * @tc.desc: test CheckSharedAndRmvInvalidModule (Set the bundle status to BundleStatus::ENABLED)
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleInvalidBundleTest_1100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_1100 start";
    bool isBundleValid = true;
    InnerBundleInfo info;
    const InnerBundleInfo::BundleStatus data = InnerBundleInfo::BundleStatus::ENABLED;
    info.SetInstallMark(BUNDLE_NAME, Package_NAME, InstallExceptionStatus::INSTALL_FINISH);
    info.SetBundleStatus(data);
    info.SetApplicationBundleType(BundleType::SHARED);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.versionCode = 1;
    InnerModuleInfo innerModuleInfo2;
    innerModuleInfo2.versionCode = 2;
    info.InsertInnerSharedModuleInfo("test", innerModuleInfo);
    info.InsertInnerSharedModuleInfo("test", innerModuleInfo2);
    bundleExceptionHandler_->HandleInvalidBundle(info, isBundleValid);
    EXPECT_EQ(isBundleValid, true);
    GTEST_LOG_(INFO) << "HandleInvalidBundleTest_1100 end";
}

/**
 * @tc.number: InnerBundleInfo_0100
 * @tc.name: SetNeedSendNotify
 * @tc.desc: test SetNeedSendNotify
 */
HWTEST_F(BmsBundleExceptionHandlerTest, InnerBundleInfo_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.SetNeedSendNotify(true);
    EXPECT_TRUE(info.isNeedSendNotify_);
}

/**
 * @tc.number: InnerBundleInfo_0100
 * @tc.name: GetOdid
 * @tc.desc: test GetOdid
 */
HWTEST_F(BmsBundleExceptionHandlerTest, InnerBundleInfo_0200, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    std::string odid;
    std::string developerId;
    info.UpdateOdid(developerId, BUNDLE_NAME);
    info.GetOdid(odid);
    EXPECT_EQ(odid, BUNDLE_NAME);
}

/**
 * @tc.number: InnerBundleInfo_0300
 * @tc.name: SetResourcesApply
 * @tc.desc: test SetResourcesApply
 */
HWTEST_F(BmsBundleExceptionHandlerTest, InnerBundleInfo_0300, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    std::vector<int32_t> resourcesApply;
    resourcesApply.push_back(USERID);
    info.SetResourcesApply(resourcesApply);
    EXPECT_FALSE(info.baseApplicationInfo_->resourcesApply.empty());
}

/**
 * @tc.number: InnerBundleInfo_0400
 * @tc.name: GetLastInstallationTime
 * @tc.desc: test GetLastInstallationTime
 */
HWTEST_F(BmsBundleExceptionHandlerTest, InnerBundleInfo_0400, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    auto ret = info.GetLastInstallationTime();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: HandleUninstallPackageStart_0100
 * @tc.name: Test HandleUninstallPackageStart with only module
 * @tc.desc: Test HandleUninstallPackageStart when IsOnlyModule returns true
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleUninstallPackageStart_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    bool isBundleValid = true;
    InstallMark mark;
    mark.packageName = Package_NAME;
    std::string appCodePath = BUNDLE_OR_MOUDLE_DIR + BUNDLE_NAME;
    std::string effectiveBundleName = BUNDLE_NAME;
    std::string moduleDir = appCodePath + "/" + Package_NAME;
    std::string moduleDataDir = effectiveBundleName + "/haps/" + Package_NAME;

    bundleExceptionHandler_->HandleUninstallPackageStart(
        info, isBundleValid, mark, appCodePath, effectiveBundleName, moduleDir, moduleDataDir);
    // In mock environment, RemoveBundleAndDataDir will fail, so isBundleValid remains true
    EXPECT_TRUE(isBundleValid);
}

/**
 * @tc.number: HandleUninstallPackageStart_0200
 * @tc.name: Test HandleUninstallPackageStart with non-module package
 * @tc.desc: Test HandleUninstallPackageStart when IsOnlyModule returns false
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleUninstallPackageStart_0200, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    bool isBundleValid = true;
    InstallMark mark;
    mark.packageName = EMPTY_STRING;
    std::string appCodePath = BUNDLE_OR_MOUDLE_DIR + BUNDLE_NAME;
    std::string effectiveBundleName = BUNDLE_NAME;
    std::string moduleDir = appCodePath + "/base";
    std::string moduleDataDir = effectiveBundleName + "/haps/base";

    bundleExceptionHandler_->HandleUninstallPackageStart(
        info, isBundleValid, mark, appCodePath, effectiveBundleName, moduleDir, moduleDataDir);
    // In mock environment, RemoveBundleAndDataDir will fail, so isBundleValid remains true
    EXPECT_TRUE(isBundleValid);
}

/**
 * @tc.number: HandleUninstallPackageStart_0300
 * @tc.name: Test HandleUninstallPackageStart with empty paths
 * @tc.desc: Test HandleUninstallPackageStart with empty path parameters
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleUninstallPackageStart_0300, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    bool isBundleValid = true;
    InstallMark mark;
    std::string emptyPath = "";

    bundleExceptionHandler_->HandleUninstallPackageStart(
        info, isBundleValid, mark, emptyPath, emptyPath, emptyPath, emptyPath);
    // With empty paths, RemoveBundleAndDataDir will fail, so isBundleValid remains true
    EXPECT_TRUE(isBundleValid);
}

/**
 * @tc.number: InnerHandleInvalidBundle_0500
 * @tc.name: Test UNINSTALL_PACKAGE_START path
 * @tc.desc: Test InnerHandleInvalidBundle with UNINSTALL_PACKAGE_START status
 */
HWTEST_F(BmsBundleExceptionHandlerTest, InnerHandleInvalidBundle_0500, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    InstallMark mark;
    mark.status = InstallExceptionStatus::UNINSTALL_PACKAGE_START;
    mark.packageName = Package_NAME;
    info.SetInstallMark(BUNDLE_NAME, Package_NAME, InstallExceptionStatus::UNINSTALL_PACKAGE_START);
    bool isBundleValid = true;

    bundleExceptionHandler_->InnerHandleInvalidBundle(info, isBundleValid);
    // Function should call HandleUninstallPackageStart and complete without crash
    // In mock environment, RemoveBundleAndDataDir will fail, so isBundleValid remains true
    EXPECT_TRUE(isBundleValid);
}

/**
 * @tc.number: HandleUninstallPackageStart_0400
 * @tc.name: Test HandleUninstallPackageStart where second RemoveBundleAndDataDir fails
 * @tc.desc: Exercise the else branch (error log) in HandleUninstallPackageStart by using a
 *           negative userId so RemoveModuleDataDir / RemoveBundleDataDir fails in the mock.
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleUninstallPackageStart_0400, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    info.SetUserId(-1);  // negative userId causes RemoveBundleDataDir/RemoveModuleDataDir to fail
    bool isBundleValid = true;
    InstallMark mark;
    mark.packageName = Package_NAME;
    std::string appCodePath = BUNDLE_OR_MOUDLE_DIR + BUNDLE_NAME;
    std::string effectiveBundleName = BUNDLE_NAME;
    std::string moduleDir = appCodePath + "/" + Package_NAME;
    std::string moduleDataDir = effectiveBundleName + "/haps/" + Package_NAME;

    bundleExceptionHandler_->HandleUninstallPackageStart(
        info, isBundleValid, mark, appCodePath, effectiveBundleName, moduleDir, moduleDataDir);
    // First branch: IsOnlyModule is false (empty module map), so we go to second RemoveBundleAndDataDir.
    // With negative userId, RemoveBundleAndDataDir fails → else branch logs error, isBundleValid stays true.
    EXPECT_TRUE(isBundleValid);
}

/**
 * @tc.number: HandleUninstallPackageStart_0500
 * @tc.name: Test HandleUninstallPackageStart where first branch succeeds (IsOnlyModule + remove ok)
 * @tc.desc: Exercise the first branch where IsOnlyModule returns true and RemoveBundleAndDataDir
 *           succeeds, setting isBundleValid to false.
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleUninstallPackageStart_0500, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    bool isBundleValid = true;
    InstallMark mark;
    mark.packageName = Package_NAME;
    // Insert exactly one module so IsOnlyModule returns true
    InnerModuleInfo moduleInfo;
    info.InsertInnerModuleInfo(Package_NAME, moduleInfo);
    std::string appCodePath = BUNDLE_OR_MOUDLE_DIR + BUNDLE_NAME;
    std::string effectiveBundleName = BUNDLE_NAME;
    std::string moduleDir = appCodePath + "/" + Package_NAME;
    std::string moduleDataDir = effectiveBundleName + "/haps/" + Package_NAME;

    bundleExceptionHandler_->HandleUninstallPackageStart(
        info, isBundleValid, mark, appCodePath, effectiveBundleName, moduleDir, moduleDataDir);
    // IsOnlyModule true + RemoveBundleAndDataDir succeeds → isBundleValid set to false
    EXPECT_FALSE(isBundleValid);
}

/**
 * @tc.number: InnerHandleInvalidBundle_0600
 * @tc.name: Test INSTALL_START success path via InnerHandleInvalidBundle
 * @tc.desc: When RemoveBundleAndDataDir succeeds for INSTALL_START, isBundleValid should be
 *           set to false and bundle info deleted from storage.
 */
HWTEST_F(BmsBundleExceptionHandlerTest, InnerHandleInvalidBundle_0600, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    info.SetInstallMark(BUNDLE_NAME, Package_NAME, InstallExceptionStatus::INSTALL_START);
    bool isBundleValid = true;

    bundleExceptionHandler_->InnerHandleInvalidBundle(info, isBundleValid);
    // RemoveBundleAndDataDir succeeds in mock (valid bundleName, userId=0) → isBundleValid = false
    EXPECT_FALSE(isBundleValid);
}

/**
 * @tc.number: HandleInvalidBundleTest_1200
 * @tc.name: Test HandleInvalidBundle with APP_SERVICE_FWK type
 * @tc.desc: When bundle type is APP_SERVICE_FWK and isBundleValid remains true after
 *           InnerHandleInvalidBundle, InnerCheckSystemHspPath should be called.
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleInvalidBundleTest_1200, Function | SmallTest | Level0)
{
    bool isBundleValid = true;
    InnerBundleInfo info;
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    info.SetInstallMark(BUNDLE_NAME, Package_NAME, InstallExceptionStatus::INSTALL_FINISH);
    info.SetApplicationBundleType(BundleType::APP_SERVICE_FWK);
    bundleExceptionHandler_->HandleInvalidBundle(info, isBundleValid);
    // INSTALL_FINISH returns early from InnerHandleInvalidBundle, isBundleValid stays true,
    // then InnerCheckSystemHspPath is called (no crash expected).
    EXPECT_TRUE(isBundleValid);
}

/**
 * @tc.number: InnerHandleInvalidBundle_0700
 * @tc.name: Test INSTALL_START with RemoveBundleAndDataDir failure (empty effectiveBundleName)
 * @tc.desc: When bundleName is empty, effectiveBundleName is empty, so RemoveBundleDataDir
 *           fails in the mock (empty bundleName check). This covers the else branch at L183
 *           where isBundleValid stays true and an error is logged.
 */
HWTEST_F(BmsBundleExceptionHandlerTest, InnerHandleInvalidBundle_0700, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    // Leave bundleName empty so effectiveBundleName is empty → RemoveBundleDataDir fails
    info.SetInstallMark("", Package_NAME, InstallExceptionStatus::INSTALL_START);
    bool isBundleValid = true;

    bundleExceptionHandler_->InnerHandleInvalidBundle(info, isBundleValid);
    // RemoveBundleAndDataDir returns false (empty effectiveBundleName) → else branch fires
    // isBundleValid should remain true
    EXPECT_TRUE(isBundleValid);
}

/**
 * @tc.number: HandleUninstallPackageStart_0600
 * @tc.name: Test HandleUninstallPackageStart with IsOnlyModule true but RemoveBundleAndDataDir fails
 * @tc.desc: Insert one module so IsOnlyModule returns true, but use empty effectiveBundleName
 *           so RemoveBundleAndDataDir fails. This covers L144 Branch 2 (IsOnlyModule true &&
 *           RemoveBundleAndDataDir false → falls through to second RemoveBundleAndDataDir).
 */
HWTEST_F(BmsBundleExceptionHandlerTest, HandleUninstallPackageStart_0600, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    // Leave bundleName empty so effectiveBundleName is empty → RemoveBundleDataDir fails
    bool isBundleValid = true;
    InstallMark mark;
    mark.packageName = Package_NAME;
    // Insert exactly one module so IsOnlyModule returns true
    InnerModuleInfo moduleInfo;
    info.InsertInnerModuleInfo(Package_NAME, moduleInfo);
    std::string appCodePath = BUNDLE_OR_MOUDLE_DIR + "";
    std::string effectiveBundleName = "";  // empty → RemoveBundleDataDir fails
    std::string moduleDir = appCodePath + "/" + Package_NAME;
    std::string moduleDataDir = effectiveBundleName + "/haps/" + Package_NAME;

    bundleExceptionHandler_->HandleUninstallPackageStart(
        info, isBundleValid, mark, appCodePath, effectiveBundleName, moduleDir, moduleDataDir);
    // IsOnlyModule true but RemoveBundleAndDataDir fails (empty effectiveBundleName)
    // → falls through to second RemoveBundleAndDataDir(moduleDir, moduleDataDir, userId)
    // moduleDataDir contains "haps" → RemoveModuleDataDir called (returns 0 in mock)
    // → RemoveModuleInfo + SetBundleStatus(ENABLED)
    EXPECT_TRUE(isBundleValid);  // isBundleValid not set to false in this path
}
}  // namespace OHOS
