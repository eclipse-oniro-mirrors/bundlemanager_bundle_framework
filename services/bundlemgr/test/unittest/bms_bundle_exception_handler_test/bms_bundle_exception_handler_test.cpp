/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "installd_client.h"
#include "bundle_data_storage_rdb.h"
#include "preinstall_data_storage_rdb.h"
#define private public
#include "bundle_exception_handler.h"
#include "inner_bundle_info.h"
#undef public

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
    EXPECT_EQ(isBundleValid, true);
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
}  // namespace OHOS
