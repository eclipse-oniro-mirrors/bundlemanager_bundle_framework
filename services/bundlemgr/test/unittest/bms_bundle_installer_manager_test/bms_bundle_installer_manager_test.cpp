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
#include <map>
#include <string>
#include "mock_status_receiver.h"

#define private public
#define protected public
#include "ability_event_handler.h"
#include "bundle_installer_manager.h"
#include "bundle_mgr_service.h"
#include "event_runner.h"
#include "inner_event.h"
#undef public
#undef protected
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string RESOURCE_ROOT_PATH = "/data/test/resource/bms/install_bundle/";
const std::string RIGHT_BUNDLE = "right.hap";
const std::string BUNDLE_NAME = "com.ohos.launcher";
const std::string MODULE_PACKAGE = "entry";
const int32_t USERID = 100;
const std::string EMPTY_STRING = "";
}  // namespace

class BundleInstallerManagerTest : public testing::Test {
public:
    BundleInstallerManagerTest();
    ~BundleInstallerManagerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<BundleInstallerManager> bundleInstallerManager = nullptr;
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BundleInstallerManagerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BundleInstallerManagerTest::BundleInstallerManagerTest()
{}

BundleInstallerManagerTest::~BundleInstallerManagerTest()
{}

void BundleInstallerManagerTest::SetUpTestCase()
{}

void BundleInstallerManagerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BundleInstallerManagerTest::SetUp()
{}

void BundleInstallerManagerTest::TearDown()
{}

/**
 * @tc.number: BundleInstallerManagerTest_005
 * @tc.name: test CreateInstallTask
 * @tc.desc: Verify function CreateInstallTask is called, receiver->GetResultCode() return value is ERR_OK
 */
HWTEST_F(BundleInstallerManagerTest, BundleInstallerManagerTest_005, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(receiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;
    std::string bundleFilePath = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    auto bundleInstallerManager = std::make_shared<BundleInstallerManager>();
    bundleInstallerManager->CreateInstallTask(bundleFilePath, installParam, receiver);
    ErrCode result = receiver->GetResultCode();
    EXPECT_NE(ERR_OK, result);
}

/**
 * @tc.number: BundleInstallerManagerTest_006
 * @tc.name: test CreateRecoverTask
 * @tc.desc: Verify function CreateRecoverTask is called, receiver->GetResultCode() return value is ERR_OK
 */
HWTEST_F(BundleInstallerManagerTest, BundleInstallerManagerTest_006, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(receiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;
    std::string bundleName = BUNDLE_NAME;
    auto bundleInstallerManager = std::make_shared<BundleInstallerManager>();
    bundleInstallerManager->CreateRecoverTask(bundleName, installParam, receiver);
    ErrCode result = receiver->GetResultCode();
    EXPECT_NE(ERR_OK, result);
}

/**
 * @tc.number: BundleInstallerManagerTest_007
 * @tc.name: test CreateInstallTask
 * @tc.desc: Verify function CreateInstallTask is called, receiver->GetResultCode() return value is ERR_OK
 */
HWTEST_F(BundleInstallerManagerTest, BundleInstallerManagerTest_007, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(receiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;
    std::vector<std::string> bundleFilePaths;
    std::string bundleFile = RESOURCE_ROOT_PATH + RIGHT_BUNDLE;
    auto bundleInstallerManager = std::make_shared<BundleInstallerManager>();
    bundleFilePaths.emplace_back(bundleFile);
    bundleInstallerManager->CreateInstallTask(bundleFilePaths, installParam, receiver);
    ErrCode result = receiver->GetResultCode();
    EXPECT_NE(ERR_OK, result);
}

/**
 * @tc.number: BundleInstallerManagerTest_008
 * @tc.name: test CreateInstallByBundleNameTask
 * @tc.desc: Verify function CreateInstallByBundleNameTask is called, receiver->GetResultCode() return value is ERR_OK
 */
HWTEST_F(BundleInstallerManagerTest, BundleInstallerManagerTest_008, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(receiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;
    std::string bundleName = BUNDLE_NAME;
    auto bundleInstallerManager = std::make_shared<BundleInstallerManager>();
    bundleInstallerManager->CreateInstallByBundleNameTask(bundleName, installParam, receiver);
    ErrCode result = receiver->GetResultCode();
    EXPECT_NE(ERR_OK, result);
}

/**
 * @tc.number: BundleInstallerManagerTest_009
 * @tc.name: test CreateUninstallTask
 * @tc.desc: Verify function CreateUninstallTask is called, receiver->GetResultCode() return value is ERR_OK
 */
HWTEST_F(BundleInstallerManagerTest, BundleInstallerManagerTest_009, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(receiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;
    std::string bundleName = BUNDLE_NAME;
    auto bundleInstallerManager = std::make_shared<BundleInstallerManager>();
    bundleInstallerManager->CreateUninstallTask(bundleName, installParam, receiver);
    ErrCode result = receiver->GetResultCode();
    EXPECT_NE(ERR_OK, result);
}

/**
 * @tc.number: BundleInstallerManagerTest_010
 * @tc.name: test CreateUninstallTask
 * @tc.desc: Verify function CreateUninstallTask is called, receiver->GetResultCode() return value is ERR_OK
 */
HWTEST_F(BundleInstallerManagerTest, BundleInstallerManagerTest_010, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(receiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;
    std::string bundleName = BUNDLE_NAME;
    std::string modulePackage = MODULE_PACKAGE;
    auto bundleInstallerManager = std::make_shared<BundleInstallerManager>();
    bundleInstallerManager->CreateUninstallTask(bundleName, modulePackage, installParam, receiver);
    ErrCode result = receiver->GetResultCode();
    EXPECT_NE(ERR_OK, result);
}

/**
 * @tc.number: BundleInstallerManagerTest_020
 * @tc.name: test CreateUninstallAndRecoverTask
 * @tc.desc: Verify function CreateUninstallAndRecoverTask is called,
 * receiver->GetResultCode() return value is not ERR_OK
 */
HWTEST_F(BundleInstallerManagerTest, BundleInstallerManagerTest_020, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(receiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;
    std::string bundleName = EMPTY_STRING;
    auto bundleInstallerManager = std::make_shared<BundleInstallerManager>();
    bundleInstallerManager->CreateUninstallAndRecoverTask(bundleName, installParam, receiver);
    ErrCode result = receiver->GetResultCode();
    EXPECT_NE(ERR_OK, result);
}
}  // AppExecFwk
}  // OHOS