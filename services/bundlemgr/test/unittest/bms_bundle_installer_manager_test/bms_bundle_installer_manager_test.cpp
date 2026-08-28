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
#include <atomic>
#include <chrono>
#include <map>
#include <string>
#include <thread>
#include "mock_status_receiver.h"
#include "parameters.h"
#include "appexecfwk_errors.h"

#define private public
#define protected public
#include "ability_event_handler.h"
#include "bundle_data_mgr.h"
#include "bundle_installer_manager.h"
#include "bundle_mgr_service.h"
#include "bundle_service_constants.h"
#include "dual_mode_helper.h"
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

/**
 * @tc.number: BundleInstallerManagerTest_CreateInstallLocalPluginTask_0001
 * @tc.name: test CreateInstallLocalPluginTask
 * @tc.desc: Verify CreateInstallLocalPluginTask runs and returns non-ERR_OK
 */
HWTEST_F(BundleInstallerManagerTest, BundleInstallerManagerTest_CreateInstallLocalPluginTask_0001, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(receiver, nullptr);
    InstallPluginParam installPluginParam;
    installPluginParam.userId = USERID;
    std::string hostBundleName = BUNDLE_NAME;
    std::vector<std::string> pluginFilePaths = {RESOURCE_ROOT_PATH + RIGHT_BUNDLE};
    auto bundleInstallerManager = std::make_shared<BundleInstallerManager>();
    bundleInstallerManager->CreateInstallLocalPluginTask(hostBundleName, pluginFilePaths,
        installPluginParam, receiver);
    ErrCode result = receiver->GetResultCode();
    EXPECT_NE(ERR_OK, result);
}

/**
 * @tc.number: BundleInstallerManagerTest_CreateUninstallLocalPluginTask_0001
 * @tc.name: test CreateUninstallLocalPluginTask
 * @tc.desc: Verify CreateUninstallLocalPluginTask runs and returns non-ERR_OK
 */
HWTEST_F(BundleInstallerManagerTest, BundleInstallerManagerTest_CreateUninstallLocalPluginTask_0001, TestSize.Level1)
{
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(receiver, nullptr);
    InstallPluginParam installPluginParam;
    installPluginParam.userId = USERID;
    std::string hostBundleName = BUNDLE_NAME;
    std::string pluginBundleName = MODULE_PACKAGE;
    auto bundleInstallerManager = std::make_shared<BundleInstallerManager>();
    bundleInstallerManager->CreateUninstallLocalPluginTask(hostBundleName, pluginBundleName,
        installPluginParam, receiver);
    ErrCode result = receiver->GetResultCode();
    EXPECT_NE(ERR_OK, result);
}

/**
 * @tc.number: BundleInstallerManagerTest_GetLocalPluginInstaller_0001
 * @tc.name: test GetLocalPluginInstaller when service not started
 * @tc.desc: Verify GetLocalPluginInstaller returns nullptr
 */
HWTEST_F(BundleInstallerManagerTest, BundleInstallerManagerTest_GetLocalPluginInstaller_0001, TestSize.Level1)
{
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    auto installer = hostImpl->GetLocalPluginInstaller();
    EXPECT_EQ(installer, nullptr);
}

/**
 * @tc.number: BundleInstallerManagerTest_GetCurTaskNum_0001
 * @tc.name: test GetCurTaskNum when thread pool is not started
 * @tc.desc: 1. threadPool_ is nullptr
 *           2. GetCurTaskNum returns 0
 */
HWTEST_F(BundleInstallerManagerTest, BundleInstallerManagerTest_GetCurTaskNum_0001, TestSize.Level1)
{
    auto bundleInstallerManager = std::make_shared<BundleInstallerManager>();
    EXPECT_EQ(bundleInstallerManager->GetCurTaskNum(), 0U);
    EXPECT_GT(bundleInstallerManager->GetThreadsNum(), 0);
}

/**
 * @tc.number: BundleInstallerManagerTest_DualModeMutex_0001
 * @tc.name: test AddTask task fails fast while a dual-mode switch is in flight
 * @tc.desc: 1. on a non-dual-mode device AddTask skips the wrapping at enqueue time and posts
 *              the task as-is (it runs even while the exclusive side is held — the switch entry
 *              rejects such devices at the device gate, so the lock can never matter there)
 *           2. on a dual-mode device a task queued through AddTask tries the shared side of
 *              BundleDataMgr's dualModeSwitchMutex_ at execution time: while a switch holds the
 *              exclusive side the task is DROPPED (never runs, never waits) and onReject is
 *              called instead (r13)
 *           3. after the switch releases, the dropped task stays dropped — the caller was
 *              already notified at rejection time
 */
HWTEST_F(BundleInstallerManagerTest, BundleInstallerManagerTest_DualModeMutex_0001, TestSize.Level0)
{
    // The wrapper resolves the data manager at task execution time through the service singleton
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    ASSERT_NE(service, nullptr);
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    service->dataMgr_ = dataMgr;
    auto bundleInstallerManager = std::make_shared<BundleInstallerManager>();
    auto waitTaskRan = [](const std::atomic<bool> &ran) {
        for (int i = 0; i < 100 && !ran.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return ran.load();
    };

    // Part 1 — non-dual-mode device (no test keys seeded, so IsDualModeDevice() reads missing
    // params and returns false): AddTask posts the task unwrapped and it runs even while the
    // exclusive side is held
    std::unique_lock<std::shared_mutex> switchGuard(dataMgr->dualModeSwitchMutex_);
    std::atomic<bool> bypassRan(false);
    bundleInstallerManager->AddTask([&bypassRan] { bypassRan = true; }, "DualModeMutexBypass");
    EXPECT_TRUE(waitTaskRan(bypassRan));

    // Part 2 — dual-mode device (seed the same persist.bms.* test keys the switch suite uses;
    // DualModeHelper reads them directly each call, no refresh needed): the queued task is
    // wrapped; its execution-time try of the shared side fails while the switch holds the
    // exclusive side, so the task is dropped and onReject is called instead
    OHOS::system::SetParameter("persist.bms.test_dual_mode", "true");
    OHOS::system::SetParameter("persist.bms.ispcmode",
        std::to_string(ServiceConstants::DUAL_MODE_VALUE_TABLET));
    OHOS::system::SetParameter("persist.bms.mainmode",
        std::to_string(ServiceConstants::DUAL_MODE_VALUE_TABLET));
    ASSERT_TRUE(DualModeHelper::IsDualModeDevice());
    std::atomic<bool> taskRan(false);
    std::atomic<bool> onRejectCalled(false);
    bundleInstallerManager->AddTask([&taskRan] { taskRan = true; }, "DualModeMutexProve",
        [&onRejectCalled] { onRejectCalled = true; });

    // While the switch is in flight the queued task is dropped without running — no waiting
    // state exists on the operation side (r13); the rejection hook fires instead
    EXPECT_TRUE(waitTaskRan(onRejectCalled));
    EXPECT_FALSE(taskRan.load());

    // The switch completes: the dropped task stays dropped — the caller was already notified
    switchGuard.unlock();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(taskRan.load());

    // Restore the non-dual-mode default so the mode params cannot leak into later cases
    OHOS::system::RemoveParameter("persist.bms.test_dual_mode");
    OHOS::system::RemoveParameter("persist.bms.ispcmode");
    OHOS::system::RemoveParameter("persist.bms.mainmode");
}

/**
 * @tc.number: BundleInstallerManagerTest_DualModeMutex_0002
 * @tc.name: test CreateInstallTask rejects at call time while a dual-mode switch is in flight
 * @tc.desc: on a dual-mode device with the exclusive side held, CreateInstallTask never
 *           enqueues anything: the entry-time probe (RejectTaskIfSwitchInFlight) notifies the
 *           statusReceiver with ERR_APPEXECFWK_DUAL_MODE_SWITCH_BUSY synchronously, before
 *           any installer object is created (r13)
 */
HWTEST_F(BundleInstallerManagerTest, BundleInstallerManagerTest_DualModeMutex_0002, TestSize.Level0)
{
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    ASSERT_NE(service, nullptr);
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    service->dataMgr_ = dataMgr;

    // Dual-mode device (same persist.bms.* test-key seeding as DualModeMutex_0001;
    // DualModeHelper reads them directly each call, no refresh needed); an in-flight switch
    // holds the exclusive side
    OHOS::system::SetParameter("persist.bms.test_dual_mode", "true");
    OHOS::system::SetParameter("persist.bms.ispcmode",
        std::to_string(ServiceConstants::DUAL_MODE_VALUE_TABLET));
    OHOS::system::SetParameter("persist.bms.mainmode",
        std::to_string(ServiceConstants::DUAL_MODE_VALUE_TABLET));
    ASSERT_TRUE(DualModeHelper::IsDualModeDevice());
    std::unique_lock<std::shared_mutex> switchGuard(dataMgr->dualModeSwitchMutex_);

    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    ASSERT_NE(receiver, nullptr);
    InstallParam installParam;
    installParam.userId = USERID;
    auto bundleInstallerManager = std::make_shared<BundleInstallerManager>();
    bundleInstallerManager->CreateInstallTask(RESOURCE_ROOT_PATH + RIGHT_BUNDLE, installParam, receiver);

    // Rejected at call time: BUSY delivered to the receiver synchronously — no enqueue, no
    // task body, no 2s timeout wait (the promise was already set inside CreateInstallTask)
    EXPECT_EQ(receiver->GetResultCode(), ERR_APPEXECFWK_DUAL_MODE_SWITCH_BUSY);

    switchGuard.unlock();
    // Restore the non-dual-mode default so the mode params cannot leak into later cases
    OHOS::system::RemoveParameter("persist.bms.test_dual_mode");
    OHOS::system::RemoveParameter("persist.bms.ispcmode");
    OHOS::system::RemoveParameter("persist.bms.mainmode");
}
}  // AppExecFwk
}  // OHOS