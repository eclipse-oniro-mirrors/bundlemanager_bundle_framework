/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "bundle_installer_manager.h"

#include "app_log_tag_wrapper.h"
#include "bundle_hitrace_chain.h"
#include "bundle_memory_guard.h"
#include "bundle_mgr_service.h"
#include "datetime_ex.h"
#include "ipc_skeleton.h"
#include "parameters.h"
#include "xcollie_helper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* INSTALL_TASK = "Install_Task";
constexpr const char* UNINSTALL_TASK = "Uninstall_Task";
constexpr const char* RECOVER_TASK = "Recover_Task";
constexpr const char* THREAD_POOL_NAME = "InstallerThreadPool";
constexpr unsigned int TIME_OUT_SECONDS = 60 * 25;
constexpr int8_t MAX_TASK_NUMBER = 10;
constexpr int8_t RETAIL_MODE_THREAD_NUMBER = 1;
constexpr int8_t DELAY_INTERVAL_SECONDS = 60;
static std::atomic<int32_t> g_taskCounter = 0;
}

BundleInstallerManager::BundleInstallerManager()
{
    if (system::GetBoolParameter(ServiceConstants::RETAIL_MODE_KEY, false)) {
        LOG_NOFUNC_I(BMS_TAG_INSTALLER, "RETAIL_MODE");
        threadNum_ = RETAIL_MODE_THREAD_NUMBER;
    }
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "create bundle installer manager instance");
}

BundleInstallerManager::~BundleInstallerManager()
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "destroy bundle installer manager instance");
}

void BundleInstallerManager::CreateInstallTask(
    const std::string &bundleFilePath, const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    auto installer = CreateInstaller(statusReceiver);
    if (installer == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "create installer failed");
        return;
    }
    auto traceId = HiviewDFX::HiTraceChain::GetId();
    auto task = [installer, bundleFilePath, installParam, traceId] {
        BUNDLE_MANAGER_TASK_CHAIN_ID(traceId);
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(INSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        EventReport::ReportDataPartitionUsageEvent();
        installer->Install(bundleFilePath, installParam);
        g_taskCounter--;
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task, "InstallTask path:" + bundleFilePath);
}

void BundleInstallerManager::CreateRecoverTask(
    const std::string &bundleName, const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    auto installer = CreateInstaller(statusReceiver);
    if (installer == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "create installer failed");
        return;
    }
    auto traceId = HiviewDFX::HiTraceChain::GetId();
    auto task = [installer, bundleName, installParam, traceId] {
        BUNDLE_MANAGER_TASK_CHAIN_ID(traceId);
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(RECOVER_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->Recover(bundleName, installParam);
        g_taskCounter--;
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task, "RecoverTask -n " + bundleName);
}

void BundleInstallerManager::CreateInstallTask(const std::vector<std::string> &bundleFilePaths,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    auto installer = CreateInstaller(statusReceiver);
    if (installer == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "create installer failed");
        return;
    }
    auto traceId = HiviewDFX::HiTraceChain::GetId();
    auto task = [installer, bundleFilePaths, installParam, traceId] {
        BUNDLE_MANAGER_TASK_CHAIN_ID(traceId);
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(INSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        EventReport::ReportDataPartitionUsageEvent();
        installer->Install(bundleFilePaths, installParam);
        g_taskCounter--;
        XCollieHelper::CancelTimer(timerId);
    };
    std::string paths;
    for (const auto &bundleFilePath : bundleFilePaths) {
        paths.append(bundleFilePath).append(" ");
    }
    AddTask(task, "InstallTask path:" + paths);
}

void BundleInstallerManager::CreateInstallByBundleNameTask(const std::string &bundleName,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    auto installer = CreateInstaller(statusReceiver);
    if (installer == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "create installer failed");
        return;
    }
    auto traceId = HiviewDFX::HiTraceChain::GetId();
    auto task = [installer, bundleName, installParam, traceId] {
        BUNDLE_MANAGER_TASK_CHAIN_ID(traceId);
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(INSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->InstallByBundleName(bundleName, installParam);
        g_taskCounter--;
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task, "InstallTask -n " + bundleName);
}

void BundleInstallerManager::CreateUninstallTask(
    const std::string &bundleName, const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    auto installer = CreateInstaller(statusReceiver);
    if (installer == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "create installer failed");
        return;
    }
    auto traceId = HiviewDFX::HiTraceChain::GetId();
    auto task = [installer, bundleName, installParam, traceId] {
        BUNDLE_MANAGER_TASK_CHAIN_ID(traceId);
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(UNINSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->Uninstall(bundleName, installParam);
        g_taskCounter--;
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task, "UninstallTask -n " + bundleName);
}

void BundleInstallerManager::CreateUninstallTask(const std::string &bundleName, const std::string &modulePackage,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    auto installer = CreateInstaller(statusReceiver);
    if (installer == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "create installer failed");
        return;
    }
    auto traceId = HiviewDFX::HiTraceChain::GetId();
    auto task = [installer, bundleName, modulePackage, installParam, traceId] {
        BUNDLE_MANAGER_TASK_CHAIN_ID(traceId);
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(UNINSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->Uninstall(bundleName, modulePackage, installParam);
        g_taskCounter--;
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task, "UninstallTask -n " + bundleName);
}

void BundleInstallerManager::CreateUninstallTask(const UninstallParam &uninstallParam,
    const sptr<IStatusReceiver> &statusReceive)
{
    auto installer = CreateInstaller(statusReceive);
    if (installer == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "create installer failed");
        return;
    }
    auto traceId = HiviewDFX::HiTraceChain::GetId();
    auto task = [installer, uninstallParam, traceId] {
        BUNDLE_MANAGER_TASK_CHAIN_ID(traceId);
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(UNINSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->Uninstall(uninstallParam);
        g_taskCounter--;
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task, "UninstallTask -n " + uninstallParam.bundleName);
}

void BundleInstallerManager::CreateUninstallAndRecoverTask(const std::string &bundleName,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    auto installer = CreateInstaller(statusReceiver);
    if (installer == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "create installer failed");
        return;
    }
    auto traceId = HiviewDFX::HiTraceChain::GetId();
    auto task = [installer, bundleName, installParam, traceId] {
        BUNDLE_MANAGER_TASK_CHAIN_ID(traceId);
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(UNINSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->UninstallAndRecover(bundleName, installParam);
        g_taskCounter--;
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task, "UninstallAndRecover -n " + bundleName);
}

std::shared_ptr<BundleInstaller> BundleInstallerManager::CreateInstaller(const sptr<IStatusReceiver> &statusReceiver)
{
    int64_t installerId = GetMicroTickCount();
    auto installer = std::make_shared<BundleInstaller>(installerId, statusReceiver);
    installer->SetCallingUid(IPCSkeleton::GetCallingUid());
    installer->SetCallingTokenId(IPCSkeleton::GetCallingTokenID());
    return installer;
}

void BundleInstallerManager::AddTask(const ThreadPoolTask &task, const std::string &taskName)
{
    std::lock_guard<std::mutex> guard(mutex_);
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "hold mutex");
    if (threadPool_ == nullptr) {
        LOG_NOFUNC_I(BMS_TAG_INSTALLER, "begin to start InstallerThreadPool");
        threadPool_ = std::make_shared<ThreadPool>(THREAD_POOL_NAME);
        threadPool_->Start(threadNum_);
        threadPool_->SetMaxTaskNum(MAX_TASK_NUMBER);
        auto delayCloseTask = std::bind(&BundleInstallerManager::DelayStopThreadPool, shared_from_this());
        std::thread t(delayCloseTask);
        t.detach();
    }
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "add task taskName:%{public}s", taskName.c_str());
    g_taskCounter++;
    threadPool_->AddTask(task);
}

void BundleInstallerManager::DelayStopThreadPool()
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "DelayStopThreadPool begin");
    BundleMemoryGuard memoryGuard;

    do {
        LOG_NOFUNC_I(BMS_TAG_INSTALLER, "sleep for 60s runningTask %{public}d", g_taskCounter.load());
        std::this_thread::sleep_for(std::chrono::seconds(DELAY_INTERVAL_SECONDS));
    } while (threadPool_ != nullptr && (threadPool_->GetCurTaskNum() != 0
        || g_taskCounter.load() != 0));

    std::lock_guard<std::mutex> guard(mutex_);
    if (threadPool_ == nullptr) {
        LOG_NOFUNC_I(BMS_TAG_INSTALLER, "InstallerThreadPool is null, no need to stop");
        return;
    }
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "begin to stop InstallerThreadPool");
    threadPool_->Stop();
    threadPool_ = nullptr;
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "DelayStopThreadPool end");
}

size_t BundleInstallerManager::GetCurTaskNum()
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (threadPool_ == nullptr) {
        return 0;
    }

    return threadPool_->GetCurTaskNum();
}
}  // namespace AppExecFwk
}  // namespace OHOS