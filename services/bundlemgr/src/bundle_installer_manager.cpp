/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <cinttypes>

#include "appexecfwk_errors.h"
#include "app_log_wrapper.h"
#include "bundle_memory_guard.h"
#include "bundle_mgr_service.h"
#include "datetime_ex.h"
#include "ipc_skeleton.h"
#include "xcollie_helper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string INSTALL_TASK = "Install_Task";
const std::string UNINSTALL_TASK = "Uninstall_Task";
const std::string RECOVER_TASK = "Recover_Task";
const std::string THREAD_POOL_NAME = "InstallerThreadPool";
const unsigned int TIME_OUT_SECONDS = 60 * 5;
constexpr int32_t MAX_TASK_NUMBER = 10;
constexpr int32_t DELAY_INTERVAL_SECONDS = 60;
}

BundleInstallerManager::BundleInstallerManager()
{
    APP_LOGI("create bundle installer manager instance");
}

BundleInstallerManager::~BundleInstallerManager()
{
    APP_LOGI("destroy bundle installer manager instance");
}

void BundleInstallerManager::CreateInstallTask(
    const std::string &bundleFilePath, const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    auto installer = CreateInstaller(statusReceiver);
    if (installer == nullptr) {
        APP_LOGE("create installer failed");
        return;
    }
    auto task = [installer, bundleFilePath, installParam] {
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(INSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->Install(bundleFilePath, installParam);
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task, "InstallTask : bundleFilePath : " + bundleFilePath);
}

void BundleInstallerManager::CreateRecoverTask(
    const std::string &bundleName, const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    auto installer = CreateInstaller(statusReceiver);
    if (installer == nullptr) {
        APP_LOGE("create installer failed");
        return;
    }
    auto task = [installer, bundleName, installParam] {
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(RECOVER_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->Recover(bundleName, installParam);
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task, "RecoverTask : bundleName : " + bundleName);
}

void BundleInstallerManager::CreateInstallTask(const std::vector<std::string> &bundleFilePaths,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    auto installer = CreateInstaller(statusReceiver);
    if (installer == nullptr) {
        APP_LOGE("create installer failed");
        return;
    }
    auto task = [installer, bundleFilePaths, installParam] {
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(INSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->Install(bundleFilePaths, installParam);
        XCollieHelper::CancelTimer(timerId);
    };
    std::string paths;
    for (const auto &bundleFilePath : bundleFilePaths) {
        paths.append(bundleFilePath).append(" ");
    }
    AddTask(task, "InstallTask : bundleFilePaths : " + paths);
}

void BundleInstallerManager::CreateInstallByBundleNameTask(const std::string &bundleName,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    auto installer = CreateInstaller(statusReceiver);
    if (installer == nullptr) {
        APP_LOGE("create installer failed");
        return;
    }

    auto task = [installer, bundleName, installParam] {
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(INSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->InstallByBundleName(bundleName, installParam);
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task, "InstallTask : bundleName : " + bundleName);
}

void BundleInstallerManager::CreateUninstallTask(
    const std::string &bundleName, const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    auto installer = CreateInstaller(statusReceiver);
    if (installer == nullptr) {
        APP_LOGE("create installer failed");
        return;
    }
    auto task = [installer, bundleName, installParam] {
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(UNINSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->Uninstall(bundleName, installParam);
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task, "UninstallTask : bundleName : " + bundleName);
}

void BundleInstallerManager::CreateUninstallTask(const std::string &bundleName, const std::string &modulePackage,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    auto installer = CreateInstaller(statusReceiver);
    if (installer == nullptr) {
        APP_LOGE("create installer failed");
        return;
    }
    auto task = [installer, bundleName, modulePackage, installParam] {
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(UNINSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->Uninstall(bundleName, modulePackage, installParam);
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task, "UninstallTask : bundleName : " + bundleName);
}

void BundleInstallerManager::CreateUninstallTask(const UninstallParam &uninstallParam,
    const sptr<IStatusReceiver> &statusReceive)
{
    auto installer = CreateInstaller(statusReceive);
    if (installer == nullptr) {
        APP_LOGE("create installer failed");
        return;
    }
    auto task = [installer, uninstallParam] {
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(UNINSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->Uninstall(uninstallParam);
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task, "UninstallTask : bundleName : " + uninstallParam.bundleName);
}

void BundleInstallerManager::CreateUninstallAndRecoverTask(const std::string &bundleName,
    const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver)
{
    auto installer = CreateInstaller(statusReceiver);
    if (installer == nullptr) {
        APP_LOGE("create installer failed");
        return;
    }
    auto task = [installer, bundleName, installParam] {
        BundleMemoryGuard memoryGuard;
        int32_t timerId = XCollieHelper::SetTimer(UNINSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->UninstallAndRecover(bundleName, installParam);
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task, "UninstallAndRecover: bundleName : " + bundleName);
}

std::shared_ptr<BundleInstaller> BundleInstallerManager::CreateInstaller(const sptr<IStatusReceiver> &statusReceiver)
{
    int64_t installerId = GetMicroTickCount();
    auto installer = std::make_shared<BundleInstaller>(installerId, statusReceiver);
    installer->SetCallingUid(IPCSkeleton::GetCallingUid());
    return installer;
}

void BundleInstallerManager::AddTask(const ThreadPoolTask &task, const std::string &taskName)
{
    std::lock_guard<std::mutex> guard(mutex_);
    APP_LOGI("hold mutex");
    if (threadPool_ == nullptr) {
        APP_LOGI("begin to start InstallerThreadPool");
        threadPool_ = std::make_shared<ThreadPool>(THREAD_POOL_NAME);
        threadPool_->Start(THREAD_NUMBER);
        threadPool_->SetMaxTaskNum(MAX_TASK_NUMBER);
        auto delayCloseTask = std::bind(&BundleInstallerManager::DelayStopThreadPool, shared_from_this());
        std::thread t(delayCloseTask);
        t.detach();
    }
    APP_LOGI("add task, taskName : %{public}s", taskName.c_str());
    threadPool_->AddTask(task);
}

void BundleInstallerManager::DelayStopThreadPool()
{
    APP_LOGI("DelayStopThreadPool begin");
    BundleMemoryGuard memoryGuard;

    do {
        APP_LOGI("sleep for 60s");
        std::this_thread::sleep_for(std::chrono::seconds(DELAY_INTERVAL_SECONDS));
    } while (threadPool_ != nullptr && threadPool_->GetCurTaskNum() != 0);

    std::lock_guard<std::mutex> guard(mutex_);
    if (threadPool_ == nullptr) {
        APP_LOGI("InstallerThreadPool is null, no need to stop");
        return;
    }
    APP_LOGI("begin to stop InstallerThreadPool");
    threadPool_->Stop();
    threadPool_ = nullptr;
    APP_LOGI("DelayStopThreadPool end");
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