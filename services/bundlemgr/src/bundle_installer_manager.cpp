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
const unsigned int TIME_OUT_SECONDS = 60 * 5;
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
        int timerId = XCollieHelper::SetTimer(INSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->Install(bundleFilePath, installParam);
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task);
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
        int timerId = XCollieHelper::SetTimer(RECOVER_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->Recover(bundleName, installParam);
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task);
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
        int timerId = XCollieHelper::SetTimer(INSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->Install(bundleFilePaths, installParam);
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task);
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
        int timerId = XCollieHelper::SetTimer(INSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->InstallByBundleName(bundleName, installParam);
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task);
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
        int timerId = XCollieHelper::SetTimer(UNINSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->Uninstall(bundleName, installParam);
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task);
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
        int timerId = XCollieHelper::SetTimer(UNINSTALL_TASK, TIME_OUT_SECONDS, nullptr, nullptr);
        installer->Uninstall(bundleName, modulePackage, installParam);
        XCollieHelper::CancelTimer(timerId);
    };
    AddTask(task);
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
    AddTask(task);
}

std::shared_ptr<BundleInstaller> BundleInstallerManager::CreateInstaller(const sptr<IStatusReceiver> &statusReceiver)
{
    int64_t installerId = GetMicroTickCount();
    auto installer = std::make_shared<BundleInstaller>(installerId, statusReceiver);
    installer->SetCallingUid(IPCSkeleton::GetCallingUid());
    return installer;
}

void BundleInstallerManager::AddTask(const ThreadPoolTask &task)
{
    auto bundleMgrService = DelayedSingleton<BundleMgrService>::GetInstance();
    if (bundleMgrService == nullptr) {
        APP_LOGE("bundleMgrService is nullptr");
        return;
    }

    ThreadPool &installersPool = bundleMgrService->GetThreadPool();
    installersPool.AddTask(task);
}
}  // namespace AppExecFwk
}  // namespace OHOS