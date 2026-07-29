/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
*     http://www.apache.org/licenses/LICENSE-2.0
 *
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR conditions of any kind, either express or implied.
 * See the License for the specific language governing permissions and
* limitations under the License.
 */

#include "installd/binary_security_wrapper.h"

#include <dlfcn.h>

#include "app_log_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

namespace {
constexpr uint32_t UNLOAD_DELAY_MS = 3 * 60 * 1000; // 3 minutes
constexpr const char* UNLOAD_TASK_NAME = "BinarySecurityWrapperUnloadTask";
constexpr const char* LIB_BINARY_SECURITY_SDK = "/system/lib64/libsps_binary_security_sdk.z.so";
constexpr const char* PROCESS_HAP_BIN_INSTALL_FUNC = "ProcessHapBinInstall";
constexpr const char* REQUEST_INDEPENDENT_BINARY_SWITCH_ASYNC_FUNC = "RequestIndependentBinarySwitchAsync";
constexpr const char* CHECK_HSP_PLUGIN_CERT_VALIDITY_FUNC = "CheckHspPluginCertValidity";
} // namespace

BinarySecurityWrapper& BinarySecurityWrapper::GetInstance()
{
    static BinarySecurityWrapper instance;
    return instance;
}

BinarySecurityWrapper::BinarySecurityWrapper()
{
    delayedTaskMgr_ = std::make_shared<SingleDelayedTaskMgr>(UNLOAD_TASK_NAME, UNLOAD_DELAY_MS);
}

bool BinarySecurityWrapper::LoadLibraryNoLock()
{
    if (handle_ != nullptr) {
        return true;
    }

    handle_ = dlopen(LIB_BINARY_SECURITY_SDK, RTLD_NOW | RTLD_LOCAL);
    if (handle_ == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "dlopen libsps_binary_security_sdk.z.so failed: %{public}s", dlerror());
        return false;
    }

    LOG_D(BMS_TAG_INSTALLD, "LoadLibrary libsps_binary_security_sdk.z.so success");
    return true;
}

bool BinarySecurityWrapper::HasNoResolvedSymbolsNoLock() const
{
    return processHapBinInstallFunc_ == nullptr &&
        requestIndependentBinarySwitchAsyncFunc_ == nullptr &&
        checkHspPluginCertValidityFunc_ == nullptr;
}

bool BinarySecurityWrapper::ResolveSymbolNoLock(const char* symbolName, void **func)
{
    if (func == nullptr || symbolName == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "ResolveSymbolNoLock invalid params");
        return false;
    }
    if (*func != nullptr) {
        return true;
    }
    if (handle_ == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "ResolveSymbolNoLock handle is null");
        return false;
    }

    void *symbol = dlsym(handle_, symbolName);
    if (symbol == nullptr) {
        LOG_E(BMS_TAG_INSTALLD, "dlsym %{public}s failed, error: %{public}s", symbolName, dlerror());
        if (HasNoResolvedSymbolsNoLock()) {
            UnloadLibraryNoLock();
            LOG_W(BMS_TAG_INSTALLD, "symbol resolve failed during init, library unloaded");
        } else {
            LOG_W(BMS_TAG_INSTALLD, "symbol resolve failed, keep current loaded symbols");
        }
        return false;
    }

    *func = symbol;
    return true;
}

bool BinarySecurityWrapper::ResolveProcessHapBinInstallNoLock()
{
    return ResolveSymbolNoLock(PROCESS_HAP_BIN_INSTALL_FUNC,
        reinterpret_cast<void **>(&processHapBinInstallFunc_));
}

bool BinarySecurityWrapper::ResolveRequestIndependentBinarySwitchAsyncNoLock()
{
    return ResolveSymbolNoLock(REQUEST_INDEPENDENT_BINARY_SWITCH_ASYNC_FUNC,
        reinterpret_cast<void **>(&requestIndependentBinarySwitchAsyncFunc_));
}

bool BinarySecurityWrapper::ResolveCheckHspPluginCertValidityNoLock()
{
    return ResolveSymbolNoLock(CHECK_HSP_PLUGIN_CERT_VALIDITY_FUNC,
        reinterpret_cast<void **>(&checkHspPluginCertValidityFunc_));
}

void BinarySecurityWrapper::UnloadLibrary()
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    UnloadLibraryNoLock();
}

void BinarySecurityWrapper::UnloadLibraryNoLock()
{
    if (handle_ == nullptr) {
        return;
    }
    dlclose(handle_);
    handle_ = nullptr;
    processHapBinInstallFunc_ = nullptr;
    requestIndependentBinarySwitchAsyncFunc_ = nullptr;
    checkHspPluginCertValidityFunc_ = nullptr;
    LOG_I(BMS_TAG_INSTALLD, "Unloaded libsps_binary_security_sdk.z.so");
}

void BinarySecurityWrapper::ScheduleUnload()
{
    auto unloadTask = [this]() {
        UnloadLibrary();
    };
    delayedTaskMgr_->ScheduleDelayedTask(unloadTask);
}

// These wrappers call function pointers resolved via dlsym at runtime, so CFI
// cannot validate the indirect call target here.
ErrCode __attribute__((no_sanitize("cfi"))) BinarySecurityWrapper::ProcessHapBinInstall(
    const std::string &bundleName,
    const std::string &appIdentifier, int32_t userId,
    const std::vector<BinFileInfo> &binFileInfos)
{
    // Fast path: library already loaded, use shared read lock
    {
        std::shared_lock<std::shared_mutex> readLock(mutex_);
        if (handle_ != nullptr && processHapBinInstallFunc_ != nullptr) {
            ErrCode result = processHapBinInstallFunc_(bundleName, appIdentifier, userId, binFileInfos);
            if (result != ERR_OK) {
                LOG_E(BMS_TAG_INSTALLD, "ProcessHapBinInstall failed %{public}d", result);
            }
            ScheduleUnload();
            return result;
        }
    }

    // Slow path: need to load library, use exclusive write lock
    {
        std::unique_lock<std::shared_mutex> writeLock(mutex_);
        if (!LoadLibraryNoLock() || !ResolveProcessHapBinInstallNoLock()) {
            LOG_E(BMS_TAG_INSTALLD, "LoadLibrary failed");
            return ERR_APPEXECFWK_INSTALL_FAILED_VERIFY_BIN_PERMISSION;
        }
        ErrCode result = processHapBinInstallFunc_(bundleName, appIdentifier, userId, binFileInfos);
        if (result != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLD, "ProcessHapBinInstall failed %{public}d", result);
        }
        ScheduleUnload();
        return result;
    }
}

// This wrapper calls a dlsym-resolved function pointer, so CFI is disabled for
// the runtime-resolved indirect call.
ErrCode __attribute__((no_sanitize("cfi"))) BinarySecurityWrapper::RequestIndependentBinarySwitchAsync(
    int32_t &outSwitchStatus)
{
    {
        std::shared_lock<std::shared_mutex> readLock(mutex_);
        if (handle_ != nullptr && requestIndependentBinarySwitchAsyncFunc_ != nullptr) {
            ErrCode result = requestIndependentBinarySwitchAsyncFunc_(outSwitchStatus);
            if (result != ERR_OK) {
                LOG_E(BMS_TAG_INSTALLD, "RequestIndependentBinarySwitchAsync failed %{public}d", result);
            }
            ScheduleUnload();
            return result;
        }
    }

    {
        std::unique_lock<std::shared_mutex> writeLock(mutex_);
        if (!LoadLibraryNoLock()) {
            LOG_E(BMS_TAG_INSTALLD, "LoadLibrary failed for RequestIndependentBinarySwitchAsync");
            return ERR_APPEXECFWK_INSTALL_FAILED_VERIFY_BIN_PERMISSION;
        }
        if (!ResolveRequestIndependentBinarySwitchAsyncNoLock() ||
            requestIndependentBinarySwitchAsyncFunc_ == nullptr) {
            LOG_E(BMS_TAG_INSTALLD, "RequestIndependentBinarySwitchAsync symbol not ready");
            return ERR_APPEXECFWK_INSTALL_FAILED_VERIFY_BIN_PERMISSION;
        }
        ErrCode result = requestIndependentBinarySwitchAsyncFunc_(outSwitchStatus);
        if (result != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLD, "RequestIndependentBinarySwitchAsync failed %{public}d", result);
        }
        ScheduleUnload();
        return result;
    }
}

// This wrapper calls a dlsym-resolved function pointer, so CFI is disabled for
// the runtime-resolved indirect call.
ErrCode __attribute__((no_sanitize("cfi"))) BinarySecurityWrapper::CheckHspPluginCertValidity(
    Security::Verify::HspPlugin &hspPlugin)
{
    {
        std::shared_lock<std::shared_mutex> readLock(mutex_);
        if (handle_ != nullptr && checkHspPluginCertValidityFunc_ != nullptr) {
            ErrCode result = checkHspPluginCertValidityFunc_(hspPlugin);
            if (result != ERR_OK) {
                LOG_E(BMS_TAG_INSTALLD, "CheckHspPluginCertValidity failed %{public}d", result);
            }
            ScheduleUnload();
            return result;
        }
    }

    {
        std::unique_lock<std::shared_mutex> writeLock(mutex_);
        if (!LoadLibraryNoLock()) {
            LOG_E(BMS_TAG_INSTALLD, "LoadLibrary failed for CheckHspPluginCertValidity");
            return ERR_APPEXECFWK_INSTALL_FAILED_VERIFY_BIN_PERMISSION;
        }
        if (!ResolveCheckHspPluginCertValidityNoLock() || checkHspPluginCertValidityFunc_ == nullptr) {
            LOG_E(BMS_TAG_INSTALLD, "CheckHspPluginCertValidity symbol not ready");
            return ERR_APPEXECFWK_INSTALL_FAILED_VERIFY_BIN_PERMISSION;
        }
        ErrCode result = checkHspPluginCertValidityFunc_(hspPlugin);
        if (result != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLD, "CheckHspPluginCertValidity failed %{public}d", result);
        }
        ScheduleUnload();
        return result;
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
