/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "driver_install_ext.h"

#include <dlfcn.h>

#include "app_log_wrapper.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {

namespace {
constexpr const char *REDIRECT_PATH_FUNCTION_NAME = "RedirectDriverInstallExtPath";
constexpr const char *GET_DRIVER_EXCUTE_FUNCTION_NAME = "GetDriverExecuteExtPaths";
constexpr const char *LIB64_DRIVER_INSTALL_EXT_SO_PATH = "system/lib64/libdriver_install_ext.z.so";
constexpr const char *PARAM_EXT_SPACE = "persist.space_mgr_service.enterprise_space_init";
const std::string EXT_SPACE_ENABLE = "2";
}  // namespace

DriverInstallExtHandler::DriverInstallExtHandler()
{
    OpenDriverInstallHandler();
}

DriverInstallExtHandler::~DriverInstallExtHandler()
{
    ClearSymbols();
}

void DriverInstallExtHandler::RedirectDriverInstallExtPath(std::string &path)
{
    if (redirectDriverInstallExtPath_ != nullptr) {
        redirectDriverInstallExtPath_(path);
        return;
    }
    APP_LOGW("redirectDriverInstallExtPath_ func is nullptr");
}

void DriverInstallExtHandler::GetDriverExecuteExtPaths(std::vector<std::string> &paths)
{
    if (getDriverExecuteExtPathsFunc_ != nullptr) {
        getDriverExecuteExtPathsFunc_(paths);
        return;
    }
    APP_LOGD("getDriverExecuteExtPathsFunc_ func is nullptr");
}

bool DriverInstallExtHandler::IsExtSpaceEnable()
{
    std::string extSpaceEnable = OHOS::system::GetParameter(PARAM_EXT_SPACE, "");
    if (extSpaceEnable == EXT_SPACE_ENABLE) {
        APP_LOGI("IsExtSpaceEnable return true.");
        return true;
    }
    APP_LOGW("IsExtSpaceEnable return false.");
    return false;
}

bool DriverInstallExtHandler::OpenDriverInstallHandler()
{
    if (!IsExtSpaceEnable()) {
        return false;
    }
    APP_LOGD("OpenDriverInstallHandler start");
    driverInstallerHandle_ = dlopen(LIB64_DRIVER_INSTALL_EXT_SO_PATH, RTLD_NOW);
    if (driverInstallerHandle_ == nullptr) {
        APP_LOGE("open driverInstall lib failed %{public}s", dlerror());
        return false;
    }
    redirectDriverInstallExtPath_ =
        reinterpret_cast<RedirectPathFunc>(dlsym(driverInstallerHandle_, REDIRECT_PATH_FUNCTION_NAME));
    if (redirectDriverInstallExtPath_ == nullptr) {
        APP_LOGE("dlsym redirectDriverInstallExtPath_ failed %{public}s", dlerror());
        ClearSymbols();
        return false;
    }
    getDriverExecuteExtPathsFunc_ =
        reinterpret_cast<GetDriverExtPathsFunc>(dlsym(driverInstallerHandle_, GET_DRIVER_EXCUTE_FUNCTION_NAME));
    if (getDriverExecuteExtPathsFunc_ == nullptr) {
        APP_LOGE("dlsym getDriverExecuteExtPathsFunc_ failed %{public}s", dlerror());
        ClearSymbols();
        return false;
    }
    return true;
}

void DriverInstallExtHandler::ClearSymbols()
{
    redirectDriverInstallExtPath_ = nullptr;
    getDriverExecuteExtPathsFunc_ = nullptr;
    if (driverInstallerHandle_) {
        dlclose(driverInstallerHandle_);
    }
    driverInstallerHandle_ = nullptr;
}

}  // AppExecFwk
}  // OHOS