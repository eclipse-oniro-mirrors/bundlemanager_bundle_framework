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

#ifndef FOUNDATION_BUNDLEMGR_SERVICES_KITS_INCLUDE_INSTALLER_HELPER_H
#define FOUNDATION_BUNDLEMGR_SERVICES_KITS_INCLUDE_INSTALLER_HELPER_H

#include "base_cb_info.h"
#include "bundle_errors.h"
#include "clone_param.h"
#include "install_param.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "plugin/install_plugin_param.h"

namespace OHOS {
namespace AppExecFwk {
struct InstallResult {
    int32_t resultCode = 0;
    std::string resultMsg;
};

enum class InstallOption {
    INSTALL = 0,
    RECOVER = 1,
    UNINSTALL = 2,
    UPDATE_BUNDLE_FOR_SELF = 3,
    UNKNOWN = 4,
    UNINSTALL_AND_RECOVER = 5,
};

class InstallerHelper {
public:
    static void CreateErrCodeMap(std::unordered_map<int32_t, int32_t>& errCodeMap);
    static void ConvertInstallResult(InstallResult& installResult);
    static void CreateProxyErrCode(std::unordered_map<int32_t, int32_t>& errCodeMap);
    static ErrCode InnerCreateAppClone(std::string& bundleName, int32_t userId, int32_t& appIndex);
    static ErrCode InnerDestroyAppClone(
        std::string& bundleName, int32_t userId, int32_t appIndex, DestroyAppCloneParam& destroyAppCloneParam);
    static ErrCode InnerAddExtResource(const std::string& bundleName, const std::vector<std::string>& filePaths);
    static ErrCode InnerRemoveExtResource(const std::string& bundleName, const std::vector<std::string>& moduleNames);
    static ErrCode InnerInstallPreexistingApp(std::string& bundleName, int32_t userId);
    static ErrCode InnerInstallPlugin(const std::string& hostBundleName,
        const std::vector<std::string>& pluginFilePaths, const InstallPluginParam& installPluginParam);
    static ErrCode InnerUninstallPlugin(const std::string& hostBundleName, const std::string& pluginBundleName,
        const InstallPluginParam& installPluginParam);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLEMGR_SERVICES_KITS_INCLUDE_INSTALLER_HELPER_H