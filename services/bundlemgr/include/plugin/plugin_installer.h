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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PLUGIN_INSTALLER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PLUGIN_INSTALLER_H

#include <string>
#include <unordered_map>
#include <vector>

#include "bundle_install_checker.h"
#include "bundle_common_event_mgr.h"
#include "event_report.h"
#include "inner_bundle_info.h"
#include "install_param.h"
#include "install_plugin_param.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class PluginInstaller final {
public:
    PluginInstaller();
    ~PluginInstaller();
    /**
     * @brief Install or update plugin application.
     * @param hostBundleName Indicates the bundle name of the host application.
     * @param pluginFilePaths Indicates the paths for storing the HSP of the plugin to install or update.
     * @param installPluginParam Indicates the install parameters.
     * @return Returns ERR_OK if the plugin application is installed successfully; returns errcode otherwise.
     */
    ErrCode InstallPlugin(const std::string &hostBundleName, const std::vector<std::string> &pluginFilePaths,
        const InstallPluginParam &installPluginParam);
    
    /**
     * @brief uninstall plugin application.
     * @param hostBundleName Indicates the bundle name of the host application.
     * @param pluginBundleName Indicates the plugin bundle name to uninstall.
     * @param installPluginParam Indicates the uninstall parameters.
     * @return Returns ERR_OK if the plugin application is uninstalled successfully; returns errcode otherwise.
     */
    ErrCode UninstallPlugin(const std::string &hostBundleName, const std::string &pluginBundleName,
        const InstallPluginParam &installPluginParam);
    
private:
    bool isPluginExist_ = false;
    bool isEnterpriseBundle_ = false;
    bool isCompressNativeLibs_ = true;
    int32_t userId_ = Constants::INVALID_USERID;
    // the real path or the parent directory of hsp files to be installed.
    std::string bundleName_;
    std::string bundleNameWithTime_;
    std::string signatureFileDir_;
    std::string nativeLibraryPath_;
    std::string appIdentifier_;
    std::string compileSdkType_;
    std::string cpuAbi_;
    std::string soPath_;
    std::unique_ptr<BundleInstallChecker> bundleInstallChecker_ = nullptr;
    std::vector<std::string> toDeleteTempHspPath_;
    std::vector<std::string> pluginIds_;
    // the key is the real path of each hsp file
    std::unordered_map<std::string, InnerBundleInfo> parsedBundles_;
    PluginBundleInfo oldPluginInfo_;
    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;

    DISALLOW_COPY_AND_MOVE(PluginInstaller);

    ErrCode ParseFiles(const std::vector<std::string> &pluginFilePaths, const InstallPluginParam &installPluginParam);
    ErrCode DeliveryProfileToCodeSign(std::vector<Security::Verify::HapVerifyResult> &hapVerifyResults) const;
    ErrCode CheckPluginId(const std::string &hostBundleName);
    ErrCode ProcessPluginInstall(const InnerBundleInfo &hostBundleInfo);
    ErrCode CreatePluginDir(const std::string &hostBundleName, std::string &pluginDir);
    ErrCode ExtractPluginBundles(const std::string &bundlePath, InnerBundleInfo &newInfo, const std::string &pluginDir);
    ErrCode CheckPluginAppLabelInfo();
    void MergePluginBundleInfo(InnerBundleInfo &pluginBundleInfo);
    ErrCode SavePluginInfoToStorage(const InnerBundleInfo &pluginInfo, const InnerBundleInfo &hostBundleInfo);
    void PluginRollBack(const std::string &hostBundleName);
    ErrCode RemovePluginDir(const InnerBundleInfo &hostBundleInfo);
    ErrCode CheckSupportPluginPermission(const std::string &hostBundleName);
    ErrCode SaveHspToInstallDir(const std::string &bundlePath, const std::string &pluginBundleDir,
        const std::string &moduleName, InnerBundleInfo &newInfo);
    void RemoveEmptyDirs(const std::string &pluginDir) const;
    void RemoveDir(const std::string &dir) const;
    bool CheckAppIdentifier() const;
    bool CheckVersionCodeForUpdate() const;
    ErrCode ProcessPluginUninstall(const InnerBundleInfo &hostBundleInfo);

    ErrCode MkdirIfNotExist(const std::string &dir);
    ErrCode CopyHspToSecurityDir(std::vector<std::string> &bundlePaths, const InstallPluginParam &installPluginParam);
    ErrCode ObtainHspFileAndSignatureFilePath(const std::vector<std::string> &inBundlePaths,
        std::vector<std::string> &bundlePaths, std::string &signatureFilePath);
    ErrCode ProcessNativeLibrary(const std::string &bundlePath,
        const std::string &moduleDir, const std::string &moduleName, const std::string &pluginBundleDir,
        InnerBundleInfo &newInfo);
    ErrCode VerifyCodeSignatureForNativeFiles(const std::string &bundlePath, const std::string &cpuAbi,
        const std::string &targetSoPath, const std::string &signatureFileDir, bool isPreInstalledBundle) const;
    ErrCode VerifyCodeSignatureForHsp(const std::string &hspPath, const std::string &appIdentifier,
        bool isEnterpriseBundle, bool isCompileSdkOpenHarmony) const;
    bool ParsePluginId(const std::string &appServiceCapabilities, std::vector<std::string> &pluginIds);
    void RemoveOldInstallDir();
    void UninstallRollBack(const std::string &hostBundleName);
    bool InitDataMgr();
    ErrCode ParseHapPaths(const InstallPluginParam &installPluginParam,
        const std::vector<std::string> &inBundlePaths, std::vector<std::string> &parsedPaths);
    void NotifyPluginEvents(const NotifyType &type, int32_t uid);
    std::string GetModuleNames();

#define CHECK_RESULT(errcode, errmsg)                                              \
    do {                                                                           \
        if ((errcode) != ERR_OK) {                                                   \
            APP_LOGE(errmsg, errcode);                                             \
            return errcode;                                                        \
        }                                                                          \
    } while (0)
};
} // AppExecFwk
} // OHOS

#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PLUGIN_INSTALLER_H