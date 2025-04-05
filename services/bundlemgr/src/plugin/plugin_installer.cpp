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

#include "plugin_installer.h"

#include <fcntl.h>

#include "app_log_tag_wrapper.h"
#include "app_provision_info_manager.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_util.h"
#include "hitrace_meter.h"
#include "installd_client.h"
#include "ipc_skeleton.h"
#include "json_util.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::Security;
namespace {
constexpr const char* COMPILE_SDK_TYPE_OPEN_HARMONY = "OpenHarmony";
constexpr const char* DEBUG_APP_IDENTIFIER = "DEBUG_LIB_ID";
constexpr const char* PLUGINS = "+plugins";
constexpr const char* LIBS_TMP = "libs_tmp";
constexpr const char* PERMISSION_KEY = "ohos.permission.kernel.SUPPORT_PLUGIN";
constexpr const char* PLUGIN_ID = "pluginDistributionIDs";
constexpr const char* PLUGIN_ID_SEPARATOR = "|";
constexpr const char* REMOVE_TMP_SUFFIX = "_removed";
constexpr const char* APP_INSTALL_SANDBOX_PATH = "/data/bms_app_install/";
}

PluginInstaller::PluginInstaller()
    : bundleInstallChecker_(std::make_unique<BundleInstallChecker>())
{
    APP_LOGD("create PluginInstaller instance");
}

PluginInstaller::~PluginInstaller()
{
    APP_LOGD("destroy PluginInstaller instance");
    BundleUtil::DeleteTempDirs(toDeleteTempHspPath_);
    toDeleteTempHspPath_.clear();
}

ErrCode PluginInstaller::InstallPlugin(const std::string &hostBundleName,
    const std::vector<std::string> &pluginFilePaths, const InstallPluginParam &installPluginParam)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "begin to install plugin for %{public}s", hostBundleName.c_str());

    if (!InitDataMgr()) {
        return ERR_APPEXECFWK_NULL_PTR;
    }
    // check userId
    if (installPluginParam.userId < Constants::DEFAULT_USERID) {
        APP_LOGE("userId(%{public}d) invalid", installPluginParam.userId);
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }
    if (!dataMgr_->HasUserId(installPluginParam.userId)) {
        APP_LOGE("user %{public}d not exist", installPluginParam.userId);
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }
    auto &mtx = dataMgr_->GetBundleMutex(hostBundleName);
    std::lock_guard lock {mtx};
    // check host application exist in userId
    InnerBundleInfo hostBundleInfo;
    if (!dataMgr_->FetchInnerBundleInfo(hostBundleName, hostBundleInfo)) {
        APP_LOGE("hostBundleName:%{public}s get bundle info failed", hostBundleName.c_str());
        return ERR_APPEXECFWK_HOST_APPLICATION_NOT_FOUND;
    }
    if (!hostBundleInfo.HasInnerBundleUserInfo(installPluginParam.userId)) {
        APP_LOGE("HostBundleName: %{public}s not installed in user %{public}d",
            hostBundleName.c_str(), installPluginParam.userId);
        return ERR_APPEXECFWK_HOST_APPLICATION_NOT_FOUND;
    }
    userId_ = installPluginParam.userId;
    // check host application permission
    ErrCode result = ERR_OK;
    result = CheckSupportPluginPermission(hostBundleInfo.GetBundleName());
    CHECK_RESULT(result, "check host application permission failed %{public}d");
    // parse hsp file
    result = ParseFiles(pluginFilePaths, installPluginParam);
    CHECK_RESULT(result, "parse file failed %{public}d");
    if (bundleName_ == hostBundleName) {
        APP_LOGE("plugin name:%{public}s same as host bundle name", bundleName_.c_str());
        return ERR_APPEXECFWK_PLUGIN_INSTALL_SAME_BUNDLE_NAME;
    }
    bundleNameWithTime_ = bundleName_ + "." + std::to_string(BundleUtil::GetCurrentTimeNs());
    // check host application and plugin
    result = CheckPluginId(hostBundleName);
    CHECK_RESULT(result, "check pluginId failed %{public}d");

    result = ProcessPluginInstall(hostBundleInfo);
    CHECK_RESULT(result, "process plugin install failed %{public}d");

    int32_t uid = hostBundleInfo.GetUid(userId_);
    NotifyPluginEvents(isPluginExist_ ? NotifyType::UPDATE : NotifyType::INSTALL, uid);
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "install plugin finished");
    return ERR_OK;
}

ErrCode PluginInstaller::UninstallPlugin(const std::string &hostBundleName, const std::string &pluginBundleName,
    const InstallPluginParam &installPluginParam)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "begin to uninstall plugin %{public}s for %{public}s",
        pluginBundleName.c_str(), hostBundleName.c_str());

    ErrCode result = ERR_OK;
    if (!InitDataMgr()) {
        return ERR_APPEXECFWK_NULL_PTR;
    }
    // check userId
    if (installPluginParam.userId < Constants::DEFAULT_USERID) {
        APP_LOGE("userId(%{public}d) invalid", installPluginParam.userId);
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }
    if (!dataMgr_->HasUserId(installPluginParam.userId)) {
        APP_LOGE("user %{public}d not exist", installPluginParam.userId);
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }
    auto &mtx = dataMgr_->GetBundleMutex(hostBundleName);
    std::lock_guard lock {mtx};
    // check host application exist in userId
    InnerBundleInfo hostBundleInfo;
    if (!dataMgr_->FetchInnerBundleInfo(hostBundleName, hostBundleInfo)) {
        APP_LOGE("hostBundleName:%{public}s get bundle info failed", hostBundleName.c_str());
        return ERR_APPEXECFWK_HOST_APPLICATION_NOT_FOUND;
    }
    if (!hostBundleInfo.HasInnerBundleUserInfo(installPluginParam.userId)) {
        APP_LOGE("HostBundleName: %{public}s not installed in user %{public}d",
            hostBundleName.c_str(), installPluginParam.userId);
        return ERR_APPEXECFWK_HOST_APPLICATION_NOT_FOUND;
    }
    // check plugin exist in host application
    isPluginExist_ = dataMgr_->GetPluginBundleInfo(hostBundleName, pluginBundleName,
        installPluginParam.userId, oldPluginInfo_);
    if (!isPluginExist_) {
        APP_LOGE("plugin: %{public}s not installed in host application:%{public}s user %{public}d",
            pluginBundleName.c_str(), hostBundleName.c_str(), installPluginParam.userId);
        return ERR_APPEXECFWK_PLUGIN_NOT_FOUND;
    }
    userId_ = installPluginParam.userId;
    bundleName_ = pluginBundleName;
    result = ProcessPluginUninstall(hostBundleInfo);
    CHECK_RESULT(result, "process plugin install failed %{public}d");

    int32_t uid = hostBundleInfo.GetUid(userId_);
    NotifyPluginEvents(NotifyType::UNINSTALL_BUNDLE, uid);
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "uninstall plugin finish");
    return ERR_OK;
}

ErrCode PluginInstaller::ParseFiles(const std::vector<std::string> &pluginFilePaths,
    const InstallPluginParam &installPluginParam)
{
    APP_LOGD("parsing plugin bundle files, path : %{private}s",
        GetJsonStrFromInfo(pluginFilePaths).c_str());
    ErrCode result = ERR_OK;

    std::vector<std::string> parsedPaths;
    result = ParseHapPaths(installPluginParam, pluginFilePaths, parsedPaths);
    CHECK_RESULT(result, "hsp file parse failed %{public}d");
    // check file paths
    std::vector<std::string> inBundlePaths;
    result = BundleUtil::CheckFilePath(parsedPaths, inBundlePaths);
    CHECK_RESULT(result, "hsp files check failed %{public}d");

    // copy the haps to the dir which cannot be accessed from caller
    result = CopyHspToSecurityDir(inBundlePaths, installPluginParam);
    CHECK_RESULT(result, "copy file failed %{public}d");

    // check number and type of the hsp and sig files
    std::vector<std::string> bundlePaths;
    result = ObtainHspFileAndSignatureFilePath(inBundlePaths, bundlePaths, signatureFileDir_);
    CHECK_RESULT(result, "obtain hsp file path or signature file path failed due to %{public}d");

    // check syscap
    result = bundleInstallChecker_->CheckSysCap(bundlePaths);
    bool isSysCapValid = (result == ERR_OK);
    if (!isSysCapValid) {
        APP_LOGI("hap syscap check failed %{public}d", result);
    }
    // verify signature info for all haps
    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    result = bundleInstallChecker_->CheckMultipleHapsSignInfo(bundlePaths, hapVerifyResults);
    if (result != ERR_OK) {
        APP_LOGE("check multi hap signature info failed %{public}d", result);
        return ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE;
    }

    // parse bundle infos
    InstallCheckParam checkParam;
    checkParam.needSendEvent = false;
    result = bundleInstallChecker_->ParseHapFiles(bundlePaths, checkParam, hapVerifyResults, parsedBundles_);
    if (result != ERR_OK) {
        APP_LOGE("parse haps file failed %{public}d", result);
        return ERR_APPEXECFWK_PLUGIN_PARSER_ERROR;
    }
    if (!parsedBundles_.empty() &&
        parsedBundles_.begin()->second.GetApplicationBundleType() != BundleType::APP_PLUGIN) {
        result = ERR_APPEXECFWK_PLUGIN_INSTALL_NOT_ALLOW;
        CHECK_RESULT(result, "plugin bundle type  %{public}d");
    }

    // check hsp install condition
    result = bundleInstallChecker_->CheckHspInstallCondition(hapVerifyResults);
    CHECK_RESULT(result, "check hsp install condition failed %{public}d");

    // check device type
    if (!isSysCapValid) {
        result = bundleInstallChecker_->CheckDeviceType(parsedBundles_);
        if (result != ERR_OK) {
            APP_LOGE("check device type failed %{public}d", result);
            return ERR_APPEXECFWK_INSTALL_SYSCAP_FAILED_AND_DEVICE_TYPE_ERROR;
        }
    }

    // check label info
    result = CheckPluginAppLabelInfo();
    CHECK_RESULT(result, "check plugin label info failed %{public}d");

    // delivery sign profile to code signature
    result = DeliveryProfileToCodeSign(hapVerifyResults);
    CHECK_RESULT(result, "delivery sign profile failed %{public}d");

    // check native file
    result = bundleInstallChecker_->CheckMultiNativeFile(parsedBundles_);
    CHECK_RESULT(result, "native so is incompatible in all haps %{public}d");

    // check enterprise bundle
    /* At this place, hapVerifyResults cannot be empty and unnecessary to check it */
    isEnterpriseBundle_ = bundleInstallChecker_->CheckEnterpriseBundle(hapVerifyResults[0]);
    appIdentifier_ = (hapVerifyResults[0].GetProvisionInfo().type == Security::Verify::ProvisionType::DEBUG) ?
        DEBUG_APP_IDENTIFIER : hapVerifyResults[0].GetProvisionInfo().bundleInfo.appIdentifier;
    compileSdkType_ = parsedBundles_.empty() ? COMPILE_SDK_TYPE_OPEN_HARMONY :
        (parsedBundles_.begin()->second).GetBaseApplicationInfo().compileSdkType;
    if (!ParsePluginId(hapVerifyResults[0].GetProvisionInfo().appServiceCapabilities, pluginIds_)) {
        APP_LOGE("parse plugin id failed");
        return ERR_APPEXECFWK_PLUGIN_INSTALL_PARSE_PLUGINID_ERROR;
    }
    return result;
}

ErrCode PluginInstaller::MkdirIfNotExist(const std::string &dir)
{
    bool isDirExist = false;
    ErrCode result = InstalldClient::GetInstance()->IsExistDir(dir, isDirExist);
    CHECK_RESULT(result, "check if dir exist failed %{public}d");
    if (!isDirExist) {
        result = InstalldClient::GetInstance()->CreateBundleDir(dir);
        CHECK_RESULT(result, "create dir failed %{public}d");
    }
    return result;
}

ErrCode PluginInstaller::ParseHapPaths(const InstallPluginParam &installPluginParam,
    const std::vector<std::string> &inBundlePaths, std::vector<std::string> &parsedPaths)
{
    parsedPaths.reserve(inBundlePaths.size());
    if (!inBundlePaths.empty() && inBundlePaths.front().find(APP_INSTALL_SANDBOX_PATH) != 0) {
        for (auto &bundlePath : inBundlePaths) {
            if (bundlePath.find("..") != std::string::npos) {
                APP_LOGE("path invalid: %{public}s", bundlePath.c_str());
                return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
            }
            parsedPaths.emplace_back(bundlePath);
        }
        return ERR_OK;
    }
    APP_LOGI("rename install");
    const std::string newPrefix = std::string(ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH) +
        ServiceConstants::GALLERY_DOWNLOAD_PATH + std::to_string(userId_) + ServiceConstants::PATH_SEPARATOR;

    for (const auto &bundlePath : inBundlePaths) {
        if (bundlePath.find("..") != std::string::npos) {
            APP_LOGE("path invalid: %{public}s", bundlePath.c_str());
            return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
        }
        if (bundlePath.find(APP_INSTALL_SANDBOX_PATH) == 0) {
            std::string newPath = newPrefix + bundlePath.substr(std::strlen(APP_INSTALL_SANDBOX_PATH));
            parsedPaths.push_back(newPath);
            APP_LOGD("parsed path: %{public}s", newPath.c_str());
        } else {
            APP_LOGE("path invalid: %{public}s", bundlePath.c_str());
            return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
        }
    }
    return ERR_OK;
}

ErrCode PluginInstaller::CopyHspToSecurityDir(std::vector<std::string> &bundlePaths,
    const InstallPluginParam &installPluginParam)
{
    for (size_t index = 0; index < bundlePaths.size(); ++index) {
        auto destination = BundleUtil::CopyFileToSecurityDir(bundlePaths[index], DirType::STREAM_INSTALL_DIR,
            toDeleteTempHspPath_, installPluginParam.IsRenameInstall());
        if (destination.empty()) {
            APP_LOGE("copy file %{public}s to security dir failed", bundlePaths[index].c_str());
            return ERR_APPEXECFWK_INSTALL_COPY_HAP_FAILED;
        }
        bundlePaths[index] = destination;
    }
    return ERR_OK;
}

ErrCode PluginInstaller::ObtainHspFileAndSignatureFilePath(const std::vector<std::string> &inBundlePaths,
    std::vector<std::string> &bundlePaths, std::string &signatureFilePath)
{
    if (inBundlePaths.empty()) {
        APP_LOGE("number of files in single shared lib path is illegal");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    if (inBundlePaths.size() == 1) {
        if (!BundleUtil::EndWith(inBundlePaths[0], ServiceConstants::HSP_FILE_SUFFIX)) {
            APP_LOGE("invalid file in plugin bundle dir");
            return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
        }
        bundlePaths.emplace_back(inBundlePaths[0]);
        return ERR_OK;
    }
    int32_t numberOfHsp = 0;
    int32_t numberOfSignatureFile = 0;
    for (const auto &path : inBundlePaths) {
        if ((path.find(ServiceConstants::HSP_FILE_SUFFIX) == std::string::npos) &&
            (path.find(ServiceConstants::CODE_SIGNATURE_FILE_SUFFIX) == std::string::npos)) {
            APP_LOGE("only hsp or sig file can be contained in shared bundle dir");
            return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
        }
        if (BundleUtil::EndWith(path, ServiceConstants::HSP_FILE_SUFFIX)) {
            numberOfHsp++;
            bundlePaths.emplace_back(path);
        }
        if (BundleUtil::EndWith(path, ServiceConstants::CODE_SIGNATURE_FILE_SUFFIX)) {
            numberOfSignatureFile++;
            signatureFilePath = path;
        }
    }
    APP_LOGD("signatureFilePath is %{public}s", signatureFilePath.c_str());
    return ERR_OK;
}

ErrCode PluginInstaller::ProcessNativeLibrary(
    const std::string &bundlePath,
    const std::string &moduleDir,
    const std::string &moduleName,
    const std::string &pluginBundleDir,
    InnerBundleInfo &newInfo)
{
    std::string cpuAbi;
    if (!newInfo.FetchNativeSoAttrs(moduleName, cpuAbi, nativeLibraryPath_)) {
        return ERR_OK;
    }
    isCompressNativeLibs_ = newInfo.IsCompressNativeLibs(moduleName);
    if (isCompressNativeLibs_) {
        if (nativeLibraryPath_.empty()) {
            APP_LOGW("nativeLibraryPath is empty");
            return ERR_OK;
        }
        std::string soPath = pluginBundleDir + ServiceConstants::PATH_SEPARATOR + nativeLibraryPath_;
        APP_LOGD("tempSoPath=%{public}s,cpuAbi=%{public}s, bundlePath=%{public}s",
            soPath.c_str(), cpuAbi.c_str(), bundlePath.c_str());

        auto result = InstalldClient::GetInstance()->ExtractModuleFiles(bundlePath, moduleDir, soPath, cpuAbi);
        CHECK_RESULT(result, "extract module files failed %{public}d");
        // verify hap or hsp code signature for compressed so files
        result = VerifyCodeSignatureForNativeFiles(
            bundlePath, cpuAbi, soPath, signatureFileDir_, newInfo.IsPreInstallApp());
        CHECK_RESULT(result, "fail to VerifyCodeSignature, error is %{public}d");
        cpuAbi_ = cpuAbi;
        soPath_ = soPath;
    } else {
        std::vector<std::string> fileNames;
        auto result = InstalldClient::GetInstance()->GetNativeLibraryFileNames(bundlePath, cpuAbi, fileNames);
        CHECK_RESULT(result, "fail to GetNativeLibraryFileNames, error is %{public}d");
        newInfo.SetNativeLibraryFileNames(moduleName, fileNames);
    }
    return ERR_OK;
}

ErrCode PluginInstaller::VerifyCodeSignatureForNativeFiles(const std::string &bundlePath,
    const std::string &cpuAbi, const std::string &targetSoPath, const std::string &signatureFileDir,
    bool isPreInstalledBundle) const
{
    if (!isPreInstalledBundle) {
        APP_LOGD("not pre-install app, skip verify code signature for native files");
        return ERR_OK;
    }
    APP_LOGD("begin to verify code signature for hsp native files");
    bool isCompileSdkOpenHarmony = (compileSdkType_ == COMPILE_SDK_TYPE_OPEN_HARMONY);
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = bundlePath;
    codeSignatureParam.cpuAbi = cpuAbi;
    codeSignatureParam.targetSoPath = targetSoPath;
    codeSignatureParam.signatureFileDir = signatureFileDir;
    codeSignatureParam.isEnterpriseBundle = isEnterpriseBundle_;
    codeSignatureParam.appIdentifier = appIdentifier_;
    codeSignatureParam.isCompileSdkOpenHarmony = isCompileSdkOpenHarmony;
    codeSignatureParam.isPreInstalledBundle = isPreInstalledBundle;
    codeSignatureParam.isCompressNativeLibrary = isCompressNativeLibs_;
    if (InstalldClient::GetInstance()->VerifyCodeSignature(codeSignatureParam) != ERR_OK) {
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED;
    }
    return ERR_OK;
}

ErrCode PluginInstaller::VerifyCodeSignatureForHsp(const std::string &hspPath,
    const std::string &appIdentifier, bool isEnterpriseBundle, bool isCompileSdkOpenHarmony) const
{
    APP_LOGD("begin to verify code signature for hsp");
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = hspPath;
    codeSignatureParam.cpuAbi = cpuAbi_;
    codeSignatureParam.targetSoPath = soPath_;
    codeSignatureParam.appIdentifier = appIdentifier;
    codeSignatureParam.signatureFileDir = signatureFileDir_;
    codeSignatureParam.isEnterpriseBundle = isEnterpriseBundle;
    codeSignatureParam.isCompileSdkOpenHarmony = isCompileSdkOpenHarmony;
    codeSignatureParam.isPreInstalledBundle = false;
    if (InstalldClient::GetInstance()->VerifyCodeSignatureForHap(codeSignatureParam) != ERR_OK) {
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED;
    }
    return ERR_OK;
}

ErrCode PluginInstaller::DeliveryProfileToCodeSign(
    std::vector<Security::Verify::HapVerifyResult> &hapVerifyResults) const
{
    if (hapVerifyResults.empty()) {
        APP_LOGE("no sign info in the all haps");
        return ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
    }

    Security::Verify::ProvisionInfo provisionInfo = hapVerifyResults[0].GetProvisionInfo();
    if (provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE ||
        provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_NORMAL ||
        provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_MDM ||
        provisionInfo.type == Security::Verify::ProvisionType::DEBUG) {
        if (provisionInfo.profileBlockLength == 0 || provisionInfo.profileBlock == nullptr) {
            APP_LOGE("invalid sign profile");
            return ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
        }
        return InstalldClient::GetInstance()->DeliverySignProfile(provisionInfo.bundleInfo.bundleName,
            provisionInfo.profileBlockLength, provisionInfo.profileBlock.get());
    }
    return ERR_OK;
}

ErrCode PluginInstaller::CheckPluginId(const std::string &hostBundleName)
{
    if (pluginIds_.empty()) {
        APP_LOGE("plugin id is empty");
        return ERR_APPEXECFWK_PLUGIN_INSTALL_CHECK_PLUGINID_ERROR;
    }
    auto appProvisionInfoMgr = DelayedSingleton<AppProvisionInfoManager>::GetInstance();
    if (!appProvisionInfoMgr) {
        APP_LOGE("appProvisionInfoMgr is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    AppProvisionInfo hostAppProvisionInfo;
    if (!appProvisionInfoMgr->GetAppProvisionInfo(hostBundleName, hostAppProvisionInfo)) {
        APP_LOGW("bundleName:%{public}s GetAppProvisionInfo failed", hostBundleName.c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::vector<std::string> hostPluginIds;
    if (!ParsePluginId(hostAppProvisionInfo.appServiceCapabilities, hostPluginIds)) {
        APP_LOGE("parse host application plugin id failed");
        return ERR_APPEXECFWK_PLUGIN_INSTALL_PARSE_PLUGINID_ERROR;
    }
    if (hostPluginIds.empty()) {
        APP_LOGE("host application plugin id is empty");
        return ERR_APPEXECFWK_PLUGIN_INSTALL_CHECK_PLUGINID_ERROR;
    }
    std::unordered_set<std::string> pluginIdSet(hostPluginIds.begin(), hostPluginIds.end());
    for (const auto &item : pluginIds_) {
        if (pluginIdSet.find(item) != pluginIdSet.end()) {
            return ERR_OK;
        }
    }
    APP_LOGD("check plugin id success");
    return ERR_APPEXECFWK_PLUGIN_INSTALL_CHECK_PLUGINID_ERROR;
}

bool PluginInstaller::ParsePluginId(const std::string &appServiceCapabilities,
    std::vector<std::string> &pluginIds)
{
    if (appServiceCapabilities.empty()) {
        APP_LOGE("appServiceCapabilities is empty");
        return false;
    }
    auto appServiceCapabilityMap = BundleUtil::ParseMapFromJson(appServiceCapabilities);
    for (auto &item : appServiceCapabilityMap) {
        if (item.first == PERMISSION_KEY) {
            std::unordered_map<std::string, std::string> pluginIdMap = BundleUtil::ParseMapFromJson(item.second);
            auto it = pluginIdMap.find(PLUGIN_ID);
            if (it == pluginIdMap.end()) {
                APP_LOGE("pluginDistributionIDs not found in appServiceCapability");
                return false;
            }
            OHOS::SplitStr(it->second, PLUGIN_ID_SEPARATOR, pluginIds);
            return true;
        }
    }
    APP_LOGE("support plugin permission not found in appServiceCapability");
    return false;
}

ErrCode PluginInstaller::CheckSupportPluginPermission(const std::string &hostBundleName)
{
    if (BundlePermissionMgr::VerifyPermission(hostBundleName, ServiceConstants::PERMISSION_SUPPORT_PLUGIN,
        userId_) == AccessToken::PermissionState::PERMISSION_GRANTED) {
        APP_LOGD("verify support plugin permission success");
        return ERR_OK;
    }
    return ERR_APPEXECFWK_SUPPORT_PLUGIN_PERMISSION_ERROR;
}

ErrCode PluginInstaller::CheckPluginAppLabelInfo()
{
    if (parsedBundles_.empty()) {
        APP_LOGE("parsedBundles is empty");
        return ERR_OK;
    }
    bundleName_ = parsedBundles_.begin()->second.GetBundleName();

    ErrCode ret = bundleInstallChecker_->CheckAppLabelInfo(parsedBundles_);
    if (ret != ERR_OK) {
        APP_LOGE("check plugin app label info failed");
        return ERR_APPEXECFWK_PLUGIN_CHECK_APP_LABEL_ERROR;
    }
    return ERR_OK;
}

ErrCode PluginInstaller::ProcessPluginInstall(const InnerBundleInfo &hostBundleInfo)
{
    if (parsedBundles_.empty()) {
        APP_LOGD("no bundle to install");
        return ERR_OK;
    }
    if (!InitDataMgr()) {
        return ERR_APPEXECFWK_NULL_PTR;
    }
    ErrCode result = ERR_OK;
    std::string pluginDir;
    result = CreatePluginDir(hostBundleInfo.GetBundleName(), pluginDir);
    CHECK_RESULT(result, "plugin dir check failed %{public}d");
    isPluginExist_ = dataMgr_->FetchPluginBundleInfo(hostBundleInfo.GetBundleName(), bundleName_, oldPluginInfo_);
    if (isPluginExist_) {
        if (!CheckAppIdentifier()) {
            return ERR_APPEXECFWK_INSTALL_FAILED_INCONSISTENT_SIGNATURE;
        }
        if (!CheckVersionCodeForUpdate()) {
            return ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE;
        }
    }
    ScopeGuard deleteDirGuard([&] { RemovePluginDir(hostBundleInfo);});
    for (auto &item : parsedBundles_) {
        result = ExtractPluginBundles(item.first, item.second, pluginDir);
        CHECK_RESULT(result, "extract plugin bundles failed %{public}d");
    }

    ScopeGuard dataRollBackGuard([&] { PluginRollBack(hostBundleInfo.GetBundleName());});
    InnerBundleInfo pluginInfo;
    MergePluginBundleInfo(pluginInfo);
    result = SavePluginInfoToStorage(pluginInfo, hostBundleInfo);
    CHECK_RESULT(result, "save plugin info to storage failed %{public}d");

    RemoveEmptyDirs(pluginDir);
    RemoveOldInstallDir();
    deleteDirGuard.Dismiss();
    dataRollBackGuard.Dismiss();
    APP_LOGD("install plugin bundle successfully: %{public}s", bundleName_.c_str());
    return result;
}

ErrCode PluginInstaller::CreatePluginDir(const std::string &hostBundleName, std::string &pluginDir)
{
    ErrCode result = ERR_OK;
    std::string bundleDir = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR + hostBundleName;
    result = MkdirIfNotExist(bundleDir);
    CHECK_RESULT(result, "check bundle dir failed %{public}d");

    pluginDir = bundleDir + ServiceConstants::PATH_SEPARATOR + PLUGINS;
    result = MkdirIfNotExist(pluginDir);
    CHECK_RESULT(result, "check plugin dir failed %{public}d");

    return result;
}

bool PluginInstaller::CheckAppIdentifier() const
{
    auto &newInfo = parsedBundles_.begin()->second;
    if (!newInfo.GetAppIdentifier().empty() &&
        !oldPluginInfo_.appIdentifier.empty() &&
        newInfo.GetAppIdentifier() == oldPluginInfo_.appIdentifier) {
        return true;
    }
    if (oldPluginInfo_.appId == newInfo.GetAppId()) {
        return true;
    }
    APP_LOGE("the appIdentifier or appId of the new bundle is not the same as old one");
    return false;
}

bool PluginInstaller::CheckVersionCodeForUpdate() const
{
    auto &newInfo = parsedBundles_.begin()->second;
    if (newInfo.GetVersionCode() < oldPluginInfo_.versionCode) {
        APP_LOGE("fail to update lower version plugin");
        return false;
    }
    return true;
}

ErrCode PluginInstaller::ExtractPluginBundles(const std::string &bundlePath, InnerBundleInfo &newInfo,
    const std::string &pluginDir)
{
    ErrCode result = ERR_OK;
    std::string pluginBundleDir = pluginDir + ServiceConstants::PATH_SEPARATOR + bundleNameWithTime_;  // pass pluginDir
    result = MkdirIfNotExist(pluginBundleDir);
    CHECK_RESULT(result, "check plugin bundle dir failed %{public}d");
    newInfo.SetAppCodePath(pluginBundleDir);

    auto &moduleName = newInfo.GetInnerModuleInfos().begin()->second.moduleName;
    std::string moduleDir = pluginBundleDir + ServiceConstants::PATH_SEPARATOR + moduleName;
    result = MkdirIfNotExist(moduleDir);
    CHECK_RESULT(result, "check module dir failed %{public}d");

    result = ProcessNativeLibrary(bundlePath, moduleDir, moduleName, pluginBundleDir, newInfo);
    CHECK_RESULT(result, "ProcessNativeLibrary failed %{public}d");

    // save hsp and so files to installation dir
    result = SaveHspToInstallDir(bundlePath, pluginBundleDir, moduleName, newInfo);
    CHECK_RESULT(result, "save hsp file failed %{public}d");

    newInfo.AddModuleSrcDir(moduleDir);
    newInfo.AddModuleResPath(moduleDir);
    return ERR_OK;
}

void PluginInstaller::MergePluginBundleInfo(InnerBundleInfo &pluginBundleInfo)
{
    auto iter = parsedBundles_.begin();
    pluginBundleInfo = iter->second;
    InnerBundleUserInfo newInnerBundleUserInfo;
    newInnerBundleUserInfo.bundleName = bundleName_;
    newInnerBundleUserInfo.bundleUserInfo.userId = userId_;
    pluginBundleInfo.AddInnerBundleUserInfo(newInnerBundleUserInfo);
    iter++;

    if (!InitDataMgr()) {
        return;
    }
    for (; iter != parsedBundles_.end(); ++iter) {
        InnerBundleInfo &currentInfo = iter->second;
        dataMgr_->AddNewModuleInfo(currentInfo, pluginBundleInfo);
    }
}

ErrCode PluginInstaller::SavePluginInfoToStorage(const InnerBundleInfo &pluginInfo,
    const InnerBundleInfo &hostBundleInfo)
{
    ErrCode result = ERR_OK;
    PluginBundleInfo pluginBundleInfo;
    pluginInfo.ConvertPluginBundleInfo(bundleNameWithTime_, pluginBundleInfo);

    if (!InitDataMgr()) {
        return ERR_APPEXECFWK_NULL_PTR;
    }
    result = dataMgr_->AddPluginInfo(hostBundleInfo.GetBundleName(), pluginBundleInfo, userId_);
    if (result != ERR_OK) {
        APP_LOGE("save pluginInfo to storage failed %{public}d, userId:%{public}d",
            result, userId_);
        return result;
    }
    APP_LOGI("save pluginInfo:%{public}s success", bundleName_.c_str());
    return ERR_OK;
}

void PluginInstaller::PluginRollBack(const std::string &hostBundleName)
{
    if (!InitDataMgr()) {
        return;
    }
    ErrCode result = ERR_OK;
    if (!isPluginExist_) {
        //rollback database
        result = dataMgr_->RemovePluginInfo(hostBundleName, bundleName_, userId_);
        if (result != ERR_OK) {
            APP_LOGW("plugin:%{public}s clean PluginInfo failed", bundleName_.c_str());
        }
        return;
    }
    // for update
    result = dataMgr_->UpdatePluginBundleInfo(hostBundleName, oldPluginInfo_);
    if (result != ERR_OK) {
        APP_LOGW("save old pluginInfo failed %{public}d when rollback", result);
    }
    result = dataMgr_->RemovePluginFromUserInfo(hostBundleName, bundleName_, userId_);
    if (result != ERR_OK) {
        APP_LOGW("plugin:%{public}s clean Plugin from userInfo failed", bundleName_.c_str());
    }
}

ErrCode PluginInstaller::RemovePluginDir(const InnerBundleInfo &hostBundleInfo)
{
    std::string pluginDir = hostBundleInfo.GetAppCodePath() + ServiceConstants::PATH_SEPARATOR + PLUGINS;
    std::string pluginBundleDir = pluginDir + ServiceConstants::PATH_SEPARATOR + bundleNameWithTime_;
    ErrCode err = InstalldClient::GetInstance()->RemoveDir(pluginBundleDir);
    if (err != ERR_OK) {
        APP_LOGW("remove dir of %{public}s failed: %{public}s", bundleName_.c_str(), pluginBundleDir.c_str());
        return err;
    }
    return ERR_OK;
}

ErrCode PluginInstaller::SaveHspToInstallDir(const std::string &bundlePath,
    const std::string &pluginBundleDir,
    const std::string &moduleName,
    InnerBundleInfo &newInfo)
{
    ErrCode result = ERR_OK;
    std::string hspPath = pluginBundleDir + ServiceConstants::PATH_SEPARATOR + moduleName +
        ServiceConstants::HSP_FILE_SUFFIX;
    if (!signatureFileDir_.empty()) {
        result = InstalldClient::GetInstance()->CopyFile(bundlePath, hspPath, signatureFileDir_);
        CHECK_RESULT(result, "copy hsp to install dir failed %{public}d");
    } else {
        result = InstalldClient::GetInstance()->MoveHapToCodeDir(bundlePath, hspPath);
        CHECK_RESULT(result, "move hsp to install dir failed %{public}d");
        bool isCompileSdkOpenHarmony = (compileSdkType_ == COMPILE_SDK_TYPE_OPEN_HARMONY);
        result = VerifyCodeSignatureForHsp(hspPath, appIdentifier_, isEnterpriseBundle_,
            isCompileSdkOpenHarmony);
    }
    newInfo.SetModuleHapPath(hspPath);

    FILE *hspFp = fopen(hspPath.c_str(), "r");
    if (hspFp == nullptr) {
        APP_LOGE("fopen %{public}s failed", hspPath.c_str());
    } else {
        int32_t hspFd = fileno(hspFp);
        if (hspFd < 0) {
            APP_LOGE("open %{public}s failed", hspPath.c_str());
        } else if (fsync(hspFd) != 0) {
            APP_LOGE("fsync %{public}s failed", hspPath.c_str());
        }
        fclose(hspFp);
    }
    CHECK_RESULT(result, "verify code signature failed %{public}d");
    return ERR_OK;
}

void PluginInstaller::RemoveEmptyDirs(const std::string &pluginDir) const
{
    for (auto &item : parsedBundles_) {
        std::string moduleDir = pluginDir + ServiceConstants::PATH_SEPARATOR + bundleNameWithTime_
            + ServiceConstants::PATH_SEPARATOR + item.second.GetCurModuleName();
        bool isEmpty = false;
        InstalldClient::GetInstance()->IsDirEmpty(moduleDir, isEmpty);
        if (isEmpty) {
            APP_LOGD("remove empty dir : %{public}s", moduleDir.c_str());
            RemoveDir(moduleDir);
        }
    }
}

void PluginInstaller::RemoveDir(const std::string &dir) const
{
    auto result = InstalldClient::GetInstance()->RemoveDir(dir);
    if (result != ERR_OK) {
        APP_LOGW("remove dir %{public}s failed, error is %{public}d", dir.c_str(), result);
    }
}

ErrCode PluginInstaller::ProcessPluginUninstall(const InnerBundleInfo &hostBundleInfo)
{
    ErrCode result = ERR_OK;
    if (!InitDataMgr()) {
        return ERR_APPEXECFWK_NULL_PTR;
    }
    std::string hostBundleName = hostBundleInfo.GetBundleName();
    bool isMultiUser = hostBundleInfo.HasMultiUserPlugin(bundleName_);
    if (isMultiUser) {
        result = dataMgr_->RemovePluginFromUserInfo(hostBundleName, bundleName_, userId_);
        if (result != ERR_OK) {
            APP_LOGE("bundleName:%{public}s remove plugin:%{public}s from userInfo failed",
                hostBundleName.c_str(), bundleName_.c_str());
            return ERR_APPEXECFWK_REMOVE_PLUGIN_INFO_ERROR;
        }
        return ERR_OK;
    }

    ScopeGuard removeDataGuard([&] { UninstallRollBack(hostBundleName); });
    result = dataMgr_->RemovePluginInfo(hostBundleName, bundleName_, userId_);
    if (result != ERR_OK) {
        APP_LOGE("bundleName:%{public}s remove plugin info %{public}s failed",
            hostBundleInfo.GetBundleName().c_str(), bundleName_.c_str());
        return ERR_APPEXECFWK_REMOVE_PLUGIN_INFO_ERROR;
    }
    removeDataGuard.Dismiss();

    std::string pluginBundleDir = oldPluginInfo_.codePath;
    std::string deleteDir = pluginBundleDir + REMOVE_TMP_SUFFIX;
    if (!BundleUtil::RenameFile(pluginBundleDir, deleteDir)) {
        APP_LOGW("rename failed, %{public}s -> %{public}s", pluginBundleDir.c_str(), deleteDir.c_str());
        result = InstalldClient::GetInstance()->RemoveDir(pluginBundleDir);
    } else {
        result = InstalldClient::GetInstance()->RemoveDir(deleteDir);
    }
    if (result != ERR_OK) {
        APP_LOGW("bundleName:%{public}s remove plugin:%{public}s dir failed",
            hostBundleInfo.GetBundleName().c_str(), bundleName_.c_str());
    }
    InstalldClient::GetInstance()->RemoveSignProfile(bundleName_);

    return ERR_OK;
}

void PluginInstaller::RemoveOldInstallDir()
{
    if (!isPluginExist_) {
        return;
    }
    RemoveDir(oldPluginInfo_.codePath);
    APP_LOGI("remove old install dir:%{public}s", oldPluginInfo_.codePath.c_str());
}

void PluginInstaller::UninstallRollBack(const std::string &hostBundleName)
{
    if (!InitDataMgr()) {
        return;
    }
    ErrCode err = dataMgr_->AddPluginInfo(hostBundleName, oldPluginInfo_, userId_);
    if (err != ERR_OK) {
        APP_LOGW("save old pluginInfo failed %{public}d, userId:%{public}d", err, userId_);
    }
}

bool PluginInstaller::InitDataMgr()
{
    if (dataMgr_ == nullptr) {
        dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr_ == nullptr) {
            LOG_E(BMS_TAG_INSTALLER, "Get dataMgr shared_ptr nullptr");
            return false;
        }
    }
    return true;
}

std::string PluginInstaller::GetModuleNames()
{
    if (parsedBundles_.empty()) {
        APP_LOGW("module name is empty");
        return Constants::EMPTY_STRING;
    }
    std::string moduleNames;
    for (const auto &item : parsedBundles_) {
        moduleNames.append(item.second.GetCurrentModulePackage()).append(ServiceConstants::MODULE_NAME_SEPARATOR);
    }
    moduleNames.pop_back();
    APP_LOGD("moduleNames : %{public}s", moduleNames.c_str());
    return moduleNames;
}

void PluginInstaller::NotifyPluginEvents(const NotifyType &type, int32_t uid)
{
    NotifyBundleEvents event = {
        .type = type,
        .bundleType = static_cast<int32_t>(BundleType::APP_PLUGIN),
        .bundleName = bundleName_,
        .uid = uid,
        .modulePackage = GetModuleNames(),
    };
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    commonEventMgr->NotifyPluginEvents(event, dataMgr_);
}
} // AppExecFwk
} // OHOS