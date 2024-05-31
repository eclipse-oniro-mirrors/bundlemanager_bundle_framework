/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "base_bundle_installer.h"

#include <sys/stat.h>
#include <unordered_set>
#include "nlohmann/json.hpp"

#include <unistd.h>

#include "account_helper.h"
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
#include "aging/bundle_aging_mgr.h"
#endif
#include "aot/aot_handler.h"
#include "app_control_constants.h"
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
#include "default_app_mgr.h"
#endif
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
#include "quick_fix/app_quick_fix.h"
#include "quick_fix/inner_app_quick_fix.h"
#include "quick_fix/quick_fix_data_mgr.h"
#include "quick_fix/quick_fix_switcher.h"
#include "quick_fix/quick_fix_deleter.h"
#endif
#include "ability_manager_helper.h"
#include "app_log_wrapper.h"
#include "app_provision_info_manager.h"
#include "bms_extension_data_mgr.h"
#include "bundle_clone_installer.h"
#include "bundle_constants.h"
#include "bundle_extractor.h"
#include "bundle_mgr_service.h"
#include "bundle_sandbox_app_helper.h"
#include "bundle_permission_mgr.h"
#include "bundle_resource_helper.h"
#include "bundle_util.h"
#include "data_group_info.h"
#include "datetime_ex.h"
#include "driver_installer.h"
#include "hitrace_meter.h"
#include "installd_client.h"
#include "parameter.h"
#include "parameters.h"
#include "perf_profile.h"
#include "preinstalled_application_info.h"
#include "scope_guard.h"
#include "string_ex.h"
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
#include "bundle_overlay_data_manager.h"
#include "bundle_overlay_install_checker.h"
#endif

#ifdef STORAGE_SERVICE_ENABLE
#include "storage_manager_proxy.h"
#endif
#include "iservice_registry.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::Security;
namespace {
constexpr const char* ARK_CACHE_PATH = "/data/local/ark-cache/";
constexpr const char* ARK_PROFILE_PATH = "/data/local/ark-profile/";
constexpr const char* COMPILE_SDK_TYPE_OPEN_HARMONY = "OpenHarmony";
constexpr const char* LOG = "log";
constexpr const char* HSP_VERSION_PREFIX = "v";
constexpr const char* PRE_INSTALL_HSP_PATH = "/shared_bundles/";
constexpr const char* APP_INSTALL_PATH = "/data/app/el1/bundle";
constexpr const char* DEBUG_APP_IDENTIFIER = "DEBUG_LIB_ID";
constexpr const char* SKILL_URI_SCHEME_HTTPS = "https";
constexpr int32_t DATA_GROUP_DIR_MODE = 02770;

#ifdef STORAGE_SERVICE_ENABLE
#ifdef QUOTA_PARAM_SET_ENABLE
const std::string SYSTEM_PARAM_ATOMICSERVICE_DATASIZE_THRESHOLD =
    "persist.sys.bms.aging.policy.atomicservice.datasize.threshold";
const int32_t THRESHOLD_VAL_LEN = 20;
#endif // QUOTA_PARAM_SET_ENABLE
const int32_t STORAGE_MANAGER_MANAGER_ID = 5003;
#endif // STORAGE_SERVICE_ENABLE
const int32_t ATOMIC_SERVICE_DATASIZE_THRESHOLD_MB_PRESET = 50;
const int32_t SINGLE_HSP_VERSION = 1;
const char* BMS_KEY_SHELL_UID = "const.product.shell.uid";
const std::set<std::string> SINGLETON_WHITE_LIST = {
    "com.ohos.sceneboard",
    "com.ohos.callui",
    "com.ohos.mms",
    "com.ohos.FusionSearch"
};
constexpr const char* DATA_EXTENSION_PATH = "/extension/";
constexpr const char* BMS_ACTIVATION_LOCK = "persist.bms.activation-lock";
constexpr const char* BMS_TRUE = "true";
const int32_t BMS_ACTIVATION_LOCK_VAL_LEN = 20;

std::string GetHapPath(const InnerBundleInfo &info, const std::string &moduleName)
{
    std::string fileSuffix = Constants::INSTALL_FILE_SUFFIX;
    auto moduleInfo = info.GetInnerModuleInfoByModuleName(moduleName);
    if (moduleInfo && moduleInfo->distro.moduleType == Profile::MODULE_TYPE_SHARED) {
        APP_LOGD("The module(%{public}s) is shared.", moduleName.c_str());
        fileSuffix = Constants::HSP_FILE_SUFFIX;
    }

    return info.GetAppCodePath() + Constants::PATH_SEPARATOR + moduleName + fileSuffix;
}

std::string GetHapPath(const InnerBundleInfo &info)
{
    return GetHapPath(info, info.GetModuleName(info.GetCurrentModulePackage()));
}

std::string BuildTempNativeLibraryPath(const std::string &nativeLibraryPath)
{
    auto position = nativeLibraryPath.find(Constants::PATH_SEPARATOR);
    if (position == std::string::npos) {
        return nativeLibraryPath;
    }

    auto prefixPath = nativeLibraryPath.substr(0, position);
    auto suffixPath = nativeLibraryPath.substr(position);
    return prefixPath + Constants::TMP_SUFFIX + suffixPath;
}
} // namespace

BaseBundleInstaller::BaseBundleInstaller()
    : bundleInstallChecker_(std::make_unique<BundleInstallChecker>()) {}

BaseBundleInstaller::~BaseBundleInstaller()
{
    bundlePaths_.clear();
    BundleUtil::DeleteTempDirs(toDeleteTempHapPath_);
    toDeleteTempHapPath_.clear();
    signatureFileTmpMap_.clear();
}

ErrCode BaseBundleInstaller::InstallBundle(
    const std::string &bundlePath, const InstallParam &installParam, const Constants::AppType appType)
{
    std::vector<std::string> bundlePaths { bundlePath };
    return InstallBundle(bundlePaths, installParam, appType);
}

void BaseBundleInstaller::sendStartInstallNotify(const InstallParam &installParam,
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    if (!installParam.needSendEvent) {
        APP_LOGW("sendStartInstallNotify needSendEvent is false");
        return;
    }
    if (bundleName_.empty()) {
        APP_LOGW("sendStartInstallNotify bundleName is empty");
        return;
    }
    for (auto item : infos) {
        APP_LOGD("sendStartInstallNotify %{public}s  %{public}s %{public}s %{public}s",
            bundleName_.c_str(), item.second.GetCurModuleName().c_str(),
            item.second.GetAppId().c_str(), item.second.GetAppIdentifier().c_str());
        NotifyBundleEvents installRes = {
            .bundleName = bundleName_,
            .modulePackage = item.second.GetCurModuleName(),
            .type = NotifyType::START_INSTALL,
            .appId = item.second.GetAppId(),
            .appIdentifier = item.second.GetAppIdentifier()
        };
        if (NotifyBundleStatus(installRes) != ERR_OK) {
            APP_LOGW("notify status failed for start install");
        }
    }
}

ErrCode BaseBundleInstaller::InstallBundle(
    const std::vector<std::string> &bundlePaths, const InstallParam &installParam, const Constants::AppType appType)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGI("begin to process bundle install");

    PerfProfile::GetInstance().SetBundleInstallStartTime(GetTickCount());

    int32_t uid = Constants::INVALID_UID;
    ErrCode result = ProcessBundleInstall(bundlePaths, installParam, appType, uid);
    if (installParam.needSendEvent && dataMgr_ && !bundleName_.empty()) {
        NotifyBundleEvents installRes = {
            .bundleName = bundleName_,
            .modulePackage = moduleName_,
            .abilityName = mainAbility_,
            .resultCode = result,
            .type = GetNotifyType(),
            .uid = uid,
            .accessTokenId = accessTokenId_,
            .isModuleUpdate = isModuleUpdate_,
            .appDistributionType = appDistributionType_,
            .bundleType = static_cast<int32_t>(bundleType_),
            .atomicServiceModuleUpgrade = atomicServiceModuleUpgrade_
        };
        if (installParam.allUser) {
            AddBundleStatus(installRes);
        } else if (NotifyBundleStatus(installRes) != ERR_OK) {
            APP_LOGW("notify status failed for installation");
        }
    }

    if (result == ERR_OK) {
        OnSingletonChange(installParam.noSkipsKill);
    }

    if (!bundlePaths.empty()) {
        SendBundleSystemEvent(
            bundleName_.empty() ? bundlePaths[0] : bundleName_,
            ((isAppExist_ && hasInstalledInUser_) ? BundleEventType::UPDATE : BundleEventType::INSTALL),
            installParam,
            sysEventInfo_.preBundleScene,
            result);
    }
    PerfProfile::GetInstance().SetBundleInstallEndTime(GetTickCount());
    APP_LOGD("finish to process bundle install");
    return result;
}

ErrCode BaseBundleInstaller::InstallBundleByBundleName(
    const std::string &bundleName, const InstallParam &installParam)
{
    APP_LOGI("begin to process bundle install by bundleName, which is %{public}s.", bundleName.c_str());
    PerfProfile::GetInstance().SetBundleInstallStartTime(GetTickCount());

    int32_t uid = Constants::INVALID_UID;
    ErrCode result = ProcessInstallBundleByBundleName(bundleName, installParam, uid);
    if (installParam.needSendEvent && dataMgr_ && !bundleName.empty()) {
        NotifyBundleEvents installRes = {
            .bundleName = bundleName,
            .resultCode = result,
            .type = NotifyType::INSTALL,
            .uid = uid,
            .accessTokenId = accessTokenId_,
            .appDistributionType = appDistributionType_,
            .bundleType = static_cast<int32_t>(bundleType_),
            .atomicServiceModuleUpgrade = atomicServiceModuleUpgrade_
        };
        if (installParam.concentrateSendEvent) {
            AddNotifyBundleEvents(installRes);
        } else if (NotifyBundleStatus(installRes) != ERR_OK) {
            APP_LOGW("notify status failed for installation");
        }
    }

    SendBundleSystemEvent(
        bundleName,
        BundleEventType::INSTALL,
        installParam,
        InstallScene::CREATE_USER,
        result);
    PerfProfile::GetInstance().SetBundleInstallEndTime(GetTickCount());
    APP_LOGD("finish to process %{public}s bundle install", bundleName.c_str());
    return result;
}

ErrCode BaseBundleInstaller::Recover(
    const std::string &bundleName, const InstallParam &installParam)
{
    APP_LOGI("begin to process bundle recover by bundleName, which is %{public}s.", bundleName.c_str());
    PerfProfile::GetInstance().SetBundleInstallStartTime(GetTickCount());
    int32_t uid = Constants::INVALID_UID;
    ErrCode result = ProcessRecover(bundleName, installParam, uid);
    if (installParam.needSendEvent && dataMgr_ && !bundleName_.empty() && !modulePackage_.empty()) {
        NotifyBundleEvents installRes = {
            .bundleName = bundleName,
            .resultCode = result,
            .type = NotifyType::INSTALL,
            .uid = uid,
            .accessTokenId = accessTokenId_,
            .appDistributionType = appDistributionType_,
            .bundleType = static_cast<int32_t>(bundleType_)
        };
        if (NotifyBundleStatus(installRes) != ERR_OK) {
            APP_LOGW("notify status failed for installation");
        }
    }

    auto recoverInstallParam = installParam;
    recoverInstallParam.isPreInstallApp = true;
    SendBundleSystemEvent(
        bundleName,
        BundleEventType::RECOVER,
        recoverInstallParam,
        sysEventInfo_.preBundleScene,
        result);
    PerfProfile::GetInstance().SetBundleInstallEndTime(GetTickCount());
    APP_LOGD("finish to process %{public}s bundle recover", bundleName.c_str());
    return result;
}

ErrCode BaseBundleInstaller::UninstallBundle(const std::string &bundleName, const InstallParam &installParam)
{
    APP_LOGI("begin to process %{public}s bundle uninstall", bundleName.c_str());
    PerfProfile::GetInstance().SetBundleUninstallStartTime(GetTickCount());

    // uninstall all sandbox app before
    UninstallAllSandboxApps(bundleName, installParam.userId);

    std::shared_ptr<BundleCloneInstaller> cloneInstaller = std::make_shared<BundleCloneInstaller>();
    cloneInstaller->UninstallAllCloneApps(bundleName, installParam.userId);

    int32_t uid = Constants::INVALID_UID;
    bool isUninstalledFromBmsExtension = false;
    ErrCode result = ProcessBundleUninstall(bundleName, installParam, uid);
    if ((result == ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_BUNDLE) &&
        (UninstallBundleFromBmsExtension(bundleName) == ERR_OK)) {
        isUninstalledFromBmsExtension = true;
        result = ERR_OK;
    }
    if (installParam.needSendEvent && dataMgr_) {
        NotifyBundleEvents installRes = {
            .bundleName = bundleName,
            .resultCode = result,
            .type = NotifyType::UNINSTALL_BUNDLE,
            .uid = uid,
            .accessTokenId = accessTokenId_,
            .isAgingUninstall = installParam.isAgingUninstall,
            .isBmsExtensionUninstalled = isUninstalledFromBmsExtension,
            .appId = uninstallBundleAppId_,
            .bundleType = static_cast<int32_t>(bundleType_)
        };

        if (installParam.concentrateSendEvent) {
            AddNotifyBundleEvents(installRes);
        } else if (NotifyBundleStatus(installRes) != ERR_OK) {
            APP_LOGW("notify status failed for installation");
        }
    }

    if (result == ERR_OK) {
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
        DefaultAppMgr::GetInstance().HandleUninstallBundle(userId_, bundleName);
#endif
    }

    SendBundleSystemEvent(
        bundleName,
        BundleEventType::UNINSTALL,
        installParam,
        sysEventInfo_.preBundleScene,
        result);
    PerfProfile::GetInstance().SetBundleUninstallEndTime(GetTickCount());
    APP_LOGD("finish to process %{public}s bundle uninstall", bundleName.c_str());
    return result;
}


ErrCode BaseBundleInstaller::CheckUninstallInnerBundleInfo(const InnerBundleInfo &info, const std::string &bundleName)
{
    if (!info.GetRemovable()) {
        APP_LOGE("uninstall system app");
        return ERR_APPEXECFWK_UNINSTALL_SYSTEM_APP_ERROR;
    }
    if (!info.GetUninstallState()) {
        APP_LOGE("bundle : %{public}s can not be uninstalled, uninstallState : %{public}d",
            bundleName.c_str(), info.GetUninstallState());
        return ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_UNINSTALL;
    }
    if (info.GetApplicationBundleType() != BundleType::SHARED) {
        APP_LOGE("uninstall bundle is not shared library");
        return ERR_APPEXECFWK_UNINSTALL_SHARE_APP_LIBRARY_IS_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::UninstallBundleByUninstallParam(const UninstallParam &uninstallParam)
{
    APP_LOGI("begin to process cross-app bundle %{public}s uninstall", uninstallParam.bundleName.c_str());
    std::string bundleName = uninstallParam.bundleName;
    int32_t versionCode = uninstallParam.versionCode;
    if (bundleName.empty()) {
        APP_LOGE("uninstall bundle name or module name empty");
        return ERR_APPEXECFWK_UNINSTALL_SHARE_APP_LIBRARY_IS_NOT_EXIST;
    }

    dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr_) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    auto &mtx = dataMgr_->GetBundleMutex(bundleName);
    std::lock_guard lock {mtx};
    InnerBundleInfo info;
    if (!dataMgr_->GetInnerBundleInfo(bundleName, info)) {
        APP_LOGE("uninstall bundle info missing");
        return ERR_APPEXECFWK_UNINSTALL_SHARE_APP_LIBRARY_IS_NOT_EXIST;
    }
    ScopeGuard enableGuard([&] { dataMgr_->EnableBundle(bundleName); });
    ErrCode ret = CheckUninstallInnerBundleInfo(info, bundleName);
    if (ret != ERR_OK) {
        APP_LOGW("CheckUninstallInnerBundleInfo failed, errcode: %{public}d", ret);
        return ret;
    }
    if (dataMgr_->CheckHspVersionIsRelied(versionCode, info)) {
        APP_LOGE("uninstall shared library is relied");
        return ERR_APPEXECFWK_UNINSTALL_SHARE_APP_LIBRARY_IS_RELIED;
    }
    // if uninstallParam do not contain versionCode, versionCode is ALL_VERSIONCODE
    std::vector<uint32_t> versionCodes = info.GetAllHspVersion();
    if (versionCode != Constants::ALL_VERSIONCODE &&
        std::find(versionCodes.begin(), versionCodes.end(), versionCode) == versionCodes.end()) {
        APP_LOGE("input versionCode is not exist");
        return ERR_APPEXECFWK_UNINSTALL_SHARE_APP_LIBRARY_IS_NOT_EXIST;
    }
    std::string uninstallDir = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + bundleName;
    if ((versionCodes.size() > SINGLE_HSP_VERSION && versionCode == Constants::ALL_VERSIONCODE) ||
        versionCodes.size() == SINGLE_HSP_VERSION) {
        return UninstallHspBundle(uninstallDir, info.GetBundleName());
    } else {
        uninstallDir += Constants::PATH_SEPARATOR + HSP_VERSION_PREFIX + std::to_string(versionCode);
        return UninstallHspVersion(uninstallDir, versionCode, info);
    }
}

ErrCode BaseBundleInstaller::UninstallHspBundle(std::string &uninstallDir, const std::string &bundleName)
{
    APP_LOGD("begin to process hsp bundle %{public}s uninstall", bundleName.c_str());
    // remove bundle dir first, then delete data in bundle data manager
    ErrCode errCode;
     // delete bundle bunlde in data
    if (!dataMgr_->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START)) {
        APP_LOGE("uninstall start failed");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    if ((errCode = InstalldClient::GetInstance()->RemoveDir(uninstallDir)) != ERR_OK) {
        APP_LOGE("delete dir %{public}s failed!", uninstallDir.c_str());
        return errCode;
    }
    if (!dataMgr_->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_SUCCESS)) {
        APP_LOGE("update uninstall success failed");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(bundleName)) {
        APP_LOGW("bundleName: %{public}s delete appProvisionInfo failed.", bundleName.c_str());
    }
    InstallParam installParam;
    versionCode_ = Constants::ALL_VERSIONCODE;
    userId_ = Constants::ALL_USERID;
    SendBundleSystemEvent(
        bundleName,
        BundleEventType::UNINSTALL,
        installParam,
        sysEventInfo_.preBundleScene,
        errCode);
    PerfProfile::GetInstance().SetBundleUninstallEndTime(GetTickCount());
    /* remove sign profile from code signature for cross-app hsp */
    RemoveProfileFromCodeSign(bundleName);
    return ERR_OK;
}

ErrCode BaseBundleInstaller::UninstallHspVersion(std::string &uninstallDir, int32_t versionCode, InnerBundleInfo &info)
{
    APP_LOGD("begin to process hsp bundle %{public}s uninstall", info.GetBundleName().c_str());
    // remove bundle dir first, then delete data in innerBundleInfo
    ErrCode errCode;
    if (!dataMgr_->UpdateBundleInstallState(info.GetBundleName(), InstallState::UNINSTALL_START)) {
        APP_LOGE("uninstall start failed");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    if ((errCode = InstalldClient::GetInstance()->RemoveDir(uninstallDir)) != ERR_OK) {
        APP_LOGE("delete dir %{public}s failed!", uninstallDir.c_str());
        return errCode;
    }
    if (!dataMgr_->RemoveHspModuleByVersionCode(versionCode, info)) {
        APP_LOGE("remove hsp module by versionCode failed!");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    if (!dataMgr_->UpdateBundleInstallState(info.GetBundleName(), InstallState::INSTALL_SUCCESS)) {
        APP_LOGE("update install success failed");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    InstallParam installParam;
    versionCode_ = Constants::ALL_VERSIONCODE;
    userId_ = Constants::ALL_USERID;
    std::string bundleName = info.GetBundleName();
    SendBundleSystemEvent(
        bundleName,
        BundleEventType::UNINSTALL,
        installParam,
        sysEventInfo_.preBundleScene,
        errCode);
    PerfProfile::GetInstance().SetBundleUninstallEndTime(GetTickCount());
    return ERR_OK;
}

ErrCode BaseBundleInstaller::UninstallBundle(
    const std::string &bundleName, const std::string &modulePackage, const InstallParam &installParam)
{
    APP_LOGI("begin to process %{public}s module in %{public}s uninstall", modulePackage.c_str(), bundleName.c_str());
    PerfProfile::GetInstance().SetBundleUninstallStartTime(GetTickCount());

    // uninstall all sandbox app before
    UninstallAllSandboxApps(bundleName, installParam.userId);

    int32_t uid = Constants::INVALID_UID;
    bool isUninstalledFromBmsExtension = false;
    ErrCode result = ProcessBundleUninstall(bundleName, modulePackage, installParam, uid);
    if ((result == ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_BUNDLE) &&
        (UninstallBundleFromBmsExtension(bundleName) == ERR_OK)) {
        isUninstalledFromBmsExtension = true;
        result = ERR_OK;
    }
    if (installParam.needSendEvent && dataMgr_) {
        NotifyBundleEvents installRes = {
            .bundleName = bundleName,
            .modulePackage = modulePackage,
            .resultCode = result,
            .type = NotifyType::UNINSTALL_MODULE,
            .uid = uid,
            .accessTokenId = accessTokenId_,
            .isAgingUninstall = installParam.isAgingUninstall,
            .isBmsExtensionUninstalled = isUninstalledFromBmsExtension,
            .appId = uninstallBundleAppId_,
            .bundleType = static_cast<int32_t>(bundleType_)
        };
        if (NotifyBundleStatus(installRes) != ERR_OK) {
            APP_LOGW("notify status failed for installation");
        }
    }

    SendBundleSystemEvent(
        bundleName,
        BundleEventType::UNINSTALL,
        installParam,
        sysEventInfo_.preBundleScene,
        result);
    PerfProfile::GetInstance().SetBundleUninstallEndTime(GetTickCount());
    APP_LOGD("finish to process %{public}s module in %{public}s uninstall", modulePackage.c_str(), bundleName.c_str());
    return result;
}

bool BaseBundleInstaller::UninstallAppControl(const std::string &appId, int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
    std::vector<std::string> appIds;
    ErrCode ret = DelayedSingleton<AppControlManager>::GetInstance()->GetAppInstallControlRule(
        AppControlConstants::EDM_CALLING, AppControlConstants::APP_DISALLOWED_UNINSTALL, userId, appIds);
    if (ret != ERR_OK) {
        APP_LOGE("GetAppInstallControlRule failed code:%{public}d", ret);
        return true;
    }
    if (std::find(appIds.begin(), appIds.end(), appId) == appIds.end()) {
        return true;
    }
    APP_LOGW("appId is not removable");
    return false;
#else
    APP_LOGW("app control is disable");
    return true;
#endif
}

ErrCode BaseBundleInstaller::InstallNormalAppControl(
    const std::string &installAppId,
    int32_t userId,
    bool isPreInstallApp)
{
    APP_LOGD("InstallNormalAppControl start ");
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
    if (isPreInstallApp) {
        APP_LOGD("the preInstalled app does not support app control feature");
        return ERR_OK;
    }
    std::vector<std::string> allowedAppIds;
    ErrCode ret = DelayedSingleton<AppControlManager>::GetInstance()->GetAppInstallControlRule(
        AppControlConstants::EDM_CALLING, AppControlConstants::APP_ALLOWED_INSTALL, userId, allowedAppIds);
    if (ret != ERR_OK) {
        APP_LOGE("GetAppInstallControlRule allowedInstall failed code:%{public}d", ret);
        return ret;
    }

    std::vector<std::string> disallowedAppIds;
    ret = DelayedSingleton<AppControlManager>::GetInstance()->GetAppInstallControlRule(
        AppControlConstants::EDM_CALLING, AppControlConstants::APP_DISALLOWED_INSTALL, userId, disallowedAppIds);
    if (ret != ERR_OK) {
        APP_LOGE("GetAppInstallControlRule disallowedInstall failed code:%{public}d", ret);
        return ret;
    }

    // disallowed list and allowed list all empty.
    if (disallowedAppIds.empty() && allowedAppIds.empty()) {
        return ERR_OK;
    }

    // only allowed list empty.
    if (allowedAppIds.empty()) {
        if (std::find(disallowedAppIds.begin(), disallowedAppIds.end(), installAppId) != disallowedAppIds.end()) {
            APP_LOGE("disallowedAppIds:%{public}s is disallow install", installAppId.c_str());
            return ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_INSTALL;
        }
        return ERR_OK;
    }

    // only disallowed list empty.
    if (disallowedAppIds.empty()) {
        if (std::find(allowedAppIds.begin(), allowedAppIds.end(), installAppId) == allowedAppIds.end()) {
            APP_LOGE("allowedAppIds:%{public}s is disallow install", installAppId.c_str());
            return ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_INSTALL;
        }
        return ERR_OK;
    }

    // disallowed list and allowed list all not empty.
    if (std::find(allowedAppIds.begin(), allowedAppIds.end(), installAppId) == allowedAppIds.end()) {
        APP_LOGE("allowedAppIds:%{public}s is disallow install", installAppId.c_str());
        return ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_INSTALL;
    } else if (std::find(disallowedAppIds.begin(), disallowedAppIds.end(), installAppId) != disallowedAppIds.end()) {
        APP_LOGE("disallowedAppIds:%{public}s is disallow install", installAppId.c_str());
        return ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_INSTALL;
    }
    return ERR_OK;
#else
    APP_LOGW("app control is disable");
    return ERR_OK;
#endif
}

void BaseBundleInstaller::UpdateInstallerState(const InstallerState state)
{
    APP_LOGD("UpdateInstallerState in BaseBundleInstaller state %{public}d", state);
    SetInstallerState(state);
}

void BaseBundleInstaller::SaveOldRemovableInfo(
    InnerModuleInfo &newModuleInfo, InnerBundleInfo &oldInfo, bool existModule)
{
    if (existModule) {
        // save old module useId isRemovable info to new module
        auto oldModule = oldInfo.FetchInnerModuleInfos().find(newModuleInfo.modulePackage);
        if (oldModule == oldInfo.FetchInnerModuleInfos().end()) {
            APP_LOGE("can not find module %{public}s in oldInfo", newModuleInfo.modulePackage.c_str());
            return;
        }
        for (const auto &remove : oldModule->second.isRemovable) {
            auto result = newModuleInfo.isRemovable.try_emplace(remove.first, remove.second);
            if (!result.second) {
                APP_LOGE("%{public}s removable add %{public}s from old:%{public}d failed",
                    newModuleInfo.modulePackage.c_str(), remove.first.c_str(), remove.second);
            }
            APP_LOGD("%{public}s removable add %{public}s from old:%{public}d",
                newModuleInfo.modulePackage.c_str(), remove.first.c_str(), remove.second);
        }
    }
}

void BaseBundleInstaller::CheckEnableRemovable(std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    InnerBundleInfo &oldInfo, int32_t &userId, bool isFreeInstallFlag, bool isAppExist)
{
    for (auto &item : newInfos) {
        std::map<std::string, InnerModuleInfo> &moduleInfo = item.second.FetchInnerModuleInfos();
        bool hasInstalledInUser = oldInfo.HasInnerBundleUserInfo(userId);
        // now there are three cases for set haps isRemovable true:
        // 1. FREE_INSTALL flag
        // 2. bundle not exist in current user
        // 3. bundle exist, hap not exist
        // 4. hap exist not in current userId
        for (auto &iter : moduleInfo) {
            APP_LOGD("modulePackage:(%{public}s), userId:%{public}d, flag:%{public}d, isAppExist:%{public}d",
                iter.second.modulePackage.c_str(), userId, isFreeInstallFlag, isAppExist);
            bool existModule = oldInfo.FindModule(iter.second.modulePackage);
            bool hasModuleInUser = item.second.IsUserExistModule(iter.second.moduleName, userId);
            APP_LOGD("hasInstalledInUser:%{public}d, existModule:(%{public}d), hasModuleInUser:(%{public}d)",
                hasInstalledInUser, existModule, hasModuleInUser);
            if (isFreeInstallFlag && (!isAppExist || !hasInstalledInUser || !existModule || !hasModuleInUser)) {
                APP_LOGD("hasInstalledInUser:%{public}d, isAppExist:%{public}d existModule:(%{public}d)",
                    hasInstalledInUser, isAppExist, existModule);
                item.second.SetModuleRemovable(iter.second.moduleName, true, userId);
                SaveOldRemovableInfo(iter.second, oldInfo, existModule);
            }
        }
    }
}

bool BaseBundleInstaller::CheckDuplicateProxyData(const InnerBundleInfo &newInfo,
    const InnerBundleInfo &oldInfo)
{
    std::vector<ProxyData> proxyDatas;
    oldInfo.GetAllProxyDataInfos(proxyDatas);
    newInfo.GetAllProxyDataInfos(proxyDatas);
    return CheckDuplicateProxyData(proxyDatas);
}

bool BaseBundleInstaller::CheckDuplicateProxyData(const std::unordered_map<std::string, InnerBundleInfo> &newInfos)
{
    std::vector<ProxyData> proxyDatas;
    for (const auto &innerBundleInfo : newInfos) {
        innerBundleInfo.second.GetAllProxyDataInfos(proxyDatas);
    }
    return CheckDuplicateProxyData(proxyDatas);
}

bool BaseBundleInstaller::CheckDuplicateProxyData(const std::vector<ProxyData> &proxyDatas)
{
    std::set<std::string> uriSet;
    for (const auto &proxyData : proxyDatas) {
        if (!uriSet.insert(proxyData.uri).second) {
            APP_LOGE("uri %{public}s in proxyData is duplicated", proxyData.uri.c_str());
            return false;
        }
    }
    return true;
}

ErrCode BaseBundleInstaller::InnerProcessBundleInstall(std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    InnerBundleInfo &oldInfo, const InstallParam &installParam, int32_t &uid)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGI("InnerProcessBundleInstall with bundleName %{public}s, userId is %{public}d", bundleName_.c_str(),
        userId_);
    // try to get the bundle info to decide use install or update. Always keep other exceptions below this line.
    if (!GetInnerBundleInfo(oldInfo, isAppExist_)) {
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    APP_LOGI("flag:%{public}d, userId:%{public}d, isAppExist:%{public}d",
        installParam.installFlag, userId_, isAppExist_);

    ErrCode result = ERR_OK;
    result = CheckAppService(newInfos.begin()->second, oldInfo, isAppExist_);
    CHECK_RESULT(result, "Check appService failed %{public}d");

    if (installParam.needSavePreInstallInfo) {
        PreInstallBundleInfo preInstallBundleInfo;
        preInstallBundleInfo.SetBundleName(bundleName_);
        dataMgr_->GetPreInstallBundleInfo(bundleName_, preInstallBundleInfo);
        preInstallBundleInfo.SetAppType(newInfos.begin()->second.GetAppType());
        preInstallBundleInfo.SetVersionCode(newInfos.begin()->second.GetVersionCode());
        preInstallBundleInfo.SetIsUninstalled(false);
        for (const auto &item : newInfos) {
            preInstallBundleInfo.AddBundlePath(item.first);
        }
#ifdef USE_PRE_BUNDLE_PROFILE
        preInstallBundleInfo.SetRemovable(installParam.removable);
#else
        preInstallBundleInfo.SetRemovable(newInfos.begin()->second.GetRemovable());
#endif
        for (const auto &innerBundleInfo : newInfos) {
            auto applicationInfo = innerBundleInfo.second.GetBaseApplicationInfo();
            preInstallBundleInfo.SetLabelId(applicationInfo.labelResource.id);
            preInstallBundleInfo.SetIconId(applicationInfo.iconResource.id);
            preInstallBundleInfo.SetModuleName(applicationInfo.labelResource.moduleName);
            auto bundleInfo = innerBundleInfo.second.GetBaseBundleInfo();
            if (!bundleInfo.hapModuleInfos.empty() &&
                bundleInfo.hapModuleInfos[0].moduleType == ModuleType::ENTRY) {
                break;
            }
        }
        dataMgr_->SavePreInstallBundleInfo(bundleName_, preInstallBundleInfo);
    }

    result = CheckSingleton(newInfos.begin()->second, userId_);
    CHECK_RESULT(result, "Check singleton failed %{public}d");

    bool isFreeInstallFlag = (installParam.installFlag == InstallFlag::FREE_INSTALL);
    CheckEnableRemovable(newInfos, oldInfo, userId_, isFreeInstallFlag, isAppExist_);
    // check MDM self update
    result = CheckMDMUpdateBundleForSelf(installParam, oldInfo, newInfos, isAppExist_);
    CHECK_RESULT(result, "update MDM app failed %{public}d");

    if (isAppExist_) {
        SetAtomicServiceModuleUpgrade(oldInfo);
        if (oldInfo.GetApplicationBundleType() == BundleType::SHARED) {
            APP_LOGE("old bundle info is shared package");
            return ERR_APPEXECFWK_INSTALL_COMPATIBLE_POLICY_NOT_SAME;
        }

        result = CheckInstallationFree(oldInfo, newInfos);
        CHECK_RESULT(result, "CheckInstallationFree failed %{public}d");
        // to guarantee that the hap version can be compatible.
        result = CheckVersionCompatibility(oldInfo);
        CHECK_RESULT(result, "The app has been installed and update lower version bundle %{public}d");
        // to check native file between oldInfo and newInfos.
        result = CheckNativeFileWithOldInfo(oldInfo, newInfos);
        CHECK_RESULT(result, "Check native so between oldInfo and newInfos failed %{public}d");

        for (auto &info : newInfos) {
            std::string packageName = info.second.GetCurrentModulePackage();
            if (oldInfo.FindModule(packageName)) {
                installedModules_[packageName] = true;
            }
        }

        hasInstalledInUser_ = oldInfo.HasInnerBundleUserInfo(userId_);
        if (!hasInstalledInUser_) {
            APP_LOGD("new userInfo with bundleName %{public}s and userId %{public}d",
                bundleName_.c_str(), userId_);
            InnerBundleUserInfo newInnerBundleUserInfo;
            newInnerBundleUserInfo.bundleUserInfo.userId = userId_;
            newInnerBundleUserInfo.bundleName = bundleName_;
            oldInfo.AddInnerBundleUserInfo(newInnerBundleUserInfo);
            ScopeGuard userGuard([&] { RemoveBundleUserData(oldInfo, false); });
            Security::AccessToken::AccessTokenIDEx accessTokenIdEx;
            if (BundlePermissionMgr::InitHapToken(oldInfo, userId_, 0, accessTokenIdEx) != ERR_OK) {
                APP_LOGE("bundleName:%{public}s InitHapToken failed", bundleName_.c_str());
                return ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED;
            }
            accessTokenId_ = accessTokenIdEx.tokenIdExStruct.tokenID;
            oldInfo.SetAccessTokenIdEx(accessTokenIdEx, userId_);
            result = CreateBundleUserData(oldInfo);
            CHECK_RESULT(result, "CreateBundleUserData failed %{public}d");

            if (!isFeatureNeedUninstall_) {
                // extract ap file in old haps
                result = ExtractAllArkProfileFile(oldInfo, true);
                CHECK_RESULT(result, "ExtractAllArkProfileFile failed %{public}d");
            }

            userGuard.Dismiss();
        }
    }

    auto it = newInfos.begin();
    if (!isAppExist_) {
        APP_LOGI("app is not exist");
        InnerBundleInfo &newInfo = it->second;
        modulePath_ = it->first;
        InnerBundleUserInfo newInnerBundleUserInfo;
        newInnerBundleUserInfo.bundleUserInfo.userId = userId_;
        newInnerBundleUserInfo.bundleName = bundleName_;
        newInfo.AddInnerBundleUserInfo(newInnerBundleUserInfo);
        APP_LOGI("SetIsFreeInstallApp(%{public}d)", InstallFlag::FREE_INSTALL == installParam.installFlag);
        newInfo.SetIsFreeInstallApp(InstallFlag::FREE_INSTALL == installParam.installFlag);
        result = ProcessBundleInstallStatus(newInfo, uid);
        CHECK_RESULT(result, "ProcessBundleInstallStatus failed %{public}d");

        it++;
        hasInstalledInUser_ = true;
    }

    InnerBundleInfo bundleInfo;
    bool isBundleExist = false;
    if (!GetInnerBundleInfo(bundleInfo, isBundleExist) || !isBundleExist) {
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    InnerBundleUserInfo innerBundleUserInfo;
    if (!bundleInfo.GetInnerBundleUserInfo(userId_, innerBundleUserInfo)) {
        APP_LOGE("oldInfo do not have user");
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }

    ScopeGuard userGuard([&] {
        if (!hasInstalledInUser_ || (!isAppExist_)) {
            RemoveBundleUserData(oldInfo, false);
        }
    });

    // update haps
    for (; it != newInfos.end(); ++it) {
        // install entry module firstly
        APP_LOGD("update module %{public}s, entry module packageName is %{public}s",
            it->second.GetCurrentModulePackage().c_str(), entryModuleName_.c_str());
        if ((result = InstallEntryMoudleFirst(newInfos, bundleInfo, innerBundleUserInfo,
            installParam)) != ERR_OK) {
            APP_LOGE("install entry module failed due to error %{public}d", result);
            break;
        }
        if (it->second.GetCurrentModulePackage().compare(entryModuleName_) == 0) {
            APP_LOGD("enrty has been installed");
            continue;
        }
        modulePath_ = it->first;
        InnerBundleInfo &newInfo = it->second;
        newInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
        bool isReplace = (installParam.installFlag == InstallFlag::REPLACE_EXISTING ||
            installParam.installFlag == InstallFlag::FREE_INSTALL);
        // app exist, but module may not
        if ((result = ProcessBundleUpdateStatus(
            bundleInfo, newInfo, isReplace, installParam.noSkipsKill)) != ERR_OK) {
            break;
        }
    }

    if (result == ERR_OK) {
        userGuard.Dismiss();
    }

    uid = bundleInfo.GetUid(userId_);
    mainAbility_ = bundleInfo.GetMainAbility();
    return result;
}

void BaseBundleInstaller::SetAtomicServiceModuleUpgrade(const InnerBundleInfo &oldInfo)
{
    std::vector<std::string> moduleNames;
    oldInfo.GetModuleNames(moduleNames);
    for (const std::string &moduleName : moduleNames) {
        int32_t flag = static_cast<int32_t>(oldInfo.GetModuleUpgradeFlag(moduleName));
        if (flag) {
            atomicServiceModuleUpgrade_ = flag;
            return;
        }
    }
}

ErrCode BaseBundleInstaller::CheckAppService(
    const InnerBundleInfo &newInfo, const InnerBundleInfo &oldInfo, bool isAppExist)
{
    if ((newInfo.GetApplicationBundleType() == BundleType::APP_SERVICE_FWK) && !isAppExist) {
        APP_LOGW("Not alloweded instal appService hap(%{public}s) due to the hsp does not exist.",
            newInfo.GetBundleName().c_str());
        return ERR_APP_SERVICE_FWK_INSTALL_TYPE_FAILED;
    }

    if (isAppExist) {
        isAppService_ = oldInfo.GetApplicationBundleType() == BundleType::APP_SERVICE_FWK;
        if (isAppService_ && oldInfo.GetApplicationBundleType() != newInfo.GetApplicationBundleType()) {
            APP_LOGW("Bundle(%{public}s) type is not same.", newInfo.GetBundleName().c_str());
            return ERR_APPEXECFWK_BUNDLE_TYPE_NOT_SAME;
        }
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CheckSingleton(const InnerBundleInfo &info, const int32_t userId)
{
    if (isAppService_) {
        if (userId != Constants::DEFAULT_USERID) {
            APP_LOGW("appService(%{public}s) only install U0.", info.GetBundleName().c_str());
            return ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON;
        }

        return ERR_OK;
    }
    // singleton app can only be installed in U0 and U0 can only install singleton app.
    bool isSingleton = info.IsSingleton();
    if ((isSingleton && (userId != Constants::DEFAULT_USERID)) ||
        (!isSingleton && (userId == Constants::DEFAULT_USERID))) {
        APP_LOGW("singleton(%{public}d) app(%{public}s) and user(%{public}d) are not matched.",
            isSingleton, info.GetBundleName().c_str(), userId);
        return ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON;
    }

    return ERR_OK;
}

ErrCode BaseBundleInstaller::ProcessBundleInstall(const std::vector<std::string> &inBundlePaths,
    const InstallParam &installParam, const Constants::AppType appType, int32_t &uid)
{
    APP_LOGD("ProcessBundleInstall bundlePath install paths=%{public}s, hspPaths=%{public}s",
        GetJsonStrFromInfo(inBundlePaths).c_str(), GetJsonStrFromInfo(installParam.sharedBundleDirPaths).c_str());
    if (dataMgr_ == nullptr) {
        dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr_ == nullptr) {
            APP_LOGE("Get dataMgr shared_ptr nullptr");
            return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
        }
    }

    SharedBundleInstaller sharedBundleInstaller(installParam, appType);
    ErrCode result = sharedBundleInstaller.ParseFiles();
    CHECK_RESULT(result, "parse cross-app shared bundles failed %{public}d");

    if (inBundlePaths.empty() && sharedBundleInstaller.NeedToInstall()) {
        result = sharedBundleInstaller.Install(sysEventInfo_);
        sync();
        bundleType_ = BundleType::SHARED;
        APP_LOGI("install cross-app shared bundles only, result : %{public}d", result);
        return result;
    }

    userId_ = GetUserId(installParam.userId);
    result = CheckUserId(userId_);
    CHECK_RESULT(result, "userId check failed %{public}d");

    std::vector<std::string> bundlePaths;
    // check hap paths
    result = BundleUtil::CheckFilePath(inBundlePaths, bundlePaths);
    CHECK_RESULT(result, "hap file check failed %{public}d");
    UpdateInstallerState(InstallerState::INSTALL_BUNDLE_CHECKED);                  // ---- 5%

    // copy the haps to the dir which cannot be accessed from caller
    result = CopyHapsToSecurityDir(installParam, bundlePaths);
    CHECK_RESULT(result, "copy file failed %{public}d");

    // check syscap
    result = CheckSysCap(bundlePaths);
    CHECK_RESULT(result, "hap syscap check failed %{public}d");
    UpdateInstallerState(InstallerState::INSTALL_SYSCAP_CHECKED);                  // ---- 10%

    // verify signature info for all haps
    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    result = CheckMultipleHapsSignInfo(bundlePaths, installParam, hapVerifyResults);
    CHECK_RESULT(result, "hap files check signature info failed %{public}d");
    UpdateInstallerState(InstallerState::INSTALL_SIGNATURE_CHECKED);               // ---- 15%

    // parse the bundle infos for all haps
    // key is bundlePath , value is innerBundleInfo
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    result = ParseHapFiles(bundlePaths, installParam, appType, hapVerifyResults, newInfos);
    CHECK_RESULT(result, "parse haps file failed %{public}d");
    // washing machine judge
    for (const auto &infoIter: newInfos) {
        if (!infoIter.second.IsSystemApp() && !VerifyActivationLock()) {
            result = ERR_APPEXECFWK_INSTALL_FAILED_CONTROLLED;
            break;
        }
    }
    CHECK_RESULT(result, "check install verifyActivation failed %{public}d");
    result = CheckInstallPermission(installParam, hapVerifyResults);
    CHECK_RESULT(result, "check install permission failed %{public}d");
    result = CheckInstallCondition(hapVerifyResults, newInfos);
    CHECK_RESULT(result, "check install condition failed %{public}d");
    // check the dependencies whether or not exists
    result = CheckDependency(newInfos, sharedBundleInstaller);
    CHECK_RESULT(result, "check dependency failed %{public}d");
    // hapVerifyResults at here will not be empty
    verifyRes_ = hapVerifyResults[0];
    UpdateInstallerState(InstallerState::INSTALL_PARSED);                          // ---- 20%

    userId_ = GetConfirmUserId(userId_, newInfos);

    // check hap hash param
    result = CheckHapHashParams(newInfos, installParam.hashParams);
    CHECK_RESULT(result, "check hap hash param failed %{public}d");
    UpdateInstallerState(InstallerState::INSTALL_HAP_HASH_PARAM_CHECKED);         // ---- 25%

    // check overlay installation
    result = CheckOverlayInstallation(newInfos, userId_);
    CHECK_RESULT(result, "overlay hap check failed %{public}d");
    UpdateInstallerState(InstallerState::INSTALL_OVERLAY_CHECKED);                // ---- 30%

    // check app props in the configuration file
    result = CheckAppLabelInfo(newInfos);
    CHECK_RESULT(result, "verisoncode or bundleName is different in all haps %{public}d");
    UpdateInstallerState(InstallerState::INSTALL_VERSION_AND_BUNDLENAME_CHECKED);  // ---- 35%

    // to send notify of start install application
    sendStartInstallNotify(installParam, newInfos);

    // check if bundle exists in extension
    result = CheckBundleInBmsExtension(bundleName_, userId_);
    CHECK_RESULT(result, "bundle is already existed in bms extension %{public}d");

    // check native file
    result = CheckMultiNativeFile(newInfos);
    CHECK_RESULT(result, "native so is incompatible in all haps %{public}d");
    UpdateInstallerState(InstallerState::INSTALL_NATIVE_SO_CHECKED);               // ---- 40%

    // check proxy data
    result = CheckProxyDatas(newInfos);
    CHECK_RESULT(result, "proxy data check failed %{public}d");
    UpdateInstallerState(InstallerState::INSTALL_PROXY_DATA_CHECKED);              // ---- 45%

    // check hap is allow install by app control
    result = InstallNormalAppControl((newInfos.begin()->second).GetAppId(), userId_, installParam.isPreInstallApp);
    CHECK_RESULT(result, "install app control failed %{public}d");

    auto &mtx = dataMgr_->GetBundleMutex(bundleName_);
    std::lock_guard lock {mtx};

    // uninstall all sandbox app before
    UninstallAllSandboxApps(bundleName_);
    UpdateInstallerState(InstallerState::INSTALL_REMOVE_SANDBOX_APP);              // ---- 50%

    // this state should always be set when return
    ScopeGuard stateGuard([&] {
        dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_SUCCESS);
        dataMgr_->EnableBundle(bundleName_);
    });

    InnerBundleInfo oldInfo;
    verifyCodeParams_ = installParam.verifyCodeParams;
    pgoParams_ = installParam.pgoParams;
    copyHapToInstallPath_ = installParam.copyHapToInstallPath;
    result = InnerProcessBundleInstall(newInfos, oldInfo, installParam, uid);
    CHECK_RESULT_WITH_ROLLBACK(result, "internal processing failed with result %{public}d", newInfos, oldInfo);
    UpdateInstallerState(InstallerState::INSTALL_INFO_SAVED);                      // ---- 80%

    // copy hap or hsp to real install dir
    SaveHapPathToRecords(installParam.isPreInstallApp, newInfos);
    if (installParam.copyHapToInstallPath) {
        APP_LOGD("begin to copy hap to install path");
        result = SaveHapToInstallPath(newInfos);
        CHECK_RESULT_WITH_ROLLBACK(result, "copy hap to install path failed %{public}d", newInfos, oldInfo);
    }
    // delete old native library path
    if (NeedDeleteOldNativeLib(newInfos, oldInfo)) {
        APP_LOGI("Delete old library");
        DeleteOldNativeLibraryPath();
    }

    // move so file to real installation dir
    result = MoveSoFileToRealInstallationDir(newInfos);
    CHECK_RESULT_WITH_ROLLBACK(result, "move so file to install path failed %{public}d", newInfos, oldInfo);

    // attention pls, rename operation shoule be almost the last operation to guarantee the rollback operation
    // when someone failure occurs in the installation flow
    result = RenameAllTempDir(newInfos);
    CHECK_RESULT_WITH_ROLLBACK(result, "rename temp dirs failed with result %{public}d", newInfos, oldInfo);
    UpdateInstallerState(InstallerState::INSTALL_RENAMED);                         // ---- 90%

    // delete low-version hap or hsp when higher-version hap or hsp installed
    if (!uninstallModuleVec_.empty()) {
        UninstallLowerVersionFeature(uninstallModuleVec_, installParam.noSkipsKill);
    }

    // create data group dir
    ScopeGuard groupDirGuard([&] { DeleteGroupDirsForException(); });
    result = CreateDataGroupDirs(newInfos, oldInfo);
    CHECK_RESULT_WITH_ROLLBACK(result, "create data group dirs failed with result %{public}d", newInfos, oldInfo);

    GetExtensionDirsChange(newInfos, oldInfo);
    CreateNewExtensionDirs(newInfos);
    ScopeGuard extensionDirGuard([&] { RemoveCreatedExtensionDirsForException(); });

    // install cross-app hsp which has rollback operation in sharedBundleInstaller when some one failure occurs
    result = sharedBundleInstaller.Install(sysEventInfo_);
    CHECK_RESULT_WITH_ROLLBACK(result, "install cross-app shared bundles failed %{public}d", newInfos, oldInfo);

    std::shared_ptr driverInstaller = std::make_shared<DriverInstaller>();
    result = driverInstaller->CopyAllDriverFile(newInfos, oldInfo);
    CHECK_RESULT_WITH_ROLLBACK(result, "copy driver files failed due to error %{public}d", newInfos, oldInfo);

    UpdateInstallerState(InstallerState::INSTALL_SUCCESS);                         // ---- 100%
    APP_LOGD("finish ProcessBundleInstall bundlePath install touch off aging");
    moduleName_ = GetModuleNames(newInfos);
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
    if (installParam.installFlag == InstallFlag::FREE_INSTALL) {
        DelayedSingleton<BundleMgrService>::GetInstance()->GetAgingMgr()->Start(
            BundleAgingMgr::AgingTriggertype::FREE_INSTALL);
    }
#endif
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    if (needDeleteQuickFixInfo_) {
        APP_LOGD("module update, quick fix old patch need to delete, bundleName:%{public}s", bundleName_.c_str());
        if (!oldInfo.GetAppQuickFix().deployedAppqfInfo.hqfInfos.empty()) {
            APP_LOGD("InnerBundleInfo quickFixInfo need disable, bundleName:%{public}s", bundleName_.c_str());
            auto quickFixSwitcher = std::make_unique<QuickFixSwitcher>(bundleName_, false);
            quickFixSwitcher->Execute();
        }
        auto quickFixDeleter = std::make_unique<QuickFixDeleter>(bundleName_);
        quickFixDeleter->Execute();
    }
#endif
    GetInstallEventInfo(sysEventInfo_);
    AddAppProvisionInfo(bundleName_, hapVerifyResults[0].GetProvisionInfo(), installParam);
    ProcessOldNativeLibraryPath(newInfos, oldInfo.GetVersionCode(), oldInfo.GetNativeLibraryPath());
    ProcessAOT(installParam.isOTA, newInfos);
    RemoveOldHapIfOTA(installParam.isOTA, newInfos, oldInfo);
    UpdateAppInstallControlled(userId_);
    groupDirGuard.Dismiss();
    extensionDirGuard.Dismiss();
    RemoveOldGroupDirs();
    RemoveOldExtensionDirs();
    /* process quick fix when install new moudle */
    ProcessQuickFixWhenInstallNewModule(installParam, newInfos);
    BundleResourceHelper::AddResourceInfoByBundleName(bundleName_, userId_);
    VerifyDomain();
    ForceWriteToDisk();
    return result;
}

void BaseBundleInstaller::RollBack(const std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    InnerBundleInfo &oldInfo)
{
    APP_LOGD("start rollback due to install failed");
    if (!isAppExist_) {
        RemoveBundleAndDataDir(newInfos.begin()->second, false);
        // delete accessTokenId
        if (BundlePermissionMgr::DeleteAccessTokenId(newInfos.begin()->second.GetAccessTokenId(userId_)) !=
            AccessToken::AccessTokenKitRet::RET_SUCCESS) {
            APP_LOGE("delete accessToken failed");
        }

        // remove driver file
        std::shared_ptr driverInstaller = std::make_shared<DriverInstaller>();
        for (const auto &info : newInfos) {
            driverInstaller->RemoveDriverSoFile(info.second, "", false);
        }
        // remove profile from code signature
        RemoveProfileFromCodeSign(bundleName_);
        // remove innerBundleInfo
        RemoveInfo(bundleName_, "");
        return;
    }
    InnerBundleInfo preInfo;
    bool isExist = false;
    if (!GetInnerBundleInfo(preInfo, isExist) || !isExist) {
        APP_LOGI("finish rollback due to install failed");
        return;
    }
    for (const auto &info : newInfos) {
        RollBack(info.second, oldInfo);
    }
    // need delete definePermissions and requestPermissions
    UpdateHapToken(preInfo.GetAppType() != oldInfo.GetAppType(), oldInfo);
    APP_LOGD("finish rollback due to install failed");
}

void BaseBundleInstaller::RollBack(const InnerBundleInfo &info, InnerBundleInfo &oldInfo)
{
    // rollback hap installed
    std::shared_ptr driverInstaller = std::make_shared<DriverInstaller>();
    auto modulePackage = info.GetCurrentModulePackage();
    if (installedModules_[modulePackage]) {
        std::string createModulePath = info.GetAppCodePath() + Constants::PATH_SEPARATOR +
            modulePackage + Constants::TMP_SUFFIX;
        RemoveModuleDir(createModulePath);
        oldInfo.SetCurrentModulePackage(modulePackage);
        RollBackModuleInfo(bundleName_, oldInfo);
        // remove driver file of installed module
        driverInstaller->RemoveDriverSoFile(info, info.GetModuleName(modulePackage), true);
    } else {
        RemoveModuleDir(info.GetModuleDir(modulePackage));
        // remove driver file
        driverInstaller->RemoveDriverSoFile(info, info.GetModuleName(modulePackage), false);
        // remove module info
        RemoveInfo(bundleName_, modulePackage);
    }
}

void BaseBundleInstaller::RemoveInfo(const std::string &bundleName, const std::string &packageName)
{
    APP_LOGD("remove innerBundleInfo due to rollback");
    if (packageName.empty()) {
        dataMgr_->UpdateBundleInstallState(bundleName, InstallState::UPDATING_FAIL);
    } else {
        InnerBundleInfo innerBundleInfo;
        bool isExist = false;
        if (!GetInnerBundleInfo(innerBundleInfo, isExist) || !isExist) {
            APP_LOGI("finish rollback due to install failed");
            return;
        }
        dataMgr_->UpdateBundleInstallState(bundleName, InstallState::ROLL_BACK);
        dataMgr_->RemoveModuleInfo(bundleName, packageName, innerBundleInfo);
    }
    APP_LOGD("finish to remove innerBundleInfo due to rollback");
}

void BaseBundleInstaller::RollBackModuleInfo(const std::string &bundleName, InnerBundleInfo &oldInfo)
{
    APP_LOGD("rollBackMoudleInfo due to rollback");
    InnerBundleInfo innerBundleInfo;
    bool isExist = false;
    if (!GetInnerBundleInfo(innerBundleInfo, isExist) || !isExist) {
        return;
    }
    dataMgr_->UpdateBundleInstallState(bundleName, InstallState::ROLL_BACK);
    dataMgr_->UpdateInnerBundleInfo(bundleName, oldInfo, innerBundleInfo);
    APP_LOGD("finsih rollBackMoudleInfo due to rollback");
}

ErrCode BaseBundleInstaller::ProcessBundleUninstall(
    const std::string &bundleName, const InstallParam &installParam, int32_t &uid)
{
    APP_LOGD("start to process %{public}s bundle uninstall", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("uninstall bundle name empty");
        return ERR_APPEXECFWK_UNINSTALL_INVALID_NAME;
    }

    dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr_ == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    userId_ = GetUserId(installParam.userId);
    if (userId_ == Constants::INVALID_USERID) {
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    if (!dataMgr_->HasUserId(userId_)) {
        APP_LOGE("The user %{public}d does not exist when uninstall.", userId_);
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }

    auto &mtx = dataMgr_->GetBundleMutex(bundleName);
    std::lock_guard lock {mtx};
    InnerBundleInfo oldInfo;
    if (!dataMgr_->GetInnerBundleInfo(bundleName, oldInfo)) {
        APP_LOGW("uninstall bundle info missing");
        return ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_BUNDLE;
    }
    if (installParam.isUninstallAndRecover && !oldInfo.GetIsPreInstallApp()) {
        APP_LOGE("UninstallAndRecover bundle is not pre-install app.");
        return ERR_APPEXECFWK_UNINSTALL_AND_RECOVER_NOT_PREINSTALLED_BUNDLE;
    }
    bundleType_ = oldInfo.GetApplicationBundleType();
    uninstallBundleAppId_ = oldInfo.GetAppId();
    versionCode_ = oldInfo.GetVersionCode();
    ScopeGuard enableGuard([&] { dataMgr_->EnableBundle(bundleName); });
    if (oldInfo.GetApplicationBundleType() == BundleType::SHARED) {
        APP_LOGE("uninstall bundle is shared library.");
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_IS_SHARED_LIBRARY;
    }

    InnerBundleUserInfo curInnerBundleUserInfo;
    if (!oldInfo.GetInnerBundleUserInfo(userId_, curInnerBundleUserInfo)) {
        APP_LOGE("bundle(%{public}s) get user(%{public}d) failed when uninstall.",
            oldInfo.GetBundleName().c_str(), userId_);
        return ERR_APPEXECFWK_USER_NOT_INSTALL_HAP;
    }

    uid = curInnerBundleUserInfo.uid;
    if (!installParam.forceExecuted &&
        !oldInfo.GetRemovable() && installParam.noSkipsKill && !installParam.isUninstallAndRecover) {
        APP_LOGE("uninstall system app");
        return ERR_APPEXECFWK_UNINSTALL_SYSTEM_APP_ERROR;
    }

    if (!installParam.forceExecuted &&
        !oldInfo.GetUninstallState() && installParam.noSkipsKill && !installParam.isUninstallAndRecover) {
        APP_LOGE("bundle : %{public}s can not be uninstalled, uninstallState : %{public}d",
            bundleName.c_str(), oldInfo.GetUninstallState());
        return ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_UNINSTALL;
    }

    if (!UninstallAppControl(oldInfo.GetAppId(), userId_)) {
        APP_LOGE("bundleName: %{public}s is not allow uninstall", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_UNINSTALL;
    }

    // reboot scan case will not kill the bundle
    if (installParam.noSkipsKill) {
        // kill the bundle process during uninstall.
        if (!AbilityManagerHelper::UninstallApplicationProcesses(oldInfo.GetApplicationName(), uid)) {
            APP_LOGE("can not kill process, uid : %{public}d", uid);
            return ERR_APPEXECFWK_UNINSTALL_KILLING_APP_ERROR;
        }
    }

    auto res = RemoveDataGroupDirs(oldInfo.GetBundleName(), userId_);
    CHECK_RESULT(res, "RemoveDataGroupDirs failed %{public}d");
    RemoveBundleExtensionDir(oldInfo.GetBundleName());

    if (oldInfo.GetInnerBundleUserInfos().size() > 1) {
        APP_LOGD("only delete userinfo %{public}d", userId_);
        BundleResourceHelper::DeleteResourceInfo(bundleName, userId_);
        return RemoveBundleUserData(oldInfo, installParam.isKeepData);
    }

    if (!dataMgr_->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START)) {
        APP_LOGE("uninstall already start");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    std::string packageName;
    oldInfo.SetInstallMark(bundleName, packageName, InstallExceptionStatus::UNINSTALL_BUNDLE_START);
    if (!dataMgr_->SaveInnerBundleInfo(oldInfo)) {
        APP_LOGE("save install mark failed");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    ErrCode result = RemoveBundle(oldInfo, installParam.isKeepData);
    if (result != ERR_OK) {
        APP_LOGE("remove whole bundle failed");
        return result;
    }

    result = DeleteOldArkNativeFile(oldInfo);
    if (result != ERR_OK) {
        APP_LOGE("delete old arkNativeFile failed");
        return result;
    }

    result = DeleteArkProfile(bundleName, userId_);
    if (result != ERR_OK) {
        APP_LOGE("fail to removeArkProfile, error is %{public}d", result);
        return result;
    }

    result = DeleteShaderCache(bundleName);
    if (result != ERR_OK) {
        APP_LOGE("fail to DeleteShaderCache, error is %{public}d", result);
        return result;
    }

    if ((result = CleanAsanDirectory(oldInfo)) != ERR_OK) {
        APP_LOGE("fail to remove asan log path, error is %{public}d", result);
        return result;
    }

    enableGuard.Dismiss();
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    std::shared_ptr<QuickFixDataMgr> quickFixDataMgr = DelayedSingleton<QuickFixDataMgr>::GetInstance();
    if (quickFixDataMgr != nullptr) {
        APP_LOGD("DeleteInnerAppQuickFix when bundleName :%{public}s uninstall", bundleName.c_str());
        quickFixDataMgr->DeleteInnerAppQuickFix(bundleName);
    }
#endif
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->DeleteAppProvisionInfo(bundleName)) {
        APP_LOGW("bundleName: %{public}s delete appProvisionInfo failed.", bundleName.c_str());
    }
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
    std::shared_ptr<AppControlManager> appControlMgr = DelayedSingleton<AppControlManager>::GetInstance();
    if (appControlMgr != nullptr) {
        APP_LOGD("Delete disposed rule when bundleName :%{public}s uninstall", bundleName.c_str());
        appControlMgr->DeleteAllDisposedRuleByBundle(oldInfo.GetAppId(), userId_);
    }
#endif
    APP_LOGD("finish to process %{public}s bundle uninstall", bundleName.c_str());

    // remove drive so file
    std::shared_ptr driverInstaller = std::make_shared<DriverInstaller>();
    driverInstaller->RemoveDriverSoFile(oldInfo, "", false);
    if (oldInfo.GetIsPreInstallApp()) {
        MarkPreInstallState(bundleName, true);
    }
    BundleResourceHelper::DeleteResourceInfo(bundleName);
    // remove profile from code signature
    RemoveProfileFromCodeSign(bundleName);
    ClearDomainVerifyStatus(oldInfo.GetAppIdentifier(), bundleName);
    return ERR_OK;
}

ErrCode BaseBundleInstaller::ProcessBundleUninstall(
    const std::string &bundleName, const std::string &modulePackage, const InstallParam &installParam, int32_t &uid)
{
    APP_LOGD("start to process %{public}s in %{public}s uninstall", bundleName.c_str(), modulePackage.c_str());
    if (bundleName.empty() || modulePackage.empty()) {
        APP_LOGE("uninstall bundle name or module name empty");
        return ERR_APPEXECFWK_UNINSTALL_INVALID_NAME;
    }

    dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr_) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    userId_ = GetUserId(installParam.userId);
    if (userId_ == Constants::INVALID_USERID) {
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    if (!dataMgr_->HasUserId(userId_)) {
        APP_LOGE("The user %{public}d does not exist when uninstall.", userId_);
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }

    auto &mtx = dataMgr_->GetBundleMutex(bundleName);
    std::lock_guard lock {mtx};
    InnerBundleInfo oldInfo;
    if (!dataMgr_->GetInnerBundleInfo(bundleName, oldInfo)) {
        APP_LOGW("uninstall bundle info missing");
        return ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_BUNDLE;
    }
    uninstallBundleAppId_ = oldInfo.GetAppId();
    versionCode_ = oldInfo.GetVersionCode();
    ScopeGuard enableGuard([&] { dataMgr_->EnableBundle(bundleName); });
    if (oldInfo.GetApplicationBundleType() == BundleType::SHARED) {
        APP_LOGE("uninstall bundle is shared library");
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_IS_SHARED_LIBRARY;
    }

    InnerBundleUserInfo curInnerBundleUserInfo;
    if (!oldInfo.GetInnerBundleUserInfo(userId_, curInnerBundleUserInfo)) {
        APP_LOGE("bundle(%{public}s) get user(%{public}d) failed when uninstall.",
            oldInfo.GetBundleName().c_str(), userId_);
        return ERR_APPEXECFWK_USER_NOT_INSTALL_HAP;
    }

    uid = curInnerBundleUserInfo.uid;
    if (!installParam.forceExecuted
        && !oldInfo.GetRemovable() && installParam.noSkipsKill) {
        APP_LOGE("uninstall system app");
        return ERR_APPEXECFWK_UNINSTALL_SYSTEM_APP_ERROR;
    }

    if (!installParam.forceExecuted &&
        !oldInfo.GetUninstallState() && installParam.noSkipsKill && !installParam.isUninstallAndRecover) {
        APP_LOGE("bundle : %{public}s can not be uninstalled, uninstallState : %{public}d",
            bundleName.c_str(), oldInfo.GetUninstallState());
        return ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_UNINSTALL;
    }

    bool isModuleExist = oldInfo.FindModule(modulePackage);
    if (!isModuleExist) {
        APP_LOGE("uninstall bundle info missing");
        return ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_MODULE;
    }

    if (!UninstallAppControl(oldInfo.GetAppId(), userId_)) {
        APP_LOGD("bundleName: %{public}s is not allow uninstall", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_UNINSTALL;
    }

    if (!dataMgr_->UpdateBundleInstallState(bundleName, InstallState::UNINSTALL_START)) {
        APP_LOGE("uninstall already start");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    ScopeGuard stateGuard([&] { dataMgr_->UpdateBundleInstallState(bundleName, InstallState::INSTALL_SUCCESS); });

    // reboot scan case will not kill the bundle
    if (installParam.noSkipsKill) {
        // kill the bundle process during uninstall.
        if (!AbilityManagerHelper::UninstallApplicationProcesses(oldInfo.GetApplicationName(), uid)) {
            APP_LOGE("can not kill process, uid : %{public}d", uid);
            return ERR_APPEXECFWK_UNINSTALL_KILLING_APP_ERROR;
        }
    }

    oldInfo.SetInstallMark(bundleName, modulePackage, InstallExceptionStatus::UNINSTALL_PACKAGE_START);
    if (!dataMgr_->SaveInnerBundleInfo(oldInfo)) {
        APP_LOGE("save install mark failed");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    bool onlyInstallInUser = oldInfo.GetInnerBundleUserInfos().size() == 1;
    ErrCode result = ERR_OK;
    // if it is the only module in the bundle
    if (oldInfo.IsOnlyModule(modulePackage)) {
        APP_LOGI("%{public}s is only module", modulePackage.c_str());
        enableGuard.Dismiss();
        stateGuard.Dismiss();
        if (onlyInstallInUser) {
            result = RemoveBundle(oldInfo, installParam.isKeepData);
            if (result != ERR_OK) {
                APP_LOGE("remove bundle failed");
                return result;
            }
            // remove profile from code signature
            RemoveProfileFromCodeSign(bundleName);

            ClearDomainVerifyStatus(oldInfo.GetAppIdentifier(), bundleName);

            result = DeleteOldArkNativeFile(oldInfo);
            if (result != ERR_OK) {
                APP_LOGE("delete old arkNativeFile failed");
                return result;
            }

            result = DeleteArkProfile(bundleName, userId_);
            if (result != ERR_OK) {
                APP_LOGE("fail to removeArkProfile, error is %{public}d", result);
                return result;
            }

            if ((result = CleanAsanDirectory(oldInfo)) != ERR_OK) {
                APP_LOGE("fail to remove asan log path, error is %{public}d", result);
                return result;
            }

            if (oldInfo.GetIsPreInstallApp()) {
                MarkPreInstallState(bundleName, true);
            }

            return ERR_OK;
        }
        return RemoveBundleUserData(oldInfo, installParam.isKeepData);
    }

    if (onlyInstallInUser) {
        APP_LOGI("%{public}s is only install at the userId %{public}d", bundleName.c_str(), userId_);
        result = RemoveModuleAndDataDir(oldInfo, modulePackage, userId_, installParam.isKeepData);
    } else {
        if (!installParam.isKeepData) {
            result = RemoveModuleDataDir(oldInfo, modulePackage, userId_);
        }
    }

    if (result != ERR_OK) {
        APP_LOGE("remove module dir failed");
        return result;
    }

    oldInfo.SetInstallMark(bundleName, modulePackage, InstallExceptionStatus::INSTALL_FINISH);
    APP_LOGD("start to remove module info of %{public}s in %{public}s ", modulePackage.c_str(), bundleName.c_str());
    if (!dataMgr_->RemoveModuleInfo(bundleName, modulePackage, oldInfo)) {
        APP_LOGE("RemoveModuleInfo failed");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    std::shared_ptr driverInstaller = std::make_shared<DriverInstaller>();
    driverInstaller->RemoveDriverSoFile(oldInfo, oldInfo.GetModuleName(modulePackage), false);
    APP_LOGD("finish to process %{public}s in %{public}s uninstall", bundleName.c_str(), modulePackage.c_str());
    return ERR_OK;
}

void BaseBundleInstaller::MarkPreInstallState(const std::string &bundleName, bool isUninstalled)
{
    if (!dataMgr_) {
        APP_LOGE("dataMgr is nullptr");
        return;
    }

    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(bundleName);
    if (!dataMgr_->GetPreInstallBundleInfo(bundleName, preInstallBundleInfo)) {
        APP_LOGI("No PreInstallBundleInfo(%{public}s) in db", bundleName.c_str());
        return;
    }

    preInstallBundleInfo.SetIsUninstalled(isUninstalled);
    dataMgr_->SavePreInstallBundleInfo(bundleName, preInstallBundleInfo);
}

ErrCode BaseBundleInstaller::ProcessInstallBundleByBundleName(
    const std::string &bundleName, const InstallParam &installParam, int32_t &uid)
{
    APP_LOGD("Process Install Bundle(%{public}s) start", bundleName.c_str());
    return InnerProcessInstallByPreInstallInfo(bundleName, installParam, uid);
}

ErrCode BaseBundleInstaller::ProcessRecover(
    const std::string &bundleName, const InstallParam &installParam, int32_t &uid)
{
    APP_LOGD("Process Recover Bundle(%{public}s) start", bundleName.c_str());
    ErrCode result = InnerProcessInstallByPreInstallInfo(bundleName, installParam, uid);
    return result;
}

ErrCode BaseBundleInstaller::InnerProcessInstallByPreInstallInfo(
    const std::string &bundleName, const InstallParam &installParam, int32_t &uid)
{
    dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr_ == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr.");
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    userId_ = GetUserId(installParam.userId);
    if (userId_ == Constants::INVALID_USERID) {
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    if (!dataMgr_->HasUserId(userId_)) {
        APP_LOGE("The user %{public}d does not exist.", userId_);
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }

    {
        auto &mtx = dataMgr_->GetBundleMutex(bundleName);
        std::lock_guard lock {mtx};
        InnerBundleInfo oldInfo;
        bool isAppExist = dataMgr_->GetInnerBundleInfo(bundleName, oldInfo);
        if (isAppExist) {
            dataMgr_->EnableBundle(bundleName);
            if (oldInfo.GetApplicationBundleType() == BundleType::SHARED) {
                APP_LOGD("shared bundle (%{public}s) is irrelevant to user", bundleName.c_str());
                return ERR_OK;
            }

            versionCode_ = oldInfo.GetVersionCode();
            if (oldInfo.GetApplicationBundleType() == BundleType::APP_SERVICE_FWK) {
                APP_LOGD("Appservice (%{public}s) only install in U0", bundleName.c_str());
                return ERR_OK;
            }

            if (oldInfo.HasInnerBundleUserInfo(userId_)) {
                APP_LOGE("App is exist in user(%{public}d).", userId_);
                return ERR_APPEXECFWK_INSTALL_ALREADY_EXIST;
            }

            ErrCode ret = InstallNormalAppControl(oldInfo.GetAppId(), userId_, installParam.isPreInstallApp);
            if (ret != ERR_OK) {
                APP_LOGE("appid:%{private}s check install app control failed", oldInfo.GetAppId().c_str());
                return ret;
            }

            ret = CheckSingleton(oldInfo, userId_);
            CHECK_RESULT(ret, "Check singleton failed %{public}d");

            InnerBundleUserInfo curInnerBundleUserInfo;
            curInnerBundleUserInfo.bundleUserInfo.userId = userId_;
            curInnerBundleUserInfo.bundleName = bundleName;
            oldInfo.AddInnerBundleUserInfo(curInnerBundleUserInfo);
            ScopeGuard userGuard([&] { RemoveBundleUserData(oldInfo, false); });
            Security::AccessToken::AccessTokenIDEx accessTokenIdEx;
            if (BundlePermissionMgr::InitHapToken(oldInfo, userId_, 0, accessTokenIdEx) != ERR_OK) {
                APP_LOGE("bundleName:%{public}s InitHapToken failed", bundleName_.c_str());
                return ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED;
            }
            accessTokenId_ = accessTokenIdEx.tokenIdExStruct.tokenID;
            oldInfo.SetAccessTokenIdEx(accessTokenIdEx, userId_);

            auto result = CreateBundleUserData(oldInfo);
            if (result != ERR_OK) {
                return result;
            }

            // extract ap file
            result = ExtractAllArkProfileFile(oldInfo);
            if (result != ERR_OK) {
                return result;
            }

            userGuard.Dismiss();
            uid = oldInfo.GetUid(userId_);
            GetInstallEventInfo(oldInfo, sysEventInfo_);
            return ERR_OK;
        }
    }

    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(bundleName);
    if (!dataMgr_->GetPreInstallBundleInfo(bundleName, preInstallBundleInfo)
        || preInstallBundleInfo.GetBundlePaths().empty()) {
        APP_LOGE("Get PreInstallBundleInfo faile, bundleName: %{public}s.", bundleName.c_str());
        return ERR_APPEXECFWK_RECOVER_INVALID_BUNDLE_NAME;
    }

    APP_LOGD("Get preInstall bundlePath success.");
    std::vector<std::string> pathVec;
    auto innerInstallParam = installParam;
    bool isSharedBundle = preInstallBundleInfo.GetBundlePaths().front().find(PRE_INSTALL_HSP_PATH) != std::string::npos;
    if (isSharedBundle) {
        innerInstallParam.sharedBundleDirPaths = preInstallBundleInfo.GetBundlePaths();
    } else {
        pathVec = preInstallBundleInfo.GetBundlePaths();
    }
    innerInstallParam.isPreInstallApp = true;
    innerInstallParam.removable = preInstallBundleInfo.GetRemovable();
    innerInstallParam.copyHapToInstallPath = false;
    return ProcessBundleInstall(pathVec, innerInstallParam, preInstallBundleInfo.GetAppType(), uid);
}

ErrCode BaseBundleInstaller::RemoveBundle(InnerBundleInfo &info, bool isKeepData)
{
    if (!dataMgr_->UpdateBundleInstallState(info.GetBundleName(), InstallState::UNINSTALL_SUCCESS)) {
        APP_LOGE("delete inner info failed");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    ErrCode result = RemoveBundleAndDataDir(info, isKeepData);
    if (result != ERR_OK) {
        APP_LOGE("remove bundle dir failed");
        return result;
    }

    accessTokenId_ = info.GetAccessTokenId(userId_);
    if (BundlePermissionMgr::DeleteAccessTokenId(accessTokenId_) !=
        AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        APP_LOGE("delete accessToken failed");
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::ProcessBundleInstallStatus(InnerBundleInfo &info, int32_t &uid)
{
    modulePackage_ = info.GetCurrentModulePackage();
    APP_LOGD("ProcessBundleInstallStatus with bundleName %{public}s and packageName %{public}s",
        bundleName_.c_str(), modulePackage_.c_str());
    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_START)) {
        APP_LOGE("install already start");
        return ERR_APPEXECFWK_INSTALL_STATE_ERROR;
    }

    Security::AccessToken::AccessTokenIDEx accessTokenIdEx;
    if (BundlePermissionMgr::InitHapToken(info, userId_, 0, accessTokenIdEx) != ERR_OK) {
        APP_LOGE("bundleName:%{public}s InitHapToken failed", bundleName_.c_str());
        return ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED;
    }
    accessTokenId_ = accessTokenIdEx.tokenIdExStruct.tokenID;
    info.SetAccessTokenIdEx(accessTokenIdEx, userId_);

    info.SetInstallMark(bundleName_, modulePackage_, InstallExceptionStatus::INSTALL_START);
    if (!dataMgr_->SaveInnerBundleInfo(info)) {
        APP_LOGE("save install mark to storage failed");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    ScopeGuard stateGuard([&] { dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_FAIL); });
    ErrCode result = CreateBundleAndDataDir(info);
    if (result != ERR_OK) {
        APP_LOGE("create bundle and data dir failed");
        return result;
    }

    // delivery sign profile to code signature
    result = DeliveryProfileToCodeSign();
    CHECK_RESULT(result, "delivery profile failed %{public}d");

    ScopeGuard bundleGuard([&] { RemoveBundleAndDataDir(info, false); });
    std::string modulePath = info.GetAppCodePath() + Constants::PATH_SEPARATOR + modulePackage_;
    result = ExtractModule(info, modulePath);
    if (result != ERR_OK) {
        APP_LOGE("extract module failed");
        return result;
    }

    info.SetInstallMark(bundleName_, modulePackage_, InstallExceptionStatus::INSTALL_FINISH);
    uid = info.GetUid(userId_);
    info.SetBundleInstallTime(BundleUtil::GetCurrentTimeMs(), userId_);
    if (!dataMgr_->AddInnerBundleInfo(bundleName_, info)) {
        APP_LOGE("add bundle %{public}s info failed", bundleName_.c_str());
        dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UNINSTALL_START);
        dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UNINSTALL_SUCCESS);
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    stateGuard.Dismiss();
    bundleGuard.Dismiss();

    APP_LOGD("finish to call processBundleInstallStatus");
    return ERR_OK;
}

bool BaseBundleInstaller::AllowSingletonChange(const std::string &bundleName)
{
    return SINGLETON_WHITE_LIST.find(bundleName) != SINGLETON_WHITE_LIST.end();
}

ErrCode BaseBundleInstaller::ProcessBundleUpdateStatus(
    InnerBundleInfo &oldInfo, InnerBundleInfo &newInfo, bool isReplace, bool noSkipsKill)
{
    modulePackage_ = newInfo.GetCurrentModulePackage();
    if (modulePackage_.empty()) {
        APP_LOGE("get current package failed");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    if (isFeatureNeedUninstall_) {
        uninstallModuleVec_.emplace_back(modulePackage_);
    }

    if (oldInfo.IsSingleton() != newInfo.IsSingleton()) {
        if ((oldInfo.IsSingleton() && !newInfo.IsSingleton()) && newInfo.GetIsPreInstallApp()
            && AllowSingletonChange(newInfo.GetBundleName())) {
            singletonState_ = SingletonState::SINGLETON_TO_NON;
        } else if ((!oldInfo.IsSingleton() && newInfo.IsSingleton()) && newInfo.GetIsPreInstallApp()
            && AllowSingletonChange(newInfo.GetBundleName())) {
            singletonState_ = SingletonState::NON_TO_SINGLETON;
        } else {
            APP_LOGE("Singleton not allow changed");
            return ERR_APPEXECFWK_INSTALL_SINGLETON_INCOMPATIBLE;
        }
        APP_LOGI("Singleton %{public}s changed", newInfo.GetBundleName().c_str());
    }

    auto result = CheckOverlayUpdate(oldInfo, newInfo, userId_);
    if (result != ERR_OK) {
        APP_LOGE("CheckOverlayUpdate failed due to %{public}d", result);
        return result;
    }

    APP_LOGD("bundleName %{public}s, packageName %{public}s", newInfo.GetBundleName().c_str(), modulePackage_.c_str());
    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UPDATING_START)) {
        APP_LOGE("update already start");
        return ERR_APPEXECFWK_INSTALL_STATE_ERROR;
    }

    if (!CheckAppIdentifier(oldInfo, newInfo)) {
        return ERR_APPEXECFWK_INSTALL_FAILED_INCONSISTENT_SIGNATURE;
    }
    APP_LOGD("ProcessBundleUpdateStatus noSkipsKill = %{public}d", noSkipsKill);
    // now there are two cases for updating:
    // 1. bundle exist, hap exist, update hap
    // 2. bundle exist, install new hap
    bool isModuleExist = oldInfo.FindModule(modulePackage_);
    if (isModuleExist) {
        isModuleUpdate_ = true;
    }
    newInfo.RestoreFromOldInfo(oldInfo);
    result = isModuleExist ? ProcessModuleUpdate(newInfo, oldInfo,
        isReplace, noSkipsKill) : ProcessNewModuleInstall(newInfo, oldInfo);
    if (result != ERR_OK) {
        APP_LOGE("install module failed %{public}d", result);
        return result;
    }

    APP_LOGD("finish to call ProcessBundleUpdateStatus");
    return ERR_OK;
}

bool BaseBundleInstaller::CheckAppIdentifier(InnerBundleInfo &oldInfo, InnerBundleInfo &newInfo)
{
    if (!otaInstall_ && oldInfo.GetVersionCode() == newInfo.GetVersionCode()) {
        if ((oldInfo.GetAppIdentifier() != newInfo.GetAppIdentifier()) ||
            (oldInfo.GetProvisionId() != newInfo.GetProvisionId())) {
            APP_LOGE("same versionCode, appIdentifier or appId is not same");
            return false;
        }
    }

    if (oldInfo.GetAppIdentifier().empty() || newInfo.GetAppIdentifier().empty()) {
        if (oldInfo.GetProvisionId() != newInfo.GetProvisionId()) {
            APP_LOGE("the signature of the new bundle is not the same as old one");
            return false;
        }
        return true;
    }
    if (oldInfo.GetAppIdentifier() != newInfo.GetAppIdentifier()) {
        APP_LOGE("the appIdentifier of the new bundle is not the same as old one");
        return false;
    }
    return true;
}

ErrCode BaseBundleInstaller::ProcessNewModuleInstall(InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo)
{
    APP_LOGD("ProcessNewModuleInstall %{public}s, userId: %{public}d.",
        newInfo.GetBundleName().c_str(), userId_);
    if ((!isFeatureNeedUninstall_ && !otaInstall_) && (newInfo.HasEntry() && oldInfo.HasEntry())) {
        APP_LOGE("install more than one entry module");
        return ERR_APPEXECFWK_INSTALL_ENTRY_ALREADY_EXIST;
    }

    if ((!isFeatureNeedUninstall_ && !otaInstall_) &&
        bundleInstallChecker_->IsContainModuleName(newInfo, oldInfo)) {
        APP_LOGE("moduleName is already existed");
        return ERR_APPEXECFWK_INSTALL_NOT_UNIQUE_DISTRO_MODULE_NAME;
    }

    // same version need to check app label
    ErrCode result = ERR_OK;
    if (!otaInstall_ && (oldInfo.GetVersionCode() == newInfo.GetVersionCode())) {
        result = CheckAppLabel(oldInfo, newInfo);
        if (result != ERR_OK) {
            APP_LOGE("CheckAppLabel failed %{public}d", result);
            return result;
        }
        if (!CheckDuplicateProxyData(newInfo, oldInfo)) {
            APP_LOGE("CheckDuplicateProxyData with old info failed");
            return ERR_APPEXECFWK_INSTALL_CHECK_PROXY_DATA_URI_FAILED;
        }
    }

    oldInfo.SetInstallMark(bundleName_, modulePackage_, InstallExceptionStatus::UPDATING_NEW_START);
    if (!dataMgr_->SaveInnerBundleInfo(oldInfo)) {
        APP_LOGE("save install mark failed");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    std::string modulePath = newInfo.GetAppCodePath() + Constants::PATH_SEPARATOR + modulePackage_;
    result = ExtractModule(newInfo, modulePath);
    if (result != ERR_OK) {
        APP_LOGE("extract module and rename failed");
        return result;
    }
    ScopeGuard moduleGuard([&] { RemoveModuleDir(modulePath); });
    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UPDATING_SUCCESS)) {
        APP_LOGE("new moduleupdate state failed");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    oldInfo.SetInstallMark(bundleName_, modulePackage_, InstallExceptionStatus::INSTALL_FINISH);
    oldInfo.SetBundleUpdateTime(BundleUtil::GetCurrentTimeMs(), userId_);
    if ((result = ProcessAsanDirectory(newInfo)) != ERR_OK) {
        APP_LOGE("process asan log directory failed!");
        return result;
    }
    if (!dataMgr_->AddNewModuleInfo(bundleName_, newInfo, oldInfo)) {
        APP_LOGE(
            "add module %{public}s to innerBundleInfo %{public}s failed", modulePackage_.c_str(), bundleName_.c_str());
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    auto bundleUserInfos = oldInfo.GetInnerBundleUserInfos();
    for (const auto &info : bundleUserInfos) {
        if (info.second.accessTokenId == 0) {
            continue;
        }
        Security::AccessToken::AccessTokenIDEx tokenIdEx;
        tokenIdEx.tokenIDEx = info.second.accessTokenIdEx;
        if (BundlePermissionMgr::UpdateHapToken(tokenIdEx, oldInfo) != ERR_OK) {
            APP_LOGE("UpdateHapToken failed %{public}s", bundleName_.c_str());
            return ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED;
        }
    }
    moduleGuard.Dismiss();
    return ERR_OK;
}

ErrCode BaseBundleInstaller::ProcessModuleUpdate(InnerBundleInfo &newInfo,
    InnerBundleInfo &oldInfo, bool isReplace, bool noSkipsKill)
{
    APP_LOGD("ProcessModuleUpdate, bundleName : %{public}s, moduleName : %{public}s, userId: %{public}d.",
        newInfo.GetBundleName().c_str(), newInfo.GetCurrentModulePackage().c_str(), userId_);
    // update module type is forbidden
    if ((!isFeatureNeedUninstall_ && !otaInstall_) && (newInfo.HasEntry() && oldInfo.HasEntry())) {
        if (!oldInfo.IsEntryModule(modulePackage_)) {
            APP_LOGE("install more than one entry module");
            return ERR_APPEXECFWK_INSTALL_ENTRY_ALREADY_EXIST;
        }
    }

    if ((!isFeatureNeedUninstall_ && !otaInstall_) &&
        !bundleInstallChecker_->IsExistedDistroModule(newInfo, oldInfo)) {
        APP_LOGE("moduleName is inconsistent in the updating hap");
        return ERR_APPEXECFWK_INSTALL_INCONSISTENT_MODULE_NAME;
    }

    ErrCode result = ERR_OK;
    if (!otaInstall_ && (versionCode_ == oldInfo.GetVersionCode())) {
        if (((result = CheckAppLabel(oldInfo, newInfo)) != ERR_OK)) {
            APP_LOGE("CheckAppLabel failed %{public}d", result);
            return result;
        }

        if (!isReplace) {
            if (hasInstalledInUser_) {
                APP_LOGE("fail to install already existing bundle using normal flag");
                return ERR_APPEXECFWK_INSTALL_ALREADY_EXIST;
            }

            // app versionCode equals to the old and do not need to update module
            // and only need to update userInfo
            newInfo.SetOnlyCreateBundleUser(true);
            if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UPDATING_SUCCESS)) {
                APP_LOGE("update state failed");
                return ERR_APPEXECFWK_INSTALL_STATE_ERROR;
            }
            return ERR_OK;
        }
    }
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
    result = OverlayDataMgr::GetInstance()->UpdateOverlayModule(newInfo, oldInfo);
    CHECK_RESULT(result, "UpdateOverlayModule failed %{public}d");
#endif

    APP_LOGD("ProcessModuleUpdate noSkipsKill = %{public}d", noSkipsKill);
    // reboot scan case will not kill the bundle
    if (noSkipsKill) {
        // kill the bundle process during updating
        if (!AbilityManagerHelper::UninstallApplicationProcesses(
            oldInfo.GetApplicationName(), oldInfo.GetUid(userId_), true)) {
            APP_LOGE("fail to kill running application");
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
    }

    oldInfo.SetInstallMark(bundleName_, modulePackage_, InstallExceptionStatus::UPDATING_EXISTED_START);
    if (!dataMgr_->SaveInnerBundleInfo(oldInfo)) {
        APP_LOGE("save install mark failed");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    result = CheckArkProfileDir(newInfo, oldInfo);
    CHECK_RESULT(result, "CheckArkProfileDir failed %{public}d");

    result = ProcessAsanDirectory(newInfo);
    CHECK_RESULT(result, "process asan log directory failed %{public}d");

    moduleTmpDir_ = newInfo.GetAppCodePath() + Constants::PATH_SEPARATOR + modulePackage_ + Constants::TMP_SUFFIX;
    result = ExtractModule(newInfo, moduleTmpDir_);
    CHECK_RESULT(result, "extract module and rename failed %{public}d");

    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UPDATING_SUCCESS)) {
        APP_LOGE("old module update state failed");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    newInfo.RestoreModuleInfo(oldInfo);
    oldInfo.SetInstallMark(bundleName_, modulePackage_, InstallExceptionStatus::UPDATING_FINISH);
    oldInfo.SetBundleUpdateTime(BundleUtil::GetCurrentTimeMs(), userId_);
    bool needUpdateToken = newInfo.GetAppType() != oldInfo.GetAppType();
    if (!dataMgr_->UpdateInnerBundleInfo(bundleName_, newInfo, oldInfo)) {
        APP_LOGE("update innerBundleInfo %{public}s failed", bundleName_.c_str());
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    result = UpdateHapToken(needUpdateToken, oldInfo);
    CHECK_RESULT(result, "UpdateHapToken failed %{public}d");

    result = SetDirApl(oldInfo);
    CHECK_RESULT(result, "SetDirApl failed %{public}d");

    needDeleteQuickFixInfo_ = true;
    return ERR_OK;
}

void BaseBundleInstaller::ProcessQuickFixWhenInstallNewModule(const InstallParam &installParam,
    const std::unordered_map<std::string, InnerBundleInfo> &newInfos)
{
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    // hqf extract diff file or apply diff patch failed does not affect the hap installation
    InnerBundleInfo bundleInfo;
    bool isBundleExist = false;
    if (!GetInnerBundleInfo(bundleInfo, isBundleExist) || !isBundleExist) {
        return;
    }
    for (auto &info : newInfos) {
        modulePackage_ = info.second.GetCurrentModulePackage();
        if (!installedModules_[modulePackage_]) {
            modulePath_ = info.first;
            if (bundleInfo.IsEncryptedMoudle(modulePackage_) && installParam.copyHapToInstallPath) {
                modulePath_ = GetHapPath(info.second);
            }
            ProcessHqfInfo(bundleInfo, info.second);
        }
    }
#endif
}

void BaseBundleInstaller::ProcessHqfInfo(
    const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo) const
{
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    APP_LOGI("ProcessHqfInfo start, bundleName: %{public}s, moduleName: %{public}s", bundleName_.c_str(),
        modulePackage_.c_str());
    std::string cpuAbi;
    std::string nativeLibraryPath;
    if (!newInfo.FetchNativeSoAttrs(modulePackage_, cpuAbi, nativeLibraryPath)) {
        APP_LOGI("No native so, bundleName: %{public}s, moduleName: %{public}s", bundleName_.c_str(),
            modulePackage_.c_str());
        return;
    }
    auto pos = nativeLibraryPath.rfind(Constants::LIBS);
    if (pos != std::string::npos) {
        nativeLibraryPath = nativeLibraryPath.substr(pos, nativeLibraryPath.length() - pos);
    }

    ErrCode ret = ProcessDeployedHqfInfo(
        nativeLibraryPath, cpuAbi, newInfo, oldInfo.GetAppQuickFix());
    if (ret != ERR_OK) {
        APP_LOGW("ProcessDeployedHqfInfo failed, errcode: %{public}d", ret);
        return;
    }

    ret = ProcessDeployingHqfInfo(nativeLibraryPath, cpuAbi, newInfo);
    if (ret != ERR_OK) {
        APP_LOGW("ProcessDeployingHqfInfo failed, errcode: %{public}d", ret);
        return;
    }

    APP_LOGI("ProcessHqfInfo end");
#endif
}

ErrCode BaseBundleInstaller::ProcessDeployedHqfInfo(const std::string &nativeLibraryPath,
    const std::string &cpuAbi, const InnerBundleInfo &newInfo, const AppQuickFix &oldAppQuickFix) const
{
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    APP_LOGI("ProcessDeployedHqfInfo");
    auto appQuickFix = oldAppQuickFix;
    AppqfInfo &appQfInfo = appQuickFix.deployedAppqfInfo;
    if (isFeatureNeedUninstall_ || appQfInfo.hqfInfos.empty()) {
        APP_LOGI("No need ProcessDeployedHqfInfo");
        return ERR_OK;
    }

    ErrCode ret = ProcessDiffFiles(appQfInfo, nativeLibraryPath, cpuAbi);
    if (ret != ERR_OK) {
        APP_LOGE("ProcessDeployedHqfInfo failed, errcode: %{public}d", ret);
        return ret;
    }

    std::string newSoPath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + bundleName_ +
        Constants::PATH_SEPARATOR + Constants::PATCH_PATH +
        std::to_string(appQfInfo.versionCode) + Constants::PATH_SEPARATOR + nativeLibraryPath;
    bool isExist = false;
    if ((InstalldClient::GetInstance()->IsExistDir(newSoPath, isExist) != ERR_OK) || !isExist) {
        APP_LOGW("Patch no diff file");
        return ERR_OK;
    }

    ret = UpdateLibAttrs(newInfo, cpuAbi, nativeLibraryPath, appQfInfo);
    if (ret != ERR_OK) {
        APP_LOGE("UpdateModuleLib failed, errcode: %{public}d", ret);
        return ret;
    }

    InnerBundleInfo innerBundleInfo;
    if (!dataMgr_->FetchInnerBundleInfo(bundleName_, innerBundleInfo)) {
        APP_LOGE("Fetch bundleInfo(%{public}s) failed.", bundleName_.c_str());
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    innerBundleInfo.SetAppQuickFix(appQuickFix);
    if (!dataMgr_->UpdateQuickFixInnerBundleInfo(bundleName_, innerBundleInfo)) {
        APP_LOGE("update quickfix innerbundleInfo failed");
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
#endif
    return ERR_OK;
}

ErrCode BaseBundleInstaller::ProcessDeployingHqfInfo(
    const std::string &nativeLibraryPath, const std::string &cpuAbi, const InnerBundleInfo &newInfo) const
{
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    APP_LOGI("ProcessDeployingHqfInfo");
    std::shared_ptr<QuickFixDataMgr> quickFixDataMgr = DelayedSingleton<QuickFixDataMgr>::GetInstance();
    if (quickFixDataMgr == nullptr) {
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }

    InnerAppQuickFix innerAppQuickFix;
    if (!quickFixDataMgr->QueryInnerAppQuickFix(bundleName_, innerAppQuickFix)) {
        return ERR_OK;
    }

    auto appQuickFix = innerAppQuickFix.GetAppQuickFix();
    AppqfInfo &appQfInfo = appQuickFix.deployingAppqfInfo;
    ErrCode ret = ProcessDiffFiles(appQfInfo, nativeLibraryPath, cpuAbi);
    if (ret != ERR_OK) {
        APP_LOGE("ProcessDeployingHqfInfo failed, errcode: %{public}d", ret);
        return ret;
    }

    std::string newSoPath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + bundleName_ +
        Constants::PATH_SEPARATOR + Constants::PATCH_PATH +
        std::to_string(appQfInfo.versionCode) + Constants::PATH_SEPARATOR + nativeLibraryPath;
    bool isExist = false;
    if ((InstalldClient::GetInstance()->IsExistDir(newSoPath, isExist) != ERR_OK) || !isExist) {
        APP_LOGW("Patch no diff file");
        return ERR_OK;
    }

    ret = UpdateLibAttrs(newInfo, cpuAbi, nativeLibraryPath, appQfInfo);
    if (ret != ERR_OK) {
        APP_LOGE("UpdateModuleLib failed, errcode: %{public}d", ret);
        return ret;
    }

    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    if (!quickFixDataMgr->SaveInnerAppQuickFix(innerAppQuickFix)) {
        APP_LOGE("bundleName: %{public}s, inner app quick fix save failed", bundleName_.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_SAVE_APP_QUICK_FIX_FAILED;
    }
#endif
    return ERR_OK;
}

ErrCode BaseBundleInstaller::UpdateLibAttrs(const InnerBundleInfo &newInfo,
    const std::string &cpuAbi, const std::string &nativeLibraryPath, AppqfInfo &appQfInfo) const
{
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    auto newNativeLibraryPath = Constants::PATCH_PATH +
        std::to_string(appQfInfo.versionCode) + Constants::PATH_SEPARATOR + nativeLibraryPath;
    auto moduleName = newInfo.GetCurModuleName();
    bool isLibIsolated = newInfo.IsLibIsolated(moduleName);
    if (!isLibIsolated) {
        appQfInfo.nativeLibraryPath = newNativeLibraryPath;
        appQfInfo.cpuAbi = cpuAbi;
        return ERR_OK;
    }

    for (auto &hqfInfo : appQfInfo.hqfInfos) {
        if (hqfInfo.moduleName != moduleName) {
            continue;
        }

        hqfInfo.nativeLibraryPath = newNativeLibraryPath;
        hqfInfo.cpuAbi = cpuAbi;
        if (!BundleUtil::StartWith(appQfInfo.nativeLibraryPath, Constants::PATCH_PATH)) {
            appQfInfo.nativeLibraryPath.clear();
        }

        return ERR_OK;
    }

    return ERR_BUNDLEMANAGER_QUICK_FIX_MODULE_NAME_NOT_EXIST;
#else
    return ERR_OK;
#endif
}

bool BaseBundleInstaller::CheckHapLibsWithPatchLibs(
    const std::string &nativeLibraryPath, const std::string &hqfLibraryPath) const
{
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    if (!hqfLibraryPath.empty()) {
        auto position = hqfLibraryPath.find(Constants::PATH_SEPARATOR);
        if (position == std::string::npos) {
            return false;
        }

        auto newHqfLibraryPath = hqfLibraryPath.substr(position);
        if (!BundleUtil::EndWith(nativeLibraryPath, newHqfLibraryPath)) {
            APP_LOGE("error: nativeLibraryPath not same, newInfo: %{public}s, hqf: %{public}s",
                nativeLibraryPath.c_str(), newHqfLibraryPath.c_str());
            return false;
        }
    }
#endif
    return true;
}

bool BaseBundleInstaller::ExtractSoFiles(const std::string &soPath, const std::string &cpuAbi) const
{
    ExtractParam extractParam;
    extractParam.extractFileType = ExtractFileType::SO;
    extractParam.srcPath = modulePath_;
    extractParam.targetPath = soPath;
    extractParam.cpuAbi = cpuAbi;
    if (InstalldClient::GetInstance()->ExtractFiles(extractParam) != ERR_OK) {
        APP_LOGE("bundleName: %{public}s moduleName: %{public}s extract so failed", bundleName_.c_str(),
            modulePackage_.c_str());
        return false;
    }
    return true;
}

bool BaseBundleInstaller::ExtractEncryptedSoFiles(const InnerBundleInfo &info,
    const std::string &tmpSoPath, int32_t uid) const
{
    APP_LOGD("start to extract decoded so files to tmp path");
    std::string cpuAbi = "";
    std::string nativeLibraryPath = "";
    bool isSoExisted = info.FetchNativeSoAttrs(info.GetCurrentModulePackage(), cpuAbi, nativeLibraryPath);
    if (!isSoExisted) {
        APP_LOGD("so is not existed");
        return true;
    }
    std::string realSoFilesPath;
    if (info.IsCompressNativeLibs(info.GetCurModuleName())) {
        realSoFilesPath.append(Constants::BUNDLE_CODE_DIR).append(Constants::PATH_SEPARATOR)
            .append(bundleName_).append(Constants::PATH_SEPARATOR).append(nativeLibraryPath);
        if (realSoFilesPath.back() != Constants::PATH_SEPARATOR[0]) {
            realSoFilesPath += Constants::PATH_SEPARATOR;
        }
    }
    APP_LOGD("real so files path is %{public}s, tmpSoPath is %{public}s", realSoFilesPath.c_str(), tmpSoPath.c_str());
    return InstalldClient::GetInstance()->ExtractEncryptedSoFiles(modulePath_, realSoFilesPath, cpuAbi,
        tmpSoPath, uid) == ERR_OK;
}

ErrCode BaseBundleInstaller::ProcessDiffFiles(const AppqfInfo &appQfInfo, const std::string &nativeLibraryPath,
    const std::string &cpuAbi) const
{
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    const std::string moduleName = modulePackage_;
    auto iter = find_if(appQfInfo.hqfInfos.begin(), appQfInfo.hqfInfos.end(),
        [&moduleName](const auto &hqfInfo) {
        return hqfInfo.moduleName == moduleName;
    });
    if (iter != appQfInfo.hqfInfos.end()) {
        std::string oldSoPath = Constants::HAP_COPY_PATH + Constants::PATH_SEPARATOR +
            bundleName_ + Constants::TMP_SUFFIX + Constants::LIBS;
        ScopeGuard guardRemoveOldSoPath([oldSoPath] {InstalldClient::GetInstance()->RemoveDir(oldSoPath);});

        InnerBundleInfo innerBundleInfo;
        if (dataMgr_ == nullptr || !dataMgr_->FetchInnerBundleInfo(bundleName_, innerBundleInfo)) {
            APP_LOGE("Fetch bundleInfo(%{public}s) failed.", bundleName_.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST;
        }

        int32_t bundleUid = Constants::INVALID_UID;
        if (innerBundleInfo.IsEncryptedMoudle(modulePackage_)) {
            InnerBundleUserInfo innerBundleUserInfo;
            if (!innerBundleInfo.GetInnerBundleUserInfo(Constants::ALL_USERID, innerBundleUserInfo)) {
                APP_LOGE("no user info of bundle %{public}s", bundleName_.c_str());
                return ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST;
            }
            bundleUid = innerBundleUserInfo.uid;
            if (!ExtractEncryptedSoFiles(innerBundleInfo, oldSoPath, bundleUid)) {
                APP_LOGW("module:%{public}s has no so file", moduleName.c_str());
                return ERR_BUNDLEMANAGER_QUICK_FIX_EXTRACT_DIFF_FILES_FAILED;
            }
        } else {
            if (!ExtractSoFiles(oldSoPath, cpuAbi)) {
                return ERR_BUNDLEMANAGER_QUICK_FIX_EXTRACT_DIFF_FILES_FAILED;
            }
        }

        const std::string tempDiffPath = Constants::HAP_COPY_PATH + Constants::PATH_SEPARATOR +
            bundleName_ + Constants::TMP_SUFFIX;
        ScopeGuard removeDiffPath([tempDiffPath] { InstalldClient::GetInstance()->RemoveDir(tempDiffPath); });
        ErrCode ret = InstalldClient::GetInstance()->ExtractDiffFiles(iter->hqfFilePath, tempDiffPath, cpuAbi);
        if (ret != ERR_OK) {
            APP_LOGE("error: ExtractDiffFiles failed errcode :%{public}d", ret);
            return ERR_BUNDLEMANAGER_QUICK_FIX_EXTRACT_DIFF_FILES_FAILED;
        }

        std::string newSoPath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + bundleName_ +
            Constants::PATH_SEPARATOR + Constants::PATCH_PATH +
            std::to_string(appQfInfo.versionCode) + Constants::PATH_SEPARATOR + nativeLibraryPath;
        ret = InstalldClient::GetInstance()->ApplyDiffPatch(oldSoPath, tempDiffPath, newSoPath, bundleUid);
        if (ret != ERR_OK) {
            APP_LOGE("error: ApplyDiffPatch failed errcode :%{public}d", ret);
            return ERR_BUNDLEMANAGER_QUICK_FIX_APPLY_DIFF_PATCH_FAILED;
        }
    }
#endif
    return ERR_OK;
}

ErrCode BaseBundleInstaller::SetDirApl(const InnerBundleInfo &info)
{
    for (const auto &el : Constants::BUNDLE_EL) {
        std::string baseBundleDataDir = Constants::BUNDLE_APP_DATA_BASE_DIR +
                                        el +
                                        Constants::PATH_SEPARATOR +
                                        std::to_string(userId_);
        std::string baseDataDir = baseBundleDataDir + Constants::BASE + info.GetBundleName();
        bool isExist = true;
        ErrCode result = InstalldClient::GetInstance()->IsExistDir(baseDataDir, isExist);
        if (result != ERR_OK) {
            APP_LOGE("IsExistDir failed, error is %{public}d", result);
            return result;
        }
        if (!isExist) {
            APP_LOGD("baseDir: %{public}s is not exist", baseDataDir.c_str());
            continue;
        }
        result = InstalldClient::GetInstance()->SetDirApl(
            baseDataDir, info.GetBundleName(), info.GetAppPrivilegeLevel(), info.GetIsPreInstallApp(),
            info.GetBaseApplicationInfo().debug);
        if (result != ERR_OK) {
            APP_LOGE("fail to SetDirApl baseDir dir, error is %{public}d", result);
            return result;
        }
        std::string databaseDataDir = baseBundleDataDir + Constants::DATABASE + info.GetBundleName();
        result = InstalldClient::GetInstance()->SetDirApl(
            databaseDataDir, info.GetBundleName(), info.GetAppPrivilegeLevel(), info.GetIsPreInstallApp(),
            info.GetBaseApplicationInfo().debug);
        if (result != ERR_OK) {
            APP_LOGE("fail to SetDirApl databaseDir dir, error is %{public}d", result);
            return result;
        }
    }

    return ERR_OK;
}

ErrCode BaseBundleInstaller::CreateBundleAndDataDir(InnerBundleInfo &info) const
{
    ErrCode result = CreateBundleCodeDir(info);
    if (result != ERR_OK) {
        APP_LOGE("fail to create bundle code dir, error is %{public}d", result);
        return result;
    }
    ScopeGuard codePathGuard([&] { InstalldClient::GetInstance()->RemoveDir(info.GetAppCodePath()); });
    result = CreateBundleDataDir(info);
    if (result != ERR_OK) {
        APP_LOGE("fail to create bundle data dir, error is %{public}d", result);
        return result;
    }
    codePathGuard.Dismiss();
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CreateBundleCodeDir(InnerBundleInfo &info) const
{
    auto appCodePath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + bundleName_;
    APP_LOGD("create bundle dir %{public}s", appCodePath.c_str());
    ErrCode result = InstalldClient::GetInstance()->CreateBundleDir(appCodePath);
    if (result != ERR_OK) {
        APP_LOGE("fail to create bundle dir, error is %{public}d", result);
        return result;
    }

    info.SetAppCodePath(appCodePath);
    return ERR_OK;
}

static void SendToStorageQuota(const std::string &bundleName, const int uid,
    const std::string &bundleDataDirPath, const int limitSizeMb)
{
#ifdef STORAGE_SERVICE_ENABLE
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        APP_LOGW("SendToStorageQuota, systemAbilityManager error");
        return;
    }

    auto remote = systemAbilityManager->CheckSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        APP_LOGW("SendToStorageQuota, CheckSystemAbility error");
        return;
    }

    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        APP_LOGW("SendToStorageQuotactl, proxy get error");
        return;
    }

    int err = proxy->SetBundleQuota(bundleName, uid, bundleDataDirPath, limitSizeMb);
    if (err != ERR_OK) {
        APP_LOGW("SendToStorageQuota, SetBundleQuota error, err=%{public}d, uid=%{public}d", err, uid);
    }
#endif // STORAGE_SERVICE_ENABLE
}

static void PrepareBundleDirQuota(const std::string &bundleName, const int uid, const std::string &bundleDataDirPath)
{
    int32_t atomicserviceDatasizeThreshold = ATOMIC_SERVICE_DATASIZE_THRESHOLD_MB_PRESET;
#ifdef STORAGE_SERVICE_ENABLE
#ifdef QUOTA_PARAM_SET_ENABLE
    char szAtomicDatasizeThresholdMb[THRESHOLD_VAL_LEN] = {0};
    int32_t ret = GetParameter(SYSTEM_PARAM_ATOMICSERVICE_DATASIZE_THRESHOLD.c_str(), "",
        szAtomicDatasizeThresholdMb, THRESHOLD_VAL_LEN);
    if (ret <= 0) {
        APP_LOGI("GetParameter failed");
    } else if (strcmp(szAtomicDatasizeThresholdMb, "") != 0) {
        atomicserviceDatasizeThreshold = atoi(szAtomicDatasizeThresholdMb);
        APP_LOGI("InstalldQuotaUtils init atomicserviceDataThreshold mb success");
    }
    if (atomicserviceDatasizeThreshold <= 0) {
        APP_LOGW("no need to prepare quota");
        return;
    }
#endif // QUOTA_PARAM_SET_ENABLE
#endif // STORAGE_SERVICE_ENABLE
    SendToStorageQuota(bundleName, uid, bundleDataDirPath, atomicserviceDatasizeThreshold);
}

ErrCode BaseBundleInstaller::CreateBundleDataDir(InnerBundleInfo &info) const
{
    InnerBundleUserInfo newInnerBundleUserInfo;
    if (!info.GetInnerBundleUserInfo(userId_, newInnerBundleUserInfo)) {
        APP_LOGE("bundle(%{public}s) get user(%{public}d) failed.",
            info.GetBundleName().c_str(), userId_);
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }

    if (!dataMgr_->GenerateUidAndGid(newInnerBundleUserInfo)) {
        APP_LOGE("fail to generate uid and gid");
        return ERR_APPEXECFWK_INSTALL_GENERATE_UID_ERROR;
    }
    CreateDirParam createDirParam;
    createDirParam.bundleName = info.GetBundleName();
    createDirParam.userId = userId_;
    createDirParam.uid = newInnerBundleUserInfo.uid;
    createDirParam.gid = newInnerBundleUserInfo.uid;
    createDirParam.apl = info.GetAppPrivilegeLevel();
    createDirParam.isPreInstallApp = info.GetIsPreInstallApp();
    createDirParam.debug = info.GetBaseApplicationInfo().debug;

    auto result = InstalldClient::GetInstance()->CreateBundleDataDir(createDirParam);
    if (result != ERR_OK) {
        APP_LOGE("fail to create bundle data dir, error is %{public}d", result);
        return result;
    }
    if (info.GetApplicationBundleType() == BundleType::ATOMIC_SERVICE) {
        std::string bundleDataDir = Constants::BUNDLE_APP_DATA_BASE_DIR + Constants::BUNDLE_EL[1] +
            Constants::PATH_SEPARATOR + std::to_string(userId_) + Constants::BASE + info.GetBundleName();
        PrepareBundleDirQuota(info.GetBundleName(), newInnerBundleUserInfo.uid, bundleDataDir);
    }
    if (info.GetIsNewVersion()) {
        int32_t gid = (info.GetAppProvisionType() == Constants::APP_PROVISION_TYPE_DEBUG) ?
            GetIntParameter(BMS_KEY_SHELL_UID, Constants::SHELL_UID) :
            newInnerBundleUserInfo.uid;
        result = CreateArkProfile(
            info.GetBundleName(), userId_, newInnerBundleUserInfo.uid, gid);
        if (result != ERR_OK) {
            APP_LOGE("fail to create ark profile, error is %{public}d", result);
            return result;
        }
    }

    result = CreateShaderCache(info.GetBundleName(), createDirParam.uid, createDirParam.gid);
    if (result != ERR_OK) {
        APP_LOGW("fail to create shader cache, error is %{public}d", result);
    }

    // create asan log directory when asanEnabled is true
    // In update condition, delete asan log directory when asanEnabled is false if directory is exist
    if ((result = ProcessAsanDirectory(info)) != ERR_OK) {
        APP_LOGE("process asan log directory failed!");
        return result;
    }

    std::string dataBaseDir = Constants::BUNDLE_APP_DATA_BASE_DIR + Constants::BUNDLE_EL[1] +
        Constants::DATABASE + info.GetBundleName();
    info.SetAppDataBaseDir(dataBaseDir);
    info.AddInnerBundleUserInfo(newInnerBundleUserInfo);
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CreateDataGroupDirs(
    const std::unordered_map<std::string, InnerBundleInfo> &newInfos, const InnerBundleInfo &oldInfo)
{
    for (auto iter = newInfos.begin(); iter != newInfos.end(); iter++) {
        auto result = GetGroupDirsChange(iter->second, oldInfo, isAppExist_);
        CHECK_RESULT(result, "GetGroupDirsChange failed %{public}d");
    }
    auto result = CreateGroupDirs();
    CHECK_RESULT(result, "GetGroupDirsChange failed %{public}d");
    return ERR_OK;
}

ErrCode BaseBundleInstaller::GetGroupDirsChange(const InnerBundleInfo &info,
    const InnerBundleInfo &oldInfo, bool oldInfoExisted)
{
    if (oldInfoExisted) {
        auto result = GetRemoveDataGroupDirs(oldInfo, info);
        CHECK_RESULT(result, "GetRemoveDataGroupDirs failed %{public}d");
    }
    auto result = GetDataGroupCreateInfos(info);
    CHECK_RESULT(result, "GetDataGroupCreateInfos failed %{public}d");
    return ERR_OK;
}

ErrCode BaseBundleInstaller::GetRemoveDataGroupDirs(
    const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo)
{
    auto oldDataGroupInfos = oldInfo.GetDataGroupInfos();
    auto newDataGroupInfos = newInfo.GetDataGroupInfos();
    if (dataMgr_ == nullptr) {
        APP_LOGE("dataMgr_ is nullptr");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    for (auto &item : oldDataGroupInfos) {
        if (newDataGroupInfos.find(item.first) == newDataGroupInfos.end() &&
            !(dataMgr_->IsShareDataGroupId(item.first, userId_)) && !item.second.empty()) {
            std::string dir = Constants::REAL_DATA_PATH + Constants::PATH_SEPARATOR + std::to_string(userId_)
                + Constants::DATA_GROUP_PATH + item.second[0].uuid;
            APP_LOGD("remove dir: %{public}s", dir.c_str());
            removeGroupDirs_.emplace_back(dir);
        }
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::RemoveOldGroupDirs() const
{
    for (const std::string &dir : removeGroupDirs_) {
        APP_LOGD("RemoveOldGroupDirs %{public}s", dir.c_str());
        auto result = InstalldClient::GetInstance()->RemoveDir(dir);
        CHECK_RESULT(result, "RemoveDir failed %{public}d");
    }
    APP_LOGD("RemoveOldGroupDirs success");
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CreateGroupDirs() const
{
    for (const DataGroupInfo &dataGroupInfo : createGroupDirs_) {
        std::string dir = Constants::REAL_DATA_PATH + Constants::PATH_SEPARATOR + std::to_string(userId_)
            + Constants::DATA_GROUP_PATH + dataGroupInfo.uuid;
        APP_LOGD("create group dir: %{public}s", dir.c_str());
        auto result = InstalldClient::GetInstance()->Mkdir(dir,
            DATA_GROUP_DIR_MODE, dataGroupInfo.uid, dataGroupInfo.gid);
        CHECK_RESULT(result, "make groupDir failed %{public}d");
    }
    APP_LOGD("CreateGroupDirs success");
    return ERR_OK;
}

ErrCode BaseBundleInstaller::GetDataGroupCreateInfos(const InnerBundleInfo &newInfo)
{
    auto newDataGroupInfos = newInfo.GetDataGroupInfos();
    for (auto &item : newDataGroupInfos) {
        const std::string &dataGroupId = item.first;
        if (item.second.empty()) {
            APP_LOGE("dataGroupInfos in bundle: %{public}s is empty", newInfo.GetBundleName().c_str());
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
        std::string dir = Constants::REAL_DATA_PATH + Constants::PATH_SEPARATOR + std::to_string(userId_)
            + Constants::DATA_GROUP_PATH + item.second[0].uuid;
        bool dirExist = false;
        auto result = InstalldClient::GetInstance()->IsExistDir(dir, dirExist);
        CHECK_RESULT(result, "check IsExistDir failed %{public}d");
        if (!dirExist) {
            APP_LOGD("dir: %{public}s need to be created.", dir.c_str());
            createGroupDirs_.emplace_back(item.second[0]);
        }
    }
    return ERR_OK;
}

void BaseBundleInstaller::DeleteGroupDirsForException() const
{
    for (const DataGroupInfo &info : createGroupDirs_) {
        std::string dir = Constants::REAL_DATA_PATH + Constants::PATH_SEPARATOR + std::to_string(userId_)
            + Constants::DATA_GROUP_PATH + info.uuid;
        InstalldClient::GetInstance()->RemoveDir(dir);
    }
}

ErrCode BaseBundleInstaller::RemoveDataGroupDirs(const std::string &bundleName, int32_t userId) const
{
    std::vector<DataGroupInfo> infos;
    if (dataMgr_ == nullptr) {
        APP_LOGE("dataMgr_ is nullptr");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    if (!(dataMgr_->QueryDataGroupInfos(bundleName, userId, infos))) {
        return ERR_OK;
    }
    std::vector<std::string> removeDirs;
    for (auto iter = infos.begin(); iter != infos.end(); iter++) {
        std::string dir;
        if (!(dataMgr_->IsShareDataGroupId(iter->dataGroupId, userId)) &&
            dataMgr_->GetGroupDir(iter->dataGroupId, dir, userId)) {
            APP_LOGD("dir: %{public}s need to be deleted.", dir.c_str());
            removeDirs.emplace_back(dir);
        }
    }
    for (const std::string &dir : removeDirs) {
        auto result = InstalldClient::GetInstance()->RemoveDir(dir);
        CHECK_RESULT(result, "RemoveDir failed %{public}d");
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CreateArkProfile(
    const std::string &bundleName, int32_t userId, int32_t uid, int32_t gid) const
{
    ErrCode result = DeleteArkProfile(bundleName, userId);
    if (result != ERR_OK) {
        APP_LOGE("fail to removeArkProfile, error is %{public}d", result);
        return result;
    }

    std::string arkProfilePath;
    arkProfilePath.append(ARK_PROFILE_PATH).append(std::to_string(userId))
        .append(Constants::PATH_SEPARATOR).append(bundleName);
    APP_LOGI("CreateArkProfile %{public}s", arkProfilePath.c_str());
    int32_t mode = (uid == gid) ? S_IRWXU : (S_IRWXU | S_IRGRP | S_IXGRP);
    return InstalldClient::GetInstance()->Mkdir(arkProfilePath, mode, uid, gid);
}

ErrCode BaseBundleInstaller::DeleteArkProfile(const std::string &bundleName, int32_t userId) const
{
    std::string arkProfilePath;
    arkProfilePath.append(ARK_PROFILE_PATH).append(std::to_string(userId))
        .append(Constants::PATH_SEPARATOR).append(bundleName);
    APP_LOGI("DeleteArkProfile %{public}s", arkProfilePath.c_str());
    return InstalldClient::GetInstance()->RemoveDir(arkProfilePath);
}

ErrCode BaseBundleInstaller::ExtractModule(InnerBundleInfo &info, const std::string &modulePath)
{
    auto result = InnerProcessNativeLibs(info, modulePath);
    if (result != ERR_OK) {
        APP_LOGE("fail to InnerProcessNativeLibs, error is %{public}d", result);
        return result;
    }
    result = ExtractArkNativeFile(info, modulePath);
    if (result != ERR_OK) {
        APP_LOGE("fail to extractArkNativeFile, error is %{public}d", result);
        return result;
    }
    if (info.GetIsNewVersion()) {
        result = CopyPgoFileToArkProfileDir(modulePackage_, modulePath_, info.GetBundleName(), userId_);
        if (result != ERR_OK) {
            APP_LOGE("fail to CopyPgoFileToArkProfileDir, error is %{public}d", result);
            return result;
        }
    }

    ExtractResourceFiles(info, modulePath);

    result = ExtractResFileDir(modulePath);
    if (result != ERR_OK) {
        APP_LOGE("fail to ExtractResFileDir, error is %{public}d", result);
        return result;
    }

    if (info.GetIsPreInstallApp()) {
        info.SetModuleHapPath(modulePath_);
    } else {
        info.SetModuleHapPath(GetHapPath(info));
    }

    auto moduleDir = info.GetAppCodePath() + Constants::PATH_SEPARATOR + info.GetCurrentModulePackage();
    info.AddModuleSrcDir(moduleDir);
    info.AddModuleResPath(moduleDir);
    return ERR_OK;
}

void BaseBundleInstaller::ExtractResourceFiles(const InnerBundleInfo &info, const std::string &targetPath) const
{
    APP_LOGD("ExtractResourceFiles begin");
    int32_t apiTargetVersion = info.GetBaseApplicationInfo().apiTargetVersion;
    if (info.GetIsPreInstallApp() || apiTargetVersion > Constants::API_VERSION_NINE) {
        APP_LOGD("no need to extract resource files");
        return;
    }
    APP_LOGD("apiTargetVersion is %{public}d, extract resource files", apiTargetVersion);
    ExtractParam extractParam;
    extractParam.srcPath = modulePath_;
    extractParam.targetPath = targetPath + Constants::PATH_SEPARATOR;
    extractParam.extractFileType = ExtractFileType::RESOURCE;
    ErrCode ret = InstalldClient::GetInstance()->ExtractFiles(extractParam);
    APP_LOGD("ExtractResourceFiles ret : %{public}d", ret);
}

ErrCode BaseBundleInstaller::ExtractResFileDir(const std::string &modulePath) const
{
    APP_LOGD("ExtractResFileDir begin");
    ExtractParam extractParam;
    extractParam.srcPath = modulePath_;
    extractParam.targetPath = modulePath + Constants::PATH_SEPARATOR + Constants::RES_FILE_PATH;
    APP_LOGD("ExtractResFileDir targetPath: %{public}s", extractParam.targetPath.c_str());
    extractParam.extractFileType = ExtractFileType::RES_FILE;
    ErrCode ret = InstalldClient::GetInstance()->ExtractFiles(extractParam);
    if (ret != ERR_OK) {
        APP_LOGE("ExtractResFileDir ExtractFiles failed, error is %{public}d", ret);
        return ret;
    }
    APP_LOGD("ExtractResFileDir end");
    return ret;
}

ErrCode BaseBundleInstaller::ExtractArkNativeFile(InnerBundleInfo &info, const std::string &modulePath)
{
    if (!info.GetArkNativeFilePath().empty()) {
        APP_LOGD("Module %{public}s no need to extract an", modulePackage_.c_str());
        return ERR_OK;
    }

    std::string cpuAbi = info.GetArkNativeFileAbi();
    if (cpuAbi.empty()) {
        APP_LOGD("Module %{public}s no native file", modulePackage_.c_str());
        return ERR_OK;
    }

    if (Constants::ABI_MAP.find(cpuAbi) == Constants::ABI_MAP.end()) {
        APP_LOGE("No support %{public}s abi", cpuAbi.c_str());
        return ERR_APPEXECFWK_PARSE_AN_FAILED;
    }

    std::string arkNativeFilePath;
    arkNativeFilePath.append(Constants::ABI_MAP.at(cpuAbi)).append(Constants::PATH_SEPARATOR);
    std::string targetPath;
    targetPath.append(ARK_CACHE_PATH).append(info.GetBundleName())
        .append(Constants::PATH_SEPARATOR).append(arkNativeFilePath);
    APP_LOGD("Begin to extract an file, modulePath : %{public}s, targetPath : %{public}s, cpuAbi : %{public}s",
        modulePath.c_str(), targetPath.c_str(), cpuAbi.c_str());
    ExtractParam extractParam;
    extractParam.srcPath = modulePath_;
    extractParam.targetPath = targetPath;
    extractParam.cpuAbi = cpuAbi;
    extractParam.extractFileType = ExtractFileType::AN;
    auto result = InstalldClient::GetInstance()->ExtractFiles(extractParam);
    if (result != ERR_OK) {
        APP_LOGE("extract files failed, error is %{public}d", result);
        return result;
    }

    info.SetArkNativeFilePath(arkNativeFilePath);
    return ERR_OK;
}

ErrCode BaseBundleInstaller::ExtractAllArkProfileFile(const InnerBundleInfo &oldInfo, bool checkRepeat) const
{
    if (!oldInfo.GetIsNewVersion()) {
        return ERR_OK;
    }
    std::string bundleName = oldInfo.GetBundleName();
    APP_LOGI("Begin to ExtractAllArkProfileFile, bundleName : %{public}s", bundleName.c_str());
    const auto &innerModuleInfos = oldInfo.GetInnerModuleInfos();
    for (auto iter = innerModuleInfos.cbegin(); iter != innerModuleInfos.cend(); ++iter) {
        if (checkRepeat && installedModules_.find(iter->first) != installedModules_.end()) {
            continue;
        }

        ErrCode ret = CopyPgoFileToArkProfileDir(iter->second.name, iter->second.hapPath, bundleName, userId_);
        if (ret != ERR_OK) {
            APP_LOGE("fail to CopyPgoFileToArkProfileDir, error is %{public}d", ret);
            return ret;
        }
    }
    APP_LOGD("ExtractAllArkProfileFile succeed, bundleName : %{public}s", bundleName.c_str());
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CopyPgoFileToArkProfileDir(
    const std::string &moduleName,
    const std::string &modulePath,
    const std::string &bundleName,
    int32_t userId) const
{
    auto it = pgoParams_.find(moduleName);
    if (it != pgoParams_.end()) {
        return CopyPgoFile(moduleName, it->second, bundleName, userId);
    }
    return ExtractArkProfileFile(modulePath, bundleName, userId);
}

ErrCode BaseBundleInstaller::CopyPgoFile(
    const std::string &moduleName,
    const std::string &pgoPath,
    const std::string &bundleName,
    int32_t userId) const
{
    std::string targetPath;
    targetPath.append(ARK_PROFILE_PATH).append(std::to_string(userId))
        .append(Constants::PATH_SEPARATOR).append(bundleName)
        .append(Constants::PATH_SEPARATOR).append(moduleName)
        .append(Constants::AP_SUFFIX);
    if (InstalldClient::GetInstance()->CopyFile(pgoPath, targetPath) != ERR_OK) {
        APP_LOGE("copy file from %{public}s to %{public}s failed", pgoPath.c_str(), targetPath.c_str());
        return ERR_APPEXECFWK_INSTALL_COPY_HAP_FAILED;
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::ExtractArkProfileFile(
    const std::string &modulePath,
    const std::string &bundleName,
    int32_t userId) const
{
    std::string targetPath;
    targetPath.append(ARK_PROFILE_PATH).append(std::to_string(userId))
        .append(Constants::PATH_SEPARATOR).append(bundleName);
    APP_LOGD("Begin to extract ap file, modulePath : %{public}s, targetPath : %{public}s",
        modulePath.c_str(), targetPath.c_str());
    ExtractParam extractParam;
    extractParam.srcPath = modulePath;
    extractParam.targetPath = targetPath;
    extractParam.cpuAbi = Constants::EMPTY_STRING;
    extractParam.extractFileType = ExtractFileType::AP;
    auto result = InstalldClient::GetInstance()->ExtractFiles(extractParam);
    if (result != ERR_OK) {
        APP_LOGE("extract ap files failed, error is %{public}d", result);
        return result;
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::DeleteOldArkNativeFile(const InnerBundleInfo &oldInfo)
{
    std::string targetPath;
    targetPath.append(ARK_CACHE_PATH).append(oldInfo.GetBundleName());
    auto result = InstalldClient::GetInstance()->RemoveDir(targetPath);
    if (result != ERR_OK) {
        APP_LOGE("fail to remove arkNativeFilePath %{public}s, error is %{public}d",
            targetPath.c_str(), result);
    }

    return result;
}

ErrCode BaseBundleInstaller::RemoveBundleAndDataDir(const InnerBundleInfo &info, bool isKeepData) const
{
    ErrCode result = ERR_OK;
    if (!isKeepData) {
        result = RemoveBundleDataDir(info);
        if (result != ERR_OK) {
            APP_LOGE("fail to remove bundleData dir %{public}s, error is %{public}d",
                info.GetBundleName().c_str(), result);
            return result;
        }
    }
    // remove bundle dir
    result = RemoveBundleCodeDir(info);
    if (result != ERR_OK) {
        APP_LOGE("fail to remove bundle dir %{public}s, error is %{public}d", info.GetAppCodePath().c_str(), result);
        return result;
    }
    return result;
}

ErrCode BaseBundleInstaller::RemoveBundleCodeDir(const InnerBundleInfo &info) const
{
    auto result = InstalldClient::GetInstance()->RemoveDir(info.GetAppCodePath());
    if (result != ERR_OK) {
        APP_LOGE("fail to remove bundle code dir %{public}s, error is %{public}d",
            info.GetAppCodePath().c_str(), result);
    }
    return result;
}

ErrCode BaseBundleInstaller::RemoveBundleDataDir(const InnerBundleInfo &info) const
{
    ErrCode result =
        InstalldClient::GetInstance()->RemoveBundleDataDir(info.GetBundleName(), userId_);
    CHECK_RESULT(result, "RemoveBundleDataDir failed %{public}d");
    return result;
}

void BaseBundleInstaller::RemoveEmptyDirs(const std::unordered_map<std::string, InnerBundleInfo> &infos) const
{
    for (const auto &item : infos) {
        const InnerBundleInfo &info = item.second;
        std::string moduleDir = info.GetAppCodePath() + Constants::PATH_SEPARATOR + info.GetCurrentModulePackage();
        bool isDirEmpty = false;
        InstalldClient::GetInstance()->IsDirEmpty(moduleDir, isDirEmpty);
        if (isDirEmpty) {
            APP_LOGD("remove empty dir : %{public}s", moduleDir.c_str());
            InstalldClient::GetInstance()->RemoveDir(moduleDir);
        }
    }
}

std::string BaseBundleInstaller::GetModuleNames(const std::unordered_map<std::string, InnerBundleInfo> &infos) const
{
    if (infos.empty()) {
        return Constants::EMPTY_STRING;
    }
    std::string moduleNames;
    for (const auto &item : infos) {
        moduleNames.append(item.second.GetCurrentModulePackage()).append(Constants::MODULE_NAME_SEPARATOR);
    }
    moduleNames.pop_back();
    APP_LOGD("moduleNames : %{public}s", moduleNames.c_str());
    return moduleNames;
}

ErrCode BaseBundleInstaller::RemoveModuleAndDataDir(
    const InnerBundleInfo &info, const std::string &modulePackage, int32_t userId, bool isKeepData) const
{
    APP_LOGD("RemoveModuleAndDataDir with package name %{public}s", modulePackage.c_str());
    auto moduleDir = info.GetModuleDir(modulePackage);
    auto result = RemoveModuleDir(moduleDir);
    if (result != ERR_OK) {
        APP_LOGE("fail to remove module dir, error is %{public}d", result);
        return result;
    }

    // remove hap
    result = RemoveModuleDir(GetHapPath(info, info.GetModuleName(modulePackage)));
    if (result != ERR_OK) {
        APP_LOGE("fail to remove module hap, error is %{public}d", result);
        return result;
    }

    if (!isKeepData) {
        // uninstall hap remove current userId data dir
        if (userId != Constants::UNSPECIFIED_USERID) {
            RemoveModuleDataDir(info, modulePackage, userId);
            return ERR_OK;
        }

        // update hap remove all lower version data dir
        for (auto infoItem : info.GetInnerBundleUserInfos()) {
            int32_t installedUserId = infoItem.second.bundleUserInfo.userId;
            RemoveModuleDataDir(info, modulePackage, installedUserId);
        }
    }
    APP_LOGD("RemoveModuleAndDataDir successfully");
    return ERR_OK;
}

ErrCode BaseBundleInstaller::RemoveModuleDir(const std::string &modulePath) const
{
    APP_LOGD("module dir %{public}s to be removed", modulePath.c_str());
    return InstalldClient::GetInstance()->RemoveDir(modulePath);
}

ErrCode BaseBundleInstaller::RemoveModuleDataDir(
    const InnerBundleInfo &info, const std::string &modulePackage, int32_t userId) const
{
    APP_LOGD("RemoveModuleDataDir bundleName: %{public}s  modulePackage: %{public}s",
             info.GetBundleName().c_str(),
             modulePackage.c_str());
    auto hapModuleInfo = info.FindHapModuleInfo(modulePackage);
    if (!hapModuleInfo) {
        APP_LOGE("fail to findHapModule info modulePackage: %{public}s", modulePackage.c_str());
        return ERR_NO_INIT;
    }
    std::string moduleDataDir = info.GetBundleName() + Constants::HAPS + (*hapModuleInfo).moduleName;
    APP_LOGD("RemoveModuleDataDir moduleDataDir: %{public}s", moduleDataDir.c_str());
    auto result = InstalldClient::GetInstance()->RemoveModuleDataDir(moduleDataDir, userId);
    if (result != ERR_OK) {
        APP_LOGE("fail to remove HapModuleData dir, error is %{public}d", result);
    }
    return result;
}

ErrCode BaseBundleInstaller::ExtractModuleFiles(const InnerBundleInfo &info, const std::string &modulePath,
    const std::string &targetSoPath, const std::string &cpuAbi)
{
    APP_LOGD("extract module to %{public}s", modulePath.c_str());
    auto result = InstalldClient::GetInstance()->ExtractModuleFiles(modulePath_, modulePath, targetSoPath, cpuAbi);
    if (result != ERR_OK) {
        APP_LOGE("extract module files failed, error is %{public}d", result);
        return result;
    }

    return ERR_OK;
}

ErrCode BaseBundleInstaller::RenameModuleDir(const InnerBundleInfo &info) const
{
    auto moduleDir = info.GetAppCodePath() + Constants::PATH_SEPARATOR + info.GetCurrentModulePackage();
    APP_LOGD("rename module to %{public}s", moduleDir.c_str());
    auto result = InstalldClient::GetInstance()->RenameModuleDir(moduleDir + Constants::TMP_SUFFIX, moduleDir);
    if (result != ERR_OK) {
        APP_LOGE("rename module dir failed, error is %{public}d", result);
        return result;
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CheckSysCap(const std::vector<std::string> &bundlePaths)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    return bundleInstallChecker_->CheckSysCap(bundlePaths);
}

ErrCode BaseBundleInstaller::CheckMultipleHapsSignInfo(
    const std::vector<std::string> &bundlePaths,
    const InstallParam &installParam,
    std::vector<Security::Verify::HapVerifyResult>& hapVerifyRes)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    return bundleInstallChecker_->CheckMultipleHapsSignInfo(bundlePaths, hapVerifyRes);
}

ErrCode BaseBundleInstaller::ParseHapFiles(
    const std::vector<std::string> &bundlePaths,
    const InstallParam &installParam,
    const Constants::AppType appType,
    std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes,
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    InstallCheckParam checkParam;
    checkParam.isPreInstallApp = installParam.isPreInstallApp;
    checkParam.crowdtestDeadline = installParam.crowdtestDeadline;
    checkParam.specifiedDistributionType = installParam.specifiedDistributionType;
    checkParam.appType = appType;
    checkParam.removable = installParam.removable;
    ErrCode ret = bundleInstallChecker_->ParseHapFiles(
        bundlePaths, checkParam, hapVerifyRes, infos);
    if (ret != ERR_OK) {
        APP_LOGE("parse hap file failed due to errorCode : %{public}d", ret);
        return ret;
    }
    if (!infos.empty()) {
        bundleType_ = infos.begin()->second.GetApplicationBundleType();
    }
    GenerateOdid(infos, hapVerifyRes);
    ProcessDataGroupInfo(bundlePaths, infos, installParam.userId, hapVerifyRes);
    isContainEntry_ = bundleInstallChecker_->IsContainEntry();
    /* At this place, hapVerifyRes cannot be empty and unnecessary to check it */
    isEnterpriseBundle_ = bundleInstallChecker_->CheckEnterpriseBundle(hapVerifyRes[0]);
    appIdentifier_ = (hapVerifyRes[0].GetProvisionInfo().type == Security::Verify::ProvisionType::DEBUG) ?
        DEBUG_APP_IDENTIFIER : hapVerifyRes[0].GetProvisionInfo().bundleInfo.appIdentifier;
    SetAppDistributionType(infos);
    UpdateExtensionSandboxInfo(infos, hapVerifyRes);
    return ret;
}

void BaseBundleInstaller::UpdateExtensionSandboxInfo(std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes)
{
    if (newInfos.empty() || hapVerifyRes.empty()) {
        APP_LOGE("innerBundleInfo map or hapVerifyRes is empty");
        return;
    }
    Security::Verify::ProvisionInfo provisionInfo = hapVerifyRes.begin()->GetProvisionInfo();
    auto dataGroupGids = provisionInfo.bundleInfo.dataGroupIds;
    for (auto &item : newInfos) {
        auto innerBundleInfo = item.second;
        auto extensionInfoMap = innerBundleInfo.GetInnerExtensionInfos();
        for (auto iter = extensionInfoMap.begin(); iter != extensionInfoMap.end(); iter++) {
            if (!iter->second.needCreateSandbox) {
                continue;
            }
            std::string dir = Constants::REAL_DATA_PATH + Constants::PATH_SEPARATOR + std::to_string(userId_)
                            + DATA_EXTENSION_PATH
                            + iter->second.bundleName + Constants::PATH_SEPARATOR
                            + iter->second.moduleName + Constants::PATH_SEPARATOR
                            + iter->second.name;
            std::string key = iter->second.bundleName + "." + iter->second.moduleName + "." +  iter->second.name;

            std::vector<std::string> validGroupIds;
            GetValidDataGroupIds(iter->second.dataGroupIds, dataGroupGids, validGroupIds);
            APP_LOGI("extension %{public}s need to create dir on user %{public}d", iter->second.name.c_str(), userId_);
            item.second.UpdateExtensionDirInfo(key, userId_, dir, validGroupIds);
        }
    }
}

void BaseBundleInstaller::GetValidDataGroupIds(const std::vector<std::string> &extensionDataGroupIds,
    const std::vector<std::string> &bundleDataGroupIds, std::vector<std::string> &validGroupIds) const
{
    for (const std::string &dataGroupId : extensionDataGroupIds) {
        if (std::find(bundleDataGroupIds.begin(), bundleDataGroupIds.end(), dataGroupId) != bundleDataGroupIds.end()) {
            validGroupIds.emplace_back(dataGroupId);
        }
        APP_LOGI("dataGroupId %{public}s is invalid", dataGroupId.c_str());
    }
}

void BaseBundleInstaller::GetExtensionDirsChange(std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    const InnerBundleInfo &oldInfo)
{
    GetCreateExtensionDirs(newInfos);
    GetRemoveExtensionDirs(newInfos, oldInfo);
    CheckRemoveExtensionModuleDir(newInfos, oldInfo);
    CheckRemoveExtensionBundleDir(newInfos, oldInfo);
}

void BaseBundleInstaller::GetCreateExtensionDirs(std::unordered_map<std::string, InnerBundleInfo> &newInfos)
{
    for (auto &item : newInfos) {
        auto innerBundleInfo = item.second;
        auto moduleName = innerBundleInfo.GetCurModuleName();
        auto extensionDirSet = innerBundleInfo.GetAllExtensionDirsInSpecifiedModule(moduleName, userId_);
        for (const std::string &dir : extensionDirSet) {
            newExtensionDirs_.emplace_back(dir);
            bool dirExist = false;
            auto result = InstalldClient::GetInstance()->IsExistDir(dir, dirExist);
            if (result != ERR_OK || !dirExist) {
                APP_LOGI("dir: %{public}s need to be created.", dir.c_str());
                createExtensionDirs_.emplace_back(dir);
            }
        }
    }
}

void BaseBundleInstaller::GetRemoveExtensionDirs(
    std::unordered_map<std::string, InnerBundleInfo> &newInfos, const InnerBundleInfo &oldInfo)
{
    if (!isAppExist_) {
        // Install it for the first time
        return;
    }
    std::vector<std::string> oldModuleNames;
    oldInfo.GetModuleNames(oldModuleNames);
    std::vector<std::string> oldExtensionDirs;
    for (const std::string &oldModuleName : oldModuleNames) {
        auto dirSet = oldInfo.GetAllExtensionDirsInSpecifiedModule(oldModuleName, userId_);
        std::copy(dirSet.begin(), dirSet.end(), std::back_inserter(oldExtensionDirs));
    }
    if (isFeatureNeedUninstall_) {
        std::set<std::string> newModules;
        for (const auto &item : newInfos) {
            std::vector<std::string> curModules;
            item.second.GetModuleNames(curModules);
            newModules.insert(curModules.begin(), curModules.end());
        }
        for (const std::string &oldModuleName : oldModuleNames) {
            if (newModules.find(oldModuleName) == newModules.end()) {
                std::string dir = Constants::REAL_DATA_PATH + Constants::PATH_SEPARATOR + std::to_string(userId_)
                            + DATA_EXTENSION_PATH
                            + oldInfo.GetBundleName() + Constants::PATH_SEPARATOR
                            + oldModuleName;
                APP_LOGI("dir %{public}s need to be removed", dir.c_str());
                removeExtensionDirs_.emplace_back(dir);
            }
        }
    }
    std::set<std::string> newModuleNameSet;
    for (const auto& item : newInfos) {
        std::string modulePackage = item.second.GetCurrentModulePackage();
        if (!oldInfo.FindModule(modulePackage)) {
            // install a new module
            continue;
        }
        // update a existed module
        auto oldDirSet = oldInfo.GetAllExtensionDirsInSpecifiedModule(
            oldInfo.GetModuleNameByPackage(modulePackage), userId_);
        for (const std::string &oldDir : oldDirSet) {
            if (std::find(newExtensionDirs_.begin(), newExtensionDirs_.end(), oldDir) == newExtensionDirs_.end()) {
                APP_LOGI("dir %{public}s need to be removed", oldDir.c_str());
                removeExtensionDirs_.emplace_back(oldDir);
            }
        }
    }
}

void BaseBundleInstaller::CreateNewExtensionDirs(const std::unordered_map<std::string, InnerBundleInfo> &infos) const
{
    if (createExtensionDirs_.empty()) {
        APP_LOGD("no need to create extension sandbox dir");
        return;
    }
    if (infos.empty()) {
        APP_LOGE("innerBundleInfo infos is empty");
        return;
    }
    InnerBundleUserInfo newInnerBundleUserInfo;
    if (!infos.begin()->second.GetInnerBundleUserInfo(userId_, newInnerBundleUserInfo)) {
        APP_LOGE("bundle(%{public}s) get user(%{public}d) failed.",
            infos.begin()->second.GetBundleName().c_str(), userId_);
        return;
    }
    for (const std::string &dir : createExtensionDirs_) {
        APP_LOGI("create dir %{public}s", dir.c_str());
        auto result = InstalldClient::GetInstance()->Mkdir(
            dir, DATA_GROUP_DIR_MODE, newInnerBundleUserInfo.uid, newInnerBundleUserInfo.uid);
        if (result != ERR_OK) {
            APP_LOGW("create extension sandbox dir %{public}s failed.", dir.c_str());
            continue;
        }
    }
}

void BaseBundleInstaller::RemoveOldExtensionDirs() const
{
    if (removeExtensionDirs_.empty()) {
        APP_LOGD("no need to remove old extension sandbox dir");
        return;
    }
    for (const std::string &dir : removeExtensionDirs_) {
        APP_LOGI("remove dir %{public}s", dir.c_str());
        auto result = InstalldClient::GetInstance()->RemoveDir(dir);
        if (result != ERR_OK) {
            APP_LOGW("remove old extension sandbox dir %{public}s failed.", dir.c_str());
            continue;
        }
    }
}

void BaseBundleInstaller::CheckRemoveExtensionBundleDir(
    std::unordered_map<std::string, InnerBundleInfo> &newInfos, const InnerBundleInfo &oldInfo)
{
    if (!isAppExist_ || !newExtensionDirs_.empty()) {
        APP_LOGD("no need to remove extension dir for bundle");
        return;
    }
    std::string dir = Constants::REAL_DATA_PATH + Constants::PATH_SEPARATOR + std::to_string(userId_)
        + DATA_EXTENSION_PATH + oldInfo.GetBundleName();
    if (isFeatureNeedUninstall_) {
        if (!oldInfo.GetAllExtensionDirs(userId_).empty()) {
            removeExtensionDirs_.clear();
            APP_LOGI("need to remove extension dir for bundle, dir is %{public}s", dir.c_str());
            removeExtensionDirs_.emplace_back(dir);
        }
        return;
    }

    std::vector<std::string> oldModuleNames;
    oldInfo.GetModuleNames(oldModuleNames);
    std::set<std::string> curModules;
    for (const auto &item : newInfos) {
        curModules.insert(item.second.GetModuleNameByPackage(item.second.GetCurrentModulePackage()));
    }
    for (const std::string &moduleName : oldModuleNames) {
        if (curModules.find(moduleName) == curModules.end() &&
            !oldInfo.GetAllExtensionDirsInSpecifiedModule(moduleName, userId_).empty()) {
            return;
        }
    }
    removeExtensionDirs_.clear();
    APP_LOGI("need to remove extension dir for bundle, dir is %{public}s", dir.c_str());
    removeExtensionDirs_.emplace_back(dir);
}

void BaseBundleInstaller::CheckRemoveExtensionModuleDir(
    std::unordered_map<std::string, InnerBundleInfo> &newInfos, const InnerBundleInfo &oldInfo)
{
    if (!isAppExist_) {
        APP_LOGD("no need to remove extension dir for module");
        return;
    }
    std::vector<std::string> oldModuleNames;
    oldInfo.GetModuleNames(oldModuleNames);
    if (isFeatureNeedUninstall_) {
        CheckRemoveExtensionModuleDirWhenUpgrade(oldModuleNames, newInfos, oldInfo);
        return;
    }
    // version same, only folders created by currently installed modules will be affected
    for (const auto &item : newInfos) {
        std::string curModuleName = item.second.GetModuleNameByPackage(item.second.GetCurrentModulePackage());
        if (!item.second.GetAllExtensionDirsInSpecifiedModule(curModuleName, userId_).empty()) {
            continue;
        }
        // current module need not to create extension dir
        if (!oldInfo.GetAllExtensionDirsInSpecifiedModule(curModuleName, userId_).empty()) {
            std::string dir = Constants::REAL_DATA_PATH + Constants::PATH_SEPARATOR + std::to_string(userId_)
                    + DATA_EXTENSION_PATH + oldInfo.GetBundleName()
                    + curModuleName;
            APP_LOGI("need to remove extension dir for module, dir is %{public}s", dir.c_str());
            removeExtensionDirs_.emplace_back(dir);
        }
    }
}

void BaseBundleInstaller::CheckRemoveExtensionModuleDirWhenUpgrade(const std::vector<std::string> &oldModules,
    std::unordered_map<std::string, InnerBundleInfo> &newInfos, const InnerBundleInfo &oldInfo)
{
    // version update, folders created by other modules may be affected
    if (!isFeatureNeedUninstall_ || oldInfo.GetAllExtensionDirs(userId_).empty()) {
        return;
    }
    std::set<std::string> curModules;
    std::set<std::string> withExtensionModules;
    for (const auto &item : newInfos) {
        std::string moduleName = item.second.GetModuleNameByPackage(item.second.GetCurrentModulePackage());
        curModules.insert(moduleName);
        if (!item.second.GetAllExtensionDirsInSpecifiedModule(moduleName, userId_).empty()) {
            withExtensionModules.insert(moduleName);
        }
    }
    for (const std::string &moduleName : oldModules) {
        std::string dir = Constants::REAL_DATA_PATH + Constants::PATH_SEPARATOR + std::to_string(userId_)
                    + DATA_EXTENSION_PATH + oldInfo.GetBundleName()
                    + moduleName;
        if (oldInfo.GetAllExtensionDirsInSpecifiedModule(moduleName, userId_).empty()) {
            APP_LOGI("dir %{public}s not existed", dir.c_str());
            continue;
        }
        if (curModules.find(moduleName) == curModules.end() ||
            withExtensionModules.find(moduleName) == withExtensionModules.end()) {
            // after version upgrade： 1. without this module 2. this module need not to create sandbox dir
            APP_LOGI("need to remove extension dir for module, dir is %{public}s", dir.c_str());
            removeExtensionDirs_.emplace_back(dir);
        }
    }
}

void BaseBundleInstaller::RemoveCreatedExtensionDirsForException() const
{
    if (createExtensionDirs_.empty()) {
        APP_LOGI("no need to remove extension sandbox dir");
        return;
    }
    for (const std::string &dir : createExtensionDirs_) {
        auto result = InstalldClient::GetInstance()->RemoveDir(dir);
        if (result != ERR_OK) {
            APP_LOGW("remove created extension sandbox dir %{public}s failed.", dir.c_str());
            continue;
        }
    }
}

void BaseBundleInstaller::RemoveBundleExtensionDir(const std::string &bundleName) const
{
    if (bundleName.empty()) {
        APP_LOGW("bundleName is empty");
        return;
    }
    std::string dir =  Constants::REAL_DATA_PATH + Constants::PATH_SEPARATOR + std::to_string(userId_)
        + DATA_EXTENSION_PATH + bundleName;
    auto result = InstalldClient::GetInstance()->RemoveDir(dir);
    if (result != ERR_OK) {
        APP_LOGW("remove extension dir %{public}s failed", dir.c_str());
    }
}

void BaseBundleInstaller::SetAppDistributionType(const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    if (infos.empty()) {
        return;
    }
    appDistributionType_ = infos.begin()->second.GetAppDistributionType();
}

void BaseBundleInstaller::GenerateOdid(
    std::unordered_map<std::string, InnerBundleInfo> &infos,
    const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes) const
{
    if (hapVerifyRes.size() < infos.size() || infos.empty()) {
        APP_LOGE("hapVerifyRes size less than infos size or infos is empty");
        return;
    }
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return;
    }

    std::string developerId = hapVerifyRes[0].GetProvisionInfo().bundleInfo.developerId;
    if (developerId.empty()) {
        developerId = hapVerifyRes[0].GetProvisionInfo().bundleInfo.bundleName;
    }
    std::string odid;
    dataMgr->GenerateOdid(developerId, odid);

    for (auto &item : infos) {
        item.second.UpdateOdid(developerId, odid);
    }
}

void BaseBundleInstaller::ProcessDataGroupInfo(const std::vector<std::string> &bundlePaths,
    std::unordered_map<std::string, InnerBundleInfo> &infos,
    int32_t userId, const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes)
{
    if (hapVerifyRes.size() < bundlePaths.size()) {
        APP_LOGE("hapVerifyRes size less than bundlePaths size");
        return;
    }
    for (uint32_t i = 0; i < bundlePaths.size(); ++i) {
        Security::Verify::ProvisionInfo provisionInfo = hapVerifyRes[i].GetProvisionInfo();
        auto dataGroupGids = provisionInfo.bundleInfo.dataGroupIds;
        if (dataGroupGids.empty()) {
            APP_LOGD("has no data-group-id in provisionInfo");
            return;
        }
        std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr == nullptr) {
            APP_LOGE("Get dataMgr shared_ptr nullptr");
            return;
        }
        dataMgr->GenerateDataGroupInfos(infos[bundlePaths[i]], dataGroupGids, userId);
    }
}

ErrCode BaseBundleInstaller::CheckInstallCondition(
    std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes,
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    ErrCode ret = bundleInstallChecker_->CheckDeviceType(infos);
    if (ret != ERR_OK) {
        APP_LOGE("CheckDeviceType failed due to errorCode : %{public}d", ret);
        return ret;
    }
    ret = bundleInstallChecker_->CheckIsolationMode(infos);
    if (ret != ERR_OK) {
        APP_LOGE("CheckIsolationMode failed due to errorCode : %{public}d", ret);
        return ret;
    }
    ret = bundleInstallChecker_->CheckHspInstallCondition(hapVerifyRes);
    if (ret != ERR_OK) {
        APP_LOGE("CheckInstallCondition failed due to errorCode : %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CheckInstallPermission(const InstallParam &installParam,
    std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes)
{
    if ((installParam.installBundlePermissionStatus != PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS ||
        installParam.installEnterpriseBundlePermissionStatus != PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS ||
        installParam.installEtpNormalBundlePermissionStatus != PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS ||
        installParam.installEtpMdmBundlePermissionStatus != PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS ||
        installParam.installUpdateSelfBundlePermissionStatus != PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS) &&
        !bundleInstallChecker_->VaildInstallPermission(installParam, hapVerifyRes)) {
        // need vaild permission
        APP_LOGE("install permission denied");
        return ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED;
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CheckDependency(std::unordered_map<std::string, InnerBundleInfo> &infos,
    const SharedBundleInstaller &sharedBundleInstaller)
{
    for (const auto &info : infos) {
        if (!sharedBundleInstaller.CheckDependency(info.second)) {
            APP_LOGE("cross-app dependency check failed");
            return ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST;
        }
    }

    return bundleInstallChecker_->CheckDependency(infos);
}

ErrCode BaseBundleInstaller::CheckHapHashParams(
    std::unordered_map<std::string, InnerBundleInfo> &infos,
    std::map<std::string, std::string> hashParams)
{
    return bundleInstallChecker_->CheckHapHashParams(infos, hashParams);
}

ErrCode BaseBundleInstaller::CheckAppLabelInfo(const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    for (const auto &info : infos) {
        if (info.second.GetApplicationBundleType() == BundleType::SHARED) {
            APP_LOGE("installing cross-app shared library");
            return ERR_APPEXECFWK_INSTALL_FILE_IS_SHARED_LIBRARY;
        }
    }

    ErrCode ret = bundleInstallChecker_->CheckAppLabelInfo(infos);
    if (ret != ERR_OK) {
        return ret;
    }

    if (!CheckApiInfo(infos)) {
        APP_LOGE("CheckApiInfo failed.");
        return ERR_APPEXECFWK_INSTALL_SDK_INCOMPATIBLE;
    }

    bundleName_ = (infos.begin()->second).GetBundleName();
    versionCode_ = (infos.begin()->second).GetVersionCode();
    return ERR_OK;
}

bool BaseBundleInstaller::CheckApiInfo(const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    std::string compileSdkType = infos.begin()->second.GetBaseApplicationInfo().compileSdkType;
    auto bundleInfo = infos.begin()->second.GetBaseBundleInfo();
    if (compileSdkType == COMPILE_SDK_TYPE_OPEN_HARMONY) {
        return bundleInfo.compatibleVersion <= static_cast<uint32_t>(GetSdkApiVersion());
    }
    BmsExtensionDataMgr bmsExtensionDataMgr;
    return bmsExtensionDataMgr.CheckApiInfo(infos.begin()->second.GetBaseBundleInfo(),
        static_cast<uint32_t>(GetSdkApiVersion()));
}

ErrCode BaseBundleInstaller::CheckMultiNativeFile(
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    return bundleInstallChecker_->CheckMultiNativeFile(infos);
}

ErrCode BaseBundleInstaller::CheckProxyDatas(
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    if (!CheckDuplicateProxyData(infos)) {
        APP_LOGE("duplicated uri in proxyDatas");
        return ERR_APPEXECFWK_INSTALL_CHECK_PROXY_DATA_URI_FAILED;
    }
    for (const auto &info : infos) {
        ErrCode ret = bundleInstallChecker_->CheckProxyDatas(info.second);
        if (ret != ERR_OK) {
            return ret;
        }
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CheckMDMUpdateBundleForSelf(const InstallParam &installParam,
    InnerBundleInfo &oldInfo, const std::unordered_map<std::string, InnerBundleInfo> &newInfos, bool isAppExist)
{
    if (!installParam.isSelfUpdate) {
        return ERR_OK;
    }
    if (!OHOS::system::GetBoolParameter(Constants::ALLOW_ENTERPRISE_BUNDLE, false) &&
        !OHOS::system::GetBoolParameter(Constants::IS_ENTERPRISE_DEVICE, false) &&
        !OHOS::system::GetBoolParameter(Constants::DEVELOPERMODE_STATE, false)) {
        APP_LOGE("not enterprise device or developer mode is off");
        return ERR_APPEXECFWK_INSTALL_ENTERPRISE_BUNDLE_NOT_ALLOWED;
    }
    if (!isAppExist) {
        APP_LOGE("not self update");
        return ERR_APPEXECFWK_INSTALL_SELF_UPDATE_BUNDLENAME_NOT_SAME;
    }
    std::string appDistributionType = oldInfo.GetAppDistributionType();
    if (appDistributionType != Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM) {
        APP_LOGE("not mdm app");
        return ERR_APPEXECFWK_INSTALL_SELF_UPDATE_NOT_MDM;
    }
    std::string bundleName = oldInfo.GetBundleName();
    for (const auto &info : newInfos) {
        if (bundleName != info.second.GetBundleName()) {
            APP_LOGE("bundleName %{public}s not same", info.second.GetBundleName().c_str());
            return ERR_APPEXECFWK_INSTALL_SELF_UPDATE_BUNDLENAME_NOT_SAME;
        }
    }
    return ERR_OK;
}

bool BaseBundleInstaller::GetInnerBundleInfo(InnerBundleInfo &info, bool &isAppExist)
{
    if (dataMgr_ == nullptr) {
        dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr_ == nullptr) {
            APP_LOGE("Get dataMgr shared_ptr nullptr");
            return false;
        }
    }
    isAppExist = dataMgr_->GetInnerBundleInfo(bundleName_, info);
    return true;
}

ErrCode BaseBundleInstaller::CheckVersionCompatibility(const InnerBundleInfo &oldInfo)
{
    if (oldInfo.GetEntryInstallationFree()) {
        return CheckVersionCompatibilityForHmService(oldInfo);
    }
    return CheckVersionCompatibilityForApplication(oldInfo);
}

// In the process of hap updating, the version code of the entry hap which is about to be updated must not less the
// version code of the current entry haps in the device; if no-entry hap in the device, the updating haps should
// have same version code with the current version code; if the no-entry haps is to be updated, which should has the
// same version code with that of the entry hap in the device.
ErrCode BaseBundleInstaller::CheckVersionCompatibilityForApplication(const InnerBundleInfo &oldInfo)
{
    APP_LOGD("start to check version compatibility for application");
    if (oldInfo.HasEntry()) {
        if (isContainEntry_ && versionCode_ < oldInfo.GetVersionCode()) {
            APP_LOGE("fail to update lower version bundle");
            return ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE;
        }
        if (!isContainEntry_ && versionCode_ > oldInfo.GetVersionCode()) {
            APP_LOGE("version code is not compatible");
            return ERR_APPEXECFWK_INSTALL_VERSION_NOT_COMPATIBLE;
        }
        if (!isContainEntry_ && versionCode_ < oldInfo.GetVersionCode()) {
            APP_LOGE("version code is not compatible");
            return ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE;
        }
    } else {
        if (versionCode_ < oldInfo.GetVersionCode()) {
            APP_LOGE("fail to update lower version bundle");
            return ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE;
        }
    }

    if (versionCode_ > oldInfo.GetVersionCode()) {
        if (oldInfo.GetApplicationBundleType() == BundleType::APP_SERVICE_FWK) {
            APP_LOGE("Not alloweded instal appService hap(%{public}s) due to the hsp does not exist.",
                oldInfo.GetBundleName().c_str());
            return ERR_APP_SERVICE_FWK_INSTALL_TYPE_FAILED;
        }
        APP_LOGD("need to uninstall lower version feature hap");
        isFeatureNeedUninstall_ = true;
    }
    APP_LOGD("finish to check version compatibility for application");
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CheckVersionCompatibilityForHmService(const InnerBundleInfo &oldInfo)
{
    APP_LOGD("start to check version compatibility for hm service");
    if (versionCode_ < oldInfo.GetVersionCode()) {
        APP_LOGE("fail to update lower version bundle");
        return ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE;
    }
    if (versionCode_ > oldInfo.GetVersionCode()) {
        APP_LOGD("need to uninstall lower version hap");
        isFeatureNeedUninstall_ = true;
    }
    APP_LOGD("finish to check version compatibility for hm service");
    return ERR_OK;
}

ErrCode BaseBundleInstaller::UninstallLowerVersionFeature(const std::vector<std::string> &packageVec, bool noSkipsKill)
{
    APP_LOGD("start to uninstall lower version feature hap");
    InnerBundleInfo info;
    bool isExist = false;
    if (!GetInnerBundleInfo(info, isExist) || !isExist) {
        return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UNINSTALL_START)) {
        APP_LOGE("uninstall already start");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    // kill the bundle process during uninstall.
    if (noSkipsKill) {
        if (!AbilityManagerHelper::UninstallApplicationProcesses(
            info.GetApplicationName(), info.GetUid(userId_), true)) {
            APP_LOGW("can not kill process");
        }
    }

    std::vector<std::string> moduleVec = info.GetModuleNameVec();
    InnerBundleInfo oldInfo = info;
    for (const auto &package : moduleVec) {
        if (find(packageVec.begin(), packageVec.end(), package) == packageVec.end()) {
            APP_LOGD("uninstall package %{public}s", package.c_str());
            ErrCode result = RemoveModuleAndDataDir(info, package, Constants::UNSPECIFIED_USERID, true);
            if (result != ERR_OK) {
                APP_LOGE("remove module dir failed");
                return result;
            }

            // remove driver file
            std::shared_ptr driverInstaller = std::make_shared<DriverInstaller>();
            driverInstaller->RemoveDriverSoFile(info, info.GetModuleName(package), false);

            if (!dataMgr_->RemoveModuleInfo(bundleName_, package, info)) {
                APP_LOGE("RemoveModuleInfo failed");
                return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
            }
        }
    }
    // need to delete lower version feature hap definePermissions and requestPermissions
    APP_LOGD("delete lower version feature hap definePermissions and requestPermissions");
    ErrCode ret = UpdateHapToken(oldInfo.GetAppType() != info.GetAppType(), info);
    CHECK_RESULT(ret, "UpdateHapToken failed %{public}d");
    needDeleteQuickFixInfo_ = true;
    APP_LOGD("finish to uninstall lower version feature hap");
    return ERR_OK;
}

int32_t BaseBundleInstaller::GetConfirmUserId(
    const int32_t &userId, std::unordered_map<std::string, InnerBundleInfo> &newInfos)
{
    if (userId != Constants::UNSPECIFIED_USERID || newInfos.size() <= 0) {
        return userId;
    }

    bool isSingleton = newInfos.begin()->second.IsSingleton();
    APP_LOGI("The userId is Unspecified and app is singleton(%{public}d) when install.",
        static_cast<int32_t>(isSingleton));
    return isSingleton ? Constants::DEFAULT_USERID : AccountHelper::GetCurrentActiveUserId();
}

ErrCode BaseBundleInstaller::CheckUserId(const int32_t &userId) const
{
    if (userId == Constants::UNSPECIFIED_USERID) {
        return ERR_OK;
    }

    if (!dataMgr_->HasUserId(userId)) {
        APP_LOGE("The user %{public}d does not exist when install.", userId);
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }

    return ERR_OK;
}

int32_t BaseBundleInstaller::GetUserId(const int32_t &userId) const
{
    if (userId == Constants::UNSPECIFIED_USERID) {
        return userId;
    }

    if (userId < Constants::DEFAULT_USERID) {
        APP_LOGE("userId(%{public}d) is invalid.", userId);
        return Constants::INVALID_USERID;
    }

    APP_LOGD("BundleInstaller GetUserId, now userId is %{public}d", userId);
    return userId;
}

ErrCode BaseBundleInstaller::CreateBundleUserData(InnerBundleInfo &innerBundleInfo)
{
    APP_LOGI("CreateNewUserData %{public}s userId: %{public}d.",
        innerBundleInfo.GetBundleName().c_str(), userId_);
    if (!innerBundleInfo.HasInnerBundleUserInfo(userId_)) {
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }

    ErrCode result = CreateBundleDataDir(innerBundleInfo);
    if (result != ERR_OK) {
        RemoveBundleDataDir(innerBundleInfo);
        return result;
    }

    innerBundleInfo.SetBundleInstallTime(BundleUtil::GetCurrentTimeMs(), userId_);
    InnerBundleUserInfo innerBundleUserInfo;
    if (!innerBundleInfo.GetInnerBundleUserInfo(userId_, innerBundleUserInfo)) {
        APP_LOGE("oldInfo do not have user");
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }

#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
    OverlayDataMgr::GetInstance()->AddOverlayModuleStates(innerBundleInfo, innerBundleUserInfo);
#endif

    if (!dataMgr_->AddInnerBundleUserInfo(innerBundleInfo.GetBundleName(), innerBundleUserInfo)) {
        APP_LOGE("update bundle user info to db failed %{public}s when createNewUser",
            innerBundleInfo.GetBundleName().c_str());
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    return ERR_OK;
}

ErrCode BaseBundleInstaller::UninstallAllSandboxApps(const std::string &bundleName, int32_t userId)
{
    // All sandbox will be uninstalled when the original application is updated or uninstalled
    APP_LOGD("UninstallAllSandboxApps begin");
    if (bundleName.empty()) {
        APP_LOGE("UninstallAllSandboxApps failed due to empty bundle name");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }
    auto helper = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    if (helper == nullptr) {
        APP_LOGE("UninstallAllSandboxApps failed due to helper nullptr");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    if (helper->UninstallAllSandboxApps(bundleName, userId) != ERR_OK) {
        APP_LOGW("UninstallAllSandboxApps failed");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    APP_LOGD("UninstallAllSandboxApps finish");
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CheckNativeFileWithOldInfo(
    const InnerBundleInfo &oldInfo, std::unordered_map<std::string, InnerBundleInfo> &newInfos)
{
    APP_LOGD("CheckNativeFileWithOldInfo begin");
    if (HasAllOldModuleUpdate(oldInfo, newInfos)) {
        APP_LOGD("All installed haps will be updated");
        return ERR_OK;
    }

    ErrCode result = CheckNativeSoWithOldInfo(oldInfo, newInfos);
    if (result != ERR_OK) {
        APP_LOGE("Check nativeSo with oldInfo failed, result: %{public}d", result);
        return result;
    }

    result = CheckArkNativeFileWithOldInfo(oldInfo, newInfos);
    if (result != ERR_OK) {
        APP_LOGE("Check arkNativeFile with oldInfo failed, result: %{public}d", result);
        return result;
    }

    APP_LOGD("CheckNativeFileWithOldInfo end");
    return ERR_OK;
}

bool BaseBundleInstaller::HasAllOldModuleUpdate(
    const InnerBundleInfo &oldInfo, std::unordered_map<std::string, InnerBundleInfo> &newInfos)
{
    const auto &newInfo = newInfos.begin()->second;
    bool allOldModuleUpdate = true;
    if (newInfo.GetVersionCode() > oldInfo.GetVersionCode()) {
        APP_LOGD("All installed haps will be updated");
        DeleteOldArkNativeFile(oldInfo);
        return allOldModuleUpdate;
    }

    std::vector<std::string> installedModules = oldInfo.GetModuleNameVec();
    for (const auto &installedModule : installedModules) {
        auto updateModule = std::find_if(std::begin(newInfos), std::end(newInfos),
            [ &installedModule ] (const auto &item) { return item.second.FindModule(installedModule); });
        if (updateModule == newInfos.end()) {
            APP_LOGD("Some installed haps will not be updated");
            allOldModuleUpdate = false;
            break;
        }
    }
    return allOldModuleUpdate;
}

ErrCode BaseBundleInstaller::CheckArkNativeFileWithOldInfo(
    const InnerBundleInfo &oldInfo, std::unordered_map<std::string, InnerBundleInfo> &newInfos)
{
    APP_LOGD("CheckArkNativeFileWithOldInfo begin");
    std::string oldArkNativeFileAbi = oldInfo.GetArkNativeFileAbi();
    if (oldArkNativeFileAbi.empty()) {
        APP_LOGD("OldInfo no arkNativeFile");
        return ERR_OK;
    }

    std::string arkNativeFileAbi = newInfos.begin()->second.GetArkNativeFileAbi();
    if (arkNativeFileAbi.empty()) {
        APP_LOGD("NewInfos no arkNativeFile");
        for (auto& item : newInfos) {
            item.second.SetArkNativeFileAbi(oldInfo.GetArkNativeFileAbi());
            item.second.SetArkNativeFilePath(oldInfo.GetArkNativeFilePath());
        }
        return ERR_OK;
    } else {
        if (arkNativeFileAbi != oldArkNativeFileAbi) {
            APP_LOGE("An incompatible in oldInfo and newInfo");
            return ERR_APPEXECFWK_INSTALL_AN_INCOMPATIBLE;
        }
    }

    APP_LOGD("CheckArkNativeFileWithOldInfo end");
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CheckNativeSoWithOldInfo(
    const InnerBundleInfo &oldInfo, std::unordered_map<std::string, InnerBundleInfo> &newInfos)
{
    APP_LOGD("CheckNativeSoWithOldInfo begin");
    bool oldInfoHasSo = !oldInfo.GetNativeLibraryPath().empty();
    if (!oldInfoHasSo) {
        APP_LOGD("OldInfo does not has so");
        return ERR_OK;
    }

    const auto &newInfo = newInfos.begin()->second;
    bool newInfoHasSo = !newInfo.GetNativeLibraryPath().empty();
    if (newInfoHasSo && (oldInfo.GetNativeLibraryPath() != newInfo.GetNativeLibraryPath()
        || oldInfo.GetCpuAbi() != newInfo.GetCpuAbi())) {
        APP_LOGE("Install failed due to so incompatible in oldInfo and newInfo");
        return ERR_APPEXECFWK_INSTALL_SO_INCOMPATIBLE;
    }

    if (!newInfoHasSo) {
        for (auto& item : newInfos) {
            item.second.SetNativeLibraryPath(oldInfo.GetNativeLibraryPath());
            item.second.SetCpuAbi(oldInfo.GetCpuAbi());
        }
    }

    APP_LOGD("CheckNativeSoWithOldInfo end");
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CheckAppLabel(const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo) const
{
    // check app label for inheritance installation
    APP_LOGD("CheckAppLabel begin");
    if (oldInfo.GetMinCompatibleVersionCode() != newInfo.GetMinCompatibleVersionCode()) {
        return ERR_APPEXECFWK_INSTALL_MINCOMPATIBLE_VERSIONCODE_NOT_SAME;
    }
    if (oldInfo.GetTargetVersion()!= newInfo.GetTargetVersion()) {
        return ERR_APPEXECFWK_INSTALL_RELEASETYPE_TARGET_NOT_SAME;
    }
    if (oldInfo.GetCompatibleVersion() != newInfo.GetCompatibleVersion()) {
        return ERR_APPEXECFWK_INSTALL_RELEASETYPE_COMPATIBLE_NOT_SAME;
    }
    if (oldInfo.GetReleaseType() != newInfo.GetReleaseType()) {
        return ERR_APPEXECFWK_INSTALL_RELEASETYPE_NOT_SAME;
    }
    if (oldInfo.GetAppDistributionType() != newInfo.GetAppDistributionType()) {
        return ERR_APPEXECFWK_INSTALL_APP_DISTRIBUTION_TYPE_NOT_SAME;
    }
    if (oldInfo.GetAppProvisionType() != newInfo.GetAppProvisionType()) {
        return ERR_APPEXECFWK_INSTALL_APP_PROVISION_TYPE_NOT_SAME;
    }
    if (oldInfo.GetAppFeature() != newInfo.GetAppFeature()) {
        return ERR_APPEXECFWK_INSTALL_APPTYPE_NOT_SAME;
    }
    if (oldInfo.GetIsNewVersion() != newInfo.GetIsNewVersion()) {
        APP_LOGE("same version update module condition, model type must be the same");
        return ERR_APPEXECFWK_INSTALL_STATE_ERROR;
    }
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
    if (oldInfo.GetTargetBundleName() != newInfo.GetTargetBundleName()) {
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_TARGET_BUNDLE_NAME_NOT_SAME;
    }
    if (oldInfo.GetTargetPriority() != newInfo.GetTargetPriority()) {
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_TARGET_PRIORITY_NOT_SAME;
    }
#endif
    if (oldInfo.GetApplicationBundleType() != newInfo.GetApplicationBundleType()) {
        return ERR_APPEXECFWK_BUNDLE_TYPE_NOT_SAME;
    }

    ErrCode ret = CheckDebugType(oldInfo, newInfo);
    APP_LOGD("CheckAppLabel end");
    return ret;
}

ErrCode BaseBundleInstaller::CheckDebugType(
    const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo) const
{
    if (!oldInfo.HasEntry() && !newInfo.HasEntry()) {
        return ERR_OK;
    }

    if (oldInfo.HasEntry() && newInfo.HasEntry()) {
        if (oldInfo.GetBaseApplicationInfo().debug != newInfo.GetBaseApplicationInfo().debug) {
            return ERR_APPEXECFWK_INSTALL_DEBUG_NOT_SAME;
        }

        return ERR_OK;
    }

    if (oldInfo.HasEntry() && !oldInfo.GetBaseApplicationInfo().debug && newInfo.GetBaseApplicationInfo().debug) {
        return ERR_APPEXECFWK_INSTALL_DEBUG_NOT_SAME;
    }

    if (newInfo.HasEntry() && !newInfo.GetBaseApplicationInfo().debug && oldInfo.GetBaseApplicationInfo().debug) {
        return ERR_APPEXECFWK_INSTALL_DEBUG_NOT_SAME;
    }

    return ERR_OK;
}

ErrCode BaseBundleInstaller::RemoveBundleUserData(InnerBundleInfo &innerBundleInfo, bool needRemoveData)
{
    auto bundleName = innerBundleInfo.GetBundleName();
    APP_LOGD("remove user(%{public}d) in bundle(%{public}s).", userId_, bundleName.c_str());
    if (!innerBundleInfo.HasInnerBundleUserInfo(userId_)) {
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }

    innerBundleInfo.RemoveInnerBundleUserInfo(userId_);
    if (!dataMgr_->RemoveInnerBundleUserInfo(bundleName, userId_)) {
        APP_LOGE("update bundle user info to db failed %{public}s when remove user",
            bundleName.c_str());
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    ErrCode result = ERR_OK;
    if (!needRemoveData) {
        result = RemoveBundleDataDir(innerBundleInfo);
        if (result != ERR_OK) {
            APP_LOGE("remove user data directory failed.");
            return result;
        }
    }

    result = DeleteArkProfile(bundleName, userId_);
    if (result != ERR_OK) {
        APP_LOGE("fail to removeArkProfile, error is %{public}d", result);
        return result;
    }

    if ((result = CleanAsanDirectory(innerBundleInfo)) != ERR_OK) {
        APP_LOGE("fail to remove asan log path, error is %{public}d", result);
        return result;
    }

    // delete accessTokenId
    accessTokenId_ = innerBundleInfo.GetAccessTokenId(userId_);
    if (BundlePermissionMgr::DeleteAccessTokenId(accessTokenId_) !=
        AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        APP_LOGE("delete accessToken failed");
    }

    return ERR_OK;
}

ErrCode BaseBundleInstaller::CheckInstallationFree(const InnerBundleInfo &innerBundleInfo,
    const std::unordered_map<std::string, InnerBundleInfo> &infos) const
{
    for (const auto &item : infos) {
        if (innerBundleInfo.GetEntryInstallationFree() != item.second.GetEntryInstallationFree()) {
            APP_LOGE("CheckInstallationFree cannot install application and hm service simultaneously");
            return ERR_APPEXECFWK_INSTALL_TYPE_ERROR;
        }
    }
    return ERR_OK;
}

void BaseBundleInstaller::SaveHapPathToRecords(
    bool isPreInstallApp, const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    if (isPreInstallApp) {
        APP_LOGD("PreInstallApp do not need to save hap path to record");
        return;
    }

    for (const auto &item : infos) {
        auto hapPathIter = hapPathRecords_.find(item.first);
        if (hapPathIter == hapPathRecords_.end()) {
            std::string tempDir = GetTempHapPath(item.second);
            if (tempDir.empty()) {
                APP_LOGW("get temp hap path failed");
                continue;
            }
            APP_LOGD("tempDir is %{public}s", tempDir.c_str());
            hapPathRecords_.emplace(item.first, tempDir);
        }

        std::string signatureFileDir = "";
        FindSignatureFileDir(item.second.GetCurModuleName(), signatureFileDir);
        auto signatureFileIter = signatureFileMap_.find(item.first);
        if (signatureFileIter == signatureFileMap_.end()) {
            signatureFileMap_.emplace(item.first, signatureFileDir);
        }
    }
}

ErrCode BaseBundleInstaller::SaveHapToInstallPath(const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    // size of code signature files should be same with the size of hap and hsp
    if (!signatureFileMap_.empty() && (signatureFileMap_.size() != hapPathRecords_.size())) {
        APP_LOGE("each hap or hsp needs to be verified code signature");
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED;
    }
    // 1. copy hsp or hap file to temp installation dir
    ErrCode result = ERR_OK;
    for (const auto &hapPathRecord : hapPathRecords_) {
        APP_LOGD("Save from(%{public}s) to(%{public}s)", hapPathRecord.first.c_str(), hapPathRecord.second.c_str());
        if ((signatureFileMap_.find(hapPathRecord.first) != signatureFileMap_.end()) &&
            (!signatureFileMap_.at(hapPathRecord.first).empty())) {
            result = InstalldClient::GetInstance()->CopyFile(hapPathRecord.first, hapPathRecord.second,
                signatureFileMap_.at(hapPathRecord.first));
            CHECK_RESULT(result, "Copy hap to install path failed or code signature hap failed %{public}d");
        } else {
            if (InstalldClient::GetInstance()->CopyFile(
                hapPathRecord.first, hapPathRecord.second) != ERR_OK) {
                APP_LOGE("Copy hap to install path failed");
                return ERR_APPEXECFWK_INSTALL_COPY_HAP_FAILED;
            }
            if (VerifyCodeSignatureForHap(infos, hapPathRecord.first, hapPathRecord.second) != ERR_OK) {
                APP_LOGE("enable code signature failed");
                return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED;
            }
        }
    }
    APP_LOGD("copy hap to install path success");

    // 2. check encryption of hap
    if ((result = CheckHapEncryption(infos)) != ERR_OK) {
        APP_LOGE("check encryption of hap failed %{public}d", result);
        return result;
    }

    // 3. move file from temp dir to real installation dir
    if ((result = MoveFileToRealInstallationDir(infos)) != ERR_OK) {
        APP_LOGE("move file to real installation path failed %{public}d", result);
        return result;
    }
    return ERR_OK;
}

void BaseBundleInstaller::ResetInstallProperties()
{
    bundleInstallChecker_->ResetProperties();
    isContainEntry_ = false;
    isAppExist_ = false;
    hasInstalledInUser_ = false;
    isFeatureNeedUninstall_ = false;
    versionCode_ = 0;
    uninstallModuleVec_.clear();
    installedModules_.clear();
    state_ = InstallerState::INSTALL_START;
    singletonState_ = SingletonState::DEFAULT;
    accessTokenId_ = 0;
    sysEventInfo_.Reset();
    moduleName_.clear();
    verifyCodeParams_.clear();
    pgoParams_.clear();
    otaInstall_ = false;
    signatureFileMap_.clear();
    hapPathRecords_.clear();
    uninstallBundleAppId_.clear();
    isModuleUpdate_ = false;
    isEntryInstalled_ = false;
    entryModuleName_.clear();
    isEnterpriseBundle_ = false;
    appIdentifier_.clear();
    targetSoPathMap_.clear();
}

void BaseBundleInstaller::OnSingletonChange(bool noSkipsKill)
{
    if (singletonState_ == SingletonState::DEFAULT) {
        return;
    }

    InnerBundleInfo info;
    bool isExist = false;
    if (!GetInnerBundleInfo(info, isExist) || !isExist) {
        APP_LOGE("Get innerBundleInfo failed when singleton changed");
        return;
    }

    InstallParam installParam;
    installParam.needSendEvent = false;
    installParam.forceExecuted = true;
    installParam.noSkipsKill = noSkipsKill;
    if (singletonState_ == SingletonState::SINGLETON_TO_NON) {
        APP_LOGI("Bundle changes from singleton app to non singleton app");
        installParam.userId = Constants::DEFAULT_USERID;
        UninstallBundle(bundleName_, installParam);
        return;
    }

    if (singletonState_ == SingletonState::NON_TO_SINGLETON) {
        APP_LOGI("Bundle changes from non singleton app to singleton app");
        for (auto infoItem : info.GetInnerBundleUserInfos()) {
            int32_t installedUserId = infoItem.second.bundleUserInfo.userId;
            if (installedUserId == Constants::DEFAULT_USERID) {
                continue;
            }

            installParam.userId = installedUserId;
            UninstallBundle(bundleName_, installParam);
        }
    }
}

void BaseBundleInstaller::SendBundleSystemEvent(const std::string &bundleName, BundleEventType bundleEventType,
    const InstallParam &installParam, InstallScene preBundleScene, ErrCode errCode)
{
    sysEventInfo_.bundleName = bundleName;
    sysEventInfo_.isPreInstallApp = installParam.isPreInstallApp;
    sysEventInfo_.errCode = errCode;
    sysEventInfo_.isFreeInstallMode = (installParam.installFlag == InstallFlag::FREE_INSTALL);
    sysEventInfo_.userId = userId_;
    sysEventInfo_.versionCode = versionCode_;
    sysEventInfo_.preBundleScene = preBundleScene;
    GetCallingEventInfo(sysEventInfo_);
    EventReport::SendBundleSystemEvent(bundleEventType, sysEventInfo_);
}

void BaseBundleInstaller::GetCallingEventInfo(EventInfo &eventInfo)
{
    APP_LOGD("GetCallingEventInfo start, bundleName:%{public}s", eventInfo.callingBundleName.c_str());
    if (dataMgr_ == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return;
    }
    if (!dataMgr_->GetBundleNameForUid(eventInfo.callingUid, eventInfo.callingBundleName)) {
        APP_LOGW("CallingUid %{public}d is not hap, no bundleName", eventInfo.callingUid);
        eventInfo.callingBundleName = Constants::EMPTY_STRING;
        return;
    }
    BundleInfo bundleInfo;
    if (!dataMgr_->GetBundleInfo(eventInfo.callingBundleName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo,
        eventInfo.callingUid / Constants::BASE_USER_RANGE)) {
        APP_LOGE("GetBundleInfo failed, bundleName: %{public}s", eventInfo.callingBundleName.c_str());
        return;
    }
    eventInfo.callingAppId = bundleInfo.appId;
}

void BaseBundleInstaller::GetInstallEventInfo(EventInfo &eventInfo)
{
    APP_LOGD("GetInstallEventInfo start, bundleName:%{public}s", bundleName_.c_str());
    InnerBundleInfo info;
    bool isExist = false;
    if (!GetInnerBundleInfo(info, isExist) || !isExist) {
        APP_LOGE("Get innerBundleInfo failed, bundleName: %{public}s", bundleName_.c_str());
        return;
    }
    eventInfo.fingerprint = info.GetCertificateFingerprint();
    eventInfo.appDistributionType = info.GetAppDistributionType();
    eventInfo.hideDesktopIcon = info.IsHideDesktopIcon();
    eventInfo.timeStamp = info.GetBundleUpdateTime(userId_);
    // report hapPath and hashValue
    for (const auto &innerModuleInfo : info.GetInnerModuleInfos()) {
        eventInfo.filePath.push_back(innerModuleInfo.second.hapPath);
        eventInfo.hashValue.push_back(innerModuleInfo.second.hashValue);
    }
}

void BaseBundleInstaller::GetInstallEventInfo(const InnerBundleInfo &bundleInfo, EventInfo &eventInfo)
{
    APP_LOGD("GetInstallEventInfo start, bundleName:%{public}s", bundleInfo.GetBundleName().c_str());
    eventInfo.fingerprint = bundleInfo.GetCertificateFingerprint();
    eventInfo.appDistributionType = bundleInfo.GetAppDistributionType();
    eventInfo.hideDesktopIcon = bundleInfo.IsHideDesktopIcon();
    eventInfo.timeStamp = bundleInfo.GetBundleUpdateTime(userId_);
    // report hapPath and hashValue
    for (const auto &innerModuleInfo : bundleInfo.GetInnerModuleInfos()) {
        eventInfo.filePath.push_back(innerModuleInfo.second.hapPath);
        eventInfo.hashValue.push_back(innerModuleInfo.second.hashValue);
    }
}

void BaseBundleInstaller::SetCallingUid(int32_t callingUid)
{
    sysEventInfo_.callingUid = callingUid;
}

ErrCode BaseBundleInstaller::NotifyBundleStatus(const NotifyBundleEvents &installRes)
{
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    commonEventMgr->NotifyBundleStatus(installRes, dataMgr_);
    return ERR_OK;
}

void BaseBundleInstaller::AddBundleStatus(const NotifyBundleEvents &installRes)
{
    bundleEvents_.emplace_back(installRes);
}

bool BaseBundleInstaller::NotifyAllBundleStatus()
{
    if (bundleEvents_.empty()) {
        APP_LOGE("bundleEvents is empty.");
        return false;
    }

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return false;
    }

    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    for (const auto &bundleEvent : bundleEvents_) {
        commonEventMgr->NotifyBundleStatus(bundleEvent, dataMgr);
    }
    return true;
}

void BaseBundleInstaller::AddNotifyBundleEvents(const NotifyBundleEvents &notifyBundleEvents)
{
    auto userMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleUserMgr();
    if (userMgr == nullptr) {
        APP_LOGE("userMgr is null");
        return;
    }

    userMgr->AddNotifyBundleEvents(notifyBundleEvents);
}

ErrCode BaseBundleInstaller::CheckOverlayInstallation(std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
    std::shared_ptr<BundleOverlayInstallChecker> overlayChecker = std::make_shared<BundleOverlayInstallChecker>();
    return overlayChecker->CheckOverlayInstallation(newInfos, userId, overlayType_);
#else
    APP_LOGD("overlay is not supported");
    return ERR_OK;
#endif
}

ErrCode BaseBundleInstaller::CheckOverlayUpdate(const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo,
    int32_t userId) const
{
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
    std::shared_ptr<BundleOverlayInstallChecker> overlayChecker = std::make_shared<BundleOverlayInstallChecker>();
    return overlayChecker->CheckOverlayUpdate(oldInfo, newInfo, userId);
#else
    APP_LOGD("overlay is not supported");
    return ERR_OK;
#endif
}

NotifyType BaseBundleInstaller::GetNotifyType()
{
    if (isAppExist_ && hasInstalledInUser_) {
        if (overlayType_ != NON_OVERLAY_TYPE) {
            return NotifyType::OVERLAY_UPDATE;
        }
        return NotifyType::UPDATE;
    }

    if (overlayType_ != NON_OVERLAY_TYPE) {
        return NotifyType::OVERLAY_INSTALL;
    }
    return NotifyType::INSTALL;
}

ErrCode BaseBundleInstaller::CheckArkProfileDir(const InnerBundleInfo &newInfo, const InnerBundleInfo &oldInfo) const
{
    if (newInfo.GetVersionCode() > oldInfo.GetVersionCode()) {
        const auto userInfos = oldInfo.GetInnerBundleUserInfos();
        for (auto iter = userInfos.begin(); iter != userInfos.end(); iter++) {
            int32_t userId = iter->second.bundleUserInfo.userId;
            int32_t gid = (newInfo.GetAppProvisionType() == Constants::APP_PROVISION_TYPE_DEBUG) ?
                GetIntParameter(BMS_KEY_SHELL_UID, Constants::SHELL_UID) :
                oldInfo.GetUid(userId);
            ErrCode result = newInfo.GetIsNewVersion() ?
                CreateArkProfile(bundleName_, userId, oldInfo.GetUid(userId), gid) :
                DeleteArkProfile(bundleName_, userId);
            if (result != ERR_OK) {
                APP_LOGE("bundleName: %{public}s CheckArkProfileDir failed, result:%{public}d",
                    bundleName_.c_str(), result);
                return result;
            }
        }
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::ProcessAsanDirectory(InnerBundleInfo &info) const
{
    const std::string bundleName = info.GetBundleName();
    const std::string asanLogDir = Constants::BUNDLE_ASAN_LOG_DIR + Constants::PATH_SEPARATOR
        + std::to_string(userId_) + Constants::PATH_SEPARATOR + bundleName + Constants::PATH_SEPARATOR + LOG;
    bool dirExist = false;
    ErrCode errCode = InstalldClient::GetInstance()->IsExistDir(asanLogDir, dirExist);
    if (errCode != ERR_OK) {
        APP_LOGE("check asan log directory failed!");
        return errCode;
    }
    bool asanEnabled = info.GetAsanEnabled();
    // create asan log directory if asanEnabled is true
    if (!dirExist && asanEnabled) {
        InnerBundleUserInfo newInnerBundleUserInfo;
        if (!info.GetInnerBundleUserInfo(userId_, newInnerBundleUserInfo)) {
            APP_LOGE("bundle(%{public}s) get user(%{public}d) failed.",
                info.GetBundleName().c_str(), userId_);
            return ERR_APPEXECFWK_USER_NOT_EXIST;
        }

        if (!dataMgr_->GenerateUidAndGid(newInnerBundleUserInfo)) {
            APP_LOGE("fail to gererate uid and gid");
            return ERR_APPEXECFWK_INSTALL_GENERATE_UID_ERROR;
        }
        mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        if ((errCode = InstalldClient::GetInstance()->Mkdir(asanLogDir, mode,
            newInnerBundleUserInfo.uid, newInnerBundleUserInfo.uid)) != ERR_OK) {
            APP_LOGE("create asan log directory failed!");
            return errCode;
        }
    }
    if (asanEnabled) {
        info.SetAsanLogPath(LOG);
    }
    // clean asan directory
    if (dirExist && !asanEnabled) {
        if ((errCode = CleanAsanDirectory(info)) != ERR_OK) {
            APP_LOGE("clean asan log directory failed!");
            return errCode;
        }
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CleanAsanDirectory(InnerBundleInfo &info) const
{
    const std::string bundleName = info.GetBundleName();
    const std::string asanLogDir = Constants::BUNDLE_ASAN_LOG_DIR + Constants::PATH_SEPARATOR
        + std::to_string(userId_) + Constants::PATH_SEPARATOR + bundleName;
    ErrCode errCode =  InstalldClient::GetInstance()->RemoveDir(asanLogDir);
    if (errCode != ERR_OK) {
        APP_LOGE("clean asan log path failed!");
        return errCode;
    }
    info.SetAsanLogPath("");
    return errCode;
}

void BaseBundleInstaller::AddAppProvisionInfo(const std::string &bundleName,
    const Security::Verify::ProvisionInfo &provisionInfo,
    const InstallParam &installParam) const
{
    AppProvisionInfo appProvisionInfo = bundleInstallChecker_->ConvertToAppProvisionInfo(provisionInfo);
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(
        bundleName, appProvisionInfo)) {
        APP_LOGW("bundleName: %{public}s add appProvisionInfo failed.", bundleName.c_str());
    }
    if (!installParam.specifiedDistributionType.empty()) {
        if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetSpecifiedDistributionType(
            bundleName, installParam.specifiedDistributionType)) {
            APP_LOGW("bundleName: %{public}s SetSpecifiedDistributionType failed.", bundleName.c_str());
        }
    }
    if (!installParam.additionalInfo.empty()) {
        if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->SetAdditionalInfo(
            bundleName, installParam.additionalInfo)) {
            APP_LOGW("bundleName: %{public}s SetAdditionalInfo failed.", bundleName.c_str());
        }
    }
}

ErrCode BaseBundleInstaller::InnerProcessNativeLibs(InnerBundleInfo &info, const std::string &modulePath)
{
    std::string targetSoPath;
    std::string cpuAbi;
    std::string nativeLibraryPath;
    bool isCompressNativeLibrary = info.IsCompressNativeLibs(info.GetCurModuleName());
    if (info.FetchNativeSoAttrs(modulePackage_, cpuAbi, nativeLibraryPath)) {
        if (isCompressNativeLibrary) {
            bool isLibIsolated = info.IsLibIsolated(info.GetCurModuleName());
            // extract so file: if hap so is not isolated, then extract so to tmp path.
            if (isLibIsolated) {
                if (BundleUtil::EndWith(modulePath, Constants::TMP_SUFFIX)) {
                    nativeLibraryPath = BuildTempNativeLibraryPath(nativeLibraryPath);
                }
            } else {
                nativeLibraryPath = info.GetCurrentModulePackage() + Constants::TMP_SUFFIX +
                    Constants::PATH_SEPARATOR + nativeLibraryPath;
            }
            APP_LOGD("Need extract to temp dir: %{public}s", nativeLibraryPath.c_str());
            targetSoPath.append(Constants::BUNDLE_CODE_DIR).append(Constants::PATH_SEPARATOR)
                .append(info.GetBundleName()).append(Constants::PATH_SEPARATOR).append(nativeLibraryPath)
                .append(Constants::PATH_SEPARATOR);
            targetSoPathMap_.emplace(info.GetCurModuleName(), targetSoPath);
        }
    }

    APP_LOGD("begin to extract module files, modulePath : %{public}s, targetSoPath : %{public}s, cpuAbi : %{public}s",
        modulePath.c_str(), targetSoPath.c_str(), cpuAbi.c_str());
    std::string signatureFileDir = "";
    auto ret = FindSignatureFileDir(info.GetCurModuleName(), signatureFileDir);
    if (ret != ERR_OK) {
        return ret;
    }
    if (isCompressNativeLibrary) {
        auto result = ExtractModuleFiles(info, modulePath, targetSoPath, cpuAbi);
        CHECK_RESULT(result, "fail to extract module dir, error is %{public}d");
        // verify hap or hsp code signature for compressed so files
        result = VerifyCodeSignatureForNativeFiles(info, cpuAbi, targetSoPath, signatureFileDir);
        CHECK_RESULT(result, "fail to VerifyCodeSignature, error is %{public}d");
        // check whether the hap or hsp is encrypted
        result = CheckSoEncryption(info, cpuAbi, targetSoPath);
        CHECK_RESULT(result, "fail to CheckSoEncryption, error is %{public}d");
    } else {
        auto result = InstalldClient::GetInstance()->CreateBundleDir(modulePath);
        CHECK_RESULT(result, "fail to create temp bundle dir, error is %{public}d");
        std::vector<std::string> fileNames;
        result = InstalldClient::GetInstance()->GetNativeLibraryFileNames(modulePath_, cpuAbi, fileNames);
        CHECK_RESULT(result, "fail to GetNativeLibraryFileNames, error is %{public}d");
        info.SetNativeLibraryFileNames(modulePackage_, fileNames);
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::VerifyCodeSignatureForNativeFiles(InnerBundleInfo &info, const std::string &cpuAbi,
    const std::string &targetSoPath, const std::string &signatureFileDir) const
{
    if (copyHapToInstallPath_) {
        APP_LOGI("hap will be copied to install path, and native files will be verified code signature later");
        return ERR_OK;
    }
    APP_LOGD("begin to verify code signature for native files");
    const std::string compileSdkType = info.GetBaseApplicationInfo().compileSdkType;
    CodeSignatureParam codeSignatureParam;
    codeSignatureParam.modulePath = modulePath_;
    codeSignatureParam.cpuAbi = cpuAbi;
    codeSignatureParam.targetSoPath = targetSoPath;
    codeSignatureParam.signatureFileDir = signatureFileDir;
    codeSignatureParam.isEnterpriseBundle = isEnterpriseBundle_;
    codeSignatureParam.appIdentifier = appIdentifier_;
    codeSignatureParam.isPreInstalledBundle = info.GetIsPreInstallApp();
    codeSignatureParam.isCompileSdkOpenHarmony = (compileSdkType == COMPILE_SDK_TYPE_OPEN_HARMONY);
    return InstalldClient::GetInstance()->VerifyCodeSignature(codeSignatureParam);
}

ErrCode BaseBundleInstaller::VerifyCodeSignatureForHap(const std::unordered_map<std::string, InnerBundleInfo> &infos,
    const std::string &srcHapPath, const std::string &realHapPath)
{
    APP_LOGD("begin to verify code signature for hap or internal hsp");
    auto iter = infos.find(srcHapPath);
    if (iter == infos.end()) {
        return ERR_OK;
    }
    std::string moduleName = (iter->second).GetCurModuleName();
    std::string cpuAbi;
    std::string nativeLibraryPath;
    (iter->second).FetchNativeSoAttrs((iter->second).GetCurrentModulePackage(), cpuAbi, nativeLibraryPath);
    const std::string compileSdkType = (iter->second).GetBaseApplicationInfo().compileSdkType;
    std::string signatureFileDir = "";
    auto ret = FindSignatureFileDir(moduleName, signatureFileDir);
    if (ret != ERR_OK) {
        return ret;
    }
    auto targetSoPath = targetSoPathMap_.find(moduleName);
    CodeSignatureParam codeSignatureParam;
    if (targetSoPath != targetSoPathMap_.end()) {
        codeSignatureParam.targetSoPath = targetSoPath->second;
    }
    codeSignatureParam.cpuAbi = cpuAbi;
    codeSignatureParam.modulePath = realHapPath;
    codeSignatureParam.signatureFileDir = signatureFileDir;
    codeSignatureParam.isEnterpriseBundle = isEnterpriseBundle_;
    codeSignatureParam.appIdentifier = appIdentifier_;
    codeSignatureParam.isCompileSdkOpenHarmony = (compileSdkType == COMPILE_SDK_TYPE_OPEN_HARMONY);
    codeSignatureParam.isPreInstalledBundle = (iter->second).GetIsPreInstallApp();
    return InstalldClient::GetInstance()->VerifyCodeSignatureForHap(codeSignatureParam);
}

ErrCode BaseBundleInstaller::CheckSoEncryption(InnerBundleInfo &info, const std::string &cpuAbi,
    const std::string &targetSoPath)
{
    APP_LOGD("begin to check so encryption");
    CheckEncryptionParam param;
    param.modulePath = modulePath_;
    param.cpuAbi = cpuAbi;
    param.targetSoPath = targetSoPath;
    int uid = info.GetUid(userId_);
    param.bundleId = uid - userId_ * Constants::BASE_USER_RANGE;
    param.isCompressNativeLibrary = info.IsCompressNativeLibs(info.GetCurModuleName());
    if (info.GetModuleTypeByPackage(modulePackage_) == Profile::MODULE_TYPE_SHARED) {
        param.installBundleType = InstallBundleType::INTER_APP_HSP;
    }
    bool isEncrypted = false;
    ErrCode result = InstalldClient::GetInstance()->CheckEncryption(param, isEncrypted);
    CHECK_RESULT(result, "fail to CheckSoEncryption, error is %{public}d");
    if (isEncrypted) {
        APP_LOGD("module %{public}s is encrypted", modulePath_.c_str());
        info.SetApplicationReservedFlag(static_cast<uint32_t>(ApplicationReservedFlag::ENCRYPTED_APPLICATION));
    }
    return ERR_OK;
}

void BaseBundleInstaller::ProcessOldNativeLibraryPath(const std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    uint32_t oldVersionCode, const std::string &oldNativeLibraryPath) const
{
    if (((oldVersionCode >= versionCode_) && !otaInstall_) || oldNativeLibraryPath.empty()) {
        return;
    }
    for (const auto &item : newInfos) {
        const auto &moduleInfos = item.second.GetInnerModuleInfos();
        for (const auto &moduleItem: moduleInfos) {
            if (moduleItem.second.compressNativeLibs) {
                // no need to delete library path
                return;
            }
        }
    }
    std::string oldLibPath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + bundleName_ +
        Constants::PATH_SEPARATOR + Constants::LIBS;
    if (InstalldClient::GetInstance()->RemoveDir(oldLibPath) != ERR_OK) {
        APP_LOGW("bundleNmae: %{public}s remove old libs dir failed.", bundleName_.c_str());
    }
}

void BaseBundleInstaller::ProcessAOT(bool isOTA, const std::unordered_map<std::string, InnerBundleInfo> &infos) const
{
    if (isOTA) {
        APP_LOGD("is OTA, no need to AOT");
        return;
    }
    AOTHandler::GetInstance().HandleInstall(infos);
}

void BaseBundleInstaller::RemoveOldHapIfOTA(bool isOTA,
    const std::unordered_map<std::string, InnerBundleInfo> &newInfos, const InnerBundleInfo &oldInfo) const
{
    if (!isOTA) {
        return;
    }
    for (const auto &info : newInfos) {
        std::string oldHapPath = oldInfo.GetModuleHapPath(info.second.GetCurrentModulePackage());
        if (oldHapPath.empty() || oldHapPath.rfind(Constants::BUNDLE_CODE_DIR, 0) != 0) {
            continue;
        }
        if (!InstalldClient::GetInstance()->RemoveDir(oldHapPath)) {
            APP_LOGW("remove old hap failed, errno: %{public}d", errno);
        }
    }
}

ErrCode BaseBundleInstaller::CopyHapsToSecurityDir(const InstallParam &installParam,
    std::vector<std::string> &bundlePaths)
{
    if (!installParam.withCopyHaps) {
        APP_LOGD("no need to copy preInstallApp to secure dir");
        return ERR_OK;
    }
    if (!bundlePaths_.empty()) {
        bundlePaths = bundlePaths_;
        APP_LOGD("using the existed hap files in security dir");
        return ERR_OK;
    }
    for (size_t index = 0; index < bundlePaths.size(); ++index) {
        if (!BundleUtil::CheckSystemSize(bundlePaths[index], APP_INSTALL_PATH)) {
            APP_LOGE("install bundle(%{public}s) failed due to insufficient disk memory", bundlePaths[index].c_str());
            return ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT;
        }
        auto destination = BundleUtil::CopyFileToSecurityDir(bundlePaths[index], DirType::STREAM_INSTALL_DIR,
            toDeleteTempHapPath_);
        if (destination.empty()) {
            APP_LOGE("copy file %{public}s to security dir failed", bundlePaths[index].c_str());
            return ERR_APPEXECFWK_INSTALL_COPY_HAP_FAILED;
        }
        if (bundlePaths[index].find(Constants::STREAM_INSTALL_PATH) != std::string::npos) {
            BundleUtil::DeleteDir(bundlePaths[index]);
        }
        bundlePaths[index] = destination;
    }
    bundlePaths_ = bundlePaths;
    return ERR_OK;
}

ErrCode BaseBundleInstaller::RenameAllTempDir(const std::unordered_map<std::string, InnerBundleInfo> &newInfos) const
{
    APP_LOGD("begin to rename all temp dir");
    ErrCode ret = ERR_OK;
    for (const auto &info : newInfos) {
        if (info.second.GetOnlyCreateBundleUser()) {
            continue;
        }
        if ((ret = RenameModuleDir(info.second)) != ERR_OK) {
            APP_LOGE("rename dir failed");
            break;
        }
    }
    RemoveEmptyDirs(newInfos);
    return ret;
}

ErrCode BaseBundleInstaller::FindSignatureFileDir(const std::string &moduleName, std::string &signatureFileDir)
{
    APP_LOGD("begin to find code signature file of moudle %{public}s", moduleName.c_str());
    if (verifyCodeParams_.empty()) {
        signatureFileDir = "";
        APP_LOGD("verifyCodeParams_ is empty and no need to verify code signature of module %{public}s",
            moduleName.c_str());
        return ERR_OK;
    }
    if (signatureFileTmpMap_.find(moduleName) != signatureFileTmpMap_.end()) {
        signatureFileDir = signatureFileTmpMap_.at(moduleName);
        APP_LOGD("signature file of %{public}s is existed in temp map", moduleName.c_str());
        return ERR_OK;
    }
    auto iterator = verifyCodeParams_.find(moduleName);
    if (iterator == verifyCodeParams_.end()) {
        APP_LOGE("no signature file dir exist of module %{public}s", moduleName.c_str());
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FAILED;
    }
    signatureFileDir = verifyCodeParams_.at(moduleName);

    // check validity of the signature file
    auto ret = bundleInstallChecker_->CheckSignatureFileDir(signatureFileDir);
    if (ret != ERR_OK) {
        APP_LOGE("checkout signature file dir %{public}s failed", signatureFileDir.c_str());
        return ret;
    }

    // copy code signature file to security dir
    if (!BundleUtil::CheckSystemSize(signatureFileDir, APP_INSTALL_PATH)) {
        APP_LOGE("copy signature file(%{public}s) failed due to insufficient disk memory", signatureFileDir.c_str());
        return ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT;
    }
    std::string destinationStr =
        BundleUtil::CopyFileToSecurityDir(signatureFileDir, DirType::SIG_FILE_DIR, toDeleteTempHapPath_);
    if (destinationStr.empty()) {
        APP_LOGE("copy file %{public}s to security dir failed", signatureFileDir.c_str());
        return ERR_APPEXECFWK_INSTALL_COPY_HAP_FAILED;
    }
    if (signatureFileDir.find(Constants::SIGNATURE_FILE_PATH) != std::string::npos) {
        BundleUtil::DeleteDir(signatureFileDir);
    }
    signatureFileDir = destinationStr;
    signatureFileTmpMap_.emplace(moduleName, destinationStr);
    APP_LOGD("signatureFileDir is %{public}s", signatureFileDir.c_str());
    return ERR_OK;
}

std::string BaseBundleInstaller::GetTempHapPath(const InnerBundleInfo &info)
{
    std::string hapPath = GetHapPath(info);
    if (hapPath.empty() || (!BundleUtil::EndWith(hapPath, Constants::INSTALL_FILE_SUFFIX) &&
        !BundleUtil::EndWith(hapPath, Constants::HSP_FILE_SUFFIX))) {
        APP_LOGE("invalid hapPath %{public}s", hapPath.c_str());
        return "";
    }
    auto posOfPathSep = hapPath.rfind(Constants::PATH_SEPARATOR);
    if (posOfPathSep == std::string::npos) {
        return "";
    }

    std::string tempDir = hapPath.substr(0, posOfPathSep + 1) + info.GetCurrentModulePackage();
    if (installedModules_[info.GetCurrentModulePackage()]) {
        tempDir += Constants::TMP_SUFFIX;
    }

    return tempDir.append(hapPath.substr(posOfPathSep));
}

ErrCode BaseBundleInstaller::CheckHapEncryption(const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    APP_LOGD("begin to check hap encryption");
    InnerBundleInfo oldInfo;
    bool isExist = false;
    if (!GetInnerBundleInfo(oldInfo, isExist) || !isExist) {
        APP_LOGE("Get innerBundleInfo failed, bundleName: %{public}s", bundleName_.c_str());
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    for (const auto &info : infos) {
        if (hapPathRecords_.find(info.first) == hapPathRecords_.end()) {
            APP_LOGE("path %{public}s cannot be found in hapPathRecord", info.first.c_str());
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
        std::string hapPath = hapPathRecords_.at(info.first);
        CheckEncryptionParam param;
        param.modulePath = hapPath;
        int uid = info.second.GetUid(userId_);
        param.bundleId = uid - userId_ * Constants::BASE_USER_RANGE;
        param.isCompressNativeLibrary = info.second.IsCompressNativeLibs(info.second.GetCurModuleName());
        if (info.second.GetModuleTypeByPackage(modulePackage_) == Profile::MODULE_TYPE_SHARED) {
            param.installBundleType = InstallBundleType::INTER_APP_HSP;
        }
        bool isEncrypted = false;
        ErrCode result = InstalldClient::GetInstance()->CheckEncryption(param, isEncrypted);
        CHECK_RESULT(result, "fail to CheckHapEncryption, error is %{public}d");
        oldInfo.SetMoudleIsEncrpted(info.second.GetCurrentModulePackage(), isEncrypted);
    }
    if (oldInfo.IsContainEncryptedModule()) {
        APP_LOGD("application contains encrypted module");
        oldInfo.SetApplicationReservedFlag(static_cast<uint32_t>(ApplicationReservedFlag::ENCRYPTED_APPLICATION));
    } else {
        APP_LOGD("application does not contain encrypted module");
        oldInfo.ClearApplicationReservedFlag(static_cast<uint32_t>(ApplicationReservedFlag::ENCRYPTED_APPLICATION));
    }
    if (dataMgr_ == nullptr || !dataMgr_->UpdateInnerBundleInfo(oldInfo)) {
        APP_LOGE("save UpdateInnerBundleInfo failed");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::MoveFileToRealInstallationDir(
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    APP_LOGD("start to move file to real installation dir");
    for (const auto &info : infos) {
        if (hapPathRecords_.find(info.first) == hapPathRecords_.end()) {
            APP_LOGE("path %{public}s cannot be found in hapPathRecord", info.first.c_str());
            return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
        }

        std::string realInstallationPath = GetHapPath(info.second);
        APP_LOGD("move hsp or hsp file from path %{public}s to path %{public}s",
            hapPathRecords_.at(info.first).c_str(), realInstallationPath.c_str());
        // 1. move hap or hsp to real installation dir
        auto result = InstalldClient::GetInstance()->MoveFile(hapPathRecords_.at(info.first), realInstallationPath);
        if (result != ERR_OK) {
            APP_LOGE("move file to real path failed %{public}d", result);
            return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
        }
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::MoveSoFileToRealInstallationDir(
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    APP_LOGD("start to move so file to real installation dir");
    for (const auto &info : infos) {
        if (info.second.IsLibIsolated(info.second.GetCurModuleName()) ||
            !info.second.IsCompressNativeLibs(info.second.GetCurModuleName())) {
            APP_LOGI("so files are isolated or decompressed and no necessary to move so files");
            continue;
        }
        std::string cpuAbi = "";
        std::string nativeLibraryPath = "";
        bool isSoExisted = info.second.FetchNativeSoAttrs(info.second.GetCurrentModulePackage(), cpuAbi,
            nativeLibraryPath);
        if (isSoExisted) {
            std::string tempSoDir;
            tempSoDir.append(Constants::BUNDLE_CODE_DIR).append(Constants::PATH_SEPARATOR)
                .append(info.second.GetBundleName()).append(Constants::PATH_SEPARATOR)
                .append(info.second.GetCurrentModulePackage())
                .append(Constants::TMP_SUFFIX).append(Constants::PATH_SEPARATOR)
                .append(nativeLibraryPath);
            bool isDirExisted = false;
            auto result = InstalldClient::GetInstance()->IsExistDir(tempSoDir, isDirExisted);
            if (result != ERR_OK) {
                APP_LOGE("check if dir existed failed %{public}d", result);
                return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
            }
            if (!isDirExisted) {
                APP_LOGW("temp so dir %{public}s is not existed and dose not need to be moved", tempSoDir.c_str());
                continue;
            }
            std::string realSoDir;
            realSoDir.append(Constants::BUNDLE_CODE_DIR).append(Constants::PATH_SEPARATOR)
                .append(info.second.GetBundleName()).append(Constants::PATH_SEPARATOR)
                .append(nativeLibraryPath);
            APP_LOGD("move so file from path %{public}s to path %{public}s", tempSoDir.c_str(), realSoDir.c_str());
            isDirExisted = false;
            result = InstalldClient::GetInstance()->IsExistDir(realSoDir, isDirExisted);
            if (result != ERR_OK) {
                APP_LOGE("check if dir existed failed %{public}d", result);
                return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
            }
            if (!isDirExisted) {
                InstalldClient::GetInstance()->CreateBundleDir(realSoDir);
            }
            result = InstalldClient::GetInstance()->MoveFiles(tempSoDir, realSoDir);
            if (result != ERR_OK) {
                APP_LOGE("move file to real path failed %{public}d", result);
                return ERR_APPEXECFWK_INSTALLD_MOVE_FILE_FAILED;
            }
            RemoveTempSoDir(tempSoDir);
            if (!installedModules_[info.second.GetCurrentModulePackage()]) {
                RemoveTempPathOnlyUsedForSo(info.second);
            }
        }
    }
    return ERR_OK;
}

void BaseBundleInstaller::UpdateAppInstallControlled(int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
    if (!DelayedSingleton<AppControlManager>::GetInstance()->IsAppInstallControlEnabled()) {
        APP_LOGD("app control feature is disabled");
        return;
    }

    if (bundleName_.empty() || dataMgr_ == nullptr) {
        APP_LOGW("invalid bundleName_ or dataMgr is nullptr");
        return;
    }
    InnerBundleInfo info;
    bool isAppExisted = dataMgr_->QueryInnerBundleInfo(bundleName_, info);
    if (!isAppExisted) {
        APP_LOGW("bundle %{public}s is not existed", bundleName_.c_str());
        return;
    }

    InnerBundleUserInfo userInfo;
    if (!info.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGW("current bundle (%{public}s) is not installed at current userId (%{public}d)",
            bundleName_.c_str(), userId);
        return;
    }

    std::string currentAppId = info.GetAppId();
    std::vector<std::string> appIds;
    ErrCode ret = DelayedSingleton<AppControlManager>::GetInstance()->GetAppInstallControlRule(
        AppControlConstants::EDM_CALLING, AppControlConstants::APP_DISALLOWED_UNINSTALL, userId, appIds);
    if ((ret == ERR_OK) && (std::find(appIds.begin(), appIds.end(), currentAppId) != appIds.end())) {
        APP_LOGW("bundle %{public}s cannot be removed", bundleName_.c_str());
        userInfo.isRemovable = false;
        dataMgr_->AddInnerBundleUserInfo(bundleName_, userInfo);
    }
#else
    APP_LOGW("app control is disable");
#endif
}

ErrCode BaseBundleInstaller::UninstallBundleFromBmsExtension(const std::string &bundleName)
{
    APP_LOGD("start to uninstall bundle from bms extension");
    if (!DelayedSingleton<BundleMgrService>::GetInstance()->IsBrokerServiceStarted()) {
        APP_LOGW("broker is not started");
        return ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_BUNDLE;
    }
    BmsExtensionDataMgr bmsExtensionDataMgr;
    auto ret = bmsExtensionDataMgr.Uninstall(bundleName);
    if (ret == ERR_OK) {
        APP_LOGD("uninstall bundle(%{public}s) from bms extension successfully", bundleName.c_str());
        return ERR_OK;
    }
    if ((ret == ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_BUNDLE) ||
        (ret == ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED)) {
        APP_LOGE("uninstall failed due to bundle(%{public}s is not existed)", bundleName.c_str());
        return ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_BUNDLE;
    }
    APP_LOGE("uninstall bundle(%{public}s) from bms extension faile due to errcode %{public}d",
        bundleName.c_str(), ret);
    return ERR_BUNDLE_MANAGER_UNINSTALL_FROM_BMS_EXTENSION_FAILED;
}

ErrCode BaseBundleInstaller::CheckBundleInBmsExtension(const std::string &bundleName, int32_t userId)
{
    APP_LOGD("start to check bundle(%{public}s) from bms extension", bundleName.c_str());
    if (!DelayedSingleton<BundleMgrService>::GetInstance()->IsBrokerServiceStarted()) {
        APP_LOGW("broker is not started");
        return ERR_OK;
    }
    BmsExtensionDataMgr bmsExtensionDataMgr;
    BundleInfo extensionBundleInfo;
    auto ret = bmsExtensionDataMgr.GetBundleInfo(bundleName, BundleFlag::GET_BUNDLE_DEFAULT, userId,
        extensionBundleInfo);
    if (ret == ERR_OK) {
        APP_LOGE("the bundle(%{public}s) is already existed in the bms extension", bundleName.c_str());
        return ERR_APPEXECFWK_INSTALL_ALREADY_EXIST;
    }
    return ERR_OK;
}

void BaseBundleInstaller::RemoveTempSoDir(const std::string &tempSoDir)
{
    auto firstPos = tempSoDir.find(Constants::TMP_SUFFIX);
    if (firstPos == std::string::npos) {
        APP_LOGW("invalid tempSoDir %{public}s", tempSoDir.c_str());
        return;
    }
    auto secondPos = tempSoDir.find(Constants::PATH_SEPARATOR, firstPos);
    if (secondPos == std::string::npos) {
        APP_LOGW("invalid tempSoDir %{public}s", tempSoDir.c_str());
        return;
    }
    auto thirdPos = tempSoDir.find(Constants::PATH_SEPARATOR, secondPos + 1);
    if (thirdPos == std::string::npos) {
        InstalldClient::GetInstance()->RemoveDir(tempSoDir);
        return;
    }
    std::string subTempSoDir = tempSoDir.substr(0, thirdPos);
    InstalldClient::GetInstance()->RemoveDir(subTempSoDir);
}

ErrCode BaseBundleInstaller::InstallEntryMoudleFirst(std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    InnerBundleInfo &bundleInfo, const InnerBundleUserInfo &innerBundleUserInfo, const InstallParam &installParam)
{
    APP_LOGD("start to install entry firstly");
    if (!isAppExist_ || isEntryInstalled_) {
        APP_LOGD("no need to install entry firstly");
        return ERR_OK;
    }
    ErrCode result = ERR_OK;
    for (auto &info : newInfos) {
        if (info.second.HasEntry()) {
            modulePath_ = info.first;
            InnerBundleInfo &newInfo = info.second;
            newInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
            bool isReplace = (installParam.installFlag == InstallFlag::REPLACE_EXISTING ||
                installParam.installFlag == InstallFlag::FREE_INSTALL);
            // app exist, but module may not
            result = ProcessBundleUpdateStatus(bundleInfo, newInfo, isReplace, installParam.noSkipsKill);
            if (result == ERR_OK) {
                entryModuleName_ = info.second.GetCurrentModulePackage();
                APP_LOGD("entry packageName is %{public}s", entryModuleName_.c_str());
            }
            break;
        }
    }
    isEntryInstalled_ = true;
    return result;
}

ErrCode BaseBundleInstaller::DeliveryProfileToCodeSign() const
{
    APP_LOGD("start to delivery sign profile to code signature");
    Security::Verify::ProvisionInfo provisionInfo = verifyRes_.GetProvisionInfo();
    if (provisionInfo.profileBlockLength == 0 || provisionInfo.profileBlock == nullptr) {
        APP_LOGD("Emulator does not verify signature");
        return ERR_OK;
    }
    if (provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE ||
        provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_NORMAL ||
        provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_MDM ||
        provisionInfo.type == Security::Verify::ProvisionType::DEBUG) {
        return InstalldClient::GetInstance()->DeliverySignProfile(provisionInfo.bundleInfo.bundleName,
            provisionInfo.profileBlockLength, provisionInfo.profileBlock.get());
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::RemoveProfileFromCodeSign(const std::string &bundleName) const
{
    APP_LOGD("start to remove sign profile of bundle %{public}s from code signature", bundleName.c_str());
    return InstalldClient::GetInstance()->RemoveSignProfile(bundleName);
}

void BaseBundleInstaller::DeleteOldNativeLibraryPath() const
{
    std::string oldLibPath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + bundleName_ +
        Constants::PATH_SEPARATOR + Constants::LIBS;
    if (InstalldClient::GetInstance()->RemoveDir(oldLibPath) != ERR_OK) {
        APP_LOGW("bundleNmae: %{public}s remove old libs dir failed.", bundleName_.c_str());
    }
}

void BaseBundleInstaller::RemoveTempPathOnlyUsedForSo(const InnerBundleInfo &innerBundleInfo) const
{
    APP_LOGD("start");
    std::string tempDir;
    tempDir.append(Constants::BUNDLE_CODE_DIR).append(Constants::PATH_SEPARATOR)
        .append(innerBundleInfo.GetBundleName()).append(Constants::PATH_SEPARATOR)
        .append(innerBundleInfo.GetCurrentModulePackage())
        .append(Constants::TMP_SUFFIX);
    bool isDirEmpty = false;
    if (InstalldClient::GetInstance()->IsDirEmpty(tempDir, isDirEmpty) != ERR_OK) {
        APP_LOGW("IsDirEmpty failed");
    }
    if (isDirEmpty && (InstalldClient::GetInstance()->RemoveDir(tempDir) != ERR_OK)) {
        APP_LOGW("remove tmp so path:%{public}s failed", tempDir.c_str());
    }
    APP_LOGD("end");
}

bool BaseBundleInstaller::NeedDeleteOldNativeLib(
    std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    const InnerBundleInfo &oldInfo)
{
    if (newInfos.empty()) {
        APP_LOGD("NewInfos is null");
        return false;
    }

    if (!isAppExist_) {
        APP_LOGD("No old app");
        return false;
    }

    if (oldInfo.GetNativeLibraryPath().empty()) {
        APP_LOGD("Old app no library");
        return false;
    }

    if ((versionCode_ > oldInfo.GetVersionCode())) {
        APP_LOGD("Higher versionCode");
        return true;
    }

    if (oldInfo.GetApplicationBundleType() == BundleType::APP_SERVICE_FWK) {
        APP_LOGD("Appservice not delete library");
        return false;
    }

    for (const auto &info : newInfos) {
        if (info.second.GetOnlyCreateBundleUser()) {
            APP_LOGD("Some hap no update module.");
            return false;
        }
    }

    return otaInstall_ || HasAllOldModuleUpdate(oldInfo, newInfos);
}

ErrCode BaseBundleInstaller::UpdateHapToken(bool needUpdateToken, InnerBundleInfo &newInfo)
{
    APP_LOGI("UpdateHapToken %{public}s start", bundleName_.c_str());
    auto bundleUserInfos = newInfo.GetInnerBundleUserInfos();
    for (const auto &uerInfo : bundleUserInfos) {
        if (uerInfo.second.accessTokenId == 0) {
            continue;
        }
        Security::AccessToken::AccessTokenIDEx accessTokenIdEx;
        accessTokenIdEx.tokenIDEx = uerInfo.second.accessTokenIdEx;
        if (BundlePermissionMgr::UpdateHapToken(accessTokenIdEx, newInfo) != ERR_OK) {
            APP_LOGE("UpdateHapToken failed %{public}s", bundleName_.c_str());
            return ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED;
        }
        if (needUpdateToken) {
            newInfo.SetAccessTokenIdEx(accessTokenIdEx, uerInfo.second.bundleUserInfo.userId);
        }
    }
    if (needUpdateToken && !dataMgr_->UpdateInnerBundleInfo(newInfo)) {
        APP_LOGE("save UpdateInnerBundleInfo failed %{publlic}s", bundleName_.c_str());
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    APP_LOGI("UpdateHapToken %{public}s end", bundleName_.c_str());
    return ERR_OK;
}

void BaseBundleInstaller::ForceWriteToDisk() const
{
    auto task = []() {
        APP_LOGI("sync begin");
        sync();
        APP_LOGI("sync end");
    };
    std::thread(task).detach();
}

#ifdef APP_DOMAIN_VERIFY_ENABLED
void BaseBundleInstaller::PrepareSkillUri(const std::vector<Skill> &skills,
    std::vector<AppDomainVerify::SkillUri> &skillUris) const
{
    for (const auto &skill : skills) {
        if (!skill.domainVerify) {
            continue;
        }
        for (const auto &uri : skill.uris) {
            if (uri.scheme != SKILL_URI_SCHEME_HTTPS) {
                continue;
            }
            AppDomainVerify::SkillUri skillUri;
            skillUri.scheme = uri.scheme;
            skillUri.host = uri.host;
            skillUri.port = uri.port;
            skillUri.path = uri.path;
            skillUri.pathStartWith = uri.pathStartWith;
            skillUri.pathRegex = uri.pathRegex;
            skillUri.type = uri.type;
            skillUris.push_back(skillUri);
        }
    }
}
#endif

void BaseBundleInstaller::VerifyDomain()
{
#ifdef APP_DOMAIN_VERIFY_ENABLED
    APP_LOGD("start to verify domain");
    InnerBundleInfo bundleInfo;
    bool isExist = false;
    if (!GetInnerBundleInfo(bundleInfo, isExist) || !isExist) {
        APP_LOGE("Get innerBundleInfo failed, bundleName: %{public}s", bundleName_.c_str());
        return;
    }
    std::string appIdentifier = bundleInfo.GetAppIdentifier();
    if (isAppExist_) {
        APP_LOGI("app exist, need to clear old domain info");
        ClearDomainVerifyStatus(appIdentifier, bundleName_);
    }
    std::vector<AppDomainVerify::SkillUri> skillUris;
    std::map<std::string, std::vector<Skill>> skillInfos = bundleInfo.GetInnerSkillInfos();
    for (const auto &skillInfo : skillInfos) {
        PrepareSkillUri(skillInfo.second, skillUris);
    }
    if (skillUris.empty()) {
        APP_LOGI("no skill uri need to verify domain");
        return;
    }
    std::string fingerprint = bundleInfo.GetCertificateFingerprint();
    APP_LOGI("start to call VerifyDomain, size of skillUris: %{public}zu", skillUris.size());
    // call VerifyDomain
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    DelayedSingleton<AppDomainVerify::AppDomainVerifyMgrClient>::GetInstance()->VerifyDomain(
        appIdentifier, bundleName_, fingerprint, skillUris);
    IPCSkeleton::SetCallingIdentity(identity);
#else
    APP_LOGI("app domain verify is disabled");
    return;
#endif
}

void BaseBundleInstaller::ClearDomainVerifyStatus(const std::string &appIdentifier,
    const std::string &bundleName) const
{
#ifdef APP_DOMAIN_VERIFY_ENABLED
    APP_LOGI("start to clear domain verify status");
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    // call ClearDomainVerifyStatus
    if (!DelayedSingleton<AppDomainVerify::AppDomainVerifyMgrClient>::GetInstance()->ClearDomainVerifyStatus(
        appIdentifier, bundleName)) {
        APP_LOGW("ClearDomainVerifyStatus failed");
    }
    IPCSkeleton::SetCallingIdentity(identity);
#else
    APP_LOGI("app domain verify is disabled");
    return;
#endif
}

ErrCode BaseBundleInstaller::CreateShaderCache(const std::string &bundleName, int32_t uid, int32_t gid) const
{
    std::string shaderCachePath;
    shaderCachePath.append(Constants::SHADER_CACHE_PATH).append(bundleName);
    bool isExist = true;
    ErrCode result = InstalldClient::GetInstance()->IsExistDir(shaderCachePath, isExist);
    if (result != ERR_OK) {
        APP_LOGE("IsExistDir failed, error is %{public}d", result);
        return result;
    }
    if (isExist) {
        APP_LOGD("shaderCachePath is exist");
        return ERR_OK;
    }
    APP_LOGI("CreateShaderCache %{public}s", shaderCachePath.c_str());
    return InstalldClient::GetInstance()->Mkdir(shaderCachePath, S_IRWXU, uid, gid);
}

ErrCode BaseBundleInstaller::DeleteShaderCache(const std::string &bundleName) const
{
    std::string shaderCachePath;
    shaderCachePath.append(Constants::SHADER_CACHE_PATH).append(bundleName);
    APP_LOGI("DeleteShaderCache %{public}s", shaderCachePath.c_str());
    return InstalldClient::GetInstance()->RemoveDir(shaderCachePath);
}

std::string BaseBundleInstaller::GetCheckResultMsg() const
{
    return bundleInstallChecker_->GetCheckResultMsg();
}

void BaseBundleInstaller::SetCheckResultMsg(const std::string checkResultMsg) const
{
    bundleInstallChecker_->SetCheckResultMsg(checkResultMsg);
}

bool BaseBundleInstaller::VerifyActivationLock() const
{
    // otherwise, pass
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
