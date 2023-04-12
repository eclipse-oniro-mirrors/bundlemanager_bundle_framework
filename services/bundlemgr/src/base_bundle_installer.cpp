/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "nlohmann/json.hpp"

#include <unistd.h>

#include "account_helper.h"
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
#include "aging/bundle_aging_mgr.h"
#endif
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
#include "bundle_constants.h"
#include "bundle_extractor.h"
#include "bundle_mgr_service.h"
#include "bundle_sandbox_app_helper.h"
#include "bundle_permission_mgr.h"
#include "bundle_util.h"
#include "hitrace_meter.h"
#include "datetime_ex.h"
#include "installd_client.h"
#include "parameter.h"
#include "perf_profile.h"
#include "scope_guard.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::Security;
namespace {
const std::string ARK_CACHE_PATH = "/data/local/ark-cache/";
const std::string ARK_PROFILE_PATH = "/data/local/ark-profile/";
const std::string LOG = "log";
const char* BMS_KEY_SHELL_UID = "const.product.shell.uid";

std::string GetHapPath(const InnerBundleInfo &info, const std::string &moduleName)
{
    std::string fileSuffix = Constants::INSTALL_FILE_SUFFIX;
    auto moduleInfo = info.GetInnerModuleInfoByModuleName(moduleName);
    if (moduleInfo && moduleInfo->distro.moduleType == Profile::MODULE_TYPE_SHARED) {
        APP_LOGD("The module(%{public}s) is shared.", moduleName.c_str());
        fileSuffix = Constants::INSTALL_SHARED_FILE_SUFFIX;
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
}

BaseBundleInstaller::BaseBundleInstaller()
    : bundleInstallChecker_(std::make_unique<BundleInstallChecker>())
{
    APP_LOGI("base bundle installer instance is created");
}

BaseBundleInstaller::~BaseBundleInstaller()
{
    APP_LOGI("base bundle installer instance is destroyed");
}

ErrCode BaseBundleInstaller::InstallBundle(
    const std::string &bundlePath, const InstallParam &installParam, const Constants::AppType appType)
{
    std::vector<std::string> bundlePaths { bundlePath };
    return InstallBundle(bundlePaths, installParam, appType);
}

ErrCode BaseBundleInstaller::InstallBundle(
    const std::vector<std::string> &bundlePaths, const InstallParam &installParam, const Constants::AppType appType)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to process bundle install");

    PerfProfile::GetInstance().SetBundleInstallStartTime(GetTickCount());

    int32_t uid = Constants::INVALID_UID;
    ErrCode result = ProcessBundleInstall(bundlePaths, installParam, appType, uid);
    if (installParam.needSendEvent && dataMgr_ && !bundleName_.empty()) {
        NotifyBundleEvents installRes = {
            .bundleName = bundleName_,
            .abilityName = mainAbility_,
            .resultCode = result,
            .type = (isAppExist_ && hasInstalledInUser_) ? NotifyType::UPDATE : NotifyType::INSTALL,
            .uid = uid,
            .accessTokenId = accessTokenId_
        };
        if (NotifyBundleStatus(installRes) != ERR_OK) {
            APP_LOGW("notify status failed for installation");
        }
    }

    SendBundleSystemEvent(
        bundleName_,
        ((isAppExist_ && hasInstalledInUser_) ? BundleEventType::UPDATE : BundleEventType::INSTALL),
        installParam,
        sysEventInfo_.preBundleScene,
        result);
    PerfProfile::GetInstance().SetBundleInstallEndTime(GetTickCount());
    APP_LOGD("finish to process bundle install");
    return result;
}

ErrCode BaseBundleInstaller::InstallBundleByBundleName(
    const std::string &bundleName, const InstallParam &installParam)
{
    APP_LOGD("begin to process bundle install by bundleName, which is %{public}s.", bundleName.c_str());
    PerfProfile::GetInstance().SetBundleInstallStartTime(GetTickCount());

    int32_t uid = Constants::INVALID_UID;
    ErrCode result = ProcessInstallBundleByBundleName(bundleName, installParam, uid);
    if (installParam.needSendEvent && dataMgr_ && !bundleName.empty()) {
        NotifyBundleEvents installRes = {
            .bundleName = bundleName,
            .resultCode = result,
            .type = NotifyType::INSTALL,
            .uid = uid,
            .accessTokenId = accessTokenId_
        };
        if (NotifyBundleStatus(installRes) != ERR_OK) {
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
    APP_LOGD("begin to process bundle recover by bundleName, which is %{public}s.", bundleName.c_str());
    PerfProfile::GetInstance().SetBundleInstallStartTime(GetTickCount());
    if (!BundlePermissionMgr::Init()) {
        APP_LOGW("BundlePermissionMgr::Init failed");
    }
    int32_t uid = Constants::INVALID_UID;
    ErrCode result = ProcessRecover(bundleName, installParam, uid);
    if (installParam.needSendEvent && dataMgr_ && !bundleName_.empty() && !modulePackage_.empty()) {
        NotifyBundleEvents installRes = {
            .bundleName = bundleName,
            .resultCode = result,
            .type = NotifyType::INSTALL,
            .uid = uid,
            .accessTokenId = accessTokenId_
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
    BundlePermissionMgr::UnInit();
    APP_LOGD("finish to process %{public}s bundle recover", bundleName.c_str());
    return result;
}

ErrCode BaseBundleInstaller::UninstallBundle(const std::string &bundleName, const InstallParam &installParam)
{
    APP_LOGD("begin to process %{public}s bundle uninstall", bundleName.c_str());
    PerfProfile::GetInstance().SetBundleUninstallStartTime(GetTickCount());

    // uninstall all sandbox app before
    UninstallAllSandboxApps(bundleName, installParam.userId);

    int32_t uid = Constants::INVALID_UID;
    ErrCode result = ProcessBundleUninstall(bundleName, installParam, uid);
    if (installParam.needSendEvent && dataMgr_) {
        NotifyBundleEvents installRes = {
            .bundleName = bundleName,
            .resultCode = result,
            .type = NotifyType::UNINSTALL_BUNDLE,
            .uid = uid,
            .accessTokenId = accessTokenId_,
            .isAgingUninstall = installParam.isAgingUninstall
        };
        if (NotifyBundleStatus(installRes) != ERR_OK) {
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

ErrCode BaseBundleInstaller::UninstallBundle(
    const std::string &bundleName, const std::string &modulePackage, const InstallParam &installParam)
{
    APP_LOGD("begin to process %{public}s module in %{public}s uninstall", modulePackage.c_str(), bundleName.c_str());
    PerfProfile::GetInstance().SetBundleUninstallStartTime(GetTickCount());

    // uninstall all sandbox app before
    UninstallAllSandboxApps(bundleName, installParam.userId);

    int32_t uid = Constants::INVALID_UID;
    ErrCode result = ProcessBundleUninstall(bundleName, modulePackage, installParam, uid);
    if (installParam.needSendEvent && dataMgr_) {
        NotifyBundleEvents installRes = {
            .bundleName = bundleName,
            .modulePackage = modulePackage,
            .resultCode = result,
            .type = NotifyType::UNINSTALL_MODULE,
            .uid = uid,
            .accessTokenId = accessTokenId_,
            .isAgingUninstall = installParam.isAgingUninstall
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

ErrCode BaseBundleInstaller::InstallAppControl(
    const std::vector<std::string> &installAppIds, int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
    std::vector<std::string> appIds;
    ErrCode ret = DelayedSingleton<AppControlManager>::GetInstance()->GetAppInstallControlRule(
        AppControlConstants::EDM_CALLING, AppControlConstants::APP_ALLOWED_INSTALL, userId, appIds);
    if (ret != ERR_OK) {
        APP_LOGE("GetAppInstallControlRule failed code:%{public}d", ret);
        return ret;
    }
    if (appIds.empty()) {
        return ERR_OK;
    }
    for (const auto &installAppId : installAppIds) {
        if (std::find(appIds.begin(), appIds.end(), installAppId) == appIds.end()) {
            APP_LOGE("appId:%{public}s is dis allow install", installAppId.c_str());
            return ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_INSTALL;
        }
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

ErrCode BaseBundleInstaller::InnerProcessBundleInstall(std::unordered_map<std::string, InnerBundleInfo> &newInfos,
    InnerBundleInfo &oldInfo, const InstallParam &installParam, int32_t &uid)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGI("InnerProcessBundleInstall with bundleName %{public}s, userId is %{public}d", bundleName_.c_str(),
        userId_);
    if (installParam.needSavePreInstallInfo) {
        PreInstallBundleInfo preInstallBundleInfo;
        dataMgr_->GetPreInstallBundleInfo(bundleName_, preInstallBundleInfo);
        preInstallBundleInfo.SetAppType(newInfos.begin()->second.GetAppType());
        preInstallBundleInfo.SetVersionCode(newInfos.begin()->second.GetVersionCode());
        for (const auto &item : newInfos) {
            preInstallBundleInfo.AddBundlePath(item.first);
        }
#ifdef USE_PRE_BUNDLE_PROFILE
    preInstallBundleInfo.SetRemovable(installParam.removable);
#else
    preInstallBundleInfo.SetRemovable(newInfos.begin()->second.IsRemovable());
#endif
        dataMgr_->SavePreInstallBundleInfo(bundleName_, preInstallBundleInfo);
    }

    // singleton app can only be installed in U0 and U0 can only install singleton app.
    bool isSingleton = newInfos.begin()->second.IsSingleton();
    if ((isSingleton && (userId_ != Constants::DEFAULT_USERID)) ||
        (!isSingleton && (userId_ == Constants::DEFAULT_USERID))) {
        APP_LOGW("singleton(%{public}d) app(%{public}s) and user(%{public}d) are not matched.",
            isSingleton, bundleName_.c_str(), userId_);
        return ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON;
    }

    // try to get the bundle info to decide use install or update. Always keep other exceptions below this line.
    if (!GetInnerBundleInfo(oldInfo, isAppExist_)) {
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    APP_LOGI("flag:%{public}d, userId:%{public}d, isAppExist:%{public}d",
        installParam.installFlag, userId_, isAppExist_);
    bool isFreeInstallFlag = (installParam.installFlag == InstallFlag::FREE_INSTALL);
    CheckEnableRemovable(newInfos, oldInfo, userId_, isFreeInstallFlag, isAppExist_);

    ErrCode result = ERR_OK;
    if (isAppExist_) {
        result = CheckInstallationFree(oldInfo, newInfos);
        CHECK_RESULT(result, "CheckInstallationFree failed %{public}d");
        // to guarantee that the hap version can be compatible.
        result = CheckVersionCompatibility(oldInfo);
        CHECK_RESULT(result, "The app has been installed and update lower version bundle %{public}d");
        // to check native file between oldInfo and newInfos.
        result = CheckNativeFileWithOldInfo(oldInfo, newInfos);
        CHECK_RESULT(result, "Check native so between oldInfo and newInfos failed %{public}d");

        hasInstalledInUser_ = oldInfo.HasInnerBundleUserInfo(userId_);
        if (!hasInstalledInUser_) {
            APP_LOGD("new userInfo with bundleName %{public}s and userId %{public}d",
                bundleName_.c_str(), userId_);
            InnerBundleUserInfo newInnerBundleUserInfo;
            newInnerBundleUserInfo.bundleUserInfo.userId = userId_;
            newInnerBundleUserInfo.bundleName = bundleName_;
            oldInfo.AddInnerBundleUserInfo(newInnerBundleUserInfo);
            ScopeGuard userGuard([&] { RemoveBundleUserData(oldInfo, false); });
            accessTokenId_ = CreateAccessTokenId(oldInfo);
            oldInfo.SetAccessTokenId(accessTokenId_, userId_);
            result = GrantRequestPermissions(oldInfo, accessTokenId_);
            CHECK_RESULT(result, "GrantRequestPermissions failed %{public}d");

            result = CreateBundleUserData(oldInfo);
            CHECK_RESULT(result, "CreateBundleUserData failed %{public}d");
            // extract ap file
            result = ExtractAllArkProfileFile(oldInfo);
            CHECK_RESULT(result, "ExtractAllArkProfileFile failed %{public}d");

            userGuard.Dismiss();
        }

        for (auto &info : newInfos) {
            std::string packageName = info.second.GetCurrentModulePackage();
            if (oldInfo.FindModule(packageName)) {
                installedModules_[packageName] = true;
            }
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

uint32_t BaseBundleInstaller::CreateAccessTokenId(const InnerBundleInfo &info)
{
    return BundlePermissionMgr::CreateAccessTokenId(info, info.GetBundleName(), userId_);
}

ErrCode BaseBundleInstaller::GrantRequestPermissions(const InnerBundleInfo &info, const uint32_t tokenId)
{
    if (!BundlePermissionMgr::GrantRequestPermissions(info, tokenId)) {
        APP_LOGE("GrantRequestPermissions failed, bundleName: %{public}s", info.GetBundleName().c_str());
        return ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED;
    }
    return ERR_OK;
}

ErrCode BaseBundleInstaller::ProcessBundleInstall(const std::vector<std::string> &inBundlePaths,
    const InstallParam &installParam, const Constants::AppType appType, int32_t &uid)
{
    APP_LOGD("ProcessBundleInstall bundlePath install");
    if (dataMgr_ == nullptr) {
        dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr_ == nullptr) {
            APP_LOGE("Get dataMgr shared_ptr nullptr");
            return ERR_APPEXECFWK_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR;
        }
    }

    userId_ = GetUserId(installParam.userId);
    ErrCode result = CheckUserId(userId_);
    CHECK_RESULT(result, "userId check failed %{public}d");

    std::vector<std::string> bundlePaths;
    // check hap paths
    result = BundleUtil::CheckFilePath(inBundlePaths, bundlePaths);
    CHECK_RESULT(result, "hap file check failed %{public}d");
    UpdateInstallerState(InstallerState::INSTALL_BUNDLE_CHECKED);                  // ---- 5%

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
    // check the dependencies whether or not exists
    result = CheckDependency(newInfos);
    CHECK_RESULT(result, "check dependency failed %{public}d");
    UpdateInstallerState(InstallerState::INSTALL_PARSED);                          // ---- 20%

    userId_ = GetConfirmUserId(userId_, newInfos);
    // check hap is allow install by app control
    std::vector<std::string> installAppIds;
    for (const auto &info : newInfos) {
        installAppIds.emplace_back(info.second.GetAppId());
    }
    result = InstallAppControl(installAppIds, userId_);
    CHECK_RESULT(result, "install app control failed %{public}d");

    // check hap hash param
    result = CheckHapHashParams(newInfos, installParam.hashParams);
    CHECK_RESULT(result, "check hap hash param failed %{public}d");
    UpdateInstallerState(InstallerState::INSTALL_HAP_HASH_PARAM_CHECKED);          // ---- 25%

    // check versioncode and bundleName
    result = CheckAppLabelInfo(newInfos);
    CHECK_RESULT(result, "verisoncode or bundleName is different in all haps %{public}d");
    UpdateInstallerState(InstallerState::INSTALL_VERSION_AND_BUNDLENAME_CHECKED);  // ---- 30%

    // check native file
    result = CheckMultiNativeFile(newInfos);
    CHECK_RESULT(result, "native so is incompatible in all haps %{public}d");
    UpdateInstallerState(InstallerState::INSTALL_NATIVE_SO_CHECKED);               // ---- 35%

    auto &mtx = dataMgr_->GetBundleMutex(bundleName_);
    std::lock_guard lock {mtx};

    // uninstall all sandbox app before
    UninstallAllSandboxApps(bundleName_);
    UpdateInstallerState(InstallerState::INSTALL_REMOVE_SANDBOX_APP);              // ---- 50%

    // this state should always be set when return
    ScopeGuard stateGuard([&] { dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_SUCCESS); });

    // this state should always be set when return
    ScopeGuard enableGuard([&] { dataMgr_->EnableBundle(bundleName_); });
    InnerBundleInfo oldInfo;
    result = InnerProcessBundleInstall(newInfos, oldInfo, installParam, uid);
    CHECK_RESULT_WITH_ROLLBACK(result, "internal processing failed with result %{public}d", newInfos, oldInfo);
    UpdateInstallerState(InstallerState::INSTALL_INFO_SAVED);                      // ---- 80%

    // rename for all temp dirs
    for (const auto &info : newInfos) {
        if (info.second.IsOnlyCreateBundleUser()) {
            continue;
        }
        if ((result = RenameModuleDir(info.second)) != ERR_OK) {
            break;
        }
    }
    UpdateInstallerState(InstallerState::INSTALL_RENAMED);                         // ---- 90%

    CHECK_RESULT_WITH_ROLLBACK(result, "rename temp dirs failed with result %{public}d", newInfos, oldInfo);
    if (!uninstallModuleVec_.empty()) {
        UninstallLowerVersionFeature(uninstallModuleVec_);
    }

    SaveHapPathToRecords(installParam.isPreInstallApp, newInfos);
    RemoveEmptyDirs(newInfos);
    if (installParam.copyHapToInstallPath) {
        APP_LOGD("begin to copy hap to install path");
        if (!SaveHapToInstallPath()) {
            APP_LOGE("copy hap to install path failed.");
            return ERR_APPEXECFWK_INSTALL_COPY_HAP_FAILED;
        }
        APP_LOGD("copy hap to install path success");
    }
    UpdateInstallerState(InstallerState::INSTALL_SUCCESS);                         // ---- 100%
    APP_LOGD("finish ProcessBundleInstall bundlePath install touch off aging");
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
    OnSingletonChange(installParam.noSkipsKill);
    sync();
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
    ErrCode ret = UpdateDefineAndRequestPermissions(preInfo, oldInfo);
    if (ret != ERR_OK) {
        return;
    }
    APP_LOGD("finish rollback due to install failed");
}

ErrCode BaseBundleInstaller::UpdateDefineAndRequestPermissions(const InnerBundleInfo &oldInfo,
    const InnerBundleInfo &newInfo)
{
    APP_LOGD("UpdateDefineAndRequestPermissions %{public}s start", bundleName_.c_str());
    auto bundleUserInfos = newInfo.GetInnerBundleUserInfos();
    for (const auto &uerInfo : bundleUserInfos) {
        if (uerInfo.second.accessTokenId == 0) {
            continue;
        }
        std::vector<std::string> newRequestPermName;
        if (!BundlePermissionMgr::UpdateDefineAndRequestPermissions(uerInfo.second.accessTokenId, oldInfo,
            newInfo, newRequestPermName)) {
            APP_LOGE("UpdateDefineAndRequestPermissions %{public}s failed", bundleName_.c_str());
            return ERR_APPEXECFWK_INSTALL_UPDATE_HAP_TOKEN_FAILED;
        }
        if (!BundlePermissionMgr::GrantRequestPermissions(newInfo, newRequestPermName, uerInfo.second.accessTokenId)) {
            APP_LOGE("BundlePermissionMgr::GrantRequestPermissions failed %{public}s", bundleName_.c_str());
            return ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED;
        }
    }
    APP_LOGD("UpdateDefineAndRequestPermissions %{public}s end", bundleName_.c_str());
    return ERR_OK;
}

void BaseBundleInstaller::RollBack(const InnerBundleInfo &info, InnerBundleInfo &oldInfo)
{
    // rollback hap installed
    if (installedModules_[info.GetCurrentModulePackage()]) {
        std::string createModulePath = info.GetAppCodePath() + Constants::PATH_SEPARATOR +
            info.GetCurrentModulePackage() + Constants::TMP_SUFFIX;
        RemoveModuleDir(createModulePath);
        oldInfo.SetCurrentModulePackage(info.GetCurrentModulePackage());
        RollBackMoudleInfo(bundleName_, oldInfo);
    } else {
        auto modulePackage = info.GetCurrentModulePackage();
        RemoveModuleDir(info.GetModuleDir(modulePackage));
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

void BaseBundleInstaller::RollBackMoudleInfo(const std::string &bundleName, InnerBundleInfo &oldInfo)
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
        APP_LOGE("uninstall bundle info missing");
        return ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_BUNDLE;
    }

    versionCode_ = oldInfo.GetVersionCode();
    ScopeGuard enableGuard([&] { dataMgr_->EnableBundle(bundleName); });

    InnerBundleUserInfo curInnerBundleUserInfo;
    if (!oldInfo.GetInnerBundleUserInfo(userId_, curInnerBundleUserInfo)) {
        APP_LOGE("bundle(%{public}s) get user(%{public}d) failed when uninstall.",
            oldInfo.GetBundleName().c_str(), userId_);
        return ERR_APPEXECFWK_USER_NOT_INSTALL_HAP;
    }

    uid = curInnerBundleUserInfo.uid;
    if (!installParam.forceExecuted && oldInfo.GetBaseApplicationInfo().isSystemApp &&
        !oldInfo.IsRemovable() && installParam.noSkipsKill) {
        APP_LOGE("uninstall system app");
        return ERR_APPEXECFWK_UNINSTALL_SYSTEM_APP_ERROR;
    }

    if (!UninstallAppControl(oldInfo.GetAppId(), userId_)) {
        APP_LOGE("bundleName: %{public}s is not allow uninstall", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_UNINSTALL;
    }

    // reboot scan case will not kill the bundle
    if (installParam.noSkipsKill) {
        // kill the bundle process during uninstall.
        if (!AbilityManagerHelper::UninstallApplicationProcesses(oldInfo.GetApplicationName(), uid)) {
            APP_LOGE("can not kill process");
            return ERR_APPEXECFWK_UNINSTALL_KILLING_APP_ERROR;
        }
    }

    if (oldInfo.GetInnerBundleUserInfos().size() > 1) {
        APP_LOGD("only delete userinfo %{public}d", userId_);
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
    APP_LOGD("finish to process %{public}s bundle uninstall", bundleName.c_str());
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
        APP_LOGE("uninstall bundle info missing");
        return ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_BUNDLE;
    }

    versionCode_ = oldInfo.GetVersionCode();
    ScopeGuard enableGuard([&] { dataMgr_->EnableBundle(bundleName); });

    InnerBundleUserInfo curInnerBundleUserInfo;
    if (!oldInfo.GetInnerBundleUserInfo(userId_, curInnerBundleUserInfo)) {
        APP_LOGE("bundle(%{public}s) get user(%{public}d) failed when uninstall.",
            oldInfo.GetBundleName().c_str(), userId_);
        return ERR_APPEXECFWK_USER_NOT_INSTALL_HAP;
    }

    uid = curInnerBundleUserInfo.uid;
    if (!installParam.forceExecuted && oldInfo.GetBaseApplicationInfo().isSystemApp
        && !oldInfo.IsRemovable() && installParam.noSkipsKill) {
        APP_LOGE("uninstall system app");
        return ERR_APPEXECFWK_UNINSTALL_SYSTEM_APP_ERROR;
    }

    bool isModuleExist = oldInfo.FindModule(modulePackage);
    if (!isModuleExist) {
        APP_LOGE("uninstall bundle info missing");
        return ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_MODULE;
    }

    if (!UninstallAppControl(oldInfo.GetAppId(), userId_)) {
        APP_LOGE("bundleName: %{public}s is not allow uninstall", bundleName.c_str());
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
            APP_LOGE("can not kill process");
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

    APP_LOGD("finish to process %{public}s in %{public}s uninstall", bundleName.c_str(), modulePackage.c_str());
    return ERR_OK;
}

ErrCode BaseBundleInstaller::ProcessInstallBundleByBundleName(
    const std::string &bundleName, const InstallParam &installParam, int32_t &uid)
{
    APP_LOGD("Process Install Bundle(%{public}s) start", bundleName.c_str());
    return InnerProcessInstallByPreInstallInfo(bundleName, installParam, uid, false);
}

ErrCode BaseBundleInstaller::ProcessRecover(
    const std::string &bundleName, const InstallParam &installParam, int32_t &uid)
{
    APP_LOGD("Process Recover Bundle(%{public}s) start", bundleName.c_str());
    ErrCode result = InnerProcessInstallByPreInstallInfo(bundleName, installParam, uid, true);
    return result;
}

ErrCode BaseBundleInstaller::InnerProcessInstallByPreInstallInfo(
    const std::string &bundleName, const InstallParam &installParam, int32_t &uid, bool recoverMode)
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
            versionCode_ = oldInfo.GetVersionCode();
            if (oldInfo.HasInnerBundleUserInfo(userId_)) {
                APP_LOGE("App is exist in user(%{public}d).", userId_);
                return ERR_APPEXECFWK_INSTALL_ALREADY_EXIST;
            }

            std::vector<std::string> installAppIds(1, oldInfo.GetAppId());
            ErrCode result = InstallAppControl(installAppIds, userId_);
            if (result != ERR_OK) {
                APP_LOGE("appid:%{private}s check install app control failed", oldInfo.GetAppId().c_str());
                return result;
            }

            bool isSingleton = oldInfo.IsSingleton();
            if ((isSingleton && (userId_ != Constants::DEFAULT_USERID)) ||
                (!isSingleton && (userId_ == Constants::DEFAULT_USERID))) {
                APP_LOGW("singleton(%{public}d) app(%{public}s) and user(%{public}d) are not matched.",
                    isSingleton, bundleName_.c_str(), userId_);
                return ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON;
            }

            InnerBundleUserInfo curInnerBundleUserInfo;
            curInnerBundleUserInfo.bundleUserInfo.userId = userId_;
            curInnerBundleUserInfo.bundleName = bundleName;
            oldInfo.AddInnerBundleUserInfo(curInnerBundleUserInfo);
            ScopeGuard userGuard([&] { RemoveBundleUserData(oldInfo, false); });
            accessTokenId_ = CreateAccessTokenId(oldInfo);
            oldInfo.SetAccessTokenId(accessTokenId_, userId_);
            result = GrantRequestPermissions(oldInfo, accessTokenId_);
            if (result != ERR_OK) {
                return result;
            }

            result = CreateBundleUserData(oldInfo);
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

    if (recoverMode) {
        if (preInstallBundleInfo.GetAppType() != Constants::AppType::SYSTEM_APP) {
            APP_LOGE("recover failed due to not system app");
            return ERR_APPEXECFWK_RECOVER_GET_BUNDLEPATH_ERROR;
        }
    }

    APP_LOGD("Get preInstall bundlePath success.");
    std::vector<std::string> pathVec { preInstallBundleInfo.GetBundlePaths() };
    auto innerInstallParam = installParam;
    innerInstallParam.isPreInstallApp = true;
    innerInstallParam.removable = preInstallBundleInfo.IsRemovable();
    innerInstallParam.copyHapToInstallPath = false;
    return ProcessBundleInstall(pathVec, innerInstallParam, preInstallBundleInfo.GetAppType(), uid);
}

ErrCode BaseBundleInstaller::RemoveBundle(InnerBundleInfo &info, bool isKeepData)
{
    ErrCode result = RemoveBundleAndDataDir(info, isKeepData);
    if (result != ERR_OK) {
        APP_LOGE("remove bundle dir failed");
        dataMgr_->UpdateBundleInstallState(info.GetBundleName(), InstallState::INSTALL_SUCCESS);
        return result;
    }

    if (!dataMgr_->UpdateBundleInstallState(info.GetBundleName(), InstallState::UNINSTALL_SUCCESS)) {
        APP_LOGE("delete inner info failed");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
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
    if (!VerifyUriPrefix(info, userId_)) {
        APP_LOGE("VerifyUriPrefix failed");
        return ERR_APPEXECFWK_INSTALL_URI_DUPLICATE;
    }
    modulePackage_ = info.GetCurrentModulePackage();
    APP_LOGD("ProcessBundleInstallStatus with bundleName %{public}s and packageName %{public}s",
        bundleName_.c_str(), modulePackage_.c_str());
    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::INSTALL_START)) {
        APP_LOGE("install already start");
        return ERR_APPEXECFWK_INSTALL_STATE_ERROR;
    }
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

    ScopeGuard bundleGuard([&] { RemoveBundleAndDataDir(info, false); });
    std::string modulePath = info.GetAppCodePath() + Constants::PATH_SEPARATOR + modulePackage_;
    result = ExtractModule(info, modulePath);
    if (result != ERR_OK) {
        APP_LOGE("extract module failed");
        return result;
    }

    info.SetInstallMark(bundleName_, modulePackage_, InstallExceptionStatus::INSTALL_FINISH);
    uid = info.GetUid(userId_);
    info.SetBundleInstallTime(BundleUtil::GetCurrentTime(), userId_);
    accessTokenId_ = CreateAccessTokenId(info);
    info.SetAccessTokenId(accessTokenId_, userId_);
    result = GrantRequestPermissions(info, accessTokenId_);
    if (result != ERR_OK) {
        return result;
    }
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

#ifdef USE_PRE_BUNDLE_PROFILE
    if (oldInfo.IsSingleton() != newInfo.IsSingleton()) {
        APP_LOGE("Singleton not allow changed");
        return ERR_APPEXECFWK_INSTALL_SINGLETON_INCOMPATIBLE;
    }
#else
    if (oldInfo.IsSingleton() && !newInfo.IsSingleton()) {
        singletonState_ = SingletonState::SINGLETON_TO_NON;
    } else if (!oldInfo.IsSingleton() && newInfo.IsSingleton()) {
        singletonState_ = SingletonState::NON_TO_SINGLETON;
    }
#endif

    APP_LOGD("ProcessBundleUpdateStatus with bundleName %{public}s and packageName %{public}s",
        newInfo.GetBundleName().c_str(), modulePackage_.c_str());
    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UPDATING_START)) {
        APP_LOGE("update already start");
        return ERR_APPEXECFWK_INSTALL_STATE_ERROR;
    }

    if (oldInfo.GetProvisionId() != newInfo.GetProvisionId()) {
        APP_LOGE("the signature of the new bundle is not the same as old one");
        return ERR_APPEXECFWK_INSTALL_FAILED_INCONSISTENT_SIGNATURE;
    }
    APP_LOGD("ProcessBundleUpdateStatus noSkipsKill = %{public}d", noSkipsKill);
    // now there are two cases for updating:
    // 1. bundle exist, hap exist, update hap
    // 2. bundle exist, install new hap
    bool isModuleExist = oldInfo.FindModule(modulePackage_);
    newInfo.RestoreFromOldInfo(oldInfo);
    auto result = isModuleExist ? ProcessModuleUpdate(newInfo, oldInfo,
        isReplace, noSkipsKill) : ProcessNewModuleInstall(newInfo, oldInfo);
    if (result != ERR_OK) {
        APP_LOGE("install module failed %{public}d", result);
        return result;
    }

    APP_LOGD("finish to call ProcessBundleUpdateStatus");
    return ERR_OK;
}

ErrCode BaseBundleInstaller::ProcessNewModuleInstall(InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo)
{
    APP_LOGD("ProcessNewModuleInstall %{public}s, userId: %{public}d.",
        newInfo.GetBundleName().c_str(), userId_);
    if (!VerifyUriPrefix(newInfo, userId_)) {
        APP_LOGE("VerifyUriPrefix failed");
        return ERR_APPEXECFWK_INSTALL_URI_DUPLICATE;
    }

    if (newInfo.HasEntry() && oldInfo.HasEntry()) {
        APP_LOGE("install more than one entry module");
        return ERR_APPEXECFWK_INSTALL_ENTRY_ALREADY_EXIST;
    }

    if (bundleInstallChecker_->IsContainModuleName(newInfo, oldInfo)) {
        APP_LOGE("moduleName is already existed");
        return ERR_APPEXECFWK_INSTALL_NOT_UNIQUE_DISTRO_MODULE_NAME;
    }

    // same version need to check app label
    ErrCode result = ERR_OK;
    if (oldInfo.GetVersionCode() == newInfo.GetVersionCode()) {
        result = CheckAppLabel(oldInfo, newInfo);
        if (result != ERR_OK) {
            APP_LOGE("CheckAppLabel failed %{public}d", result);
            return result;
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

    auto bundleUserInfos = oldInfo.GetInnerBundleUserInfos();
    for (const auto &info : bundleUserInfos) {
        if (info.second.accessTokenId == 0) {
            continue;
        }
        std::vector<std::string> newRequestPermName;
        if (!BundlePermissionMgr::AddDefineAndRequestPermissions(info.second.accessTokenId, newInfo,
            newRequestPermName)) {
            APP_LOGE("BundlePermissionMgr::AddDefineAndRequestPermissions failed %{public}s", bundleName_.c_str());
            return ERR_APPEXECFWK_INSTALL_UPDATE_HAP_TOKEN_FAILED;
        }
        if (!BundlePermissionMgr::GrantRequestPermissions(newInfo, newRequestPermName, info.second.accessTokenId)) {
            APP_LOGE("BundlePermissionMgr::GrantRequestPermissions failed %{public}s", bundleName_.c_str());
            return ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED;
        }
    }

    oldInfo.SetBundleUpdateTime(BundleUtil::GetCurrentTime(), userId_);
    if ((result = ProcessAsanDirectory(newInfo)) != ERR_OK) {
        APP_LOGE("process asan log directory failed!");
        return result;
    }
    if (!dataMgr_->AddNewModuleInfo(bundleName_, newInfo, oldInfo)) {
        APP_LOGE(
            "add module %{public}s to innerBundleInfo %{public}s failed", modulePackage_.c_str(), bundleName_.c_str());
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    moduleGuard.Dismiss();
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    // hqf extract diff file or apply diff patch failed does not affect the hap installation
    ProcessHqfInfo(oldInfo, newInfo);
#endif
    return ERR_OK;
}

ErrCode BaseBundleInstaller::ProcessModuleUpdate(InnerBundleInfo &newInfo,
    InnerBundleInfo &oldInfo, bool isReplace, bool noSkipsKill)
{
    APP_LOGD("ProcessModuleUpdate, bundleName : %{public}s, moduleName : %{public}s, userId: %{public}d.",
        newInfo.GetBundleName().c_str(), newInfo.GetCurrentModulePackage().c_str(), userId_);
    if (!VerifyUriPrefix(newInfo, userId_, true)) {
        APP_LOGE("VerifyUriPrefix failed");
        return ERR_APPEXECFWK_INSTALL_URI_DUPLICATE;
    }
    if (newInfo.HasEntry() && oldInfo.HasEntry()) {
        if (!oldInfo.IsEntryModule(modulePackage_)) {
            APP_LOGE("install more than one entry module");
            return ERR_APPEXECFWK_INSTALL_ENTRY_ALREADY_EXIST;
        }
    }

    if (!bundleInstallChecker_->IsExistedDistroModule(newInfo, oldInfo)) {
        APP_LOGE("moduleName is inconsistent in the updating hap");
        return ERR_APPEXECFWK_INSTALL_INCONSISTENT_MODULE_NAME;
    }

    ErrCode result = ERR_OK;
    if (versionCode_ == oldInfo.GetVersionCode()) {
        if ((result = CheckAppLabel(oldInfo, newInfo)) != ERR_OK) {
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

    APP_LOGE("ProcessModuleUpdate noSkipsKill = %{public}d", noSkipsKill);
    // reboot scan case will not kill the bundle
    if (noSkipsKill) {
        // kill the bundle process during updating
        if (!AbilityManagerHelper::UninstallApplicationProcesses(
            oldInfo.GetApplicationName(), oldInfo.GetUid(userId_))) {
            APP_LOGE("fail to kill running application");
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
    }

    oldInfo.SetInstallMark(bundleName_, modulePackage_, InstallExceptionStatus::UPDATING_EXISTED_START);
    if (!dataMgr_->SaveInnerBundleInfo(oldInfo)) {
        APP_LOGE("save install mark failed");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    if ((result = ProcessAsanDirectory(newInfo)) != ERR_OK) {
        APP_LOGE("process asan log directory failed!");
        return result;
    }
    result = CheckArkProfileDir(newInfo, oldInfo);
    if (result != ERR_OK) {
        return result;
    }

    moduleTmpDir_ = newInfo.GetAppCodePath() + Constants::PATH_SEPARATOR + modulePackage_ + Constants::TMP_SUFFIX;
    result = ExtractModule(newInfo, moduleTmpDir_);
    if (result != ERR_OK) {
        APP_LOGE("extract module and rename failed");
        return result;
    }

    if (!dataMgr_->UpdateBundleInstallState(bundleName_, InstallState::UPDATING_SUCCESS)) {
        APP_LOGE("old module update state failed");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    newInfo.RestoreModuleInfo(oldInfo);
    oldInfo.SetInstallMark(bundleName_, modulePackage_, InstallExceptionStatus::UPDATING_FINISH);
    oldInfo.SetBundleUpdateTime(BundleUtil::GetCurrentTime(), userId_);
    auto noUpdateInfo = oldInfo;
    if (!dataMgr_->UpdateInnerBundleInfo(bundleName_, newInfo, oldInfo)) {
        APP_LOGE("update innerBundleInfo %{public}s failed", bundleName_.c_str());
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    auto bundleUserInfos = oldInfo.GetInnerBundleUserInfos();
    for (const auto &info : bundleUserInfos) {
        if (info.second.accessTokenId == 0) {
            continue;
        }

        std::vector<std::string> newRequestPermName;
        if (!BundlePermissionMgr::UpdateDefineAndRequestPermissions(info.second.accessTokenId, noUpdateInfo,
            oldInfo, newRequestPermName)) {
            APP_LOGE("UpdateDefineAndRequestPermissions %{public}s failed", bundleName_.c_str());
            return ERR_APPEXECFWK_INSTALL_UPDATE_HAP_TOKEN_FAILED;
        }

        if (!BundlePermissionMgr::GrantRequestPermissions(oldInfo, newRequestPermName, info.second.accessTokenId)) {
            APP_LOGE("BundlePermissionMgr::GrantRequestPermissions failed %{public}s", bundleName_.c_str());
            return ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED;
        }
    }

    ErrCode ret = SetDirApl(newInfo);
    if (ret != ERR_OK) {
        APP_LOGE("SetDirApl failed");
        return ret;
    }
    needDeleteQuickFixInfo_ = true;
    return ERR_OK;
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

    ErrCode ret = ProcessDiffFiles(appQfInfo, nativeLibraryPath);
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
    ErrCode ret = ProcessDiffFiles(appQfInfo, nativeLibraryPath);
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

ErrCode BaseBundleInstaller::ProcessDiffFiles(const AppqfInfo &appQfInfo, const std::string &nativeLibraryPath) const
{
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    const std::string moduleName = modulePackage_;
    auto iter = find_if(appQfInfo.hqfInfos.begin(), appQfInfo.hqfInfos.end(),
        [&moduleName](const auto &hqfInfo) {
        return hqfInfo.moduleName == moduleName;
    });
    if (iter != appQfInfo.hqfInfos.end()) {
        // appQfInfo.nativeLibraryPath may be start with patch_versionCode
        if (!CheckHapLibsWithPatchLibs(nativeLibraryPath, appQfInfo.nativeLibraryPath)) {
            APP_LOGE("CheckHapLibsWithPatchLibs failed newInfo: %{public}s, hqf: %{public}s",
                     nativeLibraryPath.c_str(), appQfInfo.nativeLibraryPath.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_SO_INCOMPATIBLE;
        }
        const std::string tempDiffPath = Constants::HAP_COPY_PATH + Constants::PATH_SEPARATOR +
            bundleName_ + Constants::TMP_SUFFIX;
        ScopeGuard removeDiffPath([tempDiffPath] { InstalldClient::GetInstance()->RemoveDir(tempDiffPath); });
        ErrCode ret = InstalldClient::GetInstance()->ExtractDiffFiles(iter->hqfFilePath,
            tempDiffPath, appQfInfo.cpuAbi);
        if (ret != ERR_OK) {
            APP_LOGE("error: ExtractDiffFiles failed errcode :%{public}d", ret);
            return ERR_BUNDLEMANAGER_QUICK_FIX_EXTRACT_DIFF_FILES_FAILED;
        }
        std::string oldSoPath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + bundleName_ +
            Constants::PATH_SEPARATOR + nativeLibraryPath;
        std::string newSoPath = Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR + bundleName_ +
            Constants::PATH_SEPARATOR + Constants::PATCH_PATH +
            std::to_string(appQfInfo.versionCode) + Constants::PATH_SEPARATOR + nativeLibraryPath;
        ret = InstalldClient::GetInstance()->ApplyDiffPatch(oldSoPath, tempDiffPath, newSoPath);
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
            baseDataDir, info.GetBundleName(), info.GetAppPrivilegeLevel());
        if (result != ERR_OK) {
            APP_LOGE("fail to SetDirApl baseDir dir, error is %{public}d", result);
            return result;
        }
        std::string databaseDataDir = baseBundleDataDir + Constants::DATABASE + info.GetBundleName();
        result = InstalldClient::GetInstance()->SetDirApl(
            databaseDataDir, info.GetBundleName(), info.GetAppPrivilegeLevel());
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
    APP_LOGD("create bundle dir %{private}s", appCodePath.c_str());
    ErrCode result = InstalldClient::GetInstance()->CreateBundleDir(appCodePath);
    if (result != ERR_OK) {
        APP_LOGE("fail to create bundle dir, error is %{public}d", result);
        return result;
    }

    info.SetAppCodePath(appCodePath);
    return ERR_OK;
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

    auto result = InstalldClient::GetInstance()->CreateBundleDataDir(info.GetBundleName(), userId_,
        newInnerBundleUserInfo.uid, newInnerBundleUserInfo.uid, info.GetAppPrivilegeLevel());
    if (result != ERR_OK) {
        APP_LOGE("fail to create bundle data dir, error is %{public}d", result);
        return result;
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
    std::string targetSoPath;
    std::string cpuAbi;
    std::string nativeLibraryPath;
    if (info.FetchNativeSoAttrs(modulePackage_, cpuAbi, nativeLibraryPath)) {
        bool isLibIsolated = info.IsLibIsolated(info.GetCurModuleName());
        if (isLibIsolated && BundleUtil::EndWith(modulePath, Constants::TMP_SUFFIX)) {
            nativeLibraryPath = BuildTempNativeLibraryPath(nativeLibraryPath);
            APP_LOGD("Need extract to temp dir: %{public}s", nativeLibraryPath.c_str());
        }
        targetSoPath.append(Constants::BUNDLE_CODE_DIR).append(Constants::PATH_SEPARATOR)
            .append(info.GetBundleName()).append(Constants::PATH_SEPARATOR)
            .append(nativeLibraryPath).append(Constants::PATH_SEPARATOR);
    }

    APP_LOGD("begin to extract module files, modulePath : %{private}s, targetSoPath : %{private}s, cpuAbi : %{public}s",
        modulePath.c_str(), targetSoPath.c_str(), cpuAbi.c_str());
    auto result = ExtractModuleFiles(info, modulePath, targetSoPath, cpuAbi);
    if (result != ERR_OK) {
        APP_LOGE("fail to extrace module dir, error is %{public}d", result);
        return result;
    }

    result = ExtractArkNativeFile(info, modulePath);
    if (result != ERR_OK) {
        APP_LOGE("fail to extractArkNativeFile, error is %{public}d", result);
        return result;
    }

    if (info.GetIsNewVersion()) {
        result = ExtractArkProfileFile(modulePath_, info.GetBundleName(), userId_);
        if (result != ERR_OK) {
            APP_LOGE("fail to ExtractArkProfileFile, error is %{public}d", result);
            return result;
        }
    }

    if (info.IsPreInstallApp()) {
        info.SetModuleHapPath(modulePath_);
    } else {
        info.SetModuleHapPath(GetHapPath(info));
    }

    auto moduleDir = info.GetAppCodePath() + Constants::PATH_SEPARATOR + info.GetCurrentModulePackage();
    info.AddModuleSrcDir(moduleDir);
    info.AddModuleResPath(moduleDir);
    return ERR_OK;
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
    APP_LOGD("Begin to extract an file, modulePath : %{private}s, targetPath : %{private}s, cpuAbi : %{public}s",
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

ErrCode BaseBundleInstaller::ExtractAllArkProfileFile(const InnerBundleInfo &oldInfo) const
{
    if (!oldInfo.GetIsNewVersion()) {
        return ERR_OK;
    }
    std::string bundleName = oldInfo.GetBundleName();
    APP_LOGD("Begin to ExtractAllArkProfileFile, bundleName : %{public}s", bundleName.c_str());
    const auto &innerModuleInfos = oldInfo.GetInnerModuleInfos();
    for (auto iter = innerModuleInfos.cbegin(); iter != innerModuleInfos.cend(); ++iter) {
        ErrCode ret = ExtractArkProfileFile(iter->second.hapPath, bundleName, userId_);
        if (ret != ERR_OK) {
            return ret;
        }
    }
    APP_LOGD("ExtractAllArkProfileFile succeed, bundleName : %{public}s", bundleName.c_str());
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
    APP_LOGD("Begin to extract ap file, modulePath : %{private}s, targetPath : %{private}s",
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
    std::string arkNativeFilePath = oldInfo.GetArkNativeFilePath();
    if (arkNativeFilePath.empty()) {
        APP_LOGD("OldInfo(%{public}s) no arkNativeFilePath", oldInfo.GetBundleName().c_str());
        return ERR_OK;
    }

    std::string targetPath;
    targetPath.append(ARK_CACHE_PATH).append(oldInfo.GetBundleName());
    auto result = InstalldClient::GetInstance()->RemoveDir(targetPath);
    if (result != ERR_OK) {
        APP_LOGE("fail to remove arkNativeFilePath %{public}s, error is %{public}d",
            arkNativeFilePath.c_str(), result);
    }

    return result;
}

ErrCode BaseBundleInstaller::RemoveBundleAndDataDir(const InnerBundleInfo &info, bool isKeepData) const
{
    // remove bundle dir
    auto result = RemoveBundleCodeDir(info);
    if (result != ERR_OK) {
        APP_LOGE("fail to remove bundle dir %{private}s, error is %{public}d", info.GetAppCodePath().c_str(), result);
        return result;
    }
    if (!isKeepData) {
        result = RemoveBundleDataDir(info);
        if (result != ERR_OK) {
            APP_LOGE("fail to remove bundleData dir %{private}s, error is %{public}d",
                info.GetBundleName().c_str(), result);
        }
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
    if (result != ERR_OK) {
        APP_LOGE("fail to remove bundleName: %{public}s, error is %{public}d",
            info.GetBundleName().c_str(), result);
    }
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
    APP_LOGD("module dir %{private}s to be removed", modulePath.c_str());
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
    APP_LOGD("extract module to %{private}s", modulePath.c_str());
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
    checkParam.appType = appType;
    checkParam.removable = installParam.removable;
    ErrCode ret = bundleInstallChecker_->ParseHapFiles(
        bundlePaths, checkParam, hapVerifyRes, infos);
    if (ret != ERR_OK) {
        APP_LOGE("parse hap file failed due to errorCode : %{public}d", ret);
        return ret;
    }
    isContainEntry_ = bundleInstallChecker_->IsContainEntry();
    ret = bundleInstallChecker_->CheckDeviceType(infos);
    if (ret != ERR_OK) {
        APP_LOGE("CheckDeviceType failed due to errorCode : %{public}d", ret);
    }
    return ret;
}

ErrCode BaseBundleInstaller::CheckDependency(std::unordered_map<std::string, InnerBundleInfo> &infos)
{
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
    ErrCode ret = bundleInstallChecker_->CheckAppLabelInfo(infos);
    if (ret != ERR_OK) {
        return ret;
    }

    bundleName_ = (infos.begin()->second).GetBundleName();
    versionCode_ = (infos.begin()->second).GetVersionCode();
    return ERR_OK;
}

ErrCode BaseBundleInstaller::CheckMultiNativeFile(
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    return bundleInstallChecker_->CheckMultiNativeFile(infos);
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

ErrCode BaseBundleInstaller::UninstallLowerVersionFeature(const std::vector<std::string> &packageVec)
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
    if (!AbilityManagerHelper::UninstallApplicationProcesses(info.GetApplicationName(), info.GetUid(userId_))) {
        APP_LOGW("can not kill process");
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
            if (!dataMgr_->RemoveModuleInfo(bundleName_, package, info)) {
                APP_LOGE("RemoveModuleInfo failed");
                return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
            }
        }
    }
    // need to delete lower version feature hap definePermissions and requestPermissions
    APP_LOGD("delete lower version feature hap definePermissions and requestPermissions");
    ErrCode ret = UpdateDefineAndRequestPermissions(oldInfo, info);
    if (ret != ERR_OK) {
        return ret;
    }
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
    APP_LOGD("CreateNewUserData %{public}s userId: %{public}d.",
        innerBundleInfo.GetBundleName().c_str(), userId_);
    if (!innerBundleInfo.HasInnerBundleUserInfo(userId_)) {
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }

    ErrCode result = CreateBundleDataDir(innerBundleInfo);
    if (result != ERR_OK) {
        RemoveBundleDataDir(innerBundleInfo);
        return result;
    }

    innerBundleInfo.SetBundleInstallTime(BundleUtil::GetCurrentTime(), userId_);
    InnerBundleUserInfo innerBundleUserInfo;
    if (!innerBundleInfo.GetInnerBundleUserInfo(userId_, innerBundleUserInfo)) {
        APP_LOGE("oldInfo do not have user");
        return ERR_APPEXECFWK_USER_NOT_EXIST;
    }

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
    if (oldInfo.GetVersionName() != newInfo.GetVersionName()) {
        return ERR_APPEXECFWK_INSTALL_VERSIONNAME_NOT_SAME;
    }
    if (oldInfo.GetMinCompatibleVersionCode() != newInfo.GetMinCompatibleVersionCode()) {
        return ERR_APPEXECFWK_INSTALL_MINCOMPATIBLE_VERSIONCODE_NOT_SAME;
    }
    if (oldInfo.GetVendor() != newInfo.GetVendor()) {
        return ERR_APPEXECFWK_INSTALL_VENDOR_NOT_SAME;
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
    if (oldInfo.GetIsNewVersion() != newInfo.GetIsNewVersion()) {
        APP_LOGE("same version update module condition, model type must be the same");
        return ERR_APPEXECFWK_INSTALL_STATE_ERROR;
    }
    if (oldInfo.GetAsanEnabled() != newInfo.GetAsanEnabled()) {
        APP_LOGE("asanEnabled is not same");
        return ERR_APPEXECFWK_INSTALL_ASAN_ENABLED_NOT_SAME;
    }
    if (oldInfo.GetApplicationBundleType() != newInfo.GetApplicationBundleType()) {
        return ERR_APPEXECFWK_BUNDLE_TYPE_NOT_SAME;
    }
    APP_LOGD("CheckAppLabel end");
    return ERR_OK;
}

ErrCode BaseBundleInstaller::RemoveBundleUserData(InnerBundleInfo &innerBundleInfo, bool needRemoveData)
{
    auto bundleName = innerBundleInfo.GetBundleName();
    APP_LOGD("remove user(%{public}d) in bundle(%{public}s).", userId_, bundleName.c_str());
    if (!innerBundleInfo.HasInnerBundleUserInfo(userId_)) {
        return ERR_APPEXECFWK_USER_NOT_EXIST;
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

    innerBundleInfo.RemoveInnerBundleUserInfo(userId_);
    if (!dataMgr_->RemoveInnerBundleUserInfo(bundleName, userId_)) {
        APP_LOGE("update bundle user info to db failed %{public}s when remove user",
            bundleName.c_str());
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    return ERR_OK;
}

bool BaseBundleInstaller::VerifyUriPrefix(const InnerBundleInfo &info, int32_t userId, bool isUpdate) const
{
    // uriPrefix must be unique
    // verify current module uriPrefix
    std::vector<std::string> currentUriPrefixList;
    info.GetUriPrefixList(currentUriPrefixList);
    if (currentUriPrefixList.empty()) {
        APP_LOGD("current module not include uri, verify uriPrefix success");
        return true;
    }
    std::set<std::string> set;
    for (const std::string &currentUriPrefix : currentUriPrefixList) {
        if (currentUriPrefix == Constants::DATA_ABILITY_URI_PREFIX) {
            APP_LOGE("uri format invalid");
            return false;
        }
        if (!set.insert(currentUriPrefix).second) {
            APP_LOGE("current module contains duplicate uriPrefix, verify uriPrefix failed");
            APP_LOGE("bundleName : %{public}s, moduleName : %{public}s, uriPrefix : %{public}s",
                info.GetBundleName().c_str(), info.GetCurrentModulePackage().c_str(), currentUriPrefix.c_str());
            return false;
        }
    }
    set.clear();
    // verify exist bundle uriPrefix
    if (dataMgr_ == nullptr) {
        APP_LOGE("dataMgr_ is null, verify uriPrefix failed");
        return false;
    }
    std::vector<std::string> uriPrefixList;
    std::string excludeModule;
    if (isUpdate) {
        excludeModule.append(info.GetBundleName()).append(".").append(info.GetCurrentModulePackage()).append(".");
    }
    dataMgr_->GetAllUriPrefix(uriPrefixList, userId, excludeModule);
    if (uriPrefixList.empty()) {
        APP_LOGD("uriPrefixList empty, verify uriPrefix success");
        return true;
    }
    for (const std::string &currentUriPrefix : currentUriPrefixList) {
        auto iter = std::find(uriPrefixList.cbegin(), uriPrefixList.cend(), currentUriPrefix);
        if (iter != uriPrefixList.cend()) {
            APP_LOGE("uriPrefix alread exist in device, uriPrefix : %{public}s", currentUriPrefix.c_str());
            APP_LOGE("verify uriPrefix failed");
            return false;
        }
    }
    APP_LOGD("verify uriPrefix success");
    return true;
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
            hapPathRecords_.emplace(item.first, GetHapPath(item.second));
        }
    }
}

bool BaseBundleInstaller::SaveHapToInstallPath()
{
    for (const auto &hapPathRecord : hapPathRecords_) {
        APP_LOGD("Save from(%{public}s) to(%{public}s)",
            hapPathRecord.first.c_str(), hapPathRecord.second.c_str());
        if (InstalldClient::GetInstance()->CopyFile(
            hapPathRecord.first, hapPathRecord.second) != ERR_OK) {
            APP_LOGE("Copy hap to install path failed");
            return false;
        }
    }
    return true;
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
        APP_LOGD("Bundle changes from singleton app to non singleton app");
        installParam.userId = Constants::DEFAULT_USERID;
        UninstallBundle(bundleName_, installParam);
        return;
    }

    if (singletonState_ == SingletonState::NON_TO_SINGLETON) {
        APP_LOGD("Bundle changes from non singleton app to singleton app");
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
    EventReport::SendBundleSystemEvent(bundleEventType, sysEventInfo_);
}

ErrCode BaseBundleInstaller::NotifyBundleStatus(const NotifyBundleEvents &installRes)
{
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    commonEventMgr->NotifyBundleStatus(installRes, dataMgr_);
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
        info.SetAsanLogPath(asanLogDir);
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
}  // namespace AppExecFwk
}  // namespace OHOS
