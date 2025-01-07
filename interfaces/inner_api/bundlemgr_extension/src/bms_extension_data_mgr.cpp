/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <dlfcn.h>

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "bms_extension_data_mgr.h"
#include "bms_extension_profile.h"
#include "bundle_mgr_ext_register.h"
#include "parameter.h"

namespace OHOS {
namespace AppExecFwk {
BmsExtension BmsExtensionDataMgr::bmsExtension_;
void *BmsExtensionDataMgr::handler_ = nullptr;
namespace {
static std::mutex stateMutex;
const std::string BMS_EXTENSION_PATH = "/system/etc/app/bms-extensions.json";
const uint32_t API_VERSION_BASE = 1000;
}

BmsExtensionDataMgr::BmsExtensionDataMgr()
{
}

ErrCode BmsExtensionDataMgr::Init()
{
    std::lock_guard<std::mutex> stateLock(stateMutex);
    if (bmsExtension_.bmsExtensionBundleMgr.extensionName.empty() || !handler_) {
        BmsExtensionProfile bmsExtensionProfile;
        auto res = bmsExtensionProfile.ParseBmsExtension(BMS_EXTENSION_PATH, bmsExtension_);
        if (res != ERR_OK) {
            APP_LOGW("ParseBmsExtension failed %{public}d", res);
            return ERR_APPEXECFWK_PARSE_UNEXPECTED;
        }
        APP_LOGD("parse bms-extension.json success, which is: %{public}s", bmsExtension_.ToString().c_str());
        if (!OpenHandler()) {
            APP_LOGW("dlopen bms-extension so failed");
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
    }
    return ERR_OK;
}

bool BmsExtensionDataMgr::OpenHandler()
{
    APP_LOGD("OpenHandler start");
    auto handle = &handler_;
    if (handle == nullptr) {
        APP_LOGE("OpenHandler error handle is nullptr");
        return false;
    }
    auto libPath = bmsExtension_.bmsExtensionBundleMgr.libPath.c_str();
    auto lib64Path = bmsExtension_.bmsExtensionBundleMgr.lib64Path.c_str();
    *handle = dlopen(lib64Path, RTLD_NOW | RTLD_GLOBAL);
    if (*handle == nullptr) {
        APP_LOGW("open %{public}s failed %{public}s", lib64Path, dlerror());
        *handle = dlopen(libPath, RTLD_NOW | RTLD_GLOBAL);
    }
    if (*handle == nullptr) {
        APP_LOGE("open %{public}s failed %{public}s", libPath, dlerror());
        return false;
    }
    APP_LOGD("OpenHandler end");
    return true;
}

bool BmsExtensionDataMgr::CheckApiInfo(const BundleInfo &bundleInfo, uint32_t sdkVersion)
{
    if ((Init() == ERR_OK) && handler_) {
        auto bundleMgrExtPtr =
            BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
        if (bundleMgrExtPtr) {
            return bundleMgrExtPtr->CheckApiInfo(bundleInfo);
        }
        APP_LOGE("create class: %{public}s failed", bmsExtension_.bmsExtensionBundleMgr.extensionName.c_str());
        return false;
    }
    APP_LOGW("access bms-extension failed");
    return CheckApiInfo(bundleInfo.compatibleVersion, sdkVersion);
}

bool BmsExtensionDataMgr::CheckApiInfo(uint32_t compatibleVersion, uint32_t sdkVersion)
{
    APP_LOGD("CheckApiInfo with compatibleVersion:%{public}d, sdkVersion:%{public}d", compatibleVersion, sdkVersion);
    uint32_t compatibleVersionOHOS = compatibleVersion % API_VERSION_BASE;
    return compatibleVersionOHOS <= sdkVersion;
}

ErrCode BmsExtensionDataMgr::HapVerify(const std::string &filePath, Security::Verify::HapVerifyResult &hapVerifyResult)
{
    if ((Init() == ERR_OK) && handler_) {
        auto bundleMgrExtPtr =
            BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
        if (bundleMgrExtPtr == nullptr) {
            APP_LOGW("bundleMgrExtPtr is nullptr");
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
        return bundleMgrExtPtr->HapVerify(filePath, hapVerifyResult);
    }
    APP_LOGW("access bms-extension failed");
    return ERR_BUNDLEMANAGER_INSTALL_FAILED_SIGNATURE_EXTENSION_NOT_EXISTED;
}

bool BmsExtensionDataMgr::IsRdDevice()
{
    if ((Init() != ERR_OK) || handler_ == nullptr) {
        APP_LOGW("link failed");
        return false;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return false;
    }
    return bundleMgrExtPtr->IsRdDevice();
}

ErrCode BmsExtensionDataMgr::QueryAbilityInfos(const Want &want, int32_t userId,
    std::vector<AbilityInfo> &abilityInfos)
{
    if ((Init() == ERR_OK) && handler_) {
        auto bundleMgrExtPtr =
            BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
        if (bundleMgrExtPtr == nullptr) {
            LOG_W(BMS_TAG_QUERY, "bundleMgrExtPtr is nullptr");
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
        return bundleMgrExtPtr->QueryAbilityInfos(want, userId, abilityInfos);
    }
    LOG_W(BMS_TAG_QUERY, "access bms-extension failed");
    return ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED;
}

ErrCode BmsExtensionDataMgr::QueryAbilityInfosWithFlag(const Want &want, int32_t flags, int32_t userId,
    std::vector<AbilityInfo> &abilityInfos, bool isNewVersion)
{
    if ((Init() == ERR_OK) && handler_) {
        auto bundleMgrExtPtr =
            BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
        if (bundleMgrExtPtr == nullptr) {
            LOG_W(BMS_TAG_QUERY, "bundleMgrExtPtr is nullptr");
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
        return bundleMgrExtPtr->QueryAbilityInfosWithFlag(want, flags, userId, abilityInfos, isNewVersion);
    }
    LOG_W(BMS_TAG_QUERY, "access bms-extension failed");
    return ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED;
}

ErrCode BmsExtensionDataMgr::GetBundleInfos(int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId,
    bool isNewVersion)
{
    if ((Init() == ERR_OK) && handler_) {
        auto bundleMgrExtPtr =
            BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
        if (bundleMgrExtPtr == nullptr) {
            LOG_W(BMS_TAG_QUERY, "bundleMgrExtPtr is nullptr");
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
        return bundleMgrExtPtr->GetBundleInfos(flags, bundleInfos, userId, isNewVersion);
    }
    LOG_W(BMS_TAG_QUERY, "access bms-extension failed");
    return ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED;
}

ErrCode BmsExtensionDataMgr::GetBundleInfo(const std::string &bundleName, int32_t flags, int32_t userId,
    BundleInfo &bundleInfo, bool isNewVersion)
{
    if ((Init() == ERR_OK) && handler_) {
        auto bundleMgrExtPtr =
            BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
        if (bundleMgrExtPtr == nullptr) {
            LOG_W(BMS_TAG_QUERY, "bundleMgrExtPtr is nullptr");
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
        return bundleMgrExtPtr->GetBundleInfo(bundleName, flags, userId, bundleInfo, isNewVersion);
    }
    LOG_W(BMS_TAG_QUERY, "access bms-extension failed");
    return ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED;
}

ErrCode BmsExtensionDataMgr::Uninstall(const std::string &bundleName)
{
    if ((Init() == ERR_OK) && handler_) {
        auto bundleMgrExtPtr =
            BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
        if (bundleMgrExtPtr == nullptr) {
            APP_LOGW("bundleMgrExtPtr is nullptr");
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
        return bundleMgrExtPtr->Uninstall(bundleName);
    }
    APP_LOGW("access bms-extension failed");
    return ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED;
}

ErrCode BmsExtensionDataMgr::GetBundleStats(
    const std::string &bundleName, int32_t userId, std::vector<int64_t> &bundleStats)
{
    if ((Init() != ERR_OK) || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    return bundleMgrExtPtr->GetBundleStats(bundleName, userId, bundleStats);
}

ErrCode BmsExtensionDataMgr::ClearData(const std::string &bundleName, int32_t userId)
{
    if ((Init() != ERR_OK) || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    return bundleMgrExtPtr->ClearData(bundleName, userId);
}

ErrCode BmsExtensionDataMgr::ClearCache(const std::string &bundleName, sptr<IRemoteObject> callback, int32_t userId)
{
    if ((Init() != ERR_OK) || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    return bundleMgrExtPtr->ClearCache(bundleName, callback, userId);
}

ErrCode BmsExtensionDataMgr::GetUidByBundleName(const std::string &bundleName, int32_t userId, int32_t &uid)
{
    if ((Init() != ERR_OK) || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    return bundleMgrExtPtr->GetUidByBundleName(bundleName, userId, uid);
}

ErrCode BmsExtensionDataMgr::GetBundleNameByUid(int32_t uid, std::string &bundleName)
{
    if ((Init() != ERR_OK) || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    return bundleMgrExtPtr->GetBundleNameByUid(uid, bundleName);
}

ErrCode BmsExtensionDataMgr::VerifyActivationLock(bool &res)
{
    if ((Init() != ERR_OK) || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    return bundleMgrExtPtr->VerifyActivationLock(res);
}

ErrCode BmsExtensionDataMgr::GetBackupUninstallList(int32_t userId, std::set<std::string> &uninstallBundles)
{
    if (Init() != ERR_OK || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    return bundleMgrExtPtr->GetBackupUninstallList(userId, uninstallBundles);
}

ErrCode BmsExtensionDataMgr::ClearBackupUninstallFile(int32_t userId)
{
    if (Init() != ERR_OK || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    return bundleMgrExtPtr->ClearBackupUninstallFile(userId);
}

bool BmsExtensionDataMgr::IsAppInBlocklist(const std::string &bundleName, const int32_t userId)
{
    if ((Init() != ERR_OK) || handler_ == nullptr) {
        APP_LOGW("link failed");
        return false;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return false;
    }
    return bundleMgrExtPtr->IsAppInBlocklist(bundleName, userId);
}

bool BmsExtensionDataMgr::CheckWhetherCanBeUninstalled(const std::string &bundleName)
{
    if ((Init() != ERR_OK) || handler_ == nullptr) {
        APP_LOGW("link failed");
        return true;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return true;
    }
    return bundleMgrExtPtr->CheckWhetherCanBeUninstalled(bundleName);
}

ErrCode BmsExtensionDataMgr::AddResourceInfoByBundleName(const std::string &bundleName, const int32_t userId)
{
    if (Init() != ERR_OK || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    ErrCode ret = bundleMgrExtPtr->AddResourceInfoByBundleName(bundleName, userId);
    APP_LOGD("call bundle mgr ext return %{public}d by bundleName:%{public}s userId:%{private}d",
        ret, bundleName.c_str(), userId);
    return ret;
}

ErrCode BmsExtensionDataMgr::AddResourceInfoByAbility(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, const int32_t userId)
{
    if (Init() != ERR_OK || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    ErrCode ret = bundleMgrExtPtr->AddResourceInfoByAbility(bundleName, moduleName, abilityName, userId);
    APP_LOGD("call bundle mgr ext return %{public}d by bundleName:%{public}s moduleName:%{public}s \
        abilityName:%{public}s userId:%{private}d",
        ret, bundleName.c_str(), moduleName.c_str(), abilityName.c_str(), userId);
    return ret;
}

ErrCode BmsExtensionDataMgr::DeleteResourceInfo(const std::string &key)
{
    if (Init() != ERR_OK || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    ErrCode ret = bundleMgrExtPtr->DeleteResourceInfo(key);
    APP_LOGD("call bundle mgr ext return %{public}d by key:%{private}s", ret, key.c_str());
    return ret;
}

ErrCode BmsExtensionDataMgr::KeyOperation(
    const std::vector<CodeProtectBundleInfo> &codeProtectBundleInfos, int32_t type)
{
    if ((Init() != ERR_OK) || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_OK;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_OK;
    }
    auto ret = bundleMgrExtPtr->KeyOperation(codeProtectBundleInfos, type);
    if (!codeProtectBundleInfos.empty()) {
        APP_LOGI("KeyOperation %{public}s %{public}d ret %{public}d",
            codeProtectBundleInfos[0].bundleName.c_str(), type, ret);
    }
    return ret;
}

ErrCode BmsExtensionDataMgr::OptimizeDisposedPredicates(const std::string &callingName, const std::string &appId,
    int32_t userId, int32_t appIndex, NativeRdb::AbsRdbPredicates &absRdbPredicates)
{
    if (Init() != ERR_OK || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    ErrCode ret = bundleMgrExtPtr->OptimizeDisposedPredicates(callingName, appId, userId, appIndex, absRdbPredicates);
    APP_LOGD("call bundle mgr ext OptimizeDisposedPredicates, return %{public}d, result:%{private}s",
        ret, absRdbPredicates.ToString().c_str());
    return ret;
}

ErrCode BmsExtensionDataMgr::GetBundleResourceInfo(const std::string &bundleName, const uint32_t flags,
    BundleResourceInfo &bundleResourceInfo, const int32_t appIndex)
{
    if (Init() != ERR_OK || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    ErrCode ret = bundleMgrExtPtr->GetBundleResourceInfo(bundleName, flags, bundleResourceInfo, appIndex);
    APP_LOGD("call bundle mgr ext GetBundleResourceInfo, return %{public}d, bundleName:%{public}s",
        ret, bundleName.c_str());
    return ret;
}

ErrCode BmsExtensionDataMgr::GetLauncherAbilityResourceInfo(const std::string &bundleName, const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfo, const int32_t appIndex)
{
    if (Init() != ERR_OK || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    ErrCode ret =
        bundleMgrExtPtr->GetLauncherAbilityResourceInfo(bundleName, flags, launcherAbilityResourceInfo, appIndex);
    APP_LOGD("call bundle mgr ext GetLauncherAbilityResourceInfo, return %{public}d, bundleName:%{public}s",
        ret, bundleName.c_str());
    return ret;
}

ErrCode BmsExtensionDataMgr::GetAllBundleResourceInfo(const uint32_t flags,
    std::vector<BundleResourceInfo> &bundleResourceInfos)
{
    if (Init() != ERR_OK || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    ErrCode ret = bundleMgrExtPtr->GetAllBundleResourceInfo(flags, bundleResourceInfos);
    APP_LOGD("call bundle mgr ext GetAllBundleResourceInfo, return %{public}d", ret);
    return ret;
}

ErrCode BmsExtensionDataMgr::GetAllLauncherAbilityResourceInfo(const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos)
{
    if (Init() != ERR_OK || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    ErrCode ret = bundleMgrExtPtr->GetAllLauncherAbilityResourceInfo(flags, launcherAbilityResourceInfos);
    APP_LOGD("call bundle mgr ext GetAllLauncherAbilityResourceInfo, return %{public}d", ret);
    return ret;
}

void BmsExtensionDataMgr::CheckBundleNameAndStratAbility(const std::string &bundleName,
    const std::string &appIdentifier)
{
    if (Init() != ERR_OK || handler_ == nullptr) {
        APP_LOGW("link failed");
        return;
    }
    if (bundleName.empty()) {
        APP_LOGW("bundleName empty");
        return;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return;
    }
    bundleMgrExtPtr->CheckBundleNameAndStratAbility(bundleName, appIdentifier);
}

bool BmsExtensionDataMgr::DetermineCloneNum(
    const std::string &bundleName, const std::string &appIdentifier, int32_t &cloneNum)
{
    if (Init() != ERR_OK || handler_ == nullptr) {
        APP_LOGW("link failed");
        return false;
    }
    if (bundleName.empty()) {
        APP_LOGW("bundleName empty");
        return false;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return false;
    }
    return bundleMgrExtPtr->DetermineCloneNum(bundleName, appIdentifier, cloneNum);
}

std::string BmsExtensionDataMgr::GetCompatibleDeviceType(const std::string &bundleName)
{
    if ((Init() == ERR_OK) && handler_) {
        auto bundleMgrExtPtr =
            BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
        if (bundleMgrExtPtr) {
            return bundleMgrExtPtr->GetCompatibleDeviceType(bundleName);
        }
        APP_LOGE("create class: %{public}s failed", bmsExtension_.bmsExtensionBundleMgr.extensionName.c_str());
        return GetDeviceType();
    }
    APP_LOGW("access bms-extension failed");
    return GetDeviceType();
}

ErrCode BmsExtensionDataMgr::VerifyActivationLockToken(bool &res)
{
    if ((Init() != ERR_OK) || handler_ == nullptr) {
        APP_LOGW("link failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR;
    }
    return bundleMgrExtPtr->VerifyActivationLockToken(res);
}

bool BmsExtensionDataMgr::IsNeedToSkipPreBundleInstall()
{
    if (Init() != ERR_OK || handler_ == nullptr) {
        APP_LOGW("link failed");
        return false;
    }
    auto bundleMgrExtPtr =
        BundleMgrExtRegister::GetInstance().GetBundleMgrExt(bmsExtension_.bmsExtensionBundleMgr.extensionName);
    if (bundleMgrExtPtr == nullptr) {
        APP_LOGW("GetBundleMgrExt failed");
        return false;
    }
    return bundleMgrExtPtr->IsNeedToSkipPreBundleInstall();
}
} // AppExecFwk
} // OHOS
