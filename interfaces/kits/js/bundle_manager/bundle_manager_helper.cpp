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

#include "bundle_manager_helper.h"

#include "app_log_wrapper.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"
#include "ipc_skeleton.h"
#include "verify_manager_client.h"

namespace OHOS {
namespace AppExecFwk {

ErrCode BundleManagerHelper::InnerBatchQueryAbilityInfos(
    const std::vector<OHOS::AAFwk::Want>& wants, int32_t flags, int32_t userId, std::vector<AbilityInfo>& abilityInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->BatchQueryAbilityInfos(wants, flags, userId, abilityInfos);
    APP_LOGD("BatchQueryAbilityInfos ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerGetDynamicIcon(const std::string& bundleName, std::string& moduleName)
{
    auto extResourceManager = CommonFunc::GetExtendResourceManager();
    if (extResourceManager == nullptr) {
        APP_LOGE("extResourceManager is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = extResourceManager->GetDynamicIcon(bundleName, moduleName);
    if (ret != ERR_OK) {
        APP_LOGE_NOFUNC("GetDynamicIcon failed");
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerIsAbilityEnabled(const AbilityInfo& abilityInfo, bool& isEnable, int32_t appIndex)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = ERR_OK;
    if (appIndex != 0) {
        ret = bundleMgr->IsCloneAbilityEnabled(abilityInfo, appIndex, isEnable);
    } else {
        ret = bundleMgr->IsAbilityEnabled(abilityInfo, isEnable);
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerSetAbilityEnabled(const AbilityInfo& abilityInfo, bool& isEnable, int32_t appIndex)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = ERR_OK;
    if (appIndex != 0) {
        ret = bundleMgr->SetCloneAbilityEnabled(abilityInfo, appIndex, isEnable);
    } else {
        ret = bundleMgr->SetAbilityEnabled(abilityInfo, isEnable);
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerSetApplicationEnabled(const std::string& bundleName, bool& isEnable, int32_t appIndex)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = ERR_OK;
    if (appIndex == 0) {
        ret = bundleMgr->SetApplicationEnabled(bundleName, isEnable);
    } else {
        ret = bundleMgr->SetCloneApplicationEnabled(bundleName, appIndex, isEnable);
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerEnableDynamicIcon(
    const std::string& bundleName, const std::string& moduleName, int32_t appIndex, int32_t userId, bool isDefault)
{
    auto extResourceManager = CommonFunc::GetExtendResourceManager();
    if (extResourceManager == nullptr) {
        APP_LOGE("extResourceManager is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = ERR_OK;
    if (isDefault) {
        ret = extResourceManager->EnableDynamicIcon(bundleName, moduleName);
    } else {
        ret = extResourceManager->EnableDynamicIcon(bundleName, moduleName, userId, appIndex);
    }
    if (ret != ERR_OK) {
        APP_LOGE("EnableDynamicIcon failed %{public}d", ret);
    }

    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerGetAppCloneIdentity(int32_t uid, std::string& bundleName, int32_t& appIndex)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetNameAndIndexForUid(uid, bundleName, appIndex);
    APP_LOGD("GetNameAndIndexForUid ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerGetBundleArchiveInfo(std::string& hapFilePath, int32_t flags, BundleInfo& bundleInfo)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetBundleArchiveInfoV9(hapFilePath, flags, bundleInfo);
    APP_LOGD("GetBundleArchiveInfoV9 ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::GetAbilityFromBundleInfo(const BundleInfo& bundleInfo, const std::string& abilityName,
    const std::string& moduleName, AbilityInfo& targetAbilityInfo)
{
    bool ifExists = false;
    for (const auto& hapModuleInfo : bundleInfo.hapModuleInfos) {
        for (const auto& abilityInfo : hapModuleInfo.abilityInfos) {
            if (abilityInfo.name == abilityName && abilityInfo.moduleName == moduleName) {
                if (!abilityInfo.enabled) {
                    APP_LOGI("ability disabled");
                    return ERR_BUNDLE_MANAGER_ABILITY_DISABLED;
                }
                ifExists = true;
                targetAbilityInfo = abilityInfo;
                break;
            }
        }
        if (ifExists) {
            break;
        }
    }
    if (!ifExists) {
        APP_LOGE("ability not exist");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode BundleManagerHelper::GetExtensionFromBundleInfo(const BundleInfo& bundleInfo, const std::string& abilityName,
    const std::string& moduleName, ExtensionAbilityInfo& targetExtensionInfo)
{
    bool ifExists = false;
    for (const auto& hapModuleInfo : bundleInfo.hapModuleInfos) {
        for (const auto& extensionInfo : hapModuleInfo.extensionInfos) {
            if (extensionInfo.name == abilityName && extensionInfo.moduleName == moduleName) {
                ifExists = true;
                targetExtensionInfo = extensionInfo;
                break;
            }
            if (!extensionInfo.enabled) {
                APP_LOGI("extension disabled");
                return ERR_BUNDLE_MANAGER_ABILITY_DISABLED;
            }
        }
        if (ifExists) {
            break;
        }
    }
    if (!ifExists) {
        APP_LOGE("ability not exist");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode BundleManagerHelper::CommonInnerGetProfile(const std::string& moduleName, const std::string& abilityName,
    const std::string& metadataName, bool isExtensionProfile, std::vector<std::string>& profileVec)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    if (abilityName.empty()) {
        APP_LOGE("InnerGetProfile failed due to empty abilityName");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }

    if (moduleName.empty()) {
        APP_LOGE("InnerGetProfile failed due to empty moduleName");
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    auto baseFlag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) +
                    static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA) +
                    static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE);
    ErrCode result;
    BundleMgrClient client;
    BundleInfo bundleInfo;
    if (!isExtensionProfile) {
        auto getAbilityFlag = baseFlag + static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY);
        result = iBundleMgr->GetBundleInfoForSelf(getAbilityFlag, bundleInfo);
        if (result != ERR_OK) {
            APP_LOGE("GetBundleInfoForSelf failed");
            return result;
        }
        AbilityInfo targetAbilityInfo;
        result = GetAbilityFromBundleInfo(bundleInfo, abilityName, moduleName, targetAbilityInfo);
        if (result != ERR_OK) {
            return result;
        }
        if (!client.GetProfileFromAbility(targetAbilityInfo, metadataName, profileVec)) {
            APP_LOGE("GetProfileFromExtension failed");
            return ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST;
        }
        return ERR_OK;
    } else {
        auto getExtensionFlag =
            baseFlag + static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY);
        result = iBundleMgr->GetBundleInfoForSelf(getExtensionFlag, bundleInfo);
        if (result != ERR_OK) {
            APP_LOGE("GetBundleInfoForSelf failed");
            return result;
        }

        ExtensionAbilityInfo targetExtensionInfo;
        result = GetExtensionFromBundleInfo(bundleInfo, abilityName, moduleName, targetExtensionInfo);
        if (result != ERR_OK) {
            return result;
        }
        if (!client.GetProfileFromExtension(targetExtensionInfo, metadataName, profileVec)) {
            APP_LOGE("GetProfileFromExtension failed");
            return ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST;
        }
        return ERR_OK;
    }

    APP_LOGE("InnerGetProfile failed due to type is invalid");
    return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
}

ErrCode BundleManagerHelper::InnerGetPermissionDef(const std::string& permissionName, PermissionDef& permissionDef)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetPermissionDef(permissionName, permissionDef);
    APP_LOGD("GetPermissionDef ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerCleanBundleCacheCallback(
    const std::string &bundleName, int32_t appIndex, const OHOS::sptr<CleanCacheCallback> cleanCacheCallback)
{
    if (cleanCacheCallback == nullptr) {
        APP_LOGE("callback nullptr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    int32_t userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    ErrCode result = iBundleMgr->CleanBundleCacheFiles(bundleName, cleanCacheCallback, userId, appIndex);
    if (result != ERR_OK) {
        APP_LOGE("call error, bundleName is %{public}s, userId is %{public}d, appIndex is %{public}d",
            bundleName.c_str(), userId, appIndex);
    }
    return CommonFunc::ConvertErrCode(result);
}

ErrCode BundleManagerHelper::InnerGetAppProvisionInfo(
    const std::string& bundleName, int32_t userId, AppProvisionInfo& appProvisionInfo)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetAppProvisionInfo(bundleName, userId, appProvisionInfo);
    APP_LOGD("GetAppProvisionInfo ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerGetAllPreinstalledApplicationInfos(
    std::vector<PreinstalledApplicationInfo>& preinstalledApplicationInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("IBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetAllPreinstalledApplicationInfos(preinstalledApplicationInfos);
    APP_LOGD("GetAllPreinstalledApplicationInfos ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerGetAllAppCloneBundleInfo(
    const std::string& bundleName, int32_t bundleFlags, int32_t userId, std::vector<BundleInfo>& bundleInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    BundleInfo bundleInfoMain;
    ErrCode ret = iBundleMgr->GetCloneBundleInfo(bundleName, bundleFlags, 0, bundleInfoMain, userId);
    APP_LOGD("GetMainBundleInfo appIndex = 0, ret=%{public}d", ret);
    if (ret == ERR_OK) {
        bundleInfos.emplace_back(bundleInfoMain);
    }
    if (ret != ERR_OK && ret != ERR_BUNDLE_MANAGER_APPLICATION_DISABLED && ret != ERR_BUNDLE_MANAGER_BUNDLE_DISABLED) {
        return CommonFunc::ConvertErrCode(ret);
    }
    // handle clone apps
    std::vector<int32_t> appIndexes;
    ErrCode getCloneIndexesRet = iBundleMgr->GetCloneAppIndexes(bundleName, appIndexes, userId);
    if (getCloneIndexesRet != ERR_OK) {
        if (ret == ERR_OK) {
            return SUCCESS;
        }
        return CommonFunc::ConvertErrCode(ret);
    }
    for (int32_t appIndex : appIndexes) {
        BundleInfo bundleInfo;
        ret = iBundleMgr->GetCloneBundleInfo(bundleName, bundleFlags, appIndex, bundleInfo, userId);
        if (ret == ERR_OK) {
            bundleInfos.emplace_back(bundleInfo);
        }
    }
    if (bundleInfos.empty()) {
        return ERROR_BUNDLE_IS_DISABLED;
    }
    return SUCCESS;
}

ErrCode BundleManagerHelper::InnerGetAllSharedBundleInfo(std::vector<SharedBundleInfo>& sharedBundles)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetAllSharedBundleInfo(sharedBundles);
    APP_LOGD("GetAllSharedBundleInfo ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerGetSharedBundleInfo(
    const std::string& bundleName, const std::string& moduleName, std::vector<SharedBundleInfo>& sharedBundles)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetSharedBundleInfo(bundleName, moduleName, sharedBundles);
    APP_LOGD("GetSharedBundleInfo ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerGetExtResource(const std::string& bundleName, std::vector<std::string>& moduleNames)
{
    auto extResourceManager = CommonFunc::GetExtendResourceManager();
    if (extResourceManager == nullptr) {
        APP_LOGE("extResourceManager is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    ErrCode ret = extResourceManager->GetExtResource(bundleName, moduleNames);
    if (ret != ERR_OK) {
        APP_LOGE("GetExtResource failed");
    }
    APP_LOGD("GetExtResource ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerDisableDynamicIcon(
    const std::string& bundleName, int32_t appIndex, int32_t userId, bool isDefault)
{
    auto extResourceManager = CommonFunc::GetExtendResourceManager();
    if (extResourceManager == nullptr) {
        APP_LOGE("extResourceManager is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }

    ErrCode ret = ERR_OK;
    if (isDefault) {
        ret = extResourceManager->DisableDynamicIcon(bundleName);
    } else {
        ret = extResourceManager->DisableDynamicIcon(bundleName, userId, appIndex);
    }
    if (ret != ERR_OK) {
        APP_LOGE("DisableDynamicIcon failed %{public}d", ret);
    }

    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerGetDynamicIconInfo(
    const std::string& bundleName, std::vector<DynamicIconInfo>& dynamicIconInfos)
{
    auto extResourceManager = CommonFunc::GetExtendResourceManager();
    if (extResourceManager == nullptr) {
        APP_LOGE("extResourceManager is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = extResourceManager->GetDynamicIconInfo(bundleName, dynamicIconInfos);
    if (ret != ERR_OK) {
        APP_LOGE_NOFUNC("-n %{public}s GetDynamicIcon failed %{public}d", bundleName.c_str(), ret);
    }

    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerGetAllDynamicIconInfo(
    const int32_t userId, std::vector<DynamicIconInfo>& dynamicIconInfos)
{
    auto extResourceManager = CommonFunc::GetExtendResourceManager();
    if (extResourceManager == nullptr) {
        APP_LOGE("extResourceManager is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = extResourceManager->GetAllDynamicIconInfo(userId, dynamicIconInfos);
    if (ret != ERR_OK) {
        APP_LOGE_NOFUNC("GetDynamicIcon failed %{public}d", ret);
    }

    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerVerify(const std::vector<std::string>& abcPaths, bool flag)
{
    ErrCode ret = VerifyManagerClient::GetInstance().Verify(abcPaths);
    if (ret == ERR_OK && flag) {
        VerifyManagerClient::GetInstance().RemoveFiles(abcPaths);
    }
    if (ret != ERR_OK) {
        APP_LOGE("VerifyAbc %{public}d", ret);
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerDeleteAbc(const std::string& path)
{
    ErrCode ret = VerifyManagerClient::GetInstance().DeleteAbc(path);
    if (ret == ERR_APPEXECFWK_NULL_PTR) {
        APP_LOGE("VerifyAbc failed due to iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    if (ret != ERR_OK) {
        APP_LOGE("DeleteAbc %{public}d", ret);
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerGetRecoverableApplicationInfo(
    std::vector<RecoverableApplicationInfo>& recoverableApplications)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetRecoverableApplicationInfo(recoverableApplications);
    APP_LOGD("GetRecoverableApplicationInfo ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerGetAllPluginInfo(
    std::string& hostBundleName, int32_t userId, std::vector<PluginBundleInfo>& pluginBundleInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetAllPluginInfo(hostBundleName, userId, pluginBundleInfos);
    APP_LOGD("GetAllPluginInfo ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerGetAbilityInfos(
    const std::string& uri, uint32_t flags, std::vector<AbilityInfo>& abilityInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->GetAbilityInfos(uri, flags, abilityInfos);
    APP_LOGD("GetAbilityInfos ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}
} // AppExecFwk
} // OHOS