/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <vector>
#include <shared_mutex>

#include "bundle_manager.h"
#include "bundle_manager_log.h"
#include "bundle_info.h"
#include "bundle_mgr_proxy.h"
#include "common_func.h"
#include "bundle_error.h"
#include "bundle_manager_sync.h"
#include "extension_ability_info.h"
#include "ability_info.h"
#include "bundle_mgr_client.h"

namespace OHOS {
namespace CJSystemapi {

namespace BundleManager {

AppExecFwk::BundleInfo BundleManagerImpl::GetBundleInfoForSelf(int32_t bundleFlags)
{
    LOGI("BundleManagerImpl::GetBundleInfoForSelf inter");
    auto iBundleMgr = AppExecFwk::CommonFunc::GetBundleMgr();
    AppExecFwk::BundleInfo bundleInfo;
    iBundleMgr->GetBundleInfoForSelf(bundleFlags, bundleInfo);
    return bundleInfo;
}
 
int32_t BundleManagerImpl::VerifyAbc(std::vector<std::string> abcPaths, bool flag)
{
    auto verifyManager = AppExecFwk::CommonFunc::GetVerifyManager();
    if (verifyManager == nullptr) {
        LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
 
    ErrCode ret = verifyManager->Verify(abcPaths);
    if (ret == ERR_OK && flag) {
        verifyManager->RemoveFiles(abcPaths);
    }
    return AppExecFwk::CommonFunc::ConvertErrCode(ret);
}

int32_t checkExtensionAbilityInfoExist(const std::string& abilityName,
    const AppExecFwk::ExtensionAbilityInfo abilityInfo,
    AppExecFwk::ExtensionAbilityInfo& targetAbilityInfo)
{
    if (abilityInfo.name == abilityName) {
        if (!abilityInfo.enabled) {
            LOGI("ability disabled");
            return ERROR_ABILITY_IS_DISABLED;
        }
        targetAbilityInfo = abilityInfo;
        return ERR_OK;
    }
    return ERROR_ABILITY_NOT_EXIST;
}

std::tuple<bool, int32_t> checkExtensionName(const AppExecFwk::ExtensionAbilityInfo& extensionInfo,
    const std::string& moduleName, const std::string& abilityName,
    AppExecFwk::ExtensionAbilityInfo& targetExtensionInfo)
{
    bool flag = false;
    if (extensionInfo.moduleName == moduleName) {
        flag = true;
        int32_t res = checkExtensionAbilityInfoExist(abilityName, extensionInfo, targetExtensionInfo);
        if (res != ERROR_ABILITY_NOT_EXIST) {
            return {flag, res};
        }
    }
    return {flag, ERROR_ABILITY_NOT_EXIST};
}

ErrCode CheckExtensionFromBundleInfo(const AppExecFwk::BundleInfo& bundleInfo, const std::string& abilityName,
    const std::string& moduleName, AppExecFwk::ExtensionAbilityInfo& targetExtensionInfo)
{
    bool flag = false;
    for (const auto& hapModuleInfo : bundleInfo.hapModuleInfos) {
        for (const auto& extensionInfo : hapModuleInfo.extensionInfos) {
            auto [flag, res] = checkExtensionName(extensionInfo, moduleName, abilityName, targetExtensionInfo);
            if (flag == true && res != ERROR_ABILITY_NOT_EXIST) {
                return res;
            }
        }
    }
    if (flag) {
        return ERROR_ABILITY_NOT_EXIST;
    } else {
        return ERROR_MODULE_NOT_EXIST;
    }
}

std::tuple<int32_t, std::vector<std::string>> BundleManagerImpl::GetProfileByExtensionAbility(
    std::string moduleName, std::string extensionAbilityName, char* metadataName)
{
    if (moduleName.empty()) {
        LOGE("param failed due to empty moduleName");
        return {ERROR_MODULE_NOT_EXIST, {}};
    }

    if (extensionAbilityName.empty()) {
        LOGE("param failed due to empty extensionAbilityName");
        return {ERROR_ABILITY_NOT_EXIST, {}};
    }
    auto naBundleMgr = AppExecFwk::CommonFunc::GetBundleMgr();
    if (naBundleMgr == nullptr) {
        return {ERROR_BUNDLE_SERVICE_EXCEPTION, {}};
    }
    auto baseFlag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) +
           static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA) +
           static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE);
    auto getExtensionFlag = baseFlag +
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY);
    AppExecFwk::BundleInfo bundleInfo;
    ErrCode ret = AppExecFwk::CommonFunc::ConvertErrCode(
        naBundleMgr->GetBundleInfoForSelf(getExtensionFlag, bundleInfo));
    if (ret != ERR_OK) {
        LOGE("GetProfileByExAbilitySync failed");
        return {ret, {}};
    }
    AppExecFwk::ExtensionAbilityInfo targetExtensionInfo;
    ret = CheckExtensionFromBundleInfo(bundleInfo, extensionAbilityName, moduleName, targetExtensionInfo);
    if (ret != ERR_OK) {
        LOGE("GetProfileByExAbilitySync failed by CheckExtensionFromBundleInfo");
        return {ret, {}};
    }
    AppExecFwk::BundleMgrClient client;
    std::vector<std::string> profileVec;
    if (!client.GetProfileFromExtension(targetExtensionInfo, metadataName, profileVec)) {
        LOGE("GetProfileByExAbilitySync failed by GetProfileFromExtension");
        return {ERROR_PROFILE_NOT_EXIST, {}};
    }
    return {SUCCESS_CODE, profileVec};
}

int32_t checkAbilityInfoExist(const std::string& abilityName, const AppExecFwk::AbilityInfo abilityInfo,
    AppExecFwk::AbilityInfo& targetAbilityInfo)
{
    if (abilityInfo.name == abilityName) {
        if (!abilityInfo.enabled) {
            LOGI("ability disabled");
            return ERROR_ABILITY_IS_DISABLED;
        }
        targetAbilityInfo = abilityInfo;
        return ERR_OK;
    }
    return ERROR_ABILITY_NOT_EXIST;
}

std::tuple<bool, int32_t> checkAbilityName(const AppExecFwk::AbilityInfo& abilityInfo, const std::string& moduleName,
    const std::string& abilityName, AppExecFwk::AbilityInfo& targetAbilityInfo)
{
    bool flag = false;
    if (abilityInfo.moduleName == moduleName) {
        flag = true;
        int32_t res = checkAbilityInfoExist(abilityName, abilityInfo, targetAbilityInfo);
        if (res != ERROR_ABILITY_NOT_EXIST) {
            return {flag, res};
        }
    }
    return {flag, ERROR_ABILITY_NOT_EXIST};
}

ErrCode CheckAbilityFromBundleInfo(const AppExecFwk::BundleInfo& bundleInfo, const std::string& abilityName,
    const std::string& moduleName, AppExecFwk::AbilityInfo& targetAbilityInfo)
{
    bool flag = false;
    std::map<std::string, std::map<std::string, bool>> abilityInfos;
    for (const auto& hapModuleInfo : bundleInfo.hapModuleInfos) {
        for (const auto& abilityInfo : hapModuleInfo.abilityInfos) {
            auto [flag, res] = checkAbilityName(abilityInfo, moduleName, abilityName, targetAbilityInfo);
            if (flag == true && res != ERROR_ABILITY_NOT_EXIST) {
                return res;
            }
        }
    }
    if (flag) {
        return ERROR_ABILITY_NOT_EXIST;
    } else {
        return ERROR_MODULE_NOT_EXIST;
    }
}

std::tuple<int32_t, std::vector<std::string>> BundleManagerImpl::GetProfileByAbility(
    std::string moduleName, std::string abilityName, char* metadataName)
{
    LOGI("NAPI GetProfileByAbilitySync called");
    if (moduleName.empty()) {
        LOGE("param failed due to empty moduleName");
        return {ERROR_MODULE_NOT_EXIST, {}};
    }
    if (abilityName.empty()) {
        LOGE("param failed due to empty abilityName");
        return {ERROR_ABILITY_NOT_EXIST, {}};
    }
    auto iBundleMgr = AppExecFwk::CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        return {ERROR_BUNDLE_SERVICE_EXCEPTION, {}};
    }
    auto baseFlag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) +
           static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA) +
           static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE);
    auto getAbilityFlag = baseFlag + static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY);
    AppExecFwk::BundleInfo bundleInfo;
    ErrCode ret = AppExecFwk::CommonFunc::ConvertErrCode(iBundleMgr->GetBundleInfoForSelf(getAbilityFlag, bundleInfo));
    if (ret != ERR_OK) {
        LOGE("GetProfileByAbilitySync failed");
        return {ret, {}};
    }
    AppExecFwk::AbilityInfo targetAbilityInfo;
    ret = CheckAbilityFromBundleInfo(bundleInfo, abilityName, moduleName, targetAbilityInfo);
    if (ret != ERR_OK) {
        LOGE("GetProfileByAbilitySync failed by CheckAbilityFromBundleInfo");
        return {ret, {}};
    }
    AppExecFwk::BundleMgrClient client;
    std::vector<std::string> profileVec;
    if (!client.GetProfileFromAbility(targetAbilityInfo, metadataName, profileVec)) {
        LOGE("GetProfileByAbilitySync failed by GetProfileFromAbility");
        return {ERROR_PROFILE_NOT_EXIST, {}};
    }
    return {SUCCESS_CODE, profileVec};
}


} // BundleManager
} // CJSystemapi
} // OHOS