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
#include "app_log_wrapper.h"
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
    APP_LOGI("BundleManagerImpl::GetBundleInfoForSelf inter");
    auto iBundleMgr = AppExecFwk::CommonFunc::GetBundleMgr();
    AppExecFwk::BundleInfo bundleInfo;
    iBundleMgr->GetBundleInfoForSelf(bundleFlags, bundleInfo);
    return bundleInfo;
}
 
int32_t BundleManagerImpl::VerifyAbc(std::vector<std::string> abcPaths, bool flag)
{
    auto verifyManager = AppExecFwk::CommonFunc::GetVerifyManager();
    if (verifyManager == nullptr) {
        APP_LOGE("VerifyAbc failed due to iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
 
    ErrCode ret = verifyManager->Verify(abcPaths);
    if (ret == ERR_OK && flag) {
        verifyManager->RemoveFiles(abcPaths);
    }
    return AppExecFwk::CommonFunc::ConvertErrCode(ret);
}

std::tuple<bool, int32_t> checkExtensionAbilityName(const AppExecFwk::ExtensionAbilityInfo& extensionInfo,
    const std::string& abilityName, AppExecFwk::ExtensionAbilityInfo& targetExtensionInfo)
{
    bool ifExists = false;
    if (extensionInfo.name == abilityName) {
        ifExists = true;
        if (!extensionInfo.enabled) {
            APP_LOGI("extension disabled");
            return {ifExists, ERROR_ABILITY_IS_DISABLED};
        }
        targetExtensionInfo = extensionInfo;
    }
    return {ifExists, SUCCESS_CODE};
}

ErrCode CheckExtensionFromBundleInfo(const AppExecFwk::BundleInfo& bundleInfo, const std::string& abilityName,
    const std::string& moduleName, AppExecFwk::ExtensionAbilityInfo& targetExtensionInfo)
{
    bool hasFoundModule = false;
    bool ifExists = false;
    int32_t res = SUCCESS_CODE;
    for (const auto& hapModuleInfo : bundleInfo.hapModuleInfos) {
        if (hapModuleInfo.moduleName != moduleName) {
            continue;
        }
        hasFoundModule = true;
        for (const auto& extensionInfo : hapModuleInfo.extensionInfos) {
            std::tie(ifExists, res) = checkExtensionAbilityName(extensionInfo, abilityName, targetExtensionInfo);
            if (res == ERROR_ABILITY_IS_DISABLED || (res == SUCCESS_CODE && ifExists == true)) {
                return res;
            }
        }
    }
    return hasFoundModule ? ERROR_ABILITY_NOT_EXIST : ERROR_MODULE_NOT_EXIST;
}

std::tuple<int32_t, std::vector<std::string>> BundleManagerImpl::GetProfileByExtensionAbility(
    std::string moduleName, std::string extensionAbilityName, char* metadataName)
{
    auto naBundleMgr = AppExecFwk::CommonFunc::GetBundleMgr();
    if (naBundleMgr == nullptr) {
        return {ERROR_BUNDLE_SERVICE_EXCEPTION, {}};
    }

    if (extensionAbilityName.empty()) {
        APP_LOGE("GetProfileByExtensionAbility failed due to empty extensionAbilityName");
        return {ERROR_ABILITY_NOT_EXIST, {}};
    }

    if (moduleName.empty()) {
        APP_LOGE("GetProfileByExtensionAbility failed due to empty moduleName");
        return {ERROR_MODULE_NOT_EXIST, {}};
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
        APP_LOGE("GetProfileByExAbility failed");
        return {ret, {}};
    }
    AppExecFwk::ExtensionAbilityInfo targetExtensionInfo;
    ret = CheckExtensionFromBundleInfo(bundleInfo, extensionAbilityName, moduleName, targetExtensionInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetProfileByExAbility failed by CheckExtensionFromBundleInfo");
        return {ret, {}};
    }
    AppExecFwk::BundleMgrClient client;
    std::vector<std::string> profileVec;
    if (!client.GetProfileFromExtension(targetExtensionInfo, metadataName, profileVec)) {
        APP_LOGE("GetProfileByExAbility failed by GetProfileFromExtension");
        return {ERROR_PROFILE_NOT_EXIST, {}};
    }
    return {SUCCESS_CODE, profileVec};
}

std::tuple<bool, int32_t> checkAbilityName(const AppExecFwk::AbilityInfo& abilityInfo,
    const std::string& abilityName, AppExecFwk::AbilityInfo& targetAbilityInfo)
{
    bool ifExists = false;
    if (abilityInfo.name == abilityName) {
        ifExists = true;
        if (!abilityInfo.enabled) {
            APP_LOGI("ability disabled");
            return {ifExists, ERROR_ABILITY_IS_DISABLED};
        }
        targetAbilityInfo = abilityInfo;
    }
    return {ifExists, SUCCESS_CODE};
}

ErrCode CheckAbilityFromBundleInfo(const AppExecFwk::BundleInfo& bundleInfo, const std::string& abilityName,
    const std::string& moduleName, AppExecFwk::AbilityInfo& targetAbilityInfo)
{
    bool hasFoundModule = false;
    bool ifExists = false;
    int32_t res = SUCCESS_CODE;
    for (const auto& hapModuleInfo : bundleInfo.hapModuleInfos) {
        if (hapModuleInfo.moduleName != moduleName) {
            continue;
        }
        hasFoundModule = true;
        for (const auto& abilityInfo : hapModuleInfo.abilityInfos) {
            std::tie(ifExists, res) = checkAbilityName(abilityInfo, abilityName, targetAbilityInfo);
            if (res == ERROR_ABILITY_IS_DISABLED || (res == SUCCESS_CODE && ifExists == true)) {
                return res;
            }
        }
    }
    return hasFoundModule ? ERROR_ABILITY_NOT_EXIST : ERROR_MODULE_NOT_EXIST;
}

std::tuple<int32_t, std::vector<std::string>> BundleManagerImpl::GetProfileByAbility(
    std::string moduleName, std::string abilityName, char* metadataName)
{
    APP_LOGI("GetProfileByAbility called");
    auto iBundleMgr = AppExecFwk::CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        return {ERROR_BUNDLE_SERVICE_EXCEPTION, {}};
    }

    if (abilityName.empty()) {
        APP_LOGE("GetProfileByAbility failed due to empty abilityName");
        return {ERROR_ABILITY_NOT_EXIST, {}};
    }

    if (moduleName.empty()) {
        APP_LOGE("GetProfileByAbility failed due to empty moduleName");
        return {ERROR_MODULE_NOT_EXIST, {}};
    }

    auto baseFlag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) +
           static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA) +
           static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE);
    auto getAbilityFlag = baseFlag + static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY);
    AppExecFwk::BundleInfo bundleInfo;
    ErrCode ret = AppExecFwk::CommonFunc::ConvertErrCode(iBundleMgr->GetBundleInfoForSelf(getAbilityFlag, bundleInfo));
    if (ret != ERR_OK) {
        APP_LOGE("GetProfileByAbility failed");
        return {ret, {}};
    }
    AppExecFwk::AbilityInfo targetAbilityInfo;
    ret = CheckAbilityFromBundleInfo(bundleInfo, abilityName, moduleName, targetAbilityInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetProfileByAbility failed by CheckAbilityFromBundleInfo");
        return {ret, {}};
    }
    AppExecFwk::BundleMgrClient client;
    std::vector<std::string> profileVec;
    if (!client.GetProfileFromAbility(targetAbilityInfo, metadataName, profileVec)) {
        APP_LOGE("GetProfileByAbility failed by GetProfileFromAbility");
        return {ERROR_PROFILE_NOT_EXIST, {}};
    }
    return {SUCCESS_CODE, profileVec};
}

bool BundleManagerImpl::InnerCanOpenLink(std::string link, int32_t& code)
{
    bool canOpen = false;
    auto iBundleMgr = AppExecFwk::CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        code = ERROR_BUNDLE_SERVICE_EXCEPTION;
        return canOpen;
    }
    code = AppExecFwk::CommonFunc::ConvertErrCode(
        iBundleMgr->CanOpenLink(link, canOpen));
    if (code != NO_ERROR) {
        APP_LOGE("CanOpenLink failed");
        return canOpen;
    }
    return canOpen;
}

} // BundleManager
} // CJSystemapi
} // OHOS