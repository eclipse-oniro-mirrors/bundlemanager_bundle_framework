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

#include "pre_bundle_profile.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int8_t COMMON_PRIORITY = 0;
constexpr int8_t HIGH_PRIORITY = 1;
constexpr const char* INSTALL_LIST = "install_list";
constexpr const char* APP_LIST = "app_list";
constexpr const char* ON_DEMAND_INSTALL_LIST = "on_demand_install_list";
constexpr const char* UNINSTALL_LIST = "uninstall_list";
constexpr const char* EXTENSION_TYPE = "extensionType";
constexpr const char* RECOVER_LIST = "recover_list";
constexpr const char* APP_DIR = "app_dir";
constexpr const char* REMOVABLE = "removable";
constexpr const char* APPIDENTIFIER = "appIdentifier";
constexpr const char* ON_DEMAND_INSTALL = "on_demand_install";
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* TYPE_NAME = "name";
constexpr const char* KEEP_ALIVE = "keepAlive";
constexpr const char* SINGLETON = "singleton";
constexpr const char* ALLOW_COMMON_EVENT = "allowCommonEvent";
constexpr const char* RUNNING_RESOURCES_APPLY = "runningResourcesApply";
constexpr const char* APP_SIGNATURE = "app_signature";
constexpr const char* ASSOCIATED_WAKE_UP = "associatedWakeUp";
constexpr const char* RESOURCES_PATH_1 = "/app/ohos.global.systemres";
constexpr const char* RESOURCES_PATH_2 = "/app/SystemResources";
constexpr const char* DATA_PRELOAD_APP = "/data/preload/app/";
constexpr const char* ALLOW_APP_DATA_NOT_CLEARED = "allowAppDataNotCleared";
constexpr const char* ALLOW_APP_MULTI_PROCESS = "allowAppMultiProcess";
constexpr const char* ALLOW_APP_DESKTOP_ICON_HIDE = "allowAppDesktopIconHide";
constexpr const char* ALLOW_ABILITY_PRIORITY_QUERIED = "allowAbilityPriorityQueried";
constexpr const char* ALLOW_ABILITY_EXCLUDE_FROM_MISSIONS = "allowAbilityExcludeFromMissions";
constexpr const char* ALLOW_MISSION_NOT_CLEARED = "allowMissionNotCleared";
constexpr const char* ALLOW_APP_USE_PRIVILEGE_EXTENSION = "allowAppUsePrivilegeExtension";
constexpr const char* ALLOW_FORM_VISIBLE_NOTIFY = "allowFormVisibleNotify";
constexpr const char* ALLOW_APP_SHARE_LIBRARY = "allowAppShareLibrary";
constexpr const char* ALLOW_ENABLE_NOTIFICATION = "allowEnableNotification";
constexpr const char* ALLOW_APP_RUN_WHEN_DEVICE_FIRST_LOCKED = "allowAppRunWhenDeviceFirstLocked";
constexpr const char* RESOURCES_APPLY = "resourcesApply";
}

ErrCode PreBundleProfile::TransformTo(
    const nlohmann::json &jsonBuf,
    std::set<PreScanInfo> &scanInfos) const
{
    APP_LOGI_NOFUNC("transform jsonBuf to PreScanInfos");
    if (jsonBuf.is_discarded()) {
        APP_LOGE("profile format error");
        return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
    }
    
    if (jsonBuf.find(INSTALL_LIST) == jsonBuf.end()) {
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }

    auto arrays = jsonBuf.at(INSTALL_LIST);
    if (!arrays.is_array() || arrays.empty()) {
        APP_LOGE("value is not array");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }
    int32_t result = ERR_OK;
    PreScanInfo preScanInfo;
    for (const auto &array : arrays) {
        if (!array.is_object()) {
            APP_LOGE("array is not json object");
            return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        }

        preScanInfo.Reset();
        const auto &jsonObjectEnd = array.end();
        int32_t parseResult = ERR_OK;
        BMSJsonUtil::GetStrValueIfFindKey(array,
            jsonObjectEnd,
            APP_DIR,
            preScanInfo.bundleDir,
            true,
            parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            REMOVABLE,
            preScanInfo.removable,
            false,
            parseResult);
        bool isResourcesPath =
            (preScanInfo.bundleDir.find(RESOURCES_PATH_1) != preScanInfo.bundleDir.npos) ||
            (preScanInfo.bundleDir.find(RESOURCES_PATH_2) != preScanInfo.bundleDir.npos);
        preScanInfo.priority = isResourcesPath ? HIGH_PRIORITY : COMMON_PRIORITY;
        if (parseResult == ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP) {
            APP_LOGE("bundleDir must exist, and it is empty here");
            continue;
        }

        if (parseResult != ERR_OK) {
            APP_LOGE("parse from install json failed, error %{public}d", parseResult);
            result = parseResult;
            continue;
        }

        APP_LOGD("preScanInfo(%{public}s)", preScanInfo.ToString().c_str());
        auto iter = std::find(scanInfos.begin(), scanInfos.end(), preScanInfo);
        if (iter != scanInfos.end()) {
            APP_LOGD("Replace old preScanInfo(%{public}s)", preScanInfo.bundleDir.c_str());
            scanInfos.erase(iter);
        }

        scanInfos.insert(preScanInfo);
    }

    return result;
}

ErrCode PreBundleProfile::TransformToAppList(const nlohmann::json &jsonBuf, std::set<PreScanInfo> &scanAppInfos,
    std::set<PreScanInfo> &scanDemandInfos) const
{
    if (jsonBuf.is_discarded()) {
        return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
    }

    if (jsonBuf.find(APP_LIST) == jsonBuf.end()) {
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }

    auto arrays = jsonBuf.at(APP_LIST);
    if (!arrays.is_array() || arrays.empty()) {
        APP_LOGE("value is not array");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }
    int32_t result = ERR_OK;
    PreScanInfo preScanInfo;
    for (const auto &array : arrays) {
        if (!array.is_object()) {
            APP_LOGE("array is not json object");
            return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        }

        preScanInfo.Reset();
        const auto &jsonObjectEnd = array.end();
        int32_t parseResult = ERR_OK;
        BMSJsonUtil::GetStrValueIfFindKey(array, jsonObjectEnd, APP_DIR, preScanInfo.bundleDir, true, parseResult);
        BMSJsonUtil::GetStrValueIfFindKey(
            array, jsonObjectEnd, APPIDENTIFIER, preScanInfo.appIdentifier, true, parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(
            array, jsonObjectEnd, ON_DEMAND_INSTALL, preScanInfo.onDemandInstall, false, parseResult);
        preScanInfo.priority = COMMON_PRIORITY;
        preScanInfo.isDataPreloadHap = (preScanInfo.bundleDir.find(DATA_PRELOAD_APP) == 0);
        if (!preScanInfo.isDataPreloadHap || preScanInfo.bundleDir.empty() || preScanInfo.appIdentifier.empty()) {
            APP_LOGE("set parameter BMS_DATA_PRELOAD false");
            result = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
            continue;
        }

        if (parseResult != ERR_OK) {
            APP_LOGE("parse from install json failed, error %{public}d", parseResult);
            result = parseResult;
            continue;
        }

        auto iter = std::find(scanAppInfos.begin(), scanAppInfos.end(), preScanInfo);
        if (iter != scanAppInfos.end()) {
            APP_LOGD("replace old preScanInfo(%{public}s)", preScanInfo.bundleDir.c_str());
            scanAppInfos.erase(iter);
        }

        scanAppInfos.insert(preScanInfo);
    }

    ProcessOnDemandList(scanAppInfos, scanDemandInfos);
    return result;
}

ErrCode PreBundleProfile::TransformToDemandList(const nlohmann::json &jsonBuf,
    std::set<PreScanInfo> &scanDemandInfos) const
{
    if (jsonBuf.is_discarded()) {
        return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
    }

    if (jsonBuf.find(ON_DEMAND_INSTALL_LIST) == jsonBuf.end()) {
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }

    auto arrays = jsonBuf.at(ON_DEMAND_INSTALL_LIST);
    if (!arrays.is_array() || arrays.empty()) {
        APP_LOGE("value is not array");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }
    int32_t result = ERR_OK;
    PreScanInfo preScanInfo;
    for (const auto &array : arrays) {
        if (!array.is_object()) {
            APP_LOGE("array is not json object");
            return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        }

        preScanInfo.Reset();
        const auto &jsonObjectEnd = array.end();
        int32_t parseResult = ERR_OK;
        BMSJsonUtil::GetStrValueIfFindKey(array, jsonObjectEnd, APP_DIR, preScanInfo.bundleDir, true, parseResult);
        preScanInfo.priority = COMMON_PRIORITY;
        preScanInfo.onDemandInstall = true;
        if (parseResult == ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP) {
            APP_LOGE("bundleDir must exist, and it is empty here");
            continue;
        }

        if (parseResult != ERR_OK) {
            APP_LOGE("parse from on demand install json failed, error %{public}d", parseResult);
            result = parseResult;
            continue;
        }

        auto iter = std::find(scanDemandInfos.begin(), scanDemandInfos.end(), preScanInfo);
        if (iter != scanDemandInfos.end()) {
            APP_LOGD("replace old scanDemandInfos(%{public}s)", preScanInfo.bundleDir.c_str());
            scanDemandInfos.erase(iter);
        }

        scanDemandInfos.insert(preScanInfo);
    }

    return result;
}

ErrCode PreBundleProfile::TransformTo(
    const nlohmann::json &jsonBuf,
    std::set<std::string> &uninstallList) const
{
    APP_LOGD("transform jsonBuf to bundleNames");
    if (jsonBuf.is_discarded()) {
        APP_LOGE("profile format error");
        return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
    }

    const auto &jsonObjectEnd = jsonBuf.end();
    int32_t parseResult = ERR_OK;
    std::vector<std::string> names;
    GetValueIfFindKey<std::vector<std::string>>(jsonBuf,
        jsonObjectEnd,
        UNINSTALL_LIST,
        names,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    for (const auto &name : names) {
        APP_LOGD("uninstall bundleName %{public}s", name.c_str());
        uninstallList.insert(name);
    }

    names.clear();
    GetValueIfFindKey<std::vector<std::string>>(jsonBuf,
        jsonObjectEnd,
        RECOVER_LIST,
        names,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    for (const auto &name : names) {
        APP_LOGD("recover bundleName %{public}s", name.c_str());
        uninstallList.erase(name);
    }

    return parseResult;
}

ErrCode PreBundleProfile::TransformTo(
    const nlohmann::json &jsonBuf,
    std::set<PreBundleConfigInfo> &preBundleConfigInfos) const
{
    APP_LOGI("transform jsonBuf to preBundleConfigInfos");
    if (jsonBuf.is_discarded()) {
        APP_LOGE("profile format error");
        return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
    }

    if (jsonBuf.find(INSTALL_LIST) == jsonBuf.end()) {
        APP_LOGE("installList no exist");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }

    auto arrays = jsonBuf.at(INSTALL_LIST);
    if (!arrays.is_array() || arrays.empty()) {
        APP_LOGE("value is not array");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }

    int32_t result = ERR_OK;
    PreBundleConfigInfo preBundleConfigInfo;
    for (const auto &array : arrays) {
        if (!array.is_object()) {
            APP_LOGE("array is not json object");
            return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        }

        preBundleConfigInfo.Reset();
        const auto &jsonObjectEnd = array.end();
        int32_t parseResult = ERR_OK;
        BMSJsonUtil::GetStrValueIfFindKey(array,
            jsonObjectEnd,
            BUNDLE_NAME,
            preBundleConfigInfo.bundleName,
            true,
            parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            KEEP_ALIVE,
            preBundleConfigInfo.keepAlive,
            false,
            parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            SINGLETON,
            preBundleConfigInfo.singleton,
            false,
            parseResult);
        GetValueIfFindKey<std::vector<std::string>>(array,
            jsonObjectEnd,
            ALLOW_COMMON_EVENT,
            preBundleConfigInfo.allowCommonEvent,
            JsonType::ARRAY,
            false,
            parseResult,
            ArrayType::STRING);
        GetValueIfFindKey<std::vector<std::string>>(array,
            jsonObjectEnd,
            APP_SIGNATURE,
            preBundleConfigInfo.appSignature,
            JsonType::ARRAY,
            false,
            parseResult,
            ArrayType::STRING);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            RUNNING_RESOURCES_APPLY,
            preBundleConfigInfo.runningResourcesApply,
            false,
            parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            ASSOCIATED_WAKE_UP,
            preBundleConfigInfo.associatedWakeUp,
            false,
            parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            ALLOW_APP_DATA_NOT_CLEARED,
            preBundleConfigInfo.userDataClearable,
            false,
            parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            ALLOW_APP_MULTI_PROCESS,
            preBundleConfigInfo.allowMultiProcess,
            false,
            parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            ALLOW_APP_DESKTOP_ICON_HIDE,
            preBundleConfigInfo.hideDesktopIcon,
            false,
            parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            ALLOW_ABILITY_PRIORITY_QUERIED,
            preBundleConfigInfo.allowQueryPriority,
            false,
            parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            ALLOW_ABILITY_EXCLUDE_FROM_MISSIONS,
            preBundleConfigInfo.allowExcludeFromMissions,
            false,
            parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            ALLOW_MISSION_NOT_CLEARED,
            preBundleConfigInfo.allowMissionNotCleared,
            false,
            parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            ALLOW_APP_USE_PRIVILEGE_EXTENSION,
            preBundleConfigInfo.allowUsePrivilegeExtension,
            false,
            parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            ALLOW_FORM_VISIBLE_NOTIFY,
            preBundleConfigInfo.formVisibleNotify,
            false,
            parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            ALLOW_APP_SHARE_LIBRARY,
            preBundleConfigInfo.appShareLibrary,
            false,
            parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            ALLOW_ENABLE_NOTIFICATION,
            preBundleConfigInfo.allowEnableNotification,
            false,
            parseResult);
        BMSJsonUtil::GetBoolValueIfFindKey(array,
            jsonObjectEnd,
            ALLOW_APP_RUN_WHEN_DEVICE_FIRST_LOCKED,
            preBundleConfigInfo.allowAppRunWhenDeviceFirstLocked,
            false,
            parseResult);
        GetValueIfFindKey<std::vector<int32_t>>(array,
            jsonObjectEnd,
            RESOURCES_APPLY,
            preBundleConfigInfo.resourcesApply,
            JsonType::ARRAY,
            false,
            parseResult,
            ArrayType::NUMBER);
        if (array.find(ALLOW_APP_DATA_NOT_CLEARED) != jsonObjectEnd) {
            preBundleConfigInfo.existInJsonFile.push_back(ALLOW_APP_DATA_NOT_CLEARED);
            preBundleConfigInfo.userDataClearable = !preBundleConfigInfo.userDataClearable;
        }
        if (array.find(ALLOW_APP_MULTI_PROCESS) != jsonObjectEnd) {
            preBundleConfigInfo.existInJsonFile.push_back(ALLOW_APP_MULTI_PROCESS);
        }
        if (array.find(ALLOW_APP_DESKTOP_ICON_HIDE) != jsonObjectEnd) {
            preBundleConfigInfo.existInJsonFile.push_back(ALLOW_APP_DESKTOP_ICON_HIDE);
        }
        if (array.find(ALLOW_ABILITY_PRIORITY_QUERIED) != jsonObjectEnd) {
            preBundleConfigInfo.existInJsonFile.push_back(ALLOW_ABILITY_PRIORITY_QUERIED);
        }
        if (array.find(ALLOW_ABILITY_EXCLUDE_FROM_MISSIONS) != jsonObjectEnd) {
            preBundleConfigInfo.existInJsonFile.push_back(ALLOW_ABILITY_EXCLUDE_FROM_MISSIONS);
        }
        if (array.find(ALLOW_MISSION_NOT_CLEARED) != jsonObjectEnd) {
            preBundleConfigInfo.existInJsonFile.push_back(ALLOW_MISSION_NOT_CLEARED);
        }
        if (array.find(ALLOW_APP_USE_PRIVILEGE_EXTENSION) != jsonObjectEnd) {
            preBundleConfigInfo.existInJsonFile.push_back(ALLOW_APP_USE_PRIVILEGE_EXTENSION);
        }
        if (array.find(ALLOW_FORM_VISIBLE_NOTIFY) != jsonObjectEnd) {
            preBundleConfigInfo.existInJsonFile.push_back(ALLOW_FORM_VISIBLE_NOTIFY);
        }
        if (array.find(ALLOW_APP_SHARE_LIBRARY) != jsonObjectEnd) {
            preBundleConfigInfo.existInJsonFile.push_back(ALLOW_APP_SHARE_LIBRARY);
        }
        if (array.find(ALLOW_ENABLE_NOTIFICATION) != jsonObjectEnd) {
            preBundleConfigInfo.existInJsonFile.push_back(ALLOW_ENABLE_NOTIFICATION);
        }
        if (parseResult == ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP) {
            APP_LOGE("bundlename must exist, and it is empty here");
            continue;
        }

        if (parseResult != ERR_OK) {
            APP_LOGE("parse from capability json failed, error %{public}d", parseResult);
            result = parseResult;
            continue;
        }

        APP_LOGD("preBundleConfigInfo(%{public}s)", preBundleConfigInfo.ToString().c_str());
        auto iter = preBundleConfigInfos.find(preBundleConfigInfo);
        if (iter != preBundleConfigInfos.end()) {
            APP_LOGD("Replace old preBundleConfigInfo(%{public}s)",
                preBundleConfigInfo.bundleName.c_str());
            preBundleConfigInfos.erase(iter);
        }

        preBundleConfigInfos.insert(preBundleConfigInfo);
    }

    return result;
}

ErrCode PreBundleProfile::TransformJsonToExtensionTypeList(
    const nlohmann::json &jsonBuf, std::set<std::string> &extensionTypeList) const
{
    if (jsonBuf.is_discarded()) {
        APP_LOGE("Profile format error");
        return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
    }

    if (jsonBuf.find(EXTENSION_TYPE) == jsonBuf.end()) {
        APP_LOGE("Profile does not have 'extensionType'key");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }

    auto arrays = jsonBuf.at(EXTENSION_TYPE);
    if (!arrays.is_array() || arrays.empty()) {
        APP_LOGE("Value is not array");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
    }

    for (const auto &array : arrays) {
        if (!array.is_object()) {
            APP_LOGE("Array is not json object");
            return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        }

        std::string extensionAbilityType;
        const auto &jsonObjectEnd = array.end();
        int32_t parseResult = ERR_OK;
        BMSJsonUtil::GetStrValueIfFindKey(array,
            jsonObjectEnd,
            TYPE_NAME,
            extensionAbilityType,
            true,
            parseResult);
        extensionTypeList.insert(extensionAbilityType);
    }

    return ERR_OK;
}

void PreBundleProfile::ProcessOnDemandList(std::set<PreScanInfo> &scanAppInfos,
    std::set<PreScanInfo> &scanDemandInfos) const
{
    for (auto iter = scanAppInfos.begin(); iter != scanAppInfos.end();) {
        if (iter->onDemandInstall) {
            PreScanInfo preScanInfo;
            preScanInfo.removable = iter->removable;
            preScanInfo.isDataPreloadHap = iter->isDataPreloadHap;
            preScanInfo.priority = iter->priority;
            preScanInfo.bundleDir = iter->bundleDir;
            preScanInfo.appIdentifier = iter->appIdentifier;
            preScanInfo.onDemandInstall = iter->onDemandInstall;
            scanDemandInfos.insert(preScanInfo);
            iter = scanAppInfos.erase(iter);
            APP_LOGI("%{public}s is onDemandInstall", iter->bundleDir.c_str());
        } else {
            ++iter;
        }
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
