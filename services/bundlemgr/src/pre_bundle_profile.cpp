/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "app_log_wrapper.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t COMMON_PRIORITY = 0;
const int32_t HIGH_PRIORITY = 1;
const std::string INSTALL_LIST = "install_list";
const std::string UNINSTALL_LIST = "uninstall_list";
const std::string EXTENSION_TYPE = "extensionType";
const std::string RECOVER_LIST = "recover_list";
const std::string INSTALL_ABILITY_CONFIGS = "install_ability_configs";
const std::string APP_DIR = "app_dir";
const std::string REMOVABLE = "removable";
const std::string PRIORITY = "priority";
const std::string BUNDLE_NAME = "bundleName";
const std::string TYPE_NAME = "name";
const std::string KEEP_ALIVE = "keepAlive";
const std::string SINGLETON = "singleton";
const std::string ALLOW_COMMON_EVENT = "allowCommonEvent";
const std::string RUNNING_RESOURCES_APPLY = "runningResourcesApply";
const std::string APP_SIGNATURE = "app_signature";
const std::string ASSOCIATED_WAKE_UP = "associatedWakeUp";
const std::string RESOURCES_PATH_1 = "/app/ohos.global.systemres";
const std::string RESOURCES_PATH_2 = "/app/SystemResources";
const std::string ALLOW_APP_DATA_NOT_CLEARED = "allowAppDataNotCleared";
const std::string ALLOW_APP_MULTI_PROCESS = "allowAppMultiProcess";
const std::string ALLOW_APP_DESKTOP_ICON_HIDE = "allowAppDesktopIconHide";
const std::string ALLOW_ABILITY_PRIORITY_QUERIED = "allowAbilityPriorityQueried";
const std::string ALLOW_ABILITY_EXCLUDE_FROM_MISSIONS = "allowAbilityExcludeFromMissions";
const std::string ALLOW_MISSION_NOT_CLEARED = "allowMissionNotCleared";
const std::string ALLOW_APP_USE_PRIVILEGE_EXTENSION = "allowAppUsePrivilegeExtension";
const std::string ALLOW_FORM_VISIBLE_NOTIFY = "allowFormVisibleNotify";
const std::string ALLOW_APP_SHARE_LIBRARY = "allowAppShareLibrary";
const std::string ALLOW_ENABLE_NOTIFICATION = "allowEnableNotification";
const std::string ALLOW_APP_RUN_WHEN_DEVICE_FIRST_LOCKED = "allowAppRunWhenDeviceFirstLocked";
const std::string RESOURCES_APPLY = "resourcesApply";
}

ErrCode PreBundleProfile::TransformTo(
    const nlohmann::json &jsonBuf,
    std::set<PreScanInfo> &scanInfos) const
{
    APP_LOGI("transform jsonBuf to PreScanInfos");
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

    PreScanInfo preScanInfo;
    for (const auto &array : arrays) {
        if (!array.is_object()) {
            APP_LOGE("array is not json object");
            return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        }

        preScanInfo.Reset();
        const auto &jsonObjectEnd = array.end();
        int32_t parseResult = ERR_OK;
        GetValueIfFindKey<std::string>(array,
            jsonObjectEnd,
            APP_DIR,
            preScanInfo.bundleDir,
            JsonType::STRING,
            true,
            parseResult,
            ArrayType::NOT_ARRAY);
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            REMOVABLE,
            preScanInfo.removable,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
        bool isResourcesPath =
            (preScanInfo.bundleDir.find(RESOURCES_PATH_1) != preScanInfo.bundleDir.npos) ||
            (preScanInfo.bundleDir.find(RESOURCES_PATH_2) != preScanInfo.bundleDir.npos);
        preScanInfo.priority = isResourcesPath ? HIGH_PRIORITY : COMMON_PRIORITY;
        if (parseResult == ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP) {
            APP_LOGE("bundleDir must exist, and it is empty here");
            continue;
        }

        if (parseResult != ERR_OK) {
            APP_LOGE("parse from json failed");
            return parseResult;
        }

        APP_LOGD("preScanInfo(%{public}s)", preScanInfo.ToString().c_str());
        auto iter = std::find(scanInfos.begin(), scanInfos.end(), preScanInfo);
        if (iter != scanInfos.end()) {
            APP_LOGD("Replace old preScanInfo(%{public}s)", preScanInfo.bundleDir.c_str());
            scanInfos.erase(iter);
        }

        scanInfos.insert(preScanInfo);
    }

    return ERR_OK;
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

    PreBundleConfigInfo preBundleConfigInfo;
    for (const auto &array : arrays) {
        if (!array.is_object()) {
            APP_LOGE("array is not json object");
            return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        }

        preBundleConfigInfo.Reset();
        const auto &jsonObjectEnd = array.end();
        int32_t parseResult = ERR_OK;
        GetValueIfFindKey<std::string>(array,
            jsonObjectEnd,
            BUNDLE_NAME,
            preBundleConfigInfo.bundleName,
            JsonType::STRING,
            true,
            parseResult,
            ArrayType::NOT_ARRAY);
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            KEEP_ALIVE,
            preBundleConfigInfo.keepAlive,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            SINGLETON,
            preBundleConfigInfo.singleton,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
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
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            RUNNING_RESOURCES_APPLY,
            preBundleConfigInfo.runningResourcesApply,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            ASSOCIATED_WAKE_UP,
            preBundleConfigInfo.associatedWakeUp,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            ALLOW_APP_DATA_NOT_CLEARED,
            preBundleConfigInfo.userDataClearable,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            ALLOW_APP_MULTI_PROCESS,
            preBundleConfigInfo.allowMultiProcess,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            ALLOW_APP_DESKTOP_ICON_HIDE,
            preBundleConfigInfo.hideDesktopIcon,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            ALLOW_ABILITY_PRIORITY_QUERIED,
            preBundleConfigInfo.allowQueryPriority,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            ALLOW_ABILITY_EXCLUDE_FROM_MISSIONS,
            preBundleConfigInfo.allowExcludeFromMissions,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            ALLOW_MISSION_NOT_CLEARED,
            preBundleConfigInfo.allowMissionNotCleared,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            ALLOW_APP_USE_PRIVILEGE_EXTENSION,
            preBundleConfigInfo.allowUsePrivilegeExtension,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            ALLOW_FORM_VISIBLE_NOTIFY,
            preBundleConfigInfo.formVisibleNotify,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            ALLOW_APP_SHARE_LIBRARY,
            preBundleConfigInfo.appShareLibrary,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            ALLOW_ENABLE_NOTIFICATION,
            preBundleConfigInfo.allowEnableNotification,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
        GetValueIfFindKey<bool>(array,
            jsonObjectEnd,
            ALLOW_APP_RUN_WHEN_DEVICE_FIRST_LOCKED,
            preBundleConfigInfo.allowAppRunWhenDeviceFirstLocked,
            JsonType::BOOLEAN,
            false,
            parseResult,
            ArrayType::NOT_ARRAY);
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
            APP_LOGE("parse from json failed");
            return parseResult;
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

    return ERR_OK;
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
        GetValueIfFindKey<std::string>(array,
            jsonObjectEnd,
            TYPE_NAME,
            extensionAbilityType,
            JsonType::STRING,
            true,
            parseResult,
            ArrayType::NOT_ARRAY);
        extensionTypeList.insert(extensionAbilityType);
    }

    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
