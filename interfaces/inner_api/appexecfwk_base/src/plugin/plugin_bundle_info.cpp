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

#include "plugin_bundle_info.h"

#include "app_log_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* PLUGIN_BUNDLE_INFO_PLUGIN_BUNDLE_NAME = "pluginBundleName";
const char* PLUGIN_BUNDLE_INFO_LABEL = "label";
const char* PLUGIN_BUNDLE_INFO_ICON = "icon";
const char* PLUGIN_BUNDLE_INFO_VERSION_NAME = "versionName";
const char* PLUGIN_BUNDLE_INFO_ICON_ID = "iconId";
const char* PLUGIN_BUNDLE_INFO_LABEL_ID = "labelId";
const char* PLUGIN_BUNDLE_INFO_VERSION_CODE = "versionCode";
const char* PLUGIN_BUNDLE_INFO_APP_IDENTIFIER = "appIdentifier";
const char* PLUGIN_BUNDLE_INFO_APP_ID = "appId";
const char* PLUGIN_BUNDLE_INFO_CODE_PATH = "codePath";
const char* PLUGIN_BUNDLE_INFO_MODULE_INFOS = "pluginModuleInfos";
const char* PLUGIN_BUNDLE_INFO_ABILITY_INFOS = "abilityInfos";
const char* PLUGIN_BUNDLE_INFO_APPLICATION_INFO = "appInfo";
const char* PLUGIN_BUNDLE_INFO_NATIVE_LIB_PATH = "nativeLibraryPath";
}

bool PluginBundleInfo::ReadFromParcel(Parcel &parcel)
{
    iconId = parcel.ReadUint32();
    labelId = parcel.ReadUint32();
    versionCode = parcel.ReadUint32();

    pluginBundleName = parcel.ReadString();
    label = parcel.ReadString();
    icon = parcel.ReadString();
    versionName = parcel.ReadString();
    appIdentifier = parcel.ReadString();
    appId = parcel.ReadString();
    codePath = parcel.ReadString();
    nativeLibraryPath = parcel.ReadString();

    int32_t size;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, size);
    CONTAINER_SECURITY_VERIFY(parcel, size, &pluginModuleInfos);
    for (auto i = 0; i < size; i++) {
        std::unique_ptr<PluginModuleInfo> info(parcel.ReadParcelable<PluginModuleInfo>());
        if (!info) {
            APP_LOGE("ReadParcelable<PluginModuleInfo> failed");
            return false;
        }
        pluginModuleInfos.emplace_back(*info);
    }

    int32_t abilityInfoSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, abilityInfoSize);
    CONTAINER_SECURITY_VERIFY(parcel, abilityInfoSize, &abilityInfos);
    for (auto i = 0; i < abilityInfoSize; i++) {
        std::string name = parcel.ReadString();
        std::unique_ptr<AbilityInfo> info(parcel.ReadParcelable<AbilityInfo>());
        if (!info) {
            APP_LOGE("ReadParcelable<AbilityInfo> failed");
            return false;
        }
        abilityInfos.emplace(name, *info);
    }
    std::unique_ptr<ApplicationInfo> applicationInfo(parcel.ReadParcelable<ApplicationInfo>());
    if (!applicationInfo) {
        APP_LOGE("ReadParcelable<ApplicationInfo> failed");
        return false;
    }
    appInfo = *applicationInfo;

    return true;
}

bool PluginBundleInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, iconId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, labelId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, pluginBundleName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, label);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, icon);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, versionName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, appIdentifier);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, appId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, codePath);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, nativeLibraryPath);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, pluginModuleInfos.size());
    for (auto &info : pluginModuleInfos) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &info);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, abilityInfos.size());
    for (const auto &abilityInfo : abilityInfos) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, abilityInfo.first);
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &abilityInfo.second);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &appInfo);
    return true;
}

PluginBundleInfo *PluginBundleInfo::Unmarshalling(Parcel &parcel)
{
    PluginBundleInfo *info = new (std::nothrow) PluginBundleInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

void to_json(nlohmann::json &jsonObject, const PluginBundleInfo &pluginBundleInfo)
{
    jsonObject = nlohmann::json {
        {PLUGIN_BUNDLE_INFO_PLUGIN_BUNDLE_NAME, pluginBundleInfo.pluginBundleName},
        {PLUGIN_BUNDLE_INFO_LABEL, pluginBundleInfo.label},
        {PLUGIN_BUNDLE_INFO_ICON, pluginBundleInfo.icon},
        {PLUGIN_BUNDLE_INFO_VERSION_NAME, pluginBundleInfo.versionName},
        {PLUGIN_BUNDLE_INFO_APP_IDENTIFIER, pluginBundleInfo.appIdentifier},
        {PLUGIN_BUNDLE_INFO_APP_ID, pluginBundleInfo.appId},
        {PLUGIN_BUNDLE_INFO_ICON_ID, pluginBundleInfo.iconId},
        {PLUGIN_BUNDLE_INFO_LABEL_ID, pluginBundleInfo.labelId},
        {PLUGIN_BUNDLE_INFO_VERSION_CODE, pluginBundleInfo.versionCode},
        {PLUGIN_BUNDLE_INFO_MODULE_INFOS, pluginBundleInfo.pluginModuleInfos},
        {PLUGIN_BUNDLE_INFO_CODE_PATH, pluginBundleInfo.codePath},
        {PLUGIN_BUNDLE_INFO_NATIVE_LIB_PATH, pluginBundleInfo.nativeLibraryPath},
        {PLUGIN_BUNDLE_INFO_ABILITY_INFOS, pluginBundleInfo.abilityInfos},
        {PLUGIN_BUNDLE_INFO_APPLICATION_INFO, pluginBundleInfo.appInfo}
    };
}

void from_json(const nlohmann::json &jsonObject, PluginBundleInfo &pluginBundleInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        PLUGIN_BUNDLE_INFO_PLUGIN_BUNDLE_NAME,
        pluginBundleInfo.pluginBundleName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        PLUGIN_BUNDLE_INFO_LABEL,
        pluginBundleInfo.label,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        PLUGIN_BUNDLE_INFO_ICON,
        pluginBundleInfo.icon,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        PLUGIN_BUNDLE_INFO_VERSION_NAME,
        pluginBundleInfo.versionName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        PLUGIN_BUNDLE_INFO_APP_IDENTIFIER,
        pluginBundleInfo.appIdentifier,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        PLUGIN_BUNDLE_INFO_APP_ID,
        pluginBundleInfo.appId,
        false,
        parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        PLUGIN_BUNDLE_INFO_ICON_ID,
        pluginBundleInfo.iconId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        PLUGIN_BUNDLE_INFO_LABEL_ID,
        pluginBundleInfo.labelId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        PLUGIN_BUNDLE_INFO_VERSION_CODE,
        pluginBundleInfo.versionCode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<PluginModuleInfo>>(jsonObject,
        jsonObjectEnd,
        PLUGIN_BUNDLE_INFO_MODULE_INFOS,
        pluginBundleInfo.pluginModuleInfos,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        PLUGIN_BUNDLE_INFO_CODE_PATH,
        pluginBundleInfo.codePath,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        PLUGIN_BUNDLE_INFO_NATIVE_LIB_PATH,
        pluginBundleInfo.nativeLibraryPath,
        false,
        parseResult);
    GetValueIfFindKey<std::unordered_map<std::string, AbilityInfo>>(jsonObject,
        jsonObjectEnd,
        PLUGIN_BUNDLE_INFO_ABILITY_INFOS,
        pluginBundleInfo.abilityInfos,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<ApplicationInfo>(jsonObject,
        jsonObjectEnd,
        PLUGIN_BUNDLE_INFO_APPLICATION_INFO,
        pluginBundleInfo.appInfo,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read pluginBundleInfo error : %{public}d", parseResult);
    }
}

bool PluginBundleInfo::GetAbilityInfoByName(const std::string &abilityName,
    const std::string &moduleName,
    AbilityInfo &info)
{
    for (const auto &ability : abilityInfos) {
        auto &abilityInfo = ability.second;
        if ((abilityInfo.name == abilityName) &&
            (moduleName.empty() || (abilityInfo.moduleName == moduleName))) {
            info = abilityInfo;
            info.applicationInfo = appInfo;
            return true;
        }
    }
    return false;
}

bool PluginBundleInfo::GetHapModuleInfo(const std::string &moduleName,
    HapModuleInfo &hapInfo)
{
    for (const auto &moduleInfo : pluginModuleInfos) {
        if (moduleInfo.moduleName == moduleName) {
            hapInfo.moduleName = moduleInfo.moduleName;
            hapInfo.hapPath = moduleInfo.hapPath;
            hapInfo.nativeLibraryPath = moduleInfo.nativeLibraryPath;
            hapInfo.cpuAbi = moduleInfo.cpuAbi;
            hapInfo.isLibIsolated = moduleInfo.isLibIsolated;
            hapInfo.compressNativeLibs = moduleInfo.compressNativeLibs;
            hapInfo.descriptionId = moduleInfo.descriptionId;
            hapInfo.description = moduleInfo.description;
            hapInfo.nativeLibraryFileNames = moduleInfo.nativeLibraryFileNames;
            hapInfo.bundleName = pluginBundleName;
            hapInfo.packageName = moduleInfo.packageName;
            hapInfo.name = moduleInfo.moduleName;
            hapInfo.package = moduleInfo.moduleName;
            hapInfo.isModuleJson = true;
            std::string key;
            key.append(".").append(moduleName).append(".");
            for (const auto &ability : abilityInfos) {
                if ((ability.first.find(key) != std::string::npos) &&
                    (ability.second.moduleName == hapInfo.moduleName)) {
                    auto &abilityInfo = hapInfo.abilityInfos.emplace_back(ability.second);
                    abilityInfo.applicationInfo = appInfo;
                }
            }
            return true;
        }
    }
    return false;
}
} // AppExecFwk
} // OHOS
