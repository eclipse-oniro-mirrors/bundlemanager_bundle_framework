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
const char* PLUGIN_BUNDLE_INFO_MODULE_INFOS = "pluginModuleInfos";
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

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, pluginModuleInfos.size());
    for (auto &info : pluginModuleInfos) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &info);
    }

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
        {PLUGIN_BUNDLE_INFO_MODULE_INFOS, pluginBundleInfo.pluginModuleInfos}
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
    if (parseResult != ERR_OK) {
        APP_LOGE("read pluginBundleInfo error : %{public}d", parseResult);
    }
}
} // AppExecFwk
} // OHOS
