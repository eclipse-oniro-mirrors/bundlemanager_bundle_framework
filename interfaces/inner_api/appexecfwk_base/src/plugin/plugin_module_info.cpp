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

#include "plugin_module_info.h"

#include "app_log_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"


namespace OHOS {
namespace AppExecFwk {
namespace {
const char* PLUGIN_MODULE_INFO_MODULENAME = "moduleName";
const char* PLUGIN_MODULE_INFO_DESCRIPTION = "description";
const char* PLUGIN_MODULE_INFO_DESCRIPTION_ID = "descriptionId";
const char* PLUGIN_MODULE_INFO_HAP_PATH = "hapPath";
const char* PLUGIN_MODULE_INFO_CPU_ABI = "cpuAbi";
const char* PLUGIN_MODULE_INFO_NATIVE_LIBRARY_PATH = "nativeLibraryPath";
const char* PLUGIN_MODULE_INFO_NATIVE_LIBRARY_FILE_NAMES = "nativeLibraryFileNames";
}

bool PluginModuleInfo::ReadFromParcel(Parcel &parcel)
{
    descriptionId = parcel.ReadUint32();
    moduleName = parcel.ReadString();
    description = parcel.ReadString();
    hapPath = parcel.ReadString();
    cpuAbi = parcel.ReadString();
    nativeLibraryPath = parcel.ReadString();
    int32_t nativeLibraryFileNamesSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, nativeLibraryFileNamesSize);
    CONTAINER_SECURITY_VERIFY(parcel, nativeLibraryFileNamesSize, &nativeLibraryFileNames);
    for (int32_t i = 0; i < nativeLibraryFileNamesSize; ++i) {
        nativeLibraryFileNames.emplace_back(parcel.ReadString());
    }
    return true;
}

bool PluginModuleInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, descriptionId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, moduleName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, description);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, hapPath);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, cpuAbi);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, nativeLibraryPath);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, nativeLibraryFileNames.size());
    for (auto &fileName : nativeLibraryFileNames) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, fileName);
    }
    return true;
}

PluginModuleInfo *PluginModuleInfo::Unmarshalling(Parcel &parcel)
{
    PluginModuleInfo *info = new (std::nothrow) PluginModuleInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

void to_json(nlohmann::json &jsonObject, const PluginModuleInfo &pluginModuleInfo)
{
    jsonObject = nlohmann::json {
        {PLUGIN_MODULE_INFO_MODULENAME, pluginModuleInfo.moduleName},
        {PLUGIN_MODULE_INFO_DESCRIPTION, pluginModuleInfo.description},
        {PLUGIN_MODULE_INFO_DESCRIPTION_ID, pluginModuleInfo.descriptionId},
        {PLUGIN_MODULE_INFO_HAP_PATH, pluginModuleInfo.hapPath},
        {PLUGIN_MODULE_INFO_CPU_ABI, pluginModuleInfo.cpuAbi},
        {PLUGIN_MODULE_INFO_NATIVE_LIBRARY_PATH, pluginModuleInfo.nativeLibraryPath},
        {PLUGIN_MODULE_INFO_NATIVE_LIBRARY_FILE_NAMES, pluginModuleInfo.nativeLibraryFileNames}
    };
}

void from_json(const nlohmann::json &jsonObject, PluginModuleInfo &pluginModuleInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd,
        PLUGIN_MODULE_INFO_MODULENAME,
        pluginModuleInfo.moduleName, false, parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd,
        PLUGIN_MODULE_INFO_DESCRIPTION,
        pluginModuleInfo.description, false, parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd,
        PLUGIN_MODULE_INFO_DESCRIPTION_ID,
        pluginModuleInfo.descriptionId, JsonType::NUMBER, false, parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd,
        PLUGIN_MODULE_INFO_HAP_PATH,
        pluginModuleInfo.hapPath, false, parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd,
        PLUGIN_MODULE_INFO_CPU_ABI,
        pluginModuleInfo.cpuAbi, false, parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd,
        PLUGIN_MODULE_INFO_NATIVE_LIBRARY_PATH,
        pluginModuleInfo.nativeLibraryPath, false, parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject, jsonObjectEnd,
        PLUGIN_MODULE_INFO_NATIVE_LIBRARY_FILE_NAMES,
        pluginModuleInfo.nativeLibraryFileNames, JsonType::ARRAY, false, parseResult,
        ArrayType::STRING);
    if (parseResult != ERR_OK) {
        APP_LOGE("read pluginModuleInfo error : %{public}d", parseResult);
    }
}
} // AppExecFwk
} // OHOS
