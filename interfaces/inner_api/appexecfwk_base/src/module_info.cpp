/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "module_info.h"

#include "nlohmann/json.hpp"
#include "string_ex.h"

#include "json_util.h"
#include "parcel_macro.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string MODULE_INFO_MODULE_SOURCE_DIR = "moduleSourceDir";
const std::string MODULE_INFO_PRELOADS = "preloads";
}

bool ModuleInfo::ReadFromParcel(Parcel &parcel)
{
    moduleName = Str16ToStr8(parcel.ReadString16());
    moduleSourceDir = Str16ToStr8(parcel.ReadString16());
    int32_t preloadsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, preloadsSize);
    CONTAINER_SECURITY_VERIFY(parcel, preloadsSize, &preloads);
    for (auto i = 0; i < preloadsSize; i++) {
        preloads.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }
    return true;
}

ModuleInfo *ModuleInfo::Unmarshalling(Parcel &parcel)
{
    ModuleInfo *info = new (std::nothrow) ModuleInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool ModuleInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleSourceDir));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, preloads.size());
    for (auto &preload : preloads) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(preload));
    }
    return true;
}

void to_json(nlohmann::json &jsonObject, const ModuleInfo &moduleInfo)
{
    jsonObject = nlohmann::json {
        {Constants::MODULE_NAME, moduleInfo.moduleName},
        {MODULE_INFO_MODULE_SOURCE_DIR, moduleInfo.moduleSourceDir},
        {MODULE_INFO_PRELOADS, moduleInfo.preloads}
    };
}

void from_json(const nlohmann::json &jsonObject, ModuleInfo &moduleInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        moduleInfo.moduleName,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        MODULE_INFO_MODULE_SOURCE_DIR,
        moduleInfo.moduleSourceDir,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        MODULE_INFO_PRELOADS,
        moduleInfo.preloads,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    if (parseResult != ERR_OK) {
        APP_LOGE("read moduleInfo jsonObject error : %{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
