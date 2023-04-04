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

#include "shared_module_info.h"

#include "app_log_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string SHARED_MODULE_INFO_NAME = "name";
const std::string SHARED_MODULE_INFO_VERSION_CODE = "versionCode";
const std::string SHARED_MODULE_INFO_VERSION_NAME = "versionName";
const std::string SHARED_MODULE_INFO_DESCRIPTION = "description";
const std::string SHARED_MODULE_INFO_DESCRIPTION_ID = "descriptionId";
}

bool SharedModuleInfo::ReadFromParcel(Parcel &parcel)
{
    name = Str16ToStr8(parcel.ReadString16());
    versionCode = parcel.ReadUint32();
    versionName = Str16ToStr8(parcel.ReadString16());
    description = Str16ToStr8(parcel.ReadString16());
    descriptionId = parcel.ReadUint32();
    return true;
}

bool SharedModuleInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(versionName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(description));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, descriptionId);
    return true;
}

SharedModuleInfo *SharedModuleInfo::Unmarshalling(Parcel &parcel)
{
    SharedModuleInfo *info = new (std::nothrow) SharedModuleInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

void to_json(nlohmann::json &jsonObject, const SharedModuleInfo &sharedModuleInfo)
{
    jsonObject = nlohmann::json {
        {SHARED_MODULE_INFO_NAME, sharedModuleInfo.name},
        {SHARED_MODULE_INFO_VERSION_CODE, sharedModuleInfo.versionCode},
        {SHARED_MODULE_INFO_VERSION_NAME, sharedModuleInfo.versionName},
        {SHARED_MODULE_INFO_DESCRIPTION, sharedModuleInfo.description},
        {SHARED_MODULE_INFO_DESCRIPTION_ID, sharedModuleInfo.descriptionId}
    };
}

void from_json(const nlohmann::json &jsonObject, SharedModuleInfo &sharedModuleInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        SHARED_MODULE_INFO_NAME,
        sharedModuleInfo.name,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        SHARED_MODULE_INFO_VERSION_CODE,
        sharedModuleInfo.versionCode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        SHARED_MODULE_INFO_VERSION_NAME,
        sharedModuleInfo.versionName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        SHARED_MODULE_INFO_DESCRIPTION,
        sharedModuleInfo.description,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        SHARED_MODULE_INFO_DESCRIPTION_ID,
        sharedModuleInfo.descriptionId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read SharedModuleInfo error, error code : %{public}d", parseResult);
    }
}
} // AppExecFwk
} // OHOS