/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hqf_info.h"

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string HQF_INFO_HAP_SHA256 = "hapSha256";
const std::string HQF_INFO_HQF_FILE_PATH = "hqfFilePath";
const std::string HQF_INFO_TYPE = "type";
const std::string HQF_INFO_CPU_ABI = "cpuAbi";
const std::string HQF_INFO_NATIVE_LIBRARY_PATH = "nativeLibraryPath";
}

void to_json(nlohmann::json &jsonObject, const HqfInfo &hqfInfo)
{
    jsonObject = nlohmann::json {
        {Constants::MODULE_NAME, hqfInfo.moduleName},
        {HQF_INFO_HAP_SHA256, hqfInfo.hapSha256},
        {HQF_INFO_HQF_FILE_PATH, hqfInfo.hqfFilePath},
        {HQF_INFO_TYPE, hqfInfo.type},
        {HQF_INFO_CPU_ABI, hqfInfo.cpuAbi},
        {HQF_INFO_NATIVE_LIBRARY_PATH, hqfInfo.nativeLibraryPath}
    };
}

void from_json(const nlohmann::json &jsonObject, HqfInfo &hqfInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        hqfInfo.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HQF_INFO_HAP_SHA256,
        hqfInfo.hapSha256,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HQF_INFO_HQF_FILE_PATH,
        hqfInfo.hqfFilePath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<QuickFixType>(jsonObject,
        jsonObjectEnd,
        HQF_INFO_TYPE,
        hqfInfo.type,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HQF_INFO_CPU_ABI,
        hqfInfo.cpuAbi,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HQF_INFO_NATIVE_LIBRARY_PATH,
        hqfInfo.nativeLibraryPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "read module hqfInfo from jsonObject error, error code : %{public}d", parseResult);
    }
}

bool HqfInfo::ReadFromParcel(Parcel &parcel)
{
    moduleName = Str16ToStr8(parcel.ReadString16());
    hapSha256 = Str16ToStr8(parcel.ReadString16());
    hqfFilePath = Str16ToStr8(parcel.ReadString16());
    type = static_cast<QuickFixType>(parcel.ReadInt32());
    cpuAbi = Str16ToStr8(parcel.ReadString16());
    nativeLibraryPath = Str16ToStr8(parcel.ReadString16());
    return true;
}

bool HqfInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapSha256));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hqfFilePath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(type));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(cpuAbi));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(nativeLibraryPath));
    return true;
}

HqfInfo *HqfInfo::Unmarshalling(Parcel &parcel)
{
    HqfInfo *info = new (std::nothrow) HqfInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        LOG_E(BMS_TAG_QUICK_FIX, "read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // AppExecFwk
} // OHOS