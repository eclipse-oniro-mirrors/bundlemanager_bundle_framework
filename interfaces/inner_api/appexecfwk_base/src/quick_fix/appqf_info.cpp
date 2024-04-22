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

#include "appqf_info.h"

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string APP_QF_INFO_VERSION_CODE = "versionCode";
const std::string APP_QF_INFO_VERSION_NAME = "versionName";
const std::string APP_QF_INFO_CPU_ABI = "cpuAbi";
const std::string APP_QF_INFO_NATIVE_LIBRARY_PATH = "nativeLibraryPath";
const std::string APP_QF_INFO_HQF_INFOS = "hqfInfos";
const std::string APP_QF_INFO_TYPE = "type";
}

void to_json(nlohmann::json &jsonObject, const AppqfInfo &appqfInfo)
{
    jsonObject = nlohmann::json {
        {APP_QF_INFO_VERSION_CODE, appqfInfo.versionCode},
        {APP_QF_INFO_VERSION_NAME, appqfInfo.versionName},
        {APP_QF_INFO_CPU_ABI, appqfInfo.cpuAbi},
        {APP_QF_INFO_NATIVE_LIBRARY_PATH, appqfInfo.nativeLibraryPath},
        {APP_QF_INFO_TYPE, appqfInfo.type},
        {APP_QF_INFO_HQF_INFOS, appqfInfo.hqfInfos}
    };
}

void from_json(const nlohmann::json &jsonObject, AppqfInfo &appqfInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd,
        APP_QF_INFO_VERSION_CODE, appqfInfo.versionCode,
        JsonType::NUMBER, false, parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd,
        APP_QF_INFO_VERSION_NAME, appqfInfo.versionName,
        JsonType::STRING, false, parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd,
        APP_QF_INFO_CPU_ABI, appqfInfo.cpuAbi,
        JsonType::STRING, false, parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd,
        APP_QF_INFO_NATIVE_LIBRARY_PATH, appqfInfo.nativeLibraryPath,
        JsonType::STRING, false, parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<QuickFixType>(jsonObject, jsonObjectEnd,
        APP_QF_INFO_TYPE, appqfInfo.type,
        JsonType::NUMBER, false, parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<std::vector<HqfInfo>>(jsonObject, jsonObjectEnd,
        APP_QF_INFO_HQF_INFOS, appqfInfo.hqfInfos,
        JsonType::ARRAY, false, parseResult,
        ArrayType::OBJECT);
    if (parseResult != ERR_OK) {
        LOG_E(BMS_TAG_QUICK_FIX, "read module appqfInfo from jsonObject error, error code : %{public}d", parseResult);
    }
}

bool AppqfInfo::ReadFromParcel(Parcel &parcel)
{
    versionCode = parcel.ReadUint32();
    versionName = Str16ToStr8(parcel.ReadString16());
    cpuAbi = Str16ToStr8(parcel.ReadString16());
    nativeLibraryPath = Str16ToStr8(parcel.ReadString16());
    type = static_cast<QuickFixType>(parcel.ReadInt32());
    int32_t hqfSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, hqfSize);
    CONTAINER_SECURITY_VERIFY(parcel, hqfSize, &hqfInfos);
    for (auto i = 0; i < hqfSize; i++) {
        std::unique_ptr<HqfInfo> hqfInfoPtr(parcel.ReadParcelable<HqfInfo>());
        if (!hqfInfoPtr) {
            LOG_E(BMS_TAG_QUICK_FIX, "ReadParcelable<HqfInfo> failed");
            return false;
        }
        hqfInfos.emplace_back(*hqfInfoPtr);
    }
    return true;
}

bool AppqfInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(versionName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(cpuAbi));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(nativeLibraryPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(type));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, hqfInfos.size());
    for (auto &hqfInfo : hqfInfos) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &hqfInfo);
    }
    return true;
}

AppqfInfo *AppqfInfo::Unmarshalling(Parcel &parcel)
{
    AppqfInfo *info = new (std::nothrow) AppqfInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        LOG_E(BMS_TAG_QUICK_FIX, "read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // AppExecFwk
} // OHOS