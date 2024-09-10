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
const std::string SHARED_MODULE_INFO_COMPRESS_NATIVE_LIBS = "compressNativeLibs";
const std::string SHARED_MODULE_INFO_HAP_PATH = "hapPath";
const std::string SHARED_MODULE_INFO_CPU_ABI = "cpuAbi";
const std::string SHARED_MODULE_INFO_NATIVE_LIBRARY_PATH = "nativeLibraryPath";
const std::string SHARED_MODULE_INFO_NATIVE_LIBRARY_FILE_NAMES = "nativeLibraryFileNames";
}

bool SharedModuleInfo::ReadFromParcel(Parcel &parcel)
{
    name = Str16ToStr8(parcel.ReadString16());
    versionCode = parcel.ReadUint32();
    versionName = Str16ToStr8(parcel.ReadString16());
    description = Str16ToStr8(parcel.ReadString16());
    descriptionId = parcel.ReadUint32();
    compressNativeLibs = parcel.ReadBool();
    hapPath = Str16ToStr8(parcel.ReadString16());
    cpuAbi = Str16ToStr8(parcel.ReadString16());
    nativeLibraryPath = Str16ToStr8(parcel.ReadString16());
    int32_t nativeLibraryFileNamesSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, nativeLibraryFileNamesSize);
    CONTAINER_SECURITY_VERIFY(parcel, nativeLibraryFileNamesSize, &nativeLibraryFileNames);
    for (int32_t i = 0; i < nativeLibraryFileNamesSize; ++i) {
        nativeLibraryFileNames.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }
    return true;
}

bool SharedModuleInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(versionName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(description));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, descriptionId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, compressNativeLibs);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(cpuAbi));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(nativeLibraryPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, nativeLibraryFileNames.size());
    for (auto &fileName : nativeLibraryFileNames) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(fileName));
    }
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
        {SHARED_MODULE_INFO_DESCRIPTION_ID, sharedModuleInfo.descriptionId},
        {SHARED_MODULE_INFO_COMPRESS_NATIVE_LIBS, sharedModuleInfo.compressNativeLibs},
        {SHARED_MODULE_INFO_HAP_PATH, sharedModuleInfo.hapPath},
        {SHARED_MODULE_INFO_CPU_ABI, sharedModuleInfo.cpuAbi},
        {SHARED_MODULE_INFO_NATIVE_LIBRARY_PATH, sharedModuleInfo.nativeLibraryPath},
        {SHARED_MODULE_INFO_NATIVE_LIBRARY_FILE_NAMES, sharedModuleInfo.nativeLibraryFileNames}
    };
}

void from_json(const nlohmann::json &jsonObject, SharedModuleInfo &sharedModuleInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd,
        SHARED_MODULE_INFO_NAME,
        sharedModuleInfo.name, JsonType::STRING, false, parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd,
        SHARED_MODULE_INFO_VERSION_CODE,
        sharedModuleInfo.versionCode, JsonType::NUMBER, false, parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd,
        SHARED_MODULE_INFO_VERSION_NAME,
        sharedModuleInfo.versionName, JsonType::STRING, false, parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd,
        SHARED_MODULE_INFO_DESCRIPTION,
        sharedModuleInfo.description, JsonType::STRING, false, parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd,
        SHARED_MODULE_INFO_DESCRIPTION_ID,
        sharedModuleInfo.descriptionId, JsonType::NUMBER, false, parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd,
        SHARED_MODULE_INFO_COMPRESS_NATIVE_LIBS,
        sharedModuleInfo.compressNativeLibs, JsonType::BOOLEAN,
        false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd,
        SHARED_MODULE_INFO_HAP_PATH,
        sharedModuleInfo.hapPath, JsonType::STRING, false, parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd,
        SHARED_MODULE_INFO_CPU_ABI,
        sharedModuleInfo.cpuAbi, JsonType::STRING, false, parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd,
        SHARED_MODULE_INFO_NATIVE_LIBRARY_PATH,
        sharedModuleInfo.nativeLibraryPath, JsonType::STRING, false, parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject, jsonObjectEnd,
        SHARED_MODULE_INFO_NATIVE_LIBRARY_FILE_NAMES,
        sharedModuleInfo.nativeLibraryFileNames, JsonType::ARRAY, false, parseResult,
        ArrayType::STRING);
    if (parseResult != ERR_OK) {
        APP_LOGE("read SharedModuleInfo error : %{public}d", parseResult);
    }
}
} // AppExecFwk
} // OHOS