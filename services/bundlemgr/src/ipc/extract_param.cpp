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

#include "ipc/extract_param.h"

#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* TYPE_ALL = "All";
constexpr const char* TYPE_SO = "So";
constexpr const char* TYPE_AN = "An";
constexpr const char* TYPE_PATCH = "Patch";
constexpr const char* TYPE_AP = "Ap";
constexpr const char* TYPE_RESOURCE = "Resource";
constexpr const char* TYPE_RES_FILE = "ResFile";
constexpr const char* TYPE_HNPS_FILE = "HnpsFile";
constexpr const char* TYPE_OTHER = "Other";
const ExtractFileType ARGS_MAP_KEY[] = {
    ExtractFileType::ALL, ExtractFileType::SO, ExtractFileType::AN, ExtractFileType::PATCH, ExtractFileType::AP,
    ExtractFileType::RESOURCE, ExtractFileType::RES_FILE, ExtractFileType::HNPS_FILE,
};
constexpr const char* ARGS_MAP_VALUE[] = {
    TYPE_ALL, TYPE_SO, TYPE_AN, TYPE_PATCH, TYPE_AP, TYPE_RESOURCE, TYPE_RES_FILE, TYPE_HNPS_FILE,
};

std::string GetExtractFileTypeStrVal(const ExtractFileType &extractFileType)
{
    std::string typeStr = TYPE_OTHER;
    size_t len = sizeof(ARGS_MAP_KEY) / sizeof(ARGS_MAP_KEY[0]);
    for (size_t i = 0; i < len; i++) {
        if (extractFileType == ARGS_MAP_KEY[i]) {
            typeStr = ARGS_MAP_VALUE[i];
            break;
        }
    }
    return typeStr;
}
}
bool ExtractParam::ReadFromParcel(Parcel &parcel)
{
    srcPath = Str16ToStr8(parcel.ReadString16());
    targetPath = Str16ToStr8(parcel.ReadString16());
    cpuAbi = Str16ToStr8(parcel.ReadString16());
    extractFileType = static_cast<ExtractFileType>(parcel.ReadInt32());
    return true;
}

bool ExtractParam::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(srcPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(targetPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(cpuAbi));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(extractFileType));
    return true;
}

ExtractParam *ExtractParam::Unmarshalling(Parcel &parcel)
{
    ExtractParam *info = new (std::nothrow) ExtractParam();
    if (info) {
        info->ReadFromParcel(parcel);
    }
    return info;
}

std::string ExtractParam::ToString() const
{
    return "[ srcPath :" +  srcPath
            + ", targetPath = " + targetPath
            + ", cpuAbi = " + cpuAbi
            + ", extractFileType = " + GetExtractFileTypeStrVal(extractFileType) + "]";
}
}  // namespace AppExecFwk
}  // namespace OHOS
