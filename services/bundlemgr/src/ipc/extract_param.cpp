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
const char* TYPE_ALL = "All";
const char* TYPE_SO = "So";
const char* TYPE_AN = "An";
const char* TYPE_PATCH = "Patch";
const char* TYPE_AP = "Ap";
const char* TYPE_RESOURCE = "Resource";
const char* TYPE_RES_FILE = "ResFile";
const char* TYPE_HNPS_FILE = "HnpsFile";
const char* TYPE_OTHER = "Other";
const std::unordered_map<ExtractFileType, std::string> ARGS_MAP = {
    { ExtractFileType::ALL, TYPE_ALL },
    { ExtractFileType::SO, TYPE_SO },
    { ExtractFileType::AN, TYPE_AN },
    { ExtractFileType::PATCH, TYPE_PATCH },
    { ExtractFileType::AP, TYPE_AP },
    { ExtractFileType::RESOURCE, TYPE_RESOURCE },
    { ExtractFileType::RES_FILE, TYPE_RES_FILE },
    { ExtractFileType::HNPS_FILE, TYPE_HNPS_FILE },
};

std::string GetExtractFileTypeStrVal(const ExtractFileType &extractFileType)
{
    std::string typeStr = TYPE_OTHER;
    auto operatorIter = ARGS_MAP.find(extractFileType);
    if (operatorIter != ARGS_MAP.end()) {
        typeStr = operatorIter->second;
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
