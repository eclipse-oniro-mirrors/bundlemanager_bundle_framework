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

#include "ipc/extract_hnp_files_param.h"

#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool ExtractHnpFilesParam::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    srcPath = Str16ToStr8(parcel.ReadString16());
    cpuAbi = Str16ToStr8(parcel.ReadString16());
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isBundleUpdate);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isModuleUpdate);
    int32_t mapSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, mapSize);
    CONTAINER_SECURITY_VERIFY(parcel, mapSize, &hnpPackageMap);
    for (int32_t i = 0; i < mapSize; ++i) {
        std::string package = Str16ToStr8(parcel.ReadString16());
        std::string type = Str16ToStr8(parcel.ReadString16());
        hnpPackageMap.try_emplace(package, type);
    }
    return true;
}

bool ExtractHnpFilesParam::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(srcPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(cpuAbi));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isBundleUpdate);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isModuleUpdate);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, hnpPackageMap.size());
    for (const auto &[package, type] : hnpPackageMap) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(package));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(type));
    }
    return true;
}

ExtractHnpFilesParam *ExtractHnpFilesParam::Unmarshalling(Parcel &parcel)
{
    ExtractHnpFilesParam *info = new (std::nothrow) ExtractHnpFilesParam();
    if (info != nullptr && !info->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
std::string ExtractHnpFilesParam::ToString() const
{
    return "[ bundleName = " + bundleName
            + ", moduleName = " + moduleName
            + ", srcPath = " + srcPath
            + ", cpuAbi = " + cpuAbi
            + ", isBundleUpdate = " + (isBundleUpdate ? "true" : "false")
            + ", isModuleUpdate = " + (isModuleUpdate ? "true" : "false")
            + ", hnpPackageMap.size = " + std::to_string(hnpPackageMap.size()) + "]";
}
}  // namespace AppExecFwk
}  // namespace OHOS