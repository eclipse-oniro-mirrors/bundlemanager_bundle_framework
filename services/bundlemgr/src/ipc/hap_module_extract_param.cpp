/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ipc/hap_module_extract_param.h"

#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool HapModuleExtractParam::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    hapCopySubDir = Str16ToStr8(parcel.ReadString16());
    hapFileName = Str16ToStr8(parcel.ReadString16());
    nativeLibraryPath = Str16ToStr8(parcel.ReadString16());
    cpuAbi = Str16ToStr8(parcel.ReadString16());
    installMode = parcel.ReadInt32();
    needFakeDecompression = parcel.ReadBool();
    isSystemApp = parcel.ReadBool();
    hapSrcPath = Str16ToStr8(parcel.ReadString16());
    return true;
}

bool HapModuleExtractParam::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapCopySubDir));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapFileName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(nativeLibraryPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(cpuAbi));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, installMode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, needFakeDecompression);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isSystemApp);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapSrcPath));
    return true;
}

HapModuleExtractParam *HapModuleExtractParam::Unmarshalling(Parcel &parcel)
{
    HapModuleExtractParam *info = new (std::nothrow) HapModuleExtractParam();
    if (info != nullptr && !info->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

std::string HapModuleExtractParam::ToString() const
{
    return "[ bundleName = " + bundleName
            + ", moduleName = " + moduleName
            + ", hapCopySubDir = " + hapCopySubDir
            + ", hapFileName = " + hapFileName
            + ", nativeLibraryPath = " + nativeLibraryPath
            + ", cpuAbi = " + cpuAbi
            + ", installMode = " + std::to_string(installMode)
            + ", needFakeDecompression = " + (needFakeDecompression ? "true" : "false")
            + ", isSystemApp = " + (isSystemApp ? "true" : "false")
            + ", hapSrcPath = " + hapSrcPath + "]";
}
}  // namespace AppExecFwk
}  // namespace OHOS
