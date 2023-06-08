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

#include "aot/aot_args.h"

#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool AOTArgs::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    compileMode = Str16ToStr8(parcel.ReadString16());
    hapPath = Str16ToStr8(parcel.ReadString16());
    coreLibPath = Str16ToStr8(parcel.ReadString16());
    outputPath = Str16ToStr8(parcel.ReadString16());
    arkProfilePath = Str16ToStr8(parcel.ReadString16());
    offset = parcel.ReadUint32();
    length = parcel.ReadUint32();
    return true;
}

bool AOTArgs::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(compileMode));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(coreLibPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(outputPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(arkProfilePath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, offset);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, length);
    return true;
}

AOTArgs *AOTArgs::Unmarshalling(Parcel &parcel)
{
    AOTArgs *aotArgs = new (std::nothrow) AOTArgs();
    if (aotArgs) {
        aotArgs->ReadFromParcel(parcel);
    }
    return aotArgs;
}

std::string AOTArgs::ToString() const
{
    return "[ bundleName = " +  bundleName
            + ", moduleName = " + moduleName
            + ", compileMode = " + compileMode
            + ", hapPath = " + hapPath
            + ", coreLibPath = " + coreLibPath
            + ", outputPath = " + outputPath
            + ", arkProfilePath = " + arkProfilePath
            + ", offset = " + std::to_string(offset)
            + ", length = " + std::to_string(length) + "]";
}
}  // namespace AppExecFwk
}  // namespace OHOS
