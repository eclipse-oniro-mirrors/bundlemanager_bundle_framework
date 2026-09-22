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

#include "ipc/copy_hap_to_install_path_param.h"

#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool CopyHapToInstallPathParam::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    hapFileName = Str16ToStr8(parcel.ReadString16());
    srcHapPath = Str16ToStr8(parcel.ReadString16());
    isUpdate = parcel.ReadBool();
    isFeatureNeedUninstall = parcel.ReadBool();
    signatureFileSubPath = Str16ToStr8(parcel.ReadString16());
    signatureFileName = Str16ToStr8(parcel.ReadString16());
    return true;
}

bool CopyHapToInstallPathParam::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapFileName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(srcHapPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isUpdate);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isFeatureNeedUninstall);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(signatureFileSubPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(signatureFileName));
    return true;
}

CopyHapToInstallPathParam *CopyHapToInstallPathParam::Unmarshalling(Parcel &parcel)
{
    CopyHapToInstallPathParam *info = new (std::nothrow) CopyHapToInstallPathParam();
    if (info) {
        info->ReadFromParcel(parcel);
    }
    return info;
}

std::string CopyHapToInstallPathParam::ToString() const
{
    return "[ bundleName = " + bundleName
            + ", moduleName = " + moduleName
            + ", hapFileName = " + hapFileName
            + ", srcHapPath = " + srcHapPath
            + ", isUpdate = " + (isUpdate ? "true" : "false")
            + ", isFeatureNeedUninstall = " + (isFeatureNeedUninstall ? "true" : "false")
            + ", signatureFileSubPath = " + signatureFileSubPath
            + ", signatureFileName = " + signatureFileName + "]";
}
}  // namespace AppExecFwk
}  // namespace OHOS
