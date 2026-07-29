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

#include "ipc/install_hnp_param.h"

#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool InstallHnpParam::ReadFromParcel(Parcel &parcel)
{
    userId = Str16ToStr8(parcel.ReadString16());
    hnpRootPath = Str16ToStr8(parcel.ReadString16());
    hapPath = Str16ToStr8(parcel.ReadString16());
    cpuAbi = Str16ToStr8(parcel.ReadString16());
    packageName = Str16ToStr8(parcel.ReadString16());
    appIdentifier = Str16ToStr8(parcel.ReadString16());
    int32_t hnpPathsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, hnpPathsSize);
    CONTAINER_SECURITY_VERIFY(parcel, hnpPathsSize, &hnpPaths);
    for (int32_t i = 0; i < hnpPathsSize; ++i) {
        std::string hnpPath = Str16ToStr8(parcel.ReadString16());
        hnpPaths.emplace_back(hnpPath);
    }
    return true;
}

bool InstallHnpParam::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(userId));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hnpRootPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(cpuAbi));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(packageName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appIdentifier));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, hnpPaths.size());
    for (auto &item : hnpPaths) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(item));
    }
    return true;
}

InstallHnpParam *InstallHnpParam::Unmarshalling(Parcel &parcel)
{
    InstallHnpParam *info = new (std::nothrow) InstallHnpParam();
    if (info != nullptr && !info->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
}  // namespace AppExecFwk
}  // namespace OHOS
