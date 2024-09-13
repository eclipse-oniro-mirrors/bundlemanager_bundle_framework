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

#include "app_provision_info.h"

#include <cstring>
#include <fcntl.h>

#include "json_util.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const size_t APP_PROVISION_INFO_CAPACITY = 102400; // 100K
}

bool AppProvisionInfo::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, validity.notBefore);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, validity.notAfter);
    versionName = Str16ToStr8(parcel.ReadString16());
    uuid = Str16ToStr8(parcel.ReadString16());
    type = Str16ToStr8(parcel.ReadString16());
    appDistributionType = Str16ToStr8(parcel.ReadString16());
    developerId = Str16ToStr8(parcel.ReadString16());
    certificate = Str16ToStr8(parcel.ReadString16());
    apl = Str16ToStr8(parcel.ReadString16());
    issuer = Str16ToStr8(parcel.ReadString16());
    appIdentifier = Str16ToStr8(parcel.ReadString16());
    appServiceCapabilities = Str16ToStr8(parcel.ReadString16());
    organization = Str16ToStr8(parcel.ReadString16());
    return true;
}

bool AppProvisionInfo::Marshalling(Parcel &parcel) const
{
    CHECK_PARCEL_CAPACITY(parcel, APP_PROVISION_INFO_CAPACITY);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, validity.notBefore);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, validity.notAfter);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(versionName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uuid));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(type));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appDistributionType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(developerId));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(certificate));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(apl));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(issuer));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appIdentifier));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appServiceCapabilities));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(organization));
    return true;
}

AppProvisionInfo *AppProvisionInfo::Unmarshalling(Parcel &parcel)
{
    AppProvisionInfo *info = new (std::nothrow) AppProvisionInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // AppExecFwk
} // OHOS
