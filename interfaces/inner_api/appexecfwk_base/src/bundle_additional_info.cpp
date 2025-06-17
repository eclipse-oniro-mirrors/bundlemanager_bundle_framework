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

#include "bundle_additional_info.h"

#include "json_util.h"
#include "parcel_macro.h"
#include "string_ex.h"
#include <cstdint>

namespace OHOS {
namespace AppExecFwk {
bool BundleAdditionalInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    additionalInfo = Str16ToStr8(parcel.ReadString16());
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, errCode);
    return true;
}

bool BundleAdditionalInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(additionalInfo));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, errCode);
    return true;
}

BundleAdditionalInfo *BundleAdditionalInfo::Unmarshalling(Parcel &parcel)
{
    BundleAdditionalInfo *info = new (std::nothrow) BundleAdditionalInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
}
}