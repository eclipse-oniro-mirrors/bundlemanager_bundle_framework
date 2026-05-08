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

#include "alternate_icon_info.h"

#include <fcntl.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool AlternateIconInfo::ReadFromParcel(Parcel &parcel)
{
    std::u16string alternateIconNameVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, alternateIconNameVal);
    alternateIconName = Str16ToStr8(alternateIconNameVal);
    std::u16string filePathVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, filePathVal);
    filePath = Str16ToStr8(filePathVal);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, userId);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, iconId);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, enabled);
    return true;
}

bool AlternateIconInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(alternateIconName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(filePath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, userId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, iconId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, enabled);
    return true;
}

AlternateIconInfo *AlternateIconInfo::Unmarshalling(Parcel &parcel)
{
    AlternateIconInfo *info = new (std::nothrow) AlternateIconInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // OHOS
} // AppExecFwk