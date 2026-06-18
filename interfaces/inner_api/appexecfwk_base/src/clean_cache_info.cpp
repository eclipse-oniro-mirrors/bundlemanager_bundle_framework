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

#include "clean_cache_info.h"

#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool CleanCacheInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    userId = parcel.ReadInt32();
    appIndex = parcel.ReadInt32();
    cacheThreshold = parcel.ReadUint64();
    return true;
}

bool CleanCacheInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, userId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint64, parcel, cacheThreshold);
    return true;
}

CleanCacheInfo *CleanCacheInfo::Unmarshalling(Parcel &parcel)
{
    CleanCacheInfo *info = new (std::nothrow) CleanCacheInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
}  // namespace AppExecFwk
}  // namespace OHOS