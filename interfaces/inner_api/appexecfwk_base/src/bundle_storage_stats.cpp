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

#include "bundle_storage_stats.h"

#include "app_log_wrapper.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool BundleStorageStats::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    int32_t statsSize = 0;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, statsSize);
    CONTAINER_SECURITY_VERIFY(parcel, statsSize, &bundleStats);
    for (auto i = 0; i < statsSize; i++) {
        bundleStats.push_back(parcel.ReadInt64());
    }
    errCode = parcel.ReadInt32();
    return true;
}

BundleStorageStats *BundleStorageStats::Unmarshalling(Parcel &parcel)
{
    BundleStorageStats *stats = new (std::nothrow) BundleStorageStats();
    if (stats && !stats->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete stats;
        stats = nullptr;
    }
    return stats;
}

bool BundleStorageStats::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    const auto statsSize = static_cast<int32_t>(bundleStats.size());
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, statsSize);
    for (auto i = 0; i < statsSize; i++) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, bundleStats[i]);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, errCode);
    return true;
}
}
}