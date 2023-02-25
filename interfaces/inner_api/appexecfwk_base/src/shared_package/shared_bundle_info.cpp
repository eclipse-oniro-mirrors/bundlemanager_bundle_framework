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

#include "shared_bundle_info.h"

#include "app_log_wrapper.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool SharedBundleInfo::ReadFromParcel(Parcel &parcel)
{
    name = Str16ToStr8(parcel.ReadString16());
    compatiblePolicy = static_cast<CompatiblePolicy>(parcel.ReadInt32());

    int32_t size;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, size);
    CONTAINER_SECURITY_VERIFY(parcel, size, &sharedModuleInfos);
    for (auto i = 0; i < size; i++) {
        std::unique_ptr<SharedModuleInfo> info(parcel.ReadParcelable<SharedModuleInfo>());
        if (!info) {
            APP_LOGE("ReadParcelable<SharedModuleInfo> failed");
            return false;
        }
        sharedModuleInfos.emplace_back(*info);
    }

    return true;
}

bool SharedBundleInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(compatiblePolicy));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, sharedModuleInfos.size());
    for (auto &info : sharedModuleInfos) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &info);
    }

    return true;
}

SharedBundleInfo *SharedBundleInfo::Unmarshalling(Parcel &parcel)
{
    SharedBundleInfo *info = new (std::nothrow) SharedBundleInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // AppExecFwk
} // OHOS