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

#include "shared_package_info.h"

#include "app_log_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool SharedPackageInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    versionCode = parcel.ReadUint32();
    versionName = Str16ToStr8(parcel.ReadString16());
    description = Str16ToStr8(parcel.ReadString16());
    compatiblePolicy = static_cast<CompatiblePolicy>(parcel.ReadInt32());

    int32_t dependenciesSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, dependenciesSize);
    CONTAINER_SECURITY_VERIFY(parcel, dependenciesSize, &dependencies);
    for (auto i = 0; i < dependenciesSize; i++) {
        std::unique_ptr<Dependency> dependency(parcel.ReadParcelable<Dependency>());
        if (!dependency) {
            APP_LOGE("ReadParcelable<Dependency> failed");
            return false;
        }
        dependencies.emplace_back(*dependency);
    }
    
    return true;
}

bool SharedPackageInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(versionName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(description));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(compatiblePolicy));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, dependencies.size());
    for (auto &dependency : dependencies) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &dependency);
    }
    return true;
}

SharedPackageInfo *SharedPackageInfo::Unmarshalling(Parcel &parcel)
{
    SharedPackageInfo *info = new (std::nothrow) SharedPackageInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // AppExecFwk
} // OHOS