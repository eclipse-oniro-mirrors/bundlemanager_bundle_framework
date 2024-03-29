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

#include "bundle_resource_info.h"

#include "app_log_wrapper.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {

bool BundleResourceInfo::ReadFromParcel(Parcel &parcel)
{
    std::u16string bundleNameVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, bundleNameVal);
    bundleName = Str16ToStr8(bundleNameVal);
    std::u16string labelVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, labelVal);
    label = Str16ToStr8(labelVal);
    std::u16string iconVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, iconVal);
    icon = Str16ToStr8(iconVal);

    int32_t foregroundSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, foregroundSize);
    CONTAINER_SECURITY_VERIFY(parcel, foregroundSize, &foreground);
    for (auto i = 0; i < foregroundSize; i++) {
        foreground.emplace_back(parcel.ReadUint8());
    }

    int32_t backgroundSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, backgroundSize);
    CONTAINER_SECURITY_VERIFY(parcel, backgroundSize, &background);
    for (auto i = 0; i < backgroundSize; i++) {
        background.emplace_back(parcel.ReadUint8());
    }
    return true;
}

bool BundleResourceInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(label));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(icon));

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, foreground.size());
    for (const auto &data : foreground) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint8, parcel, data);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, background.size());
    for (const auto &data : background) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint8, parcel, data);
    }
    return true;
}

BundleResourceInfo *BundleResourceInfo::Unmarshalling(Parcel &parcel)
{
    BundleResourceInfo *info = new (std::nothrow) BundleResourceInfo();
    if ((info != nullptr) && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // AppExecFwk
} // OHOS
