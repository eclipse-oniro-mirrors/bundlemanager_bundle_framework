/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "launcher_ability_resource_info.h"

#include "app_log_wrapper.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool LauncherAbilityResourceInfo::ReadFromParcel(Parcel &parcel)
{
    std::u16string bundleNameVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, bundleNameVal);
    bundleName = Str16ToStr8(bundleNameVal);

    std::u16string moduleNameVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, moduleNameVal);
    moduleName = Str16ToStr8(moduleNameVal);

    std::u16string abilityNameVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, abilityNameVal);
    abilityName = Str16ToStr8(abilityNameVal);

    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, label);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, icon);

    int32_t foregroundSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, foregroundSize);
    CONTAINER_SECURITY_VERIFY(parcel, foregroundSize, &foreground);
    uint8_t foregroundVal = 0;
    for (auto i = 0; i < foregroundSize; i++) {
        READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint8Unaligned, parcel, foregroundVal);
        foreground.emplace_back(foregroundVal);
    }

    int32_t backgroundSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, backgroundSize);
    CONTAINER_SECURITY_VERIFY(parcel, backgroundSize, &background);
    uint8_t backgroundVal = 0;
    for (auto i = 0; i < backgroundSize; i++) {
        READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint8Unaligned, parcel, backgroundVal);
        background.emplace_back(backgroundVal);
    }

    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isDefaultApp);
    return true;
}

bool LauncherAbilityResourceInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(abilityName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, label);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, icon);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, foreground.size());
    for (const auto &data : foreground) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint8Unaligned, parcel, data);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, background.size());
    for (const auto &data : background) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint8Unaligned, parcel, data);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isDefaultApp);
    return true;
}

LauncherAbilityResourceInfo *LauncherAbilityResourceInfo::Unmarshalling(Parcel &parcel)
{
    LauncherAbilityResourceInfo *info = new (std::nothrow) LauncherAbilityResourceInfo();
    if ((info != nullptr) && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // AppExecFwk
} // OHOS
