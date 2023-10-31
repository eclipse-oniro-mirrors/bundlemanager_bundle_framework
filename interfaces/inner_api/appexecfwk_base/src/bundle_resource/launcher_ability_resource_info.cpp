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

    std::u16string labelVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, labelVal);
    label = Str16ToStr8(labelVal);

    std::u16string iconVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, iconVal);
    icon = Str16ToStr8(iconVal);
    return true;
}

bool LauncherAbilityResourceInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(abilityName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(label));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(icon));
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
