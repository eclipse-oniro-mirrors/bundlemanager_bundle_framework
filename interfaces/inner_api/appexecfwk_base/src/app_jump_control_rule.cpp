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

#include "app_jump_control_rule.h"

#include "app_log_wrapper.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool AppJumpControlRule::ReadFromParcel(Parcel &parcel)
{
    callerPkg = Str16ToStr8(parcel.ReadString16());
    targetPkg = Str16ToStr8(parcel.ReadString16());
    controlMessage = Str16ToStr8(parcel.ReadString16());
    jumpMode = static_cast<AppExecFwk::AbilityJumpMode>(parcel.ReadInt32());
    return true;
}

bool AppJumpControlRule::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(callerPkg));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(targetPkg));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(controlMessage));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(jumpMode));
    return true;
}

AppJumpControlRule *AppJumpControlRule::Unmarshalling(Parcel &parcel)
{
    AppJumpControlRule *info = new (std::nothrow) AppJumpControlRule();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
}
}