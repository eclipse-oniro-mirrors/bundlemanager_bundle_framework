/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "app_running_control_rule.h"

#include "app_log_wrapper.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool AppRunningControlRule::ReadFromParcel(Parcel &parcel)
{
    appId = Str16ToStr8(parcel.ReadString16());
    ruleType = static_cast<AppRunningControlRuleType>(parcel.ReadInt32());
    std::unique_ptr<AppRunningControlRuleParam> ruleParamPtr(parcel.ReadParcelable<AppRunningControlRuleParam>());
    if (ruleParamPtr == nullptr) {
        APP_LOGE("ReadParcelable<AppRunningControlRuleParam> failed");
        return false;
    }
    ruleParam = *ruleParamPtr;
    return true;
}

bool AppRunningControlRule::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appId));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(ruleType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &ruleParam);
    return true;
}

AppRunningControlRule *AppRunningControlRule::Unmarshalling(Parcel &parcel)
{
    AppRunningControlRule *info = new (std::nothrow) AppRunningControlRule();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
}
}