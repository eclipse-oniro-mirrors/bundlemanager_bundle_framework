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

#include "app_running_control_rule_result.h"

#include "app_log_wrapper.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool AppRunningControlRuleResult::ReadFromParcel(Parcel &parcel)
{
    controlMessage = Str16ToStr8(parcel.ReadString16());
    std::shared_ptr<AAFwk::Want> want(parcel.ReadParcelable<AAFwk::Want>());
    controlWant = want;
    return true;
}

bool AppRunningControlRuleResult::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(controlMessage));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, controlWant.get());
    return true;
}

AppRunningControlRuleResult *AppRunningControlRuleResult::Unmarshalling(Parcel &parcel)
{
    AppRunningControlRuleResult *info = new (std::nothrow) AppRunningControlRuleResult();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
}
}