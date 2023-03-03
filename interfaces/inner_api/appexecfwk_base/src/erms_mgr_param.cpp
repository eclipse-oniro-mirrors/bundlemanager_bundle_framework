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

#include "erms_mgr_param.h"

#include <string>
#include <vector>

#include "iremote_broker.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {
using ErmsCallerInfo = OHOS::AppExecFwk::ErmsParams::CallerInfo;
using ExperienceRule = OHOS::AppExecFwk::ErmsParams::ExperienceRule;

bool ExperienceRule::ReadFromParcel(Parcel &parcel)
{
    return true;
}

ExperienceRule *ExperienceRule::Unmarshalling(Parcel &parcel)
{
    ExperienceRule *info = new (std::nothrow) ExperienceRule();
    return info;
}

bool ExperienceRule::Marshalling(Parcel &parcel) const
{
    return true;
}

bool ErmsCallerInfo::ReadFromParcel(Parcel &parcel)
{
    return true;
}

ErmsCallerInfo *ErmsCallerInfo::Unmarshalling(Parcel &parcel)
{
    ErmsCallerInfo *info = new (std::nothrow) CallerInfo();
    return info;
}

bool ErmsCallerInfo::Marshalling(Parcel &parcel) const
{
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
