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

#include "aot/aot_args.h"

#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool AOTArgs::ReadFromParcel(Parcel &parcel)
{
    return false;
}

bool AOTArgs::Marshalling(Parcel &parcel) const
{
    return false;
}

AOTArgs *AOTArgs::Unmarshalling(Parcel &parcel)
{
    return nullptr;
}

std::string AOTArgs::ToString() const
{
    return "";
}
}  // namespace AppExecFwk
}  // namespace OHOS
