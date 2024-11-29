/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "clone_param.h"

#include "nlohmann/json.hpp"
#include "string_ex.h"

#include "app_log_wrapper.h"
#include "parcel_macro.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
bool DestroyAppCloneParam::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, userId);

    uint32_t parametersSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, parametersSize);
    CONTAINER_SECURITY_VERIFY(parcel, parametersSize, &parameters);
    for (uint32_t i = 0; i < parametersSize; ++i) {
        std::string key = Str16ToStr8(parcel.ReadString16());
        std::string value = Str16ToStr8(parcel.ReadString16());
        parameters.emplace(key, value);
    }
    return true;
}

DestroyAppCloneParam* DestroyAppCloneParam::Unmarshalling(Parcel &parcel)
{
    DestroyAppCloneParam *info = new (std::nothrow) DestroyAppCloneParam();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool DestroyAppCloneParam::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, userId);
    
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, static_cast<uint32_t>(parameters.size()));
    for (const auto &parameter : parameters) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(parameter.first));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(parameter.second));
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
