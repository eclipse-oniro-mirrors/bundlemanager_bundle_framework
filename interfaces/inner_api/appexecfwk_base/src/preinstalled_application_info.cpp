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

#include "preinstalled_application_info.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool PreinstalledApplicationInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    labelId = parcel.ReadUint32();
    iconId = parcel.ReadUint32();
    return true;
}

PreinstalledApplicationInfo *PreinstalledApplicationInfo::Unmarshalling(Parcel &parcel)
{
    PreinstalledApplicationInfo *info = new (std::nothrow) PreinstalledApplicationInfo();
    if (info == nullptr) {
        APP_LOGE("Info is null");
        return nullptr;
    }
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("Read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool PreinstalledApplicationInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, labelId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, iconId);
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
