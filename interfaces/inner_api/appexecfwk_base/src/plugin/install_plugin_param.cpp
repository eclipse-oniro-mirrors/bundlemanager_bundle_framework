/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "install_plugin_param.h"

#include "app_log_wrapper.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* RENAME_INSTALL_KEY = "ohos.bms.param.renameInstall";
constexpr const char* PARAMETERS_VALUE_TRUE = "true";
}

bool InstallPluginParam::ReadFromParcel(Parcel &parcel)
{
    userId = parcel.ReadInt32();

    uint32_t parametersSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, parametersSize);
    CONTAINER_SECURITY_VERIFY(parcel, parametersSize, &parameters);
    for (uint32_t i = 0; i < parametersSize; ++i) {
        std::string key = parcel.ReadString();
        std::string value = parcel.ReadString();
        parameters.emplace(key, value);
    }
    return true;
}

InstallPluginParam *InstallPluginParam::Unmarshalling(Parcel &parcel)
{
    InstallPluginParam *info = new (std::nothrow) InstallPluginParam();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool InstallPluginParam::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, userId);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, static_cast<uint32_t>(parameters.size()));
    for (const auto &parameter : parameters) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, parameter.first);
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, parameter.second);
    }
    return true;
}

bool InstallPluginParam::IsRenameInstall() const
{
    for (const auto &item : parameters) {
        if ((item.first == RENAME_INSTALL_KEY) && (item.second == PARAMETERS_VALUE_TRUE)) {
            return true;
        } 
    }
    return false;
}
}  // namespace AppExecFwk
}  // namespace OHOS