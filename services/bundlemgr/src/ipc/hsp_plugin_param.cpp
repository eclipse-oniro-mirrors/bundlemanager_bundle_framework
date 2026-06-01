/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ipc/hsp_plugin_param.h"

#include "app_log_wrapper.h"
#include "parcel_macro.h"

namespace OHOS {
namespace AppExecFwk {
bool HspPluginParam::ReadFromParcel(Parcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, certType);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, subjectCN);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, issuerCN);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, subjectOU);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, issuerC);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, issuerO);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, issuerOU);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, subjectO);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, serialNumber);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, authKeyIdentifier);
    return true;
}

bool HspPluginParam::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, certType);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, subjectCN);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, issuerCN);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, subjectOU);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, issuerC);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, issuerO);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, issuerOU);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, subjectO);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, serialNumber);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, authKeyIdentifier);
    return true;
}

HspPluginParam *HspPluginParam::Unmarshalling(Parcel &parcel)
{
    HspPluginParam *param = new (std::nothrow) HspPluginParam();
    if (param != nullptr && !param->ReadFromParcel(parcel)) {
        APP_LOGE("read HspPluginParam from parcel failed");
        delete param;
        param = nullptr;
    }
    return param;
}
}  // namespace AppExecFwk
}  // namespace OHOS
