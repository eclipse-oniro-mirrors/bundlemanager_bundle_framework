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

#include "ipc/verify_bin_param.h"

#include "app_log_wrapper.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool VerifyBinParam::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    appIdentifier = Str16ToStr8(parcel.ReadString16());
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, userId);
    int32_t binFilePathsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, binFilePathsSize);
    CONTAINER_SECURITY_VERIFY(parcel, binFilePathsSize, &binFilePaths);
    for (int32_t i = 0; i < binFilePathsSize; ++i) {
        std::string binFilePath = Str16ToStr8(parcel.ReadString16());
        binFilePaths.emplace_back(binFilePath);
    }
    return true;
}

bool VerifyBinParam::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appIdentifier));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, userId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, binFilePaths.size());
    for (auto &item : binFilePaths) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(item));
    }
    return true;
}

VerifyBinParam *VerifyBinParam::Unmarshalling(Parcel &parcel)
{
    VerifyBinParam *param = new (std::nothrow) VerifyBinParam();
    if (param != nullptr && !param->ReadFromParcel(parcel)) {
        APP_LOGE("read VerifyBinParam from parcel failed");
        delete param;
        param = nullptr;
    }
    return param;
}
}  // namespace AppExecFwk
}  // namespace OHOS
