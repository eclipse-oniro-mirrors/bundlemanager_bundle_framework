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

#include "ipc/encryption_param.h"

#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
EncryptionParam::EncryptionParam(const std::string &name, const std::string &id, int32_t uidParam, int32_t userIdParam,
    EncryptionDirType dirType) : bundleName(name), groupId(id), uid(uidParam),
    userId(userIdParam), encryptionDirType(dirType) {};

bool EncryptionParam::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    groupId = Str16ToStr8(parcel.ReadString16());
    uid = parcel.ReadInt32();
    userId = parcel.ReadInt32();
    encryptionDirType = static_cast<EncryptionDirType>(parcel.ReadUint8());
    return true;
}

bool EncryptionParam::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(groupId));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, userId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint8, parcel, static_cast<uint8_t>(encryptionDirType));
    return true;
}

EncryptionParam *EncryptionParam::Unmarshalling(Parcel &parcel)
{
    EncryptionParam *info = new (std::nothrow) EncryptionParam();
    if (info != nullptr && !info->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
}  // namespace AppExecFwk
}  // namespace OHOS
