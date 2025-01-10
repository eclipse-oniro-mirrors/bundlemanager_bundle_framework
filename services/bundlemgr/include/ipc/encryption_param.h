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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ENCRYPTION_PARAM_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ENCRYPTION_PARAM_H

#include "message_parcel.h"

namespace OHOS {
namespace AppExecFwk {
enum EncryptionDirType : uint8_t {
    APP = 1,
    GROUP = 2
};

struct EncryptionParam : public Parcelable {
    std::string bundleName;
    // indicates dir name for group
    std::string groupId;
    int32_t uid = -1;
    int32_t userId = 0;
    EncryptionDirType encryptionDirType = EncryptionDirType::APP;

    EncryptionParam() = default;
    EncryptionParam(const std::string &name, const std::string &id, int32_t uidParam, int32_t userIdParam,
        EncryptionDirType dirType);

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static EncryptionParam *Unmarshalling(Parcel &parcel);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_ENCRYPTION_PARAM_H
