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

#ifndef FOUNDATION_BUNDLEMANAGER_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_CODE_PROTECT_BUNDLE_INFO_H
#define FOUNDATION_BUNDLEMANAGER_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_CODE_PROTECT_BUNDLE_INFO_H

#include <string>

#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
enum CodeOperation {
    ADD = 1,
    UPDATE = 2,
    DELETE = 3,
};

struct CodeProtectBundleInfo : public Parcelable {
    std::string bundleName;
    int32_t uid = -1;
    int32_t appIndex = 0;
    uint32_t versionCode = 0;
    uint32_t applicationReservedFlag = 0;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static CodeProtectBundleInfo *Unmarshalling(Parcel &parcel);
};
} // AppExecFwk
} // OHOS

#endif // FOUNDATION_BUNDLEMANAGER_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_CODE_PROTECT_BUNDLE_INFO_H