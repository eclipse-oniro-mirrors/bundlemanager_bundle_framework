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

#ifndef OHOS_ABILITY_RUNTIME_ERMS_PARAM_H
#define OHOS_ABILITY_RUNTIME_ERMS_PARAM_H

#include <string>
#include <vector>

#include "parcel.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace ErmsParams {
using Want = OHOS::AAFwk::Want;

struct ExperienceRule : public Parcelable {
    bool isAllow = false;
    std::shared_ptr<Want> replaceWant = nullptr;
    int64_t sceneCode = 0L;
    int64_t allowTypes;

    bool ReadFromParcel(Parcel &parcel);

    bool Marshalling(Parcel &parcel) const override;

    static ExperienceRule *Unmarshalling(Parcel &parcel);
};

struct CallerInfo : public Parcelable {
    std::string packageName;
    int64_t uid = 0L;
    int64_t pid = 0L;

    bool ReadFromParcel(Parcel &parcel);

    bool Marshalling(Parcel &parcel) const override;

    static CallerInfo *Unmarshalling(Parcel &parcel);
};
}  // namespace ErmsParams
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ERMS_PARAM_H
