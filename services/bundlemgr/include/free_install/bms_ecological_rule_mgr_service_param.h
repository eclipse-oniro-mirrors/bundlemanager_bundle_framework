/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef BMS_ECOLOGICALRULEMANAGERSERVICE_PARAM_H
#define BMS_ECOLOGICALRULEMANAGERSERVICE_PARAM_H

#include <string>
#include <vector>

#include "parcel.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

struct BmsExperienceRule : public Parcelable {
    bool isAllow = true;
    std::string sceneCode = "";
    sptr<Want> replaceWant = nullptr;

    bool Marshalling(Parcel &parcel) const override;

    static BmsExperienceRule *Unmarshalling(Parcel &parcel);
};

struct BmsCallerInfo : public Parcelable {
    enum:uint8_t {
        TYPE_INVALID = 0,
        TYPE_HARMONY_APP = 1,
        TYPE_ATOM_SERVICE = 2,
        TYPE_QUICK_APP = 4,
        TYPE_BOXED_ATOM_SERVICE = 5
    };

    enum:uint8_t {
        MODEL_STAGE = 0,
        MODEL_FA
    };

    std::string packageName;
    int32_t uid = 0;
    int32_t pid = 0;

    int32_t callerAppType = TYPE_INVALID;
    int32_t targetAppType = TYPE_INVALID;

    int32_t callerModelType = 0L;
    std::string targetAppDistType = "";
    std::string targetLinkFeature = "";
    int32_t targetLinkType = 0L;
    int32_t callerAbilityType = 0L;
    int32_t embedded = 0;
    std::string callerAppProvisionType;
    std::string targetAppProvisionType;

    bool ReadFromParcel(Parcel &parcel);

    bool Marshalling(Parcel &parcel) const override;

    static BmsCallerInfo *Unmarshalling(Parcel &parcel);

    std::string ToString() const;
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // BMS_ECOLOGICALRULEMANAGERSERVICE_PARAM_H
