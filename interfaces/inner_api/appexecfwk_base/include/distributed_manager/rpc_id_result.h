/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_RPC_ID_RESULT_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_RPC_ID_RESULT_H

#include <string>

#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
struct SummaryAbilityInfo : Parcelable {
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string logoUrl;
    std::string label;
    std::vector<std::string> deviceType;
    std::vector<std::string> rpcId;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static SummaryAbilityInfo *Unmarshalling(Parcel &parcel);
};


struct RpcIdResult : public Parcelable {
    int32_t retCode;
    std::string version;
    std::string transactId;
    std::string resultMsg;
    SummaryAbilityInfo abilityInfo;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static RpcIdResult *Unmarshalling(Parcel &parcel);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_RPC_ID_RESULT_H