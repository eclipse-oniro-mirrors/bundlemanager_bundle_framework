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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_HSP_PLUGIN_PARAM_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_HSP_PLUGIN_PARAM_H

#include <string>

#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
struct HspPluginParam : public Parcelable {
    int32_t certType = 0;
    std::string subjectCN;
    std::string issuerCN;
    std::string subjectOU;
    std::string issuerC;
    std::string issuerO;
    std::string issuerOU;
    std::string subjectO;
    std::string serialNumber;
    std::string authKeyIdentifier;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static HspPluginParam *Unmarshalling(Parcel &parcel);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_HSP_PLUGIN_PARAM_H
