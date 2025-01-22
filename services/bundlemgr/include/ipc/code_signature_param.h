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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_CODE_SIGNATURE_PARAM_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_CODE_SIGNATURE_PARAM_H

#include "message_parcel.h"

namespace OHOS {
namespace AppExecFwk {
struct CodeSignatureParam : public Parcelable {
    bool isEnterpriseBundle = false;
    bool isPreInstalledBundle = false;
    bool isCompileSdkOpenHarmony = false;
    bool isInternaltestingBundle = false;
    bool isCompressNativeLibrary = true;
    std::string modulePath;
    std::string cpuAbi;
    std::string targetSoPath;
    std::string signatureFileDir;
    std::string appIdentifier;

    std::string ToString() const;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static CodeSignatureParam *Unmarshalling(Parcel &parcel);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_CODE_SIGNATURE_PARAM_H
