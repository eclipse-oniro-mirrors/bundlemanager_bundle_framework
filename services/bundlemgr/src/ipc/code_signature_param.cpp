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

#include "ipc/code_signature_param.h"

#include "bundle_constants.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string CODE_SIGNATURE_MODULE_PATH = "modulePath";
const std::string CODE_SIGNATURE_CPU_ABI = "cpuAbi";
const std::string CODE_SIGNATURE_TARGET_SO_PATH = "targetSoPath";
const std::string CODE_SIGNATURE_SIGNATURE_FILE_PATH = "signatureFileDir";
const std::string CODE_SIGNATURE_IS_ENTERPRISE_BUNDLE = "isEnterpriseBundle";
const std::string CODE_SIGNATURE_APP_IDENTIFIER = "appIdentifier";
const std::string CODE_SIGNATURE_IS_PREINSTALLED_BUNDLE = "isPreInstalledBundle";
const std::string CODE_SIGNATURE_IS_COMPILE_SDK_OPENHARMONY = "isCompileSdkOpenHarmony";
} // namespace

bool CodeSignatureParam::ReadFromParcel(Parcel &parcel)
{
    modulePath = Str16ToStr8(parcel.ReadString16());
    cpuAbi = Str16ToStr8(parcel.ReadString16());
    targetSoPath = Str16ToStr8(parcel.ReadString16());
    signatureFileDir = Str16ToStr8(parcel.ReadString16());
    isEnterpriseBundle = parcel.ReadBool();
    appIdentifier = Str16ToStr8(parcel.ReadString16());
    isPreInstalledBundle = parcel.ReadBool();
    isCompileSdkOpenHarmony = parcel.ReadBool();
    return true;
}

bool CodeSignatureParam::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(modulePath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(cpuAbi));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(targetSoPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(signatureFileDir));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isEnterpriseBundle);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appIdentifier));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isPreInstalledBundle);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isCompileSdkOpenHarmony);
    return true;
}

CodeSignatureParam *CodeSignatureParam::Unmarshalling(Parcel &parcel)
{
    CodeSignatureParam *info = new (std::nothrow) CodeSignatureParam();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        APP_LOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

std::string CodeSignatureParam::ToString() const
{
    nlohmann::json codeSignatureParamJson = nlohmann::json {
        { CODE_SIGNATURE_MODULE_PATH, modulePath },
        { CODE_SIGNATURE_CPU_ABI, cpuAbi },
        { CODE_SIGNATURE_TARGET_SO_PATH, targetSoPath },
        { CODE_SIGNATURE_SIGNATURE_FILE_PATH, signatureFileDir },
        { CODE_SIGNATURE_IS_ENTERPRISE_BUNDLE, isEnterpriseBundle },
        { CODE_SIGNATURE_APP_IDENTIFIER, appIdentifier },
        { CODE_SIGNATURE_IS_PREINSTALLED_BUNDLE, isPreInstalledBundle },
        { CODE_SIGNATURE_IS_COMPILE_SDK_OPENHARMONY, isCompileSdkOpenHarmony },
    };
    return codeSignatureParamJson.dump(Constants::DUMP_INDENT);
}
} // AppExecFwk
} // OHOS