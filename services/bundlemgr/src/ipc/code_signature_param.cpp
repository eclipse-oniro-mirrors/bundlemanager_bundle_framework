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

#include "app_log_tag_wrapper.h"
#include "bundle_constants.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "securec.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* CODE_SIGNATURE_MODULE_PATH = "modulePath";
constexpr const char* CODE_SIGNATURE_CPU_ABI = "cpuAbi";
constexpr const char* CODE_SIGNATURE_TARGET_SO_PATH = "targetSoPath";
constexpr const char* CODE_SIGNATURE_SIGNATURE_FILE_PATH = "signatureFileDir";
constexpr const char* CODE_SIGNATURE_IS_ENTERPRISE_BUNDLE = "isEnterpriseBundle";
constexpr const char* CODE_SIGNATURE_APP_IDENTIFIER = "appIdentifier";
constexpr const char* CODE_SIGNATURE_IS_PREINSTALLED_BUNDLE = "isPreInstalledBundle";
constexpr const char* CODE_SIGNATURE_IS_COMPILE_SDK_OPENHARMONY = "isCompileSdkOpenHarmony";
constexpr const char* CODE_SIGNATURE_IS_COMPRESS_NATIVE_LIBRARY = "isCompressNativeLibrary";
constexpr const char* CODE_SIGNATURE_IS_PLUGIN = "isPlugin";
constexpr const char* CODE_SIGNATURE_PLUGIN_ID = "pluginId";
constexpr int32_t MAX_PROFILE_LENGTH = 1 * 1024 * 1000; // 1M
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
    isCompressNativeLibrary = parcel.ReadBool();
    isPlugin = parcel.ReadBool();
    pluginId = Str16ToStr8(parcel.ReadString16());
    profileBlockLength = parcel.ReadUint32();
    if (profileBlockLength > 0 && profileBlockLength < MAX_PROFILE_LENGTH) {
        uint8_t* originData = const_cast<uint8_t*>(parcel.ReadBuffer(profileBlockLength));
        if (originData == nullptr) {
            LOG_NOFUNC_E(BMS_TAG_INSTALLER, "Failed to read profile buffer");
            return false;
        }
        auto tempProfilePtr = std::make_unique<unsigned char[]>(profileBlockLength);
        unsigned char *tempProfileData = tempProfilePtr.get();
        if (tempProfileData == nullptr) {
            LOG_NOFUNC_E(BMS_TAG_INSTALLER, "invalid tempProfileData");
            return false;
        }
        if (memcpy_s(tempProfileData, profileBlockLength, originData, profileBlockLength) != 0) {
            LOG_NOFUNC_E(BMS_TAG_INSTALLER, "process CodeSignatureParam memcpy_s failed");
            return false;
        }
        profileBlock = std::move(tempProfilePtr);
    }
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
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isCompressNativeLibrary);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isPlugin);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(pluginId));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, profileBlockLength);
    if (profileBlockLength > 0 && profileBlockLength < MAX_PROFILE_LENGTH) {
        if (!parcel.WriteBuffer(profileBlock.get(), profileBlockLength)) {
            LOG_NOFUNC_E(BMS_TAG_INSTALLER, "Failed to write profile buffer");
            return false;
        }
    }
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
        { CODE_SIGNATURE_IS_COMPRESS_NATIVE_LIBRARY, isCompressNativeLibrary },
        { CODE_SIGNATURE_IS_PLUGIN, isPlugin },
        { CODE_SIGNATURE_PLUGIN_ID, pluginId },
    };
    return codeSignatureParamJson.dump(Constants::DUMP_INDENT);
}
} // AppExecFwk
} // OHOS
