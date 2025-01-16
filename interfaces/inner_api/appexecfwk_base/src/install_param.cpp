/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "install_param.h"

#include "nlohmann/json.hpp"
#include "string_ex.h"

#include "app_log_wrapper.h"
#include "parcel_macro.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
bool InstallParam::ReadFromParcel(Parcel &parcel)
{
    int32_t flagData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, flagData);
    installFlag = static_cast<InstallFlag>(flagData);

    int32_t locationData;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, locationData);
    installLocation = static_cast<InstallLocation>(locationData);

    userId = parcel.ReadInt32();
    isKeepData = parcel.ReadBool();

    int32_t hashParamSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, hashParamSize);
    CONTAINER_SECURITY_VERIFY(parcel, hashParamSize, &hashParams);
    for (int32_t i = 0; i < hashParamSize; ++i) {
        std::string moduleName = Str16ToStr8(parcel.ReadString16());
        std::string hashValue = Str16ToStr8(parcel.ReadString16());
        hashParams.emplace(moduleName, hashValue);
    }
    crowdtestDeadline = parcel.ReadInt64();

    int32_t sharedBundleDirPathsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, sharedBundleDirPathsSize);
    CONTAINER_SECURITY_VERIFY(parcel, sharedBundleDirPathsSize, &sharedBundleDirPaths);
    for (int32_t i = 0; i < sharedBundleDirPathsSize; ++i) {
        std::string sharedBundleDirPath = Str16ToStr8(parcel.ReadString16());
        sharedBundleDirPaths.emplace_back(sharedBundleDirPath);
    }
    specifiedDistributionType = Str16ToStr8(parcel.ReadString16());
    additionalInfo = Str16ToStr8(parcel.ReadString16());
    isDataPreloadHap = parcel.ReadBool();
    appIdentifier = Str16ToStr8(parcel.ReadString16());

    int32_t verifyCodeParamSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, verifyCodeParamSize);
    CONTAINER_SECURITY_VERIFY(parcel, verifyCodeParamSize, &verifyCodeParams);
    for (int32_t i = 0; i < verifyCodeParamSize; ++i) {
        std::string moduleName = Str16ToStr8(parcel.ReadString16());
        std::string signatureFilePath = Str16ToStr8(parcel.ReadString16());
        verifyCodeParams.emplace(moduleName, signatureFilePath);
    }
    isSelfUpdate = parcel.ReadBool();

    int32_t pgoParamsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, pgoParamsSize);
    CONTAINER_SECURITY_VERIFY(parcel, pgoParamsSize, &pgoParams);
    for (int32_t i = 0; i < pgoParamsSize; ++i) {
        std::string moduleName = Str16ToStr8(parcel.ReadString16());
        std::string pgoPath = Str16ToStr8(parcel.ReadString16());
        pgoParams.emplace(moduleName, pgoPath);
    }

    uint32_t parametersSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, parametersSize);
    CONTAINER_SECURITY_VERIFY(parcel, parametersSize, &parameters);
    for (uint32_t i = 0; i < parametersSize; ++i) {
        std::string key = Str16ToStr8(parcel.ReadString16());
        std::string value = Str16ToStr8(parcel.ReadString16());
        parameters.emplace(key, value);
    }
    isPatch = parcel.ReadBool();
    return true;
}

InstallParam *InstallParam::Unmarshalling(Parcel &parcel)
{
    InstallParam *info = new (std::nothrow) InstallParam();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool InstallParam::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(installFlag));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(installLocation));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, userId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isKeepData);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(hashParams.size()));
    for (const auto &hashParam : hashParams) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hashParam.first));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hashParam.second));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, crowdtestDeadline);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(sharedBundleDirPaths.size()));
    for (const auto& sharedBundleDirPath : sharedBundleDirPaths) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(sharedBundleDirPath));
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(specifiedDistributionType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(additionalInfo));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isDataPreloadHap);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appIdentifier));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(verifyCodeParams.size()));
    for (const auto &verifyCodeParam : verifyCodeParams) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(verifyCodeParam.first));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(verifyCodeParam.second));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isSelfUpdate);
    
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(pgoParams.size()));
    for (const auto &pgoParam : pgoParams) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(pgoParam.first));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(pgoParam.second));
    }

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, static_cast<uint32_t>(parameters.size()));
    for (const auto &parameter : parameters) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(parameter.first));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(parameter.second));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isPatch);
    return true;
}

bool UninstallParam::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, versionCode);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, userId);
    return true;
}

UninstallParam* UninstallParam::Unmarshalling(Parcel &parcel)
{
    UninstallParam *info = new (std::nothrow) UninstallParam();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool UninstallParam::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, versionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, userId);
    return true;
}

bool InstallParam::CheckPermission() const
{
    const int32_t FOUNDATION_UID = 5523;
    if (IPCSkeleton::GetCallingUid() != FOUNDATION_UID) {
        APP_LOGE("set installParam failed");
        return false;
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
