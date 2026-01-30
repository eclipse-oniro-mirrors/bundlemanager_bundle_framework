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

#include "app_install_extended_info.h"

#include "json_util.h"
#include "parcel_macro.h"
#include "string_ex.h"
#include <cstdint>


namespace OHOS {
namespace AppExecFwk {
bool AppInstallExtendedInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    int32_t dataSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, dataSize);
    CONTAINER_SECURITY_VERIFY(parcel, dataSize, &hashParam);
    for (int32_t i = 0; i<dataSize; ++i) {
        std::string key = Str16ToStr8(parcel.ReadString16());
        std::string value = Str16ToStr8(parcel.ReadString16());
        hashParam.emplace(key, value);
    }
    specifiedDistributionType = Str16ToStr8(parcel.ReadString16());
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, compatibleVersion);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, crowdtestDeadline);
    installSource = Str16ToStr8(parcel.ReadString16());
    additionalInfo = Str16ToStr8(parcel.ReadString16());

    std::unique_ptr<SharedBundleInfo> sharedBundleInfoPtr(parcel.ReadParcelable<SharedBundleInfo>());
    if (!sharedBundleInfoPtr) {
        APP_LOGE("ReadParcelable<SharedBundelInfo> failed");
        return false;
    }
    sharedBundleInfo = *sharedBundleInfoPtr;

    int32_t outerSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, outerSize);
    CONTAINER_SECURITY_VERIFY(parcel, outerSize, &requiredDeviceFeatures);
    for (int32_t i = 0; i < outerSize; ++i) {
        std::string outerKey = Str16ToStr8(parcel.ReadString16());
        int32_t innerSize;
        READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, innerSize);
        std::map<std::string, std::vector<std::string>> innerMap;
        for (int32_t j = 0; j < innerSize; ++j) {
            std::string innerKey = Str16ToStr8(parcel.ReadString16());
            int32_t vecSize;
            READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, vecSize);
            std::vector<std::string> vec;
            for (int32_t k = 0; k < vecSize; ++k) {
                vec.push_back(Str16ToStr8(parcel.ReadString16()));
            }
            innerMap[innerKey] = vec;
        }
        requiredDeviceFeatures[outerKey] = innerMap;
    }

    // read hapPath
    int32_t hapPathSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, hapPathSize);
    CONTAINER_SECURITY_VERIFY(parcel, hapPathSize, &hapPath);
    for (int32_t i = 0; i < hapPathSize; ++i) {
        hapPath.push_back(Str16ToStr8(parcel.ReadString16()));
    }

    return true;
}

bool AppInstallExtendedInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(hashParam.size()));
    for (const auto &dataItem : hashParam) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(dataItem.first));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(dataItem.second));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(specifiedDistributionType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, compatibleVersion);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, crowdtestDeadline);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(installSource));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(additionalInfo));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &sharedBundleInfo);

    int32_t outerSize = static_cast<int32_t>(requiredDeviceFeatures.size());
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, outerSize);
    for (const auto& outerPair : requiredDeviceFeatures) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(outerPair.first));
        int32_t innerSize = static_cast<int32_t>(outerPair.second.size());
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, innerSize);
        for (const auto& innerPair : outerPair.second) {
            WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(innerPair.first));
            int32_t vecSize = static_cast<int32_t>(innerPair.second.size());
            WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, vecSize);
            for (const auto& item : innerPair.second) {
                WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(item));
            }
        }
    }

    // write hapPath
    int32_t hapPathSize = static_cast<int32_t>(hapPath.size());
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, hapPathSize);
    for (const auto& path : hapPath) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(path));
    }

    return true;
}

AppInstallExtendedInfo *AppInstallExtendedInfo::Unmarshalling(Parcel &parcel)
{
    AppInstallExtendedInfo *info = new (std::nothrow) AppInstallExtendedInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // AppExecFwk
} // OHOS
