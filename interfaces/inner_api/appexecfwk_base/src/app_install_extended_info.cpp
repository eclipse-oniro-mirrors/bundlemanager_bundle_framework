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
    int32_t size;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, size);
    CONTAINER_SECURITY_VERIFY(parcel, size, &hashParam);
    for (auto i = 0; i < size; i++) {
        std::string key = Str16ToStr8(parcel.ReadString16());
        std::string value = Str16ToStr8(parcel.ReadString16());
        hashParam.emplace(key, value);
    }
    specifiedDistributionType = Str16ToStr8(parcel.ReadString16());
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, compatibleVersion);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, crowdtestDeadline);
    installSource = Str16ToStr8(parcel.ReadString16());
    additionalInfo = Str16ToStr8(parcel.ReadString16());
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, size);
    CONTAINER_SECURITY_VERIFY(parcel, size, &sharedBundleInfos);
    for (auto i = 0; i < size; i++) {
        std::unique_ptr<SharedBundleInfo> info(parcel.ReadParcelable<SharedBundleInfo>());
        if (!info) {
            APP_LOGE("ReadParcelable<SharedBundleInfo> failed");
            return false;
        }
        sharedBundleInfos.emplace_back(*info);
    }
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, size);
    CONTAINER_SECURITY_VERIFY(parcel, size, &requiredDeviceFeatures);
    for (auto i = 0; i < size; i++) {
        std::string outerKey = Str16ToStr8(parcel.ReadString16());
        int32_t innerSize;
        READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, innerSize);
        std::map<std::string, std::vector<std::string>> innerMap;
        CONTAINER_SECURITY_VERIFY(parcel, innerSize, &innerMap);
        for (auto j = 0; j < innerSize; j++) {
            std::string innerKey = Str16ToStr8(parcel.ReadString16());
            int32_t vecSize;
            READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, vecSize);
            std::vector<std::string> vec;
            CONTAINER_SECURITY_VERIFY(parcel, vecSize, &vec);
            for (auto k = 0; k < vecSize; k++) {
                vec.emplace_back(Str16ToStr8(parcel.ReadString16()));
            }
            innerMap.emplace(innerKey, vec);
        }
        requiredDeviceFeatures.emplace(outerKey, innerMap);
    }
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, size);
    CONTAINER_SECURITY_VERIFY(parcel, size, &hapPath);
    for (auto i = 0; i < size; i++) {
        hapPath.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }
    return true;
}

bool AppInstallExtendedInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, hashParam.size());
    for (const auto &[key, value] : hashParam) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(key));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(value));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(specifiedDistributionType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, compatibleVersion);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, crowdtestDeadline);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(installSource));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(additionalInfo));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, sharedBundleInfos.size());
    for (const auto &info : sharedBundleInfos) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &info);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, requiredDeviceFeatures.size());
    for (const auto &[outerKey, innerMap] : requiredDeviceFeatures) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(outerKey));
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, innerMap.size());
        for (const auto &[innerKey, vec] : innerMap) {
            WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(innerKey));
            WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, vec.size());
            for (const auto &str : vec) {
                WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(str));
            }
        }
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, hapPath.size());
    for (const auto &path : hapPath) {
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
