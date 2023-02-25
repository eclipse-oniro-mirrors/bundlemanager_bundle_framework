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

#include "parcel_macro.h"
#include "service_info.h"
#include "string_ex.h"

namespace OHOS{
namespace AppExecFwk{
bool AppInfo::ReadFromParcel(Parcel &parcel)
{
    name = Str16ToStr8(parcel.ReadString16());
    bundleName = Str16ToStr8(parcel.ReadString16());
    iconId = parcel.ReadInt32();
    labelId = parcel.ReadInt32();
    descriptionId = parcel.ReadInt32();
    return true;
}

bool AppInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, iconId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, labelId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, descriptionId);
    return true;
}

AppInfo *AppInfo::Unmarshalling(Parcel &parcel)
{
    AppInfo *info = new (std::nothrow) AppInfo();
    if (info && !info->ReadFromParcel(parcel))
    {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool ServiceInfo::ReadFromParcel(Parcel &parcel)
{
    std::unique_ptr<AppInfo> app(parcel.ReadParcelable<AppInfo>());
    if (!app)
    {
        APP_LOGE("ReadParcelable<AppInfo> failed");
        return false;
    }
    appInfo = *app;
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    abilityName = Str16ToStr8(parcel.ReadString16());
    serviceType = static_cast<ExtensionServiceType>(parcel.ReadInt32());
    iconId = parcel.ReadInt32();
    labelId = parcel.ReadInt32();
    descriptionId = parcel.ReadInt32();

    int32_t size;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, size);
    CONTAINER_SECURITY_VERIFY(parcel, size, &permissions);
    for (int32_t i = 0; i < size; i++)
    {
        permissions.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }
    
    return true;
}

bool ServiceInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &appInfo);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(abilityName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(serviceType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, iconId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, labelId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, descriptionId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, permissions.size());
    for (auto &permission : permissions)
    {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(permission));
    }
    return true;
}

ServiceInfo *ServiceInfo::Unmarshalling(Parcel &parcel)
{
    ServiceInfo *info = new (std::nothrow) ServiceInfo();
    if (info && !info->ReadFromParcel(parcel))
    {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool IntentInfo::ReadFromParcel(Parcel &parcel)
{
    std::unique_ptr<AppInfo> app(parcel.ReadParcelable<AppInfo>());
    if (!app)
    {
        APP_LOGE("ReadParcelable<AppInfo> failed");
        return false;
    }
    appInfo = *app;
    intentName = Str16ToStr8(parcel.ReadString16());
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    abilityName = Str16ToStr8(parcel.ReadString16());
    cardName = Str16ToStr8(parcel.ReadString16());
    int32_t supportDimensionSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportDimensionSize);
    CONTAINER_SECURITY_VERIFY(parcel, supportDimensionSize, &supportDimensions);
    for (int32_t i = 0; i < supportDimensionSize; i++)
    {
        supportDimensions.emplace_back(parcel.ReadInt32());
    }
    componentType = static_cast<ComponentType>(parcel.ReadInt32());
    return true;
}

bool IntentInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &appInfo);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(intentName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(abilityName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(cardName));
    const auto supportDimensionSize = static_cast<int32_t>(supportDimensions.size());
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportDimensionSize);
    for (auto i = 0; i < supportDimensionSize; i++)
    {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, supportDimensions[i]);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(componentType));
    return true;
}

IntentInfo *IntentInfo::Unmarshalling(Parcel &parcel)
{
    IntentInfo *info = new (std::nothrow) IntentInfo();
    if (info && !info->ReadFromParcel(parcel))
    {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // namespace AppExecFwk
} // namespace OHOS