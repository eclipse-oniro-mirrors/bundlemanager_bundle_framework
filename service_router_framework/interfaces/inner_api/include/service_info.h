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

#ifndef FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_INCLUDE_SERVICE_INFO_H
#define FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_INCLUDE_SERVICE_INFO_H

#include <string>
#include <vector>

#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
enum class ExtensionServiceType {
    SHARE = 0,
    UNSPECIFIED = 255
};

enum class ComponentType {
    UI_ABILITY = 0,
    FORM = 1,
    UI_EXTENSION = 2
};

struct AppInfo : public Parcelable {
    std::string name;
    std::string bundleName;
    int32_t iconId = 0;
    int32_t labelId = 0;
    int32_t descriptionId = 0;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static AppInfo *Unmarshalling(Parcel &parcel);
};

struct ServiceInfo : public Parcelable {
    AppInfo appInfo;
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    ExtensionServiceType serviceType;
    int32_t iconId = 0;
    int32_t labelId = 0;
    int32_t descriptionId = 0;
    std::vector<std::string> permissions;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static ServiceInfo *Unmarshalling(Parcel &parcel);
};

struct IntentInfo final : public Parcelable {
    AppInfo appInfo;
    std::string intentName;
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string cardName;
    std::vector<int32_t> supportDimensions;
    ComponentType componentType;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static IntentInfo *Unmarshalling(Parcel &parcel);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_INCLUDE_SERVICE_INFO_H