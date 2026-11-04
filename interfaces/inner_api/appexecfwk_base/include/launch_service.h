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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_LAUNCH_SERVICE_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_LAUNCH_SERVICE_H

#include <string>
#include <vector>

#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
// Type of a launch service. Only daemon is supported for now.
enum class LaunchServiceType : int32_t {
    DAEMON = 0,
};

inline constexpr const char *LAUNCH_SERVICE_TYPE_DAEMON = "daemon";

inline std::string LaunchServiceTypeToString(LaunchServiceType type)
{
    return type == LaunchServiceType::DAEMON ? std::string(LAUNCH_SERVICE_TYPE_DAEMON) : std::string();
}

// Strictly parses a launch service type string; returns false for unknown values.
inline bool LaunchServiceTypeFromString(const std::string &typeStr, LaunchServiceType &type)
{
    if (typeStr == LAUNCH_SERVICE_TYPE_DAEMON) {
        type = LaunchServiceType::DAEMON;
        return true;
    }
    return false;
}

struct LaunchService : public Parcelable {
    std::string name;
    std::string binaryPath;
    bool runAtLoad = false;
    bool keepAlive = false;
    bool provideIpcService = false;
    LaunchServiceType type = LaunchServiceType::DAEMON;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static LaunchService *Unmarshalling(Parcel &parcel);
};

struct LaunchServicesResult : public Parcelable {
    std::vector<LaunchService> launchServices;
    std::string developerId;
    std::string appIdentifier;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static LaunchServicesResult *Unmarshalling(Parcel &parcel);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_LAUNCH_SERVICE_H
