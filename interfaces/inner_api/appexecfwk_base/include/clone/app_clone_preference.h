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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_CLONE_APP_CLONE_PREFERENCE_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_CLONE_APP_CLONE_PREFERENCE_H

#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
enum class AppClonePreferenceMode : int32_t {
    ALWAYS_ASK = 0,
    MAIN_APP = 1,
    CLONE_APP = 2,
};

struct AppClonePreference : public Parcelable {
    AppClonePreference() = default;
    ~AppClonePreference() override = default;

    AppClonePreferenceMode mode {AppClonePreferenceMode::ALWAYS_ASK};
    int32_t appIndex {0};

    bool Marshalling(Parcel &parcel) const override
    {
        if (!parcel.WriteInt32(static_cast<int32_t>(mode))) {
            return false;
        }
        if (!parcel.WriteInt32(appIndex)) {
            return false;
        }
        return true;
    }

    static AppClonePreference *Unmarshalling(Parcel &parcel)
    {
        auto *preference = new (std::nothrow) AppClonePreference();
        if (preference == nullptr) {
            return nullptr;
        }
        int32_t typeValue = 0;
        if (!parcel.ReadInt32(typeValue)) {
            delete preference;
            return nullptr;
        }
        // Reject malformed IPC input — out-of-range values would bypass CLONE branch logic in DataMgr.
        if (typeValue < static_cast<int32_t>(AppClonePreferenceMode::ALWAYS_ASK) ||
            typeValue > static_cast<int32_t>(AppClonePreferenceMode::CLONE_APP)) {
            delete preference;
            return nullptr;
        }
        preference->mode = static_cast<AppClonePreferenceMode>(typeValue);
        if (!parcel.ReadInt32(preference->appIndex)) {
            delete preference;
            return nullptr;
        }
        return preference;
    }
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_CLONE_APP_CLONE_PREFERENCE_H
