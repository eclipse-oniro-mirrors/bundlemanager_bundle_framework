/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_BASE_INCLUDE_APP_QUICK_FIX_INFO_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_BASE_INCLUDE_APP_QUICK_FIX_INFO_H

#include <string>

#include "parcel.h"
#include "quick_fix_info.h"

namespace OHOS {
namespace AppExecFwk {
struct AppQuickFixInfo : public Parcelable {
    std::string bundleName; // original bundle name
    int32_t versionCode; // original bundle version code
    std::string versionName; // original bundle version name

    QuickFixInfo deployedQuickFix; // deployed quick fix patch
    QuickFixInfo deployingQuickFix; // deploying quick fix patch

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static AppQuickFixInfo *Unmarshalling(Parcel &parcel);
};
}
}
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_BASE_INCLUDE_APP_QUICK_FIX_INFO_H