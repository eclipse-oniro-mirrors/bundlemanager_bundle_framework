/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "bundle_dir.h"

#include "nlohmann/json.hpp"
#include "string_ex.h"

#include "json_util.h"
#include "parcel_macro.h"
#include <new>

namespace OHOS {
namespace AppExecFwk {
bool BundleDir::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    appIndex = parcel.ReadInt32();
    dir = Str16ToStr8(parcel.ReadString16());
    return true;
}

BundleDir *BundleDir::Unmarshalling(Parcel &parcel)
{
    BundleDir *bundleDir = new (std::nothrow) BundleDir();
    if (bundleDir && !bundleDir->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete bundleDir;
        bundleDir = nullptr;
    }
    return bundleDir;
}

bool BundleDir::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(dir));
    return true;
}

std::string BundleDir::ToString() const
{
    return "[ bundleName = " + bundleName
            + ", appIndex = " + std::to_string(appIndex)
            + ", dir = " + dir
            + "]";
}
}  // namespace AppExecFwk
}  // namespace OHOS