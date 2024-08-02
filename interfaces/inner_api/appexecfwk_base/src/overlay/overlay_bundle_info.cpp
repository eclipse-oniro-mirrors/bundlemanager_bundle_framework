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

#include "overlay_bundle_info.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* BUNDLE_OVERLAY_BUNDLE_NAME = "bundleName";
const char* BUNDLE_OVERLAY_BUNDLE_DIR = "bundleDir";
const char* BUNDLE_OVERLAY_BUNDLE_STATE = "state";
const char* BUNDLE_OVERLAY_BUNDLE_PRIORITY = "priority";
} // namespace
bool OverlayBundleInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    bundleDir = Str16ToStr8(parcel.ReadString16());
    state = parcel.ReadInt32();
    priority = parcel.ReadInt32();
    return true;
}

bool OverlayBundleInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleDir));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, state);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, priority);
    return true;
}

OverlayBundleInfo *OverlayBundleInfo::Unmarshalling(Parcel &parcel)
{
    OverlayBundleInfo *info = new (std::nothrow) OverlayBundleInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

void to_json(nlohmann::json &jsonObject, const OverlayBundleInfo &overlayBundleInfo)
{
    jsonObject = nlohmann::json {
        {BUNDLE_OVERLAY_BUNDLE_NAME, overlayBundleInfo.bundleName},
        {BUNDLE_OVERLAY_BUNDLE_DIR, overlayBundleInfo.bundleDir},
        {BUNDLE_OVERLAY_BUNDLE_STATE, overlayBundleInfo.state},
        {BUNDLE_OVERLAY_BUNDLE_PRIORITY, overlayBundleInfo.priority}
    };
}

void from_json(const nlohmann::json &jsonObject, OverlayBundleInfo &overlayBundleInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_OVERLAY_BUNDLE_NAME,
        overlayBundleInfo.bundleName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        BUNDLE_OVERLAY_BUNDLE_DIR,
        overlayBundleInfo.bundleDir,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        BUNDLE_OVERLAY_BUNDLE_STATE,
        overlayBundleInfo.state,
        JsonType::NUMBER,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        BUNDLE_OVERLAY_BUNDLE_PRIORITY,
        overlayBundleInfo.priority,
        JsonType::NUMBER,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("overlayBundleInfo from_json error : %{public}d", parseResult);
    }
}
} // AppExecFwk
} // OHOS
