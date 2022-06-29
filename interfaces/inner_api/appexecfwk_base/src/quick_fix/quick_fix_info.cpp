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

#include "quick_fix_info.h"

#include "app_log_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::QUICK_FIX_INFO_NATIVE_LIBRARY_PATH = "nativeLibraryPath";
const std::QUICK_FIX_INFO_HAP_QUICK_FIX_INFOS = "hapQuickFixInfos";
}

void to_json(nlohmann::json &jsonObject, const QuickFixInfo &quickFixInfo)
{
    jsonObject = nlohmann::json {
        {QUICK_FIX_INFO_NATIVE_LIBRARY_PATH, quickFixInfo.nativeLibraryPath},
        {QUICK_FIX_INFO_HAP_QUICK_FIX_INFOS, quickFixInfo.hapQuickFixInfos}
    };
}

void from_json(const nlohmann::json &jsonObject, QuickFixInfo &quickFixInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        QUICK_FIX_INFO_NATIVE_LIBRARY_PATH,
        quickFixInfo.nativeLibraryPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<HapQuickFixInfo>>(jsonObject,
        jsonObjectEnd,
        QUICK_FIX_INFO_HAP_QUICK_FIX_INFOS,
        quickFixInfo.hapQuickFixInfos,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
}

bool QuickFixInfo::ReadFromParcel(Parcel &parcel)
{
    nativeLibraryPath = Str16ToStr8(parcel.ReadString16());
    int32_t hapQuickFixSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, hapQuickFixSize);
    for (auto i = 0; i < hapQuickFixSize; i++) {
        std::unique_ptr<HapQuickFixInfo> hapQuickFixInfoPtr(parcel.ReadParcelable<HapQuickFixInfo>());
        if (!hapQuickFixInfoPtr) {
            APP_LOGE("ReadParcelable<Metadata> failed");
            return false;
        }
        hapQuickFixInfos.emplace_back(*hapQuickFixInfoPtr);
    }
    return true;
}

bool QuickFixInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(nativeLibraryPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, hapQuickFixInfo.size());
    for (auto &hapQuickFixInfo : hapQuickFixInfos) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &hapQuickFixInfo);
    }
    return true;
}

QuickFixInfo *QuickFixInfo::Unmarshalling(Parcel &parcel)
{
    QuickFixInfo *info = new (std::nothrow) QuickFixInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // AppExecFwk
} // OHOS