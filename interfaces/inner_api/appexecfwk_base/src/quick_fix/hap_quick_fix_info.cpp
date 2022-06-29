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

#include "hap_quick_fix_info.h"

#include "app_log_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::HAP_QUICK_FIX_INFO_MODULE_NAME = "moduleName";
const std::HAP_QUICK_FIX_INFO_HAP_HASH256 = "hapHash256";
const std::HAP_QUICK_FIX_INFO_HAP_FILE_PATH = "hapFilePath";
}

void to_json(nlohmann::json &jsonObject, const HapQuickFixInfo &hapQuickFixInfo)
{
    jsonObject = nlohmann::json {
        {HAP_QUICK_FIX_INFO_MODULE_NAME, hapQuickFixInfo.moduleName},
        {HAP_QUICK_FIX_INFO_HAP_HASH256, hapQuickFixInfo.hapHash256},
        {HAP_QUICK_FIX_INFO_HAP_FILE_PATH, hapQuickFixInfo.hapFilePath}
    };
}

void from_json(const nlohmann::json &jsonObject, HapQuickFixInfo &hapQuickFixInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_QUICK_FIX_INFO_MODULE_NAME,
        hapQuickFixInfo.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_QUICK_FIX_INFO_HAP_HASH256,
        hapQuickFixInfo.hapHash256,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_QUICK_FIX_INFO_HAP_FILE_PATH,
        hapQuickFixInfo.hapFilePath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
}

bool HapQuickFixInfo::ReadFromParcel(Parcel &parcel)
{
    moduleName = Str16ToStr8(parcel.ReadString16());
    hapHash256 = Str16ToStr8(parcel.ReadString16());
    hapFilePath = Str16ToStr8(parcel.ReadString16());
    return true;
}

bool HapQuickFixInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapHash256));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapFilePath));
    return true;
}

HapQuickFixInfo *HapQuickFixInfo::Unmarshalling(Parcel &parcel)
{
    HapQuickFixInfo *info = new (std::nothrow) HapQuickFixInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // AppExecFwk
} // OHOS