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

#include "app_quick_fix_info.h"

#include "app_log_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string APP_QUICK_FIX_INFO_BUNDLE_NAME = "bundleName";
const std::string APP_QUICK_FIX_INFO_VERSION_CODE = "versionCode";
const std::string APP_QUICK_FIX_INFO_VERSION_NAME = "versionName";
const std::string APP_QUICK_FIX_INFO_PATCH_VERSION_CODE = "patchVersionCode";
const std::string APP_QUICK_FIX_INFO_PATCH_VERSION_NAME = "patchVersionName";
const std::string APP_QUICK_FIX_INFO_DEPLOYED_QUICK_FIX = "deployedQuickFix";
const std::string APP_QUICK_FIX_INFO_DEPLOYING_QUICK_FIX = "deployingQuickFix";
}

void to_json(nlohmann::json &jsonObject, const AppQuickFixInfo &appQuickFixInfo)
{
    jsonObject = nlohmann::json {
        {APP_QUICK_FIX_INFO_BUNDLE_NAME, appQuickFixInfo.bundleName},
        {APP_QUICK_FIX_INFO_VERSION_CODE, appQuickFixInfo.versionCode},
        {APP_QUICK_FIX_INFO_VERSION_NAME, appQuickFixInfo.versionName},
        {APP_QUICK_FIX_INFO_PATCH_VERSION_CODE, appQuickFixInfo.patchVersionCode},
        {APP_QUICK_FIX_INFO_PATCH_VERSION_NAME, appQuickFixInfo.patchVersionName},
        {APP_QUICK_FIX_INFO_DEPLOYED_QUICK_FIX, appQuickFixInfo.deployedQuickFix},
        {APP_QUICK_FIX_INFO_DEPLOYING_QUICK_FIX, appQuickFixInfo.deployingQuickFix}
    };
}

void from_json(const nlohmann::json &jsonObject, AppQuickFixInfo &appQuickFixInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd,
        APP_QUICK_FIX_INFO_BUNDLE_NAME, appQuickFixInfo.bundleName,
        JsonType::STRING, false, parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd,
        APP_QUICK_FIX_INFO_VERSION_CODE, appQuickFixInfo.versionCode,
        JsonType::NUMBER, false, parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd,
        APP_QUICK_FIX_INFO_VERSION_NAME, appQuickFixInfo.versionName,
        JsonType::STRING, false, parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd,
        APP_QUICK_FIX_INFO_PATCH_VERSION_CODE, appQuickFixInfo.patchVersionCode,
        JsonType::NUMBER, false, parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd,
        APP_QUICK_FIX_INFO_PATCH_VERSION_NAME, appQuickFixInfo.patchVersionName,
        JsonType::STRING, false, parseResult,
        ArrayType::NOT_ARRAY);
    
    GetValueIfFindKey<QuickFixInfo>(jsonObject, jsonObjectEnd,
        APP_QUICK_FIX_INFO_DEPLOYED_QUICK_FIX, appQuickFixInfo.deployedQuickFix,
        JsonType::OBJECT, false, parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<QuickFixInfo>(jsonObject, jsonObjectEnd,
        APP_QUICK_FIX_INFO_DEPLOYING_QUICK_FIX, appQuickFixInfo.deployingQuickFix,
        JsonType::OBJECT, false, parseResult,
        ArrayType::NOT_ARRAY);
}

bool AppQuickFixInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    versionCode = parcel.ReadInt32();
    versionName = Str16ToStr8(parcel.ReadString16());
    patchVersionCode = parcel.ReadInt32();
    patchVersionName = Str16ToStr8(parcel.ReadString16());
    std::unique_ptr<QuickFixInfo> deployedQuickFixInfo(parcel.ReadParcelable<QuickFixInfo>());
    if (!deployedQuickFixInfo) {
        APP_LOGE("ReadParcelable<QuickFixInfo> failed");
        return false;
    }
    deployedQuickFix = *deployedQuickFixInfo;

    std::unique_ptr<QuickFixInfo> deployingQuickFixInfo(parcel.ReadParcelable<QuickFixInfo>());
    if (!deployingQuickFixInfo) {
        APP_LOGE("ReadParcelable<QuickFixInfo> failed");
        return false;
    }
    deployingQuickFix = *deployingQuickFixInfo;
    return true;
}

bool AppQuickFixInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, versionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(versionName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, patchVersionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(patchVersionName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &deployedQuickFix);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &deployingQuickFix);
    return true;
}

AppQuickFixInfo *AppQuickFixInfo::Unmarshalling(Parcel &parcel)
{
    AppQuickFixInfo *info = new (std::nothrow) AppQuickFixInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // AppExecFwk
} // OHOS