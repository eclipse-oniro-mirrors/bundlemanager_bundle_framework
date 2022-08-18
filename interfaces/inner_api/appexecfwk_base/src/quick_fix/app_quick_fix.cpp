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

#include "app_quick_fix.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string APP_QUICK_FIX_VERSION_CODE = "versionCode";
const std::string APP_QUICK_FIX_VERSION_NAME = "versionName";
const std::string APP_QUICK_FIX_DEPLOYED_APP_QF_INFO = "deployedAppqfInfo";
const std::string APP_QUICK_FIX_DEPLOYING_APP_QF_INFO = "deployingAppqfInfo";
}

void to_json(nlohmann::json &jsonObject, const AppQuickFix &appQuickFix)
{
    jsonObject = nlohmann::json {
        {Constants::BUNDLE_NAME, appQuickFix.bundleName},
        {APP_QUICK_FIX_VERSION_CODE, appQuickFix.versionCode},
        {APP_QUICK_FIX_VERSION_NAME, appQuickFix.versionName},
        {APP_QUICK_FIX_DEPLOYED_APP_QF_INFO, appQuickFix.deployedAppqfInfo},
        {APP_QUICK_FIX_DEPLOYING_APP_QF_INFO, appQuickFix.deployingAppqfInfo}
    };
}

void from_json(const nlohmann::json &jsonObject, AppQuickFix &appQuickFix)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd,
        Constants::BUNDLE_NAME, appQuickFix.bundleName,
        JsonType::STRING, false, parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd,
        APP_QUICK_FIX_VERSION_CODE, appQuickFix.versionCode,
        JsonType::NUMBER, false, parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd,
        APP_QUICK_FIX_VERSION_NAME, appQuickFix.versionName,
        JsonType::STRING, false, parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<AppqfInfo>(jsonObject, jsonObjectEnd,
        APP_QUICK_FIX_DEPLOYED_APP_QF_INFO, appQuickFix.deployedAppqfInfo,
        JsonType::OBJECT, false, parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<AppqfInfo>(jsonObject, jsonObjectEnd,
        APP_QUICK_FIX_DEPLOYING_APP_QF_INFO, appQuickFix.deployingAppqfInfo,
        JsonType::OBJECT, false, parseResult,
        ArrayType::NOT_ARRAY);
}

bool AppQuickFix::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    versionCode = parcel.ReadUint32();
    versionName = Str16ToStr8(parcel.ReadString16());
    std::unique_ptr<AppqfInfo> deployedAppqfInfoPtr(parcel.ReadParcelable<AppqfInfo>());
    if (!deployedAppqfInfoPtr) {
        APP_LOGE("ReadParcelable<AppqfInfo> failed");
        return false;
    }
    deployedAppqfInfo = *deployedAppqfInfoPtr;

    std::unique_ptr<AppqfInfo> deployingAppqfInfoPtr(parcel.ReadParcelable<AppqfInfo>());
    if (!deployingAppqfInfoPtr) {
        APP_LOGE("ReadParcelable<AppqfInfo> failed");
        return false;
    }
    deployingAppqfInfo = *deployingAppqfInfoPtr;
    return true;
}

bool AppQuickFix::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(versionName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &deployedAppqfInfo);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &deployingAppqfInfo);
    return true;
}

AppQuickFix *AppQuickFix::Unmarshalling(Parcel &parcel)
{
    AppQuickFix *info = new (std::nothrow) AppQuickFix();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // AppExecFwk
} // OHOS