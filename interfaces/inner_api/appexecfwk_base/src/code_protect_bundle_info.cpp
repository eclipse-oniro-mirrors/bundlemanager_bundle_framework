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

#include "code_protect_bundle_info.h"

#include "nlohmann/json.hpp"
#include "string_ex.h"

#include "json_util.h"
#include "parcel_macro.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string VERSION_CODE = "versionCode";
const std::string APPLICATION_RESERVED_FLAG = "applicationReservedFlag";
}

bool CodeProtectBundleInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    uid = parcel.ReadInt32();
    appIndex = parcel.ReadInt32();
    versionCode = parcel.ReadUint32();
    applicationReservedFlag = parcel.ReadUint32();
    return true;
}

CodeProtectBundleInfo *CodeProtectBundleInfo::Unmarshalling(Parcel &parcel)
{
    CodeProtectBundleInfo *info = new (std::nothrow) CodeProtectBundleInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool CodeProtectBundleInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, applicationReservedFlag);
    return true;
}

void to_json(nlohmann::json &jsonObject, const CodeProtectBundleInfo &CodeProtectBundleInfo)
{
    jsonObject = nlohmann::json {
        {Constants::BUNDLE_NAME, CodeProtectBundleInfo.bundleName},
        {Constants::UID, CodeProtectBundleInfo.uid},
        {Constants::APP_INDEX, CodeProtectBundleInfo.appIndex},
        {VERSION_CODE, CodeProtectBundleInfo.versionCode},
        {APPLICATION_RESERVED_FLAG, CodeProtectBundleInfo.applicationReservedFlag}
    };
}

void from_json(const nlohmann::json &jsonObject, CodeProtectBundleInfo &CodeProtectBundleInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd, Constants::BUNDLE_NAME,
        CodeProtectBundleInfo.bundleName, false, parseResult);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, Constants::UID,
        CodeProtectBundleInfo.uid, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, Constants::APP_INDEX,
        CodeProtectBundleInfo.appIndex, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, VERSION_CODE,
        CodeProtectBundleInfo.versionCode, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, APPLICATION_RESERVED_FLAG,
        CodeProtectBundleInfo.applicationReservedFlag, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read CodeProtectBundleInfo jsonObject error : %{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
