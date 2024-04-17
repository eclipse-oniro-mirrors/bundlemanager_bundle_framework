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

#include "recoverable_application_info.h"

#include "app_log_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string JSON_KEY_BUNDLE_NAME = "bundleName";
const std::string JSON_KEY_MODULE_NAME = "moduleName";
const std::string JSON_KEY_LABEL_ID = "labelId";
const std::string JSON_KEY_ICON_ID = "iconId";
const std::string JSON_KEY_SYSTEM_APP = "systemApp";
const std::string JSON_KEY_BUNDLE_TYPE = "bundleType";
const std::string JSON_KEY_CODE_PATHS = "codePaths";
}

bool RecoverableApplicationInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    labelId = parcel.ReadInt32();
    iconId = parcel.ReadInt32();
    systemApp = parcel.ReadBool();
    bundleType = static_cast<BundleType>(parcel.ReadInt32());
    int32_t codePathsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, codePathsSize);
    CONTAINER_SECURITY_VERIFY(parcel, codePathsSize, &codePaths);
    for (auto i = 0; i < codePathsSize; i++) {
        codePaths.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }
    return true;
}

bool RecoverableApplicationInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, labelId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, iconId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, systemApp);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(bundleType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, codePaths.size());
    for (auto &codePath : codePaths) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(codePath));
    }
    return true;
}

RecoverableApplicationInfo *RecoverableApplicationInfo::Unmarshalling(Parcel &parcel)
{
    RecoverableApplicationInfo *info = new (std::nothrow) RecoverableApplicationInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

void to_json(nlohmann::json &jsonObject, const RecoverableApplicationInfo &recoverableApplicationInfo)
{
    jsonObject = nlohmann::json {
        {JSON_KEY_BUNDLE_NAME, recoverableApplicationInfo.bundleName},
        {JSON_KEY_MODULE_NAME, recoverableApplicationInfo.moduleName},
        {JSON_KEY_LABEL_ID, recoverableApplicationInfo.labelId},
        {JSON_KEY_ICON_ID, recoverableApplicationInfo.iconId},
        {JSON_KEY_SYSTEM_APP, recoverableApplicationInfo.systemApp},
        {JSON_KEY_BUNDLE_TYPE, recoverableApplicationInfo.bundleType},
        {JSON_KEY_CODE_PATHS, recoverableApplicationInfo.codePaths},
    };
}

void from_json(const nlohmann::json &jsonObject, RecoverableApplicationInfo &recoverableApplicationInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, JSON_KEY_BUNDLE_NAME,
        recoverableApplicationInfo.bundleName, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, JSON_KEY_MODULE_NAME,
        recoverableApplicationInfo.moduleName, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, JSON_KEY_LABEL_ID,
        recoverableApplicationInfo.labelId, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, JSON_KEY_ICON_ID,
        recoverableApplicationInfo.iconId, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, JSON_KEY_SYSTEM_APP,
        recoverableApplicationInfo.systemApp, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<BundleType>(jsonObject, jsonObjectEnd, JSON_KEY_BUNDLE_TYPE,
        recoverableApplicationInfo.bundleType, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject, jsonObjectEnd, JSON_KEY_CODE_PATHS,
        recoverableApplicationInfo.codePaths, JsonType::ARRAY, false, parseResult, ArrayType::STRING);
    if (parseResult != ERR_OK) {
        APP_LOGE("read RecoverableApplicationInfo error, error code : %{public}d", parseResult);
    }
}
} // AppExecFwk
} // OHOS