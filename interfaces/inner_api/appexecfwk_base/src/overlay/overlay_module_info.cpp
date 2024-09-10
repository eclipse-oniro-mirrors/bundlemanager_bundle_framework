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

#include "overlay_module_info.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string MODULE_OVERLAY_BUNDLE_NAME = "bundleName";
const std::string MODULE_OVERLAY_MODULE_NAME = "moduleName";
const std::string MODULE_OVERLAY_HAP_PATH = "hapPath";
const std::string MODULE_OVERLAY_PRIORITY = "priority";
const std::string MODULE_OVERLAY_STATE = "state";
const std::string MODULE_TARGET_MODULE_NAME = "targetModuleName";
} // namespace

bool OverlayModuleInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    targetModuleName = Str16ToStr8(parcel.ReadString16());
    hapPath = Str16ToStr8(parcel.ReadString16());
    priority = parcel.ReadInt32();
    state = parcel.ReadInt32();
    return true;
}

bool OverlayModuleInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(targetModuleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, priority);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, state);
    return true;
}

OverlayModuleInfo *OverlayModuleInfo::Unmarshalling(Parcel &parcel)
{
    OverlayModuleInfo *info = new (std::nothrow) OverlayModuleInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

void to_json(nlohmann::json &jsonObject, const OverlayModuleInfo &overlayModuleInfo)
{
    jsonObject = nlohmann::json {
        {MODULE_OVERLAY_BUNDLE_NAME, overlayModuleInfo.bundleName},
        {MODULE_OVERLAY_MODULE_NAME, overlayModuleInfo.moduleName},
        {MODULE_TARGET_MODULE_NAME, overlayModuleInfo.targetModuleName},
        {MODULE_OVERLAY_HAP_PATH, overlayModuleInfo.hapPath},
        {MODULE_OVERLAY_PRIORITY, overlayModuleInfo.priority},
        {MODULE_OVERLAY_STATE, overlayModuleInfo.state}
    };
}

void from_json(const nlohmann::json &jsonObject, OverlayModuleInfo &overlayModuleInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_OVERLAY_BUNDLE_NAME,
        overlayModuleInfo.bundleName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_OVERLAY_MODULE_NAME,
        overlayModuleInfo.moduleName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_TARGET_MODULE_NAME,
        overlayModuleInfo.targetModuleName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_OVERLAY_HAP_PATH,
        overlayModuleInfo.hapPath,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        MODULE_OVERLAY_PRIORITY,
        overlayModuleInfo.priority,
        JsonType::NUMBER,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        MODULE_OVERLAY_STATE,
        overlayModuleInfo.state,
        JsonType::NUMBER,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("overlayModuleInfo from_json error : %{public}d", parseResult);
    }
}
} // AppExecFwk
} // OHOS
