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

#include "distributed_bundle_info.h"

#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* JSON_KEY_VERSION = "version";
const char* JSON_KEY_VERSION_CODE = "versionCode";
const char* JSON_KEY_COMPATIBLE_VERSION_CODE = "compatibleVersionCode";
const char* JSON_KEY_VERSION_NAME = "versionName";
const char* JSON_KEY_MIN_COMPATIBLE_VERSION = "minCompatibleVersion";
const char* JSON_KEY_TARGET_VERSION_CODE = "targetVersionCode";
const char* JSON_KEY_APP_ID = "appId";
const char* JSON_KEY_MODULE_INFOS = "moduleInfos";
const char* JSON_KEY_ENABLED = "enabled";
const char* JSON_KEY_ACCESS_TOKEN_ID = "accessTokenId";
const char* JSON_KEY_UPDATE_TIME = "updateTime";
}
bool DistributedBundleInfo::ReadFromParcel(Parcel &parcel)
{
    version = parcel.ReadUint32();
    versionCode = parcel.ReadUint32();
    compatibleVersionCode = parcel.ReadUint32();
    minCompatibleVersion = parcel.ReadUint32();
    targetVersionCode = parcel.ReadUint32();
    bundleName = Str16ToStr8(parcel.ReadString16());
    versionName = Str16ToStr8(parcel.ReadString16());
    appId = Str16ToStr8(parcel.ReadString16());

    uint32_t moduleInfosSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, moduleInfosSize);
    CONTAINER_SECURITY_VERIFY(parcel, moduleInfosSize, &moduleInfos);
    for (uint32_t i = 0; i < moduleInfosSize; i++) {
        std::unique_ptr<DistributedModuleInfo> distributedModuleInfo(parcel.ReadParcelable<DistributedModuleInfo>());
        if (!distributedModuleInfo) {
            APP_LOGE("ReadParcelable<DistributedModuleInfo> failed");
            return false;
        }
        moduleInfos.emplace_back(*distributedModuleInfo);
    }
    enabled = parcel.ReadBool();
    accessTokenId = parcel.ReadUint32();
    updateTime = parcel.ReadInt64();
    return true;
}

bool DistributedBundleInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, version);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, compatibleVersionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, minCompatibleVersion);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, targetVersionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(versionName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appId));

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, moduleInfos.size());
    for (auto &moduleInfo : moduleInfos) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &moduleInfo);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, enabled);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, accessTokenId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, updateTime);
    return true;
}

DistributedBundleInfo *DistributedBundleInfo::Unmarshalling(Parcel &parcel)
{
    DistributedBundleInfo *info = new (std::nothrow) DistributedBundleInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

std::string DistributedBundleInfo::ToString() const
{
    nlohmann::json jsonObject;
    jsonObject[JSON_KEY_VERSION] = version;
    jsonObject[Constants::BUNDLE_NAME] = bundleName;
    jsonObject[JSON_KEY_VERSION_CODE] = versionCode;
    jsonObject[JSON_KEY_VERSION_NAME] = versionName;
    jsonObject[JSON_KEY_COMPATIBLE_VERSION_CODE] = compatibleVersionCode;
    jsonObject[JSON_KEY_MIN_COMPATIBLE_VERSION] = minCompatibleVersion;
    jsonObject[JSON_KEY_TARGET_VERSION_CODE] = targetVersionCode;
    jsonObject[JSON_KEY_APP_ID] = appId;
    jsonObject[JSON_KEY_MODULE_INFOS] = moduleInfos;
    jsonObject[JSON_KEY_ENABLED] = enabled;
    jsonObject[JSON_KEY_ACCESS_TOKEN_ID] = accessTokenId;
    jsonObject[JSON_KEY_UPDATE_TIME] = updateTime;
    return jsonObject.dump();
}

bool DistributedBundleInfo::FromJsonString(const std::string &jsonString)
{
    nlohmann::json jsonObject = nlohmann::json::parse(jsonString, nullptr, false);
    if (jsonObject.is_discarded()) {
        APP_LOGE("failed parse DistributedBundleInfo: %{public}s", jsonString.c_str());
        return false;
    }

    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_VERSION,
        version,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        bundleName,
        false,
        parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_VERSION_CODE,
        versionCode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_COMPATIBLE_VERSION_CODE,
        compatibleVersionCode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_VERSION_NAME,
        versionName,
        false,
        parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_MIN_COMPATIBLE_VERSION,
        minCompatibleVersion,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_TARGET_VERSION_CODE,
        targetVersionCode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_APP_ID,
        appId,
        false,
        parseResult);
    GetValueIfFindKey<std::vector<DistributedModuleInfo>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_MODULE_INFOS,
        moduleInfos,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ENABLED,
        enabled,
        false,
        parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ACCESS_TOKEN_ID,
        accessTokenId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int64_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_UPDATE_TIME,
        updateTime,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    return parseResult == ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
