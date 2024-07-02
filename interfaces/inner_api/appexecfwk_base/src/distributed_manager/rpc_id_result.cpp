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

#include "rpc_id_result.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string JSON_KEY_RESULT_VERSION = "version";
const std::string JSON_KEY_RESULT_TRANSACT_ID = "transactId";
const std::string JSON_KEY_RESULT_RETCODE = "retCode";
const std::string JSON_KEY_RESULT_RESULT_MSG = "resultMsg";
const std::string JSON_KEY_SUMMARY_ABILITY_INFO = "abilityInfo";
const std::string JSON_KEY_SUMMARY_ABILITY_INFO_LOGO_URL = "logoUrl";
const std::string JSON_KEY_SUMMARY_ABILITY_INFO_LABEL = "label";
const std::string JSON_KEY_SUMMARY_ABILITY_INFO_DEVICE_TYPE = "deviceType";
const std::string JSON_KEY_SUMMARY_ABILITY_INFO_RPC_ID = "rpcId";
}  //  namespace

void to_json(nlohmann::json &jsonObject, const SummaryAbilityInfo &summaryAbilityInfo)
{
    jsonObject = nlohmann::json {
        {Constants::BUNDLE_NAME, summaryAbilityInfo.bundleName},
        {Constants::MODULE_NAME, summaryAbilityInfo.moduleName},
        {Constants::ABILITY_NAME, summaryAbilityInfo.abilityName},
        {JSON_KEY_SUMMARY_ABILITY_INFO_LOGO_URL, summaryAbilityInfo.logoUrl},
        {JSON_KEY_SUMMARY_ABILITY_INFO_LABEL, summaryAbilityInfo.label},
        {JSON_KEY_SUMMARY_ABILITY_INFO_DEVICE_TYPE, summaryAbilityInfo.deviceType},
        {JSON_KEY_SUMMARY_ABILITY_INFO_RPC_ID, summaryAbilityInfo.rpcId},
    };
}

void from_json(const nlohmann::json &jsonObject, SummaryAbilityInfo &summaryAbilityInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        summaryAbilityInfo.bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        summaryAbilityInfo.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::ABILITY_NAME,
        summaryAbilityInfo.abilityName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SUMMARY_ABILITY_INFO_LOGO_URL,
        summaryAbilityInfo.logoUrl,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SUMMARY_ABILITY_INFO_LABEL,
        summaryAbilityInfo.label,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SUMMARY_ABILITY_INFO_DEVICE_TYPE,
        summaryAbilityInfo.deviceType,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SUMMARY_ABILITY_INFO_RPC_ID,
        summaryAbilityInfo.rpcId,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    if (parseResult != ERR_OK) {
        APP_LOGE("read result jsonObject error : %{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const RpcIdResult &rpcIdResult)
{
    jsonObject = nlohmann::json {
        {JSON_KEY_RESULT_VERSION, rpcIdResult.version},
        {JSON_KEY_RESULT_TRANSACT_ID, rpcIdResult.transactId},
        {JSON_KEY_RESULT_RETCODE, rpcIdResult.retCode},
        {JSON_KEY_RESULT_RESULT_MSG, rpcIdResult.resultMsg},
        {JSON_KEY_SUMMARY_ABILITY_INFO, rpcIdResult.abilityInfo},
    };
}

void from_json(const nlohmann::json &jsonObject, RpcIdResult &rpcIdResult)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_RESULT_VERSION,
        rpcIdResult.version,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_RESULT_TRANSACT_ID,
        rpcIdResult.transactId,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_RESULT_RETCODE,
        rpcIdResult.retCode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_RESULT_RESULT_MSG,
        rpcIdResult.resultMsg,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<SummaryAbilityInfo>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_SUMMARY_ABILITY_INFO,
        rpcIdResult.abilityInfo,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read result jsonObject error : %{public}d", parseResult);
    }
}

bool SummaryAbilityInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    abilityName = Str16ToStr8(parcel.ReadString16());
    logoUrl = Str16ToStr8(parcel.ReadString16());
    label = Str16ToStr8(parcel.ReadString16());
    int32_t deviceTypeSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, deviceTypeSize);
    CONTAINER_SECURITY_VERIFY(parcel, deviceTypeSize, &deviceType);
    for (auto i = 0; i < deviceTypeSize; i++) {
        deviceType.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    int32_t rpcIdSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, rpcIdSize);
    CONTAINER_SECURITY_VERIFY(parcel, rpcIdSize, &rpcId);
    for (auto i = 0; i < rpcIdSize; i++) {
        rpcId.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }
    return true;
}

bool SummaryAbilityInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(abilityName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(logoUrl));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(label));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, deviceType.size());
    for (auto &type : deviceType) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(type));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, rpcId.size());
    for (auto &id : rpcId) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(id));
    }
    return true;
}

SummaryAbilityInfo *SummaryAbilityInfo::Unmarshalling(Parcel &parcel)
{
    SummaryAbilityInfo *result = new (std::nothrow) SummaryAbilityInfo();
    if (result && !result->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete result;
        result = nullptr;
    }
    return result;
}

bool RpcIdResult::ReadFromParcel(Parcel &parcel)
{
    version = Str16ToStr8(parcel.ReadString16());
    transactId = Str16ToStr8(parcel.ReadString16());
    retCode = parcel.ReadInt32();
    resultMsg = Str16ToStr8(parcel.ReadString16());
    std::unique_ptr<SummaryAbilityInfo> summaryAbilityInfo(parcel.ReadParcelable<SummaryAbilityInfo>());
    if (!summaryAbilityInfo) {
        APP_LOGE("ReadParcelable<SummaryAbilityInfo> failed");
        return false;
    }
    abilityInfo = *summaryAbilityInfo;
    return true;
}

bool RpcIdResult::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(version));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(transactId));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, retCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &abilityInfo);
    return true;
}

RpcIdResult *RpcIdResult::Unmarshalling(Parcel &parcel)
{
    RpcIdResult *result = new (std::nothrow) RpcIdResult();
    if (result && !result->ReadFromParcel(parcel)) {
        APP_LOGE("read from parcel failed");
        delete result;
        result = nullptr;
    }
    return result;
}
}
}