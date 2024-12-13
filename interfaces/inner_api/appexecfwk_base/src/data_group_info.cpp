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

#include "data_group_info.h"

#include "app_log_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* DATA_GROUP_ID = "dataGroupId";
const char* UUID = "uuid";
const char* UID = "uid";
const char* GID = "gid";
const char* USER_ID = "userId";
}  // namespace

bool DataGroupInfo::ReadFromParcel(Parcel &parcel)
{
    dataGroupId = Str16ToStr8(parcel.ReadString16());
    uuid = Str16ToStr8(parcel.ReadString16());
    uid = parcel.ReadInt32();
    gid = parcel.ReadInt32();
    userId = parcel.ReadInt32();

    return true;
}

bool DataGroupInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(dataGroupId));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(uuid));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, gid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, userId);

    return true;
}

DataGroupInfo *DataGroupInfo::Unmarshalling(Parcel &parcel)
{
    DataGroupInfo *info = new (std::nothrow) DataGroupInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

void to_json(nlohmann::json &jsonObject, const DataGroupInfo &dataGroupInfo)
{
    jsonObject = nlohmann::json {
        {DATA_GROUP_ID, dataGroupInfo.dataGroupId},
        {UUID, dataGroupInfo.uuid},
        {UID, dataGroupInfo.uid},
        {GID, dataGroupInfo.gid},
        {USER_ID, dataGroupInfo.userId}
    };
}

void from_json(const nlohmann::json &jsonObject, DataGroupInfo &dataGroupInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        DATA_GROUP_ID,
        dataGroupInfo.dataGroupId,
        false,
        parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        UUID,
        dataGroupInfo.uuid,
        false,
        parseResult);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        UID,
        dataGroupInfo.uid,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        GID,
        dataGroupInfo.gid,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        USER_ID,
        dataGroupInfo.userId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read dataGroupInfo error : %{public}d", parseResult);
    }
}

std::string DataGroupInfo::ToString() const
{
    return "[ dataGroupId = " + dataGroupId
            + ", uuid = " + uuid
            + ", uid = " + std::to_string(uid)
            + ", gid = " + std::to_string(gid)
            + ", userId = " + std::to_string(userId)
            + "]";
}
}  // namespace AppExecFwk
}  // namespace OHOS
