/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ipc_group_info.h"

#include "app_log_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* IPC_GROUP_ID = "ipcGroupId";
const char* UID = "uid";
const char* GID = "gid";
}  // namespace

bool IpcGroupInfo::ReadFromParcel(Parcel &parcel)
{
    ipcGroupId = Str16ToStr8(parcel.ReadString16());
    uid = parcel.ReadInt32();
    gid = parcel.ReadInt32();

    return true;
}

bool IpcGroupInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(ipcGroupId));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, gid);

    return true;
}

IpcGroupInfo *IpcGroupInfo::Unmarshalling(Parcel &parcel)
{
    IpcGroupInfo *info = new (std::nothrow) IpcGroupInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

void to_json(nlohmann::json &jsonObject, const IpcGroupInfo &ipcGroupInfo)
{
    jsonObject = nlohmann::json {
        {IPC_GROUP_ID, ipcGroupInfo.ipcGroupId},
        {UID, ipcGroupInfo.uid},
        {GID, ipcGroupInfo.gid}
    };
}

void from_json(const nlohmann::json &jsonObject, IpcGroupInfo &ipcGroupInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        IPC_GROUP_ID,
        ipcGroupInfo.ipcGroupId,
        false,
        parseResult);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        UID,
        ipcGroupInfo.uid,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        GID,
        ipcGroupInfo.gid,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read ipcGroupInfo error : %{public}d", parseResult);
    }
}

std::string IpcGroupInfo::ToString() const
{
    return "[ ipcGroupId = " + ipcGroupId
            + ", uid = " + std::to_string(uid)
            + ", gid = " + std::to_string(gid)
            + "]";
}
}  // namespace AppExecFwk
}  // namespace OHOS
