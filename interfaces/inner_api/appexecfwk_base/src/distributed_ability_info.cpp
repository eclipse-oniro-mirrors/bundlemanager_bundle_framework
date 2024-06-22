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

#include "distributed_ability_info.h"

#include <fcntl.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string JSON_KEY_PERMISSIONS = "permissions";
const std::string JSON_KEY_TYPE = "type";
const std::string JSON_KEY_ENABLED = "enabled";
}
bool DistributedAbilityInfo::ReadFromParcel(Parcel &parcel)
{
    abilityName = Str16ToStr8(parcel.ReadString16());

    int32_t permissionsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, permissionsSize);
    CONTAINER_SECURITY_VERIFY(parcel, permissionsSize, &permissions);
    for (auto i = 0; i < permissionsSize; i++) {
        permissions.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    type = static_cast<AbilityType>(parcel.ReadInt32());
    enabled = parcel.ReadBool();

    return true;
}

bool DistributedAbilityInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(abilityName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, permissions.size());
    for (auto &permission : permissions) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(permission));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(type));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, enabled);
    return true;
}

DistributedAbilityInfo *DistributedAbilityInfo::Unmarshalling(Parcel &parcel)
{
    DistributedAbilityInfo *info = new (std::nothrow) DistributedAbilityInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

void DistributedAbilityInfo::Dump(const std::string &prefix, int fd)
{
    APP_LOGI("called dump DistributedAbilityInfo");
    if (fd < 0) {
        APP_LOGE("dump DistributedAbilityInfo fd error");
        return;
    }
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        APP_LOGE("dump DistributedAbilityInfo fcntl error %{public}d", errno);
        return;
    }
    uint uflags = static_cast<uint>(flags);
    uflags &= O_ACCMODE;
    if ((uflags == O_WRONLY) || (uflags == O_RDWR)) {
        nlohmann::json jsonObject = *this;
        std::string result;
        result.append(prefix);
        result.append(jsonObject.dump(Constants::DUMP_INDENT));
        int ret = TEMP_FAILURE_RETRY(write(fd, result.c_str(), result.size()));
        if (ret < 0) {
            APP_LOGE("dump DistributedAbilityInfo write error %{public}d", errno);
        }
    }
}

void to_json(nlohmann::json& jsonObject, const DistributedAbilityInfo& distributedAbilityInfo)
{
    jsonObject = nlohmann::json {
        {Constants::ABILITY_NAME, distributedAbilityInfo.abilityName},
        {JSON_KEY_PERMISSIONS, distributedAbilityInfo.permissions},
        {JSON_KEY_TYPE, distributedAbilityInfo.type},
        {JSON_KEY_ENABLED, distributedAbilityInfo.enabled},
    };
}

void from_json(const nlohmann::json& jsonObject, DistributedAbilityInfo& distributedAbilityInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::ABILITY_NAME,
        distributedAbilityInfo.abilityName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_PERMISSIONS,
        distributedAbilityInfo.permissions,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<AbilityType>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_TYPE,
        distributedAbilityInfo.type,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ENABLED,
        distributedAbilityInfo.enabled,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read distributedAbilityInfo jsonObject error : %{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
