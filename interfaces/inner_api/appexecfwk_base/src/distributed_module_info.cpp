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

#include "distributed_module_info.h"

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
const char* JSON_KEY_ABILITIES = "abilities";
}
bool DistributedModuleInfo::ReadFromParcel(Parcel &parcel)
{
    moduleName = Str16ToStr8(parcel.ReadString16());

    int32_t abilityInfosSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, abilityInfosSize);
    CONTAINER_SECURITY_VERIFY(parcel, abilityInfosSize, &abilities);
    for (auto i = 0; i < abilityInfosSize; i++) {
        std::unique_ptr<DistributedAbilityInfo> abilityInfo(parcel.ReadParcelable<DistributedAbilityInfo>());
        if (!abilityInfo) {
            APP_LOGE("ReadParcelable<AbilityInfo> failed");
            return false;
        }
        abilities.emplace_back(*abilityInfo);
    }
    return true;
}

bool DistributedModuleInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, abilities.size());
    for (auto &ability : abilities) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &ability);
    }
    return true;
}

DistributedModuleInfo *DistributedModuleInfo::Unmarshalling(Parcel &parcel)
{
    DistributedModuleInfo *info = new (std::nothrow) DistributedModuleInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

void DistributedModuleInfo::Dump(const std::string &prefix, int fd)
{
    APP_LOGI("called dump DistributedModuleInfo");
    if (fd < 0) {
        APP_LOGE("dump DistributedModuleInfo fd error");
        return;
    }
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        APP_LOGE("fcntl error %{public}d", errno);
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
            APP_LOGE("write error %{public}d", errno);
        }
    }
}

void to_json(nlohmann::json& jsonObject, const DistributedModuleInfo& distributedModuleInfo)
{
    jsonObject = nlohmann::json {
        {Constants::MODULE_NAME, distributedModuleInfo.moduleName},
        {JSON_KEY_ABILITIES, distributedModuleInfo.abilities},
    };
}

void from_json(const nlohmann::json& jsonObject, DistributedModuleInfo& distributedModuleInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        distributedModuleInfo.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<DistributedAbilityInfo>>(jsonObject,
        jsonObjectEnd,
        JSON_KEY_ABILITIES,
        distributedModuleInfo.abilities,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    if (parseResult != ERR_OK) {
        APP_LOGE("read distributedModuleInfo jsonObject error : %{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
