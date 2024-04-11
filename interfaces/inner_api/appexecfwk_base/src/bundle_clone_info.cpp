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

#include "bundle_clone_info.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string BUNDLE_CLONE_INFO_USER_ID = "userId";
const std::string BUNDLE_CLONE_INFO_APP_INDEX = "appIndex";
const std::string BUNDLE_CLONE_INFO_UID = "uid";
const std::string BUNDLE_CLONE_INFO_ENABLE = "enabled";
const std::string BUNDLE_CLONE_INFO_DISABLE_ABILITIES = "disabledAbilities";
const std::string BUNDLE_CLONE_INFO_OVERLAY_STATE = "overlayState";

const std::string BUNDLE_CLONE_INFO_ACCESS_TOKEN_ID = "accessTokenId";
const std::string BUNDLE_CLONE_INFO_ACCESS_TOKEN_ID_EX = "accessTokenIdEx";
const std::string BUNDLE_CLONE_INFO_INSTALL_TIME = "installTime";
const std::string BUNDLE_CLONE_INFO_UPDATE_TIME = "updateTime";
const std::string BUNDLE_CLONE_INFO_IS_REMOVABLE = "isRemovable";
} // namespace

bool BundleCloneInfo::ReadFromParcel(Parcel &parcel)
{
    userId = parcel.ReadInt32();
    appIndex = parcel.ReadInt32();
    uid = parcel.ReadInt32();
    enabled = parcel.ReadBool();
    int32_t disabledAbilitiesSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, disabledAbilitiesSize);
    CONTAINER_SECURITY_VERIFY(parcel, disabledAbilitiesSize, &disabledAbilities);
    for (int32_t i = 0; i < disabledAbilitiesSize; i++) {
        disabledAbilities.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }
 
    int32_t overlayStateSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, overlayStateSize);
    CONTAINER_SECURITY_VERIFY(parcel, overlayStateSize, &overlayModulesState);
    for (int32_t i = 0; i < overlayStateSize; i++) {
        overlayModulesState.emplace_back(Str16ToStr8(parcel.ReadString16()));
    }

    accessTokenId = parcel.ReadUint32();
    accessTokenIdEx = parcel.ReadUint64();
    installTime = parcel.ReadInt64();
    updateTime = parcel.ReadInt64();
    isRemovable = parcel.ReadBool();
    return true;
}

BundleCloneInfo *BundleCloneInfo::Unmarshalling(Parcel &parcel)
{
    BundleCloneInfo *info = new (std::nothrow) BundleCloneInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }

    return info;
}

bool BundleCloneInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, userId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, enabled);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, disabledAbilities.size());
    for (auto &disabledAbility : disabledAbilities) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(disabledAbility));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, overlayModulesState.size());
    for (const auto &overlayModuleState : overlayModulesState) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(overlayModuleState));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, accessTokenId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint64, parcel, accessTokenIdEx);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, installTime);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, updateTime);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isRemovable);
    return true;
}

bool BundleCloneInfo::IsInitialState() const
{
    return enabled && disabledAbilities.empty();
}

void BundleCloneInfo::Reset()
{
    enabled = true;
    disabledAbilities.clear();
}

void to_json(nlohmann::json& jsonObject, const BundleCloneInfo& bundleCloneInfo)
{
    jsonObject = nlohmann::json {
        {BUNDLE_CLONE_INFO_USER_ID, bundleCloneInfo.userId},
        {BUNDLE_CLONE_INFO_APP_INDEX, bundleCloneInfo.appIndex},
        {BUNDLE_CLONE_INFO_UID, bundleCloneInfo.uid},
        {BUNDLE_CLONE_INFO_ENABLE, bundleCloneInfo.enabled},
        {BUNDLE_CLONE_INFO_DISABLE_ABILITIES, bundleCloneInfo.disabledAbilities},
        {BUNDLE_CLONE_INFO_OVERLAY_STATE, bundleCloneInfo.overlayModulesState},

        {BUNDLE_CLONE_INFO_ACCESS_TOKEN_ID, bundleCloneInfo.accessTokenId},
        {BUNDLE_CLONE_INFO_ACCESS_TOKEN_ID_EX, bundleCloneInfo.accessTokenIdEx},
        {BUNDLE_CLONE_INFO_INSTALL_TIME, bundleCloneInfo.installTime},
        {BUNDLE_CLONE_INFO_UPDATE_TIME, bundleCloneInfo.updateTime},
        {BUNDLE_CLONE_INFO_IS_REMOVABLE, bundleCloneInfo.isRemovable},
    };
}

void from_json(const nlohmann::json& jsonObject, BundleCloneInfo& bundleCloneInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_USER_ID,
        bundleCloneInfo.userId, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_APP_INDEX,
        bundleCloneInfo.appIndex, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_UID,
        bundleCloneInfo.uid, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_ENABLE,
        bundleCloneInfo.enabled, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_DISABLE_ABILITIES,
        bundleCloneInfo.disabledAbilities, JsonType::ARRAY, false, parseResult, ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_OVERLAY_STATE,
        bundleCloneInfo.overlayModulesState, JsonType::ARRAY, false, parseResult, ArrayType::STRING);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_ACCESS_TOKEN_ID,
        bundleCloneInfo.accessTokenId, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_ACCESS_TOKEN_ID_EX,
        bundleCloneInfo.accessTokenIdEx, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_INSTALL_TIME,
        bundleCloneInfo.installTime, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_UPDATE_TIME,
        bundleCloneInfo.updateTime, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, BUNDLE_CLONE_INFO_IS_REMOVABLE,
        bundleCloneInfo.isRemovable, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read module bundleCloneInfo from jsonObject error, error code : %{public}d", parseResult);
    }
}
} // namespace AppExecFwk
} // namespace OHOS