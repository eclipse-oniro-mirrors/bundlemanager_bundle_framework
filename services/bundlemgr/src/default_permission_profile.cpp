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

#include "default_permission_profile.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
int32_t g_permJson = ERR_OK;
std::mutex g_mutex;
static constexpr const char* PERMISSIONS_PROFILE_KEY_BUNDLENAME = "bundleName";
static constexpr const char* PERMISSIONS_PROFILE_KEY_PERMISSIONS = "permissions";
static constexpr const char* PERMISSIONS_PROFILE_KEY_NAME = "name";
static constexpr const char* PERMISSIONS_PROFILE_KEY_USER_CANCELLABLE = "userCancellable";
static constexpr const char* PERMISSIONS_PROFILE_KEY_APP_SIGNATURE = "app_signature";
}

void from_json(const nlohmann::json &jsonObject, PermissionInfo &permissionInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        PERMISSIONS_PROFILE_KEY_NAME,
        permissionInfo.name,
        JsonType::STRING,
        true,
        g_permJson,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        PERMISSIONS_PROFILE_KEY_USER_CANCELLABLE,
        permissionInfo.userCancellable,
        JsonType::BOOLEAN,
        true,
        g_permJson,
        ArrayType::NOT_ARRAY);
}

ErrCode DefaultPermissionProfile::TransformTo(const nlohmann::json &jsonObject,
    std::set<DefaultPermission> &defaultPermissions) const
{
    ErrCode result = ERR_OK;
    if (jsonObject.is_array() && !jsonObject.is_discarded()) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_permJson = ERR_OK;
        for (const auto &object : jsonObject) {
            if (!object.is_object()) {
                return ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
            }
            DefaultPermission defaultPermission;
            const auto &objectEnd = object.end();
            GetValueIfFindKey<std::string>(object, objectEnd,
                PERMISSIONS_PROFILE_KEY_BUNDLENAME,
                defaultPermission.bundleName,
                JsonType::STRING,
                true, g_permJson, ArrayType::NOT_ARRAY);

            GetValueIfFindKey<std::vector<std::string>>(object, objectEnd,
                PERMISSIONS_PROFILE_KEY_APP_SIGNATURE,
                defaultPermission.appSignature,
                JsonType::ARRAY,
                false, g_permJson, ArrayType::STRING);

            GetValueIfFindKey<std::vector<PermissionInfo>>(object, objectEnd,
                PERMISSIONS_PROFILE_KEY_PERMISSIONS,
                defaultPermission.grantPermission,
                JsonType::ARRAY,
                false, g_permJson, ArrayType::OBJECT);

            if (g_permJson != ERR_OK) {
                APP_LOGE("parse install_list_permissions.json failed, g_permJson is %{public}d, bundleName:%{public}s",
                    g_permJson, defaultPermission.bundleName.c_str());
                result = g_permJson;
                // need recover parse result to ERR_OK
                g_permJson = ERR_OK;
                continue;
            }

            auto iter = defaultPermissions.find(defaultPermission);
            if (iter != defaultPermissions.end()) {
                APP_LOGD("Replace old defaultPermission(%{public}s)", defaultPermission.bundleName.c_str());
                defaultPermissions.erase(iter);
            }

            defaultPermissions.insert(defaultPermission);
        }
    }
    return result;
}
}  // namespace AppExecFwk
}  // namespace OHOS

