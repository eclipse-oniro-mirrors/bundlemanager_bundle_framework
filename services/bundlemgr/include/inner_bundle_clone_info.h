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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_BUNDLE_CLONE_INFO_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_BUNDLE_CLONE_INFO_H

#include "bundle_user_info.h"
#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
struct InnerBundleCloneInfo {
    int32_t userId = Constants::INVALID_USERID;

    // Indicates whether the bundle is disabled.
    bool enabled = true;

    // indicates whether the appIndex of clone app
    int32_t appIndex = 0;

    int32_t uid = 0;

    std::vector<int32_t> gids;

    // disabled abilities of the user.
    std::vector<std::string> disabledAbilities;

    uint32_t accessTokenId = 0;

    uint64_t accessTokenIdEx = 0;

    // The time(unix time) will be recalculated
    // if the application is reinstalled after being uninstalled.
    int64_t installTime = 0;

    bool encryptedKeyExisted = false;
};

void from_json(const nlohmann::json& jsonObject, InnerBundleCloneInfo& bundleCloneInfo);
void to_json(nlohmann::json& jsonObject, const InnerBundleCloneInfo& bundleCloneInfo);
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_BUNDLE_CLONE_INFO_H