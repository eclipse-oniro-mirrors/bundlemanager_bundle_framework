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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_UNINSTALL_DATA_BUNDLE_INFO_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_UNINSTALL_DATA_BUNDLE_INFO_H

#include "application_info.h"
#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
struct UninstallDataUserInfo {
    int32_t uid = 0;
    std::vector<int32_t> gids;
    uint32_t accessTokenId = 0;
    uint64_t accessTokenIdEx = 0;
};
struct UninstallBundleInfo {
    std::string appId;
    std::string appIdentifier;
    std::string appProvisionType;
    BundleType bundleType = BundleType::APP;
    std::vector<std::string> extensionDirs;
    std::map<std::string, UninstallDataUserInfo> userInfos;

    std::string ToString() const;
    void Init();
};

void from_json(const nlohmann::json& jsonObject, UninstallBundleInfo& uninstallBundleInfo);
void to_json(nlohmann::json& jsonObject, const UninstallBundleInfo& uninstallBundleInfo);
void from_json(const nlohmann::json& jsonObject, UninstallDataUserInfo& uninstallDataUserInfo);
void to_json(nlohmann::json& jsonObject, const UninstallDataUserInfo& uninstallDataUserInfo);
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_UNINSTALL_DATA_BUNDLE_INFO_H