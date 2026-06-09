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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_CLI_SANDBOX_INFO_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_CLI_SANDBOX_INFO_H

#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {

enum class SandboxIsolationType : int32_t {
    PartialIsolation = 0,
    FullIsolation = 1,
};

struct InnerCliSandboxInfo {
    int32_t userId = Constants::INVALID_USERID;
    int32_t appIndex = 0;
    int32_t uid = 0;
    uint32_t accessTokenId = 0;
    uint64_t accessTokenIdEx = 0;
    int64_t installTime = 0;
    SandboxIsolationType sandboxType = SandboxIsolationType::FullIsolation;
    std::vector<int32_t> gids;
    std::vector<std::string> creatorBundleNames;
};

void from_json(const nlohmann::json& jsonObject, InnerCliSandboxInfo& info);
void to_json(nlohmann::json& jsonObject, const InnerCliSandboxInfo& info);

} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_CLI_SANDBOX_INFO_H
