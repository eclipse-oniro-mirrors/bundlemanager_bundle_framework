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

#include "app_log_wrapper.h"
#include "bundle_permission_mgr.h"

namespace OHOS {
namespace AppExecFwk {
bool BundlePermissionMgr::GetRequestPermissionStates(
    BundleInfo& bundleInfo, uint32_t tokenId, const std::string deviceId)
{
    APP_LOGI("[cz] mock GetRequestPermissionStates");
    return false;
}

int32_t BundlePermissionMgr::RefreshTokenStatus(const uint64_t &tokenIdEx, const int32_t &uid,
    Security::AccessToken::ReservedType type)
{
    return -1;
}
} // namespace AppExecFwk
} // namespace OHOS