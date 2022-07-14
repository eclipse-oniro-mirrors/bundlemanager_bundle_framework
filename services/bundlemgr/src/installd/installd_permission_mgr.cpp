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

#include "installd/installd_permission_mgr.h"

#include "accesstoken_kit.h"
#include "app_log_wrapper.h"
#include "ipc_skeleton.h"

using namespace OHOS::Security;
namespace OHOS {
namespace AppExecFwk {
bool InstalldPermissionMgr::VerifyCallingPermission(const std::string &permissionName)
{
    APP_LOGD("VerifyCallingPermission permission %{public}s", permissionName.c_str());
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    AccessToken::AccessTokenID firstCallerToken = IPCSkeleton::GetFirstTokenID();
    APP_LOGD("callerToken : %{private}u, firstCallerToken : %{private}u", callerToken, firstCallerToken);
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    int32_t ret = AccessToken::PermissionState::PERMISSION_DENIED;
    if (firstCallerToken == 0) {
        // hap or native call
        ret = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    } else {
        // native call
        ret = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, firstCallerToken, permissionName);
    }
    if ((ret == AccessToken::PermissionState::PERMISSION_GRANTED) ||
        (tokenType == AccessToken::ATokenTypeEnum::TOKEN_NATIVE)) {
        APP_LOGD("VerifyCallingPermission success, permission:%{public}s: PERMISSION_GRANTED",
            permissionName.c_str());
        return true;
    }
    APP_LOGE("VerifyCallingPermission failed, permission %{public}s: PERMISSION_DENIED", permissionName.c_str());
    return false;
}
} // AppExecFwk
} // OHOS