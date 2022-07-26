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
bool InstalldPermissionMgr::VerifyCallingPermission(const std::string &name)
{
    APP_LOGD("VerifyCallingPermission name %{public}s", name.c_str());
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    APP_LOGD("callerToken : %{private}u", callerToken);
    AccessToken::NativeTokenInfo tokenInfo;
    int32_t ret = AccessToken::AccessTokenKit::GetNativeTokenInfo(callerToken, tokenInfo);
    if ((ret == AccessToken::AccessTokenKitRet::RET_SUCCESS) && (tokenInfo.processName == name)) {
        APP_LOGD("VerifyCallingPermission succeed, name:%{public}s, processName: %{public}s", name.c_str(),
            tokenInfo.processName.c_str());
        return true;
    }
    APP_LOGE("VerifyCallingPermission failed, name:%{public}s, processName: %{public}s", name.c_str(),
        tokenInfo.processName.c_str());
    return false;
}
} // AppExecFwk
} // OHOS