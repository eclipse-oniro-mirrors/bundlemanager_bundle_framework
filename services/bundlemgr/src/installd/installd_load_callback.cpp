/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "installd/installd_load_callback.h"

#include "app_log_wrapper.h"
#include "installd_client.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
void InstalldLoadCallback::OnLoadSystemAbilitySuccess(
    int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject)
{
    if (systemAbilityId != INSTALLD_SERVICE_ID) {
        APP_LOGE("System ability id %{public}d mismatch.", systemAbilityId);
        return;
    }
    if (remoteObject == nullptr) {
        APP_LOGE("Object is nullptr.");
        return;
    }

    APP_LOGD("Load system ability %{public}d succeed.", systemAbilityId);
    InstalldClient::GetInstance()->OnLoadSystemAbilitySuccess(remoteObject);
}

void InstalldLoadCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    if (systemAbilityId != INSTALLD_SERVICE_ID) {
        APP_LOGE("System ability id %{public}d mismatch.", systemAbilityId);
        return;
    }

    APP_LOGD("Load system ability %{public}d failed.", systemAbilityId);
    InstalldClient::GetInstance()->OnLoadSystemAbilityFail();
}
}
}
