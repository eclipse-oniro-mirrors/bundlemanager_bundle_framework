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
#include "service_router_load_callback.h"

#include "app_log_wrapper.h"
#include "service_router_mgr_helper.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
void ServiceRouterLoadCallback::OnLoadSystemAbilitySuccess(int32_t systemAbilityId,
    const sptr<IRemoteObject> &remoteObject)
{
    if (systemAbilityId != OHOS::SERVICE_ROUTER_MGR_SERVICE_ID) {
        APP_LOGE("OnLoadSystemAbilitySuccess, not matched systemAbilityId: %{public}d", systemAbilityId);
        return;
    }
    if (remoteObject == nullptr) {
        APP_LOGE("OnLoadSystemAbilitySuccess, remoteObject is null, systemAbilityId: %{public}d", systemAbilityId);
        return;
    }
    APP_LOGI("OnLoadSystemAbilitySuccess, systemAbilityId: %{public}d", systemAbilityId);
    ServiceRouterMgrHelper::GetInstance().FinishStartSASuccess(remoteObject);
}

void ServiceRouterLoadCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    APP_LOGE("OnLoadSystemAbilitySuccess systemAbilityId: %{public}d", systemAbilityId);
    ServiceRouterMgrHelper::GetInstance().FinishStartSAFail();
}
} // namespace AppExecFwk
} // namespace OHOS
