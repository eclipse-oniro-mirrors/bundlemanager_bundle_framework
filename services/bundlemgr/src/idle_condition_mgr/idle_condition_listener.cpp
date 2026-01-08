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
 
#include "app_log_wrapper.h"
#include "idle_condition_mgr/idle_condition_listener.h"
#include "idle_condition_mgr/idle_condition_mgr.h"
 
namespace OHOS {
namespace AppExecFwk {
IdleConditionListener::IdleConditionListener()
{
    APP_LOGI("IdleConditionListener Instances create");
}
 
IdleConditionListener::~IdleConditionListener()
{
    APP_LOGI("IdleConditionListener Instances destroy");
}
 
void IdleConditionListener::OnTrim(Memory::SystemMemoryLevel level)
{
    APP_LOGI("enter level:%{public}d", level);
    auto idleMgr = DelayedSingleton<AppExecFwk::IdleConditionMgr>::GetInstance();
    if (idleMgr == nullptr) {
        APP_LOGE("idleMgr is nullptr");
        return;
    }
    idleMgr->HandleOnTrim(level);
}

}
}