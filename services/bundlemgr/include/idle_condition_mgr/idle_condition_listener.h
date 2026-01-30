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
 
#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IDLE_CONDITION_LISTENER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IDLE_CONDITION_LISTENER_H
 
#include "app_state_subscriber.h"
#include "memory_level_constants.h"
 
namespace OHOS {
namespace AppExecFwk {

class IdleConditionListener : public Memory::AppStateSubscriber {
public:
    IdleConditionListener();
    ~IdleConditionListener();
 
    void OnTrim(Memory::SystemMemoryLevel level) override;
};
}
}
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IDLE_CONDITION_LISTENER_H
