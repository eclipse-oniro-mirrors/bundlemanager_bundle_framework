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

#ifndef OHOS_BUNDLE_APPEXECFWK_CORE_IPC_INTERFACE_CODE_H
#define OHOS_BUNDLE_APPEXECFWK_CORE_IPC_INTERFACE_CODE_H

#include <stdint.h>

/* SAID: 401 */
namespace OHOS {
namespace AppExecFwk {
enum class AppControlManagerInterfaceCode : uint32_t {
    ADD_APP_INSTALL_CONTROL_RULE = 0,
    DELETE_APP_INSTALL_CONTROL_RULE,
    CLEAN_APP_INSTALL_CONTROL_RULE,
    GET_APP_INSTALL_CONTROL_RULE,
    ADD_APP_RUNNING_CONTROL_RULE,
    DELETE_APP_RUNNING_CONTROL_RULE,
    CLEAN_APP_RUNNING_CONTROL_RULE,
    GET_APP_RUNNING_CONTROL_RULE,
    GET_APP_RUNNING_CONTROL_RULE_RESULT,
    SET_DISPOSED_STATUS,
    DELETE_DISPOSED_STATUS,
    GET_DISPOSED_STATUS,
    CONFIRM_APP_JUMP_CONTROL_RULE,
    ADD_APP_JUMP_CONTROL_RULE,
    DELETE_APP_JUMP_CONTROL_RULE,
    DELETE_APP_JUMP_CONTROL_RULE_BY_CALLER,
    DELETE_APP_JUMP_CONTROL_RULE_BY_TARGET,
    GET_APP_JUMP_CONTROL_RULE,
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_BUNDLE_APPEXECFWK_CORE_IPC_INTERFACE_CODE_H