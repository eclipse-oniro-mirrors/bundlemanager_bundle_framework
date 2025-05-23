/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_APPEXECFWK_CORE_CONSTANTS_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_APPEXECFWK_CORE_CONSTANTS_H

namespace OHOS {
namespace AppExecFwk {
namespace CoreConstants {
const std::unordered_map<int32_t, int32_t> IPC_ERR_MAP = {
    {29201, ERR_APPEXECFWK_IPC_REPLY_ERROR},
    {29202, ERR_APPEXECFWK_IPC_REMOTE_FROZEN_ERROR},
    {29189, ERR_APPEXECFWK_IPC_REMOTE_DEAD_ERROR}
};
}
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_APPEXECFWK_CORE_CONSTANTS_H