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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_APP_CONTROL_CONSTANTS_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_APP_CONTROL_CONSTANTS_H

namespace OHOS {
namespace AppExecFwk {
namespace AppControlConstants {
// app control list
constexpr const char* APP_DISALLOWED_UNINSTALL = "AppDisallowedUninstall";
constexpr const char* APP_ALLOWED_INSTALL = "AppAllowedInstall";
constexpr const char* APP_DISALLOWED_RUN = "AppDisallowedRun";

constexpr const char* EDM_CALLING = "edm";
constexpr int32_t FOUNDATION_UID = 5523;
constexpr int32_t EDM_UID = 537;
constexpr int32_t LIST_MAX_SIZE = 1024;
}
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_APP_CONTROL_CONSTANTS_H