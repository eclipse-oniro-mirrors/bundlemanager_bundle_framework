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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_COMMON_EVENT_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_COMMON_EVENT_H

#include <string>

namespace OHOS {
namespace AppExecFwk {
const std::string COMMON_EVENT_SANDBOX_PACKAGE_ADDED = "usual.event.SANDBOX_PACKAGE_ADDED";

const std::string COMMON_EVENT_SANDBOX_PACKAGE_REMOVED = "usual.event.SANDBOX_PACKAGE_REMOVED";

const std::string COMMON_EVENT_BUNDLE_SCAN_FINISHED = "usual.event.BUNDLE_SCAN_FINISHED";

const std::string OVERLAY_ADD_ACTION = "usual.event.OVERLAY_PACKAGE_ADDED";

const std::string OVERLAY_CHANGED_ACTION = "usual.event.OVERLAY_PACKAGE_CHANGED";

const std::string OVERLAY_STATE_CHANGED = "usual.event.OVERLAY_STATE_CHANGED";

const std::string DISPOSED_RULE_ADDED = "usual.event.DISPOSED_RULE_ADDED";

const std::string DISPOSED_RULE_DELETED = "usual.event.DISPOSED_RULE_DELETED";
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_COMMON_EVENT_H