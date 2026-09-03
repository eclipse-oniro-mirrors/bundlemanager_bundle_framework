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

#ifndef FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_BROWSER_PERMISSION_CONFIG_H
#define FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_BROWSER_PERMISSION_CONFIG_H

#include <string>

namespace OHOS {
namespace AppExecFwk {
class BrowserPermissionConfig {
public:
    // Whether the default browser permission check (DEFAULT_WEB_BROWSER) is enabled by cloud push.
    // Returns true only when default_browser.conf has a line starting with "enable=true".
    // A missing file, a missing enable=true line, or enable=false all return false,
    // i.e. the permission check is off by default.
    static bool IsPermissionCheckEnabled();
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_DEFAULT_APPLICATION_FRAMEWORK_BROWSER_PERMISSION_CONFIG_H
