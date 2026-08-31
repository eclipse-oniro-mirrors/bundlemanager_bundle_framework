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

#ifndef MOCK_BROWSER_PERMISSION_CONFIG_H
#define MOCK_BROWSER_PERMISSION_CONFIG_H

namespace OHOS {
namespace AppExecFwk {
// Test-only seam: controllable stand-in for BrowserPermissionConfig::IsPermissionCheckEnabled().
// The production version reads /etc/ArkWebPushGlobal/generic/default_browser.conf, which does not
// exist in the unit-test sandbox (so it always returns false and the permission branch is skipped).
// This mock lets tests drive the granted/denied path explicitly. Default is false (check off),
// matching the production default and keeping existing cases unaffected (invariant I4).
void SetBrowserPermissionCheckEnabledForTest(bool enabled);
void ResetBrowserPermissionConfigForTest();
} // AppExecFwk
} // OHOS
#endif // MOCK_BROWSER_PERMISSION_CONFIG_H
