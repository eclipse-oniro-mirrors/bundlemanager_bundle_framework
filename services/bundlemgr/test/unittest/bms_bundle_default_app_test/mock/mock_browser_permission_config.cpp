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

#include "mock_browser_permission_config.h"

#include "browser_permission_config.h"

namespace {
// Default false matches the production default (no conf file => check off), so existing cases that
// never touch this seam keep the legacy "permission check skipped" behaviour.
bool g_browserPermissionCheckEnabled = false;
}

namespace OHOS {
namespace AppExecFwk {
bool BrowserPermissionConfig::IsPermissionCheckEnabled()
{
    return g_browserPermissionCheckEnabled;
}

void SetBrowserPermissionCheckEnabledForTest(bool enabled)
{
    g_browserPermissionCheckEnabled = enabled;
}

void ResetBrowserPermissionConfigForTest()
{
    g_browserPermissionCheckEnabled = false;
}
} // AppExecFwk
} // OHOS
