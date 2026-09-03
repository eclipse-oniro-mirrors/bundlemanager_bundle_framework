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

#include "browser_permission_config.h"

#include <fstream>

#include "app_log_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* DEFAULT_BROWSER_CONF_PATH =
    "/data/service/el1/public/update/param_service/install/system/etc/ArkWebPushGlobal/generic/default_browser.conf";
constexpr const char* ENABLE_TRUE = "enable=true";
}

bool BrowserPermissionConfig::IsPermissionCheckEnabled()
{
    std::ifstream file(DEFAULT_BROWSER_CONF_PATH);
    if (!file.is_open()) {
        LOG_D(BMS_TAG_DEFAULT, "default_browser.conf not open, permission check disabled");
        return false;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (line.rfind(ENABLE_TRUE, 0) == 0) {
            return true;
        }
    }
    return false;
}
} // namespace AppExecFwk
} // namespace OHOS
