/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_SHORTCUTINFO_MANAGER_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_SHORTCUTINFO_MANAGER_H

#include "base_cb_info.h"
#include "bundle_constants.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "shortcut_info.h"

namespace OHOS {
namespace AppExecFwk {

struct AddDesktopShortcutInfoCallbackInfo : public BaseCallbackInfo {
    explicit AddDesktopShortcutInfoCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    int32_t userId = 0;
    int32_t errCode = 0;
    OHOS::AppExecFwk::ShortcutInfo shortcutInfo;
};

struct DeleteDesktopShortcutInfoCallbackInfo : public BaseCallbackInfo {
    explicit DeleteDesktopShortcutInfoCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    int32_t userId = 0;
    int32_t errCode = 0;
    OHOS::AppExecFwk::ShortcutInfo shortcutInfo;
};

struct GetAllDesktopShortcutInfoCallbackInfo : public BaseCallbackInfo {
    explicit GetAllDesktopShortcutInfoCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    int32_t userId = 0;
    std::vector<OHOS::AppExecFwk::ShortcutInfo> shortcutInfos;
};

napi_value AddDesktopShortcutInfo(napi_env env, napi_callback_info info);
napi_value DeleteDesktopShortcutInfo(napi_env env, napi_callback_info info);
napi_value GetAllDesktopShortcutInfo(napi_env env, napi_callback_info info);
}
}
#endif