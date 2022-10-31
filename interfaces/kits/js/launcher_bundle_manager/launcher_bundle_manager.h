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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_LAUNCHER_BUNDLE_MANAGER_LAUNCHER_BUNDLE_MANAGER_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_LAUNCHER_BUNDLE_MANAGER_LAUNCHER_BUNDLE_MANAGER_H

#include "ability_info.h"
#include "base_cb_info.h"
#include "bundle_constants.h"
#include "bundle_info.h"
#include "launcher_ability_info.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "shortcut_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {

struct GetLauncherAbilityCallbackInfo : public BaseCallbackInfo {
    explicit GetLauncherAbilityCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::string bundleName;
    int32_t userId = 0;
    std::vector<OHOS::AppExecFwk::LauncherAbilityInfo> launcherAbilityInfos;
};

struct GetAllLauncherAbilityCallbackInfo : public BaseCallbackInfo {
    explicit GetAllLauncherAbilityCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    int32_t userId = 0;
    std::vector<OHOS::AppExecFwk::LauncherAbilityInfo> launcherAbilityInfos;
};

struct GetShortcutInfoCallbackInfo : public BaseCallbackInfo {
    explicit GetShortcutInfoCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::string bundleName;
    std::vector<OHOS::AppExecFwk::ShortcutInfo> shortcutInfos;
};

napi_value GetLauncherAbilityInfo(napi_env env, napi_callback_info info);
napi_value GetAllLauncherAbilityInfo(napi_env env, napi_callback_info info);
napi_value GetShortcutInfo(napi_env env, napi_callback_info info);
}
}
#endif