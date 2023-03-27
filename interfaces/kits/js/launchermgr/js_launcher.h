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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_LAUNCHER_MGR_JS_LAUNCHER_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_LAUNCHER_MGR_JS_LAUNCHER_H

#include "base_cb_info.h"
#include "launcher_ability_info.h"

namespace OHOS {
namespace AppExecFwk {

struct JsGetAllLauncherAbilityCallbackInfo : public BaseCallbackInfo {
    explicit JsGetAllLauncherAbilityCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    int32_t userId = 0;
    int32_t err = 0;
    std::string message;
    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
};
}
}
#endif