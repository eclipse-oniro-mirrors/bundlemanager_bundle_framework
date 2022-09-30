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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MONITOR_BUNDLE_MONITOR_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MONITOR_BUNDLE_MONITOR_H

#include "bundle_monitor_callback.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppExecFwk {
napi_value Register(napi_env env, napi_callback_info info);
napi_value Unregister(napi_env env, napi_callback_info info);
}
}
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MONITOR_BUNDLE_MONITOR_H