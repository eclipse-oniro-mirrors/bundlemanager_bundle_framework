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

#ifndef FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_KITS_JS_SERVICE_ROUTER_MGR_H
#define FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_KITS_JS_SERVICE_ROUTER_MGR_H

#include "base_cb_info.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "service_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
struct ServiceInfosCallbackInfo : public BaseCallbackInfo {
    explicit ServiceInfosCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    OHOS::AAFwk::Want want;
    int32_t serviceType = static_cast<int32_t>(ExtensionServiceType::UNSPECIFIED);
    std::vector<ServiceInfo> serviceInfos;
};

napi_value QueryServiceInfos(napi_env env, napi_callback_info info);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_KITS_JS_SERVICE_ROUTER_MGR_H