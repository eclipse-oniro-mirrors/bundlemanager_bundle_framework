/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#ifndef APPEXECFWK_STANDARD_KITS_APPKIT_NAPI_PACKAGE_PACKAGE_H
#define APPEXECFWK_STANDARD_KITS_APPKIT_NAPI_PACKAGE_PACKAGE_H
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppExecFwk {
struct CheckPackageHasInstalledResponse {
    bool result = false;
};
struct CheckPackageHasInstalledOptions {
    bool isString = false;
    int32_t errCode = 0;
    std::string bundleName;
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref successRef = nullptr;
    napi_ref failRef = nullptr;
    napi_ref completeRef = nullptr;
    CheckPackageHasInstalledResponse response;
    ~CheckPackageHasInstalledOptions();
};
napi_value HasInstalled(napi_env env, napi_callback_info info);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif /* APPEXECFWK_STANDARD_KITS_APPKIT_NAPI_PACKAGE_PACKAGE_H */
