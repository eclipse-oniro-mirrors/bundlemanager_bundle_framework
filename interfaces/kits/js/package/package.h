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
#ifndef APPEXECFWK_STANDARD_KITS_APPKIT_NAPI_PACKAGE_PACKAGE_H
#define APPEXECFWK_STANDARD_KITS_APPKIT_NAPI_PACKAGE_PACKAGE_H
#include <native_engine/native_value.h>

#include "hilog_wrapper.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "nlohmann/json.hpp"
#include "js_runtime_utils.h"
#include "js_runtime.h"

namespace OHOS {
namespace AppExecFwk {
struct CheckPackageHasInstalledResponse {
    bool result = false;
};
struct CheckPackageHasInstalledOptions {
    std::unique_ptr<NativeReference> jsSuccessRef = nullptr;
    std::unique_ptr<NativeReference> jsFailRef = nullptr;
    std::unique_ptr<NativeReference> jsCompleteRef = nullptr;
    std::string bundleName;
    bool isString = false;
    CheckPackageHasInstalledResponse response;
    ~CheckPackageHasInstalledOptions();
};
class JsPackage {
public:
    JsPackage() = default;
    ~JsPackage() = default;

    static void Finalizer(NativeEngine *engine, void *data, void *hint);
    static NativeValue* HasInstalled(NativeEngine *engine, NativeCallbackInfo *info);
private:
    NativeValue* OnHasInstalled(NativeEngine &engine, NativeCallbackInfo &info);
    NativeValue* CreateHasInstalled(NativeEngine &engine, const OHOS::AppExecFwk::CheckPackageHasInstalledOptions &
        hasInstalledOptions);
    void JsParseCheckPackageHasInstalledOptions(NativeEngine &engine, const NativeCallbackInfo &info,
        std::shared_ptr<CheckPackageHasInstalledOptions> hasInstalledOptions);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif /* APPEXECFWK_STANDARD_KITS_APPKIT_NAPI_PACKAGE_PACKAGE_H */