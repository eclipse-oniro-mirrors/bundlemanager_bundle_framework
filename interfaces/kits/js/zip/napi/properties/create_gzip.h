/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef INTERFACES_KITS_JS_ZIP_NAPI_PROPERTIES_CREATE_GZIP_H
#define INTERFACES_KITS_JS_ZIP_NAPI_PROPERTIES_CREATE_GZIP_H

#include "common/napi_async_work_callback.h"
#include "common/napi_async_work_promise.h"
#include "common/napi_class.h"
#include "common/napi_business_error.h"
#include "common/napi_exporter.h"
#include "common/napi_func_arg.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
class CreateGZip final {
public:
    static napi_value Async(napi_env env, napi_callback_info info);
    static napi_value Sync(napi_env env, napi_callback_info info);
};

const std::string PROCEDURE_CREATE_GZIP_NAME = "ZlibCreateGZip";
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // INTERFACES_KITS_JS_ZIP_NAPI_PROPERTIES_CREATE_GZIP_H