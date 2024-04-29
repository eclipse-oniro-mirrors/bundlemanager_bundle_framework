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
#include <cstdio>
#include <cstring>
#include <memory>
#include <unistd.h>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_zlib.h"
#include "class_checksum/checksum_n_exporter.h"
#include "class_zip/zip_n_exporter.h"
#include "properties/prop_n_exporter.h"
namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {

EXTERN_C_START
/*
 * The module initialization.
 */
static napi_value Init(napi_env env, napi_value exports)
{
    FlushTypeInit(env, exports);
    CompressLevelInit(env, exports);
    CompressFlushModeInit(env, exports);
    CompressMethodInit(env, exports);
    CompressStrategyInit(env, exports);
    MemLevelInit(env, exports);
    ErrorCodeInit(env, exports);
    ZlibInit(env, exports);
    std::vector<std::unique_ptr<NapiExporter>> products;
    products.emplace_back(std::make_unique<PropNExporter>(env, exports));
    products.emplace_back(std::make_unique<ChecksumNExporter>(env, exports));
    products.emplace_back(std::make_unique<ZipNExporter>(env, exports));
    for (auto &&product : products) {
#ifdef WIN_PLATFORM
        std::string nExporterName = product->GetNExporterName();
#else
        std::string nExporterName = product->GetClassName();
#endif
        if (!product->Export()) {
            APP_LOGE("Failed to export class %{public}s for module fileio", nExporterName.c_str());
            return nullptr;
        }
    }
    return exports;
}
EXTERN_C_END

/*
 * The module definition.
 */
static napi_module _module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "zlib",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

/*
 * The module registration.
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&_module);
}
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
