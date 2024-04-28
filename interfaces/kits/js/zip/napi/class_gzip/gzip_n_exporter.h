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

#ifndef INTERFACES_KITS_JS_ZIP_NAPI_CLASS_ZIP_GZIP_N_EXPORTER_H
#define INTERFACES_KITS_JS_ZIP_NAPI_CLASS_ZIP_GZIP_N_EXPORTER_H

#include "common/napi_exporter.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
class GZipNExporter final : public NapiExporter {
public:
    inline static const std::string className_ = "GZip";

    bool Export() override;
    std::string GetClassName() override;

    static napi_value Constructor(napi_env env, napi_callback_info info);

    static napi_value GZDopen(napi_env env, napi_callback_info info);
    static napi_value GZOpen(napi_env env, napi_callback_info info);
    static napi_value GZClose(napi_env env, napi_callback_info info);
    static napi_value GZOpenW(napi_env env, napi_callback_info info);
    static napi_value GZCloseW(napi_env env, napi_callback_info info);
    static napi_value GZBuffer(napi_env env, napi_callback_info info);

    static napi_value GZRead(napi_env env, napi_callback_info info);
    static napi_value GZFRead(napi_env env, napi_callback_info info);
    static napi_value GZWrite(napi_env env, napi_callback_info info);
    static napi_value GZFWrite(napi_env env, napi_callback_info info);
    static napi_value GZPutC(napi_env env, napi_callback_info info);
    static napi_value GZPutS(napi_env env, napi_callback_info info);
    static napi_value GZTell(napi_env env, napi_callback_info info);
    static napi_value GZSetParams(napi_env env, napi_callback_info info);
    static napi_value GZPrintF(napi_env env, napi_callback_info info);

    static napi_value GZCloseR(napi_env env, napi_callback_info info);
    static napi_value GZGetS(napi_env env, napi_callback_info info);
    static napi_value GZGetC(napi_env env, napi_callback_info info);
    static napi_value GZRewind(napi_env env, napi_callback_info info);
    static napi_value GZSeek(napi_env env, napi_callback_info info);
    static napi_value GZOffset(napi_env env, napi_callback_info info);
    static napi_value GZUnGetC(napi_env env, napi_callback_info info);

    static napi_value GZClearerr(napi_env env, napi_callback_info info);
    static napi_value GZDirect(napi_env env, napi_callback_info info);
    static napi_value GZeof(napi_env env, napi_callback_info info);
    static napi_value GZError(napi_env env, napi_callback_info info);
    static napi_value GZFlush(napi_env env, napi_callback_info info);

    GZipNExporter(napi_env env, napi_value exports);
    ~GZipNExporter() override;
};

const std::string PROCEDURE_GZIP_NAME = "ZlibGZip";
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // INTERFACES_KITS_JS_ZIP_NAPI_CLASS_ZIP_GZIP_N_EXPORTER_H