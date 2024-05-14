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

#ifndef INTERFACES_KITS_JS_ZIP_NAPI_CLASS_ZIP_ZIP_N_EXPORTER_H
#define INTERFACES_KITS_JS_ZIP_NAPI_CLASS_ZIP_ZIP_N_EXPORTER_H

#include "common/napi_exporter.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
class ZipNExporter final : public NapiExporter {
public:
    inline static const std::string className_ = "Zip";

    bool Export() override;
    std::vector<napi_property_descriptor> DeflateExport();
    std::vector<napi_property_descriptor> InflateExport();
    std::string GetClassName() override;

    static napi_value Constructor(napi_env env, napi_callback_info info);
    static napi_value SetZStream(napi_env env, napi_callback_info info);
    static napi_value GetZStream(napi_env env, napi_callback_info info);
    static napi_value GetZStreamSync(napi_env env, napi_callback_info info);

    static napi_value ZlibVersion(napi_env env, napi_callback_info info);
    static napi_value ZError(napi_env env, napi_callback_info info);
    static napi_value ZlibCompileFlags(napi_env env, napi_callback_info info);

    static napi_value DeflateInit(napi_env env, napi_callback_info info);
    static napi_value DeflateInit2(napi_env env, napi_callback_info info);
    static napi_value Deflate(napi_env env, napi_callback_info info);
    static napi_value DeflateEnd(napi_env env, napi_callback_info info);
    static napi_value DeflateBound(napi_env env, napi_callback_info info);
    static napi_value DeflateReset(napi_env env, napi_callback_info info);
    static napi_value DeflateResetKeep(napi_env env, napi_callback_info info);
    static napi_value DeflateParams(napi_env env, napi_callback_info info);
    static napi_value DeflatePrime(napi_env env, napi_callback_info info);
    static napi_value DeflateTune(napi_env env, napi_callback_info info);
    static napi_value DeflateSetDictionary(napi_env env, napi_callback_info info);
    static napi_value DeflateGetDictionary(napi_env env, napi_callback_info info);
    static napi_value DeflateSetHeader(napi_env env, napi_callback_info info);

    static napi_value DeflatePending(napi_env env, napi_callback_info info);
    static napi_value DeflateCopy(napi_env env, napi_callback_info info);

    static napi_value Compress(napi_env env, napi_callback_info info);
    static napi_value Compress2(napi_env env, napi_callback_info info);
    static napi_value CompressBound(napi_env env, napi_callback_info info);
    static napi_value UnCompress(napi_env env, napi_callback_info info);
    static napi_value UnCompress2(napi_env env, napi_callback_info info);

    static napi_value InflateInit(napi_env env, napi_callback_info info);
    static napi_value InflateInit2(napi_env env, napi_callback_info info);
    static napi_value InflateSync(napi_env env, napi_callback_info info);
    static napi_value Inflate(napi_env env, napi_callback_info info);
    static napi_value InflateEnd(napi_env env, napi_callback_info info);

    static napi_value InflateSetDictionary(napi_env env, napi_callback_info info);
    static napi_value InflateGetDictionary(napi_env env, napi_callback_info info);

    static napi_value InflateResetKeep(napi_env env, napi_callback_info info);
    static napi_value InflateReset2(napi_env env, napi_callback_info info);
    static napi_value InflateReset(napi_env env, napi_callback_info info);

    static napi_value InflateBackInit(napi_env env, napi_callback_info info);
    static napi_value InflateBack(napi_env env, napi_callback_info info);
    static napi_value InflateBackEnd(napi_env env, napi_callback_info info);

    static napi_value InflateCodesUsed(napi_env env, napi_callback_info info);
    static napi_value InflatePrime(napi_env env, napi_callback_info info);
    static napi_value InflateMark(napi_env env, napi_callback_info info);
    static napi_value InflateValidate(napi_env env, napi_callback_info info);
    static napi_value InflateSyncPoint(napi_env env, napi_callback_info info);

    static napi_value InflateCopy(napi_env env, napi_callback_info info);
    static napi_value InflateGetHeader(napi_env env, napi_callback_info info);

    ZipNExporter(napi_env env, napi_value exports);
    ~ZipNExporter() override;
};

const std::string PROCEDURE_ZIP_NAME = "ZlibZip";
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // INTERFACES_KITS_JS_ZIP_NAPI_CLASS_ZIP_ZIP_N_EXPORTER_H