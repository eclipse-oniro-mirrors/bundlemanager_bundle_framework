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

#ifndef INTERFACES_KITS_JS_ZIP_NAPI_CLASS_CHECKSUM_CHECKSUM_N_EXPORTER_H
#define INTERFACES_KITS_JS_ZIP_NAPI_CLASS_CHECKSUM_CHECKSUM_N_EXPORTER_H

#include "common/napi_exporter.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
class ChecksumNExporter final : public NapiExporter {
public:
    inline static const std::string className_ = "Checksum";

    bool Export() override;
    std::string GetClassName() override;

    static napi_value Constructor(napi_env env, napi_callback_info cbinfo);

    static napi_value Adler32(napi_env env, napi_callback_info cbinfo);
    static napi_value Adler32Combine(napi_env env, napi_callback_info cbinfo);
    static napi_value Adler32Combine64(napi_env env, napi_callback_info cbinfo);

    static napi_value Crc32(napi_env env, napi_callback_info cbinfo);
    static napi_value Crc32Combine(napi_env env, napi_callback_info cbinfo);
    static napi_value Crc32Combine64(napi_env env, napi_callback_info cbinfo);

    static napi_value Crc64(napi_env env, napi_callback_info info);

    static napi_value GetCrcTable(napi_env env, napi_callback_info cbinfo);
    static napi_value GetCrc64Table(napi_env env, napi_callback_info info);

    ChecksumNExporter(napi_env env, napi_value exports);
    ~ChecksumNExporter() override;
};

const std::string PROCEDURE_CHECKSUM_NAME = "ZlibChecksum";
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // INTERFACES_KITS_JS_ZIP_NAPI_CLASS_CHECKSUM_CHECKSUM_N_EXPORTER_H