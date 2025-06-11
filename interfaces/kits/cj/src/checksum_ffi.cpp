/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "app_log_wrapper.h"
#include "bundle_error.h"
#include "zip_ffi.h"
#include "zlib.h"

using namespace OHOS::CJSystemapi::BundleManager;

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
struct CjCheckSumEntity {
    int64_t Crc32(int64_t crc, uint8_t* buf, int64_t len);
};

int64_t CjCheckSumEntity::Crc32(int64_t crc, uint8_t* buf, int64_t len)
{
    return crc32(static_cast<uLong>(crc), reinterpret_cast<Bytef*>(buf), static_cast<uInt>(len));
}

extern "C" {
FFI_EXPORT void* FfiBundleManagerChecksumInstCreate()
{
    return new CjCheckSumEntity();
}

FFI_EXPORT void FfiBundleManagerChecksumInstDestroy(void* ffiInst)
{
    delete static_cast<CjCheckSumEntity*>(ffiInst);
}

FFI_EXPORT int64_t FfiBundleManagerChecksumCrc32(
    void* ffiInst, int64_t crc, uint8_t* buf, int64_t len, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || buf == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerChecksumCrc32 param check failed");
        return 0;
    }
    auto entity = static_cast<CjCheckSumEntity*>(ffiInst);
    return entity->Crc32(crc, buf, len);
}
} // extern "C"
} // namespace LIBZIP
} // namespace AppExecFwk
} // namespace OHOS
