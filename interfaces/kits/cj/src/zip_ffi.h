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

#ifndef OHOS_ZIP_FFI_H
#define OHOS_ZIP_FFI_H

#include <cstdint>
#include "cj_common_ffi.h"
#include "native/ffi_remote_data.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {

struct RetOptions {
    int32_t level;
    int32_t memLevel;
    int32_t strategy;
};

struct CArrUI8 {
    uint8_t *data;
    int32_t len;
};

extern "C" {
    FFI_EXPORT int32_t FfiBundleManagerCompressFile(CArrUI8 inFile, CArrUI8 outFile, RetOptions options);
    FFI_EXPORT int32_t FfiBundleManagerDeCompressFileOptions(CArrUI8 inFile, CArrUI8 outFile, RetOptions options);
    FFI_EXPORT int32_t FfiBundleManagerDeCompressFile(CArrUI8 inFile, CArrUI8 outFile);
}


} // LIBZIP
} // AppExecFwk
} // OHOS
#endif

