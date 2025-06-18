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

struct ZipCompressParam {
    uint8_t* destBuf;
    int64_t destBufLen;
    uint8_t* srcBuf;
    int64_t srcBufLen;
    int32_t outStatus;
    int64_t outDestLen;
    int32_t level;
};

struct CZStream {
    uint8_t* nextIn;
    uint32_t availableIn;
    uint64_t totalIn;
    uint8_t* nextOut;
    uint32_t availableOut;
    uint64_t totalOut;
    int32_t dataType;
    uint64_t adler;

    bool hasNextIn;
    bool hasAvailableIn;
    bool hasTotalIn;
    bool hasNextOut;
    bool hasAvailableOut;
    bool hasTotalOut;
    bool hasDataType;
    bool hasAdler;
};

struct DeflateInit2Param {
    int32_t level;
    int32_t method;
    int32_t windowBits;
    int32_t memLevel;
    int32_t strategy;
};

} // LIBZIP
} // AppExecFwk
} // OHOS
#endif
