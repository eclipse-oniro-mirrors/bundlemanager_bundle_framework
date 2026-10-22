/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_COMPRESS_ZSTD_ABI_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_COMPRESS_ZSTD_ABI_H

#include <cstddef>

namespace OHOS {
namespace AppExecFwk {
struct ZstdDStream;

struct ZstdInBuffer {
    const void *src = nullptr;
    size_t size = 0;
    size_t pos = 0;
};

struct ZstdOutBuffer {
    void *dst = nullptr;
    size_t size = 0;
    size_t pos = 0;
};

constexpr unsigned long long ZSTD_CONTENT_SIZE_UNKNOWN = (0ULL - 1);
constexpr unsigned long long ZSTD_CONTENT_SIZE_ERROR = (0ULL - 2);

using ZstdCreateDStreamFunc = ZstdDStream *(*)();
using ZstdFreeDStreamFunc = size_t (*)(ZstdDStream *);
using ZstdDecompressStreamFunc = size_t (*)(ZstdDStream *, ZstdOutBuffer *, ZstdInBuffer *);
using ZstdDStreamInSizeFunc = size_t (*)();
using ZstdDStreamOutSizeFunc = size_t (*)();
using ZstdGetFrameContentSizeFunc = unsigned long long (*)(const void *, size_t);
using ZstdIsErrorFunc = unsigned (*)(size_t);
using ZstdGetErrorNameFunc = const char *(*)(size_t);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_COMPRESS_ZSTD_ABI_H
