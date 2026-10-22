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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_COMPRESS_ZSTD_WRAPPER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_COMPRESS_ZSTD_WRAPPER_H

#include <cstdint>
#include <memory>
#include <mutex>

#include "single_delayed_task_mgr.h"
#include "zstd_abi.h"

namespace OHOS {
namespace AppExecFwk {
class ZstdWrapper final {
public:
    static ZstdWrapper &GetInstance();

    std::unique_ptr<ZstdWrapper, void (*)(ZstdWrapper *)> Acquire();
    std::unique_ptr<ZstdDStream, void (*)(ZstdDStream *)> CreateDStream();
    size_t DecompressStream(ZstdDStream *zds, ZstdOutBuffer *output, ZstdInBuffer *input);
    size_t DStreamInSize();
    size_t DStreamOutSize();
    unsigned long long GetFrameContentSize(const void *src, size_t srcSize);
    bool IsError(size_t code);
    const char *GetErrorName(size_t code);

private:
    ZstdWrapper();
    ~ZstdWrapper() = default;

    ZstdWrapper(const ZstdWrapper &) = delete;
    ZstdWrapper &operator=(const ZstdWrapper &) = delete;
    ZstdWrapper(ZstdWrapper &&) = delete;
    ZstdWrapper &operator=(ZstdWrapper &&) = delete;

    struct ZstdApi {
        ZstdCreateDStreamFunc createDStream = nullptr;
        ZstdFreeDStreamFunc freeDStream = nullptr;
        ZstdDecompressStreamFunc decompressStream = nullptr;
        ZstdDStreamInSizeFunc dStreamInSize = nullptr;
        ZstdDStreamOutSizeFunc dStreamOutSize = nullptr;
        ZstdGetFrameContentSizeFunc getFrameContentSize = nullptr;
        ZstdIsErrorFunc isError = nullptr;
        ZstdGetErrorNameFunc getErrorName = nullptr;
    };

    bool LoadNoLock();
    void Unload();
    static void Release(ZstdWrapper *zstd);
    static bool ResolveApi(void *handle, ZstdApi &api);
    static void FreeDStreamDeleter(ZstdDStream *zds);

    std::mutex mutex_;
    void *handle_ = nullptr;
    uint32_t refCount_ = 0;
    ZstdApi api_;
    std::shared_ptr<SingleDelayedTaskMgr> unloadTaskMgr_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_COMPRESS_ZSTD_WRAPPER_H
