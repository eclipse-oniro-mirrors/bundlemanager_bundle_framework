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

#include "zstd_wrapper.h"

#include <dlfcn.h>

#include "app_log_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* LIB_ZSTD_SO_NAME = "libzstd.z.so";
constexpr uint32_t UNLOAD_DELAY_MS = 3 * 60 * 1000;
constexpr const char* UNLOAD_TASK_NAME = "ZstdWrapperUnloadTask";
constexpr const char* ZSTD_CREATE_DSTREAM_FUNC = "ZSTD_createDStream";
constexpr const char* ZSTD_FREE_DSTREAM_FUNC = "ZSTD_freeDStream";
constexpr const char* ZSTD_DECOMPRESS_STREAM_FUNC = "ZSTD_decompressStream";
constexpr const char* ZSTD_DSTREAM_IN_SIZE_FUNC = "ZSTD_DStreamInSize";
constexpr const char* ZSTD_DSTREAM_OUT_SIZE_FUNC = "ZSTD_DStreamOutSize";
constexpr const char* ZSTD_GET_FRAME_CONTENT_SIZE_FUNC = "ZSTD_getFrameContentSize";
constexpr const char* ZSTD_IS_ERROR_FUNC = "ZSTD_isError";
constexpr const char* ZSTD_GET_ERROR_NAME_FUNC = "ZSTD_getErrorName";

template<typename T>
bool ResolveSymbol(void *handle, const char *symbolName, T &func)
{
    void *symbol = dlsym(handle, symbolName);
    if (symbol == nullptr) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "dlsym %{public}s failed: %{public}s", symbolName, dlerror());
        return false;
    }
    func = reinterpret_cast<T>(symbol);
    return true;
}
}  // namespace

ZstdWrapper::ZstdWrapper()
{
    unloadTaskMgr_ = std::make_shared<SingleDelayedTaskMgr>(UNLOAD_TASK_NAME, UNLOAD_DELAY_MS);
}

ZstdWrapper &ZstdWrapper::GetInstance()
{
    static ZstdWrapper instance;
    return instance;
}

bool ZstdWrapper::ResolveApi(void *handle, ZstdApi &api)
{
    return ResolveSymbol(handle, ZSTD_CREATE_DSTREAM_FUNC, api.createDStream) &&
        ResolveSymbol(handle, ZSTD_FREE_DSTREAM_FUNC, api.freeDStream) &&
        ResolveSymbol(handle, ZSTD_DECOMPRESS_STREAM_FUNC, api.decompressStream) &&
        ResolveSymbol(handle, ZSTD_DSTREAM_IN_SIZE_FUNC, api.dStreamInSize) &&
        ResolveSymbol(handle, ZSTD_DSTREAM_OUT_SIZE_FUNC, api.dStreamOutSize) &&
        ResolveSymbol(handle, ZSTD_GET_FRAME_CONTENT_SIZE_FUNC, api.getFrameContentSize) &&
        ResolveSymbol(handle, ZSTD_IS_ERROR_FUNC, api.isError) &&
        ResolveSymbol(handle, ZSTD_GET_ERROR_NAME_FUNC, api.getErrorName);
}

bool ZstdWrapper::LoadNoLock()
{
    if (handle_ != nullptr) {
        return true;
    }
    void *handle = dlopen(LIB_ZSTD_SO_NAME, RTLD_NOW | RTLD_LOCAL);
    if (handle == nullptr) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "dlopen libzstd.z.so failed: %{public}s", dlerror());
        return false;
    }

    ZstdApi api;
    if (!ResolveApi(handle, api)) {
        dlclose(handle);
        return false;
    }

    handle_ = handle;
    api_ = api;
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "libzstd loaded");
    return true;
}

void ZstdWrapper::Unload()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refCount_ != 0 || handle_ == nullptr) {
        return;
    }
    dlclose(handle_);
    handle_ = nullptr;
    api_ = ZstdApi();
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "libzstd unloaded");
}

std::unique_ptr<ZstdWrapper, void (*)(ZstdWrapper *)> ZstdWrapper::Acquire()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!LoadNoLock()) {
        return {nullptr, Release};
    }
    ++refCount_;
    return {this, Release};
}

void ZstdWrapper::Release(ZstdWrapper *zstd)
{
    std::lock_guard<std::mutex> lock(zstd->mutex_);
    if (--zstd->refCount_ == 0) {
        zstd->unloadTaskMgr_->ScheduleDelayedTask([zstd] { zstd->Unload(); });
    }
}

__attribute__((no_sanitize("cfi"))) void ZstdWrapper::FreeDStreamDeleter(ZstdDStream *zds)
{
    (void)GetInstance().api_.freeDStream(zds);
}

__attribute__((no_sanitize("cfi")))
std::unique_ptr<ZstdDStream, void (*)(ZstdDStream *)> ZstdWrapper::CreateDStream()
{
    return {api_.createDStream(), FreeDStreamDeleter};
}

__attribute__((no_sanitize("cfi"))) size_t ZstdWrapper::DecompressStream(
    ZstdDStream *zds, ZstdOutBuffer *output, ZstdInBuffer *input)
{
    return api_.decompressStream(zds, output, input);
}

__attribute__((no_sanitize("cfi"))) size_t ZstdWrapper::DStreamInSize()
{
    return api_.dStreamInSize();
}

__attribute__((no_sanitize("cfi"))) size_t ZstdWrapper::DStreamOutSize()
{
    return api_.dStreamOutSize();
}

__attribute__((no_sanitize("cfi"))) unsigned long long ZstdWrapper::GetFrameContentSize(
    const void *src, size_t srcSize)
{
    return api_.getFrameContentSize(src, srcSize);
}

__attribute__((no_sanitize("cfi"))) bool ZstdWrapper::IsError(size_t code)
{
    return api_.isError(code) != 0;
}

__attribute__((no_sanitize("cfi"))) const char *ZstdWrapper::GetErrorName(size_t code)
{
    return api_.getErrorName(code);
}
}  // namespace AppExecFwk
}  // namespace OHOS
