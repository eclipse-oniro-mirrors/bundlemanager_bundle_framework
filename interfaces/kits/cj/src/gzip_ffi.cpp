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
static inline ErrCode ZlibBusinessError(int32_t errCode)
{
    if (errCode == Z_STREAM_ERROR) {
        return ERR_ZLIB_ZSTREAM_ERROR;
    } else if (errCode == Z_MEM_ERROR) {
        return ERR_ZLIB_MEMORY_ALLOC_FAILED;
    } else if (errCode == Z_BUF_ERROR) {
        return ERR_ZLIB_BUFFER_ERROR;
    } else {
        return ERR_ZLIB_INTERNAL_STRUCT_ERROR;
    }
}

struct CjGZipEntity {
    int32_t Dopen(int32_t fd, const char* mode);
    int32_t Open(const char* path, const char* mode);
    int32_t Eof();
    int32_t Close(int32_t* errCode);
    int64_t Write(uint8_t* buf, int64_t len, int32_t* errCode);
    int64_t Read(uint8_t* buf, int64_t len, int32_t* errCode);
    int32_t Puts(const char* cstr, int32_t* errCode);
    char* GzGets(uint8_t* buf, int64_t len, int32_t* errCode);

    gzFile gzs = {};
};

int32_t CjGZipEntity::Dopen(int32_t fd, const char* mode)
{
    gzs = gzdopen(fd, mode);
    if (gzs == nullptr) {
        APP_LOGE("gzdopen return nullptr");
        return ERR_ZLIB_NO_SUCH_FILE_OR_MODE_ERROR;
    }
    return 0;
}

int32_t CjGZipEntity::Open(const char* path, const char* mode)
{
#if !defined(ZLIB_INTERNAL) && defined(Z_WANT64) && !defined(Z_LARGE64)
    gzs = gzopen64(path, mode);
#else
    gzs = gzopen(path, mode);
#endif
    if (gzs == nullptr) {
        APP_LOGE("gzopen return nullptr");
        return ERR_ZLIB_NO_SUCH_FILE_OR_MODE_ERROR;
    }
    return 0;
}

int32_t CjGZipEntity::Eof()
{
    return gzeof(gzs);
}

int32_t CjGZipEntity::Close(int32_t* errCode)
{
    auto ret = gzclose(gzs);
    if (ret < 0) {
        APP_LOGE("gzclose return failed, code: %{public}d", ret);
        *errCode = ZlibBusinessError(ret);
    }
    return ret;
}

int64_t CjGZipEntity::Write(uint8_t* buf, int64_t len, int32_t* errCode)
{
    int64_t writeLen = gzwrite(gzs, buf, static_cast<unsigned int>(len));
    if (writeLen <= 0) {
        APP_LOGE("gzwrite return failed, code: %{public}d", static_cast<int32_t>(writeLen));
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
    }
    return writeLen;
}

int64_t CjGZipEntity::Read(uint8_t* buf, int64_t len, int32_t* errCode)
{
    int64_t readLen = gzread(gzs, reinterpret_cast<void*>(buf), static_cast<unsigned int>(len));
    if (readLen < 0) {
        APP_LOGE("gzread return failed, code: %{public}d", static_cast<int32_t>(readLen));
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
    }
    return readLen;
}

int32_t CjGZipEntity::Puts(const char* cstr, int32_t* errCode)
{
    int64_t putLen = gzputs(gzs, cstr);
    if (putLen < 0) {
        APP_LOGE("gzputs return failed, code: %{public}d", static_cast<int32_t>(putLen));
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
    }
    return putLen;
}

char* CjGZipEntity::GzGets(uint8_t* buf, int64_t len, int32_t* errCode)
{
    auto nullTerminatedString = gzgets(gzs, reinterpret_cast<char*>(buf), static_cast<int>(len));
    if (!nullTerminatedString) {
        APP_LOGE("gzgets return failed");
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
    }
    return nullTerminatedString;
}

extern "C" {
FFI_EXPORT void* FfiBundleManagerGZipInstCreate()
{
    return new CjGZipEntity();
}

FFI_EXPORT void FfiBundleManagerGZipInstDestroy(void* ffiInst)
{
    delete static_cast<CjGZipEntity*>(ffiInst);
}

FFI_EXPORT void FfiBundleManagerGZipDopen(void* ffiInst, int32_t fd, const char* mode, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || mode == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerGZipDopen param check failed");
        return;
    }
    auto entity = static_cast<CjGZipEntity*>(ffiInst);
    *errCode = entity->Dopen(fd, mode);
    return;
}

FFI_EXPORT void FfiBundleManagerGZipOpen(void* ffiInst, const char* path, const char* mode, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || path == nullptr || mode == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerGZipOpen param check failed");
        return;
    }
    auto entity = static_cast<CjGZipEntity*>(ffiInst);
    *errCode = entity->Open(path, mode);
    return;
}

FFI_EXPORT int32_t FfiBundleManagerGZipEof(void* ffiInst, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr) {
        APP_LOGE("FfiBundleManagerGZipEof param check failed");
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        return 0;
    }
    auto entity = static_cast<CjGZipEntity*>(ffiInst);
    return entity->Eof();
}

FFI_EXPORT int32_t FfiBundleManagerGZipClose(void* ffiInst, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerGZipClose param check failed");
        return 0;
    }
    auto entity = static_cast<CjGZipEntity*>(ffiInst);
    return entity->Close(errCode);
}

FFI_EXPORT int64_t FfiBundleManagerGZipWrite(void* ffiInst, uint8_t* buf, int64_t len, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || buf == nullptr || len <= 0) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerGZipWrite param check failed");
        return 0;
    }
    auto entity = static_cast<CjGZipEntity*>(ffiInst);
    return entity->Write(buf, len, errCode);
}

FFI_EXPORT int64_t FfiBundleManagerGZipRead(void* ffiInst, uint8_t* buf, int64_t len, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || buf == nullptr || len <= 0) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerGZipRead param check failed");
        return 0;
    }
    auto entity = static_cast<CjGZipEntity*>(ffiInst);
    return entity->Read(buf, len, errCode);
}

FFI_EXPORT int32_t FfiBundleManagerGZipPuts(void* ffiInst, const char* cstr, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || cstr == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerGZipPuts param check failed");
        return 0;
    }
    auto entity = static_cast<CjGZipEntity*>(ffiInst);
    return entity->Puts(cstr, errCode);
}

FFI_EXPORT char* FfiBundleManagerGZipGets(void* ffiInst, uint8_t* buf, int64_t len, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || buf == nullptr || len <= 0) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerGZipGets param check failed");
        return 0;
    }
    auto entity = static_cast<CjGZipEntity*>(ffiInst);
    return entity->GzGets(buf, len, errCode);
}
} // extern "C"
} // namespace LIBZIP
} // namespace AppExecFwk
} // namespace OHOS
