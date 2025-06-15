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

#include "zip_ffi.h"

#include <fcntl.h>
#include <string>
#include <vector>

#include "app_log_wrapper.h"
#include "bundle_error.h"
#include "cj_common_ffi.h"
#include "cj_zip.h"
#include "common_func.h"
#include "directory_ex.h"
#include "file_path.h"
#include "zip_reader.h"
#include "zip_utils.h"
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

struct CjZipEntity {
    int32_t Compress(ZipCompressParam* param);
    int32_t Compress2(ZipCompressParam* param);
    int32_t CompressBound(int32_t sourceLen);
    int32_t UnCompress(ZipCompressParam* param);

    void GetZStream(CZStream* cStrm, int32_t* errCode);
    int32_t Deflate(CZStream* cStrm, int32_t flush, int32_t* errCode);
    int32_t DeflateEnd(CZStream* cStrm, int32_t* errCode);
    int32_t DeflateInit2(CZStream* cStrm, DeflateInit2Param* param, int32_t* errCode);

    int32_t Inflate(CZStream* cStrm, int32_t flush, int32_t* errCode);
    int32_t InflateEnd(CZStream* cStrm, int32_t* errCode);
    int32_t InflateInit(CZStream* cStrm, int32_t* errCode);
    int32_t InflateInit2(CZStream* cStrm, int32_t windowBits, int32_t* errCode);

    void InitialZStream(CZStream* cStrm);
    void SetZStreamValue(CZStream* cStrm);

    std::unique_ptr<z_stream> zs = {};
};

int32_t CjZipEntity::Compress(ZipCompressParam* param)
{
    if (param->destBuf == nullptr || param->srcBuf == nullptr) {
        APP_LOGE("destBuf or srcBuf is nullptr");
        return ERR_ZLIB_INTERNAL_STRUCT_ERROR;
    }
    uLong destLen = static_cast<uLong>(param->destBufLen);
    int32_t status =
        compress(static_cast<Bytef*>(param->destBuf), &destLen, static_cast<Bytef*>(param->srcBuf), param->srcBufLen);
    if (status < 0) {
        APP_LOGE("compress return error: %{public}d", status);
        return ZlibBusinessError(status);
    }
    param->outStatus = status;
    param->outDestLen = static_cast<int64_t>(destLen);
    return 0;
}

int32_t CjZipEntity::Compress2(ZipCompressParam* param)
{
    if (param->destBuf == nullptr || param->srcBuf == nullptr) {
        APP_LOGE("destBuf or srcBuf is nullptr");
        return ERR_ZLIB_INTERNAL_STRUCT_ERROR;
    }
    uLong destLen = static_cast<uLong>(param->destBufLen);
    int32_t status = compress2(static_cast<Bytef*>(param->destBuf), &destLen, static_cast<Bytef*>(param->srcBuf),
        param->srcBufLen, param->level);
    if (status < 0) {
        APP_LOGE("compress2 return error: %{public}d", status);
        return ZlibBusinessError(status);
    }
    param->outStatus = status;
    param->outDestLen = static_cast<int64_t>(destLen);
    return 0;
}

int32_t CjZipEntity::CompressBound(int32_t sourceLen)
{
    return static_cast<int32_t>(compressBound(sourceLen));
}

int32_t CjZipEntity::UnCompress(ZipCompressParam* param)
{
    if (param->destBuf == nullptr || param->srcBuf == nullptr) {
        APP_LOGE("destBuf or srcBuf is nullptr");
        return ERR_ZLIB_INTERNAL_STRUCT_ERROR;
    }
    uLong destLen = static_cast<uLong>(param->destBufLen);
    int32_t status =
        uncompress(static_cast<Bytef*>(param->destBuf), &destLen, static_cast<Bytef*>(param->srcBuf), param->srcBufLen);
    if (status < 0) {
        APP_LOGE("uncompress return error: %{public}d", status);
        return ZlibBusinessError(status);
    }
    param->outStatus = status;
    param->outDestLen = static_cast<int64_t>(destLen);
    return 0;
}

void CjZipEntity::GetZStream(CZStream* cStrm, int32_t* errCode)
{
    if (zs == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("GetZStream zs is nullptr");
        return;
    }
    cStrm->availableIn = zs->avail_in;
    cStrm->totalIn = zs->total_in;
    cStrm->availableOut = zs->avail_out;
    cStrm->totalOut = zs->total_out;
    cStrm->dataType = zs->data_type;
    cStrm->adler = zs->adler;
}

int32_t CjZipEntity::Deflate(CZStream* cStrm, int32_t flush, int32_t* errCode)
{
    SetZStreamValue(cStrm);
    int32_t status = deflate(zs.get(), flush);
    if (status < 0) {
        APP_LOGE("deflate return error: %{public}d", status);
        *errCode = ZlibBusinessError(status);
    }
    return status;
}

int32_t CjZipEntity::DeflateEnd(CZStream* cStrm, int32_t* errCode)
{
    SetZStreamValue(cStrm);
    int32_t status = deflateEnd(zs.get());
    if (status < 0) {
        APP_LOGE("deflateEnd return error: %{public}d", status);
        *errCode = ZlibBusinessError(status);
    }
    return status;
}

int32_t CjZipEntity::DeflateInit2(CZStream* cStrm, DeflateInit2Param* param, int32_t* errCode)
{
    zs = std::make_unique<z_stream>();
    InitialZStream(cStrm);
    int32_t status =
        deflateInit2(zs.get(), param->level, param->method, param->windowBits, param->memLevel, param->strategy);
    if (status < 0) {
        APP_LOGE("deflateInit2 return error: %{public}d", status);
        *errCode = ZlibBusinessError(status);
    }
    return status;
}

int32_t CjZipEntity::Inflate(CZStream* cStrm, int32_t flush, int32_t* errCode)
{
    SetZStreamValue(cStrm);
    int32_t status = inflate(zs.get(), flush);
    if (status < 0) {
        APP_LOGE("inflate return error: %{public}d", status);
        *errCode = ZlibBusinessError(status);
    }
    return status;
}

int32_t CjZipEntity::InflateEnd(CZStream* cStrm, int32_t* errCode)
{
    SetZStreamValue(cStrm);
    int32_t status = inflateEnd(zs.get());
    if (status < 0) {
        APP_LOGE("inflateEnd return error: %{public}d", status);
        *errCode = ZlibBusinessError(status);
    }
    return status;
}

int32_t CjZipEntity::InflateInit(CZStream* cStrm, int32_t* errCode)
{
    zs = std::make_unique<z_stream>();
    InitialZStream(cStrm);
    int32_t status = inflateInit(zs.get());
    if (status < 0) {
        APP_LOGE("inflateInit return error: %{public}d", status);
        *errCode = ZlibBusinessError(status);
    }
    return status;
}

int32_t CjZipEntity::InflateInit2(CZStream* cStrm, int32_t windowBits, int32_t* errCode)
{
    zs = std::make_unique<z_stream>();
    InitialZStream(cStrm);
    int32_t status = inflateInit2(zs.get(), windowBits);
    if (status < 0) {
        APP_LOGE("inflateInit2 return error: %{public}d", status);
        *errCode = ZlibBusinessError(status);
    }
    return status;
}

void CjZipEntity::InitialZStream(CZStream* cStrm)
{
    if (cStrm->hasNextIn) {
        zs->next_in = reinterpret_cast<Bytef*>(cStrm->nextIn);
    }
    if (cStrm->hasAvailableIn) {
        zs->avail_in = cStrm->availableIn;
    }
    if (cStrm->hasTotalIn) {
        zs->total_in = cStrm->totalIn;
    }
    if (cStrm->hasNextOut) {
        zs->next_out = reinterpret_cast<Bytef*>(cStrm->nextOut);
    }
    if (cStrm->hasAvailableOut) {
        zs->avail_out = cStrm->availableOut;
    }
    if (cStrm->hasTotalOut) {
        zs->total_out = cStrm->totalOut;
    }
    if (cStrm->hasDataType) {
        zs->data_type = cStrm->dataType;
    }
    if (cStrm->hasAdler) {
        zs->adler = cStrm->adler;
    }
}

void CjZipEntity::SetZStreamValue(CZStream* cStrm)
{
    if (!zs) {
        zs = std::make_unique<z_stream>();
    }
    if (cStrm->hasNextIn) {
        zs->next_in = cStrm->nextIn;
    }
    if (cStrm->hasAvailableIn) {
        zs->avail_in = cStrm->availableIn;
    }
    if (cStrm->hasTotalIn) {
        zs->total_in = cStrm->totalIn;
    }
    if (cStrm->hasNextOut) {
        zs->next_out = cStrm->nextOut;
    }
    if (cStrm->hasAvailableOut) {
        zs->avail_out = cStrm->availableOut;
    }
    if (cStrm->hasTotalOut) {
        zs->total_out = cStrm->totalOut;
    }
    if (cStrm->hasDataType) {
        zs->data_type = cStrm->dataType;
    }
    if (cStrm->hasAdler) {
        zs->adler = cStrm->adler;
    }
}

ErrCode GetOriginalSize(PlatformFile zipFd, int64_t& originalSize)
{
    ZipReader reader;
    if (!reader.OpenFromPlatformFile(zipFd)) {
        APP_LOGE("Failed to open, not ZIP format or damaged");
        return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
    }
    int64_t totalSize = 0;
    while (reader.HasMore()) {
        if (!reader.OpenCurrentEntryInZip()) {
            APP_LOGE("Failed to open the current file in zip");
            return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
        }
        const FilePath& constEntryPath = reader.CurrentEntryInfo()->GetFilePath();
        FilePath entryPath = constEntryPath;
        if (reader.CurrentEntryInfo()->IsUnsafe()) {
            APP_LOGE("Found an unsafe file in zip");
            return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
        }
        totalSize += reader.CurrentEntryInfo()->GetOriginalSize();
        if (!reader.AdvanceToNextEntry()) {
            APP_LOGE("Failed to advance to the next file");
            return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
        }
    }
    originalSize = totalSize;
    return ERR_OK;
}

bool ZipFileIsValid(const std::string& srcFile)
{
    if ((srcFile.size() == 0) || FilePath::HasRelativePathBaseOnAPIVersion(srcFile)) {
        APP_LOGE("srcFile len is 0 or ../");
        return false;
    }
    if (!FilePathCheckValid(srcFile)) {
        APP_LOGE("FilePathCheckValid return false");
        return false;
    }
    FilePath srcFileDir(srcFile);
    if (!FilePath::PathIsValid(srcFileDir)) {
        APP_LOGE("PathIsValid return false");
        return false;
    }
    if (!FilePath::PathIsReadable(srcFileDir)) {
        APP_LOGE("PathIsReadable return false");
        return false;
    }
    return true;
}

ErrCode GetOriginalSize(const std::string& srcFile, int64_t& originalSize)
{
    if (!ZipFileIsValid(srcFile)) {
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }
    PlatformFile zipFd = open(srcFile.c_str(), S_IREAD, O_CREAT);
    if (zipFd == kInvalidPlatformFile) {
        APP_LOGE("Failed to open file, errno: %{public}d, %{public}s", errno, strerror(errno));
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }
    ErrCode ret = GetOriginalSize(zipFd, originalSize);
    close(zipFd);
    return ret;
}

extern "C" {
FFI_EXPORT int32_t FfiBundleManagerCompressFile(const char* inFile, const char* outFile, RetOptions options)
{
    std::string strInFile(inFile);
    std::string strOutFile(outFile);
    int32_t code = ERROR_CODE_ERRNO;
    OPTIONS cOptions;
    cOptions.level = static_cast<COMPRESS_LEVEL>(options.level);
    cOptions.memLevel = static_cast<MEMORY_LEVEL>(options.memLevel);
    cOptions.strategy = static_cast<COMPRESS_STRATEGY>(options.strategy);

    code = Zip(strInFile, strOutFile, cOptions);
    int32_t err = CommonFunc::ConvertErrCode(code);

    return err;
}

FFI_EXPORT int32_t FfiBundleManagerDeCompressFileOptions(const char* inFile, const char* outFile, RetOptions options)
{
    std::string strInFile(inFile);
    std::string strOutFile(outFile);
    int32_t code = ERROR_CODE_ERRNO;
    OPTIONS cOptions;
    cOptions.level = static_cast<COMPRESS_LEVEL>(options.level);
    cOptions.memLevel = static_cast<MEMORY_LEVEL>(options.memLevel);
    cOptions.strategy = static_cast<COMPRESS_STRATEGY>(options.strategy);

    code = UnZip(strInFile, strOutFile, cOptions);
    int32_t err = CommonFunc::ConvertErrCode(code);

    return err;
}

FFI_EXPORT int32_t FfiBundleManagerDeCompressFile(const char* inFile, const char* outFile)
{
    std::string strInFile(inFile);
    std::string strOutFile(outFile);
    int32_t code = ERROR_CODE_ERRNO;
    OPTIONS cOptions;

    code = UnZip(strInFile, strOutFile, cOptions);
    int32_t err = CommonFunc::ConvertErrCode(code);

    return err;
}

FFI_EXPORT void* FfiBundleManagerZipInstCreate()
{
    return new CjZipEntity();
}

FFI_EXPORT void FfiBundleManagerZipInstDestroy(void* ffiInst)
{
    delete static_cast<CjZipEntity*>(ffiInst);
}

FFI_EXPORT void FfiBundleManagerZipCompress(void* ffiInst, ZipCompressParam* param, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || param == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerZipCompress param check failed");
        return;
    }
    auto entity = static_cast<CjZipEntity*>(ffiInst);
    *errCode = entity->Compress(param);
    return;
}

FFI_EXPORT void FfiBundleManagerZipCompress2(void* ffiInst, ZipCompressParam* param, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || param == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerZipCompress2 param check failed");
        return;
    }
    auto entity = static_cast<CjZipEntity*>(ffiInst);
    *errCode = entity->Compress2(param);
    return;
}

FFI_EXPORT int32_t FfiBundleManagerZipCompressBound(void* ffiInst, int32_t sourceLen, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerZipCompressBound param check failed");
        return 0;
    }
    auto entity = static_cast<CjZipEntity*>(ffiInst);
    return entity->CompressBound(sourceLen);
}

FFI_EXPORT int32_t FfiBundleManagerZipDeflate(void* ffiInst, CZStream* cStrm, int32_t flush, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || cStrm == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerZipDeflate param check failed");
        return 0;
    }
    auto entity = static_cast<CjZipEntity*>(ffiInst);
    return entity->Deflate(cStrm, flush, errCode);
}

FFI_EXPORT int32_t FfiBundleManagerZipDeflateEnd(void* ffiInst, CZStream* cStrm, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || cStrm == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerZipDeflateEnd param check failed");
        return 0;
    }
    auto entity = static_cast<CjZipEntity*>(ffiInst);
    return entity->DeflateEnd(cStrm, errCode);
}

FFI_EXPORT int32_t FfiBundleManagerZipDeflateInit2(
    void* ffiInst, CZStream* cStrm, DeflateInit2Param* param, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || cStrm == nullptr || param == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerZipDeflateInit2 param check failed");
        return 0;
    }
    auto entity = static_cast<CjZipEntity*>(ffiInst);
    return entity->DeflateInit2(cStrm, param, errCode);
}

FFI_EXPORT void FfiBundleManagerZipGetZStream(void* ffiInst, CZStream* cStrm, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || cStrm == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerZipGetZStream param check failed");
        return;
    }
    auto entity = static_cast<CjZipEntity*>(ffiInst);
    return entity->GetZStream(cStrm, errCode);
}

FFI_EXPORT int32_t FfiBundleManagerZipInflate(void* ffiInst, CZStream* cStrm, int32_t flush, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || cStrm == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerZipInflate param check failed");
        return 0;
    }
    auto entity = static_cast<CjZipEntity*>(ffiInst);
    return entity->Inflate(cStrm, flush, errCode);
}

FFI_EXPORT int32_t FfiBundleManagerZipInflateEnd(void* ffiInst, CZStream* cStrm, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || cStrm == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerZipInflateEnd param check failed");
        return 0;
    }
    auto entity = static_cast<CjZipEntity*>(ffiInst);
    return entity->InflateEnd(cStrm, errCode);
}

FFI_EXPORT int32_t FfiBundleManagerZipInflateInit(void* ffiInst, CZStream* cStrm, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || cStrm == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerZipInflateInit param check failed");
        return 0;
    }
    auto entity = static_cast<CjZipEntity*>(ffiInst);
    return entity->InflateInit(cStrm, errCode);
}

FFI_EXPORT int32_t FfiBundleManagerZipInflateInit2(void* ffiInst, CZStream* cStrm, int32_t windowBits, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || cStrm == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerZipInflateInit2 param check failed");
        return 0;
    }
    auto entity = static_cast<CjZipEntity*>(ffiInst);
    return entity->InflateInit2(cStrm, windowBits, errCode);
}

FFI_EXPORT void FfiBundleManagerZipUnCompress(void* ffiInst, ZipCompressParam* param, int32_t* errCode)
{
    *errCode = 0;
    if (ffiInst == nullptr || param == nullptr) {
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        APP_LOGE("FfiBundleManagerZipUnCompress param check failed");
        return;
    }
    auto entity = static_cast<CjZipEntity*>(ffiInst);
    *errCode = entity->UnCompress(param);
    return;
}

FFI_EXPORT int32_t FfiBundleManagerCompressFiles(CArrString cInFiles, const char* cOutFile, RetOptions cOptions)
{
    if (cInFiles.head == nullptr || cInFiles.size <= 0 || cOutFile == nullptr) {
        APP_LOGE("FfiBundleManagerCompressFiles param check failed");
        return ERR_ZLIB_INTERNAL_STRUCT_ERROR;
    }
    std::vector<std::string> inFiles;
    inFiles.reserve(cInFiles.size);
    for (int64_t i = 0; i < cInFiles.size; i++) {
        if (cInFiles.head[i] == nullptr) {
            APP_LOGE("FfiBundleManagerCompressFiles param check failed");
            return ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        }
        inFiles.push_back(cInFiles.head[i]);
    }
    OPTIONS options;
    options.level = static_cast<COMPRESS_LEVEL>(cOptions.level);
    options.memLevel = static_cast<MEMORY_LEVEL>(cOptions.memLevel);
    options.strategy = static_cast<COMPRESS_STRATEGY>(cOptions.strategy);
    int32_t code = Zips(inFiles, cOutFile, options);
    return CommonFunc::ConvertErrCode(code);
}

FFI_EXPORT int64_t FfiBundleManagerGetOriginalSize(const char* compressedFile, int32_t* errCode)
{
    *errCode = 0;
    if (compressedFile == nullptr) {
        APP_LOGE("FfiBundleManagerGetOriginalSize param check failed");
        *errCode = ERR_ZLIB_INTERNAL_STRUCT_ERROR;
        return 0;
    }

    int64_t originalSize = 0;
    int32_t err = GetOriginalSize(compressedFile, originalSize);
    if (err != ERR_OK) {
        *errCode = CommonFunc::ConvertErrCode(err);
    }
    return originalSize;
}
}
} // LIBZIP
} // AppExecFwk
} // OHOS
