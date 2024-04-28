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

#ifndef INTERFACES_KITS_JS_ZIP_NAPI_COMMON_COMMON_FUNC_H
#define INTERFACES_KITS_JS_ZIP_NAPI_COMMON_COMMON_FUNC_H

#include "napi_func_arg.h"
#include "napi_value.h"
#include "uv.h"
#include "zlib.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {

struct HasZStreamMember {
    bool hasNextIn = false;
    bool hasAvailIn = false;
    bool hasTotalIn = false;
    bool hasNextOut = false;
    bool hasAvailOut = false;
    bool hasTotalOut = false;
    bool hasDataType = false;
    bool hasAdler = false;
};

struct HasGZFileMember {
    bool hasHave = false;
    bool hasNext = false;
    bool hasPos = false;
};

struct NapiParam {
    napi_valuetype type;
    std::string val;
};

struct CommonFunc {
    static bool SetZStreamValue(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, int64_t, void *, size_t> GetAdler32Arg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, unsigned long, unsigned long, int64_t> GetAdler32CombineArg(
        napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, int64_t, void *, size_t> GetCrc64Arg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, z_stream, HasZStreamMember> GetZstreamArg(napi_env env, napi_value zstream);
    static std::tuple<bool, z_stream, int32_t> GetInflateInitArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, z_stream, int32_t> GetDeflateInitArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, z_stream, int32_t, int32_t, int32_t, int32_t, int32_t> GetDeflateInit2Arg(
        napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, int32_t> GetDeflateArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, void *, size_t, void *, int64_t> GetCompressArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, void *, size_t, void *, size_t, int32_t> GetCompress2Arg(
        napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, void*, size_t, void*, int64_t> GetUnCompressArg(napi_env env, const NapiFuncArg& funcArg);
    static std::tuple<bool, int32_t> GetZErrorArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, void *, size_t> GetInflateSetDictionaryArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, int32_t> GetInflateArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, int32_t> GetInflateReset2Arg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, unsigned long, void*, size_t> GetInflateBackInitArg(
        napi_env env, const NapiFuncArg& funcArg);
    static std::tuple<bool, unsigned long, void *, size_t> GetInflateBackArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, int32_t, int32_t> GetInflatePrimeArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, int32_t> GetInflateValidateArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, int32_t> GetInflateUndermineArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, gz_header> GetInflateGetHeaderArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, gz_header> GetGZHeaderArg(napi_env env, napi_value argGZheader);
    static std::tuple<bool, int32_t, int32_t> UnwrapTwoIntParams(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, int32_t> UnwrapInt32Params(napi_env env, napi_value value);
    static std::tuple<bool, uint32_t> UnwrapInt64Params(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, int32_t, int32_t, int32_t, int32_t> UnwrapDeflateTuneParams(
        napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, void *, size_t> UnwrapArrayBufferParams(napi_env env, const NapiFuncArg &funcArg);

    static std::tuple<bool, void *, size_t> GzipUnwrapArrayBufferParams(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, std::unique_ptr<char[]>, std::unique_ptr<char[]>> GetGZOpenArg(
        napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, int32_t, std::unique_ptr<char[]>> GetGZDOpenArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, uint32_t> GetGZBufferArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, std::unique_ptr<char[]>, std::unique_ptr<char[]>> GetGZOpenWArg(
        napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, gzFile_s, HasGZFileMember> GetGZFileArg(napi_env env, napi_value argGZFile);
    static std::tuple<bool, void *, uint32_t> GetGZReadArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, void *, int64_t, int64_t> GetGZFReadArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, void *, int64_t> GetGZWriteArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, void *, int64_t, int64_t> GetGZFWriteArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, int32_t> GetGZPutCArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, std::unique_ptr<char[]>> GetGZPutSArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, int32_t, int32_t> GetGzSetParamsArg(napi_env env, const NapiFuncArg &funcArg);
    static void GetLogContent(std::string& formatStr, std::vector<NapiParam>& params, std::string& ret, uint32_t& pos);
    static void ParseLogContent(std::string& formatStr, std::vector<NapiParam>& params, std::string& logContent);
    static void ParseNapiValue(napi_env env, napi_value element, std::vector<NapiParam>& params);
    static bool ParseNapiValueFromArray(napi_env env, std::vector<NapiParam>& params, const NapiFuncArg& funcArg);
    static std::tuple<bool, std::unique_ptr<char[]>, std::unique_ptr<char[]>> GetGZPrintFArg(
        napi_env env, const NapiFuncArg& funcArg);
    static std::tuple<bool, void *, size_t> GetGZGetSArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, int64_t, int32_t> GetGZSeekArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, int32_t> GetGZUnGetCArg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, uint32_t> SetGZFlushArg(napi_env env, const NapiFuncArg &funcArg);
};
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // INTERFACES_KITS_JS_ZIP_NAPI_COMMON_COMMON_FUNC_H