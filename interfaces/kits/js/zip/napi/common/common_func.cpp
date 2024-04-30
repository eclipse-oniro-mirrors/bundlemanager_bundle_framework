/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "common_func.h"

#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "app_log_wrapper.h"
#include "gzip_entity.h"
#include "napi_class.h"
#include "napi_business_error.h"
#include "zip_entity.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
using namespace std;

static constexpr int MIN_NUMBER = 1;
static constexpr int MIN_ASCII = 0;
static constexpr int MAX_ASCII = 255;

tuple<bool, int64_t, void *, size_t> CommonFunc::GetAdler32Arg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    int64_t adler = 0U;

    // The first argument
    NapiValue adlerNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, adler) = adlerNVal.ToInt64();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, nullptr, 0};
    }

    // The second argument
    NapiValue bufNVal(env, funcArg[ArgumentPosition::SECOND]);
    void *buf = nullptr;
    size_t bufLen = 0;
    tie(succ, buf, bufLen) = bufNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, nullptr, 0};
    }

    return {true, adler, buf, bufLen};
}

tuple<bool, int64_t, void *, size_t> CommonFunc::GetCrc64Arg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    int64_t crc64 = 0U;

    // The first argument
    NapiValue crc64NVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, crc64) = crc64NVal.ToInt64();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, nullptr, 0};
    }

    // The second argument
    NapiValue bufNVal(env, funcArg[ArgumentPosition::SECOND]);
    void *buf = nullptr;
    size_t bufLen = 0;
    tie(succ, buf, bufLen) = bufNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, nullptr, 0};
    }

    return {true, crc64, buf, bufLen};
}

tuple<bool, unsigned long, unsigned long, int64_t> CommonFunc::GetAdler32CombineArg(
    napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    uint64_t adler1 = 0U;
    uint64_t adler2 = 0U;
    int64_t len = 0;

    NapiValue adler1NVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, adler1) = adler1NVal.ToInt64();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0, 0};
    }

    NapiValue adler2NVal(env, funcArg[ArgumentPosition::SECOND]);
    tie(succ, adler2) = adler2NVal.ToInt64();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0, 0};
    }

    NapiValue bufLenNVal(env, funcArg[ArgumentPosition::THIRD]);
    tie(succ, len) = bufLenNVal.ToInt64();
    if (!succ || len < 0) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0, 0};
    }
    return {true, adler1, adler2, len};
}

static void SetZStreamOutValue(HasZStreamMember &hasZStreamMember, ZipEntity *zipEntity, z_stream &zs)
{
    if (hasZStreamMember.hasNextOut) {
        zipEntity->zs.get()->next_out = zs.next_out;
    }
    if (hasZStreamMember.hasAvailOut) {
        zipEntity->zs.get()->avail_out = zs.avail_out;
    }
    if (hasZStreamMember.hasTotalOut) {
        zipEntity->zs.get()->total_out = zs.total_out;
    }
    if (hasZStreamMember.hasDataType) {
        zipEntity->zs.get()->data_type = zs.data_type;
    }
    if (hasZStreamMember.hasAdler) {
        zipEntity->zs.get()->adler = zs.adler;
    }
}

bool CommonFunc::SetZStreamValue(napi_env env, const NapiFuncArg &funcArg)
{
    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return false;
    }

    bool succ = false;
    z_stream zs = {};
    HasZStreamMember hasZStreamMember;
    tie(succ, zs, hasZStreamMember) = CommonFunc::GetZstreamArg(env, funcArg[ArgumentPosition::FIRST]);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return succ;
    }

    if (!zipEntity->zs) {
        zipEntity->zs = std::make_unique<z_stream>();
    }

    if (hasZStreamMember.hasNextIn) {
        zipEntity->zs.get()->next_in = zs.next_in;
    }
    if (hasZStreamMember.hasAvailIn) {
        zipEntity->zs.get()->avail_in = zs.avail_in;
    }
    if (hasZStreamMember.hasTotalIn) {
        zipEntity->zs.get()->total_in = zs.total_in;
    }

    SetZStreamOutValue(hasZStreamMember, zipEntity, zs);
    return succ;
}

static bool GetZStreamInValue(napi_env env, NapiValue zstreamNVal, HasZStreamMember &hasZStreamMember, z_stream &zs)
{
    bool succ = false;
    if (zstreamNVal.HasProp("nextIn") && !zstreamNVal.GetProp("nextIn").TypeIs(napi_undefined)) {
        void *buf = nullptr;
        size_t bufLen = 0;
        tie(succ, buf, bufLen) = zstreamNVal.GetProp("nextIn").ToArrayBuffer();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return false;
        }
        zs.next_in = reinterpret_cast<Bytef *>(buf);
        hasZStreamMember.hasNextIn = true;
    }

    if (zstreamNVal.HasProp("availableIn") && !zstreamNVal.GetProp("availableIn").TypeIs(napi_undefined)) {
        uint32_t availableIn = 0U;
        tie(succ, availableIn) = zstreamNVal.GetProp("availableIn").ToInt32();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return false;
        }
        zs.avail_in = availableIn;
        hasZStreamMember.hasAvailIn = true;
    }

    if (zstreamNVal.HasProp("totalIn") && !zstreamNVal.GetProp("totalIn").TypeIs(napi_undefined)) {
        uint64_t totalIn = 0U;
        tie(succ, totalIn) = zstreamNVal.GetProp("totalIn").ToInt64();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return false;
        }
        zs.total_in = totalIn;
        hasZStreamMember.hasTotalIn = true;
    }

    return true;
}

static bool GetZStreamOtherValue(napi_env env, NapiValue zstreamNVal, HasZStreamMember &hasZStreamMember, z_stream &zs)
{
    bool succ = false;
    if (zstreamNVal.HasProp("dataType") && !zstreamNVal.GetProp("dataType").TypeIs(napi_undefined)) {
        int32_t dataType = 0;
        tie(succ, dataType) = zstreamNVal.GetProp("dataType").ToInt32();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return false;
        }
        zs.data_type = dataType;
        hasZStreamMember.hasDataType = true;
    }

    if (zstreamNVal.HasProp("adler") && !zstreamNVal.GetProp("adler").TypeIs(napi_undefined)) {
        uint64_t adler = 0;
        tie(succ, adler) = zstreamNVal.GetProp("adler").ToInt64();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return false;
        }
        zs.adler = adler;
        hasZStreamMember.hasAdler = true;
    }

    return true;
}

std::tuple<bool, z_stream, HasZStreamMember> CommonFunc::GetZstreamArg(napi_env env, napi_value zstream)
{
    z_stream zs = {};
    bool succ = false;
    NapiValue zstreamNVal(env, zstream);
    HasZStreamMember hasZStreamMember = {};

    succ = GetZStreamInValue(env, zstreamNVal, hasZStreamMember, zs);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return { false, {}, {} };
    }

    if (zstreamNVal.HasProp("nextOut") && !zstreamNVal.GetProp("nextOut").TypeIs(napi_undefined)) {
        void *buf = nullptr;
        size_t bufLen = 0;
        tie(succ, buf, bufLen) = zstreamNVal.GetProp("nextOut").ToArrayBuffer();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return {false, {}, {}};
        }
        zs.next_out = reinterpret_cast<Bytef *>(buf);
        hasZStreamMember.hasNextOut = true;
    }

    if (zstreamNVal.HasProp("availableOut") && !zstreamNVal.GetProp("availableOut").TypeIs(napi_undefined)) {
        uint32_t availableOut = 0U;
        tie(succ, availableOut) = zstreamNVal.GetProp("availableOut").ToInt32();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return {false, {}, {}};
        }
        zs.avail_out = availableOut;
        hasZStreamMember.hasAvailOut = true;
    }

    if (zstreamNVal.HasProp("totalOut") && !zstreamNVal.GetProp("totalOut").TypeIs(napi_undefined)) {
        uint64_t totalOut = 0U;
        tie(succ, totalOut) = zstreamNVal.GetProp("totalOut").ToInt64();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return {false, {}, {}};
        }
        zs.total_out = totalOut;
        hasZStreamMember.hasTotalOut = true;
    }

    succ = GetZStreamOtherValue(env, zstreamNVal, hasZStreamMember, zs);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return { false, {}, {} };
    }

    return {true, zs, hasZStreamMember};
}

static bool GetGZHeadValue(napi_env env, NapiValue &gzHeaderNVal, gz_header &gzHeader)
{
    bool succ = false;
    if (gzHeaderNVal.HasProp("isText") && !gzHeaderNVal.GetProp("isText").TypeIs(napi_undefined)) {
        bool text = false;
        tie(succ, text) = gzHeaderNVal.GetProp("isText").ToBool();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return false;
        }
        gzHeader.text = text;
    }

    if (gzHeaderNVal.HasProp("time") && !gzHeaderNVal.GetProp("time").TypeIs(napi_undefined)) {
        uint64_t time = 0U;
        tie(succ, time) = gzHeaderNVal.GetProp("time").ToInt64();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return false;
        }
        gzHeader.time = time;
    }

    if (gzHeaderNVal.HasProp("xflags") && !gzHeaderNVal.GetProp("xflags").TypeIs(napi_undefined)) {
        int32_t xflags = 0;
        tie(succ, xflags) = gzHeaderNVal.GetProp("xflags").ToInt32();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return false;
        }
        gzHeader.xflags = xflags;
    }

    if (gzHeaderNVal.HasProp("os") && !gzHeaderNVal.GetProp("os").TypeIs(napi_undefined)) {
        int32_t os = 0;
        tie(succ, os) = gzHeaderNVal.GetProp("os").ToInt32();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return false;
        }
        gzHeader.os = os;
    }
    return true;
}

static bool UnwrapGZHeadValue(napi_env env, NapiValue &gzHeaderNVal, gz_header &gzHeader)
{
    bool succ = false;
    if (gzHeaderNVal.HasProp("extra") && !gzHeaderNVal.GetProp("extra").TypeIs(napi_undefined)) {
        void *extra = nullptr;
        size_t extraLen = 0;
        tie(succ, extra, extraLen) = gzHeaderNVal.GetProp("extra").ToArrayBuffer();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return false;
        }
        gzHeader.extra = reinterpret_cast<Bytef *>(extra);
    }

    if (gzHeaderNVal.HasProp("done") && !gzHeaderNVal.GetProp("done").TypeIs(napi_undefined)) {
        bool done = false;
        tie(succ, done) = gzHeaderNVal.GetProp("done").ToBool();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return false;
        }
        gzHeader.done = done;
    }

    if (gzHeaderNVal.HasProp("hcrc") && !gzHeaderNVal.GetProp("hcrc").TypeIs(napi_undefined)) {
        bool hcrc = false;
        tie(succ, hcrc) = gzHeaderNVal.GetProp("hcrc").ToBool();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return false;
        }
        gzHeader.hcrc = hcrc;
    }

    return true;
}

std::tuple<bool, gz_header> CommonFunc::GetGZHeaderArg(napi_env env, napi_value argGZheader)
{
    bool succ = false;
    NapiValue gzHeaderNVal(env, argGZheader);
    gz_header gzHeader = {};

    succ = GetGZHeadValue(env, gzHeaderNVal, gzHeader);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return { false, {} };
    }

    if (gzHeaderNVal.HasProp("extraLen") && !gzHeaderNVal.GetProp("extraLen").TypeIs(napi_undefined)) {
        uint32_t extraLen = 0U;
        tie(succ, extraLen) = gzHeaderNVal.GetProp("extraLen").ToInt32();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return {false, {}};
        }
        gzHeader.extra_len = extraLen;
    }

    if (gzHeaderNVal.HasProp("name") && !gzHeaderNVal.GetProp("name").TypeIs(napi_undefined)) {
        void *name = nullptr;
        size_t nameLen = 0;
        tie(succ, name, nameLen) = gzHeaderNVal.GetProp("name").ToArrayBuffer();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return {false, {}};
        }
        gzHeader.name = reinterpret_cast<Bytef *>(name);
    }

    if (gzHeaderNVal.HasProp("comment") && !gzHeaderNVal.GetProp("comment").TypeIs(napi_undefined)) {
        void *comment = nullptr;
        size_t commentLen = 0;
        tie(succ, comment, commentLen) = gzHeaderNVal.GetProp("comment").ToArrayBuffer();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return {false, {}};
        }
        gzHeader.comment = reinterpret_cast<Bytef *>(comment);
    }

    succ = UnwrapGZHeadValue(env, gzHeaderNVal, gzHeader);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return { false, {} };
    }

    return {true, gzHeader};
}

std::tuple<bool, z_stream, int32_t> CommonFunc::GetInflateInitArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;

    // The first argument
    z_stream zs = {};
    HasZStreamMember hasZStreamMember = {};
    tie(succ, zs, hasZStreamMember) = GetZstreamArg(env, funcArg[ArgumentPosition::FIRST]);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, {}, 0};
    }

    // The second argument
    NapiValue bufNVal(env, funcArg[ArgumentPosition::SECOND]);
    int32_t windowBits = 0;
    tie(succ, windowBits) = bufNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, {}, 0};
    }

    return {true, zs, windowBits};
}

std::tuple<bool, z_stream, int32_t> CommonFunc::GetDeflateInitArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;

    // The first argument
    z_stream zs = {};
    HasZStreamMember hasZStreamMember = {};
    tie(succ, zs, hasZStreamMember) = GetZstreamArg(env, funcArg[ArgumentPosition::FIRST]);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, {}, 0};
    }

    // The second argument
    NapiValue levelNVal(env, funcArg[ArgumentPosition::SECOND]);
    int32_t level = 0;
    tie(succ, level) = levelNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, {}, 0};
    }

    return {true, zs, level};
}

std::tuple<bool, z_stream, int32_t, int32_t, int32_t, int32_t, int32_t> CommonFunc::GetDeflateInit2Arg(
    napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;

    // The first argument
    z_stream zs = {};
    HasZStreamMember hasZStreamMember = {};
    tie(succ, zs, hasZStreamMember) = GetZstreamArg(env, funcArg[ArgumentPosition::FIRST]);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, {}, 0, 0, 0, 0, 0};
    }

    // The second argument
    NapiValue levelNVal(env, funcArg[ArgumentPosition::SECOND]);
    int32_t level = 0;
    tie(succ, level) = levelNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, {}, 0, 0, 0, 0, 0};
    }

    // The third argument
    NapiValue methodNVal(env, funcArg[ArgumentPosition::THIRD]);
    int32_t method = 0;
    tie(succ, method) = methodNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, {}, 0, 0, 0, 0, 0};
    }

    // The fourth argument
    NapiValue windowBitsNVal(env, funcArg[ArgumentPosition::FOURTH]);
    int32_t windowBits = 0;
    tie(succ, windowBits) = windowBitsNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, {}, 0, 0, 0, 0, 0};
    }

    // The fifth argument
    NapiValue memLevelNVal(env, funcArg[ArgumentPosition::FIFTH]);
    int32_t memLevel = 0;
    tie(succ, memLevel) = memLevelNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, {}, 0, 0, 0, 0, 0};
    }

    // The sixth argument
    NapiValue strategyNVal(env, funcArg[ArgumentPosition::SIXTH]);
    int32_t strategy = 0;
    tie(succ, strategy) = strategyNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, {}, 0, 0, 0, 0, 0};
    }

    return {true, zs, level, method, windowBits, memLevel, strategy};
}

std::tuple<bool, int32_t> CommonFunc::GetDeflateArg(napi_env env, const NapiFuncArg &funcArg)
{
    // The first argument
    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return {false, 0};
    }

    // The second argument
    NapiValue flushNVal(env, funcArg[ArgumentPosition::SECOND]);
    int32_t flush = 0;
    tie(succ, flush) = flushNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }

    return {true, flush};
}

std::tuple<bool, void *, size_t, void *, int64_t> CommonFunc::GetCompressArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    void *dest = nullptr;
    size_t destLen = 0;
    NapiValue destNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, dest, destLen) = destNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0, nullptr, 0};
    }

    void *source = nullptr;
    size_t sourceLen = 0;
    NapiValue sourceNVal(env, funcArg[ArgumentPosition::SECOND]);
    tie(succ, source, sourceLen) = sourceNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0, nullptr, 0};
    }

    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        int64_t sourceLenIn = 0;
        NapiValue sourceLenNVal(env, funcArg[ArgumentPosition::THIRD]);
        tie(succ, sourceLenIn) = sourceLenNVal.ToInt64();
        if (!succ || sourceLenIn < 0) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return { false, nullptr, 0, nullptr, 0 };
        }
        sourceLen = sourceLenIn;
    }

    return {true, dest, destLen, source, sourceLen};
}

std::tuple<bool, void *, size_t, void *, size_t, int32_t> CommonFunc::GetCompress2Arg(
    napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    void *dest = nullptr;
    size_t destLen = 0;
    NapiValue destNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, dest, destLen) = destNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0, nullptr, 0, 0};
    }

    void *source = nullptr;
    size_t sourceLen = 0;
    NapiValue sourceNVal(env, funcArg[ArgumentPosition::SECOND]);
    tie(succ, source, sourceLen) = sourceNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0, nullptr, 0, 0};
    }

    int32_t level = 0;
    NapiValue levelNVal(env, funcArg[ArgumentPosition::THIRD]);
    tie(succ, level) = levelNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0, nullptr, 0, 0};
    }

    if (funcArg.GetArgc() == ArgumentCount::FOUR) {
        int64_t sourceLenIn = 0;
        NapiValue sourceLenNVal(env, funcArg[ArgumentPosition::FOURTH]);
        tie(succ, sourceLenIn) = sourceLenNVal.ToInt64();
        if (!succ || sourceLenIn < 0) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return {false, nullptr, 0, nullptr, 0, 0};
        }
        sourceLen = sourceLenIn;
    }

    return {true, dest, destLen, source, sourceLen, level};
}

std::tuple<bool, void *, size_t, void *, int64_t> CommonFunc::GetUnCompressArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    void *dest = nullptr;
    size_t destLen = 0;
    NapiValue destNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, dest, destLen) = destNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0, nullptr, 0};
    }

    void *source = nullptr;
    size_t sourceLen = 0;
    NapiValue sourceNVal(env, funcArg[ArgumentPosition::SECOND]);
    tie(succ, source, sourceLen) = sourceNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0, nullptr, 0};
    }

    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        int64_t sourceLenIn = 0;
        NapiValue sourceLenNVal(env, funcArg[ArgumentPosition::THIRD]);
        tie(succ, sourceLenIn) = sourceLenNVal.ToInt64();
        if (!succ || sourceLenIn < 0) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return { false, nullptr, 0, nullptr, 0 };
        }
        sourceLen = sourceLenIn;
    }

    return {true, dest, destLen, source, sourceLen};
}

std::tuple<bool, int32_t> CommonFunc::GetZErrorArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    NapiValue errNVal(env, funcArg[ArgumentPosition::FIRST]);
    int32_t zlibError = 0;
    tie(succ, zlibError) = errNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }

    return {true, zlibError};
}

std::tuple<bool, void *, size_t> CommonFunc::GetInflateSetDictionaryArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0};
    }

    NapiValue bufNVal(env, funcArg[ArgumentPosition::SECOND]);
    void *buf = nullptr;
    size_t bufLen = 0;
    tie(succ, buf, bufLen) = bufNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0};
    }

    return {true, buf, bufLen};
}

std::tuple<bool, int32_t> CommonFunc::GetInflateArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }

    NapiValue flushNVal(env, funcArg[ArgumentPosition::SECOND]);
    int32_t flush = 0;
    tie(succ, flush) = flushNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }

    return {true, flush};
}

std::tuple<bool, int32_t> CommonFunc::GetInflateReset2Arg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }

    NapiValue flushNVal(env, funcArg[ArgumentPosition::SECOND]);
    int32_t flush = 0;
    tie(succ, flush) = flushNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }

    return {true, flush};
}

std::tuple<bool, unsigned long, void*, size_t> CommonFunc::GetInflateBackInitArg(
    napi_env env, const NapiFuncArg& funcArg)
{
    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, nullptr, 0};
    }

    int32_t windowBits = 0;
    NapiValue windowBitsNVal(env, funcArg[ArgumentPosition::SECOND]);
    tie(succ, windowBits) = windowBitsNVal.ToInt64();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, nullptr, 0};
    }

    NapiValue bufNVal(env, funcArg[ArgumentPosition::THIRD]);
    void *buf = nullptr;
    size_t bufLen = 0;
    tie(succ, buf, bufLen) = bufNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, nullptr, 0};
    }

    return {true, windowBits, buf, bufLen};
}

std::tuple<bool, int32_t, int32_t> CommonFunc::GetInflatePrimeArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0};
    }

    NapiValue bitsNVal(env, funcArg[ArgumentPosition::SECOND]);
    int32_t bits = 0;
    tie(succ, bits) = bitsNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0};
    }

    // The third argument
    NapiValue valueNVal(env, funcArg[ArgumentPosition::THIRD]);
    int32_t value = 0;
    tie(succ, value) = valueNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0};
    }
    return {true, bits, value};
}

std::tuple<bool, int32_t> CommonFunc::GetInflateValidateArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }

    NapiValue checkNVal(env, funcArg[ArgumentPosition::SECOND]);
    int32_t check = 0;
    tie(succ, check) = checkNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }

    return {true, check};
}

std::tuple<bool, int32_t> CommonFunc::GetInflateUndermineArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }

    NapiValue subvertNVal(env, funcArg[ArgumentPosition::SECOND]);
    int32_t subvert = 0;
    tie(succ, subvert) = subvertNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }

    return {true, subvert};
}

std::tuple<bool, gz_header> CommonFunc::GetInflateGetHeaderArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, {}};
    }

    gz_header gzHeader = {};
    tie(succ, gzHeader) = CommonFunc::GetGZHeaderArg(env, funcArg[ArgumentPosition::SECOND]);
    if (!succ) {
        return {false, {}};
    }

    return {true, gzHeader};
}

std::tuple<bool, int32_t> CommonFunc::UnwrapInt32Params(napi_env env, napi_value value)
{
    bool succ = false;

    // The first argument
    NapiValue valueNVal(env, value);
    int32_t valueInt = 0;
    tie(succ, valueInt) = valueNVal.ToInt32();
    if (!succ || valueInt < 0) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }

    return {true, valueInt};
}

std::tuple<bool, uint32_t> CommonFunc::UnwrapInt64Params(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, {}};
    }

    // The first argument
    NapiValue valueNVal(env, funcArg[ArgumentPosition::SECOND]);
    int64_t valueInt = 0;
    tie(succ, valueInt) = valueNVal.ToInt64();
    if (!succ || valueInt < 0) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }

    return {true, valueInt};
}

std::tuple<bool, int32_t, int32_t, int32_t, int32_t> CommonFunc::UnwrapDeflateTuneParams(
    napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return {false, 0, 0, 0, 0};
    }

    // The first argument
    NapiValue goodLengthNVal(env, funcArg[ArgumentPosition::SECOND]);
    int32_t goodLength = 0;
    tie(succ, goodLength) = goodLengthNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0, 0, 0};
    }

    NapiValue maxLazyNVal(env, funcArg[ArgumentPosition::THIRD]);
    int32_t maxLazy = 0;
    tie(succ, maxLazy) = maxLazyNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0, 0, 0};
    }

    NapiValue niceLengthNVal(env, funcArg[ArgumentPosition::FOURTH]);
    int32_t niceLength = 0;
    tie(succ, niceLength) = niceLengthNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0, 0, 0};
    }

    NapiValue maxChainNVal(env, funcArg[ArgumentPosition::FIFTH]);
    int32_t maxChain = 0;
    tie(succ, maxChain) = maxChainNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0, 0, 0};
    }

    return {true, maxLazy, maxLazy, niceLength, maxChain};
}

std::tuple<bool, void *, size_t> CommonFunc::UnwrapArrayBufferParams(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return {false, nullptr, 0};
    }

    NapiValue bufNVal(env, funcArg[ArgumentPosition::SECOND]);
    void *buf = nullptr;
    size_t bufLen = 0;
    tie(succ, buf, bufLen) = bufNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0};
    }

    return {true, buf, bufLen};
}

std::tuple<bool, int32_t, int32_t> CommonFunc::UnwrapTwoIntParams(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return {false, 0, 0};
    }

    // The first argument
    NapiValue firstNVal(env, funcArg[ArgumentPosition::SECOND]);
    int32_t oneInt = 0;
    tie(succ, oneInt) = firstNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0};
    }

    // The second argument
    NapiValue secondNVal(env, funcArg[ArgumentPosition::THIRD]);
    int32_t twoInt = 0;
    tie(succ, twoInt) = secondNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0};
    }

    return {true, oneInt, twoInt};
}

std::tuple<bool, void *, size_t> CommonFunc::GzipUnwrapArrayBufferParams(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    void *buf = nullptr;
    size_t bufLen = 0;
    NapiValue bufNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, buf, bufLen) = bufNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0};
    }

    return {true, buf, bufLen};
}

std::tuple<bool, std::unique_ptr<char[]>, std::unique_ptr<char[]>> CommonFunc::GetGZOpenArg(
    napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    std::unique_ptr<char[]> path = nullptr;
    size_t bufferLen = 0;
    NapiValue pathNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, path, bufferLen) = pathNVal.ToUTF8String();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, nullptr};
    }

    std::unique_ptr<char[]> mode = nullptr;
    bufferLen = 0;
    NapiValue modeNVal(env, funcArg[ArgumentPosition::SECOND]);
    tie(succ, mode, bufferLen) = modeNVal.ToUTF8String();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, nullptr};
    }
    return {true, std::move(path), std::move(mode)};
}

std::tuple<bool, int32_t, std::unique_ptr<char[]>> CommonFunc::GetGZDOpenArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    int32_t fd = -1;
    NapiValue fdNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, fd) = fdNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, -1, nullptr};
    }

    std::unique_ptr<char[]> mode = nullptr;
    size_t bufferLen = 0;
    NapiValue modeNVal(env, funcArg[ArgumentPosition::SECOND]);
    tie(succ, mode, bufferLen) = modeNVal.ToUTF8String();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, -1, nullptr};
    }
    return {true, fd, std::move(mode)};
}

std::tuple<bool, gzFile_s, HasGZFileMember> CommonFunc::GetGZFileArg(napi_env env, napi_value argGZFile)
{
    gzFile_s gzs = {};
    bool succ = false;
    NapiValue gzFileNVal(env, argGZFile);
    HasGZFileMember hasGZFileMember = {};

    if (gzFileNVal.HasProp("have") && !gzFileNVal.GetProp("have").TypeIs(napi_undefined)) {
        uint32_t have = 0;
        tie(succ, have) = gzFileNVal.GetProp("have").ToUint32();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return {false, {}, {}};
        }
        gzs.have = have;
        hasGZFileMember.hasHave = true;
    }

    if (gzFileNVal.HasProp("next") && !gzFileNVal.GetProp("next").TypeIs(napi_undefined)) {
        void *buf = nullptr;
        size_t bufLen = 0;
        tie(succ, buf, bufLen) = gzFileNVal.GetProp("next").ToArrayBuffer();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return {false, {}, {}};
        }
        gzs.next = reinterpret_cast<Bytef *>(buf);
        hasGZFileMember.hasNext = true;
    }

    if (gzFileNVal.HasProp("pos") && !gzFileNVal.GetProp("pos").TypeIs(napi_undefined)) {
        uint64_t pos = 0U;
        tie(succ, pos) = gzFileNVal.GetProp("pos").ToInt64();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return {false, {}, {}};
        }
        gzs.pos = pos;
        hasGZFileMember.hasPos = true;
    }
    return {true, gzs, hasGZFileMember};
}

std::tuple<bool, std::unique_ptr<char[]>, std::unique_ptr<char[]>> CommonFunc::GetGZOpenWArg(
    napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    std::unique_ptr<char[]> path = nullptr;
    size_t bufferLen = 0;
    NapiValue pathNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, path, bufferLen) = pathNVal.ToUTF8String();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, nullptr};
    }

    std::unique_ptr<char[]> mode = nullptr;
    bufferLen = 0;
    NapiValue modeNVal(env, funcArg[ArgumentPosition::SECOND]);
    tie(succ, mode, bufferLen) = modeNVal.ToUTF8String();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, nullptr};
    }
    return {true, std::move(path), std::move(mode)};
}

std::tuple<bool, uint32_t> CommonFunc::GetGZBufferArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    uint32_t size = 0;
    NapiValue sizeNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, size) = sizeNVal.ToUint32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }
    return {true, size};
}

std::tuple<bool, void *, uint32_t> CommonFunc::GetGZReadArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    void *buf = nullptr;
    size_t len = 0;
    tie(succ, buf, len) = GzipUnwrapArrayBufferParams(env, funcArg);
    if (!succ || len == 0) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0};
    }
    return {true, buf, len};
}

std::tuple<bool, void *, int64_t, int64_t> CommonFunc::GetGZFReadArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    void *buf = nullptr;
    size_t len = 0;
    tie(succ, buf, len) = GzipUnwrapArrayBufferParams(env, funcArg);
    if (!succ || len == 0) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0, 0};
    }

    int64_t size = 0;
    NapiValue sizeNVal(env, funcArg[ArgumentPosition::SECOND]);
    tie(succ, size) = sizeNVal.ToInt64();
    if (!succ || size < 0) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0, 0};
    }

    int64_t nitems = 0;
    NapiValue nitemsNVal(env, funcArg[ArgumentPosition::THIRD]);
    tie(succ, nitems) = nitemsNVal.ToInt64();
    if (!succ || nitems < 0) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0, 0};
    }
    return {true, buf, size, nitems};
}

std::tuple<bool, void *, int64_t> CommonFunc::GetGZWriteArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    void *buf = nullptr;
    size_t bufLen = 0;
    tie(succ, buf, bufLen) = GzipUnwrapArrayBufferParams(env, funcArg);
    if (!succ || bufLen == 0) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0};
    }
    int64_t len = 0;
    NapiValue sizeNVal(env, funcArg[ArgumentPosition::SECOND]);
    tie(succ, len) = sizeNVal.ToInt64();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0};
    }
    return {true, buf, len};
}

std::tuple<bool, void *, int64_t, int64_t> CommonFunc::GetGZFWriteArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    void *buf = nullptr;
    size_t len = 0;
    tie(succ, buf, len) = GzipUnwrapArrayBufferParams(env, funcArg);
    if (!succ || len == 0) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0, 0};
    }

    int64_t size = 0;
    NapiValue sizeNVal(env, funcArg[ArgumentPosition::SECOND]);
    tie(succ, size) = sizeNVal.ToInt64();
    if (!succ || size < 0) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0, 0};
    }

    int64_t nitems = 0;
    NapiValue nitemsNVal(env, funcArg[ArgumentPosition::THIRD]);
    tie(succ, nitems) = nitemsNVal.ToInt64();
    if (!succ || nitems < 0) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0, 0};
    }
    return {true, buf, size, nitems};
}

std::tuple<bool, int32_t> CommonFunc::GetGZPutCArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    int32_t c = 0;
    NapiValue cNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, c) = cNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }
    if (c < MIN_ASCII || c > MAX_ASCII) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }
    return {true, c};
}

std::tuple<bool, std::unique_ptr<char[]>> CommonFunc::GetGZPutSArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    std::unique_ptr<char[]> s = nullptr;
    size_t len = 0;
    NapiValue sNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, s, len) = sNVal.ToUTF8String();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr};
    }
    return {true, std::move(s)};
}

std::tuple<bool, int32_t, int32_t> CommonFunc::GetGzSetParamsArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    int32_t level = 0;
    NapiValue levelNapiValue(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, level) = levelNapiValue.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, -1, -1};
    }

    int32_t strategy = 0;
    NapiValue strategyNapiValue(env, funcArg[ArgumentPosition::SECOND]);
    tie(succ, strategy) = strategyNapiValue.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, -1, -1};
    }
    return {true, level, strategy};
}

void CommonFunc::GetLogContent(string &formatStr, vector<NapiParam> &params, string &ret, uint32_t &pos)
{
    uint32_t count = 0;
    for (; pos < formatStr.size(); ++pos) {
        if (count >= params.size()) {
            break;
        }
        if (formatStr[pos] != '%') {
            ret += formatStr[pos];
            continue;
        }
        if (pos + 1 >= formatStr.size()) {
            break;
        }
        switch (formatStr[pos + 1]) {
            case 'd':
            case 'i':
                if (params[count].type == napi_number || params[count].type == napi_bigint) {
                    ret += params[count].val;
                }
                count++;
                ++pos;
                break;
            case 's':
                if (params[count].type == napi_string || params[count].type == napi_undefined ||
                    params[count].type == napi_boolean || params[count].type == napi_null) {
                    ret += params[count].val;
                }
                count++;
                ++pos;
                break;
            case 'O':
            case 'o':
                if (params[count].type == napi_object) {
                    ret += params[count].val;
                }
                count++;
                ++pos;
                break;
            case '%':
                ret += formatStr[pos];
                ++pos;
                break;
            default:
                ret += formatStr[pos];
                break;
        }
    }
    return;
}

void CommonFunc::ParseLogContent(string &formatStr, vector<NapiParam> &params, string &printContent)
{
    std::string &ret = printContent;
    if (params.empty()) {
        ret += formatStr;
        return;
    }
    auto len = formatStr.size();
    uint32_t pos = 0;
    GetLogContent(formatStr, params, ret, pos);
    if (pos < len) {
        ret += formatStr.substr(pos, len - pos);
    }
    return;
}

void CommonFunc::ParseNapiValue(napi_env env, napi_value element, vector<NapiParam> &params)
{
    bool succ = false;
    napi_valuetype type;
    NapiParam res = {napi_null, ""};
    napi_status typeStatus = napi_typeof(env, element, &type);
    unique_ptr<char[]> name;
    size_t len = 0;
    if (typeStatus != napi_ok) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return;
    }
    if (type == napi_number || type == napi_bigint || type == napi_object || type == napi_undefined ||
        type == napi_boolean || type == napi_null) {
        napi_value elmString;
        napi_status objectStatus = napi_coerce_to_string(env, element, &elmString);
        if (objectStatus != napi_ok) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return;
        }
        NapiValue elmNVal(env, elmString);
        tie(succ, name, len) = elmNVal.ToUTF8String();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return;
        }
    } else if (type == napi_string) {
        NapiValue elmNVal(env, element);
        tie(succ, name, len) = elmNVal.ToUTF8String();
        if (!succ) {
            NapiBusinessError().ThrowErr(env, EINVAL);
            return;
        }
    } else {
        NapiBusinessError().ThrowErr(env, EINVAL);
    }
    res.type = type;
    if (name != nullptr) {
        res.val = name.get();
    }
    params.emplace_back(res);
    return;
}

bool CommonFunc::ParseNapiValueFromArray(napi_env env, vector<NapiParam> &params, const NapiFuncArg &funcArg)
{
    napi_value array = funcArg[ArgumentPosition::SECOND];
    if (funcArg.GetArgc() != MIN_NUMBER + 1) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return false;
    }
    uint32_t length;
    napi_status lengthStatus = napi_get_array_length(env, array, &length);
    if (lengthStatus != napi_ok) {
        return false;
    }
    uint32_t i;
    for (i = 0; i < length; i++) {
        napi_value element;
        napi_status eleStatus = napi_get_element(env, array, i, &element);
        if (eleStatus != napi_ok) {
            return false;
        }
        ParseNapiValue(env, element, params);
    }
    return true;
}

std::tuple<bool, std::unique_ptr<char[]>, std::unique_ptr<char[]>> CommonFunc::GetGZPrintFArg(
    napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    std::unique_ptr<char[]> fmtChar = nullptr;
    size_t len = 0;
    NapiValue formatNapiValue(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, fmtChar, len) = formatNapiValue.ToUTF8String();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, nullptr};
    }
    std::string fmtString = fmtChar.get();

    bool res = false;
    napi_value array = funcArg[ArgumentPosition::SECOND];
    napi_is_array(env, array, &res);
    std::string printContent;
    vector<NapiParam> params;
    if (!res) {
        for (size_t i = MIN_NUMBER; i < funcArg.GetArgc(); i++) {
            napi_value argsVal = funcArg[i];
            ParseNapiValue(env, argsVal, params);
        }
    } else {
        bool isSuccess = ParseNapiValueFromArray(env, params, funcArg);
        if (!isSuccess) {
            return {false, nullptr, nullptr};
        }
    }
    ParseLogContent(fmtString, params, printContent);

    std::unique_ptr<char[]> formatChar = nullptr;
    NapiValue formatNVal = NapiValue::CreateUTF8String(env, "%s");
    tie(succ, formatChar, len) = formatNVal.ToUTF8String();
    std::unique_ptr<char[]> argsChar = nullptr;
    NapiValue printNVal = NapiValue::CreateUTF8String(env, printContent);
    tie(succ, argsChar, len) = printNVal.ToUTF8String();
    return {true, std::move(formatChar), std::move(argsChar)};
}

std::tuple<bool, void *, size_t> CommonFunc::GetGZGetSArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    void *buffer = nullptr;
    size_t bufferLen = 0;
    NapiValue bufferNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, buffer, bufferLen) = bufferNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, nullptr, 0};
    }
    return {true, buffer, bufferLen};
}

std::tuple<bool, int64_t, int32_t> CommonFunc::GetGZSeekArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    int64_t offset = 0;
    NapiValue offsetNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, offset) = offsetNVal.ToInt64();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0};
    }

    int32_t whence = 0;
    NapiValue whenceNVal(env, funcArg[ArgumentPosition::SECOND]);
    tie(succ, whence) = whenceNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0};
    }
    return {true, offset, whence};
}

std::tuple<bool, int32_t> CommonFunc::GetGZUnGetCArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    int32_t c = 0;
    NapiValue cNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, c) = cNVal.ToInt32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }
    if (c < MIN_ASCII || c > MAX_ASCII) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }
    return {true, c};
}

std::tuple<bool, uint32_t> CommonFunc::SetGZFlushArg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    uint32_t flush = 0;
    NapiValue sizeNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, flush) = sizeNVal.ToUint32();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0};
    }
    return {true, flush};
}

}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS