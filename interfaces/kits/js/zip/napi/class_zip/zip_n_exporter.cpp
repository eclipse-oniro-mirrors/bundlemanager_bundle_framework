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

#include "zip_n_exporter.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <tuple>

#include "common/common_func.h"
#include "common/napi_async_work_callback.h"
#include "common/napi_async_work_promise.h"
#include "common/napi_class.h"
#include "common/napi_func_arg.h"
#include "common/napi_business_error.h"
#include "securec.h"
#include "zip_entity.h"
#include "zlib.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
using namespace std;
static constexpr int32_t ERROR_CODE = -5;
static constexpr int32_t MIN_BITS = 0;
static constexpr int32_t MAX_BITS = 16;
struct AsyncZipArg {
    const char *zliVersion = nullptr;
    const char *zErrorMsg = nullptr;
    uLong zlibCompileFlags = 0;
    int32_t errCode = 0;
    uint32_t pending = 0U;
    int32_t bits = 0;
    uLong destLen = 0U;
    int32_t level = 0;
    uLong sourceLen = 0U;
    uInt dictLength = 0U;
    int32_t method = 0;
    int32_t windowBits = 0;
    int32_t memLevel = 0;
    int32_t strategy = 0;

    AsyncZipArg() = default;
    ~AsyncZipArg() = default;
};

struct InOutDesc {
    napi_env env = nullptr;
    napi_value func = nullptr;
    napi_value desc = nullptr;

    InOutDesc(napi_env env, napi_value func, napi_value desc) : env(env), func(func), desc(desc) {};
    ~InOutDesc() = default;
};

static NapiValue ZipOutputInfo(napi_env env, std::shared_ptr<AsyncZipArg> arg)
{
    NapiValue obj = NapiValue::CreateObject(env);
    obj.AddProp({
        NapiValue::DeclareNapiProperty("status", NapiValue::CreateInt32(env, arg->errCode).val_),
        NapiValue::DeclareNapiProperty(
            "destLen", NapiValue::CreateInt64(env, static_cast<int64_t>(arg->destLen)).val_),
    });
    return {obj};
}

static NapiValue DecompressionOutputInfo(napi_env env, std::shared_ptr<AsyncZipArg> arg)
{
    NapiValue obj = NapiValue::CreateObject(env);
    obj.AddProp({
        NapiValue::DeclareNapiProperty("status", NapiValue::CreateInt32(env, arg->errCode).val_),
        NapiValue::DeclareNapiProperty(
            "destLength", NapiValue::CreateInt64(env, static_cast<int64_t>(arg->destLen)).val_),
        NapiValue::DeclareNapiProperty(
            "sourceLength", NapiValue::CreateInt64(env, static_cast<int64_t>(arg->sourceLen)).val_),
    });
    return {obj};
}

static NapiValue DictionaryOutputInfo(napi_env env, std::shared_ptr<AsyncZipArg> arg)
{
    NapiValue obj = NapiValue::CreateObject(env);
    obj.AddProp({
        NapiValue::DeclareNapiProperty("status", NapiValue::CreateInt32(env, arg->errCode).val_),
        NapiValue::DeclareNapiProperty("dictionaryLength", NapiValue::CreateInt32(env, arg->dictLength).val_),
    });
    return {obj};
}

static NapiValue DeflatePendingOutputInfo(napi_env env, std::shared_ptr<AsyncZipArg> arg)
{
    NapiValue obj = NapiValue::CreateObject(env);
    obj.AddProp({
        NapiValue::DeclareNapiProperty("status", NapiValue::CreateInt32(env, arg->errCode).val_),
        NapiValue::DeclareNapiProperty("pending", NapiValue::CreateInt32(env, arg->pending).val_),
        NapiValue::DeclareNapiProperty("bits", NapiValue::CreateInt32(env, arg->bits).val_),
    });
    return {obj};
}

static NapiValue GetZStreamInfo(napi_env env, ZipEntity *zipEntity)
{
    NapiValue obj = NapiValue::CreateObject(env);
    obj.AddProp({
        NapiValue::DeclareNapiProperty("availableIn", NapiValue::CreateInt32(env, zipEntity->zs.get()->avail_in).val_),
        NapiValue::DeclareNapiProperty("totalIn", NapiValue::CreateInt64(env, zipEntity->zs.get()->total_in).val_),
        NapiValue::DeclareNapiProperty(
            "availableOut", NapiValue::CreateInt32(env, zipEntity->zs.get()->avail_out).val_),
        NapiValue::DeclareNapiProperty("totalOut", NapiValue::CreateInt64(env, zipEntity->zs.get()->total_out).val_),
        NapiValue::DeclareNapiProperty("dataType", NapiValue::CreateInt32(env, zipEntity->zs.get()->data_type).val_),
        NapiValue::DeclareNapiProperty("adler", NapiValue::CreateInt64(env, zipEntity->zs.get()->adler).val_),
    });
    return { obj };
}

napi_value ZipNExporter::Constructor(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    unique_ptr<ZipEntity> zipEntity = make_unique<ZipEntity>();
    if (!NapiClass::SetEntityFor<ZipEntity>(env, funcArg.GetThisVar(), move(zipEntity))) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }
    return funcArg.GetThisVar();
}

vector<napi_property_descriptor> ZipNExporter::DeflateExport()
{
    vector<napi_property_descriptor> props = {
        NapiValue::DeclareNapiFunction("deflateInit", DeflateInit),
        NapiValue::DeclareNapiFunction("deflateInit2", DeflateInit2),
        NapiValue::DeclareNapiFunction("deflate", Deflate),
        NapiValue::DeclareNapiFunction("deflateEnd", DeflateEnd),
        NapiValue::DeclareNapiFunction("deflateBound", DeflateBound),
        NapiValue::DeclareNapiFunction("deflateReset", DeflateReset),
        NapiValue::DeclareNapiFunction("deflateResetKeep", DeflateResetKeep),
        NapiValue::DeclareNapiFunction("deflateParams", DeflateParams),
        NapiValue::DeclareNapiFunction("deflatePrime", DeflatePrime),
        NapiValue::DeclareNapiFunction("deflateTune", DeflateTune),
        NapiValue::DeclareNapiFunction("deflateSetDictionary", DeflateSetDictionary),
        NapiValue::DeclareNapiFunction("deflateGetDictionary", DeflateGetDictionary),
        NapiValue::DeclareNapiFunction("deflateSetHeader", DeflateSetHeader),
        NapiValue::DeclareNapiFunction("deflatePending", DeflatePending),
        NapiValue::DeclareNapiFunction("deflateCopy", DeflateCopy),
    };
    return props;
}

vector<napi_property_descriptor> ZipNExporter::InflateExport()
{
    vector<napi_property_descriptor> props = {
        NapiValue::DeclareNapiFunction("inflateInit", InflateInit),
        NapiValue::DeclareNapiFunction("inflateInit2", InflateInit2),
        NapiValue::DeclareNapiFunction("inflateSync", InflateSync),
        NapiValue::DeclareNapiFunction("inflate", Inflate),
        NapiValue::DeclareNapiFunction("inflateEnd", InflateEnd),
        NapiValue::DeclareNapiFunction("inflateSetDictionary", InflateSetDictionary),
        NapiValue::DeclareNapiFunction("inflateGetDictionary", InflateGetDictionary),
        NapiValue::DeclareNapiFunction("inflateGetHeader", InflateGetHeader),
        NapiValue::DeclareNapiFunction("inflateReset", InflateReset),
        NapiValue::DeclareNapiFunction("inflateReset2", InflateReset2),
        NapiValue::DeclareNapiFunction("inflateResetKeep", InflateResetKeep),
        NapiValue::DeclareNapiFunction("inflateBackInit", InflateBackInit),
        NapiValue::DeclareNapiFunction("inflateBack", InflateBack),
        NapiValue::DeclareNapiFunction("inflateBackEnd", InflateBackEnd),
        NapiValue::DeclareNapiFunction("inflateCodesUsed", InflateCodesUsed),
        NapiValue::DeclareNapiFunction("inflatePrime", InflatePrime),
        NapiValue::DeclareNapiFunction("inflateMark", InflateMark),
        NapiValue::DeclareNapiFunction("inflateValidate", InflateValidate),
        NapiValue::DeclareNapiFunction("inflateUndermine", InflateUndermine),
        NapiValue::DeclareNapiFunction("inflateSyncPoint", InflateSyncPoint),
        NapiValue::DeclareNapiFunction("inflateCopy", InflateCopy),
    };
    return props;
}

bool ZipNExporter::Export()
{
    vector<napi_property_descriptor> props = {
        NapiValue::DeclareNapiFunction("setZStream", SetZStream),
        NapiValue::DeclareNapiFunction("getZStream", GetZStream),
        NapiValue::DeclareNapiFunction("getZStreamSync", GetZStreamSync),
        NapiValue::DeclareNapiFunction("zlibVersion", ZlibVersion),
        NapiValue::DeclareNapiFunction("zError", ZError),
        NapiValue::DeclareNapiFunction("zlibCompileFlags", ZlibCompileFlags),
        NapiValue::DeclareNapiFunction("compress", Compress),
        NapiValue::DeclareNapiFunction("compress2", Compress2),
        NapiValue::DeclareNapiFunction("compressBound", CompressBound),
        NapiValue::DeclareNapiFunction("uncompress", UnCompress),
        NapiValue::DeclareNapiFunction("uncompress2", UnCompress2),
    };
    for (const auto &prop : DeflateExport()) {
        props.push_back(prop);
    }

    for (const auto &prop : InflateExport()) {
        props.push_back(prop);
    }

    string className = GetClassName();
    bool succ = false;
    napi_value cls = nullptr;
    tie(succ, cls) = NapiClass::DefineClass(exports_.env_, className, ZipNExporter::Constructor, move(props));
    if (!succ) {
        NapiBusinessError().ThrowErr(exports_.env_, "Failed to define class");
        return false;
    }
    succ = NapiClass::SaveClass(exports_.env_, className, cls);
    if (!succ) {
        NapiBusinessError().ThrowErr(exports_.env_, "Failed to save class");
        return false;
    }

    return exports_.AddProp(className, cls);
}

string ZipNExporter::GetClassName()
{
    return ZipNExporter::className_;
}

ZipNExporter::ZipNExporter(napi_env env, napi_value exports) : NapiExporter(env, exports)
{}

ZipNExporter::~ZipNExporter()
{}

napi_value ZipNExporter::SetZStream(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto cbExec = [](napi_env env) -> NapiBusinessError { return NapiBusinessError(ERRNO_NOERR); };

    auto cbCompl = [](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        return {NapiValue::CreateUndefined(env)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::GetZStreamSync(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity || !zipEntity->zs) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    NapiValue obj = NapiValue::CreateObject(env);
    obj.AddProp({
        NapiValue::DeclareNapiProperty(
            "availableIn", NapiValue::CreateInt32(env, zipEntity->zs.get()->avail_in).val_),
        NapiValue::DeclareNapiProperty("totalIn", NapiValue::CreateInt64(env, zipEntity->zs.get()->total_in).val_),
        NapiValue::DeclareNapiProperty(
            "availableOut", NapiValue::CreateInt32(env, zipEntity->zs.get()->avail_out).val_),
        NapiValue::DeclareNapiProperty("totalOut", NapiValue::CreateInt64(env, zipEntity->zs.get()->total_out).val_),
        NapiValue::DeclareNapiProperty("dataType", NapiValue::CreateInt32(env, zipEntity->zs.get()->data_type).val_),
        NapiValue::DeclareNapiProperty("adler", NapiValue::CreateInt64(env, zipEntity->zs.get()->adler).val_),
    });

    return obj.val_;
}

napi_value ZipNExporter::GetZStream(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    auto cbExec = [](napi_env env) -> NapiBusinessError { return NapiBusinessError(ERRNO_NOERR); };

    auto cbCompl = [zipEntity](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!zipEntity || !zipEntity->zs) {
            return {NapiValue::CreateUndefined(env)};
        }

        NapiValue obj = GetZStreamInfo(env, zipEntity);
        return {obj};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::ZlibVersion(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->zliVersion = zlibVersion();
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateUTF8String(env, string(reinterpret_cast<const char *>(arg->zliVersion)))};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::ZError(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    int32_t zlibError = 0;
    tie(succ, zlibError) = CommonFunc::GetZErrorArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zlibError](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->zErrorMsg = zError(zlibError);
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateUTF8String(env, string(reinterpret_cast<const char *>(arg->zErrorMsg)))};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::ZlibCompileFlags(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->zlibCompileFlags = zlibCompileFlags();
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::NapiValue::CreateInt32(env, arg->zlibCompileFlags)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::DeflateInit(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    z_stream zStream = {};
    int32_t level = 0;
    tie(succ, zStream, level) = CommonFunc::GetDeflateInitArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, zStream, level](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity) {
            return NapiBusinessError(EFAULT, true);
        }
        std::unique_ptr<z_stream> zs = std::make_unique<z_stream>(zStream);
        arg->errCode = deflateInit(zs.get(), level);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        zipEntity->zs.swap(zs);
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::DeflateInit2(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::SIX, ArgumentCount::SEVEN)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    bool succ = false;
    z_stream zStream = {};
    tie(succ, zStream, arg->level, arg->method, arg->windowBits, arg->memLevel, arg->strategy) =
        CommonFunc::GetDeflateInit2Arg(env, funcArg);
    if (!succ) {
        return nullptr;
    }
    
    auto cbExec = [arg, zipEntity, zStream](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity) {
            return NapiBusinessError(EFAULT, true);
        }
        std::unique_ptr<z_stream> zs = std::make_unique<z_stream>(zStream);
        arg->errCode = deflateInit2(zs.get(), arg->level, arg->method, arg->windowBits, arg->memLevel, arg->strategy);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        zipEntity->zs.swap(zs);
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::SIX) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::Deflate(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    int32_t flush = 0;
    tie(succ, flush) = CommonFunc::GetDeflateArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, flush](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = deflate(zipEntity->zs.get(), flush);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::DeflateEnd(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = deflateEnd(zipEntity->zs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::DeflateBound(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    uint32_t sourceLen = 0;
    tie(succ, sourceLen) = CommonFunc::UnwrapInt64Params(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, sourceLen](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = deflateBound(zipEntity->zs.get(), sourceLen);
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::DeflateReset(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = deflateReset(zipEntity->zs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::DeflateResetKeep(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = deflateResetKeep(zipEntity->zs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::DeflateParams(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::THREE, ArgumentCount::FOUR)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    int32_t level = 0;
    int32_t strategy = 0;
    tie(succ, level, strategy) = CommonFunc::UnwrapTwoIntParams(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, level, strategy](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = deflateParams(zipEntity->zs.get(), level, strategy);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::DeflatePrime(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::THREE, ArgumentCount::FOUR)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    int32_t bits = 0;
    int32_t value = 0;
    tie(succ, bits, value) = CommonFunc::UnwrapTwoIntParams(env, funcArg);
    if (!succ) {
        return nullptr;
    } else if (bits < MIN_BITS || bits > MAX_BITS) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, bits, value](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = deflatePrime(zipEntity->zs.get(), bits, value);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::DeflateTune(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::FIVE, ArgumentCount::SIX)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    int32_t goodLength = 0;
    int32_t maxLazy = 0;
    int32_t niceLength = 0;
    int32_t maxChain = 0;
    tie(succ, goodLength, maxLazy, niceLength, maxChain) = CommonFunc::UnwrapDeflateTuneParams(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, goodLength, maxLazy, niceLength, maxChain](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = deflateTune(zipEntity->zs.get(), goodLength, maxLazy, niceLength, maxChain);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::FIVE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::DeflateSetDictionary(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    void *dictionary = nullptr;
    size_t dictionaryLen = 0;
    tie(succ, dictionary, dictionaryLen) = CommonFunc::UnwrapArrayBufferParams(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, dictionary, dictionaryLen](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = deflateSetDictionary(
            zipEntity->zs.get(), reinterpret_cast<const Bytef *>(dictionary), static_cast<uInt>(dictionaryLen));
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::DeflateGetDictionary(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    void *dictionary = nullptr;
    auto arg = make_shared<AsyncZipArg>();
    tie(succ, dictionary, arg->dictLength) = CommonFunc::UnwrapArrayBufferParams(env, funcArg);

    auto cbExec = [arg, zipEntity, dictionary](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = deflateGetDictionary(zipEntity->zs.get(), static_cast<Bytef *>(dictionary), &arg->dictLength);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }

        NapiValue obj = DictionaryOutputInfo(env, arg);
        return {obj};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::DeflateSetHeader(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    gz_header gzHeader = {};
    tie(succ, gzHeader) = CommonFunc::GetGZHeaderArg(env, funcArg[ArgumentPosition::SECOND]);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, gzHeader](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = deflateSetHeader(zipEntity->zs.get(), const_cast<gz_headerp>(&gzHeader));
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::DeflatePending(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = deflatePending(zipEntity->zs.get(), &arg->pending, &arg->bits);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        NapiValue obj = DeflatePendingOutputInfo(env, arg);
        return {obj};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::DeflateCopy(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    auto srcZipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg[ArgumentPosition::FIRST]);
    if (!srcZipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, srcZipEntity](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !srcZipEntity) {
            return NapiBusinessError(EFAULT, true);
        }

        if (!zipEntity->zs) {
            std::unique_ptr<z_stream> zs = std::make_unique<z_stream>();
            zipEntity->zs.swap(zs);
        }
        arg->errCode = deflateCopy(zipEntity->zs.get(), srcZipEntity->zs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::Compress(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    void *dest = nullptr;
    void *source = nullptr;
    auto arg = make_shared<AsyncZipArg>();
    tie(succ, dest, arg->destLen, source, arg->sourceLen) = CommonFunc::GetCompressArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto cbExec = [arg, dest, source](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        if (!source || !dest) {
            return NapiBusinessError(ERROR_CODE, true);
        }
        arg->errCode =
            compress(reinterpret_cast<Bytef *>(dest), &arg->destLen, reinterpret_cast<Bytef *>(source), arg->sourceLen);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        NapiValue obj = ZipOutputInfo(env, arg);
        return {obj};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO || funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::Compress2(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::THREE, ArgumentCount::FOUR)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    void *dest = nullptr;
    void *source = nullptr;
    auto arg = make_shared<AsyncZipArg>();
    tie(succ, dest, arg->destLen, source, arg->sourceLen, arg->level) = CommonFunc::GetCompress2Arg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto cbExec = [arg, dest, source](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        if (!source || !dest) {
            return NapiBusinessError(ERROR_CODE, true);
        }
        arg->errCode = compress2(
            static_cast<Bytef *>(dest), &arg->destLen, static_cast<Bytef *>(source), arg->sourceLen, arg->level);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        NapiValue obj = ZipOutputInfo(env, arg);
        return {obj};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::THREE || funcArg.GetArgc() == ArgumentCount::FOUR) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::CompressBound(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    int32_t sourceLen = 0;
    bool succ = false;
    tie(succ, sourceLen) = CommonFunc::UnwrapInt32Params(env, funcArg[ArgumentPosition::FIRST]);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, sourceLen](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = compressBound(sourceLen);
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::UnCompress(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    void *dest = nullptr;
    void *source = nullptr;
    auto arg = make_shared<AsyncZipArg>();
    tie(succ, dest, arg->destLen, source, arg->sourceLen) = CommonFunc::GetUnCompressArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto cbExec = [arg, dest, source](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        if (!source || !dest) {
            return NapiBusinessError(ERROR_CODE, true);
        }
        arg->errCode =
            uncompress(static_cast<Bytef *>(dest), &arg->destLen, static_cast<Bytef *>(source), arg->sourceLen);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        NapiValue obj = ZipOutputInfo(env, arg);
        return {obj};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO || funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::UnCompress2(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    void *dest = nullptr;
    void *source = nullptr;
    auto arg = make_shared<AsyncZipArg>();
    tie(succ, dest, arg->destLen, source, arg->sourceLen) = CommonFunc::GetUnCompressArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto cbExec = [arg, dest, source](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        if (!source || !dest) {
            return NapiBusinessError(ERROR_CODE, true);
        }
        arg->errCode =
            uncompress2(static_cast<Bytef *>(dest), &arg->destLen, static_cast<Bytef *>(source), &arg->sourceLen);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        NapiValue obj = DecompressionOutputInfo(env, arg);
        return {obj};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO || funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateInit(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    z_stream zStream = {};
    HasZStreamMember hasZStreamMember = {};
    tie(succ, zStream, hasZStreamMember) = CommonFunc::GetZstreamArg(env, funcArg[ArgumentPosition::FIRST]);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, zStream](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity) {
            return NapiBusinessError(EFAULT, true);
        }
        std::unique_ptr<z_stream> zs = std::make_unique<z_stream>(zStream);
        arg->errCode = inflateInit(zs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        zipEntity->zs.swap(zs);
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateInit2(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    z_stream zStream = {};
    int32_t windowBits = 0;
    tie(succ, zStream, windowBits) = CommonFunc::GetInflateInitArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, zStream, windowBits](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity) {
            return NapiBusinessError(EFAULT, true);
        }
        std::unique_ptr<z_stream> zs = std::make_unique<z_stream>(zStream);
        arg->errCode = inflateInit2(zs.get(), windowBits);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        zipEntity->zs.swap(zs);
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateSync(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflateSync(zipEntity->zs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::Inflate(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    int32_t flush = 0;
    tie(succ, flush) = CommonFunc::GetInflateArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, flush](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflate(zipEntity->zs.get(), flush);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateEnd(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflateEnd(zipEntity->zs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateSetDictionary(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    void *buf = nullptr;
    size_t bufLen = 0;
    tie(succ, buf, bufLen) = CommonFunc::GetInflateSetDictionaryArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, buf, bufLen](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflateSetDictionary(zipEntity->zs.get(), static_cast<Bytef *>(buf), static_cast<uInt>(bufLen));
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateGetDictionary(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!arg ||!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    void *buf = nullptr;
    tie(succ, buf, arg->dictLength) = CommonFunc::GetInflateSetDictionaryArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto cbExec = [arg, zipEntity, buf](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflateGetDictionary(zipEntity->zs.get(), static_cast<Bytef *>(buf), &arg->dictLength);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        NapiValue obj = DictionaryOutputInfo(env, arg);
        return {obj};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateResetKeep(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflateResetKeep(zipEntity->zs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateReset2(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    int32_t flush = 0;
    tie(succ, flush) = CommonFunc::GetInflateReset2Arg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, flush](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflateReset2(zipEntity->zs.get(), flush);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateReset(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflateReset(zipEntity->zs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateBackInit(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::THREE, ArgumentCount::FOUR)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    int32_t windowBits = 0;
    void *windowBuf = nullptr;
    size_t bufLen = 0;
    tie(succ, windowBits, windowBuf, bufLen) = CommonFunc::GetInflateBackInitArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, windowBits, windowBuf](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflateBackInit(zipEntity->zs.get(), windowBits, static_cast<Bytef *>(windowBuf));
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

static unsigned InFunc(void *inDesc, unsigned char **buf)
{
    InOutDesc *in = static_cast<InOutDesc *>(inDesc);
    if (!in) {
        APP_LOGE("The in function callback is nullptr");
        return 0;
    }

    NapiReference cb(NapiValue(in->env, in->func));
    if (!cb || !cb.Deref(in->env).TypeIs(napi_function)) {
        NapiBusinessError().ThrowErr(in->env, EINVAL);
        return 0;
    }
    napi_value callback = cb.Deref(in->env).val_;
    napi_value argv[ArgumentCount::ONE] = {in->desc};
    napi_value globalObj = nullptr;
    napi_status status = napi_get_global(in->env, &globalObj);
    if (status != napi_ok) {
        NapiBusinessError().ThrowErr(in->env, EINVAL);
        return 0;
    }
    napi_value return_val = nullptr;
    status = napi_call_function(in->env, globalObj, callback, ArgumentCount::ONE, argv, &return_val);
    if (status != napi_ok) {
        NapiBusinessError().ThrowErr(in->env, EINVAL);
        return 0;
    }

    NapiValue bufNVal(in->env, return_val);
    void *buffer = nullptr;
    size_t bufLen = 0;
    bool succ = false;
    tie(succ, buffer, bufLen) = bufNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(in->env, EINVAL);
        return 0;
    }
    *buf = static_cast<unsigned char *>(buffer);

    return bufLen;
}

static int32_t OutFunc(void *outDesc, unsigned char *buf, unsigned len)
{
    InOutDesc *out = static_cast<InOutDesc *>(outDesc);
    if (!out) {
        APP_LOGE("The out function callback is nullptr");
        return -1;
    }

    NapiReference cb(NapiValue(out->env, out->func));
    if (!cb || !cb.Deref(out->env).TypeIs(napi_function)) {
        NapiBusinessError().ThrowErr(out->env, EINVAL);
        return -1;
    }
    napi_value callback = cb.Deref(out->env).val_;
    void *data = nullptr;
    napi_value buffer = nullptr;
    napi_status status = napi_create_arraybuffer(out->env, len, &data, &buffer);
    if (status != napi_ok) {
        NapiBusinessError().ThrowErr(out->env, EINVAL);
        return -1;
    }
    if (memcpy_s(data, len, buf, len) != EOK) {
        NapiBusinessError().ThrowErr(out->env, EINVAL);
        return -1;
    }
    napi_value bufferLen = nullptr;
    status = napi_create_int32(out->env, len, &bufferLen);
    if (status != napi_ok) {
        NapiBusinessError().ThrowErr(out->env, EINVAL);
        return -1;
    }
    napi_value argv[ArgumentCount::THREE] = {out->desc, buffer, bufferLen};
    napi_value globalObj = nullptr;
    status = napi_get_global(out->env, &globalObj);
    if (status != napi_ok) {
        NapiBusinessError().ThrowErr(out->env, EINVAL);
        return -1;
    }
    napi_value return_val = nullptr;
    status = napi_call_function(out->env, globalObj, callback, ArgumentCount::THREE, argv, &return_val);
    if (status != napi_ok) {
        NapiBusinessError().ThrowErr(out->env, EINVAL);
        return -1;
    }
    int32_t result = 0;
    status = napi_get_value_int32(out->env, return_val, &result);
    if (status != napi_ok) {
        NapiBusinessError().ThrowErr(out->env, EINVAL);
        return -1;
    }
    return result;
}

napi_value ZipNExporter::InflateBack(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::FIVE, ArgumentCount::SIX)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!arg || !zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto inDesc = make_shared<InOutDesc>(env, funcArg[ArgumentPosition::SECOND], funcArg[ArgumentPosition::THIRD]);
    auto outDesc = make_shared<InOutDesc>(env, funcArg[ArgumentPosition::FOURTH], funcArg[ArgumentPosition::FIFTH]);
    arg->errCode = inflateBack(zipEntity->zs.get(), InFunc, inDesc.get(), OutFunc, outDesc.get());
    auto cbExec = [arg](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::FIVE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateBackEnd(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflateBackEnd(zipEntity->zs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateCodesUsed(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflateCodesUsed(zipEntity->zs.get());
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateUint32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflatePrime(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::THREE, ArgumentCount::FOUR)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    int32_t bits = 0;
    int32_t value = 0;
    tie(succ, bits, value) = CommonFunc::GetInflatePrimeArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, bits, value](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflatePrime(zipEntity->zs.get(), bits, value);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateMark(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflateMark(zipEntity->zs.get());
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateValidate(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    int32_t check = 0;
    tie(succ, check) = CommonFunc::GetInflateValidateArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, check](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflateValidate(zipEntity->zs.get(), check);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateUndermine(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    int32_t subvert = 0;
    tie(succ, subvert) = CommonFunc::GetInflateUndermineArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, subvert](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflateUndermine(zipEntity->zs.get(), subvert);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateSyncPoint(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = CommonFunc::SetZStreamValue(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflateSyncPoint(zipEntity->zs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateCopy(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    auto srcZipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg[ArgumentPosition::FIRST]);
    if (!srcZipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, srcZipEntity](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !srcZipEntity) {
            return NapiBusinessError(EFAULT, true);
        }

        if (!zipEntity->zs) {
            std::unique_ptr<z_stream> zs = std::make_unique<z_stream>();
            zipEntity->zs.swap(zs);
        }
        arg->errCode = inflateCopy(zipEntity->zs.get(), srcZipEntity->zs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ZipNExporter::InflateGetHeader(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto zipEntity = NapiClass::GetEntityOf<ZipEntity>(env, funcArg.GetThisVar());
    if (!zipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    gz_header gzHeader = {};
    tie(succ, gzHeader) = CommonFunc::GetInflateGetHeaderArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncZipArg>();
    auto cbExec = [arg, zipEntity, gzHeader](napi_env env) -> NapiBusinessError {
        if (!arg || !zipEntity || !zipEntity->zs) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = inflateGetHeader(zipEntity->zs.get(), const_cast<gz_headerp>(&gzHeader));
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_ZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
