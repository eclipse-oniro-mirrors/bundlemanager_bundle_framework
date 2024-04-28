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


}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
