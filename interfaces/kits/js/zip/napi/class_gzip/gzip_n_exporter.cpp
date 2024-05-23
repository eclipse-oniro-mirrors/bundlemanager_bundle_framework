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

#include "gzip_n_exporter.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
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
#include "gzip_entity.h"
#include "zlib.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
using namespace std;

static constexpr int MIN_NUMBER = 1;
static constexpr int MAX_NUMBER = 101;

struct AsyncGZipArg {
    std::unique_ptr<char[]> path = nullptr;
    std::unique_ptr<char[]> mode = nullptr;
    int32_t fd = -1;
    int32_t errCode = 0;
    int32_t flushMode = 0;
    const char *errMsg = nullptr;

    // write fwrite read fread gets
    void *buf = nullptr;
    int64_t bufLen = 0;
    int64_t size = 0;
    int64_t nitems = 0;
    int64_t readLen = 0;
    int64_t writeLen = 0;
    char *nullTerminatedString = nullptr;
    // putc puts
    int32_t c = 0;
    std::unique_ptr<char[]> s = nullptr;
    int32_t putLen = 0;
    // tell tell64 seek seek64 offset offset64
    int64_t seekOffset = 0;
    int32_t seekWhence = 0;
    int32_t offset = 0;
    int64_t offset64 = 0;
    // setparam
    int32_t level = 0;
    int32_t strategy = 0;
    // printf
    std::string printContent = "";
    int32_t printResult = 0;
    std::unique_ptr<char[]> format = nullptr;
    std::unique_ptr<char[]> args = nullptr;
    // ungetc
    int32_t character = -1;

    AsyncGZipArg() = default;
    ~AsyncGZipArg() = default;
};

napi_value GZipNExporter::Constructor(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    unique_ptr<GZipEntity> gzipEntity = make_unique<GZipEntity>();
    if (!NapiClass::SetEntityFor<GZipEntity>(env, funcArg.GetThisVar(), move(gzipEntity))) {
        NapiBusinessError(EIO).ThrowErr(env, "Failed to wrap entity for obj gzip");
        return nullptr;
    }
    return funcArg.GetThisVar();
}

bool GZipNExporter::Export()
{
    vector<napi_property_descriptor> props = {
        NapiValue::DeclareNapiFunction("gzdopen", GZDopen),
        NapiValue::DeclareNapiFunction("gzopen", GZOpen),
        NapiValue::DeclareNapiFunction("gzclose", GZClose),
        NapiValue::DeclareNapiFunction("gzclosew", GZCloseW),
        NapiValue::DeclareNapiFunction("gzbuffer", GZBuffer),
        NapiValue::DeclareNapiFunction("gzread", GZRead),
        NapiValue::DeclareNapiFunction("gzfread", GZFRead),
        NapiValue::DeclareNapiFunction("gzwrite", GZWrite),
        NapiValue::DeclareNapiFunction("gzfwrite", GZFWrite),
        NapiValue::DeclareNapiFunction("gzputc", GZPutC),
        NapiValue::DeclareNapiFunction("gzputs", GZPutS),
        NapiValue::DeclareNapiFunction("gztell", GZTell),
        NapiValue::DeclareNapiFunction("gzsetparams", GZSetParams),
        NapiValue::DeclareNapiFunction("gzprintf", GZPrintF),
        NapiValue::DeclareNapiFunction("gzcloser", GZCloseR),
        NapiValue::DeclareNapiFunction("gzgets", GZGetS),
        NapiValue::DeclareNapiFunction("gzgetc", GZGetC),
        NapiValue::DeclareNapiFunction("gzrewind", GZRewind),
        NapiValue::DeclareNapiFunction("gzseek", GZSeek),
        NapiValue::DeclareNapiFunction("gzoffset", GZOffset),
        NapiValue::DeclareNapiFunction("gzungetc", GZUnGetC),
        NapiValue::DeclareNapiFunction("gzclearerr", GZClearerr),
        NapiValue::DeclareNapiFunction("gzdirect", GZDirect),
        NapiValue::DeclareNapiFunction("gzeof", GZeof),
        NapiValue::DeclareNapiFunction("gzerror", GZError),
        NapiValue::DeclareNapiFunction("gzflush", GZFlush),
    };

    string className = GetClassName();
    bool succ = false;
    napi_value cls = nullptr;
    tie(succ, cls) = NapiClass::DefineClass(exports_.env_, className, GZipNExporter::Constructor, move(props));
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

string GZipNExporter::GetClassName()
{
    return GZipNExporter::className_;
}

GZipNExporter::GZipNExporter(napi_env env, napi_value exports) : NapiExporter(env, exports)
{}

GZipNExporter::~GZipNExporter()
{}

napi_value GZipNExporter::GZDopen(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    tie(succ, arg->fd, arg->mode) = CommonFunc::GetGZDOpenArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }
    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EFAULT, true);
        }
        auto file = gzdopen(arg->fd, arg->mode.get());
        if (!file) {
            return NapiBusinessError(ENOENT, true);
        }
        std::unique_ptr<gzFile_s, Deleter<gzFile_s>> gzFile(file);
        gzipEntity->gzs.swap(gzFile);
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        return {NapiValue::CreateUndefined(env)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZOpen(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    tie(succ, arg->path, arg->mode) = CommonFunc::GetGZOpenArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }
    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EFAULT, true);
        }
        gzFile file;
#if !defined(ZLIB_INTERNAL) && defined(Z_WANT64) && !defined(Z_LARGE64)
        file = gzopen64(arg->path.get(), arg->mode.get());
#else
        file = gzopen(arg->path.get(), arg->mode.get());
#endif
        if (!file) {
            return NapiBusinessError(ENOENT, true);
        }
        std::unique_ptr<gzFile_s, Deleter<gzFile_s>> gzFile(file);
        gzipEntity->gzs.swap(gzFile);
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        return {NapiValue::CreateUndefined(env)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZCloseW(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = gzclose_w(gzipEntity->gzs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZBuffer(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    uint32_t size = 0;
    tie(succ, size) = CommonFunc::GetGZBufferArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }
    auto cbExec = [arg, gzipEntity, size](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = gzbuffer(gzipEntity->gzs.get(), size);
        if (arg->errCode < 0) {
            return NapiBusinessError(ENOSTR, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZRead(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    bool succ = false;
    void *buffer = nullptr;
    tie(succ, buffer, arg->bufLen) = CommonFunc::GetGZReadArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity, buffer](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
        arg->readLen =
            gzread(gzipEntity->gzs.get(), reinterpret_cast<void *>(buffer), static_cast<unsigned int>(arg->bufLen));
        if (arg->readLen < 0) {
            return NapiBusinessError(ENOSTR, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->readLen)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZFRead(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::THREE, ArgumentCount::FOUR)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    bool succ = false;
    void *buffer = nullptr;
    tie(succ, buffer, arg->size, arg->nitems) = CommonFunc::GetGZFReadArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity, buffer](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
        arg->readLen = static_cast<int64_t>(gzfread(reinterpret_cast<void *>(buffer),
            static_cast<z_size_t>(arg->size), static_cast<z_size_t>(arg->nitems), gzipEntity->gzs.get()));
        if (arg->readLen <= 0) {
            return NapiBusinessError(ENOSTR, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->readLen)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZWrite(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    bool succ = false;
    tie(succ, arg->buf, arg->bufLen) = CommonFunc::GetGZWriteArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
        arg->writeLen = gzwrite(gzipEntity->gzs.get(), arg->buf, static_cast<unsigned int>(arg->bufLen));
        if (arg->writeLen <= 0) {
            return NapiBusinessError(ENOSTR, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->writeLen)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZFWrite(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::THREE, ArgumentCount::FOUR)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    bool succ = false;
    tie(succ, arg->buf, arg->size, arg->nitems) = CommonFunc::GetGZFWriteArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
        arg->writeLen = static_cast<int64_t>(gzfwrite(
            arg->buf, static_cast<z_size_t>(arg->size), static_cast<z_size_t>(arg->nitems), gzipEntity->gzs.get()));
        if (arg->writeLen <= 0) {
            return NapiBusinessError(ENOSTR, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->writeLen)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZPutC(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    bool succ = false;
    tie(succ, arg->c) = CommonFunc::GetGZPutCArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
        arg->c = gzputc(gzipEntity->gzs.get(), arg->c);
        if (arg->c < 0) {
            return NapiBusinessError(ENOSTR, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->c)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZPutS(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    bool succ = false;
    tie(succ, arg->s) = CommonFunc::GetGZPutSArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
        arg->putLen = gzputs(gzipEntity->gzs.get(), arg->s.get());
        if (arg->putLen < 0) {
            return NapiBusinessError(ENOSTR, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->putLen)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZTell(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
#if !defined(ZLIB_INTERNAL) && defined(Z_WANT64) && !defined(Z_LARGE64)
        arg->offset64 = gztell64(gzipEntity->gzs.get());
#else
        arg->offset = gztell(gzipEntity->gzs.get());
#endif
        if (arg->offset < 0 || arg->offset64 < 0) {
            return NapiBusinessError(ENOSTR, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
#if !defined(ZLIB_INTERNAL) && defined(Z_WANT64) && !defined(Z_LARGE64)
        return {NapiValue::CreateInt64(env, arg->offset64)};
#else
        return {NapiValue::CreateInt32(env, arg->offset)};
#endif
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZSetParams(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    bool succ = false;
    tie(succ, arg->level, arg->strategy) = CommonFunc::GetGzSetParamsArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
        arg->errCode = gzsetparams(gzipEntity->gzs.get(), arg->level, arg->strategy);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZPrintF(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(MIN_NUMBER, MAX_NUMBER)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    bool succ = false;
    tie(succ, arg->format, arg->args) = CommonFunc::GetGZPrintFArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
        arg->printResult = gzprintf(gzipEntity->gzs.get(), arg->format.get(), arg->args.get());
        if (arg->printResult <= 0) {
            return NapiBusinessError(arg->printResult, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->printResult)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
}

napi_value GZipNExporter::GZClose(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
        arg->errCode = gzclose(gzipEntity->gzs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZCloseR(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
        arg->errCode = gzclose_r(gzipEntity->gzs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZGetS(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }
    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }
    bool succ = false;
    void *buffer = nullptr;
    tie(succ, buffer, arg->bufLen) = CommonFunc::GetGZGetSArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }
    auto cbExec = [arg, gzipEntity, buffer](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
        auto nullTerminatedString =
            gzgets(gzipEntity->gzs.get(), reinterpret_cast<char *>(buffer), static_cast<int>(arg->bufLen));
        if (!nullTerminatedString) {
            return NapiBusinessError(ENOSTR, true);
        }
        arg->nullTerminatedString = nullTerminatedString;
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg->nullTerminatedString) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateUTF8String(env, arg->nullTerminatedString, strlen(arg->nullTerminatedString))};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZGetC(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
        arg->errCode = gzgetc(gzipEntity->gzs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(ENOSTR, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZRewind(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
        arg->errCode = gzrewind(gzipEntity->gzs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(ENOSTR, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZSeek(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }
    auto arg = make_shared<AsyncGZipArg>();
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }
    bool succ = false;
    tie(succ, arg->seekOffset, arg->seekWhence) = CommonFunc::GetGZSeekArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }
    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
#if !defined(ZLIB_INTERNAL) && defined(Z_WANT64) && !defined(Z_LARGE64)
        arg->offset64 = gzseek64(gzipEntity->gzs.get(), arg->seekOffset, arg->seekWhence);
#else
        arg->offset = gzseek(gzipEntity->gzs.get(), static_cast<long>(arg->seekOffset), arg->seekWhence);
#endif
        if (arg->offset < 0 || arg->offset64 < 0) {
            return NapiBusinessError(ENOSTR, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };
    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
#if !defined(ZLIB_INTERNAL) && defined(Z_WANT64) && !defined(Z_LARGE64)
        return {NapiValue::CreateInt64(env, arg->offset64)};
#else
        return {NapiValue::CreateInt32(env, arg->offset)};
#endif
    };
    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }
    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZOffset(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
#if !defined(ZLIB_INTERNAL) && defined(Z_WANT64) && !defined(Z_LARGE64)
        arg->offset64 = gzoffset64(gzipEntity->gzs.get());
#else
        arg->offset = gzoffset(gzipEntity->gzs.get());
#endif
        if (arg->offset < 0 || arg->offset64 < 0) {
            return NapiBusinessError(ENOSTR, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
#if !defined(ZLIB_INTERNAL) && defined(Z_WANT64) && !defined(Z_LARGE64)
        return {NapiValue::CreateInt64(env, arg->offset64)};
#else
        return {NapiValue::CreateInt32(env, arg->offset)};
#endif
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZUnGetC(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    int32_t ascii = -1;
    bool succ = false;
    tie(succ, ascii) = CommonFunc::GetGZUnGetCArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }
    auto cbExec = [arg, ascii, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EINVAL, true);
        }
        arg->character = gzungetc(ascii, gzipEntity->gzs.get());
        if (arg->character < 0) {
            return NapiBusinessError(ENOSTR, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->character)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZClearerr(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EFAULT, true);
        }
        gzclearerr(gzipEntity->gzs.get());
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateUndefined(env)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZDirect(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = gzdirect(gzipEntity->gzs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZeof(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = gzeof(gzipEntity->gzs.get());
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

static NapiValue CreateGzErrorOutputInfoObject(napi_env env, const AsyncGZipArg *arg)
{
    /* To get entity */
    if (!arg) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return NapiValue(env, nullptr);
    }

    NapiValue obj = NapiValue::CreateObject(env);
    obj.AddProp({
        NapiValue::DeclareNapiProperty("status", NapiValue::CreateInt64(env, arg->errCode).val_),
        NapiValue::DeclareNapiProperty("statusMsg",
            NapiValue::CreateUTF8String(env, reinterpret_cast<const char *>(arg->errMsg), strlen(arg->errMsg)).val_),
    });

    return obj;
}

napi_value GZipNExporter::GZError(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errMsg = gzerror(gzipEntity->gzs.get(), &arg->errCode);
        if (arg->errMsg == nullptr) {
            return NapiBusinessError(EZSTREAM_ERROR, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg->errMsg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {CreateGzErrorOutputInfoObject(env, arg.get())};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value GZipNExporter::GZFlush(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ONE, ArgumentCount::TWO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    auto arg = make_shared<AsyncGZipArg>();
    /* To get entity */
    auto gzipEntity = NapiClass::GetEntityOf<GZipEntity>(env, funcArg.GetThisVar());
    if (!gzipEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    uint32_t flush = 0;
    tie(succ, flush) = CommonFunc::SetGZFlushArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto cbExec = [arg, gzipEntity, flush](napi_env env) -> NapiBusinessError {
        if (!gzipEntity) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->errCode = gzflush(gzipEntity->gzs.get(), flush);
        if (arg->errCode < 0) {
            return NapiBusinessError(arg->errCode, true);
        }
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        } else if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt32(env, arg->errCode)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ONE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_GZIP_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
