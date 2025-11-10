/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "checksum_n_exporter.h"

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
#include "checksum_common_func.h"
#include "checksum_entity.h"
#include "zlib.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
using namespace std;

struct AsyncChecksumArg {
    uint64_t adler{0U};
    const z_crc_t* crcTable = nullptr;

    AsyncChecksumArg() = default;
    ~AsyncChecksumArg() = default;
};

napi_value ChecksumNExporter::Constructor(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    std::unique_ptr<ChecksumEntity> checksumEntity = std::make_unique<ChecksumEntity>();
    if (!NapiClass::SetEntityFor<ChecksumEntity>(env, funcArg.GetThisVar(), move(checksumEntity))) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }
    return funcArg.GetThisVar();
}

bool ChecksumNExporter::Export()
{
    std::vector<napi_property_descriptor> props = {
        NapiValue::DeclareNapiFunction("adler32", Adler32),
        NapiValue::DeclareNapiFunction("adler32Combine", Adler32Combine),
        NapiValue::DeclareNapiFunction("adler32Combine64", Adler32Combine64),
        NapiValue::DeclareNapiFunction("crc32", Crc32),
        NapiValue::DeclareNapiFunction("crc32Combine", Crc32Combine),
        NapiValue::DeclareNapiFunction("crc32Combine64", Crc32Combine64),
        NapiValue::DeclareNapiFunction("getCrcTable", GetCrcTable),
        NapiValue::DeclareNapiFunction("getCrc64Table", GetCrc64Table),
        NapiValue::DeclareNapiFunction("crc64", Crc64),
    };

    std::string className = GetClassName();
    bool succ = false;
    napi_value cls = nullptr;
    tie(succ, cls) = NapiClass::DefineClass(exports_.env_, className, ChecksumNExporter::Constructor, move(props));
    if (!succ) {
        NapiBusinessError().ThrowErr(exports_.env_, EFAULT);
        return false;
    }
    succ = NapiClass::SaveClass(exports_.env_, className, cls);
    if (!succ) {
        NapiBusinessError().ThrowErr(exports_.env_, EFAULT);
        return false;
    }

    return exports_.AddProp(className, cls);
}

std::string ChecksumNExporter::GetClassName()
{
    return ChecksumNExporter::className_;
}

ChecksumNExporter::ChecksumNExporter(napi_env env, napi_value exports) : NapiExporter(env, exports)
{}

ChecksumNExporter::~ChecksumNExporter()
{}

napi_value ChecksumNExporter::Adler32(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto checksumEntity = NapiClass::GetEntityOf<ChecksumEntity>(env, funcArg.GetThisVar());
    if (!checksumEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    void *buf = nullptr;
    size_t len = 0;
    uLong adler = 0U;
    tie(succ, adler, buf, len) = CommonFunc::GetAdler32Arg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = std::make_shared<AsyncChecksumArg>();
    auto cbExec = [arg, adler, buf, len](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->adler = adler32(static_cast<uLong>(adler), reinterpret_cast<Bytef *>(buf), static_cast<uInt>(len));
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->adler)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::THIRD]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::Adler32Combine(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::THREE, ArgumentCount::FOUR)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto checksumEntity = NapiClass::GetEntityOf<ChecksumEntity>(env, funcArg.GetThisVar());
    if (!checksumEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    size_t len = 0;
    uLong adler1 = 0U;
    uLong adler2 = 0U;
    tie(succ, adler1, adler2, len) = CommonFunc::GetAdler32CombineArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = std::make_shared<AsyncChecksumArg>();
    auto cbExec = [arg, adler1, adler2, len](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
#ifdef Z_LARGE64
        arg->adler = adler32_combine64(static_cast<uLong>(adler1), static_cast<uLong>(adler2), static_cast<uInt>(len));
#else
        arg->adler = adler32_combine(static_cast<uLong>(adler1), static_cast<uLong>(adler2), static_cast<uInt>(len));
#endif
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->adler)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::FOURTH]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::Adler32Combine64(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::THREE, ArgumentCount::FOUR)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto checksumEntity = NapiClass::GetEntityOf<ChecksumEntity>(env, funcArg.GetThisVar());
    if (!checksumEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    size_t len = 0;
    uLong adler1 = 0U;
    uLong adler2 = 0U;
    tie(succ, adler1, adler2, len) = CommonFunc::GetAdler32CombineArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = std::make_shared<AsyncChecksumArg>();
    auto cbExec = [arg, adler1, adler2, len](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->adler = adler32_combine(static_cast<uLong>(adler1), static_cast<uLong>(adler2), static_cast<uInt>(len));
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->adler)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::FOURTH]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::Crc32(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto checksumEntity = NapiClass::GetEntityOf<ChecksumEntity>(env, funcArg.GetThisVar());
    if (!checksumEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    void *buf = nullptr;
    size_t len = 0;
    uLong adler = 0U;
    tie(succ, adler, buf, len) = CommonFunc::GetAdler32Arg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = std::make_shared<AsyncChecksumArg>();
    auto cbExec = [arg, adler, buf, len](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->adler = crc32(static_cast<uLong>(adler), reinterpret_cast<Bytef *>(buf), static_cast<uInt>(len));
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->adler)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::THIRD]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::Crc32Combine(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::THREE, ArgumentCount::FOUR)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto checksumEntity = NapiClass::GetEntityOf<ChecksumEntity>(env, funcArg.GetThisVar());
    if (!checksumEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    int64_t len = 0;
    uLong adler1 = 0U;
    uLong adler2 = 0U;
    tie(succ, adler1, adler2, len) = CommonFunc::GetAdler32CombineArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = std::make_shared<AsyncChecksumArg>();
    auto cbExec = [arg, adler1, adler2, len](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
#ifdef Z_LARGE64
        arg->adler =
            crc32_combine64(static_cast<uLong>(adler1), static_cast<uLong>(adler2), static_cast<z_off64_t>(len));
#else
        arg->adler = crc32_combine(static_cast<uLong>(adler1), static_cast<uLong>(adler2), static_cast<z_off_t>(len));
#endif
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->adler)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::FOURTH]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::Crc32Combine64(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::THREE, ArgumentCount::FOUR)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto checksumEntity = NapiClass::GetEntityOf<ChecksumEntity>(env, funcArg.GetThisVar());
    if (!checksumEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    size_t len = 0;
    uLong adler1 = 0U;
    uLong adler2 = 0U;
    tie(succ, adler1, adler2, len) = CommonFunc::GetAdler32CombineArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = std::make_shared<AsyncChecksumArg>();
    auto cbExec = [arg, adler1, adler2, len](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->adler = crc32_combine(static_cast<uLong>(adler1), static_cast<uLong>(adler2), static_cast<uInt>(len));
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->adler)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::FOURTH]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::GetCrcTable(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    size_t tableSize = 256;
    auto arg = std::make_shared<AsyncChecksumArg>();
    auto cbExec = [arg](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->crcTable = get_crc_table();
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg, tableSize](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        std::vector<int64_t> crcVector(tableSize);
        for (size_t i = 0; i < tableSize; ++i) {
            crcVector[i] = static_cast<int64_t>(arg->crcTable[i]);
        }
        return {NapiValue::CreateInt64Array(env, crcVector)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::FIRST]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::Crc64(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    bool succ = false;
    void *buf = nullptr;
    size_t len = 0;
    uint64_t crc64 = 0U;
    tie(succ, crc64, buf, len) = CommonFunc::GetCrc64Arg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = std::make_shared<AsyncChecksumArg>();
    auto cbExec = [arg, crc64, buf, len](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->adler = ComputeCrc64(crc64, reinterpret_cast<char *>(buf), len);
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateUint64(env, arg->adler)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::THIRD]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::GetCrc64Table(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    size_t tableSize = 256;
    auto arg = std::make_shared<AsyncChecksumArg>();
    auto cbExec = [](napi_env env) -> NapiBusinessError {
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg, tableSize](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        std::vector<uint64_t> crcVector(tableSize);
        for (size_t i = 0; i < tableSize; ++i) {
            crcVector[i] = static_cast<uint64_t>(CRC64_TABLE[i]);
        }
        return {NapiValue::CreateBigUint64Array(env, crcVector)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::FIRST]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS