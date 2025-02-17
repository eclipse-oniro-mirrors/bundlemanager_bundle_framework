/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "create_checksum.h"

#include <memory>
#include <tuple>

#include "class_checksum/checksum_entity.h"
#include "class_checksum/checksum_n_exporter.h"
#include "common/common_func.h"
#include "common/file_utils.h"
#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {

static NapiValue InstantiateChecksum(napi_env env)
{
    napi_value objChecksum = NapiClass::InstantiateClass(env, ChecksumNExporter::className_, {});
    if (!objChecksum) {
        NapiBusinessError(EFAULT, true).ThrowErr(env, "INNER BUG. Cannot instantiate stream");
        return NapiValue();
    }

    return { env, objChecksum };
}

napi_value CreateChecksum::Sync(napi_env env, napi_callback_info info)
{
    return InstantiateChecksum(env).val_;
}

napi_value CreateChecksum::Async(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        APP_LOGE("Number of arguments unmatched");
        NapiBusinessError(EINVAL, true).ThrowErr(env);
        return nullptr;
    }

    auto cbExec = [](napi_env env) -> NapiBusinessError {
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return { env, err.GetNapiErr(env) };
        }
        return InstantiateChecksum(env);
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CREATE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::FIRST]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CREATE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }
}
} // namespace LIBZIP
} // namespace AppExecFwk
} // namespace OHOS