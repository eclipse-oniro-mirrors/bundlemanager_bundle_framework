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

#include "napi_func_arg.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {

NapiFuncArg::NapiFuncArg(napi_env env, napi_callback_info info) : env_(env), info_(info)
{}

NapiFuncArg::~NapiFuncArg()
{}

void NapiFuncArg::SetArgc(size_t argc)
{
    argc_ = argc;
}

void NapiFuncArg::SetThisVar(napi_value thisVar)
{
    thisVar_ = thisVar;
}

size_t NapiFuncArg::GetArgc(void) const
{
    return argc_;
}

napi_value NapiFuncArg::GetThisVar(void) const
{
    return thisVar_;
}

napi_value NapiFuncArg::GetArg(size_t argPos) const
{
    return (argPos < GetArgc()) ? argv_[argPos] : nullptr;
}

napi_value NapiFuncArg::operator[](size_t argPos) const
{
    return GetArg(argPos);
}

bool NapiFuncArg::InitArgs(std::function<bool()> argcChecker)
{
    SetArgc(0);
    argv_.reset();
    size_t argc;
    napi_value thisVar;
    napi_status status = napi_get_cb_info(env_, info_, &argc, nullptr, &thisVar, nullptr);
    if (status != napi_ok) {
        APP_LOGE("Cannot get num of func args for %{public}d", status);
        return false;
    }

    if (argc) {
        argv_ = std::make_unique<napi_value[]>(argc);
        status = napi_get_cb_info(env_, info_, &argc, argv_.get(), &thisVar, nullptr);
        if (status != napi_ok) {
            APP_LOGE("Cannot get func args for %{public}d", status);
            return false;
        }
    }

    SetArgc(argc);
    SetThisVar(thisVar);
    return argcChecker();
}

bool NapiFuncArg::InitArgs(size_t argc)
{
    return InitArgs([argc, this]() {
        size_t realArgc = GetArgc();
        if (argc != realArgc) {
            APP_LOGE("Num of args recved eq %zu while expecting %{public}zu", realArgc, argc);
            return false;
        }
        return true;
    });
}

bool NapiFuncArg::InitArgs(size_t minArgc, size_t maxArgc)
{
    return InitArgs([minArgc, maxArgc, this]() {
        size_t realArgc = GetArgc();
        if (minArgc > realArgc || maxArgc < realArgc) {
            APP_LOGE("Num of args recved eq %zu while expecting %{public}zu ~ %{public}zu", realArgc, minArgc, maxArgc);
            return false;
        }
        return true;
    });
}
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS