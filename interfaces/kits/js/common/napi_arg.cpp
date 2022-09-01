/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "napi_arg.h"

namespace OHOS {
namespace AppExecFwk {
bool NapiArg::Init(size_t expectedArgc)
{
    argc = expectedArgc;
    argv = std::make_unique<napi_value[]>(expectedArgc);
    napi_value thisArg_ = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv.get(), &thisArg_, nullptr);
    if (status != napi_ok) {
        APP_LOGE("Cannot get num of func args for %{public}d", status);
        return false;
    }
    if (argc != expectedArgc) {
        APP_LOGE("Incorrect number of arguments for %{public}d", status);
        return false;
    } else {
        return true;
    }
}

bool NapiArg::Init(size_t minArgc, size_t maxArgc)
{
    SetArgc(0);
    argv.reset();
    size_t argc_;
    napi_value thisArg_;
    napi_status status = napi_get_cb_info(env, info, &argc_, nullptr, &thisArg_, nullptr);
    if (status != napi_ok) {
        APP_LOGE("Cannot get num of func args for %{public}d", status);
        return false;
    }
    if (argc_) {
        argv = std::make_unique<napi_value[]>(argc_);
        status = napi_get_cb_info(env, info, &argc_, argv.get(), &thisArg_, nullptr);
        if (status != napi_ok) {
            APP_LOGE("Cannot get func args for %{public}d", status);
            return false;
        }
    }
    argc = argc_;
    thisArg = thisArg_;
    return true;
}

size_t NapiArg::GetArgc() const
{
    return argc;
}

void NapiArg::SetArgc(size_t argc_)
{
    argc = argc_;
}

napi_value NapiArg::GetThisArg() const
{
    return thisArg;
}

napi_value NapiArg::GetArgv(size_t pos) const
{
    return (pos < argc) ? argv[pos] : nullptr;
}

napi_value NapiArg::operator[](size_t pos) const
{
    return GetArgv(pos);
}
}
}