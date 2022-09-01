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
    argc_ = 0;
    argv_.reset();
    size_t argc;
    napi_value thisArg;
    // get argc first, in case of argv overflow
    napi_status status = napi_get_cb_info(env_, info_, &argc, nullptr, &thisArg, nullptr);
    if (status != napi_ok) {
        APP_LOGE("Cannot get number of func args for %{public}d", status);
        return false;
    }
    if (argc == 0) {
        thisArg_ = thisArg;
        return true;
    }
    if (argc == expectedArgc) {
        argv_ = std::make_unique<napi_value[]>(argc);
        status = napi_get_cb_info(env_, info_, &argc, argv_.get(), &thisArg, nullptr);
        if (status != napi_ok) {
            APP_LOGE("Cannot get func args for %{public}d", status);
            return false;
        }
    } else {
        APP_LOGE("Incorrect number of arguments");
        return false;
    }
    argc_ = argc;
    thisArg_ = thisArg;
    return true;
}

bool NapiArg::Init(size_t minArgc, size_t maxArgc)
{
    argc_ = 0;
    argv_.reset();
    size_t argc;
    napi_value thisArg;
    // get argc first, in case of argv overflow
    napi_status status = napi_get_cb_info(env_, info_, &argc, nullptr, &thisArg, nullptr);
    if (status != napi_ok) {
        APP_LOGE("Cannot get num of func args for %{public}d", status);
        return false;
    }
    if (argc == 0) {
        thisArg_ = thisArg;
        return true;
    }
    if (argc >= minArgc && argc <= maxArgc) {
        argv_ = std::make_unique<napi_value[]>(argc);
        status = napi_get_cb_info(env_, info_, &argc, argv_.get(), &thisArg, nullptr);
        if (status != napi_ok) {
            APP_LOGE("Cannot get func args for %{public}d", status);
            return false;
        }
    } else {
        APP_LOGE("Incorrect number of arguments");
        return false;
    }
    argc_ = argc;
    thisArg_ = thisArg;
    return true;
}

size_t NapiArg::GetArgc() const
{
    return argc_;
}

napi_value NapiArg::GetThisArg() const
{
    return thisArg_;
}

napi_value NapiArg::GetArgv(size_t pos) const
{
    return (pos < argc_) ? argv_[pos] : nullptr;
}

napi_value NapiArg::operator[](size_t pos) const
{
    return GetArgv(pos);
}
}
}