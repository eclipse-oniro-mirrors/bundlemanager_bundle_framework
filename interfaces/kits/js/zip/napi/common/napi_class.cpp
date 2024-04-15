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

#include "napi_class.h"

#include <iostream>
#include <sstream>

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
using namespace std;
NapiClass &NapiClass::GetInstance()
{
    static thread_local NapiClass nClass;
    return nClass;
}

tuple<bool, napi_value> NapiClass::DefineClass(
    napi_env env, const string &className, napi_callback constructor, vector<napi_property_descriptor> &&properties)
{
    napi_value classVal = nullptr;
    napi_status stat = napi_define_class(env,
        className.c_str(),
        className.length(),
        constructor,
        nullptr,
        properties.size(),
        properties.data(),
        &classVal);
    if (stat != napi_ok) {
        APP_LOGE("INNER BUG. Cannot define class %{public}s because of %{public}d", className.c_str(), stat);
    }
    return {stat == napi_ok, classVal};
}

bool NapiClass::SaveClass(napi_env env, const string &className, napi_value exClass)
{
    NapiClass &nClass = NapiClass::GetInstance();
    lock_guard(nClass.exClassMapLock);

    if (nClass.exClassMap.find(className) != nClass.exClassMap.end()) {
        return true;
    }

    napi_ref constructor;
    napi_status res = napi_create_reference(env, exClass, 1, &constructor);
    if (res == napi_ok) {
        nClass.exClassMap.insert({className, constructor});
    } else {
        APP_LOGE("INNER BUG. Cannot ref class constructor %{public}s because of %{public}d", className.c_str(), res);
    }

    return res == napi_ok;
}

napi_value NapiClass::InstantiateClass(napi_env env, const string &className, const vector<napi_value> &args)
{
    NapiClass &nClass = NapiClass::GetInstance();
    lock_guard(nClass.exClassMapLock);
    auto it = nClass.exClassMap.find(className);
    if (it == nClass.exClassMap.end()) {
        APP_LOGE("Class %{public}s hasn't been saved yet", className.c_str());
        return nullptr;
    }

    napi_value cons = nullptr;
    napi_status status = napi_get_reference_value(env, it->second, &cons);
    if (status != napi_ok) {
        APP_LOGE("INNER BUG. Cannot deref class %{public}s because of %{public}d", className.c_str(), status);
        return nullptr;
    }

    napi_value instance = nullptr;
    status = napi_new_instance(env, cons, args.size(), args.data(), &instance);
    if (status != napi_ok) {
        APP_LOGE("INNER BUG. Cannot instantiate the class %{public}s because of %{public}d", className.c_str(), status);
        return nullptr;
    }

    return instance;
}
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS