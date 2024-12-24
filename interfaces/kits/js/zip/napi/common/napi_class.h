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

#ifndef INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_CLASS_H
#define INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_CLASS_H

#include "header.h"

#include <map>

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
class NapiClass final {
public:
    NapiClass(const NapiClass &) = delete;
    NapiClass &operator=(const NapiClass &) = delete;
    static NapiClass &GetInstance();

    static std::tuple<bool, napi_value> DefineClass(napi_env env, const std::string &className,
        napi_callback constructor, std::vector<napi_property_descriptor> &&properties);
    static bool SaveClass(napi_env env, const std::string &className, napi_value exClass);
    static napi_value InstantiateClass(napi_env env, const std::string &className, const std::vector<napi_value> &args);

    template <class T>
    static T *GetEntityOf(napi_env env, napi_value objStat)
    {
        if (!env || !objStat) {
            APP_LOGE("Empty input: env %d, obj %d", env == nullptr, objStat == nullptr);
            return nullptr;
        }
        T *t = nullptr;
        napi_status status = napi_unwrap(env, objStat, (void **)&t);
        if (status != napi_ok) {
            APP_LOGE("Cannot umwarp for pointer: %d", status);
            return nullptr;
        }
        return t;
    }

    template <class T>
    static bool SetEntityFor(napi_env env, napi_value obj, std::unique_ptr<T> entity)
    {
        napi_status status = napi_wrap(
            env,
            obj,
            entity.get(),
            [](napi_env env, void *data, void *hint) {
                auto entity = static_cast<T *>(data);
                delete entity;
            },
            nullptr,
            nullptr);
        entity.release();
        return status == napi_ok;
    }

    template <class T>
    static T *RemoveEntityOfFinal(napi_env env, napi_value objStat)
    {
        if (!env || !objStat) {
            APP_LOGD("Empty input: env %d,obj %d", env == nullptr, objStat == nullptr);
            return nullptr;
        }
        T *t = nullptr;
        napi_status status = napi_remove_wrap(env, objStat, (void **)&t);
        if (status != napi_ok) {
            APP_LOGD("Cannot umwrap for pointer: %d", status);
            return nullptr;
        }
        return t;
    }

private:
    NapiClass() = default;
    ~NapiClass() = default;
    std::mutex exClassMapLock;
    std::map<std::string, napi_ref> exClassMap;
};
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_CLASS_H