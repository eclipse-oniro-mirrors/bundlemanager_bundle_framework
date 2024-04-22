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

#ifndef INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_VALUE_H
#define INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_VALUE_H

#include <string_view>
#include <any>
#include <tuple>

#include "sys/types.h"
#include "header.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
class NapiValue final {
public:
    NapiValue() = default;
    NapiValue(napi_env nEnv, napi_value NapiValue);
    NapiValue(const NapiValue &) = default;
    NapiValue &operator=(const NapiValue &) = default;
    virtual ~NapiValue() = default;

    // NOTE! env_ and val_ is LIKELY to be null
    napi_env env_ = nullptr;
    napi_value val_ = nullptr;

    explicit operator bool() const;
    bool TypeIs(napi_valuetype expType) const;
    bool TypeIsError(bool checkErrno = false) const;

    /* SHOULD ONLY BE USED FOR EXPECTED TYPE */
    std::tuple<bool, std::unique_ptr<char[]>, size_t> ToUTF8String() const;
    std::tuple<bool, std::unique_ptr<char[]>, size_t> ToUTF8String(std::string_view defaultValue) const;
    std::tuple<bool, std::unique_ptr<char[]>, size_t> ToUTF16String() const;
    std::tuple<bool, void *> ToPointer() const;
    std::tuple<bool, bool> ToBool() const;
    std::tuple<bool, bool> ToBool(bool defaultValue) const;
    std::tuple<bool, int32_t> ToInt32() const;
    std::tuple<bool, int32_t> ToInt32(int32_t defaultValue) const;
    std::tuple<bool, int64_t> ToInt64() const;
    std::tuple<bool, int64_t> ToInt64(int64_t defaultValue) const;
    std::tuple<bool, void *, size_t> ToArrayBuffer() const;
    std::tuple<bool, void *, size_t> ToTypedArray() const;
    std::tuple<bool, std::vector<std::string>, uint32_t> ToStringArray();
    std::tuple<bool, uint64_t, bool> ToUint64() const;
    std::tuple<bool, uint32_t> ToUint32() const;
    std::tuple<bool, double> ToDouble() const;

    /* Static helpers to create js objects */
    static NapiValue CreateUndefined(napi_env env);
    static NapiValue CreateBigInt64(napi_env env, int64_t val);
    static NapiValue CreateInt64(napi_env env, int64_t val);
    static NapiValue CreateUint64(napi_env env, uint64_t val);
    static NapiValue CreateInt32(napi_env env, int32_t val);
    static NapiValue CreateObject(napi_env env);
    static NapiValue CreateBool(napi_env env, bool val);
    static NapiValue CreateUTF8String(napi_env env, const std::string &str);
    static NapiValue CreateUTF8String(napi_env env, const char *str, ssize_t len);
    static NapiValue CreateUint8Array(napi_env env, void *buf, size_t bufLen);
    static NapiValue CreateArrayString(napi_env env, const std::vector<std::string> &strs);
    static std::tuple<NapiValue, void *> CreateArrayBuffer(napi_env env, size_t len);
    static NapiValue CreateInt64Array(napi_env env, const std::vector<int64_t> &int64Array);
    static NapiValue CreateBigUint64Array(napi_env env, const std::vector<uint64_t> &int64Array);
    /* SHOULD ONLY BE USED FOR OBJECT */
    bool HasProp(const std::string &propName) const;
    NapiValue GetProp(const std::string &propName) const;
    bool AddProp(std::vector<napi_property_descriptor> &&propVec) const;
    bool AddProp(const std::string &propName, napi_value val) const;

    /* Static helpers to create prop of js objects */
    static napi_property_descriptor DeclareNapiProperty(const char *name, napi_value val);
    static napi_property_descriptor DeclareNapiStaticProperty(const char *name, napi_value val);
    static napi_property_descriptor DeclareNapiFunction(const char *name, napi_callback func);
    static napi_property_descriptor DeclareNapiStaticFunction(const char *name, napi_callback func);
    static napi_property_descriptor DeclareNapiGetter(const char *name, napi_callback getter);
    static napi_property_descriptor DeclareNapiSetter(const char *name, napi_callback setter);
    static inline napi_property_descriptor DeclareNapiGetterSetter(
        const char *name, napi_callback getter, napi_callback setter);
};
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_VALUE_H