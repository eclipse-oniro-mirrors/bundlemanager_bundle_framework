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

#include "napi_value.h"

#include <string>

#include "app_log_wrapper.h"
#include "napi_business_error.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
using namespace std;

NapiValue::NapiValue(napi_env nEnv, napi_value NapiValue = nullptr) : env_(nEnv), val_(NapiValue)
{}

NapiValue::operator bool() const
{
    return env_ && val_;
}

bool NapiValue::TypeIs(napi_valuetype expType) const
{
    if (!*this) {
        return false;
    }

    napi_valuetype valueType;
    napi_typeof(env_, val_, &valueType);
    if (expType != valueType) {
        return false;
    }

    return true;
}

bool NapiValue::TypeIsError(bool checkErrno) const
{
    if (!*this) {
        return false;
    }

    bool res = false;
    napi_is_error(env_, val_, &res);

    return res;
}

std::tuple<bool, std::unique_ptr<char[]>, size_t> NapiValue::ToUTF8String() const
{
    size_t strLen = 0;
    napi_status status = napi_get_value_string_utf8(env_, val_, nullptr, -1, &strLen);
    if (status != napi_ok) {
        return {false, nullptr, 0};
    }

    size_t bufLen = strLen + 1;
    std::unique_ptr<char[]> str = std::make_unique<char[]>(bufLen);
    status = napi_get_value_string_utf8(env_, val_, str.get(), bufLen, &strLen);
    return make_tuple(status == napi_ok, move(str), strLen);
}

std::tuple<bool, std::unique_ptr<char[]>, size_t> NapiValue::ToUTF8String(string_view defaultValue) const
{
    if (TypeIs(napi_undefined) || TypeIs(napi_function)) {
        auto str = std::make_unique<char[]>(defaultValue.size() + 1);
        copy(defaultValue.begin(), defaultValue.end(), str.get());
        return make_tuple(true, move(str), defaultValue.size());
    }
    return ToUTF8String();
}

std::tuple<bool, std::unique_ptr<char[]>, size_t> NapiValue::ToUTF16String() const
{
#ifdef FILE_SUBSYSTEM_DEBUG_LOCAL
    size_t strLen = 0;
    napi_status status = napi_get_value_string_utf16(env_, val_, nullptr, -1, &strLen);
    if (status != napi_ok) {
        return {false, nullptr, 0};
    }

    auto str = std::make_unique<char16_t[]>(++strLen);
    status = napi_get_value_string_utf16(env_, val_, str.get(), strLen, nullptr);
    if (status != napi_ok) {
        return {false, nullptr, 0};
    }

    strLen = reinterpret_cast<char *>(str.get() + strLen) - reinterpret_cast<char *>(str.get());
    auto strRet = unique_ptr<char[]>(reinterpret_cast<char *>(str.release()));
    return {true, move(strRet), strLen};
#else
    // Note that quickjs doesn't support utf16
    return ToUTF8String();
#endif
}

std::tuple<bool, void *> NapiValue::ToPointer() const
{
    void *res = nullptr;
    napi_status status = napi_get_value_external(env_, val_, &res);
    return std::make_tuple(status == napi_ok, res);
}

std::tuple<bool, bool> NapiValue::ToBool() const
{
    bool flag = false;
    napi_status status = napi_get_value_bool(env_, val_, &flag);
    return std::make_tuple(status == napi_ok, flag);
}

std::tuple<bool, bool> NapiValue::ToBool(bool defaultValue) const
{
    if (TypeIs(napi_undefined) || TypeIs(napi_function)) {
        return std::make_tuple(true, defaultValue);
    }
    return ToBool();
}

std::tuple<bool, int32_t> NapiValue::ToInt32() const
{
    int32_t res = 0;
    napi_status status = napi_get_value_int32(env_, val_, &res);
    return std::make_tuple(status == napi_ok, res);
}

tuple<bool, int32_t> NapiValue::ToInt32(int32_t defaultValue) const
{
    if (TypeIs(napi_undefined) || TypeIs(napi_function)) {
        return make_tuple(true, defaultValue);
    }
    return ToInt32();
}

tuple<bool, int64_t> NapiValue::ToInt64() const
{
    int64_t res = 0;
    napi_status status = napi_get_value_int64(env_, val_, &res);
    return make_tuple(status == napi_ok, res);
}

tuple<bool, int64_t> NapiValue::ToInt64(int64_t defaultValue) const
{
    if (TypeIs(napi_undefined) || TypeIs(napi_function) || TypeIs(napi_null)) {
        return make_tuple(true, defaultValue);
    }
    return ToInt64();
}

std::tuple<bool, uint32_t> NapiValue::ToUint32() const
{
    uint32_t res = 0;
    napi_status status = napi_get_value_uint32(env_, val_, &res);
    return make_tuple(status == napi_ok, res);
}

std::tuple<bool, double> NapiValue::ToDouble() const
{
    double res = 0;
    napi_status status = napi_get_value_double(env_, val_, &res);
    return make_tuple(status == napi_ok, res);
}

std::tuple<bool, uint64_t, bool> NapiValue::ToUint64() const
{
    uint64_t res = 0;
    bool lossless = false;
    napi_status status = napi_get_value_bigint_uint64(env_, val_, &res, &lossless);
    return make_tuple(status == napi_ok, res, lossless);
}

std::tuple<bool, std::vector<string>, uint32_t> NapiValue::ToStringArray()
{
    uint32_t size;
    napi_status status = napi_get_array_length(env_, val_, &size);
    std::vector<string> stringArray;
    napi_value result;
    for (uint32_t i = 0; i < size; i++) {
        status = napi_get_element(env_, val_, i, &result);
        auto [succ, str, ignore] = NapiValue(env_, result).ToUTF8String();
        stringArray.push_back(string(str.get()));
    }
    return make_tuple(status == napi_ok, stringArray, size);
}

std::tuple<bool, void *, size_t> NapiValue::ToArrayBuffer() const
{
    void *buf = nullptr;
    size_t bufLen = 0;
    bool status = napi_get_arraybuffer_info(env_, val_, &buf, &bufLen);
    return make_tuple(status == napi_ok, buf, bufLen);
}

std::tuple<bool, void *, size_t> NapiValue::ToTypedArray() const
{
    napi_typedarray_type type;
    napi_value in_array_buffer = nullptr;
    size_t byteOffset;
    size_t length;
    void *data = nullptr;
    napi_status status =
        napi_get_typedarray_info(env_, val_, &type, &length, (void **)&data, &in_array_buffer, &byteOffset);
    return make_tuple(status == napi_ok, data, length);
}

bool NapiValue::HasProp(const std::string& propName) const
{
    bool res = false;

    if (!env_ || !val_ || !TypeIs(napi_object)) {
        return false;
    }

    napi_status status = napi_has_named_property(env_, val_, propName.c_str(), &res);
    return (status == napi_ok) && res;
}

NapiValue NapiValue::GetProp(const std::string &propName) const
{
    if (!HasProp(propName)) {
        return {env_, nullptr};
    }

    napi_value prop = nullptr;
    napi_status status = napi_get_named_property(env_, val_, propName.c_str(), &prop);
    if (status != napi_ok) {
        return {env_, nullptr};
    }

    return NapiValue(env_, prop);
}

bool NapiValue::AddProp(vector<napi_property_descriptor> &&propVec) const
{
    if (!TypeIs(napi_valuetype::napi_object)) {
        APP_LOGE("INNER BUG. Prop should only be added to objects");
        return false;
    }

    napi_status status = napi_define_properties(env_, val_, propVec.size(), propVec.data());
    if (status != napi_ok) {
        APP_LOGE("INNER BUG. Cannot define properties because of %{public}d", status);
        return false;
    }

    return true;
}

bool NapiValue::AddProp(const std::string &propName, napi_value val) const
{
    if (!TypeIs(napi_valuetype::napi_object) || HasProp(propName)) {
        APP_LOGE("INNER BUG. Prop should only be added to objects");
        return false;
    }

    napi_status status = napi_set_named_property(env_, val_, propName.c_str(), val);
    if (status != napi_ok) {
        APP_LOGE("INNER BUG. Cannot set named property because of %{public}d", status);
        return false;
    }

    return true;
}

NapiValue NapiValue::CreateUndefined(napi_env env)
{
    napi_value res = nullptr;
    napi_get_undefined(env, &res);
    return {env, res};
}

NapiValue NapiValue::CreateBigInt64(napi_env env, int64_t val)
{
    napi_value res = nullptr;
    napi_create_bigint_int64(env, val, &res);
    return {env, res};
}

NapiValue NapiValue::CreateInt64(napi_env env, int64_t val)
{
    napi_value res = nullptr;
    napi_create_int64(env, val, &res);
    return {env, res};
}

NapiValue NapiValue::CreateUint64(napi_env env, uint64_t val)
{
    napi_value res = nullptr;
    napi_create_bigint_uint64(env, val, &res);
    return {env, res};
}

NapiValue NapiValue::CreateInt32(napi_env env, int32_t val)
{
    napi_value res = nullptr;
    napi_create_int32(env, val, &res);
    return {env, res};
}

NapiValue NapiValue::CreateUint32(napi_env env, uint32_t val)
{
    napi_value res = nullptr;
    napi_create_uint32(env, val, &res);
    return {env, res};
}

NapiValue NapiValue::CreateObject(napi_env env)
{
    napi_value res = nullptr;
    napi_create_object(env, &res);
    return {env, res};
}

NapiValue NapiValue::CreateBool(napi_env env, bool val)
{
    napi_value res = nullptr;
    napi_get_boolean(env, val, &res);
    return {env, res};
}

NapiValue NapiValue::CreateUTF8String(napi_env env, const std::string &str)
{
    napi_value res = nullptr;
    napi_create_string_utf8(env, str.c_str(), str.length(), &res);
    return {env, res};
}

NapiValue NapiValue::CreateUTF8String(napi_env env, const char *str, ssize_t len)
{
    napi_value res = nullptr;
    napi_create_string_utf8(env, str, len, &res);
    return {env, res};
}

NapiValue NapiValue::CreateUint8Array(napi_env env, void *buf, size_t bufLen)
{
    napi_value output_buffer = nullptr;
    napi_create_external_arraybuffer(
        env,
        buf,
        bufLen,
        [](napi_env env, void *finalize_data, void *finalize_hint) { free(finalize_data); },
        NULL,
        &output_buffer);
    napi_value output_array = nullptr;
    napi_create_typedarray(env, napi_uint8_array, bufLen, output_buffer, 0, &output_array);
    return {env, output_array};
}

NapiValue NapiValue::CreateArrayString(napi_env env, const std::vector<string> &strs)
{
    napi_value res = nullptr;
    napi_create_array(env, &res);
    for (size_t i = 0; i < strs.size(); i++) {
        napi_value filename;
        napi_create_string_utf8(env, strs[i].c_str(), strs[i].length(), &filename);
        napi_set_element(env, res, i, filename);
    }
    return {env, res};
}

std::tuple<NapiValue, void *> NapiValue::CreateArrayBuffer(napi_env env, size_t len)
{
    napi_value val;
    void *buf = nullptr;
    napi_create_arraybuffer(env, len, &buf, &val);
    return {{env, val}, {buf}};
}

NapiValue NapiValue::CreateInt64Array(napi_env env, const std::vector<int64_t> &int64Array)
{
    napi_value jsArray;
    napi_create_array(env, &jsArray);
    for (size_t i = 0; i < int64Array.size(); ++i) {
        napi_value jsNumber;
        napi_create_int64(env, int64Array[i], &jsNumber);
        napi_set_element(env, jsArray, i, jsNumber);
    }

    return {env, jsArray};
}

NapiValue NapiValue::CreateBigUint64Array(napi_env env, const std::vector<uint64_t> &int64Array)
{
    napi_value jsArray;
    napi_create_array(env, &jsArray);
    for (size_t i = 0; i < int64Array.size(); ++i) {
        napi_value jsNumber;
        napi_create_bigint_uint64(env, int64Array[i], &jsNumber);
        napi_set_element(env, jsArray, i, jsNumber);
    }

    return {env, jsArray};
}

napi_property_descriptor NapiValue::DeclareNapiProperty(const char *name, napi_value val)
{
    return {(name), nullptr, nullptr, nullptr, nullptr, val, napi_default, nullptr};
}

napi_property_descriptor NapiValue::DeclareNapiStaticProperty(const char *name, napi_value val)
{
    return {(name), nullptr, nullptr, nullptr, nullptr, val, napi_static, nullptr};
}

napi_property_descriptor NapiValue::DeclareNapiFunction(const char *name, napi_callback func)
{
    return {(name), nullptr, (func), nullptr, nullptr, nullptr, napi_default, nullptr};
}

napi_property_descriptor NapiValue::DeclareNapiStaticFunction(const char *name, napi_callback func)
{
    return {(name), nullptr, (func), nullptr, nullptr, nullptr, napi_static, nullptr};
}

napi_property_descriptor NapiValue::DeclareNapiGetter(const char *name, napi_callback getter)
{
    return {(name), nullptr, nullptr, (getter), nullptr, nullptr, napi_default, nullptr};
}

napi_property_descriptor NapiValue::DeclareNapiSetter(const char *name, napi_callback setter)
{
    return {(name), nullptr, nullptr, nullptr, (setter), nullptr, napi_default, nullptr};
}

napi_property_descriptor NapiValue::DeclareNapiGetterSetter(
    const char* name, napi_callback getter, napi_callback setter)
{
    return { (name), nullptr, nullptr, (getter), (setter), nullptr, napi_default, nullptr };
}
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS