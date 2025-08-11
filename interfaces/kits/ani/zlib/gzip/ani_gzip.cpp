/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ani_gzip.h"
#include "ani_signature_builder.h"
#include "ani_zlib_common.h"
#include "enum_util.h"
#include "napi_business_error.h"
#include "napi_constants.h"
#include "zlib.h"

namespace OHOS {
namespace AppExecFwk {
namespace AniZLibGZip {
namespace {
constexpr const char* CLASSNAME_STRING = "std.core.String";
constexpr const char* CLASSNAME_DOUBLE = "std.core.Double";
constexpr const char* CLASSNAME_GZ_ERROR_OUTPUT_INFO_INNER = "@ohos.zlib.zlib.GzErrorOutputInfoInner";
constexpr const char* FIELD_NAME_NATIVEGZFILE = "nativeGZFile";
constexpr int INVALID_FD = -1;
constexpr uint8_t MIN_ASCII = 0;
constexpr uint8_t MAX_ASCII = 255;
} // namespace
using namespace arkts::ani_signature;

static bool TryGetNativeGZFile(ani_env* env, ani_object instance, gzFile& file, int throwsOnError)
{
    ani_long longValue = 0;
    ani_status status = env->Object_GetFieldByName_Long(instance, FIELD_NAME_NATIVEGZFILE, &longValue);
    if (status != ANI_OK) {
        APP_LOGE("Object_GetFieldByName_Long failed %{public}d", status);
        AniZLibCommon::ThrowZLibNapiError(env, throwsOnError);
        return false;
    }

    file = reinterpret_cast<gzFile>(longValue);
    return true;
}

static bool TrySetNativeGZFile(ani_env* env, ani_object instance, gzFile natieGZFile)
{
    ani_long longValue = 0;
    ani_status status =
        env->Object_SetFieldByName_Long(instance, FIELD_NAME_NATIVEGZFILE, reinterpret_cast<ani_long>(natieGZFile));
    if (status != ANI_OK) {
        APP_LOGE("Object_GetFieldByName_Long failed %{public}d", status);
        return false;
    }
    return true;
}

static bool TryGetStringArg(ani_env* env, ani_array_ref args, ani_size index, std::string& output)
{
    ani_ref ref = nullptr;
    ani_status status = env->Array_Get_Ref(args, index, &ref);
    if (status != ANI_OK) {
        APP_LOGE("Array_Get_Ref failed %{public}d", status);
        return false;
    }

    ani_boolean isNull = ANI_FALSE;
    status = env->Reference_IsNull(ref, &isNull);
    if (status != ANI_OK) {
        APP_LOGE("Reference_IsNull failed %{public}d", status);
        return false;
    }
    if (isNull == ANI_TRUE) {
        output = "null";
        return true;
    }

    ani_boolean isUndefined = ANI_FALSE;
    status = env->Reference_IsUndefined(ref, &isUndefined);
    if (status != ANI_OK) {
        APP_LOGE("Reference_IsUndefined failed %{public}d", status);
        return false;
    }
    if (isUndefined == ANI_TRUE) {
        output = "undefined";
        return true;
    }

    ani_object arg = static_cast<ani_object>(ref);

    Type type = Builder::BuildClass(CLASSNAME_STRING);
    ani_class cls = CommonFunAni::CreateClassByName(env, type.Descriptor().c_str());
    if (cls == nullptr) {
        APP_LOGE("CreateClassByName failed ");
        return false;
    }

    bool result = false;
    ani_boolean isString = ANI_FALSE;
    status = env->Object_InstanceOf(arg, cls, &isString);
    if (status == ANI_OK && isString == ANI_TRUE) {
        result = CommonFunAni::ParseString(env, static_cast<ani_string>(arg), output);
    }

    if (!result) {
        APP_LOGE("get string arg failed");
    }
    return result;
}

static bool TryGetNumberArg(ani_env* env, ani_array_ref args, ani_size index, std::string& output)
{
    ani_ref ref = nullptr;
    ani_status status = env->Array_Get_Ref(args, index, &ref);
    if (status != ANI_OK) {
        APP_LOGE("Array_Get_Ref failed %{public}d", status);
        return false;
    }

    ani_boolean isNull = ANI_FALSE;
    status = env->Reference_IsNull(ref, &isNull);
    if (status != ANI_OK) {
        APP_LOGE("Reference_IsNull failed %{public}d", status);
        return false;
    }
    if (isNull == ANI_TRUE) {
        output = "null";
        return true;
    }

    ani_boolean isUndefined = ANI_FALSE;
    status = env->Reference_IsUndefined(ref, &isUndefined);
    if (status != ANI_OK) {
        APP_LOGE("Reference_IsUndefined failed %{public}d", status);
        return false;
    }
    if (isUndefined == ANI_TRUE) {
        output = "undefined";
        return true;
    }

    ani_object arg = static_cast<ani_object>(ref);

    Type type = Builder::BuildClass(CLASSNAME_DOUBLE);
    ani_class cls = CommonFunAni::CreateClassByName(env, type.Descriptor().c_str());
    if (cls == nullptr) {
        APP_LOGE("CreateClassByName failed ");
        return false;
    }

    ani_boolean isDouble = ANI_FALSE;
    status = env->Object_InstanceOf(arg, cls, &isDouble);
    if (status == ANI_OK && isDouble == ANI_TRUE) {
        ani_double numberArg = 0;
        status = env->Object_CallMethodByName_Double(arg, CommonFunAniNS::PROPERTYNAME_UNBOXED, nullptr, &numberArg);
        output = std::to_string(static_cast<int32_t>(numberArg));
    }

    if (status != ANI_OK) {
        APP_LOGE("get double arg failed %{public}d", status);
        return false;
    }
    return true;
}

static bool GetFormattedString(ani_env* env, const std::string& format, ani_object args, std::string& formattedString)
{
    ani_size maxArgCount = 0;
    ani_status status = env->Array_GetLength(reinterpret_cast<ani_array>(args), &maxArgCount);
    if (status != ANI_OK) {
        APP_LOGE("Array_GetLength failed %{public}d", status);
        return false;
    }

    if (maxArgCount == 0) {
        formattedString = format;
        return true;
    }

    ani_size curArgCount = 0;
    std::string arg;
    for (size_t pos = 0; pos < format.size(); ++pos) {
        if (curArgCount >= maxArgCount) {
            break;
        }
        if (format[pos] != '%') {
            formattedString += format[pos];
            continue;
        }
        if (pos + 1 >= format.size()) {
            break;
        }
        switch (format[pos + 1]) {
            case 'd':
            case 'i':
                if (TryGetNumberArg(env, reinterpret_cast<ani_array_ref>(args), curArgCount, arg)) {
                    formattedString += arg;
                }
                ++curArgCount;
                ++pos;
                break;
            case 's':
                if (TryGetStringArg(env, reinterpret_cast<ani_array_ref>(args), curArgCount, arg)) {
                    formattedString += arg;
                }
                ++curArgCount;
                ++pos;
                break;
            case '%':
                formattedString += format[pos];
                ++pos;
                break;
            default:
                formattedString += format[pos];
                break;
        }
    }

    return true;
}

void gzdopenNative(ani_env* env, ani_object instance, ani_int aniFd, ani_string aniMode)
{
    APP_LOGD("gzdopenNative entry");

    CHECK_PARAM_NULL(env);
    CHECK_PARAM_NULL_THROW(instance, EFAULT);
    CHECK_PARAM_NULL_THROW(aniMode, EINVAL);

    std::string mode;
    if (!CommonFunAni::ParseString(env, aniMode, mode)) {
        APP_LOGE("get mode failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return;
    }

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EFAULT)) {
        return;
    }
    if (nativeGZFile != nullptr) {
        APP_LOGW("nativeGZFile is not null");
    }

    nativeGZFile = gzdopen(aniFd, mode.c_str());
    CHECK_PARAM_NULL_THROW(nativeGZFile, ENOENT);
    if (!TrySetNativeGZFile(env, instance, nativeGZFile)) {
        APP_LOGE("TrySetNativeGZFile failed");
        AniZLibCommon::ThrowZLibNapiError(env, EFAULT);
    }
}

ani_int gzbufferNative(ani_env* env, ani_object instance, ani_long aniSize)
{
    APP_LOGD("gzbufferNative entry");

    CHECK_PARAM_NULL_RETURN(env, -1);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, -1);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EFAULT)) {
        return -1;
    }

    int ret = gzbuffer(nativeGZFile, static_cast<uint32_t>(aniSize));
    if (ret < 0) {
        APP_LOGE("gzbuffer failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
    }
    return ret;
}

void gzopenNative(ani_env* env, ani_object instance, ani_string aniPath, ani_string aniMode)
{
    APP_LOGD("gzopenNative entry");

    CHECK_PARAM_NULL(env);
    CHECK_PARAM_NULL_THROW(instance, EFAULT);
    CHECK_PARAM_NULL_THROW(aniPath, EINVAL);
    CHECK_PARAM_NULL_THROW(aniMode, EINVAL);

    std::string path;
    if (!CommonFunAni::ParseString(env, aniPath, path)) {
        APP_LOGE("get path failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return;
    }
    std::string mode;
    if (!CommonFunAni::ParseString(env, aniMode, mode)) {
        APP_LOGE("get mode failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return;
    }

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EFAULT)) {
        return;
    }
    if (nativeGZFile != nullptr) {
        APP_LOGW("nativeGZFile is not null");
    }

#if !defined(ZLIB_INTERNAL) && defined(Z_WANT64) && !defined(Z_LARGE64)
    nativeGZFile = gzopen64(path.c_str(), mode.c_str());
#else
    nativeGZFile = gzopen(path.c_str(), mode.c_str());
#endif
    CHECK_PARAM_NULL_THROW(nativeGZFile, ENOENT);
    if (!TrySetNativeGZFile(env, instance, nativeGZFile)) {
        APP_LOGE("TrySetNativeGZFile failed");
        AniZLibCommon::ThrowZLibNapiError(env, EFAULT);
    }
}

ani_int gzeofNative(ani_env* env, ani_object instance)
{
    APP_LOGD("gzeofNative entry");

    CHECK_PARAM_NULL_RETURN(env, 0);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, 0);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EFAULT)) {
        return 0;
    }

    int ret = gzeof(nativeGZFile);
    if (ret < 0) {
        APP_LOGE("gzeof failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ret);
    }
    return ret;
}

ani_int gzdirectNative(ani_env* env, ani_object instance)
{
    APP_LOGD("gzdirectNative entry");

    CHECK_PARAM_NULL_RETURN(env, 0);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, 0);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EFAULT)) {
        return 0;
    }

    int ret = gzdirect(nativeGZFile);
    if (ret < 0) {
        APP_LOGE("gzdirect failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ret);
    }
    return ret;
}

ani_enum_item gzcloseNative(ani_env* env, ani_object instance)
{
    APP_LOGD("gzcloseNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return nullptr;
    }

    int ret = gzclose(nativeGZFile);
    if (ret < 0) {
        APP_LOGE("gzclose failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ret);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, ret);
}

void gzclearerrNative(ani_env* env, ani_object instance)
{
    APP_LOGD("gzclearerrNative entry");

    CHECK_PARAM_NULL(env);
    CHECK_PARAM_NULL_THROW(instance, EFAULT);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EFAULT)) {
        return;
    }
    CHECK_PARAM_NULL_THROW(nativeGZFile, EFAULT);

    gzclearerr(nativeGZFile);
}

ani_object gzerrorNative(ani_env* env, ani_object instance)
{
    APP_LOGD("gzerrorNative entry");

    RETURN_NULL_IF_NULL(env);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EFAULT)) {
        return nullptr;
    }

    int errCode = 0;
    const char* errMsg = gzerror(nativeGZFile, &errCode);
    CHECK_PARAM_NULL_THROW_RETURN(errMsg, LIBZIP::EZSTREAM_ERROR, nullptr);

    ani_class cls = CommonFunAni::CreateClassByName(env, CLASSNAME_GZ_ERROR_OUTPUT_INFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CommonFunAni::CreateNewObjectByClass(env, CLASSNAME_GZ_ERROR_OUTPUT_INFO_INNER, cls);
    RETURN_NULL_IF_NULL(object);

    // status: ReturnStatus
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(
        env, cls, object, "status", EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode)));

    // statusMsg: string
    ani_string string = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, errMsg, string));
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, "statusMsg", string));

    return object;
}

ani_int gzgetcNative(ani_env* env, ani_object instance)
{
    APP_LOGD("gzgetcNative entry");

    CHECK_PARAM_NULL_RETURN(env, -1);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, -1);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return -1;
    }

    int ret = gzgetc(nativeGZFile);
    if (ret < 0) {
        APP_LOGE("gzgetc failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
        return -1;
    }
    return ret;
}

ani_enum_item gzflushNative(ani_env* env, ani_object instance, ani_enum_item aniFlush)
{
    APP_LOGD("gzflushNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniFlush, EINVAL, nullptr);
    int flush = 0;
    if (!EnumUtils::EnumETSToNative(env, aniFlush, flush)) {
        APP_LOGE("parse aniFlush failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EFAULT)) {
        return nullptr;
    }

    int ret = gzflush(nativeGZFile, flush);
    if (ret < 0) {
        APP_LOGE("gzflush failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ret);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, ret);
}

ani_long gzfwriteNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf, ani_long aniSize, ani_long aniNItems)
{
    APP_LOGD("gzfwriteNative entry");

    CHECK_PARAM_NULL_RETURN(env, 0);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, 0);
    CHECK_PARAM_NULL_THROW_RETURN(aniBuf, EINVAL, 0);
    if (aniSize < 0 || aniNItems < 0) {
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return 0;
    }

    size_t bufLen = 0;
    void* buf = nullptr;
    ani_status status = env->ArrayBuffer_GetInfo(aniBuf, &buf, &bufLen);
    if (status != ANI_OK) {
        APP_LOGE("ArrayBuffer_GetInfo failed: %{public}d", status);
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return 0;
    }
    CHECK_PARAM_NULL_THROW_RETURN(buf, EINVAL, 0);
    if (bufLen == 0) {
        APP_LOGE("bufLen is 0");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return 0;
    }
    z_size_t total = static_cast<z_size_t>(aniSize) * static_cast<z_size_t>(aniNItems); //zlib will handle overflow
    if (static_cast<z_size_t>(bufLen) < total) {
        APP_LOGE("bufLen is too small");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return 0;
    }

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return 0;
    }

    z_size_t ret = gzfwrite(buf, static_cast<z_size_t>(aniSize), static_cast<z_size_t>(aniNItems), nativeGZFile);
    if (ret <= 0) {
        APP_LOGE("gzfwrite failed %{public}zu", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
        return 0;
    }

    return static_cast<ani_long>(ret);
}

ani_long gzfreadNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf, ani_long aniSize, ani_long aniNItems)
{
    APP_LOGD("gzfreadNative entry");

    CHECK_PARAM_NULL_RETURN(env, 0);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, 0);
    CHECK_PARAM_NULL_THROW_RETURN(aniBuf, EINVAL, 0);
    if (aniSize < 0 || aniNItems < 0) {
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return 0;
    }

    size_t bufLen = 0;
    void* buf = nullptr;
    ani_status status = env->ArrayBuffer_GetInfo(aniBuf, &buf, &bufLen);
    if (status != ANI_OK) {
        APP_LOGE("ArrayBuffer_GetInfo failed: %{public}d", status);
        AniZLibCommon::ThrowZLibNapiError(env, EFAULT);
        return 0;
    }
    CHECK_PARAM_NULL_THROW_RETURN(buf, EINVAL, 0);
    if (bufLen == 0) {
        APP_LOGE("bufLen is 0");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return 0;
    }
    z_size_t total = static_cast<z_size_t>(aniSize) * static_cast<z_size_t>(aniNItems); //zlib will handle overflow
    if (static_cast<z_size_t>(bufLen) < total) {
        APP_LOGE("bufLen is too small");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return 0;
    }

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return 0;
    }

    z_size_t ret = gzfread(buf, static_cast<z_size_t>(aniSize), static_cast<z_size_t>(aniNItems), nativeGZFile);
    if (ret <= 0) {
        APP_LOGE("gzfread failed %{public}zu", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
        return 0;
    }

    return static_cast<ani_long>(ret);
}

ani_enum_item gzclosewNative(ani_env* env, ani_object instance)
{
    APP_LOGD("gzclosewNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EFAULT)) {
        return nullptr;
    }

    int ret = gzclose_w(nativeGZFile);
    if (ret < 0) {
        APP_LOGE("gzclose_w failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ret);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, ret);
}

ani_enum_item gzcloserNative(ani_env* env, ani_object instance)
{
    APP_LOGD("gzcloserNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return nullptr;
    }

    int ret = gzclose_r(nativeGZFile);
    if (ret < 0) {
        APP_LOGE("gzclose_r failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ret);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, ret);
}

ani_long gzwriteNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf, ani_long aniLen)
{
    APP_LOGD("gzwriteNative entry");

    CHECK_PARAM_NULL_RETURN(env, 0);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, 0);
    CHECK_PARAM_NULL_THROW_RETURN(aniBuf, EINVAL, 0);
    if (aniLen < 0) {
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return 0;
    }

    size_t bufLen = 0;
    void* buf = nullptr;
    ani_status status = env->ArrayBuffer_GetInfo(aniBuf, &buf, &bufLen);
    if (status != ANI_OK) {
        APP_LOGE("ArrayBuffer_GetInfo failed: %{public}d", status);
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return 0;
    }
    CHECK_PARAM_NULL_THROW_RETURN(buf, EINVAL, 0);
    if (bufLen == 0) {
        APP_LOGE("bufLen is 0");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return 0;
    }
    if (bufLen < static_cast<size_t>(aniLen)) {
        APP_LOGE("bufLen is too small");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return 0;
    }

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return 0;
    }

    int ret = gzwrite(nativeGZFile, buf, static_cast<unsigned int>(aniLen));
    if (ret <= 0) {
        APP_LOGE("gzwrite failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
    }

    return ret;
}

ani_int gzungetcNative(ani_env* env, ani_object instance, ani_int aniC)
{
    APP_LOGD("gzungetcNative entry");

    CHECK_PARAM_NULL_RETURN(env, -1);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, -1);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return -1;
    }

    if (aniC < MIN_ASCII || aniC > MAX_ASCII) {
        APP_LOGE("gzungetcNative invalid c: %{public}d", aniC);
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return -1;
    }

    int ret = gzungetc(aniC, nativeGZFile);
    if (ret < 0) {
        APP_LOGE("gzungetc failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
    }

    return ret;
}

ani_long gztellNative(ani_env* env, ani_object instance)
{
    APP_LOGD("gztellNative entry");

    CHECK_PARAM_NULL_RETURN(env, -1);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, -1);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return -1;
    }

#if !defined(ZLIB_INTERNAL) && defined(Z_WANT64) && !defined(Z_LARGE64)
    z_off64_t ret = gztell64(nativeGZFile);
    if (ret < 0) {
        APP_LOGE("gztell64 failed %{public}lld", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
    }
#else
    z_off_t ret = gztell(nativeGZFile);
    if (ret < 0) {
        APP_LOGE("gztell failed %{public}ld", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
    }
#endif
    return static_cast<ani_long>(ret);
}

ani_enum_item gzsetparamsNative(ani_env* env, ani_object instance, ani_enum_item aniLevel, ani_enum_item aniStrategy)
{
    APP_LOGD("gzsetparamsNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniLevel, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrategy, EINVAL, nullptr);
    int level = 0;
    if (!EnumUtils::EnumETSToNative(env, aniLevel, level)) {
        APP_LOGE("parse aniLevel failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    int strategy = 0;
    if (!EnumUtils::EnumETSToNative(env, aniStrategy, strategy)) {
        APP_LOGE("parse aniStrategy failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return nullptr;
    }

    int ret = gzsetparams(nativeGZFile, level, strategy);
    if (ret < 0) {
        APP_LOGE("gzsetparams failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ret);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, ret);
}

ani_long gzseekNative(ani_env* env, ani_object instance, ani_long aniOffset, ani_enum_item aniWhence)
{
    APP_LOGD("gzseekNative entry");

    CHECK_PARAM_NULL_RETURN(env, -1);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, -1);
    CHECK_PARAM_NULL_THROW_RETURN(aniWhence, EINVAL, -1);

    int whence = 0;
    if (!EnumUtils::EnumETSToNative(env, aniWhence, whence)) {
        APP_LOGE("parse aniWhence failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return -1;
    }

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return -1;
    }

#if !defined(ZLIB_INTERNAL) && defined(Z_WANT64) && !defined(Z_LARGE64)
    z_off64_t ret = gzseek64(nativeGZFile, static_cast<z_off64_t>(aniOffset), whence);
    if (ret < 0) {
        APP_LOGE("gzseek64 failed %{public}lld", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
    }
#else
    z_off_t ret = gzseek(nativeGZFile, static_cast<z_off_t>(aniOffset), whence);
    if (ret < 0) {
        APP_LOGE("gzseek failed %{public}ld", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
    }
#endif
    return static_cast<ani_long>(ret);
}

ani_enum_item gzrewindNative(ani_env* env, ani_object instance)
{
    APP_LOGD("gzrewindNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return nullptr;
    }

    int ret = gzrewind(nativeGZFile);
    if (ret < 0) {
        APP_LOGE("gzrewind failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, ret);
}

ani_long gzreadNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf)
{
    APP_LOGD("gzreadNative entry");

    CHECK_PARAM_NULL_RETURN(env, -1);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, -1);
    CHECK_PARAM_NULL_THROW_RETURN(aniBuf, EINVAL, -1);

    size_t bufLen = 0;
    void* buf = nullptr;
    ani_status status = env->ArrayBuffer_GetInfo(aniBuf, &buf, &bufLen);
    if (status != ANI_OK) {
        APP_LOGE("ArrayBuffer_GetInfo failed: %{public}d", status);
        AniZLibCommon::ThrowZLibNapiError(env, EFAULT);
        return -1;
    }
    CHECK_PARAM_NULL_THROW_RETURN(buf, EINVAL, -1);
    if (bufLen == 0) {
        APP_LOGE("bufLen is 0");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return -1;
    }

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return -1;
    }

    int ret = gzread(nativeGZFile, buf, static_cast<unsigned int>(bufLen));
    if (ret < 0) {
        APP_LOGE("gzread failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
    }

    return ret;
}

ani_int gzputsNative(ani_env* env, ani_object instance, ani_string aniStr)
{
    APP_LOGD("gzputsNative entry");

    CHECK_PARAM_NULL_RETURN(env, -1);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, -1);
    CHECK_PARAM_NULL_THROW_RETURN(aniStr, EINVAL, -1);

    std::string str;
    bool result = CommonFunAni::ParseString(env, aniStr, str);
    if (!result) {
        APP_LOGE("get str failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return -1;
    }

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return -1;
    }

    int ret = gzputs(nativeGZFile, str.c_str());
    if (ret < 0) {
        APP_LOGE("gzputs failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
    }

    return ret;
}

ani_int gzputcNative(ani_env* env, ani_object instance, ani_int aniC)
{
    APP_LOGD("gzputcNative entry");

    CHECK_PARAM_NULL_RETURN(env, -1);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, -1);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return -1;
    }

    if (aniC < MIN_ASCII || aniC > MAX_ASCII) {
        APP_LOGE("gzputcNative invalid c: %{public}d", aniC);
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return -1;
    }

    int ret = gzputc(nativeGZFile, aniC);
    if (ret < 0) {
        APP_LOGE("gzputc failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
    }

    return ret;
}

ani_int gzprintfNative(ani_env* env, ani_object instance, ani_string aniFormat, ani_object args)
{
    APP_LOGD("gzprintfNative entry");

    CHECK_PARAM_NULL_RETURN(env, 0);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, 0);
    CHECK_PARAM_NULL_THROW_RETURN(aniFormat, EINVAL, 0);
    CHECK_PARAM_NULL_THROW_RETURN(args, EINVAL, 0);

    std::string format;
    bool result = CommonFunAni::ParseString(env, aniFormat, format);
    if (!result) {
        APP_LOGE("get format failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return 0;
    }
    APP_LOGD("format: %{public}s", format.c_str());

    std::string formattedStr;
    result = GetFormattedString(env, format, args, formattedStr);
    if (!result) {
        APP_LOGE("GetFormattedString failed");
        return 0;
    }
    APP_LOGD("formattedStr: %{public}s", formattedStr.c_str());

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return 0;
    }

    int ret = gzprintf(nativeGZFile, "%s", formattedStr.c_str());
    if (ret < 0) {
        APP_LOGE("gzprintf failed %{public}d", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ret);
    }
    return ret;
}

ani_long gzoffsetNative(ani_env* env, ani_object instance)
{
    APP_LOGD("gzoffsetNative entry");

    CHECK_PARAM_NULL_RETURN(env, 0);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, 0);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return 0;
    }

#if !defined(ZLIB_INTERNAL) && defined(Z_WANT64) && !defined(Z_LARGE64)
    z_off64_t ret = gzoffset64(nativeGZFile);
    if (ret < 0) {
        APP_LOGE("gzoffset64 failed %{public}lld", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
    }
#else
    z_off_t ret = gzoffset(nativeGZFile);
    if (ret < 0) {
        APP_LOGE("gzoffset failed %{public}ld", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
    }
#endif
    return static_cast<ani_long>(ret);
}

ani_string gzgetsNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf)
{
    APP_LOGD("gzgetsNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniBuf, EINVAL, nullptr);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EINVAL)) {
        return nullptr;
    }

    size_t bufLen = 0;
    void* buf = nullptr;
    ani_status status = env->ArrayBuffer_GetInfo(aniBuf, &buf, &bufLen);
    if (status != ANI_OK) {
        APP_LOGE("ArrayBuffer_GetInfo failed: %{public}d", status);
        AniZLibCommon::ThrowZLibNapiError(env, EFAULT);
        return 0;
    }
    CHECK_PARAM_NULL_THROW_RETURN(buf, EINVAL, nullptr);

    char* ret = gzgets(nativeGZFile, reinterpret_cast<char*>(buf), static_cast<int>(bufLen));
    CHECK_PARAM_NULL_THROW_RETURN(ret, ENOSTR, nullptr);

    ani_string aniStr = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, ret, aniStr));

    return aniStr;
}

} // namespace AniZLibGZip
} // namespace AppExecFwk
} // namespace OHOS