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
#include <charconv>
#include "enum_util.h"
#include "napi_business_error.h"
#include "napi_constants.h"
#include "zlib.h"

namespace OHOS {
namespace AppExecFwk {
namespace AniZLibGZip {
namespace {
constexpr const char* CLASSNAME_GZ_ERROR_OUTPUT_INFO_INNER = "@ohos.zlib.zlib.GzErrorOutputInfoInner";
constexpr const char* FIELD_NAME_NATIVE_GZFILE = "nativeGZFile";
constexpr const char* FUNCTION_TOSTRING = "toString";
constexpr const char* MANGLING_TOSTRING = ":Lstd/core/String;";
constexpr int INVALID_FD = -1;
constexpr uint8_t MIN_ASCII = 0;
constexpr uint8_t MAX_ASCII = 255;
constexpr int ANI_DOUBLE_BYTE_MAX = 64;

enum AniArgsType {
    ANI_UNKNOWN = -1,
    ANI_INT = 0,
    ANI_BOOLEAN = 1,
    ANI_NUMBER = 2,
    ANI_STRING = 3,
    ANI_BIGINT = 4,
    ANI_OBJECT = 5,
    ANI_UNDEFINED = 6,
    ANI_NULL = 7,
};
const std::pair<const char*, AniArgsType> OBJECT_TYPE[] = {
    {CommonFunAniNS::CLASSNAME_INT, AniArgsType::ANI_INT},
    {CommonFunAniNS::CLASSNAME_BOOLEAN, AniArgsType::ANI_BOOLEAN},
    {CommonFunAniNS::CLASSNAME_DOUBLE, AniArgsType::ANI_NUMBER},
    {CommonFunAniNS::CLASSNAME_STRING, AniArgsType::ANI_STRING},
    {CommonFunAniNS::CLASSNAME_BIGINT, AniArgsType::ANI_BIGINT},
    {CommonFunAniNS::CLASSNAME_OBJECT, AniArgsType::ANI_OBJECT},
};
} // namespace
using namespace arkts::ani_signature;
using AniParam = struct {
    AniArgsType type;
    std::string val;
};

static bool TryGetNativeGZFile(ani_env* env, ani_object instance, gzFile& file, int throwsOnError)
{
    ani_long longValue = 0;
    ani_status status = env->Object_GetFieldByName_Long(instance, FIELD_NAME_NATIVE_GZFILE, &longValue);
    if (status != ANI_OK) {
        APP_LOGE("Object_GetFieldByName_Long failed %{public}d", status);
        AniZLibCommon::ThrowZLibNapiError(env, throwsOnError);
        return false;
    }

    file = reinterpret_cast<gzFile>(longValue);
    return true;
}

static bool TrySetNativeGZFile(ani_env* env, ani_object instance, gzFile nativeGZFile)
{
    ani_status status =
        env->Object_SetFieldByName_Long(instance, FIELD_NAME_NATIVE_GZFILE, reinterpret_cast<ani_long>(nativeGZFile));
    if (status != ANI_OK) {
        APP_LOGE("Object_SetFieldByName_Long failed %{public}d", status);
        return false;
    }
    return true;
}

static AniArgsType AniArgGetType(ani_env *env, ani_object element)
{
    ani_boolean isUndefined = ANI_FALSE;
    ani_status status = env->Reference_IsUndefined(static_cast<ani_ref>(element), &isUndefined);
    if (status != ANI_OK) {
        APP_LOGE("Reference_IsUndefined failed %{public}d", status);
        return AniArgsType::ANI_UNKNOWN;
    }
    if (isUndefined == ANI_TRUE) {
        return AniArgsType::ANI_UNDEFINED;
    }
    ani_boolean isNull = ANI_FALSE;
    status = env->Reference_IsNull(static_cast<ani_ref>(element), &isNull);
    if (status != ANI_OK) {
        APP_LOGE("Reference_IsNull failed %{public}d", status);
        return AniArgsType::ANI_UNKNOWN;
    }
    if (isNull == ANI_TRUE) {
        return AniArgsType::ANI_NULL;
    }

    for (const auto &objType : OBJECT_TYPE) {
        ani_class cls {};
        if (ANI_OK != env->FindClass(objType.first, &cls)) {
            continue;
        }
        ani_boolean isInstance = false;
        if (ANI_OK != env->Object_InstanceOf(element, cls, &isInstance)) {
            continue;
        }
        if (static_cast<bool>(isInstance)) {
            return objType.second;
        }
    }
    return AniArgsType::ANI_UNKNOWN;
}

static std::string AniArgToString(ani_env *env, ani_object arg)
{
    ani_ref argStrRef {};
    ani_status status = env->Object_CallMethodByName_Ref(arg, FUNCTION_TOSTRING, MANGLING_TOSTRING, &argStrRef);
    if (status != ANI_OK) {
        APP_LOGE("Object_CallMethodByName_Ref failed %{public}d", status);
        return "";
    }
    ani_size strSize;
    status = env->String_GetUTF8Size(static_cast<ani_string>(argStrRef), &strSize);
    if (status != ANI_OK) {
        APP_LOGE("String_GetUTF8Size failed %{public}d", status);
        return "";
    }
    std::vector<char> buffer(strSize + 1);
    char* utf8Buffer = buffer.data();
    ani_size bytesWritten = 0;
    status = env->String_GetUTF8(static_cast<ani_string>(argStrRef), utf8Buffer, strSize + 1, &bytesWritten);
    if (status != ANI_OK) {
        APP_LOGE("String_GetUTF8 failed %{public}d", status);
        return "";
    }
    return std::string(utf8Buffer);
}

static void ParseAniValue(ani_env *env, ani_ref element, std::vector<AniParam>& params)
{
    AniParam res;
    AniArgsType type = AniArgGetType(env, static_cast<ani_object>(element));
    res.type = type;
    if (type == AniArgsType::ANI_UNDEFINED) {
        res.val = "undefined";
    } else if (type == AniArgsType::ANI_NULL) {
        res.val = "null";
    } else if (type != AniArgsType::ANI_UNKNOWN) {
        res.val = AniArgToString(env, static_cast<ani_object>(element));
    } else {
        APP_LOGW("Type mismatch");
    }
    params.emplace_back(res);
}

static void GetFormattedStringInner(const std::string& format, const ani_size maxArgCount,
    const std::vector<AniParam>& params, std::string& formattedString)
{
    ani_size curArgCount = 0;
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
                if (params[curArgCount].type == AniArgsType::ANI_NUMBER) {
                    formattedString += params[curArgCount].val;
                }
                ++curArgCount;
                ++pos;
                break;
            case 's':
                if (params[curArgCount].type == AniArgsType::ANI_STRING) {
                    formattedString += params[curArgCount].val;
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

    std::vector<AniParam> params;
    for (ani_size i = 0; i < maxArgCount; ++i) {
        ani_ref element;
        status = env->Array_Get_Ref(static_cast<ani_array_ref>(args), i, &element);
        if (status != ANI_OK) {
            APP_LOGE("Array_Get_Ref failed %{public}d", status);
            return false;
        }
        ParseAniValue(env, element, params);
    }

    GetFormattedStringInner(format, maxArgCount, params, formattedString);

    return true;
}

void GzdopenNative(ani_env* env, ani_object instance, ani_int aniFd, ani_string aniMode)
{
    APP_LOGD("GzdopenNative entry");

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
        gzclose(nativeGZFile);
        AniZLibCommon::ThrowZLibNapiError(env, EFAULT);
    }
}

ani_int GzbufferNative(ani_env* env, ani_object instance, ani_long aniSize)
{
    APP_LOGD("GzbufferNative entry");

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

void GzopenNative(ani_env* env, ani_object instance, ani_string aniPath, ani_string aniMode)
{
    APP_LOGD("GzopenNative entry");

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
        gzclose(nativeGZFile);
        AniZLibCommon::ThrowZLibNapiError(env, EFAULT);
    }
}

ani_int GzeofNative(ani_env* env, ani_object instance)
{
    APP_LOGD("GzeofNative entry");

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

ani_int GzdirectNative(ani_env* env, ani_object instance)
{
    APP_LOGD("GzdirectNative entry");

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

ani_enum_item GzcloseNative(ani_env* env, ani_object instance)
{
    APP_LOGD("GzcloseNative entry");

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

void GzclearerrNative(ani_env* env, ani_object instance)
{
    APP_LOGD("GzclearerrNative entry");

    CHECK_PARAM_NULL(env);
    CHECK_PARAM_NULL_THROW(instance, EFAULT);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EFAULT)) {
        return;
    }
    CHECK_PARAM_NULL_THROW(nativeGZFile, EFAULT);

    gzclearerr(nativeGZFile);
}

ani_object GzerrorNative(ani_env* env, ani_object instance)
{
    APP_LOGD("GzerrorNative entry");

    RETURN_NULL_IF_NULL(env);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);

    gzFile nativeGZFile = nullptr;
    if (!TryGetNativeGZFile(env, instance, nativeGZFile, EFAULT)) {
        return nullptr;
    }

    int errCode = 0;
    const char* errMsg = gzerror(nativeGZFile, &errCode);
    CHECK_PARAM_NULL_THROW_RETURN(errMsg, LIBZIP::EZSTREAM_ERROR, nullptr);

    // statusMsg: string
    ani_string statusMsg = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, errMsg, statusMsg));

    ani_value args[] = {
        { .r = EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode) },
        { .r = statusMsg },
    };
    static const std::string ctorSig =
        arkts::ani_signature::SignatureBuilder()
            .AddClass(CommonFunAniNS::CLASSNAME_ZLIB_RETURN_STATUS) // status: ReturnStatus
            .AddClass(CommonFunAniNS::CLASSNAME_STRING)             // statusMsg: string
            .BuildSignatureDescriptor();
    return CommonFunAni::CreateNewObjectByClassV2(env, CLASSNAME_GZ_ERROR_OUTPUT_INFO_INNER, ctorSig, args);
}

ani_int GzgetcNative(ani_env* env, ani_object instance)
{
    APP_LOGD("GzgetcNative entry");

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

ani_enum_item GzflushNative(ani_env* env, ani_object instance, ani_enum_item aniFlush)
{
    APP_LOGD("GzflushNative entry");

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

ani_long GzfwriteNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf, ani_long aniSize, ani_long aniNItems)
{
    APP_LOGD("GzfwriteNative entry");

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

ani_long GzfreadNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf, ani_long aniSize, ani_long aniNItems)
{
    APP_LOGD("GzfreadNative entry");

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

    z_size_t ret = gzfread(buf, static_cast<z_size_t>(aniSize), static_cast<z_size_t>(aniNItems), nativeGZFile);
    if (ret <= 0) {
        APP_LOGE("gzfread failed %{public}zu", ret);
        AniZLibCommon::ThrowZLibNapiError(env, ENOSTR);
        return 0;
    }

    return static_cast<ani_long>(ret);
}

ani_enum_item GzclosewNative(ani_env* env, ani_object instance)
{
    APP_LOGD("GzclosewNative entry");

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

ani_enum_item GzcloserNative(ani_env* env, ani_object instance)
{
    APP_LOGD("GzcloserNative entry");

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

ani_long GzwriteNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf, ani_long aniLen)
{
    APP_LOGD("GzwriteNative entry");

    CHECK_PARAM_NULL_RETURN(env, 0);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, 0);
    CHECK_PARAM_NULL_THROW_RETURN(aniBuf, EINVAL, 0);

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
    if (aniLen > static_cast<int64_t>(bufLen)) {
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

ani_int GzungetcNative(ani_env* env, ani_object instance, ani_int aniC)
{
    APP_LOGD("GzungetcNative entry");

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

ani_long GztellNative(ani_env* env, ani_object instance)
{
    APP_LOGD("GztellNative entry");

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

ani_enum_item GzsetparamsNative(ani_env* env, ani_object instance, ani_enum_item aniLevel, ani_enum_item aniStrategy)
{
    APP_LOGD("GzsetparamsNative entry");

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

ani_long GzseekNative(ani_env* env, ani_object instance, ani_long aniOffset, ani_enum_item aniWhence)
{
    APP_LOGD("GzseekNative entry");

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

ani_enum_item GzrewindNative(ani_env* env, ani_object instance)
{
    APP_LOGD("GzrewindNative entry");

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

ani_long GzreadNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf)
{
    APP_LOGD("GzreadNative entry");

    CHECK_PARAM_NULL_RETURN(env, -1);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, -1);
    CHECK_PARAM_NULL_THROW_RETURN(aniBuf, EINVAL, -1);

    size_t bufLen = 0;
    void* buf = nullptr;
    ani_status status = env->ArrayBuffer_GetInfo(aniBuf, &buf, &bufLen);
    if (status != ANI_OK) {
        APP_LOGE("ArrayBuffer_GetInfo failed: %{public}d", status);
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
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

ani_int GzputsNative(ani_env* env, ani_object instance, ani_string aniStr)
{
    APP_LOGD("GzputsNative entry");

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

ani_int GzputcNative(ani_env* env, ani_object instance, ani_int aniC)
{
    APP_LOGD("GzputcNative entry");

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

ani_int GzprintfNative(ani_env* env, ani_object instance, ani_string aniFormat, ani_object args)
{
    APP_LOGD("GzprintfNative entry");

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

ani_long GzoffsetNative(ani_env* env, ani_object instance)
{
    APP_LOGD("GzoffsetNative entry");

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

ani_string GzgetsNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf)
{
    APP_LOGD("GzgetsNative entry");

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
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
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