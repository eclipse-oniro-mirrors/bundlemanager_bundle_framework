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

#include "ani_zip.h"
#include "ani_zlib_common.h"
#include "common_fun_ani.h"
#include "enum_util.h"
#include "napi_business_error.h"
#include "napi_constants.h"
#include "securec.h"
#include "zlib.h"
#include <sstream>
#include <streambuf>
#include <iostream>

namespace OHOS {
namespace AppExecFwk {
namespace AniZLibZip {
namespace {
constexpr const char* CLASS_NAME_ZIPINTERNAL = "@ohos.zlib.zlib.ZipInternal";
constexpr const char* FIELD_NAME_NATIVEZSTREAM = "nativeZStream";
constexpr const char* METHOD_NAME_REGISTERZIPCLEANER = "registerZipCleaner";
constexpr uint8_t MIN_WINDOWBITS = 8;
constexpr uint8_t MAX_WINDOWBITS = 15;
constexpr int32_t ERROR_CODE = -5;
constexpr int32_t MIN_BITS = 0;
constexpr int32_t MAX_BITS = 16;

struct InOutDesc {
    ani_env* env = nullptr;
    ani_fn_object func = nullptr;
    ani_ref desc = nullptr;

    InOutDesc(ani_env* env, ani_fn_object func, ani_ref desc) : env(env), func(func), desc(desc) {};
    ~InOutDesc() = default;
};
} // namespace

static bool GetNativeZStream(ani_env* env, ani_object instance, z_streamp& zStream, const int throws)
{
    ani_long longValue = 0;
    ani_status status = env->Object_GetFieldByName_Long(instance, FIELD_NAME_NATIVEZSTREAM, &longValue);
    if (status != ANI_OK) {
        APP_LOGE("Object_GetFieldByName_Long failed %{public}d", status);
        AniZLibCommon::ThrowZLibNapiError(env, throws);
        return false;
    }

    zStream = reinterpret_cast<z_streamp>(longValue);
    return true;
}

static bool SetNativeZStream(ani_env* env, ani_object instance, const z_streamp zStream)
{
    ani_status status =
        env->Object_SetFieldByName_Long(instance, FIELD_NAME_NATIVEZSTREAM, reinterpret_cast<ani_long>(zStream));
    if (status != ANI_OK) {
        APP_LOGE("Object_SetFieldByName_Long failed %{public}d", status);
        return false;
    }
    ani_class cls = CommonFunAni::CreateClassByName(env, CLASS_NAME_ZIPINTERNAL);
    RETURN_FALSE_IF_NULL(cls);
    ani_method method = nullptr;
    status = env->Class_FindMethod(cls, METHOD_NAME_REGISTERZIPCLEANER, ":", &method);
    if (status != ANI_OK) {
        APP_LOGE("Class_FindMethod failed %{public}d", status);
        return false;
    }
    RETURN_FALSE_IF_NULL(method);
    status = env->Object_CallMethod_Void(instance, method);
    if (status != ANI_OK) {
        APP_LOGE("Object_CallMethod_Void failed %{public}d", status);
        return false;
    }
    return true;
}

static bool SetZStream(ani_env* env, ani_object instance, ani_object aniStrm, z_streamp& zStream)
{
    z_stream zs = {};
    LIBZIP::HasZStreamMember hasZStreamMember;
    if (!AniZLibCommon::ParseZStream(env, aniStrm, hasZStreamMember, zs)) {
        APP_LOGE("parse aniStrm failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return false;
    }

    if (zStream == nullptr) {
        zStream = new (std::nothrow)z_stream();
        if (zStream == nullptr) {
            APP_LOGE("create zStream failed");
            return false;
        }
        if (!SetNativeZStream(env, instance, zStream)) {
            APP_LOGE("set native zStream failed");
            return false;
        }
        return true;
    }

    if (hasZStreamMember.hasNextIn) {
        zStream->next_in = zs.next_in;
    }
    if (hasZStreamMember.hasAvailIn) {
        zStream->avail_in = zs.avail_in;
    }
    if (hasZStreamMember.hasTotalIn) {
        zStream->total_in = zs.total_in;
    }
    if (hasZStreamMember.hasNextOut) {
        zStream->next_out = zs.next_out;
    }
    if (hasZStreamMember.hasAvailOut) {
        zStream->avail_out = zs.avail_out;
    }
    if (hasZStreamMember.hasTotalOut) {
        zStream->total_out = zs.total_out;
    }
    if (hasZStreamMember.hasDataType) {
        zStream->data_type = zs.data_type;
    }
    if (hasZStreamMember.hasAdler) {
        zStream->adler = zs.adler;
    }

    return true;
}

static unsigned InFunc(void* inDesc, unsigned char** buf)
{
    InOutDesc* in = static_cast<InOutDesc*>(inDesc);
    if (in == nullptr) {
        APP_LOGE("The in function callback is nullptr");
        return 0;
    }

    std::vector<ani_ref> callbackArgs = { in->desc };
    ani_ref result = nullptr;
    ani_status status = in->env->FunctionalObject_Call(in->func, callbackArgs.size(), callbackArgs.data(), &result);
    if (status != ANI_OK) {
        APP_LOGE("FunctionalObject_Call failed: %{public}d", status);
        AniZLibCommon::ThrowZLibNapiError(in->env, EINVAL);
        return 0;
    }

    void* buffer = nullptr;
    size_t bufLen = 0;
    if (!AniZLibCommon::ParseArrayBuffer(in->env, reinterpret_cast<ani_arraybuffer>(result), buffer, bufLen, EINVAL)) {
        APP_LOGE("parse result failed");
        return 0;
    }
    *buf = static_cast<unsigned char *>(buffer);

    return bufLen;
}

static int32_t OutFunc(void* outDesc, unsigned char* buf, unsigned len)
{
    InOutDesc* out = static_cast<InOutDesc*>(outDesc);
    if (out == nullptr) {
        APP_LOGE("The out function callback is nullptr");
        return -1;
    }

    void* data = nullptr;
    ani_arraybuffer buffer = nullptr;
    ani_status status = out->env->CreateArrayBuffer(len, &data, &buffer);
    if (status != ANI_OK) {
        APP_LOGE("CreateArrayBuffer failed: %{public}d", status);
        AniZLibCommon::ThrowZLibNapiError(out->env, EINVAL);
        return -1;
    }
    if (memcpy_s(data, len, buf, len) != EOK) {
        APP_LOGE("memcpy_s failed");
        AniZLibCommon::ThrowZLibNapiError(out->env, EINVAL);
        return -1;
    }
    ani_ref aniLen = CommonFunAni::BoxValue(out->env, static_cast<ani_int>(len));
    if (aniLen == nullptr) {
        APP_LOGE("Box len failed");
        AniZLibCommon::ThrowZLibNapiError(out->env, EINVAL);
        return -1;
    }

    std::vector<ani_ref> callbackArgs = { out->desc, reinterpret_cast<ani_ref>(buffer), aniLen};
    ani_ref aniResult = nullptr;
    status = out->env->FunctionalObject_Call(out->func, callbackArgs.size(), callbackArgs.data(), &aniResult);
    if (status != ANI_OK) {
        APP_LOGE("FunctionalObject_Call failed: %{public}d", status);
        AniZLibCommon::ThrowZLibNapiError(out->env, EINVAL);
        return -1;
    }

    ani_int result = 0;
    status = out->env->Object_CallMethodByName_Int(
        reinterpret_cast<ani_object>(aniResult), CommonFunAniNS::PROPERTYNAME_UNBOXED, ":i", &result);
    if (status != ANI_OK) {
        APP_LOGE("Object_CallMethodByName_Int aniResult failed %{public}d", status);
        AniZLibCommon::ThrowZLibNapiError(out->env, EINVAL);
        return -1;
    }

    return static_cast<int32_t>(result);
}

ani_object GetZStreamNative(ani_env* env, ani_object instance)
{
    APP_LOGD("GetZStreamNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (zStream == nullptr) {
        APP_LOGI("zStream is nullptr");
        ani_ref undefined = nullptr;
        ani_status status = env->GetUndefined(&undefined);
        if (status != ANI_OK) {
            APP_LOGE("GetUndefined failed %{public}d", status);
            return nullptr;
        }
        return reinterpret_cast<ani_object>(undefined);
    }

    return AniZLibCommon::ConvertZStream(env, zStream);
}

ani_string ZlibVersionNative(ani_env* env, ani_object instance)
{
    APP_LOGD("ZlibVersionNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    ani_string string = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env,
        std::string(reinterpret_cast<const char *>(zlibVersion())), string));

    return string;
}

ani_int ZlibCompileFlagsNative(ani_env* env, ani_object instance)
{
    APP_LOGD("ZlibCompileFlagsNative entry");

    CHECK_PARAM_NULL_RETURN(env, -1);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, -1);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return -1;
    }

    return static_cast<ani_int>(zlibCompileFlags());
}

ani_object CompressNative(ani_env* env, ani_object instance, ani_arraybuffer aniDest, ani_arraybuffer aniSource)
{
    APP_LOGD("CompressNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniDest, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniSource, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    uLong destLen = 0;
    void* dest = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniDest, dest, destLen, EINVAL)) {
        APP_LOGE("parse aniDest failed");
        return nullptr;
    }
    uLong sourceLen = 0;
    void* source = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniSource, source, sourceLen, EINVAL)) {
        APP_LOGE("parse aniSource failed");
        return nullptr;
    }

    if (dest == nullptr || source == nullptr) {
        APP_LOGE("dest or source is nullptr");
        AniZLibCommon::ThrowZLibNapiError(env, ERROR_CODE);
        return nullptr;
    }
    int32_t errCode = compress(reinterpret_cast<Bytef *>(dest), &destLen, reinterpret_cast<Bytef *>(source), sourceLen);
    if (errCode < 0) {
        APP_LOGE("compress failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return AniZLibCommon::ConvertZipOutputInfo(env, errCode, destLen);
}

ani_object CompressWithSourceLenNative(ani_env* env, ani_object instance,
    ani_arraybuffer aniDest, ani_arraybuffer aniSource, ani_long aniSourceLen)
{
    APP_LOGD("CompressWithSourceLenNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniDest, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniSource, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    uLong destLen = 0;
    void* dest = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniDest, dest, destLen, EINVAL)) {
        APP_LOGE("parse aniDest failed");
        return nullptr;
    }
    uLong sourceLen = 0;
    void* source = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniSource, source, sourceLen, EINVAL)) {
        APP_LOGE("parse aniSource failed");
        return nullptr;
    }
    if (aniSourceLen < 0) {
        APP_LOGE("aniSourceLen is invalid");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    sourceLen = static_cast<uLong>(aniSourceLen);

    if (dest == nullptr || source == nullptr) {
        APP_LOGE("dest or source is nullptr");
        AniZLibCommon::ThrowZLibNapiError(env, ERROR_CODE);
        return nullptr;
    }
    int32_t errCode = compress(reinterpret_cast<Bytef *>(dest), &destLen, reinterpret_cast<Bytef *>(source), sourceLen);
    if (errCode < 0) {
        APP_LOGE("compress failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return AniZLibCommon::ConvertZipOutputInfo(env, errCode, destLen);
}

ani_object Compress2Native(ani_env* env, ani_object instance,
    ani_arraybuffer aniDest, ani_arraybuffer aniSource, ani_enum_item aniLevel)
{
    APP_LOGD("Compress2Native entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniDest, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniSource, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniLevel, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    uLong destLen = 0;
    void* dest = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniDest, dest, destLen, EINVAL)) {
        APP_LOGE("parse aniDest failed");
        return nullptr;
    }
    uLong sourceLen = 0;
    void* source = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniSource, source, sourceLen, EINVAL)) {
        APP_LOGE("parse aniSource failed");
        return nullptr;
    }
    int32_t level = 0;
    if (!EnumUtils::EnumETSToNative(env, aniLevel, level)) {
        APP_LOGE("Parse aniLevel failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }

    if (dest == nullptr || source == nullptr) {
        APP_LOGE("dest or source is nullptr");
        AniZLibCommon::ThrowZLibNapiError(env, ERROR_CODE);
        return nullptr;
    }
    int32_t errCode = compress2(static_cast<Bytef *>(dest), &destLen, static_cast<Bytef *>(source), sourceLen, level);
    if (errCode < 0) {
        APP_LOGE("compress2 failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return AniZLibCommon::ConvertZipOutputInfo(env, errCode, destLen);
}

ani_object Compress2WithSourceLenNative(ani_env* env, ani_object instance,
    ani_arraybuffer aniDest, ani_arraybuffer aniSource, ani_enum_item aniLevel, ani_long aniSourceLen)
{
    APP_LOGD("Compress2WithSourceLenNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniDest, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniSource, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniLevel, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    uLong destLen = 0;
    void* dest = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniDest, dest, destLen, EINVAL)) {
        APP_LOGE("parse aniDest failed");
        return nullptr;
    }
    uLong sourceLen = 0;
    void* source = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniSource, source, sourceLen, EINVAL)) {
        APP_LOGE("parse aniSource failed");
        return nullptr;
    }
    int32_t level = 0;
    if (!EnumUtils::EnumETSToNative(env, aniLevel, level)) {
        APP_LOGE("Parse aniLevel failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    if (aniSourceLen < 0) {
        APP_LOGE("aniSourceLen is invalid");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    sourceLen = static_cast<uLong>(aniSourceLen);

    if (dest == nullptr || source == nullptr) {
        APP_LOGE("dest or source is nullptr");
        AniZLibCommon::ThrowZLibNapiError(env, ERROR_CODE);
        return nullptr;
    }
    int32_t errCode = compress2(static_cast<Bytef *>(dest), &destLen, static_cast<Bytef *>(source), sourceLen, level);
    if (errCode < 0) {
        APP_LOGE("compress2 failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return AniZLibCommon::ConvertZipOutputInfo(env, errCode, destLen);
}

ani_int CompressBoundNative(ani_env* env, ani_object instance, ani_int aniSourceLen)
{
    APP_LOGD("CompressBoundNative entry");

    CHECK_PARAM_NULL_RETURN(env, -1);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, -1);

    if (aniSourceLen < 0) {
        APP_LOGE("aniSourceLen is invalid");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return -1;
    }

    return static_cast<ani_int>(compressBound(aniSourceLen));
}

ani_object UncompressNative(ani_env* env, ani_object instance, ani_arraybuffer aniDest, ani_arraybuffer aniSource)
{
    APP_LOGD("UncompressNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniDest, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniSource, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    uLong destLen = 0;
    void* dest = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniDest, dest, destLen, EINVAL)) {
        APP_LOGE("parse aniDest failed");
        return nullptr;
    }
    uLong sourceLen = 0;
    void* source = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniSource, source, sourceLen, EINVAL)) {
        APP_LOGE("parse aniSource failed");
        return nullptr;
    }

    if (dest == nullptr || source == nullptr) {
        APP_LOGE("dest or source is nullptr");
        AniZLibCommon::ThrowZLibNapiError(env, ERROR_CODE);
        return nullptr;
    }
    int32_t errCode = uncompress(static_cast<Bytef *>(dest), &destLen, static_cast<Bytef *>(source), sourceLen);
    if (errCode < 0) {
        APP_LOGE("uncompress failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return AniZLibCommon::ConvertZipOutputInfo(env, errCode, destLen);
}

ani_object UncompressWithSourceLenNative(ani_env* env, ani_object instance,
    ani_arraybuffer aniDest, ani_arraybuffer aniSource, ani_long aniSourceLen)
{
    APP_LOGD("UncompressWithSourceLenNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniDest, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniSource, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    uLong destLen = 0;
    void* dest = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniDest, dest, destLen, EINVAL)) {
        APP_LOGE("parse aniDest failed");
        return nullptr;
    }
    uLong sourceLen = 0;
    void* source = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniSource, source, sourceLen, EINVAL)) {
        APP_LOGE("parse aniSource failed");
        return nullptr;
    }
    if (aniSourceLen < 0) {
        APP_LOGE("aniSourceLen is invalid");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    sourceLen = static_cast<uLong>(aniSourceLen);

    if (dest == nullptr || source == nullptr) {
        APP_LOGE("dest or source is nullptr");
        AniZLibCommon::ThrowZLibNapiError(env, ERROR_CODE);
        return nullptr;
    }
    int32_t errCode = uncompress(static_cast<Bytef *>(dest), &destLen, static_cast<Bytef *>(source), sourceLen);
    if (errCode < 0) {
        APP_LOGE("uncompress failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return AniZLibCommon::ConvertZipOutputInfo(env, errCode, destLen);
}

ani_object Uncompress2Native(ani_env* env, ani_object instance, ani_arraybuffer aniDest, ani_arraybuffer aniSource)
{
    APP_LOGD("Uncompress2Native entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniDest, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniSource, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    uLong destLen = 0;
    void* dest = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniDest, dest, destLen, EINVAL)) {
        APP_LOGE("parse aniDest failed");
        return nullptr;
    }
    uLong sourceLen = 0;
    void* source = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniSource, source, sourceLen, EINVAL)) {
        APP_LOGE("parse aniSource failed");
        return nullptr;
    }

    if (dest == nullptr || source == nullptr) {
        APP_LOGE("dest or source is nullptr");
        AniZLibCommon::ThrowZLibNapiError(env, ERROR_CODE);
        return nullptr;
    }
    int32_t errCode = uncompress2(static_cast<Bytef *>(dest), &destLen, static_cast<Bytef *>(source), &sourceLen);
    if (errCode < 0) {
        APP_LOGE("uncompress2 failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return AniZLibCommon::ConvertDecompressionOutputInfo(env, errCode, destLen, sourceLen);
}

ani_object Uncompress2WithSourceLenNative(ani_env* env, ani_object instance,
    ani_arraybuffer aniDest, ani_arraybuffer aniSource, ani_long aniSourceLen)
{
    APP_LOGD("Uncompress2WithSourceLenNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniDest, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniSource, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    uLong destLen = 0;
    void* dest = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniDest, dest, destLen, EINVAL)) {
        APP_LOGE("parse aniDest failed");
        return nullptr;
    }
    uLong sourceLen = 0;
    void* source = nullptr;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniSource, source, sourceLen, EINVAL)) {
        APP_LOGE("parse aniSource failed");
        return nullptr;
    }
    if (aniSourceLen < 0) {
        APP_LOGE("aniSourceLen is invalid");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    sourceLen = static_cast<uLong>(aniSourceLen);

    if (dest == nullptr || source == nullptr) {
        APP_LOGE("dest or source is nullptr");
        AniZLibCommon::ThrowZLibNapiError(env, ERROR_CODE);
        return nullptr;
    }
    int32_t errCode = uncompress2(static_cast<Bytef *>(dest), &destLen, static_cast<Bytef *>(source), &sourceLen);
    if (errCode < 0) {
        APP_LOGE("uncompress2 failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return AniZLibCommon::ConvertDecompressionOutputInfo(env, errCode, destLen, sourceLen);
}

ani_enum_item InflateValidateNative(ani_env* env, ani_object instance, ani_object aniStrm, ani_int aniCheck)
{
    APP_LOGD("InflateValidateNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }

    int32_t errCode = inflateValidate(zStream, aniCheck);
    if (errCode < 0) {
        APP_LOGE("inflateValidate failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item InflateSyncPointNative(ani_env* env, ani_object instance, ani_object aniStrm)
{
    APP_LOGD("InflateSyncPointNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }

    int32_t errCode = inflateSyncPoint(zStream);
    if (errCode < 0) {
        APP_LOGE("inflateSyncPoint failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item InflateSyncNative(ani_env* env, ani_object instance, ani_object aniStrm)
{
    APP_LOGD("InflateSyncNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }

    int32_t errCode = inflateSync(zStream);
    if (errCode < 0) {
        APP_LOGE("inflateSync failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item InflateSetDictionaryNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_arraybuffer aniDictionary)
{
    APP_LOGD("InflateSetDictionaryNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniDictionary, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    void* dictionary = nullptr;
    uInt dictionaryLen = 0;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniDictionary, dictionary, dictionaryLen, EINVAL)) {
        APP_LOGE("parse aniDictionary failed");
        return nullptr;
    }

    int32_t errCode = inflateSetDictionary(zStream, static_cast<Bytef *>(dictionary), dictionaryLen);
    if (errCode < 0) {
        APP_LOGE("inflateSetDictionary failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item InflateResetKeepNative(ani_env* env, ani_object instance, ani_object aniStrm)
{
    APP_LOGD("InflateResetKeepNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }

    int32_t errCode = inflateResetKeep(zStream);
    if (errCode < 0) {
        APP_LOGE("inflateResetKeep failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item InflateReset2Native(ani_env* env, ani_object instance, ani_object aniStrm, ani_int aniWindowBits)
{
    APP_LOGD("InflateReset2Native entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }

    int32_t errCode = inflateReset2(zStream, aniWindowBits);
    if (errCode < 0) {
        APP_LOGE("inflateReset2 failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item InflateResetNative(ani_env* env, ani_object instance, ani_object aniStrm)
{
    APP_LOGD("InflateResetNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }

    int32_t errCode = inflateReset(zStream);
    if (errCode < 0) {
        APP_LOGE("inflateReset failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item InflatePrimeNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_int aniBits, ani_int aniValue)
{
    APP_LOGD("InflatePrimeNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }

    int32_t errCode = inflatePrime(zStream, aniBits, aniValue);
    if (errCode < 0) {
        APP_LOGE("inflatePrime failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_int InflateMarkNative(ani_env* env, ani_object instance, ani_object aniStrm)
{
    APP_LOGD("InflateMarkNative entry");

    CHECK_PARAM_NULL_RETURN(env, -1);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, -1);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, -1);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return -1;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return -1;
    }

    return static_cast<ani_int>(inflateMark(zStream));
}

ani_enum_item InflateInit2Native(ani_env* env, ani_object instance, ani_object aniStrm, ani_int aniWindowBits)
{
    APP_LOGD("InflateInit2Native entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    z_streamp zs = new (std::nothrow)z_stream();
    if (zs == nullptr) {
        APP_LOGE("create zs failed");
        return nullptr;
    }
    if (!SetZStream(env, instance, aniStrm, zs)) {
        APP_LOGE("set zStream failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }

    int32_t errCode = inflateInit2(zs, aniWindowBits);
    if (errCode < 0) {
        APP_LOGE("inflateInit2 failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }
    zStream = zs;
    if (!SetNativeZStream(env, instance, zStream)) {
        APP_LOGE("set native zStream failed");
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item InflateInitNative(ani_env* env, ani_object instance, ani_object aniStrm)
{
    APP_LOGD("InflateInitNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    z_streamp zs = new (std::nothrow)z_stream();
    if (zs == nullptr) {
        APP_LOGE("create zs failed");
        return nullptr;
    }
    if (!SetZStream(env, instance, aniStrm, zs)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }

    int32_t errCode = inflateInit(zs);
    if (errCode < 0) {
        APP_LOGE("inflateInit failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }
    zStream = zs;
    if (!SetNativeZStream(env, instance, zStream)) {
        APP_LOGE("set native zStream failed");
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item InflateGetHeaderNative(ani_env* env, ani_object instance, ani_object aniStrm, ani_object aniHeader)
{
    APP_LOGD("InflateGetHeaderNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniHeader, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    gz_header header = {};
    if (!AniZLibCommon::ParseGzHeader(env, aniHeader, header)) {
        APP_LOGE("parse aniHeader failed");
        return nullptr;
    }

    int32_t errCode = inflateGetHeader(zStream, const_cast<gz_headerp>(&header));
    if (errCode < 0) {
        APP_LOGE("inflateGetHeader failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_object InflateGetDictionaryNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_arraybuffer aniDictionary)
{
    APP_LOGD("InflateGetDictionaryNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniDictionary, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    void* dictionary = nullptr;
    uInt dictionaryLen = 0;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniDictionary, dictionary, dictionaryLen, EINVAL)) {
        APP_LOGE("parse aniDictionary failed");
        return nullptr;
    }

    int32_t errCode = inflateGetDictionary(zStream, static_cast<Bytef *>(dictionary), &dictionaryLen);
    if (errCode < 0) {
        APP_LOGE("inflateGetDictionary failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return AniZLibCommon::ConvertDictionaryOutputInfo(env, errCode, dictionaryLen);
}

ani_enum_item InflateEndNative(ani_env* env, ani_object instance, ani_object aniStrm)
{
    APP_LOGD("InflateEndNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }

    int32_t errCode = inflateEnd(zStream);
    if (errCode < 0) {
        APP_LOGE("inflateEnd failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item InflateCopyNative(ani_env* env, ani_object instance, ani_object aniSource)
{
    APP_LOGD("InflateCopyNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniSource, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }
    z_streamp srcZStream = nullptr;
    if (!GetNativeZStream(env, aniSource, srcZStream, EINVAL)) {
        APP_LOGE("get aniSource zStream failed");
        return nullptr;
    }

    if (zStream == nullptr) {
        zStream = new (std::nothrow)z_stream();
        if (zStream == nullptr) {
            APP_LOGE("create zStream failed");
            return nullptr;
        }
        if (!SetNativeZStream(env, instance, zStream)) {
            APP_LOGE("set native zStream failed");
            return nullptr;
        }
    }
    int32_t errCode = inflateCopy(zStream, srcZStream);
    if (errCode < 0) {
        APP_LOGE("inflateCopy failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_long InflateCodesUsedNative(ani_env* env, ani_object instance, ani_object aniStrm)
{
    APP_LOGD("InflateCodesUsedNative entry");

    CHECK_PARAM_NULL_RETURN(env, -1);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, -1);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, -1);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return -1;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return -1;
    }

    return static_cast<ani_long>(inflateCodesUsed(zStream));
}

ani_enum_item InflateBackInitNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_long aniWindowBits, ani_arraybuffer aniWindow)
{
    APP_LOGD("InflateBackInitNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniWindow, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    if (aniWindowBits < MIN_WINDOWBITS || aniWindowBits > MAX_WINDOWBITS) {
        APP_LOGE("aniWindowBits is invalid");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    void* windowBuf = nullptr;
    size_t windowLen = 0;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniWindow, windowBuf, windowLen, EINVAL)) {
        APP_LOGE("parse aniWindow failed");
        return nullptr;
    }

    int32_t errCode = inflateBackInit(zStream, static_cast<int32_t>(aniWindowBits), static_cast<Bytef *>(windowBuf));
    if (errCode < 0) {
        APP_LOGE("inflateBackInit failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item InflateBackEndNative(ani_env* env, ani_object instance, ani_object aniStrm)
{
    APP_LOGD("InflateBackEndNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }

    int32_t errCode = inflateBackEnd(zStream);
    if (errCode < 0) {
        APP_LOGE("inflateBackEnd failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item InflateBackNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_fn_object aniBackIn, ani_ref aniInDesc, ani_fn_object aniBackOut, ani_ref aniOutDesc)
{
    APP_LOGD("InflateBackNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniBackIn, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniInDesc, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniBackOut, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniOutDesc, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }

    auto inDesc = std::make_shared<InOutDesc>(env, aniBackIn, aniInDesc);
    auto outDesc = std::make_shared<InOutDesc>(env, aniBackOut, aniOutDesc);
    int32_t errCode = inflateBack(zStream, InFunc, inDesc.get(), OutFunc, outDesc.get());
    if (errCode < 0) {
        APP_LOGE("inflateBack failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item InflateNative(ani_env* env, ani_object instance, ani_object aniStrm, ani_enum_item aniFlush)
{
    APP_LOGD("InflateNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniFlush, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    int32_t flush = 0;
    if (!EnumUtils::EnumETSToNative(env, aniFlush, flush)) {
        APP_LOGE("Parse aniFlush failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }

    int32_t errCode = inflate(zStream, flush);
    if (errCode < 0) {
        APP_LOGE("inflate failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item DeflateInitNative(ani_env* env, ani_object instance, ani_object aniStrm, ani_enum_item aniLevel)
{
    APP_LOGD("DeflateInitNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniLevel, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    z_streamp zs = new (std::nothrow)z_stream();
    if (zs == nullptr) {
        APP_LOGE("create zs failed");
        return nullptr;
    }
    if (!SetZStream(env, instance, aniStrm, zs)) {
        APP_LOGE("set zs failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    int32_t level = 0;
    if (!EnumUtils::EnumETSToNative(env, aniLevel, level)) {
        APP_LOGE("Parse aniLevel failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }

    int32_t errCode = deflateInit(zs, level);
    if (errCode < 0) {
        APP_LOGE("deflateInit failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }
    zStream = zs;
    if (!SetNativeZStream(env, instance, zStream)) {
        APP_LOGE("set native zStream failed");
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item DeflateInit2Native(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_enum_item aniLevel, ani_enum_item aniMethod,
    ani_int aniWindowBits, ani_enum_item aniMemLevel, ani_enum_item aniStrategy)
{
    APP_LOGD("DeflateInit2Native entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniLevel, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniMethod, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniMemLevel, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrategy, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    z_streamp zs = new (std::nothrow)z_stream();
    if (zs == nullptr) {
        APP_LOGE("create zs failed");
        return nullptr;
    }
    if (!SetZStream(env, instance, aniStrm, zs)) {
        APP_LOGE("set zStream failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    int32_t level = 0;
    if (!EnumUtils::EnumETSToNative(env, aniLevel, level)) {
        APP_LOGE("Parse aniLevel failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    int32_t method = 0;
    if (!EnumUtils::EnumETSToNative(env, aniMethod, method)) {
        APP_LOGE("Parse aniMethod failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    int32_t memLevel = 0;
    if (!EnumUtils::EnumETSToNative(env, aniMemLevel, memLevel)) {
        APP_LOGE("Parse aniMemLevel failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    int32_t strategy = 0;
    if (!EnumUtils::EnumETSToNative(env, aniStrategy, strategy)) {
        APP_LOGE("Parse aniStrategy failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }

    int32_t errCode = deflateInit2(zs, level, method, aniWindowBits, memLevel, strategy);
    if (errCode < 0) {
        APP_LOGE("deflateInit2 failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }
    zStream = zs;
    if (!SetNativeZStream(env, instance, zStream)) {
        APP_LOGE("set native zStream failed");
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item DeflateNative(ani_env* env, ani_object instance, ani_object aniStrm, ani_enum_item aniFlush)
{
    APP_LOGD("DeflateNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniFlush, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }
    int32_t flush = 0;
    if (!EnumUtils::EnumETSToNative(env, aniFlush, flush)) {
        APP_LOGE("Parse aniFlush failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }

    int32_t errCode = deflate(zStream, flush);
    if (errCode < 0) {
        APP_LOGE("deflate failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item DeflateEndNative(ani_env* env, ani_object instance, ani_object aniStrm)
{
    APP_LOGD("DeflateEndNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }

    int32_t errCode = deflateEnd(zStream);
    if (errCode < 0) {
        APP_LOGE("deflateEnd failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_int DeflateBoundNative(ani_env* env, ani_object instance, ani_object aniStrm, ani_long aniSourceLength)
{
    APP_LOGD("DeflateBoundNative entry");

    CHECK_PARAM_NULL_RETURN(env, -1);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, -1);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, -1);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return -1;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return -1;
    }
    if (aniSourceLength < 0) {
        APP_LOGE("aniSourceLength is invalid");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return -1;
    }

    return static_cast<ani_int>(deflateBound(zStream, aniSourceLength));
}

ani_enum_item DeflateSetHeaderNative(ani_env* env, ani_object instance, ani_object aniStrm, ani_object aniHead)
{
    APP_LOGD("DeflateSetHeaderNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniHead, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }
    gz_header head = {};
    if (!AniZLibCommon::ParseGzHeader(env, aniHead, head)) {
        APP_LOGE("parse aniHead failed");
        return nullptr;
    }

    int32_t errCode = deflateSetHeader(zStream, const_cast<gz_headerp>(&head));
    if (errCode < 0) {
        APP_LOGE("deflateSetHeader failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item DeflateCopyNative(ani_env* env, ani_object instance, ani_object aniSource)
{
    APP_LOGD("DeflateCopyNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniSource, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }
    z_streamp srcZStream = nullptr;
    if (!GetNativeZStream(env, aniSource, srcZStream, EINVAL)) {
        APP_LOGE("get aniSource zStream failed");
        return nullptr;
    }

    if (zStream == nullptr) {
        zStream = new (std::nothrow)z_stream();
        if (zStream == nullptr) {
            APP_LOGE("create zStream failed");
            return nullptr;
        }
        if (!SetNativeZStream(env, instance, zStream)) {
            APP_LOGE("set native zStream failed");
            return nullptr;
        }
    }
    int32_t errCode = deflateCopy(zStream, srcZStream);
    if (errCode < 0) {
        APP_LOGE("deflateCopy failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item DeflateSetDictionaryNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_arraybuffer aniDictionary)
{
    APP_LOGD("DeflateSetDictionaryNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniDictionary, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }
    void* dictionary = nullptr;
    uInt dictionaryLen = 0;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniDictionary, dictionary, dictionaryLen, EINVAL)) {
        APP_LOGE("parse aniDictionary failed");
        return nullptr;
    }

    int32_t errCode = deflateSetDictionary(zStream, reinterpret_cast<const Bytef *>(dictionary), dictionaryLen);
    if (errCode < 0) {
        APP_LOGE("deflateSetDictionary failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_object DeflateGetDictionaryNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_arraybuffer aniDictionary)
{
    APP_LOGD("DeflateGetDictionaryNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniDictionary, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }
    void* dictionary = nullptr;
    uInt dictionaryLen = 0;
    if (!AniZLibCommon::ParseArrayBuffer(env, aniDictionary, dictionary, dictionaryLen, EINVAL)) {
        APP_LOGE("parse aniDictionary failed");
        return nullptr;
    }

    int32_t errCode = deflateGetDictionary(zStream, static_cast<Bytef *>(dictionary), &dictionaryLen);
    if (errCode < 0) {
        APP_LOGE("deflateGetDictionary failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return AniZLibCommon::ConvertDictionaryOutputInfo(env, errCode, dictionaryLen);
}

ani_enum_item DeflateTuneNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_int aniGoodLength, ani_int aniMaxLazy, ani_int aniNiceLength, ani_int aniMaxChain)
{
    APP_LOGD("DeflateTuneNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }

    int32_t errCode = deflateTune(zStream, aniGoodLength, aniMaxLazy, aniNiceLength, aniMaxChain);
    if (errCode < 0) {
        APP_LOGE("deflateTune failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item DeflateResetNative(ani_env* env, ani_object instance, ani_object aniStrm)
{
    APP_LOGD("DeflateResetNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }

    int32_t errCode = deflateReset(zStream);
    if (errCode < 0) {
        APP_LOGE("deflateReset failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item DeflateResetKeepNative(ani_env* env, ani_object instance, ani_object aniStrm)
{
    APP_LOGD("DeflateResetKeepNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }

    int32_t errCode = deflateResetKeep(zStream);
    if (errCode < 0) {
        APP_LOGE("deflateResetKeep failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_object DeflatePendingNative(ani_env* env, ani_object instance, ani_object aniStrm)
{
    APP_LOGD("DeflatePendingNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }

    uint32_t pending = 0U;
    int32_t bits = 0;
    int32_t errCode = deflatePending(zStream, &pending, &bits);
    if (errCode < 0) {
        APP_LOGE("deflatePending failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return AniZLibCommon::ConvertDeflatePendingOutputInfo(env, errCode, pending, bits);
}

ani_enum_item DeflateParamsNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_enum_item aniLevel, ani_enum_item aniStrategy)
{
    APP_LOGD("DeflateParamsNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniLevel, EINVAL, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrategy, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }
    int32_t level = 0;
    if (!EnumUtils::EnumETSToNative(env, aniLevel, level)) {
        APP_LOGE("Parse aniLevel failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }
    int32_t strategy = 0;
    if (!EnumUtils::EnumETSToNative(env, aniStrategy, strategy)) {
        APP_LOGE("Parse aniStrategy failed");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }

    int32_t errCode = deflateParams(zStream, level, strategy);
    if (errCode < 0) {
        APP_LOGE("deflateParams failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}

ani_enum_item DeflatePrimeNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_int aniBits, ani_int aniValue)
{
    APP_LOGD("DeflatePrimeNative entry");

    CHECK_PARAM_NULL_RETURN(env, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(instance, EFAULT, nullptr);
    CHECK_PARAM_NULL_THROW_RETURN(aniStrm, EINVAL, nullptr);

    z_streamp zStream = nullptr;
    if (!GetNativeZStream(env, instance, zStream, EFAULT)) {
        APP_LOGE("get native zStream failed");
        return nullptr;
    }

    if (!SetZStream(env, instance, aniStrm, zStream)) {
        APP_LOGE("set zStream failed");
        return nullptr;
    }
    if (aniBits < MIN_BITS || aniBits > MAX_BITS) {
        APP_LOGE("aniBits is invalid");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return nullptr;
    }

    int32_t errCode = deflatePrime(zStream, aniBits, aniValue);
    if (errCode < 0) {
        APP_LOGE("deflatePrime failed %{public}d", errCode);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return nullptr;
    }

    return EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode);
}
} // namespace AniZLibGZip
} // namespace AppExecFwk
} // namespace OHOS