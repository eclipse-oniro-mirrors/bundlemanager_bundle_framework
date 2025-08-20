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

#include "ani_checksum.h"
#include "ani_signature_builder.h"
#include "ani_zlib_common.h"
#include "checksum_common_func.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace AniZLibChecksum {
namespace {
constexpr const char* PARAM_NAME_BUF = "buf";
constexpr const char* PARAM_NAME_ADLER = "adler";
constexpr const char* PARAM_NAME_ADLER1 = "adler1";
constexpr const char* PARAM_NAME_ADLER2 = "adler2";
constexpr const char* PARAM_NAME_CRC = "crc";
constexpr const char* PARAM_NAME_CRC1 = "crc1";
constexpr const char* PARAM_NAME_CRC2 = "crc2";
constexpr const char* PARAM_NAME_LEN2 = "len2";
constexpr const size_t TABLE_SIZE = 256;
} // namespace

using namespace arkts::ani_signature;

template<typename tableType>
static ani_object ConvertCRCTable(ani_env* env, const tableType* table, const size_t tableSize)
{
    ani_value arg = { .i = static_cast<ani_int>(tableSize) };
    ani_object arrayObj = CommonFunAni::CreateNewObjectByClassV2(
        env, CommonFunAniNS::CLASSNAME_ARRAY, Builder::BuildSignatureDescriptor({ Builder::BuildInt() }), &arg);
    RETURN_NULL_IF_NULL(arrayObj);

    static const std::string setterSig = Builder::BuildSignatureDescriptor(
        { Builder::BuildInt(), Builder::BuildClass(CommonFunAniNS::CLASSNAME_OBJECT) });
    static const std::string longCtorSig = Builder::BuildSignatureDescriptor({ Builder::BuildLong() });
    for (size_t i = 0; i < tableSize; ++i) {
        ani_value argLong = { .l = static_cast<ani_long>(table[i]) };
        ani_object longObj =
            CommonFunAni::CreateNewObjectByClassV2(env, CommonFunAniNS::CLASSNAME_LONG, longCtorSig, &argLong);
        RETURN_NULL_IF_NULL(longObj);
        ani_status status =
            env->Object_CallMethodByName_Void(arrayObj, "$_set", setterSig.c_str(), static_cast<ani_int>(i), longObj);
        env->Reference_Delete(longObj);
        if (status != ANI_OK) {
            APP_LOGE("Object_CallMethodByName_Void failed %{public}d", status);
            return nullptr;
        }
    }

    return arrayObj;
}

ani_long adler32Native(ani_env* env, ani_object, ani_long aniAdler, ani_arraybuffer buf)
{
    APP_LOGD("adler32Native entry");

    if (buf == nullptr) {
        APP_LOGE("buf is nullptr");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    size_t bufferLength = 0;
    void* buffer = nullptr;
    ani_status status = env->ArrayBuffer_GetInfo(buf, &buffer, &bufferLength);
    if (status != ANI_OK) {
        APP_LOGE("ArrayBuffer_GetInfo failed: %{public}d", status);
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    if (buffer == nullptr) {
        APP_LOGE("native buf is nullptr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    return static_cast<ani_long>(
        adler32(static_cast<uLong>(aniAdler), reinterpret_cast<Bytef*>(buffer), static_cast<uInt>(bufferLength)));
}

ani_long adler32CombineNative(ani_env* env, ani_object, ani_long aniAdler1, ani_long aniAdler2, ani_long aniLen2)
{
    APP_LOGD("adler32CombineNative entry");

    if (aniLen2 < 0) {
        APP_LOGE("negative aniLen2");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return 0;
    }

#ifdef Z_LARGE64
    return static_cast<ani_long>(adler32_combine64(
        static_cast<uLong>(aniAdler1), static_cast<uLong>(aniAdler2), static_cast<z_off64_t>(aniLen2)));
#else
    return static_cast<ani_long>(adler32_combine(
        static_cast<uLong>(aniAdler1), static_cast<uLong>(aniAdler2), static_cast<z_off_t>(aniLen2)));
#endif
}

ani_long crc32Native(ani_env* env, ani_object, ani_long aniCrc, ani_arraybuffer buf)
{
    APP_LOGD("crc32Native entry");

    if (buf == nullptr) {
        APP_LOGE("buf is nullptr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    size_t bufferLength = 0;
    void* buffer = nullptr;
    ani_status status = env->ArrayBuffer_GetInfo(buf, &buffer, &bufferLength);
    if (status != ANI_OK) {
        APP_LOGE("ArrayBuffer_GetInfo failed: %{public}d", status);
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    if (buffer == nullptr) {
        APP_LOGE("native buf is nullptr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    return static_cast<ani_long>(
        crc32(static_cast<uLong>(aniCrc), reinterpret_cast<Bytef*>(buffer), static_cast<uInt>(bufferLength)));
}

ani_long crc32CombineNative(ani_env* env, ani_object, ani_long aniCrc1, ani_long aniCrc2, ani_long aniLen2)
{
    APP_LOGD("crc32CombineNative entry");

    if (aniLen2 < 0) {
        APP_LOGE("negative aniLen2");
        AniZLibCommon::ThrowZLibNapiError(env, EINVAL);
        return 0;
    }

#ifdef Z_LARGE64
    return static_cast<ani_long>(
        crc32_combine64(static_cast<uLong>(aniCrc1), static_cast<uLong>(aniCrc2), static_cast<z_off64_t>(aniLen2)));
#else
    return static_cast<ani_long>(
        crc32_combine(static_cast<uLong>(aniCrc1), static_cast<uLong>(aniCrc2), static_cast<z_off_t>(aniLen2)));
#endif
}

ani_long crc64Native(ani_env* env, ani_object, ani_long aniCrc, ani_arraybuffer buf)
{
    APP_LOGD("crc64Native entry");

    if (buf == nullptr) {
        APP_LOGE("buf is nullptr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    size_t bufferLength = 0;
    void* buffer = nullptr;
    ani_status status = env->ArrayBuffer_GetInfo(buf, &buffer, &bufferLength);
    if (status != ANI_OK) {
        APP_LOGE("ArrayBuffer_GetInfo failed: %{public}d", status);
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    if (buffer == nullptr) {
        APP_LOGE("native buf is nullptr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    return static_cast<ani_long>(
        LIBZIP::ComputeCrc64(static_cast<uint64_t>(aniCrc), reinterpret_cast<char*>(buffer), bufferLength));
}

ani_object getCrcTableNative(ani_env* env, ani_object)
{
    APP_LOGD("getCrcTableNative entry");

    return ConvertCRCTable(env, get_crc_table(), TABLE_SIZE);
}

ani_object getCrc64TableNative(ani_env* env, ani_object)
{
    APP_LOGD("getCrc64TableNative entry");

    return ConvertCRCTable(env, LIBZIP::CRC64_TABLE, TABLE_SIZE);
}
} // namespace AniZLibChecksum
} // namespace AppExecFwk
} // namespace OHOS