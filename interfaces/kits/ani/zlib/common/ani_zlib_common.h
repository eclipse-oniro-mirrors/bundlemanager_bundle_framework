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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ZLIB_COMMON_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ZLIB_COMMON_H

#include <ani.h>
#include "app_log_wrapper.h"
#include "common/common_func.h"
#include "napi_business_error.h"
#include "napi_constants.h"
#include "zip_utils.h"
#include "zlib.h"

#define CHECK_PARAM_NULL(param)          \
    do {                                 \
        if ((param) == nullptr) {        \
            APP_LOGE(#param " is null"); \
            return;                      \
        }                                \
    } while (0)
#define CHECK_PARAM_NULL_RETURN(param, returns) \
    do {                                        \
        if ((param) == nullptr) {               \
            APP_LOGE(#param " is null");        \
            return returns;                     \
        }                                       \
    } while (0)
#define CHECK_PARAM_NULL_THROW(param, throws)                                 \
    do {                                                                      \
        if ((param) == nullptr) {                                             \
            APP_LOGE(#param " is null");                                      \
            OHOS::AppExecFwk::AniZLibCommon::ThrowZLibNapiError(env, throws); \
            return;                                                           \
        }                                                                     \
    } while (0)
#define CHECK_PARAM_NULL_THROW_RETURN(param, throws, returns)                 \
    do {                                                                      \
        if ((param) == nullptr) {                                             \
            APP_LOGE(#param " is null");                                      \
            OHOS::AppExecFwk::AniZLibCommon::ThrowZLibNapiError(env, throws); \
            return returns;                                                   \
        }                                                                     \
    } while (0)

namespace OHOS {
namespace AppExecFwk {
namespace AniZLibCommon {
void ThrowZLibNapiError(ani_env* env, int posixError);

bool ParseOptions(ani_env* env, ani_object object, LIBZIP::OPTIONS& options);
bool ParseZStream(ani_env* env, ani_object object, LIBZIP::HasZStreamMember& hasZStreamMember, z_stream& result);
bool ParseGzHeader(ani_env* env, ani_object object, gz_header& result);

ani_object ConvertZStream(ani_env* env, const z_streamp zStream);
ani_object ConvertZipOutputInfo(ani_env* env, const int32_t errCode, const uLong destLen);
ani_object ConvertDecompressionOutputInfo(ani_env* env,
    const int32_t errCode, const uLong destLen, const ulong sourceLen);
ani_object ConvertDictionaryOutputInfo(ani_env* env, const int32_t errCode, const uInt dictionaryLen);
ani_object ConvertDeflatePendingOutputInfo(ani_env* env,
    const int32_t errCode, const uint32_t pending, const int32_t bits);

template<typename valueType>
bool ParseArrayBuffer(ani_env* env, ani_arraybuffer aniBuf, void*& buf, valueType& bufLen, const int errCode)
{
    size_t tmpLen = 0;
    ani_status status = env->ArrayBuffer_GetInfo(aniBuf, &buf, &tmpLen);
    if (status != ANI_OK) {
        APP_LOGE("ArrayBuffer_GetInfo failed: %{public}d", status);
        AniZLibCommon::ThrowZLibNapiError(env, errCode);
        return false;
    }
    bufLen = static_cast<valueType>(tmpLen);
    if (bufLen == 0) {
        buf = nullptr;
    }
    return true;
}
} // namespace AniZLibCommon
} // namespace AppExecFwk
} // namespace OHOS
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ZLIB_COMMON_H
