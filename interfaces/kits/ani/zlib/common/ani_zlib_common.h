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

#include "napi_business_error.h"
#include "napi_constants.h"

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

void ThrowZLibNapiError(ani_env* env, int posixError)
{
    auto errorPair = LIBZIP::errCodeTable.find(posixError) == LIBZIP::errCodeTable.end()
                         ? LIBZIP::errCodeTable.at(ENOSTR)
                         : LIBZIP::errCodeTable.at(posixError);
    BusinessErrorAni::ThrowError(env, errorPair.first, errorPair.second);
}
} // namespace AniZLibCommon
} // namespace AppExecFwk
} // namespace OHOS
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ZLIB_COMMON_H
