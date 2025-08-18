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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ZIP_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ZIP_H

#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include <string>

namespace OHOS {
namespace AppExecFwk {
namespace AniZLibZip {
ani_object GetZStreamNative(ani_env* env, ani_object instance);
ani_string ZlibVersionNative(ani_env* env, ani_object instance);
ani_int ZlibCompileFlagsNative(ani_env* env, ani_object instance);
ani_object CompressNative(ani_env* env, ani_object instance, ani_arraybuffer aniDest, ani_arraybuffer aniSource);
ani_object CompressWithSourceLenNative(ani_env* env, ani_object instance,
    ani_arraybuffer aniDest, ani_arraybuffer aniSource, ani_long aniSourceLen);
ani_object Compress2Native(ani_env* env, ani_object instance,
    ani_arraybuffer aniDest, ani_arraybuffer aniSource, ani_enum_item aniLevel);
ani_object Compress2WithSourceLenNative(ani_env* env, ani_object instance,
    ani_arraybuffer aniDest, ani_arraybuffer aniSource, ani_enum_item aniLevel, ani_long aniSourceLen);
ani_int CompressBoundNative(ani_env* env, ani_object instance, ani_int aniSourceLen);
ani_object UncompressNative(ani_env* env, ani_object instance, ani_arraybuffer aniDest, ani_arraybuffer aniSource);
ani_object UncompressWithSourceLenNative(ani_env* env, ani_object instance,
    ani_arraybuffer aniDest, ani_arraybuffer aniSource, ani_long aniSourceLen);
ani_object Uncompress2Native(ani_env* env, ani_object instance, ani_arraybuffer aniDest, ani_arraybuffer aniSource);
ani_object Uncompress2WithSourceLenNative(ani_env* env, ani_object instance,
    ani_arraybuffer aniDest, ani_arraybuffer aniSource, ani_long aniSourceLen);
ani_enum_item InflateValidateNative(ani_env* env, ani_object instance, ani_object aniStrm, ani_int aniCheck);
ani_enum_item InflateSyncPointNative(ani_env* env, ani_object instance, ani_object aniStrm);
ani_enum_item InflateSyncNative(ani_env* env, ani_object instance, ani_object aniStrm);
ani_enum_item InflateSetDictionaryNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_arraybuffer aniDictionary);
ani_enum_item InflateResetKeepNative(ani_env* env, ani_object instance, ani_object aniStrm);
ani_enum_item InflateReset2Native(ani_env* env, ani_object instance, ani_object aniStrm, ani_int aniWindowBits);
ani_enum_item InflateResetNative(ani_env* env, ani_object instance, ani_object aniStrm);
ani_enum_item InflatePrimeNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_int aniBits, ani_int aniValue);
ani_int InflateMarkNative(ani_env* env, ani_object instance, ani_object aniStrm);
ani_enum_item InflateInit2Native(ani_env* env, ani_object instance, ani_object aniStrm, ani_int aniWindowBits);
ani_enum_item InflateInitNative(ani_env* env, ani_object instance, ani_object aniStrm);
ani_enum_item InflateGetHeaderNative(ani_env* env, ani_object instance, ani_object aniStrm, ani_object aniHeader);
ani_object InflateGetDictionaryNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_arraybuffer aniDictionary);
ani_enum_item InflateEndNative(ani_env* env, ani_object instance, ani_object aniStrm);
ani_enum_item InflateCopyNative(ani_env* env, ani_object instance, ani_object aniSource);
ani_long InflateCodesUsedNative(ani_env* env, ani_object instance, ani_object aniStrm);
ani_enum_item InflateBackInitNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_long aniWindowBits, ani_arraybuffer aniWindow);
ani_enum_item InflateBackEndNative(ani_env* env, ani_object instance, ani_object aniStrm);
ani_enum_item InflateBackNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_fn_object aniBackIn, ani_ref aniInDesc, ani_fn_object aniBackOut, ani_ref aniOutDesc);
ani_enum_item InflateNative(ani_env* env, ani_object instance, ani_object aniStrm, ani_enum_item aniFlush);
ani_enum_item DeflateInitNative(ani_env* env, ani_object instance, ani_object aniStrm, ani_enum_item aniLevel);
ani_enum_item DeflateInit2Native(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_enum_item aniLevel, ani_enum_item aniMethod,
    ani_int aniWindowBits, ani_enum_item aniMemLevel, ani_enum_item aniStrategy);
ani_enum_item DeflateNative(ani_env* env, ani_object instance, ani_object aniStrm, ani_enum_item aniFlush);
ani_enum_item DeflateEndNative(ani_env* env, ani_object instance, ani_object aniStrm);
ani_int DeflateBoundNative(ani_env* env, ani_object instance, ani_object aniStrm, ani_long aniSourceLength);
ani_enum_item DeflateSetHeaderNative(ani_env* env, ani_object instance, ani_object aniStrm, ani_object aniHead);
ani_enum_item DeflateCopyNative(ani_env* env, ani_object instance, ani_object aniSource);
ani_enum_item DeflateSetDictionaryNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_arraybuffer aniDictionary);
ani_object DeflateGetDictionaryNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_arraybuffer aniDictionary);
ani_enum_item DeflateTuneNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_int aniGoodLength, ani_int aniMaxLazy, ani_int aniNiceLength, ani_int aniMaxChain);
ani_enum_item DeflateResetNative(ani_env* env, ani_object instance, ani_object aniStrm);
ani_enum_item DeflateResetKeepNative(ani_env* env, ani_object instance, ani_object aniStrm);
ani_object DeflatePendingNative(ani_env* env, ani_object instance, ani_object aniStrm);
ani_enum_item DeflateParamsNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_enum_item aniLevel, ani_enum_item aniStrategy);
ani_enum_item DeflatePrimeNative(ani_env* env, ani_object instance,
    ani_object aniStrm, ani_int aniBits, ani_int aniValue);
} // namespace AniZLibZip
} // namespace AppExecFwk
} // namespace OHOS
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ZIP_H