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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_GZIP_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_GZIP_H

#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "zlib.h"

namespace OHOS {
namespace AppExecFwk {
namespace AniZLibGZip {
void GzdopenNative(ani_env* env, ani_object instance, ani_int aniFd, ani_string aniMode);
ani_int GzbufferNative(ani_env* env, ani_object instance, ani_long aniSize);
void GzopenNative(ani_env* env, ani_object instance, ani_string aniPath, ani_string aniMode);
ani_int GzeofNative(ani_env* env, ani_object instance);
ani_int GzdirectNative(ani_env* env, ani_object instance);
ani_enum_item GzcloseNative(ani_env* env, ani_object instance);
void GzclearerrNative(ani_env* env, ani_object instance);
ani_object GzerrorNative(ani_env* env, ani_object instance);
ani_int GzgetcNative(ani_env* env, ani_object instance);
ani_enum_item GzflushNative(ani_env* env, ani_object instance, ani_enum_item aniFlush);
ani_long GzfwriteNative(
    ani_env* env, ani_object instance, ani_arraybuffer aniBuf, ani_long aniSize, ani_long aniNItems);
ani_long GzfreadNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf, ani_long aniSize, ani_long aniNItems);
ani_enum_item GzclosewNative(ani_env* env, ani_object instance);
ani_enum_item GzcloserNative(ani_env* env, ani_object instance);
ani_long GzwriteNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf, ani_long aniLen);
ani_int GzungetcNative(ani_env* env, ani_object instance, ani_int aniC);
ani_long GztellNative(ani_env* env, ani_object instance);
ani_enum_item GzsetparamsNative(ani_env* env, ani_object instance, ani_enum_item aniLevel, ani_enum_item aniStrategy);
ani_long GzseekNative(ani_env* env, ani_object instance, ani_long aniOffset, ani_enum_item aniWhence);
ani_enum_item GzrewindNative(ani_env* env, ani_object instance);
ani_long GzreadNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf);
ani_int GzputsNative(ani_env* env, ani_object instance, ani_string aniStr);
ani_int GzputcNative(ani_env* env, ani_object instance, ani_int aniC);
ani_int GzprintfNative(ani_env* env, ani_object instance, ani_string aniFormat, ani_object args);
ani_long GzoffsetNative(ani_env* env, ani_object instance);
ani_string GzgetsNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf);
} // namespace AniZLibGZip
} // namespace AppExecFwk
} // namespace OHOS
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_GZIP_H