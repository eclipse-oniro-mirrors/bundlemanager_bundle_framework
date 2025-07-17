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
void gzdopenNative(ani_env* env, ani_object instance, ani_int aniFd, ani_string aniMode);
ani_int gzbufferNative(ani_env* env, ani_object instance, ani_long aniSize);
void gzopenNative(ani_env* env, ani_object instance, ani_string aniPath, ani_string aniMode);
ani_int gzeofNative(ani_env* env, ani_object instance);
ani_int gzdirectNative(ani_env* env, ani_object instance);
ani_enum_item gzcloseNative(ani_env* env, ani_object instance);
void gzclearerrNative(ani_env* env, ani_object instance);
ani_object gzerrorNative(ani_env* env, ani_object instance);
ani_int gzgetcNative(ani_env* env, ani_object instance);
ani_enum_item gzflushNative(ani_env* env, ani_object instance, ani_enum_item aniFlush);
ani_long gzfwriteNative(
    ani_env* env, ani_object instance, ani_arraybuffer aniBuf, ani_long aniSize, ani_long aniNItems);
ani_long gzfreadNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf, ani_long aniSize, ani_long aniNItems);
ani_enum_item gzclosewNative(ani_env* env, ani_object instance);
ani_enum_item gzcloserNative(ani_env* env, ani_object instance);
ani_long gzwriteNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf, ani_long aniLen);
ani_int gzungetcNative(ani_env* env, ani_object instance, ani_int aniC);
ani_long gztellNative(ani_env* env, ani_object instance);
ani_enum_item gzsetparamsNative(ani_env* env, ani_object instance, ani_enum_item aniLevel, ani_enum_item aniStrategy);
ani_long gzseekNative(ani_env* env, ani_object instance, ani_long aniOffset, ani_enum_item aniWhence);
ani_enum_item gzrewindNative(ani_env* env, ani_object instance);
ani_long gzreadNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf);
ani_int gzputsNative(ani_env* env, ani_object instance, ani_string aniStr);
ani_int gzputcNative(ani_env* env, ani_object instance, ani_int aniC);
ani_int gzprintfNative(ani_env* env, ani_object instance, ani_string aniFormat, ani_object args);
ani_long gzoffsetNative(ani_env* env, ani_object instance);
ani_string gzgetsNative(ani_env* env, ani_object instance, ani_arraybuffer aniBuf);
} // namespace AniZLibGZip
} // namespace AppExecFwk
} // namespace OHOS
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_GZIP_H