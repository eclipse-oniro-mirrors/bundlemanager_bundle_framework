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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_CHECKSUM_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_CHECKSUM_H

#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "zlib.h"

namespace OHOS {
namespace AppExecFwk {
namespace AniZLibChecksum {
ani_long adler32Native(ani_env* env, ani_object, ani_long aniAdler, ani_arraybuffer buf);
ani_long adler32CombineNative(ani_env* env, ani_object, ani_long aniAdler1, ani_long aniAdler2, ani_long aniLen2);
ani_long crc32Native(ani_env* env, ani_object, ani_long aniCrc, ani_arraybuffer buf);
ani_long crc32CombineNative(ani_env* env, ani_object, ani_long aniCrc1, ani_long aniCrc2, ani_long aniLen2);
ani_long crc64Native(ani_env* env, ani_object, ani_long aniCrc, ani_arraybuffer buf);
ani_object getCrcTableNative(ani_env* env, ani_object);
ani_object getCrc64TableNative(ani_env* env, ani_object);
} // namespace AniZLibChecksum
} // namespace AppExecFwk
} // namespace OHOS
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_CHECKSUM_H