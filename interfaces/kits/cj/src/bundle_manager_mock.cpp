/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cj_common_ffi.h"

extern "C" {
FFI_EXPORT int32_t FfiOHOSGetCallingUid = 0;
FFI_EXPORT int32_t FfiOHOSGetBundleInfoForSelf = 0;
FFI_EXPORT int32_t FfiOHOSVerifyAbc = 0;
FFI_EXPORT int32_t FfiGetProfileByExtensionAbility = 0;
FFI_EXPORT int32_t FfiGetProfileByAbility = 0;
FFI_EXPORT int32_t FfiBundleManagerIsDefaultApplication = 0;
FFI_EXPORT int32_t FfiBundleManagerCompressFile = 0;
FFI_EXPORT int32_t FfiBundleManagerDeCompressFileOptions = 0;
FFI_EXPORT int32_t FfiBundleManagerDeCompressFile = 0;
FFI_EXPORT int32_t FfiBundleManagerCanOpenLink = 0;
FFI_EXPORT int32_t FfiOHOSGetAPITargetVersion = 0;
}