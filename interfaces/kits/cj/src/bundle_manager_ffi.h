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

#ifndef OHOS_BUNDLE_MANAGER_FFI_H
#define OHOS_BUNDLE_MANAGER_FFI_H

#include "native/ffi_remote_data.h"
#include "cj_common_ffi.h"
#include "bundle_manager_utils.h"

namespace OHOS {
namespace CJSystemapi {
namespace BundleManager {

extern "C" {
    FFI_EXPORT int32_t FfiOHOSGetCallingUid();
    FFI_EXPORT RetBundleInfo FfiOHOSGetBundleInfoForSelf(int32_t bundleFlags);
    FFI_EXPORT RetBundleInfoV2 FfiOHOSGetBundleInfoForSelfV2(int32_t bundleFlags);
    FFI_EXPORT int32_t FfiOHOSVerifyAbc(CArrString cAbcPaths, bool deleteOriginalFiles);
    FFI_EXPORT RetCArrString FfiGetProfileByExtensionAbility(
        char* moduleName, char* extensionAbilityName, char* metadataName);
    FFI_EXPORT RetCArrString FfiGetProfileByAbility(char* moduleName, char* extensionAbilityName, char* metadataName);
    FFI_EXPORT bool FfiBundleManagerCanOpenLink(char* link, int32_t& code);
    FFI_EXPORT uint32_t FfiOHOSGetAPITargetVersion();
}

} // BundleManager
} // CJSystemapi
} // OHOS

#endif