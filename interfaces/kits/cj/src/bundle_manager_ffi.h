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

struct Query {
    std::string nBundleName;
    std::string nInterfaceType;
    int32_t nFlags = 0;
    int32_t nUserId = AppExecFwk::Constants::UNSPECIFIED_USERID;
 
    Query(const std::string &bundleName, const std::string &interfaceType, int32_t flags, int32_t userId)
        : nBundleName(bundleName), nInterfaceType(interfaceType), nFlags(flags), nUserId(userId) {}
 
    bool operator==(const Query &query) const
    {
        return nBundleName == query.nBundleName && nInterfaceType == query.nInterfaceType &&
            nFlags == query.nFlags && nUserId == query.nUserId;
    }
};

struct QueryHash  {
    size_t operator()(const Query &query) const
    {
        return std::hash<std::string>()(query.nBundleName) ^ std::hash<std::string>()(query.nInterfaceType) ^
            std::hash<int32_t>()(query.nFlags) ^ std::hash<int32_t>()(query.nUserId);
    }
};

extern "C" {
    FFI_EXPORT RetBundleInfo FfiOHOSGetBundleInfoForSelf(int32_t bundleFlags);
    FFI_EXPORT int32_t FfiOHOSVerifyAbc(CArrString cAbcPaths, bool deleteOriginalFiles);
    FFI_EXPORT RetCArrString FfiGetProfileByExtensionAbility(
        char* moduleName, char* extensionAbilityName, char* metadataName);
    FFI_EXPORT RetCArrString FfiGetProfileByAbility(char* moduleName, char* extensionAbilityName, char* metadataName);
}

} // BundleManager
} // CJSystemapi
} // OHOS

#endif