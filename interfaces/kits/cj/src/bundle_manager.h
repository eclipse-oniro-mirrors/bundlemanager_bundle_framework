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

#ifndef OHOS_BUNDLE_MANAGER_H
#define OHOS_BUNDLE_MANAGER_H
 
 
#include <cstdint>
#include <string>
#include "bundle_manager_utils.h"
#include "bundle_info.h"
#include "recoverable_application_info.h"

namespace OHOS {
namespace CJSystemapi {
namespace BundleManager {

constexpr int8_t UNSPECIFIED_USERID = -2;
constexpr int32_t BASE_USER_RANGE = 200000;
const std::string GET_BUNDLE_INFO = "GetBundleInfo";

class BundleManagerImpl {
public:
    static AppExecFwk::BundleInfo GetBundleInfoForSelf(int32_t bundleFlags);
    static int32_t VerifyAbc(std::vector<std::string> abcPaths, bool flag);
    static std::tuple<int32_t, std::vector<std::string>> GetProfileByExtensionAbility(
        std::string moduleName, std::string extensionAbilityName, char* metadataName);
    static std::tuple<int32_t, std::vector<std::string>> GetProfileByAbility(
        std::string moduleName, std::string abilityName, char* metadataName);
};

} // BundleManager
} // CJSystemapi
} // OHOS

#endif