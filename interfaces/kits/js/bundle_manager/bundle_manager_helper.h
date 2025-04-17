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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_BUNDLE_MANAGER_HELPER_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_BUNDLE_MANAGER_HELPER_H

#include "bundle_errors.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {
class BundleManagerHelper {
public:
    static ErrCode InnerBatchQueryAbilityInfos(const std::vector<OHOS::AAFwk::Want> &wants,
        int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos);
    static ErrCode InnerGetDynamicIcon(const std::string &bundleName, std::string &moduleName);
    static ErrCode InnerIsAbilityEnabled(const AbilityInfo &abilityInfo, bool &isEnable, int32_t appIndex);
    static ErrCode InnerSetAbilityEnabled(const AbilityInfo &abilityInfo, bool &isEnable, int32_t appIndex);
    static ErrCode InnerSetApplicationEnabled(const std::string &bundleName, bool &isEnable, int32_t appIndex);
};
} // AppExecFwk
} // OHOS
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_BUNDLE_MANAGER_HELPER_H