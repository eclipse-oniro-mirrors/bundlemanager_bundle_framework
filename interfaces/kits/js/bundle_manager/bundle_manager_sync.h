/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_BUNDLE_MANAGER_SYNC_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_BUNDLE_MANAGER_SYNC_H

#include "ability_info.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {

struct ExtensionParamInfo {
    OHOS::AAFwk::Want want;
    int32_t extensionAbilityType = static_cast<int32_t>(ExtensionAbilityType::UNSPECIFIED);
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::string extensionTypeName;
    bool isExtensionTypeName = false;
};

napi_value SetApplicationEnabledSync(napi_env env, napi_callback_info info);
napi_value SetAbilityEnabledSync(napi_env env, napi_callback_info info);
napi_value IsApplicationEnabledSync(napi_env env, napi_callback_info info);
napi_value IsAbilityEnabledSync(napi_env env, napi_callback_info info);
napi_value QueryExtensionInfosSync(napi_env env, napi_callback_info info);
napi_value GetPermissionDefSync(napi_env env, napi_callback_info info);
napi_value GetAbilityLabelSync(napi_env env, napi_callback_info info);
napi_value GetLaunchWantForBundleSync(napi_env env, napi_callback_info info);
napi_value GetBundleArchiveInfoSync(napi_env env, napi_callback_info info);
napi_value GetBundleNameByUidSync(napi_env env, napi_callback_info info);
napi_value GetProfileByAbilitySync(napi_env env, napi_callback_info info);
napi_value GetProfileByExAbilitySync(napi_env env, napi_callback_info info);
napi_value GetAppProvisionInfoSync(napi_env env, napi_callback_info info);
napi_value GetSignatureInfoSync(napi_env env, napi_callback_info info);

bool ParseWantWithParameter(napi_env env, napi_value args, OHOS::AAFwk::Want &want);
bool ParseWantListWithParameter(napi_env env, napi_value args, std::vector<OHOS::AAFwk::Want> &wants);
bool IsArray(napi_env env, napi_value value);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_BUNDLE_MANAGER_SYNC_H
