/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACE_KITS_JS_SKILL_MANAGER_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACE_KITS_JS_SKILL_MANAGER_H

#include "base_cb_info.h"
#include "bundle_skill/skill_info.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppExecFwk {

struct SkillInfoCallback : public BaseCallbackInfo {
    explicit SkillInfoCallback(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::string moduleName;
    std::string skillName;
    uint32_t flags = 0;
    int32_t userId = 0;
    SkillInfo skillInfo;
};

struct SkillInfosCallback : public BaseCallbackInfo {
    explicit SkillInfosCallback(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    uint32_t flags = 0;
    int32_t userId = 0;
    std::vector<SkillInfo> skillInfos;
};

struct GetSkillInfoCallback : public BaseCallbackInfo {
    explicit GetSkillInfoCallback(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::string bundleName;
    std::string moduleName;
    std::string skillName;
    uint32_t flags = 0;
    int32_t userId = 0;
    SkillInfo skillInfo;
};

struct GetSkillInfosCallback : public BaseCallbackInfo {
    explicit GetSkillInfosCallback(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    std::string bundleName;
    uint32_t flags = 0;
    int32_t userId = 0;
    std::vector<SkillInfo> skillInfos;
};

napi_value GetSkillInfoForSelf(napi_env env, napi_callback_info info);
napi_value GetSkillInfosForSelf(napi_env env, napi_callback_info info);
napi_value GetSkillInfo(napi_env env, napi_callback_info info);
napi_value GetSkillInfos(napi_env env, napi_callback_info info);
napi_value GetAllSkillInfos(napi_env env, napi_callback_info info);
void CreateSkillInfoFlagObject(napi_env env, napi_value value);

}  // namespace AppExecFwk
}  // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACE_KITS_JS_SKILL_MANAGER_H
