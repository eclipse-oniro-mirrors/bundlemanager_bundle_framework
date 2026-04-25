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

#include "app_log_wrapper.h"
#include "skill_manager.h"

namespace OHOS {
namespace AppExecFwk {
static napi_value SkillManagerExport(napi_env env, napi_value exports)
{
    napi_value skillInfoFlag = nullptr;
    NAPI_CALL(env, napi_create_object(env, &skillInfoFlag));
    CreateSkillInfoFlagObject(env, skillInfoFlag);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getSkillInfoForSelf", GetSkillInfoForSelf),
        DECLARE_NAPI_FUNCTION("getSkillInfosForSelf", GetSkillInfosForSelf),
        DECLARE_NAPI_FUNCTION("getSkillInfo", GetSkillInfo),
        DECLARE_NAPI_FUNCTION("getSkillInfos", GetSkillInfos),
        DECLARE_NAPI_FUNCTION("getAllSkillInfos", GetAllSkillInfos),
        DECLARE_NAPI_PROPERTY("SkillInfoFlag", skillInfoFlag),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    APP_LOGI("init skill manager success");
    return exports;
}

static napi_module skill_manager_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = SkillManagerExport,
    .nm_modname = "bundle.skillManager",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

extern "C" __attribute__((constructor)) void SkillManagerRegister(void)
{
    napi_module_register(&skill_manager_module);
}
} // namespace AppExecFwk
} // namespace OHOS
