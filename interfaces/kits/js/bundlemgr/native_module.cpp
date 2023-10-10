/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include <pthread.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "bundle_mgr.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AbilityRuntime;
EXTERN_C_START
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports)
{
    napi_value nInstallErrorCode = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nInstallErrorCode));
    CreateInstallErrorCodeObject(env, nInstallErrorCode);

    napi_value nAbilityType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nAbilityType));
    nAbilityType = CreateAbilityTypeObject(env);

    napi_value nAbilitySubType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nAbilitySubType));
    nAbilitySubType = CreateAbilitySubTypeObject(env);

    napi_value nDisplayOrientation = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nDisplayOrientation));
    nDisplayOrientation = CreateDisplayOrientationObject(env);

    napi_value nLaunchMode = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nLaunchMode));
    nLaunchMode = CreateLaunchModeObject(env);

    napi_value nColorMode = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nColorMode));
    nColorMode = CreateColorModeObject(env);

    napi_value nGrantStatus = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nGrantStatus));
    nGrantStatus = CreateGrantStatusObject(env);

    napi_value nModuleRemoveFlag = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nModuleRemoveFlag));
    nModuleRemoveFlag = CreateModuleRemoveFlagObject(env);

    napi_value nSignatureCompareResult = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nSignatureCompareResult));
    nSignatureCompareResult = CreateSignatureCompareResultObject(env);

    napi_value nShortcutExistence = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nShortcutExistence));
    nShortcutExistence = CreateShortcutExistenceObject(env);

    napi_value nQueryShortCutFlag = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nQueryShortCutFlag));
    nQueryShortCutFlag = CreateQueryShortCutFlagObject(env);

    napi_value nBundleFlag = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nBundleFlag));
    nBundleFlag = CreateBundleFlagObject(env);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getApplicationInfos", GetApplicationInfos),
        DECLARE_NAPI_FUNCTION("getBundleInfos", GetBundleInfos),
        DECLARE_NAPI_FUNCTION("getBundleInfo", GetBundleInfo),
        DECLARE_NAPI_FUNCTION("getNameForUid", GetNameForUid),
        DECLARE_NAPI_FUNCTION("getAbilityInfo", GetAbilityInfo),
        DECLARE_NAPI_FUNCTION("getAbilityLabel", GetAbilityLabel),
        DECLARE_NAPI_FUNCTION("cleanBundleCacheFiles", ClearBundleCache),
        DECLARE_NAPI_FUNCTION("getAllBundleInfo", GetBundleInfos),
        DECLARE_NAPI_FUNCTION("getPermissionDef", GetPermissionDef),
        DECLARE_NAPI_FUNCTION("getLaunchWantForBundle", GetLaunchWantForBundle),
        DECLARE_NAPI_FUNCTION("isAbilityEnabled", IsAbilityEnabled),
        DECLARE_NAPI_FUNCTION("isApplicationEnabled", IsApplicationEnabled),
        DECLARE_NAPI_FUNCTION("queryAbilityByWant", QueryAbilityInfos),
        DECLARE_NAPI_FUNCTION("getBundleArchiveInfo", GetBundleArchiveInfo),
        DECLARE_NAPI_FUNCTION("getAbilityIcon", GetAbilityIcon),
        DECLARE_NAPI_FUNCTION("getAllApplicationInfo", GetAllApplicationInfo),
        DECLARE_NAPI_FUNCTION("getApplicationInfo", GetApplicationInfo),
        DECLARE_NAPI_FUNCTION("setAbilityEnabled", SetAbilityEnabled),
        DECLARE_NAPI_FUNCTION("setApplicationEnabled", SetApplicationEnabled),
        DECLARE_NAPI_FUNCTION("getBundleInstaller", GetBundleInstaller),
        DECLARE_NAPI_PROPERTY("InstallErrorCode", nInstallErrorCode),
        DECLARE_NAPI_PROPERTY("AbilityType", nAbilityType),
        DECLARE_NAPI_PROPERTY("AbilitySubType", nAbilitySubType),
        DECLARE_NAPI_PROPERTY("DisplayOrientation", nDisplayOrientation),
        DECLARE_NAPI_PROPERTY("LaunchMode", nLaunchMode),
        DECLARE_NAPI_PROPERTY("ColorMode", nColorMode),
        DECLARE_NAPI_PROPERTY("GrantStatus", nGrantStatus),
        DECLARE_NAPI_PROPERTY("ModuleRemoveFlag", nModuleRemoveFlag),
        DECLARE_NAPI_PROPERTY("SignatureCompareResult", nSignatureCompareResult),
        DECLARE_NAPI_PROPERTY("ShortcutExistence", nShortcutExistence),
        DECLARE_NAPI_PROPERTY("QueryShortCutFlag", nQueryShortCutFlag),
        DECLARE_NAPI_PROPERTY("BundleFlag", nBundleFlag)
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));

    napi_value m_classBundleInstaller;
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("install", Install),
        DECLARE_NAPI_FUNCTION("recover", Recover),
        DECLARE_NAPI_FUNCTION("uninstall", Uninstall),
    };
    NAPI_CALL(env,
        napi_define_class(env,
            "BundleInstaller",
            NAPI_AUTO_LENGTH,
            BundleInstallerConstructor,
            nullptr,
            sizeof(properties) / sizeof(*properties),
            properties,
            &m_classBundleInstaller));
    napi_create_reference(env, m_classBundleInstaller, 1, &g_classBundleInstaller);
    APP_LOGI("Init end");
    return exports;
}
EXTERN_C_END

/*
 * Module define
 */
static napi_module _module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "bundle",
    .nm_priv = ((void *)0),
    .reserved = {0}
};
/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&_module);
}
}  // namespace AppExecFwk
}  // namespace OHOS