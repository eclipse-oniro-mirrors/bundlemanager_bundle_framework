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
static NativeValue* JsBundleMgrInit(NativeEngine* engine, NativeValue* exports)
{
    APP_LOGD("JsBundleMgrInit is called");
    if (engine == nullptr || exports == nullptr) {
        APP_LOGE("Invalid input parameters");
        return nullptr;
    }

    NativeObject* object = ConvertNativeValueTo<NativeObject>(exports);
    if (object == nullptr) {
        APP_LOGE("object is nullptr");
        return nullptr;
    }

    std::unique_ptr<JsBundleMgr> jsBundleMgr = std::make_unique<JsBundleMgr>();
    object->SetNativePointer(jsBundleMgr.release(), JsBundleMgr::Finalizer, nullptr);
    napi_env env = reinterpret_cast<napi_env>(engine);
    object->SetProperty("AbilityType", reinterpret_cast<NativeValue*>(CreateAbilityTypeObject(env)));
    object->SetProperty("AbilitySubType", reinterpret_cast<NativeValue*>(CreateAbilitySubTypeObject(env)));
    object->SetProperty("DisplayOrientation", reinterpret_cast<NativeValue*>(CreateDisplayOrientationObject(env)));
    object->SetProperty("LaunchMode", reinterpret_cast<NativeValue*>(CreateLaunchModeObject(env)));
    object->SetProperty("ColorMode", reinterpret_cast<NativeValue*>(CreateColorModeObject(env)));
    object->SetProperty("GrantStatus", reinterpret_cast<NativeValue*>(CreateGrantStatusObject(env)));
    object->SetProperty("ModuleRemoveFlag", reinterpret_cast<NativeValue*>(CreateModuleRemoveFlagObject(env)));
    object->SetProperty("SignatureCompareResult", reinterpret_cast<NativeValue*>(CreateSignatureCompareResultObject(env)));
    object->SetProperty("ShortcutExistence", reinterpret_cast<NativeValue*>(CreateShortcutExistenceObject(env)));
    object->SetProperty("QueryShortCutFlag", reinterpret_cast<NativeValue*>(CreateQueryShortCutFlagObject(env)));
    object->SetProperty("InstallErrorCode", reinterpret_cast<NativeValue*>(CreateInstallErrorCodeObject(env)));
    object->SetProperty("BundleFlag", reinterpret_cast<NativeValue*>(CreateBundleFlagObject(env)));

    const char *moduleName = "JsBundleMgr";
    BindNativeFunction(*engine, *object, "getAllApplicationInfo", moduleName, JsBundleMgr::GetAllApplicationInfo);
    BindNativeFunction(*engine, *object, "getApplicationInfo", moduleName, JsBundleMgr::GetApplicationInfo);
    BindNativeFunction(*engine, *object, "getBundleArchiveInfo", moduleName, JsBundleMgr::GetBundleArchiveInfo);
    BindNativeFunction(*engine, *object, "getLaunchWantForBundle", moduleName, JsBundleMgr::GetLaunchWantForBundle);
    BindNativeFunction(*engine, *object, "isAbilityEnabled", moduleName, JsBundleMgr::IsAbilityEnabled);
    BindNativeFunction(*engine, *object, "isApplicationEnabled", moduleName, JsBundleMgr::IsApplicationEnabled);
    BindNativeFunction(*engine, *object, "getAbilityIcon", moduleName, JsBundleMgr::GetAbilityIcon);
    BindNativeFunction(*engine, *object, "getBundleInfo", moduleName, JsBundleMgr::GetBundleInfo);
    BindNativeFunction(*engine, *object, "getNameForUid", moduleName, JsBundleMgr::GetNameForUid);
    BindNativeFunction(*engine, *object, "getAbilityInfo", moduleName, JsBundleMgr::GetAbilityInfo);
    BindNativeFunction(*engine, *object, "getAbilityLabel", moduleName, JsBundleMgr::GetAbilityLabel);
    BindNativeFunction(*engine, *object, "setAbilityEnabled", moduleName, JsBundleMgr::SetAbilityEnabled);
    BindNativeFunction(*engine, *object, "setApplicationEnabled", moduleName, JsBundleMgr::SetApplicationEnabled);
    BindNativeFunction(*engine, *object, "queryAbilityByWant", moduleName, JsBundleMgr::QueryAbilityInfos);
    BindNativeFunction(*engine, *object, "getAllBundleInfo", moduleName, JsBundleMgr::GetAllBundleInfo);
    BindNativeFunction(*engine, *object, "getPermissionDef", moduleName, JsBundleMgr::GetPermissionDef);
    BindNativeFunction(*engine, *object, "getBundleInstaller", moduleName, JsBundleMgr::GetBundleInstaller);
    return exports;
}

static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getApplicationInfos", GetApplicationInfos),
        DECLARE_NAPI_FUNCTION("getBundleInfos", GetBundleInfos),
        DECLARE_NAPI_FUNCTION("cleanBundleCacheFiles", ClearBundleCache),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));

    APP_LOGI("Init end");
    return reinterpret_cast<napi_value>(JsBundleMgrInit(reinterpret_cast<NativeEngine*>(env),
        reinterpret_cast<NativeValue*>(exports)));
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