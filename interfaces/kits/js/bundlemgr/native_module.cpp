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

    const char *moduleName = "JsBundleMgr";
    BindNativeFunction(*engine, *object, "getAllApplicationInfo", moduleName, JsBundleMgr::GetAllApplicationInfo);
    BindNativeFunction(*engine, *object, "getApplicationInfo", moduleName, JsBundleMgr::GetApplicationInfo);
    BindNativeFunction(*engine, *object, "getBundleArchiveInfo", moduleName, JsBundleMgr::GetBundleArchiveInfo);
    BindNativeFunction(*engine, *object, "getLaunchWantForBundle", moduleName, JsBundleMgr::GetLaunchWantForBundle);
    BindNativeFunction(*engine, *object, "isAbilityEnabled", moduleName, JsBundleMgr::IsAbilityEnabled);
    BindNativeFunction(*engine, *object, "isApplicationEnabled", moduleName, JsBundleMgr::IsApplicationEnabled);
    BindNativeFunction(*engine, *object, "getAbilityIcon", moduleName, JsBundleMgr::GetAbilityIcon);
    BindNativeFunction(*engine, *object, "getProfileByAbility", moduleName, JsBundleMgr::GetProfileByAbility);
    BindNativeFunction(*engine, *object, "getProfileByExtensionAbility", moduleName,
        JsBundleMgr::GetProfileByExtensionAbility);
    BindNativeFunction(*engine, *object, "getBundleInfo", moduleName, JsBundleMgr::GetBundleInfo);
    BindNativeFunction(*engine, *object, "getNameForUid", moduleName, JsBundleMgr::GetNameForUid);
    BindNativeFunction(*engine, *object, "getAbilityInfo", moduleName, JsBundleMgr::GetAbilityInfo);
    BindNativeFunction(*engine, *object, "getAbilityLabel", moduleName, JsBundleMgr::GetAbilityLabel);
    BindNativeFunction(*engine, *object, "setApplicationEnabled", moduleName, JsBundleMgr::SetApplicationEnabled);
    BindNativeFunction(*engine, *object, "queryAbilityByWant", moduleName, JsBundleMgr::QueryAbilityInfos);
    BindNativeFunction(*engine, *object, "getAllBundleInfo", moduleName, JsBundleMgr::GetAllBundleInfo);
    BindNativeFunction(*engine, *object, "queryExtensionAbilityInfos", moduleName,
        JsBundleMgr::QueryExtensionAbilityInfos);
    BindNativeFunction(*engine, *object, "getBundleInstaller", moduleName, JsBundleMgr::GetBundleInstaller);
    return exports;
}

static napi_value Init(napi_env env, napi_value exports)
{
    napi_value nAbilityType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nAbilityType));
    CreateAbilityTypeObject(env, nAbilityType);

    napi_value nAbilitySubType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nAbilitySubType));
    CreateAbilitySubTypeObject(env, nAbilitySubType);

    napi_value nDisplayOrientation = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nDisplayOrientation));
    CreateDisplayOrientationObject(env, nDisplayOrientation);

    napi_value nLaunchMode = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nLaunchMode));
    CreateLaunchModeObject(env, nLaunchMode);

    napi_value nModuleUpdateFlag = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nModuleUpdateFlag));
    CreateModuleUpdateFlagObject(env, nModuleUpdateFlag);

    napi_value nColorMode = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nColorMode));
    CreateColorModeObject(env, nColorMode);

    napi_value nGrantStatus = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nGrantStatus));
    CreateGrantStatusObject(env, nGrantStatus);

    napi_value nModuleRemoveFlag = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nModuleRemoveFlag));
    CreateModuleRemoveFlagObject(env, nModuleRemoveFlag);

    napi_value nSignatureCompareResult = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nSignatureCompareResult));
    CreateSignatureCompareResultObject(env, nSignatureCompareResult);

    napi_value nShortcutExistence = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nShortcutExistence));
    CreateShortcutExistenceObject(env, nShortcutExistence);

    napi_value nQueryShortCutFlag = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nQueryShortCutFlag));
    CreateQueryShortCutFlagObject(env, nShortcutExistence);

    napi_value nExtensionAbilityType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nExtensionAbilityType));
    CreateExtensionAbilityTypeObject(env, nExtensionAbilityType);

    napi_value nExtensionFlag = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nExtensionFlag));
    CreateExtensionFlagObject(env, nExtensionFlag);

    napi_value nUpgradeFlag = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nUpgradeFlag));
    CreateUpgradeFlagObject(env, nUpgradeFlag);

    napi_value nBundleFlag = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nBundleFlag));
    CreateBundleFlagObject(env, nBundleFlag);

    napi_value nInstallErrorCode = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nInstallErrorCode));
    CreateInstallErrorCodeObject(env, nInstallErrorCode);

    napi_value nSupportWindowMode = nullptr;
    NAPI_CALL(env, napi_create_object(env, &nSupportWindowMode));
    CreateSupportWindowModesObject(env, nSupportWindowMode);
    /*
     * Propertise define
     */
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getApplicationInfos", GetApplicationInfos),
        DECLARE_NAPI_FUNCTION("getApplicationInfoSync", GetApplicationInfoSync),
        DECLARE_NAPI_FUNCTION("getBundleInfos", GetBundleInfos),
        DECLARE_NAPI_FUNCTION("getBundleInfoSync", GetBundleInfoSync),
        DECLARE_NAPI_FUNCTION("getBundlePackInfo", GetBundlePackInfo),
        DECLARE_NAPI_FUNCTION("getPermissionDef", GetPermissionDef),
        DECLARE_NAPI_FUNCTION("getDispatcherVersion", GetDispatcherVersion),
        DECLARE_NAPI_FUNCTION("cleanBundleCacheFiles", ClearBundleCache),
        DECLARE_NAPI_FUNCTION("setAbilityEnabled", SetAbilityEnabled),
        DECLARE_NAPI_FUNCTION("isModuleRemovable", IsModuleRemovable),
        DECLARE_NAPI_FUNCTION("setModuleUpgradeFlag", SetModuleUpgradeFlag),
        DECLARE_NAPI_FUNCTION("setDisposedStatus", SetDisposedStatus),
        DECLARE_NAPI_FUNCTION("getDisposedStatus", GetDisposedStatus),
        DECLARE_NAPI_PROPERTY("AbilityType", nAbilityType),
        DECLARE_NAPI_PROPERTY("AbilitySubType", nAbilitySubType),
        DECLARE_NAPI_PROPERTY("DisplayOrientation", nDisplayOrientation),
        DECLARE_NAPI_PROPERTY("LaunchMode", nLaunchMode),
        DECLARE_NAPI_PROPERTY("ModuleUpdateFlag", nModuleUpdateFlag),
        DECLARE_NAPI_PROPERTY("ColorMode", nColorMode),
        DECLARE_NAPI_PROPERTY("GrantStatus", nGrantStatus),
        DECLARE_NAPI_PROPERTY("ModuleRemoveFlag", nModuleRemoveFlag),
        DECLARE_NAPI_PROPERTY("SignatureCompareResult", nSignatureCompareResult),
        DECLARE_NAPI_PROPERTY("ShortcutExistence", nShortcutExistence),
        DECLARE_NAPI_PROPERTY("QueryShortCutFlag", nQueryShortCutFlag),
        DECLARE_NAPI_PROPERTY("InstallErrorCode", nInstallErrorCode),
        DECLARE_NAPI_PROPERTY("SupportWindowMode", nSupportWindowMode),
        DECLARE_NAPI_PROPERTY("ExtensionAbilityType", nExtensionAbilityType),
        DECLARE_NAPI_PROPERTY("BundleFlag", nBundleFlag),
        DECLARE_NAPI_PROPERTY("ExtensionFlag", nExtensionFlag),
        DECLARE_NAPI_PROPERTY("UpgradeFlag", nUpgradeFlag)
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