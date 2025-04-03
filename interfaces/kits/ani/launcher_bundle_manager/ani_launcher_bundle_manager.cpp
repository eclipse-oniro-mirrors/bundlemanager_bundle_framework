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

#include <string>

#include "ability_manager_client.h"
#include "ani.h"
#include "app_log_wrapper.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "js_launcher_service.h"
#include "launcher_ability_info.h"
#include "shortcut_info.h"
#include "start_options.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t EMPTY_USER_ID = -500;
constexpr int32_t ANI_CONSTRUCTOR_FIND_NAMESPACE_ERR = 2;
constexpr int32_t ANI_CONSTRUCTOR_BIND_NATIVE_FUNC_ERR = 3;
constexpr int32_t ANI_CONSTRUCTOR_ENV_ERR = 9;

const std::map<int32_t, int32_t> START_SHORTCUT_RES_MAP = { { ERR_OK, ERR_OK },
    { ERR_PERMISSION_DENIED, ERR_BUNDLE_MANAGER_PERMISSION_DENIED },
    { ERR_NOT_SYSTEM_APP, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED } };

constexpr const char* GET_SHORTCUT_INFO_SYNC = "GetShortcutInfoSync";
constexpr const char* PERMISSION_GET_BUNDLE_INFO_PRIVILEGED = "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
constexpr const char* ERROR_EMPTY_WANT = "want in ShortcutInfo cannot be empty";
constexpr const char* ERROR_EMPTY_BUNDLE_NAME = "bundle name is empty";
constexpr const char* PARSE_SHORTCUT_INFO = "parse ShortcutInfo failed";
} // namespace

static void StartShortcutSync([[maybe_unused]] ani_env *env, ani_object aniShortcutInfo)
{
    ShortcutInfo shortcutInfo;
    if (!CommonFunAni::ParseShortcutInfo(env, aniShortcutInfo, shortcutInfo)) {
        APP_LOGE("ParseShortcutInfo error");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARSE_SHORTCUT_INFO);
        return;
    }
    if (shortcutInfo.intents.empty()) {
        APP_LOGW("intents is empty");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, ERROR_EMPTY_WANT);
        return;
    }
    AAFwk::Want want;
    ElementName element;
    element.SetBundleName(shortcutInfo.intents[0].targetBundle);
    element.SetModuleName(shortcutInfo.intents[0].targetModule);
    element.SetAbilityName(shortcutInfo.intents[0].targetClass);
    want.SetElement(element);
    std::for_each(shortcutInfo.intents[0].parameters.begin(), shortcutInfo.intents[0].parameters.end(),
        [&want](const auto& item) { want.SetParam(item.first, item.second); });

    want.SetParam(AAFwk::Want::PARAM_APP_CLONE_INDEX_KEY, shortcutInfo.appIndex);
    auto abilityManagerClient = AAFwk::AbilityManagerClient::GetInstance();
    if (abilityManagerClient == nullptr) {
        APP_LOGI("abilityManagerClient is nullptr");
        return;
    }
    StartOptions startOptions;
    auto result = abilityManagerClient->StartShortcut(want, startOptions);
    auto iter = START_SHORTCUT_RES_MAP.find(result);
    result = iter == START_SHORTCUT_RES_MAP.end() ? ERR_BUNDLE_MANAGER_START_SHORTCUT_FAILED : iter->second;
    if (result != ERR_OK) {
        APP_LOGE("StartShortcut failed, result: %{public}d", result);
        BusinessErrorAni::CreateCommonError(env, CommonFunc::ConvertErrCode(result));
    }
}

static ani_object GetShortcutInfoSync([[maybe_unused]] ani_env *env, ani_string aniBundleName, ani_double aniUserId)
{
    std::string bundleName = CommonFunAni::AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        APP_LOGE("BundleName is empty");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, ERROR_EMPTY_BUNDLE_NAME);
        return nullptr;
    }
    int32_t userId = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("try cast userId failed");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::USER_ID, CommonFunAniNS::TYPE_INT);
        return nullptr;
    }
    if (userId == EMPTY_USER_ID) {
        userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    auto launcherService = JSLauncherService::GetLauncherService();
    if (launcherService == nullptr) {
        APP_LOGE("launcherService is nullptr");
        BusinessErrorAni::ThrowParameterTypeError(
            env, ERROR_BUNDLE_SERVICE_EXCEPTION, GET_SHORTCUT_INFO_SYNC, PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    std::vector<ShortcutInfo> shortcutInfos;
    ErrCode result = launcherService->GetShortcutInfoV9(bundleName, shortcutInfos, userId);
    ErrCode ret = CommonFunc::ConvertErrCode(result);
    if (ret != ERR_OK) {
        APP_LOGE("GetShortcutInfoV9 failed, ret %{public}d", ret);
        BusinessErrorAni::CreateCommonError(
            env, ret, GET_SHORTCUT_INFO_SYNC, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    ani_object arrayShortcutInfos =
        CommonFunAni::ConvertAniArray(env, shortcutInfos, CommonFunAni::ConvertShortcutInfo);
    if (arrayShortcutInfos == nullptr) {
        APP_LOGE("ConvertAniArray failed");
        return nullptr;
    }
    return arrayShortcutInfos;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    APP_LOGI("ANI_Constructor called");
    ani_env* env;
    if (vm == nullptr) {
        APP_LOGE("ANI_Constructor vm is nullptr");
        return static_cast<ani_status>(ANI_CONSTRUCTOR_ENV_ERR);
    }
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        APP_LOGE("Unsupported ANI_VERSION_1");
        return static_cast<ani_status>(ANI_CONSTRUCTOR_ENV_ERR);
    }
    if (env == nullptr) {
        APP_LOGE("ANI_Constructor env is nullptr");
        return static_cast<ani_status>(ANI_CONSTRUCTOR_ENV_ERR);
    }
    static const char* nsName = "L@ohos/bundle/launcherBundleManager/launcherBundleManager;";
    ani_namespace kitNs;
    if (env->FindNamespace(nsName, &kitNs) != ANI_OK) {
        APP_LOGE("Not found nameSpace name: %{public}s", nsName);
        return static_cast<ani_status>(ANI_CONSTRUCTOR_FIND_NAMESPACE_ERR);
    }

    std::array methods = {
        ani_native_function {
            "StartShortcutSync",
            "LbundleManager/ShortcutInfo/ShortcutInfo;:V",
            reinterpret_cast<void*>(StartShortcutSync)
        },
        ani_native_function {
            "GetShortcutInfoSync",
            "Lstd/core/String;D:Lescompat/Array;",
            reinterpret_cast<void*>(GetShortcutInfoSync)
        },
    };

    if (env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size()) != ANI_OK) {
        APP_LOGE("Cannot bind native methods to %{public}s", nsName);
        return static_cast<ani_status>(ANI_CONSTRUCTOR_BIND_NATIVE_FUNC_ERR);
    };

    *result = ANI_VERSION_1;
    APP_LOGI("ANI_Constructor finished");
    return ANI_OK;
}
} // extern "C"
} // namespace AppExecFwk
} // namespace OHOS