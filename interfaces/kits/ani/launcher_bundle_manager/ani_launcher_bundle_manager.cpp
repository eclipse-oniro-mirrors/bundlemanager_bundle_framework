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
#include "ani_common_start_options.h"
#include <ani_signature_builder.h>
#include "app_log_wrapper.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "ipc_skeleton.h"
#include "js_launcher_service.h"
#include "launcher_ability_info.h"
#include "napi_constants.h"
#include "shortcut_info.h"
#include "start_options.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t EMPTY_USER_ID = -500;
constexpr const char* PARSE_SHORTCUT_INFO = "parse ShortcutInfo failed";
constexpr const char* NS_NAME_LAUNCHERMANAGER = "@ohos.bundle.launcherBundleManager.launcherBundleManager";

const std::map<int32_t, int32_t> START_SHORTCUT_RES_MAP = {
    { ERR_OK, ERR_OK },
    { ERR_PERMISSION_DENIED, ERR_BUNDLE_MANAGER_PERMISSION_DENIED },
    { ERR_NOT_SYSTEM_APP, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED }
};
} // namespace

static void AniStartShortcut(ani_env *env, ani_object aniShortcutInfo, ani_object aniStartOptions)
{
    APP_LOGD("ani StartShortcut called");
    ShortcutInfo shortcutInfo;
    if (!CommonFunAni::ParseShortcutInfo(env, aniShortcutInfo, shortcutInfo)) {
        APP_LOGE("parse shortcutInfo failed");
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
    if (aniStartOptions != nullptr) {
        if (!UnwrapStartOptions(env, aniStartOptions, startOptions)) {
            APP_LOGE("ParseStartOptions error");
            BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARSE_START_OPTIONS);
            return;
        }
    }
    ErrCode result = abilityManagerClient->StartShortcut(want, startOptions);
    auto iter = START_SHORTCUT_RES_MAP.find(result);
    result = iter == START_SHORTCUT_RES_MAP.end() ? ERR_BUNDLE_MANAGER_START_SHORTCUT_FAILED : iter->second;
    if (result != ERR_OK) {
        APP_LOGE("StartShortcut failed, result: %{public}d", result);
        BusinessErrorAni::ThrowCommonError(
            env, CommonFunc::ConvertErrCode(result), START_SHORTCUT, Constants::PERMISSION_START_SHORTCUT);
    }
}

static ani_object AniGetShortcutInfo(ani_env *env,
    ani_string aniBundleName, ani_double aniUserId, ani_boolean aniIsSync)
{
    APP_LOGD("ani GetShortcutInfo called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGW("try cast userId falied");
    }
    if (userId == EMPTY_USER_ID) {
        userId = Constants::UNSPECIFIED_USERID;
    }
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    auto launcherService = JSLauncherService::GetLauncherService();
    if (launcherService == nullptr) {
        APP_LOGE("launcherService is nullptr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            isSync ? GET_SHORTCUT_INFO_SYNC : GET_SHORTCUT_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    std::vector<ShortcutInfo> shortcutInfos;
    ErrCode ret = launcherService->GetShortcutInfoV9(bundleName, shortcutInfos, userId);
    if (ret != ERR_OK) {
        APP_LOGE("GetShortcutInfoV9 failed, ret %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            isSync ? GET_SHORTCUT_INFO_SYNC : GET_SHORTCUT_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }
    ani_object shortcutInfosObject =
        CommonFunAni::ConvertAniArray(env, shortcutInfos, CommonFunAni::ConvertShortcutInfo);
    if (shortcutInfosObject == nullptr) {
        APP_LOGE("nullptr shortcutInfosObject");
        return nullptr;
    }
    return shortcutInfosObject;
}

static ani_object AniGetLauncherAbilityInfo(ani_env *env,
    ani_string aniBundleName, ani_double aniUserId, ani_boolean aniIsSync)
{
    APP_LOGD("ani GetLauncherAbilityInfo called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("parse bundleName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    int32_t userId = Constants::UNSPECIFIED_USERID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("try cast userId failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
        return nullptr;
    }
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);

    auto launcherService = JSLauncherService::GetLauncherService();
    if (launcherService == nullptr) {
        APP_LOGE("launcherService is nullptr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            isSync ? GET_LAUNCHER_ABILITY_INFO_SYNC : GET_LAUNCHER_ABILITY_INFO,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    ErrCode ret = ERR_OK;
    if (isSync) {
        ret = launcherService->GetLauncherAbilityInfoSync(bundleName, userId, launcherAbilityInfos);
    } else {
        ret = launcherService->GetLauncherAbilityByBundleName(bundleName, userId, launcherAbilityInfos);
    }
    if (ret != ERR_OK) {
        APP_LOGE("GetLauncherAbilityInfo failed ret:%{public}d, bundleName:%{public}s, userId:%{public}d",
            ret, bundleName.c_str(), userId);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            isSync ? GET_LAUNCHER_ABILITY_INFO_SYNC : GET_LAUNCHER_ABILITY_INFO,
            Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    ani_object launcherAbilityInfosObject = CommonFunAni::ConvertAniArray(
        env, launcherAbilityInfos, CommonFunAni::ConvertLauncherAbilityInfo);
    if (launcherAbilityInfosObject == nullptr) {
        APP_LOGE("nullptr launcherAbilityInfosObject");
    }

    return launcherAbilityInfosObject;
}

static ani_object AniGetAllLauncherAbilityInfo(ani_env *env, ani_double aniUserId)
{
    APP_LOGD("ani GetAllLauncherAbilityInfo called");
    int32_t userId = 0;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("try cast userId failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, USER_ID, TYPE_NUMBER);
        return nullptr;
    }

    auto launcherService = JSLauncherService::GetLauncherService();
    if (launcherService == nullptr) {
        APP_LOGE("launcherService is nullptr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            GET_ALL_LAUNCHER_ABILITY_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    std::vector<LauncherAbilityInfo> launcherAbilityInfos;
    ErrCode ret = launcherService->GetAllLauncherAbility(userId, launcherAbilityInfos);
    if (ret != ERR_OK) {
        APP_LOGE("GetAllLauncherAbility failed ret:%{public}d,userId:%{public}d", ret, userId);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            GET_ALL_LAUNCHER_ABILITY_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        return nullptr;
    }

    ani_object launcherAbilityInfosObject = CommonFunAni::ConvertAniArray(
        env, launcherAbilityInfos, CommonFunAni::ConvertLauncherAbilityInfo);
    if (launcherAbilityInfosObject == nullptr) {
        APP_LOGE("nullptr launcherAbilityInfosObject");
    }

    return launcherAbilityInfosObject;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    APP_LOGI("ANI_Constructor launcherBundleManager called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace nsName = arkts::ani_signature::Builder::BuildNamespace(NS_NAME_LAUNCHERMANAGER);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(nsName.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_LAUNCHERMANAGER, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "startShortcutNative", nullptr, reinterpret_cast<void*>(AniStartShortcut) },
        ani_native_function { "getShortcutInfoNative", nullptr, reinterpret_cast<void*>(AniGetShortcutInfo) },
        ani_native_function { "getLauncherAbilityInfoNative", nullptr,
            reinterpret_cast<void*>(AniGetLauncherAbilityInfo) },
        ani_native_function { "getAllLauncherAbilityInfoNative", nullptr,
            reinterpret_cast<void*>(AniGetAllLauncherAbilityInfo) },
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE("Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_LAUNCHERMANAGER, status);
        return status;
    }

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
} // extern "C"
} // namespace AppExecFwk
} // namespace OHOS