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
#include <ani_signature_builder.h>

#include "ani_common_want.h"
#include "app_control_interface.h"
#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AAFwk;
namespace {
constexpr const char* NS_NAME_APPCONTROL = "@ohos.bundle.appControl.appControl";
} // namespace

static void SetDisposedStatusSync(ani_env* env, ani_string aniAppId, ani_object aniWant)
{
    std::string appId = CommonFunAni::AniStrToString(env, aniAppId);
    if (appId.empty()) {
        APP_LOGE("AppId is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPID,
            SET_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
        return;
    }
    Want want;
    if (!CommonFunAni::ParseWantWithoutVerification(env, aniWant, want)) {
        APP_LOGE("want invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, DISPOSED_WANT, TYPE_WANT);
        return;
    }

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            SET_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
        return;
    }

    ErrCode ret = appControlProxy->SetDisposedStatus(appId, want);
    if (ret != ERR_OK) {
        APP_LOGE("SetDisposedStatusSync failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            SET_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
    }
}

static ani_object GetDisposedStatusSync(ani_env* env, ani_string aniAppId)
{
    std::string appId = CommonFunAni::AniStrToString(env, aniAppId);
    if (appId.empty()) {
        APP_LOGE("AppId is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPID,
            GET_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
        return nullptr;
    }

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            GET_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
        return nullptr;
    }

    Want want;
    ErrCode ret = appControlProxy->GetDisposedStatus(appId, want);
    if (ret != ERR_OK) {
        APP_LOGE("GetDisposedStatusSync failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            GET_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
        return nullptr;
    }

    return WrapWant(env, want);
}

static void DeleteDisposedStatusSync(ani_env* env, ani_string aniAppId, ani_double aniAppIndex)
{
    std::string appId = CommonFunAni::AniStrToString(env, aniAppId);
    if (appId.empty()) {
        APP_LOGE("AppId is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPID,
            DELETE_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
        return;
    }
    int32_t appIndex = Constants::MAIN_APP_INDEX;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGW("parse appIndex falied");
    }

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            DELETE_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
        return;
    }

    ErrCode ret = ERR_OK;
    if (appIndex == Constants::MAIN_APP_INDEX) {
        ret = appControlProxy->DeleteDisposedStatus(appId);
    } else {
        ret = appControlProxy->DeleteDisposedRuleForCloneApp(appId, appIndex);
    }
    if (ret != ERR_OK) {
        APP_LOGE("DeleteDisposedStatusSync failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            DELETE_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
    }
}

static ani_object GetDisposedRule(ani_env* env, ani_string aniAppId, ani_double aniAppIndex)
{
    std::string appId = CommonFunAni::AniStrToString(env, aniAppId);
    if (appId.empty()) {
        APP_LOGE("AppId is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPID, GET_DISPOSED_STATUS, "");
        return nullptr;
    }
    int32_t appIndex = Constants::MAIN_APP_INDEX;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGW("parse appIndex falied");
    }

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_DISPOSED_STATUS, "");
        return nullptr;
    }

    DisposedRule disposedRule;
    ErrCode ret = ERR_OK;
    if (appIndex == Constants::MAIN_APP_INDEX) {
        ret = appControlProxy->GetDisposedRule(appId, disposedRule);
    } else {
        ret = appControlProxy->GetDisposedRuleForCloneApp(appId, disposedRule, appIndex);
    }
    if (ret != ERR_OK) {
        APP_LOGE("GetDisposedRule failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            GET_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
        return nullptr;
    }

    return CommonFunAni::ConvertDisposedRule(env, disposedRule);
}

static void SetDisposedRule(ani_env* env, ani_string aniAppId, ani_object aniRule, ani_double aniAppIndex)
{
    std::string appId = CommonFunAni::AniStrToString(env, aniAppId);
    if (appId.empty()) {
        APP_LOGE("AppId is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPID, SET_DISPOSED_STATUS, "");
        return;
    }
    DisposedRule rule;
    if (!CommonFunAni::ParseDisposedRule(env, aniRule, rule)) {
        APP_LOGE("rule invalid!");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, DISPOSED_RULE, DISPOSED_RULE_TYPE);
        return;
    }
    int32_t appIndex = Constants::MAIN_APP_INDEX;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGW("parse appIndex falied");
    }

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, SET_DISPOSED_STATUS, "");
        return;
    }

    ErrCode ret = ERR_OK;
    if (appIndex == Constants::MAIN_APP_INDEX) {
        ret = appControlProxy->SetDisposedRule(appId, rule);
    } else {
        ret = appControlProxy->SetDisposedRuleForCloneApp(appId, rule, appIndex);
    }
    if (ret != ERR_OK) {
        APP_LOGE("SetDisposedRule failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            SET_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
    }
}

static void SetUninstallDisposedRule(ani_env* env,
    ani_string aniAppIdentifier, ani_object aniRule, ani_double aniAppIndex)
{
    std::string appIdentifier = CommonFunAni::AniStrToString(env, aniAppIdentifier);
    if (appIdentifier.empty()) {
        APP_LOGE("AppIdentifier is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPIDENTIFIER, SET_UNINSTALL_DISPOSED_RULE, "");
        return;
    }
    UninstallDisposedRule rule;
    if (!CommonFunAni::ParseUninstallDisposedRule(env, aniRule, rule)) {
        APP_LOGE("rule invalid!");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR,
            UNINSTALL_DISPOSED_RULE, UNINSTALL_DISPOSED_RULE_TYPE);
        return;
    }
    int32_t appIndex = Constants::MAIN_APP_INDEX;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGW("parse appIndex falied");
    }
    int32_t userId = Constants::UNSPECIFIED_USERID;

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, SET_UNINSTALL_DISPOSED_RULE, "");
        return;
    }

    ErrCode ret = appControlProxy->SetUninstallDisposedRule(appIdentifier, rule, appIndex, userId);
    if (ret != ERR_OK) {
        APP_LOGE("SetUninstallDisposedRule failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            SET_UNINSTALL_DISPOSED_RULE, PERMISSION_DISPOSED_STATUS);
    }
}

static ani_object GetUninstallDisposedRule(ani_env* env, ani_string aniAppIdentifier, ani_double aniAppIndex)
{
    std::string appIdentifier = CommonFunAni::AniStrToString(env, aniAppIdentifier);
    if (appIdentifier.empty()) {
        APP_LOGE("AppIdentifier is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPIDENTIFIER, GET_UNINSTALL_DISPOSED_RULE, "");
        return nullptr;
    }
    int32_t appIndex = Constants::MAIN_APP_INDEX;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGW("parse appIndex falied");
    }
    int32_t userId = Constants::UNSPECIFIED_USERID;

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_UNINSTALL_DISPOSED_RULE, "");
        return nullptr;
    }

    UninstallDisposedRule uninstallDisposedRule;
    ErrCode ret = appControlProxy->GetUninstallDisposedRule(appIdentifier, appIndex, userId, uninstallDisposedRule);
    if (ret != ERR_OK) {
        APP_LOGE("GetUninstallDisposedRule failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            GET_UNINSTALL_DISPOSED_RULE, PERMISSION_DISPOSED_STATUS);
        return nullptr;
    }

    return CommonFunAni::ConvertUninstallDisposedRule(env, uninstallDisposedRule);
}

static void DeleteUninstallDisposedRule(ani_env* env, ani_string aniAppIdentifier, ani_double aniAppIndex)
{
    std::string appIdentifier = CommonFunAni::AniStrToString(env, aniAppIdentifier);
    if (appIdentifier.empty()) {
        APP_LOGE("AppIdentifier is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPIDENTIFIER, DELETE_UNINSTALL_DISPOSED_RULE, "");
        return;
    }
    int32_t appIndex = Constants::MAIN_APP_INDEX;
    if (!CommonFunAni::TryCastDoubleTo(aniAppIndex, &appIndex)) {
        APP_LOGW("parse appIndex falied");
    }
    int32_t userId = Constants::UNSPECIFIED_USERID;

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("AppControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, DELETE_UNINSTALL_DISPOSED_RULE, "");
        return;
    }

    ErrCode ret = appControlProxy->DeleteUninstallDisposedRule(appIdentifier, appIndex, userId);
    if (ret != ERR_OK) {
        APP_LOGE("DeleteUninstallDisposedRule failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            DELETE_UNINSTALL_DISPOSED_RULE, PERMISSION_DISPOSED_STATUS);
    }
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor appControl called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace freeInstallNS =
        arkts::ani_signature::Builder::BuildNamespace(NS_NAME_APPCONTROL);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(freeInstallNS.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_APPCONTROL, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "setDisposedStatusSync", nullptr, reinterpret_cast<void*>(SetDisposedStatusSync) },
        ani_native_function { "getDisposedStatusSync", nullptr, reinterpret_cast<void*>(GetDisposedStatusSync) },
        ani_native_function { "deleteDisposedStatusSyncNative", nullptr,
            reinterpret_cast<void*>(DeleteDisposedStatusSync) },
        ani_native_function { "getDisposedRuleNative", nullptr, reinterpret_cast<void*>(GetDisposedRule) },
        ani_native_function { "setDisposedRuleNative", nullptr, reinterpret_cast<void*>(SetDisposedRule) },
        ani_native_function { "setUninstallDisposedRuleNative", nullptr,
            reinterpret_cast<void*>(SetUninstallDisposedRule) },
        ani_native_function { "getUninstallDisposedRuleNative", nullptr,
            reinterpret_cast<void*>(GetUninstallDisposedRule) },
        ani_native_function { "deleteUninstallDisposedRuleNative", nullptr,
            reinterpret_cast<void*>(DeleteUninstallDisposedRule) }
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE("Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_APPCONTROL, status);
        return status;
    }

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // AppExecFwk
} // OHOS