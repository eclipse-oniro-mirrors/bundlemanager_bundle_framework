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

#include "ani_app_control_common.h"
#include "ani_common_want.h"
#include "app_control_interface.h"
#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "ipc_skeleton.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AAFwk;
namespace {
constexpr const char* NS_NAME_APPCONTROL = "@ohos.bundle.appControl.appControl";
constexpr const char* PROPERTYNAME_APPID = "appId";
constexpr const char* PROPERTYNAME_APPINDEX = "appIndex";
constexpr const char* PROPERTYNAME_DISPOSEDRULE = "disposedRule";
constexpr const char* PARAM_LENGTH_ERROR = "parameter length invalid";
constexpr uint32_t MAX_VECTOR_NUM = 1000;
} // namespace

static void AniSetDisposedStatus(ani_env* env, ani_string aniAppId, ani_object aniWant, ani_boolean aniIsSync)
{
    APP_LOGD("ani SetDisposedStatus called");
    std::string appId;
    if (!CommonFunAni::ParseString(env, aniAppId, appId)) {
        APP_LOGE("appId %{public}s invalid", appId.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
        return;
    }
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (appId.empty()) {
        APP_LOGE("appId is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPID,
            isSync ? SET_DISPOSED_STATUS_SYNC : SET_DISPOSED_STATUS,
            isSync ? "" : PERMISSION_DISPOSED_STATUS);
        return;
    }
    Want want;
    if (!AniAppControlCommon::ParseWantWithoutVerification(env, aniWant, want)) {
        APP_LOGE("want invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, DISPOSED_WANT, TYPE_WANT);
        return;
    }

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("appControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            isSync ? SET_DISPOSED_STATUS_SYNC : SET_DISPOSED_STATUS,
            isSync ? "" : PERMISSION_DISPOSED_STATUS);
        return;
    }

    ErrCode ret = appControlProxy->SetDisposedStatus(appId, want);
    if (ret != ERR_OK) {
        APP_LOGE("SetDisposedStatus failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            isSync ? SET_DISPOSED_STATUS_SYNC : SET_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
    }
}

static ani_object AniGetDisposedStatus(ani_env* env, ani_string aniAppId, ani_boolean aniIsSync)
{
    APP_LOGD("ani GetDisposedStatus called");
    std::string appId;
    if (!CommonFunAni::ParseString(env, aniAppId, appId)) {
        APP_LOGE("appId %{public}s invalid", appId.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
        return nullptr;
    }
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (appId.empty()) {
        APP_LOGE("appId is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPID,
            isSync ? GET_DISPOSED_STATUS_SYNC : GET_DISPOSED_STATUS,
            isSync ? "" : PERMISSION_DISPOSED_APP_STATUS);
        return nullptr;
    }

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("appControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            isSync ? GET_DISPOSED_STATUS_SYNC : GET_DISPOSED_STATUS,
            isSync ? "" : PERMISSION_DISPOSED_APP_STATUS);
        return nullptr;
    }

    Want want;
    ErrCode ret = appControlProxy->GetDisposedStatus(appId, want);
    if (ret != ERR_OK) {
        APP_LOGE("GetDisposedStatusSync failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            isSync ? GET_DISPOSED_STATUS_SYNC : GET_DISPOSED_STATUS, PERMISSION_DISPOSED_APP_STATUS);
        return nullptr;
    }

    return CommonFunAni::ConvertWantInfo(env, want);
}

static void AniDeleteDisposedStatus(ani_env* env, ani_string aniAppId, ani_int aniAppIndex, ani_boolean aniIsSync)
{
    APP_LOGD("ani DeleteDisposedStatus called");
    std::string appId;
    if (!CommonFunAni::ParseString(env, aniAppId, appId)) {
        APP_LOGE("appId %{public}s invalid", appId.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
        return;
    }
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    if (appId.empty()) {
        APP_LOGE("appId is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPID,
            isSync ? DELETE_DISPOSED_STATUS_SYNC : DELETE_DISPOSED_STATUS,
            isSync ? "" : PERMISSION_DISPOSED_STATUS);
        return;
    }

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("appControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
            isSync ? DELETE_DISPOSED_STATUS_SYNC : DELETE_DISPOSED_STATUS,
            isSync ? "" : PERMISSION_DISPOSED_STATUS);
        return;
    }

    ErrCode ret = ERR_OK;
    if (aniAppIndex == Constants::MAIN_APP_INDEX) {
        ret = appControlProxy->DeleteDisposedStatus(appId);
    } else {
        ret = appControlProxy->DeleteDisposedRuleForCloneApp(appId, aniAppIndex);
    }
    if (ret != ERR_OK) {
        APP_LOGE("DeleteDisposedStatusSync failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            isSync ? DELETE_DISPOSED_STATUS_SYNC : DELETE_DISPOSED_STATUS, PERMISSION_DISPOSED_STATUS);
    }
}

static ani_object AniGetDisposedRule(ani_env* env, ani_string aniAppId, ani_int aniAppIndex)
{
    APP_LOGD("ani GetDisposedRule called");
    std::string appId;
    if (!CommonFunAni::ParseString(env, aniAppId, appId)) {
        APP_LOGE("appId %{public}s invalid", appId.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
        return nullptr;
    }
    if (appId.empty()) {
        APP_LOGE("appId is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPID, GET_DISPOSED_RULE, "");
        return nullptr;
    }

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("appControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_DISPOSED_RULE, "");
        return nullptr;
    }

    DisposedRule disposedRule;
    ErrCode ret = ERR_OK;
    if (aniAppIndex == Constants::MAIN_APP_INDEX) {
        ret = appControlProxy->GetDisposedRule(appId, disposedRule);
    } else {
        ret = appControlProxy->GetDisposedRuleForCloneApp(appId, disposedRule, aniAppIndex);
    }
    if (ret != ERR_OK) {
        APP_LOGE("GetDisposedRule failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            GET_DISPOSED_RULE, PERMISSION_DISPOSED_APP_STATUS);
        return nullptr;
    }

    return AniAppControlCommon::ConvertDisposedRule(env, disposedRule);
}

static ani_object AniGetAllDisposedRules(ani_env* env)
{
    APP_LOGD("ani GetAllDisposedRules called");
    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("appControlProxy is null");
        BusinessErrorAni::ThrowCommonNewError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, GET_ALL_DISPOSED_RULES, "");
        return nullptr;
    }
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    ErrCode ret = ERR_OK;
    ret = appControlProxy->GetDisposedRules(userId, disposedRuleConfigurations);
    if (ret != ERR_OK) {
        APP_LOGE("GetAllDisposedRules failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonNewError(env, CommonFunc::ConvertErrCode(ret),
            GET_ALL_DISPOSED_RULES, PERMISSION_DISPOSED_APP_STATUS);
        return nullptr;
    }

    return CommonFunAni::ConvertAniArray(
        env, disposedRuleConfigurations, AniAppControlCommon::ConvertDisposedRuleConfiguration);
}

static ani_object AniGetDisposedRulesBySetter(ani_env* env, ani_string aniBundleName)
{
    APP_LOGD("ani GetDisposedRulesBySetter called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("appControlProxy is null");
        BusinessErrorAni::ThrowCommonNewError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, GET_ALL_DISPOSED_RULES, "");
        return nullptr;
    }
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    ErrCode ret = ERR_OK;
    ret = appControlProxy->GetDisposedRulesBySetter(bundleName, Constants::MAIN_APP_INDEX,
        userId, disposedRuleConfigurations);
    if (ret != ERR_OK) {
        APP_LOGE("GetDisposedRulesBySetter failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonNewError(env, CommonFunc::ConvertErrCode(ret),
            GET_ALL_DISPOSED_RULES, PERMISSION_DISPOSED_APP_STATUS);
        return nullptr;
    }

    return CommonFunAni::ConvertAniArray(
        env, disposedRuleConfigurations, AniAppControlCommon::ConvertDisposedRuleConfiguration);
}

static void AniSetDisposedRule(ani_env* env, ani_string aniAppId, ani_object aniRule, ani_int aniAppIndex)
{
    APP_LOGD("ani SetDisposedRule called");
    std::string appId;
    if (!CommonFunAni::ParseString(env, aniAppId, appId)) {
        APP_LOGE("appId %{public}s invalid", appId.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
        return;
    }
    if (appId.empty()) {
        APP_LOGE("appId is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPID, SET_DISPOSED_RULE, "");
        return;
    }
    DisposedRule rule;
    if (!AniAppControlCommon::ParseDisposedRule(env, aniRule, rule)) {
        APP_LOGE("rule invalid!");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, DISPOSED_RULE, DISPOSED_RULE_TYPE);
        return;
    }

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("appControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, SET_DISPOSED_RULE, "");
        return;
    }

    ErrCode ret = ERR_OK;
    if (aniAppIndex == Constants::MAIN_APP_INDEX) {
        ret = appControlProxy->SetDisposedRule(appId, rule);
    } else {
        ret = appControlProxy->SetDisposedRuleForCloneApp(appId, rule, aniAppIndex);
    }
    if (ret != ERR_OK) {
        APP_LOGE("SetDisposedRule failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            SET_DISPOSED_RULE, PERMISSION_DISPOSED_STATUS);
    }
}

static void AniSetUninstallDisposedRule(ani_env* env,
    ani_string aniAppIdentifier, ani_object aniRule, ani_int aniAppIndex)
{
    APP_LOGD("ani SetUninstallDisposedRule called");
    std::string appIdentifier;
    if (!CommonFunAni::ParseString(env, aniAppIdentifier, appIdentifier)) {
        APP_LOGE("appIdentifier %{public}s invalid", appIdentifier.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_IDENTIFIER, TYPE_STRING);
        return;
    }
    if (appIdentifier.empty()) {
        APP_LOGE("appIdentifier is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPIDENTIFIER, SET_UNINSTALL_DISPOSED_RULE, "");
        return;
    }
    UninstallDisposedRule rule;
    if (!AniAppControlCommon::ParseUninstallDisposedRule(env, aniRule, rule)) {
        APP_LOGE("rule invalid!");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR,
            UNINSTALL_DISPOSED_RULE, UNINSTALL_DISPOSED_RULE_TYPE);
        return;
    }
    int32_t userId = Constants::UNSPECIFIED_USERID;

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("appControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, SET_UNINSTALL_DISPOSED_RULE, "");
        return;
    }

    ErrCode ret = appControlProxy->SetUninstallDisposedRule(appIdentifier, rule, aniAppIndex, userId);
    if (ret != ERR_OK) {
        APP_LOGE("SetUninstallDisposedRule failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            SET_UNINSTALL_DISPOSED_RULE, PERMISSION_DISPOSED_STATUS);
    }
}

static ani_object AniGetUninstallDisposedRule(ani_env* env, ani_string aniAppIdentifier, ani_int aniAppIndex)
{
    APP_LOGD("ani GetUninstallDisposedRule called");
    std::string appIdentifier;
    if (!CommonFunAni::ParseString(env, aniAppIdentifier, appIdentifier)) {
        APP_LOGE("appIdentifier %{public}s invalid", appIdentifier.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_IDENTIFIER, TYPE_STRING);
        return nullptr;
    }
    if (appIdentifier.empty()) {
        APP_LOGE("appIdentifier is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPIDENTIFIER, GET_UNINSTALL_DISPOSED_RULE, "");
        return nullptr;
    }
    int32_t userId = Constants::UNSPECIFIED_USERID;

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("appControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_UNINSTALL_DISPOSED_RULE, "");
        return nullptr;
    }

    UninstallDisposedRule uninstallDisposedRule;
    ErrCode ret = appControlProxy->GetUninstallDisposedRule(appIdentifier, aniAppIndex, userId, uninstallDisposedRule);
    if (ret != ERR_OK) {
        APP_LOGE("GetUninstallDisposedRule failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            GET_UNINSTALL_DISPOSED_RULE, PERMISSION_DISPOSED_APP_STATUS);
        return nullptr;
    }

    return AniAppControlCommon::ConvertUninstallDisposedRule(env, uninstallDisposedRule);
}

static void AniDeleteUninstallDisposedRule(ani_env* env, ani_string aniAppIdentifier, ani_int aniAppIndex)
{
    APP_LOGD("ani DeleteUninstallDisposedRule called");
    std::string appIdentifier;
    if (!CommonFunAni::ParseString(env, aniAppIdentifier, appIdentifier)) {
        APP_LOGE("appIdentifier %{public}s invalid", appIdentifier.c_str());
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_IDENTIFIER, TYPE_STRING);
        return;
    }
    if (appIdentifier.empty()) {
        APP_LOGE("appIdentifier is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPIDENTIFIER, DELETE_UNINSTALL_DISPOSED_RULE, "");
        return;
    }
    int32_t userId = Constants::UNSPECIFIED_USERID;

    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("appControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, DELETE_UNINSTALL_DISPOSED_RULE, "");
        return;
    }

    ErrCode ret = appControlProxy->DeleteUninstallDisposedRule(appIdentifier, aniAppIndex, userId);
    if (ret != ERR_OK) {
        APP_LOGE("DeleteUninstallDisposedRule failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            DELETE_UNINSTALL_DISPOSED_RULE, PERMISSION_DISPOSED_STATUS);
    }
}

static bool ParseDisposedRuleConfiguration(
    ani_env* env, ani_object object, DisposedRuleConfiguration& disposedRuleConfiguration)
{
    if (env == nullptr || object == nullptr) {
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_TYPE_CHECK_ERROR);
        return false;
    }

    // appId: string
    ani_string appId = nullptr;
    if (!CommonFunAni::CallGetter(env, object, PROPERTYNAME_APPID, &appId)) {
        APP_LOGE("appId invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_ID, TYPE_STRING);
        return false;
    }
    disposedRuleConfiguration.appId = CommonFunAni::AniStrToString(env, appId);
    if (disposedRuleConfiguration.appId.empty()) {
        APP_LOGE("appId empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPID, SET_DISPOSED_RULES, "");
        return false;
    }

    // appIndex: int
    ani_int appIndex = Constants::MAIN_APP_INDEX;
    if (!CommonFunAni::CallGetter(env, object, PROPERTYNAME_APPINDEX, &appIndex)) {
        APP_LOGE("appIndex invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, APP_INDEX, TYPE_NUMBER);
        return false;
    }
    if (appIndex < Constants::MAIN_APP_INDEX || appIndex > Constants::CLONE_APP_INDEX_MAX) {
        APP_LOGE("appIndex invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_INVALID_APPINDEX, SET_DISPOSED_RULES, "");
        return false;
    }
    disposedRuleConfiguration.appIndex = appIndex;

    // disposedRule: DisposedRule
    ani_object disposedRuleObject = nullptr;
    if (!CommonFunAni::CallGetter(env, object, PROPERTYNAME_DISPOSEDRULE, &disposedRuleObject) ||
        !AniAppControlCommon::ParseDisposedRule(env, disposedRuleObject, disposedRuleConfiguration.disposedRule)) {
        APP_LOGE("disposedRule invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, DISPOSED_RULE, DISPOSED_RULE_TYPE);
        return false;
    }
    return true;
}

static void SetDisposedRules(ani_env* env, ani_object aniDisposedRuleConfigurations)
{
    APP_LOGD("ani SetDisposedRules called");
    std::vector<DisposedRuleConfiguration> disposedRuleConfigurations;
    if (!CommonFunAni::ParseAniArray(env, aniDisposedRuleConfigurations, disposedRuleConfigurations,
        ParseDisposedRuleConfiguration)) {
        APP_LOGE("Parse disposedRuleConfigurations invalid");
        return;
    }
    uint32_t arrayLength = disposedRuleConfigurations.size();
    if (arrayLength == 0 || arrayLength > MAX_VECTOR_NUM) {
        APP_LOGE("disposedRuleConfigurations length invalid!");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_LENGTH_ERROR);
        return;
    }
    auto appControlProxy = CommonFunc::GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("appControlProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, SET_DISPOSED_RULES, "");
        return;
    }

    int32_t userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    ErrCode ret = appControlProxy->SetDisposedRules(disposedRuleConfigurations, userId);
    if (ret != ERR_OK) {
        APP_LOGE("SetDisposedRules failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(
            env, CommonFunc::ConvertErrCode(ret), SET_DISPOSED_RULES, PERMISSION_DISPOSED_STATUS);
    }
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor appControl called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace nsName =
        arkts::ani_signature::Builder::BuildNamespace(NS_NAME_APPCONTROL);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(nsName.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_APPCONTROL, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "setDisposedStatusNative", nullptr, reinterpret_cast<void*>(AniSetDisposedStatus) },
        ani_native_function { "getDisposedStatusNative", nullptr, reinterpret_cast<void*>(AniGetDisposedStatus) },
        ani_native_function { "deleteDisposedStatusNative", nullptr, reinterpret_cast<void*>(AniDeleteDisposedStatus) },
        ani_native_function { "getDisposedRuleNative", nullptr, reinterpret_cast<void*>(AniGetDisposedRule) },
        ani_native_function { "getAllDisposedRulesNative", nullptr, reinterpret_cast<void*>(AniGetAllDisposedRules) },
        ani_native_function { "getAllDisposedRulesBySetterNative", nullptr,
            reinterpret_cast<void*>(AniGetDisposedRulesBySetter) },
        ani_native_function { "setDisposedRuleNative", nullptr, reinterpret_cast<void*>(AniSetDisposedRule) },
        ani_native_function { "setUninstallDisposedRuleNative", nullptr,
            reinterpret_cast<void*>(AniSetUninstallDisposedRule) },
        ani_native_function { "getUninstallDisposedRuleNative", nullptr,
            reinterpret_cast<void*>(AniGetUninstallDisposedRule) },
        ani_native_function { "deleteUninstallDisposedRuleNative", nullptr,
            reinterpret_cast<void*>(AniDeleteUninstallDisposedRule) },
        ani_native_function { "setDisposedRules", nullptr, reinterpret_cast<void*>(SetDisposedRules) },
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