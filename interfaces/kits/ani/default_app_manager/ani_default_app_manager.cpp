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

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_mgr_interface.h"
#include "business_error_ani.h"
#include "common_func.h"
#include "common_fun_ani.h"
#include "ipc_skeleton.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AAFwk;
namespace {
constexpr int32_t EMPTY_USER_ID = -500;
constexpr const char* NS_NAME_DEFAULTAPPMANAGER = "@ohos.bundle.defaultAppManager.defaultAppManager";
} // namespace

static bool ParseType(ani_env *env, ani_string aniType, std::string& result)
{
    result = CommonFunAni::AniStrToString(env, aniType);
    if (TYPE_MAPPING.find(result) != TYPE_MAPPING.end()) {
        result = TYPE_MAPPING.at(result);
    }
    return true;
}

static ani_boolean IsDefaultApplicationSync(ani_env *env, ani_string aniType)
{
    std::string type;
    if (!ParseType(env, aniType, type)) {
        APP_LOGE("type invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, TYPE_CHECK, TYPE_STRING);
        return CommonFunAni::BoolToAniBoolean(false);
    }

    auto defaultAppProxy = CommonFunc::GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        APP_LOGE("defaultAppProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION, IS_DEFAULT_APPLICATION, "");
        return CommonFunAni::BoolToAniBoolean(false);
    }

    bool isDefaultApp = false;
    ErrCode ret = defaultAppProxy->IsDefaultApplication(type, isDefaultApp);
    if (ret != ERR_OK) {
        APP_LOGE("IsDefaultApplication failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret), IS_DEFAULT_APPLICATION, "");
        return CommonFunAni::BoolToAniBoolean(false);
    }

    return CommonFunAni::BoolToAniBoolean(isDefaultApp);
}

static ani_object GetDefaultApplicationSync(ani_env *env, ani_string aniType, ani_double aniUserId)
{
    std::string type;
    if (!ParseType(env, aniType, type)) {
        APP_LOGE("type invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, TYPE_CHECK, TYPE_STRING);
        return nullptr;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("Cast userId failed");
        return nullptr;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (userId == EMPTY_USER_ID) {
        userId = callingUid / Constants::BASE_USER_RANGE;
    }
    auto defaultAppProxy = CommonFunc::GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        APP_LOGE("defaultAppProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            GET_DEFAULT_APPLICATION, Constants::PERMISSION_GET_DEFAULT_APPLICATION);
        return nullptr;
    }

    BundleInfo bundleInfo;
    ErrCode ret = defaultAppProxy->GetDefaultApplication(userId, type, bundleInfo);
    if (ret != ERR_OK) {
        APP_LOGE("GetDefaultApplication failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            GET_DEFAULT_APPLICATION, Constants::PERMISSION_GET_DEFAULT_APPLICATION);
        return nullptr;
    }

    return CommonFunAni::ConvertDefaultAppBundleInfo(env, bundleInfo);
}

static void SetDefaultApplicationSync(ani_env *env, ani_string aniType, ani_object aniElementName, ani_double aniUserId)
{
    std::string type;
    if (!ParseType(env, aniType, type)) {
        APP_LOGE("type invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, TYPE_CHECK, TYPE_STRING);
        return;
    }
    ElementName elementName;
    if (!CommonFunAni::ParseElementName(env, aniElementName, elementName)) {
        APP_LOGE("ParseElementName failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, WANT_CHECK, TYPE_OBJECT);
        return;
    }
    Want want;
    want.SetElement(elementName);
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("Cast userId failed");
        return;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (userId == EMPTY_USER_ID) {
        userId = callingUid / Constants::BASE_USER_RANGE;
    }
    auto defaultAppProxy = CommonFunc::GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        APP_LOGE("defaultAppProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            SET_DEFAULT_APPLICATION, Constants::PERMISSION_SET_DEFAULT_APPLICATION);
        return;
    }

    ErrCode ret = defaultAppProxy->SetDefaultApplication(userId, type, want);
    if (ret != ERR_OK) {
        APP_LOGE("SetDefaultApplication failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            SET_DEFAULT_APPLICATION, Constants::PERMISSION_SET_DEFAULT_APPLICATION);
    }
}

static void ResetDefaultApplicationSync(ani_env *env, ani_string aniType, ani_double aniUserId)
{
    std::string type;
    if (!ParseType(env, aniType, type)) {
        APP_LOGE("type invalid");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, TYPE_CHECK, TYPE_STRING);
        return;
    }
    int32_t userId = EMPTY_USER_ID;
    if (!CommonFunAni::TryCastDoubleTo(aniUserId, &userId)) {
        APP_LOGE("Cast userId failed");
        return;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (userId == EMPTY_USER_ID) {
        userId = callingUid / Constants::BASE_USER_RANGE;
    }
    auto defaultAppProxy = CommonFunc::GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        APP_LOGE("defaultAppProxy is null");
        BusinessErrorAni::ThrowCommonError(env, ERROR_BUNDLE_SERVICE_EXCEPTION,
            RESET_DEFAULT_APPLICATION, Constants::PERMISSION_SET_DEFAULT_APPLICATION);
        return;
    }

    ErrCode ret = defaultAppProxy->ResetDefaultApplication(userId, type);
    if (ret != ERR_OK) {
        APP_LOGE("ResetDefaultApplication failed ret: %{public}d", ret);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(ret),
            RESET_DEFAULT_APPLICATION, Constants::PERMISSION_SET_DEFAULT_APPLICATION);
    }
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor defaultAppManager called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace nsName = arkts::ani_signature::Builder::BuildNamespace(NS_NAME_DEFAULTAPPMANAGER);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(nsName.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_DEFAULTAPPMANAGER, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "isDefaultApplicationSync", nullptr, reinterpret_cast<void*>(IsDefaultApplicationSync) },
        ani_native_function { "getDefaultApplicationSyncNative", nullptr,
            reinterpret_cast<void*>(GetDefaultApplicationSync) },
        ani_native_function { "setDefaultApplicationSyncNative", nullptr,
            reinterpret_cast<void*>(SetDefaultApplicationSync) },
        ani_native_function { "resetDefaultApplicationSyncNative", nullptr,
            reinterpret_cast<void*>(ResetDefaultApplicationSync) }
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE(
            "Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_DEFAULTAPPMANAGER, status);
        return status;
    }

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // AppExecFwk
} // OHOS