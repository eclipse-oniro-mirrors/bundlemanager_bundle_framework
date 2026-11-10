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

#include "ani_skill_manager.h"

#include <ani_signature_builder.h>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "ipc_skeleton.h"
#include "napi_constants.h"
#include "skill_manager_helper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* SKILL_NAME = "skillName";
constexpr const char* GET_SKILL_INFO_FOR_SELF = "getSkillInfoForSelf";
constexpr const char* GET_SKILL_INFOS_FOR_SELF = "getSkillInfosForSelf";
constexpr const char* GET_SKILL_INFO = "getSkillInfo";
constexpr const char* GET_SKILL_INFOS = "getSkillInfos";
constexpr const char* GET_ALL_SKILL_INFOS = "getAllSkillInfos";
uint32_t ParseFlags(ani_int aniFlags)
{
    int32_t flags = static_cast<int32_t>(aniFlags);
    if (flags < 0) {
        return static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_DEFAULT);
    }
    return static_cast<uint32_t>(flags);
}

int32_t ParseUserId(ani_int aniUserId)
{
    int32_t userId = static_cast<int32_t>(aniUserId);
    if (userId == EMPTY_USER_ID) {
        return IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    }
    return userId;
}

ani_object GetSkillInfoForSelfNative(ani_env* env,
    ani_string aniModuleName, ani_string aniSkillName, ani_int aniFlags)
{
    APP_LOGD("ani GetSkillInfoForSelfNative called");
    std::string moduleName;
    if (!CommonFunAni::ParseString(env, aniModuleName, moduleName)) {
        APP_LOGE("moduleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
        return nullptr;
    }
    std::string skillName;
    if (!CommonFunAni::ParseString(env, aniSkillName, skillName)) {
        APP_LOGE("skillName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, SKILL_NAME, TYPE_STRING);
        return nullptr;
    }

    uint32_t flags = ParseFlags(aniFlags);

    SkillInfo skillInfo;
    ErrCode err = SkillManagerHelper::InnerGetSkillInfoForSelf(moduleName, skillName, flags, skillInfo);
    if (err != ERR_OK) {
        APP_LOGE("GetSkillInfoForSelfNative failed, err: %{public}d", err);
        BusinessErrorAni::ThrowCommonError(env, err, GET_SKILL_INFO_FOR_SELF, "");
        return nullptr;
    }
    return CommonFunAni::ConvertSkillInfo(env, skillInfo, flags);
}

ani_object GetSkillInfosForSelfNative(ani_env* env, ani_int aniFlags)
{
    APP_LOGD("ani GetSkillInfosForSelfNative called");
    uint32_t flags = ParseFlags(aniFlags);

    std::vector<SkillInfo> skillInfos;
    ErrCode err = SkillManagerHelper::InnerGetSkillInfosForSelf(flags, skillInfos);
    if (err != ERR_OK) {
        APP_LOGE("GetSkillInfosForSelfNative failed, err: %{public}d", err);
        BusinessErrorAni::ThrowCommonError(env, err, GET_SKILL_INFOS_FOR_SELF, "");
        return nullptr;
    }
    return CommonFunAni::ConvertSkillInfos(env, skillInfos, flags);
}

ani_object GetSkillInfoNative(ani_env* env, ani_string aniBundleName, ani_string aniModuleName,
    ani_string aniSkillName, ani_int aniFlags, ani_int aniUserId)
{
    APP_LOGD("ani GetSkillInfoNative called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    std::string moduleName;
    if (!CommonFunAni::ParseString(env, aniModuleName, moduleName)) {
        APP_LOGE("moduleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
        return nullptr;
    }
    std::string skillName;
    if (!CommonFunAni::ParseString(env, aniSkillName, skillName)) {
        APP_LOGE("skillName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, SKILL_NAME, TYPE_STRING);
        return nullptr;
    }

    uint32_t flags = ParseFlags(aniFlags);
    int32_t userId = ParseUserId(aniUserId);

    SkillInfo skillInfo;
    ErrCode err = SkillManagerHelper::InnerGetSkillInfo(bundleName, moduleName, skillName, flags, userId, skillInfo);
    if (err != ERR_OK) {
        APP_LOGE("GetSkillInfoNative failed, err: %{public}d", err);
        BusinessErrorAni::ThrowCommonError(env, err, GET_SKILL_INFO,
            Constants::PERMISSION_MANAGE_SKILL_AND_INTERACT_ACROSS_LOCAL_ACCOUNTS);
        return nullptr;
    }
    return CommonFunAni::ConvertSkillInfo(env, skillInfo, flags);
}

ani_object GetSkillInfosNative(ani_env* env, ani_string aniBundleName, ani_int aniFlags, ani_int aniUserId)
{
    APP_LOGD("ani GetSkillInfosNative called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName)) {
        APP_LOGE("bundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }

    uint32_t flags = ParseFlags(aniFlags);
    int32_t userId = ParseUserId(aniUserId);

    std::vector<SkillInfo> skillInfos;
    ErrCode err = SkillManagerHelper::InnerGetSkillInfos(bundleName, flags, userId, skillInfos);
    if (err != ERR_OK) {
        APP_LOGE("GetSkillInfosNative failed, err: %{public}d", err);
        BusinessErrorAni::ThrowCommonError(env, err, GET_SKILL_INFOS,
            Constants::PERMISSION_MANAGE_SKILL_AND_INTERACT_ACROSS_LOCAL_ACCOUNTS);
        return nullptr;
    }
    return CommonFunAni::ConvertSkillInfos(env, skillInfos, flags);
}

ani_object GetAllSkillInfosNative(ani_env* env, ani_int aniFlags, ani_int aniUserId)
{
    APP_LOGD("ani GetAllSkillInfosNative called");
    uint32_t flags = ParseFlags(aniFlags);
    int32_t userId = ParseUserId(aniUserId);

    std::vector<SkillInfo> skillInfos;
    ErrCode err = SkillManagerHelper::InnerGetAllSkillInfos(flags, userId, skillInfos);
    if (err != ERR_OK) {
        APP_LOGE("GetAllSkillInfosNative failed, err: %{public}d", err);
        BusinessErrorAni::ThrowCommonError(env, err, GET_ALL_SKILL_INFOS,
            Constants::PERMISSION_MANAGE_SKILL_AND_INTERACT_ACROSS_LOCAL_ACCOUNTS);
        return nullptr;
    }
    return CommonFunAni::ConvertSkillInfos(env, skillInfos, flags);
}
} // namespace

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor called");
    ani_env* env;
    ani_status res = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Unsupported ANI_VERSION_1");

    auto nsName = arkts::ani_signature::Builder::BuildNamespace(
        {"@ohos", "bundle", "skillManager", "skillManager"});
    ani_namespace kitNs;
    res = env->FindNamespace(nsName.Descriptor().c_str(), &kitNs);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Not found nameSpace L@ohos/bundle/skillManager/skillManager;");

    std::array methods = {
        ani_native_function { "getSkillInfoForSelfNative", nullptr,
            reinterpret_cast<void*>(GetSkillInfoForSelfNative) },
        ani_native_function { "getSkillInfosForSelfNative", nullptr,
            reinterpret_cast<void*>(GetSkillInfosForSelfNative) },
        ani_native_function { "getSkillInfoNative", nullptr,
            reinterpret_cast<void*>(GetSkillInfoNative) },
        ani_native_function { "getSkillInfosNative", nullptr,
            reinterpret_cast<void*>(GetSkillInfosNative) },
        ani_native_function { "getAllSkillInfosNative", nullptr,
            reinterpret_cast<void*>(GetAllSkillInfosNative) },
    };

    res = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Cannot bind native methods");

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");
    return ANI_OK;
}
} // extern "C"

} // namespace AppExecFwk
} // namespace OHOS
