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

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error_ani.h"
#include "common_func.h"
#include "common_fun_ani.h"
#include "ipc_skeleton.h"
#include "skill_manager_helper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* CLASSNAME_SKILL_INFO_INNER = "skillManager.SkillInfoInner";
constexpr const char* CLASSNAME_SKILL_TYPE = "skillManager.SkillType";
constexpr const char* GET_SKILL_INFO_FOR_SELF = "getSkillInfoForSelf";
constexpr const char* GET_SKILL_INFOS_FOR_SELF = "getSkillInfosForSelf";
constexpr const char* GET_SKILL_INFO = "getSkillInfo";
constexpr const char* GET_SKILL_INFOS = "getSkillInfos";
constexpr const char* GET_ALL_SKILL_INFOS = "getAllSkillInfos";

ani_object ConvertSkillInfo(ani_env* env, const SkillInfo& skillInfo)
{
    APP_LOGD("ConvertSkillInfo start");
    RETURN_NULL_IF_NULL(env);

    ani_string bundleName = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, skillInfo.bundleName, bundleName));

    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, skillInfo.moduleName, moduleName));

    ani_string skillName = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, skillInfo.skillName, skillName));

    ani_string hapPath = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, skillInfo.hapPath, hapPath));

    ani_string skillPath = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, skillInfo.skillPath, skillPath));

    ani_string abilityName = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, skillInfo.abilityName, abilityName));

    ani_string description = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, skillInfo.description, description));

    ani_object srcEntriesArray = CommonFunAni::ConvertAniArrayString(env, skillInfo.srcEntries);
    RETURN_NULL_IF_NULL(srcEntriesArray);

    ani_object permissionsArray = CommonFunAni::ConvertAniArrayString(env, skillInfo.permissions);
    RETURN_NULL_IF_NULL(permissionsArray);

    ani_object requestPermissionsArray = CommonFunAni::ConvertAniArrayString(env, skillInfo.requestPermissions);
    RETURN_NULL_IF_NULL(requestPermissionsArray);

    ani_object skillTypeObj = CommonFunAni::CreateNewObjectByClass(
        env, CLASSNAME_SKILL_TYPE, "i:", { .i = static_cast<ani_int>(skillInfo.skillType) });
    RETURN_NULL_IF_NULL(skillTypeObj);

    ani_value args[] = {
        { .r = bundleName },
        { .r = moduleName },
        { .r = skillName },
        { .i = skillInfo.skillId },
        { .r = skillTypeObj },
        { .r = hapPath },
        { .r = skillPath },
        { .r = abilityName },
        { .r = description },
        { .r = srcEntriesArray },
        { .r = permissionsArray },
        { .r = requestPermissionsArray },
    };

    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)   // bundleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)   // moduleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)   // skillName: string
        .AddInt()                                     // skillId: int
        .AddClass(CLASSNAME_SKILL_TYPE)               // skillType: SkillType
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)   // hapPath: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)   // skillPath: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)   // abilityName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)   // description: string
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)    // srcEntries: Array<string>
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)    // permissions: Array<string>
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)    // requestPermissions: Array<string>
        .BuildSignatureDescriptor();
    return CommonFunAni::CreateNewObjectByClassV2(env, CLASSNAME_SKILL_INFO_INNER, ctorSig, args);
}

ani_object ConvertSkillInfos(ani_env* env, const std::vector<SkillInfo>& skillInfos)
{
    APP_LOGD("ConvertSkillInfos start");
    return CommonFunAni::ConvertAniArray(env, skillInfos, ConvertSkillInfo);
}

static ani_object GetSkillInfoForSelfNative(ani_env* env,
    ani_string aniModuleName, ani_string aniSkillName, ani_int aniFlags, ani_int aniUserId)
{
    APP_LOGD("ani GetSkillInfoForSelfNative called");
    std::string moduleName;
    if (!CommonFunAni::ParseString(env, aniModuleName, moduleName) || moduleName.empty()) {
        APP_LOGE("moduleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
        return nullptr;
    }
    std::string skillName;
    if (!CommonFunAni::ParseString(env, aniSkillName, skillName) || skillName.empty()) {
        APP_LOGE("skillName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, "skillName", TYPE_STRING);
        return nullptr;
    }

    uint32_t flags = static_cast<uint32_t>(aniFlags);
    int32_t userId = static_cast<int32_t>(aniUserId);

    SkillInfo skillInfo;
    ErrCode err = SkillManagerHelper::InnerGetSkillInfoForSelf(moduleName, skillName, userId, flags, skillInfo);
    if (err != ERR_OK) {
        APP_LOGE("GetSkillInfoForSelfNative failed, err: %{public}d", err);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(err), GET_SKILL_INFO_FOR_SELF,
            Constants::PERMISSION_GET_BUNDLE_RESOURCES);
        return nullptr;
    }
    return ConvertSkillInfo(env, skillInfo);
}

static ani_object GetSkillInfosForSelfNative(ani_env* env, ani_int aniFlags, ani_int aniUserId)
{
    APP_LOGD("ani GetSkillInfosForSelfNative called");
    uint32_t flags = static_cast<uint32_t>(aniFlags);
    int32_t userId = static_cast<int32_t>(aniUserId);

    std::vector<SkillInfo> skillInfos;
    ErrCode err = SkillManagerHelper::InnerGetSkillInfosForSelf(flags, userId, skillInfos);
    if (err != ERR_OK) {
        APP_LOGE("GetSkillInfosForSelfNative failed, err: %{public}d", err);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(err), GET_SKILL_INFOS_FOR_SELF,
            Constants::PERMISSION_GET_BUNDLE_RESOURCES);
        return nullptr;
    }
    return ConvertSkillInfos(env, skillInfos);
}

static ani_object GetSkillInfoNative(ani_env* env, ani_string aniBundleName, ani_string aniModuleName,
    ani_string aniSkillName, ani_int aniFlags, ani_int aniUserId)
{
    APP_LOGD("ani GetSkillInfoNative called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName) || bundleName.empty()) {
        APP_LOGE("bundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }
    std::string moduleName;
    if (!CommonFunAni::ParseString(env, aniModuleName, moduleName) || moduleName.empty()) {
        APP_LOGE("moduleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
        return nullptr;
    }
    std::string skillName;
    if (!CommonFunAni::ParseString(env, aniSkillName, skillName) || skillName.empty()) {
        APP_LOGE("skillName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, "skillName", TYPE_STRING);
        return nullptr;
    }

    uint32_t flags = static_cast<uint32_t>(aniFlags);
    int32_t userId = static_cast<int32_t>(aniUserId);

    SkillInfo skillInfo;
    ErrCode err = SkillManagerHelper::InnerGetSkillInfo(bundleName, moduleName, skillName, flags, userId, skillInfo);
    if (err != ERR_OK) {
        APP_LOGE("GetSkillInfoNative failed, err: %{public}d", err);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(err), GET_SKILL_INFO,
            Constants::PERMISSION_GET_BUNDLE_RESOURCES);
        return nullptr;
    }
    return ConvertSkillInfo(env, skillInfo);
}

static ani_object GetSkillInfosNative(ani_env* env, ani_string aniBundleName, ani_int aniFlags, ani_int aniUserId)
{
    APP_LOGD("ani GetSkillInfosNative called");
    std::string bundleName;
    if (!CommonFunAni::ParseString(env, aniBundleName, bundleName) || bundleName.empty()) {
        APP_LOGE("bundleName parse failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
        return nullptr;
    }

    uint32_t flags = static_cast<uint32_t>(aniFlags);
    int32_t userId = static_cast<int32_t>(aniUserId);

    std::vector<SkillInfo> skillInfos;
    ErrCode err = SkillManagerHelper::InnerGetSkillInfos(bundleName, flags, userId, skillInfos);
    if (err != ERR_OK) {
        APP_LOGE("GetSkillInfosNative failed, err: %{public}d", err);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(err), GET_SKILL_INFOS,
            Constants::PERMISSION_GET_BUNDLE_RESOURCES);
        return nullptr;
    }
    return ConvertSkillInfos(env, skillInfos);
}

static ani_object GetAllSkillInfosNative(ani_env* env, ani_int aniFlags, ani_int aniUserId)
{
    APP_LOGD("ani GetAllSkillInfosNative called");
    uint32_t flags = static_cast<uint32_t>(aniFlags);
    int32_t userId = static_cast<int32_t>(aniUserId);

    std::vector<SkillInfo> skillInfos;
    ErrCode err = SkillManagerHelper::InnerGetAllSkillInfos(flags, userId, skillInfos);
    if (err != ERR_OK) {
        APP_LOGE("GetAllSkillInfosNative failed, err: %{public}d", err);
        BusinessErrorAni::ThrowCommonError(env, CommonFunc::ConvertErrCode(err), GET_ALL_SKILL_INFOS,
            Constants::PERMISSION_GET_BUNDLE_RESOURCES);
        return nullptr;
    }
    return ConvertSkillInfos(env, skillInfos);
}

} // namespace

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor called");
    ani_env* env;
    ani_status res = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Unsupported ANI_VERSION_1");

    auto nsName = arkts::ani_signature::Builder::BuildNamespace({"@ohos", "bundle", "skillManager", "skillManager"});
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
