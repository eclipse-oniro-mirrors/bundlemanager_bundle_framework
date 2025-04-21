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

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* ADD_DESKTOP_SHORTCUT_INFO = "AddDesktopShortcutInfo";
constexpr const char* DELETE_DESKTOP_SHORTCUT_INFO = "DeleteDesktopShortcutInfo";
constexpr const char* GET_ALL_DESKTOP_SHORTCUT_INFO = "GetAllDesktopShortcutInfo";
constexpr const char* PARSE_SHORTCUT_INFO = "ParseShortcutInfo";
}

static void AddDesktopShortcutInfo([[maybe_unused]] ani_env* env, ani_object info, ani_double userId)
{
    int32_t userIdInt = 0;
    if (!CommonFunAni::TryCastDoubleTo(userId, &userIdInt)) {
        APP_LOGE("Cast userId failed");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::USER_ID, CommonFunAniNS::TYPE_INT);
        return;
    }
    
    ShortcutInfo shortcutInfo;
    if (!CommonFunAni::ParseShortcutInfo(env, info, shortcutInfo) ||
        !CommonFunc::CheckShortcutInfo(shortcutInfo)) {
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARSE_SHORTCUT_INFO);
        APP_LOGE("Parse shortcutInfo err. userId:%{public}d", userIdInt);
        return;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        BusinessErrorAni::ThrowError(env, ERR_APPEXECFWK_SERVICE_NOT_READY, ADD_DESKTOP_SHORTCUT_INFO);
        return;
    }
    ErrCode ret = iBundleMgr->AddDesktopShortcutInfo(shortcutInfo, userIdInt);
    if (ret != ERR_OK) {
        APP_LOGE("AddDesktopShortcutInfo failed ret:%{public}d,userId:%{public}d", ret, userIdInt);
        BusinessErrorAni::ThrowCommonError(
            env, CommonFunc::ConvertErrCode(ret), ADD_DESKTOP_SHORTCUT_INFO, Constants::PERMISSION_MANAGER_SHORTCUT);
    }
}

static void DeleteDesktopShortcutInfo([[maybe_unused]] ani_env* env, ani_object info, ani_double userId)
{
    int32_t userIdInt = 0;
    if (!CommonFunAni::TryCastDoubleTo(userId, &userIdInt)) {
        APP_LOGE("Cast userId failed");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::USER_ID, CommonFunAniNS::TYPE_INT);
        return;
    }

    ShortcutInfo shortcutInfo;
    if (!CommonFunAni::ParseShortcutInfo(env, info, shortcutInfo) ||
        !CommonFunc::CheckShortcutInfo(shortcutInfo)) {
        APP_LOGE("Parse shortcutInfo err. userId:%{public}d", userIdInt);
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARSE_SHORTCUT_INFO);
        return;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        BusinessErrorAni::ThrowError(env, ERR_APPEXECFWK_SERVICE_NOT_READY, DELETE_DESKTOP_SHORTCUT_INFO);
        return;
    }
    ErrCode ret = iBundleMgr->DeleteDesktopShortcutInfo(shortcutInfo, userIdInt);
    if (ret != ERR_OK) {
        APP_LOGE("DeleteDesktopShortcutInfo failed ret:%{public}d,userId:%{public}d", ret, userIdInt);
        BusinessErrorAni::ThrowCommonError(
            env, CommonFunc::ConvertErrCode(ret),
            DELETE_DESKTOP_SHORTCUT_INFO, Constants::PERMISSION_MANAGER_SHORTCUT);
    }
}

static ani_ref GetAllDesktopShortcutInfo([[maybe_unused]] ani_env* env, ani_double userId)
{
    int32_t userIdInt = 0;
    if (!CommonFunAni::TryCastDoubleTo(userId, &userIdInt)) {
        APP_LOGE("Cast userId failed");
        BusinessErrorAni::ThrowCommonError(
            env, ERROR_PARAM_CHECK_ERROR, Constants::USER_ID, CommonFunAniNS::TYPE_INT);
        return nullptr;
    }

    std::vector<ShortcutInfo> shortcutInfos;
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        BusinessErrorAni::ThrowError(env, ERR_APPEXECFWK_SERVICE_NOT_READY, GET_ALL_DESKTOP_SHORTCUT_INFO);
        return nullptr;
    }
    ErrCode ret = iBundleMgr->GetAllDesktopShortcutInfo(userIdInt, shortcutInfos);
    if (ret != ERR_OK) {
        APP_LOGE("GetAllDesktopShortcutInfo failed ret:%{public}d,userId:%{public}d", ret, userIdInt);
        BusinessErrorAni::ThrowCommonError(
            env, CommonFunc::ConvertErrCode(ret),
            GET_ALL_DESKTOP_SHORTCUT_INFO, Constants::PERMISSION_MANAGER_SHORTCUT);
        return nullptr;
    }
    ani_ref shortcutInfosRef = CommonFunAni::ConvertAniArray(env, shortcutInfos, CommonFunAni::ConvertShortcutInfo);
    if (shortcutInfosRef == nullptr) {
        APP_LOGE("nullptr shortcutInfosRef");
    }

    return shortcutInfosRef;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor called");
    ani_env* env;
    ani_status res = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Unsupported ANI_VERSION_1");

    static const char* nsName = "L@ohos/bundle/shortcutManager/shortcutManager;";
    ani_namespace kitNs;
    res = env->FindNamespace(nsName, &kitNs);
    RETURN_ANI_STATUS_IF_NOT_OK(
        res, "Not found nameSpace L@ohos/bundle/shortcutManager/shortcutManager;");

    std::array methods = {
        ani_native_function {
            "AddDesktopShortcutInfo",
            "LbundleManager/ShortcutInfo/ShortcutInfo;D:V",
            reinterpret_cast<void*>(AddDesktopShortcutInfo)
        },
        ani_native_function {
            "DeleteDesktopShortcutInfo",
            "LbundleManager/ShortcutInfo/ShortcutInfo;D:V",
            reinterpret_cast<void*>(DeleteDesktopShortcutInfo)
        },
        ani_native_function {
            "GetAllDesktopShortcutInfo",
            "D:Lescompat/Array;",
            reinterpret_cast<void*>(GetAllDesktopShortcutInfo)
        },
    };

    res = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Cannot bind native methods");

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // AppExecFwk
} // OHOS