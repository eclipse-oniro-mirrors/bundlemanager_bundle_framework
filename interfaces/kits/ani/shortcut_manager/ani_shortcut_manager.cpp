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
#include <ani_signature_builder.h>
#include "bundle_errors.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "ipc_skeleton.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* NS_NAME_SHORTCUTMANAGER = "@ohos.bundle.shortcutManager.shortcutManager";
}

static void AniAddDesktopShortcutInfo(ani_env* env, ani_object info, ani_int aniUserId)
{
    APP_LOGD("ani AddDesktopShortcutInfo called");
    ShortcutInfo shortcutInfo;
    if (!CommonFunAni::ParseShortcutInfo(env, info, shortcutInfo) ||
        !CommonFunc::CheckShortcutInfo(shortcutInfo)) {
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARSE_SHORTCUT_INFO);
        APP_LOGE("Parse shortcutInfo err. userId:%{public}d", aniUserId);
        return;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        BusinessErrorAni::ThrowError(env, ERR_APPEXECFWK_SERVICE_NOT_READY, ADD_DESKTOP_SHORTCUT_INFO);
        return;
    }
    ErrCode ret = iBundleMgr->AddDesktopShortcutInfo(shortcutInfo, aniUserId);
    if (ret != ERR_OK) {
        APP_LOGE("AddDesktopShortcutInfo failed ret:%{public}d,userId:%{public}d", ret, aniUserId);
        BusinessErrorAni::ThrowCommonError(
            env, CommonFunc::ConvertErrCode(ret), ADD_DESKTOP_SHORTCUT_INFO, Constants::PERMISSION_MANAGER_SHORTCUT);
    }
}

static void AniDeleteDesktopShortcutInfo(ani_env* env, ani_object info, ani_int aniUserId)
{
    APP_LOGD("ani DeleteDesktopShortcutInfo called");
    ShortcutInfo shortcutInfo;
    if (!CommonFunAni::ParseShortcutInfo(env, info, shortcutInfo) ||
        !CommonFunc::CheckShortcutInfo(shortcutInfo)) {
        APP_LOGE("Parse shortcutInfo err. userId:%{public}d", aniUserId);
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARSE_SHORTCUT_INFO);
        return;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        BusinessErrorAni::ThrowError(env, ERR_APPEXECFWK_SERVICE_NOT_READY, DELETE_DESKTOP_SHORTCUT_INFO);
        return;
    }
    ErrCode ret = iBundleMgr->DeleteDesktopShortcutInfo(shortcutInfo, aniUserId);
    if (ret != ERR_OK) {
        APP_LOGE("DeleteDesktopShortcutInfo failed ret:%{public}d,userId:%{public}d", ret, aniUserId);
        BusinessErrorAni::ThrowCommonError(
            env, CommonFunc::ConvertErrCode(ret),
            DELETE_DESKTOP_SHORTCUT_INFO, Constants::PERMISSION_MANAGER_SHORTCUT);
    }
}

static ani_ref AniGetAllDesktopShortcutInfo(ani_env* env, ani_int aniUserId)
{
    APP_LOGD("ani GetAllDesktopShortcutInfo called");
    std::vector<ShortcutInfo> shortcutInfos;
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("Can not get iBundleMgr");
        BusinessErrorAni::ThrowError(env, ERR_APPEXECFWK_SERVICE_NOT_READY, GET_ALL_DESKTOP_SHORTCUT_INFO);
        return nullptr;
    }
    ErrCode ret = iBundleMgr->GetAllDesktopShortcutInfo(aniUserId, shortcutInfos);
    if (ret != ERR_OK) {
        APP_LOGE("GetAllDesktopShortcutInfo failed ret:%{public}d,userId:%{public}d", ret, aniUserId);
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
    APP_LOGI("ANI_Constructor shortcutManager called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace nsName = arkts::ani_signature::Builder::BuildNamespace(NS_NAME_SHORTCUTMANAGER);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(nsName.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_SHORTCUTMANAGER, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "addDesktopShortcutInfoNative", nullptr,
            reinterpret_cast<void*>(AniAddDesktopShortcutInfo) },
        ani_native_function { "deleteDesktopShortcutInfoNative", nullptr,
            reinterpret_cast<void*>(AniDeleteDesktopShortcutInfo) },
        ani_native_function { "getAllDesktopShortcutInfoNative", nullptr,
            reinterpret_cast<void*>(AniGetAllDesktopShortcutInfo) },
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE("Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_SHORTCUTMANAGER, status);
        return status;
    }

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // AppExecFwk
} // OHOS