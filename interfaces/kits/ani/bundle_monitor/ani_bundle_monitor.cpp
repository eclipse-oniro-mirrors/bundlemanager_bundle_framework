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

#include "ani_bundle_monitor_event_handler.h"
#include "app_log_wrapper.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* NS_NAME_BUNDLE_MONITOR = "@ohos.bundle.bundleMonitor.bundleMonitor";
constexpr const char* INTERFACE_NAME_ON_ADD = "onAdd";
constexpr const char* INTERFACE_NAME_ON_UPDATE = "onUpdate";
constexpr const char* INTERFACE_NAME_ON_REMOVE = "onRemove";
constexpr const char* INTERFACE_NAME_OFF_ADD = "offAdd";
constexpr const char* INTERFACE_NAME_OFF_UPDATE = "offUpdate";
constexpr const char* INTERFACE_NAME_OFF_REMOVE = "offRemove";
constexpr const char* EVENT_TYPE_ADD = "add";
constexpr const char* EVENT_TYPE_UPDATE = "update";
constexpr const char* EVENT_TYPE_REMOVE = "remove";
constexpr const char* PERMISSION_LISTEN_BUNDLE_CHANGE = "ohos.permission.LISTEN_BUNDLE_CHANGE";
constexpr const char* CALLBACK = "callback";
static std::mutex g_aniBundleMonitorMutex;
static std::shared_ptr<ANIBundleMonitorEventHandler> g_aniBundleMonitor;
} // namespace

static ani_status IsNullOrUndefined(ani_env* env, ani_ref ref, bool& result)
{
    if (ref == nullptr) {
        result = true;
        return ANI_OK;
    }
    ani_boolean isNull = ANI_FALSE;
    ani_boolean isUndefined = ANI_FALSE;
    ani_status status = env->Reference_IsNull(ref, &isNull);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Reference_IsNull failed");
    if (isNull == ANI_TRUE) {
        result = true;
        return ANI_OK;
    }
    status = env->Reference_IsUndefined(ref, &isUndefined);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Reference_IsUndefined failed");
    result = isUndefined == ANI_TRUE;
    return ANI_OK;
}

static void RegisterBundleChangedEvent(ani_env* env,
    const std::string& eventType, ani_object aniCallback, const std::string& interfaceName)
{
    APP_LOGD("Register %{public}s event entry", eventType.c_str());

    bool isCallbackEmpty = false;
    ani_status status = IsNullOrUndefined(env, aniCallback, isCallbackEmpty);
    if (status != ANI_OK) {
        APP_LOGE("check empty fail, status: %{public}d", status);
        return;
    }
    if (isCallbackEmpty) {
        APP_LOGE("callback is empty");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, CALLBACK, TYPE_FUNCTION);
        return;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return;
    }

    if (!iBundleMgr->VerifySystemApi(Constants::INVALID_API_VERSION)) {
        APP_LOGE("register bundle status callback failed due to non-sys app calling");
        auto error = BusinessErrorAni::CreateCommonError(env, ERROR_NOT_SYSTEM_APP);
        env->ThrowError(static_cast<ani_error>(error));
        return;
    }

    if (!iBundleMgr->VerifyCallingPermission(Constants::LISTEN_BUNDLE_CHANGE)) {
        APP_LOGE("register bundle status callback failed due to lack of permission");
        auto error = BusinessErrorAni::CreateCommonError(
            env, ERROR_PERMISSION_DENIED_ERROR, interfaceName, PERMISSION_LISTEN_BUNDLE_CHANGE);
        env->ThrowError(static_cast<ani_error>(error));
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_aniBundleMonitorMutex);
        if (g_aniBundleMonitor == nullptr) {
            APP_LOGE("environment init failed");
            return;
        }
        g_aniBundleMonitor->RegisterBundleChangedEvent(env, eventType, aniCallback);
    }

    APP_LOGD("Register %{public}s event exit", eventType.c_str());
}

static void UnregisterBundleChangedEvent(ani_env* env,
    const std::string& eventType, ani_object aniCallback, const std::string& interfaceName)
{
    APP_LOGD("Unregister %{public}s event entry", eventType.c_str());

    bool isCallbackEmpty = false;
    ani_status status = IsNullOrUndefined(env, aniCallback, isCallbackEmpty);
    if (status != ANI_OK) {
        APP_LOGE("check empty fail, status: %{public}d", status);
        return;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return;
    }

    if (!iBundleMgr->VerifySystemApi(Constants::INVALID_API_VERSION)) {
        APP_LOGE("register bundle status callback failed due to non-sys app calling");
        auto error = BusinessErrorAni::CreateCommonError(env, ERROR_NOT_SYSTEM_APP);
        env->ThrowError(static_cast<ani_error>(error));
        return;
    }

    if (!iBundleMgr->VerifyCallingPermission(Constants::LISTEN_BUNDLE_CHANGE)) {
        APP_LOGE("unregister bundle status callback failed due to lack of permission");
        auto error = BusinessErrorAni::CreateCommonError(
            env, ERROR_PERMISSION_DENIED_ERROR, interfaceName, PERMISSION_LISTEN_BUNDLE_CHANGE);
        env->ThrowError(static_cast<ani_error>(error));
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_aniBundleMonitorMutex);
        if (g_aniBundleMonitor == nullptr) {
            APP_LOGE("environment init failed");
            return;
        }
        if (isCallbackEmpty) {
            g_aniBundleMonitor->UnregisterBundleChangedEvent(env, eventType);
        } else {
            g_aniBundleMonitor->UnregisterBundleChangedEvent(env, eventType, aniCallback);
        }
    }

    APP_LOGD("Unregister %{public}s event exit", eventType.c_str());
}

static void RegisterAddEvent(ani_env* env, ani_object aniCallback)
{
    RegisterBundleChangedEvent(env, EVENT_TYPE_ADD, aniCallback, INTERFACE_NAME_ON_ADD);
}

static void RegisterUpdateEvent(ani_env* env, ani_object aniCallback)
{
    RegisterBundleChangedEvent(env, EVENT_TYPE_UPDATE, aniCallback, INTERFACE_NAME_ON_UPDATE);
}

static void RegisterRemoveEvent(ani_env* env, ani_object aniCallback)
{
    RegisterBundleChangedEvent(env, EVENT_TYPE_REMOVE, aniCallback, INTERFACE_NAME_ON_REMOVE);
}

static void UnregisterAddEvent(ani_env* env, ani_object aniCallback)
{
    UnregisterBundleChangedEvent(env, EVENT_TYPE_ADD, aniCallback, INTERFACE_NAME_OFF_ADD);
}

static void UnRegisterUpdateEvent(ani_env* env, ani_object aniCallback)
{
    UnregisterBundleChangedEvent(env, EVENT_TYPE_UPDATE, aniCallback, INTERFACE_NAME_OFF_UPDATE);
}

static void UnregisterRemoveEvent(ani_env* env, ani_object aniCallback)
{
    UnregisterBundleChangedEvent(env, EVENT_TYPE_REMOVE, aniCallback, INTERFACE_NAME_OFF_REMOVE);
}

static void InitializeBundleMonitor(ani_vm* vm)
{
    std::lock_guard<std::mutex> lock(g_aniBundleMonitorMutex);
    if (g_aniBundleMonitor != nullptr) {
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    g_aniBundleMonitor = std::make_shared<ANIBundleMonitorEventHandler>(vm, subscribeInfo);
    (void)EventFwk::CommonEventManager::SubscribeCommonEvent(g_aniBundleMonitor);
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace bundleMonitorNS =
        arkts::ani_signature::Builder::BuildNamespace(NS_NAME_BUNDLE_MONITOR);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(bundleMonitorNS.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_BUNDLE_MONITOR, status);
        return status;
    }
    std::array methods = {
        ani_native_function { INTERFACE_NAME_ON_ADD, nullptr, reinterpret_cast<void*>(RegisterAddEvent) },
        ani_native_function { INTERFACE_NAME_ON_UPDATE, nullptr, reinterpret_cast<void*>(RegisterUpdateEvent) },
        ani_native_function { INTERFACE_NAME_ON_REMOVE, nullptr, reinterpret_cast<void*>(RegisterRemoveEvent) },
        ani_native_function { INTERFACE_NAME_OFF_ADD, nullptr, reinterpret_cast<void*>(UnregisterAddEvent) },
        ani_native_function { INTERFACE_NAME_OFF_UPDATE, nullptr, reinterpret_cast<void*>(UnRegisterUpdateEvent) },
        ani_native_function { INTERFACE_NAME_OFF_REMOVE, nullptr, reinterpret_cast<void*>(UnregisterRemoveEvent) },
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE("Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_BUNDLE_MONITOR, status);
        return status;
    }

    *result = ANI_VERSION_1;

    InitializeBundleMonitor(vm);

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // namespace AppExecFwk
} // namespace OHOS
