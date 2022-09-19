/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "bundle_monitor.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error.h"
#include "bundle_monitor_callback.h"
#include "common_func.h"
#include "common_event_subscribe_info.h"
#include "common_event_support.h"
#include "matching_skills.h"
#include "ipc_skeleton.h"
#include "napi_arg.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<BundleMonitorCallback> g_bundleMonitor = nullptr;

napi_value Register(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi begin to BundleMonitorOn");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_TWO)) {
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string type;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], type)) {
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    napi_valuetype callbackType = napi_undefined;
    napi_typeof(env, args[ARGS_POS_ONE], &callbackType);
    if (callbackType != napi_function) {
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    if (!iBundleMgr->VerifyCallingPermission(Constants::LISTEN_BUNDLE_CHANGE)) {
        APP_LOGE("register bundle status callback failed due to lack of permission");
        BusinessError::ThrowError(env, ERROR_PERMISSION_DENIED_ERROR);
        return nullptr;
    }
    g_bundleMonitor->BundleMonitorOn(env, args[ARGS_POS_ONE], type);
    return nullptr;
}

napi_value Unregister(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi begin to BundleMonitorOff");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    std::string type;
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], type)) {
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return nullptr;
    }
    if (!iBundleMgr->VerifyCallingPermission(Constants::LISTEN_BUNDLE_CHANGE)) {
        APP_LOGE("register bundle status callback failed due to lack of permission");
        BusinessError::ThrowError(env, ERROR_PERMISSION_DENIED_ERROR);
        return nullptr;
    }
    // parse callback
    if (args.GetMaxArgc() >= ARGS_SIZE_TWO) {
        napi_valuetype callbackType = napi_undefined;
        napi_typeof(env, args[ARGS_POS_ONE], &callbackType);
        if (callbackType != napi_function) {
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }

        if (g_bundleMonitor == nullptr) {
            APP_LOGE("register callback first!");
            BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR);
            return nullptr;
        }
        g_bundleMonitor->BundleMonitorOff(env, args[ARGS_POS_ONE], type);
        return nullptr;
    }
    g_bundleMonitor->BundleMonitorOff(env, type);
    return nullptr;
}

static napi_value BundleMonitorExport(napi_env env, napi_value exports)
{
    APP_LOGD("BundleMonitorExport Enter");
    static napi_property_descriptor bundleMonitorDesc[] = {
        DECLARE_NAPI_FUNCTION("on", Register),
        DECLARE_NAPI_FUNCTION("off", Unregister),
    };
    NAPI_CALL(env, napi_define_properties(env, exports,
        sizeof(bundleMonitorDesc) / sizeof(bundleMonitorDesc[0]), bundleMonitorDesc));
    if (g_bundleMonitor == nullptr) {
        EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
        EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
        g_bundleMonitor = std::make_shared<BundleMonitorCallback>(subscribeInfo);
        EventFwk::CommonEventManager::SubscribeCommonEvent(g_bundleMonitor);
    }
    APP_LOGD("BundleMonitorExport finish");
    return exports;
}

static napi_module bundleMonitorModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = BundleMonitorExport,
    .nm_modname = "bundle.bundleMonitor",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void BundleMonitorRegister()
{
    napi_module_register(&bundleMonitorModule);
}

}
}