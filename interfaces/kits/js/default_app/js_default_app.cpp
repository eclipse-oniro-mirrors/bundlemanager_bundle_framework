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

#include "js_default_app.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AAFwk;
namespace {
constexpr int32_t NO_ERROR = 0;
constexpr int32_t PARAM_TYPE_ERROR = 1;
constexpr int32_t EXECUTE_ERROR = 2;
constexpr int32_t NAPI_RETURN_ZERO = 0;
constexpr size_t ARGS_SIZE_FOUR = 4;
constexpr size_t ARGS_SIZE_ZERO = 0;
constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t ARGS_SIZE_THREE = 3;
constexpr int32_t NAPI_RETURN_ONE = 1;
}

DefaultAppInfo::DefaultAppInfo(napi_env napiEnv)
{
    env = napiEnv;
}

DefaultAppInfo::~DefaultAppInfo()
{
    if (callback) {
        napi_delete_reference(env, callback);
        callback = nullptr;
    }
    if (asyncWork) {
        napi_delete_async_work(env, asyncWork);
        asyncWork = nullptr;
    }
}

static OHOS::sptr<OHOS::AppExecFwk::IDefaultApp> GetDefaultAppProxy()
{
    auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        APP_LOGE("systemAbilityManager is null.");
        return nullptr;
    }
    auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleMgrSa == nullptr) {
        APP_LOGE("bundleMgrSa is null.");
        return nullptr;
    }
    auto bundleMgr = OHOS::iface_cast<IBundleMgr>(bundleMgrSa);
    if (bundleMgr == nullptr) {
        APP_LOGE("iface_cast failed.");
        return nullptr;
    }
    auto defaultAppProxy = bundleMgr->GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        APP_LOGE("GetDefaultAppProxy failed.");
        return nullptr;
    }
    return defaultAppProxy;
}

static void ParseString(napi_env env, napi_value value, std::string& result)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    if (valueType != napi_string) {
        APP_LOGE("ParseString type mismatch!");
        return;
    }
    size_t size = 0;
    if (napi_get_value_string_utf8(env, value, nullptr, NAPI_RETURN_ZERO, &size) != napi_ok) {
        APP_LOGE("napi_get_value_string_utf8 error.");
        return;
    }
    result.reserve(size + 1);
    result.resize(size);
    if (napi_get_value_string_utf8(env, value, result.data(), (size + 1), &size) != napi_ok) {
        APP_LOGE("napi_get_value_string_utf8 error");
    }
}

static void ParseElementName(napi_env env, napi_value args, Want &want)
{
    APP_LOGD("begin to parse ElementName.");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, args, &valueType);
    if (valueType != napi_object) {
        APP_LOGE("args not object type.");
        return;
    }
    napi_value prop = nullptr;
    napi_get_named_property(env, args, "bundleName", &prop);
    std::string bundleName;
    ParseString(env, prop, bundleName);

    prop = nullptr;
    napi_get_named_property(env, args, "moduleName", &prop);
    std::string moduleName;
    ParseString(env, prop, moduleName);

    prop = nullptr;
    napi_get_named_property(env, args, "abilityName", &prop);
    std::string abilityName;
    ParseString(env, prop, abilityName);

    APP_LOGD("ParseElementName, bundleName:%{public}s, moduleName: %{public}s, abilityName:%{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    ElementName elementName("", bundleName, abilityName, moduleName);
    want.SetElement(elementName);
}

static napi_value WrapVoidToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

static void ConvertAbilityInfo(napi_env env, napi_value objAbilityInfo, const AbilityInfo &abilityInfo)
{
    APP_LOGD("begin to ConvertAbilityInfo.");
    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "bundleName", nBundleName));

    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.moduleName.c_str(), NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "moduleName", nModuleName));

    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, abilityInfo.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "name", nName));

    napi_value nLabel;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, abilityInfo.label.c_str(), NAPI_AUTO_LENGTH, &nLabel));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "label", nLabel));

    napi_value nLabelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, abilityInfo.labelId, &nLabelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "labelId", nLabelId));

    napi_value nDescription;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.description.c_str(), NAPI_AUTO_LENGTH, &nDescription));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "description", nDescription));

    napi_value nDescriptionId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, abilityInfo.descriptionId, &nDescriptionId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "descriptionId", nDescriptionId));

    napi_value nIconPath;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.iconPath.c_str(), NAPI_AUTO_LENGTH, &nIconPath));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "icon", nIconPath));

    napi_value nIconId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, abilityInfo.iconId, &nIconId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "iconId", nIconId));
    APP_LOGD("ConvertAbilityInfo done.");
}

static void ConvertExtensionInfo(napi_env env, napi_value objExtensionInfo, const ExtensionAbilityInfo& extensionInfo)
{
    APP_LOGD("begin to ConvertExtensionInfo.");
    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, extensionInfo.bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, "bundleName", nBundleName));

    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, extensionInfo.moduleName.c_str(), NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, "moduleName", nModuleName));

    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, extensionInfo.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, "name", nName));

    napi_value nLabelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, extensionInfo.labelId, &nLabelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, "labelId", nLabelId));

    napi_value nDescriptionId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, extensionInfo.descriptionId, &nDescriptionId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, "descriptionId", nDescriptionId));

    napi_value nIconId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, extensionInfo.iconId, &nIconId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, "iconId", nIconId));
    APP_LOGD("ConvertExtensionInfo done.");
}

static void ConvertBundleInfo(napi_env env, napi_value objBundleInfo, const BundleInfo &bundleInfo)
{
    APP_LOGD("begin to ConvertBundleInfo.");
    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, bundleInfo.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "name", nName));

    napi_value nAbilityInfos;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nAbilityInfos));
    for (size_t idx = 0; idx < bundleInfo.abilityInfos.size(); idx++) {
        napi_value objAbilityInfo;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objAbilityInfo));
        ConvertAbilityInfo(env, objAbilityInfo, bundleInfo.abilityInfos[idx]);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nAbilityInfos, idx, objAbilityInfo));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "abilityInfos", nAbilityInfos));

    napi_value nExtensionAbilityInfos;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nExtensionAbilityInfos));
    for (size_t idx = 0; idx < bundleInfo.extensionInfos.size(); idx++) {
        napi_value objExtensionInfo;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objExtensionInfo));
        ConvertExtensionInfo(env, objExtensionInfo, bundleInfo.extensionInfos[idx]);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nExtensionAbilityInfos, idx, objExtensionInfo));
    }
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(env, objBundleInfo, "extensionAbilityInfo", nExtensionAbilityInfos));
    APP_LOGD("ConvertBundleInfo done.");
}

static bool InnerIsDefaultApplication(napi_env env, const std::string& type)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        APP_LOGE("defaultAppProxy is null.");
        return false;
    }
    return defaultAppProxy->IsDefaultApplication(type);
}

static bool InnerGetDefaultApplication(napi_env env, int32_t userId, const std::string& type, BundleInfo& bundleInfo)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        APP_LOGE("defaultAppProxy is null.");
        return false;
    }
    return defaultAppProxy->GetDefaultApplication(userId, type, bundleInfo);
}

static bool InnerSetDefaultApplication(napi_env env, int32_t userId, const std::string& type, const Want& want)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        APP_LOGE("defaultAppProxy is null.");
        return false;
    }
    return defaultAppProxy->SetDefaultApplication(userId, type, want);
}

static bool InnerResetDefaultApplication(napi_env env, int32_t userId, const std::string& type)
{
    auto defaultAppProxy = GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        APP_LOGE("defaultAppProxy is null.");
        return false;
    }
    return defaultAppProxy->ResetDefaultApplication(userId, type);
}

napi_value IsDefaultApplication(napi_env env, napi_callback_info info)
{
    APP_LOGD("begin to call NAPI IsDefaultApplication.");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    APP_LOGD("argc = [%{public}zu]", argc);
    if (argc > ARGS_SIZE_TWO) {
        APP_LOGE("param count invalid.");
        return WrapVoidToJS(env);
    }
    DefaultAppInfo *asyncCallbackInfo = new (std::nothrow) DefaultAppInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return WrapVoidToJS(env);
    }
    std::unique_ptr<DefaultAppInfo> callbackPtr {asyncCallbackInfo};

    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if ((i == ARGS_SIZE_ZERO) && (valueType == napi_string)) {
            ParseString(env, argv[i], asyncCallbackInfo->type);
        } else if ((i == ARGS_SIZE_ONE) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
        }
    }
    if (argc == ARGS_SIZE_ZERO) {
        APP_LOGE("param is zero.");
        asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
    }
    napi_value promise = nullptr;
    if (asyncCallbackInfo->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncCallbackInfo->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env,  &promise));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "IsDefaultApplication", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            DefaultAppInfo *asyncCallbackInfo = (DefaultAppInfo *)data;
            if (asyncCallbackInfo->errCode == NO_ERROR) {
                asyncCallbackInfo->result = InnerIsDefaultApplication(env, asyncCallbackInfo->type);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            DefaultAppInfo *asyncCallbackInfo = (DefaultAppInfo *)data;
            std::unique_ptr<DefaultAppInfo> callbackPtr {asyncCallbackInfo};
            napi_value result[2] = { 0 };
            if (asyncCallbackInfo->errCode != NO_ERROR) {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(asyncCallbackInfo->errCode),
                    &result[0]));
                NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, "type mismatch",
                    NAPI_AUTO_LENGTH, &result[1]));
            } else {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
                NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncCallbackInfo->result, &result[1]));
            }
            if (asyncCallbackInfo->deferred) {
                if (asyncCallbackInfo->errCode == NO_ERROR) {
                    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[1]));
                } else {
                    NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
                }
            } else {
                napi_value callback = nullptr;
                napi_value placeHolder = nullptr;
                NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
                NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
                    sizeof(result) / sizeof(result[0]), result, &placeHolder));
            }
        },
        (void*)asyncCallbackInfo, &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    callbackPtr.release();
    APP_LOGD("call IsDefaultApplication done.");
    return promise;
}

napi_value GetDefaultApplication(napi_env env, napi_callback_info info)
{
    APP_LOGI("begin to GetDefaultApplication.");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    APP_LOGD("argc = [%{public}zu]", argc);
    if (argc > ARGS_SIZE_THREE) {
        APP_LOGE("param count invalid.");
        return WrapVoidToJS(env);
    }
    DefaultAppInfo *asyncCallbackInfo = new (std::nothrow) DefaultAppInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return WrapVoidToJS(env);
    }
    std::unique_ptr<DefaultAppInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;

    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if ((i == ARGS_SIZE_ZERO) && (valueType == napi_string)) {
            ParseString(env, argv[i], asyncCallbackInfo->type);
        } else if (i == ARGS_SIZE_ONE) {
            if (valueType == napi_number) {
                napi_get_value_int32(env, argv[i], &asyncCallbackInfo->userId);
            } else if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
            }
        } else if ((i == ARGS_SIZE_TWO) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
        }
    }
    if (argc == ARGS_SIZE_ZERO) {
        APP_LOGE("param is zero.");
        asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
    }
    napi_value promise = nullptr;
    if (asyncCallbackInfo->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncCallbackInfo->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env,  &promise));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetDefaultApplication", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            DefaultAppInfo *asyncCallbackInfo = (DefaultAppInfo *)data;
            if (asyncCallbackInfo->errCode == NO_ERROR) {
                asyncCallbackInfo->result = InnerGetDefaultApplication(env, asyncCallbackInfo->userId,
                    asyncCallbackInfo->type, asyncCallbackInfo->bundleInfo);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            DefaultAppInfo *asyncCallbackInfo = (DefaultAppInfo *)data;
            std::unique_ptr<DefaultAppInfo> callbackPtr {asyncCallbackInfo};
            napi_value result[2] = { 0 };
            if (asyncCallbackInfo->errCode != NO_ERROR) {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(asyncCallbackInfo->errCode),
                    &result[0]));
                NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, "type mismatch",
                    NAPI_AUTO_LENGTH, &result[1]));
            } else {
                if (asyncCallbackInfo->result) {
                    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
                    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[1]));
                    ConvertBundleInfo(env, result[1], asyncCallbackInfo->bundleInfo);
                } else {
                    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, EXECUTE_ERROR, &result[0]));
                    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
                }
            }
            if (asyncCallbackInfo->deferred) {
                if (asyncCallbackInfo->result) {
                    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[1]));
                } else {
                    NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
                }
            } else {
                napi_value callback = nullptr;
                napi_value placeHolder = nullptr;
                NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
                NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
                    sizeof(result) / sizeof(result[0]), result, &placeHolder));
            }
        },
        (void*)asyncCallbackInfo, &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    callbackPtr.release();
    APP_LOGI("call GetDefaultApplication done.");
    return promise;
}

napi_value SetDefaultApplication(napi_env env, napi_callback_info info)
{
    APP_LOGI("begin to SetDefaultApplication.");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    APP_LOGD("argc = [%{public}zu]", argc);
    if (argc > ARGS_SIZE_FOUR) {
        APP_LOGE("param count invalid.");
        return WrapVoidToJS(env);
    }
    DefaultAppInfo *asyncCallbackInfo = new (std::nothrow) DefaultAppInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return WrapVoidToJS(env);
    }
    std::unique_ptr<DefaultAppInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;

    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if ((i == ARGS_SIZE_ZERO) && (valueType == napi_string)) {
            ParseString(env, argv[i], asyncCallbackInfo->type);
        } else if ((i == ARGS_SIZE_ONE) && (valueType == napi_object)) {
            ParseElementName(env, argv[i], asyncCallbackInfo->want);
        } else if (i == ARGS_SIZE_TWO) {
            if (valueType == napi_number) {
                napi_get_value_int32(env, argv[i], &asyncCallbackInfo->userId);
            } else if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
            }
        } else if ((i == ARGS_SIZE_THREE) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
        }
    }
    if (argc < ARGS_SIZE_TWO) {
        APP_LOGE("param less than 2.");
        asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
    }
    napi_value promise = nullptr;
    if (asyncCallbackInfo->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncCallbackInfo->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env,  &promise));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "SetDefaultApplication", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            DefaultAppInfo *asyncCallbackInfo = (DefaultAppInfo *)data;
            if (asyncCallbackInfo->errCode == NO_ERROR) {
                asyncCallbackInfo->result = InnerSetDefaultApplication(env, asyncCallbackInfo->userId,
                    asyncCallbackInfo->type, asyncCallbackInfo->want);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            DefaultAppInfo *asyncCallbackInfo = (DefaultAppInfo *)data;
            std::unique_ptr<DefaultAppInfo> callbackPtr {asyncCallbackInfo};
            if (asyncCallbackInfo->errCode == NO_ERROR && !asyncCallbackInfo->result) {
                asyncCallbackInfo->errCode = EXECUTE_ERROR;
            }
            napi_value result[1] = { 0 };
            if (asyncCallbackInfo->errCode != NO_ERROR) {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(asyncCallbackInfo->errCode),
                    &result[0]));
            }
            if (asyncCallbackInfo->deferred) {
                if (asyncCallbackInfo->errCode == NO_ERROR) {
                    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[0]));
                    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[0]));
                } else {
                    NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
                }
            } else {
                napi_value callback = nullptr;
                napi_value placeHolder = nullptr;
                NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
                NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
                    sizeof(result) / sizeof(result[0]), result, &placeHolder));
            }
        },
        (void*)asyncCallbackInfo, &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    callbackPtr.release();
    APP_LOGI("call SetDefaultApplication done.");
    return promise;
}

napi_value ResetDefaultApplication(napi_env env, napi_callback_info info)
{
    APP_LOGI("begin to ResetDefaultApplication.");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    APP_LOGD("argc = [%{public}zu]", argc);
    if (argc > ARGS_SIZE_THREE) {
        APP_LOGE("param count invalid.");
        return WrapVoidToJS(env);
    }
    DefaultAppInfo *asyncCallbackInfo = new (std::nothrow) DefaultAppInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null.");
        return WrapVoidToJS(env);
    }
    std::unique_ptr<DefaultAppInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;

    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if ((i == ARGS_SIZE_ZERO) && (valueType == napi_string)) {
            ParseString(env, argv[i], asyncCallbackInfo->type);
        } else if (i == ARGS_SIZE_ONE) {
            if (valueType == napi_number) {
                napi_get_value_int32(env, argv[i], &asyncCallbackInfo->userId);
            } else if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            } else {
                asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
            }
        } else if ((i == ARGS_SIZE_TWO) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
        }
    }
    if (argc == ARGS_SIZE_ZERO) {
        APP_LOGE("param is zero.");
        asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
    }
    napi_value promise = nullptr;
    if (asyncCallbackInfo->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncCallbackInfo->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env,  &promise));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "ResetDefaultApplication", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            DefaultAppInfo *asyncCallbackInfo = (DefaultAppInfo *)data;
            if (asyncCallbackInfo->errCode == NO_ERROR) {
                asyncCallbackInfo->result = InnerResetDefaultApplication(env, asyncCallbackInfo->userId,
                    asyncCallbackInfo->type);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            DefaultAppInfo *asyncCallbackInfo = (DefaultAppInfo *)data;
            std::unique_ptr<DefaultAppInfo> callbackPtr {asyncCallbackInfo};
            if (asyncCallbackInfo->errCode == NO_ERROR && !asyncCallbackInfo->result) {
                asyncCallbackInfo->errCode = EXECUTE_ERROR;
            }
            napi_value result[1] = { 0 };
            if (asyncCallbackInfo->errCode != NO_ERROR) {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(asyncCallbackInfo->errCode),
                    &result[0]));
            }
            if (asyncCallbackInfo->deferred) {
                if (asyncCallbackInfo->errCode == NO_ERROR) {
                    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[0]));
                    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[0]));
                } else {
                    NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
                }
            } else {
                napi_value callback = nullptr;
                napi_value placeHolder = nullptr;
                NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
                NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
                    sizeof(result) / sizeof(result[0]), result, &placeHolder));
            }
        },
        (void*)asyncCallbackInfo, &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    callbackPtr.release();
    APP_LOGI("call ResetDefaultApplication done.");
    return promise;
}
}
}
