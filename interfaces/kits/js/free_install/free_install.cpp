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
#include "free_install.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error.h"
#include "common_func.h"
#include "napi_arg.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
enum class UpgradeFlag {
    NOT_UPGRADE = 0,
    SINGLE_UPGRADE = 1,
    RELATION_UPGRADE = 2,
};
const std::vector<int32_t> BUNDLE_PACK_FLAGS = {
    BundlePackFlag::GET_PACK_INFO_ALL,
    BundlePackFlag::GET_PACKAGES,
    BundlePackFlag::GET_BUNDLE_SUMMARY,
    BundlePackFlag::GET_MODULE_SUMMARY,
};
const std::string RESOURCE_NAME_OF_IS_HAP_MODULE_REMOVABLE = "isHapModuleRemovable";
const std::string RESOURCE_NAME_OF_SET_HAP_MODULE_UPGRADE_FLAG = "setHapModuleUpgradeFlag";
const std::string RESOURCE_NAME_OF_GET_BUNDLE_PACK_INFO = "getBundlePackInfo";
const std::string RESOURCE_NAME_OF_GET_DISPATCH_INFO = "getDispatchInfo";
const std::string DISPATCH_INFO_VERSION = "1";
const std::string DISPATCH_INFO_DISPATCH_API = "1.0";
const std::string BUNDLE_NAME = "bundleName";
const std::string MODULE_NAME = "moduleName";
const std::string UPGRADE_FLAG = "upgradeFlag";
const std::string BUNDLE_PACK_FLAG = "bundlePackFlag";
}

static ErrCode InnerIsHapModuleRemovable(const std::string &bundleName,
    const std::string &moduleName, bool &isRemovable)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto result = iBundleMgr->IsModuleRemovable(bundleName, moduleName, isRemovable);
    if (result != ERR_OK) {
        APP_LOGE("InnerIsHapModuleRemovable::IsModuleRemovable failed");
    }
    return CommonFunc::ConvertErrCode(result);
}

void IsHapModuleRemovableExec(napi_env env, void *data)
{
    HapModuleRemovableCallbackInfo *asyncCallbackInfo = reinterpret_cast<HapModuleRemovableCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerIsHapModuleRemovable(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->moduleName, asyncCallbackInfo->result);
}

void IsHapModuleRemovableComplete(napi_env env, napi_status status, void *data)
{
    HapModuleRemovableCallbackInfo *asyncCallbackInfo = reinterpret_cast<HapModuleRemovableCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<HapModuleRemovableCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncCallbackInfo->result, &result[ARGS_SIZE_ONE]));
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            RESOURCE_NAME_OF_IS_HAP_MODULE_REMOVABLE, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_SIZE_ONE]));
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == SUCCESS) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[ARGS_SIZE_ONE]));
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
}

napi_value IsHapModuleRemovable(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_IsHapModuleRemovable start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("param count invalid.");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    HapModuleRemovableCallbackInfo *asyncCallbackInfo = new (std::nothrow) HapModuleRemovableCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<HapModuleRemovableCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (args.GetMaxArgc() >= ARGS_SIZE_TWO) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], asyncCallbackInfo->moduleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (args.GetMaxArgc() == ARGS_SIZE_THREE) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[ARGS_POS_TWO], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_TWO],
                    NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    } else {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<HapModuleRemovableCallbackInfo>(
        env, asyncCallbackInfo, RESOURCE_NAME_OF_IS_HAP_MODULE_REMOVABLE,
        IsHapModuleRemovableExec, IsHapModuleRemovableComplete);
    callbackPtr.release();
    APP_LOGD("call IsHapModuleRemovable done");
    return promise;
}

static ErrCode InnerSetHapModuleUpgradeFlag(const std::string &bundleName,
    const std::string &moduleName, int32_t upgradeFlag)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto result = iBundleMgr->SetModuleUpgradeFlag(bundleName, moduleName, upgradeFlag);
    if (result != ERR_OK) {
        APP_LOGE("InnerSetHapModuleUpgradeFlag::SetModuleUpgradeFlag failed");
    }
    return CommonFunc::ConvertErrCode(result);
}

void SetHapModuleUpgradeFlagExec(napi_env env, void *data)
{
    SetHapModuleUpgradeFlagCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<SetHapModuleUpgradeFlagCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerSetHapModuleUpgradeFlag(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->moduleName, asyncCallbackInfo->upgradeFlag);
}

void SetHapModuleUpgradeFlagComplete(napi_env env, napi_status status, void *data)
{
    SetHapModuleUpgradeFlagCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<SetHapModuleUpgradeFlagCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<SetHapModuleUpgradeFlagCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_ONE] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            RESOURCE_NAME_OF_SET_HAP_MODULE_UPGRADE_FLAG, Constants::PERMISSION_INSTALL_BUNDLE);
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == SUCCESS) {
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
}

napi_value SetHapModuleUpgradeFlag(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_SetHapModuleUpgradeFlag start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FOUR)) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    SetHapModuleUpgradeFlagCallbackInfo *asyncCallbackInfo =
        new (std::nothrow) SetHapModuleUpgradeFlagCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<SetHapModuleUpgradeFlagCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (args.GetMaxArgc() >= ARGS_SIZE_THREE) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], asyncCallbackInfo->moduleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, MODULE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_TWO], asyncCallbackInfo->upgradeFlag)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, UPGRADE_FLAG, TYPE_NUMBER);
            return nullptr;
        }
        if (args.GetMaxArgc() == ARGS_SIZE_FOUR) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[ARGS_POS_THREE], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_THREE],
                    NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    } else {
        APP_LOGE("parameters error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<SetHapModuleUpgradeFlagCallbackInfo>(
        env, asyncCallbackInfo, RESOURCE_NAME_OF_SET_HAP_MODULE_UPGRADE_FLAG,
        SetHapModuleUpgradeFlagExec, SetHapModuleUpgradeFlagComplete);
    callbackPtr.release();
    APP_LOGD("call SetHapModuleUpgradeFlag done");
    return promise;
}

void CreateUpgradeFlagObject(napi_env env, napi_value value)
{
    napi_value nNotUpgrade;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(UpgradeFlag::NOT_UPGRADE), &nNotUpgrade));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "NOT_UPGRADE", nNotUpgrade));

    napi_value nSingleUpgrade;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(UpgradeFlag::SINGLE_UPGRADE), &nSingleUpgrade));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SINGLE_UPGRADE", nSingleUpgrade));

    napi_value nRelationUpgrade;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(UpgradeFlag::RELATION_UPGRADE), &nRelationUpgrade));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "RELATION_UPGRADE", nRelationUpgrade));
}

void CreateBundlePackFlagObject(napi_env env, napi_value value)
{
    napi_value nGetPackInfoAll;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(BundlePackFlag::GET_PACK_INFO_ALL),
        &nGetPackInfoAll));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_PACK_INFO_ALL", nGetPackInfoAll));

    napi_value nGetPackages;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(BundlePackFlag::GET_PACKAGES),
        &nGetPackages));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_PACKAGES", nGetPackages));

    napi_value nGetBundleSummary;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(BundlePackFlag::GET_BUNDLE_SUMMARY),
        &nGetBundleSummary));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_BUNDLE_SUMMARY", nGetBundleSummary));

    napi_value nGetModuleSummary;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(BundlePackFlag::GET_MODULE_SUMMARY),
        &nGetModuleSummary));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "GET_MODULE_SUMMARY", nGetModuleSummary));
}

static void ConvertSummaryApp(napi_env env, napi_value &app, const BundlePackInfo &bundlePackInfo)
{
    napi_value bundleName;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_string_utf8(env, bundlePackInfo.summary.app.bundleName.c_str(), NAPI_AUTO_LENGTH, &bundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, app, "bundleName", bundleName));
    napi_value version;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &version));
    napi_value versionName;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_string_utf8(env, bundlePackInfo.summary.app.version.name.c_str(), NAPI_AUTO_LENGTH, &versionName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, version, "name", versionName));
    napi_value versionCode;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, bundlePackInfo.summary.app.version.code, &versionCode));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, version, "code", versionCode));
    napi_value minCompatibleVersionCode;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, bundlePackInfo.summary.app.version.minCompatibleVersionCode, &minCompatibleVersionCode));
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, version, "minCompatibleVersionCode", minCompatibleVersionCode));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, app, "version", version));
}

static void ConvertModulesApiVersion(
    napi_env env, napi_value &modulesObject, const OHOS::AppExecFwk::PackageModule &module)
{
    napi_value apiVersion;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &apiVersion));
    napi_value releaseType;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, module.apiVersion.releaseType.c_str(), NAPI_AUTO_LENGTH, &releaseType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, apiVersion, "releaseType", releaseType));
    napi_value compatible;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, module.apiVersion.compatible, &compatible));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, apiVersion, "compatible", compatible));
    napi_value target;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, module.apiVersion.target, &target));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, apiVersion, "target", target));

    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, modulesObject, "apiVersion", apiVersion));
}

static void ConvertDeviceType(napi_env env, napi_value &Object, std::vector<std::string> deviceTypes)
{
    napi_value nDeviceTypes;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nDeviceTypes));
    size_t typeIndex = 0;
    for (const auto &type : deviceTypes) {
        napi_value typeValue;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, type.c_str(), NAPI_AUTO_LENGTH, &typeValue));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nDeviceTypes, typeIndex, typeValue));
        typeIndex++;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, Object, "deviceTypes", nDeviceTypes));
}

static void ConvertDistro(napi_env env, napi_value &modulesObject, const PackageModule &module)
{
    napi_value distro;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &distro));
    napi_value deliveryWithInstall;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, module.distro.deliveryWithInstall, &deliveryWithInstall));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, distro, "deliveryWithInstall", deliveryWithInstall));
    napi_value installationFree;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, module.distro.installationFree, &installationFree));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, distro, "installationFree", installationFree));
    napi_value moduleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, module.distro.moduleName.c_str(), NAPI_AUTO_LENGTH, &moduleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, distro, "moduleName", moduleName));
    napi_value moduleType;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, module.distro.moduleType.c_str(), NAPI_AUTO_LENGTH, &moduleType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, distro, "moduleType", moduleType));

    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, modulesObject, "distro", distro));
}

static void ConvertFormsInfo(napi_env env, napi_value &abilityObject,
    const std::vector<OHOS::AppExecFwk::AbilityFormInfo> &forms)
{
    napi_value formsArray;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &formsArray));
    size_t index = 0;
    for (const auto &form : forms) {
        napi_value formObject;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &formObject));
        napi_value name;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, form.name.c_str(), NAPI_AUTO_LENGTH, &name));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, formObject, "name", name));
        napi_value type;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, form.type.c_str(), NAPI_AUTO_LENGTH, &type));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, formObject, "type", type));
        napi_value updateEnabled;
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, form.updateEnabled, &updateEnabled));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, formObject, "updateEnabled", updateEnabled));
        napi_value scheduledUpdateTime;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, form.scheduledUpdateTime.c_str(),
            NAPI_AUTO_LENGTH, &scheduledUpdateTime));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, formObject, "scheduledUpdateTime",
            scheduledUpdateTime));
        napi_value updateDuration;
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, form.updateDuration, &updateDuration));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, formObject, "updateDuration", updateDuration));
        napi_value supportDimensions;
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &supportDimensions));
        size_t indexValue = 0;
        for (const auto &dimension : form.supportDimensions) {
            napi_value value;
            NAPI_CALL_RETURN_VOID(
                env, napi_create_string_utf8(env, dimension.c_str(), NAPI_AUTO_LENGTH, &value));
            NAPI_CALL_RETURN_VOID(env, napi_set_element(env, supportDimensions, indexValue, value));
            indexValue++;
        }
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, formObject, "supportDimensions", supportDimensions));
        napi_value defaultDimension;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, form.defaultDimension.c_str(), NAPI_AUTO_LENGTH, &defaultDimension));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, formObject, "defaultDimension", defaultDimension));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, formsArray, index, formObject));
        index++;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, abilityObject, "forms", formsArray));
}

static void ConvertAbilities(napi_env env, napi_value &modulesObject, const PackageModule &module)
{
    napi_value abilities;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &abilities));
    size_t index = 0;
    for (const auto &ability : module.abilities) {
        napi_value abilityObject;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &abilityObject));
        napi_value name;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, ability.name.c_str(), NAPI_AUTO_LENGTH, &name));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, abilityObject, "name", name));
        napi_value label;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, ability.label.c_str(), NAPI_AUTO_LENGTH, &label));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, abilityObject, "label", label));
        napi_value visible;
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, ability.visible, &visible));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, abilityObject, "visible", visible));
        napi_value nExported;
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, ability.visible, &nExported));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, abilityObject, "exported", nExported));
        ConvertFormsInfo(env, abilityObject, ability.forms);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, abilities, index, abilityObject));
        index++;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, modulesObject, "abilities", abilities));
}

static void ConvertExtensionAbilities(
    napi_env env, napi_value &modulesObject, const OHOS::AppExecFwk::PackageModule &module)
{
    napi_value extensionAbilities;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &extensionAbilities));
    size_t index = 0;
    for (const auto &extensionAbility : module.extensionAbilities) {
        napi_value abilityObject;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &abilityObject));
        napi_value name;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, extensionAbility.name.c_str(), NAPI_AUTO_LENGTH, &name));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, abilityObject, "name", name));
        ConvertFormsInfo(env, abilityObject, extensionAbility.forms);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, extensionAbilities, index, abilityObject));
        index++;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, modulesObject, "extensionAbilities", extensionAbilities));
}

static void ConvertSummaryModules(
    napi_env env, napi_value &modulesArray, const BundlePackInfo &bundlePackInfo)
{
    size_t index = 0;
    for (const auto &module : bundlePackInfo.summary.modules) {
        napi_value modulesObject;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &modulesObject));
        napi_value mainAbility;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, module.mainAbility.c_str(), NAPI_AUTO_LENGTH, &mainAbility));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, modulesObject, "mainAbility", mainAbility));
        ConvertModulesApiVersion(env, modulesObject, module);
        ConvertDeviceType(env, modulesObject, module.deviceType);
        ConvertDistro(env, modulesObject, module);
        ConvertAbilities(env, modulesObject, module);
        ConvertExtensionAbilities(env, modulesObject, module);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, modulesArray, index, modulesObject));
        index++;
    }
}

static void ConvertPackageSummary(
    napi_env env, napi_value &jsSummary, const BundlePackInfo &bundlePackInfo)
{
    napi_value app;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &app));
    ConvertSummaryApp(env, app, bundlePackInfo);
    napi_value modules;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &modules));
    ConvertSummaryModules(env, modules, bundlePackInfo);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, jsSummary, "app", app));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, jsSummary, "modules", modules));
}

static void ConvertPackages(
    napi_env env, napi_value &jsPackagesArray, const BundlePackInfo &bundlePackInfo)
{
    size_t index = 0;
    for (const auto &package : bundlePackInfo.packages) {
        napi_value jsPackagesObject;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &jsPackagesObject));
        ConvertDeviceType(env, jsPackagesObject, package.deviceType);
        napi_value packageName;
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, package.name.c_str(), NAPI_AUTO_LENGTH, &packageName));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, jsPackagesObject, "name", packageName));
        napi_value moduleType;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, package.moduleType.c_str(), NAPI_AUTO_LENGTH, &moduleType));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, jsPackagesObject, "moduleType", moduleType));
        napi_value deliveryWithInstall;
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, package.deliveryWithInstall, &deliveryWithInstall));
        NAPI_CALL_RETURN_VOID(
            env, napi_set_named_property(env, jsPackagesObject, "deliveryWithInstall", deliveryWithInstall));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, jsPackagesArray, index, jsPackagesObject));
        index++;
    }
}

static void ConvertBundlePackInfo(
    napi_env env, napi_value &result, int32_t flag, const BundlePackInfo &bundlePackInfo)
{
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result));
    if (static_cast<uint32_t>(flag) & BundlePackFlag::GET_PACKAGES) {
        napi_value jsPackagesArray;
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &jsPackagesArray));
        ConvertPackages(env, jsPackagesArray, bundlePackInfo);
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "packages", jsPackagesArray));
        return;
    }
    if (static_cast<uint32_t>(flag) & BundlePackFlag::GET_BUNDLE_SUMMARY) {
        napi_value jsSummary;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &jsSummary));
        ConvertPackageSummary(env, jsSummary, bundlePackInfo);
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "summary", jsSummary));
        return;
    }
    if (static_cast<uint32_t>(flag) & BundlePackFlag::GET_MODULE_SUMMARY) {
        napi_value jsSummary;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &jsSummary));
        napi_value modules;
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &modules));
        ConvertSummaryModules(env, modules, bundlePackInfo);
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, jsSummary, "modules", modules));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "summary", jsSummary));
        return;
    }
    napi_value jsSummary;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &jsSummary));
    ConvertPackageSummary(env, jsSummary, bundlePackInfo);
    napi_value jsPackagesArray;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &jsPackagesArray));
    ConvertPackages(env, jsPackagesArray, bundlePackInfo);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "packages", jsPackagesArray));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "summary", jsSummary));
}

static ErrCode InnerGetBundlePackInfo(const std::string &bundleName, int32_t flags, BundlePackInfo &bundlePackInfo)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    auto ret = iBundleMgr->GetBundlePackInfo(bundleName, flags, bundlePackInfo);
    if (ret != ERR_OK) {
        APP_LOGE("InnerGetBundlePackInfo failed");
    }
    return CommonFunc::ConvertErrCode(ret);
}

void GetBundlePackInfoExec(napi_env env, void *data)
{
    GetBundlePackInfoCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<GetBundlePackInfoCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerGetBundlePackInfo(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->bundlePackFlag, asyncCallbackInfo->bundlePackInfo);
}

void GetBundlePackInfoComplete(napi_env env, napi_status status, void *data)
{
    GetBundlePackInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetBundlePackInfoCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<GetBundlePackInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        ConvertBundlePackInfo(env, result[ARGS_SIZE_ONE],
            asyncCallbackInfo->bundlePackFlag, asyncCallbackInfo->bundlePackInfo);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            RESOURCE_NAME_OF_GET_BUNDLE_PACK_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_SIZE_ONE]));
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == SUCCESS) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[ARGS_SIZE_ONE]));
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
}

napi_value GetBundlePackInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_GetBundlePackInfo start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    GetBundlePackInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetBundlePackInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<GetBundlePackInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (args.GetMaxArgc() >= ARGS_SIZE_TWO) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_NAME, TYPE_STRING);
            return nullptr;
        }
        if (!CommonFunc::ParseInt(env, args[ARGS_POS_ONE], asyncCallbackInfo->bundlePackFlag)) {
            BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_PACK_FLAG, TYPE_NUMBER);
            return nullptr;
        }
        if (args.GetMaxArgc() == ARGS_SIZE_THREE) {
            napi_valuetype valueType = napi_undefined;
            napi_typeof(env, args[ARGS_POS_TWO], &valueType);
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_TWO],
                    NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
        }
    } else {
        APP_LOGE("parameters error");
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    if (std::find(BUNDLE_PACK_FLAGS.begin(), BUNDLE_PACK_FLAGS.end(), asyncCallbackInfo->bundlePackFlag) ==
        BUNDLE_PACK_FLAGS.end()) {
        BusinessError::ThrowParameterTypeError(env, ERROR_PARAM_CHECK_ERROR, BUNDLE_PACK_FLAG, "BundlePackFlag");
        return nullptr;
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetBundlePackInfoCallbackInfo>(
        env, asyncCallbackInfo, RESOURCE_NAME_OF_GET_BUNDLE_PACK_INFO,
        GetBundlePackInfoExec, GetBundlePackInfoComplete);
    callbackPtr.release();
    APP_LOGD("call GetBundlePackInfo end");
    return promise;
}

static void ConvertDispatcherVersion(
    napi_env env, napi_value &value, const std::string &version, const std::string &dispatchAPI)
{
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &value));
    napi_value napiVersion;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, version.c_str(), NAPI_AUTO_LENGTH, &napiVersion));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "version", napiVersion));
    napi_value napiDispatchAPIVersion;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, dispatchAPI.c_str(), NAPI_AUTO_LENGTH,
        &napiDispatchAPIVersion));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "dispatchAPIVersion", napiDispatchAPIVersion));
}

static ErrCode InnerGetDispatchInfo(std::string &version, std::string &dispatchAPI)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    if (!iBundleMgr->VerifySystemApi(Constants::INVALID_API_VERSION)) {
        APP_LOGE("non-system app calling system api");
        return ERROR_NOT_SYSTEM_APP;
    }
    if (!iBundleMgr->VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("GetDispatchInfo failed due to permission denied");
        return ERROR_PERMISSION_DENIED_ERROR;
    }
    version = DISPATCH_INFO_VERSION;
    dispatchAPI = DISPATCH_INFO_DISPATCH_API;
    return SUCCESS;
}

void GetDispatchInfoExec(napi_env env, void *data)
{
    GetDispatchInfoCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<GetDispatchInfoCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s, asyncCallbackInfo == nullptr.", __func__);
        return;
    }
    asyncCallbackInfo->err = InnerGetDispatchInfo(asyncCallbackInfo->version, asyncCallbackInfo->dispatchAPI);
}

void GetDispatchInfoComplete(napi_env env, napi_status status, void *data)
{
    GetDispatchInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetDispatchInfoCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null in %{public}s", __func__);
        return;
    }
    std::unique_ptr<GetDispatchInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err == SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[0]));
        ConvertDispatcherVersion(env, result[ARGS_SIZE_ONE],
            asyncCallbackInfo->version, asyncCallbackInfo->dispatchAPI);
    } else {
        result[0] = BusinessError::CreateCommonError(env, asyncCallbackInfo->err,
            RESOURCE_NAME_OF_GET_DISPATCH_INFO, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[ARGS_SIZE_ONE]));
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == SUCCESS) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[ARGS_SIZE_ONE]));
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
}

napi_value GetDispatchInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_GetDispatchInfo start");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ZERO, ARGS_SIZE_ONE)) {
        BusinessError::ThrowTooFewParametersError(env, ERROR_PARAM_CHECK_ERROR);
        return nullptr;
    }
    GetDispatchInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetDispatchInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<GetDispatchInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (args.GetMaxArgc() >= ARGS_SIZE_ONE) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[ARGS_POS_ZERO], &valueType);
        if (valueType == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_ZERO],
                NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetDispatchInfoCallbackInfo>(
        env, asyncCallbackInfo, RESOURCE_NAME_OF_GET_DISPATCH_INFO,
        GetDispatchInfoExec, GetDispatchInfoComplete);
    callbackPtr.release();
    APP_LOGD("call GetDispatchInfo end");
    return promise;
}
} // AppExecFwk
} // OHOS