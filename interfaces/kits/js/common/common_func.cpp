/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "common_func.h"

#include <vector>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_errors.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "iservice_registry.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "system_ability_definition.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t NAPI_RETURN_ZERO = 0;
constexpr int32_t NAPI_RETURN_ONE = 1;
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* ABILITY_NAME = "abilityName";
constexpr const char* URI = "uri";
constexpr const char* TYPE = "type";
constexpr const char* ACTION = "action";
constexpr const char* ENTITIES = "entities";
constexpr const char* FLAGS = "flags";
constexpr const char* DEVICE_ID = "deviceId";
constexpr const char* NAME = "name";
constexpr const char* IS_VISIBLE = "isVisible";
constexpr const char* EXPORTED = "exported";
constexpr const char* PERMISSIONS = "permissions";
constexpr const char* META_DATA = "metadata";
constexpr const char* ENABLED = "enabled";
constexpr const char* READ_PERMISSION = "readPermission";
constexpr const char* WRITE_PERMISSION = "writePermission";
constexpr const char* LABEL = "label";
constexpr const char* LABEL_ID = "labelId";
constexpr const char* DESCRIPTION = "description";
constexpr const char* DESCRIPTION_ID = "descriptionId";
constexpr const char* ICON = "icon";
constexpr const char* ICON_ID = "iconId";
constexpr const char* APPLICATION_INFO = "applicationInfo";
static std::unordered_map<int32_t, int32_t> ERR_MAP = {
    { ERR_OK, SUCCESS },
    { ERR_BUNDLE_MANAGER_PERMISSION_DENIED, ERROR_PERMISSION_DENIED_ERROR },
    { ERR_BUNDLE_MANAGER_PARAM_ERROR, ERROR_PARAM_CHECK_ERROR },
    { ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST, ERROR_BUNDLE_NOT_EXIST },
    { ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST, ERROR_MODULE_NOT_EXIST },
    { ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST, ERROR_ABILITY_NOT_EXIST },
    { ERR_BUNDLE_MANAGER_INVALID_USER_ID, ERROR_INVALID_USER_ID },
    { ERR_BUNDLE_MANAGER_QUERY_PERMISSION_DEFINE_FAILED, ERROR_PERMISSION_NOT_EXIST },
    { ERR_BUNDLE_MANAGER_DEVICE_ID_NOT_EXIST, ERROR_DEVICE_ID_NOT_EXIST },
    { ERR_BUNDLE_MANAGER_INVALID_UID, ERROR_INVALID_UID },
    { ERR_BUNDLE_MANAGER_INVALID_HAP_PATH, ERROR_INVALID_HAP_PATH },
    { ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST, ERROR_DEFAULT_APP_NOT_EXIST },
    { ERR_BUNDLE_MANAGER_INVALID_TYPE, ERROR_INVALID_TYPE },
    { ERR_BUNDLE_MANAGER_ABILITY_AND_TYPE_MISMATCH, ERROR_ABILITY_AND_TYPE_MISMATCH },
    { ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST, ERROR_PROFILE_NOT_EXIST },
    { ERR_BUNDLE_MANAGER_APPLICATION_DISABLED, ERROR_BUNDLE_IS_DISABLED },
    { ERROR_DISTRIBUTED_SERVICE_NOT_RUNNING, ERROR_DISTRIBUTED_SERVICE_NOT_RUNNING },
    { ERR_BUNDLE_MANAGER_ABILITY_DISABLED, ERROR_ABILITY_IS_DISABLED },
    { ERR_BUNDLE_MANAGER_CAN_NOT_CLEAR_USER_DATA, ERROR_CLEAR_CACHE_FILES_UNSUPPORTED },
    { ERR_ZLIB_SRC_FILE_DISABLED, ERR_ZLIB_SRC_FILE_INVALID },
    { ERR_ZLIB_DEST_FILE_DISABLED, ERR_ZLIB_DEST_FILE_INVALID },
    { ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, ERROR_NOT_SYSTEM_APP}
};
}
using Want = OHOS::AAFwk::Want;

sptr<IBundleMgr> CommonFunc::bundleMgr_ = nullptr;
std::mutex CommonFunc::bundleMgrMutex_;

napi_value CommonFunc::WrapVoidToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

napi_value CommonFunc::ParseInt(napi_env env, napi_value args, int32_t &param)
{
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args, &valuetype));
    APP_LOGD("valuetype=%{public}d.", valuetype);
    if (valuetype != napi_number) {
        APP_LOGE("Wrong argument type. int32 expected.");
        return nullptr;
    }
    int32_t value = 0;
    napi_get_value_int32(env, args, &value);
    APP_LOGD("param=%{public}d.", value);
    param = value;
    napi_value result = nullptr;
    napi_status status = napi_create_int32(env, NAPI_RETURN_ONE, &result);
    if (status != napi_ok) {
        APP_LOGE("napi_create_int32 error!");
        return nullptr;
    }
    return result;
}

bool CommonFunc::ParsePropertyArray(napi_env env, napi_value args, const std::string &propertyName,
    std::vector<napi_value> &valueVec)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, args, &type), false);
    if (type != napi_object) {
        APP_LOGE("args is not an object!");
        return false;
    }

    bool hasKey = false;
    napi_has_named_property(env, args, propertyName.c_str(), &hasKey);
    if (!hasKey) {
        APP_LOGW("%{public}s is not existed", propertyName.c_str());
        return true;
    }
    napi_value property = nullptr;
    napi_status status = napi_get_named_property(env, args, propertyName.c_str(), &property);
    if (status != napi_ok) {
        APP_LOGE("napi get named hashParams property error!");
        return false;
    }
    bool isArray = false;
    NAPI_CALL_BASE(env, napi_is_array(env, property, &isArray), false);
    if (!isArray) {
        APP_LOGE("hashParams is not array!");
        return false;
    }
    uint32_t arrayLength = 0;
    NAPI_CALL_BASE(env, napi_get_array_length(env, property, &arrayLength), false);
    APP_LOGD("ParseHashParams property is array, length=%{public}ud", arrayLength);

    napi_value valueAry = 0;
    for (uint32_t j = 0; j < arrayLength; j++) {
        NAPI_CALL_BASE(env, napi_get_element(env, property, j, &valueAry), false);
        valueVec.emplace_back(valueAry);
    }
    return true;
}

bool CommonFunc::ParseStringPropertyFromObject(napi_env env, napi_value args, const std::string &propertyName,
    bool isNecessary, std::string &value)
{
    napi_valuetype type = napi_undefined;
        NAPI_CALL_BASE(env, napi_typeof(env, args, &type), false);
        if (type != napi_object) {
            APP_LOGE("args is not an object!");
            return false;
        }
        bool hasKey = false;
        napi_has_named_property(env, args, propertyName.c_str(), &hasKey);
        if (!hasKey) {
            if (isNecessary) {
                APP_LOGE("%{public}s is not existed", propertyName.c_str());
                return false;
            }
            return true;
        }
        napi_value property = nullptr;
        napi_status status = napi_get_named_property(env, args, propertyName.c_str(), &property);
        if (status != napi_ok) {
            APP_LOGE("napi get named %{public}s property error!", propertyName.c_str());
            return false;
        }
        napi_typeof(env, property, &type);
        if (type != napi_string) {
            APP_LOGE("property type incorrect!");
            return false;
        }
        if (property == nullptr) {
            APP_LOGE("property is nullptr!");
            return false;
        }
        if (!CommonFunc::ParseString(env, property, value)) {
            APP_LOGE("parse string failed");
            return false;
        }
        return true;
}

bool CommonFunc::ParsePropertyFromObject(napi_env env, napi_value args, const PropertyInfo &propertyInfo,
    napi_value &property)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, args, &type), false);
    if (type != napi_object) {
        APP_LOGE("args is not an object!");
        return false;
    }
    bool hasKey = false;
    napi_has_named_property(env, args, propertyInfo.propertyName.c_str(), &hasKey);
    if (!hasKey) {
        if (propertyInfo.isNecessary) {
            APP_LOGE("%{public}s is not existed", propertyInfo.propertyName.c_str());
            return false;
        }
        return true;
    }

    napi_status status = napi_get_named_property(env, args, propertyInfo.propertyName.c_str(), &property);
    if (status != napi_ok) {
        APP_LOGE("napi get named %{public}s property error!", propertyInfo.propertyName.c_str());
        return false;
    }
    napi_typeof(env, property, &type);
    if (type != propertyInfo.propertyType) {
        APP_LOGE("property type incorrect!");
        return false;
    }
    if (property == nullptr) {
        APP_LOGE("property is nullptr");
        return false;
    }
    return true;
}

bool CommonFunc::ParseBool(napi_env env, napi_value value, bool& result)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    if (valueType != napi_boolean) {
        APP_LOGE("ParseBool type mismatch!");
        return false;
    }
    if (napi_get_value_bool(env, value, &result) != napi_ok) {
        APP_LOGE("napi_get_value_bool error");
        return false;
    }
    return true;
}

bool CommonFunc::ParseString(napi_env env, napi_value value, std::string& result)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    if (valueType != napi_string) {
        APP_LOGE("ParseString type mismatch!");
        return false;
    }
    size_t size = 0;
    if (napi_get_value_string_utf8(env, value, nullptr, NAPI_RETURN_ZERO, &size) != napi_ok) {
        APP_LOGE("napi_get_value_string_utf8 error.");
        return false;
    }
    result.reserve(size + 1);
    result.resize(size);
    if (napi_get_value_string_utf8(env, value, result.data(), (size + 1), &size) != napi_ok) {
        APP_LOGE("napi_get_value_string_utf8 error");
        return false;
    }
    return true;
}

bool CommonFunc::ParseAbilityInfo(napi_env env, napi_value param, AbilityInfo& abilityInfo)
{
    napi_valuetype valueType;
    NAPI_CALL_BASE(env, napi_typeof(env, param, &valueType), false);
    if (valueType != napi_object) {
        APP_LOGE("ParseAbilityInfo type mismatch!");
        return false;
    }

    napi_value prop = nullptr;
    // parse bundleName
    napi_get_named_property(env, param, "bundleName", &prop);
    std::string bundleName;
    if (!ParseString(env, prop, bundleName)) {
        return false;
    }
    abilityInfo.bundleName = bundleName;

    // parse moduleName
    napi_get_named_property(env, param, "moduleName", &prop);
    std::string moduleName;
    if (!ParseString(env, prop, moduleName)) {
        return false;
    }
    abilityInfo.moduleName = moduleName;

    // parse abilityName
    napi_get_named_property(env, param, "name", &prop);
    std::string abilityName;
    if (!ParseString(env, prop, abilityName)) {
        return false;
    }
    abilityInfo.name = abilityName;
    return true;
}

sptr<IBundleMgr> CommonFunc::GetBundleMgr()
{
    if (bundleMgr_ == nullptr) {
        std::lock_guard<std::mutex> lock(bundleMgrMutex_);
        if (bundleMgr_ == nullptr) {
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
            bundleMgr_ = OHOS::iface_cast<IBundleMgr>(bundleMgrSa);
            if (bundleMgr_ == nullptr) {
                APP_LOGE("iface_cast failed.");
                return nullptr;
            }
        }
    }
    return bundleMgr_;
}

sptr<IBundleInstaller> CommonFunc::GetBundleInstaller()
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return nullptr;
    }
    return iBundleMgr->GetBundleInstaller();
}

std::string CommonFunc::GetStringFromNAPI(napi_env env, napi_value value)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    if (valueType != napi_string) {
        APP_LOGE("GetStringFromNAPI type mismatch!");
        return "";
    }
    std::string result;
    size_t size = 0;

    if (napi_get_value_string_utf8(env, value, nullptr, NAPI_RETURN_ZERO, &size) != napi_ok) {
        APP_LOGE("can not get string size");
        return "";
    }
    result.reserve(size + NAPI_RETURN_ONE);
    result.resize(size);
    if (napi_get_value_string_utf8(env, value, result.data(), (size + NAPI_RETURN_ONE), &size) != napi_ok) {
        APP_LOGE("can not get string value");
        return "";
    }
    return result;
}

napi_value CommonFunc::ParseStringArray(napi_env env, std::vector<std::string> &stringArray, napi_value args)
{
    APP_LOGD("begin to parse string array");
    bool isArray = false;
    NAPI_CALL(env, napi_is_array(env, args, &isArray));
    if (!isArray) {
        APP_LOGE("args not array");
        return nullptr;
    }
    uint32_t arrayLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, args, &arrayLength));
    APP_LOGD("length=%{public}ud", arrayLength);
    for (uint32_t j = 0; j < arrayLength; j++) {
        napi_value value = nullptr;
        NAPI_CALL(env, napi_get_element(env, args, j, &value));
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, value, &valueType));
        if (valueType != napi_string) {
            APP_LOGE("array inside not string type");
            stringArray.clear();
            return nullptr;
        }
        stringArray.push_back(GetStringFromNAPI(env, value));
    }
    // create result code
    napi_value result;
    napi_status status = napi_create_int32(env, NAPI_RETURN_ONE, &result);
    if (status != napi_ok) {
        APP_LOGE("napi_create_int32 error!");
        return nullptr;
    }
    return result;
}

void CommonFunc::ConvertWantInfo(napi_env env, napi_value objWantInfo, const Want &want)
{
    ElementName elementName = want.GetElement();
    napi_value nbundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, elementName.GetBundleName().c_str(), NAPI_AUTO_LENGTH, &nbundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objWantInfo, "bundleName", nbundleName));

    napi_value ndeviceId;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, elementName.GetDeviceID().c_str(), NAPI_AUTO_LENGTH, &ndeviceId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objWantInfo, "deviceId", ndeviceId));

    napi_value nabilityName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, elementName.GetAbilityName().c_str(), NAPI_AUTO_LENGTH, &nabilityName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objWantInfo, "abilityName", nabilityName));

    napi_value naction;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, want.GetAction().c_str(), NAPI_AUTO_LENGTH, &naction));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objWantInfo, "action", naction));

    auto entities = want.GetEntities();
    napi_value nGetEntities;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nGetEntities));
    if (entities.size() > 0) {
        size_t index = 0;
        for (const auto &item:entities) {
            napi_value objEntities;
            NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, item.c_str(), NAPI_AUTO_LENGTH, &objEntities));
            NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nGetEntities, index, objEntities));
            index++;
        }
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objWantInfo, "entities", nGetEntities));
    }
}

bool CommonFunc::ParseElementName(napi_env env, napi_value args, Want &want)
{
    APP_LOGD("begin to parse ElementName.");
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, args, &valueType);
    if (valueType != napi_object) {
        APP_LOGE("args not object type.");
        return false;
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
    return true;
}

void CommonFunc::ConvertElementName(napi_env env, napi_value elementInfo,
    const OHOS::AppExecFwk::ElementName &elementName)
{
    // wrap deviceId
    napi_value deviceId;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, elementName.GetDeviceID().c_str(), NAPI_AUTO_LENGTH, &deviceId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, elementInfo, "deviceId", deviceId));

    // wrap bundleName
    napi_value bundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, elementName.GetBundleName().c_str(), NAPI_AUTO_LENGTH, &bundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, elementInfo, "bundleName", bundleName));

    // wrap moduleName
    napi_value moduleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, elementName.GetModuleName().c_str(), NAPI_AUTO_LENGTH, &moduleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, elementInfo, "moduleName", moduleName));

    // wrap abilityName
    napi_value abilityName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, elementName.GetAbilityName().c_str(), NAPI_AUTO_LENGTH, &abilityName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, elementInfo, "abilityName", abilityName));

    // wrap uri
    napi_value uri;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, elementName.GetURI().c_str(), NAPI_AUTO_LENGTH, &uri));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, elementInfo, "uri", uri));

    // wrap shortName
    napi_value shortName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, "", NAPI_AUTO_LENGTH, &shortName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, elementInfo, "shortName", shortName));
}

ErrCode CommonFunc::ConvertErrCode(ErrCode nativeErrCode)
{
    if (ERR_MAP.find(nativeErrCode) != ERR_MAP.end()) {
        return ERR_MAP.at(nativeErrCode);
    }
    return ERROR_BUNDLE_SERVICE_EXCEPTION;
}

bool CommonFunc::ParseWant(napi_env env, napi_value args, Want &want)
{
    APP_LOGD("begin to parse want");
    napi_valuetype valueType;
    NAPI_CALL_BASE(env, napi_typeof(env, args, &valueType), false);
    if (valueType != napi_object) {
        APP_LOGE("args not object type");
        return false;
    }
    napi_value prop = nullptr;
    napi_get_named_property(env, args, BUNDLE_NAME, &prop);
    std::string bundleName = GetStringFromNAPI(env, prop);

    prop = nullptr;
    napi_get_named_property(env, args, MODULE_NAME, &prop);
    std::string moduleName = GetStringFromNAPI(env, prop);

    prop = nullptr;
    napi_get_named_property(env, args, ABILITY_NAME, &prop);
    std::string abilityName = GetStringFromNAPI(env, prop);

    prop = nullptr;
    napi_get_named_property(env, args, URI, &prop);
    std::string uri = GetStringFromNAPI(env, prop);

    prop = nullptr;
    napi_get_named_property(env, args, TYPE, &prop);
    std::string type = GetStringFromNAPI(env, prop);

    prop = nullptr;
    napi_get_named_property(env, args, ACTION, &prop);
    std::string action = GetStringFromNAPI(env, prop);

    prop = nullptr;
    napi_get_named_property(env, args, ENTITIES, &prop);
    std::vector<std::string> entities;
    ParseStringArray(env, entities, prop);
    for (size_t idx = 0; idx < entities.size(); ++idx) {
        APP_LOGD("entity:%{public}s", entities[idx].c_str());
        want.AddEntity(entities[idx]);
    }

    prop = nullptr;
    int32_t flags = 0;
    napi_get_named_property(env, args, FLAGS, &prop);
    napi_typeof(env, prop, &valueType);
    if (valueType == napi_number) {
        napi_get_value_int32(env, prop, &flags);
    }

    prop = nullptr;
    napi_get_named_property(env, args, DEVICE_ID, &prop);
    std::string deviceId = GetStringFromNAPI(env, prop);

    APP_LOGD("bundleName:%{public}s, moduleName: %{public}s, abilityName:%{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    APP_LOGD("action:%{public}s, uri:%{private}s, type:%{public}s, flags:%{public}d",
        action.c_str(), uri.c_str(), type.c_str(), flags);
    bool isExplicit = !bundleName.empty() && !abilityName.empty();
    if (!isExplicit && action.empty() && entities.empty() && uri.empty() && type.empty()) {
        APP_LOGE("implicit params all empty");
        return false;
    }
    want.SetAction(action);
    want.SetUri(uri);
    want.SetType(type);
    want.SetFlags(flags);
    ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    want.SetElement(elementName);
    return true;
}

bool CommonFunc::ParseWantPerformance(napi_env env, napi_value args, Want &want)
{
    APP_LOGD("begin to parse want performance");
    napi_valuetype valueType;
    NAPI_CALL_BASE(env, napi_typeof(env, args, &valueType), false);
    if (valueType != napi_object) {
        APP_LOGE("args not object type");
        return false;
    }
    napi_value prop = nullptr;
    napi_get_named_property(env, args, BUNDLE_NAME, &prop);
    std::string bundleName = GetStringFromNAPI(env, prop);

    prop = nullptr;
    napi_get_named_property(env, args, MODULE_NAME, &prop);
    std::string moduleName = GetStringFromNAPI(env, prop);

    prop = nullptr;
    napi_get_named_property(env, args, ABILITY_NAME, &prop);
    std::string abilityName = GetStringFromNAPI(env, prop);
    if (!bundleName.empty() && !abilityName.empty()) {
        ElementName elementName("", bundleName, abilityName, moduleName);
        want.SetElement(elementName);
        return true;
    }
    return ParseWant(env, args, want);
}

bool CommonFunc::ParseWantWithoutVerification(napi_env env, napi_value args, Want &want)
{
    napi_valuetype valueType;
    NAPI_CALL_BASE(env, napi_typeof(env, args, &valueType), false);
    if (valueType != napi_object) {
        return false;
    }
    napi_value prop = nullptr;
    napi_get_named_property(env, args, BUNDLE_NAME, &prop);
    std::string bundleName = GetStringFromNAPI(env, prop);
    prop = nullptr;
    napi_get_named_property(env, args, MODULE_NAME, &prop);
    std::string moduleName = GetStringFromNAPI(env, prop);
    prop = nullptr;
    napi_get_named_property(env, args, ABILITY_NAME, &prop);
    std::string abilityName = GetStringFromNAPI(env, prop);
    prop = nullptr;
    napi_get_named_property(env, args, URI, &prop);
    std::string uri = GetStringFromNAPI(env, prop);
    prop = nullptr;
    napi_get_named_property(env, args, TYPE, &prop);
    std::string type = GetStringFromNAPI(env, prop);
    prop = nullptr;
    napi_get_named_property(env, args, ACTION, &prop);
    std::string action = GetStringFromNAPI(env, prop);
    prop = nullptr;
    napi_get_named_property(env, args, ENTITIES, &prop);
    std::vector<std::string> entities;
    ParseStringArray(env, entities, prop);
    for (size_t idx = 0; idx < entities.size(); ++idx) {
        APP_LOGD("entity:%{public}s", entities[idx].c_str());
        want.AddEntity(entities[idx]);
    }
    prop = nullptr;
    int32_t flags = 0;
    napi_get_named_property(env, args, FLAGS, &prop);
    napi_typeof(env, prop, &valueType);
    if (valueType == napi_number) {
        napi_get_value_int32(env, prop, &flags);
    }
    prop = nullptr;
    napi_get_named_property(env, args, DEVICE_ID, &prop);
    std::string deviceId = GetStringFromNAPI(env, prop);
    want.SetAction(action);
    want.SetUri(uri);
    want.SetType(type);
    want.SetFlags(flags);
    ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    want.SetElement(elementName);
    return true;
}

void CommonFunc::ConvertWindowSize(napi_env env, const AbilityInfo &abilityInfo, napi_value value)
{
    napi_value nMaxWindowRatio;
    NAPI_CALL_RETURN_VOID(env, napi_create_double(env, abilityInfo.maxWindowRatio, &nMaxWindowRatio));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "maxWindowRatio", nMaxWindowRatio));

    napi_value mMinWindowRatio;
    NAPI_CALL_RETURN_VOID(env, napi_create_double(env, abilityInfo.minWindowRatio, &mMinWindowRatio));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "minWindowRatio", mMinWindowRatio));

    napi_value nMaxWindowWidth;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, abilityInfo.maxWindowWidth, &nMaxWindowWidth));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "maxWindowWidth", nMaxWindowWidth));

    napi_value nMinWindowWidth;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, abilityInfo.minWindowWidth, &nMinWindowWidth));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "minWindowWidth", nMinWindowWidth));

    napi_value nMaxWindowHeight;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, abilityInfo.maxWindowHeight, &nMaxWindowHeight));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "maxWindowHeight", nMaxWindowHeight));

    napi_value nMinWindowHeight;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, abilityInfo.minWindowHeight, &nMinWindowHeight));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "minWindowHeight", nMinWindowHeight));
}

void CommonFunc::ConvertMetadata(napi_env env, const Metadata &metadata, napi_value value)
{
    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, metadata.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, NAME, nName));

    napi_value nValue;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, metadata.value.c_str(), NAPI_AUTO_LENGTH, &nValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "value", nValue));

    napi_value nResource;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, metadata.resource.c_str(), NAPI_AUTO_LENGTH, &nResource));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "resource", nResource));
}

void CommonFunc::ConvertAbilityInfos(napi_env env, const std::vector<AbilityInfo> &abilityInfos, napi_value value)
{
    for (size_t index = 0; index < abilityInfos.size(); ++index) {
        napi_value objAbilityInfo = nullptr;
        napi_create_object(env, &objAbilityInfo);
        ConvertAbilityInfo(env, abilityInfos[index], objAbilityInfo);
        napi_set_element(env, value, index, objAbilityInfo);
    }
}

void CommonFunc::ConvertAbilityInfo(napi_env env, const AbilityInfo &abilityInfo, napi_value objAbilityInfo)
{
    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, BUNDLE_NAME, nBundleName));

    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.moduleName.c_str(), NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, MODULE_NAME, nModuleName));

    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, abilityInfo.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, NAME, nName));

    napi_value nLabel;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, abilityInfo.label.c_str(), NAPI_AUTO_LENGTH, &nLabel));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, LABEL, nLabel));

    napi_value nLabelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, abilityInfo.labelId, &nLabelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, LABEL_ID, nLabelId));

    napi_value nDescription;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.description.c_str(), NAPI_AUTO_LENGTH, &nDescription));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, DESCRIPTION, nDescription));

    napi_value nDescriptionId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, abilityInfo.descriptionId, &nDescriptionId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, DESCRIPTION_ID, nDescriptionId));

    napi_value nIconPath;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.iconPath.c_str(), NAPI_AUTO_LENGTH, &nIconPath));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, ICON, nIconPath));

    napi_value nIconId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, abilityInfo.iconId, &nIconId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, ICON_ID, nIconId));

    napi_value nProcess;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, abilityInfo.process.c_str(), NAPI_AUTO_LENGTH, &nProcess));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "process", nProcess));

    napi_value nVisible;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, abilityInfo.visible, &nVisible));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, IS_VISIBLE, nVisible));

    napi_value nExported;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, abilityInfo.visible, &nExported));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, EXPORTED, nExported));

    napi_value nType;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(abilityInfo.type), &nType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "type", nType));

    napi_value nOrientation;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(abilityInfo.orientation), &nOrientation));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "orientation", nOrientation));

    napi_value nLaunchType;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(abilityInfo.launchMode), &nLaunchType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "launchType", nLaunchType));

    napi_value nPermissions;
    size_t size = abilityInfo.permissions.size();
    NAPI_CALL_RETURN_VOID(env, napi_create_array_with_length(env, size, &nPermissions));
    for (size_t idx = 0; idx < size; ++idx) {
        napi_value nPermission;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, abilityInfo.permissions[idx].c_str(), NAPI_AUTO_LENGTH, &nPermission));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nPermissions, idx, nPermission));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, PERMISSIONS, nPermissions));

    napi_value nReadPermission;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.readPermission.c_str(), NAPI_AUTO_LENGTH, &nReadPermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, READ_PERMISSION, nReadPermission));

    napi_value nWritePermission;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.writePermission.c_str(), NAPI_AUTO_LENGTH, &nWritePermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, WRITE_PERMISSION, nWritePermission));

    napi_value nUri;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, abilityInfo.uri.c_str(), NAPI_AUTO_LENGTH, &nUri));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, URI, nUri));

    napi_value nDeviceTypes;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nDeviceTypes));
    for (size_t idx = 0; idx < abilityInfo.deviceTypes.size(); ++idx) {
        napi_value nDeviceType;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, abilityInfo.deviceTypes[idx].c_str(), NAPI_AUTO_LENGTH, &nDeviceType));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nDeviceTypes, idx, nDeviceType));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "deviceTypes", nDeviceTypes));

    napi_value nApplicationInfo;
    if (!abilityInfo.applicationInfo.name.empty()) {
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nApplicationInfo));
        ConvertApplicationInfo(env, nApplicationInfo, abilityInfo.applicationInfo);
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &nApplicationInfo));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, APPLICATION_INFO, nApplicationInfo));

    napi_value nMetadata;
    size = abilityInfo.metadata.size();
    NAPI_CALL_RETURN_VOID(env, napi_create_array_with_length(env, size, &nMetadata));
    for (size_t index = 0; index < size; ++index) {
        napi_value nMetaData;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nMetaData));
        ConvertMetadata(env, abilityInfo.metadata[index], nMetaData);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nMetadata, index, nMetaData));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, META_DATA, nMetadata));

    napi_value nEnabled;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, abilityInfo.enabled, &nEnabled));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, ENABLED, nEnabled));

    napi_value nSupportWindowModes;
    size = abilityInfo.windowModes.size();
    NAPI_CALL_RETURN_VOID(env, napi_create_array_with_length(env, size, &nSupportWindowModes));
    for (size_t index = 0; index < size; ++index) {
        napi_value innerMode;
        NAPI_CALL_RETURN_VOID(env,
            napi_create_int32(env, static_cast<int32_t>(abilityInfo.windowModes[index]), &innerMode));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nSupportWindowModes, index, innerMode));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "supportWindowModes", nSupportWindowModes));

    napi_value nWindowSize;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nWindowSize));
    ConvertWindowSize(env, abilityInfo, nWindowSize);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "windowSize", nWindowSize));
}

void CommonFunc::ConvertExtensionInfos(napi_env env, const std::vector<ExtensionAbilityInfo> &extensionInfos,
    napi_value value)
{
    for (size_t index = 0; index < extensionInfos.size(); ++index) {
        napi_value objExtensionInfo = nullptr;
        napi_create_object(env, &objExtensionInfo);
        ConvertExtensionInfo(env, extensionInfos[index], objExtensionInfo);
        napi_set_element(env, value, index, objExtensionInfo);
    }
}

void CommonFunc::ConvertStringArrays(napi_env env, const std::vector<std::string> &strs, napi_value value)
{
    for (size_t index = 0; index < strs.size(); ++index) {
        napi_value nStr;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, strs[index].c_str(), NAPI_AUTO_LENGTH, &nStr));
        napi_set_element(env, value, index, nStr);
    }
}

void CommonFunc::ConvertExtensionInfo(napi_env env, const ExtensionAbilityInfo &extensionInfo,
    napi_value objExtensionInfo)
{
    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, extensionInfo.bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, BUNDLE_NAME, nBundleName));

    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, extensionInfo.moduleName.c_str(), NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, MODULE_NAME, nModuleName));

    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, extensionInfo.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, NAME, nName));

    napi_value nLabelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, extensionInfo.labelId, &nLabelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, LABEL_ID, nLabelId));

    napi_value nDescriptionId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, extensionInfo.descriptionId, &nDescriptionId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, DESCRIPTION_ID, nDescriptionId));

    napi_value nIconId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, extensionInfo.iconId, &nIconId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, ICON_ID, nIconId));

    napi_value nVisible;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, extensionInfo.visible, &nVisible));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, IS_VISIBLE, nVisible));

    napi_value nExported;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, extensionInfo.visible, &nExported));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, EXPORTED, nExported));

    napi_value nExtensionAbilityType;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, static_cast<int32_t>(extensionInfo.type), &nExtensionAbilityType));
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(env, objExtensionInfo, "extensionAbilityType", nExtensionAbilityType));

    napi_value nPermissions;
    size_t size = extensionInfo.permissions.size();
    NAPI_CALL_RETURN_VOID(env, napi_create_array_with_length(env, size, &nPermissions));
    for (size_t i = 0; i < size; ++i) {
        napi_value permission;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, extensionInfo.permissions[i].c_str(), NAPI_AUTO_LENGTH, &permission));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nPermissions, i, permission));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, PERMISSIONS, nPermissions));

    napi_value nApplicationInfo;
    if (!extensionInfo.applicationInfo.name.empty()) {
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nApplicationInfo));
        ConvertApplicationInfo(env, nApplicationInfo, extensionInfo.applicationInfo);
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &nApplicationInfo));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, APPLICATION_INFO, nApplicationInfo));

    napi_value nMetadata;
    size = extensionInfo.metadata.size();
    NAPI_CALL_RETURN_VOID(env, napi_create_array_with_length(env, size, &nMetadata));
    for (size_t i = 0; i < size; ++i) {
        napi_value nMetaData;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nMetaData));
        ConvertMetadata(env, extensionInfo.metadata[i], nMetaData);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nMetadata, i, nMetaData));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, META_DATA, nMetadata));

    napi_value nEnabled;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, extensionInfo.enabled, &nEnabled));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, ENABLED, nEnabled));

    napi_value nReadPermission;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, extensionInfo.readPermission.c_str(), NAPI_AUTO_LENGTH, &nReadPermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, READ_PERMISSION, nReadPermission));

    napi_value nWritePermission;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, extensionInfo.writePermission.c_str(), NAPI_AUTO_LENGTH, &nWritePermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objExtensionInfo, WRITE_PERMISSION, nWritePermission));
}


void CommonFunc::ConvertResource(napi_env env, const Resource &resource, napi_value objResource)
{
    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, resource.bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objResource, BUNDLE_NAME, nBundleName));

    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, resource.moduleName.c_str(), NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objResource, MODULE_NAME, nModuleName));

    napi_value nId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, resource.id, &nId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objResource, "id", nId));
}

void CommonFunc::ConvertApplicationInfo(napi_env env, napi_value objAppInfo, const ApplicationInfo &appInfo)
{
    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, NAME, nName));
    APP_LOGI("ConvertApplicationInfo name=%{public}s.", appInfo.name.c_str());

    napi_value nBundleType;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(appInfo.bundleType), &nBundleType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "bundleType", nBundleType));

    napi_value nDescription;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, appInfo.description.c_str(), NAPI_AUTO_LENGTH, &nDescription));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, DESCRIPTION, nDescription));

    napi_value nDescriptionId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, appInfo.descriptionId, &nDescriptionId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, DESCRIPTION_ID, nDescriptionId));

    napi_value nEnabled;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, appInfo.enabled, &nEnabled));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, ENABLED, nEnabled));

    napi_value nLabel;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.label.c_str(), NAPI_AUTO_LENGTH, &nLabel));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, LABEL, nLabel));

    napi_value nLabelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, appInfo.labelId, &nLabelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, LABEL_ID, nLabelId));

    napi_value nIconPath;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.iconPath.c_str(), NAPI_AUTO_LENGTH, &nIconPath));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, ICON, nIconPath));

    napi_value nIconId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, appInfo.iconId, &nIconId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, ICON_ID, nIconId));

    napi_value nProcess;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.process.c_str(), NAPI_AUTO_LENGTH, &nProcess));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "process", nProcess));

    napi_value nPermissions;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nPermissions));
    for (size_t idx = 0; idx < appInfo.permissions.size(); idx++) {
        napi_value nPermission;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, appInfo.permissions[idx].c_str(), NAPI_AUTO_LENGTH, &nPermission));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nPermissions, idx, nPermission));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, PERMISSIONS, nPermissions));

    napi_value nEntryDir;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, appInfo.entryDir.c_str(), NAPI_AUTO_LENGTH, &nEntryDir));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "entryDir", nEntryDir));

    napi_value nCodePath;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, appInfo.codePath.c_str(), NAPI_AUTO_LENGTH, &nCodePath));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "codePath", nCodePath));

    napi_value nMetaData;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nMetaData));
    for (const auto &item : appInfo.metadata) {
        napi_value nmetaDataArray;
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nmetaDataArray));
        for (size_t j = 0; j < item.second.size(); j++) {
            napi_value nmetaData;
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nmetaData));
            ConvertMetadata(env, item.second[j], nmetaData);
            NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nmetaDataArray, j, nmetaData));
        }
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, nMetaData, item.first.c_str(), nmetaDataArray));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, META_DATA, nMetaData));

    napi_value nRemovable;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, appInfo.removable, &nRemovable));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "removable", nRemovable));

    napi_value nAccessTokenId;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, appInfo.accessTokenId, &nAccessTokenId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "accessTokenId", nAccessTokenId));

    napi_value nUid;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, appInfo.uid, &nUid));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "uid", nUid));

    napi_value nIconResource;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nIconResource));
    ConvertResource(env, appInfo.iconResource, nIconResource);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "iconResource", nIconResource));

    napi_value nLabelResource;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nLabelResource));
    ConvertResource(env, appInfo.labelResource, nLabelResource);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "labelResource", nLabelResource));

    napi_value nDescriptionResource;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nDescriptionResource));
    ConvertResource(env, appInfo.descriptionResource, nDescriptionResource);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "descriptionResource", nDescriptionResource));

    napi_value nAppDistributionType;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.appDistributionType.c_str(), NAPI_AUTO_LENGTH,
        &nAppDistributionType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "appDistributionType", nAppDistributionType));

    napi_value nAppProvisionType;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.appProvisionType.c_str(), NAPI_AUTO_LENGTH,
        &nAppProvisionType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "appProvisionType", nAppProvisionType));

    napi_value nIsSystemApp;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, appInfo.isSystemApp, &nIsSystemApp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "systemApp", nIsSystemApp));
}

void CommonFunc::ConvertPermissionDef(napi_env env, napi_value result, const PermissionDef &permissionDef)
{
    napi_value nPermissionName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, permissionDef.permissionName.c_str(), NAPI_AUTO_LENGTH, &nPermissionName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "permissionName", nPermissionName));

    napi_value nGrantMode;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, permissionDef.grantMode, &nGrantMode));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "grantMode", nGrantMode));

    napi_value nLabelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, permissionDef.labelId, &nLabelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "labelId", nLabelId));

    napi_value nDescriptionId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, permissionDef.descriptionId, &nDescriptionId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "descriptionId", nDescriptionId));
}

void CommonFunc::ConvertDependency(napi_env env, const std::string &moduleName, napi_value value)
{
    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, moduleName.c_str(), NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, MODULE_NAME, nModuleName));
}

void CommonFunc::ConvertRequestPermissionUsedScene(napi_env env,
    const RequestPermissionUsedScene &requestPermissionUsedScene, napi_value result)
{
    napi_value nAbilities;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nAbilities));
    for (size_t index = 0; index < requestPermissionUsedScene.abilities.size(); index++) {
        napi_value objAbility;
        NAPI_CALL_RETURN_VOID(env,
            napi_create_string_utf8(env, requestPermissionUsedScene.abilities[index].c_str(),
                                    NAPI_AUTO_LENGTH, &objAbility));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nAbilities, index, objAbility));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "abilities", nAbilities));

    napi_value nWhen;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_string_utf8(env, requestPermissionUsedScene.when.c_str(), NAPI_AUTO_LENGTH, &nWhen));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "when", nWhen));
}

void CommonFunc::ConvertRequestPermission(napi_env env, const RequestPermission &requestPermission, napi_value result)
{
    napi_value nPermissionName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, requestPermission.name.c_str(), NAPI_AUTO_LENGTH, &nPermissionName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, NAME, nPermissionName));

    napi_value nReason;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, requestPermission.reason.c_str(), NAPI_AUTO_LENGTH, &nReason));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "reason", nReason));

    napi_value nReasonId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, requestPermission.reasonId, &nReasonId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "reasonId", nReasonId));

    napi_value nUsedScene;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nUsedScene));
    ConvertRequestPermissionUsedScene(env, requestPermission.usedScene, nUsedScene);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "usedScene", nUsedScene));
}

void CommonFunc::ConvertPreloadItem(napi_env env, const PreloadItem &preloadItem, napi_value value)
{
    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env,
        preloadItem.moduleName.c_str(), NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "moduleName", nModuleName));
}

void CommonFunc::ConvertSignatureInfo(napi_env env, const SignatureInfo &signatureInfo, napi_value value)
{
    napi_value nAppId;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, signatureInfo.appId.c_str(), NAPI_AUTO_LENGTH, &nAppId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "appId", nAppId));

    napi_value nFingerprint;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, signatureInfo.fingerprint.c_str(), NAPI_AUTO_LENGTH, &nFingerprint));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "fingerprint", nFingerprint));
}

void CommonFunc::ConvertHapModuleInfo(napi_env env, const HapModuleInfo &hapModuleInfo, napi_value objHapModuleInfo)
{
    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, hapModuleInfo.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, NAME, nName));
    APP_LOGI("ConvertHapModuleInfo name=%{public}s.", hapModuleInfo.name.c_str());

    napi_value nIcon;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, hapModuleInfo.iconPath.c_str(), NAPI_AUTO_LENGTH, &nIcon));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, ICON, nIcon));

    napi_value nIconId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, hapModuleInfo.iconId, &nIconId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, ICON_ID, nIconId));

    napi_value nLabel;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, hapModuleInfo.label.c_str(), NAPI_AUTO_LENGTH, &nLabel));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, LABEL, nLabel));

    napi_value nLabelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, hapModuleInfo.labelId, &nLabelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, LABEL_ID, nLabelId));

    napi_value nDescription;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, hapModuleInfo.description.c_str(), NAPI_AUTO_LENGTH, &nDescription));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, DESCRIPTION, nDescription));

    napi_value ndescriptionId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, hapModuleInfo.descriptionId, &ndescriptionId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, DESCRIPTION_ID, ndescriptionId));

    napi_value nMainElementName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, hapModuleInfo.mainElementName.c_str(), NAPI_AUTO_LENGTH,
        &nMainElementName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "mainElementName", nMainElementName));

    napi_value nAbilityInfos;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nAbilityInfos));
    for (size_t idx = 0; idx < hapModuleInfo.abilityInfos.size(); idx++) {
        napi_value objAbilityInfo;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objAbilityInfo));
        ConvertAbilityInfo(env, hapModuleInfo.abilityInfos[idx], objAbilityInfo);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nAbilityInfos, idx, objAbilityInfo));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "abilitiesInfo", nAbilityInfos));

    napi_value nExtensionAbilityInfos;
    napi_create_array_with_length(env, hapModuleInfo.extensionInfos.size(), &nExtensionAbilityInfos);
    ConvertExtensionInfos(env, hapModuleInfo.extensionInfos, nExtensionAbilityInfos);
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(env, objHapModuleInfo, "extensionAbilitiesInfo", nExtensionAbilityInfos));

    napi_value nMetadata;
    size_t size = hapModuleInfo.metadata.size();
    NAPI_CALL_RETURN_VOID(env, napi_create_array_with_length(env, size, &nMetadata));
    for (size_t index = 0; index < size; ++index) {
        napi_value innerMeta;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &innerMeta));
        ConvertMetadata(env, hapModuleInfo.metadata[index], innerMeta);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nMetadata, index, innerMeta));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "metadata", nMetadata));

    napi_value nDeviceTypes;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nDeviceTypes));
    for (size_t idx = 0; idx < hapModuleInfo.deviceTypes.size(); idx++) {
        napi_value nDeviceType;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, hapModuleInfo.deviceTypes[idx].c_str(), NAPI_AUTO_LENGTH, &nDeviceType));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nDeviceTypes, idx, nDeviceType));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "deviceTypes", nDeviceTypes));

    napi_value nInstallationFree;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, hapModuleInfo.installationFree, &nInstallationFree));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "installationFree", nInstallationFree));

    napi_value nHashValue;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, hapModuleInfo.hashValue.c_str(), NAPI_AUTO_LENGTH, &nHashValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "hashValue", nHashValue));

    napi_value nModuleSourceDir;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, hapModuleInfo.moduleSourceDir.c_str(), NAPI_AUTO_LENGTH,
        &nModuleSourceDir));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "moduleSourceDir", nModuleSourceDir));

    napi_value nPreloads;
    size = hapModuleInfo.preloads.size();
    NAPI_CALL_RETURN_VOID(env, napi_create_array_with_length(env, size, &nPreloads));
    for (size_t index = 0; index < size; ++index) {
        napi_value nPreload;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nPreload));
        ConvertPreloadItem(env, hapModuleInfo.preloads[index], nPreload);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nPreloads, index, nPreload));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "preloads", nPreloads));

    napi_value nType;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(hapModuleInfo.moduleType), &nType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "type", nType));

    napi_value nDependencies;
    size = hapModuleInfo.dependencies.size();
    NAPI_CALL_RETURN_VOID(env, napi_create_array_with_length(env, size, &nDependencies));
    for (size_t index = 0; index < size; ++index) {
        napi_value nDependency;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nDependency));
        ConvertDependency(env, hapModuleInfo.dependencies[index], nDependency);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nDependencies, index, nDependency));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "dependencies", nDependencies));
}

void CommonFunc::ConvertBundleInfo(napi_env env, const BundleInfo &bundleInfo, napi_value objBundleInfo, int32_t flags)
{
    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, bundleInfo.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, NAME, nName));

    napi_value nVendor;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, bundleInfo.vendor.c_str(), NAPI_AUTO_LENGTH, &nVendor));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "vendor", nVendor));

    napi_value nVersionCode;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, bundleInfo.versionCode, &nVersionCode));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "versionCode", nVersionCode));

    napi_value nVersionName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, bundleInfo.versionName.c_str(), NAPI_AUTO_LENGTH, &nVersionName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "versionName", nVersionName));

    napi_value nMinCompatibleVersionCode;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_int32(env, bundleInfo.minCompatibleVersionCode, &nMinCompatibleVersionCode));
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, objBundleInfo, "minCompatibleVersionCode", nMinCompatibleVersionCode));

    napi_value nTargetVersion;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, bundleInfo.targetVersion, &nTargetVersion));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "targetVersion", nTargetVersion));

    napi_value nAppInfo;
    if ((static_cast<uint32_t>(flags) & static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION))
        == static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)) {
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nAppInfo));
        ConvertApplicationInfo(env, nAppInfo, bundleInfo.applicationInfo);
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &nAppInfo));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "appInfo", nAppInfo));

    napi_value nHapModuleInfos;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nHapModuleInfos));
    for (size_t idx = 0; idx < bundleInfo.hapModuleInfos.size(); idx++) {
        napi_value objHapModuleInfo;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objHapModuleInfo));
        ConvertHapModuleInfo(env, bundleInfo.hapModuleInfos[idx], objHapModuleInfo);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nHapModuleInfos, idx, objHapModuleInfo));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "hapModulesInfo", nHapModuleInfos));

    napi_value nReqPermissionDetails;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nReqPermissionDetails));
    for (size_t idx = 0; idx < bundleInfo.reqPermissionDetails.size(); idx++) {
        napi_value objReqPermission;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objReqPermission));
        ConvertRequestPermission(env, bundleInfo.reqPermissionDetails[idx], objReqPermission);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nReqPermissionDetails, idx, objReqPermission));
    }
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, objBundleInfo, "reqPermissionDetails", nReqPermissionDetails));

    napi_value nReqPermissionStates;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nReqPermissionStates));
    for (size_t idx = 0; idx < bundleInfo.reqPermissionStates.size(); idx++) {
        napi_value nReqPermissionState;
        NAPI_CALL_RETURN_VOID(env,
            napi_create_int32(env, static_cast<int32_t>(bundleInfo.reqPermissionStates[idx]), &nReqPermissionState));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nReqPermissionStates, idx, nReqPermissionState));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "permissionGrantStates",
        nReqPermissionStates));

    napi_value nSignatureInfo;
    if ((static_cast<uint32_t>(flags) & static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO))
        == static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO)) {
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nSignatureInfo));
        ConvertSignatureInfo(env, bundleInfo.signatureInfo, nSignatureInfo);
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &nSignatureInfo));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "signatureInfo", nSignatureInfo));

    napi_value nInstallTime;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, bundleInfo.installTime, &nInstallTime));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "installTime", nInstallTime));

    napi_value nUpdateTime;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, bundleInfo.updateTime, &nUpdateTime));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "updateTime", nUpdateTime));
}

void CommonFunc::ConvertBundleChangeInfo(napi_env env, const std::string &bundleName,
    int32_t userId, napi_value bundleChangeInfo)
{
    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, bundleChangeInfo, "bundleName", nBundleName));

    napi_value nUserId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, userId, &nUserId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, bundleChangeInfo, "userId", nUserId));
}

void CommonFunc::ConvertLauncherAbilityInfo(napi_env env,
    const LauncherAbilityInfo &launcherAbility, napi_value value)
{
    // wrap labelId
    napi_value labelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, launcherAbility.labelId, &labelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "labelId", labelId));

    // wrap iconId
    napi_value iconId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, launcherAbility.iconId, &iconId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "iconId", iconId));

    // wrap userId
    napi_value userId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, launcherAbility.userId, &userId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "userId", userId));

    // wrap installTime
    napi_value installTime;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, launcherAbility.installTime, &installTime));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "installTime", installTime));

    // wrap elementName
    napi_value elementName;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &elementName));
    ConvertElementName(env, elementName, launcherAbility.elementName);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "elementName", elementName));

    // wrap application
    napi_value appInfo;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &appInfo));
    ConvertApplicationInfo(env, appInfo, launcherAbility.applicationInfo);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "applicationInfo", appInfo));
}

void CommonFunc::ConvertLauncherAbilityInfos(napi_env env,
    const std::vector<LauncherAbilityInfo> &launcherAbilities, napi_value value)
{
    if (launcherAbilities.empty()) {
        return;
    }
    size_t index = 0;
    for (const auto &launcherAbility : launcherAbilities) {
        napi_value launcherAbilityObj = nullptr;
        napi_create_object(env, &launcherAbilityObj);
        ConvertLauncherAbilityInfo(env, launcherAbility, launcherAbilityObj);
        napi_set_element(env, value, index, launcherAbilityObj);
        ++index;
    }
}

void CommonFunc::ConvertShortcutIntent(napi_env env,
    const OHOS::AppExecFwk::ShortcutIntent &shortcutIntent, napi_value value)
{
    napi_value nTargetBundle;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, shortcutIntent.targetBundle.c_str(), NAPI_AUTO_LENGTH, &nTargetBundle));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "targetBundle", nTargetBundle));

    napi_value nTargetModule;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, shortcutIntent.targetModule.c_str(), NAPI_AUTO_LENGTH, &nTargetModule));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "targetModule", nTargetModule));

    napi_value nTargetClass;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, shortcutIntent.targetClass.c_str(), NAPI_AUTO_LENGTH, &nTargetClass));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "targetAbility", nTargetClass));
}

void CommonFunc::ConvertShortCutInfo(napi_env env, const ShortcutInfo &shortcutInfo, napi_value value)
{
    // wrap id
    napi_value shortId;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, shortcutInfo.id.c_str(), NAPI_AUTO_LENGTH, &shortId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "id", shortId));
    // wrap bundleName
    napi_value bundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, shortcutInfo.bundleName.c_str(), NAPI_AUTO_LENGTH, &bundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "bundleName", bundleName));
    // wrap moduleName
    napi_value moduleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, shortcutInfo.moduleName.c_str(), NAPI_AUTO_LENGTH, &moduleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "moduleName", moduleName));
    // wrap hostAbility
    napi_value hostAbility;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, shortcutInfo.hostAbility.c_str(), NAPI_AUTO_LENGTH, &hostAbility));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "hostAbility", hostAbility));
    // wrap icon
    napi_value icon;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, shortcutInfo.icon.c_str(), NAPI_AUTO_LENGTH, &icon));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "icon", icon));
    // wrap iconId
    napi_value iconId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, shortcutInfo.iconId, &iconId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "iconId", iconId));
    // wrap label
    napi_value label;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, shortcutInfo.label.c_str(), NAPI_AUTO_LENGTH, &label));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "label", label));
    // wrap labelId
    napi_value labelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, shortcutInfo.labelId, &labelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "labelId", labelId));

    // wrap wants
    napi_value intents;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &intents));
    for (size_t index = 0; index < shortcutInfo.intents.size(); ++index) {
        napi_value intent;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &intent));
        ConvertShortcutIntent(env, shortcutInfo.intents[index], intent);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, intents, index, intent));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "wants", intents));
}

void CommonFunc::ConvertShortCutInfos(napi_env env, const std::vector<ShortcutInfo> &shortcutInfos, napi_value value)
{
    if (shortcutInfos.empty()) {
        return;
    }
    size_t index = 0;
    for (const auto &shortcutInfo : shortcutInfos) {
        napi_value shortcutObj = nullptr;
        napi_create_object(env, &shortcutObj);
        ConvertShortCutInfo(env, shortcutInfo, shortcutObj);
        napi_set_element(env, value, index, shortcutObj);
        ++index;
    }
}

}
}
