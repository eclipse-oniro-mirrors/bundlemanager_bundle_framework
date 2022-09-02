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
#include "common_func.h"

#include <vector>

#include "app_log_wrapper.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t NAPI_RETURN_ZERO = 0;
constexpr int32_t NAPI_RETURN_ONE = 1;
}
using Want = OHOS::AAFwk::Want;

napi_value ParseInt(napi_env env, int &param, napi_value args)
{
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args, &valuetype));
    APP_LOGD("valuetype=%{public}d.", valuetype);
    NAPI_ASSERT(env, valuetype == napi_number, "Wrong argument type. int32 expected.");
    int32_t value = 0;
    napi_get_value_int32(env, args, &value);
    APP_LOGD("param=%{public}d.", value);
    param = value;
    napi_value result = nullptr;
    napi_status status = napi_create_int32(env, NAPI_RETURN_ONE, &result);
    NAPI_ASSERT(env, status == napi_ok, "napi_create_int32 error!");
    return result;
}

bool ParseString(napi_env env, napi_value value, std::string& result)
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

std::string GetStringFromNAPI(napi_env env, napi_value value)
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

napi_value ParseStringArray(napi_env env, std::vector<std::string> &stringArray, napi_value args)
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
    NAPI_ASSERT(env, status == napi_ok, "napi_create_int32 error!");
    return result;
}

void ConvertWantInfo(napi_env env, napi_value objWantInfo, const Want &want)
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


bool ParseElementName(napi_env env, napi_value args, Want &want)
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
}
}