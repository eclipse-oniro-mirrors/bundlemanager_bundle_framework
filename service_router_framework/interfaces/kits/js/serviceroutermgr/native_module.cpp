/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "service_info.h"
#include "service_router_mgr.h"

namespace OHOS {
namespace AppExecFwk {
static napi_status SetEnumItem(napi_env env, napi_value object, const char* name, int32_t value)
{
    napi_status status;
    napi_value itemValue;
    napi_value itemName;

    NAPI_CALL_BASE(env, status = napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &itemName), status);
    NAPI_CALL_BASE(env, status = napi_create_int32(env, value, &itemValue), status);
    NAPI_CALL_BASE(env, status = napi_set_property(env, object, itemName, itemValue), status);
    NAPI_CALL_BASE(env, status = napi_set_property(env, object, itemValue, itemName), status);
    return napi_ok;
}

static napi_value InitBusinessTypeObject(napi_env env)
{
    napi_value object;
    NAPI_CALL(env, napi_create_object(env, &object));

    NAPI_CALL(env, SetEnumItem(env, object, "SHARE", static_cast<int32_t>(BusinessType::SHARE)));
    NAPI_CALL(env, SetEnumItem(env, object, "UNSPECIFIED", static_cast<int32_t>(BusinessType::UNSPECIFIED)));
    return object;
}

static napi_value BusinessRouterExport(napi_env env, napi_value exports)
{
    napi_value businessType = InitBusinessTypeObject(env);
    if (businessType == nullptr) {
        APP_LOGE("failed to create business type object");
        return nullptr;
    }

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("queryBusinessAbilityInfo", QueryBusinessAbilityInfos),
        DECLARE_NAPI_PROPERTY("BusinessType", businessType),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_module business_router_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = BusinessRouterExport,
    .nm_modname = "businessRouter",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

extern "C" __attribute__((constructor)) void BusinessRouterRegister(void)
{
    napi_module_register(&business_router_module);
}
}
}