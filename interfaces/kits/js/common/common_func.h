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

#ifndef COMMON_FUNC_H
#define COMMON_FUNC_H

#include <vector>
#include <mutex>

#include "app_log_wrapper.h"
#include "bundle_mgr_interface.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

struct PropertyInfo {
    const std::string propertyName;
    bool isNecessary = false;
    napi_valuetype propertyType = napi_undefined;
};

class CommonFunc {
public:
static napi_value WrapVoidToJS(napi_env env);

static napi_value ParseInt(napi_env env, int &param, napi_value args);

static std::string GetStringFromNAPI(napi_env env, napi_value value);

static sptr<IBundleMgr> GetBundleMgr();

static sptr<IBundleInstaller> GetBundleInstaller();

static bool ParsePropertyArray(napi_env env, napi_value args, const std::string &propertyName,
    std::vector<napi_value> &valueVec);

static bool ParseStringPropertyFromObject(napi_env env, napi_value args, const std::string &propertyName,
    bool isNecessary, std::string &value);

static bool ParsePropertyFromObject(napi_env env, napi_value args, const PropertyInfo &propertyInfo,
    napi_value &property);

static bool ParseString(napi_env env, napi_value value, std::string& result);

static napi_value ParseStringArray(napi_env env, std::vector<std::string> &stringArray, napi_value args);

static void ConvertWantInfo(napi_env env, napi_value objWantInfo, const Want &want);

static bool ParseElementName(napi_env env, napi_value args, Want &want);

static bool ParseWant(napi_env env, napi_value args, Want &want);

static bool ParseAbilityInfo(napi_env env, napi_value param, AbilityInfo& abilityInfo);

static ErrCode ConvertErrCode(ErrCode nativeErrCode);

static void ConvertWindowSize(napi_env env, const AbilityInfo &abilityInfo, napi_value value);

static void ConvertMetadata(napi_env env, const Metadata &metadata, napi_value value);

static void ConvertAbilityInfos(napi_env env, const std::vector<AbilityInfo> &abilityInfos, napi_value value);

static void ConvertAbilityInfo(napi_env env, const AbilityInfo &abilityInfo, napi_value objAbilityInfo);

static void ConvertExtensionInfos(napi_env env, const std::vector<ExtensionAbilityInfo> &extensionInfos,
    napi_value value);

static void ConvertExtensionInfo(napi_env env, const ExtensionAbilityInfo &extensionInfo, napi_value objExtensionInfo);

template<typename T>
static napi_value AsyncCallNativeMethod(napi_env env,
                                 T *asyncCallbackInfo,
                                 std::string methodName,
                                 void (*execFunc)(napi_env, void *),
                                 void (*completeFunc)(napi_env, napi_status, void *))
{
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    napi_value promise = nullptr;
    if (asyncCallbackInfo->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncCallbackInfo->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &promise));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, methodName.c_str(), NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource, execFunc, completeFunc,
        (void*)asyncCallbackInfo, &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    return promise;
}

private:
    static sptr<IBundleMgr> bundleMgr_;
    static std::mutex bundleMgrMutex_;
};

#define PARSE_PROPERTY(env, property, funcType, value)                                        \
    do {                                                                                      \
        NAPI_CALL_BASE(env, napi_get_value_##funcType(env, property, &value), false);         \
    } while (0)
} // AppExecFwk
} // OHOS
#endif