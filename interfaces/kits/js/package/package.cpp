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
#include "package.h"
#include <string>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_mgr_host.h"
#include "bundle_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "securec.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
namespace {
constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr int32_t PARAM0 = 0;
constexpr int32_t INVALID_PARAM = 2;
constexpr int32_t INVALID_NUMBER = 202;
}

CheckPackageHasInstalledOptions::~CheckPackageHasInstalledOptions()
{
    if (jsSuccessRef) {
        APP_LOGD("CheckPackageHasInstalledOptions::~CheckPackageHasInstalledOptions delete successRef");
        jsSuccessRef = nullptr;
    }
    if (jsFailRef) {
        APP_LOGD("CheckPackageHasInstalledOptions::~CheckPackageHasInstalledOptions delete failRef");
        jsFailRef = nullptr;
    }
    if (jsCompleteRef) {
        APP_LOGD("CheckPackageHasInstalledOptions::~CheckPackageHasInstalledOptions delete completeRef");
        jsCompleteRef = nullptr;
    }
}

static OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> GetBundleMgr()
{
    auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        APP_LOGE("GetBundleMgr GetSystemAbilityManager is null");
        return nullptr;
    }
    auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleMgrSa == nullptr) {
        APP_LOGE("GetBundleMgr GetSystemAbility is null");
        return nullptr;
    }
    auto bundleMgr = OHOS::iface_cast<IBundleMgr>(bundleMgrSa);
    if (bundleMgr == nullptr) {
        APP_LOGE("GetBundleMgr iface_cast get null");
    }
    return bundleMgr;
}

static bool InnerHasInstalled(std::string bundleName)
{
    if (bundleName.empty()) {
        APP_LOGE("bundleName is invalid param");
        return false;
    }
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    BundleInfo bundleInfo;
    bool ret = iBundleMgr->GetBundleInfo(bundleName, 0, bundleInfo);
    if (!ret) {
        APP_LOGE("bundleInfo is not find, bundleName=%{public}s.", bundleName.c_str());
    }
    return ret;
}

void JsPackage::Finalizer(NativeEngine *engine, void *data, void *hint)
{
    APP_LOGE("JsPackage::Finalizer is called");
    std::unique_ptr<JsPackage>(static_cast<JsPackage*>(data));
}

NativeValue* JsPackage::HasInstalled(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsPackage* me = OHOS::AbilityRuntime::CheckParamsAndGetThis<JsPackage>(engine, info);
    return (me != nullptr) ? me->OnHasInstalled(*engine, *info) : nullptr;
}

void JsPackage::JsParseCheckPackageHasInstalledOptions(NativeEngine &engine, const NativeCallbackInfo &info,
    std::shared_ptr<CheckPackageHasInstalledOptions> hasInstalledOptions)
{
    if (hasInstalledOptions == nullptr) {
        APP_LOGE("hasInstalledOptions is nullptr");
        return;
    }

    auto param = info.argv[0];
    if (param == nullptr) {
        APP_LOGI("param is nullptr");
        return;
    }

    NativeObject *object = AbilityRuntime::ConvertNativeValueTo<NativeObject>(param);
    NativeValue *jsBundleName = object->GetProperty("bundleName");
    if (jsBundleName->TypeOf() == NATIVE_STRING) {
        if (!AbilityRuntime::ConvertFromJsValue(engine, jsBundleName, hasInstalledOptions->bundleName)) {
            APP_LOGI("Convert the Js value error.");
            return;
        }
        hasInstalledOptions->isString = true;
    } else {
        hasInstalledOptions->isString = false;
    }

    NativeValue *jsFunction = nullptr;
    jsFunction = object->GetProperty("success");
    if (jsFunction->IsCallable()) {
        hasInstalledOptions->jsSuccessRef.reset(engine.CreateReference(jsFunction, 1));
    }

    jsFunction = object->GetProperty("fail");
    if (jsFunction->IsCallable()) {
        hasInstalledOptions->jsFailRef.reset(engine.CreateReference(jsFunction, 1));
    }

    jsFunction = object->GetProperty("complete");
    if (jsFunction->IsCallable()) {
        hasInstalledOptions->jsCompleteRef.reset(engine.CreateReference(jsFunction, 1));
    }
}

NativeValue* JsPackage::OnHasInstalled(NativeEngine &engine, NativeCallbackInfo &info)
{
    APP_LOGI("%{public}s called.", __func__);
    int32_t errCode = 0;

    std::shared_ptr<CheckPackageHasInstalledOptions> asyncCallbackInfo =
        std::make_shared<CheckPackageHasInstalledOptions>();
    if (info.argc < ARGS_SIZE_ONE || info.argc > ARGS_SIZE_TWO) {
        APP_LOGI("input params is not object!");
        return engine.CreateUndefined();
    }

    if (info.argv[PARAM0]->TypeOf() == NATIVE_OBJECT) {
        JsParseCheckPackageHasInstalledOptions(engine, info, asyncCallbackInfo);
    } else {
        errCode = INVALID_PARAM;
    }

    if (!errCode && asyncCallbackInfo->isString && asyncCallbackInfo->jsSuccessRef) {
        asyncCallbackInfo->response.result = InnerHasInstalled(asyncCallbackInfo->bundleName);
    }

    if (!asyncCallbackInfo->isString) {
        if (asyncCallbackInfo->jsFailRef) {
            std::string data = "value is not an available number";
            NativeValue *args[] = {AbilityRuntime::CreateJsValue(engine, data),
                AbilityRuntime::CreateJsValue(engine, INVALID_NUMBER)};
            NativeValue *value = asyncCallbackInfo->jsFailRef->Get();
            NativeValue *callback = asyncCallbackInfo->jsFailRef->Get();
            engine.CallFunction(value, callback, args, ARGS_SIZE_TWO);
        }
    } else {
        if (asyncCallbackInfo->jsSuccessRef) {
            NativeValue *objValue = engine.CreateObject();
            NativeObject *object = AbilityRuntime::ConvertNativeValueTo<NativeObject>(objValue);
            object->SetProperty("result", AbilityRuntime::CreateJsValue(engine, asyncCallbackInfo->response.result));

            NativeValue *args[] = {objValue};
            NativeValue *value = asyncCallbackInfo->jsSuccessRef->Get();
            NativeValue *callback = asyncCallbackInfo->jsSuccessRef->Get();
            engine.CallFunction(value, callback, args, ARGS_SIZE_ONE);
        }
    }
    if (asyncCallbackInfo->jsCompleteRef) {
        NativeValue *args[] = {engine.CreateUndefined()};
        NativeValue *value = asyncCallbackInfo->jsCompleteRef->Get();
        NativeValue *callback = asyncCallbackInfo->jsCompleteRef->Get();
        engine.CallFunction(value, callback, args, ARGS_SIZE_ONE);
    }
    return engine.CreateUndefined();
}
}  // namespace AppExecFwk
}  // namespace OHOS