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

#ifndef COMMON_FUNC_H
#define COMMON_FUNC_H

#include <vector>
#include <mutex>

#include "app_log_wrapper.h"
#include "bundle_mgr_interface.h"
#include "iremote_object.h"
#include "launcher_ability_info.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "shared/shared_bundle_info.h"
#include "shared/shared_module_info.h"
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

static bool ParseInt(napi_env env, napi_value args, int32_t &param);

static std::string GetStringFromNAPI(napi_env env, napi_value value);

static sptr<IBundleMgr> GetBundleMgr();

static sptr<IBundleInstaller> GetBundleInstaller();

static sptr<IVerifyManager> GetVerifyManager();

static sptr<IExtendResourceManager> GetExtendResourceManager();

static bool ParsePropertyArray(napi_env env, napi_value args, const std::string &propertyName,
    std::vector<napi_value> &valueVec);

static bool ParseStringPropertyFromObject(napi_env env, napi_value args, const std::string &propertyName,
    bool isNecessary, std::string &value);

static bool ParsePropertyFromObject(napi_env env, napi_value args, const PropertyInfo &propertyInfo,
    napi_value &property);

static bool ParseBool(napi_env env, napi_value value, bool& result);

static bool ParseString(napi_env env, napi_value value, std::string& result);

static napi_value ParseStringArray(napi_env env, std::vector<std::string> &stringArray, napi_value args);

static void ConvertWantInfo(napi_env env, napi_value objWantInfo, const Want &want);

static bool ParseElementName(napi_env env, napi_value args, Want &want);

static bool ParseElementName(napi_env env, napi_value args, ElementName &elementName);

static void ConvertElementName(napi_env env, napi_value elementInfo, const OHOS::AppExecFwk::ElementName &elementName);

static bool ParseWant(napi_env env, napi_value args, Want &want);

static bool ParseWantPerformance(napi_env env, napi_value args, Want &want);

static bool ParseWantWithoutVerification(napi_env env, napi_value args, Want &want);

static bool ParseAbilityInfo(napi_env env, napi_value param, AbilityInfo& abilityInfo);

static bool ParseShortCutInfo(napi_env env, napi_value param, ShortcutInfo &shortcutInfo);

static bool ParseShortcutWant(napi_env env, napi_value param, ShortcutIntent &shortcutIntent);

static bool ParseShortcutWantArray(
    napi_env env, napi_value args, std::vector<ShortcutIntent> &shortcutIntents);

static bool ParseParameters(
    napi_env env, napi_value args, std::map<std::string, std::string> &parameters);

static bool ParseParameterItem(napi_env env, napi_value param, std::string &key, std::string &value);

static ErrCode ConvertErrCode(ErrCode nativeErrCode);

static void ConvertWindowSize(napi_env env, const AbilityInfo &abilityInfo, napi_value value);

static void ConvertMetadata(napi_env env, const Metadata &metadata, napi_value value);

static void ConvertAbilityInfos(napi_env env, const std::vector<AbilityInfo> &abilityInfos, napi_value value);

static void ConvertAbilityInfo(napi_env env, const AbilityInfo &abilityInfo, napi_value objAbilityInfo);

static void ConvertExtensionInfos(napi_env env, const std::vector<ExtensionAbilityInfo> &extensionInfos,
    napi_value value);

static void ConvertStringArrays(napi_env env, const std::vector<std::string> &strs, napi_value value);

static void ConvertValidity(napi_env env, const Validity &validity, napi_value objValidity);

static void ConvertAppProvisionInfo(
    napi_env env, const AppProvisionInfo &appProvisionInfo, napi_value objAppProvisionInfo);

static void ConvertExtensionInfo(napi_env env, const ExtensionAbilityInfo &extensionInfo, napi_value objExtensionInfo);

static void ConvertResource(napi_env env, const Resource &resource, napi_value objResource);

static void ConvertApplicationInfo(napi_env env, napi_value objAppInfo, const ApplicationInfo &appInfo);

static void ConvertPermissionDef(napi_env env, napi_value result, const PermissionDef &permissionDef);

static void ConvertRequestPermission(napi_env env, const RequestPermission &requestPermission, napi_value result);

static void ConvertRequestPermissionUsedScene(napi_env env,
    const RequestPermissionUsedScene &requestPermissionUsedScene, napi_value result);

static void ConvertSignatureInfo(napi_env env, const SignatureInfo &signatureInfo, napi_value value);

static void ConvertHapModuleInfo(napi_env env, const HapModuleInfo &hapModuleInfo, napi_value objHapModuleInfo);

static void ConvertDependency(napi_env env, const Dependency &dependency, napi_value value);

static void ConvertBundleInfo(napi_env env, const BundleInfo &bundleInfo, napi_value objBundleInfo, int32_t flags);

static void ConvertBundleChangeInfo(napi_env env, const std::string &bundleName,
    int32_t userId, int32_t appIndex, napi_value bundleChangeInfo);

static void ConvertLauncherAbilityInfo(napi_env env, const LauncherAbilityInfo &launcherAbility, napi_value value);

static void ConvertLauncherAbilityInfos(napi_env env,
    const std::vector<LauncherAbilityInfo> &launcherAbilities, napi_value value);

static void ConvertShortcutIntent(napi_env env,
    const OHOS::AppExecFwk::ShortcutIntent &shortcutIntent, napi_value value);

static void ConvertShortCutInfo(napi_env env, const ShortcutInfo &shortcutInfo, napi_value value);

static void ConvertShortCutInfos(napi_env env, const std::vector<ShortcutInfo> &shortcutInfos, napi_value value);

static void ConvertPreloadItem(napi_env env, const PreloadItem &preloadItem, napi_value value);

static void ConvertOverlayModuleInfo(napi_env env, const OverlayModuleInfo &info, napi_value objOverlayModuleInfo);

static void ConvertOverlayModuleInfos(napi_env env, const std::vector<OverlayModuleInfo> &Infos, napi_value objInfos);

static void ConvertModuleMetaInfos(napi_env env,
    const std::map<std::string, std::vector<Metadata>> &metadata, napi_value objInfos);

static std::string ObtainCallingBundleName();

static void ConvertSharedModuleInfo(napi_env env, napi_value value, const SharedModuleInfo &moduleInfo);
static void ConvertSharedBundleInfo(napi_env env, napi_value value, const SharedBundleInfo &bundleInfo);
static void ConvertAllSharedBundleInfo(napi_env env, napi_value value,
    const std::vector<SharedBundleInfo> &sharedBundles);
static void ConvertRecoverableApplicationInfo(
    napi_env env, napi_value value, const RecoverableApplicationInfo &recoverableApplication);
static void ConvertRecoverableApplicationInfos(napi_env env, napi_value value,
    const std::vector<RecoverableApplicationInfo> &recoverableApplications);

static void ConvertRouterItem(napi_env env, const RouterItem &routerItem, napi_value value);
static void ConvertRouterDataInfos(napi_env env, const std::map<std::string, std::string> &data, napi_value objInfos);
static void ConvertAbilitySkillUri(napi_env env, const SkillUri &skillUri, napi_value value, bool isExtension);
static void ConvertAbilitySkill(napi_env env, const Skill &skill, napi_value value, bool isExtension);

static void ConvertParameters(napi_env env,
    const std::map<std::string, std::string> &data, napi_value objInfos);

static bool CheckShortcutInfo(const ShortcutInfo &shortcutInfo);

class BundleMgrCommonDeathRecipient : public IRemoteObject::DeathRecipient {
    void OnRemoteDied([[maybe_unused]] const wptr<IRemoteObject>& remote) override;
};

template<typename T>
static napi_value AsyncCallNativeMethod(napi_env env,
                                 T *asyncCallbackInfo,
                                 const std::string &methodName,
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
        reinterpret_cast<void*>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    return promise;
}

template<typename T>
static void NapiReturnDeferred(napi_env env, T *asyncCallbackInfo, napi_value result[], const size_t resultSize)
{
    const size_t size = 1;
    if (resultSize < size) {
        return;
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->err == 0) {
            if (resultSize == size) {
                napi_get_undefined(env, &result[0]);
                NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[0]));
            } else {
                NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[size]));
            }
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback, resultSize, result, &placeHolder));
    }
}

private:
    static sptr<IBundleMgr> bundleMgr_;
    static std::mutex bundleMgrMutex_;
    static sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};

#define PARSE_PROPERTY(env, property, funcType, value)                                        \
    do {                                                                                      \
        NAPI_CALL_BASE(env, napi_get_value_##funcType(env, property, (&(value))), false);         \
    } while (0)

#define CHKRV_SCOPE(env, state, scope) \
    do { \
        if ((state) != napi_ok) { \
            napi_close_handle_scope(env, scope); \
            return; \
        } \
    } while (0)
} // AppExecFwk
} // OHOS
#endif