/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef BUNDLE_MGR_H
#define BUNDLE_MGR_H
#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

#include "application_info.h"
#include "bundle_death_recipient.h"
#include "bundle_mgr_interface.h"
#include "cleancache_callback.h"
#include "js_runtime_utils.h"
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
#include "pixel_map.h"
#endif
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
struct AsyncWorkData {
    explicit AsyncWorkData(napi_env napiEnv);
    virtual ~AsyncWorkData();
    napi_env env;
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;
};

struct BaseCallbackInfo: public AsyncWorkData {
    explicit BaseCallbackInfo(napi_env napiEnv) : AsyncWorkData(napiEnv) {}
    int32_t err = 0;
    std::string message;
};

struct QueryParameter {
    int flags;
    std::string userId;
};

struct BundleOptions {
    int32_t userId = Constants::UNSPECIFIED_USERID;
};

struct AbilityEnableCallbackInfo : public BaseCallbackInfo {
    explicit AbilityEnableCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    bool isEnable = false;
    AbilityInfo abilityInfo;
};

struct ApplicationEnableCallbackInfo : public BaseCallbackInfo {
    explicit ApplicationEnableCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    bool isEnable = false;
    std::string bundleName;
};

struct LaunchWantCallbackInfo : public BaseCallbackInfo {
    explicit LaunchWantCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    int32_t userId = Constants::UNSPECIFIED_USERID;
    ErrCode ret = ERR_OK;
    std::string bundleName;
    OHOS::AAFwk::Want want;
};

struct GetBundleArchiveInfoCallbackInfo : public BaseCallbackInfo {
    explicit GetBundleArchiveInfoCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    bool ret = false;
    int32_t flags = 0;
    std::string hapFilePath;
    BundleInfo bundleInfo;
};

struct AbilityIconCallbackInfo : public BaseCallbackInfo {
    explicit AbilityIconCallbackInfo(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}
    bool hasModuleName = false;
    ErrCode ret = ERR_OK;
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
#endif
};

struct AsyncAbilityInfoCallbackInfo : public AsyncWorkData {
    explicit AsyncAbilityInfoCallbackInfo(napi_env env) : AsyncWorkData(env) {}
    bool ret = false;
    int32_t err = 0;
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::vector<OHOS::AppExecFwk::AbilityInfo> abilityInfos;
    OHOS::AAFwk::Want want;
};

struct AsyncAbilityInfosCallbackInfo : public AsyncWorkData {
    explicit AsyncAbilityInfosCallbackInfo(napi_env env) : AsyncWorkData(env) {}
    bool hasModuleName = false;
    bool ret = false;
    int32_t err = 0;
    int32_t flags = 0;
    std::string message;
    std::string bundleName;
    std::string abilityName;
    std::string moduleName = "";
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
};

struct AsyncBundleInfoCallbackInfo : public AsyncWorkData {
    explicit AsyncBundleInfoCallbackInfo(napi_env env) : AsyncWorkData(env) {}
    bool ret = false;
    int32_t err = 0;
    int32_t flags = 0;
    std::string param;
    std::string message;
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    BundleOptions bundleOptions;
};

struct AsyncApplicationInfoCallbackInfo : public AsyncWorkData {
    explicit AsyncApplicationInfoCallbackInfo(napi_env env) : AsyncWorkData(env) {}
    bool ret = false;
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    int32_t err = 0;
    std::string bundleName;
    std::string message;
    OHOS::AppExecFwk::ApplicationInfo appInfo;
};

struct AsyncPermissionDefCallbackInfo : public AsyncWorkData {
    explicit AsyncPermissionDefCallbackInfo(napi_env env) : AsyncWorkData(env) {}
    bool ret = false;
    int32_t err = 0;
    std::string message;
    std::string permissionName;
    OHOS::AppExecFwk::PermissionDef permissionDef;
};

struct AsyncBundleInfosCallbackInfo : public AsyncWorkData {
    explicit AsyncBundleInfosCallbackInfo(napi_env env) : AsyncWorkData(env) {}
    bool ret = false;
    int32_t flags = 0;
    int32_t err = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::string message;
    std::vector<OHOS::AppExecFwk::BundleInfo> bundleInfos;
};

struct AsyncApplicationInfosCallbackInfo : public AsyncWorkData {
    explicit AsyncApplicationInfosCallbackInfo(napi_env env) : AsyncWorkData(env) {}
    bool ret = false;
    int32_t flags = 0;
    int32_t userId = Constants::UNSPECIFIED_USERID;
    int32_t err = 0;
    std::string message;
    std::vector<OHOS::AppExecFwk::ApplicationInfo> appInfos;
};

struct AsyncAbilityLabelCallbackInfo : public AsyncWorkData {
    explicit AsyncAbilityLabelCallbackInfo(napi_env env) : AsyncWorkData(env) {}
    bool hasModuleName = false;
    int32_t err = 0;
    std::string bundleName;
    std::string className;
    std::string moduleName = "";
    std::string abilityLabel;
    std::string message;
};

struct InstallResult {
    int32_t resultCode = 0;
    std::string resultMsg;
};

struct AsyncInstallCallbackInfo : public AsyncWorkData {
    explicit AsyncInstallCallbackInfo(napi_env env) : AsyncWorkData(env) {}
    int32_t errCode = 0;
    std::string bundleName;
    std::string param;
    std::vector<std::string> hapFiles;
    OHOS::AppExecFwk::InstallParam installParam;
    InstallResult installResult;
};

struct AsyncGetBundleInstallerCallbackInfo : public AsyncWorkData {
    explicit AsyncGetBundleInstallerCallbackInfo(napi_env env) : AsyncWorkData(env) {}
};

struct AsyncFormInfosCallbackInfo : public AsyncWorkData {
    explicit AsyncFormInfosCallbackInfo(napi_env env) : AsyncWorkData(env) {}
    bool ret = false;
    std::vector<OHOS::AppExecFwk::FormInfo> formInfos;
};

struct AsyncFormInfosByModuleCallbackInfo : public AsyncWorkData {
    explicit AsyncFormInfosByModuleCallbackInfo(napi_env env) : AsyncWorkData(env) {}
    bool ret = false;
    std::string bundleName;
    std::string moduleName;
    std::vector<OHOS::AppExecFwk::FormInfo> formInfos;
};

struct AsyncFormInfosByAppCallbackInfo : public AsyncWorkData {
    explicit AsyncFormInfosByAppCallbackInfo(napi_env env) : AsyncWorkData(env) {}
    bool ret = false;
    std::string bundleName;
    std::vector<OHOS::AppExecFwk::FormInfo> formInfos;
};

struct AsyncLaunchWantForBundleCallbackInfo : public AsyncWorkData {
    explicit AsyncLaunchWantForBundleCallbackInfo(napi_env env) : AsyncWorkData(env) {}
    bool ret = false;
    int32_t err = 0;
    std::string bundleName;
    OHOS::AAFwk::Want want;
};

struct AsyncGetBundleGidsCallbackInfo : public AsyncWorkData {
    explicit AsyncGetBundleGidsCallbackInfo(napi_env env) : AsyncWorkData(env) {}
    bool ret = false;
    int32_t err = 0;
    std::string message;
    std::string bundleName;
    std::vector<int32_t> gids;
};

struct AsyncGetNameByUidInfo : public AsyncWorkData {
    explicit AsyncGetNameByUidInfo(napi_env env) : AsyncWorkData(env) {}
    bool ret = false;
    int32_t uid = 0;
    int32_t err = 0;
    std::string bundleName;
};

struct AsyncHandleBundleContext : public AsyncWorkData {
    explicit AsyncHandleBundleContext(napi_env env) : AsyncWorkData(env) {}
    bool ret = false;
    uint32_t labelId = 0;
    uint32_t iconId = 0;
    int32_t err = 0;
    std::string bundleName;
    std::string className;
    OHOS::sptr<CleanCacheCallback> cleanCacheCallback;
};

struct EnabledInfo : public AsyncWorkData {
    explicit EnabledInfo(napi_env env) : AsyncWorkData(env) {}
    bool isEnable = false;
    bool result = false;
    int32_t errCode = 0;
    std::string errMssage;
    std::string bundleName;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
};

struct AsyncAbilityInfo : public AsyncWorkData {
    explicit AsyncAbilityInfo(napi_env env) : AsyncWorkData(env) {}
    bool hasModuleName = false;
    bool result = false;
    int32_t errCode = 0;
    std::string bundleName;
    std::string abilityName;
    std::string moduleName = "";
    std::string errMssage;
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
    std::shared_ptr<Media::PixelMap> pixelMap;
#endif
};

struct Query {
    std::string bundleName_;
    std::string interfaceType_;
    int32_t flags_ = 0;
    int32_t userId_ = Constants::UNSPECIFIED_USERID;
    napi_env env_;
    Query(const std::string &bundleName, const std::string &interfaceType, int32_t flags, int32_t userId, napi_env env)
        : bundleName_(bundleName), interfaceType_(interfaceType), flags_(flags), userId_(userId), env_(env) {}

    bool operator==(const Query &query) const
    {
        return bundleName_ == query.bundleName_ && interfaceType_ == query.interfaceType_ &&
            flags_ == query.flags_ && userId_ == query.userId_ && env_ == query.env_;
    }
};

struct QueryHash  {
    size_t operator()(const Query &query) const
    {
        return std::hash<std::string>()(query.bundleName_) ^ std::hash<std::string>()(query.interfaceType_) ^
            std::hash<int32_t>()(query.flags_) ^ std::hash<int32_t>()(query.userId_);
    }
};

class BundleMgrDeathRecipient : public IRemoteObject::DeathRecipient {
    virtual void OnRemoteDied([[maybe_unused]] const wptr<IRemoteObject>& remote) override;
};

extern thread_local napi_ref g_classBundleInstaller;

napi_value WrapVoidToJS(napi_env env);
napi_value GetApplicationInfos(napi_env env, napi_callback_info info);
napi_value QueryAbilityInfos(napi_env env, napi_callback_info info);
napi_value GetBundleInfos(napi_env env, napi_callback_info info);
napi_value GetPermissionDef(napi_env env, napi_callback_info info);
napi_value GetBundleInfo(napi_env env, napi_callback_info info);
napi_value GetNameForUid(napi_env env, napi_callback_info info);
napi_value GetPermissionDef(napi_env env, napi_callback_info info);
napi_value GetAllFormsInfo(napi_env env, napi_callback_info info);
napi_value GetFormsInfoByApp(napi_env env, napi_callback_info info);
napi_value GetFormsInfoByModule(napi_env env, napi_callback_info info);
napi_value GetShortcutInfos(napi_env env, napi_callback_info info);
napi_value UnregisterPermissionsChanged(napi_env env, napi_callback_info info);
napi_value ClearBundleCache(napi_env env, napi_callback_info info);
napi_value GetBundleArchiveInfo(napi_env env, napi_callback_info info);
napi_value GetAbilityIcon(napi_env env, napi_callback_info info);
napi_value GetLaunchWantForBundle(napi_env env, napi_callback_info info);
napi_value IsApplicationEnabled(napi_env env, napi_callback_info info);
napi_value IsAbilityEnabled(napi_env env, napi_callback_info info);
napi_value SetAbilityEnabled(napi_env env, napi_callback_info info);
napi_value SetApplicationEnabled(napi_env env, napi_callback_info info);
napi_value GetBundleGids(napi_env env, napi_callback_info info);
napi_value GetAbilityInfo(napi_env env, napi_callback_info info);
napi_value GetAbilityLabel(napi_env env, napi_callback_info info);
napi_value GetBundleInstaller(napi_env env, napi_callback_info info);
napi_value Install(napi_env env, napi_callback_info info);
napi_value Recover(napi_env env, napi_callback_info info);
napi_value Uninstall(napi_env env, napi_callback_info info);
napi_value BundleInstallerConstructor(napi_env env, napi_callback_info info);
bool UnwrapAbilityInfo(napi_env env, napi_value param, OHOS::AppExecFwk::AbilityInfo& abilityInfo);
void CreateInstallErrorCodeObject(napi_env env, napi_value value);

napi_value CreateAbilityTypeObject(napi_env env);
napi_value CreateAbilitySubTypeObject(napi_env env);
napi_value CreateDisplayOrientationObject(napi_env env);
napi_value CreateLaunchModeObject(napi_env env);
napi_value CreateColorModeObject(napi_env env);
napi_value CreateGrantStatusObject(napi_env env);
napi_value CreateModuleRemoveFlagObject(napi_env env);
napi_value CreateSignatureCompareResultObject(napi_env env);
napi_value CreateShortcutExistenceObject(napi_env env);
napi_value CreateQueryShortCutFlagObject(napi_env env);
napi_value CreateBundleFlagObject(napi_env env);
napi_value GetAllApplicationInfo(napi_env env, napi_callback_info info);
napi_value GetApplicationInfo(napi_env env, napi_callback_info info);
class JsBundleMgr {
public:
    JsBundleMgr() = default;
    ~JsBundleMgr() = default;

    struct JsAbilityInfo {
        bool hasModuleName = false;
        bool ret = false;
        std::string bundleName;
        std::string abilityName;
        std::string moduleName = "";
        OHOS::AppExecFwk::AbilityInfo abilityInfo;
    };

    struct JsNameForUid {
        bool ret = false;
        int32_t uid;
        std::string bundleName;
    };

    struct JsAbilityLabel {
        bool hasModuleName = false;
        std::string bundleName;
        std::string className;
        std::string moduleName = "";
        std::string abilityLabel;
    };

    struct JsAbilityIcon {
        bool hasModuleName = false;
        std::string bundleName;
        std::string abilityName;
        std::string moduleName = "";
    };

    struct JsGetPermissionDef {
        bool ret = false;
        std::string permissionName;
        OHOS::AppExecFwk::PermissionDef permissionDef;
    };

    struct JsQueryAbilityInfo {
        bool ret = false;
        bool getCache = false;
        std::vector<AbilityInfo> abilityInfos;
    };
    std::string errMessage_;

private:
};

class JsBundleInstall {
public:
    JsBundleInstall() = default;
    ~JsBundleInstall() = default;
    struct BundleInstallResult {
        int32_t resCode = 0;
        std::string resMessage;
    };
private:
    static void ConvertInstallResult(std::shared_ptr<BundleInstallResult> installResult);
};

}  // namespace AppExecFwk
}  // namespace OHOS
#endif /* BUNDLE_MGR_H */
