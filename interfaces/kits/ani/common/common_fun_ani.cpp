/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <charconv>
#include <vector>

#include "ani_signature_builder.h"
#include "app_log_wrapper.h"
#include "common_fun_ani.h"

namespace OHOS {
namespace AppExecFwk {
using namespace arkts::ani_signature;
using Want = OHOS::AAFwk::Want;
namespace {
constexpr const char* CLASSNAME_ABILITY_INFO_INNER = "bundleManager.AbilityInfoInner.AbilityInfoInner";
constexpr const char* CLASSNAME_EXTENSION_ABILITY_INFO_INNER =
    "bundleManager.ExtensionAbilityInfoInner.ExtensionAbilityInfoInner";
constexpr const char* CLASSNAME_WINDOW_SIZE = "bundleManager.AbilityInfo.WindowSize";
constexpr const char* CLASSNAME_WINDOW_SIZE_INNER = "bundleManager.AbilityInfoInner.WindowSizeInner";
constexpr const char* CLASSNAME_APPLICATION_INFO = "bundleManager.ApplicationInfo.ApplicationInfo";
constexpr const char* CLASSNAME_APPLICATION_INFO_INNER = "bundleManager.ApplicationInfoInner.ApplicationInfoInner";
constexpr const char* CLASSNAME_MODULE_METADATA_INNER = "bundleManager.ApplicationInfoInner.ModuleMetadataInner";
constexpr const char* CLASSNAME_MULTI_APP_MODE = "bundleManager.ApplicationInfo.MultiAppMode";
constexpr const char* CLASSNAME_MULTI_APP_MODE_INNER = "bundleManager.ApplicationInfoInner.MultiAppModeInner";
constexpr const char* CLASSNAME_BUNDLE_INFO_INNER = "bundleManager.BundleInfoInner.BundleInfoInner";
constexpr const char* CLASSNAME_PERMISSION_INNER = "bundleManager.BundleInfoInner.ReqPermissionDetailInner";
constexpr const char* CLASSNAME_USED_SCENE = "bundleManager.BundleInfo.UsedScene";
constexpr const char* CLASSNAME_USED_SCENE_INNER = "bundleManager.BundleInfoInner.UsedSceneInner";
constexpr const char* CLASSNAME_SIGNATURE_INFO = "bundleManager.BundleInfo.SignatureInfo";
constexpr const char* CLASSNAME_SIGNATURE_INFO_INNER = "bundleManager.BundleInfoInner.SignatureInfoInner";
constexpr const char* CLASSNAME_APP_CLONE_IDENTITY_INNER = "bundleManager.BundleInfoInner.AppCloneIdentityInner";
constexpr const char* CLASSNAME_DYNAMIC_ICON_INFO_INNER = "bundleManager.BundleInfoInner.DynamicIconInfoInner";
constexpr const char* CLASSNAME_PERMISSION_DEF_INNER = "bundleManager.PermissionDefInner.PermissionDefInner";
constexpr const char* CLASSNAME_SHARED_BUNDLE_INFO_INNER = "bundleManager.SharedBundleInfoInner.SharedBundleInfoInner";
constexpr const char* CLASSNAME_SHARED_MODULE_INFO_INNER = "bundleManager.SharedBundleInfoInner.SharedModuleInfoInner";
constexpr const char* CLASSNAME_APP_PROVISION_INFO_INNER = "bundleManager.AppProvisionInfoInner.AppProvisionInfoInner";
constexpr const char* CLASSNAME_VALIDITY = "bundleManager.AppProvisionInfo.Validity";
constexpr const char* CLASSNAME_VALIDITY_INNER = "bundleManager.AppProvisionInfoInner.ValidityInner";
constexpr const char* CLASSNAME_RECOVERABLE_APPLICATION_INFO_INNER =
    "bundleManager.RecoverableApplicationInfoInner.RecoverableApplicationInfoInner";
constexpr const char* CLASSNAME_PREINSTALLED_APPLICATION_INFO_INNER =
    "bundleManager.ApplicationInfoInner.PreinstalledApplicationInfoInner";
constexpr const char* CLASSNAME_PLUGIN_BUNDLE_INFO_INNER = "bundleManager.PluginBundleInfoInner.PluginBundleInfoInner";
constexpr const char* CLASSNAME_PLUGIN_MODULE_INFO_INNER = "bundleManager.PluginBundleInfoInner.PluginModuleInfoInner";
constexpr const char* CLASSNAME_METADATA_INNER = "bundleManager.MetadataInner.MetadataInner";
constexpr const char* CLASSNAME_RESOURCE = "global.resource.Resource";
constexpr const char* CLASSNAME_RESOURCE_INNER = "global.resourceInner.ResourceInner";
constexpr const char* CLASSNAME_ROUTER_ITEM_INNER = "bundleManager.HapModuleInfoInner.RouterItemInner";
constexpr const char* CLASSNAME_PRELOAD_ITEM_INNER = "bundleManager.HapModuleInfoInner.PreloadItemInner";
constexpr const char* CLASSNAME_DEPENDENCY_INNER = "bundleManager.HapModuleInfoInner.DependencyInner";
constexpr const char* CLASSNAME_HAP_MODULE_INFO_INNER = "bundleManager.HapModuleInfoInner.HapModuleInfoInner";
constexpr const char* CLASSNAME_DATA_ITEM_INNER = "bundleManager.HapModuleInfoInner.DataItemInner";
constexpr const char* CLASSNAME_ELEMENT_NAME = "bundleManager.ElementName.ElementNam";
constexpr const char* CLASSNAME_ELEMENT_NAME_INNER = "bundleManager.ElementNameInner.ElementNameInner";
constexpr const char* CLASSNAME_SKILL_INNER = "bundleManager.SkillInner.SkillInner";
constexpr const char* CLASSNAME_SKILL_URI_INNER = "bundleManager.SkillInner.SkillUriInner";
constexpr const char* CLASSNAME_SHORTCUT_INFO_INNER = "bundleManager.ShortcutInfo.ShortcutInfoInner";
constexpr const char* CLASSNAME_SHORTCUT_WANT_INNER = "bundleManager.ShortcutInfo.ShortcutWantInner";
constexpr const char* CLASSNAME_SHORTCUT_PARAMETER_ITEM_INNER = "bundleManager.ShortcutInfo.ParameterItemInner";
constexpr const char* CLASSNAME_LAUNCHER_ABILITY_INFO_INNER =
    "bundleManager.LauncherAbilityInfoInner.LauncherAbilityInfoInner";
constexpr const char* CLASSNAME_BUNDLE_CHANGED_INFO_INNER =
    "@ohos.bundle.bundleMonitor.bundleMonitor.BundleChangedInfoInner";
constexpr const char* CLASSNAME_BUNDLE_PACK_INFO_INNER = "bundleManager.BundlePackInfoInner.BundlePackInfoInner";
constexpr const char* CLASSNAME_PACKAGE_CONFIG_INNER = "bundleManager.BundlePackInfoInner.PackageConfigInner";
constexpr const char* CLASSNAME_PACKAGE_SUMMARY = "bundleManager.BundlePackInfo.PackageSummary";
constexpr const char* CLASSNAME_PACKAGE_SUMMARY_INNER = "bundleManager.BundlePackInfoInner.PackageSummaryInner";
constexpr const char* CLASSNAME_BUNDLE_CONFIG_INFO = "bundleManager.BundlePackInfo.BundleConfigInfo";
constexpr const char* CLASSNAME_BUNDLE_CONFIG_INFO_INNER = "bundleManager.BundlePackInfoInner.BundleConfigInfoInner";
constexpr const char* CLASSNAME_EXTENSION_ABILITY_INNER = "bundleManager.BundlePackInfoInner.ExtensionAbilityInner";
constexpr const char* CLASSNAME_MODULE_CONFIG_INFO_INNER = "bundleManager.BundlePackInfoInner.ModuleConfigInfoInner";
constexpr const char* CLASSNAME_MODULE_DISTRO_INFO = "bundleManager.BundlePackInfo.ModuleDistroInfo";
constexpr const char* CLASSNAME_MODULE_DISTRO_INFO_INNER = "bundleManager.BundlePackInfoInner.ModuleDistroInfoInner";
constexpr const char* CLASSNAME_MODULE_ABILITY_INFO_INNER =
    "bundleManager.BundlePackInfoInner.ModuleAbilityInfoInner";
constexpr const char* CLASSNAME_ABILITY_FORM_INFO_INNER = "bundleManager.BundlePackInfoInner.AbilityFormInfoInner";
constexpr const char* CLASSNAME_VERSION = "bundleManager.BundlePackInfo.Version";
constexpr const char* CLASSNAME_VERSION_INNER = "bundleManager.BundlePackInfoInner.VersionInner";
constexpr const char* CLASSNAME_API_VERSION = "bundleManager.BundlePackInfo.ApiVersion";
constexpr const char* CLASSNAME_API_VERSION_INNER = "bundleManager.BundlePackInfoInner.ApiVersionInner";
constexpr const char* CLASSNAME_DISPATCH_INFO_INNER = "bundleManager.DispatchInfoInner.DispatchInfoInner";
constexpr const char* CLASSNAME_OVERLAY_MODULE_INFO_INNER =
    "bundleManager.OverlayModuleInfoInner.OverlayModuleInfoInner";
constexpr const char* CLASSNAME_WANT = "@ohos.app.ability.Want.Want";
constexpr const char* CLASSNAME_ZLIB_CHECKSUM_INTERNAL = "@ohos.zlib.zlib.ChecksumInternal";
constexpr const char* CLASSNAME_ZLIB_GZIP_INTERNAL = "@ohos.zlib.zlib.GZipInternal";

constexpr const char* PROPERTYNAME_NAME = "name";
constexpr const char* PROPERTYNAME_VERSION_CODE = "versionCode";
constexpr const char* PROPERTYNAME_APP_INDEX = "appIndex";
constexpr const char* PROPERTYNAME_KEY = "key";
constexpr const char* PROPERTYNAME_VALUE = "value";
constexpr const char* PROPERTYNAME_MODULE_NAME = "moduleName";
constexpr const char* PROPERTYNAME_LABEL = "label";
constexpr const char* PROPERTYNAME_LABEL_ID = "labelId";
constexpr const char* PROPERTYNAME_ICON = "icon";
constexpr const char* PROPERTYNAME_ICON_ID = "iconId";
constexpr const char* PROPERTYNAME_BUNDLE_NAME = "bundleName";
constexpr const char* PROPERTYNAME_ID = "id";
constexpr const char* PROPERTYNAME_HASH_VALUE = "hashValue";
constexpr const char* PROPERTYNAME_DEVICE_ID = "deviceId";
constexpr const char* PROPERTYNAME_ABILITY_NAME = "abilityName";
constexpr const char* PROPERTYNAME_ENTITIES = "entities";
constexpr const char* PROPERTYNAME_HOST_ABILITY = "hostAbility";
constexpr const char* PROPERTYNAME_WANTS = "wants";
constexpr const char* PROPERTYNAME_SOURCE_TYPE = "sourceType";
constexpr const char* PROPERTYNAME_TARGET_BUNDLE = "targetBundle";
constexpr const char* PROPERTYNAME_TARGET_MODULE = "targetModule";
constexpr const char* PROPERTYNAME_TARGET_ABILITY = "targetAbility";
constexpr const char* PROPERTYNAME_PARAMETERS = "parameters";
constexpr const char* PROPERTYNAME_USER_ID = "userId";
constexpr const char* PROPERTYNAME_HASH_PARAMS = "hashParams";
constexpr const char* PROPERTYNAME_PGO_FILE_PATH = "pgoFilePath";
constexpr const char* PROPERTYNAME_PGO_PARAMS = "pgoParams";
constexpr const char* PROPERTYNAME_SPECIFIED_DISTRIBUTION_TYPE = "specifiedDistributionType";
constexpr const char* PROPERTYNAME_IS_KEEP_DATA = "isKeepData";
constexpr const char* PROPERTYNAME_INSTALL_FLAG = "installFlag";
constexpr const char* PROPERTYNAME_CROWD_TEST_DEADLINE = "crowdtestDeadline";
constexpr const char* PROPERTYNAME_SHARED_BUNDLE_DIR_PATHS = "sharedBundleDirPaths";
constexpr const char* PROPERTYNAME_ADDITIONAL_INFO = "additionalInfo";
constexpr const char* PROPERTYNAME_VISIBLE = "visible";
constexpr const char* PROPERTYNAME_ACTION = "action";

constexpr const char* PATH_PREFIX = "/data/app/el1/bundle/public";
constexpr const char* CODE_PATH_PREFIX = "/data/storage/el1/bundle/";
constexpr const char* CONTEXT_DATA_STORAGE_BUNDLE = "/data/storage/el1/bundle/";

struct ANIClassCacheItem {
    ani_ref classRef = nullptr;
    std::map<std::string, ani_method> classMethodMap;
};
static std::mutex g_aniClassCacherMutex;
static std::map<std::string, ANIClassCacheItem> g_aniClassCache = {
    { CommonFunAniNS::CLASSNAME_BOOLEAN, { } },
    { CommonFunAniNS::CLASSNAME_INT, { } },
    { CommonFunAniNS::CLASSNAME_LONG, { } },
    { CommonFunAniNS::CLASSNAME_DOUBLE, { } },
    { CommonFunAniNS::CLASSNAME_ARRAY, { } },
    { CLASSNAME_BUNDLE_INFO_INNER, { } },
    { CLASSNAME_APPLICATION_INFO_INNER, { } },
    { CLASSNAME_MODULE_METADATA_INNER, { } },
    { CLASSNAME_METADATA_INNER, { } },
    { CLASSNAME_RESOURCE_INNER, { } },
    { CLASSNAME_MULTI_APP_MODE_INNER, { } },
    { CLASSNAME_HAP_MODULE_INFO_INNER, { } },
    { CLASSNAME_ABILITY_INFO_INNER, { } },
    { CLASSNAME_SKILL_INNER, { } },
    { CLASSNAME_WINDOW_SIZE_INNER, { } },
    { CLASSNAME_EXTENSION_ABILITY_INFO_INNER, { } },
    { CLASSNAME_DEPENDENCY_INNER, { } },
    { CLASSNAME_PRELOAD_ITEM_INNER, { } },
    { CLASSNAME_ROUTER_ITEM_INNER, { } },
    { CLASSNAME_DATA_ITEM_INNER, { } },
    { CLASSNAME_ZLIB_CHECKSUM_INTERNAL, { } },
    { CLASSNAME_ZLIB_GZIP_INTERNAL, { } },
};

static ani_class GetCacheClass(ani_env* env, const std::string& className)
{
    RETURN_NULL_IF_NULL(env);

    std::lock_guard<std::mutex> lock(g_aniClassCacherMutex);
    auto iter = g_aniClassCache.find(className);
    if (iter == g_aniClassCache.end()) {
        return nullptr;
    }
    if (iter->second.classRef != nullptr) {
        return reinterpret_cast<ani_class>(iter->second.classRef);
    }

    ani_class cls = nullptr;
    ani_status status = env->FindClass(className.c_str(), &cls);
    if (status != ANI_OK) {
        APP_LOGE("FindClass %{public}s failed %{public}d", className.c_str(), status);
        return nullptr;
    }
    ani_ref ref = nullptr;
    status = env->GlobalReference_Create(cls, &ref);
    if (status == ANI_OK) {
        iter->second.classRef = ref;
    }

    return cls;
}

static ani_method GetCacheCtorMethod(ani_env* env, const std::string& className, ani_class cls,
    const std::string& ctorSig = Builder::BuildSignatureDescriptor({}))
{
    RETURN_NULL_IF_NULL(env);
    RETURN_NULL_IF_NULL(cls);

    std::lock_guard<std::mutex> lock(g_aniClassCacherMutex);
    auto iter = g_aniClassCache.find(className);
    if (iter == g_aniClassCache.end()) {
        return nullptr;
    }

    auto iterMethod = iter->second.classMethodMap.find(ctorSig);
    if (iterMethod != iter->second.classMethodMap.end() && iterMethod->second != nullptr) {
        return iterMethod->second;
    }

    ani_method method = nullptr;
    ani_status status =
        env->Class_FindMethod(cls, Builder::BuildConstructorName().c_str(), ctorSig.c_str(), &method);
    if (status != ANI_OK) {
        APP_LOGE("Class_FindMethod ctorSig %{public}s failed %{public}d", ctorSig.c_str(), status);
        return nullptr;
    }
    iter->second.classMethodMap[ctorSig] = method;

    return method;
}

static ani_method GetCtorMethod(ani_env* env, const std::string& className, ani_class cls,
    const std::string& ctorSig = Builder::BuildSignatureDescriptor({}))
{
    RETURN_NULL_IF_NULL(env);
    RETURN_NULL_IF_NULL(cls);

    ani_method method = GetCacheCtorMethod(env, className, cls, ctorSig);
    if (method != nullptr) {
        return method;
    }

    ani_status status =
        env->Class_FindMethod(cls, Builder::BuildConstructorName().c_str(), ctorSig.c_str(), &method);
    if (status != ANI_OK) {
        APP_LOGE("Class_FindMethod ctorSig %{public}s failed %{public}d", ctorSig.c_str(), status);
        return nullptr;
    }

    return method;
}
} // namespace

std::string CommonFunAni::AniStrToString(ani_env* env, ani_string aniStr)
{
    if (env == nullptr || aniStr == nullptr) {
        APP_LOGE("env or aniStr is null");
        return "";
    }

    ani_size strSize = 0;
    ani_status status = env->String_GetUTF8Size(aniStr, &strSize);
    if (status != ANI_OK) {
        APP_LOGE("String_GetUTF8Size failed %{public}d", status);
        return "";
    }

    std::string buffer;
    buffer.resize(strSize + 1);
    ani_size retSize = 0;
    status = env->String_GetUTF8(aniStr, buffer.data(), buffer.size(), &retSize);
    if (status != ANI_OK) {
        APP_LOGE("String_GetUTF8SubString failed %{public}d", status);
        return "";
    }

    buffer.resize(retSize);
    return buffer;
}

bool CommonFunAni::ParseString(ani_env* env, ani_string aniStr, std::string& result)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(aniStr);

    ani_size strSize = 0;
    ani_status status = env->String_GetUTF8Size(aniStr, &strSize);
    if (status != ANI_OK) {
        APP_LOGE("String_GetUTF8Size failed %{public}d", status);
        return false;
    }

    result.resize(strSize + 1);
    ani_size retSize = 0;
    status = env->String_GetUTF8(aniStr, result.data(), result.size(), &retSize);
    if (status != ANI_OK) {
        APP_LOGE("String_GetUTF8SubString failed %{public}d", status);
        return false;
    }

    result.resize(retSize);
    return true;
}

ani_class CommonFunAni::CreateClassByName(ani_env* env, const std::string& className)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = GetCacheClass(env, className);
    if (cls == nullptr) {
        ani_status status = env->FindClass(className.c_str(), &cls);
        if (status != ANI_OK) {
            APP_LOGE("FindClass %{public}s failed %{public}d", className.c_str(), status);
            return nullptr;
        }
    }

    return cls;
}

ani_object CommonFunAni::CreateNewObjectByClass(ani_env* env, const std::string& className, ani_class cls)
{
    RETURN_NULL_IF_NULL(env);
    RETURN_NULL_IF_NULL(cls);

    ani_method method = GetCtorMethod(env, className, cls);
    RETURN_NULL_IF_NULL(method);

    ani_object object = nullptr;
    ani_status status = env->Object_New(cls, method, &object);
    if (status != ANI_OK) {
        APP_LOGE("Object_New failed %{public}d", status);
        return nullptr;
    }
    return object;
}

ani_object CommonFunAni::CreateNewObjectByClassV2(
    ani_env* env, const std::string& className, const std::string& ctorSig, const ani_value* args)
{
    RETURN_NULL_IF_NULL(env);
    RETURN_NULL_IF_NULL(args);

    ani_class cls = CreateClassByName(env, className);
    RETURN_NULL_IF_NULL(cls);

    ani_method method = GetCtorMethod(env, className, cls, ctorSig);
    RETURN_NULL_IF_NULL(method);
    ani_object object = nullptr;
    ani_status status = env->Object_New_A(cls, method, &object, args);
    if (status != ANI_OK) {
        APP_LOGE("Object_New_A failed %{public}d", status);
        return nullptr;
    }
    return object;
}

ani_object CommonFunAni::ConvertBundleInfo(ani_env* env, const BundleInfo& bundleInfo, int32_t flags)
{
    RETURN_NULL_IF_NULL(env);

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleInfo.name, name));

    // vendor: string
    ani_string vendor = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleInfo.vendor, vendor));

    // versionName: string
    ani_string versionName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleInfo.versionName, versionName));

    // appInfo: ApplicationInfo
    ani_ref appInfo = nullptr;
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)) ==
        static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)) {
        appInfo = ConvertApplicationInfo(env, bundleInfo.applicationInfo);
    } else {
        ani_status status = env->GetNull(&appInfo);
        if (status != ANI_OK) {
            APP_LOGE("GetNull appInfo failed %{public}d", status);
            return nullptr;
        }
    }
    RETURN_NULL_IF_NULL(appInfo);

    // hapModulesInfo: Array<HapModuleInfo>
    ani_object hapModulesInfo = ConvertAniArray(env, bundleInfo.hapModuleInfos, ConvertHapModuleInfo);
    RETURN_NULL_IF_NULL(hapModulesInfo);

    // reqPermissionDetails: Array<ReqPermissionDetail>
    ani_object reqPermissionDetails = ConvertAniArray(env, bundleInfo.reqPermissionDetails, ConvertRequestPermission);
    RETURN_NULL_IF_NULL(reqPermissionDetails);

    // permissionGrantStates: Array<bundleManager.PermissionGrantState>
    ani_object permissionGrantStates = ConvertAniArrayEnum(
        env, bundleInfo.reqPermissionStates, EnumUtils::EnumNativeToETS_BundleManager_PermissionGrantState);
    RETURN_NULL_IF_NULL(permissionGrantStates);

    // signatureInfo: SignatureInfo
    ani_ref signatureInfo = nullptr;
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO)) ==
        static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO)) {
        signatureInfo = ConvertSignatureInfo(env, bundleInfo.signatureInfo);
    } else {
        ani_status status = env->GetNull(&signatureInfo);
        if (status != ANI_OK) {
            APP_LOGE("GetNull signatureInfo failed %{public}d", status);
            return nullptr;
        }
    }
    RETURN_NULL_IF_NULL(signatureInfo);

    // routerMap: Array<RouterItem>
    ani_object routerMap = ConvertAniArray(env, bundleInfo.routerArray, ConvertRouterItem);
    RETURN_NULL_IF_NULL(routerMap);

    // firstInstallTime?: long
    ani_object firstInstallTime = BoxValue(env, bundleInfo.firstInstallTime);
    RETURN_NULL_IF_FALSE(firstInstallTime);

    ani_value args[] = {
        { .r = name },
        { .r = vendor },
        { .l = static_cast<ani_long>(bundleInfo.versionCode) },
        { .r = versionName },
        { .i = static_cast<ani_int>(bundleInfo.minCompatibleVersionCode) },
        { .i = static_cast<ani_int>(bundleInfo.targetVersion) },
        { .r = appInfo },
        { .r = hapModulesInfo },
        { .r = reqPermissionDetails },
        { .r = permissionGrantStates },
        { .r = signatureInfo },
        { .l = bundleInfo.installTime },
        { .l = bundleInfo.updateTime },
        { .r = routerMap },
        { .i = bundleInfo.appIndex },
        { .r = firstInstallTime },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // moduleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // vendor: string
        .AddLong()                                  // versionCode: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // versionName: string
        .AddInt()                                   // minCompatibleVersionCode: int
        .AddInt()                                   // targetVersion: int
        .AddClass(CLASSNAME_APPLICATION_INFO)       // appInfo: ApplicationInfo
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // hapModulesInfo: Array<HapModuleInfo>
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // reqPermissionDetails: Array<ReqPermissionDetail>
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // permissionGrantStates: Array<bundleManager.PermissionGrantState>
        .AddClass(CLASSNAME_SIGNATURE_INFO)         // signatureInfo: SignatureInfo
        .AddLong()                                  // installTime: long
        .AddLong()                                  // updateTime: long
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // routerMap: Array<RouterItem>
        .AddInt()                                   // appIndex: int
        .AddClass(CommonFunAniNS::CLASSNAME_LONG)   // firstInstallTime?: long
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_BUNDLE_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertDefaultAppAbilityInfo(ani_env* env, const AbilityInfo& abilityInfo)
{
    RETURN_NULL_IF_NULL(env);

    // bundleName: string
    ani_string bundleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.bundleName, bundleName));

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.moduleName, moduleName));

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.name, name));

    // label: string
    ani_string label = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.label, label));

    // description: string
    ani_string description = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.description, description));

    // icon: string
    ani_string icon = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.iconPath, icon));

    ani_value args[] = {
        { .r = bundleName },
        { .r = moduleName },
        { .r = name },
        { .r = label },
        { .l = static_cast<ani_long>(abilityInfo.labelId) },
        { .r = description },
        { .l = static_cast<ani_long>(abilityInfo.descriptionId) },
        { .r = icon },
        { .l = static_cast<ani_long>(abilityInfo.iconId) },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // bundleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // moduleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // name: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // label: string
        .AddLong()                                  // labelId: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // description: string
        .AddLong()                                  // descriptionId: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // icon: string
        .AddLong()                                  // iconId: long
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_ABILITY_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertDefaultAppExtensionInfo(ani_env* env, const ExtensionAbilityInfo& extensionInfo)
{
    RETURN_NULL_IF_NULL(env);

    // bundleName: string
    ani_string bundleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionInfo.bundleName, bundleName));

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionInfo.moduleName, moduleName));

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionInfo.name, name));

    ani_value args[] = {
        { .r = bundleName },
        { .r = moduleName },
        { .r = name },
        { .l = static_cast<ani_long>(extensionInfo.labelId) },
        { .l = static_cast<ani_long>(extensionInfo.descriptionId) },
        { .l = static_cast<ani_long>(extensionInfo.iconId) },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // bundleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // moduleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // name: string
        .AddLong()                                  // labelId: long
        .AddLong()                                  // descriptionId: long
        .AddLong()                                  // iconId: long
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_EXTENSION_ABILITY_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertDefaultAppHapModuleInfo(ani_env* env, const BundleInfo& bundleInfo)
{
    RETURN_NULL_IF_NULL(env);

    // abilitiesInfo: Array<AbilityInfo>
    ani_object abilitiesInfo = ConvertAniArray(env, bundleInfo.abilityInfos, ConvertDefaultAppAbilityInfo);
    RETURN_NULL_IF_NULL(abilitiesInfo);

    // extensionAbilitiesInfo: Array<ExtensionAbilityInfo>
    ani_object extensionAbilitiesInfo = ConvertAniArray(env, bundleInfo.extensionInfos, ConvertDefaultAppExtensionInfo);
    RETURN_NULL_IF_NULL(extensionAbilitiesInfo);

    ani_value args[] = {
        { .r = abilitiesInfo },
        { .r = extensionAbilitiesInfo },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY) // abilitiesInfo: Array<AbilityInfo>
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY) // extensionAbilitiesInfo: Array<ExtensionAbilityInfo>
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_HAP_MODULE_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertDefaultAppBundleInfo(ani_env* env, const BundleInfo& bundleInfo)
{
    RETURN_NULL_IF_NULL(env);

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleInfo.name, name));

    // hapModulesInfo: Array<HapModuleInfo>
    std::vector<BundleInfo> bundleInfos = { bundleInfo };
    ani_object hapModulesInfo = ConvertAniArray(env, bundleInfos, ConvertDefaultAppHapModuleInfo);
    RETURN_NULL_IF_NULL(hapModulesInfo);

    ani_value args[] = {
        { .r = name },
        { .r = hapModulesInfo },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // name: string
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY) // hapModulesInfo: Array<HapModuleInfo>
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_BUNDLE_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertMetadata(ani_env* env, const Metadata& metadata)
{
    RETURN_NULL_IF_NULL(env);

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, metadata.name, name));

    // value: string
    ani_string value = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, metadata.value, value));

    // resource: string
    ani_string resource = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, metadata.resource, resource));

    // valueId?: long
    ani_object valueId = BoxValue(env, static_cast<ani_long>(metadata.valueId));
    RETURN_NULL_IF_NULL(valueId);

    ani_value args[] = {
        { .r = name },
        { .r = value },
        { .r = resource },
        { .r = valueId },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // name: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // value: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // resource: string
        .AddClass(CommonFunAniNS::CLASSNAME_LONG)   // valueId?: long
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_METADATA_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertMultiAppMode(ani_env* env, const MultiAppModeData& multiAppMode)
{
    RETURN_NULL_IF_NULL(env);

    ani_value args[] = {
        { .r = EnumUtils::EnumNativeToETS_BundleManager_MultiAppModeType(
            env, static_cast<int32_t>(multiAppMode.multiAppModeType)) },
        { .i = multiAppMode.maxCount },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_MULTI_APP_MODE_TYPE) // multiAppModeType
        .AddInt()                                                              // maxCount: int
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_MULTI_APP_MODE_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertModuleMetaInfosItem(
    ani_env* env, const std::pair<std::string, std::vector<Metadata>>& item)
{
    RETURN_NULL_IF_NULL(env);

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, item.first, moduleName));

    // metadata: Array<Metadata>
    ani_object metadata = ConvertAniArray(env, item.second, ConvertMetadata);
    RETURN_NULL_IF_NULL(metadata);

    ani_value args[] = {
        { .r = moduleName },
        { .r = metadata },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // moduleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // metadata: Array<Metadata>
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_MODULE_METADATA_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertApplicationInfo(ani_env* env, const ApplicationInfo& appInfo)
{
    RETURN_NULL_IF_NULL(env);

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.name, name));

    // description: string
    ani_string description = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.description, description));

    // label: string
    ani_string label = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.label, label));

    // icon: string
    ani_string icon = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.iconPath, icon));

    // process: string
    ani_string process = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.process, process));

    // permissions: Array<string>
    ani_ref permissions = ConvertAniArrayString(env, appInfo.permissions);
    RETURN_NULL_IF_NULL(permissions);

    // codePath: string
    ani_string codePath = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.codePath, codePath));

    // metadataArray: Array<ModuleMetadata>
    ani_object metadataArray = ConvertAniArray(env, appInfo.metadata, ConvertModuleMetaInfosItem);
    RETURN_NULL_IF_NULL(metadataArray);

    // iconResource: Resource
    ani_object iconResource = ConvertResource(env, appInfo.iconResource);
    RETURN_NULL_IF_NULL(iconResource);

    // labelResource: Resource
    ani_object labelResource = ConvertResource(env, appInfo.labelResource);
    RETURN_NULL_IF_NULL(labelResource);

    // descriptionResource: Resource
    ani_object descriptionResource = ConvertResource(env, appInfo.descriptionResource);
    RETURN_NULL_IF_NULL(descriptionResource);

    // appDistributionType: string
    ani_string appDistributionType = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.appDistributionType, appDistributionType));

    // appProvisionType: string
    ani_string appProvisionType = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.appProvisionType, appProvisionType));

    // nativeLibraryPath: string
    ani_string nativeLibraryPath = nullptr;
    std::string externalNativeLibraryPath = "";
    if (!appInfo.nativeLibraryPath.empty()) {
        externalNativeLibraryPath = CONTEXT_DATA_STORAGE_BUNDLE + appInfo.nativeLibraryPath;
    }
    RETURN_NULL_IF_FALSE(StringToAniStr(env, externalNativeLibraryPath, nativeLibraryPath));

    // multiAppMode: MultiAppMode
    ani_object multiAppMode = ConvertMultiAppMode(env, appInfo.multiAppMode);
    RETURN_NULL_IF_NULL(multiAppMode);

    // installSource: string
    ani_string installSource = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.installSource, installSource));

    // releaseType: string
    ani_string releaseType = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.apiReleaseType, releaseType));

    // flags?: int
    ani_object flags = BoxValue(env, appInfo.applicationFlags);
    RETURN_NULL_IF_NULL(flags);

    ani_value args[] = {
        { .r = name },
        { .r = description },
        { .l = static_cast<ani_long>(appInfo.descriptionId) },
        { .z = BoolToAniBoolean(appInfo.enabled) },
        { .r = label },
        { .l = static_cast<ani_long>(appInfo.labelId) },
        { .r = icon },
        { .l = static_cast<ani_long>(appInfo.iconId) },
        { .r = process },
        { .r = permissions },
        { .r = codePath },
        { .r = metadataArray },
        { .z = BoolToAniBoolean(appInfo.removable) },
        { .l = static_cast<ani_long>(appInfo.accessTokenId) },
        { .i = appInfo.uid },
        { .r = iconResource },
        { .r = labelResource },
        { .r = descriptionResource },
        { .r = appDistributionType },
        { .r = appProvisionType },
        { .z = BoolToAniBoolean(appInfo.isSystemApp) },
        { .r = EnumUtils::EnumNativeToETS_BundleManager_BundleType(env, static_cast<int32_t>(appInfo.bundleType)) },
        { .z = BoolToAniBoolean(appInfo.debug) },
        { .z = BoolToAniBoolean(!appInfo.userDataClearable) },
        { .r = nativeLibraryPath },
        { .r = multiAppMode },
        { .i = appInfo.appIndex },
        { .r = installSource },
        { .r = releaseType },
        { .z = BoolToAniBoolean(appInfo.cloudFileSyncEnabled) },
        { .r = flags },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // name: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // description: string
        .AddLong()                                                     // descriptionId: long
        .AddBoolean()                                                  // enabled: boolean
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // label: string
        .AddLong()                                                     // labelId: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // icon: string
        .AddLong()                                                     // iconId: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // process: string
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)                     // permissions: Array<string>
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // codePath: string
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)                     // metadataArray: Array<Metadata>
        .AddBoolean()                                                  // removable: boolean
        .AddLong()                                                     // accessTokenId: long
        .AddInt()                                                      // uid: int
        .AddClass(CLASSNAME_RESOURCE)                                  // iconResource: Resource
        .AddClass(CLASSNAME_RESOURCE)                                  // labelResource: Resource
        .AddClass(CLASSNAME_RESOURCE)                                  // descriptionResource: Resource
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // appDistributionType: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // appProvisionType: string
        .AddBoolean()                                                  // systemApp: boolean
        .AddClass(CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_BUNDLE_TYPE) // bundleType: bundleManager.BundleType
        .AddBoolean()                                                  // debug: boolean
        .AddBoolean()                                                  // dataUnclearable: boolean
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // nativeLibraryPath: string
        .AddClass(CLASSNAME_MULTI_APP_MODE)                            // multiAppMode: MultiAppMode
        .AddInt()                                                      // appIndex: int
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // installSource: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // releaseType: string
        .AddBoolean()                                                  // cloudFileSyncEnabled: boolean
        .AddClass(CommonFunAniNS::CLASSNAME_INT)                       // flags?: int
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_APPLICATION_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertAbilityInfo(ani_env* env, const AbilityInfo& abilityInfo)
{
    RETURN_NULL_IF_NULL(env);

    // bundleName: string
    ani_string bundleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.bundleName, bundleName));

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.moduleName, moduleName));

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.name, name));

    // label: string
    ani_string label = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.label, label));

    // description: string
    ani_string description = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.description, description));

    // icon: string
    ani_string icon = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.iconPath, icon));

    // process: string
    ani_string process = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.process, process));

    // permissions: Array<string>
    ani_ref permissions = ConvertAniArrayString(env, abilityInfo.permissions);
    RETURN_NULL_IF_NULL(permissions);

    // deviceTypes: Array<string>
    ani_ref deviceTypes = ConvertAniArrayString(env, abilityInfo.deviceTypes);
    RETURN_NULL_IF_NULL(deviceTypes);

    // applicationInfo: ApplicationInfo
    ani_ref applicationInfo = nullptr;
    if (!abilityInfo.applicationInfo.name.empty()) {
        applicationInfo = ConvertApplicationInfo(env, abilityInfo.applicationInfo);
    } else {
        ani_status status = env->GetNull(&applicationInfo);
        if (status != ANI_OK) {
            APP_LOGE("GetNull applicationInfo failed %{public}d", status);
            return nullptr;
        }
    }
    RETURN_NULL_IF_NULL(applicationInfo);

    // metadata: Array<Metadata>
    ani_object metadata = ConvertAniArray(env, abilityInfo.metadata, ConvertMetadata);
    RETURN_NULL_IF_NULL(metadata);

    // supportWindowModes: Array<bundleManager.SupportWindowMode>
    ani_object supportWindowModes =
        ConvertAniArrayEnum(env, abilityInfo.windowModes, EnumUtils::EnumNativeToETS_BundleManager_SupportWindowMode);
    RETURN_NULL_IF_NULL(supportWindowModes);

    // windowSize: WindowSize
    ani_object windowSize = ConvertWindowSize(env, abilityInfo);
    RETURN_NULL_IF_NULL(windowSize);

    // skills: Array<Skill>
    ani_object skills = ConvertAniArray(env, abilityInfo.skills, ConvertAbilitySkill);
    RETURN_NULL_IF_NULL(skills);

    ani_value args[] = {
        { .r = bundleName },
        { .r = moduleName },
        { .r = name },
        { .r = label },
        { .l = static_cast<ani_long>(abilityInfo.labelId) },
        { .r = description },
        { .l = static_cast<ani_long>(abilityInfo.descriptionId) },
        { .r = icon },
        { .l = static_cast<ani_long>(abilityInfo.iconId) },
        { .r = process },
        { .z = BoolToAniBoolean(abilityInfo.visible) },
        { .r = EnumUtils::EnumNativeToETS_BundleManager_DisplayOrientation(
            env, static_cast<int32_t>(abilityInfo.orientation)) },
        { .r = EnumUtils::EnumNativeToETS_BundleManager_LaunchType(
            env, static_cast<int32_t>(abilityInfo.launchMode)) },
        { .r = permissions },
        { .r = deviceTypes },
        { .r = applicationInfo },
        { .r = metadata },
        { .z = BoolToAniBoolean(abilityInfo.enabled) },
        { .r = supportWindowModes },
        { .r = windowSize },
        { .z = BoolToAniBoolean(abilityInfo.excludeFromDock) },
        { .r = skills },
        { .i = abilityInfo.appIndex },
        { .l = static_cast<ani_long>(abilityInfo.orientationId) },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                            // bundleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                            // moduleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                            // name: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                            // label: string
        .AddLong()                                                             // labelId: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                            // description: string
        .AddLong()                                                             // descriptionId: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                            // icon: string
        .AddLong()                                                             // iconId: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                            // process: string
        .AddBoolean()                                                          // exported: boolean
        .AddClass(CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_DISPLAY_ORIENTATION) // orientation
        .AddClass(CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_LAUNCH_TYPE)         // launchType: bundleManager.LaunchType
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)                             // permissions: Array<string>
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)                             // deviceTypes: Array<string>
        .AddClass(CLASSNAME_APPLICATION_INFO)                                  // applicationInfo: ApplicationInfo
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)                             // metadata: Array<Metadata>
        .AddBoolean()                                                          // enabled: boolean
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY) // supportWindowModes: Array<bundleManager.SupportWindowMode>
        .AddClass(CLASSNAME_WINDOW_SIZE)           // windowSize: WindowSize
        .AddBoolean()                              // excludeFromDock: boolean
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY) // skills: Array<Skill>
        .AddInt()                                  // appIndex: int
        .AddLong()                                 // orientationId: long
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_ABILITY_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertWindowSize(ani_env* env, const AbilityInfo& abilityInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_value args[] = {
        { .d = abilityInfo.maxWindowRatio },
        { .d = abilityInfo.minWindowRatio },
        { .l = static_cast<ani_long>(abilityInfo.maxWindowWidth) },
        { .l = static_cast<ani_long>(abilityInfo.minWindowWidth) },
        { .l = static_cast<ani_long>(abilityInfo.maxWindowHeight) },
        { .l = static_cast<ani_long>(abilityInfo.minWindowHeight) },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddDouble() // maxWindowRatio: double
        .AddDouble() // minWindowRatio: double
        .AddLong()   // maxWindowWidth: long
        .AddLong()   // minWindowWidth: long
        .AddLong()   // maxWindowHeight: long
        .AddLong()   // minWindowHeight: long
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_WINDOW_SIZE_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertExtensionInfo(ani_env* env, const ExtensionAbilityInfo& extensionInfo)
{
    RETURN_NULL_IF_NULL(env);

    // bundleName: string
    ani_string bundleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionInfo.bundleName, bundleName));

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionInfo.moduleName, moduleName));

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionInfo.name, name));

    // extensionAbilityTypeName: string
    ani_string extensionAbilityTypeName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionInfo.extensionTypeName, extensionAbilityTypeName));

    // permissions: Array<string>
    ani_ref permissions = ConvertAniArrayString(env, extensionInfo.permissions);
    RETURN_NULL_IF_NULL(permissions);

    // applicationInfo: ApplicationInfo
    ani_ref applicationInfo = nullptr;
    if (!extensionInfo.applicationInfo.name.empty()) {
        applicationInfo = ConvertApplicationInfo(env, extensionInfo.applicationInfo);
    } else {
        ani_status status = env->GetNull(&applicationInfo);
        if (status != ANI_OK) {
            APP_LOGE("GetNull applicationInfo failed %{public}d", status);
            return nullptr;
        }
    }
    RETURN_NULL_IF_NULL(applicationInfo);

    // metadata: Array<Metadata>
    ani_object metadata = ConvertAniArray(env, extensionInfo.metadata, ConvertMetadata);
    RETURN_NULL_IF_NULL(metadata);

    // readPermission: string
    ani_string readPermission = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionInfo.readPermission, readPermission));

    // writePermission: string
    ani_string writePermission = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionInfo.writePermission, writePermission));

    // skills: Array<Skill>
    ani_object skills = ConvertAniArray(env, extensionInfo.skills, ConvertExtensionAbilitySkill);
    RETURN_NULL_IF_NULL(skills);

    ani_value args[] = {
        { .r = bundleName },
        { .r = moduleName },
        { .r = name },
        { .l = static_cast<ani_long>(extensionInfo.labelId) },
        { .l = static_cast<ani_long>(extensionInfo.descriptionId) },
        { .l = static_cast<ani_long>(extensionInfo.iconId) },
        { .z = BoolToAniBoolean(extensionInfo.visible) },
        { .r = EnumUtils::EnumNativeToETS_BundleManager_ExtensionAbilityType(
            env, static_cast<int32_t>(extensionInfo.type)) },
        { .r = extensionAbilityTypeName },
        { .r = permissions },
        { .r = applicationInfo },
        { .r = metadata },
        { .z = BoolToAniBoolean(extensionInfo.enabled) },
        { .r = readPermission },
        { .r = writePermission },
        { .r = skills },
        { .i = extensionInfo.appIndex },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                               // bundleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                               // moduleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                               // name: string
        .AddLong()                                                                // labelId: long
        .AddLong()                                                                // descriptionId: long
        .AddLong()                                                                // iconId: long
        .AddBoolean()                                                             // exported: boolean
        .AddClass(CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_EXTENSION_ABILITY_TYPE) // extensionAbilityType
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                               // extensionAbilityTypeName: string
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)                                // permissions: Array<string>
        .AddClass(CLASSNAME_APPLICATION_INFO)                                     // applicationInfo: ApplicationInfo
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)                                // metadata: Array<Metadata>
        .AddBoolean()                                                             // enabled: boolean
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                               // readPermission: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                               // writePermission: string
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)                                // skills: Array<Skill>
        .AddInt()                                                                 // appIndex: int
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_EXTENSION_ABILITY_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertResource(ani_env* env, const Resource& resource)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_RESOURCE_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, CLASSNAME_RESOURCE_INNER, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // bundleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, resource.bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLE_NAME, string));

    // moduleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, resource.moduleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULE_NAME, string));

    // id: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ID, resource.id));

    return object;
}

ani_object CommonFunAni::ConvertSignatureInfo(ani_env* env, const SignatureInfo& signatureInfo)
{
    RETURN_NULL_IF_NULL(env);

    // appId: string
    ani_string appId = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, signatureInfo.appId, appId));

    // fingerprint: string
    ani_string fingerprint = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, signatureInfo.fingerprint, fingerprint));

    // appIdentifier: string
    ani_string appIdentifier = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, signatureInfo.appIdentifier, appIdentifier));

    // certificate?: string
    ani_string certificate = nullptr;
    ani_ref certificateRef = nullptr;
    if (StringToAniStr(env, signatureInfo.certificate, certificate)) {
        certificateRef = certificate;
    } else {
        env->GetUndefined(&certificateRef);
    }

    ani_value args[] = {
        { .r = appId },
        { .r = fingerprint },
        { .r = appIdentifier },
        { .r = certificateRef },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)  // appId: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)  // fingerprint: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)  // appIdentifier: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)  // certificate?: string
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_SIGNATURE_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertKeyValuePair(
    ani_env* env, const std::pair<std::string, std::string>& item, const std::string& className)
{
    RETURN_NULL_IF_NULL(env);

    // key: string
    ani_string key = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, item.first, key));

    // value: string
    ani_string value = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, item.second, value));

    ani_value args[] = {
        { .r = key },
        { .r = value },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)  // key: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)  // value: string
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, className, ctorSig, args);
}

inline ani_object CommonFunAni::ConvertDataItem(ani_env* env, const std::pair<std::string, std::string>& item)
{
    return ConvertKeyValuePair(env, item, CLASSNAME_DATA_ITEM_INNER);
}

ani_object CommonFunAni::ConvertRouterItem(ani_env* env, const RouterItem& routerItem)
{
    RETURN_NULL_IF_NULL(env);

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, routerItem.name, name));

    // pageSourceFile: string
    ani_string pageSourceFile = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, routerItem.pageSourceFile, pageSourceFile));

    // buildFunction: string
    ani_string buildFunction = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, routerItem.buildFunction, buildFunction));

    // customData: string
    ani_string customData = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, routerItem.customData, customData));

    // data: Array<DataItem>
    ani_object aDataArrayObject = ConvertAniArray(env, routerItem.data, ConvertDataItem);
    RETURN_NULL_IF_NULL(aDataArrayObject);

    ani_value args[] = {
        { .r = name },
        { .r = pageSourceFile },
        { .r = buildFunction },
        { .r = customData },
        { .r = aDataArrayObject },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // name: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // pageSourceFile: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // buildFunction: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // customData: string
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // data: Array<DataItem>
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_ROUTER_ITEM_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertRequestPermission(ani_env* env, const RequestPermission& requestPermission)
{
    RETURN_NULL_IF_NULL(env);

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, requestPermission.name, name));

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, requestPermission.moduleName, moduleName));

    // reason: string
    ani_string reason = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, requestPermission.reason, reason));

    // usedScene: UsedScene
    ani_object usedScene = ConvertRequestPermissionUsedScene(env, requestPermission.usedScene);
    RETURN_NULL_IF_NULL(usedScene);

    ani_value args[] = {
        { .r = name },
        { .r = moduleName },
        { .r = reason },
        { .l = static_cast<ani_long>(requestPermission.reasonId) },
        { .r = usedScene },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // name: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // moduleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // reason: string
        .AddLong()                                  // reasonId: long
        .AddClass(CLASSNAME_USED_SCENE)             // usedScene: UsedScene
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_PERMISSION_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertRequestPermissionUsedScene(
    ani_env* env, const RequestPermissionUsedScene& requestPermissionUsedScene)
{
    RETURN_NULL_IF_NULL(env);

    // abilities: Array<string>
    ani_object abilities = ConvertAniArrayString(env, requestPermissionUsedScene.abilities);
    RETURN_NULL_IF_NULL(abilities);

    // when: string
    ani_string when = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, requestPermissionUsedScene.when, when));

    ani_value args[] = {
        { .r = abilities },
        { .r = when },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)   // abilities: Array<string>
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)  // when: string
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_USED_SCENE_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertPreloadItem(ani_env* env, const PreloadItem& preloadItem)
{
    RETURN_NULL_IF_NULL(env);

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, preloadItem.moduleName, moduleName));

    ani_value args[] = {
        { .r = moduleName },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)  // moduleName: string
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_PRELOAD_ITEM_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertDependency(ani_env* env, const Dependency& dependency)
{
    RETURN_NULL_IF_NULL(env);

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, dependency.moduleName, moduleName));

    // bundleName: string
    ani_string bundleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, dependency.bundleName, bundleName));

    ani_value args[] = {
        { .r = moduleName },
        { .r = bundleName },
        { .l = static_cast<ani_long>(dependency.versionCode) },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // moduleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // bundleName: string
        .AddLong()                                  // versionCode: long
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_DEPENDENCY_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertHapModuleInfo(ani_env* env, const HapModuleInfo& hapModuleInfo)
{
    RETURN_NULL_IF_NULL(env);

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapModuleInfo.name, name));

    // icon: string
    ani_string icon = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapModuleInfo.iconPath, icon));

    // label: string
    ani_string label = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapModuleInfo.label, label));

    // description: string
    ani_string description = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapModuleInfo.description, description));

    // mainElementName: string
    ani_string mainElementName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapModuleInfo.mainElementName, mainElementName));

    // abilitiesInfo: Array<AbilityInfo>
    ani_object abilitiesInfo = ConvertAniArray(env, hapModuleInfo.abilityInfos, ConvertAbilityInfo);
    RETURN_NULL_IF_NULL(abilitiesInfo);

    // extensionAbilitiesInfo: Array<ExtensionAbilityInfo>
    ani_object extensionAbilitiesInfo = ConvertAniArray(env, hapModuleInfo.extensionInfos, ConvertExtensionInfo);
    RETURN_NULL_IF_NULL(extensionAbilitiesInfo);

    // metadata: Array<Metadata>
    ani_object metadata = ConvertAniArray(env, hapModuleInfo.metadata, ConvertMetadata);
    RETURN_NULL_IF_NULL(metadata);

    // deviceTypes: Array<string>
    ani_object deviceTypes = ConvertAniArrayString(env, hapModuleInfo.deviceTypes);
    RETURN_NULL_IF_NULL(deviceTypes);

    // hashValue: string
    ani_string hashValue = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapModuleInfo.hashValue, hashValue));

    // dependencies: Array<Dependency>
    ani_object dependencies = ConvertAniArray(env, hapModuleInfo.dependencies, ConvertDependency);
    RETURN_NULL_IF_NULL(dependencies);

    // preloads: Array<PreloadItem>
    ani_object preloads = ConvertAniArray(env, hapModuleInfo.preloads, ConvertPreloadItem);
    RETURN_NULL_IF_NULL(preloads);

    // fileContextMenuConfig: string
    ani_string fileContextMenuConfig = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapModuleInfo.fileContextMenu, fileContextMenuConfig));

    // routerMap: Array<RouterItem>
    ani_object routerMap = ConvertAniArray(env, hapModuleInfo.routerArray, ConvertRouterItem);
    RETURN_NULL_IF_NULL(routerMap);

    // nativeLibraryPath: string
    ani_string nativeLibraryPath = nullptr;
    std::string externalNativeLibraryPath = "";
    if (!hapModuleInfo.nativeLibraryPath.empty() && !hapModuleInfo.moduleName.empty()) {
        externalNativeLibraryPath = CONTEXT_DATA_STORAGE_BUNDLE + hapModuleInfo.nativeLibraryPath;
    }
    RETURN_NULL_IF_FALSE(StringToAniStr(env, externalNativeLibraryPath, nativeLibraryPath));

    // codePath: string
    ani_string codePath = nullptr;
    std::string hapPath = hapModuleInfo.hapPath;
    size_t result = hapModuleInfo.hapPath.find(PATH_PREFIX);
    if (result != std::string::npos) {
        size_t pos = hapModuleInfo.hapPath.find_last_of('/');
        hapPath = CODE_PATH_PREFIX;
        if (pos != std::string::npos && pos != hapModuleInfo.hapPath.size() - 1) {
            hapPath.append(hapModuleInfo.hapPath.substr(pos + 1));
        }
    }
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapPath, codePath));

    ani_value args[] = {
        { .r = name },
        { .r = icon },
        { .l = static_cast<ani_long>(hapModuleInfo.iconId) },
        { .r = label },
        { .l = static_cast<ani_long>(hapModuleInfo.labelId) },
        { .r = description },
        { .l = static_cast<ani_long>(hapModuleInfo.descriptionId) },
        { .r = mainElementName },
        { .r = abilitiesInfo },
        { .r = extensionAbilitiesInfo },
        { .r = metadata },
        { .r = deviceTypes },
        { .z = BoolToAniBoolean(hapModuleInfo.installationFree) },
        { .r = hashValue },
        { .r = EnumUtils::EnumNativeToETS_BundleManager_ModuleType(
            env, static_cast<int32_t>(hapModuleInfo.moduleType)) },
        { .r = dependencies },
        { .r = preloads },
        { .r = fileContextMenuConfig },
        { .r = routerMap },
        { .r = nativeLibraryPath },
        { .r = codePath },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // name: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // icon: string
        .AddLong()                                  // iconId: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // label: string
        .AddLong()                                  // labelId: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // description: string
        .AddLong()                                  // descriptionId: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // mainElementName: string
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // abilitiesInfo: Array<AbilityInfo>
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // extensionAbilitiesInfo: Array<ExtensionAbilityInfo>
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // metadata: Array<Metadata>
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // deviceTypes: Array<string>
        .AddBoolean()                               // installationFree: boolean
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // hashValue: string
        .AddClass(CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_MODULE_TYPE) // type: bundleManager.ModuleType
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)                     // dependencies: Array<Dependency>
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)                     // preloads: Array<PreloadItem>
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // fileContextMenuConfig: string
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)                     // routerMap: Array<RouterItem>
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // nativeLibraryPath: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // codePath: string
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_HAP_MODULE_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertElementName(ani_env* env, const ElementName& elementName)
{
    RETURN_NULL_IF_NULL(env);

    ani_ref refUndefined = nullptr;
    ani_status status = env->GetUndefined(&refUndefined);
    if (status != ANI_OK) {
        APP_LOGE("GetUndefined failed %{public}d", status);
        return nullptr;
    }

    // deviceId?: string
    ani_ref deviceId = refUndefined;
    ani_string deviceIdString = nullptr;
    if (StringToAniStr(env, elementName.GetDeviceID(), deviceIdString)) {
        deviceId = deviceIdString;
    }

    // bundleName: string
    ani_string bundleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, elementName.GetBundleName(), bundleName));

    // moduleName?: string
    ani_ref moduleName = refUndefined;
    ani_string moduleNameString = nullptr;
    if (StringToAniStr(env, elementName.GetModuleName(), moduleNameString)) {
        moduleName = moduleNameString;
    }

    // abilityName: string
    ani_string abilityName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, elementName.GetAbilityName(), abilityName));

    // uri?: string
    ani_ref uri = refUndefined;
    ani_string uriString = nullptr;
    if (StringToAniStr(env, elementName.GetURI(), uriString)) {
        uri = uriString;
    }

    // shortName?: string
    ani_ref shortName = refUndefined;
    ani_string shortNameString = nullptr;
    if (StringToAniStr(env, "", shortNameString)) {
        shortName = shortNameString;
    }

    ani_value args[] = {
        { .r = bundleName },
        { .r = abilityName },
        { .r = deviceId },
        { .r = moduleName },
        { .r = uri },
        { .r = shortName },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // bundleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // abilityName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // deviceId?: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // moduleName?: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // uri?: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // shortName?: string
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_ELEMENT_NAME_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertAbilitySkillUriInner(ani_env* env, const SkillUri& skillUri, bool isExtension)
{
    RETURN_NULL_IF_NULL(env);

    // scheme: string
    ani_string scheme = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, skillUri.scheme, scheme));

    // host: string
    ani_string host = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, skillUri.host, host));

    // port: int
    int32_t port = 0;
    if (!skillUri.port.empty()) {
        auto [ptr, ec] = std::from_chars(skillUri.port.data(), skillUri.port.data() + skillUri.port.size(), port);
        if (ec != std::errc() || ptr != skillUri.port.data() + skillUri.port.size()) {
            APP_LOGE("skillUri port convert failed");
            return nullptr;
        }
    }

    // path: string
    ani_string path = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, skillUri.path, path));

    // pathStartWith: string
    ani_string pathStartWith = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, skillUri.pathStartWith, pathStartWith));

    // pathRegex: string
    ani_string pathRegex = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, skillUri.pathRegex, pathRegex));

    // type: string
    ani_string type = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, skillUri.type, type));

    // utd: string
    ani_string utd = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, skillUri.utd, utd));

    // linkFeature: string
    ani_string linkFeature = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, isExtension? std::string(): skillUri.linkFeature, linkFeature));

    ani_value args[] = {
        { .r = scheme },
        { .r = host },
        { .i = port },
        { .r = path },
        { .r = pathStartWith },
        { .r = pathRegex },
        { .r = type },
        { .r = utd },
        { .i = skillUri.maxFileSupported },
        { .r = linkFeature },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // scheme: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // host: string
        .AddInt()                                   // port: int
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // path: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // pathStartWith: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // pathRegex: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // type: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // utd: string
        .AddInt()                                   // maxFileSupported: int
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // linkFeature: string
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_SKILL_URI_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertAbilitySkillInner(ani_env* env, const Skill& skill, bool isExtension)
{
    RETURN_NULL_IF_NULL(env);

    // actions: Array<string>
    ani_object actions = ConvertAniArrayString(env, skill.actions);
    RETURN_NULL_IF_NULL(actions);

    // entities: Array<string>
    ani_object entities = ConvertAniArrayString(env, skill.entities);
    RETURN_NULL_IF_NULL(entities);

    // uris: Array<SkillUri>
    ani_object uris =
        ConvertAniArray(env, skill.uris, isExtension ? ConvertExtensionAbilitySkillUri : ConvertAbilitySkillUri);
    RETURN_NULL_IF_NULL(uris);

    ani_value args[] = {
        { .r = actions },
        { .r = entities },
        { .r = uris },
        { .z = BoolToAniBoolean(isExtension? false: skill.domainVerify) },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY) // actions: Array<string>
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY) // entities: Array<string>
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY) // uris: Array<SkillUri>
        .AddBoolean()                              // domainVerify: boolean
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_SKILL_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertAppCloneIdentity(ani_env* env, const std::string& bundleName, const int32_t appIndex)
{
    RETURN_NULL_IF_NULL(env);

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleName, name));

    ani_value args[] = {
        { .r = name },
        { .i = appIndex },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // name: string
        .AddInt()                                   // appIndex: int
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_APP_CLONE_IDENTITY_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertPermissionDef(ani_env* env, const PermissionDef& permissionDef)
{
    RETURN_NULL_IF_NULL(env);

    // permissionName: string
    ani_string permissionName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, permissionDef.permissionName, permissionName));

    ani_value args[] = {
        { .r = permissionName },
        { .i = permissionDef.grantMode },
        { .l = static_cast<ani_long>(permissionDef.labelId) },
        { .l = static_cast<ani_long>(permissionDef.descriptionId) },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // permissionName: string
        .AddInt()                                   // grantMode: int
        .AddLong()                                  // labelId: long
        .AddLong()                                  // descriptionId: long
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_PERMISSION_DEF_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertSharedBundleInfo(ani_env* env, const SharedBundleInfo& sharedBundleInfo)
{
    RETURN_NULL_IF_NULL(env);

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, sharedBundleInfo.name, name));

    // sharedModuleInfo: Array<SharedModuleInfo>
    ani_object sharedModuleInfo =
        ConvertAniArray(env, sharedBundleInfo.sharedModuleInfos, ConvertSharedModuleInfo);
    RETURN_NULL_IF_NULL(sharedModuleInfo);

    ani_value args[] = {
        { .r = name },
        { .r = EnumUtils::EnumNativeToETS_BundleManager_CompatiblePolicy(
            env, static_cast<int32_t>(CompatiblePolicy::BACKWARD_COMPATIBILITY)) },
        { .r = sharedModuleInfo },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                          // permissionName: string
        .AddClass(CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_COMPATIBLE_POLICY) // compatiblePolicy
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY) // sharedModuleInfo: Array<SharedModuleInfo>
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_SHARED_BUNDLE_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertSharedModuleInfo(ani_env* env, const SharedModuleInfo& sharedModuleInfo)
{
    RETURN_NULL_IF_NULL(env);

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, sharedModuleInfo.name, name));

    // versionName: string
    ani_string versionName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, sharedModuleInfo.versionName, versionName));

    // description: string
    ani_string description = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, sharedModuleInfo.description, description));

    ani_value args[] = {
        { .r = name },
        { .l = static_cast<ani_long>(sharedModuleInfo.versionCode) },
        { .r = versionName },
        { .r = description },
        { .l = static_cast<ani_long>(sharedModuleInfo.descriptionId) },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // name: string
        .AddLong()                                  // versionCode: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // versionName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // description: string
        .AddLong()                                  // descriptionId: long
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_SHARED_MODULE_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertAppProvisionInfo(ani_env* env, const AppProvisionInfo& appProvisionInfo)
{
    RETURN_NULL_IF_NULL(env);

    // versionName: string
    ani_string versionName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.versionName, versionName));

    // uuid: string
    ani_string uuid = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.uuid, uuid));

    // type: string
    ani_string type = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.type, type));

    // appDistributionType: string
    ani_string appDistributionType = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.appDistributionType, appDistributionType));

    // validity: Validity
    ani_object validity = ConvertValidity(env, appProvisionInfo.validity);
    RETURN_NULL_IF_NULL(validity);

    // developerId: string
    ani_string developerId = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.developerId, developerId));

    // certificate: string
    ani_string certificate = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.certificate, certificate));

    // apl: string
    ani_string apl = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.apl, apl));

    // issuer: string
    ani_string issuer = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.issuer, issuer));

    // appIdentifier: string
    ani_string appIdentifier = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.appIdentifier, appIdentifier));

    // organization: string
    ani_string organization = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.organization, organization));

    ani_value args[] = {
        { .l = static_cast<ani_long>(appProvisionInfo.versionCode) },
        { .r = versionName },
        { .r = uuid },
        { .r = type },
        { .r = appDistributionType },
        { .r = validity },
        { .r = developerId },
        { .r = certificate },
        { .r = apl },
        { .r = issuer },
        { .r = appIdentifier },
        { .r = organization },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddLong()                                  // versionCode: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // versionName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // uuid: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // type: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // appDistributionType: string
        .AddClass(CLASSNAME_VALIDITY)               // validity: Validity
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // developerId: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // certificate: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // apl: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // issuer: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // appIdentifier: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // organization: string
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_APP_PROVISION_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertValidity(ani_env* env, const Validity& validity)
{
    RETURN_NULL_IF_NULL(env);

    ani_value args[] = {
        { .l = validity.notBefore },
        { .l = validity.notAfter },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddLong() // notBefore: long
        .AddLong() // notAfter: long
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_VALIDITY_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertRecoverableApplicationInfo(
    ani_env* env, const RecoverableApplicationInfo& recoverableApplicationInfo)
{
    RETURN_NULL_IF_NULL(env);

    // bundleName: string
    ani_string bundleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, recoverableApplicationInfo.bundleName, bundleName));

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, recoverableApplicationInfo.moduleName, moduleName));

    // codePaths: Array<string>
    ani_ref codePaths = ConvertAniArrayString(env, recoverableApplicationInfo.codePaths);
    RETURN_NULL_IF_NULL(codePaths);

    ani_value args[] = {
        { .r = bundleName },
        { .r = moduleName },
        { .l = static_cast<ani_long>(recoverableApplicationInfo.labelId) },
        { .l = static_cast<ani_long>(recoverableApplicationInfo.iconId) },
        { .z = BoolToAniBoolean(recoverableApplicationInfo.systemApp) },
        { .r = EnumUtils::EnumNativeToETS_BundleManager_BundleType(
            env, static_cast<int32_t>(recoverableApplicationInfo.bundleType)) },
        { .r = codePaths },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // bundleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)                    // moduleName: string
        .AddLong()                                                     // labelId: long
        .AddLong()                                                     // iconId: long
        .AddBoolean()                                                  // systemApp: boolean
        .AddClass(CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_BUNDLE_TYPE) // bundleType: bundleManager.BundleType
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)                     // codePaths: Array<string>
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_RECOVERABLE_APPLICATION_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertPreinstalledApplicationInfo(
    ani_env* env, const PreinstalledApplicationInfo& reinstalledApplicationInfo)
{
    RETURN_NULL_IF_NULL(env);

    // bundleName: string
    ani_string bundleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, reinstalledApplicationInfo.bundleName, bundleName));

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, reinstalledApplicationInfo.moduleName, moduleName));

    ani_value args[] = {
        { .r = bundleName },
        { .r = moduleName },
        { .l = static_cast<ani_long>(reinstalledApplicationInfo.iconId) },
        { .l = static_cast<ani_long>(reinstalledApplicationInfo.labelId) },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // bundleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // moduleName: string
        .AddLong()                                  // iconId: long
        .AddLong()                                  // labelId: long
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_PREINSTALLED_APPLICATION_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertPluginBundleInfo(ani_env* env, const PluginBundleInfo& pluginBundleInfo)
{
    RETURN_NULL_IF_NULL(env);

    // label: string
    ani_string label = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, pluginBundleInfo.label, label));

    // icon: string
    ani_string icon = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, pluginBundleInfo.icon, icon));

    // pluginBundleName: string
    ani_string pluginBundleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, pluginBundleInfo.pluginBundleName, pluginBundleName));

    // versionName: string
    ani_string versionName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, pluginBundleInfo.versionName, versionName));

    // pluginModuleInfos: Array<PluginModuleInfo>
    ani_object pluginModuleInfos =
        ConvertAniArray(env, pluginBundleInfo.pluginModuleInfos, ConvertPluginModuleInfo);
    RETURN_NULL_IF_NULL(pluginModuleInfos);

    ani_value args[] = {
        { .r = label },
        { .l = static_cast<ani_long>(pluginBundleInfo.labelId) },
        { .r = icon },
        { .l = static_cast<ani_long>(pluginBundleInfo.iconId) },
        { .r = pluginBundleName },
        { .l = static_cast<ani_long>(pluginBundleInfo.versionCode) },
        { .r = versionName },
        { .r = pluginModuleInfos },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // label: string
        .AddLong()                                  // labelId: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // icon: string
        .AddLong()                                  // iconId: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // pluginBundleName: string
        .AddLong()                                  // versionCode: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // versionName: string
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // pluginModuleInfos: Array<PluginModuleInfo>
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_PLUGIN_BUNDLE_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertPluginModuleInfo(ani_env* env, const PluginModuleInfo& pluginModuleInfo)
{
    RETURN_NULL_IF_NULL(env);

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, pluginModuleInfo.moduleName, moduleName));

    // description: string
    ani_string description = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, pluginModuleInfo.description, description));

    ani_value args[] = {
        { .r = moduleName },
        { .l = static_cast<ani_long>(pluginModuleInfo.descriptionId) },
        { .r = description },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // moduleName: string
        .AddLong()                                  // descriptionId: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // description: string
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_PLUGIN_MODULE_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertShortcutInfo(ani_env* env, const ShortcutInfo& shortcutInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_ref refUndefined = nullptr;
    ani_status status = env->GetUndefined(&refUndefined);
    if (status != ANI_OK) {
        APP_LOGE("GetUndefined failed %{public}d", status);
        return nullptr;
    }

    // id: string
    ani_string id = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, shortcutInfo.id, id));

    // bundleName: string
    ani_string bundleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, shortcutInfo.bundleName, bundleName));

    // moduleName?: string
    ani_ref moduleName = refUndefined;
    ani_string moduleNameString = nullptr;
    if (StringToAniStr(env, shortcutInfo.moduleName, moduleNameString)) {
        moduleName = moduleNameString;
    }

    // hostAbility?: string
    ani_ref hostAbility = refUndefined;
    ani_string hostAbilityString = nullptr;
    if (StringToAniStr(env, shortcutInfo.hostAbility, hostAbilityString)) {
        hostAbility = hostAbilityString;
    }

    // icon?: string
    ani_ref icon = refUndefined;
    ani_string iconString = nullptr;
    if (StringToAniStr(env, shortcutInfo.icon, iconString)) {
        icon = iconString;
    }

    // iconId?: long
    ani_object iconId = BoxValue(env, static_cast<ani_long>(shortcutInfo.iconId));
    RETURN_NULL_IF_FALSE(iconId);

    // label?: string
    ani_ref label = refUndefined;
    ani_string labelString = nullptr;
    if (StringToAniStr(env, shortcutInfo.label, labelString)) {
        label = labelString;
    }

    // labelId?: long
    ani_object labelId = BoxValue(env, static_cast<ani_long>(shortcutInfo.labelId));
    RETURN_NULL_IF_FALSE(labelId);

    // wants?: Array<ShortcutWant>
    ani_object wants = ConvertAniArray(env, shortcutInfo.intents, ConvertShortcutIntent);
    RETURN_NULL_IF_NULL(wants);

    // visible?: boolean
    ani_object visible = BoxValue(env, BoolToAniBoolean(shortcutInfo.visible));
    RETURN_NULL_IF_FALSE(visible);

    ani_value args[] = {
        { .r = id },
        { .r = bundleName },
        { .i = shortcutInfo.appIndex },
        { .i = shortcutInfo.sourceType },
        { .r = moduleName },
        { .r = hostAbility },
        { .r = icon },
        { .r = iconId },
        { .r = label },
        { .r = labelId },
        { .r = wants },
        { .r = visible },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)  // id: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)  // bundleName: string
        .AddInt()                                    // appIndex: int
        .AddInt()                                    // sourceType: int
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)  // moduleName?: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)  // hostAbility?: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)  // icon?: string
        .AddClass(CommonFunAniNS::CLASSNAME_LONG)    // iconId?: long
        .AddClass(CommonFunAniNS::CLASSNAME_STRING)  // label?: string
        .AddClass(CommonFunAniNS::CLASSNAME_LONG)    // labelId?: long
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)   // wants?: Array<ShortcutWant>
        .AddClass(CommonFunAniNS::CLASSNAME_BOOLEAN) // visible?: boolean
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_SHORTCUT_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertShortcutIntent(ani_env* env, const ShortcutIntent& shortcutIntent)
{
    RETURN_NULL_IF_NULL(env);

    ani_ref refUndefined = nullptr;
    ani_status status = env->GetUndefined(&refUndefined);
    if (status != ANI_OK) {
        APP_LOGE("GetUndefined failed %{public}d", status);
        return nullptr;
    }

    // targetBundle: string
    ani_string targetBundle = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, shortcutIntent.targetBundle, targetBundle));

    // targetModule?: string
    ani_ref targetModule = refUndefined;
    ani_string targetModuleString = nullptr;
    if (StringToAniStr(env, shortcutIntent.targetModule, targetModuleString)) {
        targetModule = targetModuleString;
    }

    // targetAbility: string
    ani_string targetAbility = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, shortcutIntent.targetClass, targetAbility));

    // parameters?: Array<ParameterItem>
    ani_object parameters = ConvertAniArray(env, shortcutIntent.parameters, ConvertShortcutIntentParameter);
    RETURN_NULL_IF_NULL(parameters);

    ani_value args[] = {
        { .r = targetBundle },
        { .r = targetAbility },
        { .r = targetModule },
        { .r = parameters },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // targetBundle: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // targetAbility: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // targetModule?: string
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // parameters?: Array<ParameterItem>
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_SHORTCUT_WANT_INNER, ctorSig, args);
}

inline ani_object CommonFunAni::ConvertShortcutIntentParameter(
    ani_env* env, const std::pair<std::string, std::string>& item)
{
    return ConvertKeyValuePair(env, item, CLASSNAME_SHORTCUT_PARAMETER_ITEM_INNER);
}

ani_object CommonFunAni::ConvertLauncherAbilityInfo(ani_env* env, const LauncherAbilityInfo& launcherAbility)
{
    RETURN_NULL_IF_NULL(env);

    // applicationInfo: ApplicationInfo
    ani_object applicationInfo = ConvertApplicationInfo(env, launcherAbility.applicationInfo);
    RETURN_NULL_IF_NULL(applicationInfo);

    // elementName: ElementName
    ani_object elementName = ConvertElementName(env, launcherAbility.elementName);
    RETURN_NULL_IF_NULL(elementName);

    ani_value args[] = {
        { .r = applicationInfo },
        { .r = elementName },
        { .l = static_cast<ani_long>(launcherAbility.labelId) },
        { .l = static_cast<ani_long>(launcherAbility.iconId) },
        { .i = launcherAbility.userId },
        { .l = launcherAbility.installTime },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CLASSNAME_APPLICATION_INFO) // applicationInfo: ApplicationInfo
        .AddClass(CLASSNAME_ELEMENT_NAME)     // elementName: ElementName
        .AddLong()                            // labelId: long
        .AddLong()                            // iconId: long
        .AddInt()                             // userId: int
        .AddLong()                            // installTime: long
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_LAUNCHER_ABILITY_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertOverlayModuleInfo(ani_env* env, const OverlayModuleInfo& overlayModuleInfo)
{
    RETURN_NULL_IF_NULL(env);

    // bundleName: string
    ani_string bundleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, overlayModuleInfo.bundleName, bundleName));

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, overlayModuleInfo.moduleName, moduleName));

    // targetModuleName: string
    ani_string targetModuleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, overlayModuleInfo.targetModuleName, targetModuleName));

    ani_value args[] = {
        { .r = bundleName },
        { .r = moduleName },
        { .r = targetModuleName },
        { .i = overlayModuleInfo.priority },
        { .i = overlayModuleInfo.state },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // bundleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // moduleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // targetModuleName: string
        .AddInt()                                   // priority: int
        .AddInt()                                   // state: int
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_OVERLAY_MODULE_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::CreateBundleChangedInfo(
    ani_env* env, const std::string& bundleName, int32_t userId, int32_t appIndex)
{
    RETURN_NULL_IF_NULL(env);

    // bundleName: string
    ani_string aniBundleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleName, aniBundleName));

    ani_value args[] = {
        { .r = aniBundleName },
        { .i = userId },
        { .i = appIndex },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // bundleName: string
        .AddInt()                                   // userId: int
        .AddInt()                                   // appIndex: int
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_BUNDLE_CHANGED_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertVersion(ani_env* env, const Version& version)
{
    RETURN_NULL_IF_NULL(env);

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, version.name, name));

    ani_value args[] = {
        { .i = static_cast<ani_int>(version.minCompatibleVersionCode) },
        { .r = name },
        { .i = static_cast<ani_int>(version.code) },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddInt()                                   // minCompatibleVersionCode: int
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // name: string
        .AddInt()                                   // code: int
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_VERSION_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertPackageApp(ani_env* env, const PackageApp& packageApp)
{
    RETURN_NULL_IF_NULL(env);

    // bundleName: string
    ani_string bundleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, packageApp.bundleName, bundleName));

    // version: Version
    ani_object version = ConvertVersion(env, packageApp.version);
    RETURN_NULL_IF_NULL(version);

    ani_value args[] = {
        { .r = bundleName },
        { .r = version },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // bundleName: string
        .AddClass(CLASSNAME_VERSION)                // version: Version
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_BUNDLE_CONFIG_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertAbilityFormInfo(ani_env* env, const AbilityFormInfo& abilityFormInfo)
{
    RETURN_NULL_IF_NULL(env);

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityFormInfo.name, name));

    // type: string
    ani_string type = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityFormInfo.type, type));

    // scheduledUpdateTime: string
    ani_string scheduledUpdateTime = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityFormInfo.scheduledUpdateTime, scheduledUpdateTime));

    // supportDimensions: Array<string>
    ani_ref supportDimensions = ConvertAniArrayString(env, abilityFormInfo.supportDimensions);
    RETURN_NULL_IF_NULL(supportDimensions);

    // defaultDimension: string
    ani_string defaultDimension = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityFormInfo.defaultDimension, defaultDimension));

    ani_value args[] = {
        { .r = name },
        { .r = type },
        { .z = BoolToAniBoolean(abilityFormInfo.updateEnabled) },
        { .r = scheduledUpdateTime },
        { .i = static_cast<ani_int>(abilityFormInfo.updateDuration) },
        { .r = supportDimensions },
        { .r = defaultDimension },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // name: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // type: string
        .AddBoolean()                               // updateEnabled: boolean
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // scheduledUpdateTime: string
        .AddInt()                                   // updateDuration: int
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // supportDimensions: Array<string>
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // defaultDimension: string
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_ABILITY_FORM_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertModuleAbilityInfo(ani_env* env, const ModuleAbilityInfo& moduleAbilityInfo)
{
    RETURN_NULL_IF_NULL(env);

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, moduleAbilityInfo.name, name));

    // label: string
    ani_string label = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, moduleAbilityInfo.label, label));

    // forms: Array<AbilityFormInfo>
    ani_object forms = ConvertAniArray(env, moduleAbilityInfo.forms, ConvertAbilityFormInfo);
    RETURN_NULL_IF_NULL(forms);

    ani_value args[] = {
        { .r = name },
        { .r = label },
        { .z = BoolToAniBoolean(moduleAbilityInfo.visible) },
        { .r = forms },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // name: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // label: string
        .AddBoolean()                               // exported: boolean
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // forms: Array<AbilityFormInfo>
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_MODULE_ABILITY_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertModuleDistro(ani_env* env, const ModuleDistro& moduleDistro)
{
    RETURN_NULL_IF_NULL(env);

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, moduleDistro.moduleName, moduleName));

    // moduleType: string
    ani_string moduleType = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, moduleDistro.moduleType, moduleType));

    ani_value args[] = {
        { .z = BoolToAniBoolean(moduleDistro.deliveryWithInstall) },
        { .z = BoolToAniBoolean(moduleDistro.installationFree) },
        { .r = moduleName },
        { .r = moduleType },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddBoolean()                               // deliveryWithInstall: boolean
        .AddBoolean()                               // installationFree: boolean
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // moduleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // moduleType: string
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_MODULE_DISTRO_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertApiVersion(ani_env* env, const ApiVersion& apiVersion)
{
    RETURN_NULL_IF_NULL(env);

    // releaseType: string
    ani_string releaseType = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, apiVersion.releaseType, releaseType));

    ani_value args[] = {
        { .r = releaseType },
        { .i = static_cast<ani_int>(apiVersion.compatible) },
        { .i = static_cast<ani_int>(apiVersion.target) },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // releaseType: string
        .AddInt()                                   // compatible: int
        .AddInt()                                   // target: int
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_API_VERSION_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertExtensionAbilities(ani_env* env, const ExtensionAbilities& extensionAbilities)
{
    RETURN_NULL_IF_NULL(env);

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionAbilities.name, name));

    // forms: Array<AbilityFormInfo>
    ani_object forms = ConvertAniArray(env, extensionAbilities.forms, ConvertAbilityFormInfo);
    RETURN_NULL_IF_NULL(forms);

    ani_value args[] = {
        { .r = name },
        { .r = forms },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // name: string
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // forms: Array<AbilityFormInfo>
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_EXTENSION_ABILITY_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertPackageModule(ani_env* env, const PackageModule& packageModule)
{
    RETURN_NULL_IF_NULL(env);

    // mainAbility: string
    ani_string mainAbility = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, packageModule.mainAbility, mainAbility));

    // apiVersion: ApiVersion
    ani_object apiVersion = ConvertApiVersion(env, packageModule.apiVersion);
    RETURN_NULL_IF_NULL(apiVersion);

    // deviceTypes: Array<string>
    ani_ref deviceTypes = ConvertAniArrayString(env, packageModule.deviceType);
    RETURN_NULL_IF_NULL(deviceTypes);

    // distro: ModuleDistroInfo
    ani_object distro = ConvertModuleDistro(env, packageModule.distro);
    RETURN_NULL_IF_NULL(distro);

    // abilities: Array<ModuleAbilityInfo>
    ani_object abilities = ConvertAniArray(env, packageModule.abilities, ConvertModuleAbilityInfo);
    RETURN_NULL_IF_NULL(abilities);

    // extensionAbilities: Array<ExtensionAbility>
    ani_object extensionAbilities =
        ConvertAniArray(env, packageModule.extensionAbilities, ConvertExtensionAbilities);
    RETURN_NULL_IF_NULL(extensionAbilities);

    ani_value args[] = {
        { .r = mainAbility },
        { .r = apiVersion },
        { .r = deviceTypes },
        { .r = distro },
        { .r = abilities },
        { .r = extensionAbilities },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // mainAbility: string
        .AddClass(CLASSNAME_API_VERSION)            // apiVersion: ApiVersion
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // deviceTypes: Array<string>
        .AddClass(CLASSNAME_MODULE_DISTRO_INFO)     // distro: ModuleDistroInfo
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // abilities: Array<ModuleAbilityInfo>
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // extensionAbilities: Array<ExtensionAbility>
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_MODULE_CONFIG_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertSummary(ani_env* env, const Summary& summary, bool withApp)
{
    RETURN_NULL_IF_NULL(env);

    // app: BundleConfigInfo
    ani_object app = nullptr;
    if (withApp) {
        app = ConvertPackageApp(env, summary.app);
        RETURN_NULL_IF_NULL(app);
    }

    // modules: Array<ModuleConfigInfo>
    ani_object modules = ConvertAniArray(env, summary.modules, ConvertPackageModule);
    RETURN_NULL_IF_NULL(modules);

    ani_value args[] = {
        { .r = modules },
        { .r = app },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY) // modules: Array<ModuleConfigInfo>
        .BuildSignatureDescriptor();
    static const std::string ctorSigWithApp = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY) // modules: Array<ModuleConfigInfo>
        .AddClass(CLASSNAME_BUNDLE_CONFIG_INFO)    // app: BundleConfigInfo
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_PACKAGE_SUMMARY_INNER, withApp ? ctorSigWithApp : ctorSig, args);
}

ani_object CommonFunAni::ConvertPackages(ani_env* env, const Packages& packages)
{
    RETURN_NULL_IF_NULL(env);

    // deviceTypes: Array<string>
    ani_ref deviceTypes = ConvertAniArrayString(env, packages.deviceType);
    RETURN_NULL_IF_NULL(deviceTypes);

    // name: string
    ani_string name = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, packages.name, name));

    // moduleType: string
    ani_string moduleType = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, packages.moduleType, moduleType));

    ani_value args[] = {
        { .r = deviceTypes },
        { .r = name },
        { .r = moduleType },
        { .z = BoolToAniBoolean(packages.deliveryWithInstall) },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)  // deviceTypes: Array<string>
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // name: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // moduleType: string
        .AddBoolean()                               // deliveryWithInstall: boolean
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_PACKAGE_CONFIG_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertBundlePackInfo(ani_env* env, const BundlePackInfo& bundlePackInfo, const uint32_t flag)
{
    RETURN_NULL_IF_NULL(env);

    if (flag & BundlePackFlag::GET_PACKAGES) {
        // packages: Array<PackageConfig>
        ani_object packages = ConvertAniArray(env, bundlePackInfo.packages, ConvertPackages);
        RETURN_NULL_IF_NULL(packages);

        ani_value args[] = {
            { .r = packages },
        };
        static const std::string ctorSigPackages = SignatureBuilder()
            .AddClass(CommonFunAniNS::CLASSNAME_ARRAY) // packages: Array<PackageConfig>
            .BuildSignatureDescriptor();
        return CreateNewObjectByClassV2(env, CLASSNAME_BUNDLE_PACK_INFO_INNER, ctorSigPackages, args);
    }

    if (flag & BundlePackFlag::GET_BUNDLE_SUMMARY) {
        // summary: PackageSummary
        ani_object summary = ConvertSummary(env, bundlePackInfo.summary, true);
        RETURN_NULL_IF_NULL(summary);

        ani_value args[] = {
            { .r = summary },
        };
        static const std::string ctorSigBundleSummary = SignatureBuilder()
            .AddClass(CLASSNAME_PACKAGE_SUMMARY) // summary: PackageSummary
            .BuildSignatureDescriptor();
        return CreateNewObjectByClassV2(env, CLASSNAME_BUNDLE_PACK_INFO_INNER, ctorSigBundleSummary, args);
    }

    if (flag & BundlePackFlag::GET_MODULE_SUMMARY) {
        // summary: PackageSummary
        ani_object summary = ConvertSummary(env, bundlePackInfo.summary, false);
        RETURN_NULL_IF_NULL(summary);

        ani_value args[] = {
            { .r = summary },
        };
        static const std::string ctorSigModuleSummary = SignatureBuilder()
            .AddClass(CLASSNAME_PACKAGE_SUMMARY) // summary: PackageSummary
            .BuildSignatureDescriptor();
        return CreateNewObjectByClassV2(env, CLASSNAME_BUNDLE_PACK_INFO_INNER, ctorSigModuleSummary, args);
    }

    // packages: Array<PackageConfig>
    ani_object packages = ConvertAniArray(env, bundlePackInfo.packages, ConvertPackages);
    RETURN_NULL_IF_NULL(packages);

    // summary: PackageSummary
    ani_object summary = ConvertSummary(env, bundlePackInfo.summary, true);
    RETURN_NULL_IF_NULL(summary);

    ani_value args[] = {
        { .r = packages },
        { .r = summary },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_ARRAY) // packages: Array<PackageConfig>
        .AddClass(CLASSNAME_PACKAGE_SUMMARY)       // summary: PackageSummary
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_BUNDLE_PACK_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::CreateDispatchInfo(
    ani_env* env, const std::string& version, const std::string& dispatchAPIVersion)
{
    RETURN_NULL_IF_NULL(env);

    // version: string
    ani_string aniVersion = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, version, aniVersion));

    // dispatchAPIVersion: string
    ani_string aniDispatchAPIVersion = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, dispatchAPIVersion, aniDispatchAPIVersion));

    ani_value args[] = {
        { .r = aniVersion },
        { .r = aniDispatchAPIVersion },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // version: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // dispatchAPIVersion: string
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_DISPATCH_INFO_INNER, ctorSig, args);
}

ani_object CommonFunAni::ConvertDynamicIconInfo(ani_env* env, const DynamicIconInfo& dynamicIconInfo)
{
    RETURN_NULL_IF_NULL(env);

    // bundleName: string
    ani_string bundleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, dynamicIconInfo.bundleName, bundleName));

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, dynamicIconInfo.moduleName, moduleName));

    ani_value args[] = {
        { .r = bundleName },
        { .r = moduleName },
        { .i = dynamicIconInfo.userId },
        { .i = dynamicIconInfo.appIndex },
    };
    static const std::string ctorSig = SignatureBuilder()
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // bundleName: string
        .AddClass(CommonFunAniNS::CLASSNAME_STRING) // moduleName: string
        .AddInt()                                   // userId: int
        .AddInt()                                   // appIndex: int
        .BuildSignatureDescriptor();
    return CreateNewObjectByClassV2(env, CLASSNAME_DYNAMIC_ICON_INFO_INNER, ctorSig, args);
}

bool CommonFunAni::ParseBundleOptions(ani_env* env, ani_object object, int32_t& appIndex, int32_t& userId)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_int intValue = 0;
    bool isDefault = true;

    // userId?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_USER_ID, &intValue)) {
        if (intValue < 0) {
            intValue = Constants::INVALID_USERID;
        }
        userId = intValue;
        isDefault = false;
    }

    // appIndex?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_APP_INDEX, &intValue)) {
        appIndex = intValue;
        isDefault = false;
    }

    return isDefault;
}

ani_object CommonFunAni::ConvertWantInfo(ani_env* env, const Want& want)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_WANT);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, CLASSNAME_WANT, cls);
    RETURN_NULL_IF_NULL(object);

    // bundleName?: string
    ani_string string = nullptr;
    if (StringToAniStr(env, want.GetElement().GetBundleName(), string)) {
        RETURN_NULL_IF_FALSE(CallSetField(env, cls, object, PROPERTYNAME_BUNDLE_NAME, string));
    }

    // abilityName?: string
    if (StringToAniStr(env, want.GetElement().GetAbilityName(), string)) {
        RETURN_NULL_IF_FALSE(CallSetField(env, cls, object, PROPERTYNAME_ABILITY_NAME, string));
    }

    // deviceId?: string
    if (StringToAniStr(env, want.GetElement().GetDeviceID(), string)) {
        RETURN_NULL_IF_FALSE(CallSetField(env, cls, object, PROPERTYNAME_DEVICE_ID, string));
    }

    // action?: string
    if (StringToAniStr(env, want.GetAction(), string)) {
        RETURN_NULL_IF_FALSE(CallSetField(env, cls, object, PROPERTYNAME_ACTION, string));
    }

    // entities?: Array<string>
    auto entities = want.GetEntities();
    if (entities.size() > 0) {
        ani_object aEntities = ConvertAniArrayString(env, entities);
        RETURN_NULL_IF_NULL(aEntities);
        RETURN_NULL_IF_FALSE(CallSetField(env, cls, object, PROPERTYNAME_ENTITIES, aEntities));
    }

    // moduleName?: string
    if (StringToAniStr(env, want.GetElement().GetModuleName(), string)) {
        RETURN_NULL_IF_FALSE(CallSetField(env, cls, object, PROPERTYNAME_MODULE_NAME, string));
    }

    return object;
}

bool CommonFunAni::ParseShortcutInfo(ani_env* env, ani_object object, ShortcutInfo& shortcutInfo)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_string string = nullptr;
    ani_int intValue = 0;
    uint32_t uintValue = 0;

    // id: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ID, &string));
    shortcutInfo.id = AniStrToString(env, string);

    // bundleName: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_BUNDLE_NAME, &string));
    shortcutInfo.bundleName = AniStrToString(env, string);

    // moduleName?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_MODULE_NAME, &string)) {
        shortcutInfo.moduleName = AniStrToString(env, string);
    }

    // hostAbility?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_HOST_ABILITY, &string)) {
        shortcutInfo.hostAbility = AniStrToString(env, string);
    }

    // icon?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_ICON, &string)) {
        shortcutInfo.icon = AniStrToString(env, string);
    }

    // iconId?: long
    if (CallGetterOptional(env, object, PROPERTYNAME_ICON_ID, &uintValue)) {
        shortcutInfo.iconId = uintValue;
    }

    // label?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_LABEL, &string)) {
        shortcutInfo.label = AniStrToString(env, string);
    }

    // labelId?: long
    if (CallGetterOptional(env, object, PROPERTYNAME_LABEL_ID, &uintValue)) {
        shortcutInfo.labelId = uintValue;
    }

    // wants?: Array<ShortcutWant>
    ani_array array = nullptr;
    if (CallGetterOptional(env, object, PROPERTYNAME_WANTS, &array)) {
        RETURN_FALSE_IF_FALSE(ParseAniArray(env, array, shortcutInfo.intents, ParseShortcutIntent));
    }

    // appIndex: int
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_APP_INDEX, &intValue));
    shortcutInfo.appIndex = intValue;

    // sourceType: int
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_SOURCE_TYPE, &intValue));
    shortcutInfo.sourceType = intValue;

    ani_boolean boolValue = false;
    // visible?: boolean
    if (CallGetterOptional(env, object, PROPERTYNAME_VISIBLE, &boolValue)) {
        shortcutInfo.visible = boolValue;
    }

    return true;
}

bool CommonFunAni::ParseShortcutIntent(ani_env* env, ani_object object, ShortcutIntent& shortcutIntent)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_string string = nullptr;

    // targetBundle: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_TARGET_BUNDLE, &string));
    shortcutIntent.targetBundle = AniStrToString(env, string);

    // targetModule?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_TARGET_MODULE, &string)) {
        shortcutIntent.targetModule = AniStrToString(env, string);
    }

    // targetAbility: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_TARGET_ABILITY, &string));
    shortcutIntent.targetClass = AniStrToString(env, string);

    // parameters?: Array<ParameterItem>
    ani_array array = nullptr;
    if (CallGetterOptional(env, object, PROPERTYNAME_PARAMETERS, &array)) {
        std::vector<std::pair<std::string, std::string>> parameters;
        RETURN_FALSE_IF_FALSE(ParseAniArray(env, array, parameters, ParseKeyValuePair));
        for (const auto& parameter : parameters) {
            shortcutIntent.parameters[parameter.first] = parameter.second;
        }
    }

    return true;
}

bool CommonFunAni::ParseKeyValuePairWithName(ani_env* env, ani_object object, std::pair<std::string, std::string>& pair,
    const char* keyName, const char* valueName)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_string string = nullptr;

    // key: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, keyName, &string));
    pair.first = AniStrToString(env, string);

    // value: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, valueName, &string));
    pair.second = AniStrToString(env, string);

    return true;
}

bool CommonFunAni::ParseKeyValuePair(ani_env* env, ani_object object, std::pair<std::string, std::string>& pair)
{
    return ParseKeyValuePairWithName(env, object, pair, PROPERTYNAME_KEY, PROPERTYNAME_VALUE);
}

bool CommonFunAni::ParseHashParams(ani_env* env, ani_object object, std::pair<std::string, std::string>& pair)
{
    return ParseKeyValuePairWithName(env, object, pair, PROPERTYNAME_MODULE_NAME, PROPERTYNAME_HASH_VALUE);
}

bool CommonFunAni::ParsePgoParams(ani_env* env, ani_object object, std::pair<std::string, std::string>& pair)
{
    return ParseKeyValuePairWithName(env, object, pair, PROPERTYNAME_MODULE_NAME, PROPERTYNAME_PGO_FILE_PATH);
}

bool CommonFunAni::ParseInstallParam(ani_env* env, ani_object object, InstallParam& installParam)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_array array = nullptr;
    // hashParams?
    if (CallGetterOptional(env, object, PROPERTYNAME_HASH_PARAMS, &array)) {
        std::vector<std::pair<std::string, std::string>> hashParams;
        RETURN_FALSE_IF_FALSE(ParseAniArray(env, array, hashParams, ParseHashParams));
        for (const auto& parameter : hashParams) {
            if (parameter.first.empty() || parameter.second.empty()) {
                APP_LOGE("key or value is empty");
                return false;
            }
            if (installParam.hashParams.find(parameter.first) != installParam.hashParams.end()) {
                APP_LOGE("duplicate key found");
                return false;
            }
            installParam.hashParams[parameter.first] = parameter.second;
        }
    }

    // parameters?
    if (CallGetterOptional(env, object, PROPERTYNAME_PARAMETERS, &array)) {
        std::vector<std::pair<std::string, std::string>> parameters;
        RETURN_FALSE_IF_FALSE(ParseAniArray(env, array, parameters, ParseKeyValuePair));
        for (const auto& parameter : parameters) {
            installParam.parameters[parameter.first] = parameter.second;
        }
    }

    // pgoParams?
    if (CallGetterOptional(env, object, PROPERTYNAME_PGO_PARAMS, &array)) {
        std::vector<std::pair<std::string, std::string>> pgoParams;
        RETURN_FALSE_IF_FALSE(ParseAniArray(env, array, pgoParams, ParsePgoParams));
        for (const auto& parameter : pgoParams) {
            if (parameter.first.empty() || parameter.second.empty()) {
                APP_LOGE("key or value is empty");
                return false;
            }
            installParam.pgoParams[parameter.first] = parameter.second;
        }
    }

    ani_int intValue = 0;
    // userId?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_USER_ID, &intValue)) {
        installParam.userId = intValue;
    } else {
        APP_LOGW("Parse userId failed,using default value");
    }
    // installFlag?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_INSTALL_FLAG, &intValue)) {
        if ((intValue != static_cast<int32_t>(OHOS::AppExecFwk::InstallFlag::NORMAL)) &&
            (intValue != static_cast<int32_t>(OHOS::AppExecFwk::InstallFlag::REPLACE_EXISTING)) &&
            (intValue != static_cast<int32_t>(OHOS::AppExecFwk::InstallFlag::FREE_INSTALL))) {
            APP_LOGE("invalid installFlag param");
        } else {
            installParam.installFlag = static_cast<OHOS::AppExecFwk::InstallFlag>(intValue);
        }
    } else {
        APP_LOGW("Parse installFlag failed,using default value");
    }

    ani_boolean boolValue = false;
    // isKeepData?: boolean
    if (CallGetterOptional(env, object, PROPERTYNAME_IS_KEEP_DATA, &boolValue)) {
        installParam.isKeepData = boolValue;
    } else {
        APP_LOGW("Parse isKeepData failed,using default value");
    }

    ani_long longValue = 0;
    // crowdtestDeadline?: long
    if (CallGetterOptional(env, object, PROPERTYNAME_CROWD_TEST_DEADLINE, &longValue)) {
        installParam.crowdtestDeadline = longValue;
    } else {
        APP_LOGW("Parse crowdtestDeadline failed,using default value");
    }

    // sharedBundleDirPaths?: Array<string>
    if (CallGetterOptional(env, object, PROPERTYNAME_SHARED_BUNDLE_DIR_PATHS, &array)) {
        RETURN_FALSE_IF_FALSE(ParseStrArray(env, array, installParam.sharedBundleDirPaths));
    }

    ani_string string = nullptr;

    // specifiedDistributionType?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_SPECIFIED_DISTRIBUTION_TYPE, &string)) {
        installParam.specifiedDistributionType = AniStrToString(env, string);
    } else {
        APP_LOGW("Parse specifiedDistributionType failed,using default value");
    }

    // additionalInfo?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_ADDITIONAL_INFO, &string)) {
        installParam.additionalInfo = AniStrToString(env, string);
    } else {
        APP_LOGW("Parse additionalInfo failed,using default value");
    }
    return true;
}

bool CommonFunAni::ParseUninstallParam(ani_env* env, ani_object object, UninstallParam& uninstallParam)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);
    ani_string string = nullptr;
    // bundleName: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_BUNDLE_NAME, &string));
    uninstallParam.bundleName = AniStrToString(env, string);
    ani_int intValue = 0;
    // versionCode?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_VERSION_CODE, &intValue)) {
        uninstallParam.versionCode = intValue;
    } else {
        APP_LOGW("Parse crowdtestDeadline failed,using default value");
    }
    return true;
}

bool CommonFunAni::ParseDestroyAppCloneParam(
    ani_env* env, ani_object object, DestroyAppCloneParam& destroyAppCloneParam)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);
    ani_int intValue = 0;
    // userId?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_USER_ID, &intValue)) {
        destroyAppCloneParam.userId = intValue;
    } else {
        destroyAppCloneParam.userId = Constants::UNSPECIFIED_USERID;
        APP_LOGW("Parse userId failed,using default value");
    }
    ani_array array = nullptr;
    // parameters?
    if (CallGetterOptional(env, object, PROPERTYNAME_PARAMETERS, &array)) {
        std::vector<std::pair<std::string, std::string>> parameters;
        RETURN_FALSE_IF_FALSE(ParseAniArray(env, array, parameters, ParseKeyValuePair));
        for (const auto& parameter : parameters) {
            destroyAppCloneParam.parameters[parameter.first] = parameter.second;
        }
    }
    return true;
}

bool CommonFunAni::ParsePluginParam(ani_env* env, ani_object object, InstallPluginParam& installPluginParam)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_int intValue = 0;
    ani_array array = nullptr;

    // userId?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_USER_ID, &intValue)) {
        installPluginParam.userId = intValue;
    } else {
        installPluginParam.userId = Constants::UNSPECIFIED_USERID;
        APP_LOGW("Parse userId failed, using default value");
    }

    // parameters?
    if (CallGetterOptional(env, object, PROPERTYNAME_PARAMETERS, &array)) {
        std::vector<std::pair<std::string, std::string>> parameters;
        RETURN_FALSE_IF_FALSE(ParseAniArray(env, array, parameters, ParseKeyValuePair));
        for (const auto& parameter : parameters) {
            installPluginParam.parameters[parameter.first] = parameter.second;
        }
    }

    return true;
}

bool CommonFunAni::ParseCreateAppCloneParam(ani_env* env, ani_object object, int32_t& userId, int32_t& appIdx)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);
    ani_int intValue = 0;
    // userId?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_USER_ID, &intValue)) {
        userId = intValue;
    } else {
        userId = Constants::UNSPECIFIED_USERID;
        APP_LOGW("Parse userId failed,using default value");
    }

    // appIdx?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_APP_INDEX, &intValue)) {
        appIdx = intValue;
    } else {
        appIdx = Constants::INITIAL_APP_INDEX;
        APP_LOGW("Parse appIdx failed,using default value");
    }
    return true;
}

bool CommonFunAni::ParseAbilityInfo(ani_env* env, ani_object object, AbilityInfo& abilityInfo)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_string string = nullptr;
    // bundleName: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_BUNDLE_NAME, &string));
    abilityInfo.bundleName = AniStrToString(env, string);

    // moduleName: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MODULE_NAME, &string));
    abilityInfo.moduleName = AniStrToString(env, string);

    // name: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_NAME, &string));
    abilityInfo.name = AniStrToString(env, string);

    return true;
}

bool CommonFunAni::ParseElementName(ani_env* env, ani_object object, ElementName& elementName)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_string string = nullptr;

    // deviceId?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_DEVICE_ID, &string)) {
        elementName.SetDeviceID(AniStrToString(env, string));
    }

    // bundleName: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_BUNDLE_NAME, &string));
    elementName.SetBundleName(AniStrToString(env, string));

    // moduleName?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_MODULE_NAME, &string)) {
        elementName.SetModuleName(AniStrToString(env, string));
    }

    // abilityName: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ABILITY_NAME, &string));
    elementName.SetAbilityName(AniStrToString(env, string));

    return true;
}
} // namespace AppExecFwk
} // namespace OHOS