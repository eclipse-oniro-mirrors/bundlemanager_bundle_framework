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
constexpr const char* RAW_CLASSNAME_INT = "std.core.Int";
constexpr const char* RAW_CLASSNAME_LONG = "std.core.Long";
constexpr const char* RAW_CLASSNAME_ARRAY = "escompat.Array";
constexpr const char* RAW_CLASSNAME_STRING = "std.core.String";
constexpr const char* RAW_CLASSNAME_BUNDLEMANAGER_BUNDLE_TYPE = "@ohos.bundle.bundleManager.bundleManager.BundleType";
constexpr const char* RAW_CLASSNAME_BUNDLEMANAGER_MULTIAPPMODE_TYPE =
    "@ohos.bundle.bundleManager.bundleManager.MultiAppModeType";
constexpr const char* RAW_CLASSNAME_BUNDLEMANAGER_DISPLAYORIENTATION =
    "@ohos.bundle.bundleManager.bundleManager.DisplayOrientation";
constexpr const char* RAW_CLASSNAME_BUNDLEMANAGER_LAUNCH_TYPE = "@ohos.bundle.bundleManager.bundleManager.LaunchType";
constexpr const char* RAW_CLASSNAME_BUNDLEMANAGER_EXTENSIONABILITY_TYPE =
    "@ohos.bundle.bundleManager.bundleManager.ExtensionAbilityType";
constexpr const char* RAW_CLASSNAME_BUNDLEMANAGER_MODULE_TYPE = "@ohos.bundle.bundleManager.bundleManager.ModuleType";

constexpr const char* CLASSNAME_ABILITYINFO_INNER = "bundleManager.AbilityInfoInner.AbilityInfoInner";
constexpr const char* CLASSNAME_EXTENSIONABILITYINFO_INNER =
    "bundleManager.ExtensionAbilityInfoInner.ExtensionAbilityInfoInner";
constexpr const char* RAW_CLASSNAME_WINDOWSIZE = "bundleManager.AbilityInfo.WindowSize";
constexpr const char* CLASSNAME_WINDOWSIZE_INNER = "bundleManager.AbilityInfoInner.WindowSizeInner";
constexpr const char* RAW_CLASSNAME_APPLICATIONINFO = "bundleManager.ApplicationInfo.ApplicationInfo";
constexpr const char* CLASSNAME_APPLICATIONINFO_INNER = "bundleManager.ApplicationInfoInner.ApplicationInfoInner";
constexpr const char* CLASSNAME_MODULEMETADATA_INNER = "bundleManager.ApplicationInfoInner.ModuleMetadataInner";
constexpr const char* RAW_CLASSNAME_MULTIAPPMODE = "bundleManager.ApplicationInfo.MultiAppMode";
constexpr const char* CLASSNAME_MULTIAPPMODE_INNER = "bundleManager.ApplicationInfoInner.MultiAppModeInner";
constexpr const char* CLASSNAME_BUNDLEINFO_INNER = "bundleManager.BundleInfoInner.BundleInfoInner";
constexpr const char* CLASSNAME_PERMISSION_INNER = "bundleManager.BundleInfoInner.ReqPermissionDetailInner";
constexpr const char* RAW_CLASSNAME_USEDSCENE = "bundleManager.BundleInfo.UsedScene";
constexpr const char* CLASSNAME_USEDSCENE_INNER = "bundleManager.BundleInfoInner.UsedSceneInner";
constexpr const char* RAW_CLASSNAME_SIGNATUREINFO = "bundleManager.BundleInfo.SignatureInfo";
constexpr const char* CLASSNAME_SIGNATUREINFO_INNER = "bundleManager.BundleInfoInner.SignatureInfoInner";
constexpr const char* CLASSNAME_APPCLONEIDENTITY_INNER = "bundleManager.BundleInfoInner.AppCloneIdentityInner";
constexpr const char* CLASSNAME_DYNAMICICONINFO_INNER = "bundleManager.BundleInfoInner.DynamicIconInfoInner";
constexpr const char* CLASSNAME_PERMISSIONDEF_INNER = "bundleManager.PermissionDefInner.PermissionDefInner";
constexpr const char* CLASSNAME_SHAREDBUNDLEINFO_INNER = "bundleManager.SharedBundleInfoInner.SharedBundleInfoInner";
constexpr const char* CLASSNAME_SHAREDMODULEINFO_INNER = "bundleManager.SharedBundleInfoInner.SharedModuleInfoInner";
constexpr const char* CLASSNAME_APPPROVISIONINFO_INNER = "bundleManager.AppProvisionInfoInner.AppProvisionInfoInner";
constexpr const char* CLASSNAME_VALIDITY_INNER = "bundleManager.AppProvisionInfoInner.ValidityInner";
constexpr const char* CLASSNAME_RECOVERABLEAPPLICATIONINFO_INNER =
    "bundleManager.RecoverableApplicationInfoInner.RecoverableApplicationInfoInner";
constexpr const char* CLASSNAME_PREINSTALLEDAPPLICATIONINFO_INNER =
    "bundleManager.ApplicationInfoInner.PreinstalledApplicationInfoInner";
constexpr const char* CLASSNAME_PLUGINBUNDLEINFO_INNER = "bundleManager.PluginBundleInfoInner.PluginBundleInfoInner";
constexpr const char* CLASSNAME_PLUGINMODULEINFO_INNER = "bundleManager.PluginBundleInfoInner.PluginModuleInfoInner";
constexpr const char* CLASSNAME_METADATA_INNER = "bundleManager.MetadataInner.MetadataInner";
constexpr const char* RAW_CLASSNAME_RESOURCE = "global.resource.Resource";
constexpr const char* CLASSNAME_RESOURCE_INNER = "global.resourceInner.ResourceInner";
constexpr const char* CLASSNAME_ROUTERITEM_INNER = "bundleManager.HapModuleInfoInner.RouterItemInner";
constexpr const char* CLASSNAME_PRELOADITEM_INNER = "bundleManager.HapModuleInfoInner.PreloadItemInner";
constexpr const char* CLASSNAME_DEPENDENCY_INNER = "bundleManager.HapModuleInfoInner.DependencyInner";
constexpr const char* CLASSNAME_HAPMODULEINFO_INNER = "bundleManager.HapModuleInfoInner.HapModuleInfoInner";
constexpr const char* CLASSNAME_DATAITEM_INNER = "bundleManager.HapModuleInfoInner.DataItemInner";
constexpr const char* CLASSNAME_ELEMENTNAME_INNER = "bundleManager.ElementNameInner.ElementNameInner";
constexpr const char* CLASSNAME_SKILL_INNER = "bundleManager.SkillInner.SkillInner";
constexpr const char* CLASSNAME_SKILLURI_INNER = "bundleManager.SkillInner.SkillUriInner";
constexpr const char* CLASSNAME_SHORTCUTINFO_INNER = "bundleManager.ShortcutInfo.ShortcutInfoInner";
constexpr const char* CLASSNAME_SHORTCUTWANT_INNER = "bundleManager.ShortcutInfo.ShortcutWantInner";
constexpr const char* CLASSNAME_SHORTCUT_PARAMETERITEM_INNER = "bundleManager.ShortcutInfo.ParameterItemInner";
constexpr const char* CLASSNAME_LAUNCHER_ABILITY_INFO_INNER =
    "bundleManager.LauncherAbilityInfoInner.LauncherAbilityInfoInner";
constexpr const char* CLASSNAME_BUNDLE_CHANGED_INFO_INNER =
    "@ohos.bundle.bundleMonitor.bundleMonitor.BundleChangedInfoInner";
constexpr const char* CLASSNAME_BUNDLE_PACK_INFO_INNER = "bundleManager.BundlePackInfoInner.BundlePackInfoInner";
constexpr const char* CLASSNAME_PACKAGE_CONFIG_INNER = "bundleManager.BundlePackInfoInner.PackageConfigInner";
constexpr const char* CLASSNAME_PACKAGE_SUMMARY_INNER = "bundleManager.BundlePackInfoInner.PackageSummaryInner";
constexpr const char* CLASSNAME_BUNDLE_CONFIG_INFO_INNER = "bundleManager.BundlePackInfoInner.BundleConfigInfoInner";
constexpr const char* CLASSNAME_EXTENSION_ABILITY_INNER = "bundleManager.BundlePackInfoInner.ExtensionAbilityInner";
constexpr const char* CLASSNAME_MODULE_CONFIG_INFO_INNER = "bundleManager.BundlePackInfoInner.ModuleConfigInfoInner";
constexpr const char* CLASSNAME_MODULE_DISTRO_INFO_INNER = "bundleManager.BundlePackInfoInner.ModuleDistroInfoInner";
constexpr const char* CLASSNAME_MODULE_ABILITY_INFO_INNER =
    "bundleManager.BundlePackInfoInner.ModuleAbilityInfoInner";
constexpr const char* CLASSNAME_ABILITY_FORM_INFO_INNER = "bundleManager.BundlePackInfoInner.AbilityFormInfoInner";
constexpr const char* CLASSNAME_VERSION_INNER = "bundleManager.BundlePackInfoInner.VersionInner";
constexpr const char* CLASSNAME_API_VERSION_INNER = "bundleManager.BundlePackInfoInner.ApiVersionInner";
constexpr const char* CLASSNAME_DISPATCH_INFO_INNER = "bundleManager.DispatchInfoInner.DispatchInfoInner";
constexpr const char* CLASSNAME_OVERLAY_MOUDLE_INFO_INNER =
    "bundleManager.OverlayModuleInfoInner.OverlayModuleInfoInner";
constexpr const char* CLASSNAME_WANT = "@ohos.app.ability.Want.Want";

constexpr const char* PROPERTYNAME_NAME = "name";
constexpr const char* PROPERTYNAME_VERSIONCODE = "versionCode";
constexpr const char* PROPERTYNAME_VERSIONNAME = "versionName";
constexpr const char* PROPERTYNAME_MINCOMPATIBLEVERSIONCODE = "minCompatibleVersionCode";
constexpr const char* PROPERTYNAME_HAPMODULESINFO = "hapModulesInfo";
constexpr const char* PROPERTYNAME_INSTALLTIME = "installTime";
constexpr const char* PROPERTYNAME_APPINDEX = "appIndex";
constexpr const char* PROPERTYNAME_KEY = "key";
constexpr const char* PROPERTYNAME_VALUE = "value";
constexpr const char* PROPERTYNAME_RESOURCE = "resource";
constexpr const char* PROPERTYNAME_VALUEID = "valueId";
constexpr const char* PROPERTYNAME_MAXCOUNT = "maxCount";
constexpr const char* PROPERTYNAME_MULTIAPPMODETYPE = "multiAppModeType";
constexpr const char* PROPERTYNAME_MODULENAME = "moduleName";
constexpr const char* PROPERTYNAME_METADATA = "metadata";
constexpr const char* PROPERTYNAME_DESCRIPTION = "description";
constexpr const char* PROPERTYNAME_DESCRIPTIONID = "descriptionId";
constexpr const char* PROPERTYNAME_ENABLED = "enabled";
constexpr const char* PROPERTYNAME_LABEL = "label";
constexpr const char* PROPERTYNAME_LABELID = "labelId";
constexpr const char* PROPERTYNAME_ICON = "icon";
constexpr const char* PROPERTYNAME_ICONID = "iconId";
constexpr const char* PROPERTYNAME_PROCESS = "process";
constexpr const char* PROPERTYNAME_PERMISSIONS = "permissions";
constexpr const char* PROPERTYNAME_CODEPATH = "codePath";
constexpr const char* PROPERTYNAME_METADATAARRAY = "metadataArray";
constexpr const char* PROPERTYNAME_REMOVABLE = "removable";
constexpr const char* PROPERTYNAME_ACCESSTOKENID = "accessTokenId";
constexpr const char* PROPERTYNAME_UID = "uid";
constexpr const char* PROPERTYNAME_ICONRESOURCE = "iconResource";
constexpr const char* PROPERTYNAME_LABELRESOURCE = "labelResource";
constexpr const char* PROPERTYNAME_DESCRIPTIONRESOURCE = "descriptionResource";
constexpr const char* PROPERTYNAME_APPDISTRIBUTIONTYPE = "appDistributionType";
constexpr const char* PROPERTYNAME_APPPROVISIONTYPE = "appProvisionType";
constexpr const char* PROPERTYNAME_SYSTEMAPP = "systemApp";
constexpr const char* PROPERTYNAME_BUNDLETYPE = "bundleType";
constexpr const char* PROPERTYNAME_DEBUG = "debug";
constexpr const char* PROPERTYNAME_DATAUNCLEARABLE = "dataUnclearable";
constexpr const char* PROPERTYNAME_NATIVELIBRARYPATH = "nativeLibraryPath";
constexpr const char* PROPERTYNAME_MULTIAPPMODE = "multiAppMode";
constexpr const char* PROPERTYNAME_INSTALLSOURCE = "installSource";
constexpr const char* PROPERTYNAME_RELEASETYPE = "releaseType";
constexpr const char* PROPERTYNAME_CLOUDFILESYNCENABLED = "cloudFileSyncEnabled";
constexpr const char* PROPERTYNAME_FLAGS = "flags";
constexpr const char* PROPERTYNAME_BUNDLENAME = "bundleName";
constexpr const char* PROPERTYNAME_EXPORTED = "exported";
constexpr const char* PROPERTYNAME_TYPE = "type";
constexpr const char* PROPERTYNAME_ORIENTATION = "orientation";
constexpr const char* PROPERTYNAME_LAUNCHTYPE = "launchType";
constexpr const char* PROPERTYNAME_URI = "uri";
constexpr const char* PROPERTYNAME_DEVICETYPES = "deviceTypes";
constexpr const char* PROPERTYNAME_APPLICATIONINFO = "applicationInfo";
constexpr const char* PROPERTYNAME_SUPPORTWINDOWMODES = "supportWindowModes";
constexpr const char* PROPERTYNAME_WINDOWSIZE = "windowSize";
constexpr const char* PROPERTYNAME_EXCLUDEFROMDOCK = "excludeFromDock";
constexpr const char* PROPERTYNAME_SKILLS = "skills";
constexpr const char* PROPERTYNAME_ORIENTATIONID = "orientationId";
constexpr const char* PROPERTYNAME_MAXWINDOWRATIO = "maxWindowRatio";
constexpr const char* PROPERTYNAME_MINWINDOWRATIO = "minWindowRatio";
constexpr const char* PROPERTYNAME_MAXWINDOWWIDTH = "maxWindowWidth";
constexpr const char* PROPERTYNAME_MINWINDOWWIDTH = "minWindowWidth";
constexpr const char* PROPERTYNAME_MAXWINDOWHEIGHT = "maxWindowHeight";
constexpr const char* PROPERTYNAME_MINWINDOWHEIGHT = "minWindowHeight";
constexpr const char* PROPERTYNAME_ID = "id";
constexpr const char* PROPERTYNAME_APPIDENTIFIER = "appIdentifier";
constexpr const char* PROPERTYNAME_CERTIFICATE = "certificate";
constexpr const char* PROPERTYNAME_ABILITIES = "abilities";
constexpr const char* PROPERTYNAME_ABILITIESINFO = "abilitiesInfo";
constexpr const char* PROPERTYNAME_EXTENSIONABILITIESINFO = "extensionAbilitiesInfo";
constexpr const char* PROPERTYNAME_INSTALLATIONFREE = "installationFree";
constexpr const char* PROPERTYNAME_HASHVALUE = "hashValue";
constexpr const char* PROPERTYNAME_DEVICEID = "deviceId";
constexpr const char* PROPERTYNAME_ABILITYNAME = "abilityName";
constexpr const char* PROPERTYNAME_SHORTNAME = "shortName";
constexpr const char* PROPERTYNAME_SCHEME = "scheme";
constexpr const char* PROPERTYNAME_HOST = "host";
constexpr const char* PROPERTYNAME_PORT = "port";
constexpr const char* PROPERTYNAME_PATH = "path";
constexpr const char* PROPERTYNAME_PATHSTARTWITH = "pathStartWith";
constexpr const char* PROPERTYNAME_PATHREGEX = "pathRegex";
constexpr const char* PROPERTYNAME_UTD = "utd";
constexpr const char* PROPERTYNAME_MAXFILESUPPORTED = "maxFileSupported";
constexpr const char* PROPERTYNAME_LINKFEATURE = "linkFeature";
constexpr const char* PROPERTYNAME_ACTIONS = "actions";
constexpr const char* PROPERTYNAME_ENTITIES = "entities";
constexpr const char* PROPERTYNAME_URIS = "uris";
constexpr const char* PROPERTYNAME_DOMAINVERIFY = "domainVerify";
constexpr const char* PROPERTYNAME_HOSTABILITY = "hostAbility";
constexpr const char* PROPERTYNAME_WANTS = "wants";
constexpr const char* PROPERTYNAME_SOURCETYPE = "sourceType";
constexpr const char* PROPERTYNAME_TARGETBUNDLE = "targetBundle";
constexpr const char* PROPERTYNAME_TARGETMODULE = "targetModule";
constexpr const char* PROPERTYNAME_TARGETABILITY = "targetAbility";
constexpr const char* PROPERTYNAME_PARAMETERS = "parameters";
constexpr const char* PROPERTYNAME_ELEMENTNAME = "elementName";
constexpr const char* PROPERTYNAME_USERID = "userId";
constexpr const char* PROPERTYNAME_HASHPARAMS = "hashParams";
constexpr const char* PROPERTYNAME_PGOFILEPATH = "pgoFilePath";
constexpr const char* PROPERTYNAME_PGOPARAMS = "pgoParams";
constexpr const char* PROPERTYNAME_SPECIFIEDDISTRIBUTIONTYPE = "specifiedDistributionType";
constexpr const char* PROPERTYNAME_ISKEEPDATA = "isKeepData";
constexpr const char* PROPERTYNAME_INSTALLFLAG = "installFlag";
constexpr const char* PROPERTYNAME_CROWDTESTDEADLINE = "crowdtestDeadline";
constexpr const char* PROPERTYNAME_SHAREDBUNDLEDIRPATHS = "sharedBundleDirPaths";
constexpr const char* PROPERTYNAME_ADDITIONALINFO = "additionalInfo";
constexpr const char* PROPERTYNAME_CODE = "code";
constexpr const char* PROPERTYNAME_VERSION = "version";
constexpr const char* PROPERTYNAME_UPDATEENABLED = "updateEnabled";
constexpr const char* PROPERTYNAME_SCHEDULEDUPDATETIME = "scheduledUpdateTime";
constexpr const char* PROPERTYNAME_UPDATEDURATION = "updateDuration";
constexpr const char* PROPERTYNAME_SUPPORTDIMENSIONS = "supportDimensions";
constexpr const char* PROPERTYNAME_DEFAULTDIMENSION = "defaultDimension";
constexpr const char* PROPERTYNAME_FORMS = "forms";
constexpr const char* PROPERTYNAME_DELIVERYWITHINSTALL = "deliveryWithInstall";
constexpr const char* PROPERTYNAME_MODULETYPE = "moduleType";
constexpr const char* PROPERTYNAME_COMPATIBLE = "compatible";
constexpr const char* PROPERTYNAME_TARGET = "target";
constexpr const char* PROPERTYNAME_MAINABILITY = "mainAbility";
constexpr const char* PROPERTYNAME_APIVERSION = "apiVersion";
constexpr const char* PROPERTYNAME_DISTRO = "distro";
constexpr const char* PROPERTYNAME_EXTENSIONABILITIES = "extensionAbilities";
constexpr const char* PROPERTYNAME_APP = "app";
constexpr const char* PROPERTYNAME_MODULES = "modules";
constexpr const char* PROPERTYNAME_PACKAGES = "packages";
constexpr const char* PROPERTYNAME_SUMMARY = "summary";
constexpr const char* PROPERTYNAME_DISPATCHAPIVERSION = "dispatchAPIVersion";
constexpr const char* PROPERTYNAME_TARGETMOUDLENAME = "targetModuleName";
constexpr const char* PROPERTYNAME_PRIORITY = "priority";
constexpr const char* PROPERTYNAME_STATE = "state";
constexpr const char* PROPERTYNAME_PERMISSIONNAME = "permissionName";
constexpr const char* PROPERTYNAME_GRANTMODE = "grantMode";
constexpr const char* PROPERTYNAME_COMPATIBLEPOLICY = "compatiblePolicy";
constexpr const char* PROPERTYNAME_SHAREDMODULEINFO = "sharedModuleInfo";
constexpr const char* PROPERTYNAME_UUID = "uuid";
constexpr const char* PROPERTYNAME_NOTBEFORE = "notBefore";
constexpr const char* PROPERTYNAME_NOTAFTER = "notAfter";
constexpr const char* PROPERTYNAME_VALIDITY = "validity";
constexpr const char* PROPERTYNAME_DEVELOPERID = "developerId";
constexpr const char* PROPERTYNAME_APL = "apl";
constexpr const char* PROPERTYNAME_ISSUER = "issuer";
constexpr const char* PROPERTYNAME_ORGANIZATION = "organization";
constexpr const char* PROPERTYNAME_CODEPATHS = "codePaths";
constexpr const char* PROPERTYNAME_PLUGINBUNDLENAME = "pluginBundleName";
constexpr const char* PROPERTYNAME_PLUGINMODULEINFOS = "pluginModuleInfos";
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
    { CLASSNAME_BUNDLEINFO_INNER, { } },
    { CLASSNAME_APPLICATIONINFO_INNER, { } },
    { CLASSNAME_MODULEMETADATA_INNER, { } },
    { CLASSNAME_METADATA_INNER, { } },
    { CLASSNAME_RESOURCE_INNER, { } },
    { CLASSNAME_MULTIAPPMODE_INNER, { } },
    { CLASSNAME_HAPMODULEINFO_INNER, { } },
    { CLASSNAME_ABILITYINFO_INNER, { } },
    { CLASSNAME_SKILL_INNER, { } },
    { CLASSNAME_WINDOWSIZE_INNER, { } },
    { CLASSNAME_EXTENSIONABILITYINFO_INNER, { } },
    { CLASSNAME_DEPENDENCY_INNER, { } },
    { CLASSNAME_PRELOADITEM_INNER, { } },
    { CLASSNAME_ROUTERITEM_INNER, { } },
    { CLASSNAME_DATAITEM_INNER, { } },
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

static ani_method GetCacheCtorMethod(
    ani_env* env, ani_class cls, const std::string& ctorSig = Builder::BuildSignatureDescriptor({}))
{
    RETURN_NULL_IF_NULL(env);
    RETURN_NULL_IF_NULL(cls);

    std::lock_guard<std::mutex> lock(g_aniClassCacherMutex);
    auto iter = std::find_if(g_aniClassCache.begin(), g_aniClassCache.end(), [env, cls](const auto& pair) {
        ani_boolean equals = ANI_FALSE;
        env->Reference_StrictEquals(pair.second.classRef, cls, &equals);
        return equals == ANI_TRUE;
    });
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

static ani_method GetCtorMethod(
    ani_env* env, ani_class cls, const std::string& ctorSig = Builder::BuildSignatureDescriptor({}))
{
    RETURN_NULL_IF_NULL(env);
    RETURN_NULL_IF_NULL(cls);

    ani_method method = GetCacheCtorMethod(env, cls, ctorSig);
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

ani_object CommonFunAni::CreateNewObjectByClass(ani_env* env, ani_class cls)
{
    RETURN_NULL_IF_NULL(env);
    RETURN_NULL_IF_NULL(cls);

    ani_method method = GetCtorMethod(env, cls);
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
    ani_env* env, ani_class cls, const std::string& ctorSig, const ani_value* args)
{
    RETURN_NULL_IF_NULL(env);
    RETURN_NULL_IF_NULL(cls);
    RETURN_NULL_IF_NULL(args);

    ani_method method = GetCtorMethod(env, cls, ctorSig.empty()? nullptr: ctorSig.c_str());
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

    ani_class cls = CreateClassByName(env, CLASSNAME_BUNDLEINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

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
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_STRING)          // moduleName: string
        .AddClass(RAW_CLASSNAME_STRING)          // vendor: string
        .AddLong()                               // versionCode: long
        .AddClass(RAW_CLASSNAME_STRING)          // versionName: string
        .AddInt()                                // minCompatibleVersionCode: int
        .AddInt()                                // targetVersion: int
        .AddClass(RAW_CLASSNAME_APPLICATIONINFO) // appInfo: ApplicationInfo
        .AddClass(RAW_CLASSNAME_ARRAY)           // hapModulesInfo: Array<HapModuleInfo>
        .AddClass(RAW_CLASSNAME_ARRAY)           // reqPermissionDetails: Array<ReqPermissionDetail>
        .AddClass(RAW_CLASSNAME_ARRAY)           // permissionGrantStates: Array<bundleManager.PermissionGrantState>
        .AddClass(RAW_CLASSNAME_SIGNATUREINFO)   // signatureInfo: SignatureInfo
        .AddLong()                               // installTime: long
        .AddLong()                               // updateTime: long
        .AddClass(RAW_CLASSNAME_ARRAY)           // routerMap: Array<RouterItem>
        .AddInt()                                // appIndex: int
        .AddClass(RAW_CLASSNAME_LONG);           // firstInstallTime?: long
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertDefaultAppAbilityInfo(ani_env* env, const AbilityInfo& abilityInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_ABILITYINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // bundleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // moduleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.moduleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string));

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // label: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.label, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABEL, string));

    // labelId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABELID, abilityInfo.labelId));

    // description: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.description, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTION, string));

    // descriptionId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONID, abilityInfo.descriptionId));

    // icon: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.iconPath, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICON, string));

    // iconId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICONID, abilityInfo.iconId));

    return object;
}

ani_object CommonFunAni::ConvertDefaultAppExtensionInfo(ani_env* env, const ExtensionAbilityInfo& extensionInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_EXTENSIONABILITYINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // bundleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionInfo.bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // moduleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionInfo.moduleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string));

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionInfo.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // labelId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABELID, extensionInfo.labelId));

    // descriptionId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONID, extensionInfo.descriptionId));

    // iconId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICONID, extensionInfo.iconId));

    return object;
}

ani_object CommonFunAni::ConvertDefaultAppHapModuleInfo(ani_env* env, const BundleInfo& bundleInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_HAPMODULEINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    // abilitiesInfo: Array<AbilityInfo>
    ani_object aAbilityInfoObject = ConvertAniArray(env, bundleInfo.abilityInfos, ConvertDefaultAppAbilityInfo);
    RETURN_NULL_IF_NULL(aAbilityInfoObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ABILITIESINFO, aAbilityInfoObject));

    // extensionAbilitiesInfo: Array<ExtensionAbilityInfo>
    ani_object aExtensionInfoObject = ConvertAniArray(env, bundleInfo.extensionInfos, ConvertDefaultAppExtensionInfo);
    RETURN_NULL_IF_NULL(aExtensionInfoObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_EXTENSIONABILITIESINFO, aExtensionInfoObject));

    return object;
}

ani_object CommonFunAni::ConvertDefaultAppBundleInfo(ani_env* env, const BundleInfo& bundleInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_BUNDLEINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleInfo.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // hapModulesInfo: Array<HapModuleInfo>
    std::vector<BundleInfo> bundleInfos = { bundleInfo };
    ani_object aHapModuleInfosObject = ConvertAniArray(env, bundleInfos, ConvertDefaultAppHapModuleInfo);
    RETURN_NULL_IF_NULL(aHapModuleInfosObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_HAPMODULESINFO, aHapModuleInfosObject));

    return object;
}

ani_object CommonFunAni::ConvertMetadata(ani_env* env, const Metadata& metadata)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_METADATA_INNER);
    RETURN_NULL_IF_NULL(cls);

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
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_STRING) // name: string
        .AddClass(RAW_CLASSNAME_STRING) // value: string
        .AddClass(RAW_CLASSNAME_STRING) // resource: string
        .AddClass(RAW_CLASSNAME_LONG);  // valueId?: long
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertMultiAppMode(ani_env* env, const MultiAppModeData& multiAppMode)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_MULTIAPPMODE_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_value args[] = {
        { .r = EnumUtils::EnumNativeToETS_BundleManager_MultiAppModeType(
            env, static_cast<int32_t>(multiAppMode.multiAppModeType)) },
        { .i = multiAppMode.maxCount },
    };
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_BUNDLEMANAGER_MULTIAPPMODE_TYPE) // multiAppModeType: bundleManager.MultiAppModeType
        .AddInt();                                               // maxCount: int
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertModuleMetaInfosItem(
    ani_env* env, const std::pair<std::string, std::vector<Metadata>>& item)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_MODULEMETADATA_INNER);
    RETURN_NULL_IF_NULL(cls);

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
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_STRING) // moduleName: string
        .AddClass(RAW_CLASSNAME_ARRAY); // metadata: Array<Metadata>
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertApplicationInfo(ani_env* env, const ApplicationInfo& appInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_APPLICATIONINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

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
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_STRING)                    // name: string
        .AddClass(RAW_CLASSNAME_STRING)                    // description: string
        .AddLong()                                         // descriptionId: long
        .AddBoolean()                                      // enabled: boolean
        .AddClass(RAW_CLASSNAME_STRING)                    // label: string
        .AddLong()                                         // labelId: long
        .AddClass(RAW_CLASSNAME_STRING)                    // icon: string
        .AddLong()                                         // iconId: long
        .AddClass(RAW_CLASSNAME_STRING)                    // process: string
        .AddClass(RAW_CLASSNAME_ARRAY)                     // permissions: Array<string>
        .AddClass(RAW_CLASSNAME_STRING)                    // codePath: string
        .AddClass(RAW_CLASSNAME_ARRAY)                     // metadataArray: Array<Metadata>
        .AddBoolean()                                      // removable: boolean
        .AddLong()                                         // accessTokenId: long
        .AddInt()                                          // uid: int
        .AddClass(RAW_CLASSNAME_RESOURCE)                  // iconResource: Resource
        .AddClass(RAW_CLASSNAME_RESOURCE)                  // labelResource: Resource
        .AddClass(RAW_CLASSNAME_RESOURCE)                  // descriptionResource: Resource
        .AddClass(RAW_CLASSNAME_STRING)                    // appDistributionType: string
        .AddClass(RAW_CLASSNAME_STRING)                    // appProvisionType: string
        .AddBoolean()                                      // systemApp: boolean
        .AddClass(RAW_CLASSNAME_BUNDLEMANAGER_BUNDLE_TYPE) // bundleType: bundleManager.BundleType
        .AddBoolean()                                      // debug: boolean
        .AddBoolean()                                      // dataUnclearable: boolean
        .AddClass(RAW_CLASSNAME_STRING)                    // nativeLibraryPath: string
        .AddClass(RAW_CLASSNAME_MULTIAPPMODE)              // multiAppMode: MultiAppMode
        .AddInt()                                          // appIndex: int
        .AddClass(RAW_CLASSNAME_STRING)                    // installSource: string
        .AddClass(RAW_CLASSNAME_STRING)                    // releaseType: string
        .AddBoolean()                                      // cloudFileSyncEnabled: boolean
        .AddClass(RAW_CLASSNAME_INT);                      // flags?: int
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertAbilityInfo(ani_env* env, const AbilityInfo& abilityInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_ABILITYINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

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
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_STRING)                           // bundleName: string
        .AddClass(RAW_CLASSNAME_STRING)                           // moduleName: string
        .AddClass(RAW_CLASSNAME_STRING)                           // name: string
        .AddClass(RAW_CLASSNAME_STRING)                           // label: string
        .AddLong()                                                // labelId: long
        .AddClass(RAW_CLASSNAME_STRING)                           // description: string
        .AddLong()                                                // descriptionId: long
        .AddClass(RAW_CLASSNAME_STRING)                           // icon: string
        .AddLong()                                                // iconId: long
        .AddClass(RAW_CLASSNAME_STRING)                           // process: string
        .AddBoolean()                                             // exported: boolean
        .AddClass(RAW_CLASSNAME_BUNDLEMANAGER_DISPLAYORIENTATION) // orientation: bundleManager.DisplayOrientation
        .AddClass(RAW_CLASSNAME_BUNDLEMANAGER_LAUNCH_TYPE)        // launchType: bundleManager.LaunchType
        .AddClass(RAW_CLASSNAME_ARRAY)                            // permissions: Array<string>
        .AddClass(RAW_CLASSNAME_ARRAY)                            // deviceTypes: Array<string>
        .AddClass(RAW_CLASSNAME_APPLICATIONINFO)                  // applicationInfo: ApplicationInfo
        .AddClass(RAW_CLASSNAME_ARRAY)                            // metadata: Array<Metadata>
        .AddBoolean()                                             // enabled: boolean
        .AddClass(RAW_CLASSNAME_ARRAY)      // supportWindowModes: Array<bundleManager.SupportWindowMode>
        .AddClass(RAW_CLASSNAME_WINDOWSIZE) // windowSize: WindowSize
        .AddBoolean()                       // excludeFromDock: boolean
        .AddClass(RAW_CLASSNAME_ARRAY)      // skills: Array<Skill>
        .AddInt()                           // appIndex: int
        .AddLong();                         // orientationId: long
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertWindowSize(ani_env* env, const AbilityInfo& abilityInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_WINDOWSIZE_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_value args[] = {
        { .d = abilityInfo.maxWindowRatio },
        { .d = abilityInfo.minWindowRatio },
        { .l = static_cast<ani_long>(abilityInfo.maxWindowWidth) },
        { .l = static_cast<ani_long>(abilityInfo.minWindowWidth) },
        { .l = static_cast<ani_long>(abilityInfo.maxWindowHeight) },
        { .l = static_cast<ani_long>(abilityInfo.minWindowHeight) },
    };
    SignatureBuilder sign {};
    sign.AddDouble() // maxWindowRatio: double
        .AddDouble() // minWindowRatio: double
        .AddLong()   // maxWindowWidth: long
        .AddLong()   // minWindowWidth: long
        .AddLong()   // maxWindowHeight: long
        .AddLong();  // minWindowHeight: long
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertExtensionInfo(ani_env* env, const ExtensionAbilityInfo& extensionInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_EXTENSIONABILITYINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

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
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_STRING)                              // bundleName: string
        .AddClass(RAW_CLASSNAME_STRING)                              // moduleName: string
        .AddClass(RAW_CLASSNAME_STRING)                              // name: string
        .AddLong()                                                   // labelId: long
        .AddLong()                                                   // descriptionId: long
        .AddLong()                                                   // iconId: long
        .AddBoolean()                                                // exported: boolean
        .AddClass(RAW_CLASSNAME_BUNDLEMANAGER_EXTENSIONABILITY_TYPE) // extensionAbilityType
        .AddClass(RAW_CLASSNAME_STRING)                              // extensionAbilityTypeName: string
        .AddClass(RAW_CLASSNAME_ARRAY)                               // permissions: Array<string>
        .AddClass(RAW_CLASSNAME_APPLICATIONINFO)                     // applicationInfo: ApplicationInfo
        .AddClass(RAW_CLASSNAME_ARRAY)                               // metadata: Array<Metadata>
        .AddBoolean()                                                // enabled: boolean
        .AddClass(RAW_CLASSNAME_STRING)                              // readPermission: string
        .AddClass(RAW_CLASSNAME_STRING)                              // writePermission: string
        .AddClass(RAW_CLASSNAME_ARRAY)                               // skills: Array<Skill>
        .AddInt();                                                   // appIndex: int
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertResource(ani_env* env, const Resource& resource)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_RESOURCE_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // bundleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, resource.bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // moduleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, resource.moduleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string));

    // id: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ID, resource.id));

    return object;
}

ani_object CommonFunAni::ConvertSignatureInfo(ani_env* env, const SignatureInfo& signatureInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_SIGNATUREINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

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
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_STRING)  // appId: string
        .AddClass(RAW_CLASSNAME_STRING)  // fingerprint: string
        .AddClass(RAW_CLASSNAME_STRING)  // appIdentifier: string
        .AddClass(RAW_CLASSNAME_STRING); // certificate?: string
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertKeyValuePair(
    ani_env* env, const std::pair<std::string, std::string>& item, const std::string& className)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, className);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // key: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, item.first, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_KEY, string));

    // value: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, item.second, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VALUE, string));

    return object;
}

ani_object CommonFunAni::ConvertKeyValuePairV2(
    ani_env* env, const std::pair<std::string, std::string>& item, const std::string& className)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, className);
    RETURN_NULL_IF_NULL(cls);

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
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_STRING)  // key: string
        .AddClass(RAW_CLASSNAME_STRING); // value: string
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

inline ani_object CommonFunAni::ConvertDataItem(ani_env* env, const std::pair<std::string, std::string>& item)
{
    return ConvertKeyValuePairV2(env, item, CLASSNAME_DATAITEM_INNER);
}

ani_object CommonFunAni::ConvertRouterItem(ani_env* env, const RouterItem& routerItem)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_ROUTERITEM_INNER);
    RETURN_NULL_IF_NULL(cls);

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
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_STRING) // name: string
        .AddClass(RAW_CLASSNAME_STRING) // pageSourceFile: string
        .AddClass(RAW_CLASSNAME_STRING) // buildFunction: string
        .AddClass(RAW_CLASSNAME_STRING) // customData: string
        .AddClass(RAW_CLASSNAME_ARRAY); // data: Array<DataItem>
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertRequestPermission(ani_env* env, const RequestPermission& requestPermission)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_PERMISSION_INNER);
    RETURN_NULL_IF_NULL(cls);

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
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_STRING)     // name: string
        .AddClass(RAW_CLASSNAME_STRING)     // moduleName: string
        .AddClass(RAW_CLASSNAME_STRING)     // reason: string
        .AddLong()                          // reasonId: long
        .AddClass(RAW_CLASSNAME_USEDSCENE); // usedScene: UsedScene
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertRequestPermissionUsedScene(
    ani_env* env, const RequestPermissionUsedScene& requestPermissionUsedScene)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_USEDSCENE_INNER);
    RETURN_NULL_IF_NULL(cls);

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
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_ARRAY)   // abilities: Array<string>
        .AddClass(RAW_CLASSNAME_STRING); // when: string
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertPreloadItem(ani_env* env, const PreloadItem& preloadItem)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_PRELOADITEM_INNER);
    RETURN_NULL_IF_NULL(cls);

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, preloadItem.moduleName, moduleName));

    ani_value args[] = {
        { .r = moduleName },
    };
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_STRING); // moduleName: string
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertDependency(ani_env* env, const Dependency& dependency)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_DEPENDENCY_INNER);
    RETURN_NULL_IF_NULL(cls);

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
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_STRING) // moduleName: string
        .AddClass(RAW_CLASSNAME_STRING) // bundleName: string
        .AddLong();                     // versionCode: long
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertHapModuleInfo(ani_env* env, const HapModuleInfo& hapModuleInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_HAPMODULEINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

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
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_STRING)                    // name: string
        .AddClass(RAW_CLASSNAME_STRING)                    // icon: string
        .AddLong()                                         // iconId: long
        .AddClass(RAW_CLASSNAME_STRING)                    // label: string
        .AddLong()                                         // labelId: long
        .AddClass(RAW_CLASSNAME_STRING)                    // description: string
        .AddLong()                                         // descriptionId: long
        .AddClass(RAW_CLASSNAME_STRING)                    // mainElementName: string
        .AddClass(RAW_CLASSNAME_ARRAY)                     // abilitiesInfo: Array<AbilityInfo>
        .AddClass(RAW_CLASSNAME_ARRAY)                     // extensionAbilitiesInfo: Array<ExtensionAbilityInfo>
        .AddClass(RAW_CLASSNAME_ARRAY)                     // metadata: Array<Metadata>
        .AddClass(RAW_CLASSNAME_ARRAY)                     // deviceTypes: Array<string>
        .AddBoolean()                                      // installationFree: boolean
        .AddClass(RAW_CLASSNAME_STRING)                    // hashValue: string
        .AddClass(RAW_CLASSNAME_BUNDLEMANAGER_MODULE_TYPE) // type: bundleManager.ModuleType
        .AddClass(RAW_CLASSNAME_ARRAY)                     // dependencies: Array<Dependency>
        .AddClass(RAW_CLASSNAME_ARRAY)                     // preloads: Array<PreloadItem>
        .AddClass(RAW_CLASSNAME_STRING)                    // fileContextMenuConfig: string
        .AddClass(RAW_CLASSNAME_ARRAY)                     // routerMap: Array<RouterItem>
        .AddClass(RAW_CLASSNAME_STRING)                    // nativeLibraryPath: string
        .AddClass(RAW_CLASSNAME_STRING);                   // codePath: string
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertElementName(ani_env* env, const ElementName& elementName)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_ELEMENTNAME_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // deviceId?: string
    if (StringToAniStr(env, elementName.GetDeviceID(), string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_DEVICEID, string));
    }

    // bundleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, elementName.GetBundleName(), string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // moduleName?: string
    if (StringToAniStr(env, elementName.GetModuleName(), string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_MODULENAME, string));
    }

    // abilityName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, elementName.GetAbilityName(), string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ABILITYNAME, string));

    // uri?: string
    if (StringToAniStr(env, elementName.GetURI(), string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_URI, string));
    }

    // shortName?: string
    if (StringToAniStr(env, "", string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_SHORTNAME, string));
    }

    return object;
}

ani_object CommonFunAni::ConvertAbilitySkillUriInner(ani_env* env, const SkillUri& skillUri, bool isExtension)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_SKILLURI_INNER);
    RETURN_NULL_IF_NULL(cls);

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
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_STRING)  // scheme: string
        .AddClass(RAW_CLASSNAME_STRING)  // host: string
        .AddInt()                        // port: int
        .AddClass(RAW_CLASSNAME_STRING)  // path: string
        .AddClass(RAW_CLASSNAME_STRING)  // pathStartWith: string
        .AddClass(RAW_CLASSNAME_STRING)  // pathRegex: string
        .AddClass(RAW_CLASSNAME_STRING)  // type: string
        .AddClass(RAW_CLASSNAME_STRING)  // utd: string
        .AddInt()                        // maxFileSupported: int
        .AddClass(RAW_CLASSNAME_STRING); // linkFeature: string
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertAbilitySkillInner(ani_env* env, const Skill& skill, bool isExtension)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_SKILL_INNER);
    RETURN_NULL_IF_NULL(cls);

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
    SignatureBuilder sign {};
    sign.AddClass(RAW_CLASSNAME_ARRAY) // actions: Array<string>
        .AddClass(RAW_CLASSNAME_ARRAY) // entities: Array<string>
        .AddClass(RAW_CLASSNAME_ARRAY) // uris: Array<SkillUri>
        .AddBoolean();                 // domainVerify: boolean
    return CreateNewObjectByClassV2(env, cls, sign.BuildSignatureDescriptor(), args);
}

ani_object CommonFunAni::ConvertAppCloneIdentity(ani_env* env, const std::string& bundleName, const int32_t appIndex)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_APPCLONEIDENTITY_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // appIndex: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, appIndex));

    return object;
}

ani_object CommonFunAni::ConvertPermissionDef(ani_env* env, const PermissionDef& permissionDef)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_PERMISSIONDEF_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // permissionName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, permissionDef.permissionName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PERMISSIONNAME, string));

    // grantMode: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_GRANTMODE, permissionDef.grantMode));

    // labelId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABELID, permissionDef.labelId));

    // descriptionId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONID, permissionDef.descriptionId));

    return object;
}

ani_object CommonFunAni::ConvertSharedBundleInfo(ani_env* env, const SharedBundleInfo& sharedBundleInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_SHAREDBUNDLEINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, sharedBundleInfo.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // bundleType: bundleManager.CompatiblePolicy
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_COMPATIBLEPOLICY,
        EnumUtils::EnumNativeToETS_BundleManager_CompatiblePolicy(
            env, static_cast<int32_t>(CompatiblePolicy::BACKWARD_COMPATIBILITY))));

    // sharedModuleInfo: Array<SharedModuleInfo>
    ani_object aSharedModuleInfosObject =
        ConvertAniArray(env, sharedBundleInfo.sharedModuleInfos, ConvertSharedModuleInfo);
    RETURN_NULL_IF_NULL(aSharedModuleInfosObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_SHAREDMODULEINFO, aSharedModuleInfosObject));

    return object;
}

ani_object CommonFunAni::ConvertSharedModuleInfo(ani_env* env, const SharedModuleInfo& sharedModuleInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_SHAREDMODULEINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, sharedModuleInfo.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // versionCode: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VERSIONCODE, sharedModuleInfo.versionCode));

    // versionName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, sharedModuleInfo.versionName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VERSIONNAME, string));

    // description: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, sharedModuleInfo.description, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTION, string));

    // descriptionId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONID, sharedModuleInfo.descriptionId));

    return object;
}

ani_object CommonFunAni::ConvertAppProvisionInfo(ani_env* env, const AppProvisionInfo& appProvisionInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_APPPROVISIONINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // versionCode: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VERSIONCODE, appProvisionInfo.versionCode));

    // versionName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.versionName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VERSIONNAME, string));

    // uuid: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.uuid, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_UUID, string));

    // type: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.type, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_TYPE, string));

    // appDistributionType: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.appDistributionType, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPDISTRIBUTIONTYPE, string));

    // validity: Validity
    ani_object aniValidityObject = ConvertValidity(env, appProvisionInfo.validity);
    RETURN_NULL_IF_NULL(aniValidityObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VALIDITY, aniValidityObject));

    // developerId: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.developerId, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DEVELOPERID, string));

    // certificate: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.certificate, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_CERTIFICATE, string));

    // apl: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.apl, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APL, string));

    // issuer: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.issuer, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ISSUER, string));

    // appIdentifier: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.appIdentifier, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPIDENTIFIER, string));

    // organization: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appProvisionInfo.organization, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ORGANIZATION, string));

    return object;
}

ani_object CommonFunAni::ConvertValidity(ani_env* env, const Validity& validity)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_VALIDITY_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    // notBefore: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NOTBEFORE, validity.notBefore));

    // notAfter: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NOTAFTER, validity.notAfter));

    return object;
}

ani_object CommonFunAni::ConvertRecoverableApplicationInfo(
    ani_env* env, const RecoverableApplicationInfo& recoverableApplicationInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_RECOVERABLEAPPLICATIONINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // bundleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, recoverableApplicationInfo.bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // moduleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, recoverableApplicationInfo.moduleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string));

    // labelId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABELID, recoverableApplicationInfo.labelId));

    // iconId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICONID, recoverableApplicationInfo.iconId));

    // systemApp: boolean
    RETURN_NULL_IF_FALSE(
        CallSetter(env, cls, object, PROPERTYNAME_SYSTEMAPP, BoolToAniBoolean(recoverableApplicationInfo.systemApp)));

    // bundleType: bundleManager.BundleType
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLETYPE,
        EnumUtils::EnumNativeToETS_BundleManager_BundleType(
            env, static_cast<int32_t>(recoverableApplicationInfo.bundleType))));

    // codePaths: Array<string>
    ani_ref aCodePaths = ConvertAniArrayString(env, recoverableApplicationInfo.codePaths);
    RETURN_NULL_IF_NULL(aCodePaths);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_CODEPATHS, aCodePaths));

    return object;
}

ani_object CommonFunAni::ConvertPreinstalledApplicationInfo(
    ani_env* env, const PreinstalledApplicationInfo& reinstalledApplicationInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_PREINSTALLEDAPPLICATIONINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // bundleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, reinstalledApplicationInfo.bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // moduleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, reinstalledApplicationInfo.moduleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string));

    // iconId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICONID, reinstalledApplicationInfo.iconId));

    // labelId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABELID, reinstalledApplicationInfo.labelId));

    return object;
}

ani_object CommonFunAni::ConvertPluginBundleInfo(ani_env* env, const PluginBundleInfo& pluginBundleInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_PLUGINBUNDLEINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // label: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, pluginBundleInfo.label, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABEL, string));

    // labelId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABELID, pluginBundleInfo.labelId));

    // icon: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, pluginBundleInfo.icon, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICON, string));

    // iconId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICONID, pluginBundleInfo.iconId));

    // pluginBundleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, pluginBundleInfo.pluginBundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PLUGINBUNDLENAME, string));

    // versionCode: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VERSIONCODE, pluginBundleInfo.versionCode));

    // versionName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, pluginBundleInfo.versionName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VERSIONNAME, string));

    // pluginModuleInfos: Array<PluginModuleInfo>
    ani_object apluginModuleInfosObject =
        ConvertAniArray(env, pluginBundleInfo.pluginModuleInfos, ConvertPluginModuleInfo);
    RETURN_NULL_IF_NULL(apluginModuleInfosObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PLUGINMODULEINFOS, apluginModuleInfosObject));

    return object;
}

ani_object CommonFunAni::ConvertPluginModuleInfo(ani_env* env, const PluginModuleInfo& pluginModuleInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_PLUGINMODULEINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // moduleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, pluginModuleInfo.moduleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string));

    // descriptionId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONID, pluginModuleInfo.descriptionId));

    // description: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, pluginModuleInfo.description, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTION, string));

    return object;
}

ani_object CommonFunAni::ConvertShortcutInfo(ani_env* env, const ShortcutInfo& shortcutInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_SHORTCUTINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // id: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, shortcutInfo.id, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ID, string));

    // bundleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, shortcutInfo.bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // moduleName?: string
    if (StringToAniStr(env, shortcutInfo.moduleName, string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_MODULENAME, string));
    }

    // hostAbility?: string
    if (StringToAniStr(env, shortcutInfo.hostAbility, string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_HOSTABILITY, string));
    }

    // icon?: string
    if (StringToAniStr(env, shortcutInfo.icon, string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_ICON, string));
    }

    // iconId?: long
    RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_ICONID, shortcutInfo.iconId));

    // label?: string
    if (StringToAniStr(env, shortcutInfo.label, string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_LABEL, string));
    }

    // labelId?: long
    RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_LABELID, shortcutInfo.labelId));

    // wants?: Array<ShortcutWant>
    ani_object aShortcutWantObject = ConvertAniArray(env, shortcutInfo.intents, ConvertShortcutIntent);
    RETURN_NULL_IF_NULL(aShortcutWantObject);
    RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_WANTS, aShortcutWantObject));

    // appIndex: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, shortcutInfo.appIndex));

    // sourceType: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_SOURCETYPE, shortcutInfo.sourceType));

    // visible?: boolean
    RETURN_NULL_IF_FALSE(CallSetterOptional(
        env, cls, object, PROPERTYNAME_VISIBLE, BoolToAniBoolean(shortcutInfo.visible)));

    return object;
}

ani_object CommonFunAni::ConvertShortcutIntent(ani_env* env, const ShortcutIntent& shortcutIntent)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_SHORTCUTWANT_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // targetBundle: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, shortcutIntent.targetBundle, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_TARGETBUNDLE, string));

    // targetModule?: string
    if (StringToAniStr(env, shortcutIntent.targetModule, string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_TARGETMODULE, string));
    }

    // targetAbility: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, shortcutIntent.targetClass, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_TARGETABILITY, string));

    // parameters?: Array<ParameterItem>
    ani_object aParameters = ConvertAniArray(env, shortcutIntent.parameters, ConvertShortcutIntentParameter);
    RETURN_NULL_IF_NULL(aParameters);
    RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_PARAMETERS, aParameters));

    return object;
}

inline ani_object CommonFunAni::ConvertShortcutIntentParameter(
    ani_env* env, const std::pair<std::string, std::string>& item)
{
    return ConvertKeyValuePair(env, item, CLASSNAME_SHORTCUT_PARAMETERITEM_INNER);
}

ani_object CommonFunAni::ConvertLauncherAbilityInfo(ani_env* env, const LauncherAbilityInfo& launcherAbility)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_LAUNCHER_ABILITY_INFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    // applicationInfo: ApplicationInfo
    ani_object aObject = ConvertApplicationInfo(env, launcherAbility.applicationInfo);
    RETURN_NULL_IF_NULL(aObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPLICATIONINFO, aObject));

    // elementName: ElementName
    ani_object aElementNameObject = ConvertElementName(env, launcherAbility.elementName);
    RETURN_NULL_IF_NULL(aElementNameObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ELEMENTNAME, aElementNameObject));

    // labelId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABELID, launcherAbility.labelId));

    // iconId: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICONID, launcherAbility.iconId));

    // userId: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_USERID, launcherAbility.userId));

    // installTime: long
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_INSTALLTIME, launcherAbility.installTime));

    return object;
}

ani_object CommonFunAni::ConvertOverlayModuleInfo(ani_env* env, const OverlayModuleInfo& overlayModuleInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_OVERLAY_MOUDLE_INFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // bundleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, overlayModuleInfo.bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // moduleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, overlayModuleInfo.moduleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string));

    // targetModuleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, overlayModuleInfo.targetModuleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_TARGETMOUDLENAME, string));

    // priority: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PRIORITY, overlayModuleInfo.priority));

    // state: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_STATE, overlayModuleInfo.state));

    return object;
}

ani_object CommonFunAni::CreateBundleChangedInfo(
    ani_env* env, const std::string& bundleName, int32_t userId, int32_t appIndex)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_BUNDLE_CHANGED_INFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // bundleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // userId: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_USERID, userId));

    // appIndex: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, appIndex));

    return object;
}

ani_object CommonFunAni::ConvertVersion(ani_env* env, const Version& version)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_VERSION_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // minCompatibleVersionCode: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MINCOMPATIBLEVERSIONCODE,
        static_cast<ani_int>(version.minCompatibleVersionCode)));

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, version.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // code: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_CODE, static_cast<ani_int>(version.code)));

    return object;
}

ani_object CommonFunAni::ConvertPackageApp(ani_env* env, const PackageApp& packageApp)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_BUNDLE_CONFIG_INFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // bundleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, packageApp.bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // version: Version
    ani_object aObject = ConvertVersion(env, packageApp.version);
    RETURN_NULL_IF_NULL(aObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VERSION, aObject));

    return object;
}

ani_object CommonFunAni::ConvertAbilityFormInfo(ani_env* env, const AbilityFormInfo& abilityFormInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_ABILITY_FORM_INFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityFormInfo.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // type: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityFormInfo.type, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_TYPE, string));

    // updateEnabled: boolean
    RETURN_NULL_IF_FALSE(
        CallSetter(env, cls, object, PROPERTYNAME_UPDATEENABLED, BoolToAniBoolean(abilityFormInfo.updateEnabled)));

    // scheduledUpdateTime: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityFormInfo.scheduledUpdateTime, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_SCHEDULEDUPDATETIME, string));

    // updateDuration: int
    RETURN_NULL_IF_FALSE(CallSetter(
        env, cls, object, PROPERTYNAME_UPDATEDURATION, static_cast<ani_int>(abilityFormInfo.updateDuration)));

    // supportDimensions: Array<string>
    ani_ref aSupportDimensions = ConvertAniArrayString(env, abilityFormInfo.supportDimensions);
    RETURN_NULL_IF_NULL(aSupportDimensions);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_SUPPORTDIMENSIONS, aSupportDimensions));

    // defaultDimension: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityFormInfo.defaultDimension, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DEFAULTDIMENSION, string));

    return object;
}

ani_object CommonFunAni::ConvertModuleAbilityInfo(ani_env* env, const ModuleAbilityInfo& moduleAbilityInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_MODULE_ABILITY_INFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, moduleAbilityInfo.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // label: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, moduleAbilityInfo.label, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABEL, string));

    // exported: boolean
    RETURN_NULL_IF_FALSE(
        CallSetter(env, cls, object, PROPERTYNAME_EXPORTED, BoolToAniBoolean(moduleAbilityInfo.visible)));

    // forms: Array<AbilityFormInfo>
    ani_object aAbilityFormInfoObject = ConvertAniArray(env, moduleAbilityInfo.forms, ConvertAbilityFormInfo);
    RETURN_NULL_IF_NULL(aAbilityFormInfoObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_FORMS, aAbilityFormInfoObject));

    return object;
}

ani_object CommonFunAni::ConvertModuleDistro(ani_env* env, const ModuleDistro& moduleDistro)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_MODULE_DISTRO_INFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // deliveryWithInstall: boolean
    RETURN_NULL_IF_FALSE(CallSetter(
        env, cls, object, PROPERTYNAME_DELIVERYWITHINSTALL, BoolToAniBoolean(moduleDistro.deliveryWithInstall)));

    // installationFree: boolean
    RETURN_NULL_IF_FALSE(
        CallSetter(env, cls, object, PROPERTYNAME_INSTALLATIONFREE, BoolToAniBoolean(moduleDistro.installationFree)));

    // moduleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, moduleDistro.moduleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string));

    // moduleType: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, moduleDistro.moduleType, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULETYPE, string));

    return object;
}

ani_object CommonFunAni::ConvertApiVersion(ani_env* env, const ApiVersion& apiVersion)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_API_VERSION_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // releaseType: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, apiVersion.releaseType, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_RELEASETYPE, string));

    // compatible: int
    RETURN_NULL_IF_FALSE(
        CallSetter(env, cls, object, PROPERTYNAME_COMPATIBLE, static_cast<ani_int>(apiVersion.compatible)));

    // target: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_TARGET, static_cast<ani_int>(apiVersion.target)));

    return object;
}

ani_object CommonFunAni::ConvertExtensionAbilities(ani_env* env, const ExtensionAbilities& extensionAbilities)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_EXTENSION_ABILITY_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionAbilities.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // forms: Array<AbilityFormInfo>
    ani_object aAbilityFormInfoObject = ConvertAniArray(env, extensionAbilities.forms, ConvertAbilityFormInfo);
    RETURN_NULL_IF_NULL(aAbilityFormInfoObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_FORMS, aAbilityFormInfoObject));

    return object;
}

ani_object CommonFunAni::ConvertPackageModule(ani_env* env, const PackageModule& packageModule)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_MODULE_CONFIG_INFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // mainAbility: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, packageModule.mainAbility, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MAINABILITY, string));

    // apiVersion: ApiVersion
    ani_object aApiVersionObject = ConvertApiVersion(env, packageModule.apiVersion);
    RETURN_NULL_IF_NULL(aApiVersionObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APIVERSION, aApiVersionObject));

    // deviceTypes: Array<string>
    ani_ref aDeviceTypes = ConvertAniArrayString(env, packageModule.deviceType);
    RETURN_NULL_IF_NULL(aDeviceTypes);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DEVICETYPES, aDeviceTypes));

    // distro: ModuleDistroInfo
    ani_object aModuleDistroInfoObject = ConvertModuleDistro(env, packageModule.distro);
    RETURN_NULL_IF_NULL(aModuleDistroInfoObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DISTRO, aModuleDistroInfoObject));

    // abilities: Array<ModuleAbilityInfo>
    ani_object aModuleAbilityInfoObject = ConvertAniArray(env, packageModule.abilities, ConvertModuleAbilityInfo);
    RETURN_NULL_IF_NULL(aModuleAbilityInfoObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ABILITIES, aModuleAbilityInfoObject));

    // extensionAbilities: Array<ExtensionAbility>
    ani_object aExtensionAbilityObject =
        ConvertAniArray(env, packageModule.extensionAbilities, ConvertExtensionAbilities);
    RETURN_NULL_IF_NULL(aExtensionAbilityObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_EXTENSIONABILITIES, aExtensionAbilityObject));

    return object;
}

ani_object CommonFunAni::ConvertSummary(ani_env* env, const Summary& summary, bool withApp)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_PACKAGE_SUMMARY_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    if (withApp) {
        // app: BundleConfigInfo
        ani_object aBundleConfigInfoObject = ConvertPackageApp(env, summary.app);
        RETURN_NULL_IF_NULL(aBundleConfigInfoObject);
        RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APP, aBundleConfigInfoObject));
    }

    // modules: Array<ModuleConfigInfo>
    ani_object aModuleConfigInfoObject = ConvertAniArray(env, summary.modules, ConvertPackageModule);
    RETURN_NULL_IF_NULL(aModuleConfigInfoObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULES, aModuleConfigInfoObject));

    return object;
}

ani_object CommonFunAni::ConvertPackages(ani_env* env, const Packages& packages)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_PACKAGE_CONFIG_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // deviceTypes: Array<string>
    ani_ref aDeviceTypes = ConvertAniArrayString(env, packages.deviceType);
    RETURN_NULL_IF_NULL(aDeviceTypes);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DEVICETYPES, aDeviceTypes));

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, packages.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // moduleType: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, packages.moduleType, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULETYPE, string));

    // deliveryWithInstall: boolean
    RETURN_NULL_IF_FALSE(
        CallSetter(env, cls, object, PROPERTYNAME_DELIVERYWITHINSTALL, BoolToAniBoolean(packages.deliveryWithInstall)));

    return object;
}

ani_object CommonFunAni::ConvertBundlePackInfo(ani_env* env, const BundlePackInfo& bundlePackInfo, const uint32_t flag)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_BUNDLE_PACK_INFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    // packages: Array<PackageConfig>
    ani_object aPackageConfigObject = ConvertAniArray(env, bundlePackInfo.packages, ConvertPackages);
    RETURN_NULL_IF_NULL(aPackageConfigObject);

    if (flag & BundlePackFlag::GET_PACKAGES) {
        RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PACKAGES, aPackageConfigObject));
        return object;
    }

    // summary: PackageSummary
    ani_object aPackageSummaryObject = ConvertSummary(env, bundlePackInfo.summary, true);
    RETURN_NULL_IF_NULL(aPackageSummaryObject);

    if (flag & BundlePackFlag::GET_BUNDLE_SUMMARY) {
        RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_SUMMARY, aPackageSummaryObject));
        return object;
    }

    if (flag & BundlePackFlag::GET_MODULE_SUMMARY) {
        ani_object aPackageSummaryWithoutApp = ConvertSummary(env, bundlePackInfo.summary, false);
        RETURN_NULL_IF_NULL(aPackageSummaryWithoutApp);
        RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_SUMMARY, aPackageSummaryWithoutApp));
        return object;
    }

    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PACKAGES, aPackageConfigObject));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_SUMMARY, aPackageSummaryObject));

    return object;
}

ani_object CommonFunAni::CreateDispatchInfo(
    ani_env* env, const std::string& version, const std::string& dispatchAPIVersion)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_DISPATCH_INFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // version: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, version, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VERSION, string));

    // dispatchAPIVersion: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, dispatchAPIVersion, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DISPATCHAPIVERSION, string));

    return object;
}

ani_object CommonFunAni::ConvertDynamicIconInfo(ani_env* env, const DynamicIconInfo& dynamicIconInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_DYNAMICICONINFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // bundleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, dynamicIconInfo.bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // moduleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, dynamicIconInfo.moduleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string));

    // userId: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_USERID, dynamicIconInfo.userId));

    // appIndex: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, dynamicIconInfo.appIndex));

    return object;
}

bool CommonFunAni::ParseBundleOptions(ani_env* env, ani_object object, int32_t& appIndex, int32_t& userId)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_int intValue = 0;
    bool isDefault = true;

    // userId?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_USERID, &intValue)) {
        if (intValue < 0) {
            intValue = Constants::INVALID_USERID;
        }
        userId = intValue;
        isDefault = false;
    }

    // appIndex?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_APPINDEX, &intValue)) {
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

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    // bundleName?: string
    ani_string string = nullptr;
    if (StringToAniStr(env, want.GetElement().GetBundleName(), string)) {
        RETURN_NULL_IF_FALSE(CallSetField(env, cls, object, PROPERTYNAME_BUNDLENAME, string));
    }

    // abilityName?: string
    if (StringToAniStr(env, want.GetElement().GetAbilityName(), string)) {
        RETURN_NULL_IF_FALSE(CallSetField(env, cls, object, PROPERTYNAME_ABILITYNAME, string));
    }

    // deviceId?: string
    if (StringToAniStr(env, want.GetElement().GetDeviceID(), string)) {
        RETURN_NULL_IF_FALSE(CallSetField(env, cls, object, PROPERTYNAME_DEVICEID, string));
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
        RETURN_NULL_IF_FALSE(CallSetField(env, cls, object, PROPERTYNAME_MODULENAME, string));
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
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_BUNDLENAME, &string));
    shortcutInfo.bundleName = AniStrToString(env, string);

    // moduleName?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_MODULENAME, &string)) {
        shortcutInfo.moduleName = AniStrToString(env, string);
    }

    // hostAbility?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_HOSTABILITY, &string)) {
        shortcutInfo.hostAbility = AniStrToString(env, string);
    }

    // icon?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_ICON, &string)) {
        shortcutInfo.icon = AniStrToString(env, string);
    }

    // iconId?: long
    if (CallGetterOptional(env, object, PROPERTYNAME_ICONID, &uintValue)) {
        shortcutInfo.iconId = uintValue;
    }

    // label?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_LABEL, &string)) {
        shortcutInfo.label = AniStrToString(env, string);
    }

    // labelId?: long
    if (CallGetterOptional(env, object, PROPERTYNAME_LABELID, &uintValue)) {
        shortcutInfo.labelId = uintValue;
    }

    // wants?: Array<ShortcutWant>
    ani_array array = nullptr;
    if (CallGetterOptional(env, object, PROPERTYNAME_WANTS, &array)) {
        RETURN_FALSE_IF_FALSE(ParseAniArray(env, array, shortcutInfo.intents, ParseShortcutIntent));
    }

    // appIndex: int
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_APPINDEX, &intValue));
    shortcutInfo.appIndex = intValue;

    // sourceType: int
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_SOURCETYPE, &intValue));
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
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_TARGETBUNDLE, &string));
    shortcutIntent.targetBundle = AniStrToString(env, string);

    // targetModule?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_TARGETMODULE, &string)) {
        shortcutIntent.targetModule = AniStrToString(env, string);
    }

    // targetAbility: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_TARGETABILITY, &string));
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
    return ParseKeyValuePairWithName(env, object, pair, PROPERTYNAME_MODULENAME, PROPERTYNAME_HASHVALUE);
}

bool CommonFunAni::ParsePgoParams(ani_env* env, ani_object object, std::pair<std::string, std::string>& pair)
{
    return ParseKeyValuePairWithName(env, object, pair, PROPERTYNAME_MODULENAME, PROPERTYNAME_PGOFILEPATH);
}

bool CommonFunAni::ParseInstallParam(ani_env* env, ani_object object, InstallParam& installParam)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_array array = nullptr;
    // hashParams?
    if (CallGetterOptional(env, object, PROPERTYNAME_HASHPARAMS, &array)) {
        std::vector<std::pair<std::string, std::string>> hashParams;
        RETURN_FALSE_IF_FALSE(ParseAniArray(env, array, hashParams, ParseHashParams));
        for (const auto& parameter : hashParams) {
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
    if (CallGetterOptional(env, object, PROPERTYNAME_PGOPARAMS, &array)) {
        std::vector<std::pair<std::string, std::string>> pgoParams;
        RETURN_FALSE_IF_FALSE(ParseAniArray(env, array, pgoParams, ParsePgoParams));
        for (const auto& parameter : pgoParams) {
            installParam.pgoParams[parameter.first] = parameter.second;
        }
    }

    ani_int intValue = 0;
    // userId?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_USERID, &intValue)) {
        installParam.userId = intValue;
    } else {
        APP_LOGW("Parse userId failed,using default value");
    }
    // installFlag?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_INSTALLFLAG, &intValue)) {
        if ((intValue != static_cast<int32_t>(OHOS::AppExecFwk::InstallFlag::NORMAL)) &&
            (intValue != static_cast<int32_t>(OHOS::AppExecFwk::InstallFlag::REPLACE_EXISTING)) &&
            (intValue != static_cast<int32_t>(OHOS::AppExecFwk::InstallFlag::FREE_INSTALL))) {
            APP_LOGE("invalid installFlag param");
        }
        installParam.installFlag = static_cast<OHOS::AppExecFwk::InstallFlag>(intValue);
    } else {
        APP_LOGW("Parse installFlag failed,using default value");
    }

    ani_boolean boolValue = false;
    // isKeepData?: boolean
    if (CallGetterOptional(env, object, PROPERTYNAME_ISKEEPDATA, &boolValue)) {
        installParam.isKeepData = boolValue;
    } else {
        APP_LOGW("Parse isKeepData failed,using default value");
    }

    ani_long longValue = 0;
    // crowdtestDeadline?: long
    if (CallGetterOptional(env, object, PROPERTYNAME_CROWDTESTDEADLINE, &longValue)) {
        installParam.crowdtestDeadline = longValue;
    } else {
        APP_LOGW("Parse crowdtestDeadline failed,using default value");
    }

    // sharedBundleDirPaths?: Array<string>
    if (CallGetterOptional(env, object, PROPERTYNAME_SHAREDBUNDLEDIRPATHS, &array)) {
        RETURN_FALSE_IF_FALSE(ParseStrArray(env, array, installParam.sharedBundleDirPaths));
    }

    ani_string string = nullptr;

    // specifiedDistributionType?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_SPECIFIEDDISTRIBUTIONTYPE, &string)) {
        installParam.specifiedDistributionType = AniStrToString(env, string);
    } else {
        APP_LOGW("Parse specifiedDistributionType failed,using default value");
    }

    // additionalInfo?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_ADDITIONALINFO, &string)) {
        installParam.specifiedDistributionType = AniStrToString(env, string);
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
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_BUNDLENAME, &string));
    uninstallParam.bundleName = AniStrToString(env, string);
    ani_int intValue = 0;
    // versionCode?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_VERSIONCODE, &intValue)) {
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
    if (CallGetterOptional(env, object, PROPERTYNAME_USERID, &intValue)) {
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
    if (CallGetterOptional(env, object, PROPERTYNAME_USERID, &intValue)) {
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
    if (CallGetterOptional(env, object, PROPERTYNAME_USERID, &intValue)) {
        userId = intValue;
    } else {
        userId = Constants::UNSPECIFIED_USERID;
        APP_LOGW("Parse userId failed,using default value");
    }

    // appIdx?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_APPINDEX, &intValue)) {
        appIdx = intValue;
    } else {
        appIdx = Constants::INITIAL_APP_INDEX;
        APP_LOGW("Parse appIdx failed,using default value");
    }
    return true;
}

bool CommonFunAni::ParseMetadata(ani_env* env, ani_object object, Metadata& metadata)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_string string = nullptr;
    uint32_t uintValue = 0;

    // name: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_NAME, &string));
    metadata.name = AniStrToString(env, string);

    // value: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_VALUE, &string));
    metadata.value = AniStrToString(env, string);

    // resource: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_RESOURCE, &string));
    metadata.resource = AniStrToString(env, string);

    // valueId?: long
    if (CallGetterOptional(env, object, PROPERTYNAME_VALUEID, &uintValue)) {
        metadata.valueId = uintValue;
    }

    return true;
}

bool CommonFunAni::ParseResource(ani_env* env, ani_object object, Resource& resource)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_string string = nullptr;

    // bundleName: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_BUNDLENAME, &string));
    resource.bundleName = AniStrToString(env, string);

    // moduleName: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MODULENAME, &string));
    resource.moduleName = AniStrToString(env, string);

    // id: long
    ani_long longValue = 0;
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ID, &longValue));
    resource.id = longValue;

    return true;
}

bool CommonFunAni::ParseMultiAppMode(ani_env* env, ani_object object, MultiAppModeData& multiAppMode)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_enum_item enumItem = nullptr;
    ani_int intValue = 0;

    // maxCount: int
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MAXCOUNT, &intValue));
    multiAppMode.maxCount = intValue;

    // multiAppModeType: bundleManager.MultiAppModeType
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MULTIAPPMODETYPE, &enumItem));
    RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, multiAppMode.multiAppModeType));

    return true;
}

bool CommonFunAni::ParseApplicationInfo(ani_env* env, ani_object object, ApplicationInfo& appInfo)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_string string = nullptr;
    // name: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_NAME, &string));
    appInfo.name = AniStrToString(env, string);

    // description: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_DESCRIPTION, &string));
    appInfo.description = AniStrToString(env, string);

    uint32_t uintValue = 0;
    // descriptionId: long
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_DESCRIPTIONID, &uintValue));
    appInfo.descriptionId = uintValue;

    ani_boolean boolValue = ANI_FALSE;
    // enabled: boolean
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ENABLED, &boolValue));
    appInfo.enabled = AniBooleanToBool(boolValue);

    // label: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_LABEL, &string));
    appInfo.label = AniStrToString(env, string);

    // labelId: long
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_LABELID, &uintValue));
    appInfo.labelId = uintValue;

    // icon: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ICON, &string));
    appInfo.iconPath = AniStrToString(env, string);

    // iconId: long
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ICONID, &uintValue));
    appInfo.iconId = uintValue;

    // process: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_PROCESS, &string));
    appInfo.process = AniStrToString(env, string);

    ani_object arrayObject = nullptr;
    // permissions: Array<string>
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_PERMISSIONS, &arrayObject));
    RETURN_FALSE_IF_FALSE(ParseStrArray(env, arrayObject, appInfo.permissions));

    // codePath: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_CODEPATH, &string));
    appInfo.codePath = AniStrToString(env, string);

    // metadataArray: Array<ModuleMetadata>
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_METADATAARRAY, &arrayObject));
    RETURN_FALSE_IF_FALSE(AniArrayForeach(env, arrayObject, [env, &appInfo](ani_object itemModuleMetadataANI) {
        // moduleName: string
        ani_string stringValue = nullptr;
        RETURN_FALSE_IF_FALSE(CallGetter(env, itemModuleMetadataANI, PROPERTYNAME_MODULENAME, &stringValue));
        std::string key = AniStrToString(env, stringValue);
        RETURN_FALSE_IF_FALSE(!key.empty());

        // metadata: Array<Metadata>
        ani_object arrayMetadataANI = nullptr;
        RETURN_FALSE_IF_FALSE(CallGetter(env, itemModuleMetadataANI, PROPERTYNAME_METADATA, &arrayMetadataANI));
        std::vector<Metadata> arrayMetadataNative;
        RETURN_FALSE_IF_FALSE(ParseAniArray(env, arrayMetadataANI, arrayMetadataNative, ParseMetadata));

        appInfo.metadata.emplace(key, std::move(arrayMetadataNative));

        return true;
    }));

    // removable: boolean
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_REMOVABLE, &boolValue));
    appInfo.removable = AniBooleanToBool(boolValue);

    // accessTokenId: long
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ACCESSTOKENID, &uintValue));
    appInfo.accessTokenId = uintValue;

    ani_int intValue = 0;
    // uid: int
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_UID, &intValue));
    appInfo.uid = intValue;

    ani_object aniObject = nullptr;
    // iconResource: Resource
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ICONRESOURCE, &aniObject));
    RETURN_FALSE_IF_FALSE(ParseResource(env, aniObject, appInfo.iconResource));

    // labelResource: Resource
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_LABELRESOURCE, &aniObject));
    RETURN_FALSE_IF_FALSE(ParseResource(env, aniObject, appInfo.labelResource));

    // descriptionResource: Resource
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_DESCRIPTIONRESOURCE, &aniObject));
    RETURN_FALSE_IF_FALSE(ParseResource(env, aniObject, appInfo.descriptionResource));

    // appDistributionType: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_APPDISTRIBUTIONTYPE, &string));
    appInfo.appDistributionType = AniStrToString(env, string);

    // appProvisionType: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_APPPROVISIONTYPE, &string));
    appInfo.appProvisionType = AniStrToString(env, string);

    // systemApp: boolean
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_SYSTEMAPP, &boolValue));
    appInfo.isSystemApp = AniBooleanToBool(boolValue);

    ani_enum_item enumItem = nullptr;
    // bundleType: bundleManager.BundleType
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_BUNDLETYPE, &enumItem));
    RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, appInfo.bundleType));

    // debug: boolean
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_DEBUG, &boolValue));
    appInfo.debug = AniBooleanToBool(boolValue);

    // dataUnclearable: boolean
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_DATAUNCLEARABLE, &boolValue));
    appInfo.userDataClearable = AniBooleanToBool(!boolValue);

    // nativeLibraryPath: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_NATIVELIBRARYPATH, &string));
    appInfo.nativeLibraryPath = AniStrToString(env, string);

    // multiAppMode: MultiAppMode
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MULTIAPPMODE, &aniObject));
    RETURN_FALSE_IF_FALSE(ParseMultiAppMode(env, aniObject, appInfo.multiAppMode));

    // appIndex: int
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_APPINDEX, &intValue));
    appInfo.appIndex = intValue;

    // installSource: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_INSTALLSOURCE, &string));
    appInfo.installSource = AniStrToString(env, string);

    // releaseType: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_RELEASETYPE, &string));
    appInfo.apiReleaseType = AniStrToString(env, string);

    // cloudFileSyncEnabled: boolean
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_CLOUDFILESYNCENABLED, &boolValue));
    appInfo.cloudFileSyncEnabled = AniBooleanToBool(boolValue);

    // flags?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_FLAGS, &intValue)) {
        appInfo.flags = intValue;
    }

    return true;
}

bool CommonFunAni::ParseWindowSize(ani_env* env, ani_object object, AbilityInfo& abilityInfo)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_double doubleValue = 0;
    uint32_t uintValue = 0;

    // maxWindowRatio: double
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MAXWINDOWRATIO, &doubleValue));
    abilityInfo.maxWindowRatio = doubleValue;

    // minWindowRatio: double
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MINWINDOWRATIO, &doubleValue));
    abilityInfo.minWindowRatio = doubleValue;

    // maxWindowWidth: long
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MAXWINDOWWIDTH, &uintValue));
    abilityInfo.maxWindowWidth = uintValue;

    // minWindowWidth: long
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MINWINDOWWIDTH, &uintValue));
    abilityInfo.minWindowWidth = uintValue;

    // maxWindowHeight: long
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MAXWINDOWHEIGHT, &uintValue));
    abilityInfo.maxWindowHeight = uintValue;

    // minWindowHeight: long
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MINWINDOWHEIGHT, &uintValue));
    abilityInfo.minWindowHeight = uintValue;

    return object;
}

bool CommonFunAni::ParseAbilitySkillUriInner(ani_env* env, ani_object object, SkillUri& skillUri, bool isExtension)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_string string = nullptr;
    ani_int intValue = 0;

    // scheme: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_SCHEME, &string));
    skillUri.scheme = AniStrToString(env, string);

    // host: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_HOST, &string));
    skillUri.host = AniStrToString(env, string);

    // port: int
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_PORT, &intValue));
    skillUri.port = std::to_string(intValue);

    // path: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_PATH, &string));
    skillUri.path = AniStrToString(env, string);

    // pathStartWith: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_PATHSTARTWITH, &string));
    skillUri.pathStartWith = AniStrToString(env, string);

    // pathRegex: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_PATHREGEX, &string));
    skillUri.pathRegex = AniStrToString(env, string);

    // type: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_TYPE, &string));
    skillUri.type = AniStrToString(env, string);

    // utd: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_UTD, &string));
    skillUri.utd = AniStrToString(env, string);

    // maxFileSupported: int
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MAXFILESUPPORTED, &intValue));
    skillUri.maxFileSupported = intValue;

    if (!isExtension) {
        // linkFeature: string
        RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_LINKFEATURE, &string));
        skillUri.linkFeature = AniStrToString(env, string);
    }

    return true;
}

bool CommonFunAni::ParseAbilitySkillInner(ani_env* env, ani_object object, Skill& skill, bool isExtension)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_object arrayObject = nullptr;
    ani_boolean boolValue = ANI_FALSE;

    // actions: Array<string>
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ACTIONS, &arrayObject));
    RETURN_FALSE_IF_FALSE(ParseStrArray(env, arrayObject, skill.actions));

    // entities: Array<string>
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ENTITIES, &arrayObject));
    RETURN_FALSE_IF_FALSE(ParseStrArray(env, arrayObject, skill.entities));

    // uris: Array<SkillUri>
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_URIS, &arrayObject));
    RETURN_FALSE_IF_FALSE(ParseAniArray(
        env, arrayObject, skill.uris, isExtension ? ParseExtensionAbilitySkillUri : ParseAbilitySkillUri));

    if (!isExtension) {
        // domainVerify: boolean
        RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_DOMAINVERIFY, &boolValue));
        skill.domainVerify = AniBooleanToBool(boolValue);
    }

    return true;
}

bool CommonFunAni::ParseAbilityInfo(ani_env* env, ani_object object, AbilityInfo& abilityInfo)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_string string = nullptr;
    // bundleName: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_BUNDLENAME, &string));
    abilityInfo.bundleName = AniStrToString(env, string);

    // moduleName: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MODULENAME, &string));
    abilityInfo.moduleName = AniStrToString(env, string);

    // name: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_NAME, &string));
    abilityInfo.name = AniStrToString(env, string);

    // label: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_LABEL, &string));
    abilityInfo.label = AniStrToString(env, string);

    uint32_t uintValue = 0;
    // labelId: long
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_LABELID, &uintValue));
    abilityInfo.labelId = uintValue;

    // description: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_DESCRIPTION, &string));
    abilityInfo.description = AniStrToString(env, string);

    // descriptionId: long
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_DESCRIPTIONID, &uintValue));
    abilityInfo.descriptionId = uintValue;

    // icon: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ICON, &string));
    abilityInfo.iconPath = AniStrToString(env, string);

    // iconId: long
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ICONID, &uintValue));
    abilityInfo.iconId = uintValue;

    // process: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_PROCESS, &string));
    abilityInfo.process = AniStrToString(env, string);

    ani_boolean boolValue = ANI_FALSE;
    // exported: boolean
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_EXPORTED, &boolValue));
    abilityInfo.visible = AniBooleanToBool(boolValue);

    ani_enum_item enumItem = nullptr;
    // orientation: bundleManager.DisplayOrientation
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ORIENTATION, &enumItem));
    RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, abilityInfo.orientation));

    // launchType: bundleManager.LaunchType
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_LAUNCHTYPE, &enumItem));
    RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, abilityInfo.launchMode));

    ani_object arrayObject = nullptr;
    // permissions: Array<string>
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_PERMISSIONS, &arrayObject));
    RETURN_FALSE_IF_FALSE(ParseStrArray(env, arrayObject, abilityInfo.permissions));

    // deviceTypes: Array<string>
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_DEVICETYPES, &arrayObject));
    RETURN_FALSE_IF_FALSE(ParseStrArray(env, arrayObject, abilityInfo.deviceTypes));

    ani_object aniObject = nullptr;
    // applicationInfo: ApplicationInfo
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_APPLICATIONINFO, &aniObject));
    RETURN_FALSE_IF_FALSE(ParseApplicationInfo(env, aniObject, abilityInfo.applicationInfo));

    // metadata: Array<Metadata>
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_METADATA, &arrayObject));
    RETURN_FALSE_IF_FALSE(ParseAniArray(env, arrayObject, abilityInfo.metadata, ParseMetadata));

    // enabled: boolean
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ENABLED, &boolValue));
    abilityInfo.enabled = AniBooleanToBool(boolValue);

    // supportWindowModes: Array<bundleManager.SupportWindowMode>
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_SUPPORTWINDOWMODES, &arrayObject));
    RETURN_FALSE_IF_FALSE(ParseEnumArray(env, arrayObject, abilityInfo.windowModes));

    // windowSize: WindowSize
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_WINDOWSIZE, &aniObject));
    RETURN_FALSE_IF_FALSE(ParseWindowSize(env, aniObject, abilityInfo));

    // excludeFromDock: boolean
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_EXCLUDEFROMDOCK, &boolValue));
    abilityInfo.excludeFromDock = AniBooleanToBool(boolValue);

    // skills: Array<Skill>
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_SKILLS, &arrayObject));
    RETURN_FALSE_IF_FALSE(ParseAniArray(env, arrayObject, abilityInfo.skills, ParseAbilitySkill));

    ani_int intValue = 0;
    // appIndex: int
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_APPINDEX, &intValue));
    abilityInfo.appIndex = intValue;

    // orientationId: long
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ORIENTATIONID, &uintValue));
    abilityInfo.orientationId = uintValue;

    return true;
}

bool CommonFunAni::ParseElementName(ani_env* env, ani_object object, ElementName& elementName)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_string string = nullptr;

    // deviceId?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_DEVICEID, &string)) {
        elementName.SetDeviceID(AniStrToString(env, string));
    }

    // bundleName: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_BUNDLENAME, &string));
    elementName.SetBundleName(AniStrToString(env, string));

    // moduleName?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_MODULENAME, &string)) {
        elementName.SetModuleName(AniStrToString(env, string));
    }

    // abilityName: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ABILITYNAME, &string));
    elementName.SetAbilityName(AniStrToString(env, string));

    return true;
}
} // namespace AppExecFwk
} // namespace OHOS