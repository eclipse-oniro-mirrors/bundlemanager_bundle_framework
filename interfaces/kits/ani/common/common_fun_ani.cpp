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

#include <charconv>
#include <vector>

#include "app_log_wrapper.h"
#include "common_fun_ani.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* CLASSNAME_ABILITYINFO = "LbundleManager/AbilityInfoInner/AbilityInfoInner;";
constexpr const char* CLASSNAME_EXTENSIONABILITYINFO =
    "LbundleManager/ExtensionAbilityInfoInner/ExtensionAbilityInfoInner;";
constexpr const char* CLASSNAME_WINDOWSIZE = "LbundleManager/AbilityInfoInner/WindowSizeInner;";
constexpr const char* CLASSNAME_APPLICATIONINFO = "LbundleManager/ApplicationInfoInner/ApplicationInfoInner;";
constexpr const char* CLASSNAME_MODULEMETADATA = "LbundleManager/ApplicationInfoInner/ModuleMetadataInner;";
constexpr const char* CLASSNAME_MULTIAPPMODE = "LbundleManager/ApplicationInfoInner/MultiAppModeInner;";
constexpr const char* CLASSNAME_BUNDLEINFO = "LbundleManager/BundleInfoInner/BundleInfoInner;";
constexpr const char* CLASSNAME_PERMISSION = "LbundleManager/BundleInfoInner/ReqPermissionDetailInner;";
constexpr const char* CLASSNAME_USEDSCENE = "LbundleManager/BundleInfoInner/UsedSceneInner;";
constexpr const char* CLASSNAME_SIGNATUREINFO = "LbundleManager/BundleInfoInner/SignatureInfoInner;";
constexpr const char* CLASSNAME_APPCLONEIDENTITY = "LbundleManager/BundleInfoInner/AppCloneIdentityInner;";
constexpr const char* CLASSNAME_METADATA = "LbundleManager/MetadataInner/MetadataInner;";
constexpr const char* CLASSNAME_RESOURCE = "Lglobal/resourceInner/ResourceInner;";
constexpr const char* CLASSNAME_ROUTERITEM = "LbundleManager/HapModuleInfoInner/RouterItemInner;";
constexpr const char* CLASSNAME_PRELOADITEM = "LbundleManager/HapModuleInfoInner/PreloadItemInner;";
constexpr const char* CLASSNAME_DEPENDENCY = "LbundleManager/HapModuleInfoInner/DependencyInner;";
constexpr const char* CLASSNAME_HAPMODULEINFO = "LbundleManager/HapModuleInfoInner/HapModuleInfoInner;";
constexpr const char* CLASSNAME_DATAITEM = "LbundleManager/HapModuleInfoInner/DataItemInner;";
constexpr const char* CLASSNAME_ELEMENTNAME = "LbundleManager/ElementNameInner/ElementNameInner;";
constexpr const char* CLASSNAME_CUSTOMIZEDATA = "LbundleManager/customizeDataInner/CustomizeDataInner;";
constexpr const char* CLASSNAME_SKILL = "LbundleManager/SkillInner/SkillInner;";
constexpr const char* CLASSNAME_SKILLURI = "LbundleManager/SkillInner/SkillUriInner;";
constexpr const char* CLASSNAME_BUNDLERESINFO = "LbundleManager/BundleResourceInfoInner/BundleResourceInfoInner;";
constexpr const char* CLASSNAME_SHORTCUTINFO = "LbundleManager/ShortcutInfo/ShortcutInfoInner;";
constexpr const char* CLASSNAME_SHORTCUTWANT = "LbundleManager/ShortcutInfo/ShortcutWantInner;";
constexpr const char* CLASSNAME_SHORTCUT_PARAMETERITEM = "LbundleManager/ShortcutInfo/ParameterItemInner;";
constexpr const char* CLASSNAME_LAUNCHER_ABILITY_INFO_INNER =
    "LbundleManager/LauncherAbilityInfoInner/LauncherAbilityInfoInner;";

constexpr const char* PROPERTYNAME_NAME = "name";
constexpr const char* PROPERTYNAME_VENDOR = "vendor";
constexpr const char* PROPERTYNAME_VERSIONCODE = "versionCode";
constexpr const char* PROPERTYNAME_VERSIONNAME = "versionName";
constexpr const char* PROPERTYNAME_MINCOMPATIBLEVERSIONCODE = "minCompatibleVersionCode";
constexpr const char* PROPERTYNAME_TARGETVERSION = "targetVersion";
constexpr const char* PROPERTYNAME_APPINFO = "appInfo";
constexpr const char* PROPERTYNAME_HAPMODULESINFO = "hapModulesInfo";
constexpr const char* PROPERTYNAME_REQPERMISSIONDETAILS = "reqPermissionDetails";
constexpr const char* PROPERTYNAME_PERMISSIONGRANTSTATES = "permissionGrantStates";
constexpr const char* PROPERTYNAME_SIGNATUREINFO = "signatureInfo";
constexpr const char* PROPERTYNAME_INSTALLTIME = "installTime";
constexpr const char* PROPERTYNAME_UPDATETIME = "updateTime";
constexpr const char* PROPERTYNAME_FIRSTINSTALLTIME = "firstInstallTime";
constexpr const char* PROPERTYNAME_ROUTERMAP = "routerMap";
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
constexpr const char* PROPERTYNAME_READPERMISSION = "readPermission";
constexpr const char* PROPERTYNAME_WRITEPERMISSION = "writePermission";
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
constexpr const char* PROPERTYNAME_EXTENSIONABILITYTYPE = "extensionAbilityType";
constexpr const char* PROPERTYNAME_EXTENSIONABILITYTYPENAME = "extensionAbilityTypeName";
constexpr const char* PROPERTYNAME_ID = "id";
constexpr const char* PROPERTYNAME_APPID = "appId";
constexpr const char* PROPERTYNAME_FINGERPRINT = "fingerprint";
constexpr const char* PROPERTYNAME_APPIDENTIFIER = "appIdentifier";
constexpr const char* PROPERTYNAME_CERTIFICATE = "certificate";
constexpr const char* PROPERTYNAME_PAGESOURCEFILE = "pageSourceFile";
constexpr const char* PROPERTYNAME_BUILDFUNCTION = "buildFunction";
constexpr const char* PROPERTYNAME_CUSTOMDATA = "customData";
constexpr const char* PROPERTYNAME_DATA = "data";
constexpr const char* PROPERTYNAME_REASON = "reason";
constexpr const char* PROPERTYNAME_REASONID = "reasonId";
constexpr const char* PROPERTYNAME_USEDSCENE = "usedScene";
constexpr const char* PROPERTYNAME_WHEN = "when";
constexpr const char* PROPERTYNAME_ABILITIES = "abilities";
constexpr const char* PROPERTYNAME_MAINELEMENTNAME = "mainElementName";
constexpr const char* PROPERTYNAME_ABILITIESINFO = "abilitiesInfo";
constexpr const char* PROPERTYNAME_EXTENSIONABILITIESINFO = "extensionAbilitiesInfo";
constexpr const char* PROPERTYNAME_INSTALLATIONFREE = "installationFree";
constexpr const char* PROPERTYNAME_HASHVALUE = "hashValue";
constexpr const char* PROPERTYNAME_DEPENDENCIES = "dependencies";
constexpr const char* PROPERTYNAME_PRELOADS = "preloads";
constexpr const char* PROPERTYNAME_FILECONTEXTMENUCONFIG = "fileContextMenuConfig";
constexpr const char* PROPERTYNAME_DEVICEID = "deviceId";
constexpr const char* PROPERTYNAME_ABILITYNAME = "abilityName";
constexpr const char* PROPERTYNAME_SHORTNAME = "shortName";
constexpr const char* PROPERTYNAME_EXTRA = "extra";
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

constexpr const char* PATH_PREFIX = "/data/app/el1/bundle/public";
constexpr const char* CODE_PATH_PREFIX = "/data/storage/el1/bundle/";
} // namespace

std::string CommonFunAni::AniStrToString(ani_env* env, ani_string aniStr)
{
    if (env == nullptr) {
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
    ani_size retSize;
    status = env->String_GetUTF8(aniStr, buffer.data(), buffer.size(), &retSize);
    if (status != ANI_OK || retSize < 0) {
        APP_LOGE("String_GetUTF8SubString failed %{public}d", status);
        return "";
    }

    buffer.resize(retSize);
    return buffer;
}

ani_class CommonFunAni::CreateClassByName(ani_env* env, const std::string& className)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = nullptr;
    ani_status status = env->FindClass(className.c_str(), &cls);
    if (status != ANI_OK) {
        APP_LOGE("FindClass failed %{public}d", status);
        return nullptr;
    }
    return cls;
}

ani_object CommonFunAni::CreateNewObjectByClass(ani_env* env, ani_class cls)
{
    RETURN_NULL_IF_NULL(env);

    ani_method method = nullptr;
    ani_status status = env->Class_FindMethod(cls, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        APP_LOGE("Class_FindMethod failed %{public}d", status);
        return nullptr;
    }

    ani_object object = nullptr;
    status = env->Object_New(cls, method, &object);
    if (status != ANI_OK) {
        APP_LOGE("Object_New failed %{public}d", status);
        return nullptr;
    }
    return object;
}

ani_object CommonFunAni::ConvertBundleInfo(ani_env* env, const BundleInfo& bundleInfo, int32_t flags)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_BUNDLEINFO);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleInfo.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // vendor: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleInfo.vendor, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VENDOR, string));

    // versionCode: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VERSIONCODE, bundleInfo.versionCode));

    // versionName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleInfo.versionName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VERSIONNAME, string));

    // minCompatibleVersionCode: number
    RETURN_NULL_IF_FALSE(
        CallSetter(env, cls, object, PROPERTYNAME_MINCOMPATIBLEVERSIONCODE, bundleInfo.minCompatibleVersionCode));

    // targetVersion: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_TARGETVERSION, bundleInfo.targetVersion));

    // appInfo: ApplicationInfo
    if ((static_cast<uint32_t>(flags) & static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)) ==
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)) {
        ani_object aObject = ConvertApplicationInfo(env, bundleInfo.applicationInfo);
        RETURN_NULL_IF_NULL(aObject);
        RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPINFO, aObject));
    } else {
        RETURN_NULL_IF_FALSE(CallSetterNull(env, cls, object, PROPERTYNAME_APPINFO));
    }

    // hapModulesInfo: Array<HapModuleInfo>
    ani_object aHapModuleInfosObject = ConvertAniArray(env, bundleInfo.hapModuleInfos, ConvertHapModuleInfo);
    RETURN_NULL_IF_NULL(aHapModuleInfosObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_HAPMODULESINFO, aHapModuleInfosObject));

    // reqPermissionDetails: Array<ReqPermissionDetail>
    ani_object aPermissionArrayObject = ConvertAniArray(env, bundleInfo.reqPermissionDetails, ConvertRequestPermission);
    RETURN_NULL_IF_NULL(aPermissionArrayObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_REQPERMISSIONDETAILS, aPermissionArrayObject));

    // permissionGrantStates: Array<bundleManager.PermissionGrantState>
    ani_object aPermissionGrantStates = ConvertAniArrayEnum(
        env, bundleInfo.reqPermissionStates, EnumUtils::EnumNativeToETS_BundleManager_PermissionGrantState);
    RETURN_NULL_IF_NULL(aPermissionGrantStates);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PERMISSIONGRANTSTATES, aPermissionGrantStates));

    // signatureInfo: SignatureInfo
    if ((static_cast<uint32_t>(flags) & static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO)) ==
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO)) {
        ani_object aniSignatureInfoObj = ConvertSignatureInfo(env, bundleInfo.signatureInfo);
        RETURN_NULL_IF_NULL(aniSignatureInfoObj);
        RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_SIGNATUREINFO, aniSignatureInfoObj));
    } else {
        RETURN_NULL_IF_FALSE(CallSetterNull(env, cls, object, PROPERTYNAME_SIGNATUREINFO));
    }

    // installTime: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_INSTALLTIME, bundleInfo.installTime));

    // updateTime: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_UPDATETIME, bundleInfo.updateTime));

    // routerMap: Array<RouterItem>
    ani_object aRouterMapObject = ConvertAniArray(env, bundleInfo.routerArray, ConvertRouterItem);
    RETURN_NULL_IF_NULL(aRouterMapObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ROUTERMAP, aRouterMapObject));

    // appIndex: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, bundleInfo.appIndex));

    // firstInstallTime?: number
    RETURN_NULL_IF_FALSE(
        CallSetterOptional(env, cls, object, PROPERTYNAME_FIRSTINSTALLTIME, bundleInfo.firstInstallTime));

    return object;
}

ani_object CommonFunAni::ConvertMetadata(ani_env* env, const Metadata& metadata)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_METADATA);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, metadata.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // value: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, metadata.value, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VALUE, string));

    // resource: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, metadata.resource, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_RESOURCE, string));

    // valueId?: number
    RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_VALUEID, metadata.valueId));

    return object;
}

ani_object CommonFunAni::ConvertMultiAppMode(ani_env* env, const MultiAppModeData& multiAppMode)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_MULTIAPPMODE);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    // maxCount: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MAXCOUNT, multiAppMode.maxCount));

    // multiAppModeType: bundleManager.MultiAppModeType
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MULTIAPPMODETYPE,
        EnumUtils::EnumNativeToETS_BundleManager_MultiAppModeType(
            env, static_cast<int32_t>(multiAppMode.multiAppModeType))));

    return object;
}

ani_object CommonFunAni::ConvertModuleMetaInfosItem(
    ani_env* env, const std::pair<std::string, std::vector<Metadata>>& item)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_MODULEMETADATA);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // moduleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, item.first, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string));

    // metadata: Array<Metadata>
    ani_object aMetadataObject = ConvertAniArray(env, item.second, ConvertMetadata);
    RETURN_NULL_IF_NULL(aMetadataObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_METADATA, aMetadataObject));

    return object;
}

ani_object CommonFunAni::ConvertApplicationInfo(ani_env* env, const ApplicationInfo& appInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_APPLICATIONINFO);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // description: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.description, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTION, string));

    // descriptionId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONID, appInfo.descriptionId));

    // enabled: boolean
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ENABLED, BoolToAniBoolean(appInfo.enabled)));

    // label: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.label, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABEL, string));

    // labelId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABELID, appInfo.labelId));

    // icon: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.iconPath, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICON, string));

    // iconId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICONID, appInfo.iconId));

    // process: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.process, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PROCESS, string));

    // permissions: Array<string>
    ani_ref aPermissions = ConvertAniArrayString(env, appInfo.permissions);
    RETURN_NULL_IF_NULL(aPermissions);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PERMISSIONS, aPermissions));

    // codePath: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.codePath, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_CODEPATH, string));

    // metadataArray: Array<ModuleMetadata>
    ani_object aMetadataArrayObject = ConvertAniArray(env, appInfo.metadata, ConvertModuleMetaInfosItem);
    RETURN_NULL_IF_NULL(aMetadataArrayObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_METADATAARRAY, aMetadataArrayObject));

    // removable: boolean
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_REMOVABLE, BoolToAniBoolean(appInfo.removable)));

    // accessTokenId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ACCESSTOKENID, appInfo.accessTokenId));

    // uid: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_UID, appInfo.uid));

    // iconResource: Resource
    ani_object aIconResource = ConvertResource(env, appInfo.iconResource);
    RETURN_NULL_IF_NULL(aIconResource);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICONRESOURCE, aIconResource));

    // labelResource: Resource
    ani_object aLabelResource = ConvertResource(env, appInfo.labelResource);
    RETURN_NULL_IF_NULL(aLabelResource);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABELRESOURCE, aLabelResource));

    // descriptionResource: Resource
    ani_object aDescriptionResource = ConvertResource(env, appInfo.descriptionResource);
    RETURN_NULL_IF_NULL(aDescriptionResource);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONRESOURCE, aDescriptionResource));

    // appDistributionType: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.appDistributionType, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPDISTRIBUTIONTYPE, string));

    // appProvisionType: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.appProvisionType, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPPROVISIONTYPE, string));

    // systemApp: boolean
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_SYSTEMAPP, BoolToAniBoolean(appInfo.isSystemApp)));

    // bundleType: bundleManager.BundleType
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLETYPE,
        EnumUtils::EnumNativeToETS_BundleManager_BundleType(env, static_cast<int32_t>(appInfo.bundleType))));

    // debug: boolean
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DEBUG, BoolToAniBoolean(appInfo.debug)));

    // dataUnclearable: boolean
    RETURN_NULL_IF_FALSE(
        CallSetter(env, cls, object, PROPERTYNAME_DATAUNCLEARABLE, BoolToAniBoolean(!appInfo.userDataClearable)));

    // nativeLibraryPath: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.nativeLibraryPath, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NATIVELIBRARYPATH, string));

    // multiAppMode: MultiAppMode
    ani_object aniMultiAppModeObj = ConvertMultiAppMode(env, appInfo.multiAppMode);
    RETURN_NULL_IF_NULL(aniMultiAppModeObj);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MULTIAPPMODE, aniMultiAppModeObj));

    // appIndex: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, appInfo.appIndex));

    // installSource: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.installSource, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_INSTALLSOURCE, string));

    // releaseType: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, appInfo.apiReleaseType, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_RELEASETYPE, string));

    // cloudFileSyncEnabled: boolean
    RETURN_NULL_IF_FALSE(CallSetter(
        env, cls, object, PROPERTYNAME_CLOUDFILESYNCENABLED, BoolToAniBoolean(appInfo.cloudFileSyncEnabled)));

    // flags?: number
    RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_FLAGS, appInfo.flags));

    return object;
}

ani_object CommonFunAni::ConvertAbilityInfo(ani_env* env, const AbilityInfo& abilityInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_ABILITYINFO);
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

    // labelId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABELID, abilityInfo.labelId));

    // description: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.description, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTION, string));

    // descriptionId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONID, abilityInfo.descriptionId));

    // icon: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.iconPath, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICON, string));

    // iconId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICONID, abilityInfo.iconId));

    // process: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.process, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PROCESS, string));

    // exported: boolean
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_EXPORTED, BoolToAniBoolean(abilityInfo.visible)));

    // orientation: bundleManager.DisplayOrientation
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ORIENTATION,
        EnumUtils::EnumNativeToETS_BundleManager_DisplayOrientation(
            env, static_cast<int32_t>(abilityInfo.orientation))));

    // launchType: bundleManager.LaunchType
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LAUNCHTYPE,
        EnumUtils::EnumNativeToETS_BundleManager_LaunchType(env, static_cast<int32_t>(abilityInfo.launchMode))));

    // permissions: Array<string>
    ani_ref aPermissions = ConvertAniArrayString(env, abilityInfo.permissions);
    RETURN_NULL_IF_NULL(aPermissions);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PERMISSIONS, aPermissions));

    // deviceTypes: Array<string>
    ani_ref aDeviceTypes = ConvertAniArrayString(env, abilityInfo.deviceTypes);
    RETURN_NULL_IF_NULL(aDeviceTypes);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DEVICETYPES, aDeviceTypes));

    // applicationInfo: ApplicationInfo
    ani_object aObject = ConvertApplicationInfo(env, abilityInfo.applicationInfo);
    RETURN_NULL_IF_NULL(aObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPLICATIONINFO, aObject));

    // metadata: Array<Metadata>
    ani_object aMetadataObject = ConvertAniArray(env, abilityInfo.metadata, ConvertMetadata);
    RETURN_NULL_IF_NULL(aMetadataObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_METADATA, aMetadataObject));

    // enabled: boolean
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ENABLED, BoolToAniBoolean(abilityInfo.enabled)));

    // supportWindowModes: Array<bundleManager.SupportWindowMode>
    ani_object aSupportWindowModes =
        ConvertAniArrayEnum(env, abilityInfo.windowModes, EnumUtils::EnumNativeToETS_BundleManager_SupportWindowMode);
    RETURN_NULL_IF_NULL(aSupportWindowModes);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_SUPPORTWINDOWMODES, aSupportWindowModes));

    // windowSize: WindowSize
    ani_object aniWindowSizeObj = ConvertWindowSize(env, abilityInfo);
    RETURN_NULL_IF_NULL(aniWindowSizeObj);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_WINDOWSIZE, aniWindowSizeObj));

    // excludeFromDock: boolean
    RETURN_NULL_IF_FALSE(
        CallSetter(env, cls, object, PROPERTYNAME_EXCLUDEFROMDOCK, BoolToAniBoolean(abilityInfo.excludeFromDock)));

    // skills: Array<Skill>
    ani_object aSkillsObject = ConvertAniArray(env, abilityInfo.skills, ConvertAbilitySkill);
    RETURN_NULL_IF_NULL(aSkillsObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_SKILLS, aSkillsObject));

    // appIndex: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, abilityInfo.appIndex));

    // orientationId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ORIENTATIONID, abilityInfo.orientationId));

    return object;
}

ani_object CommonFunAni::ConvertWindowSize(ani_env* env, const AbilityInfo& abilityInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_WINDOWSIZE);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    // maxWindowRatio: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MAXWINDOWRATIO, abilityInfo.maxWindowRatio));

    // minWindowRatio: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MINWINDOWRATIO, abilityInfo.minWindowRatio));

    // maxWindowWidth: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MAXWINDOWWIDTH, abilityInfo.maxWindowWidth));

    // minWindowWidth: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MINWINDOWWIDTH, abilityInfo.minWindowWidth));

    // maxWindowHeight: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MAXWINDOWHEIGHT, abilityInfo.maxWindowHeight));

    // minWindowHeight: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MINWINDOWHEIGHT, abilityInfo.minWindowHeight));

    return object;
}

ani_object CommonFunAni::ConvertExtensionInfo(ani_env* env, const ExtensionAbilityInfo& extensionInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_EXTENSIONABILITYINFO);
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

    // labelId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABELID, extensionInfo.labelId));

    // descriptionId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONID, extensionInfo.descriptionId));

    // iconId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICONID, extensionInfo.iconId));

    // exported: boolean
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_EXPORTED, extensionInfo.visible));

    // extensionAbilityType: bundleManager.ExtensionAbilityType
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_EXTENSIONABILITYTYPE,
        EnumUtils::EnumNativeToETS_BundleManager_ExtensionAbilityType(env, static_cast<int32_t>(extensionInfo.type))));

    // extensionAbilityTypeName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionInfo.extensionTypeName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_EXTENSIONABILITYTYPENAME, string));

    // permissions: Array<string>
    ani_ref aPermissions = ConvertAniArrayString(env, extensionInfo.permissions);
    RETURN_NULL_IF_NULL(aPermissions);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PERMISSIONS, aPermissions));

    // applicationInfo: ApplicationInfo
    ani_object aObject = ConvertApplicationInfo(env, extensionInfo.applicationInfo);
    RETURN_NULL_IF_NULL(aObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPLICATIONINFO, aObject));

    // metadata: Array<Metadata>
    ani_object aMetadataObject = ConvertAniArray(env, extensionInfo.metadata, ConvertMetadata);
    RETURN_NULL_IF_NULL(aMetadataObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_METADATA, aMetadataObject));

    // enabled: boolean
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ENABLED, extensionInfo.enabled));

    // readPermission: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionInfo.readPermission, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_READPERMISSION, string));

    // writePermission: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, extensionInfo.writePermission, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_WRITEPERMISSION, string));

    // skills: Array<Skill>
    ani_object aSkillsObject = ConvertAniArray(env, extensionInfo.skills, ConvertExtensionAbilitySkill);
    RETURN_NULL_IF_NULL(aSkillsObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_SKILLS, aSkillsObject));

    // appIndex: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, extensionInfo.appIndex));

    return object;
}

ani_object CommonFunAni::ConvertResource(ani_env* env, const Resource& resource)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_RESOURCE);
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

    // id: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ID, resource.id));

    return object;
}

ani_object CommonFunAni::ConvertSignatureInfo(ani_env* env, const SignatureInfo& signatureInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_SIGNATUREINFO);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // appId: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, signatureInfo.appId, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPID, string));

    // fingerprint: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, signatureInfo.fingerprint, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_FINGERPRINT, string));

    // appIdentifier: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, signatureInfo.appIdentifier, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPIDENTIFIER, string));

    // certificate?: string
    if (StringToAniStr(env, signatureInfo.certificate, string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_CERTIFICATE, string));
    }

    return object;
}

ani_object CommonFunAni::ConvertKeyValuePair(
    ani_env* env, const std::pair<std::string, std::string>& item, const char* className)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_DATAITEM);
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

inline ani_object CommonFunAni::ConvertDataItem(ani_env* env, const std::pair<std::string, std::string>& item)
{
    return ConvertKeyValuePair(env, item, CLASSNAME_DATAITEM);
}

ani_object CommonFunAni::ConvertRouterItem(ani_env* env, const RouterItem& routerItem)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_ROUTERITEM);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, routerItem.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // pageSourceFile: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, routerItem.pageSourceFile, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PAGESOURCEFILE, string));

    // buildFunction: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, routerItem.buildFunction, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUILDFUNCTION, string));

    // customData: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, routerItem.customData, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_CUSTOMDATA, string));

    // data: Array<DataItem>
    ani_object aDataArrayObject = ConvertAniArray(env, routerItem.data, ConvertDataItem);
    RETURN_NULL_IF_NULL(aDataArrayObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DATA, aDataArrayObject));

    return object;
}

ani_object CommonFunAni::ConvertRequestPermission(ani_env* env, const RequestPermission& requestPermission)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_PERMISSION);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, requestPermission.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // moduleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, requestPermission.moduleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string));

    // reason: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, requestPermission.reason, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_REASON, string));

    // reasonId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_REASONID, requestPermission.reasonId));

    // usedScene: UsedScene
    ani_object aObject = ConvertRequestPermissionUsedScene(env, requestPermission.usedScene);
    RETURN_NULL_IF_NULL(aObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_USEDSCENE, aObject));

    return object;
}

ani_object CommonFunAni::ConvertRequestPermissionUsedScene(
    ani_env* env, const RequestPermissionUsedScene& requestPermissionUsedScene)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_USEDSCENE);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;
    // when: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, requestPermissionUsedScene.when, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_WHEN, string));

    // abilities: Array<string>
    ani_ref aAbilities = ConvertAniArrayString(env, requestPermissionUsedScene.abilities);
    RETURN_NULL_IF_NULL(aAbilities);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ABILITIES, aAbilities));

    return object;
}

ani_object CommonFunAni::ConvertPreloadItem(ani_env* env, const PreloadItem& preloadItem)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_PRELOADITEM);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // moduleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, preloadItem.moduleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string));

    return object;
}

ani_object CommonFunAni::ConvertDependency(ani_env* env, const Dependency& dependency)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_DEPENDENCY);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;
    // moduleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, dependency.moduleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string));

    // bundleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, dependency.bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // versionCode: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VERSIONCODE, dependency.versionCode));

    return object;
}

ani_object CommonFunAni::ConvertHapModuleInfo(ani_env* env, const HapModuleInfo& hapModuleInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_HAPMODULEINFO);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapModuleInfo.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // icon: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapModuleInfo.iconPath, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICON, string));

    // iconId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICONID, hapModuleInfo.iconId));

    // label: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapModuleInfo.label, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABEL, string));

    // labelId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABELID, hapModuleInfo.labelId));

    // description: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapModuleInfo.description, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTION, string));

    // descriptionId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONID, hapModuleInfo.descriptionId));

    // mainElementName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapModuleInfo.mainElementName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MAINELEMENTNAME, string));

    // abilitiesInfo: Array<AbilityInfo>
    ani_object aAbilityInfoObject = ConvertAniArray(env, hapModuleInfo.abilityInfos, ConvertAbilityInfo);
    RETURN_NULL_IF_NULL(aAbilityInfoObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ABILITIESINFO, aAbilityInfoObject));

    // extensionAbilitiesInfo: Array<ExtensionAbilityInfo>
    ani_object aExtensionAbilityInfoObject = ConvertAniArray(env, hapModuleInfo.extensionInfos, ConvertExtensionInfo);
    RETURN_NULL_IF_NULL(aExtensionAbilityInfoObject);
    RETURN_NULL_IF_FALSE(
        CallSetter(env, cls, object, PROPERTYNAME_EXTENSIONABILITIESINFO, aExtensionAbilityInfoObject));

    // metadata: Array<Metadata>
    ani_object aMetadataObject = ConvertAniArray(env, hapModuleInfo.metadata, ConvertMetadata);
    RETURN_NULL_IF_NULL(aMetadataObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_METADATA, aMetadataObject));

    // deviceTypes: Array<string>
    ani_ref aDeviceTypes = ConvertAniArrayString(env, hapModuleInfo.deviceTypes);
    RETURN_NULL_IF_NULL(aDeviceTypes);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DEVICETYPES, aDeviceTypes));

    // installationFree: boolean
    RETURN_NULL_IF_FALSE(
        CallSetter(env, cls, object, PROPERTYNAME_INSTALLATIONFREE, BoolToAniBoolean(hapModuleInfo.installationFree)));

    // hashValue: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapModuleInfo.hashValue, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_HASHVALUE, string));

    // type: bundleManager.ModuleType
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_TYPE,
        EnumUtils::EnumNativeToETS_BundleManager_ModuleType(env, static_cast<int32_t>(hapModuleInfo.moduleType))));

    // dependencies: Array<Dependency>
    ani_object aDependenciesObject = ConvertAniArray(env, hapModuleInfo.dependencies, ConvertDependency);
    RETURN_NULL_IF_NULL(aDependenciesObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DEPENDENCIES, aDependenciesObject));

    // preloads: Array<PreloadItem>
    ani_object aPreloadsObject = ConvertAniArray(env, hapModuleInfo.preloads, ConvertPreloadItem);
    RETURN_NULL_IF_NULL(aPreloadsObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PRELOADS, aPreloadsObject));

    // fileContextMenuConfig: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapModuleInfo.fileContextMenu, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_FILECONTEXTMENUCONFIG, string));

    // routerMap: Array<RouterItem>
    ani_object aRouterMapObject = ConvertAniArray(env, hapModuleInfo.routerArray, ConvertRouterItem);
    RETURN_NULL_IF_NULL(aRouterMapObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ROUTERMAP, aRouterMapObject));

    // nativeLibraryPath: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, hapModuleInfo.nativeLibraryPath, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NATIVELIBRARYPATH, string));

    // codePath: string
    std::string codePath = hapModuleInfo.hapPath;
    size_t result = hapModuleInfo.hapPath.find(PATH_PREFIX);
    if (result != std::string::npos) {
        size_t pos = hapModuleInfo.hapPath.find_last_of('/');
        codePath = CODE_PATH_PREFIX;
        if (pos != std::string::npos && pos != hapModuleInfo.hapPath.size() - 1) {
            codePath.append(hapModuleInfo.hapPath.substr(pos + 1));
        }
    }
    RETURN_NULL_IF_FALSE(StringToAniStr(env, codePath, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_CODEPATH, string));

    return object;
}

ani_object CommonFunAni::ConvertElementName(ani_env* env, const ElementName& elementName)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_ELEMENTNAME);
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

ani_object CommonFunAni::ConvertCustomizeData(ani_env* env, const CustomizeData& customizeData)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_CUSTOMIZEDATA);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, customizeData.name, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_NAME, string));

    // value: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, customizeData.value, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_VALUE, string));

    // extra: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, customizeData.extra, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_EXTRA, string));

    return object;
}

ani_object CommonFunAni::ConvertAbilitySkillUriInner(ani_env* env, const SkillUri& skillUri, bool isExtension)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_SKILLURI);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // scheme: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, skillUri.scheme, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_SCHEME, string));

    // host: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, skillUri.host, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_HOST, string));

    // port: number
    int32_t nPort = 0;
    if (!skillUri.port.empty()) {
        auto [ptr, ec] = std::from_chars(skillUri.port.data(), skillUri.port.data() + skillUri.port.size(), nPort);
        if (ec != std::errc() || ptr != skillUri.port.data() + skillUri.port.size()) {
            APP_LOGE("skillUri port convert failed");
            return nullptr;
        }
    }
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PORT, nPort));

    // path: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, skillUri.path, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PATH, string));

    // pathStartWith: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, skillUri.pathStartWith, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PATHSTARTWITH, string));

    // pathRegex: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, skillUri.pathRegex, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PATHREGEX, string));

    // type: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, skillUri.type, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_TYPE, string));

    // utd: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, skillUri.utd, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_UTD, string));

    // maxFileSupported: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_MAXFILESUPPORTED, skillUri.maxFileSupported));

    if (!isExtension) {
        // linkFeature: string
        RETURN_NULL_IF_FALSE(StringToAniStr(env, skillUri.linkFeature, string));
        RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LINKFEATURE, string));
    }

    return object;
}

ani_object CommonFunAni::ConvertAbilitySkillInner(ani_env* env, const Skill& skill, bool isExtension)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_SKILL);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    // actions: Array<string>
    ani_ref aActions = ConvertAniArrayString(env, skill.actions);
    RETURN_NULL_IF_NULL(aActions);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ACTIONS, aActions));

    // entities: Array<string>
    ani_ref aEntities = ConvertAniArrayString(env, skill.entities);
    RETURN_NULL_IF_NULL(aEntities);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ENTITIES, aEntities));

    // uris: Array<SkillUri>
    ani_object aSkillUri =
        ConvertAniArray(env, skill.uris, isExtension ? ConvertExtensionAbilitySkillUri : ConvertAbilitySkillUri);
    RETURN_NULL_IF_NULL(aSkillUri);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_URIS, aSkillUri));

    if (!isExtension) {
        // domainVerify: boolean
        RETURN_NULL_IF_FALSE(
            CallSetter(env, cls, object, PROPERTYNAME_DOMAINVERIFY, BoolToAniBoolean(skill.domainVerify)));
    }

    return object;
}

ani_object CommonFunAni::ConvertAppCloneIdentity(
    ani_env* env, const std::string& bundleName, const int32_t appIndex)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_APPCLONEIDENTITY);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // name: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // appIndex: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, appIndex));

    return object;
}

ani_object CommonFunAni::ConvertBundleResourceInfo(ani_env* env, const BundleResourceInfo& bundleResInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_BUNDLERESINFO);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // bundleName: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleResInfo.bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // icon: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleResInfo.icon, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICON, string));

    // label: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, bundleResInfo.label, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABEL, string));

    // drawableDecriptor: drawableDecriptor

    // appIndex: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, bundleResInfo.appIndex));

    return object;
}

ani_object CommonFunAni::ConvertShortcutInfo(ani_env* env, const ShortcutInfo& shortcutInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_SHORTCUTINFO);
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

    // iconId?: number
    RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_ICONID, shortcutInfo.iconId));

    // label?: string
    if (StringToAniStr(env, shortcutInfo.label, string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_LABEL, string));
    }

    // labelId?: number
    RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_LABELID, shortcutInfo.labelId));

    // wants?: Array<ShortcutWant>
    ani_object aShortcutWantObject = ConvertAniArray(env, shortcutInfo.intents, ConvertShortcutIntent);
    RETURN_NULL_IF_NULL(aShortcutWantObject);
    RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_WANTS, aShortcutWantObject));

    // appIndex: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, shortcutInfo.appIndex));

    // sourceType: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_SOURCETYPE, shortcutInfo.sourceType));

    return object;
}

ani_object CommonFunAni::ConvertShortcutIntent(ani_env* env, const ShortcutIntent& shortcutIntent)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CreateClassByName(env, CLASSNAME_SHORTCUTWANT);
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
    return ConvertKeyValuePair(env, item, CLASSNAME_SHORTCUT_PARAMETERITEM);
}


ani_object CommonFunAni::ConvertLauncherAbilityInfo(ani_env* env, const LauncherAbilityInfo &launcherAbility)
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

    // labelId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABELID, launcherAbility.labelId));

    // iconId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ICONID, launcherAbility.iconId));

    // userId: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_USERID, launcherAbility.userId));

    // installTime: number
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_INSTALLTIME, launcherAbility.installTime));

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

    // iconId?: number
    if (CallGetterOptional(env, object, PROPERTYNAME_ICONID, &uintValue)) {
        shortcutInfo.iconId = uintValue;
    }

    // label?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_LABEL, &string)) {
        shortcutInfo.label = AniStrToString(env, string);
    }

    // labelId?: number
    if (CallGetterOptional(env, object, PROPERTYNAME_LABELID, &intValue)) {
        shortcutInfo.labelId = intValue;
    }

    // wants?: Array<ShortcutWant>
    ani_array array = nullptr;
    if (CallGetterOptional(env, object, PROPERTYNAME_WANTS, &array)) {
        RETURN_FALSE_IF_FALSE(ParseAniArray(env, array, shortcutInfo.intents, ParseShortcutIntent));
    }

    // appIndex: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_APPINDEX, &intValue));
    shortcutInfo.appIndex = intValue;

    // sourceType: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_SOURCETYPE, &intValue));
    shortcutInfo.sourceType = intValue;

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

bool CommonFunAni::ParseKeyValuePairWithName(ani_env* env, ani_object object,
    std::pair<std::string, std::string>& pair, const char* keyName, const char* valueName)
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
    // pgoParams?
    if (CallGetterOptional(env, object, PROPERTYNAME_PGOPARAMS, &array)) {
        std::vector<std::pair<std::string, std::string>> pgoParams;
        RETURN_FALSE_IF_FALSE(ParseAniArray(env, array, pgoParams, ParsePgoParams));
        for (const auto& parameter : pgoParams) {
            installParam.pgoParams[parameter.first] = parameter.second;
        }
    }

    ani_int intValue = 0;
    // userId?: number
    if (CallGetterOptional(env, object, PROPERTYNAME_USERID, &intValue)) {
        installParam.userId = intValue;
    } else {
        APP_LOGW("Parse userId failed,using default value");
    }
    // installFlag?: number
    if (CallGetterOptional(env, object, PROPERTYNAME_INSTALLFLAG, &intValue)) {
        if ((intValue != static_cast<int32_t>(OHOS::AppExecFwk::InstallFlag::NORMAL)) &&
            (intValue != static_cast<int32_t>(OHOS::AppExecFwk::InstallFlag::REPLACE_EXISTING)) &&
            (intValue != static_cast<int32_t>(OHOS::AppExecFwk::InstallFlag::FREE_INSTALL))) {
            APP_LOGE("invalid installFlag param");
            return false;
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

    // crowdtestDeadline?: number
    if (CallGetterOptional(env, object, PROPERTYNAME_CROWDTESTDEADLINE, &intValue)) {
        installParam.crowdtestDeadline = intValue;
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
    // versionCode?: number
    if (CallGetterOptional(env, object, PROPERTYNAME_VERSIONCODE, &intValue)) {
        uninstallParam.versionCode = intValue;
    } else {
        APP_LOGW("Parse crowdtestDeadline failed,using default value");
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

    // valueId?: number
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
    uint32_t uintValue = 0;

    // bundleName: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_BUNDLENAME, &string));
    resource.bundleName = AniStrToString(env, string);

    // moduleName: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MODULENAME, &string));
    resource.moduleName = AniStrToString(env, string);

    // id: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ID, &uintValue));
    resource.id = uintValue;

    return true;
}

bool CommonFunAni::ParseMultiAppMode(ani_env* env, ani_object object, MultiAppModeData& multiAppMode)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_enum_item enumItem = nullptr;
    ani_int intValue = 0;

    // maxCount: number
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
    ani_object arrayObject = nullptr;
    ani_object aniObject = nullptr;
    ani_enum_item enumItem = nullptr;
    ani_int intValue = 0;
    ani_boolean boolValue = ANI_FALSE;
    uint32_t uintValue = 0;

    // name: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_NAME, &string));
    appInfo.name = AniStrToString(env, string);

    // description: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_DESCRIPTION, &string));
    appInfo.description = AniStrToString(env, string);

    // descriptionId: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_DESCRIPTIONID, &uintValue));
    appInfo.descriptionId = uintValue;

    // enabled: boolean
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ENABLED, &boolValue));
    appInfo.enabled = AniBooleanToBool(boolValue);

    // label: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_LABEL, &string));
    appInfo.label = AniStrToString(env, string);

    // labelId: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_LABELID, &uintValue));
    appInfo.labelId = uintValue;

    // icon: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ICON, &string));
    appInfo.iconPath = AniStrToString(env, string);

    // iconId: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ICONID, &uintValue));
    appInfo.iconId = uintValue;

    // process: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_PROCESS, &string));
    appInfo.process = AniStrToString(env, string);

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

    // accessTokenId: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ACCESSTOKENID, &uintValue));
    appInfo.accessTokenId = uintValue;

    // uid: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_UID, &intValue));
    appInfo.uid = intValue;

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

    // appIndex: number
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

    // flags?: number
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

    // maxWindowRatio: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MAXWINDOWRATIO, &doubleValue));
    abilityInfo.maxWindowRatio = doubleValue;

    // minWindowRatio: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MINWINDOWRATIO, &doubleValue));
    abilityInfo.minWindowRatio = doubleValue;

    // maxWindowWidth: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MAXWINDOWWIDTH, &uintValue));
    abilityInfo.maxWindowWidth = uintValue;

    // minWindowWidth: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MINWINDOWWIDTH, &uintValue));
    abilityInfo.minWindowWidth = uintValue;

    // maxWindowHeight: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_MAXWINDOWHEIGHT, &uintValue));
    abilityInfo.maxWindowHeight = uintValue;

    // minWindowHeight: number
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

    // port: number
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

    // maxFileSupported: number
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
    RETURN_FALSE_IF_FALSE(ParseAniArray(env, arrayObject, skill.uris,
        isExtension? ParseExtensionAbilitySkillUri: ParseAbilitySkillUri));

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
    ani_object arrayObject = nullptr;
    ani_object aniObject = nullptr;
    ani_enum_item enumItem = nullptr;
    ani_int intValue = 0;
    ani_boolean boolValue = ANI_FALSE;
    uint32_t uintValue = 0;

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

    // labelId: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_LABELID, &uintValue));
    abilityInfo.labelId = uintValue;

    // description: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_DESCRIPTION, &string));
    abilityInfo.description = AniStrToString(env, string);

    // descriptionId: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_DESCRIPTIONID, &uintValue));
    abilityInfo.descriptionId = uintValue;

    // icon: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ICON, &string));
    abilityInfo.iconPath = AniStrToString(env, string);

    // iconId: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ICONID, &uintValue));
    abilityInfo.iconId = uintValue;

    // process: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_PROCESS, &string));
    abilityInfo.process = AniStrToString(env, string);

    // exported: boolean
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_EXPORTED, &boolValue));
    abilityInfo.visible = AniBooleanToBool(boolValue);

    // orientation: bundleManager.DisplayOrientation
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ORIENTATION, &enumItem));
    RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, abilityInfo.orientation));

    // launchType: bundleManager.LaunchType
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_LAUNCHTYPE, &enumItem));
    RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, abilityInfo.launchMode));

    // permissions: Array<string>
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_PERMISSIONS, &arrayObject));
    RETURN_FALSE_IF_FALSE(ParseStrArray(env, arrayObject, abilityInfo.permissions));

    // deviceTypes: Array<string>
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_DEVICETYPES, &arrayObject));
    RETURN_FALSE_IF_FALSE(ParseStrArray(env, arrayObject, abilityInfo.deviceTypes));

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

    // appIndex: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_APPINDEX, &intValue));
    abilityInfo.appIndex = intValue;

    // orientationId: number
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_ORIENTATIONID, &uintValue));
    abilityInfo.orientationId = uintValue;

    return true;
}
} // namespace AppExecFwk
} // namespace OHOS