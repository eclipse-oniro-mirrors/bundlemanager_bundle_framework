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

#include "app_log_wrapper.h"
#include "common_fun_ani.h"
#include "enum_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* CLASSNAME_STDSTRING = "Lstd/core/String;";
constexpr const char* CLASSNAME_ABILITYINFO = "LAbilityInfo/AbilityInfoInner;";
constexpr const char* CLASSNAME_EXTENSIONABILITYINFO = "LExtensionAbilityInfo/ExtensionAbilityInfoInner;";
constexpr const char* CLASSNAME_WINDOWSIZE = "LAbilityInfo/WindowSizeInner;";
constexpr const char* CLASSNAME_APPLICATIONINFO = "LApplicationInfo/ApplicationInfoInner;";
constexpr const char* CLASSNAME_MODULEMETADATA = "LApplicationInfo/ModuleMetadataInner;";
constexpr const char* CLASSNAME_MULTIAPPMODE = "LApplicationInfo/MultiAppModeInner;";
constexpr const char* CLASSNAME_BUNDLEINFO = "LBundleInfo/BundleInfoInner;";
constexpr const char* CLASSNAME_PERMISSION = "LBundleInfo/ReqPermissionDetailInner;";
constexpr const char* CLASSNAME_USEDSCENE = "LBundleInfo/UsedSceneInner;";
constexpr const char* CLASSNAME_SIGNATUREINFO = "LBundleInfo/SignatureInfoInner;";
constexpr const char* CLASSNAME_METADATA = "LMetadata/MetadataInner;";
constexpr const char* CLASSNAME_RESOURCE = "Lresource/ResourceInner;";
constexpr const char* CLASSNAME_ROUTERITEM = "LHapModuleInfo/RouterItemInner;";
constexpr const char* CLASSNAME_PRELOADITEM = "LHapModuleInfo/PreloadItemInner;";
constexpr const char* CLASSNAME_DEPENDENCY = "LHapModuleInfo/DependencyInner;";
constexpr const char* CLASSNAME_HAPMODULEINFO = "LHapModuleInfo/HapModuleInfoInner;";
constexpr const char* CLASSNAME_DATAITEM = "LHapModuleInfo/DataItemInner;";
constexpr const char* CLASSNAME_ELEMENTNAME = "LElementName/ElementNameInner;";
constexpr const char* CLASSNAME_CUSTOMIZEDATA = "LcustomizeData/CustomizeDataInner;";
constexpr const char* CLASSNAME_SKILL = "LSkill/SkillInner;";
constexpr const char* CLASSNAME_SKILLURI = "LSkill/SkillUriInner;";
constexpr const char* CLASSNAME_BUNDLERESINFO = "LbundleManager/BundleResourceInfo/BundleResourceInfoInner;";
constexpr const char* CLASSNAME_SHORTCUTINFO = "LShortcutInfo/ShortcutInfoInner;";
constexpr const char* CLASSNAME_SHORTCUTWANT = "LShortcutInfo/ShortcutWantInner;";
constexpr const char* CLASSNAME_SHORTCUT_PARAMETERITEM = "LShortcutInfo/ParameterItemInner;";

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
constexpr const char* PROPERTYNAME_ROUTERMAP = "routerMap";
constexpr const char* PROPERTYNAME_APPINDEX = "appIndex";
constexpr const char* PROPERTYNAME_KEY = "key";
constexpr const char* PROPERTYNAME_VALUE = "value";
constexpr const char* PROPERTYNAME_RESOURCE = "resource";
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

ani_ref CommonFunAni::ConvertAniArrayString(ani_env* env, const std::vector<std::string>& cArray)
{
    RETURN_NULL_IF_NULL(env);

    ani_size length = cArray.size();
    ani_array_ref aArrayRef = nullptr;
    ani_class aStringcls = nullptr;
    ani_status status = env->FindClass(CLASSNAME_STDSTRING, &aStringcls);
    if (status != ANI_OK) {
        APP_LOGE("FindClass failed %{public}d", status);
        return nullptr;
    }
    status = env->Array_New_Ref(aStringcls, length, nullptr, &aArrayRef);
    if (status != ANI_OK) {
        APP_LOGE("Array_New_Ref failed %{public}d", status);
        return nullptr;
    }
    ani_string aString = nullptr;
    for (ani_size i = 0; i < length; ++i) {
        if (StringToAniStr(env, cArray[i], aString)) {
            env->Array_Set_Ref(aArrayRef, i, aString);
        } else {
            return nullptr;
        }
    }
    return aArrayRef;
}

ani_object CommonFunAni::ConvertBundleInfo(ani_env* env, const BundleInfo& bundleInfo)
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
    ani_object aObject = ConvertApplicationInfo(env, bundleInfo.applicationInfo);
    RETURN_NULL_IF_NULL(aObject);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPINFO, aObject));

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
    ani_object aniSignatureInfoObj = ConvertSignatureInfo(env, bundleInfo.signatureInfo);
    RETURN_NULL_IF_NULL(aniSignatureInfoObj);
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_SIGNATUREINFO, aniSignatureInfoObj));

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

    // type: bundleManager.AbilityType
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_TYPE,
        EnumUtils::EnumNativeToETS_BundleManager_AbilityType(env, static_cast<int32_t>(abilityInfo.type))));

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

    // readPermission: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.readPermission, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_READPERMISSION, string));

    // writePermission: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.writePermission, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_WRITEPERMISSION, string));

    // uri: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, abilityInfo.uri, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_URI, string));

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

    // labelId: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_LABELID, extensionInfo.labelId));

    // descriptionId: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONID, extensionInfo.descriptionId));

    // iconId: int
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

    // appIndex: int
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

    // id: int
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

    // certificate: string
    RETURN_NULL_IF_FALSE(StringToAniStr(env, signatureInfo.certificate, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_CERTIFICATE, string));

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

    // reasonId: int
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

    // versionCode: int
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

    // port: int
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_PORT, std::stoi(skillUri.port)));

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

    // maxFileSupported: int
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

    // id: string;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, shortcutInfo.id, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_ID, string));

    // bundleName: string;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, shortcutInfo.bundleName, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // moduleName?: string;
    if (StringToAniStr(env, shortcutInfo.moduleName, string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_MODULENAME, string));
    }

    // hostAbility?: string;
    if (StringToAniStr(env, shortcutInfo.hostAbility, string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_HOSTABILITY, string));
    }

    // icon?: string;
    if (StringToAniStr(env, shortcutInfo.icon, string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_ICON, string));
    }

    // iconId?: int;
    RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_ICONID, shortcutInfo.iconId));

    // label?: string;
    if (StringToAniStr(env, shortcutInfo.label, string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_LABEL, string));
    }

    // labelId?: int;
    RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_LABELID, shortcutInfo.labelId));

    // wants?: Array<ShortcutWant>;
    ani_object aShortcutWantObject = ConvertAniArray(env, shortcutInfo.intents, ConvertShortcutIntent);
    RETURN_NULL_IF_NULL(aShortcutWantObject);
    RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_WANTS, aShortcutWantObject));

    // appIndex: int;
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, shortcutInfo.appIndex));

    // sourceType: int;
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

    // targetBundle: string;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, shortcutIntent.targetBundle, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_TARGETBUNDLE, string));

    // targetModule?: string;
    if (StringToAniStr(env, shortcutIntent.targetModule, string)) {
        RETURN_NULL_IF_FALSE(CallSetterOptional(env, cls, object, PROPERTYNAME_TARGETMODULE, string));
    }

    // targetAbility: string;
    RETURN_NULL_IF_FALSE(StringToAniStr(env, shortcutIntent.targetClass, string));
    RETURN_NULL_IF_FALSE(CallSetter(env, cls, object, PROPERTYNAME_TARGETABILITY, string));

    // parameters?: Array<ParameterItem>;
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

bool CommonFunAni::ParseShortcutInfo(ani_env* env, ani_object object, ShortcutInfo& shortcutInfo)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_string string = nullptr;
    ani_int intValue = 0;

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

    // iconId?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_ICONID, &intValue)) {
        shortcutInfo.iconId = intValue;
    }

    // label?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_LABEL, &string)) {
        shortcutInfo.label = AniStrToString(env, string);
    }

    // labelId?: int
    if (CallGetterOptional(env, object, PROPERTYNAME_LABELID, &intValue)) {
        shortcutInfo.labelId = intValue;
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

bool CommonFunAni::ParseKeyValuePair(ani_env* env, ani_object object, std::pair<std::string, std::string>& pair)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_string string = nullptr;

    // key: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_KEY, &string));
    pair.first = AniStrToString(env, string);

    // value: string
    RETURN_FALSE_IF_FALSE(CallGetter(env, object, PROPERTYNAME_VALUE, &string));
    pair.second = AniStrToString(env, string);

    return true;
}
} // namespace AppExecFwk
} // namespace OHOS