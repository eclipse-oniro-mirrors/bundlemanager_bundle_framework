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
    ani_size substrSize = 0;
    ani_status status = env->String_GetUTF8Size(aniStr, &substrSize);
    if (status != ANI_OK) {
        APP_LOGE("String_GetUTF8Size failed");
        return "";
    }

    std::vector<char> buffer(substrSize + 1);
    ani_size nameSize;
    status = env->String_GetUTF8(aniStr, buffer.data(), buffer.size(), &nameSize);
    if (status != ANI_OK) {
        APP_LOGE("String_GetUTF8SubString failed");
        return "";
    }

    return std::string(buffer.data(), nameSize);
}

ani_class CommonFunAni::CreateClassByName(ani_env* env, const std::string& className)
{
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

ani_ref CommonFunAni::ConvertAniArrayByClass(
    ani_env* env, const std::string& className, const std::vector<ani_object>& aArray)
{
    ani_size length = aArray.size();
    ani_array_ref aArrayRef = nullptr;
    ani_class aCls = nullptr;
    ani_status status = env->FindClass(className.c_str(), &aCls);
    if (status != ANI_OK) {
        APP_LOGE("FindClass failed %{public}d", status);
        return nullptr;
    }
    status = env->Array_New_Ref(aCls, length, nullptr, &aArrayRef);
    if (status != ANI_OK) {
        APP_LOGE("Array_New_Ref failed %{public}d", status);
        return nullptr;
    }
    for (ani_size i = 0; i < length; ++i) {
        env->Array_Set_Ref(aArrayRef, i, aArray[i]);
    }
    return aArrayRef;
}

ani_ref CommonFunAni::ConvertAniArrayString(ani_env* env, const std::vector<std::string>& cArray)
{
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
        }
    }
    return aArrayRef;
}

ani_object CommonFunAni::ConvertBundleInfo(ani_env* env, const BundleInfo& bundleInfo)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_BUNDLEINFO);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertBundleInfo failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // name: string
    if (StringToAniStr(env, bundleInfo.name, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_NAME, string);
    }

    // vendor: string
    if (StringToAniStr(env, bundleInfo.vendor, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_VENDOR, string);
    }

    // versionCode: number
    CallSetter(env, cls, object, PROPERTYNAME_VERSIONCODE, bundleInfo.versionCode);

    // versionName: string
    if (StringToAniStr(env, bundleInfo.versionName, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_VERSIONNAME, string);
    }

    // minCompatibleVersionCode: number
    CallSetter(env, cls, object, PROPERTYNAME_MINCOMPATIBLEVERSIONCODE, bundleInfo.minCompatibleVersionCode);

    // targetVersion: number
    CallSetter(env, cls, object, PROPERTYNAME_TARGETVERSION, bundleInfo.targetVersion);

    // appInfo: ApplicationInfo
    ani_object aObject = ConvertApplicationInfo(env, bundleInfo.applicationInfo);
    CallSetter(env, cls, object, PROPERTYNAME_APPINFO, aObject);

    // hapModulesInfo: Array<HapModuleInfo>
    std::vector<ani_object> aHapModuleInfos;
    for (size_t i = 0; i < bundleInfo.hapModuleInfos.size(); ++i) {
        aHapModuleInfos.emplace_back(ConvertHapModuleInfo(env, bundleInfo.hapModuleInfos[i]));
    }
    ani_ref aHapModuleInfosRef = ConvertAniArrayByClass(env, CLASSNAME_HAPMODULEINFO, aHapModuleInfos);
    CallSetter(env, cls, object, PROPERTYNAME_HAPMODULESINFO, aHapModuleInfosRef);

    // reqPermissionDetails: Array<ReqPermissionDetail>
    std::vector<ani_object> aArray;
    for (size_t i = 0; i < bundleInfo.reqPermissionDetails.size(); ++i) {
        aArray.emplace_back(ConvertRequestPermission(env, bundleInfo.reqPermissionDetails[i]));
    }
    ani_ref aPermissionArrayRef = ConvertAniArrayByClass(env, CLASSNAME_PERMISSION, aArray);
    CallSetter(env, cls, object, PROPERTYNAME_REQPERMISSIONDETAILS, aPermissionArrayRef);

    // permissionGrantStates: Array<bundleManager.PermissionGrantState>
    ani_array_int aPermissionGrantStates = ConvertAniArrayEnum(
        env, bundleInfo.reqPermissionStates, EnumUtils::NativeValueToIndex_BundleManager_PermissionGrantState);
    CallSetter(env, cls, object, PROPERTYNAME_PERMISSIONGRANTSTATES, aPermissionGrantStates);

    // signatureInfo: SignatureInfo
    ani_object aniSignatureInfoObj = ConvertSignatureInfo(env, bundleInfo.signatureInfo);
    CallSetter(env, cls, object, PROPERTYNAME_SIGNATUREINFO, aniSignatureInfoObj);

    // installTime: number
    CallSetter(env, cls, object, PROPERTYNAME_INSTALLTIME, bundleInfo.installTime);

    // updateTime: number
    CallSetter(env, cls, object, PROPERTYNAME_UPDATETIME, bundleInfo.updateTime);

    // routerMap: Array<RouterItem>
    std::vector<ani_object> aRouterMap;
    for (size_t i = 0; i < bundleInfo.routerArray.size(); ++i) {
        aRouterMap.emplace_back(ConvertRouterItem(env, bundleInfo.routerArray[i]));
    }
    ani_ref aRouterMapRef = ConvertAniArrayByClass(env, CLASSNAME_ROUTERITEM, aRouterMap);
    CallSetter(env, cls, object, PROPERTYNAME_ROUTERMAP, aRouterMapRef);

    // appIndex: number
    CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, bundleInfo.appIndex);

    return object;
}

ani_object CommonFunAni::ConvertMetadata(ani_env* env, const Metadata& metadata)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_METADATA);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertMetadata failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // name: string
    if (StringToAniStr(env, metadata.name, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_NAME, string);
    }

    // value: string
    if (StringToAniStr(env, metadata.value, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_VALUE, string);
    }

    // resource: string
    if (StringToAniStr(env, metadata.resource, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_RESOURCE, string);
    }

    return object;
}

ani_object CommonFunAni::ConvertMultiAppMode(ani_env* env, const MultiAppModeData& multiAppMode)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_MULTIAPPMODE);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertMultiAppMode failed.");
        return nullptr;
    }

    // maxCount: number
    CallSetter(env, cls, object, PROPERTYNAME_MAXCOUNT, multiAppMode.maxCount);

    // multiAppModeType: bundleManager.MultiAppModeType
    CallSetter(env, cls, object, PROPERTYNAME_MULTIAPPMODETYPE,
        EnumUtils::NativeValueToIndex_BundleManager_MultiAppModeType(
            static_cast<int32_t>(multiAppMode.multiAppModeType)));

    return object;
}

ani_ref CommonFunAni::ConvertModuleMetaInfos(ani_env* env, const std::map<std::string, std::vector<Metadata>>& metadata)
{
    std::vector<ani_object> aDataItem;
    size_t index = 0;
    for (const auto& item : metadata) {
        ani_string string = nullptr;
        ani_class cls = CreateClassByName(env, CLASSNAME_MODULEMETADATA);
        ani_object object = CreateNewObjectByClass(env, cls);
        if (cls == nullptr || object == nullptr) {
            APP_LOGE("ConvertModuleMetaInfos failed.");
            return nullptr;
        }
        // moduleName: string
        if (StringToAniStr(env, item.first, string)) {
            CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string);
        }

        // metadata: Array<Metadata>
        std::vector<ani_object> aMetadata;
        for (size_t i = 0; i < item.second.size(); ++i) {
            aMetadata.emplace_back(ConvertMetadata(env, item.second[i]));
        }
        ani_ref aMetadataRef = ConvertAniArrayByClass(env, CLASSNAME_MODULEMETADATA, aMetadata);
        CallSetter(env, cls, object, PROPERTYNAME_METADATA, aMetadataRef);
        aDataItem.emplace_back(object);
        index++;
    }
    ani_ref aDataItemRef = ConvertAniArrayByClass(env, CLASSNAME_DATAITEM, aDataItem);

    return aDataItemRef;
}

ani_object CommonFunAni::ConvertApplicationInfo(ani_env* env, const ApplicationInfo& appInfo)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_APPLICATIONINFO);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertApplicationInfo failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // name: string
    if (StringToAniStr(env, appInfo.name, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_NAME, string);
    }

    // description: string
    if (StringToAniStr(env, appInfo.description, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTION, string);
    }

    // descriptionId: number
    CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONID, appInfo.descriptionId);

    // enabled: boolean
    CallSetter(env, cls, object, PROPERTYNAME_ENABLED, BoolToAniBoolean(appInfo.enabled));

    // label: string
    if (StringToAniStr(env, appInfo.label, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_LABEL, string);
    }

    // labelId: number
    CallSetter(env, cls, object, PROPERTYNAME_LABELID, appInfo.labelId);

    // icon: string
    if (StringToAniStr(env, appInfo.iconPath, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_ICON, string);
    }

    // iconId: number
    CallSetter(env, cls, object, PROPERTYNAME_ICONID, appInfo.iconId);

    // process: string
    if (StringToAniStr(env, appInfo.process, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_PROCESS, string);
    }

    // permissions: Array<string>
    ani_ref aPermissions = ConvertAniArrayString(env, appInfo.permissions);
    CallSetter(env, cls, object, PROPERTYNAME_PERMISSIONS, aPermissions);

    // codePath: string
    if (StringToAniStr(env, appInfo.codePath, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_CODEPATH, string);
    }

    // metadataArray: Array<ModuleMetadata>
    ani_ref aMetadataArrayRef = ConvertModuleMetaInfos(env, appInfo.metadata);
    CallSetter(env, cls, object, PROPERTYNAME_METADATAARRAY, aMetadataArrayRef);

    // removable: boolean
    CallSetter(env, cls, object, PROPERTYNAME_REMOVABLE, BoolToAniBoolean(appInfo.removable));

    // accessTokenId: number
    CallSetter(env, cls, object, PROPERTYNAME_ACCESSTOKENID, appInfo.accessTokenId);

    // uid: number
    CallSetter(env, cls, object, PROPERTYNAME_UID, appInfo.uid);

    // iconResource: Resource
    ani_object aIconResource = ConvertResource(env, appInfo.iconResource);
    CallSetter(env, cls, object, PROPERTYNAME_ICONRESOURCE, aIconResource);

    // labelResource: Resource
    ani_object aLabelResource = ConvertResource(env, appInfo.labelResource);
    CallSetter(env, cls, object, PROPERTYNAME_LABELRESOURCE, aLabelResource);

    // descriptionResource: Resource
    ani_object aDescriptionResource = ConvertResource(env, appInfo.descriptionResource);
    CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONRESOURCE, aDescriptionResource);

    // appDistributionType: string
    if (StringToAniStr(env, appInfo.appDistributionType, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_APPDISTRIBUTIONTYPE, string);
    }

    // appProvisionType: string
    if (StringToAniStr(env, appInfo.appProvisionType, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_APPPROVISIONTYPE, string);
    }

    // systemApp: boolean
    CallSetter(env, cls, object, PROPERTYNAME_SYSTEMAPP, BoolToAniBoolean(appInfo.isSystemApp));

    // bundleType: bundleManager.BundleType
    CallSetter(env, cls, object, PROPERTYNAME_BUNDLETYPE,
        EnumUtils::NativeValueToIndex_BundleManager_BundleType(static_cast<int32_t>(appInfo.bundleType)));

    // debug: boolean
    CallSetter(env, cls, object, PROPERTYNAME_DEBUG, BoolToAniBoolean(appInfo.debug));

    // dataUnclearable: boolean
    CallSetter(env, cls, object, PROPERTYNAME_DATAUNCLEARABLE, BoolToAniBoolean(!appInfo.userDataClearable));

    // nativeLibraryPath: string
    if (StringToAniStr(env, appInfo.nativeLibraryPath, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_NATIVELIBRARYPATH, string);
    }

    // multiAppMode: MultiAppMode
    ani_object aniMultiAppModeObj = ConvertMultiAppMode(env, appInfo.multiAppMode);
    CallSetter(env, cls, object, PROPERTYNAME_MULTIAPPMODE, aniMultiAppModeObj);

    // appIndex: number
    CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, appInfo.appIndex);

    // installSource: string
    if (StringToAniStr(env, appInfo.installSource, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_INSTALLSOURCE, string);
    }

    // releaseType: string
    if (StringToAniStr(env, appInfo.apiReleaseType, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_RELEASETYPE, string);
    }

    // cloudFileSyncEnabled: boolean
    CallSetter(env, cls, object, PROPERTYNAME_CLOUDFILESYNCENABLED, BoolToAniBoolean(appInfo.cloudFileSyncEnabled));

    // flags?: number
    CallSetterOptional(env, cls, object, PROPERTYNAME_FLAGS, appInfo.flags);

    return object;
}

ani_object CommonFunAni::ConvertAbilityInfo(ani_env* env, const AbilityInfo& abilityInfo)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_ABILITYINFO);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertAbilityInfo failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // bundleName: string
    if (StringToAniStr(env, abilityInfo.bundleName, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string);
    }

    // moduleName: string
    if (StringToAniStr(env, abilityInfo.moduleName, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string);
    }

    // name: string
    if (StringToAniStr(env, abilityInfo.name, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_NAME, string);
    }

    // label: string
    if (StringToAniStr(env, abilityInfo.label, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_LABEL, string);
    }

    // labelId: number
    CallSetter(env, cls, object, PROPERTYNAME_LABELID, abilityInfo.labelId);

    // description: string
    if (StringToAniStr(env, abilityInfo.description, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTION, string);
    }

    // descriptionId: number
    CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONID, abilityInfo.descriptionId);

    // icon: string
    if (StringToAniStr(env, abilityInfo.iconPath, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_ICON, string);
    }

    // iconId: number
    CallSetter(env, cls, object, PROPERTYNAME_ICONID, abilityInfo.iconId);

    // process: string
    if (StringToAniStr(env, abilityInfo.process, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_PROCESS, string);
    }

    // exported: boolean
    CallSetter(env, cls, object, PROPERTYNAME_EXPORTED, BoolToAniBoolean(abilityInfo.visible));

    // type: bundleManager.AbilityType
    CallSetter(env, cls, object, PROPERTYNAME_TYPE,
        EnumUtils::NativeValueToIndex_BundleManager_AbilityType(static_cast<int32_t>(abilityInfo.type)));

    // orientation: bundleManager.DisplayOrientation
    CallSetter(env, cls, object, PROPERTYNAME_ORIENTATION,
        EnumUtils::NativeValueToIndex_BundleManager_DisplayOrientation(static_cast<int32_t>(abilityInfo.orientation)));

    // launchType: bundleManager.LaunchType
    CallSetter(env, cls, object, PROPERTYNAME_LAUNCHTYPE,
        EnumUtils::NativeValueToIndex_BundleManager_LaunchType(static_cast<int32_t>(abilityInfo.launchMode)));

    // permissions: Array<string>
    ani_ref aPermissions = ConvertAniArrayString(env, abilityInfo.permissions);
    CallSetter(env, cls, object, PROPERTYNAME_PERMISSIONS, aPermissions);

    // readPermission: string
    if (StringToAniStr(env, abilityInfo.readPermission, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_READPERMISSION, string);
    }

    // writePermission: string
    if (StringToAniStr(env, abilityInfo.writePermission, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_WRITEPERMISSION, string);
    }

    // uri: string
    if (StringToAniStr(env, abilityInfo.uri, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_URI, string);
    }

    // deviceTypes: Array<string>
    ani_ref aDeviceTypes = ConvertAniArrayString(env, abilityInfo.deviceTypes);
    CallSetter(env, cls, object, PROPERTYNAME_DEVICETYPES, aDeviceTypes);

    // applicationInfo: ApplicationInfo
    ani_object aObject = ConvertApplicationInfo(env, abilityInfo.applicationInfo);
    CallSetter(env, cls, object, PROPERTYNAME_APPLICATIONINFO, aObject);

    // metadata: Array<Metadata>
    std::vector<ani_object> aMetadata;
    for (size_t i = 0; i < abilityInfo.metadata.size(); ++i) {
        aMetadata.emplace_back(ConvertMetadata(env, abilityInfo.metadata[i]));
    }
    ani_ref aMetadataRef = ConvertAniArrayByClass(env, CLASSNAME_METADATA, aMetadata);
    CallSetter(env, cls, object, PROPERTYNAME_METADATA, aMetadataRef);

    // enabled: boolean
    CallSetter(env, cls, object, PROPERTYNAME_ENABLED, BoolToAniBoolean(abilityInfo.enabled));

    // supportWindowModes: Array<bundleManager.SupportWindowMode>
    ani_array_int aSupportWindowModes = ConvertAniArrayEnum(
        env, abilityInfo.windowModes, EnumUtils::NativeValueToIndex_BundleManager_SupportWindowMode);
    CallSetter(env, cls, object, PROPERTYNAME_SUPPORTWINDOWMODES, aSupportWindowModes);

    // windowSize: WindowSize
    ani_object aniWindowSizeObj = ConvertWindowSize(env, abilityInfo);
    CallSetter(env, cls, object, PROPERTYNAME_WINDOWSIZE, aniWindowSizeObj);

    // excludeFromDock: boolean
    CallSetter(env, cls, object, PROPERTYNAME_EXCLUDEFROMDOCK, BoolToAniBoolean(abilityInfo.excludeFromDock));

    // skills: Array<Skill>
    std::vector<ani_object> aSkills;
    for (size_t i = 0; i < abilityInfo.skills.size(); ++i) {
        aSkills.emplace_back(ConvertAbilitySkill(env, abilityInfo.skills[i], false));
    }
    ani_ref aSkillsRef = ConvertAniArrayByClass(env, CLASSNAME_SKILL, aSkills);
    CallSetter(env, cls, object, PROPERTYNAME_SKILLS, aSkillsRef);

    // appIndex: number
    CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, abilityInfo.appIndex);

    // orientationId: number
    CallSetter(env, cls, object, PROPERTYNAME_ORIENTATIONID, abilityInfo.orientationId);

    return object;
}

ani_object CommonFunAni::ConvertWindowSize(ani_env* env, const AbilityInfo& abilityInfo)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_WINDOWSIZE);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertWindowSize failed.");
        return nullptr;
    }

    // maxWindowRatio: number
    CallSetter(env, cls, object, PROPERTYNAME_MAXWINDOWRATIO, abilityInfo.maxWindowRatio);

    // minWindowRatio: number
    CallSetter(env, cls, object, PROPERTYNAME_MINWINDOWRATIO, abilityInfo.minWindowRatio);

    // maxWindowWidth: number
    CallSetter(env, cls, object, PROPERTYNAME_MAXWINDOWWIDTH, abilityInfo.maxWindowWidth);

    // minWindowWidth: number
    CallSetter(env, cls, object, PROPERTYNAME_MINWINDOWWIDTH, abilityInfo.minWindowWidth);

    // maxWindowHeight: number
    CallSetter(env, cls, object, PROPERTYNAME_MAXWINDOWHEIGHT, abilityInfo.maxWindowHeight);

    // minWindowHeight: number
    CallSetter(env, cls, object, PROPERTYNAME_MINWINDOWHEIGHT, abilityInfo.minWindowHeight);

    return object;
}

ani_object CommonFunAni::ConvertExtensionInfo(ani_env* env, const ExtensionAbilityInfo& extensionInfo)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_EXTENSIONABILITYINFO);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertExtensionInfo failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // bundleName: string
    if (StringToAniStr(env, extensionInfo.bundleName, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string);
    }

    // moduleName: string
    if (StringToAniStr(env, extensionInfo.moduleName, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string);
    }

    // name: string
    if (StringToAniStr(env, extensionInfo.name, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_NAME, string);
    }

    // labelId: int
    CallSetter(env, cls, object, PROPERTYNAME_LABELID, extensionInfo.labelId);

    // descriptionId: int
    CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONID, extensionInfo.descriptionId);

    // iconId: int
    CallSetter(env, cls, object, PROPERTYNAME_ICONID, extensionInfo.iconId);

    // exported: boolean
    CallSetter(env, cls, object, PROPERTYNAME_EXPORTED, extensionInfo.visible);

    // extensionAbilityType: bundleManager.ExtensionAbilityType
    CallSetter(env, cls, object, PROPERTYNAME_EXTENSIONABILITYTYPE,
        EnumUtils::NativeValueToIndex_BundleManager_ExtensionAbilityType(static_cast<int32_t>(extensionInfo.type)));

    // extensionAbilityTypeName: string
    if (StringToAniStr(env, extensionInfo.extensionTypeName, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_EXTENSIONABILITYTYPENAME, string);
    }

    // permissions: Array<string>
    ani_ref aPermissions = ConvertAniArrayString(env, extensionInfo.permissions);
    CallSetter(env, cls, object, PROPERTYNAME_PERMISSIONS, aPermissions);

    // applicationInfo: ApplicationInfo
    ani_object aObject = ConvertApplicationInfo(env, extensionInfo.applicationInfo);
    CallSetter(env, cls, object, PROPERTYNAME_APPLICATIONINFO, aObject);

    // metadata: Array<Metadata>
    std::vector<ani_object> aMetadata;
    for (size_t i = 0; i < extensionInfo.metadata.size(); ++i) {
        aMetadata.emplace_back(ConvertMetadata(env, extensionInfo.metadata[i]));
    }
    ani_ref aMetadataRef = ConvertAniArrayByClass(env, CLASSNAME_METADATA, aMetadata);
    CallSetter(env, cls, object, PROPERTYNAME_METADATA, aMetadataRef);

    // enabled: boolean
    CallSetter(env, cls, object, PROPERTYNAME_ENABLED, extensionInfo.enabled);

    // readPermission: string
    if (StringToAniStr(env, extensionInfo.readPermission, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_READPERMISSION, string);
    }

    // writePermission: string
    if (StringToAniStr(env, extensionInfo.writePermission, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_WRITEPERMISSION, string);
    }

    // skills: Array<Skill>
    std::vector<ani_object> aSkills;
    for (size_t i = 0; i < extensionInfo.skills.size(); ++i) {
        aSkills.emplace_back(ConvertAbilitySkill(env, extensionInfo.skills[i], true));
    }
    ani_ref aSkillsRef = ConvertAniArrayByClass(env, CLASSNAME_SKILL, aSkills);
    CallSetter(env, cls, object, PROPERTYNAME_SKILLS, aSkillsRef);

    // appIndex: int
    CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, extensionInfo.appIndex);

    return object;
}

ani_object CommonFunAni::ConvertResource(ani_env* env, const Resource& resource)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_RESOURCE);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertResource failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // bundleName: string
    if (StringToAniStr(env, resource.bundleName, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string);
    }

    // moduleName: string
    if (StringToAniStr(env, resource.moduleName, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string);
    }

    // id: int
    CallSetter(env, cls, object, PROPERTYNAME_ID, resource.id);

    return object;
}

ani_object CommonFunAni::ConvertSignatureInfo(ani_env* env, const SignatureInfo& signatureInfo)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_SIGNATUREINFO);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertSignatureInfo failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // appId: string
    if (StringToAniStr(env, signatureInfo.appId, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_APPID, string);
    }

    // fingerprint: string
    if (StringToAniStr(env, signatureInfo.fingerprint, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_FINGERPRINT, string);
    }

    // appIdentifier: string
    if (StringToAniStr(env, signatureInfo.appIdentifier, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_APPIDENTIFIER, string);
    }

    // certificate: string
    if (StringToAniStr(env, signatureInfo.certificate, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_CERTIFICATE, string);
    }

    return object;
}

ani_object CommonFunAni::ConvertDataItem(ani_env* env, const std::string& key, const std::string& value)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_DATAITEM);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertDataItem failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // key: string
    if (StringToAniStr(env, key, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_KEY, string);
    }

    // value: string
    if (StringToAniStr(env, value, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_VALUE, string);
    }

    return object;
}

ani_object CommonFunAni::ConvertRouterItem(ani_env* env, const RouterItem& routerItem)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_ROUTERITEM);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertRouterItem failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // name: string
    if (StringToAniStr(env, routerItem.name, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_NAME, string);
    }

    // pageSourceFile: string
    if (StringToAniStr(env, routerItem.pageSourceFile, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_PAGESOURCEFILE, string);
    }

    // buildFunction: string
    if (StringToAniStr(env, routerItem.buildFunction, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_BUILDFUNCTION, string);
    }

    // customData: string
    if (StringToAniStr(env, routerItem.customData, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_CUSTOMDATA, string);
    }

    // data: Array<DataItem>
    ani_ref aDataArrayRef = ConvertRouterDataInfos(env, routerItem.data);
    CallSetter(env, cls, object, PROPERTYNAME_DATA, aDataArrayRef);

    return object;
}

ani_ref CommonFunAni::ConvertRouterDataInfos(ani_env* env, const std::map<std::string, std::string>& data)
{
    std::vector<ani_object> aDataItem;
    size_t index = 0;
    for (const auto& item : data) {
        ani_string string = nullptr;
        ani_class cls = CreateClassByName(env, CLASSNAME_DATAITEM);
        ani_object object = CreateNewObjectByClass(env, cls);
        if (cls == nullptr || object == nullptr) {
            APP_LOGE("ConvertRouterDataInfos failed.");
            return nullptr;
        }
        // name: key
        if (StringToAniStr(env, item.first, string)) {
            CallSetter(env, cls, object, PROPERTYNAME_KEY, string);
        }

        // name: value
        if (StringToAniStr(env, item.second, string)) {
            CallSetter(env, cls, object, PROPERTYNAME_VALUE, string);
        }
        aDataItem[index] = object;
        index++;
    }
    ani_ref aDataItemRef = ConvertAniArrayByClass(env, CLASSNAME_DATAITEM, aDataItem);

    return aDataItemRef;
}

ani_object CommonFunAni::ConvertRequestPermission(ani_env* env, const RequestPermission& requestPermission)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_PERMISSION);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertRequestPermission failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // name: string
    if (StringToAniStr(env, requestPermission.name, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_NAME, string);
    }

    // moduleName: string
    if (StringToAniStr(env, requestPermission.moduleName, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string);
    }

    // reason: string
    if (StringToAniStr(env, requestPermission.reason, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_REASON, string);
    }

    // reasonId: int
    CallSetter(env, cls, object, PROPERTYNAME_REASONID, requestPermission.reasonId);

    // usedScene: UsedScene
    ani_object aObject = ConvertRequestPermissionUsedScene(env, requestPermission.usedScene);
    CallSetter(env, cls, object, PROPERTYNAME_USEDSCENE, aObject);

    return object;
}

ani_object CommonFunAni::ConvertRequestPermissionUsedScene(
    ani_env* env, const RequestPermissionUsedScene& requestPermissionUsedScene)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_USEDSCENE);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertRequestPermissionUsedScene failed.");
        return nullptr;
    }

    ani_string string = nullptr;
    // when: string
    if (StringToAniStr(env, requestPermissionUsedScene.when, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_WHEN, string);
    }

    // abilities: Array<string>
    ani_ref aAbilities = ConvertAniArrayString(env, requestPermissionUsedScene.abilities);
    CallSetter(env, cls, object, PROPERTYNAME_ABILITIES, aAbilities);

    return object;
}

ani_object CommonFunAni::ConvertPreloadItem(ani_env* env, const PreloadItem& preloadItem)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_PRELOADITEM);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertPreloadItem failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // moduleName: string
    if (StringToAniStr(env, preloadItem.moduleName, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string);
    }

    return object;
}

ani_object CommonFunAni::ConvertDependency(ani_env* env, const Dependency& dependency)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_DEPENDENCY);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertDependency failed.");
        return nullptr;
    }

    ani_string string = nullptr;
    // moduleName: string
    if (StringToAniStr(env, dependency.moduleName, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string);
    }

    // bundleName: string
    if (StringToAniStr(env, dependency.bundleName, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string);
    }

    // versionCode: int
    CallSetter(env, cls, object, PROPERTYNAME_VERSIONCODE, dependency.versionCode);

    return object;
}

ani_object CommonFunAni::ConvertHapModuleInfo(ani_env* env, const HapModuleInfo& hapModuleInfo)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_HAPMODULEINFO);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertHapModuleInfo failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // name: string
    if (StringToAniStr(env, hapModuleInfo.name, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_NAME, string);
    }

    // icon: string
    if (StringToAniStr(env, hapModuleInfo.iconPath, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_ICON, string);
    }

    // iconId: number
    CallSetter(env, cls, object, PROPERTYNAME_ICONID, hapModuleInfo.iconId);

    // label: string
    if (StringToAniStr(env, hapModuleInfo.label, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_LABEL, string);
    }

    // labelId: number
    CallSetter(env, cls, object, PROPERTYNAME_LABELID, hapModuleInfo.labelId);

    // description: string
    if (StringToAniStr(env, hapModuleInfo.description, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTION, string);
    }

    // descriptionId: number
    CallSetter(env, cls, object, PROPERTYNAME_DESCRIPTIONID, hapModuleInfo.descriptionId);

    // mainElementName: string
    if (StringToAniStr(env, hapModuleInfo.mainElementName, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_MAINELEMENTNAME, string);
    }

    // abilitiesInfo: Array<AbilityInfo>
    std::vector<ani_object> aAbilityInfo;
    for (size_t i = 0; i < hapModuleInfo.abilityInfos.size(); ++i) {
        aAbilityInfo.emplace_back(ConvertAbilityInfo(env, hapModuleInfo.abilityInfos[i]));
    }
    ani_ref aAbilityInfoRef = ConvertAniArrayByClass(env, CLASSNAME_ABILITYINFO, aAbilityInfo);
    CallSetter(env, cls, object, PROPERTYNAME_ABILITIESINFO, aAbilityInfoRef);

    // extensionAbilitiesInfo: Array<ExtensionAbilityInfo>
    std::vector<ani_object> aExtensionAbilityInfo;
    for (size_t i = 0; i < hapModuleInfo.extensionInfos.size(); ++i) {
        aExtensionAbilityInfo.emplace_back(ConvertExtensionInfo(env, hapModuleInfo.extensionInfos[i]));
    }
    ani_ref aExtensionAbilityInfoRef =
        ConvertAniArrayByClass(env, CLASSNAME_EXTENSIONABILITYINFO, aExtensionAbilityInfo);
    CallSetter(env, cls, object, PROPERTYNAME_EXTENSIONABILITIESINFO, aExtensionAbilityInfoRef);

    // metadata: Array<Metadata>
    std::vector<ani_object> aMetadata;
    for (size_t i = 0; i < hapModuleInfo.metadata.size(); ++i) {
        aMetadata.emplace_back(ConvertMetadata(env, hapModuleInfo.metadata[i]));
    }
    ani_ref aMetadataRef = ConvertAniArrayByClass(env, CLASSNAME_METADATA, aMetadata);
    CallSetter(env, cls, object, PROPERTYNAME_METADATA, aMetadataRef);

    // deviceTypes: Array<string>
    ani_ref aDeviceTypes = ConvertAniArrayString(env, hapModuleInfo.deviceTypes);
    CallSetter(env, cls, object, PROPERTYNAME_DEVICETYPES, aDeviceTypes);

    // installationFree: boolean
    CallSetter(env, cls, object, PROPERTYNAME_INSTALLATIONFREE, BoolToAniBoolean(hapModuleInfo.installationFree));

    // hashValue: string
    if (StringToAniStr(env, hapModuleInfo.hashValue, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_HASHVALUE, string);
    }

    // type: bundleManager.ModuleType
    CallSetter(env, cls, object, PROPERTYNAME_TYPE,
        EnumUtils::NativeValueToIndex_BundleManager_ModuleType(static_cast<int32_t>(hapModuleInfo.moduleType)));

    // dependencies: Array<Dependency>
    std::vector<ani_object> aDependencies;
    for (size_t i = 0; i < hapModuleInfo.dependencies.size(); ++i) {
        aDependencies.emplace_back(ConvertDependency(env, hapModuleInfo.dependencies[i]));
    }
    ani_ref aDependenciesRef = ConvertAniArrayByClass(env, CLASSNAME_DEPENDENCY, aDependencies);
    CallSetter(env, cls, object, PROPERTYNAME_DEPENDENCIES, aDependenciesRef);

    // preloads: Array<PreloadItem>
    std::vector<ani_object> aPreloads;
    for (size_t i = 0; i < hapModuleInfo.preloads.size(); ++i) {
        aPreloads.emplace_back(ConvertPreloadItem(env, hapModuleInfo.preloads[i]));
    }
    ani_ref aPreloadsRef = ConvertAniArrayByClass(env, CLASSNAME_PRELOADITEM, aPreloads);
    CallSetter(env, cls, object, PROPERTYNAME_PRELOADS, aPreloadsRef);

    // fileContextMenuConfig: string
    if (StringToAniStr(env, hapModuleInfo.fileContextMenu, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_FILECONTEXTMENUCONFIG, string);
    }

    // routerMap: Array<RouterItem>
    std::vector<ani_object> aRrouterMap;
    for (size_t i = 0; i < hapModuleInfo.routerArray.size(); ++i) {
        aRrouterMap.emplace_back(ConvertRouterItem(env, hapModuleInfo.routerArray[i]));
    }
    ani_ref aRouterMapRef = ConvertAniArrayByClass(env, CLASSNAME_ROUTERITEM, aRrouterMap);
    CallSetter(env, cls, object, PROPERTYNAME_ROUTERMAP, aRouterMapRef);

    // nativeLibraryPath: string
    if (StringToAniStr(env, hapModuleInfo.nativeLibraryPath, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_NATIVELIBRARYPATH, string);
    }

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
    if (StringToAniStr(env, codePath, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_CODEPATH, string);
    }

    return object;
}

ani_object CommonFunAni::ConvertElementName(ani_env* env, const ElementName& elementName)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_ELEMENTNAME);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertElementName failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // deviceId?: string
    if (StringToAniStr(env, elementName.GetDeviceID(), string)) {
        CallSetterOptional(env, cls, object, PROPERTYNAME_DEVICEID, string);
    }

    // bundleName: string
    if (StringToAniStr(env, elementName.GetBundleName(), string)) {
        CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string);
    }

    // moduleName?: string
    if (StringToAniStr(env, elementName.GetModuleName(), string)) {
        CallSetterOptional(env, cls, object, PROPERTYNAME_MODULENAME, string);
    }

    // abilityName: string
    if (StringToAniStr(env, elementName.GetAbilityName(), string)) {
        CallSetter(env, cls, object, PROPERTYNAME_ABILITYNAME, string);
    }

    // uri?: string
    if (StringToAniStr(env, elementName.GetURI(), string)) {
        CallSetterOptional(env, cls, object, PROPERTYNAME_URI, string);
    }

    // shortName?: string
    if (StringToAniStr(env, "", string)) {
        CallSetterOptional(env, cls, object, PROPERTYNAME_SHORTNAME, string);
    }

    return object;
}

ani_object CommonFunAni::ConvertCustomizeData(ani_env* env, const CustomizeData& customizeData)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_CUSTOMIZEDATA);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertCustomizeData failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // name: string
    if (StringToAniStr(env, customizeData.name, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_NAME, string);
    }

    // value: string
    if (StringToAniStr(env, customizeData.value, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_VALUE, string);
    }

    // extra: string
    if (StringToAniStr(env, customizeData.extra, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_EXTRA, string);
    }

    return object;
}

ani_object CommonFunAni::ConvertAbilitySkillUri(ani_env* env, const SkillUri& skillUri, bool isExtension)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_SKILLURI);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertAbilitySkillUri failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // scheme: string
    if (StringToAniStr(env, skillUri.scheme, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_SCHEME, string);
    }

    // host: string
    if (StringToAniStr(env, skillUri.host, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_HOST, string);
    }

    // port: int
    CallSetter(env, cls, object, PROPERTYNAME_PORT, std::stoi(skillUri.port));

    // path: string
    if (StringToAniStr(env, skillUri.path, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_PATH, string);
    }

    // pathStartWith: string
    if (StringToAniStr(env, skillUri.pathStartWith, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_PATHSTARTWITH, string);
    }

    // pathRegex: string
    if (StringToAniStr(env, skillUri.pathRegex, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_PATHREGEX, string);
    }

    // type: string
    if (StringToAniStr(env, skillUri.type, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_TYPE, string);
    }

    // utd: string
    if (StringToAniStr(env, skillUri.utd, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_UTD, string);
    }

    // maxFileSupported: int
    CallSetter(env, cls, object, PROPERTYNAME_MAXFILESUPPORTED, skillUri.maxFileSupported);

    if (!isExtension) {
        // linkFeature: string
        if (StringToAniStr(env, skillUri.linkFeature, string)) {
            CallSetter(env, cls, object, PROPERTYNAME_LINKFEATURE, string);
        }
    }

    return object;
}

ani_object CommonFunAni::ConvertAbilitySkill(ani_env* env, const Skill& skill, bool isExtension)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_SKILL);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertAbilitySkill failed.");
        return nullptr;
    }

    // actions: Array<string>
    ani_ref aActions = nullptr;
    aActions = ConvertAniArrayString(env, skill.actions);
    CallSetter(env, cls, object, PROPERTYNAME_ACTIONS, aActions);

    // entities: Array<string>
    ani_ref aEntities = nullptr;
    aEntities = ConvertAniArrayString(env, skill.entities);
    CallSetter(env, cls, object, PROPERTYNAME_ENTITIES, aEntities);

    // uris: Array<SkillUri>
    std::vector<ani_object> aArray;
    for (size_t i = 0; i < skill.uris.size(); ++i) {
        aArray.emplace_back(ConvertAbilitySkillUri(env, skill.uris[i], isExtension));
    }
    ani_ref aSkillUri = ConvertAniArrayByClass(env, CLASSNAME_SKILLURI, aArray);
    CallSetter(env, cls, object, PROPERTYNAME_URIS, aSkillUri);

    if (!isExtension) {
        // domainVerify: boolean
        CallSetter(env, cls, object, PROPERTYNAME_DOMAINVERIFY, BoolToAniBoolean(skill.domainVerify));
    }

    return object;
}

ani_object CommonFunAni::ConvertShortcutInfo(ani_env* env, const ShortcutInfo& shortcutInfo)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_SHORTCUTINFO);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertShortcutInfo failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // id: string;
    if (StringToAniStr(env, shortcutInfo.id, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_ID, string);
    }

    // bundleName: string;
    if (StringToAniStr(env, shortcutInfo.bundleName, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string);
    }

    // moduleName?: string;
    if (StringToAniStr(env, shortcutInfo.moduleName, string)) {
        CallSetterOptional(env, cls, object, PROPERTYNAME_MODULENAME, string);
    }

    // hostAbility?: string;
    if (StringToAniStr(env, shortcutInfo.hostAbility, string)) {
        CallSetterOptional(env, cls, object, PROPERTYNAME_HOSTABILITY, string);
    }

    // icon?: string;
    if (StringToAniStr(env, shortcutInfo.icon, string)) {
        CallSetterOptional(env, cls, object, PROPERTYNAME_ICON, string);
    }

    // iconId?: int;
    CallSetterOptional(env, cls, object, PROPERTYNAME_ICONID, shortcutInfo.iconId);

    // label?: string;
    if (StringToAniStr(env, shortcutInfo.label, string)) {
        CallSetterOptional(env, cls, object, PROPERTYNAME_LABEL, string);
    }

    // labelId?: int;
    CallSetterOptional(env, cls, object, PROPERTYNAME_LABELID, shortcutInfo.labelId);

    // wants?: Array<ShortcutWant>;
    std::vector<ani_object> aArray;
    for (size_t i = 0; i < shortcutInfo.intents.size(); ++i) {
        aArray.emplace_back(ConvertShortcutIntent(env, shortcutInfo.intents[i]));
    }
    ani_ref aShortcutWant = ConvertAniArrayByClass(env, CLASSNAME_SHORTCUTWANT, aArray);
    CallSetterOptional(env, cls, object, PROPERTYNAME_WANTS, aShortcutWant);

    // appIndex: int;
    CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, shortcutInfo.appIndex);

    // sourceType: int;
    CallSetter(env, cls, object, PROPERTYNAME_SOURCETYPE, shortcutInfo.sourceType);

    return object;
}

ani_ref CommonFunAni::ConvertShortcutInfos(ani_env* env, const std::vector<ShortcutInfo>& shortcutInfos)
{
    std::vector<ani_object> aArray;
    for (const auto& shortcutInfo : shortcutInfos) {
        aArray.emplace_back(ConvertShortcutInfo(env, shortcutInfo));
    }
    ani_ref aShortcutInfoRef = ConvertAniArrayByClass(env, CLASSNAME_SHORTCUTINFO, aArray);

    return aShortcutInfoRef;
}

ani_object CommonFunAni::ConvertShortcutIntent(ani_env* env, const ShortcutIntent& shortcutIntent)
{
    ani_class cls = CreateClassByName(env, CLASSNAME_SHORTCUTWANT);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertShortcutIntent failed.");
        return nullptr;
    }

    ani_string string = nullptr;

    // targetBundle: string;
    if (StringToAniStr(env, shortcutIntent.targetBundle, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_TARGETBUNDLE, string);
    }

    // targetModule?: string;
    if (StringToAniStr(env, shortcutIntent.targetModule, string)) {
        CallSetterOptional(env, cls, object, PROPERTYNAME_TARGETMODULE, string);
    }

    // targetAbility: string;
    if (StringToAniStr(env, shortcutIntent.targetClass, string)) {
        CallSetter(env, cls, object, PROPERTYNAME_TARGETABILITY, string);
    }

    // parameters?: Array<ParameterItem>;
    ani_ref aParameters =
        ConvertShortcutIntentParameters(env, shortcutIntent.parameters, CLASSNAME_SHORTCUT_PARAMETERITEM);
    CallSetterOptional(env, cls, object, PROPERTYNAME_PARAMETERS, aParameters);

    return object;
}

ani_ref CommonFunAni::ConvertShortcutIntentParameters(
    ani_env* env, const std::map<std::string, std::string>& data, const std::string& className)
{
    std::vector<ani_object> aArray;
    ani_class cls = CreateClassByName(env, className);
    ani_string string = nullptr;

    for (const auto& item : data) {
        ani_object object = CreateNewObjectByClass(env, cls);
        if (cls == nullptr || object == nullptr) {
            APP_LOGE("ConvertShortcutIntentParameters failed.");
            return nullptr;
        }

        // key: string;
        if (StringToAniStr(env, item.first, string)) {
            CallSetter(env, cls, object, PROPERTYNAME_KEY, string);
        }

        // value: string;
        if (StringToAniStr(env, item.second, string)) {
            CallSetter(env, cls, object, PROPERTYNAME_VALUE, string);
        }
        aArray.emplace_back(object);
    }
    ani_ref parametersRef = ConvertAniArrayByClass(env, className, aArray);

    return parametersRef;
}

bool CommonFunAni::ParseShortcutInfo(ani_env* env, ani_object object, ShortcutInfo& shortcutInfo)
{
    ani_string string = nullptr;
    ani_int intValue = 0;

    // id: string
    CallGetter(env, object, PROPERTYNAME_ID, &string);
    shortcutInfo.id = AniStrToString(env, string);

    // bundleName: string
    CallGetter(env, object, PROPERTYNAME_BUNDLENAME, &string);
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
        ParseAniArray(env, array, shortcutInfo.intents, ParseShortcutIntent);
    }

    // appIndex: int
    CallGetter(env, object, PROPERTYNAME_APPINDEX, &intValue);
    shortcutInfo.appIndex = intValue;

    // sourceType: int
    CallGetter(env, object, PROPERTYNAME_SOURCETYPE, &intValue);
    shortcutInfo.sourceType = intValue;

    return true;
}

bool CommonFunAni::ParseShortcutIntent(ani_env* env, ani_object object, ShortcutIntent& shortcutIntent)
{
    ani_string string = nullptr;

    // targetBundle: string
    CallGetter(env, object, PROPERTYNAME_TARGETBUNDLE, &string);
    shortcutIntent.targetBundle = AniStrToString(env, string);

    // targetModule?: string
    if (CallGetterOptional(env, object, PROPERTYNAME_TARGETMODULE, &string)) {
        shortcutIntent.targetModule = AniStrToString(env, string);
    }

    // targetAbility: string
    CallGetter(env, object, PROPERTYNAME_TARGETABILITY, &string);
    shortcutIntent.targetClass = AniStrToString(env, string);

    // parameters?: Array<ParameterItem>
    ani_array array = nullptr;
    if (CallGetterOptional(env, object, PROPERTYNAME_PARAMETERS, &array)) {
        std::vector<std::pair<std::string, std::string>> parameters;
        ParseAniArray(env, array, parameters, ParseKeyValuePair);
        for (const auto& parameter : parameters) {
            shortcutIntent.parameters[parameter.first] = parameter.second;
        }
    }

    return true;
}

bool CommonFunAni::ParseKeyValuePair(ani_env* env, ani_object object, std::pair<std::string, std::string>& pair)
{
    ani_string string = nullptr;

    // key: string
    CallGetter(env, object, PROPERTYNAME_KEY, &string);
    pair.first = AniStrToString(env, string);

    // value: string
    CallGetter(env, object, PROPERTYNAME_VALUE, &string);
    pair.second = AniStrToString(env, string);

    return true;
}
} // namespace AppExecFwk
} // namespace OHOS