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

constexpr const char* PATH_PREFIX = "/data/app/el1/bundle/public";
constexpr const char* CODE_PATH_PREFIX = "/data/storage/el1/bundle/";

#define SETTER_METHOD_NAME(property) "<set>" #property
} // namespace
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
        env->String_NewUTF8(cArray[i].c_str(), cArray[i].size(), &aString);
        env->Array_Set_Ref(aArrayRef, i, aString);
    }
    return aArrayRef;
}

template<typename enumType>
ani_array_int CommonFunAni::ConvertAniArrayEnum(
    ani_env* env, const std::vector<enumType>& cArray, std::function<ani_int(const int32_t)> converter)
{
    ani_size length = cArray.size();
    ani_array_int aArrayEnum = nullptr;
    ani_status status = env->Array_New_Int(length, &aArrayEnum);
    if (status != ANI_OK) {
        APP_LOGE("Array_New_Int failed %{public}d", status);
        return nullptr;
    }
    std::vector<ani_int> buffer(length);
    for (ani_size i = 0; i < length; ++i) {
        buffer[i] = converter(static_cast<int32_t>(cArray[i]));
    }
    env->Array_SetRegion_Int(aArrayEnum, 0, length, &buffer[0]);
    return aArrayEnum;
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
    env->String_NewUTF8(bundleInfo.name.c_str(), bundleInfo.name.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(name), string);

    // vendor: string
    env->String_NewUTF8(bundleInfo.vendor.c_str(), bundleInfo.vendor.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(vendor), string);

    // versionCode: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(versionCode), bundleInfo.versionCode);

    // versionName: string
    env->String_NewUTF8(bundleInfo.versionName.c_str(), bundleInfo.versionName.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(versionName), string);

    // minCompatibleVersionCode: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(minCompatibleVersionCode), bundleInfo.minCompatibleVersionCode);

    // targetVersion: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(targetVersion), bundleInfo.targetVersion);

    // appInfo: ApplicationInfo
    ani_object aObject = ConvertApplicationInfo(env, bundleInfo.applicationInfo);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(appInfo), aObject);

    // hapModulesInfo: Array<HapModuleInfo>
    std::vector<ani_object> aHapModuleInfos;
    for (size_t i = 0; i < bundleInfo.hapModuleInfos.size(); ++i) {
        aHapModuleInfos.emplace_back(ConvertHapModuleInfo(env, bundleInfo.hapModuleInfos[i]));
    }
    ani_ref aHapModuleInfosRef = ConvertAniArrayByClass(env, CLASSNAME_HAPMODULEINFO, aHapModuleInfos);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(hapModulesInfo), aHapModuleInfosRef);

    // reqPermissionDetails: Array<ReqPermissionDetail>
    std::vector<ani_object> aArray;
    for (size_t i = 0; i < bundleInfo.reqPermissionDetails.size(); ++i) {
        aArray.emplace_back(ConvertRequestPermission(env, bundleInfo.reqPermissionDetails[i]));
    }
    ani_ref aPermissionArrayRef = ConvertAniArrayByClass(env, CLASSNAME_PERMISSION, aArray);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(reqPermissionDetails), aPermissionArrayRef);

    // permissionGrantStates: Array<bundleManager.PermissionGrantState>
    ani_array_int aPermissionGrantStates = ConvertAniArrayEnum(
        env, bundleInfo.reqPermissionStates, EnumUtils::NativeValueToIndex_BundleManager_PermissionGrantState);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(permissionGrantStates), aPermissionGrantStates);

    // signatureInfo: SignatureInfo
    ani_object aniSignatureInfoObj = ConvertSignatureInfo(env, bundleInfo.signatureInfo);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(signatureInfo), aniSignatureInfoObj);

    // installTime: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(installTime), bundleInfo.installTime);

    // updateTime: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(updateTime), bundleInfo.updateTime);

    // routerMap: Array<RouterItem>
    std::vector<ani_object> aRouterMap;
    for (size_t i = 0; i < bundleInfo.routerArray.size(); ++i) {
        aRouterMap.emplace_back(ConvertRouterItem(env, bundleInfo.routerArray[i]));
    }
    ani_ref aRouterMapRef = ConvertAniArrayByClass(env, CLASSNAME_ROUTERITEM, aRouterMap);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(routerMap), aRouterMapRef);

    // appIndex: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(appIndex), bundleInfo.appIndex);

    std::cout << "CommonFunAni::ConvertBundleInfo exit" << std::endl;
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
    env->String_NewUTF8(metadata.name.c_str(), metadata.name.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(name), string);

    // value: string
    env->String_NewUTF8(metadata.value.c_str(), metadata.value.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(value), string);

    // resource: string
    env->String_NewUTF8(metadata.resource.c_str(), metadata.resource.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(resource), string);

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
    CallSetter(env, cls, object, SETTER_METHOD_NAME(maxCount), multiAppMode.maxCount);

    // multiAppModeType: bundleManager.MultiAppModeType
    CallSetter(env, cls, object, SETTER_METHOD_NAME(multiAppModeType),
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
        env->String_NewUTF8(item.first.c_str(), item.first.size(), &string);
        CallSetter(env, cls, object, SETTER_METHOD_NAME(moduleName), string);

        // metadata: Array<Metadata>
        std::vector<ani_object> aMetadata;
        for (size_t i = 0; i < item.second.size(); ++i) {
            aMetadata.emplace_back(ConvertMetadata(env, item.second[i]));
        }
        ani_ref aMetadataRef = ConvertAniArrayByClass(env, CLASSNAME_MODULEMETADATA, aMetadata);
        CallSetter(env, cls, object, SETTER_METHOD_NAME(metadata), aMetadataRef);
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
    env->String_NewUTF8(appInfo.name.c_str(), appInfo.name.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(name), string);

    // description: string
    env->String_NewUTF8(appInfo.description.c_str(), appInfo.description.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(description), string);

    // descriptionId: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(descriptionId), appInfo.descriptionId);

    // enabled: boolean
    CallSetter(env, cls, object, SETTER_METHOD_NAME(enabled), BoolToAniBoolean(appInfo.enabled));

    // label: string
    env->String_NewUTF8(appInfo.label.c_str(), appInfo.label.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(label), string);

    // labelId: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(labelId), appInfo.labelId);

    // icon: string
    env->String_NewUTF8(appInfo.iconPath.c_str(), appInfo.iconPath.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(icon), string);

    // iconId: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(iconId), appInfo.iconId);

    // process: string
    env->String_NewUTF8(appInfo.process.c_str(), appInfo.process.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(process), string);

    // permissions: Array<string>
    ani_ref aPermissions = ConvertAniArrayString(env, appInfo.permissions);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(permissions), aPermissions);

    // codePath: string
    env->String_NewUTF8(appInfo.codePath.c_str(), appInfo.codePath.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(codePath), string);

    // metadataArray: Array<ModuleMetadata>
    ani_ref aMetadataArrayRef = ConvertModuleMetaInfos(env, appInfo.metadata);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(metadataArray), aMetadataArrayRef);

    // removable: boolean
    CallSetter(env, cls, object, SETTER_METHOD_NAME(removable), BoolToAniBoolean(appInfo.removable));

    // accessTokenId: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(accessTokenId), appInfo.accessTokenId);

    // uid: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(uid), appInfo.uid);

    // iconResource: Resource
    ani_object aIconResource = ConvertResource(env, appInfo.iconResource);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(iconResource), aIconResource);

    // labelResource: Resource
    ani_object aLabelResource = ConvertResource(env, appInfo.labelResource);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(labelResource), aLabelResource);

    // descriptionResource: Resource
    ani_object aDescriptionResource = ConvertResource(env, appInfo.descriptionResource);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(descriptionResource), aDescriptionResource);

    // appDistributionType: string
    env->String_NewUTF8(appInfo.appDistributionType.c_str(), appInfo.appDistributionType.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(appDistributionType), string);

    // appProvisionType: string
    env->String_NewUTF8(appInfo.appProvisionType.c_str(), appInfo.appProvisionType.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(appProvisionType), string);

    // systemApp: boolean
    CallSetter(env, cls, object, SETTER_METHOD_NAME(systemApp), BoolToAniBoolean(appInfo.isSystemApp));

    // bundleType: bundleManager.BundleType
    CallSetter(env, cls, object, SETTER_METHOD_NAME(bundleType),
        EnumUtils::NativeValueToIndex_BundleManager_BundleType(static_cast<int32_t>(appInfo.bundleType)));

    // debug: boolean
    CallSetter(env, cls, object, SETTER_METHOD_NAME(debug), BoolToAniBoolean(appInfo.debug));

    // dataUnclearable: boolean
    CallSetter(env, cls, object, SETTER_METHOD_NAME(dataUnclearable), BoolToAniBoolean(!appInfo.userDataClearable));

    // nativeLibraryPath: string
    env->String_NewUTF8(appInfo.nativeLibraryPath.c_str(), appInfo.nativeLibraryPath.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(nativeLibraryPath), string);

    // multiAppMode: MultiAppMode
    ani_object aniMultiAppModeObj = ConvertMultiAppMode(env, appInfo.multiAppMode);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(multiAppMode), aniMultiAppModeObj);

    // appIndex: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(appIndex), appInfo.appIndex);

    // installSource: string
    env->String_NewUTF8(appInfo.installSource.c_str(), appInfo.installSource.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(installSource), string);

    // releaseType: string
    env->String_NewUTF8(appInfo.apiReleaseType.c_str(), appInfo.apiReleaseType.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(releaseType), string);

    // cloudFileSyncEnabled: boolean
    CallSetter(
        env, cls, object, SETTER_METHOD_NAME(cloudFileSyncEnabled), BoolToAniBoolean(appInfo.cloudFileSyncEnabled));

    // flags?: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(flags), appInfo.flags);

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
    env->String_NewUTF8(abilityInfo.bundleName.c_str(), abilityInfo.bundleName.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(bundleName), string);

    // moduleName: string
    env->String_NewUTF8(abilityInfo.moduleName.c_str(), abilityInfo.moduleName.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(moduleName), string);

    // name: string
    env->String_NewUTF8(abilityInfo.name.c_str(), abilityInfo.name.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(name), string);

    // label: string
    env->String_NewUTF8(abilityInfo.label.c_str(), abilityInfo.label.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(label), string);

    // labelId: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(labelId), abilityInfo.labelId);

    // description: string
    env->String_NewUTF8(abilityInfo.description.c_str(), abilityInfo.description.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(description), string);

    // descriptionId: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(descriptionId), abilityInfo.descriptionId);

    // icon: string
    env->String_NewUTF8(abilityInfo.iconPath.c_str(), abilityInfo.iconPath.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(icon), string);

    // iconId: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(iconId), abilityInfo.iconId);

    // process: string
    env->String_NewUTF8(abilityInfo.process.c_str(), abilityInfo.process.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(process), string);

    // exported: boolean
    CallSetter(env, cls, object, SETTER_METHOD_NAME(exported), BoolToAniBoolean(abilityInfo.visible));

    // type: bundleManager.AbilityType
    CallSetter(env, cls, object, SETTER_METHOD_NAME(type),
        EnumUtils::NativeValueToIndex_BundleManager_AbilityType(static_cast<int32_t>(abilityInfo.type)));

    // orientation: bundleManager.DisplayOrientation
    CallSetter(env, cls, object, SETTER_METHOD_NAME(orientation),
        EnumUtils::NativeValueToIndex_BundleManager_DisplayOrientation(static_cast<int32_t>(abilityInfo.orientation)));

    // launchType: bundleManager.LaunchType
    CallSetter(env, cls, object, SETTER_METHOD_NAME(launchType),
        EnumUtils::NativeValueToIndex_BundleManager_LaunchType(static_cast<int32_t>(abilityInfo.launchMode)));

    // permissions: Array<string>
    ani_ref aPermissions = ConvertAniArrayString(env, abilityInfo.permissions);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(permissions), aPermissions);

    // readPermission: string
    env->String_NewUTF8(abilityInfo.readPermission.c_str(), abilityInfo.readPermission.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(readPermission), string);

    // writePermission: string
    env->String_NewUTF8(abilityInfo.writePermission.c_str(), abilityInfo.writePermission.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(writePermission), string);

    // uri: string
    env->String_NewUTF8(abilityInfo.uri.c_str(), abilityInfo.uri.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(uri), string);

    // deviceTypes: Array<string>
    ani_ref aDeviceTypes = ConvertAniArrayString(env, abilityInfo.deviceTypes);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(deviceTypes), aDeviceTypes);

    // applicationInfo: ApplicationInfo
    ani_object aObject = ConvertApplicationInfo(env, abilityInfo.applicationInfo);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(applicationInfo), aObject);

    // metadata: Array<Metadata>
    std::vector<ani_object> aMetadata;
    for (size_t i = 0; i < abilityInfo.metadata.size(); ++i) {
        aMetadata.emplace_back(ConvertMetadata(env, abilityInfo.metadata[i]));
    }
    ani_ref aMetadataRef = ConvertAniArrayByClass(env, CLASSNAME_METADATA, aMetadata);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(metadata), aMetadataRef);

    // enabled: boolean
    CallSetter(env, cls, object, SETTER_METHOD_NAME(enabled), BoolToAniBoolean(abilityInfo.enabled));

    // supportWindowModes: Array<bundleManager.SupportWindowMode>
    ani_array_int aSupportWindowModes = ConvertAniArrayEnum(
        env, abilityInfo.windowModes, EnumUtils::NativeValueToIndex_BundleManager_SupportWindowMode);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(supportWindowModes), aSupportWindowModes);

    // windowSize: WindowSize
    ani_object aniWindowSizeObj = ConvertWindowSize(env, abilityInfo);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(windowSize), aniWindowSizeObj);

    // excludeFromDock: boolean
    CallSetter(env, cls, object, SETTER_METHOD_NAME(excludeFromDock), BoolToAniBoolean(abilityInfo.excludeFromDock));

    // skills: Array<Skill>
    std::vector<ani_object> aSkills;
    for (size_t i = 0; i < abilityInfo.skills.size(); ++i) {
        aSkills.emplace_back(ConvertAbilitySkill(env, abilityInfo.skills[i], false));
    }
    ani_ref aSkillsRef = ConvertAniArrayByClass(env, CLASSNAME_SKILL, aSkills);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(skills), aSkillsRef);

    // appIndex: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(appIndex), abilityInfo.appIndex);

    // orientationId: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(orientationId), abilityInfo.orientationId);

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
    CallSetter(env, cls, object, SETTER_METHOD_NAME(maxWindowRatio), abilityInfo.maxWindowRatio);

    // minWindowRatio: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(minWindowRatio), abilityInfo.minWindowRatio);

    // maxWindowWidth: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(maxWindowWidth), abilityInfo.maxWindowWidth);

    // minWindowWidth: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(minWindowWidth), abilityInfo.minWindowWidth);

    // maxWindowHeight: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(maxWindowHeight), abilityInfo.maxWindowHeight);

    // minWindowHeight: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(minWindowHeight), abilityInfo.minWindowHeight);

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
    env->String_NewUTF8(extensionInfo.bundleName.c_str(), extensionInfo.bundleName.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(bundleName), string);

    // moduleName: string
    env->String_NewUTF8(extensionInfo.moduleName.c_str(), extensionInfo.moduleName.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(moduleName), string);

    // name: string
    env->String_NewUTF8(extensionInfo.name.c_str(), extensionInfo.name.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(name), string);

    // labelId: int
    CallSetter(env, cls, object, SETTER_METHOD_NAME(labelId), extensionInfo.labelId);

    // descriptionId: int
    CallSetter(env, cls, object, SETTER_METHOD_NAME(descriptionId), extensionInfo.descriptionId);

    // iconId: int
    CallSetter(env, cls, object, SETTER_METHOD_NAME(iconId), extensionInfo.iconId);

    // exported: boolean
    CallSetter(env, cls, object, SETTER_METHOD_NAME(exported), extensionInfo.visible);

    // extensionAbilityType: bundleManager.ExtensionAbilityType
    CallSetter(env, cls, object, SETTER_METHOD_NAME(extensionAbilityType),
        EnumUtils::NativeValueToIndex_BundleManager_ExtensionAbilityType(static_cast<int32_t>(extensionInfo.type)));

    // extensionAbilityTypeName: string
    env->String_NewUTF8(extensionInfo.extensionTypeName.c_str(), extensionInfo.extensionTypeName.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(extensionAbilityTypeName), string);

    // permissions: Array<string>
    ani_ref aPermissions = ConvertAniArrayString(env, extensionInfo.permissions);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(permissions), aPermissions);

    // applicationInfo: ApplicationInfo
    ani_object aObject = ConvertApplicationInfo(env, extensionInfo.applicationInfo);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(applicationInfo), aObject);

    // metadata: Array<Metadata>
    std::vector<ani_object> aMetadata;
    for (size_t i = 0; i < extensionInfo.metadata.size(); ++i) {
        aMetadata.emplace_back(ConvertMetadata(env, extensionInfo.metadata[i]));
    }
    ani_ref aMetadataRef = ConvertAniArrayByClass(env, CLASSNAME_METADATA, aMetadata);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(metadata), aMetadataRef);

    // enabled: boolean
    CallSetter(env, cls, object, SETTER_METHOD_NAME(enabled), extensionInfo.enabled);

    // readPermission: string
    env->String_NewUTF8(extensionInfo.readPermission.c_str(), extensionInfo.readPermission.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(readPermission), string);

    // writePermission: string
    env->String_NewUTF8(extensionInfo.writePermission.c_str(), extensionInfo.writePermission.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(writePermission), string);

    // skills: Array<Skill>
    std::vector<ani_object> aSkills;
    for (size_t i = 0; i < extensionInfo.skills.size(); ++i) {
        aSkills.emplace_back(ConvertAbilitySkill(env, extensionInfo.skills[i], false));
    }
    ani_ref aSkillsRef = ConvertAniArrayByClass(env, CLASSNAME_SKILL, aSkills);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(skills), aSkillsRef);

    // appIndex: int
    CallSetter(env, cls, object, SETTER_METHOD_NAME(appIndex), extensionInfo.appIndex);

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
    env->String_NewUTF8(resource.bundleName.c_str(), resource.bundleName.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(bundleName), string);

    // moduleName: string
    env->String_NewUTF8(resource.moduleName.c_str(), resource.moduleName.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(moduleName), string);

    // id: int
    CallSetter(env, cls, object, SETTER_METHOD_NAME(id), resource.id);

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
    env->String_NewUTF8(signatureInfo.appId.c_str(), signatureInfo.appId.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(appId), string);

    // fingerprint: string
    env->String_NewUTF8(signatureInfo.fingerprint.c_str(), signatureInfo.fingerprint.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(fingerprint), string);

    // appIdentifier: string
    env->String_NewUTF8(signatureInfo.appIdentifier.c_str(), signatureInfo.appIdentifier.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(appIdentifier), string);

    // certificate: string
    env->String_NewUTF8(signatureInfo.certificate.c_str(), signatureInfo.certificate.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(certificate), string);

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
    env->String_NewUTF8(key.c_str(), key.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(key), string);

    // value: string
    env->String_NewUTF8(value.c_str(), value.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(value), string);

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
    env->String_NewUTF8(routerItem.name.c_str(), routerItem.name.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(name), string);

    // pageSourceFile: string
    env->String_NewUTF8(routerItem.pageSourceFile.c_str(), routerItem.pageSourceFile.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(pageSourceFile), string);

    // buildFunction: string
    env->String_NewUTF8(routerItem.buildFunction.c_str(), routerItem.buildFunction.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(buildFunction), string);

    // customData: string
    env->String_NewUTF8(routerItem.customData.c_str(), routerItem.customData.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(customData), string);

    // data: Array<DataItem>
    ani_ref aDataArrayRef = ConvertRouterDataInfos(env, routerItem.data);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(data), aDataArrayRef);

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
        env->String_NewUTF8(item.first.c_str(), item.first.size(), &string);
        CallSetter(env, cls, object, SETTER_METHOD_NAME(key), string);

        // name: value
        env->String_NewUTF8(item.second.c_str(), item.second.size(), &string);
        CallSetter(env, cls, object, SETTER_METHOD_NAME(value), string);
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
    env->String_NewUTF8(requestPermission.name.c_str(), requestPermission.name.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(name), string);

    // moduleName: string
    env->String_NewUTF8(requestPermission.moduleName.c_str(), requestPermission.moduleName.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(moduleName), string);

    // reason: string
    env->String_NewUTF8(requestPermission.reason.c_str(), requestPermission.reason.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(reason), string);

    // reasonId: int
    CallSetter(env, cls, object, SETTER_METHOD_NAME(reasonId), requestPermission.reasonId);

    // usedScene: UsedScene
    ani_object aObject = ConvertRequestPermissionUsedScene(env, requestPermission.usedScene);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(usedScene), aObject);

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
    env->String_NewUTF8(requestPermissionUsedScene.when.c_str(), requestPermissionUsedScene.when.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(when), string);

    // abilities: Array<string>
    ani_ref aAbilities = ConvertAniArrayString(env, requestPermissionUsedScene.abilities);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(abilities), aAbilities);

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
    env->String_NewUTF8(preloadItem.moduleName.c_str(), preloadItem.moduleName.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(moduleName), string);

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
    env->String_NewUTF8(dependency.moduleName.c_str(), dependency.moduleName.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(moduleName), string);

    // bundleName: string
    env->String_NewUTF8(dependency.bundleName.c_str(), dependency.bundleName.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(bundleName), string);

    // versionCode: int
    CallSetter(env, cls, object, SETTER_METHOD_NAME(versionCode), dependency.versionCode);

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
    env->String_NewUTF8(hapModuleInfo.name.c_str(), hapModuleInfo.name.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(name), string);

    // icon: string
    env->String_NewUTF8(hapModuleInfo.iconPath.c_str(), hapModuleInfo.iconPath.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(icon), string);

    // iconId: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(iconId), hapModuleInfo.iconId);

    // label: string
    env->String_NewUTF8(hapModuleInfo.label.c_str(), hapModuleInfo.label.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(label), string);

    // labelId: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(labelId), hapModuleInfo.labelId);

    // description: string
    env->String_NewUTF8(hapModuleInfo.description.c_str(), hapModuleInfo.description.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(description), string);

    // descriptionId: number
    CallSetter(env, cls, object, SETTER_METHOD_NAME(descriptionId), hapModuleInfo.descriptionId);

    // mainElementName: string
    env->String_NewUTF8(hapModuleInfo.mainElementName.c_str(), hapModuleInfo.mainElementName.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(mainElementName), string);

    // abilitiesInfo: Array<AbilityInfo>
    std::vector<ani_object> aAbilityInfo;
    for (size_t i = 0; i < hapModuleInfo.abilityInfos.size(); ++i) {
        aAbilityInfo.emplace_back(ConvertAbilityInfo(env, hapModuleInfo.abilityInfos[i]));
    }
    ani_ref aAbilityInfoRef = ConvertAniArrayByClass(env, CLASSNAME_ABILITYINFO, aAbilityInfo);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(abilitiesInfo), aAbilityInfoRef);

    // extensionAbilitiesInfo: Array<ExtensionAbilityInfo>
    std::vector<ani_object> aExtensionAbilityInfo;
    for (size_t i = 0; i < hapModuleInfo.extensionInfos.size(); ++i) {
        aExtensionAbilityInfo.emplace_back(ConvertExtensionInfo(env, hapModuleInfo.extensionInfos[i]));
    }
    ani_ref aExtensionAbilityInfoRef =
        ConvertAniArrayByClass(env, CLASSNAME_EXTENSIONABILITYINFO, aExtensionAbilityInfo);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(extensionAbilitiesInfo), aExtensionAbilityInfoRef);

    // metadata: Array<Metadata>
    std::vector<ani_object> aMetadata;
    for (size_t i = 0; i < hapModuleInfo.metadata.size(); ++i) {
        aMetadata.emplace_back(ConvertMetadata(env, hapModuleInfo.metadata[i]));
    }
    ani_ref aMetadataRef = ConvertAniArrayByClass(env, CLASSNAME_METADATA, aMetadata);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(metadata), aMetadataRef);

    // deviceTypes: Array<string>
    ani_ref aDeviceTypes = ConvertAniArrayString(env, hapModuleInfo.deviceTypes);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(deviceTypes), aDeviceTypes);

    // installationFree: boolean
    CallSetter(
        env, cls, object, SETTER_METHOD_NAME(installationFree), BoolToAniBoolean(hapModuleInfo.installationFree));

    // hashValue: string
    env->String_NewUTF8(hapModuleInfo.hashValue.c_str(), hapModuleInfo.hashValue.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(hashValue), string);

    // type: bundleManager.ModuleType
    CallSetter(env, cls, object, SETTER_METHOD_NAME(type),
        EnumUtils::NativeValueToIndex_BundleManager_ModuleType(static_cast<int32_t>(hapModuleInfo.moduleType)));

    // dependencies: Array<Dependency>
    std::vector<ani_object> aDependencies;
    for (size_t i = 0; i < hapModuleInfo.dependencies.size(); ++i) {
        aDependencies.emplace_back(ConvertDependency(env, hapModuleInfo.dependencies[i]));
    }
    ani_ref aDependenciesRef = ConvertAniArrayByClass(env, CLASSNAME_DEPENDENCY, aDependencies);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(dependencies), aDependenciesRef);

    // preloads: Array<PreloadItem>
    std::vector<ani_object> aPreloads;
    for (size_t i = 0; i < hapModuleInfo.preloads.size(); ++i) {
        aPreloads.emplace_back(ConvertPreloadItem(env, hapModuleInfo.preloads[i]));
    }
    ani_ref aPreloadsRef = ConvertAniArrayByClass(env, CLASSNAME_PRELOADITEM, aPreloads);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(preloads), aPreloadsRef);

    // fileContextMenuConfig: string
    env->String_NewUTF8(hapModuleInfo.fileContextMenu.c_str(), hapModuleInfo.fileContextMenu.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(fileContextMenuConfig), string);

    // routerMap: Array<RouterItem>
    std::vector<ani_object> aRrouterMap;
    for (size_t i = 0; i < hapModuleInfo.routerArray.size(); ++i) {
        aRrouterMap.emplace_back(ConvertRouterItem(env, hapModuleInfo.routerArray[i]));
    }
    ani_ref aRouterMapRef = ConvertAniArrayByClass(env, CLASSNAME_ROUTERITEM, aRrouterMap);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(routerMap), aRouterMapRef);

    // nativeLibraryPath: string
    env->String_NewUTF8(hapModuleInfo.nativeLibraryPath.c_str(), hapModuleInfo.nativeLibraryPath.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(nativeLibraryPath), string);

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
    env->String_NewUTF8(codePath.c_str(), codePath.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(codePath), string);

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
    env->String_NewUTF8(elementName.GetDeviceID().c_str(), elementName.GetDeviceID().size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(deviceId), string);

    // bundleName: string
    env->String_NewUTF8(elementName.GetBundleName().c_str(), elementName.GetBundleName().size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(bundleName), string);

    // moduleName?: string
    env->String_NewUTF8(elementName.GetModuleName().c_str(), elementName.GetModuleName().size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(moduleName), string);

    // abilityName: string
    env->String_NewUTF8(elementName.GetAbilityName().c_str(), elementName.GetAbilityName().size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(abilityName), string);

    // uri?: string
    env->String_NewUTF8(elementName.GetURI().c_str(), elementName.GetURI().size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(uri), string);

    // shortName?: string
    env->String_NewUTF8("", 0, &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(shortName), string);

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
    env->String_NewUTF8(customizeData.name.c_str(), customizeData.name.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(name), string);

    // value: string
    env->String_NewUTF8(customizeData.value.c_str(), customizeData.value.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(value), string);

    // extra: string
    env->String_NewUTF8(customizeData.extra.c_str(), customizeData.extra.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(extra), string);

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
    env->String_NewUTF8(skillUri.scheme.c_str(), skillUri.scheme.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(scheme), string);

    // host: string
    env->String_NewUTF8(skillUri.host.c_str(), skillUri.host.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(host), string);

    // port: int
    CallSetter(env, cls, object, SETTER_METHOD_NAME(port), std::stoi(skillUri.port));

    // path: string
    env->String_NewUTF8(skillUri.port.c_str(), skillUri.port.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(port), string);

    // pathStartWith: string
    env->String_NewUTF8(skillUri.pathStartWith.c_str(), skillUri.pathStartWith.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(pathStartWith), string);

    // pathRegex: string
    env->String_NewUTF8(skillUri.pathRegex.c_str(), skillUri.pathRegex.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(pathRegex), string);

    // type: string
    env->String_NewUTF8(skillUri.type.c_str(), skillUri.type.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(type), string);

    // utd: string
    env->String_NewUTF8(skillUri.utd.c_str(), skillUri.utd.size(), &string);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(utd), string);

    // maxFileSupported: int
    CallSetter(env, cls, object, SETTER_METHOD_NAME(maxFileSupported), skillUri.maxFileSupported);

    if (!isExtension) {
        // linkFeature: string
        env->String_NewUTF8(skillUri.linkFeature.c_str(), skillUri.linkFeature.size(), &string);
        CallSetter(env, cls, object, SETTER_METHOD_NAME(linkFeature), string);
    }

    return object;
}

ani_object CommonFunAni::ConvertAbilitySkill(ani_env* env, const Skill& skill, bool isExtension)
{
    std::cout << "CommonFunAni::CLASSNAME_SKILL entry" << std::endl;

    ani_class cls = CreateClassByName(env, CLASSNAME_SKILL);
    ani_object object = CreateNewObjectByClass(env, cls);
    if (cls == nullptr || object == nullptr) {
        APP_LOGE("ConvertAbilitySkill failed.");
        return nullptr;
    }

    // actions: Array<string>
    ani_ref aActions = nullptr;
    aActions = ConvertAniArrayString(env, skill.actions);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(actions), aActions);

    // entities: Array<string>
    ani_ref aEntities = nullptr;
    aEntities = ConvertAniArrayString(env, skill.entities);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(entities), aEntities);

    // uris: Array<SkillUri>
    std::vector<ani_object> aArray;
    for (size_t i = 0; i < skill.uris.size(); ++i) {
        aArray.emplace_back(ConvertAbilitySkillUri(env, skill.uris[i], isExtension));
    }
    ani_ref aSkillUri = ConvertAniArrayByClass(env, CLASSNAME_SKILLURI, aArray);
    CallSetter(env, cls, object, SETTER_METHOD_NAME(uris), aSkillUri);

    if (!isExtension) {
        // domainVerify: boolean
        CallSetter(env, cls, object, SETTER_METHOD_NAME(domainVerify), BoolToAniBoolean(skill.domainVerify));
    }

    std::cout << "CommonFunAni::CLASSNAME_SKILL exit" << std::endl;
    return object;
}
} // namespace AppExecFwk
} // namespace OHOS