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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_COMMON_FUN_ANI_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_COMMON_FUN_ANI_H

#include <ani.h>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "bundle_mgr_interface.h"
#include "bundle_resource_info.h"

namespace OHOS {
namespace AppExecFwk {

class CommonFunAni {
public:
    // Data conversion.
    static inline bool AniBooleanToBool(ani_boolean value)
    {
        return value == ANI_TRUE;
    }
    static inline ani_boolean BoolToAniBoolean(bool value)
    {
        return value ? ANI_TRUE : ANI_FALSE;
    }
    static ani_ref ConvertAniArrayByClass(
        ani_env* env, const std::string& className, const std::vector<ani_object>& aArray);
    static ani_ref ConvertAniArrayString(ani_env* env, const std::vector<std::string>& cArray);
    template<typename enumType>
    static ani_object ConvertAniArrayEnum(ani_env* env, const std::vector<enumType>& cArray,
        std::function<ani_enum_item(ani_env*, const int32_t)> converter);
    static ani_class CreateClassByName(ani_env* env, const std::string& className);
    static ani_object CreateNewObjectByClass(ani_env* env, ani_class cls);

    // Convert BundleInfo related methods.
    static ani_object ConvertMultiAppMode(ani_env* env, const MultiAppModeData& multiAppMode);
    static ani_object ConvertMetadata(ani_env* env, const Metadata& metadata);
    static ani_ref ConvertModuleMetaInfos(ani_env* env, const std::map<std::string, std::vector<Metadata>>& metadata);
    static ani_object ConvertResource(ani_env* env, const Resource& resource);
    static ani_object ConvertApplicationInfo(ani_env* env, const ApplicationInfo& appInfo);

    static ani_object ConvertAbilityInfo(ani_env* env, const AbilityInfo& abilityInfo);
    static ani_object ConvertWindowSize(ani_env* env, const AbilityInfo& abilityInfo);
    static ani_object ConvertExtensionInfo(ani_env* env, const ExtensionAbilityInfo& extensionInfo);
    static ani_object ConvertDependency(ani_env* env, const Dependency& dependency);
    static ani_object ConvertPreloadItem(ani_env* env, const PreloadItem& preloadItem);
    static ani_object ConvertHapModuleInfo(ani_env* env, const HapModuleInfo& hapModuleInfo);

    static ani_object ConvertRequestPermissionUsedScene(
        ani_env* env, const RequestPermissionUsedScene& requestPermissionUsedScene);
    static ani_object ConvertRequestPermission(ani_env* env, const RequestPermission& requestPermission);

    static ani_object ConvertSignatureInfo(ani_env* env, const SignatureInfo& signatureInfo);

    static ani_ref ConvertRouterDataInfos(ani_env* env, const std::map<std::string, std::string>& data);
    static ani_object ConvertDataItem(ani_env* env, const std::string& key, const std::string& value);
    static ani_object ConvertRouterItem(ani_env* env, const RouterItem& routerItem);

    static ani_object ConvertElementName(ani_env* env, const ElementName& elementName);

    static ani_object ConvertCustomizeData(ani_env* env, const CustomizeData& customizeData);

    static ani_object ConvertAbilitySkillUri(ani_env* env, const SkillUri& skillUri, bool isExtension);
    static ani_object ConvertAbilitySkill(ani_env* env, const Skill& skill, bool isExtension);

    static ani_object ConvertBundleInfo(ani_env* env, const BundleInfo& bundleInfo);
    static std::string AniStrToString(ani_env* env, ani_ref aniStr);
    static ani_object ConvertBundleResourceInfo(ani_env* env, const BundleResourceInfo& bundleResInfo);

    template<typename valueType>
    static inline void CallSetter(
        ani_env* env, ani_class cls, ani_object object, const char* setterName, valueType value)
    {
        ani_status status = ANI_ERROR;
        ani_method setter;
        if ((status = env->Class_FindMethod(cls, setterName, nullptr, &setter)) != ANI_OK) {
            std::cerr << setterName << " Class_FindMethod Fail " << status << std::endl;
        }
        if ((status = env->Object_CallMethod_Void(object, setter, value)) != ANI_OK) {
            std::cerr << "Object_CallMethod_Void Fail " << status << std::endl;
        }
    }
};
} // namespace AppExecFwk
} // namespace OHOS
#endif