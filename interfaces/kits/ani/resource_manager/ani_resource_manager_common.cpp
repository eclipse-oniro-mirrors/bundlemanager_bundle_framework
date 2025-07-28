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
#include "ani_resource_manager_common.h"
#include "ani_resource_manager_drawable_utils.h"
#include "common_fun_ani.h"

namespace OHOS {
namespace AppExecFwk {

namespace  {
constexpr const char* CLASSNAME_BUNDLE_RES_INFO_INNER =
    "LbundleManager/BundleResourceInfoInner/BundleResourceInfoInner;";
constexpr const char* CLASSNAME_LAUNCHER_ABILITY_RESOURCE_INFO_INNER =
    "LbundleManager/LauncherAbilityResourceInfoInner/LauncherAbilityResourceInfoInner;";
constexpr const char* PROPERTYNAME_BUNDLENAME = "bundleName";
constexpr const char* PROPERTYNAME_MODULENAME = "moduleName";
constexpr const char* PROPERTYNAME_ABILITYNAME = "abilityName";
constexpr const char* PROPERTYNAME_ICON = "icon";
constexpr const char* PROPERTYNAME_LABEL = "label";
constexpr const char* PROPERTYNAME_DRAWABLEDESCRIPTOR = "drawableDescriptor";
constexpr const char* PROPERTYNAME_APPINDEX = "appIndex";
}

ani_object AniResourceManagerCommon::ConvertBundleResourceInfo(ani_env* env, const BundleResourceInfo& bundleResInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CommonFunAni::CreateClassByName(env, CLASSNAME_BUNDLE_RES_INFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CommonFunAni::CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // bundleName: string
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, bundleResInfo.bundleName, string));
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // icon: string
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, bundleResInfo.icon, string));
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_ICON, string));

    // label: string
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, bundleResInfo.label, string));
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_LABEL, string));

    // drawableDecriptor: DrawableDescriptor
    ani_object aDrawableDescriptor = AniResourceManagerDrawableUtils::ConvertDrawableDescriptor(env,
        bundleResInfo.foreground, bundleResInfo.background);
    if (aDrawableDescriptor == nullptr) {
        RETURN_NULL_IF_FALSE(CommonFunAni::CallSetterNull(env, cls, object, PROPERTYNAME_DRAWABLEDESCRIPTOR));
    } else {
        RETURN_NULL_IF_FALSE(
            CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_DRAWABLEDESCRIPTOR, aDrawableDescriptor));
    }

    // appIndex: int
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, bundleResInfo.appIndex));

    return object;
}

ani_object AniResourceManagerCommon::ConvertLauncherAbilityResourceInfo(ani_env* env,
    const LauncherAbilityResourceInfo& launcherAbilityResourceInfo)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CommonFunAni::CreateClassByName(env, CLASSNAME_LAUNCHER_ABILITY_RESOURCE_INFO_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CommonFunAni::CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    ani_string string = nullptr;

    // bundleName: string
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, launcherAbilityResourceInfo.bundleName, string));
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_BUNDLENAME, string));

    // moduleName: string
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, launcherAbilityResourceInfo.moduleName, string));
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_MODULENAME, string));

    // abilityName: string
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, launcherAbilityResourceInfo.abilityName, string));
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_ABILITYNAME, string));

    // icon: string
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, launcherAbilityResourceInfo.icon, string));
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_ICON, string));

    // label: string
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, launcherAbilityResourceInfo.label, string));
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_LABEL, string));

    // drawableDescriptor: DrawableDescriptor
    ani_object aDrawableDescriptor = AniResourceManagerDrawableUtils::ConvertDrawableDescriptor(env,
        launcherAbilityResourceInfo.foreground, launcherAbilityResourceInfo.background);
    if (aDrawableDescriptor == nullptr) {
        RETURN_NULL_IF_FALSE(CommonFunAni::CallSetterNull(env, cls, object, PROPERTYNAME_DRAWABLEDESCRIPTOR));
    } else {
        RETURN_NULL_IF_FALSE(
            CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_DRAWABLEDESCRIPTOR, aDrawableDescriptor));
    }

    // appIndex: int
    RETURN_NULL_IF_FALSE(
        CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_APPINDEX, launcherAbilityResourceInfo.appIndex));

    return object;
}
} // AppExecFwk
} // OHOS