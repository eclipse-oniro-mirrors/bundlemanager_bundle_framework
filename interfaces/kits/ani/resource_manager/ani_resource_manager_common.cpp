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

#include <ani_signature_builder.h>

#include "ani_resource_manager_common.h"
#include "ani_resource_manager_drawable_utils.h"
#include "common_fun_ani.h"

namespace OHOS {
namespace AppExecFwk {

namespace  {
constexpr const char* CLASSNAME_BUNDLE_RES_INFO_INNER =
    "bundleManager.BundleResourceInfoInner.BundleResourceInfoInner";
constexpr const char* CLASSNAME_LAUNCHER_ABILITY_RESOURCE_INFO_INNER =
    "bundleManager.LauncherAbilityResourceInfoInner.LauncherAbilityResourceInfoInner";
constexpr const char* CLASSNAME_DRAWABLE_DESCRIPTOR = "@ohos.arkui.drawableDescriptor.DrawableDescriptor";
}

ani_object AniResourceManagerCommon::ConvertBundleResourceInfo(ani_env* env, const BundleResourceInfo& bundleResInfo)
{
    RETURN_NULL_IF_NULL(env);

    // bundleName: string
    ani_string bundleName = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, bundleResInfo.bundleName, bundleName));

    // icon: string
    ani_string icon = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, bundleResInfo.icon, icon));

    // label: string
    ani_string label = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, bundleResInfo.label, label));

    // drawableDecriptor: DrawableDescriptor
    ani_ref drawableDecriptor = nullptr;
    ani_object drawableDecriptorObj = AniResourceManagerDrawableUtils::ConvertDrawableDescriptor(env,
        bundleResInfo.foreground, bundleResInfo.background);
    if (drawableDecriptorObj == nullptr) {
        ani_status status = env->GetNull(&drawableDecriptor);
        if (status != ANI_OK) {
            APP_LOGE("GetNull failed %{public}d", status);
            return nullptr;
        }
    } else {
        drawableDecriptor = drawableDecriptorObj;
    }

    ani_value args[] = {
        { .r = bundleName },
        { .r = icon },
        { .r = label },
        { .r = drawableDecriptor },
        { .i = bundleResInfo.appIndex },
    };
    static const std::string ctorSig =
        arkts::ani_signature::SignatureBuilder()
            .AddClass(CommonFunAniNS::CLASSNAME_STRING) // bundleName: string
            .AddClass(CommonFunAniNS::CLASSNAME_STRING) // icon: string
            .AddClass(CommonFunAniNS::CLASSNAME_STRING) // label: string
            .AddClass(CLASSNAME_DRAWABLE_DESCRIPTOR)    // drawableDecriptor: DrawableDescriptor
            .AddInt()                                   // appIndex: int
            .BuildSignatureDescriptor();
    return CommonFunAni::CreateNewObjectByClassV2(env, CLASSNAME_BUNDLE_RES_INFO_INNER, ctorSig, args);
}

ani_object AniResourceManagerCommon::ConvertLauncherAbilityResourceInfo(ani_env* env,
    const LauncherAbilityResourceInfo& launcherAbilityResourceInfo)
{
    RETURN_NULL_IF_NULL(env);

    // bundleName: string
    ani_string bundleName = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, launcherAbilityResourceInfo.bundleName, bundleName));

    // moduleName: string
    ani_string moduleName = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, launcherAbilityResourceInfo.moduleName, moduleName));

    // abilityName: string
    ani_string abilityName = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, launcherAbilityResourceInfo.abilityName, abilityName));

    // icon: string
    ani_string icon = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, launcherAbilityResourceInfo.icon, icon));

    // label: string
    ani_string label = nullptr;
    RETURN_NULL_IF_FALSE(CommonFunAni::StringToAniStr(env, launcherAbilityResourceInfo.label, label));

    // drawableDescriptor: DrawableDescriptor
    ani_ref drawableDecriptor = nullptr;
    ani_object drawableDecriptorObj = AniResourceManagerDrawableUtils::ConvertDrawableDescriptor(env,
        launcherAbilityResourceInfo.foreground, launcherAbilityResourceInfo.background);
    if (drawableDecriptorObj == nullptr) {
        ani_status status = env->GetNull(&drawableDecriptor);
        if (status != ANI_OK) {
            APP_LOGE("GetNull failed %{public}d", status);
            return nullptr;
        }
    } else {
        drawableDecriptor = drawableDecriptorObj;
    }

    ani_value args[] = {
        { .r = bundleName },
        { .r = moduleName },
        { .r = abilityName },
        { .r = icon },
        { .r = label },
        { .r = drawableDecriptor },
        { .i = launcherAbilityResourceInfo.appIndex },
    };
    static const std::string ctorSig =
        arkts::ani_signature::SignatureBuilder()
            .AddClass(CommonFunAniNS::CLASSNAME_STRING) // bundleName: string
            .AddClass(CommonFunAniNS::CLASSNAME_STRING) // moduleName: string
            .AddClass(CommonFunAniNS::CLASSNAME_STRING) // abilityName: string
            .AddClass(CommonFunAniNS::CLASSNAME_STRING) // icon: string
            .AddClass(CommonFunAniNS::CLASSNAME_STRING) // label: string
            .AddClass(CLASSNAME_DRAWABLE_DESCRIPTOR)    // drawableDecriptor: DrawableDescriptor
            .AddInt()                                   // appIndex: int
            .BuildSignatureDescriptor();
    return CommonFunAni::CreateNewObjectByClassV2(env, CLASSNAME_LAUNCHER_ABILITY_RESOURCE_INFO_INNER, ctorSig, args);
}
} // AppExecFwk
} // OHOS